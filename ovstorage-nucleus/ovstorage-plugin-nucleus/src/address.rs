// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ovstorage_plugin::{Error, ErrorCode, Result, Url, address};

pub(crate) const NUCLEUS_KIND: &str = "nucleus";
pub(crate) const NUCLEUS_SCHEME: &str = "omniverse";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NucleusTarget {
    pub server: String,
    pub path: String,
    pub branch: Option<String>,
    pub checkpoint: Option<u64>,
}

pub(crate) fn parse_nucleus_address(addr: &Url) -> Result<NucleusTarget> {
    if addr.scheme() != NUCLEUS_SCHEME {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Nucleus addresses must use omniverse://",
        ));
    }
    let host = addr.host_str().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "Nucleus address is missing a server",
        )
    })?;
    if host.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Nucleus address is missing a server",
        ));
    }
    let server = match addr.port() {
        Some(port) => format!("{}:{}", host.to_ascii_lowercase(), port),
        None => host.to_ascii_lowercase(),
    };

    // omni1 expects the literal (percent-decoded) path, with the leading '/'.
    let raw_path = addr.path();
    if raw_path.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Nucleus address must include a path",
        ));
    }
    // `address::key_utf8` strips the leading slash; rebuild it. Root ('/')
    // returns "" and rebuilds to "/". The path is serialized on the omni1 wire
    // as a `String`, so a key that is not valid UTF-8 is refused here rather
    // than collapsed into one the server would resolve to a different node.
    let path = format!("/{}", address::key_utf8(addr)?);

    let (branch, checkpoint) = match addr.query() {
        Some(selector) => parse_checkpoint_selector(selector)?,
        None => (None, None),
    };

    Ok(NucleusTarget {
        server,
        path,
        branch,
        checkpoint,
    })
}

fn parse_checkpoint_selector(query: &str) -> Result<(Option<String>, Option<u64>)> {
    if query.is_empty() {
        return Ok((None, None));
    }
    if let Some(value) = query.strip_prefix('&') {
        return Ok((None, Some(parse_checkpoint_id(value)?)));
    }
    if let Some(value) = query.strip_prefix("checkpoint=") {
        return Ok((None, Some(parse_checkpoint_id(value)?)));
    }
    if query.chars().all(|ch| ch.is_ascii_digit()) {
        return Ok((None, Some(parse_checkpoint_id(query)?)));
    }
    let mut parts = query.split('&');
    let branch = parts.next().unwrap_or_default();
    let checkpoint = parts.next().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "Nucleus checkpoint selector must be ?&N, ?checkpoint=N, ?N, or ?branch&N",
        )
    })?;
    if parts.next().is_some() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Nucleus checkpoint selector has too many components",
        ));
    }
    Ok((
        if branch.is_empty() {
            None
        } else {
            Some(branch.to_string())
        },
        Some(parse_checkpoint_id(checkpoint)?),
    ))
}

fn parse_checkpoint_id(value: &str) -> Result<u64> {
    if value.is_empty() || !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Nucleus checkpoint id must be an unsigned integer",
        ));
    }
    value.parse::<u64>().map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "Nucleus checkpoint id is out of range",
        )
    })
}

pub(crate) fn canonical_server_from_root(root: &Url) -> Result<String> {
    parse_nucleus_address(root).map(|target| target.server)
}

pub(crate) fn path_is_under_prefix(path: &str, prefix: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fragment names the same node, so an address carrying one is served.
    ///
    /// This parser sits on the path every verb takes, after canonicalization
    /// has already stripped the fragment — so a rejection here could not fire,
    /// which is worse than no check because a reader takes it for a live
    /// guarantee. Its message named a checkpoint-in-fragment syntax that never
    /// existed; nothing anywhere reads one.
    #[test]
    fn an_address_written_with_a_fragment_names_the_node_without_it() {
        let with =
            parse_nucleus_address(&address::parse("omniverse://server/p#x").unwrap()).unwrap();
        let without =
            parse_nucleus_address(&address::parse("omniverse://server/p").unwrap()).unwrap();
        assert_eq!(with.path, "/p");
        assert_eq!(with.path, without.path);
        assert_eq!(with.server, without.server);
    }

    /// The control: a checkpoint selector is query syntax and still parses.
    #[test]
    fn a_checkpoint_selector_is_read_from_the_query() {
        let target =
            parse_nucleus_address(&address::parse("omniverse://server/p?checkpoint=7").unwrap())
                .unwrap();
        assert_eq!(target.checkpoint, Some(7));
    }
}
