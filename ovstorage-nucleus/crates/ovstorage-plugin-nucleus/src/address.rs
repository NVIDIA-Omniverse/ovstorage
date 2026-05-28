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

    if addr.fragment().is_some() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Nucleus checkpoint selectors must use query syntax",
        ));
    }

    // omni1 expects the literal (percent-decoded) path, with the leading '/'.
    let raw_path = addr.path();
    if raw_path.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Nucleus address must include a path",
        ));
    }
    // `address::key` strips the leading slash; rebuild it. Root ('/') returns "" and rebuilds to "/".
    let path = format!("/{}", address::key(addr));

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
