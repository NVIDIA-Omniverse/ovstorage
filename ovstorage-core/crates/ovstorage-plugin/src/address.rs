// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Address helpers operating on [`url::Url`].
//!
//! Addresses are RFC 3986 URLs. The path component (after
//! percent-decoding) is the backend's primary key; the query
//! component is reserved for backend-specific address modifiers.

use url::Url;

use crate::{Error, ErrorCode, Result};

/// Parse and validate an ovstorage URL. Single error-mapping site
/// for `url::ParseError → InvalidArgument`. Output is RFC 3986
/// canonical: scheme + host lowercased, default ports stripped, all
/// components percent-encoded.
///
/// Authority-with-empty-path (e.g. `omniverse://host`) is normalized to
/// `omniverse://host/` so route-prefix matching is consistent regardless
/// of whether the user typed the trailing slash. The `url` crate already
/// does this for special schemes (http/https/ftp) but not for ours.
pub fn parse(value: &str) -> Result<Url> {
    let mut url = Url::parse(value)
        .map_err(|error| Error::new(ErrorCode::InvalidArgument, format!("invalid URL: {error}")))?;
    if url.has_authority() && url.path().is_empty() {
        url.set_path("/");
    }
    Ok(url)
}

/// Backend's primary object key — the URL path with percent-encoding
/// removed. Empty for the root and opaque URLs.
pub fn key(url: &Url) -> String {
    let path = url.path();
    let path = path.strip_prefix('/').unwrap_or(path);
    percent_decode(path)
}

/// True when the URL refers to a directory (path ends with `/`).
pub fn is_directory(url: &Url) -> bool {
    url.path().ends_with('/')
}

/// Append `/` if missing, preserving query and fragment.
pub fn to_directory(url: &Url) -> Result<Url> {
    if is_directory(url) {
        return Ok(url.clone());
    }
    let mut out = url.clone();
    let new_path = format!("{}/", out.path());
    out.set_path(&new_path);
    Ok(out)
}

/// Split into `(parent_directory, child_name)`. `child_name` is
/// percent-decoded. Returns `None` for directory-form URLs, root
/// paths, or URLs carrying a fragment.
pub fn parent_and_name(url: &Url) -> Option<(Url, String)> {
    if is_directory(url) || url.fragment().is_some() {
        return None;
    }
    let path = url.path();
    let slash = path.rfind('/')?;
    let name = &path[slash + 1..];
    if name.is_empty() {
        return None;
    }
    let mut parent = url.clone();
    parent.set_path(&path[..=slash]);
    parent.set_query(None);
    parent.set_fragment(None);
    Some((parent, percent_decode(name)))
}

/// Replace `prefix` with `replacement` at the head of `url`.
/// Returns `Err(NoRoute)` for a non-prefix.
pub fn replace_prefix(url: &Url, prefix: &Url, replacement: &Url) -> Result<Url> {
    let suffix = strip_prefix(url, prefix).ok_or_else(|| {
        Error::new(
            ErrorCode::NoRoute,
            "address is not under the selected route prefix",
        )
    })?;
    let combined = format!("{}{}", replacement.as_str(), suffix);
    parse(&combined)
}

/// Suffix after `prefix`, or `None` for a non-prefix.
pub fn strip_prefix<'a>(url: &'a Url, prefix: &Url) -> Option<&'a str> {
    if !is_prefix_of(prefix, url) {
        return None;
    }
    url.as_str().strip_prefix(prefix.as_str())
}

/// True when `prefix` is a segment-aligned prefix of `addr`. Boundaries
/// are `/`, `?`, `#`; `&` is also a boundary when the prefix already
/// contains a query. `s3://bucket/foo` does NOT match
/// `s3://bucket/foobar`.
pub fn is_prefix_of(prefix: &Url, addr: &Url) -> bool {
    let prefix = prefix.as_str();
    let addr = addr.as_str();
    if !addr.starts_with(prefix) {
        return false;
    }
    if prefix.ends_with('/') || addr.len() == prefix.len() {
        return true;
    }
    let boundary = addr.as_bytes().get(prefix.len());
    if prefix.contains('?') {
        matches!(boundary, Some(b'/' | b'?' | b'#' | b'&'))
    } else {
        matches!(boundary, Some(b'/' | b'?' | b'#'))
    }
}

/// Append or replace one query parameter with URL-parser semantics.
pub fn with_query_pair(url: &Url, key: &str, value: &str) -> Result<Url> {
    if key.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "query parameter key must not be empty",
        ));
    }
    let mut out = url.clone();
    let preserved: Vec<(String, String)> = out
        .query_pairs()
        .filter(|(k, _)| k != key)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    out.set_query(None);
    {
        let mut q = out.query_pairs_mut();
        for (k, v) in &preserved {
            q.append_pair(k, v);
        }
        q.append_pair(key, value);
    }
    Ok(out)
}

/// Append a relative path. The relative path must not start with `/`.
/// Empty relative paths are a no-op.
pub fn join_relative(url: &Url, relative_path: &str) -> Result<Url> {
    if relative_path.starts_with('/') {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "relative paths must not start with '/'",
        ));
    }
    if relative_path.is_empty() {
        return Ok(url.clone());
    }
    let mut base = url.clone();
    let new_path = if base.path().ends_with('/') {
        format!("{}{}", base.path(), relative_path)
    } else {
        format!("{}/{}", base.path(), relative_path)
    };
    base.set_path(&new_path);
    Ok(base)
}

fn percent_decode(input: &str) -> String {
    // Manual decode: `url`'s `percent_decode_str` is gated behind a
    // feature flag, and pulling in `percent-encoding` separately is
    // not worth it for this single use site.
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoded_path_decodes_to_key() {
        let url = parse("s3://bucket/foo%20bar.txt").unwrap();
        assert_eq!(url.as_str(), "s3://bucket/foo%20bar.txt");
        assert_eq!(key(&url), "foo bar.txt");
    }

    #[test]
    fn double_percent_encoding_round_trips_literal_percent() {
        let url = parse("s3://bucket/foo%2520bar.txt").unwrap();
        assert_eq!(key(&url), "foo%20bar.txt");
    }

    #[test]
    fn question_mark_in_key_must_be_percent_encoded() {
        // Literal ? would split into a query.
        let url = parse("s3://bucket/foo%3Fbar.txt").unwrap();
        assert_eq!(key(&url), "foo?bar.txt");
        assert!(url.query().is_none());
    }

    #[test]
    fn space_in_input_canonicalizes_to_percent_encoded() {
        let url = parse("s3://bucket/foo bar.txt").unwrap();
        assert_eq!(url.as_str(), "s3://bucket/foo%20bar.txt");
        assert_eq!(key(&url), "foo bar.txt");
    }

    #[test]
    fn is_prefix_of_segment_aligned() {
        let prefix = parse("s3://bucket/foo").unwrap();
        let same = parse("s3://bucket/foo").unwrap();
        let child = parse("s3://bucket/foo/bar").unwrap();
        let unrelated = parse("s3://bucket/foobar").unwrap();
        assert!(is_prefix_of(&prefix, &same));
        assert!(is_prefix_of(&prefix, &child));
        assert!(!is_prefix_of(&prefix, &unrelated));
    }

    #[test]
    fn is_prefix_of_directory_form_matches_descendants() {
        let prefix = parse("s3://bucket/dir/").unwrap();
        let child = parse("s3://bucket/dir/sub/file.txt").unwrap();
        assert!(is_prefix_of(&prefix, &child));
    }

    #[test]
    fn parent_and_name_splits_on_last_slash() {
        let url = parse("s3://bucket/dir/file.txt").unwrap();
        let (parent, name) = parent_and_name(&url).unwrap();
        assert_eq!(parent.as_str(), "s3://bucket/dir/");
        assert_eq!(name, "file.txt");
    }

    #[test]
    fn parent_and_name_decodes_filename() {
        let url = parse("s3://bucket/dir/foo%20bar.txt").unwrap();
        let (parent, name) = parent_and_name(&url).unwrap();
        assert_eq!(parent.as_str(), "s3://bucket/dir/");
        assert_eq!(name, "foo bar.txt");
    }

    #[test]
    fn parent_and_name_directory_returns_none() {
        let url = parse("s3://bucket/dir/").unwrap();
        assert!(parent_and_name(&url).is_none());
    }

    #[test]
    fn to_directory_appends_slash() {
        let url = parse("s3://bucket/dir").unwrap();
        let dir = to_directory(&url).unwrap();
        assert_eq!(dir.as_str(), "s3://bucket/dir/");
    }

    #[test]
    fn with_query_pair_appends_to_existing_query() {
        let url = parse("s3://bucket/foo.txt?other=ignored").unwrap();
        let out = with_query_pair(&url, "versionId", "abc").unwrap();
        assert!(out.as_str().contains("versionId=abc"));
        assert!(out.as_str().contains("other=ignored"));
    }

    #[test]
    fn replace_prefix_swaps_segment() {
        let addr = parse("server://new/bar/baz.txt").unwrap();
        let old = parse("server://new/").unwrap();
        let new = parse("server://old/").unwrap();
        let out = replace_prefix(&addr, &old, &new).unwrap();
        assert_eq!(out.as_str(), "server://old/bar/baz.txt");
    }
}
