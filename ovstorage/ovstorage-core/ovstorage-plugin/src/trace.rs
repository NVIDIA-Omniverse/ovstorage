// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-RPC span field helpers; centralises redaction + recording.
//!
//! Span attrs: `policy_epoch`, `principal.id`, `audit_id`, `cache.hit`,
//! `redirect.kind`, plus the redacted `object.address`. `route.id` and
//! `backend.id` are deferred until operators stamp routes.

use std::fmt;

use crate::Url;

/// `Display` emits `scheme://host[:port]` + path; drops query,
/// fragment, userinfo so signed-URL tokens never land in traces /
/// audit records / log lines.
///
/// A URL with no authority (`urn:reader:secret@x/p`, anything the parser
/// reports as cannot-be-a-base) emits its **scheme alone**. For that class
/// every byte after the scheme is one opaque string with no structure the
/// parser will split, so it lands in `path()` — userinfo and query included —
/// and rendering it would print exactly what this type exists to withhold,
/// under a `://` nobody wrote. The scheme is the part that helps and the part
/// that is safe, which is the same answer the address boundary gives when it
/// refuses to interpolate one of these.
pub struct RedactedUrl<'a>(pub &'a Url);

impl fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.cannot_be_a_base() {
            return write!(f, "{}:<opaque>", self.0.scheme());
        }
        write!(f, "{}://", self.0.scheme())?;
        if let Some(host) = self.0.host_str() {
            write!(f, "{host}")?;
            if let Some(port) = self.0.port() {
                write!(f, ":{port}")?;
            }
        }
        // Path is kept so the operator can identify the address-tree;
        // query/fragment/userinfo are dropped.
        write!(f, "{}", self.0.path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn redacts_query_string() {
        let url = parse("https://broker.example.com/objects/a?signature=secret");
        assert_eq!(
            RedactedUrl(&url).to_string(),
            "https://broker.example.com/objects/a"
        );
    }

    #[test]
    fn redacts_fragment() {
        let url = parse("https://broker.example.com/objects/a#section");
        assert_eq!(
            RedactedUrl(&url).to_string(),
            "https://broker.example.com/objects/a"
        );
    }

    #[test]
    fn redacts_userinfo() {
        let url = parse("https://user:pass@broker.example.com/objects/a");
        assert_eq!(
            RedactedUrl(&url).to_string(),
            "https://broker.example.com/objects/a"
        );
    }

    #[test]
    fn keeps_scheme_host_port_path() {
        let url = parse("grpc+tls://broker.example.com:4321/api/v1/services");
        assert_eq!(
            RedactedUrl(&url).to_string(),
            "grpc+tls://broker.example.com:4321/api/v1/services"
        );
    }

    /// An authority-less URL is rendered as its scheme and nothing else.
    ///
    /// `path()` is the whole post-scheme payload for this class, so emitting
    /// it would print the userinfo and query this type exists to drop. The
    /// comma in the fixture matters: it ends the error redactor's URL scan, so
    /// a caller that passes this string on to `Error::new` gets no second
    /// chance at it either.
    #[test]
    fn an_authority_less_url_renders_only_its_scheme() {
        let url = Url::parse("urn:reader:tok,en@x/p?api_key=supersecret").unwrap();
        assert!(url.cannot_be_a_base(), "the fixture must be that class");
        assert_eq!(RedactedUrl(&url).to_string(), "urn:<opaque>");
    }

    #[test]
    fn handles_file_scheme_without_authority() {
        let url = parse("file:///var/data/object.bin");
        assert_eq!(RedactedUrl(&url).to_string(), "file:///var/data/object.bin");
    }
}
