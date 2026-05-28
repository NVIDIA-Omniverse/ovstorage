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
pub struct RedactedUrl<'a>(pub &'a Url);

impl fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

    #[test]
    fn handles_file_scheme_without_authority() {
        let url = parse("file:///var/data/object.bin");
        assert_eq!(RedactedUrl(&url).to_string(), "file:///var/data/object.bin");
    }
}
