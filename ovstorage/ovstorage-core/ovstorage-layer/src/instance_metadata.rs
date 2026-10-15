// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Refusal of cloud instance-metadata endpoints.
//!
//! Every major cloud runs an HTTP service on a fixed address that hands the
//! instance its own identity: AWS IMDS at `169.254.169.254` and
//! `fd00:ec2::254`, the ECS task-credential endpoint at `169.254.170.2`, GCE
//! at `metadata.google.internal` (the same IPv4 address again), Azure IMDS at
//! that address once more and the Azure wireserver at `168.63.129.16`, Alibaba
//! Cloud ECS at `100.100.100.200`. A process that can be talked into fetching
//! from one of those on a caller's behalf hands the caller the instance's role
//! credentials, which is the canonical server-side request forgery. The
//! anonymous fallback is exactly such a surface — the caller chooses the
//! address and the process reaches it from its own network position — and so
//! is every redirect a remote server mints. So every host the fallback derives
//! from an address, every configured fallback endpoint, and every redirect
//! destination is judged here before a socket opens.
//!
//! # Polarity
//!
//! **True means refuse.** `ovstorage::net::is_local_cleartext_host` answers
//! the opposite question — *is this host local enough that cleartext is
//! acceptable?* — and returns true for loopback, private and link-local ranges
//! alike. Reusing it here would refuse `localhost` and every private address,
//! which the loopback test seams and MinIO-style operator endpoints depend on,
//! while adding nothing on the link-local range the two predicates share. Do
//! not reuse it in either direction.
//!
//! # Names are matched exactly, never by suffix
//!
//! `metadata.google.internal.evil.test` is somebody else's host, and
//! `evil.metadata.goog` is too. Suffix matching would also invite the reverse
//! mistake the http plugin's `is_loopback_host` documents for `localhost`:
//! treating a suffix as an identity when the resolver does not. One trailing
//! dot is stripped, because `metadata.google.internal.` is the fully qualified
//! spelling of the same name and the resolver answers both identically.
//!
//! # What this does not catch
//!
//! The predicate judges the host as written. A DNS name that resolves to a
//! link-local address is not caught here: an attacker-controlled name pointing
//! at `169.254.169.254` passes, and only a connector that resolves and then
//! checks the resolved address before dialing can close that. Until such a
//! connector exists, this predicate is the guard for the literal forms, which
//! are the ones every published exploit reaches for first.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Error, ErrorCode, Result, Url, origin_only};

/// Host names that name a cloud instance-metadata service. GCE answers
/// `metadata.google.internal` and the short alias `metadata.goog`; the bare
/// `metadata` is what GCE's own resolver search path expands, and a host in
/// any other cloud gains nothing from reaching a name that short.
const INSTANCE_METADATA_NAMES: &[&str] = &["metadata.google.internal", "metadata.goog", "metadata"];

/// The AWS IMDS IPv6 endpoint, which sits outside `fe80::/10` and so needs
/// naming on its own.
const AWS_IMDS_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// The Alibaba Cloud ECS metadata service, which sits outside `169.254.0.0/16`
/// and so needs naming on its own.
const ALIBABA_ECS_METADATA: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 200);

/// The Azure wireserver, which hands an instance its goal state and tenant
/// certificates and also sits outside `169.254.0.0/16`.
const AZURE_WIRESERVER: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);

/// Whether `host` — as a URL's `host_str` reports it, brackets included for an
/// IPv6 literal — names a cloud instance-metadata endpoint.
///
/// Refused: any IPv4 address in `169.254.0.0/16`, `100.100.100.200`,
/// `168.63.129.16`, any IPv6 address in `fe80::/10`, `fd00:ec2::254`, an IPv6
/// address embedding a refused IPv4 address (`::ffff:169.254.169.254`,
/// `::169.254.169.254`), and the exact names in the module doc,
/// ASCII-case-insensitively with one trailing dot tolerated.
pub fn is_instance_metadata_host_str(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    let host = host.to_ascii_lowercase();
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return is_refused_v4(v4);
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        // `to_ipv4` unwraps both the mapped (`::ffff:a.b.c.d`) and the
        // compatible (`::a.b.c.d`) embedding, either of which a dual-stack
        // socket delivers to the IPv4 endpoint.
        return is_unicast_link_local(v6)
            || v6 == AWS_IMDS_IPV6
            || v6.to_ipv4().is_some_and(is_refused_v4);
    }
    INSTANCE_METADATA_NAMES.contains(&host.as_str())
}

/// Whether `url` addresses a cloud instance-metadata endpoint. A URL with no
/// host (`file:///`, `s3:///`) addresses nothing on the network and is not.
pub fn is_instance_metadata_url(url: &Url) -> bool {
    url.host_str().is_some_and(is_instance_metadata_host_str)
}

/// Refuse `url` when it addresses a cloud instance-metadata endpoint. Called
/// before any socket opens toward a host the process did not get from its
/// operator's configuration.
///
/// # Errors
///
/// - [`ErrorCode::PermissionDenied`] — the host is an instance-metadata
///   endpoint. The message names the origin only: the path and query of such
///   a URL are the attacker's, and not worth echoing.
pub fn refuse_instance_metadata(url: &Url) -> Result<()> {
    if is_instance_metadata_url(url) {
        return Err(Error::new(
            ErrorCode::PermissionDenied,
            format!(
                "refusing to contact {}: it is a cloud instance-metadata endpoint, and \
                 ovstorage never fetches from one on a caller's behalf",
                origin_only(url)
            ),
        ));
    }
    Ok(())
}

/// `169.254.0.0/16` plus the two metadata addresses that sit outside it.
fn is_refused_v4(addr: Ipv4Addr) -> bool {
    addr.is_link_local() || addr == ALIBABA_ECS_METADATA || addr == AZURE_WIRESERVER
}

/// `fe80::/10`, RFC 4291 §2.5.6.
fn is_unicast_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(url: &str) -> bool {
        is_instance_metadata_url(&Url::parse(url).unwrap())
    }

    #[test]
    fn instance_metadata_endpoints_are_refused() {
        for url in [
            // AWS IMDS, with and without a port, and the ECS task endpoint.
            "http://169.254.169.254/latest/meta-data",
            "https://169.254.169.254:8443/",
            "http://169.254.170.2/",
            // The whole link-local /16, not just the well-known address.
            "http://169.254.0.1/",
            "http://169.254.255.255/",
            // Alibaba Cloud ECS and the Azure wireserver, outside link-local.
            "http://100.100.100.200/latest/meta-data/",
            "http://168.63.129.16/machine?comp=goalstate",
            // IPv6: link-local, the AWS IPv6 endpoint, and an embedded IPv4.
            "http://[fe80::1]/",
            "http://[FE80::1]/",
            "http://[febf::1]/",
            "http://[fd00:ec2::254]/",
            "http://[::ffff:169.254.169.254]/",
            "http://[::169.254.169.254]/",
            "http://[::ffff:100.100.100.200]/",
            "http://[::168.63.129.16]/",
            // GCE names, exactly, in any case, with or without the root dot.
            "http://metadata.google.internal/",
            "http://METADATA.GOOGLE.INTERNAL./",
            "http://metadata.goog/",
            "http://metadata/",
            "http://metadata./",
        ] {
            assert!(refused(url), "must refuse: {url}");
        }
    }

    #[test]
    fn ordinary_hosts_are_allowed() {
        for url in [
            // Neighbours of the link-local range on either side.
            "http://169.253.255.255/",
            "http://169.255.0.0/",
            // Neighbours of the two addresses outside the link-local range.
            "http://100.100.100.199/",
            "http://100.100.100.201/",
            "http://168.63.129.15/",
            "http://168.63.129.17/",
            "http://[::ffff:100.100.100.201]/",
            // IPv6 outside fe80::/10 and the AWS endpoint's neighbour.
            "http://[fec0::1]/",
            "http://[fe7f::1]/",
            "http://[fd00:ec2::255]/",
            "http://[::ffff:10.0.0.1]/",
            "http://[::1]/",
            // Names that merely contain a metadata name.
            "http://notmetadata.google.internal/",
            "http://metadata.google.internal.evil.test/",
            "http://evil.metadata.goog/",
            "http://metadata.example/",
            // The endpoints the fallback exists to reach.
            "https://storage.googleapis.com/",
            "https://bucket.s3.amazonaws.com/",
            "https://acct.blob.core.windows.net/",
            // Loopback and private: local, but not instance metadata. The
            // test seams and operator-run MinIO live here.
            "http://localhost:9000/",
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
        ] {
            assert!(!refused(url), "must allow: {url}");
        }
    }

    #[test]
    fn a_hostless_url_is_not_an_endpoint() {
        for url in ["file:///etc/hosts", "s3:///", "mem:///x"] {
            let url = Url::parse(url).unwrap();
            assert!(!is_instance_metadata_url(&url), "{url}");
            assert!(refuse_instance_metadata(&url).is_ok(), "{url}");
        }
    }

    /// The predicate also takes a bare host string, as a backend derives one
    /// from a bucket or account before it has a URL to hand over.
    #[test]
    fn a_bare_host_string_is_judged_the_same_way() {
        assert!(is_instance_metadata_host_str("169.254.169.254"));
        assert!(is_instance_metadata_host_str("100.100.100.200"));
        assert!(is_instance_metadata_host_str("168.63.129.16"));
        assert!(is_instance_metadata_host_str("[fe80::1]"));
        assert!(is_instance_metadata_host_str("fe80::1"));
        assert!(is_instance_metadata_host_str("Metadata.Google.Internal."));
        assert!(!is_instance_metadata_host_str("bucket.s3.amazonaws.com"));
        assert!(!is_instance_metadata_host_str("localhost"));
        assert!(!is_instance_metadata_host_str(""));
        assert!(!is_instance_metadata_host_str("."));
    }

    #[test]
    fn refuse_instance_metadata_names_only_the_origin() {
        let url = Url::parse(
            "http://169.254.169.254:8080/latest/meta-data/iam/security-credentials/?token=abc",
        )
        .unwrap();
        let error = refuse_instance_metadata(&url).unwrap_err();
        assert!(
            error.message().contains("http://169.254.169.254:8080"),
            "{}",
            error.message()
        );
        assert!(!error.message().contains("latest"), "{}", error.message());
        assert!(
            !error.message().contains("security-credentials"),
            "{}",
            error.message()
        );
        assert!(!error.message().contains("token"), "{}", error.message());
    }

    #[test]
    fn the_refusal_is_permission_denied() {
        let error =
            refuse_instance_metadata(&Url::parse("http://metadata.google.internal/").unwrap())
                .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
        assert!(
            error.message().contains("instance-metadata endpoint"),
            "{}",
            error.message()
        );
        assert!(
            refuse_instance_metadata(&Url::parse("https://storage.googleapis.com/").unwrap())
                .is_ok()
        );
    }
}
