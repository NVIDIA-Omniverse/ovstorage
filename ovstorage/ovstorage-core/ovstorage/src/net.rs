// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network address helpers shared across crates.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Returns true if the given host indicates a local/private network where
/// cleartext (`http://`, `grpc+tcp://`) is acceptable. False for anything
/// reachable on the public internet.
///
/// Matches:
/// - `localhost`, `*.local`
/// - IPv4 loopback / private (10.0.0.0/8, 172.16/12, 192.168/16) / link-local /
///   unspecified / broadcast
/// - IPv6 loopback / unspecified / unique-local (`fc00::/7`) / link-local
///   unicast (`fe80::/10`)
pub fn is_local_cleartext_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if host.to_ascii_lowercase().ends_with(".local") {
        return true;
    }
    if let Ok(addr) = host.parse::<Ipv6Addr>() {
        return addr.is_loopback()
            || addr.is_unspecified()
            || is_ipv6_unique_local(&addr)
            || is_ipv6_unicast_link_local(&addr);
    }
    if let Ok(addr) = host.parse::<Ipv4Addr>() {
        return addr.is_loopback()
            || addr.is_private()
            || addr.is_link_local()
            || addr.is_unspecified()
            || addr.is_broadcast();
    }
    false
}

fn is_ipv6_unique_local(a: &Ipv6Addr) -> bool {
    (a.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_unicast_link_local(a: &Ipv6Addr) -> bool {
    (a.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(is_local_cleartext_host("localhost"));
        assert!(is_local_cleartext_host("LOCALHOST"));
        assert!(is_local_cleartext_host("broker.local"));
        assert!(!is_local_cleartext_host("broker.example.com"));
    }

    /// The unspecified and limited-broadcast addresses qualify, and the
    /// invariant is asserted HERE rather than only in a downstream crate.
    ///
    /// Measured: deleting `is_unspecified()` from the IPv4 arm reddens only
    /// `plaintext_to_a_non_local_host_is_refused` in
    /// `ovstorage-plugin-services-client`, while `cargo test -p ovstorage
    /// --lib net::` stayed green — so a tightening made in this file was
    /// invisible to this file's own suite.
    ///
    /// They qualify because none can carry a connection off this host:
    /// `0.0.0.0` and `::` dial the local host, and `255.255.255.255` is not a
    /// connectable unicast destination.
    #[test]
    fn unspecified_and_broadcast_are_local() {
        assert!(is_local_cleartext_host("0.0.0.0"));
        assert!(is_local_cleartext_host("::"));
        assert!(is_local_cleartext_host("255.255.255.255"));
        // The near neighbours must NOT qualify, or the assertions above pass
        // for a classifier that accepts everything.
        assert!(!is_local_cleartext_host("0.0.0.1"));
        assert!(!is_local_cleartext_host("255.255.255.254"));
    }

    #[test]
    fn ipv4() {
        assert!(is_local_cleartext_host("127.0.0.1"));
        assert!(is_local_cleartext_host("10.0.0.5"));
        assert!(is_local_cleartext_host("172.16.0.1"));
        assert!(is_local_cleartext_host("192.168.1.1"));
        assert!(is_local_cleartext_host("169.254.1.1"));
        assert!(!is_local_cleartext_host("8.8.8.8"));
        assert!(!is_local_cleartext_host("172.32.0.1"));
    }

    #[test]
    fn ipv6() {
        assert!(is_local_cleartext_host("::1"));
        assert!(is_local_cleartext_host("[::1]"));
        assert!(is_local_cleartext_host("fc00::1"));
        assert!(is_local_cleartext_host("fe80::1"));
        assert!(!is_local_cleartext_host("2001:db8::1"));
    }
}
