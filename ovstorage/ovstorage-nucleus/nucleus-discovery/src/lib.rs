// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

pub mod types;

pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

pub type DiscoveryClient = nucleus_transport::SowsTransport;

pub use nucleus_transport::{self, Transport};

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use types::{DiscoverInterfaceQuery, ServiceInterface, SupportedTransport, TransportSettings};

pub fn discovery_url(host: &str) -> String {
    let scheme = match parse_authority(host) {
        Some(auth) if is_local_cleartext(&auth) => "ws",
        Some(_) => "wss",
        None => "wss",
    };
    let rendered = parse_authority(host)
        .map(|a| a.render())
        .unwrap_or_else(|| host.to_string());
    let url = format!("{scheme}://{rendered}/omni/discovery");
    tracing::debug!(host, %url, "nucleus discovery URL resolved");
    url
}

#[derive(Debug, Clone)]
struct Authority {
    host: HostPart,
    port: Option<u16>,
}

#[derive(Debug, Clone)]
enum HostPart {
    Name(String),
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl Authority {
    fn render(&self) -> String {
        match (&self.host, self.port) {
            (HostPart::Name(n), Some(p)) => format!("{n}:{p}"),
            (HostPart::Name(n), None) => n.clone(),
            (HostPart::V4(a), Some(p)) => format!("{a}:{p}"),
            (HostPart::V4(a), None) => a.to_string(),
            (HostPart::V6(a), Some(p)) => format!("[{a}]:{p}"),
            (HostPart::V6(a), None) => format!("[{a}]"),
        }
    }
}

fn parse_authority(input: &str) -> Option<Authority> {
    if input.is_empty() {
        return None;
    }
    if input.starts_with('[') {
        let close = input.find(']')?;
        let inside = &input[1..close];
        let v6: Ipv6Addr = inside.parse().ok()?;
        let rest = &input[close + 1..];
        let port = if rest.is_empty() {
            None
        } else if let Some(p) = rest.strip_prefix(':') {
            Some(parse_port(p)?)
        } else {
            return None;
        };
        return Some(Authority {
            host: HostPart::V6(v6),
            port,
        });
    }

    if let Ok(v6) = input.parse::<Ipv6Addr>() {
        return Some(Authority {
            host: HostPart::V6(v6),
            port: None,
        });
    }

    if let Some(idx) = input.rfind(':') {
        let head = &input[..idx];
        let tail = &input[idx + 1..];
        if !head.contains(':') {
            let port = parse_port(tail)?;
            if let Ok(v4) = head.parse::<Ipv4Addr>() {
                return Some(Authority {
                    host: HostPart::V4(v4),
                    port: Some(port),
                });
            }
            if is_valid_dns_name(head) {
                return Some(Authority {
                    host: HostPart::Name(head.to_string()),
                    port: Some(port),
                });
            }
            return None;
        }
        return None;
    }

    if let Ok(v4) = input.parse::<Ipv4Addr>() {
        return Some(Authority {
            host: HostPart::V4(v4),
            port: None,
        });
    }
    if is_valid_dns_name(input) {
        return Some(Authority {
            host: HostPart::Name(input.to_string()),
            port: None,
        });
    }
    None
}

fn parse_port(s: &str) -> Option<u16> {
    let n: u32 = s.parse().ok()?;
    if (1..=65535).contains(&n) {
        Some(n as u16)
    } else {
        None
    }
}

fn is_valid_dns_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' || ch == '_' {
            continue;
        }
        return false;
    }
    !s.starts_with('.') && !s.ends_with('.')
}

fn is_local_cleartext(auth: &Authority) -> bool {
    match &auth.host {
        HostPart::Name(n) => n == "localhost" || n.ends_with(".local"),
        HostPart::V4(a) => {
            a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
        }
        HostPart::V6(a) => {
            a.is_loopback()
                || a.is_unspecified()
                || is_ipv6_unique_local(a)
                || is_ipv6_unicast_link_local(a)
        }
    }
}

fn is_ipv6_unique_local(a: &Ipv6Addr) -> bool {
    (a.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_unicast_link_local(a: &Ipv6Addr) -> bool {
    (a.segments()[0] & 0xffc0) == 0xfe80
}

pub fn supported_transports<T: Transport>() -> Vec<SupportedTransport> {
    T::descriptors()
        .into_iter()
        .map(|d| SupportedTransport {
            name: d.name.to_string(),
            meta: Some(
                d.meta
                    .iter()
                    .map(|&(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
        })
        .collect()
}

pub fn make_query(
    origin: &str,
    name: &str,
    capabilities: Option<HashMap<String, u64>>,
    deployment: Option<&str>,
    supported_transport: &[SupportedTransport],
) -> DiscoverInterfaceQuery {
    let meta = deployment.map(|d| {
        let mut m = HashMap::new();
        m.insert("deployment".to_string(), d.to_string());
        m
    });

    DiscoverInterfaceQuery {
        service_interface: ServiceInterface {
            origin: origin.to_string(),
            name: name.to_string(),
            capabilities,
        },
        supported_transport: Some(supported_transport.to_vec()),
        meta,
    }
}

fn validate_host_string(host: &str) -> Option<HostPart> {
    if host.is_empty() {
        return None;
    }
    for ch in host.chars() {
        if ch.is_control() || ch.is_whitespace() {
            return None;
        }
        if matches!(ch, '@' | '/' | '?' | '#' | '\\') {
            return None;
        }
    }
    if let Some(stripped) = host.strip_prefix('[') {
        let inner = stripped.strip_suffix(']')?;
        let v6: Ipv6Addr = inner.parse().ok()?;
        return Some(HostPart::V6(v6));
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return Some(HostPart::V6(v6));
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Some(HostPart::V4(v4));
    }
    if is_valid_dns_name(host) {
        return Some(HostPart::Name(host.to_string()));
    }
    None
}

fn validate_path(path: &str) -> Option<&str> {
    if path.is_empty() {
        return Some(path);
    }
    if !path.starts_with('/') {
        return None;
    }
    for ch in path.chars() {
        if ch.is_control() {
            return None;
        }
    }
    Some(path)
}

fn url_from_transport_inner(transport: &TransportSettings) -> Option<String> {
    let params: serde_json::Value = serde_json::from_str(&transport.params).ok()?;

    // ConnLib (`{"url": "wss://host:port/path"}`) hands us a fully-formed URL;
    // SOWS (`{"host", "port", "path"}`) splits the parts and we assemble them.
    if let Some(url) = params.get("url").and_then(|v| v.as_str()) {
        return Some(url.to_string());
    }

    let host_str = params.get("host")?.as_str()?;
    let port_raw = params.get("port")?.as_u64()?;
    if !(1..=65535).contains(&port_raw) {
        return None;
    }
    let port = port_raw as u16;
    let path_str = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let path = validate_path(path_str)?;

    let host = validate_host_string(host_str)?;
    let host_rendered = match host {
        HostPart::Name(n) => n,
        HostPart::V4(a) => a.to_string(),
        HostPart::V6(a) => format!("[{a}]"),
    };

    let ssl = transport
        .meta
        .get("ssl")
        .map(|v| v == "true")
        .unwrap_or(false);
    let scheme = if ssl { "wss" } else { "ws" };
    Some(format!("{scheme}://{host_rendered}:{port}{path}"))
}

pub fn url_from_transport(transport: &TransportSettings) -> Option<String> {
    match url_from_transport_inner(transport) {
        Some(url) => {
            tracing::debug!(transport_name = %transport.name, %url, "nucleus discovery: transport URL resolved");
            Some(url)
        }
        None => {
            tracing::warn!(
                transport_name = %transport.name,
                params = %transport.params,
                "nucleus discovery: transport params invalid or missing host/port"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_url_public_host_uses_wss() {
        let url = discovery_url("example.com");
        assert!(url.starts_with("wss://"));
        assert!(url.contains("/omni/discovery"));
    }

    #[test]
    fn discovery_url_localhost_uses_ws() {
        let url = discovery_url("localhost");
        assert_eq!(url, "ws://localhost/omni/discovery");
    }

    #[test]
    fn discovery_url_private_ipv4_uses_ws() {
        let url = discovery_url("192.168.1.1");
        assert_eq!(url, "ws://192.168.1.1/omni/discovery");
    }

    #[test]
    fn discovery_url_dot_local_uses_ws() {
        let url = discovery_url("host.local");
        assert_eq!(url, "ws://host.local/omni/discovery");
    }

    #[test]
    fn discovery_url_localhost_with_port_uses_ws() {
        let url = discovery_url("localhost:3333");
        assert_eq!(url, "ws://localhost:3333/omni/discovery");
    }

    #[test]
    fn discovery_url_private_ipv4_with_port_uses_ws() {
        let url = discovery_url("10.0.0.1:3333");
        assert_eq!(url, "ws://10.0.0.1:3333/omni/discovery");
    }

    #[test]
    fn discovery_url_public_host_with_port() {
        let url = discovery_url("nucleus.example.com:443");
        assert_eq!(url, "wss://nucleus.example.com:443/omni/discovery");
    }

    #[test]
    fn discovery_url_public_ipv4_uses_wss() {
        let url = discovery_url("203.0.113.10");
        assert_eq!(url, "wss://203.0.113.10/omni/discovery");
    }

    #[test]
    fn discovery_url_public_ipv4_with_port_uses_wss() {
        let url = discovery_url("198.51.100.20:3333");
        assert_eq!(url, "wss://198.51.100.20:3333/omni/discovery");
    }

    #[test]
    fn discovery_url_loopback_ipv4_uses_ws() {
        let url = discovery_url("127.0.0.1");
        assert_eq!(url, "ws://127.0.0.1/omni/discovery");
    }

    #[test]
    fn discovery_url_link_local_ipv4_uses_ws() {
        let url = discovery_url("169.254.1.1");
        assert_eq!(url, "ws://169.254.1.1/omni/discovery");
    }

    #[test]
    fn discovery_url_bare_ipv6_loopback_uses_ws() {
        let url = discovery_url("::1");
        assert_eq!(url, "ws://[::1]/omni/discovery");
    }

    #[test]
    fn discovery_url_bracketed_ipv6_loopback_uses_ws() {
        let url = discovery_url("[::1]");
        assert_eq!(url, "ws://[::1]/omni/discovery");
    }

    #[test]
    fn discovery_url_bracketed_ipv6_loopback_with_port_uses_ws() {
        let url = discovery_url("[::1]:3333");
        assert_eq!(url, "ws://[::1]:3333/omni/discovery");
    }

    #[test]
    fn discovery_url_public_ipv6_uses_wss() {
        let url = discovery_url("[2001:db8::1]:443");
        assert_eq!(url, "wss://[2001:db8::1]:443/omni/discovery");
    }

    #[test]
    fn discovery_url_unique_local_ipv6_uses_ws() {
        let url = discovery_url("[fd00::1]");
        assert_eq!(url, "ws://[fd00::1]/omni/discovery");
    }

    #[test]
    fn discovery_url_link_local_ipv6_uses_ws() {
        let url = discovery_url("[fe80::1]");
        assert_eq!(url, "ws://[fe80::1]/omni/discovery");
    }

    #[test]
    fn make_query_basic() {
        let transports = vec![SupportedTransport {
            name: "connlib".to_string(),
            meta: None,
        }];
        let query = make_query("origin.idl", "Connection", None, None, &transports);
        assert_eq!(query.service_interface.origin, "origin.idl");
        assert_eq!(query.service_interface.name, "Connection");
        assert!(query.service_interface.capabilities.is_none());
        assert!(query.meta.is_none());
        assert_eq!(query.supported_transport.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn make_query_with_capabilities() {
        let mut caps = HashMap::new();
        caps.insert("auth".to_string(), 2);
        caps.insert("list2".to_string(), 1);

        let transports = vec![SupportedTransport {
            name: "sows".to_string(),
            meta: None,
        }];
        let query = make_query("origin.idl", "Svc", Some(caps), None, &transports);
        let returned_caps = query.service_interface.capabilities.unwrap();
        assert_eq!(returned_caps.get("auth"), Some(&2));
        assert_eq!(returned_caps.get("list2"), Some(&1));
    }

    #[test]
    fn make_query_with_deployment() {
        let transports = vec![SupportedTransport {
            name: "sows".to_string(),
            meta: None,
        }];
        let query = make_query("origin", "Svc", None, Some("external"), &transports);
        let meta = query.meta.unwrap();
        assert_eq!(meta.get("deployment").unwrap(), "external");
    }

    #[test]
    fn make_query_empty_supported_transport_is_some_empty() {
        let query = make_query("origin", "Svc", None, None, &[]);
        assert_eq!(query.supported_transport.as_ref().unwrap().len(), 0);
    }

    #[test]
    fn make_query_non_empty_supported_transport_is_some() {
        let transports = vec![SupportedTransport {
            name: "sows".to_string(),
            meta: None,
        }];
        let query = make_query("origin", "Svc", None, None, &transports);
        assert_eq!(query.supported_transport.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn url_from_transport_valid() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"example.com","port":3100,"path":"/omni/auth"}"#.to_string(),
            meta: {
                let mut m = HashMap::new();
                m.insert("ssl".to_string(), "true".to_string());
                m
            },
        };
        let url = url_from_transport(&transport).unwrap();
        assert_eq!(url, "wss://example.com:3100/omni/auth");
    }

    #[test]
    fn url_from_transport_no_ssl() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"localhost","port":3100,"path":"/auth"}"#.to_string(),
            meta: HashMap::new(),
        };
        let url = url_from_transport(&transport).unwrap();
        assert_eq!(url, "ws://localhost:3100/auth");
    }

    #[test]
    fn url_from_transport_no_path_field() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"localhost","port":3100}"#.to_string(),
            meta: HashMap::new(),
        };
        let url = url_from_transport(&transport).unwrap();
        assert_eq!(url, "ws://localhost:3100");
    }

    #[test]
    fn url_from_transport_missing_host() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"port":3100}"#.to_string(),
            meta: HashMap::new(),
        };
        assert!(url_from_transport(&transport).is_none());
    }

    #[test]
    fn url_from_transport_missing_port() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"localhost"}"#.to_string(),
            meta: HashMap::new(),
        };
        assert!(url_from_transport(&transport).is_none());
    }

    #[test]
    fn url_from_transport_invalid_json() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: "not json".to_string(),
            meta: HashMap::new(),
        };
        assert!(url_from_transport(&transport).is_none());
    }

    #[test]
    fn url_from_transport_userinfo_injection_rejected() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"expected.example@attacker.example","port":3100,"path":"/x"}"#
                .to_string(),
            meta: HashMap::new(),
        };
        assert!(url_from_transport(&transport).is_none());
    }

    #[test]
    fn url_from_transport_slash_in_host_rejected() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"example.com/evil","port":3100,"path":"/x"}"#.to_string(),
            meta: HashMap::new(),
        };
        assert!(url_from_transport(&transport).is_none());
    }

    #[test]
    fn url_from_transport_port_zero_rejected() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"localhost","port":0,"path":"/x"}"#.to_string(),
            meta: HashMap::new(),
        };
        assert!(url_from_transport(&transport).is_none());
    }

    #[test]
    fn url_from_transport_port_too_large_rejected() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"localhost","port":65536,"path":"/x"}"#.to_string(),
            meta: HashMap::new(),
        };
        assert!(url_from_transport(&transport).is_none());
    }

    #[test]
    fn url_from_transport_path_without_leading_slash_rejected() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"localhost","port":3100,"path":"omni/auth"}"#.to_string(),
            meta: HashMap::new(),
        };
        assert!(url_from_transport(&transport).is_none());
    }

    #[test]
    fn url_from_transport_crlf_in_path_rejected() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"localhost","port":3100,"path":"/x\r\nHost: evil"}"#.to_string(),
            meta: HashMap::new(),
        };
        assert!(url_from_transport(&transport).is_none());
    }

    #[test]
    fn url_from_transport_bare_ipv6_in_host_bracketed() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"::1","port":3100,"path":"/x"}"#.to_string(),
            meta: HashMap::new(),
        };
        let url = url_from_transport(&transport).unwrap();
        assert_eq!(url, "ws://[::1]:3100/x");
    }

    #[test]
    fn url_from_transport_bracketed_ipv6_in_host_preserved() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"[2001:db8::1]","port":443,"path":"/x"}"#.to_string(),
            meta: {
                let mut m = HashMap::new();
                m.insert("ssl".to_string(), "true".to_string());
                m
            },
        };
        let url = url_from_transport(&transport).unwrap();
        assert_eq!(url, "wss://[2001:db8::1]:443/x");
    }

    #[test]
    fn url_from_transport_garbage_ssl_treated_as_false() {
        let transport = TransportSettings {
            name: "sows".to_string(),
            params: r#"{"host":"example.com","port":3100,"path":"/x"}"#.to_string(),
            meta: {
                let mut m = HashMap::new();
                m.insert("ssl".to_string(), "yes".to_string());
                m
            },
        };
        let url = url_from_transport(&transport).unwrap();
        assert_eq!(url, "ws://example.com:3100/x");
    }
}
