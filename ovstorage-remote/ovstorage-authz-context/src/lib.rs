// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `AuthCredential` and its versioned, flat wire codec.
//!
//! This crate is **pure** (no host/FFI deps). It holds the [`AuthCredential`]
//! type carried across the broker/REST authorization boundary and the
//! byte-exact [`AuthCredential::encode`] / [`AuthCredential::decode`] codec the
//! built-in auth layer and both hosts parse.
//!
//! The layout is fixed and treated as a cross-language ABI: flat, fixed-width,
//! little-endian, and length-prefixed, so it is parseable from C or Python with
//! no serialization library. The only decoder in this tree is
//! [`AuthCredential::decode`]; FFI marshaling and SDK accessors are the intended
//! second readers, and the fixed layout is what lets them be added without
//! renegotiating the format.
//!
//! # Wire layout (version 2)
//!
//! All integers are fixed-width **little-endian**. Byte-strings are `u32`
//! length-prefixed. Fields appear in this exact order:
//!
//! ```text
//! version:u8                       // AUTH_CREDENTIAL_WIRE_VERSION
//! bearer_len:u32                   // 0 = absent; N = N bytes follow
//! bearer[bearer_len]               // present only when bearer_len != 0
//! transport_tag:u8                 // 0 = Tcp, 1 = Uds, 2 = NamedPipe
//! <transport fields>               // per tag, below
//! forwarded_header_count:u32       // 0 = absent
//! repeated forwarded_header_count times:
//!   name_len:u32 | name[name_len] | value_len:u32 | value[value_len]
//! ```
//!
//! Transport `Tcp` (tag 0):
//! ```text
//! peer_addr_len:u32 | peer_addr[peer_addr_len]
//! cert_len:u32      | cert[cert_len]           // cert_len 0 = absent
//! ```
//!
//! Transport `Uds` (tag 1):
//! ```text
//! uid:u32 | gid:u32 | pid:i32
//! ```
//!
//! Transport `NamedPipe` (tag 2):
//! ```text
//! sid_len:u32 | sid[sid_len] | pid:u32
//! ```
//!
//! ## Version compatibility is reader-side only
//!
//! [`AuthCredential::decode`] accepts version 1 (no forwarded-header tail) and
//! version 2. [`AuthCredential::encode`] always emits
//! [`AUTH_CREDENTIAL_WIRE_VERSION`], including the `forwarded_header_count = 0`
//! tail when no forwarded metadata is present — it never emits a lower version,
//! even for a credential a lower version can express. Readers accept a range;
//! writers target one version, so every consumer must parse the current
//! version. Version 1 therefore has no producer in this tree: the decoder arm
//! exists so a version-1 buffer from any other source parses, and it is
//! unreachable from [`AuthCredential::encode`].
//!
//! `decode` maps an empty forwarded vector to `None`, so a
//! `Some(ForwardedHeaders { values: vec![] })` is not round-trip-stable: it
//! encodes as `forwarded_header_count = 0` and decodes back as `None`. This is
//! the same "0 means absent" rule the length prefixes follow, applied to the
//! repeated tail.
//!
//! ## Length-prefix `0` means absent
//!
//! Per the ABI, a `bearer_len`/`cert_len` of `0` encodes *absent*
//! (`None`). A `Some` holding an empty byte-string is therefore indistinguishable
//! on the wire from `None` and decodes back as `None`. Callers that need to
//! distinguish "present but empty" must not rely on this codec to preserve it.

use thiserror::Error;

/// Wire-format version emitted by [`AuthCredential::encode`]. The decoder also
/// accepts legacy version 1 credentials, which have no forwarded-header tail.
pub const AUTH_CREDENTIAL_WIRE_VERSION: u8 = 2;
const LEGACY_AUTH_CREDENTIAL_WIRE_VERSION: u8 = 1;

/// The stable id of the anonymous principal — no credential presented, or a
/// credential that carries no usable identity. The single home for this literal:
/// the auth layer's `ResolvedPrincipal::anonymous`, the peer resolver's
/// fallbacks, and the attribution wrapper's principal-absence default all
/// reference it so identity semantics stay in lockstep.
pub const ANONYMOUS_PRINCIPAL_ID: &str = "anonymous";

/// Extract the raw token from an HTTP/gRPC `Authorization` value. The host
/// strips only the case-insensitive `Bearer` scheme prefix and surrounding
/// whitespace; validation and decoding remain the auth layer's responsibility.
/// A different scheme is returned unchanged so the configured authenticator
/// rejects it consistently.
pub fn bearer_from_authorization_value(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    let mut parts = value.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or_default();
    let token = if scheme.eq_ignore_ascii_case("bearer") {
        parts.next().unwrap_or_default().trim()
    } else {
        value
    };
    (!token.is_empty()).then(|| token.as_bytes().to_vec())
}

const TAG_TCP: u8 = 0;
const TAG_UDS: u8 = 1;
const TAG_NAMED_PIPE: u8 = 2;

/// Transport-level identity of the peer that presented the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// TCP peer, optionally with a presented TLS client certificate (DER).
    Tcp {
        peer_addr: String,
        tls_client_cert: Option<Vec<u8>>,
    },
    /// Unix-domain-socket peer credentials (`SO_PEERCRED`).
    Uds { uid: u32, gid: u32, pid: i32 },
    /// Windows named-pipe peer (security identifier + process id).
    NamedPipe { sid: String, pid: u32 },
}

/// Raw textual gRPC metadata gathered by the broker. The built-in auth layer
/// reads configured identity fields only in `trusted_forwarded_headers` mode
/// and only after enforcing the connection peer's CIDR allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedHeaders {
    /// Raw ASCII metadata pairs, preserving duplicates so the auth layer can
    /// reject ambiguous identity inputs instead of choosing one value.
    pub values: Vec<(String, String)>,
}

/// A credential presented by a remote caller: an optional bearer token,
/// transport-level peer identity, and optional raw forwarded metadata.
///
/// `Debug` is **hand-written and redacted**: the bearer is a live secret (a raw
/// JWT), so `{:?}` prints only its presence and byte length, never the bytes.
/// Any type embedding an `AuthCredential` and deriving `Debug` (e.g. the broker's
/// `RequestContext`) inherits this redaction.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthCredential {
    pub bearer: Option<Vec<u8>>,
    pub transport: Transport,
    pub forwarded: Option<ForwardedHeaders>,
}

impl std::fmt::Debug for AuthCredential {
    /// Redacted: emits bearer presence + length only (never the token bytes) and
    /// the transport variant (its own `Debug`, which carries no bearer secret).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bearer = match &self.bearer {
            Some(bytes) => format!("Some(<redacted; {} bytes>)", bytes.len()),
            None => "None".to_string(),
        };
        f.debug_struct("AuthCredential")
            .field("bearer", &format_args!("{bearer}"))
            .field("transport", &self.transport)
            .field("forwarded_headers", &self.forwarded.is_some())
            .finish()
    }
}

/// Failure modes of [`AuthCredential::decode`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    /// The leading version byte is not [`AUTH_CREDENTIAL_WIRE_VERSION`].
    #[error("unsupported wire version")]
    UnsupportedVersion,
    /// The buffer ended before a required field was fully read.
    #[error("truncated buffer")]
    Truncated,
    /// The transport tag byte is not a known variant.
    #[error("bad transport tag")]
    BadTag,
    /// A length-prefixed string field was not valid UTF-8.
    #[error("invalid utf-8 in string field")]
    Utf8,
    /// The credential parsed, but the buffer carried extra bytes after it — a
    /// well-formed credential followed by junk is rejected rather than silently
    /// accepted.
    #[error("trailing data after credential")]
    TrailingData,
}

impl AuthCredential {
    /// A credential with no forwarded metadata — the common case for every
    /// listener that is not in `trusted_forwarded_headers` mode. Call sites use
    /// this instead of exhaustive struct literals so a future wire field does not
    /// churn every construction point.
    pub fn new(bearer: Option<Vec<u8>>, transport: Transport) -> Self {
        Self {
            bearer,
            transport,
            forwarded: None,
        }
    }

    /// Serialize to the versioned flat wire format (see module docs).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(AUTH_CREDENTIAL_WIRE_VERSION);
        put_opt_bytes(&mut out, self.bearer.as_deref());
        match &self.transport {
            Transport::Tcp {
                peer_addr,
                tls_client_cert,
            } => {
                out.push(TAG_TCP);
                put_bytes(&mut out, peer_addr.as_bytes());
                put_opt_bytes(&mut out, tls_client_cert.as_deref());
            }
            Transport::Uds { uid, gid, pid } => {
                out.push(TAG_UDS);
                out.extend_from_slice(&uid.to_le_bytes());
                out.extend_from_slice(&gid.to_le_bytes());
                out.extend_from_slice(&pid.to_le_bytes());
            }
            Transport::NamedPipe { sid, pid } => {
                out.push(TAG_NAMED_PIPE);
                put_bytes(&mut out, sid.as_bytes());
                out.extend_from_slice(&pid.to_le_bytes());
            }
        }
        match &self.forwarded {
            Some(forwarded) => {
                out.extend_from_slice(&(forwarded.values.len() as u32).to_le_bytes());
                for (key, value) in &forwarded.values {
                    put_bytes(&mut out, key.as_bytes());
                    put_bytes(&mut out, value.as_bytes());
                }
            }
            None => {
                out.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        out
    }

    /// Parse from the versioned flat wire format (see module docs).
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = Cursor::new(bytes);
        let version = cur.u8()?;
        if !matches!(
            version,
            LEGACY_AUTH_CREDENTIAL_WIRE_VERSION | AUTH_CREDENTIAL_WIRE_VERSION
        ) {
            return Err(DecodeError::UnsupportedVersion);
        }
        let bearer = cur.opt_bytes()?;
        let transport = match cur.u8()? {
            TAG_TCP => Transport::Tcp {
                peer_addr: cur.string()?,
                tls_client_cert: cur.opt_bytes()?,
            },
            TAG_UDS => Transport::Uds {
                uid: cur.u32()?,
                gid: cur.u32()?,
                pid: cur.i32()?,
            },
            TAG_NAMED_PIPE => Transport::NamedPipe {
                sid: cur.string()?,
                pid: cur.u32()?,
            },
            _ => return Err(DecodeError::BadTag),
        };
        let forwarded = if version == AUTH_CREDENTIAL_WIRE_VERSION {
            let value_count = cur.u32()? as usize;
            let mut values = Vec::with_capacity(value_count.min(16));
            for _ in 0..value_count {
                values.push((cur.string()?, cur.string()?));
            }
            (!values.is_empty()).then_some(ForwardedHeaders { values })
        } else {
            None
        };
        // The wire layout is fixed-width per variant, so a complete credential
        // consumes the whole buffer. Extra bytes mean a malformed/padded input;
        // reject rather than silently ignore the tail.
        if cur.pos != bytes.len() {
            return Err(DecodeError::TrailingData);
        }
        Ok(AuthCredential {
            bearer,
            transport,
            forwarded,
        })
    }
}

/// Append a `u32`-length-prefixed byte-string.
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Append an optional byte-string. `None` and `Some(&[])` both encode as a
/// length prefix of `0` (see the module docs on absence semantics).
fn put_opt_bytes(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
    put_bytes(out, bytes.unwrap_or(&[]));
}

/// Bounds-checked forward reader over a wire buffer.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let b: [u8; 4] = self.take(4)?.try_into().expect("take(4) yields 4 bytes");
        Ok(u32::from_le_bytes(b))
    }

    fn i32(&mut self) -> Result<i32, DecodeError> {
        let b: [u8; 4] = self.take(4)?.try_into().expect("take(4) yields 4 bytes");
        Ok(i32::from_le_bytes(b))
    }

    /// Read a `u32`-length-prefixed byte-string.
    fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// Read a length-prefixed byte-string, mapping length `0` to `None`.
    fn opt_bytes(&mut self) -> Result<Option<Vec<u8>>, DecodeError> {
        let b = self.bytes()?;
        Ok(if b.is_empty() { None } else { Some(b.to_vec()) })
    }

    /// Read a length-prefixed UTF-8 string.
    fn string(&mut self) -> Result<String, DecodeError> {
        let b = self.bytes()?;
        std::str::from_utf8(b)
            .map(str::to_owned)
            .map_err(|_| DecodeError::Utf8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_uds_no_bearer() {
        let c = AuthCredential {
            bearer: None,
            forwarded: None,
            transport: Transport::Uds {
                uid: 1000,
                gid: 1000,
                pid: 42,
            },
        };
        assert_eq!(AuthCredential::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn roundtrip_tcp_bearer_and_cert() {
        let c = AuthCredential {
            bearer: Some(b"tok".to_vec()),
            forwarded: None,
            transport: Transport::Tcp {
                peer_addr: "1.2.3.4:443".into(),
                tls_client_cert: Some(vec![0xde, 0xad]),
            },
        };
        assert_eq!(AuthCredential::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn roundtrip_tcp_no_bearer_no_cert() {
        let c = AuthCredential {
            bearer: None,
            forwarded: None,
            transport: Transport::Tcp {
                peer_addr: "[::1]:8443".into(),
                tls_client_cert: None,
            },
        };
        assert_eq!(AuthCredential::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn roundtrip_forwarded_headers() {
        let c = AuthCredential {
            bearer: None,
            transport: Transport::Tcp {
                peer_addr: "10.0.0.4:8443".into(),
                tls_client_cert: None,
            },
            forwarded: Some(ForwardedHeaders {
                values: vec![
                    ("x-authenticated-user".into(), "alice".into()),
                    ("x-authenticated-role".into(), "artist".into()),
                ],
            }),
        };
        assert_eq!(AuthCredential::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn roundtrip_uds_bearer() {
        let c = AuthCredential {
            bearer: Some(vec![0x00, 0x01, 0xff]),
            forwarded: None,
            transport: Transport::Uds {
                uid: 0,
                gid: 0,
                pid: -1,
            },
        };
        assert_eq!(AuthCredential::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn roundtrip_named_pipe() {
        let c = AuthCredential {
            bearer: Some(b"bearer".to_vec()),
            forwarded: None,
            transport: Transport::NamedPipe {
                sid: "S-1-5-21-1004336348".into(),
                pid: 4321,
            },
        };
        assert_eq!(AuthCredential::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn decode_rejects_wrong_version() {
        assert_eq!(
            AuthCredential::decode(&[99, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(DecodeError::UnsupportedVersion)
        );
    }

    #[test]
    fn decode_accepts_legacy_v1_without_forwarded_headers() {
        let legacy = [
            1, // version
            0, 0, 0, 0, // bearer absent
            TAG_UDS, 7, 0, 0, 0, // uid
            8, 0, 0, 0, // gid
            9, 0, 0, 0, // pid
        ];
        assert_eq!(
            AuthCredential::decode(&legacy).unwrap(),
            AuthCredential {
                bearer: None,
                forwarded: None,
                transport: Transport::Uds {
                    uid: 7,
                    gid: 8,
                    pid: 9,
                },
            }
        );
    }

    #[test]
    fn decode_rejects_truncated() {
        let good = AuthCredential {
            bearer: None,
            forwarded: None,
            transport: Transport::Uds {
                uid: 1,
                gid: 2,
                pid: 3,
            },
        }
        .encode();
        assert_eq!(
            AuthCredential::decode(&good[..good.len() - 2]),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn decode_rejects_empty() {
        assert_eq!(AuthCredential::decode(&[]), Err(DecodeError::Truncated));
    }

    #[test]
    fn decode_rejects_bad_tag() {
        // version 1, bearer absent, transport tag 7 (unknown).
        assert_eq!(
            AuthCredential::decode(&[1, 0, 0, 0, 0, 7]),
            Err(DecodeError::BadTag)
        );
    }

    #[test]
    fn decode_rejects_trailing_data() {
        // A valid encoding with junk appended must not decode: the cursor did not
        // consume the whole buffer.
        let mut bytes = AuthCredential {
            bearer: Some(b"tok".to_vec()),
            forwarded: None,
            transport: Transport::Uds {
                uid: 1,
                gid: 2,
                pid: 3,
            },
        }
        .encode();
        bytes.extend_from_slice(&[0xde, 0xad]);
        assert_eq!(
            AuthCredential::decode(&bytes),
            Err(DecodeError::TrailingData)
        );
    }

    #[test]
    fn decode_rejects_bad_utf8() {
        // version 1, bearer absent, tag Tcp, peer_addr_len 1, byte 0xff (invalid utf8).
        assert_eq!(
            AuthCredential::decode(&[1, 0, 0, 0, 0, TAG_TCP, 1, 0, 0, 0, 0xff]),
            Err(DecodeError::Utf8)
        );
    }

    // -----------------------------------------------------------------------
    // Golden byte-vector tests
    //
    // The wire layout is a fixed cross-language ABI, so round-trip coverage
    // alone would not catch a layout change that is self-consistent in Rust:
    // encode and decode move together and the test still passes. These pin the
    // EXACT bytes for one credential of each transport, including a negative pid
    // and absent/empty optionals, so the format stays parseable by a reader that
    // does not share this code. The
    // vectors are exact-length (no trailing bytes) so a future strict
    // trailing-data check still decodes them cleanly.
    // -----------------------------------------------------------------------

    #[test]
    fn golden_tcp_bearer_and_cert() {
        let credential = AuthCredential {
            bearer: Some(b"AB".to_vec()),
            forwarded: None,
            transport: Transport::Tcp {
                peer_addr: "h:1".into(),
                tls_client_cert: Some(vec![0xDE, 0xAD]),
            },
        };
        let golden: &[u8] = &[
            2, // version
            2, 0, 0, 0, b'A', b'B',    // bearer_len=2 + "AB"
            TAG_TCP, // transport tag
            3, 0, 0, 0, b'h', b':', b'1', // peer_addr_len=3 + "h:1"
            2, 0, 0, 0, 0xDE, 0xAD, // cert_len=2 + cert bytes
            0, 0, 0, 0, // forwarded header count
        ];
        assert_eq!(credential.encode(), golden, "Tcp encode must be byte-exact");
        assert_eq!(AuthCredential::decode(golden).unwrap(), credential);
    }

    #[test]
    fn golden_uds_negative_pid_no_bearer() {
        let credential = AuthCredential {
            bearer: None,
            forwarded: None,
            transport: Transport::Uds {
                uid: 7,
                gid: 8,
                pid: -2,
            },
        };
        let golden: &[u8] = &[
            2, // version
            0, 0, 0, 0,       // bearer_len=0 (absent)
            TAG_UDS, // transport tag
            7, 0, 0, 0, // uid
            8, 0, 0, 0, // gid
            0xFE, 0xFF, 0xFF, 0xFF, // pid = -2 as little-endian i32
            0, 0, 0, 0, // forwarded header count
        ];
        assert_eq!(credential.encode(), golden, "Uds encode must be byte-exact");
        assert_eq!(AuthCredential::decode(golden).unwrap(), credential);
    }

    #[test]
    fn golden_named_pipe_absent_optionals() {
        let credential = AuthCredential {
            bearer: None,
            forwarded: None,
            transport: Transport::NamedPipe {
                sid: "S-1".into(),
                pid: 5,
            },
        };
        let golden: &[u8] = &[
            2, // version
            0,
            0,
            0,
            0,              // bearer_len=0 (absent)
            TAG_NAMED_PIPE, // transport tag
            3,
            0,
            0,
            0,
            b'S',
            b'-',
            b'1', // sid_len=3 + "S-1"
            5,
            0,
            0,
            0, // pid u32
            0,
            0,
            0,
            0, // forwarded header count
        ];
        assert_eq!(
            credential.encode(),
            golden,
            "NamedPipe encode must be byte-exact"
        );
        assert_eq!(AuthCredential::decode(golden).unwrap(), credential);
    }

    #[test]
    fn golden_tcp_populated_forwarded_headers() {
        // The forwarded tail's per-entry layout (name_len | name | value_len |
        // value, little-endian u32 lengths) is pinned here. A round-trip cannot
        // catch a self-consistent layout change — swapped name/value order, or
        // big-endian lengths — because encode and decode would move together.
        // Only a fixed byte vector holds the ABI still for a reader outside this
        // crate.
        let credential = AuthCredential {
            bearer: None,
            transport: Transport::Tcp {
                peer_addr: "h:1".into(),
                tls_client_cert: None,
            },
            forwarded: Some(ForwardedHeaders {
                values: vec![("x-u".into(), "alice".into()), ("x-t".into(), "art".into())],
            }),
        };
        let golden: &[u8] = &[
            2, // version
            0, 0, 0, 0,       // bearer_len=0 (absent)
            TAG_TCP, // transport tag
            3, 0, 0, 0, b'h', b':', b'1', // peer_addr_len=3 + "h:1"
            0, 0, 0, 0, // cert_len=0 (absent)
            2, 0, 0, 0, // forwarded_header_count=2
            3, 0, 0, 0, b'x', b'-', b'u', // name_len=3 + "x-u"
            5, 0, 0, 0, b'a', b'l', b'i', b'c', b'e', // value_len=5 + "alice"
            3, 0, 0, 0, b'x', b'-', b't', // name_len=3 + "x-t"
            3, 0, 0, 0, b'a', b'r', b't', // value_len=3 + "art"
        ];
        assert_eq!(
            credential.encode(),
            golden,
            "populated forwarded-header encode must be byte-exact"
        );
        assert_eq!(AuthCredential::decode(golden).unwrap(), credential);
    }

    #[test]
    fn empty_bearer_encodes_identically_to_absent_and_decodes_to_none() {
        let with_empty = AuthCredential {
            bearer: Some(vec![]),
            forwarded: None,
            transport: Transport::Uds {
                uid: 1,
                gid: 2,
                pid: 3,
            },
        };
        let absent = AuthCredential {
            bearer: None,
            forwarded: None,
            transport: Transport::Uds {
                uid: 1,
                gid: 2,
                pid: 3,
            },
        };
        // Documented absence semantics: `Some(empty)` and `None` are
        // indistinguishable on the wire and both decode back to `None`.
        assert_eq!(with_empty.encode(), absent.encode());
        assert_eq!(
            AuthCredential::decode(&with_empty.encode()).unwrap().bearer,
            None
        );
        assert_eq!(
            AuthCredential::decode(&absent.encode()).unwrap().bearer,
            None
        );
    }

    #[test]
    fn encode_always_emits_the_current_version_with_a_forwarded_tail() {
        // Version compatibility is reader-side only: a credential an older reader
        // could have parsed is still written at the current version, with the
        // `forwarded_header_count = 0` tail. Pinned so a "write v1 when the
        // credential fits v1" optimization cannot land silently.
        for credential in [
            AuthCredential::new(
                None,
                Transport::Uds {
                    uid: 1,
                    gid: 2,
                    pid: 3,
                },
            ),
            AuthCredential::new(
                Some(b"tok".to_vec()),
                Transport::Tcp {
                    peer_addr: "h:1".into(),
                    tls_client_cert: None,
                },
            ),
            AuthCredential::new(
                None,
                Transport::NamedPipe {
                    sid: "S-1".into(),
                    pid: 5,
                },
            ),
        ] {
            let bytes = credential.encode();
            assert_eq!(bytes[0], AUTH_CREDENTIAL_WIRE_VERSION);
            assert_eq!(
                &bytes[bytes.len() - 4..],
                &0u32.to_le_bytes(),
                "a forwarded-free credential still carries the count=0 tail"
            );
        }
    }

    #[test]
    fn new_matches_an_exhaustive_forwarded_free_literal() {
        let transport = Transport::Uds {
            uid: 1,
            gid: 2,
            pid: 3,
        };
        assert_eq!(
            AuthCredential::new(Some(b"tok".to_vec()), transport.clone()),
            AuthCredential {
                bearer: Some(b"tok".to_vec()),
                transport,
                forwarded: None,
            }
        );
    }

    #[test]
    fn bearer_parser_is_shared_and_case_insensitive() {
        assert_eq!(
            bearer_from_authorization_value("  BeArEr token-value  "),
            Some(b"token-value".to_vec())
        );
        assert_eq!(
            bearer_from_authorization_value("Basic opaque"),
            Some(b"Basic opaque".to_vec())
        );
        assert_eq!(bearer_from_authorization_value("Bearer   "), None);
    }
}
