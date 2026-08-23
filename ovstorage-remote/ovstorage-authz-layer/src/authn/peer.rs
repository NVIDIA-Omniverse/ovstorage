// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OS peer-credential + dev-current-user authn for the built-in combined auth
//! layer.
//!
//! Ported from the broker's `authn.rs` peer/dev principal construction
//! (`GrpcAuthnMode::{DevCurrentUser, PeerCred}`), adapted from a live gRPC
//! connection to the already-gathered transport peer credentials the auth layer
//! receives in an [`AuthCredential`](ovstorage_authz_context::AuthCredential)'s
//! [`Transport::Uds`] / [`Transport::NamedPipe`]. The broker read `uid`/`gid`/
//! `pid` off tonic's `UdsConnectInfo` (Unix) and the client process id off
//! `NamedPipeConnectInfo` (Windows); here those values arrive decoded in the
//! transport variant, so this module only reproduces the *principal-construction*
//! half of the broker's peer authn.

use std::collections::HashMap;

use ovstorage::Result;
use ovstorage_authz_context::Transport;

use crate::ResolvedPrincipal;

/// Configuration for the peer/dev authn front-end.
#[derive(Debug, Default, Clone)]
pub(crate) struct PeerConfig {
    /// When set, a peer (`Uds`/`NamedPipe`) connection resolves to the host
    /// process's current OS user (the broker's `dev_current_user` mode) instead
    /// of the peer's transport credentials. A local-development convenience —
    /// never enable it for a shared listener.
    pub(crate) dev_current_user: bool,
}

/// Resolve a principal from transport peer credentials. Mirrors the broker's
/// `GrpcAuthnMode::{DevCurrentUser, PeerCred}` principal construction:
///
/// - `dev_current_user` → the host's current OS user (env `USERNAME`/`USER`,
///   else `"local"`), no attributes — the broker's `DevCurrentUser`.
/// - [`Transport::Uds`] → id `"uid:{uid}"`, attributes `{uid, gid, pid}` — the
///   broker's Unix `peer_cred`.
/// - [`Transport::NamedPipe`] → id `"sid:{sid}"`, attributes `{sid, pid}` — the
///   broker's Windows `peer_cred`, keyed on the SID the transport variant now
///   carries (the broker only had the client pid over tonic).
///
/// A missing-credential sentinel — a `Uds` `uid == u32::MAX` or a `NamedPipe`
/// with an empty SID — resolves to anonymous (it carries no identity, and a
/// `uid:*` glob must not match a credential-less caller).
pub(crate) fn resolve_peer(transport: &Transport, cfg: &PeerConfig) -> Result<ResolvedPrincipal> {
    if cfg.dev_current_user {
        return Ok(dev_current_user_principal());
    }
    match transport {
        // Missing-peer-credential sentinel (`uid == u32::MAX`, stamped by the host
        // when `SO_PEERCRED` yields nothing): carries no identity, so resolve to
        // anonymous — a broad `uid:*` policy glob must not match a credential-less
        // caller.
        Transport::Uds { uid, .. } if *uid == u32::MAX => Ok(ResolvedPrincipal::anonymous()),
        Transport::Uds { uid, gid, pid } => Ok(uds_principal(*uid, *gid, *pid)),
        Transport::NamedPipe { sid, pid } => named_pipe_principal(sid, *pid),
        // `resolve_peer` is only reached for peer transports; a `Tcp` bearer
        // resolves via the JWT front-end. A `Tcp` credential with no usable peer
        // identity falls through to anonymous.
        Transport::Tcp { .. } => Ok(ResolvedPrincipal::anonymous()),
    }
}

/// Unix `peer_cred` principal: `SO_PEERCRED` `uid` is the identity; `gid`/`pid`
/// are carried as attributes for future attribute-based policy.
fn uds_principal(uid: u32, gid: u32, pid: i32) -> ResolvedPrincipal {
    let mut attributes = HashMap::new();
    attributes.insert("uid".to_string(), uid.to_string());
    attributes.insert("gid".to_string(), gid.to_string());
    attributes.insert("pid".to_string(), pid.to_string());
    ResolvedPrincipal {
        id: format!("uid:{uid}"),
        display_name: None,
        attributes,
    }
}

/// Windows `peer_cred` principal: the named-pipe SID is the identity; the client
/// `pid` is carried as an attribute. An empty SID (SID gathering deferred)
/// resolves to anonymous.
fn named_pipe_principal(sid: &str, pid: u32) -> Result<ResolvedPrincipal> {
    if sid.trim().is_empty() {
        // Client-SID gathering is deferred, so the SID is empty today: resolve to
        // anonymous so an anonymous-configured named-pipe listener still functions.
        // A real SID resolves to `sid:{sid}` once gathering lands.
        return Ok(ResolvedPrincipal::anonymous());
    }
    let mut attributes = HashMap::new();
    attributes.insert("sid".to_string(), sid.to_string());
    attributes.insert("pid".to_string(), pid.to_string());
    Ok(ResolvedPrincipal {
        id: format!("sid:{sid}"),
        display_name: None,
        attributes,
    })
}

/// The `dev_current_user` principal: the host's current OS user, no attributes.
fn dev_current_user_principal() -> ResolvedPrincipal {
    ResolvedPrincipal {
        id: current_principal(),
        display_name: None,
        attributes: HashMap::new(),
    }
}

/// The host process's current OS user: env `USERNAME` (Windows), else `USER`
/// (Unix), else `"local"`. Ported verbatim from the broker's `current_principal`.
fn current_principal() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "local".into())
}
