// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
//! # Credential lock order
//!
//! Every lock a credential operation may hold, in the order they must be
//! acquired. A path may take a suffix or a prefix of this order, never a
//! permutation.
//!
//! 1. **Publication lock.** Held across a durable write and across an
//!    identity-changing install, so a keyring write and an install cannot
//!    interleave. It exists as a lock of its own — rather than reusing the
//!    identity fence — because an OS secret-store round trip (DBus, Keychain, the
//!    Windows credential manager) can take seconds, and the identity fence is
//!    on the read path. It is acquired FIRST for the same reason: a lock taken
//!    ahead of it is held for that entire round trip, and the credential cells
//!    are read by the transport interceptor on every RPC.
//! 2. **Credential state locks** (access token → refresh token → expiry →
//!    cached client credentials). Held by an install so the bundle it writes is
//!    never observed half-applied. They are synchronous locks, not async ones,
//!    precisely so an install can hold the publication lock — a
//!    `std::sync::MutexGuard` — while acquiring them.
//! 3. **Binding mutex / identity fence.** Held across the identity generation
//!    bump and the binding write, so the two are one step to any observer. Work
//!    under it must be bounded and non-blocking: no I/O, no further locks.
//!
//! **Every** install site takes the publication lock before any credential
//! guard — the `client_credentials` update included, not just the token
//! installs. These locks are synchronous and non-reentrant, so a single site
//! that took a credential guard first would close the graph into a cycle and
//! permanently deadlock the connection's credential path (and, with it, durable
//! persistence, which takes the publication lock on every write). The compiler
//! does not catch this: holding a `parking_lot` guard across a
//! `std::sync::Mutex::lock()` is legal Rust. Enumerate the sites by reading.
//!
//! None of these is held across an `.await`. The durable writes they guard are
//! synchronous host callbacks, which is what makes that possible.

mod address;
mod auth;
mod backend;
mod config;
mod convert;
mod driver;
mod handshake;
mod layer;
mod ops;
mod trace;

#[cfg(any(test, feature = "_test_support"))]
#[doc(hidden)]
pub mod test_support;

pub use backend::NucleusBackend;
pub use layer::NucleusLayerFactory;

/// Build a bare `NucleusBackend` (no session, no auth) from a raw config map.
/// FOR TESTS ONLY (gated behind the `_test_support` feature, activated by
/// this crate's self dev-dependency): `tests/precondition.rs` pins that every
/// refusal-on-precondition check fires synchronously at the SPI entry point,
/// before any wire or auth interaction.
#[cfg(any(test, feature = "_test_support"))]
pub fn __test_only_backend(
    config: &std::collections::HashMap<String, ovstorage_plugin::ConfigValue>,
) -> ovstorage_plugin::Result<NucleusBackend> {
    let request = ovstorage_plugin::ConnectionRequest {
        backend_kind: crate::address::NUCLEUS_KIND.into(),
        config: config.clone(),
        credentials: ovstorage_plugin::SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    let parsed = crate::config::NucleusConfig::from_request(&request)?;
    let shared = crate::backend::session::NucleusShared::new(
        parsed,
        ovstorage_plugin::SecretBundle::default(),
    );
    Ok(NucleusBackend::from_shared(shared))
}

/// Build a bare `NucleusBackend` wired to an in-process
/// [`test_support::MockTransport`] — mock ops installed on the shared
/// session cell, no auth, no network. FOR TESTS ONLY: external
/// integration tests (the conformance suite in particular) enqueue canned
/// omni1 frames on the returned transport and drive real data-op
/// round-trips through the backend; the in-src `#[cfg(test)]`
/// `factory_with_mock` seam is this construction path's origin.
#[cfg(any(test, feature = "_test_support"))]
#[doc(hidden)]
pub fn __test_only_backend_with_mock(
    config: &std::collections::HashMap<String, ovstorage_plugin::ConfigValue>,
) -> ovstorage_plugin::Result<(NucleusBackend, std::sync::Arc<test_support::MockTransport>)> {
    use std::sync::Arc;
    let request = ovstorage_plugin::ConnectionRequest {
        backend_kind: crate::address::NUCLEUS_KIND.into(),
        config: config.clone(),
        credentials: ovstorage_plugin::SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    let parsed = crate::config::NucleusConfig::from_request(&request)?;
    let shared = crate::backend::session::NucleusShared::new(
        parsed,
        ovstorage_plugin::SecretBundle::default(),
    );
    let mock = Arc::new(test_support::MockTransport::new());
    let ops: Arc<dyn crate::ops::NucleusOps> = Arc::new(crate::ops::RuntimeOps::new(
        test_support::MockTransportHandle::new(Arc::clone(&mock)),
    ));
    *shared.ops.lock().unwrap() = Some(ops);
    Ok((NucleusBackend::from_shared(shared), mock))
}

ovstorage_plugin::ovstorage_layer_plugin!(backend, NucleusLayerFactory::default);
