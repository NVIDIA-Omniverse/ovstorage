// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Omniverse Storage Service backend for ovstorage.
//!
//! Loads as a cdylib via the ABI-v2 Layer surface declared by
//! `ovstorage-plugin`. A single `layer::OmniverseStorageLayer` owns its
//! connections, routes addresses to the Omniverse Storage Service's gRPC
//! services (stat / read / write / list / copy / write_redirect / …), and
//! surfaces connection management + interactive auth on the vtable slots.
//! Discovery + OIDC bearer auth mirror the C++ reference client.
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

pub mod auth;
pub mod backend;
pub mod config;
pub mod convert;
pub mod discovery;
pub mod driver;
pub mod factory;
pub mod layer;
pub mod multipart;
pub mod trace;
pub mod transport;

pub use backend::OmniverseStorageBackend;
pub use factory::OmniverseStorageFactory;
pub use layer::OmniverseStorageLayerFactory;

ovstorage_plugin::ovstorage_layer_plugin!(backend, OmniverseStorageLayerFactory::default);
