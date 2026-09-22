// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Connect-only client for the Omniverse Hub cache-aside protocol.
//!
//! The hub (`usd-workstation-cache`) speaks a small length-prefixed
//! protobuf protocol over a persistent TCP connection, not gRPC. This crate
//! owns that wire format end to end: the vendored `.proto` schema, the frame
//! codec, and the client that performs the connect handshake and correlates
//! out-of-order responses with pending requests. Layers built on top of this
//! crate use its client API; they never see a proto type directly.
//!
//! It also owns key derivation ([`hub_key`]), including the scheme that
//! reproduces omni.client's keys so both clients share one cached copy of
//! an object.
//!
//! ```no_run
//! # use ovstorage_hub_client::{HubCacheClient, HubClientConfig, ReadOpen};
//! # async fn example() {
//! let client = HubCacheClient::new(HubClientConfig::default());
//! match client.open_for_read("some-key", "s3", "bin").await {
//!     Ok(ReadOpen::Opened(handle)) => {
//!         // Read `handle.path()`, then release the lease.
//!         let _ = handle.close().await;
//!     }
//!     Ok(ReadOpen::NotCached | ReadOpen::PendingWrite) => { /* fetch from the source */ }
//!     Err(err) if err.is_unavailable() => { /* behave as if the cache were absent */ }
//!     Err(_) => { /* the hub misbehaved; fall back to the source */ }
//! }
//! # }
//! ```
//!
//! # The `fake-hub` feature
//!
//! Enabling it exports `fake::FakeHub`: an in-process hub that speaks this
//! wire protocol on a loopback port and implements the cache-aside semantics
//! over a real directory, so a dependent crate can exercise its cache
//! behaviour (write-once keys, pending writes, the extension trap, lease
//! accounting) without a hub process. The feature adds nothing to a default
//! build.

mod client;
mod keys;
pub(crate) mod proto;
mod types;
pub(crate) mod wire;

#[cfg(any(test, feature = "fake-hub"))]
pub mod fake;

pub use client::{HubCacheClient, ReadHandle, WriteHandle};
pub use keys::{HubKey, KeyScheme, hub_key};
pub use types::{
    DEFAULT_HUB_ENDPOINT, HubClientConfig, HubError, HubResultCode, ReadOpen, WriteOpen,
};
