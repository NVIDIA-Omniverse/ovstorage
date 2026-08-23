// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic connection-lifecycle library. A connection-owning backend layer embeds a
//! [`ConnectionSet<D>`] and implements the small per-backend
//! [`ConnectionAuthDriver`] (validate / refresh / interactive / classify, plus
//! optional persistence + on-authenticated hooks). The `ConnectionSet` supplies
//! everything backend-agnostic — the [`crate::ConnectionAuthState`] machine and
//! its transitions, single-flight bring-up coalescing + failure cooldown,
//! per-connection credential state, one background-refresh task per
//! auth-bearing connection, cross-process refresh coalescing + secret
//! persistence through the host callbacks (`crate::marshal`), the data-path
//! invalidate-and-retry-once recovery loop, and `ConnectionChange` emission —
//! so a backend author writes only protocol.

// The credential-transaction conformance expectation every credential-owning
// driver — real or double — is held to. Compiled for this crate's own tests,
// and for downstream crates that turn on `test-credential-conformance` from a
// dev-dependency so their real drivers can stand the same harness.
//
// Plain comments, not `///`: rustc merges a declaration-site doc block with the
// module file's own `//!` header, and rustdoc then resolves the whole merged
// string in THIS scope, where the items those headers link to are not in scope.
#[cfg(any(test, feature = "test-credential-conformance"))]
pub mod credential_conformance;
// The regression harnesses for the credential lock order, shared by the driver
// crates that keep a publication lock. Same gate as `credential_conformance`,
// and for the same reason: dev-dependency only, so production builds of a
// plugin leave it out.
#[cfg(any(test, feature = "test-credential-conformance"))]
pub mod credential_lock_order;
mod driver;
pub mod identity;
pub mod promotion;
mod set;

pub use driver::{
    AuthErrorClass, ConnectionAuthDriver, GrantPolicy, Obtained, ProbeOutcome, Refreshed,
    default_classify,
};
pub use set::{ConnectionSet, ConnectionSetConfig};
