// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wire-level generated types for the hub cache-aside protocol.
//!
//! These are the prost bindings for `nvidia.omniverse.hub.v1alpha`, the
//! protobuf schema the hub speaks over its length-prefixed TCP framing.
//! They are internal to this crate: the client translates them into
//! engine-owned types, and the in-process fake hub speaks them directly to
//! exercise the client without a real hub process. Nothing outside this
//! crate touches a proto type.
//!
//! The vendored schema covers the hub's full wire surface (cache-aside,
//! block-cache, connect/version probes); this crate implements only the
//! cache-aside subset, so generated message types outside that subset go
//! unconstructed here by design.
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/nvidia.omniverse.hub.v1alpha.rs"));
