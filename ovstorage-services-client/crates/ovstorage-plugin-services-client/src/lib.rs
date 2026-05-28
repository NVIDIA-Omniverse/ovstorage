// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Omniverse Storage Service backend for ovstorage.
//!
//! Loads as a cdylib via the C ABI declared by `ovstorage-plugin`. Maps SPI
//! calls (stat / read / write / list / copy / write_redirect / …) onto the
//! Omniverse Storage Service's gRPC services. Discovery + OIDC bearer
//! auth mirror the C++ reference client.

pub mod auth;
pub mod backend;
pub mod config;
pub mod convert;
pub mod discovery;
pub mod factory;
pub mod multipart;
pub mod trace;
pub mod transport;

pub use backend::OmniverseStorageBackend;
pub use factory::OmniverseStorageFactory;

ovstorage_plugin::ovstorage_plugin!(OmniverseStorageFactory::default);
