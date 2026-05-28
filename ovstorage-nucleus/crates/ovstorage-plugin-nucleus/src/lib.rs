// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

mod address;
mod auth;
mod backend;
mod config;
mod convert;
mod handshake;
mod ops;
mod trace;

#[cfg(test)]
mod test_support;

pub use backend::{NucleusBackend, NucleusBackendFactory};

ovstorage_plugin::ovstorage_plugin!(NucleusBackendFactory::default);
