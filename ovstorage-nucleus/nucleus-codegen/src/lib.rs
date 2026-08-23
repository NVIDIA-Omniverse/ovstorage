// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

pub mod ast;
pub mod codegen;
pub mod generator;
pub mod parser;

pub use codegen::{generate_from_file, generate_from_str, preprocess_source};

/// Initialize tracing for build-time codegen. Call before `generate_from_file` when
/// `NUCLEUS_CODEGEN_LOG` or `RUST_LOG` is set to see codegen logs.
pub fn init_logging() {
    if std::env::var("NUCLEUS_CODEGEN_LOG").is_ok() || std::env::var("RUST_LOG").is_ok() {
        use tracing_subscriber::EnvFilter;
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_target(false)
            .try_init()
            .ok();
    }
}
