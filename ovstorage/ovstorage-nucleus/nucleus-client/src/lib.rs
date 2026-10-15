// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

pub mod deprecated_methods;
pub mod lft;
pub mod types;

pub mod generated {

    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

pub type NucleusClient = nucleus_transport::ConnLibTransport;

pub use generated::{Connection, ServerFeatures};
pub use lft::{LftClient, LftUploadInfo};
pub use nucleus_transport::{self, Transport};
