// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

pub mod flow;
pub mod types;

pub mod generated {

    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

pub type AuthClient = nucleus_transport::SowsTransport;

pub use flow::{
    DEFAULT_EXPIRES_IN, DEFAULT_POLL_INTERVAL, DEFAULT_START_TIMEOUT, InteractiveHandshakeStart,
    start_interactive, start_interactive_with_timeout,
};
pub use nucleus_transport::{self, Transport};
