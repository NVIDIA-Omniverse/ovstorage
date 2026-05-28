// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

pub mod ffi;
pub use ffi::*;

#[cfg(test)]
mod tests;
