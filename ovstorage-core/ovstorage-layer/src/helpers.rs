// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Error, ErrorCode};

/// Construct the canonical bounded-read failure shared by hosts and cache
/// Layers.
pub fn read_bytes_max_bytes_error(cap: u64) -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        format!("read exceeded max_bytes cap of {cap} bytes"),
    )
    .with_next_action(
        "Increase ReadOptions::max_bytes, narrow the read range \
         via ReadOptions::range, or use read_stream to consume \
         the object incrementally.",
    )
}

/// Synthesize the canonical validator for a file's size and modification time.
///
/// File stat, watch events, and followed `file://` redirects use this one
/// implementation so validators round-trip across those paths.
pub fn synthesize_file_etag(size: u64, mtime: Option<SystemTime>) -> String {
    let nanos = mtime
        .and_then(|mtime| mtime.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("size:{size},mtime:{nanos}")
}
