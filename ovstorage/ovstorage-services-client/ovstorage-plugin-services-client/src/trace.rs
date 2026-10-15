// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/// Formats a URL without query string, fragment, or userinfo — safe to emit
/// at any log level. Query strings on storage-backend URLs frequently contain
/// signed credentials; this newtype prevents accidental disclosure.
pub struct RedactedUrl<'a>(pub &'a url::Url);

impl std::fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}://{}{}",
            self.0.scheme(),
            self.0.host_str().unwrap_or(""),
            self.0.path()
        )
    }
}
