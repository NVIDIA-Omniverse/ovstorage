// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) struct RedactedUrl<'a>(pub &'a ovstorage_plugin::Url);
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
