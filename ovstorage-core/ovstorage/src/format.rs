// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Reject an `update_metadata` request that both sets and removes the same key.
/// Called by hosts such as the broker before dispatching an update through a
/// Stack.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the request sets and removes the same
///   user-metadata key.
pub fn validate_update_metadata_options(options: &UpdateMetadataOptions) -> Result<()> {
    for key in &options.user_metadata_remove {
        if options.user_metadata_set.contains_key(key) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "metadata update cannot set and remove the same key",
            ));
        }
    }
    Ok(())
}
