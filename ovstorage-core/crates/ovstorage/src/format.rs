// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

static MATERIALIZE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn validate_update_metadata_options(options: &UpdateMetadataOptions) -> Result<()> {
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

pub(crate) fn materialize_temp_path() -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let seq = MATERIALIZE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "ovstorage-local-delegate-{}-{stamp}-{seq}.tmp",
        std::process::id()
    ))
}

pub(crate) fn materialize_temp_file(bytes: &[u8]) -> Result<std::path::PathBuf> {
    let path = materialize_temp_path();
    let mut file = std::fs::File::create(&path).map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    Ok(path)
}
