// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust binding runner. Expands the shared scenario contract into one test per
//! `(backend, scenario)`. Everything runs under plain `cargo test`: the
//! credential-free `file` backend always executes (the hermetic gate); cloud
//! backends run only when their `OVSTORAGE_<BACKEND>_*` env is set and skip
//! (visibly) otherwise. No `#[ignore]`, no `cfg` gating.
//!
//! `OVSTORAGE_REQUIRE_LIVE_BACKENDS` / `OVSTORAGE_FORBID_LIVE_BACKENDS` turn
//! "a target silently skipped" and "a target unexpectedly connected" into
//! app-construction failures — see the crate docs.

use ovstorage_integration_tests::app_suite;

app_suite! {
    backends: [File, Azure, S3, Gcs, Huggingface],
    scenarios: [
        write_stat_read,
        delete,
        list_prefix_delimiter,
        list_recursive_and_pagination,
        copy,
        rename,
        update_metadata,
        attribution_round_trip,
        message_annotation,
        check_access,
        error_path_not_found,
        range_read,
        read_stream_and_materialize,
        key_encoding,
        conditional_write,
        write_stream,
        directory_ops,
        directory_marker_ops,
        list_versions,
        get_latest_version,
        read_only_list_stat_read,
        read_only_range_read,
        read_only_version_pinning,
    ],
}
