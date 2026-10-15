// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// `RouteTable`, `fresh_id`, `paginate_list_items`, and
// `fold_markers_and_infer_subdir_kinds` moved down to `ovstorage-plugin` so
// in-tree ABI-v2 backend plugins (which cannot see this host crate's
// internals) can reuse them. Re-exported here so every existing
// `crate::routing::…` call site — and the crate-root `pub use routing::*` —
// keeps resolving unchanged.
pub(crate) use ovstorage_plugin::routing::{fresh_id, paginate_list_items};
