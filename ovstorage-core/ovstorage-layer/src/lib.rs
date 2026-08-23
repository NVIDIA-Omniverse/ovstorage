// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![warn(clippy::missing_errors_doc)]

pub mod address;
pub mod attribution;
pub mod convert;
mod empty;
mod errors;
pub mod ext;
mod helpers;
pub mod ordered;
pub mod redact;
mod traits;
mod types;

pub use address::{
    canonicalize, canonicalize_preserves_node, encode_canonical_path, node_address, node_key,
    node_path, node_rank, node_segment_count, node_spellings, normalize_decoded_path,
    parsing_preserves_authority, parsing_preserves_node, scheme_folds_backslash,
};
pub use attribution::{
    ATTRIBUTION_KEY_MODIFIED_BY, RESERVED_METADATA_PREFIX, attested_modified_by,
    is_reserved_metadata_key, reassert_attribution, strip_reserved_metadata,
};
pub use convert::*;
pub use empty::{EMPTY_LAYER_KIND, EmptyLayer, EmptyLayerFactory};
pub use errors::*;
pub use helpers::*;
pub use redact::{REDACTED_QUERY_KEYS, redact_message, redact_url};
pub use tokio_util::sync::CancellationToken;
pub use traits::*;
pub use types::*;
pub use url::Url;
