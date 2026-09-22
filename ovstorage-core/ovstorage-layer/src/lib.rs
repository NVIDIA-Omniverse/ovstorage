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
pub mod fallback;
mod helpers;
pub mod instance_metadata;
pub mod ordered;
pub mod redact;
pub mod spellings;
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
pub use fallback::{
    ANONYMOUS_FALLBACK_AVAILABLE_SCHEMES, ANONYMOUS_FALLBACK_KEY, ANONYMOUS_FALLBACK_KEY_PREFIX,
    ANONYMOUS_FALLBACK_KINDS, ANONYMOUS_FALLBACK_SCHEMES, SCHEME_FALLBACK_ANONYMOUS,
    SCHEME_FALLBACK_METADATA_KEY, SCHEME_FALLBACK_PLACEHOLDER_HOST, decode_anonymous_fallback,
    fallback_mutation_refused, is_anonymous_fallback_key, is_scheme_fallback_root,
    read_only_capabilities, scheme_fallback_root, schemes_for_kind, split_anonymous_fallback_keys,
};
pub use helpers::*;
pub use instance_metadata::{
    is_instance_metadata_host_str, is_instance_metadata_url, refuse_instance_metadata,
};
pub use redact::{REDACTED_QUERY_KEYS, origin_only, redact_message, redact_url};
pub use spellings::{
    ACCEPTED_URL_SPELLINGS_METADATA_KEY, ALIAS_DERIVED_FROM_METADATA_KEY, CARRIED_QUERY_KEYS,
    decode_url_spellings, encode_url_spellings, generated_rule_may_answer,
};
pub use tokio_util::sync::CancellationToken;
pub use traits::*;
pub use types::*;
pub use url::Url;
