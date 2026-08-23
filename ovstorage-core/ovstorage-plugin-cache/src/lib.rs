// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use ovstorage_plugin::*;

mod byte_cache;
mod metadata_cache;
mod notification_drain;

pub use byte_cache::{ByteCacheGenerations, ByteCacheWrapperFactory};
pub use metadata_cache::MetadataCacheWrapperFactory;

pub const BYTE_CACHE_KIND: &str = "byte_cache";
pub const METADATA_CACHE_KIND: &str = "metadata_cache";

pub(crate) const READ_TO_BYTES_EXTENSION: &str = "ovstorage.read_to_bytes";

pub(crate) mod ext {
    pub(crate) use ovstorage_layer::ext::{PRINCIPAL_ID, RESOLVED_OAUTH_CREDENTIAL};
}

pub(crate) mod layers {
    pub(crate) use crate::{BYTE_CACHE_KIND, METADATA_CACHE_KIND, descriptor};
}

pub(crate) mod routing {
    use ovstorage_plugin::{ListOptions, StatOptions, Url, address};

    pub(crate) fn list_options_are_cacheable_for_stat(options: &ListOptions) -> bool {
        !options.recursive
            && options.max_results.is_none()
            && options.page_token.is_none()
            && !options.full_metadata
    }

    /// Whether a `stat` of `address` under `options` produces a cache entry.
    ///
    /// One definition, because two layers read it: the metadata cache decides
    /// what to store with it, and the byte cache decides with it whether a
    /// forwarded read is worth a watch scope. A scope registered for a read
    /// that stores nothing spends a candidate slot on nothing.
    pub(crate) fn stat_is_cacheable(address: &Url, options: &StatOptions) -> bool {
        !address::is_directory(address) && !options.full_metadata
    }

    /// Whether a `list` of `prefix` under `options` produces a cache entry.
    /// See [`stat_is_cacheable`] for why this is shared.
    pub(crate) fn list_is_cacheable(prefix: &Url, options: &ListOptions) -> bool {
        list_options_are_cacheable_for_stat(options)
            && prefix.query().is_none()
            && prefix.fragment().is_none()
    }
}

pub(crate) mod read_helpers {
    pub(crate) use ovstorage_layer::read_bytes_max_bytes_error;
}

pub(crate) fn descriptor(
    kind: impl Into<String>,
    layer_type: LayerType,
    accepts_connections: bool,
) -> LayerKindDescriptor {
    let kind = kind.into();
    LayerKindDescriptor {
        display_name: kind.clone(),
        kind,
        layer_type,
        description: None,
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections,
        auth_capable: false,
        // The layers this crate registers own no storage, so none of them can
        // carry a write's `user_metadata`.
        supports_user_metadata: false,
    }
}

pub(crate) fn config_u64(value: &ConfigValue, key: &str) -> Result<u64> {
    match value {
        ConfigValue::Int(value) if *value >= 0 => Ok(*value as u64),
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("layer config `{key}` must be a non-negative integer"),
        )),
    }
}

pub(crate) fn cache_config_field(
    key: &str,
    display_name: &str,
    kind: ConfigFieldKind,
    required: bool,
    help: &str,
) -> ConfigField {
    ConfigField {
        key: key.to_string(),
        display_name: display_name.to_string(),
        kind,
        required,
        default: None,
        help: Some(help.to_string()),
        example: None,
        group: None,
        advanced: false,
    }
}

pub(crate) async fn buffer_read_stream(
    mut stream: ReadStream,
    max_bytes: Option<u64>,
) -> Result<Vec<u8>> {
    use futures::StreamExt as _;

    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if let Some(cap) = max_bytes
            && (bytes.len() as u64).saturating_add(chunk.len() as u64) > cap
        {
            return Err(read_helpers::read_bytes_max_bytes_error(cap));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
