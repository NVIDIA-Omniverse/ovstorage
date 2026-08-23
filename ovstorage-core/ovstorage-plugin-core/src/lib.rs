// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use ovstorage_plugin::*;

mod alias;
mod copy_rename_fallback;
mod retry;
mod router;

pub use alias::{AliasRules, AliasWrapperFactory};
pub use copy_rename_fallback::{CopyRenameFallbackWrapperFactory, MAX_BUFFERED_TRANSFER_BYTES};
pub use retry::RetryWrapperFactory;
pub use router::RouterFactoryImpl;

pub const ROUTER_KIND: &str = "router";
pub const COPY_RENAME_FALLBACK_KIND: &str = "copy_rename_fallback";
pub const ALIAS_KIND: &str = "alias";
pub const RETRY_KIND: &str = "retry";

pub const ALIAS_TO_METADATA_KEY: &str = "org.omniverse.ovstorage/alias-to";
pub const ALIAS_VISIBILITY_METADATA_KEY: &str = "org.omniverse.ovstorage/alias-visibility";

pub(crate) mod layers {
    pub(crate) use crate::{
        ALIAS_KIND, ALIAS_TO_METADATA_KEY, ALIAS_VISIBILITY_METADATA_KEY,
        COPY_RENAME_FALLBACK_KIND, RETRY_KIND, descriptor,
    };
}

pub(crate) mod routing {
    pub(crate) use ovstorage_plugin::routing::fresh_id;
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
