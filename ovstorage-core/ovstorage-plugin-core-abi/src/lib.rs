// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! ABI-v2 cdylib export of the public core Layer factories.
//!
//! Keeping the fixed-name ABI entry points in this cdylib-only crate lets
//! Rust hosts link the implementation crate without exporting another
//! plugin's symbols from their own binaries.

use ovstorage_plugin_core::{
    AliasWrapperFactory, CopyRenameFallbackWrapperFactory, RetryWrapperFactory, RouterFactoryImpl,
};

ovstorage_plugin::ovstorage_layer_plugin!((
    (router, || RouterFactoryImpl),
    (wrapper, AliasWrapperFactory::default),
    (wrapper, || CopyRenameFallbackWrapperFactory),
    (wrapper, || RetryWrapperFactory),
));
