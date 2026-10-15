// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! ABI-v2 cdylib export of the public cache Layer factories.

use ovstorage_plugin_cache::{ByteCacheWrapperFactory, MetadataCacheWrapperFactory};

ovstorage_plugin::ovstorage_layer_plugin!((
    (wrapper, MetadataCacheWrapperFactory::default),
    (wrapper, ByteCacheWrapperFactory::default),
));
