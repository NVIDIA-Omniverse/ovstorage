// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! ABI-v2 cdylib export of the hub cache Layer factory.

use ovstorage_plugin_hub_cache::HubCacheWrapperFactory;

ovstorage_plugin::ovstorage_layer_plugin!(((wrapper, HubCacheWrapperFactory::default),));
