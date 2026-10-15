// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! ABI-v2 cdylib export of the public HTTP Layer factories.

use ovstorage_plugin_http::{HttpBackendLayerFactory, RedirectFollowerWrapperFactory};

ovstorage_plugin::ovstorage_layer_plugin!((
    (backend, HttpBackendLayerFactory::default),
    (wrapper, || RedirectFollowerWrapperFactory),
));
