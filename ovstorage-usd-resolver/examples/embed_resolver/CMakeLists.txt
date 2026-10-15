# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

add_executable(ovstorage_usd_resolver_embed
    embed_resolver.cpp
)
set_target_properties(ovstorage_usd_resolver_embed PROPERTIES
    OUTPUT_NAME ovstorage-usd-resolver-embed
)
target_compile_features(ovstorage_usd_resolver_embed PRIVATE cxx_std_20)
target_link_libraries(ovstorage_usd_resolver_embed
    PRIVATE
        ovstorage::usd_resolver_ovstorage_bridge
        ovstorage_usd_resolver_openusd
        usd_m
)
if(_ovs_ovstorage_lib_dir)
    set_target_properties(ovstorage_usd_resolver_embed PROPERTIES
        BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
    )
endif()
