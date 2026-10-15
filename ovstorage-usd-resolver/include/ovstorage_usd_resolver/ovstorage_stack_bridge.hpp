// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// ovstorage stack bridge — one concrete implementation of the
// `StorageBridge` contract, backed by an ovstorage `Stack` + `Layer`.
// See storage_bridge.hpp for the contract this satisfies, and
// docs/architecture.md § "ovstorage Boundary" for the layering rationale.
//
// Bridge options for the ovstorage-backed resolver:
//   - `layerHandle`: callers hand the bridge a pre-built
//     `::ovstorage::LayerHandle`. The bridge adopts it verbatim and
//     derives capabilities / write routing from the built Layer's
//     address roots — it does not re-compose the stack itself.
//   - `configPath` / `loadDefaultConfig`: path to an ovstorage stack
//     configuration file. Loaded via ovstorage's
//     `StackConfig::from_toml_*` / `StackConfig::build` path; the
//     resolver does not re-implement stack composition on this side
//     of the boundary.
//   - `pluginDirectory`: optional trusted directory containing
//     native provider libraries (`libovstorage_plugin_*.so` on Linux,
//     `ovstorage_plugin_*.dll` on Windows, `.dylib` on macOS). The bridge loads
//     every matching library into the Registry used by StackConfig and
//     pins those plugins for the LayerHandle lifetime. StackConfig
//     deliberately does not discover plugins itself.
//
// Bridge composition is ovstorage's responsibility: this header does
// not expose per-backend option fields. Programmatic callers either
// hand the bridge a fully composed `LayerHandle` or select ovstorage's
// declarative StackConfig path plus an optional generic plugin source.

#pragma once

#include "ovstorage_usd_resolver/configuration.hpp"
#include "ovstorage_usd_resolver/storage_bridge.hpp"

// `OvStorageBridgeOptions::layerHandle` carries an owned
// `::ovstorage::LayerHandle` handed in by a host that has already composed
// its own ovstorage `Stack`. `LayerHandle` is move-only in ovstorage's
// C++ wrapper, so this header must see its full definition when the
// ovstorage bridge library is being built or consumed. Every TU
// that links against `ovstorage::usd_resolver_ovstorage_bridge` gets the
// `OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE=1` define and the
// `OVS_OVSTORAGE_INCLUDE_DIR` on its include path via CMakeLists. The
// no-SDK CLI translation unit deliberately includes this header without
// linking the bridge library, so the include is guarded to preserve the
// "header is safe to include without the SDK" property documented in
// tools/ovstorage_usd_resolver_cli.cpp. A no-SDK caller sees the
// `layerHandle` field disappear from the struct — the same build already
// lacks `createOvStorageBridge`, so nobody could construct a bridge in
// that configuration anyway.
#ifdef OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE
#include "ovstorage.hpp"
#endif

#include <filesystem>
#include <memory>
#include <optional>

namespace ovstorage::usd_resolver
{

struct OvStorageBridgeOptions
{
    // Path to an ovstorage stack configuration file. Loaded via
    // ovstorage's `StackConfig::from_toml_*` / `StackConfig::build`
    // path; the resolver does not re-implement stack composition on
    // this side of the boundary. Setting `loadDefaultConfig` selects
    // ovstorage's documented default-path search instead of an
    // explicit path. Setting both is invalid.
    std::optional<std::filesystem::path> configPath;
    bool loadDefaultConfig = false;

    // Optional trusted provider-plugin directory used only by the
    // StackConfig construction path. Every regular file matching
    // the native provider naming convention is loaded, registered, and pinned for
    // the resulting LayerHandle lifetime. The bridge does not infer
    // provider kinds or schemes from the TOML. Callers that need an
    // exact plugin allowlist should compose a Registry/LayerHandle
    // themselves and use `layerHandle` instead.
    std::optional<std::filesystem::path> pluginDirectory;

#ifdef OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE
    // Host-provided `LayerHandle`. When set at construction time,
    // the bridge adopts this handle as its `m_layer` (move-in). This
    // is the programmatic construction path. `LayerHandle`
    // is move-only in ovstorage's C++ wrapper (copy ctor and
    // copy-assign are `= delete`; move ctor is `noexcept`), which is
    // why this field is a `std::optional<LayerHandle>` rather than a
    // by-value handle: `std::optional` makes "explicitly provided" a
    // distinct state from "default-constructed and null."
    // `std::optional<move-only>` is itself non-copyable, so the
    // struct as a whole is non-copyable **unconditionally** on
    // SDK-on builds (i.e. whenever this field exists) — engaged or
    // not. Call sites that used to copy `OvStorageBridgeOptions`
    // must `std::move` it into `createOvStorageBridge` /
    // `ovStorageBridgeFactory`.
    //
    // Engaged-but-null is rejected: an `optional<LayerHandle>` can
    // be engaged while the underlying handle is null
    // (default-constructed via `.emplace()`, moved-from, or reused
    // after `ovStorageBridgeFactory` already consumed it). The
    // constructor fails with `InvalidArgument` in that case, and
    // `ovStorageBridgeFactory` is explicitly single-shot — a second
    // invocation returns an `UnavailableStorageBridge`.
    std::optional<::ovstorage::LayerHandle> layerHandle;
#endif
};

std::unique_ptr<StorageBridge> createOvStorageBridge(OvStorageBridgeOptions options);
// Checked construction for language bindings and hosts that need eager setup
// diagnostics without probing an arbitrary object. Existing construction
// behavior is unchanged; the status describes only configuration/build.
std::unique_ptr<StorageBridge> createOvStorageBridge(
    OvStorageBridgeOptions options, StorageStatus& initializationStatus);
StorageBridgeFactory ovStorageBridgeFactory(OvStorageBridgeOptions options);

} // namespace ovstorage::usd_resolver
