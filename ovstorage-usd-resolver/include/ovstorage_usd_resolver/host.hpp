// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Host-owned stack API, storage half.
//
// A host that builds the process's one ovstorage stack hands it to the
// resolver here. The resolver never composes a second stack on these paths:
// there is no configuration input, and `ResolverOptions::storageBridgeFactory`
// is replaced by a bridge over the host's stack.
//
// Two handoff shapes, chosen by which compiled copy of ovstorage's C runtime
// built the host's stack:
//
//   - `createRuntimeForStack`: the host and this resolver link the SAME copy
//     (for example, the host links `ovstorage::usd_resolver_host`, which
//     carries the resolver bridge's copy). The host lends its
//     `OvStorage_LayerHandle*` for the duration of the call; the runtime keeps
//     its own counted reference to the same root Layer.
//   - `createRuntimeForSharedStack`: the host embeds a DIFFERENT copy: a
//     separately compiled ovstorage C source drop, or ovstorage's Rust
//     runtime. That copy mints the handle (`ovstorage_export_handle` in C)
//     and the host hands it to this C++ call; this resolver's copy consumes
//     it with `ovstorage_import_handle`. Passing an `OvStorage_LayerHandle*`
//     across copies is undefined behaviour; only the exported
//     `OvStoragePlugin_LayerHandle` crosses that boundary, and both copies
//     must support the same ovstorage plugin ABI version. ovstorage's Python
//     package can export a built layer too: `LayerBase.export_handle()`
//     returns the integer address of a heap-allocated `{state, vtable}` pair
//     with this struct's layout. The host supplies its own glue to read that
//     pair and pass it here, and frees the allocation as ovstorage documents
//     for `export_handle`; this resolver ships no such glue and does not test
//     that path.
//
// Linking `ovstorage::usd_resolver_host` puts this resolver's copy of the C
// runtime, with its global `ovstorage_*` symbols, into the host. On Linux, a
// copy that exports those symbols into the process's global scope can capture
// another copy's calls to the same names. So every copy, this one included,
// keeps its `ovstorage_*` symbols out of that scope: no two copies in one
// binary (duplicate definitions), and none exported from a shared library the
// executable links or opens with `RTLD_GLOBAL`, or from an executable linked
// with `--export-dynamic`. In a host that is itself a shared library,
// `-Wl,--exclude-libs,ALL` keeps a copy linked from a static archive local,
// as this package's is; a copy compiled from ovstorage's C sources into the
// library itself needs hidden visibility or a version script instead. To
// check a prebuilt library the host cannot relink, list its dynamic exports
// (`nm -D --defined-only`) and look for `ovstorage_` names. Provider plugins
// and Python extension modules export `ovstorage_plugin_*` helpers, but
// ovstorage and Python open them with `RTLD_LOCAL`, outside the global scope.
// A Windows DLL exports only functions marked for export, and ovstorage's
// headers mark none.
//
// Either result is an ordinary `ResolverRuntime`: bind it to OpenUSD with
// `openusd_host.hpp`, which also states the order of operations.
//
// Lifetime, for both shapes: the copy that built the stack, and the provider
// plugins its Layers came from, must stay loaded until the returned runtime is
// released. An exported handle keeps the stack's root Layer alive, not the
// plugins behind it, so a host that releases its own stack handle early must
// still keep its `OvStorage_Plugin` handles until the resolver lets go. The
// runtime is released with its last reference, and the host's handle is only
// one of them: every `ArResolverContext` made from it, and every copy of that
// context a stage, binder or worker keeps, holds another. Unload only after
// the last of them is gone.
//
// This header is C++17. Besides this resolver's own C++17 headers
// (configuration.hpp, runtime.hpp), it includes only ovstorage's C header, so
// a C++17 host can include it. The library behind it,
// `ovstorage::usd_resolver_host`, contains the concrete ovstorage bridge and
// has that bridge's compiler floor.

#pragma once

#include "ovstorage_usd_resolver/configuration.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"

#include "ovstorage.h"

namespace ovstorage::usd_resolver
{

// Adopt a stack built by the SAME C-runtime copy this resolver links.
//
// `borrowedStack` must be a live root from `ovstorage_stack_build`,
// `ovstorage_stack_build_from_config`, or `ovstorage_import_handle` of that
// copy. It is only used during this call: the runtime takes its own counted
// reference to the same root Layer (an export/import round trip inside this
// copy, which never rebuilds or re-composes anything), so the host may destroy
// its handle whenever it likes afterwards, subject to the lifetime rule above.
//
// `options` supplies schemes, trace sink, isolation key and Resolve-existence
// policy. Its `storageBridgeFactory` is ignored and replaced.
//
// Errors: a null stack is `InvalidArgument`; ovstorage handoff failures map
// through the resolver's ovstorage error taxonomy, except that an ovstorage
// `NotFound` is reported as `Unsupported`, because a setup failure is never
// evidence that a USD object is absent; option validation failures are
// returned unchanged.
ResolverRuntimeCreateResult createRuntimeForStack(
    const OvStorage_LayerHandle* borrowedStack,
    ResolverOptions options = defaultResolverOptions());

// Adopt a stack exported by ANOTHER C-runtime copy (or by this one).
//
// Ownership of `exportedStack` transfers to this call unless it returns
// `InvalidArgument`. That code means the handle was not touched: its `state`
// or `vtable` is NULL, its vtable is smaller than this copy's (`struct_size`
// below `sizeof(OvStoragePlugin_LayerVTableV1)`, as from an exporter built
// against an older ovstorage, whose `drop` slot ovstorage does not trust), or
// `options` failed validation. The caller still owns it and disposes of it as
// its producer requires. Every other result, success or failure, means the
// handle was imported or dropped exactly once, and the caller must not use or
// drop it again. A handle whose `abi_version` this copy does not support is
// dropped and reported as `AbiMismatch`.
//
// Other errors are reported as for `createRuntimeForStack`.
//
// The exporting copy must outlive the returned runtime (ovstorage's export
// contract: an exported handle does not keep its producer loaded), and the
// lifetime rule above applies.
//
// The resolver calls through the handle's vtable, in this process, for `drop`
// and every storage operation. Pass only a handle that trusted code already
// running in this process exported; never one built from external or
// serialized input.
ResolverRuntimeCreateResult createRuntimeForSharedStack(
    OvStoragePlugin_LayerHandle exportedStack,
    ResolverOptions options = defaultResolverOptions());

} // namespace ovstorage::usd_resolver
