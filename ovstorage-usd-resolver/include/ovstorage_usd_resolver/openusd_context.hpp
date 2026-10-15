// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ovstorage_usd_resolver/runtime.hpp"

#include <pxr/pxr.h>
#include <pxr/usd/ar/defineResolverContext.h>
#include <pxr/usd/ar/resolverContext.h>
#include <pxr/usd/ar/resolverContextBinder.h>

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <utility>

namespace ovstorage::usd_resolver
{

class OpenUsdResolverContext
{
public:
    OpenUsdResolverContext() = default;

    OpenUsdResolverContext(std::shared_ptr<ResolverRuntime> runtime, std::string debugName = {})
        : m_runtime(std::move(runtime)),
          m_debugName(std::move(debugName))
    {
    }

    const std::shared_ptr<ResolverRuntime>& runtime() const
    {
        return m_runtime;
    }

    const std::string& debugName() const
    {
        return m_debugName;
    }

    bool operator==(const OpenUsdResolverContext& other) const
    {
        return m_runtime == other.m_runtime && m_debugName == other.m_debugName;
    }

    bool operator<(const OpenUsdResolverContext& other) const
    {
        if (m_runtime.owner_before(other.m_runtime))
        {
            return true;
        }
        if (other.m_runtime.owner_before(m_runtime))
        {
            return false;
        }
        return m_debugName < other.m_debugName;
    }

private:
    std::shared_ptr<ResolverRuntime> m_runtime;
    std::string m_debugName;
};

} // namespace ovstorage::usd_resolver

PXR_NAMESPACE_OPEN_SCOPE
AR_DECLARE_RESOLVER_CONTEXT(ovstorage::usd_resolver::OpenUsdResolverContext);
PXR_NAMESPACE_CLOSE_SCOPE

namespace ovstorage::usd_resolver
{

inline std::size_t hash_value(const OpenUsdResolverContext& context)
{
    return std::hash<const void*>()(context.runtime().get()) ^ std::hash<std::string>()(context.debugName());
}

inline std::string ArGetDebugString(const OpenUsdResolverContext& context)
{
    if (!context.runtime())
    {
        return "ovstorage-usd-resolver:empty";
    }
    if (context.debugName().empty())
    {
        return "ovstorage-usd-resolver:runtime";
    }
    return "ovstorage-usd-resolver:" + context.debugName();
}

inline PXR_NS::ArResolverContext makeOpenUsdResolverContext(
    std::shared_ptr<ResolverRuntime> runtime,
    std::string debugName = {})
{
    return PXR_NS::ArResolverContext(OpenUsdResolverContext(std::move(runtime), std::move(debugName)));
}

// Register a resolver runtime that this plugin will use to build the
// default `ArResolverContext` when OpenUSD calls
// `_CreateDefaultContext`, `_CreateDefaultContextForAsset`, or
// `_CreateContextFromString`. Not registered by default — a host must
// call this once during process setup. Passing a null shared_ptr clears
// any registered default. CreateDefaultContext() and
// CreateDefaultContextForAsset() first snapshot an explicit binding on the
// calling thread, even if its runtime is null; otherwise they use this default
// or return an empty context. Registering a new default does not replace an
// existing scope's captured runtime. CreateContextFromString() deliberately
// uses only the process default and treats its string as a debug label.
//
// Note that because `ovstorage-usd-resolver` is a URI resolver (not
// the primary), UsdStage's own dispatch of `CreateDefaultContextForAsset`
// on a plain `UsdStage::Open(url)` call may not reach these overrides
// in every OpenUSD version. For a portable "just works" pattern the
// host should combine `setDefaultResolverRuntime` with the
// `ScopedDefaultContext` RAII below, which binds the same context
// through `ArResolverContextBinder` — that binding is unambiguous for
// URI resolvers and covers every subsequent `UsdStage::Open` call in
// the same scope on the current thread. Worker threads must bind their
// own copy of the context around OpenUSD work.
//
// Registration replaces the previous default atomically under a
// process-static mutex. Hosts must synchronize registration against
// concurrent `UsdStage::Open` activity.
void setDefaultResolverRuntime(std::shared_ptr<ResolverRuntime> runtime);
std::shared_ptr<ResolverRuntime> getDefaultResolverRuntime();

// RAII helper that binds a default context for one lexical scope on the
// constructing thread. Every `UsdStage::Open(url)` in that thread and scope
// uses the wrapped runtime — no per-stage context construction or
// `Open(url, context)` overload is required. This is not a process-wide
// binding: construct a binder around OpenUSD work on each worker thread, or
// pass the captured `ArResolverContext` explicitly to APIs that accept it.
//
// The scoped binder is portable across OpenUSD versions because
// `ArResolverContextBinder` is the documented dispatch mechanism for
// URI resolvers, whereas `UsdStage::Open`'s own dispatch of
// `CreateDefaultContextForAsset` may or may not reach a URI resolver's
// override.
//
// Non-copyable; move is disabled to keep the binding tied to a single stack
// frame and thread.
class ScopedDefaultContext
{
public:
    // Uses the runtime last registered via `setDefaultResolverRuntime`.
    // If no runtime is registered, the binder wraps an
    // `OpenUsdResolverContext` with a null runtime — behaviorally
    // inert for asset resolution because `_OpenAsset` returns empty
    // when the bound context has no runtime.
    ScopedDefaultContext()
        : ScopedDefaultContext(getDefaultResolverRuntime())
    {
    }

    // Uses the caller-provided runtime; takes precedence over the registered
    // default when a stage captures its context, including dependency loads.
    // Convenient for tests that need to control the runtime lifetime
    // explicitly.
    explicit ScopedDefaultContext(std::shared_ptr<ResolverRuntime> runtime, std::string debugName = "scoped-default")
        : m_context(makeOpenUsdResolverContext(std::move(runtime), std::move(debugName))),
          m_binder(m_context)
    {
    }

    ScopedDefaultContext(const ScopedDefaultContext&) = delete;
    ScopedDefaultContext& operator=(const ScopedDefaultContext&) = delete;
    ScopedDefaultContext(ScopedDefaultContext&&) = delete;
    ScopedDefaultContext& operator=(ScopedDefaultContext&&) = delete;

    const PXR_NS::ArResolverContext& context() const { return m_context; }

private:
    PXR_NS::ArResolverContext m_context;
    PXR_NS::ArResolverContextBinder m_binder;
};

} // namespace ovstorage::usd_resolver
