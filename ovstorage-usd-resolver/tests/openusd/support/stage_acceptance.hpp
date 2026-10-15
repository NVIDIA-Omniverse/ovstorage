// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ovstorage_usd_resolver/configuration.hpp"

#include <pxr/usd/usd/stage.h>
#include <pxr/usd/usd/primRange.h>
#include <pxr/usd/pcp/errors.h>

#include <cstddef>
#include <charconv>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <ostream>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace ovstorage::usd_resolver::test_support
{

struct StageObservation
{
    std::string rootIdentifier;
    std::set<std::string> primPaths;
    std::set<std::string> usedLayerIdentifiers;
    std::set<std::string> successfulOpenIdentifiers;
    std::vector<ResolverTraceEvent> failedTraceEvents;
    std::vector<std::string> compositionErrors;
    std::size_t compositionErrorCount = 0;
};

struct ExactStageSignature
{
    std::set<std::string> primPaths;
    std::set<std::string> usedLayerIdentifiers;
    std::set<std::string> successfulOpenIdentifiers;
    std::size_t anonymousLayerCount = 1;
};

struct MinimumStageSignature
{
    std::size_t primCount = 1;
    std::size_t usedLayerCount = 1;
    std::size_t successfulOpenCount = 1;
    std::set<std::string> requiredPrimPaths;
};

class StageTraceRecorder
{
public:
    void record(const ResolverTraceEvent& event)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_events.push_back(event);
    }

    ResolverTraceSink sink()
    {
        return [this](const ResolverTraceEvent& event) { record(event); };
    }

    std::vector<ResolverTraceEvent> snapshot() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_events;
    }

    void clear()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_events.clear();
    }

private:
    mutable std::mutex m_mutex;
    std::vector<ResolverTraceEvent> m_events;
};

inline StageObservation observeStage(
    const PXR_NS::UsdStageRefPtr& stage,
    const StageTraceRecorder& trace)
{
    StageObservation result;
    if (stage)
    {
        result.rootIdentifier = stage->GetRootLayer()->GetIdentifier();
        for (const auto& prim : stage->Traverse())
        {
            result.primPaths.insert(prim.GetPath().GetString());
        }
        for (const auto& layer : stage->GetUsedLayers())
        {
            result.usedLayerIdentifiers.insert(layer->GetIdentifier());
        }
        const auto compositionErrors = stage->GetCompositionErrors();
        result.compositionErrorCount = compositionErrors.size();
        for (const auto& error : compositionErrors)
        {
            result.compositionErrors.push_back(
                error ? error->ToString() : "unknown composition error");
        }
    }

    for (const auto& event : trace.snapshot())
    {
        if (event.operation == "open_asset.end" && event.status.ok())
        {
            result.successfulOpenIdentifiers.insert(event.identifier);
        }
        if (!event.status.ok())
        {
            result.failedTraceEvents.push_back(event);
        }
    }
    return result;
}

inline void printStageObservation(
    std::ostream& stream,
    const StageObservation& observation)
{
    stream << "stage acceptance observation:\n"
           << "  root:               " << observation.rootIdentifier << '\n'
           << "  prims:              " << observation.primPaths.size() << '\n'
           << "  used layers:        " << observation.usedLayerIdentifiers.size() << '\n'
           << "  successful opens:   " << observation.successfulOpenIdentifiers.size() << '\n'
           << "  failed trace events:" << observation.failedTraceEvents.size() << '\n'
           << "  composition errors: " << observation.compositionErrorCount << '\n';
    for (const auto& identifier : observation.usedLayerIdentifiers)
    {
        stream << "    layer: " << identifier << '\n';
    }
    for (const auto& event : observation.failedTraceEvents)
    {
        stream << "    failure: " << event.operation << " " << event.identifier
               << " (" << event.message << ")\n";
    }
    for (const auto& error : observation.compositionErrors)
    {
        stream << "    composition: " << error << '\n';
    }
}

// Exact-set acceptance is deliberately coupled to the trace interval used by
// the caller. Clear the recorder immediately before the deterministic stage
// operation and observe before unrelated resolver calls; otherwise a valid
// extra open would correctly make the exact signature fail. Duplicate opens
// of the same identifier collapse into the set because this contract proves
// complete dependency coverage, not a provider-specific request count.
inline bool strictlyAccepts(
    const StageObservation& observation,
    const ExactStageSignature& signature)
{
    std::set<std::string> nonAnonymousLayers;
    std::size_t anonymousLayerCount = 0;
    for (const auto& identifier : observation.usedLayerIdentifiers)
    {
        if (identifier.rfind("anon:", 0) == 0)
        {
            ++anonymousLayerCount;
        }
        else
        {
            nonAnonymousLayers.insert(identifier);
        }
    }

    return observation.primPaths == signature.primPaths &&
        nonAnonymousLayers == signature.usedLayerIdentifiers &&
        anonymousLayerCount == signature.anonymousLayerCount &&
        observation.successfulOpenIdentifiers ==
            signature.successfulOpenIdentifiers &&
        observation.failedTraceEvents.empty() &&
        observation.compositionErrorCount == 0;
}

inline bool strictlyAccepts(
    const StageObservation& observation,
    const MinimumStageSignature& signature)
{
    if (observation.primPaths.size() < signature.primCount ||
        observation.usedLayerIdentifiers.size() < signature.usedLayerCount ||
        observation.successfulOpenIdentifiers.size() <
            signature.successfulOpenCount ||
        !observation.failedTraceEvents.empty() ||
        observation.compositionErrorCount != 0)
    {
        return false;
    }

    for (const auto& path : signature.requiredPrimPaths)
    {
        if (observation.primPaths.find(path) == observation.primPaths.end())
        {
            return false;
        }
    }
    return true;
}

inline std::optional<std::size_t> environmentSize(
    const char* name,
    std::size_t defaultValue)
{
    const char* value = std::getenv(name);
    if (value == nullptr || *value == '\0')
    {
        return defaultValue;
    }
    std::size_t parsed = 0;
    const std::string text(value);
    const auto result = std::from_chars(
        text.data(), text.data() + text.size(), parsed);
    if (result.ec != std::errc() || result.ptr != text.data() + text.size() ||
        parsed == 0)
    {
        return std::nullopt;
    }
    return parsed;
}

inline std::set<std::string> environmentList(
    const char* name,
    char delimiter = ';')
{
    std::set<std::string> result;
    const char* value = std::getenv(name);
    if (value == nullptr || *value == '\0')
    {
        return result;
    }
    const std::string text(value);
    std::size_t start = 0;
    while (start <= text.size())
    {
        const auto end = text.find(delimiter, start);
        const auto item = text.substr(
            start, end == std::string::npos ? std::string::npos : end - start);
        if (!item.empty())
        {
            result.insert(item);
        }
        if (end == std::string::npos)
        {
            break;
        }
        start = end + 1;
    }
    return result;
}

} // namespace ovstorage::usd_resolver::test_support
