// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <fstream>
#include <string_view>

namespace ovstorage::usd_resolver::test_support
{

inline constexpr std::string_view kHuggingFaceRepoId =
    "nvidia/Spark-AnomalyGen-USD";
inline constexpr std::string_view kHuggingFaceRepoType = "dataset";
inline constexpr std::string_view kHuggingFaceRevision =
    "0bbac7b7322afcfa0d58c837c17fddaee84d9b76";
inline constexpr std::string_view kHuggingFaceRootUrl =
    "hf://datasets/nvidia/Spark-AnomalyGen-USD/";
inline constexpr std::string_view kHuggingFaceStageUrl =
    "hf://datasets/nvidia/Spark-AnomalyGen-USD/pcb.usd";
inline constexpr std::string_view kHuggingFacePasteMaskLayerUrl =
    "hf://datasets/nvidia/Spark-AnomalyGen-USD/ECAD_3D/L_PASTEMASK_TOP.usd";
inline constexpr std::string_view kHuggingFaceSolderMaskLayerUrl =
    "hf://datasets/nvidia/Spark-AnomalyGen-USD/ECAD_3D/L_SOLDERMASK_TOP.usd";

inline bool writeHuggingFaceStackConfig(const std::filesystem::path& path)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream)
    {
        return false;
    }

    // Keep this graph aligned with the host-facing StackConfig path: the core
    // retry wrapper handles transient operations while the native Hugging Face
    // plugin retains ownership of hf:// routing and Hub/CDN redirects.
    stream
        << "[ovstorage]\n"
        << "root = \"retry\"\n\n"
        << "[ovstorage.layers.retry]\n"
        << "kind = \"retry\"\n"
        << "inner = \"huggingface\"\n"
        << "config = { max_attempts = 6, initial_delay_ms = 500 }\n\n"
        << "[ovstorage.layers.huggingface]\n\n"
        << "[[ovstorage.connections]]\n"
        << "backend_kind = \"huggingface\"\n"
        << "config = { repo_id = \"" << kHuggingFaceRepoId
        << "\", repo_type = \"" << kHuggingFaceRepoType
        << "\", revision = \"" << kHuggingFaceRevision << "\" }\n";
    return stream.good();
}

} // namespace ovstorage::usd_resolver::test_support
