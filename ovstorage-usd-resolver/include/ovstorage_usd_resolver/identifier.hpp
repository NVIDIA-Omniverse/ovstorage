// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace ovstorage::usd_resolver
{

struct SdfFormatArgsSplit
{
    std::string assetPath;
    std::string suffix;
    bool hasArgs = false;
};

struct PackageIdentifier
{
    bool isPackage = false;
    bool valid = true;
    std::string outerAsset;
    std::string innerPath;
    std::string error;
};

bool hasUriScheme(std::string_view identifier);
std::string uriScheme(std::string_view identifier);
bool isRemoteIdentifier(std::string_view identifier);

SdfFormatArgsSplit splitSdfFormatArgs(std::string_view identifier);
PackageIdentifier parsePackageIdentifier(std::string_view identifier);

// Return the identifier understood by a storage provider: SDF format
// arguments and package-inner paths are removed, leaving the outer object.
std::string storageProviderIdentifier(std::string_view identifier);

// Return the canonical whole-object target for a storage write. SDF format
// arguments do not identify a distinct provider object and are removed.
// Package-inner identifiers cannot be represented by a whole-object PUT and
// return nullopt; callers write the outer package only by naming it directly.
std::optional<std::string> storageWriteTargetIdentifier(std::string_view identifier);

std::string normalizeIdentifier(std::string_view identifier);
std::string joinIdentifier(std::string_view baseIdentifier, std::string_view assetPath);
std::string identifierExtension(std::string_view identifier);

// Return an identifier suitable for passive diagnostics. URI userinfo is
// removed, query and fragment values are replaced with markers, and SDF format
// arguments are hidden. The result is for display only and must never be sent
// to a storage provider.
std::string redactIdentifierForDiagnostics(std::string_view identifier);

// Apply the same policy to every URI-shaped token in a diagnostic message.
// Non-URI text is preserved.
std::string redactDiagnosticMessage(std::string_view message);

} // namespace ovstorage::usd_resolver
