# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

import grpc


def map_grpc_codes(grpc_code):
    status_code_map = {
        "NOT_FOUND": grpc.StatusCode.NOT_FOUND,
        "PERMISSION_DENIED": grpc.StatusCode.PERMISSION_DENIED,
        "INVALID_ARGUMENT": grpc.StatusCode.INVALID_ARGUMENT,
        "FAILED_PRECONDITION": grpc.StatusCode.FAILED_PRECONDITION,
        "ALREADY_EXISTS": grpc.StatusCode.ALREADY_EXISTS,
        "UNKNOWN": grpc.StatusCode.UNKNOWN,
    }

    if grpc_code not in status_code_map:
        raise ValueError(f"Unmapped grpc Status code: {grpc_code}, please add to map")

    return status_code_map[grpc_code]


def map_download_preference(download_preference, scenario_state):
    if download_preference == "body":
        return scenario_state.sapi_test_client.fileobject_pb2(
            scenario_state.version_under_test["fileobject"]
        ).DownloadPreference.DOWNLOAD_PREFERENCE_BODY
    elif download_preference == "redirect":
        return scenario_state.sapi_test_client.fileobject_pb2(
            scenario_state.version_under_test["fileobject"]
        ).DownloadPreference.DOWNLOAD_PREFERENCE_REDIRECT
    else:
        raise ValueError(f"unknown download preference, must be one of body or redirect: {download_preference}")
