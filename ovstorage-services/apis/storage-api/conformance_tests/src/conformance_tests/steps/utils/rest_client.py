# SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.
import os
from typing import (
    List,
    Optional,
    Tuple,
)
from urllib.parse import quote_plus

import requests

# Default timeout for HTTP requests (configurable via environment variable)
DEFAULT_TIMEOUT = int(os.getenv("STORAGEAPI_TEST_HTTP_TIMEOUT", "60"))


class RestClient:
    def __init__(self, base_url: str):
        self._base_url = base_url

    def list_services(self) -> requests.Response:
        for version in ("v1alpha", "v1beta", "v1"):
            resp = requests.get(
                f"{self._base_url}/{version}/capabilities/services",
                timeout=DEFAULT_TIMEOUT,
            )
            if resp.status_code != 404:
                return resp
        return resp  # last response (likely 404 from v1)

    def enumerate_data_objects(self, address: str, fileobject_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.get(f"{self._base_url}/{fileobject_version}/fileobject/data-objects/{quote_plus(address)}", **kwargs)

    def stat_data_object(self, address: str, fileobject_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.head(f"{self._base_url}/{fileobject_version}/fileobject/by-address/{quote_plus(address)}", **kwargs)

    def read_data_object_by_address(self, address: str, fileobject_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.get(f"{self._base_url}/{fileobject_version}/fileobject/by-address/{quote_plus(address)}", **kwargs)

    def read_data_object_by_identity(self, identity: str, fileobject_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.get(f"{self._base_url}/{fileobject_version}/fileobject/by-identity/{quote_plus(identity)}", **kwargs)

    def get_upload_options(self, address: str, write_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.get(f"{self._base_url}/{write_version}/fileobject/upload-options/by-address/{quote_plus(address)}", **kwargs)

    def write_data_object(self, address: str, write_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.put(f"{self._base_url}/{write_version}/fileobject/by-address/{quote_plus(address)}", **kwargs)

    def complete_redirect_upload(self, address: str, additional_headers: List[Tuple[str, str]], write_version: str) -> requests.Response:
        json_message = {"additional_headers": [{"name": h[0], "value": h[1]} for h in additional_headers]}
        return requests.post(
            f"{self._base_url}/{write_version}/fileobject/by-address/{quote_plus(address)}/redirect/complete",
            json=json_message,
            timeout=DEFAULT_TIMEOUT,
        )

    def create_multipart_part_upload_request(self, address: str, multipart_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.post(
            f"{self._base_url}/{multipart_version}/fileobject/by-address/{quote_plus(address)}/multipart/prepare", **kwargs
        )

    def complete_multipart_upload(self, address: str, multipart_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.post(
            f"{self._base_url}/{multipart_version}/fileobject/by-address/{quote_plus(address)}/multipart/complete", **kwargs
        )

    def abort_multipart_upload(self, address: str, upload_id: str, multipart_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.post(
            f"{self._base_url}/{multipart_version}/fileobject/by-address/{quote_plus(address)}/multipart/abort",
            json={"upload_id": upload_id},
            **kwargs,
        )

    def enumerate_versions(self, address: str, versioning_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.get(f"{self._base_url}/{versioning_version}/versioning/{quote_plus(address)}/versions", **kwargs)

    def list_data_objects(self, address: str, filefolder_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.get(f"{self._base_url}/{filefolder_version}/filefolder/list/{quote_plus(address)}", **kwargs)

    def list_stat_data_objects(self, address: str, filefolder_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.get(f"{self._base_url}/{filefolder_version}/filefolder/liststat/{quote_plus(address)}", **kwargs)

    def delete_data_object(self, address: str, fileobject_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.delete(f"{self._base_url}/{fileobject_version}/fileobject/by-address/{quote_plus(address)}", **kwargs)

    def copy_object(
        self, source_identity: str, destination_address: str, previous_version: Optional[str], fileobject_version: str, **kwargs
    ) -> requests.Response:
        if previous_version is not None:
            json_message = {"destination_resource_address": destination_address, "previous_version": previous_version}
        else:
            json_message = {"destination_resource_address": destination_address}
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.post(
            f"{self._base_url}/{fileobject_version}/fileobject/by-identity/{quote_plus(source_identity)}/copy", json=json_message, **kwargs
        )

    def delete_folder(self, address: str, filefolder_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.delete(f"{self._base_url}/{filefolder_version}/filefolder/list/{quote_plus(address)}", **kwargs)

    def create_folder(self, address: str, filefolder_version: str, **kwargs) -> requests.Response:
        """Create a folder at the given address. Returns 201 when created, 200 if already exists (idempotent)."""
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.put(f"{self._base_url}/{filefolder_version}/filefolder/{quote_plus(address)}", **kwargs)

    def get_folder_mode(self, folder_address: str, filefolder_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.get(f"{self._base_url}/{filefolder_version}/filefolder/get-folder-mode/{quote_plus(folder_address)}", **kwargs)

    def list_top_level_addresses(self, capabilities_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.get(f"{self._base_url}/{capabilities_version}/capabilities/top-level-addresses", **kwargs)

    def move_data_object(self, source_address: str, move_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.post(
            f"{self._base_url}/{move_version}/fileobject/by-address/{quote_plus(source_address)}/move",
            **kwargs,
        )

    def get_metadata(self, address: str, metadata_version: str, metadata_keys: Optional[List[str]] = None, **kwargs) -> requests.Response:
        """Fetch metadata keys for a resource via REST.

        This endpoint expects a JSON array body (e.g. `["key1", "key2"]`).
        To avoid accidental form/string payloads that trigger 422 validation
        errors, callers should pass `metadata_keys` or an explicit `json=...`
        kwarg.
        """
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        if metadata_keys is not None:
            if "json" in kwargs or "data" in kwargs:
                raise ValueError("metadata_keys cannot be combined with explicit body kwargs")
            kwargs["json"] = metadata_keys
        elif "data" in kwargs and "json" not in kwargs:
            raise ValueError("get_metadata requires JSON body; use metadata_keys=... or json=...")
        return requests.post(f"{self._base_url}/{metadata_version}/metadata/{quote_plus(address)}", **kwargs)

    def update_metadata(self, address: str, key: str, metadata_version: str, **kwargs) -> requests.Response:
        """Update a metadata key via REST with a JSON value body.

        This endpoint expects a JSON value body (string/number/object/etc).
        Callers should pass `json=...` so requests sets `Content-Type:
        application/json`. Passing raw `data=...` without `json` can trigger
        415 on strict deployments.
        """
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        if "data" in kwargs and "json" not in kwargs:
            raise ValueError("update_metadata requires JSON body; use json=...")
        return requests.put(f"{self._base_url}/{metadata_version}/metadata/{quote_plus(address)}/{quote_plus(key)}", **kwargs)

    def delete_metadata(self, address: str, key: str, metadata_version: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        return requests.delete(f"{self._base_url}/{metadata_version}/metadata/{quote_plus(address)}/{quote_plus(key)}", **kwargs)
