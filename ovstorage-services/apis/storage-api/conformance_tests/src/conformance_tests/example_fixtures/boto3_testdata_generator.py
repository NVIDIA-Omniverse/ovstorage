# SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.
import logging
import os
from datetime import datetime
from typing import (
    Optional,
    Tuple,
)

import boto3
import botocore.config
import grpc
import pytest
from botocore.exceptions import ClientError
from conformance_tests.storage_testclient import ConformanceTestClient
from conformance_tests.storage_testdata_generator import AbstractTestDataGenerator


def parse_s3_bucket_key(url: str) -> Tuple[str, str, Optional[str]]:
    """Given an S3 URL in any of the s3 or https styles, returns Bucket, Key, and Region.

    Region might be None if not specified in the URL.

    Raises ValueError if the URL is not a valid S3 URL."""
    # Local import, so we don't accidentally use urlparse anywhere else.
    from urllib.parse import (
        urlparse,
    )

    parsed = urlparse(url)
    pure_path = parsed.path.lstrip("/")
    if parsed.hostname is None:
        raise ValueError(f"No hostname in URL {url}")
    if parsed.scheme == "s3":
        return parsed.hostname, pure_path, None

    if parsed.scheme == "https" and "amazonaws.com" in parsed.hostname:
        split_host = parsed.hostname.split(".")

        path_split = pure_path.split("/", 1)
        bucket, key = path_split[0], path_split[1] if len(path_split) > 1 else ""

        if len(split_host) == 3:
            # Legacy hostname path style
            if parsed.hostname == "s3.amazonaws.com":
                return bucket, key, None
            # Dash style legacy outlier
            if split_host[0].startswith("s3"):
                region = split_host[0].split("-", 1)[-1] if "-" in split_host[0] else None
                return bucket, key, region
        elif len(split_host) == 4:
            # Deprecated path-style
            if split_host[0] == "s3" and split_host[-2:] == ["amazonaws", "com"]:
                return bucket, key, split_host[1]
            # S3-accelerate transfer endpoint URL
            if split_host[1].startswith("s3") and split_host[-2:] == ["amazonaws", "com"]:
                return split_host[0], pure_path, None
        elif len(split_host) == 5:
            # Modern virtual host style
            if split_host[1] == "s3" and split_host[-2:] == ["amazonaws", "com"]:
                return split_host[0], pure_path, split_host[2]
            # Dualstack (IP6) URL, potentially with s3-accelerate
            if split_host[1].startswith("s3") and split_host[-3:] == ["dualstack", "amazonaws", "com"]:
                return split_host[0], pure_path, None
            # Legacy hostname with virtual host style
            if split_host[2:] == ["s3", "amazonaws", "com"]:
                return split_host[0], pure_path, split_host[1]
        elif len(split_host) == 6:
            # Dualstack (IP6) with region
            if split_host[1:3] == ["s3", "dualstack"] and split_host[-2:] == ["amazonaws", "com"]:
                return split_host[0], pure_path, split_host[3]

    raise ValueError(f"Not an S3 url: {url}")


class Boto3TestDataGenerator(AbstractTestDataGenerator):
    def __init__(self):
        now = datetime.now()
        self._test_folder = "storageapi_conformity_test/" + now.isoformat().replace(":", "-")
        # configure the session using the usual AWS environment variables:
        # AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_ENDPOINT_URL and AWS_REGION environment variables,
        # and the key_id and secr
        self._s3_session = boto3.Session()
        connect_timeout = float(os.getenv("TEST_STORAGE_API_BOTO3_CONNECT_TIMEOUT", 5.0))
        max_pool_connections = int(os.getenv("TEST_STORAGE_API_BOTO3_MAX_POOL_CONNECTIONS", 10 * 2))
        extra_config = botocore.config.Config(connect_timeout=connect_timeout, max_pool_connections=max_pool_connections)
        self._s3 = self._s3_session.client("s3", config=extra_config)
        self._create_folder_flag = os.getenv("CREATE_FOLDER", "false").lower() == "true"

    @staticmethod
    def _endpoint_looks_like_minio(endpoint_url: str | None):
        return endpoint_url and (
            "minio" in endpoint_url or "localhost" in endpoint_url or "127.0.0.1" in endpoint_url or ":9000" in endpoint_url
        )

    def _create_bucket(self, bucket_name: str):
        try:
            logging.info(f"Creating bucket {bucket_name} with endpoint {self._s3.meta.endpoint_url}...")
            self._s3.create_bucket(Bucket=bucket_name)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "BucketAlreadyOwnedByYou":
                logging.info(f"Bucket '{bucket_name}' already exists and is owned by you.")
            elif error_code == "BucketAlreadyExists":
                logging.info(f"Bucket '{bucket_name}' already exists but is owned by someone else.")
            else:
                raise

    def create_namespace(self, namespace_name) -> str:
        bucket_name = os.getenv("TEST_STORAGE_API_BOTO3_BUCKET_NAME", "sapiv")
        if self._endpoint_looks_like_minio(self._s3.meta.endpoint_url):
            os.environ["BOTO_EXPERIMENTAL__NO_EMPTY_CONTINUE"] = (
                "true"  # Avoid issues with minio and boto3; see https://github.com/boto/botocore/pull/3123.
            )
            self._create_bucket(bucket_name)

        aws_region = os.getenv("AWS_REGION", "us-east-1")
        return f"https://{bucket_name}.s3.{aws_region}.amazonaws.com/{self._test_folder}/{namespace_name}"

    def make_resource_address(self, namespace_path, object_name) -> str:
        namespace_path = namespace_path.rstrip("/") + "/"
        object_name = object_name.lstrip("/")
        return namespace_path + object_name

    def make_enumerable_resource_address(self, namespace_path, dirname) -> str:
        fullpath = namespace_path.rstrip("/") + "/" + dirname.lstrip("/")
        return fullpath

    def get_non_empty_root_address(self) -> str:
        bucket_name = os.getenv("TEST_STORAGE_API_BOTO3_BUCKET_NAME", "sapiv")
        if self._endpoint_looks_like_minio(self._s3.meta.endpoint_url):
            os.environ["BOTO_EXPERIMENTAL__NO_EMPTY_CONTINUE"] = (
                "true"  # Avoid issues with minio and boto3; see https://github.com/boto/botocore/pull/3123.
            )
            self._create_bucket(bucket_name)

        aws_region = os.getenv("AWS_REGION", "us-east-1")
        return f"https://{bucket_name}.s3.{aws_region}.amazonaws.com"

    def is_bucket_versioned(self, bucket_name: str) -> bool:
        """Check if a bucket has versioning enabled.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            True if versioning is enabled, False otherwise
        """
        try:
            response = self._s3.get_bucket_versioning(Bucket=bucket_name)
            status = response.get("Status", None)
            # Status can be 'Enabled', 'Suspended', or absent (meaning not enabled)
            return status == "Enabled"
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchBucket":
                logging.warning(f"Bucket {bucket_name} does not exist")
                return False
            logging.error(f"Error checking versioning for bucket {bucket_name}: {e}")
            raise

    def get_bucket_versioning_status(self, bucket_name: str) -> dict:
        """Get detailed versioning status for a bucket.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            Dictionary containing:
            - status: 'Enabled', 'Suspended', or 'Not Enabled'
            - mfa_delete: MFA delete configuration status
            - is_enabled: Boolean indicating if versioning is currently enabled
            - was_ever_enabled: Boolean indicating if versioning was ever enabled
        """
        try:
            response = self._s3.get_bucket_versioning(Bucket=bucket_name)

            status = response.get("Status", "Not Enabled")
            mfa_delete = response.get("MFADelete", "Not Configured")

            return {
                "status": status,
                "mfa_delete": mfa_delete,
                "is_enabled": status == "Enabled",
                "was_ever_enabled": status in ["Enabled", "Suspended"],
            }
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchBucket":
                logging.warning(f"Bucket {bucket_name} does not exist")
                return {"status": "Bucket Does Not Exist", "mfa_delete": False, "is_enabled": False, "was_ever_enabled": False}
            logging.error(f"Error getting versioning status for bucket {bucket_name}: {e}")
            raise

    def delete_if_exists(self, resource_address: str):
        bucket, key, _region = parse_s3_bucket_key(resource_address)
        self._s3.delete_object(Bucket=bucket, Key=key)

    def obliterate(self, resource_address: str):
        """Delete all versions of the object at the given resource address.

        This method lists all versions (including delete markers) and deletes each one.
        Works on both versioned and non-versioned buckets:
        - Versioned buckets: Deletes all versions and delete markers
        - Non-versioned buckets: Deletes the single object (which has VersionId='null')
        """
        bucket, key, region = parse_s3_bucket_key(resource_address)

        # Log bucket versioning status for debugging
        versioning_status = self.get_bucket_versioning_status(bucket)
        logging.debug(f"Obliterating {resource_address} from bucket with versioning status: {versioning_status['status']}")

        try:
            # List all versions of the object
            # This works on both versioned and non-versioned buckets
            # Note: Prefix is used for efficiency, but exact key matching is done below
            paginator = self._s3.get_paginator("list_object_versions")
            pages = paginator.paginate(Bucket=bucket, Prefix=key)

            versions_to_delete = []
            for page in pages:
                # Collect all versions
                if "Versions" in page:
                    for version in page["Versions"]:
                        if version["Key"] == key:  # Exact match only
                            versions_to_delete.append({"VersionId": version["VersionId"]})

                # Collect delete markers
                if "DeleteMarkers" in page:
                    for marker in page["DeleteMarkers"]:
                        if marker["Key"] == key:  # Exact match only
                            versions_to_delete.append({"VersionId": marker["VersionId"]})

            # Delete all versions in batch if any exist
            if versions_to_delete:
                # Batch delete (S3 allows up to 1000 objects per request)
                for i in range(0, len(versions_to_delete), 1000):
                    batch = versions_to_delete[i : i + 1000]
                    objects_to_delete = [{"Key": key, "VersionId": v["VersionId"]} for v in batch]
                    self._s3.delete_objects(Bucket=bucket, Delete={"Objects": objects_to_delete, "Quiet": True})
                logging.info(f"Obliterated {len(versions_to_delete)} versions of {resource_address}")
            else:
                logging.info(f"No versions found to obliterate for {resource_address}")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchBucket":
                logging.warning(f"Bucket {bucket} does not exist, nothing to obliterate")
            else:
                logging.error(f"Error obliterating {resource_address}: {e}")
                raise

    def delete_by_identity(self, resource_identity: str):
        # Assuming resource_address = resource_identity
        self.delete_if_exists(resource_identity)

    def create_object_of_given_size(self, resource_address: str, size: int, seed: Optional[int] = None):
        bucket, key, region = parse_s3_bucket_key(resource_address)
        self._s3.put_object(Bucket=bucket, Key=key, Body=AbstractTestDataGenerator.generate_random_bytes(size, seed=seed))

    def create_object_with_no_read_permission(self, resource_address: str):
        raise NotImplementedError("Boto3 test data generated cannot generate objects without read permission, not implemented!")

    def make_invalid_resource_address(self) -> str:
        return "omniverse://not_an_s3_address"

    def make_invalid_resource_identity(self) -> str:
        return "1:2:\0:3"

    def add_version_object_of_given_size(self, resource_address: str, size: int, seed: Optional[int] = None):
        bucket, key, region = parse_s3_bucket_key(resource_address)
        self._s3.put_object(Bucket=bucket, Key=key, Body=AbstractTestDataGenerator.generate_random_bytes(size, seed=seed))

    def remove_write_permission_via_address(self, resource_address: str):
        raise NotImplementedError("Boto3 test data generator cannot remove write permissions, not implemented!")

    def create_folder(self, resource_address: str):
        if self._create_folder_flag:
            fullpath = resource_address.rstrip("/") + "/"
            bucket, key, region = parse_s3_bucket_key(fullpath)
            self._s3.put_object(Bucket=bucket, Key=key, Body=b"")
        else:
            # Folder creation is disabled, folders will be a side effect of uploading files
            pass

    def remove_read_permission_via_identity(self, resource_identity: str):
        raise NotImplementedError("Boto3 test data generator cannot remove read permissions, not implemented!")


@pytest.fixture(scope="session")
def sapi_test_client():
    rest_endpoint = os.getenv("TEST_STORAGE_API_REST_ENDPOINT", "http://localhost:8011")
    grpc_endpoint = os.getenv("TEST_STORAGE_API_GRPC_ENDPOINT", "localhost:50051")
    test_data_generator = Boto3TestDataGenerator()

    grpc_port = grpc_endpoint.split(":")[-1]
    with grpc.insecure_channel(grpc_endpoint) as channel:
        yield ConformanceTestClient(
            grpc_port=grpc_port, grpc_channel=channel, rest_endpoint=rest_endpoint, testdata_generator=test_data_generator
        )


@pytest.fixture(scope="session")
def sapi_test_server_launch():
    # No auto launching of the storage service implemented, the service needs to be launched before the tests are executed
    yield "No auto launching"
