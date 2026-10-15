# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import struct
import json
from unittest.mock import patch
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import acquire_openusd_sdk  # noqa: E402


def _reparse_record(target: str) -> bytes:
    encoded = target.encode("utf-16-le")
    path_buffer = encoded + encoded
    data_length = 12 + len(path_buffer)
    return struct.pack(
        "<IHHHHHHI",
        0xA000000C,
        data_length,
        0,
        len(encoded),
        len(encoded),
        0,
        len(encoded),
        1,
    ) + path_buffer


class ReparseSymlinkTests(unittest.TestCase):
    def test_reads_relative_target(self) -> None:
        self.assertEqual(
            acquire_openusd_sdk._reparse_symlink_target(
                _reparse_record("libtbb.so.12")
            ),
            "libtbb.so.12",
        )

    def test_ignores_normal_small_file(self) -> None:
        self.assertIsNone(acquire_openusd_sdk._reparse_symlink_target(b"normal"))

    def test_rejects_parent_traversal(self) -> None:
        with self.assertRaises(acquire_openusd_sdk.AcquisitionError):
            acquire_openusd_sdk._reparse_symlink_target(
                _reparse_record("../outside.so")
            )

    def test_repairs_archive_link(self) -> None:
        with tempfile.TemporaryDirectory() as temp_value:
            root = Path(temp_value)
            target = root / "libexample.so.1"
            target.write_bytes(b"library")
            link = root / "libexample.so"
            link.write_bytes(_reparse_record(target.name))

            repaired = acquire_openusd_sdk._repair_reparse_symlinks(root)

            self.assertEqual(repaired, 1)
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.readlink(), Path(target.name))


class PackageTests(unittest.TestCase):
    def test_host_aliases(self):
        for system, machine, expected in [
            ("Linux", "x86_64", "linux-x86_64"),
            ("Linux", "aarch64", "linux-aarch64"),
            ("Windows", "AMD64", "windows-x86_64"),
        ]:
            with self.subTest(system=system, machine=machine), \
                 patch.object(acquire_openusd_sdk.platform, "system", return_value=system), \
                 patch.object(acquire_openusd_sdk.platform, "machine", return_value=machine):
                self.assertEqual(acquire_openusd_sdk.host_target(), expected)

    def test_unsupported_native_targets_fail(self):
        for system, machine in [("Darwin", "arm64"), ("Windows", "ARM64"),
                                ("Linux", "riscv64")]:
            with self.subTest(system=system, machine=machine), \
                 patch.object(acquire_openusd_sdk.platform, "system", return_value=system), \
                 patch.object(acquire_openusd_sdk.platform, "machine", return_value=machine):
                with self.assertRaisesRegex(acquire_openusd_sdk.AcquisitionError,
                                            "no qualified Kit OpenUSD package"):
                    acquire_openusd_sdk.host_target()

    def test_wrong_archive_fails_without_download(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "cached.7z"
            archive.write_bytes(b"wrong platform or corrupted archive")
            with patch.object(acquire_openusd_sdk, "_download") as download:
                for package in acquire_openusd_sdk.PACKAGES.values():
                    with self.assertRaisesRegex(acquire_openusd_sdk.AcquisitionError,
                                                "cached archive SHA-256"):
                        acquire_openusd_sdk._checked_archive(archive, package)
                download.assert_not_called()
            self.assertEqual(archive.read_bytes(), b"wrong platform or corrupted archive")

    def test_windows_layout_requires_import_library_and_runtime(self):
        package = acquire_openusd_sdk.PACKAGES["windows-x86_64"]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ["pxrConfig.cmake", "cmake/pxrTargets.cmake",
                         "include/pxr/usd/ar/resolver.h", "lib/ov_25.11usd_ms.dll",
                         "lib/ov_25.11usd_ms.lib", "lib/tbb.lib", "bin/tbb12.dll"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture")
            marker = root / acquire_openusd_sdk.PROVENANCE_FILE
            marker.write_text(json.dumps(package.provenance))
            acquire_openusd_sdk._validate_sdk(root, package, require_provenance=True)
            for name in ["lib/ov_25.11usd_ms.lib", "bin/tbb12.dll"]:
                path = root / name
                path.unlink()
                with self.assertRaisesRegex(acquire_openusd_sdk.AcquisitionError,
                                            "missing required files"):
                    acquire_openusd_sdk._validate_sdk(root, package, require_provenance=True)
                path.write_bytes(b"fixture")
            marker.write_text(json.dumps(acquire_openusd_sdk.PACKAGES["linux-x86_64"].provenance))
            with self.assertRaisesRegex(acquire_openusd_sdk.AcquisitionError,
                                        "provenance does not match"):
                acquire_openusd_sdk._validate_sdk(root, package, require_provenance=True)


if __name__ == "__main__":
    unittest.main()
