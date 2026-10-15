# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import stage_ovstorage_providers as providers


class ProviderStagingTests(unittest.TestCase):
    def fixture(self, directory):
        storage = Path(directory)
        (storage / "tools/ovtasks").mkdir(parents=True)
        (storage / "tools/ovtasks/_dist.py").write_text(
            "def wheel_plugin_filenames():\n"
            "    return ('libovstorage_plugin_core.so', 'libovstorage_plugin_http.so')\n")
        (storage / "dist/plugins").mkdir(parents=True)
        for name in ("core", "http", "test_abi"):
            (storage / f"dist/plugins/libovstorage_plugin_{name}.so").write_bytes(name.encode())
        return storage

    def test_copies_component_runtime_inventory_without_conformance_plugin(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = self.fixture(directory)
            destination = providers.stage(storage)
            self.assertEqual(sorted(p.name for p in destination.iterdir()),
                             ["libovstorage_plugin_core.so", "libovstorage_plugin_http.so"])
            self.assertEqual((destination / "libovstorage_plugin_http.so").read_bytes(), b"http")
            self.assertTrue((storage / "dist/plugins/libovstorage_plugin_test_abi.so").is_file())
            with self.assertRaisesRegex(ValueError, "already exists"):
                providers.stage(storage)

    def test_missing_provider_fails_before_creating_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            storage = self.fixture(directory)
            (storage / "dist/plugins/libovstorage_plugin_http.so").unlink()
            with self.assertRaisesRegex(ValueError, "missing"):
                providers.stage(storage)
            self.assertFalse((storage / "plugins").exists())


if __name__ == "__main__":
    unittest.main()
