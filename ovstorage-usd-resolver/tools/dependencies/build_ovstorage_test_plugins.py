# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Local-development helper to build providers from an ovstorage source checkout.

Not release qualification: wheel CI and candidates use the released PyPI bundle.
"""
import argparse
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    env = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0")
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=source, env=env))
    packages = {item["name"] for item in metadata["packages"]}
    command = ["cargo", "build", "--locked", "-j", "4"]
    for provider in ("http", "core", "s3", "huggingface"):
        base = f"ovstorage-plugin-{provider}"
        package = base + "-abi" if base + "-abi" in packages else base
        command.extend(["-p", package])
    subprocess.run(command, cwd=source, env=env, check=True)
    destination = source / "plugins"
    destination.mkdir(exist_ok=True)
    for provider in ("http", "core", "s3", "huggingface"):
        if sys.platform == "win32":
            name = f"ovstorage_plugin_{provider}.dll"
        elif sys.platform == "darwin":
            name = f"libovstorage_plugin_{provider}.dylib"
        else:
            name = f"libovstorage_plugin_{provider}.so"
        shutil.copy2(source / "target" / "debug" / name, destination / name)


if __name__ == "__main__":
    main()
