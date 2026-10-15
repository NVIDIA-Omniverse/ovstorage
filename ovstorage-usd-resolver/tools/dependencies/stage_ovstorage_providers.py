# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Stage source-built runtime providers using ovstorage's public wheel policy."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


def stage(storage: Path) -> Path:
    destination = storage / "plugins"
    if destination.exists():
        raise ValueError(f"runtime provider directory already exists; remove {destination} and restage, "
                         "or use a fresh storage tree")
    names = json.loads(subprocess.check_output(
        [sys.executable, "-c",
         "import sys, json; sys.path.insert(0, sys.argv[1]); "
         "import _dist; print(json.dumps(_dist.wheel_plugin_filenames()))",
         str(storage / "tools/ovtasks")], text=True))
    if not names or len(names) != len(set(names)):
        raise ValueError("storage runtime provider inventory is empty or contains duplicates")
    for name in names:
        if not isinstance(name, str) or Path(name).name != name or name in (".", "..") or "\\" in name:
            raise ValueError("invalid storage runtime provider filename")
        source = storage / "dist/plugins" / name
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"source-built runtime provider missing: {name}")
    destination.mkdir()
    for name in names:
        shutil.copy2(storage / "dist/plugins" / name, destination / name)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ovstorage-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(stage(args.ovstorage_root.resolve()))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"provider staging: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
