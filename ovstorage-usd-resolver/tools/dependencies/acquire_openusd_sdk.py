# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Acquire the exact OpenUSD SDK used to validate the 0.1 source release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path, PurePosixPath
from dataclasses import dataclass


PACKAGE_VERSION = "0.25.11.kit.4-gl.21081"


@dataclass(frozen=True)
class Package:
    platform: str
    sha256: str

    @property
    def name(self) -> str:
        return f"usd.nopy.{self.platform}.ov-full-monolithic.release"

    @property
    def archive_name(self) -> str:
        return f"{self.name}@{PACKAGE_VERSION}.7z"

    @property
    def url(self) -> str:
        return f"https://d4i3qtqj3r0z5.cloudfront.net/{self.archive_name}"

    @property
    def provenance(self) -> dict[str, str]:
        return {"package": self.name, "version": PACKAGE_VERSION,
                "url": self.url, "sha256": self.sha256}


PACKAGES = {
    "linux-x86_64": Package("manylinux_2_35_x86_64",
        "e89a24d8c7f9c315115204c40dbe0925e9689c8e3f330df12d44a05f6ee7745d"),
    "linux-aarch64": Package("manylinux_2_35_aarch64",
        "b808bca4f7202dd0dc38ead625c170d8da4ed3f0addb3f65f84c1e9ce0d36f58"),
    "windows-x86_64": Package("windows-x86_64",
        "4413994b5324eb3f830f8735a909aac2441ac1c4f8f84d87d5fb8f5e010d3bdb"),
}
PROVENANCE_FILE = ".ovs-openusd-sdk.json"

_SYMLINK_REPARSE_TAG = 0xA000000C
_REPARSE_HEADER = struct.Struct("<IHHHHHHI")


class AcquisitionError(RuntimeError):
    """The selected SDK could not be acquired or validated."""


def host_target() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    target = f"{system}-{machine}"
    if target not in PACKAGES:
        raise AcquisitionError(
            f"no qualified Kit OpenUSD package for {target}; supported SDK targets: "
            + ", ".join(PACKAGES))
    return target


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(archive: Path, package: Package) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    partial = archive.with_name(archive.name + ".partial")
    request = urllib.request.Request(
        package.url, headers={"User-Agent": "ovstorage-usd-resolver-source-build"}
    )
    last_error: Exception | None = None
    for attempt in range(1, 4):
        partial.unlink(missing_ok=True)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                with partial.open("wb") as output:
                    shutil.copyfileobj(response, output, length=1024 * 1024)
            break
        except Exception as exc:
            last_error = exc
            partial.unlink(missing_ok=True)
            if attempt < 3:
                time.sleep(2 * attempt)
    else:
        raise AcquisitionError(f"download failed after 3 attempts: {last_error}")

    actual = _sha256(partial)
    if actual != package.sha256:
        partial.unlink(missing_ok=True)
        raise AcquisitionError(
            f"downloaded archive SHA-256 is {actual}, expected {package.sha256}"
        )
    os.replace(partial, archive)


def _checked_archive(path: Path, package: Package) -> None:
    if not path.is_file():
        _download(path, package)
        return
    actual = _sha256(path)
    if actual != package.sha256:
        raise AcquisitionError(
            f"cached archive SHA-256 is {actual}, expected {package.sha256}: {path}"
        )


def _reparse_symlink_target(data: bytes) -> str | None:
    if len(data) < _REPARSE_HEADER.size:
        return None
    (
        tag,
        data_length,
        _reserved,
        substitute_offset,
        substitute_length,
        print_offset,
        print_length,
        _flags,
    ) = _REPARSE_HEADER.unpack_from(data)
    if tag != _SYMLINK_REPARSE_TAG:
        return None
    if data_length + 8 > len(data):
        raise AcquisitionError("truncated Windows symlink reparse record")

    path_buffer = data[_REPARSE_HEADER.size : data_length + 8]
    offset = print_offset if print_length else substitute_offset
    length = print_length if print_length else substitute_length
    if offset + length > len(path_buffer) or length % 2:
        raise AcquisitionError("invalid Windows symlink reparse record")
    try:
        target = path_buffer[offset : offset + length].decode("utf-16-le")
    except UnicodeDecodeError as exc:
        raise AcquisitionError("invalid Windows symlink target encoding") from exc

    target_path = PurePosixPath(target.replace("\\", "/"))
    if target_path.is_absolute() or ".." in target_path.parts:
        raise AcquisitionError(f"unsafe archive symlink target: {target}")
    if len(target_path.parts) != 1 or not target_path.name:
        raise AcquisitionError(f"unsupported archive symlink target: {target}")
    return target_path.name


def _repair_reparse_symlinks(root: Path) -> int:
    repaired = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
            continue
        target = _reparse_symlink_target(path.read_bytes())
        if target is None:
            continue
        if not (path.parent / target).exists():
            raise AcquisitionError(f"archive symlink target does not exist: {path} -> {target}")
        path.unlink()
        path.symlink_to(target)
        repaired += 1
    return repaired


def _validate_sdk(root: Path, package: Package, *, require_provenance: bool) -> None:
    windows = package.platform.startswith("windows-")
    required = (
        root / "pxrConfig.cmake",
        root / "cmake" / "pxrTargets.cmake",
        root / "include" / "pxr" / "usd" / "ar" / "resolver.h",
        root / "lib" / ("ov_25.11usd_ms.dll" if windows else "libov_25.11usd_ms.so"),
    )
    if windows:
        required += (root / "lib" / "ov_25.11usd_ms.lib",
                     root / "lib" / "tbb.lib", root / "bin" / "tbb12.dll")
    missing = [str(path.relative_to(root)) for path in required if not path.is_file()]
    if missing:
        raise AcquisitionError("SDK is missing required files: " + ", ".join(missing))
    if not windows and not (root / "lib" / "libtbb.so").is_symlink():
        raise AcquisitionError("SDK shared-library links were not restored")

    if not require_provenance:
        return
    marker = root / PROVENANCE_FILE
    try:
        provenance = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AcquisitionError(f"SDK provenance is missing or invalid: {marker}") from exc
    expected = package.provenance
    if provenance != expected:
        raise AcquisitionError(f"SDK provenance does not match the 0.1 target: {marker}")


def acquire(output: Path, archive_cache: Path | None = None,
            target: str | None = None) -> None:
    package = PACKAGES[target or host_target()]

    output = output.expanduser().resolve()
    if output.exists():
        _validate_sdk(output, package, require_provenance=True)
        print(f"OpenUSD SDK already present: {output}")
        return

    output.parent.mkdir(parents=True, exist_ok=True)
    cmake = shutil.which("cmake")
    if cmake is None:
        raise AcquisitionError("cmake is required to extract the OpenUSD archive")

    with tempfile.TemporaryDirectory(prefix=".openusd-sdk-", dir=output.parent) as temp:
        temp_root = Path(temp)
        archive = (
            archive_cache.expanduser().resolve()
            if archive_cache is not None
            else temp_root / package.archive_name
        )
        _checked_archive(archive, package)

        staging = temp_root / "sdk"
        staging.mkdir()
        completed = subprocess.run(
            [cmake, "-E", "tar", "xf", str(archive)],
            cwd=staging,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise AcquisitionError(f"archive extraction failed: {detail}")

        repaired = _repair_reparse_symlinks(staging)
        _validate_sdk(staging, package, require_provenance=False)
        provenance = package.provenance
        (staging / PROVENANCE_FILE).write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(staging, output)

    print(f"OpenUSD SDK: {output}")
    print(f"Package:     {package.name}@{PACKAGE_VERSION}")
    print(f"Links fixed: {repaired}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(".deps/openusd") / PACKAGE_VERSION,
        help="SDK destination (default: .deps/openusd/<package-version>)",
    )
    parser.add_argument(
        "--archive-cache",
        type=Path,
        help="optional persistent path for the verified downloaded archive",
    )
    parser.add_argument(
        "--target", choices=tuple(PACKAGES),
        help="SDK target (default: native host); explicit selection acquires only, "
             "it does not configure a cross compiler",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        acquire(args.output, args.archive_cache, args.target)
    except AcquisitionError as exc:
        print(f"OpenUSD SDK acquisition failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
