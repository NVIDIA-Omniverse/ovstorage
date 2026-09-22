# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Extract perf results and run the report-only regression comparison."""

from __future__ import annotations

import argparse
from pathlib import Path

import _perf_report
from _repo import run_task

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract = subparsers.add_parser(
        "extract-criterion",
        help="flatten criterion estimates into one JSON document",
    )
    extract.add_argument(
        "--criterion-dir",
        type=Path,
        default=Path("target/criterion"),
        help="criterion output directory (default: target/criterion)",
    )
    extract.add_argument("--commit", required=True, help="commit SHA to record")
    extract.add_argument(
        "--output", type=Path, required=True, help="path of the JSON document to write"
    )

    compare = subparsers.add_parser(
        "compare",
        help="report-only comparison of a live run against prior-run history",
    )
    compare.add_argument(
        "--current", type=Path, required=True, help="current live-run JSON document"
    )
    compare.add_argument(
        "--history-dir",
        type=Path,
        required=True,
        help="directory of prior live-run JSON documents (may be empty or absent)",
    )
    compare.add_argument(
        "--output-md",
        type=Path,
        required=True,
        help="path of the markdown summary to write",
    )

    args = parser.parse_args()
    if args.command == "extract-criterion":
        run_task(
            lambda: _perf_report.extract_criterion(
                args.criterion_dir, args.commit, args.output
            )
        )
    else:
        run_task(
            lambda: _perf_report.compare(args.current, args.history_dir, args.output_md)
        )
