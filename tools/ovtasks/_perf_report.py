# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Perf-result extraction and report-only regression comparison.

Two commands share this module (entry script ``perf_report.py``):

``extract-criterion``
    Flattens criterion's per-benchmark ``new/estimates.json`` files into one
    machine-readable document, so a CI run can upload a single artifact
    instead of the whole ``target/criterion`` tree. Criterion's on-disk
    layout is undocumented-but-stable; the criterion version is pinned in the
    workspace, and this reader takes only the three point estimates it needs.

``compare``
    Evaluates the current live read-perf run against a moving window of prior
    nightly runs. The heuristic is deliberately conservative because live
    cloud numbers from hosted runners are noisy in ways single-baseline diffs
    misread: a cell alerts only when every condition holds —

    * at least ``MIN_HISTORY`` prior points exist (record-only before that);
    * the current median is at least ``MIN_EFFECT`` worse than the window
      median (the floor that keeps ultra-stable cells with IQR ~ 0 from
      alerting on trivia);
    * the current value falls outside window median +/- ``IQR_FENCE`` * IQR
      (the outlier-robust fence that keeps naturally noisy cells quiet);
    * the immediately previous run also breached, judged against its own
      at-least-``MIN_HISTORY``-point baseline (one-off network blips never
      confirm twice, and a breach cannot be confirmed by a run that was
      itself still recording or missing the cell); and
    * the ``file`` backend's matching cell did not also breach — the local
      control shares runner hardware but no network, so a simultaneous
      control breach marks the alert as suspected runner noise instead. The
      control only gets that veto once its own window has ``MIN_HISTORY``
      points; a control series too thin to judge is too thin to veto.

    A real regression rolls into the window after ~``MIN_HISTORY`` nights and
    silently becomes the new baseline; that is inherent to moving windows and
    acceptable because the alert fires before absorption.

    ``compare`` always exits 0 apart from usage/IO errors: this stage is
    report-only by contract, and a wrong number must never block CI.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from _repo import TaskError, eprint

SCHEMA_VERSION = 1
LIVE_KIND = "ovstorage-perf-live"
MICRO_KIND = "ovstorage-perf-micro"

MIN_HISTORY = 5
MIN_EFFECT = 0.20
IQR_FENCE = 3.0

# The control backend runs against local disk: it shares the runner's
# hardware-lottery and noisy-neighbour exposure with the cloud cells but has
# no network leg, so it separates "the runner is slow tonight" from "the read
# path regressed".
CONTROL_BACKEND = "file"

# (metric key in ``stats``, True when larger values are better). p99 is
# recorded for humans but never evaluated: at nightly sample counts it is one
# or two worst-case samples wearing a percentile costume. throughput_mbps is
# ``size_bytes / p50_ms`` by construction (see ``CellStats::compute``), so
# evaluating it beside p50 would double-report every regression; MB/s stays
# in the rendered table because it is the number humans read. ttfb_p50_ms
# exists only on streaming-read cells; cells without a metric skip it.
METRICS = (("p50_ms", False), ("ttfb_p50_ms", False))


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- extract-criterion ------------------------------------------------------


def _point(estimates: dict, key: str) -> float | None:
    entry = estimates.get(key)
    if isinstance(entry, dict) and isinstance(
        entry.get("point_estimate"), (int, float)
    ):
        return float(entry["point_estimate"])
    return None


def extract_criterion(criterion_dir: Path, commit: str, output: Path) -> None:
    """Collect every ``**/new/estimates.json`` under ``criterion_dir``."""
    if not criterion_dir.is_dir():
        raise TaskError(f"criterion directory not found: {criterion_dir}")
    benches = []
    for estimates_path in sorted(criterion_dir.rglob("new/estimates.json")):
        try:
            estimates = json.loads(estimates_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as err:
            eprint(f"note: skipping unreadable {estimates_path}: {err}")
            continue
        new_dir = estimates_path.parent
        bench_id = None
        benchmark_path = new_dir / "benchmark.json"
        if benchmark_path.is_file():
            try:
                bench_id = json.loads(
                    benchmark_path.read_text(encoding="utf-8")
                ).get("full_id")
            except (OSError, ValueError):
                bench_id = None
        if not bench_id:
            bench_id = new_dir.parent.relative_to(criterion_dir).as_posix()
        benches.append(
            {
                "id": bench_id,
                "mean_ns": _point(estimates, "mean"),
                "median_ns": _point(estimates, "median"),
                "std_dev_ns": _point(estimates, "std_dev"),
            }
        )
    if not benches:
        raise TaskError(f"no criterion estimates found under {criterion_dir}")
    benches.sort(key=lambda bench: bench["id"])
    document = {
        "schema_version": SCHEMA_VERSION,
        "kind": MICRO_KIND,
        "commit": commit,
        "timestamp": _utc_now_iso(),
        "benches": benches,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(benches)} benchmark estimates to {output}")


# --- compare ----------------------------------------------------------------

# Row statuses, in the order a reader should worry about them.
STATUS_ALERT = "ALERT"
STATUS_SUSPECT = "suspected runner noise"
STATUS_WATCH = "watch (first breach)"
STATUS_OK = "ok"
STATUS_RECORDING = "recording"


@dataclass
class Row:
    backend: str
    size_bytes: int
    mode: str
    metric: str
    current: float
    window_median: float | None
    window_count: int
    delta_pct: float | None
    status: str


@dataclass
class Report:
    rows: list[Row] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def alerts(self) -> list[Row]:
        return [row for row in self.rows if row.status == STATUS_ALERT]


def _cell_key(cell: dict) -> tuple[str, int, str]:
    return (cell["backend"], cell["size_bytes"], cell["mode"])


def _metric_value(cell: dict | None, metric: str) -> float | None:
    if cell is None:
        return None
    value = cell.get("stats", {}).get(metric)
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _iqr(series: list[float]) -> float:
    if len(series) < 2:
        return 0.0
    quartiles = statistics.quantiles(series, n=4, method="inclusive")
    return quartiles[2] - quartiles[0]


def _breaches(current: float, window: list[float], larger_is_better: bool) -> bool:
    """The stateless core: effect-size floor AND the IQR fence, both required."""
    if not window:
        return False
    window_median = statistics.median(window)
    if window_median == 0:
        return False
    fence = IQR_FENCE * _iqr(window)
    if larger_is_better:
        return (
            (window_median - current) / window_median >= MIN_EFFECT
            and current < window_median - fence
        )
    return (
        (current - window_median) / window_median >= MIN_EFFECT
        and current > window_median + fence
    )


def _valid_cell(cell: object) -> bool:
    """A cell usable by the heuristic: the key fields `_cell_key` reads and a
    stats mapping. Anything less is malformed, and history loading must skip
    the whole document with a note rather than let a later lookup raise."""
    return (
        isinstance(cell, dict)
        and isinstance(cell.get("backend"), str)
        and isinstance(cell.get("size_bytes"), int)
        and not isinstance(cell.get("size_bytes"), bool)
        and isinstance(cell.get("mode"), str)
        and isinstance(cell.get("stats"), dict)
    )


def _load_run(path: Path) -> dict | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != SCHEMA_VERSION
        or document.get("kind") != LIVE_KIND
        or not isinstance(document.get("cells"), list)
        or not all(_valid_cell(cell) for cell in document["cells"])
    ):
        return None
    return document


def load_history(history_dir: Path, notes: list[str]) -> list[dict]:
    """Prior run documents, oldest first. A missing directory is an empty
    history (the first night has nothing to download), never an error.

    The CI job materializes one subdirectory per prior run, each holding that
    run's full artifact (``results.json`` plus the rendered ``compare.md``),
    so only ``results.json`` files are read and runs are ordered by the
    timestamp recorded inside each document, not by directory name."""
    if not history_dir.is_dir():
        notes.append(f"history directory {history_dir} not found; treating as empty")
        return []
    runs = []
    for path in sorted(history_dir.rglob("results.json")):
        document = _load_run(path)
        if document is None:
            notes.append(
                f"skipped malformed or foreign history file {path.parent.name}/{path.name}"
            )
            continue
        runs.append(document)
    runs.sort(key=lambda run: str(run.get("timestamp", "")))
    return runs


def _series(history: list[dict], key: tuple[str, int, str], metric: str) -> list[float]:
    values = []
    for run in history:
        cells = {_cell_key(cell): cell for cell in run["cells"]}
        value = _metric_value(cells.get(key), metric)
        if value is not None:
            values.append(value)
    return values


def _previous_run_confirmed(
    history: list[dict], key: tuple[str, int, str], metric: str,
    larger_is_better: bool,
) -> bool:
    """True when the metric exists in the immediately previous run
    (``history[-1]``) and that value breached against its own baseline — the
    runs before it — with at least ``MIN_HISTORY`` baseline points. A cell
    absent from the previous run cannot confirm tonight's breach (the two
    breaches would not be consecutive), and a prior breach judged against a
    still-recording baseline is no confirmation either."""
    if not history:
        return False
    previous_cells = {_cell_key(cell): cell for cell in history[-1]["cells"]}
    previous = _metric_value(previous_cells.get(key), metric)
    if previous is None:
        return False
    baseline = _series(history[:-1], key, metric)
    if len(baseline) < MIN_HISTORY:
        return False
    return _breaches(previous, baseline, larger_is_better)


def _control_breached(
    current_cells: dict, history: list[dict], key: tuple[str, int, str], metric: str,
    larger_is_better: bool,
) -> bool:
    control_key = (CONTROL_BACKEND, key[1], key[2])
    control_current = _metric_value(current_cells.get(control_key), metric)
    if control_current is None:
        return False
    control_window = _series(history, control_key, metric)
    # Same gate the main path applies: a control window too thin to judge on
    # its own is too thin to veto another cell's confirmed alert.
    if len(control_window) < MIN_HISTORY:
        return False
    return _breaches(control_current, control_window, larger_is_better)


def evaluate(current: dict, history: list[dict]) -> Report:
    """Pure evaluation of one run against its history; no IO."""
    report = Report()
    current_cells = {_cell_key(cell): cell for cell in current["cells"]}
    current_keys = set(current_cells)
    historical_keys = {
        _cell_key(cell) for run in history for cell in run["cells"]
    }
    for key in sorted(historical_keys - current_keys):
        report.notes.append(
            f"cell {key[0]}/{key[1]}/{key[2]} present in history but missing "
            "from the current run"
        )

    for key in sorted(current_keys):
        cell = current_cells[key]
        for metric, larger_is_better in METRICS:
            value = _metric_value(cell, metric)
            if value is None:
                continue
            window = _series(history, key, metric)
            row = Row(
                backend=key[0],
                size_bytes=key[1],
                mode=key[2],
                metric=metric,
                current=value,
                window_median=statistics.median(window) if window else None,
                window_count=len(window),
                delta_pct=None,
                status=STATUS_OK,
            )
            if row.window_median:
                row.delta_pct = (value - row.window_median) / row.window_median * 100
            if len(window) < MIN_HISTORY:
                row.status = f"{STATUS_RECORDING} ({len(window)}/{MIN_HISTORY})"
                report.rows.append(row)
                continue
            if not _breaches(value, window, larger_is_better):
                report.rows.append(row)
                continue
            # Confirmation: the immediately previous run must also have
            # breached, judged against its own fully-recorded baseline, so a
            # single bad night — or one landing right after the recording
            # phase — never alerts.
            if not _previous_run_confirmed(history, key, metric, larger_is_better):
                row.status = STATUS_WATCH
            elif key[0] != CONTROL_BACKEND and _control_breached(
                current_cells, history, key, metric, larger_is_better
            ):
                row.status = STATUS_SUSPECT
            else:
                row.status = STATUS_ALERT
            report.rows.append(row)
    return report


def _format_size(size_bytes: int) -> str:
    if size_bytes % (1024 * 1024) == 0:
        return f"{size_bytes // (1024 * 1024)} MiB"
    if size_bytes % 1024 == 0:
        return f"{size_bytes // 1024} KiB"
    return f"{size_bytes} B"


def _format_value(metric: str, value: float | None) -> str:
    if value is None:
        return "-"
    unit = "MB/s" if metric == "throughput_mbps" else "ms"
    return f"{value:.2f} {unit}"


def render_markdown(current: dict, report: Report) -> str:
    lines = [
        "## ovstorage live read-perf report",
        "",
        f"- commit: `{current.get('commit', 'unknown')}`",
        f"- run: {current.get('run_id', '?')} (attempt "
        f"{current.get('run_attempt', '?')}) at {current.get('timestamp', '?')}",
        f"- runner: {current.get('runner', {}).get('os', '?')}, "
        f"{current.get('runner', {}).get('cpu_model', '?')} "
        f"({current.get('runner', {}).get('cpu_cores', '?')} cores)",
        "",
        "| Backend | Size | Mode | Metric | Current | Window median (n) | Δ% | Status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in report.rows:
        median = _format_value(row.metric, row.window_median)
        window = f"{median} ({row.window_count})" if row.window_count else "-"
        delta = f"{row.delta_pct:+.1f}%" if row.delta_pct is not None else "-"
        lines.append(
            f"| {row.backend} | {_format_size(row.size_bytes)} | {row.mode} "
            f"| {row.metric} | {_format_value(row.metric, row.current)} "
            f"| {window} | {delta} | {row.status} |"
        )
    if report.notes:
        lines += ["", "### Notes", ""]
        lines += [f"- {note}" for note in report.notes]
    lines += [
        "",
        "_Report-only: this check never fails the job. Alerts require a "
        f"{MIN_EFFECT:.0%} effect outside {IQR_FENCE:g}×IQR of the "
        f"{MIN_HISTORY}+-run window, confirmed on two consecutive runs, with "
        "the local `file` control quiet._",
        "",
    ]
    return "\n".join(lines)


def emit_annotations(report: Report) -> None:
    """GitHub workflow commands for alerts; plain notes for everything else."""
    for row in report.alerts:
        print(
            "::warning title=ovstorage perf regression::"
            f"{row.backend} {_format_size(row.size_bytes)} {row.mode} "
            f"{row.metric}: {_format_value(row.metric, row.current)} vs window "
            f"median {_format_value(row.metric, row.window_median)} "
            f"({row.delta_pct:+.1f}%)"
        )
    for row in report.rows:
        if row.status in (STATUS_WATCH, STATUS_SUSPECT):
            print(
                f"note: {row.backend} {_format_size(row.size_bytes)} "
                f"{row.mode} {row.metric}: {row.status}"
            )
    for note in report.notes:
        print(f"note: {note}")


def compare(current_path: Path, history_dir: Path, output_md: Path) -> None:
    try:
        current = json.loads(current_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise TaskError(f"cannot read current results {current_path}: {err}")
    if (
        not isinstance(current, dict)
        or current.get("schema_version") != SCHEMA_VERSION
        or current.get("kind") != LIVE_KIND
        or not isinstance(current.get("cells"), list)
        or not all(_valid_cell(cell) for cell in current["cells"])
    ):
        raise TaskError(
            f"{current_path} is not a well-formed schema-version-{SCHEMA_VERSION} "
            f"{LIVE_KIND} document"
        )
    notes: list[str] = []
    history = load_history(history_dir, notes)
    report = evaluate(current, history)
    report.notes = notes + report.notes
    if not history:
        report.notes.append(
            "no usable history yet; recording this run as the first baseline point"
        )
    try:
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(render_markdown(current, report), encoding="utf-8")
    except OSError as err:
        raise TaskError(f"cannot write {output_md}: {err}")
    emit_annotations(report)
    print(
        f"evaluated {len(report.rows)} metric cells against {len(history)} "
        f"prior runs: {len(report.alerts)} alert(s)"
    )
