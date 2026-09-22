# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the perf-report heuristic and the criterion extractor.

The compare heuristic is the piece worth pinning: it is the difference
between a nightly perf signal people trust and one they mute. Every gate in
the AND-chain (minimum history, effect-size floor, IQR fence, two-run
confirmation, file-backend control) exists to kill a specific false-positive
mode, so each has a test proving it suppresses that mode and one proving a
genuine sustained regression still alerts. Latency and TTFB are the
evaluated metrics; throughput is render-only (it is size/p50 by
construction), and the direction-flip machinery is pinned at the
``_breaches`` level.

``evaluate`` is pure (documents in, report out) and the tests drive it
directly; one end-to-end case goes through ``compare`` to cover the file IO,
markdown, and always-exit-0 contract.
"""

import json

import _perf_report as pr
from _repo import TaskError

import pytest


def _cell(backend, size, mode, p50, throughput=None, p99=None, ttfb=None):
    stats = {
        "count": 10,
        "p50_ms": p50,
        "p90_ms": p50 * 1.2,
        "p99_ms": p99,
        "min_ms": p50 * 0.9,
        "max_ms": p50 * 1.5,
        "mean_ms": p50 * 1.05,
        "iqr_ms": p50 * 0.1,
        "throughput_mbps": throughput,
        "ttfb_p50_ms": ttfb,
        "ttfb_p90_ms": ttfb if ttfb is None else ttfb * 1.2,
    }
    return {
        "backend": backend,
        "size_bytes": size,
        "mode": mode,
        "samples_ms": [p50] * 10,
        "cold_ms": p50 * 2,
        "stats": stats,
    }


def _run(timestamp, cells):
    return {
        "schema_version": 1,
        "kind": "ovstorage-perf-live",
        "commit": "0" * 40,
        "run_id": "1",
        "run_attempt": "1",
        "timestamp": timestamp,
        "runner": {"os": "linux", "cpu_model": "test", "cpu_cores": 4},
        "cells": cells,
    }


def _history(values, backend="s3", *, control=100.0):
    """One run per value: `backend` p50 = value, `file` control p50 stable."""
    return [
        _run(
            f"2026-08-{day:02d}T00:00:00+00:00",
            [
                _cell(backend, 4096, "read_bytes", value),
                _cell("file", 4096, "read_bytes", control),
            ],
        )
        for day, value in enumerate(values, start=1)
    ]


def _row(report, backend, metric="p50_ms"):
    rows = [
        row
        for row in report.rows
        if row.backend == backend and row.metric == metric
    ]
    assert len(rows) == 1
    return rows[0]


# --- minimum history --------------------------------------------------------


def test_no_history_records_only():
    current = _run("2026-08-20T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 500)])
    report = pr.evaluate(current, [])
    assert _row(report, "s3").status.startswith(pr.STATUS_RECORDING)
    assert report.alerts == []


def test_short_history_records_only():
    history = _history([100, 100, 100])
    current = _run("2026-08-20T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 500)])
    report = pr.evaluate(current, history)
    assert _row(report, "s3").status == f"{pr.STATUS_RECORDING} (3/{pr.MIN_HISTORY})"
    assert report.alerts == []


# --- the AND-chain, gate by gate --------------------------------------------


def test_clean_run_is_ok():
    history = _history([100, 102, 98, 101, 99])
    current = _run("2026-08-20T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 101)])
    report = pr.evaluate(current, history)
    assert _row(report, "s3").status == pr.STATUS_OK
    assert report.alerts == []


def test_first_breach_is_watch_not_alert():
    history = _history([100, 100, 100, 100, 100])
    current = _run("2026-08-20T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 150)])
    report = pr.evaluate(current, history)
    assert _row(report, "s3").status == pr.STATUS_WATCH
    assert report.alerts == []


def test_second_consecutive_breach_alerts():
    history = _history([100, 100, 100, 100, 100, 150])
    current = _run("2026-08-21T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 150)])
    report = pr.evaluate(current, history)
    row = _row(report, "s3")
    assert row.status == pr.STATUS_ALERT
    assert row.delta_pct == pytest.approx(50.0)
    assert len(report.alerts) == 1


def test_breach_right_after_the_recording_phase_is_watch_not_alert():
    # With exactly MIN_HISTORY points [100, 100, 100, 100, 150] the window is
    # judgeable, but the previous run's own baseline was only four points —
    # still recording — so its breach confirms nothing yet.
    history = _history([100, 100, 100, 100, 150])
    current = _run("2026-08-21T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 150)])
    report = pr.evaluate(current, history)
    assert _row(report, "s3").status == pr.STATUS_WATCH
    assert report.alerts == []


def test_a_gap_night_between_breaches_is_watch_not_alert():
    # The cell breached two nights ago, was missing last night, and breaches
    # again tonight. Confirmation reads the immediately previous run
    # specifically, so non-consecutive breaches never confirm.
    history = _history([100, 100, 100, 100, 100, 150])
    history.append(
        _run("2026-08-07T00:00:00+00:00", [_cell("file", 4096, "read_bytes", 100)])
    )
    current = _run("2026-08-21T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 150)])
    report = pr.evaluate(current, history)
    assert _row(report, "s3").status == pr.STATUS_WATCH
    assert report.alerts == []


def test_control_breach_downgrades_to_suspected_noise():
    history = _history([100, 100, 100, 100, 100, 150])
    # The control cell regresses in step with s3: blame the runner.
    current = _run(
        "2026-08-21T00:00:00+00:00",
        [
            _cell("s3", 4096, "read_bytes", 150),
            _cell("file", 4096, "read_bytes", 200),
        ],
    )
    report = pr.evaluate(current, history)
    assert _row(report, "s3").status == pr.STATUS_SUSPECT
    assert report.alerts == []


def test_thin_control_window_cannot_veto_a_confirmed_alert():
    # The control series has only two points — below MIN_HISTORY, so its own
    # row is held at "recording" — and those same two points must not be
    # trusted to veto a twice-confirmed 50% cloud regression: sub-millisecond
    # local reads wobble past the 20% floor on ordinary noise.
    values = [100, 100, 100, 100, 100, 150]
    history = []
    for day, value in enumerate(values, start=1):
        cells = [_cell("s3", 4096, "read_bytes", value)]
        if day >= 5:
            cells.append(_cell("file", 4096, "read_bytes", 0.40 + 0.01 * (day - 5)))
        history.append(_run(f"2026-08-{day:02d}T00:00:00+00:00", cells))
    current = _run(
        "2026-08-21T00:00:00+00:00",
        [
            _cell("s3", 4096, "read_bytes", 150),
            _cell("file", 4096, "read_bytes", 0.50),
        ],
    )
    report = pr.evaluate(current, history)
    assert _row(report, "file").status.startswith(pr.STATUS_RECORDING)
    assert _row(report, "s3").status == pr.STATUS_ALERT
    assert len(report.alerts) == 1


def test_iqr_zero_cell_still_needs_the_effect_floor():
    history = _history([100, 100, 100, 100, 100, 100])
    # A perfectly stable window has IQR 0, so the fence alone would flag any
    # increase; the 20% floor is what keeps a 10% wobble quiet.
    current = _run("2026-08-21T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 110)])
    report = pr.evaluate(current, history)
    assert _row(report, "s3").status == pr.STATUS_OK
    assert report.alerts == []


def test_noisy_window_iqr_fence_suppresses_a_20pct_swing():
    # Median 100 but a wide spread: 130 is >= 20% worse yet inside the fence.
    history = _history([60, 80, 100, 120, 140, 100])
    current = _run("2026-08-21T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 130)])
    report = pr.evaluate(current, history)
    assert _row(report, "s3").status == pr.STATUS_OK


# --- direction handling -----------------------------------------------------


def _throughput_history(values):
    return [
        _run(
            f"2026-08-{day:02d}T00:00:00+00:00",
            [
                _cell("s3", 4096, "read_bytes", 100, throughput=value),
                _cell("file", 4096, "read_bytes", 100, throughput=500.0),
            ],
        )
        for day, value in enumerate(values, start=1)
    ]


def test_throughput_is_rendered_but_never_evaluated():
    # throughput_mbps is size_bytes / p50_ms by construction, so evaluating
    # it beside p50 would double-report every regression. A sustained 30%
    # throughput drop must therefore produce no throughput rows at all —
    # the drop surfaces through p50 or not at all.
    history = _throughput_history([200, 200, 200, 200, 200, 140])
    current = _run(
        "2026-08-21T00:00:00+00:00",
        [_cell("s3", 4096, "read_bytes", 100, throughput=140)],
    )
    report = pr.evaluate(current, history)
    assert all(row.metric != "throughput_mbps" for row in report.rows)
    assert report.alerts == []


def test_breaches_direction_flip_for_larger_is_better():
    # The direction machinery stays load-bearing for larger-is-better metrics
    # even with none currently in METRICS, so it is pinned at the
    # `_breaches` level.
    window = [200.0] * 5
    assert pr._breaches(140.0, window, True)  # a 30% drop breaches
    assert not pr._breaches(300.0, window, True)  # an improvement never does
    assert pr._breaches(300.0, window, False)  # same numbers, latency flips
    assert not pr._breaches(140.0, window, False)


def test_breaches_flipped_fence_suppresses_a_drop_inside_noise():
    # Sorted [60, 80, 100, 100, 120, 140]: median 100, inclusive IQR 30, so
    # the flipped fence floor is 100 - 3 * 30 = 10. A drop to 70 is a 30%
    # effect but sits far inside the fence — a noisy series stays quiet.
    window = [140.0, 120.0, 100.0, 80.0, 60.0, 100.0]
    assert not pr._breaches(70.0, window, True)


def _ttfb_history(values):
    return [
        _run(
            f"2026-08-{day:02d}T00:00:00+00:00",
            [
                _cell("s3", 4096, "read_stream", 100, ttfb=value),
                _cell("file", 4096, "read_stream", 100, ttfb=5.0),
            ],
        )
        for day, value in enumerate(values, start=1)
    ]


def test_ttfb_regression_alerts_independently_of_total_time():
    # An extra round trip before the first byte moves TTFB but is diluted in
    # total time on transfer-dominated cells; TTFB is evaluated as its own
    # metric so that regression still surfaces.
    history = _ttfb_history([20, 20, 20, 20, 20, 30])
    current = _run(
        "2026-08-21T00:00:00+00:00",
        [
            _cell("s3", 4096, "read_stream", 100, ttfb=30),
            _cell("file", 4096, "read_stream", 100, ttfb=5.0),
        ],
    )
    report = pr.evaluate(current, history)
    assert _row(report, "s3", "ttfb_p50_ms").status == pr.STATUS_ALERT
    assert _row(report, "s3", "p50_ms").status == pr.STATUS_OK
    assert len(report.alerts) == 1


def test_cells_without_ttfb_produce_no_ttfb_rows():
    history = _history([100, 100, 100, 100, 100])
    current = _run("2026-08-20T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 100)])
    report = pr.evaluate(current, history)
    assert all(row.metric != "ttfb_p50_ms" for row in report.rows)


def test_p99_is_never_evaluated():
    history = _history([100, 100, 100, 100, 100, 100])
    current = _run(
        "2026-08-21T00:00:00+00:00",
        [_cell("s3", 4096, "read_bytes", 100, p99=100000.0)],
    )
    report = pr.evaluate(current, history)
    assert all(row.metric != "p99_ms" for row in report.rows)
    assert report.alerts == []


# --- shape changes and malformed input --------------------------------------


def test_disappeared_cell_is_noted():
    history = _history([100, 100, 100, 100, 100])
    current = _run("2026-08-20T00:00:00+00:00", [_cell("file", 4096, "read_bytes", 100)])
    report = pr.evaluate(current, history)
    assert any("missing from the current run" in note for note in report.notes)


def _write_history_run(history_dir, name, content):
    run_dir = history_dir / name
    run_dir.mkdir(parents=True)
    (run_dir / "results.json").write_text(content, encoding="utf-8")
    (run_dir / "compare.md").write_text("prior report\n", encoding="utf-8")


def test_history_reads_only_results_json_per_run_directory(tmp_path):
    # The CI job materializes history as one directory per prior run, each
    # with results.json beside the rendered compare.md; ordering must come
    # from the timestamp inside the document, not the directory name.
    late = _run("2026-08-02T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 200)])
    early = _run("2026-08-01T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 100)])
    _write_history_run(tmp_path, "run-a", json.dumps(late))
    _write_history_run(tmp_path, "run-b", json.dumps(early))
    (tmp_path / "run-a" / "stray.json").write_text("{not json", encoding="utf-8")
    notes = []
    runs = pr.load_history(tmp_path, notes)
    assert [run["timestamp"] for run in runs] == [
        "2026-08-01T00:00:00+00:00",
        "2026-08-02T00:00:00+00:00",
    ]
    assert notes == []


def test_malformed_history_file_is_skipped_with_note(tmp_path):
    good = _run("2026-08-01T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 100)])
    _write_history_run(tmp_path, "run-good", json.dumps(good))
    _write_history_run(tmp_path, "run-bad", "{not json")
    _write_history_run(tmp_path, "run-foreign", json.dumps({"kind": "other"}))
    notes = []
    runs = pr.load_history(tmp_path, notes)
    assert len(runs) == 1
    assert len(notes) == 2


def test_missing_history_dir_is_empty_history(tmp_path):
    notes = []
    assert pr.load_history(tmp_path / "absent", notes) == []
    assert notes


def test_history_run_with_a_malformed_cell_is_skipped_with_note(tmp_path):
    # A document that parses and carries the right kind but holds a cell the
    # heuristic cannot key must be skipped whole, never crash the compare.
    good = _run("2026-08-01T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 100)])
    missing_keys = _run("2026-08-02T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 100)])
    missing_keys["cells"].append({"backend": "s3"})
    non_dict = _run("2026-08-03T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 100)])
    non_dict["cells"].append("not a cell")
    _write_history_run(tmp_path, "run-good", json.dumps(good))
    _write_history_run(tmp_path, "run-missing-keys", json.dumps(missing_keys))
    _write_history_run(tmp_path, "run-non-dict", json.dumps(non_dict))
    notes = []
    runs = pr.load_history(tmp_path, notes)
    assert len(runs) == 1
    assert len(notes) == 2


# --- end to end through compare ---------------------------------------------


def test_compare_end_to_end_writes_markdown_and_exits_zero(tmp_path, capsys):
    history_dir = tmp_path / "history"
    history_dir.mkdir()
    for index, run in enumerate(_history([100, 100, 100, 100, 100, 150])):
        _write_history_run(history_dir, f"run-{index}", json.dumps(run))
    current = _run("2026-08-21T00:00:00+00:00", [_cell("s3", 4096, "read_bytes", 150)])
    current_path = tmp_path / "current.json"
    current_path.write_text(json.dumps(current), encoding="utf-8")
    output_md = tmp_path / "summary.md"

    # Report-only contract: an alert is annotations + markdown, never a raise.
    pr.compare(current_path, history_dir, output_md)

    out = capsys.readouterr().out
    assert "::warning title=ovstorage perf regression::" in out
    markdown = output_md.read_text(encoding="utf-8")
    assert "| s3 | 4 KiB | read_bytes | p50_ms |" in markdown
    assert pr.STATUS_ALERT in markdown


def test_compare_rejects_a_foreign_current_document(tmp_path):
    current_path = tmp_path / "current.json"
    current_path.write_text(json.dumps({"kind": "other"}), encoding="utf-8")
    with pytest.raises(TaskError):
        pr.compare(current_path, tmp_path, tmp_path / "summary.md")


# --- extract-criterion ------------------------------------------------------


def _estimates(mean, median, std_dev):
    def entry(value):
        return {
            "confidence_interval": {
                "confidence_level": 0.95,
                "lower_bound": value,
                "upper_bound": value,
            },
            "point_estimate": value,
            "standard_error": 0.0,
        }

    return {
        "mean": entry(mean),
        "median": entry(median),
        "median_abs_dev": entry(0.0),
        "slope": None,
        "std_dev": entry(std_dev),
    }


def test_extract_criterion_flattens_a_fabricated_tree(tmp_path):
    criterion_dir = tmp_path / "criterion"
    with_id = criterion_dir / "stack_read" / "read_bytes_4k" / "new"
    with_id.mkdir(parents=True)
    (with_id / "estimates.json").write_text(
        json.dumps(_estimates(1000.0, 990.0, 25.0)), encoding="utf-8"
    )
    (with_id / "benchmark.json").write_text(
        json.dumps({"full_id": "stack_read/read_bytes_4k"}), encoding="utf-8"
    )
    without_id = criterion_dir / "address" / "canonicalize" / "new"
    without_id.mkdir(parents=True)
    (without_id / "estimates.json").write_text(
        json.dumps(_estimates(50.0, 49.0, 2.0)), encoding="utf-8"
    )
    # Criterion also keeps `base/` (the saved baseline) and `change/` (the
    # relative delta, fractional values) beside `new/`; only `new/` is data.
    for sibling, estimates in (
        ("base", _estimates(2000.0, 1990.0, 30.0)),
        ("change", _estimates(0.03, 0.02, 0.01)),
    ):
        sibling_dir = criterion_dir / "stack_read" / "read_bytes_4k" / sibling
        sibling_dir.mkdir(parents=True)
        (sibling_dir / "estimates.json").write_text(
            json.dumps(estimates), encoding="utf-8"
        )

    output = tmp_path / "micro.json"
    pr.extract_criterion(criterion_dir, "abc123", output)

    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["kind"] == "ovstorage-perf-micro"
    assert document["commit"] == "abc123"
    ids = [bench["id"] for bench in document["benches"]]
    assert ids == ["address/canonicalize", "stack_read/read_bytes_4k"]
    assert document["benches"][1]["mean_ns"] == 1000.0
    assert document["benches"][0]["median_ns"] == 49.0


def test_extract_criterion_empty_tree_is_an_error(tmp_path):
    empty = tmp_path / "criterion"
    empty.mkdir()
    with pytest.raises(TaskError):
        pr.extract_criterion(empty, "abc123", tmp_path / "out.json")
