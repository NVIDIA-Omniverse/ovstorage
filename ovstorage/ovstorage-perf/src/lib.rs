// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Measurement bookkeeping shared by the ovstorage performance harnesses:
//! the sample/percentile math, the `schema_version` 1 live-report JSON
//! contract, and a markdown rendering of a report for CI job summaries.
//!
//! The regression tooling consumes the JSON emitted from these types, so the
//! serialized shape is a cross-tool contract: field renames or semantic
//! changes require a `schema_version` bump, not an in-place edit.

use serde::{Deserialize, Serialize};

/// Version stamp of the serialized [`LiveReport`] shape.
pub const SCHEMA_VERSION: u32 = 1;

/// Discriminator naming the report family, so a reader can reject a JSON
/// document produced by some other tool before trusting its fields.
pub const REPORT_KIND: &str = "ovstorage-perf-live";

/// Warm samples below this count make an empirical p99 meaningless: under
/// the nearest-rank rule `round(p * (n - 1))` the p99 IS the maximum for
/// every n <= 51, so a 50-sample cell would report p99 == max. [`CellStats`]
/// reports `p99_ms: null` under this gate, and since the nightly matrix tops
/// out at 50 warm samples per cell, v1 records no p99 anywhere by design.
pub const P99_MIN_SAMPLES: usize = 100;

/// Which read-path operation a cell measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    ReadBytes,
    ReadStream,
    Stat,
}

impl Mode {
    /// Stable label used in benchmark ids and report tables.
    pub fn label(self) -> &'static str {
        match self {
            Mode::ReadBytes => "read_bytes",
            Mode::ReadStream => "read_stream",
            Mode::Stat => "stat",
        }
    }

    /// Whether the operation moves object bytes, i.e. whether a throughput
    /// figure is meaningful for it.
    pub fn moves_bytes(self) -> bool {
        !matches!(self, Mode::Stat)
    }
}

/// Identity of the machine that produced a run. Recorded because hosted CI
/// runners are drawn from heterogeneous hardware pools; without the CPU
/// model an outlier run cannot be told apart from a hardware-lottery draw.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunnerInfo {
    pub os: String,
    pub cpu_model: String,
    pub cpu_cores: u32,
}

impl RunnerInfo {
    /// Best-effort detection: `/proc/cpuinfo` is Linux-only, and absence
    /// degrades to `"unknown"` rather than an error so non-Linux dev runs
    /// still produce a valid report.
    pub fn detect() -> Self {
        let cpu_model = std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find(|line| line.starts_with("model name"))
                    .and_then(|line| line.split(':').nth(1))
                    .map(|model| model.trim().to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());
        let cpu_cores = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(0);
        Self {
            os: std::env::consts::OS.to_string(),
            cpu_model,
            cpu_cores,
        }
    }
}

/// Aggregates over one cell's warm samples.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CellStats {
    pub count: usize,
    pub p50_ms: f64,
    pub p90_ms: f64,
    /// `null` below [`P99_MIN_SAMPLES`] warm samples — see the constant.
    pub p99_ms: Option<f64>,
    pub min_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
    pub iqr_ms: f64,
    /// Decimal MB/s derived from the *median* sample (`size_bytes` /
    /// median seconds / 1e6); `null` for operations that move no bytes.
    /// Render-only downstream: it is an exact function of `p50_ms`, so the
    /// regression tooling evaluates p50 and leaves MB/s to human readers.
    pub throughput_mbps: Option<f64>,
    /// Warm time-to-first-chunk percentiles; only streaming reads record
    /// TTFB, so `null` elsewhere. Evaluated by the regression tooling as its
    /// own metric: an extra round trip before the first byte is diluted in
    /// total time on transfer-dominated cells.
    pub ttfb_p50_ms: Option<f64>,
    pub ttfb_p90_ms: Option<f64>,
}

impl CellStats {
    /// Compute aggregates over `samples_ms`; `throughput_bytes` names the
    /// per-operation payload size when the operation moves bytes.
    ///
    /// An empty sample set yields a zeroed record (count 0, `null`
    /// optionals) so a skipped cell still serializes without panicking.
    pub fn compute(samples_ms: &[f64], throughput_bytes: Option<u64>) -> Self {
        if samples_ms.is_empty() {
            return Self {
                count: 0,
                p50_ms: 0.0,
                p90_ms: 0.0,
                p99_ms: None,
                min_ms: 0.0,
                max_ms: 0.0,
                mean_ms: 0.0,
                iqr_ms: 0.0,
                throughput_mbps: None,
                ttfb_p50_ms: None,
                ttfb_p90_ms: None,
            };
        }
        let mut sorted = samples_ms.to_vec();
        sorted.sort_by(f64::total_cmp);
        let p50 = percentile(&sorted, 0.50);
        let p99 = (sorted.len() >= P99_MIN_SAMPLES).then(|| percentile(&sorted, 0.99));
        let throughput_mbps = throughput_bytes
            .and_then(|bytes| (p50 > 0.0).then(|| bytes as f64 / (p50 / 1_000.0) / 1_000_000.0));
        Self {
            count: sorted.len(),
            p50_ms: p50,
            p90_ms: percentile(&sorted, 0.90),
            p99_ms: p99,
            min_ms: sorted[0],
            max_ms: sorted[sorted.len() - 1],
            mean_ms: sorted.iter().sum::<f64>() / sorted.len() as f64,
            iqr_ms: percentile(&sorted, 0.75) - percentile(&sorted, 0.25),
            throughput_mbps,
            ttfb_p50_ms: None,
            ttfb_p90_ms: None,
        }
    }
}

/// One measured `(backend, size, mode)` combination.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cell {
    pub backend: String,
    pub size_bytes: u64,
    pub mode: Mode,
    /// Warm wall-time samples, in measurement order (not sorted), so a
    /// reader can inspect drift within a run. Cold samples are excluded.
    pub samples_ms: Vec<f64>,
    /// Warm time-to-first-chunk samples; only streaming reads have one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttfb_ms: Option<Vec<f64>>,
    /// The backend's first data-plane request of the run, measured before
    /// any fixture stat/put warmed the connection pool; `null` when the
    /// cell was not the first operation against its backend.
    pub cold_ms: Option<f64>,
    pub stats: CellStats,
}

impl Cell {
    /// Build a cell, deriving [`CellStats`] from the warm samples. The
    /// throughput figure is taken over `size_bytes` only when `mode` moves
    /// bytes; TTFB percentiles are derived when TTFB samples are present.
    pub fn from_samples(
        backend: impl Into<String>,
        size_bytes: u64,
        mode: Mode,
        samples_ms: Vec<f64>,
        ttfb_ms: Option<Vec<f64>>,
        cold_ms: Option<f64>,
    ) -> Self {
        let mut stats = CellStats::compute(&samples_ms, mode.moves_bytes().then_some(size_bytes));
        if let Some(ttfb) = &ttfb_ms
            && !ttfb.is_empty()
        {
            let mut sorted = ttfb.clone();
            sorted.sort_by(f64::total_cmp);
            stats.ttfb_p50_ms = Some(percentile(&sorted, 0.50));
            stats.ttfb_p90_ms = Some(percentile(&sorted, 0.90));
        }
        Self {
            backend: backend.into(),
            size_bytes,
            mode,
            samples_ms,
            ttfb_ms,
            cold_ms,
            stats,
        }
    }
}

/// The `schema_version` 1 live-report document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveReport {
    pub schema_version: u32,
    pub kind: String,
    pub commit: String,
    pub run_id: String,
    pub run_attempt: String,
    pub timestamp: String,
    pub runner: RunnerInfo,
    pub cells: Vec<Cell>,
}

impl LiveReport {
    pub fn new(
        commit: impl Into<String>,
        run_id: impl Into<String>,
        run_attempt: impl Into<String>,
        timestamp: impl Into<String>,
        runner: RunnerInfo,
        cells: Vec<Cell>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            kind: REPORT_KIND.to_string(),
            commit: commit.into(),
            run_id: run_id.into(),
            run_attempt: run_attempt.into(),
            timestamp: timestamp.into(),
            runner,
            cells,
        }
    }

    /// Serialize for upload as a CI artifact.
    ///
    /// # Errors
    ///
    /// Propagates `serde_json` serialization failure.
    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Render the per-cell aggregates as a GitHub-flavored markdown table
    /// for the job summary.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Read performance — commit `{}`, run {} (attempt {}), {} ({} × {} cores)\n\n",
            self.commit,
            self.run_id,
            self.run_attempt,
            self.runner.os,
            self.runner.cpu_model,
            self.runner.cpu_cores,
        ));
        out.push_str(
            "| backend | mode | size | n | p50 ms | p90 ms | max ms | ttfb p50 ms | MB/s | cold ms |\n",
        );
        out.push_str("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|\n");
        for cell in &self.cells {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {:.3} | {:.3} | {:.3} | {} | {} | {} |\n",
                cell.backend,
                cell.mode.label(),
                human_size(cell.size_bytes),
                cell.stats.count,
                cell.stats.p50_ms,
                cell.stats.p90_ms,
                cell.stats.max_ms,
                cell.stats
                    .ttfb_p50_ms
                    .map_or_else(|| "-".to_string(), |ms| format!("{ms:.3}")),
                cell.stats
                    .throughput_mbps
                    .map_or_else(|| "-".to_string(), |mbps| format!("{mbps:.1}")),
                cell.cold_ms
                    .map_or_else(|| "-".to_string(), |ms| format!("{ms:.3}")),
            ));
        }
        out
    }
}

/// Nearest-rank percentile over an ascending-sorted slice: index
/// `round(p * (n - 1))`. Callers guarantee `sorted` is non-empty.
pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    debug_assert!(!sorted.is_empty(), "percentile of an empty sample set");
    debug_assert!((0.0..=1.0).contains(&p), "percentile rank out of range");
    let index = (p * (sorted.len() - 1) as f64).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

/// Human label for the power-of-two object sizes the harness uses.
pub fn human_size(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if bytes >= MIB && bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= KIB && bytes.is_multiple_of(KIB) {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ascending(n: usize) -> Vec<f64> {
        (1..=n).map(|value| value as f64).collect()
    }

    #[test]
    fn percentile_is_nearest_rank() {
        let sorted = ascending(5); // [1, 2, 3, 4, 5]
        assert_eq!(percentile(&sorted, 0.0), 1.0);
        assert_eq!(percentile(&sorted, 0.50), 3.0);
        // round(0.9 * 4) = round(3.6) = 4 -> value 5.
        assert_eq!(percentile(&sorted, 0.90), 5.0);
        assert_eq!(percentile(&sorted, 1.0), 5.0);
        assert_eq!(percentile(&[42.0], 0.99), 42.0);
    }

    #[test]
    fn stats_iqr_and_extremes() {
        // Unsorted input proves compute() sorts internally.
        let samples = vec![9.0, 1.0, 5.0, 3.0, 7.0, 2.0, 8.0, 4.0, 6.0];
        let stats = CellStats::compute(&samples, None);
        assert_eq!(stats.count, 9);
        assert_eq!(stats.min_ms, 1.0);
        assert_eq!(stats.max_ms, 9.0);
        assert_eq!(stats.p50_ms, 5.0);
        assert_eq!(stats.mean_ms, 5.0);
        // p25 = index round(0.25*8)=2 -> 3, p75 = index round(0.75*8)=6 -> 7.
        assert_eq!(stats.iqr_ms, 4.0);
        assert_eq!(stats.throughput_mbps, None);
    }

    #[test]
    fn p99_needs_one_hundred_samples() {
        // The nightly matrix's largest cell (n = 50) must stay p99-less: at
        // that count the nearest-rank p99 is just the maximum.
        assert_eq!(CellStats::compute(&ascending(50), None).p99_ms, None);
        assert_eq!(CellStats::compute(&ascending(99), None).p99_ms, None);
        let stats = CellStats::compute(&ascending(100), None);
        // round(0.99 * 99) = round(98.01) = 98 -> value 99, distinct from
        // the maximum (100).
        assert_eq!(stats.p99_ms, Some(99.0));
        assert_eq!(stats.max_ms, 100.0);
    }

    #[test]
    fn throughput_uses_median_and_gates_on_mode() {
        // Median 2 ms over 1 MiB => 1 MiB / 0.002 s / 1e6 = 524.288 MB/s.
        let read = Cell::from_samples(
            "s3",
            1024 * 1024,
            Mode::ReadBytes,
            vec![2.0, 2.0, 2.0],
            None,
            Some(10.0),
        );
        let mbps = read.stats.throughput_mbps.expect("read moves bytes");
        assert!((mbps - 524.288).abs() < 1e-9, "got {mbps}");

        let stat = Cell::from_samples("s3", 4096, Mode::Stat, vec![1.0], None, None);
        assert_eq!(stat.stats.throughput_mbps, None);
    }

    #[test]
    fn ttfb_percentiles_derive_from_ttfb_samples_only() {
        let stream = Cell::from_samples(
            "s3",
            4096,
            Mode::ReadStream,
            vec![10.0, 20.0, 30.0],
            Some(vec![3.0, 1.0, 2.0]),
            None,
        );
        assert_eq!(stream.stats.ttfb_p50_ms, Some(2.0));
        assert_eq!(stream.stats.ttfb_p90_ms, Some(3.0));

        let buffered =
            Cell::from_samples("s3", 4096, Mode::ReadBytes, vec![10.0, 20.0], None, None);
        assert_eq!(buffered.stats.ttfb_p50_ms, None);
        assert_eq!(buffered.stats.ttfb_p90_ms, None);
    }

    #[test]
    fn empty_samples_serialize_without_panicking() {
        let stats = CellStats::compute(&[], Some(4096));
        assert_eq!(stats.count, 0);
        assert_eq!(stats.p99_ms, None);
        assert_eq!(stats.throughput_mbps, None);
    }

    #[test]
    fn json_shape_matches_the_schema_contract() {
        let report = LiveReport::new(
            "abc1234",
            "123",
            "1",
            "2026-08-25T00:00:00Z",
            RunnerInfo {
                os: "linux".into(),
                cpu_model: "TestCPU".into(),
                cpu_cores: 4,
            },
            vec![
                Cell::from_samples(
                    "azure",
                    4096,
                    Mode::ReadBytes,
                    vec![1.0, 2.0, 3.0],
                    None,
                    Some(9.0),
                ),
                Cell::from_samples(
                    "s3",
                    1024 * 1024,
                    Mode::ReadStream,
                    vec![4.0, 5.0],
                    Some(vec![0.5, 0.6]),
                    None,
                ),
            ],
        );
        let value: serde_json::Value =
            serde_json::from_str(&report.to_json_pretty().unwrap()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["kind"], "ovstorage-perf-live");
        assert_eq!(value["runner"]["cpu_cores"], 4);

        let read_bytes = &value["cells"][0];
        assert_eq!(read_bytes["mode"], "read_bytes");
        assert_eq!(read_bytes["cold_ms"], 9.0);
        // Nullable-but-present versus absent-when-missing:
        assert!(read_bytes["stats"].get("p99_ms").is_some());
        assert!(read_bytes["stats"]["p99_ms"].is_null());
        assert!(read_bytes["stats"]["ttfb_p50_ms"].is_null());
        assert!(read_bytes.get("ttfb_ms").is_none());

        let read_stream = &value["cells"][1];
        assert_eq!(read_stream["mode"], "read_stream");
        assert_eq!(read_stream["ttfb_ms"][1], 0.6);
        // Nearest-rank over [0.5, 0.6]: round(0.5 * 1) rounds half away from
        // zero, so both percentiles land on the second sample.
        assert_eq!(read_stream["stats"]["ttfb_p50_ms"], 0.6);
        assert_eq!(read_stream["stats"]["ttfb_p90_ms"], 0.6);
        assert!(read_stream["cold_ms"].is_null());

        // The document round-trips through the typed model.
        let parsed: LiveReport = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.cells.len(), 2);
        assert_eq!(parsed.cells[1].mode, Mode::ReadStream);
    }

    #[test]
    fn markdown_renders_one_row_per_cell() {
        let report = LiveReport::new(
            "abc1234",
            "123",
            "1",
            "2026-08-25T00:00:00Z",
            RunnerInfo {
                os: "linux".into(),
                cpu_model: "TestCPU".into(),
                cpu_cores: 4,
            },
            vec![Cell::from_samples(
                "file",
                1024 * 1024,
                Mode::ReadBytes,
                vec![2.0, 2.0, 2.0],
                None,
                None,
            )],
        );
        let markdown = report.to_markdown();
        assert!(markdown.contains("| backend | mode | size |"));
        assert!(markdown.contains("| file | read_bytes | 1 MiB | 3 | 2.000 |"));
        assert!(markdown.contains("| 524.3 |"), "markdown:\n{markdown}");
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(4096), "4 KiB");
        assert_eq!(human_size(64 * 1024 * 1024), "64 MiB");
        assert_eq!(human_size(100), "100 B");
        assert_eq!(human_size(1024 * 1024 + 1), "1048577 B");
    }
}
