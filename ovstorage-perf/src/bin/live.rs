// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Live read-performance harness. Drives the routed `Stack` exactly as the
//! integration suite does — same env-resolved targets, same plugin staging,
//! same REQUIRE/FORBID guard contract — and measures buffered reads,
//! streaming reads (with time-to-first-chunk), and stat against immutable
//! fixture objects, emitting the `schema_version` 1 JSON report consumed by
//! the perf regression tooling.
//!
//! Sample-count philosophy: this is a small number of expensive, network-
//! dominated measurements reported as percentiles, not a micro-benchmark.
//! Regression decisions are made downstream over a multi-run window, so a
//! single run only has to be internally consistent, never authoritative.

use std::time::Instant;

use futures::StreamExt;
use ovstorage::ext::LayerExt as _;
use ovstorage::{ErrorCode, ReadOptions};
use ovstorage_integration_tests::{Access, AppState, Backend, Target, app, block_on};
use ovstorage_perf::{Cell, LiveReport, Mode, RunnerInfo};

/// Fixture keys are versioned so a change to size ladder or content scheme
/// gets a fresh prefix instead of silently reinterpreting old objects.
const FIXTURE_PREFIX: &str = "ovstorage-perf/fixtures/v1";

/// One rung of the size ladder: object size, warm samples, discarded warmups.
#[derive(Clone, Copy)]
struct Rung {
    size: u64,
    samples: usize,
    warmups: usize,
}

const KIB: u64 = 1024;
const MIB: u64 = 1024 * 1024;

/// Full matrix for the nightly job. Counts shrink as sizes grow so the whole
/// run stays inside a bounded time and egress budget (~1.6 GB per backend).
const NIGHTLY_RUNGS: &[Rung] = &[
    Rung {
        size: 4 * KIB,
        samples: 50,
        warmups: 3,
    },
    Rung {
        size: MIB,
        samples: 30,
        warmups: 3,
    },
    Rung {
        size: 16 * MIB,
        samples: 15,
        warmups: 3,
    },
    Rung {
        size: 64 * MIB,
        samples: 8,
        warmups: 1,
    },
];
const NIGHTLY_STAT_SAMPLES: usize = 50;
const NIGHTLY_STAT_WARMUPS: usize = 3;

/// Hermetic smoke profile: proves the harness end to end in seconds against
/// the file backend; never a source of regression data.
const SMOKE_RUNGS: &[Rung] = &[
    Rung {
        size: 4 * KIB,
        samples: 3,
        warmups: 1,
    },
    Rung {
        size: MIB,
        samples: 3,
        warmups: 1,
    },
];
const SMOKE_STAT_SAMPLES: usize = 3;
const SMOKE_STAT_WARMUPS: usize = 1;

/// Backends in fixed measurement order. `File` first: it is the hermetic
/// runner-health control cell the regression report cross-references.
const BACKENDS: &[Backend] = &[Backend::File, Backend::Azure, Backend::S3, Backend::Gcs];

struct Options {
    profile: Profile,
    output: Option<std::path::PathBuf>,
    url: Option<String>,
    samples: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Profile {
    Nightly,
    Smoke,
}

const USAGE: &str = "\
ovstorage-perf-live — measure read performance through the routed Stack.

USAGE:
    ovstorage-perf-live [--profile nightly|smoke] [--output <path>]
    ovstorage-perf-live --url <address> [--samples <n>] [--output <path>]

OPTIONS:
    --profile <name>   Matrix profile: `nightly` (full size ladder, default)
                       or `smoke` (tiny, seconds against file://).
    --output <path>    Write the JSON report here. Overrides the
                       OVSTORAGE_PERF_OUTPUT environment variable.
    --url <address>    Generic single-URL mode: buffered-read the address
                       repeatedly through the Stack instead of the matrix.
    --samples <n>      Warm sample count for --url mode (default 10).

ENVIRONMENT:
    Backend targets resolve from the same OVSTORAGE_* environment contract
    as ovstorage-integration-tests, including the guard pair
    OVSTORAGE_REQUIRE_LIVE_BACKENDS / OVSTORAGE_FORBID_LIVE_BACKENDS, which
    fail the run at construction rather than skipping silently.
    OVSTORAGE_PERF_OUTPUT names the JSON output path when --output is absent.

EXIT CODES:
    0   run completed (individual failed cells are dropped with a note)
    1   a configured cloud backend completed zero cells — a plumbing
        failure, not a perf number — or the JSON report was not writable
    2   usage error
";

fn parse_args() -> Result<Options, String> {
    let mut opts = Options {
        profile: Profile::Nightly,
        output: std::env::var_os("OVSTORAGE_PERF_OUTPUT").map(Into::into),
        url: None,
        samples: 10,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} requires a value"));
        match arg.as_str() {
            "--profile" => {
                opts.profile = match value("--profile")?.as_str() {
                    "nightly" => Profile::Nightly,
                    "smoke" => Profile::Smoke,
                    other => return Err(format!("unknown profile {other:?}")),
                }
            }
            "--output" => opts.output = Some(value("--output")?.into()),
            "--url" => opts.url = Some(value("--url")?),
            "--samples" => {
                opts.samples = value("--samples")?
                    .parse()
                    .map_err(|e| format!("--samples: {e}"))?
            }
            "--help" | "-h" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(opts)
}

fn main() {
    let opts = match parse_args() {
        Ok(opts) => opts,
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    let (cells, cloud_outcomes) = block_on(async {
        let app = app().await;
        match &opts.url {
            Some(url) => single_url_cells(app, url, opts.samples).await,
            None => matrix_cells(app, opts.profile).await,
        }
    });

    let report = LiveReport::new(
        env_or("GITHUB_SHA", "unknown"),
        env_or("GITHUB_RUN_ID", "local"),
        env_or("GITHUB_RUN_ATTEMPT", "local"),
        iso8601_utc_now(),
        RunnerInfo::detect(),
        cells,
    );

    print!("{}", report.to_markdown());

    if let Some(path) = &opts.output {
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            eprintln!("error: create {}: {e}", parent.display());
            std::process::exit(1);
        }
        let json = report.to_json_pretty().expect("serialize LiveReport");
        if let Err(e) = std::fs::write(path, json) {
            eprintln!("error: write {}: {e}", path.display());
            std::process::exit(1);
        }
        eprintln!("report written to {}", path.display());
    } else {
        eprintln!("note: no --output/OVSTORAGE_PERF_OUTPUT; JSON report not written");
    }

    // Report-only posture with visible plumbing failures: individual cell
    // failures never fail the run, but a configured cloud backend that
    // completed zero cells is plumbing, not a perf number. Left green, that
    // backend could silently stop being measured for weeks — its points age
    // out of the moving window and any later regression restarts at
    // record-only — which is exactly the vacuous-green mode the
    // REQUIRE/FORBID guards exist to prevent. Backends that break before
    // their first sample count as attempted-with-zero-completed, so
    // pre-measurement failures cannot defeat this guard. The file control
    // never affects the exit code.
    let broken = broken_backends(&cloud_outcomes);
    if !broken.is_empty() {
        for backend in &broken {
            eprintln!(
                "error: cloud backend {backend} was configured but completed no cells; \
                 treating as a plumbing failure (see notes above)"
            );
        }
        std::process::exit(1);
    }
}

/// Cloud backends that were measured at all (`attempted > 0`) yet produced
/// nothing — the exit-1 condition of `main`.
fn broken_backends(outcomes: &[(&'static str, usize, usize)]) -> Vec<&'static str> {
    outcomes
        .iter()
        .filter(|(_, attempted, completed)| *attempted > 0 && *completed == 0)
        .map(|(backend, _, _)| *backend)
        .collect()
}

fn env_or(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_string())
}

/// Measure the full matrix. Returns the cells plus per-cloud-backend
/// `(label, attempted, completed)` cell counts for the exit-code decision:
/// aggregate counting would let one healthy backend keep the run green while
/// another stopped being measured entirely.
async fn matrix_cells(
    app: &'static AppState,
    profile: Profile,
) -> (Vec<Cell>, Vec<(&'static str, usize, usize)>) {
    let (rungs, stat_samples, stat_warmups) = match profile {
        Profile::Nightly => (NIGHTLY_RUNGS, NIGHTLY_STAT_SAMPLES, NIGHTLY_STAT_WARMUPS),
        Profile::Smoke => (SMOKE_RUNGS, SMOKE_STAT_SAMPLES, SMOKE_STAT_WARMUPS),
    };
    let mut cells = Vec::new();
    let mut outcomes = Vec::new();
    for &backend in BACKENDS {
        let Some(target) = app.target(backend, Access::Default) else {
            // Unconfigured backends already produced a visible skip (or a
            // REQUIRE failure) inside app construction; nothing to add.
            continue;
        };
        let before = cells.len();
        let attempted = backend_cells(target, rungs, stat_samples, stat_warmups, &mut cells).await;
        if backend != Backend::File {
            outcomes.push((backend.label(), attempted, cells.len() - before));
        }
    }
    (cells, outcomes)
}

/// Measure one backend. Returns how many cells were attempted (the cells
/// themselves are pushed onto `cells`; a failed cell is dropped with a note).
/// A backend that breaks before any cell can be measured — cold read failed,
/// or no usable fixture could be produced — still returns one attempted cell
/// with zero completed, so its attempted-with-nothing-completed outcome
/// trips the per-backend exit-1 guard in `main` rather than leaving a broken
/// backend green and unmeasured.
async fn backend_cells(
    target: &Target,
    rungs: &[Rung],
    stat_samples: usize,
    stat_warmups: usize,
    cells: &mut Vec<Cell>,
) -> usize {
    let backend = target.backend.label();
    let first_rung = rungs[0];
    let first_key = fixture_key(first_rung.size);

    // Cold discipline: the FIRST data-plane request of the process against
    // this backend is the measured cold read — before any stat/put has warmed
    // DNS, TLS, or the connection pool. A NotFound here means the fixtures
    // do not exist yet (first run against this bucket, or the file backend's
    // fresh per-process scratch root): create them and forgo the cold sample
    // for this run.
    let started = Instant::now();
    let cold_ms = match target.get(&first_key).await {
        Ok(bytes) => {
            let elapsed = elapsed_ms(started);
            if bytes.len() as u64 == first_rung.size {
                Some(elapsed)
            } else {
                note(backend, "cold", "fixture size mismatch; recreating");
                if put_fixture(target, first_rung.size).await.is_err() {
                    return 1;
                }
                None
            }
        }
        Err(e) if e.code() == ErrorCode::NotFound => {
            if create_all_fixtures(target, rungs).await.is_err() {
                return 1;
            }
            None
        }
        Err(e) => {
            note(backend, "cold", &format!("cold read failed: {e}"));
            return 1;
        }
    };

    // Remaining fixtures: verify by stat, create only what is missing. The
    // content is deterministic per size, so recreation is byte-identical and
    // the objects are effectively immutable. Rungs whose fixture could not be
    // produced are skipped below rather than measured as doomed requests.
    let mut unavailable: Vec<u64> = Vec::new();
    for rung in &rungs[1..] {
        if ensure_fixture(target, rung.size).await.is_err() {
            note(
                backend,
                "fixtures",
                &format!("skipping {} cells", rung.size),
            );
            unavailable.push(rung.size);
        }
    }

    let mut attempted = 0;
    let mut cold_ms = cold_ms;
    for rung in rungs {
        if unavailable.contains(&rung.size) {
            continue;
        }
        let key = fixture_key(rung.size);

        attempted += 1;
        // The cold sample belongs to the first buffered-read cell only.
        let cell_cold = cold_ms.take();
        if let Some(samples) =
            sample_read_bytes(target, &key, rung.size, rung.warmups, rung.samples).await
        {
            cells.push(Cell::from_samples(
                backend,
                rung.size,
                Mode::ReadBytes,
                samples,
                None,
                cell_cold,
            ));
        }

        attempted += 1;
        if let Some((totals, ttfbs)) =
            sample_read_stream(target, &key, rung.size, rung.warmups, rung.samples).await
        {
            cells.push(Cell::from_samples(
                backend,
                rung.size,
                Mode::ReadStream,
                totals,
                Some(ttfbs),
                None,
            ));
        }
    }

    attempted += 1;
    if let Some(samples) = sample_stat(
        target,
        &fixture_key(first_rung.size),
        stat_warmups,
        stat_samples,
    )
    .await
    {
        cells.push(Cell::from_samples(
            backend,
            first_rung.size,
            Mode::Stat,
            samples,
            None,
            None,
        ));
    }

    attempted
}

/// Generic single-URL mode: repeated buffered reads of one address through
/// the routed Stack. The size is taken from the first (warmup) read. The
/// pseudo-backend `url` participates in the exit-code accounting like a
/// cloud backend: a failed session exits non-zero.
async fn single_url_cells(
    app: &'static AppState,
    url: &str,
    samples: usize,
) -> (Vec<Cell>, Vec<(&'static str, usize, usize)>) {
    let address = match ovstorage::Url::parse(url) {
        Ok(address) => address,
        Err(e) => {
            eprintln!("error: --url {url:?}: {e}");
            std::process::exit(2);
        }
    };
    let warmup = match app
        .stack
        .read_bytes(address.clone(), ReadOptions::default(), None)
        .await
    {
        Ok((bytes, _)) => bytes.len() as u64,
        Err(e) => {
            eprintln!("error: --url warmup read failed: {e}");
            std::process::exit(1);
        }
    };
    let mut collected = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        match app
            .stack
            .read_bytes(address.clone(), ReadOptions::default(), None)
            .await
        {
            Ok(_) => collected.push(elapsed_ms(started)),
            Err(e) => {
                note("url", "read_bytes", &format!("sample failed: {e}"));
                return (Vec::new(), vec![("url", 1, 0)]);
            }
        }
    }
    let cell = Cell::from_samples("url", warmup, Mode::ReadBytes, collected, None, None);
    (vec![cell], vec![("url", 1, 1)])
}

async fn sample_read_bytes(
    target: &Target,
    key: &str,
    size: u64,
    warmups: usize,
    samples: usize,
) -> Option<Vec<f64>> {
    let mut collected = Vec::with_capacity(samples);
    for round in 0..(warmups + samples) {
        let started = Instant::now();
        match target.get(key).await {
            Ok(bytes) => {
                let elapsed = elapsed_ms(started);
                if bytes.len() as u64 != size {
                    note(
                        target.backend.label(),
                        "read_bytes",
                        &format!("short read: {} of {size} bytes", bytes.len()),
                    );
                    return None;
                }
                if round >= warmups {
                    collected.push(elapsed);
                }
            }
            Err(e) => {
                note(
                    target.backend.label(),
                    "read_bytes",
                    &format!("sample failed: {e}"),
                );
                return None;
            }
        }
    }
    Some(collected)
}

async fn sample_read_stream(
    target: &Target,
    key: &str,
    size: u64,
    warmups: usize,
    samples: usize,
) -> Option<(Vec<f64>, Vec<f64>)> {
    let mut totals = Vec::with_capacity(samples);
    let mut ttfbs = Vec::with_capacity(samples);
    for round in 0..(warmups + samples) {
        let started = Instant::now();
        let (mut stream, _info) = match target
            .stack()
            .read_stream(target.addr(key), ReadOptions::default(), None)
            .await
        {
            Ok(open) => open,
            Err(e) => {
                note(
                    target.backend.label(),
                    "read_stream",
                    &format!("open failed: {e}"),
                );
                return None;
            }
        };
        let mut received: u64 = 0;
        let mut ttfb = None;
        loop {
            match stream.next().await {
                Some(Ok(chunk)) => {
                    if ttfb.is_none() {
                        ttfb = Some(elapsed_ms(started));
                    }
                    received += chunk.len() as u64;
                }
                Some(Err(e)) => {
                    note(
                        target.backend.label(),
                        "read_stream",
                        &format!("chunk failed: {e}"),
                    );
                    return None;
                }
                None => break,
            }
        }
        let total = elapsed_ms(started);
        if received != size {
            note(
                target.backend.label(),
                "read_stream",
                &format!("short stream: {received} of {size} bytes"),
            );
            return None;
        }
        if round >= warmups {
            totals.push(total);
            // An empty object would stream zero chunks; fixture sizes are
            // all non-zero, so a missing TTFB is a short stream caught above.
            ttfbs.push(ttfb.unwrap_or(total));
        }
    }
    Some((totals, ttfbs))
}

async fn sample_stat(
    target: &Target,
    key: &str,
    warmups: usize,
    samples: usize,
) -> Option<Vec<f64>> {
    let mut collected = Vec::with_capacity(samples);
    for round in 0..(warmups + samples) {
        let started = Instant::now();
        match target.stat(key).await {
            Ok(_) => {
                if round >= warmups {
                    collected.push(elapsed_ms(started));
                }
            }
            Err(e) => {
                note(
                    target.backend.label(),
                    "stat",
                    &format!("sample failed: {e}"),
                );
                return None;
            }
        }
    }
    Some(collected)
}

fn fixture_key(size: u64) -> String {
    format!("{FIXTURE_PREFIX}/{size}.bin")
}

/// Deterministic content: an 8 KiB xorshift block seeded from the size,
/// repeated to length. Recreating a fixture therefore reproduces it
/// byte-for-byte, which is what lets the harness treat existing objects as
/// immutable and never rewrite them.
fn fixture_content(size: u64) -> Vec<u8> {
    const BLOCK: usize = 8 * 1024;
    let mut block = Vec::with_capacity(BLOCK);
    let mut state = size | 1;
    while block.len() < BLOCK {
        // xorshift64: cheap, stable, and dependency-free.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        block.extend_from_slice(&state.to_le_bytes());
    }
    block.truncate(BLOCK);
    let mut content = block.repeat(size.div_ceil(BLOCK as u64) as usize);
    content.truncate(size as usize);
    content
}

async fn create_all_fixtures(target: &Target, rungs: &[Rung]) -> Result<(), ()> {
    for rung in rungs {
        put_fixture(target, rung.size).await?;
    }
    Ok(())
}

async fn put_fixture(target: &Target, size: u64) -> Result<(), ()> {
    let key = fixture_key(size);
    target
        .put(&key, fixture_content(size))
        .await
        .map(|_| ())
        .map_err(|e| {
            note(
                target.backend.label(),
                "fixtures",
                &format!("create {key} failed: {e}"),
            );
        })
}

/// Stat-then-create: existing fixtures are never rewritten (their content is
/// deterministic), so steady-state nightly runs cost zero PUTs.
async fn ensure_fixture(target: &Target, size: u64) -> Result<(), ()> {
    match target.stat(&fixture_key(size)).await {
        Ok(info) if info.size == Some(size) => Ok(()),
        Ok(_) => {
            note(
                target.backend.label(),
                "fixtures",
                "size mismatch; recreating",
            );
            put_fixture(target, size).await
        }
        Err(e) if e.code() == ErrorCode::NotFound => put_fixture(target, size).await,
        Err(e) => {
            note(
                target.backend.label(),
                "fixtures",
                &format!("stat failed: {e}"),
            );
            Err(())
        }
    }
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

fn note(backend: &str, phase: &str, message: &str) {
    eprintln!("note[{backend}/{phase}]: {message}");
}

/// ISO-8601 UTC timestamp from `SystemTime`, without a date-time dependency.
/// Uses the standard civil-from-days algorithm.
fn iso8601_utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let (hh, mm, ss) = ((secs / 3_600) % 24, (secs / 60) % 60, secs % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_content_is_deterministic_and_sized() {
        assert_eq!(fixture_content(4096).len(), 4096);
        assert_eq!(fixture_content(4096), fixture_content(4096));
        assert_ne!(fixture_content(4096)[..], fixture_content(8192)[..4096]);
        assert_eq!(fixture_content(10_000).len(), 10_000);
    }

    #[test]
    fn broken_backends_flags_attempted_with_zero_completed() {
        // One healthy backend must not shield a broken one, an unattempted
        // backend is app()'s concern rather than this guard's, and an empty
        // outcome list (nothing configured beyond file) stays green.
        let outcomes = [("azure", 9, 9), ("s3", 9, 0), ("gcs", 0, 0)];
        assert_eq!(broken_backends(&outcomes), vec!["s3"]);
        assert!(broken_backends(&[]).is_empty());
        assert!(broken_backends(&[("azure", 9, 1)]).is_empty());
    }

    #[test]
    fn timestamps_are_iso8601() {
        let stamp = iso8601_utc_now();
        assert_eq!(stamp.len(), 20, "{stamp}");
        assert!(stamp.ends_with('Z'));
        assert_eq!(&stamp[4..5], "-");
        assert_eq!(&stamp[10..11], "T");
    }
}
