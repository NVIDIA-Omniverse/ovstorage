// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::ValueEnum;
use futures::StreamExt;
use ovstorage::ext::LayerExt;
use ovstorage::{
    AccessOps, BodyStream, ByteRange, CancellationToken, ChangeEvent, ChangeKind, ConfigValue,
    Error, ErrorCode, IfDestExists, ObjectInfo, ReadOptions, Stack, StateConfig, Url, address,
};
use ovstorage_cache::{Cache, CacheConfig};

/// Output format for `list` and `list-versions`. Defaults to `human`
/// (one address per line, current behavior); `table` renders aligned
/// columns suitable for `column -t` consumers.
#[derive(Copy, Clone, Debug, Default, ValueEnum)]
pub(crate) enum OutputFormat {
    #[default]
    Human,
    Table,
}

pub(crate) async fn stream_read_to_writer<W: Write>(
    stack: &Arc<Stack>,
    addr: Url,
    opts: ReadOptions,
    out: &mut W,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let (mut stream, _) = stack.read_stream(addr, opts, Some(cancel.clone())).await?;
    while let Some(chunk) = stream.next().await {
        let bytes = chunk?;
        out.write_all(&bytes).map_err(io_error)?;
    }
    out.flush().map_err(io_error)
}

pub(crate) async fn stream_read_to_path(
    stack: &Arc<Stack>,
    addr: Url,
    opts: ReadOptions,
    path: &Path,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    let file = std::fs::File::create(path).map_err(io_error)?;
    let mut writer = std::io::BufWriter::new(file);
    stream_read_to_writer(stack, addr, opts, &mut writer, cancel).await
}

/// Stream stdin chunk-by-chunk into `Body::Stream`. Buffering all of stdin
/// here would defeat the streaming-write contract on the public gateway —
/// the project's "streaming writes must be true-streaming" rule forbids it
/// explicitly.
pub(crate) fn stdin_body_stream() -> BodyStream {
    const CHUNK: usize = 64 * 1024;
    let mut stdin = std::io::stdin();
    let iter = std::iter::from_fn(move || {
        let mut buf = vec![0u8; CHUNK];
        match stdin.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some(Ok(buf))
            }
            Err(err) => Some(Err(io_error(err))),
        }
    });
    BodyStream::from_iter(iter)
}

pub(crate) fn cache_from_loaded_or_env(
    state: Option<&StateConfig>,
) -> ovstorage::Result<Option<Cache>> {
    cache_config_resolved(state)?.map(Cache::open).transpose()
}

/// Read the on-disk cache/state roots from the stack's configured `byte_cache`
/// layer, if one is declared. The `cache-*` / `state-status` inspection
/// commands open a second read-only `Cache` handle onto the same roots the live
/// byte_cache layer provisions, so an operator who declares
/// `[ovstorage.layers.byte_cache]` can inspect and GC the cache the stack
/// actually uses. `OVSTORAGE_CACHE_ROOT` / `OVSTORAGE_STATE_ROOT` still override
/// per-invocation (see [`cache_config_resolved`]). Returns `None` when the stack
/// declares no byte_cache layer, leaving the commands env-only.
pub(crate) fn byte_cache_state_config(stack: &Stack) -> Option<StateConfig> {
    let layer = stack
        .spec()
        .layers
        .iter()
        .find(|l| l.kind == ovstorage::layers::BYTE_CACHE_KIND)?;
    let path = |key| match layer.config.get(key) {
        Some(ConfigValue::String(value)) => Some(PathBuf::from(value)),
        _ => None,
    };
    Some(StateConfig {
        state_root: path("state_root"),
        cache_root: path("cache_root"),
    })
}

/// Env vars override TOML so operators can flip cache roots per-invocation
/// without rewriting their config. Both halves must come from the same layer.
pub(crate) fn cache_config_resolved(
    state: Option<&StateConfig>,
) -> ovstorage::Result<Option<CacheConfig>> {
    let env_state = std::env::var_os("OVSTORAGE_STATE_ROOT").map(PathBuf::from);
    let env_cache = std::env::var_os("OVSTORAGE_CACHE_ROOT").map(PathBuf::from);
    let toml_state = state.and_then(|s| s.state_root.clone());
    let toml_cache = state.and_then(|s| s.cache_root.clone());
    let state_root = env_state.or(toml_state);
    let cache_root = env_cache.or(toml_cache);
    match (state_root, cache_root) {
        (Some(state_root), Some(cache_root)) => Ok(Some(CacheConfig {
            state_root,
            cache_root,
        })),
        (None, None) => Ok(None),
        _ => Err(invalid(
            "state_root and cache_root must be set together (via OVSTORAGE_STATE_ROOT/OVSTORAGE_CACHE_ROOT or [state] in the config)",
        )),
    }
}

pub(crate) fn print_info(info: &ObjectInfo) {
    println!("address={}", info.address);
    if let Some(size) = info.size {
        println!("size={size}");
    }
    if let Some(mtime) = info.mtime
        && let Ok(duration) = mtime.duration_since(std::time::UNIX_EPOCH)
    {
        println!("mtime_unix_nanos={}", duration.as_nanos());
    }
    if let Some(metadata) = &info.user_metadata {
        for (key, value) in metadata {
            // user_metadata originates from object writers; on a public-facing
            // gateway that's untrusted input. Escape via JSON-style escapes so
            // a `\n` in a value can't forge another key=value line in
            // operator-script output.
            println!(
                "user_metadata.{}=\"{}\"",
                json_escape(key),
                json_escape(value)
            );
        }
    }
}

pub(crate) fn print_change_event(event: &ChangeEvent) -> ovstorage::Result<()> {
    match event {
        ChangeEvent::Object {
            address,
            kind,
            etag,
            version,
            size,
            mtime,
            cursor,
            ..
        } => {
            print!(
                "{{\"type\":\"object\",\"address\":\"{}\",\"kind\":\"{}\",\"cursor_b64\":\"{}\"",
                json_escape(address.as_str()),
                change_kind_name(*kind),
                encode_cursor_b64(&cursor.0)
            );
            if let Some(etag) = etag {
                print!(",\"etag\":\"{}\"", json_escape(etag));
            }
            if let Some(version) = version {
                print!(",\"version\":\"{}\"", json_escape(version));
            }
            if let Some(size) = size {
                print!(",\"size\":{size}");
            }
            if let Some(mtime) = mtime
                && let Ok(duration) = mtime.duration_since(std::time::UNIX_EPOCH)
            {
                print!(",\"mtime_unix_nanos\":{}", duration.as_nanos());
            }
            println!("}}");
        }
        ChangeEvent::Lapsed { cursor, .. } => {
            println!(
                "{{\"type\":\"lapsed\",\"cursor_b64\":\"{}\"}}",
                encode_cursor_b64(&cursor.0)
            );
        }
    }
    std::io::stdout().flush().map_err(io_error)
}

pub(crate) fn encode_cursor_b64(cursor: &[u8]) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    STANDARD.encode(cursor)
}

pub(crate) fn decode_cursor_b64(cursor: &str) -> ovstorage::Result<Vec<u8>> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    STANDARD.decode(cursor.as_bytes()).map_err(|err| {
        invalid(format!(
            "--since must be base64 (as emitted by watch-directory cursor_b64): {err}"
        ))
    })
}

pub(crate) fn change_kind_name(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::Created => "created",
        ChangeKind::Modified => "modified",
        ChangeKind::Deleted => "deleted",
        ChangeKind::MetadataChanged => "metadata_changed",
    }
}

pub(crate) fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

/// Resolve an address from a user input. If the input is a fully-qualified URL
/// (`scheme://...` or `scheme:opaque`), parse it as-is. Otherwise treat it as
/// a relative URL and join it onto the current directory using RFC 3986
/// resolution (the `url` crate's `Url::join` handles `..`, `.`, etc.).
pub(crate) fn resolve_address(input: &str, pwd: Option<&Url>) -> ovstorage::Result<Url> {
    let Some(pwd) = pwd else {
        return address::parse(input);
    };
    let joined = pwd.join(input).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("could not resolve '{input}' against {pwd}: {err}"),
        )
    })?;
    Ok(joined)
}

/// Ensure the address ends with a trailing slash. Required for directory-
/// shaped addresses so subsequent `Url::join` resolves children correctly
/// instead of treating the last segment as a sibling file.
pub(crate) fn ensure_trailing_slash(addr: Url) -> ovstorage::Result<Url> {
    if addr.as_str().ends_with('/') {
        Ok(addr)
    } else {
        address::parse(&format!("{}/", addr.as_str()))
    }
}

pub(crate) fn parse_range(value: &str) -> ovstorage::Result<ByteRange> {
    let Some((start, end)) = value.split_once('-') else {
        return Err(invalid("range must be START-END"));
    };
    Ok(ByteRange {
        start: start
            .parse()
            .map_err(|_| invalid("range start must be an integer"))?,
        end_inclusive: if end.is_empty() {
            None
        } else {
            Some(
                end.parse()
                    .map_err(|_| invalid("range end must be an integer"))?,
            )
        },
    })
}

pub(crate) fn parse_key_value(value: &str) -> ovstorage::Result<(String, String)> {
    value
        .split_once('=')
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .ok_or_else(|| invalid("expected key=value"))
}

/// Convert the optional `--if-match` / `--if-source` CLI value into the
/// SPI etag string. The SPI etag is opaque — the CLI passes the value
/// through untouched; backends encode whatever they want into the
/// string (the `file` plugin synthesizes `"size:N,mtime:T"`,
/// HTTP-derived backends use the wire `ETag` value verbatim).
pub(crate) fn parse_if_match_opt(raw: Option<&str>) -> ovstorage::Result<Option<String>> {
    Ok(raw.map(str::to_string))
}

/// Parse the `--if-dest` CLI value into [`IfDestExists`].
///
/// Accepted spellings:
/// - `overwrite` — clobber unconditionally (default when the flag is
///   omitted).
/// - `fail` — refuse if the destination exists (`AlreadyExists`).
/// - `match:<etag>` — overwrite only when the destination's current
///   etag matches `<etag>` (`PreconditionFailed` otherwise).
///
/// The colon-separated form keeps the flag scriptable from a single
/// shell argument — no JSON tagged-union wrapping the way MCP carries
/// `{"kind":"match_etag","etag":"..."}`.
pub(crate) fn parse_if_dest(raw: &str) -> ovstorage::Result<IfDestExists> {
    match raw {
        "overwrite" => Ok(IfDestExists::Overwrite),
        "fail" => Ok(IfDestExists::Fail),
        other => {
            let etag = other.strip_prefix("match:").ok_or_else(|| {
                invalid(format!(
                    "--if-dest must be 'overwrite', 'fail', or 'match:<etag>' (got {other:?})"
                ))
            })?;
            if etag.is_empty() {
                return Err(invalid(
                    "--if-dest=match: requires a non-empty etag after the colon",
                ));
            }
            Ok(IfDestExists::MatchEtag(etag.to_string()))
        }
    }
}

pub(crate) fn parse_if_dest_opt(raw: Option<&str>) -> ovstorage::Result<IfDestExists> {
    match raw {
        None => Ok(IfDestExists::Overwrite),
        Some(value) => parse_if_dest(value),
    }
}

/// Print a 2D table of strings with column widths derived from the
/// widest cell per column. Columns are tab-separated for the header
/// and space-padded for the body; downstream `column -t` handles both.
pub(crate) fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (col, cell) in row.iter().enumerate() {
            if col < widths.len() && cell.len() > widths[col] {
                widths[col] = cell.len();
            }
        }
    }
    let mut header_line = String::new();
    for (i, h) in headers.iter().enumerate() {
        if i > 0 {
            header_line.push_str("  ");
        }
        header_line.push_str(&format!("{:<width$}", h, width = widths[i]));
    }
    println!("{}", header_line.trim_end());
    for row in rows {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                line.push_str("  ");
            }
            let width = widths.get(i).copied().unwrap_or(0);
            line.push_str(&format!("{:<width$}", cell, width = width));
        }
        println!("{}", line.trim_end());
    }
}

pub(crate) fn parse_ops(value: &str) -> ovstorage::Result<AccessOps> {
    let mut ops = AccessOps::default();
    for op in value.split(',') {
        match op {
            "read" => ops.read = true,
            "write" => ops.write = true,
            "delete" => ops.delete = true,
            "update_metadata" => ops.update_metadata = true,
            other => return Err(invalid(format!("unknown access op '{other}'"))),
        }
    }
    Ok(ops)
}

pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}

pub(crate) fn io_error(error: std::io::Error) -> Error {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        std::io::ErrorKind::BrokenPipe => ErrorCode::Cancelled,
        _ => ErrorCode::Transient,
    };
    Error::new(code, error.to_string())
}

/// Outcome of a single cancellable iterator step.
#[derive(Debug)]
pub(crate) enum Step<I, T> {
    /// The iterator yielded an event. Carries the iterator back so the
    /// caller can take the next step.
    Event(I, T),
    /// The iterator returned `None`. Carries the iterator back for
    /// any final cleanup the caller wants to do.
    Done(I),
    /// The cancellation token fired before `.next()` returned. The
    /// iterator is left inside the `spawn_blocking` task and dropped
    /// whenever its in-flight `.next()` eventually returns.
    Cancelled,
}

/// Pump one `.next()` of a synchronous iterator on a blocking thread,
/// racing the wait against a `CancellationToken`.
pub(crate) async fn next_or_cancel<I, T>(mut iter: I, token: &CancellationToken) -> Step<I, T>
where
    I: Iterator<Item = T> + Send + 'static,
    T: Send + 'static,
{
    let join = tokio::task::spawn_blocking(move || {
        let next = iter.next();
        (iter, next)
    });
    tokio::select! {
        joined = join => {
            let (iter, next) = joined.expect("blocking task panicked");
            match next {
                Some(t) => Step::Event(iter, t),
                None => Step::Done(iter),
            }
        }
        _ = token.cancelled() => Step::Cancelled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stack declaring `[ovstorage.layers.byte_cache]` exposes its
    /// `cache_root`/`state_root` so the `cache-*` commands inspect the cache the
    /// stack actually uses instead of silently reporting `cache=disabled`
    /// (regression for the env-only `cache_from_loaded_or_env(None)` stub).
    #[tokio::test]
    async fn byte_cache_state_config_reads_configured_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ovstorage::Url::from_directory_path(tmp.path()).unwrap();
        let cache_root = tmp.path().join("cache");
        let state_root = tmp.path().join("state");
        let toml = format!(
            r#"
[ovstorage]
root = "byte_cache"

[ovstorage.layers.byte_cache]
kind = "byte_cache"
inner = "file"
cache_root = "{cache}"
state_root = "{state}"

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{root}"
"#,
            cache = cache_root.display(),
            state = state_root.display(),
        );
        let cfg = ovstorage::StackConfig::from_toml_str(&toml).unwrap();
        let stack = ovstorage::host::build_stack(&cfg, crate::commands::test_layer_factories())
            .await
            .unwrap();

        let resolved = byte_cache_state_config(&stack).expect("byte_cache layer present");
        assert_eq!(resolved.cache_root.as_deref(), Some(cache_root.as_path()));
        assert_eq!(resolved.state_root.as_deref(), Some(state_root.as_path()));
    }

    /// No byte_cache layer → `None`, leaving the commands env-only.
    #[tokio::test]
    async fn byte_cache_state_config_absent_when_no_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ovstorage::Url::from_directory_path(tmp.path()).unwrap();
        let toml = format!(
            r#"
[ovstorage]
root = "file"

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{root}"
"#
        );
        let cfg = ovstorage::StackConfig::from_toml_str(&toml).unwrap();
        let stack = ovstorage::host::build_stack(&cfg, crate::commands::test_layer_factories())
            .await
            .unwrap();
        assert!(byte_cache_state_config(&stack).is_none());
    }

    #[test]
    fn parse_if_match_opt_passes_etag_through() {
        let etag = parse_if_match_opt(Some("\"abc\"")).unwrap().unwrap();
        assert_eq!(etag, "\"abc\"");
    }

    #[test]
    fn parse_if_match_opt_passes_through_none() {
        assert!(parse_if_match_opt(None).unwrap().is_none());
    }

    #[test]
    fn parse_if_dest_overwrite() {
        assert!(matches!(
            parse_if_dest("overwrite").unwrap(),
            IfDestExists::Overwrite
        ));
    }

    #[test]
    fn parse_if_dest_fail() {
        assert!(matches!(parse_if_dest("fail").unwrap(), IfDestExists::Fail));
    }

    #[test]
    fn parse_if_dest_match_etag() {
        match parse_if_dest("match:opaque-token").unwrap() {
            IfDestExists::MatchEtag(etag) => assert_eq!(etag, "opaque-token"),
            other => panic!("expected MatchEtag, got {other:?}"),
        }
    }

    #[test]
    fn parse_if_dest_match_requires_non_empty_etag() {
        let err = parse_if_dest("match:").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn parse_if_dest_rejects_unknown_form() {
        let err = parse_if_dest("clobber").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn parse_if_dest_opt_defaults_to_overwrite() {
        assert!(matches!(
            parse_if_dest_opt(None).unwrap(),
            IfDestExists::Overwrite
        ));
    }

    #[test]
    fn cursor_b64_round_trips_non_utf8_bytes() {
        let raw: Vec<u8> = vec![0xff, 0x00, 0xfe, 0x80, 0x7f];
        let encoded = encode_cursor_b64(&raw);
        let decoded = decode_cursor_b64(&encoded).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn decode_cursor_b64_rejects_invalid() {
        let err = decode_cursor_b64("not!valid!b64").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn io_error_maps_broken_pipe_to_cancelled() {
        let err = io_error(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "downstream closed",
        ));
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn next_or_cancel_returns_event_when_iterator_yields() {
        let iter = vec![10_u32, 20].into_iter();
        let token = ovstorage::CancellationToken::new();
        match next_or_cancel(iter, &token).await {
            Step::Event(rest, value) => {
                assert_eq!(value, 10);
                assert_eq!(rest.collect::<Vec<_>>(), vec![20]);
            }
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn next_or_cancel_returns_done_when_iterator_exhausted() {
        let iter = std::iter::empty::<u32>();
        let token = ovstorage::CancellationToken::new();
        match next_or_cancel(iter, &token).await {
            Step::Done(_) => {}
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn next_or_cancel_returns_cancelled_when_token_fires_before_next() {
        // Iterator that blocks until a oneshot is signaled; cancellation
        // should race ahead of the .next() call returning.
        let (tx, rx) = std::sync::mpsc::channel::<u32>();
        let iter = std::iter::from_fn(move || rx.recv().ok());
        let token = ovstorage::CancellationToken::new();
        token.cancel();
        match next_or_cancel(iter, &token).await {
            Step::Cancelled => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
        // tx never sent; sender keeps the channel alive so the blocking
        // thread can park there indefinitely. Drop it to let the leaked
        // spawn_blocking thread exit.
        drop(tx);
    }
}
