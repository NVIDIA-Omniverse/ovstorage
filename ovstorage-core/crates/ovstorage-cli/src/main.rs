// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

mod commands;
mod interrupt;
mod session;

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ovstorage::{CancellationToken, Error, ErrorCode, Library, LibraryConfig};

use crate::commands::util::{OutputFormat, cache_from_loaded_or_env};
use crate::interrupt::{InterruptDecision, interrupt_decision};

#[derive(Parser)]
#[command(
    name = "ovstorage",
    version,
    about = "Command-line tool for ovstorage."
)]
pub(crate) struct Cli {
    /// Load configuration from PATH (overrides $OVSTORAGE_CONFIG and the default search path).
    #[arg(long, value_name = "PATH", global = true, conflicts_with = "no_config")]
    config: Option<PathBuf>,
    /// Skip startup config loading entirely.
    #[arg(long, global = true)]
    no_config: bool,
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// List configured routes.
    #[command(aliases = ["routes", "list-roots", "roots"])]
    ListRoutes,
    /// List registered backends.
    #[command(aliases = ["backends", "kinds"])]
    ListBackends,
    /// Show local cache status (requires OVSTORAGE_CACHE_ROOT + OVSTORAGE_STATE_ROOT).
    CacheStatus,
    /// Run the cache crash-recovery sweep in dry-run mode and print the
    /// counts that would be touched (no mutations).
    CacheDoctor,
    /// Force a cache eviction pass against the configured byte budget.
    /// Equivalent to the implicit eviction triggered by `put`, but
    /// runnable on demand so operators can reclaim space without a
    /// write.
    CacheGc,
    /// Show detailed cache statistics: byte totals by state (CAS,
    /// staging), entry counts, live process leases.
    CacheStats,
    /// Show local state status (requires OVSTORAGE_STATE_ROOT + OVSTORAGE_CACHE_ROOT).
    StateStatus,
    /// Aggregate library diagnostic state into a single report.
    Doctor {
        /// Emit the report as a versioned JSON envelope on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Print metadata for an object.
    #[command(alias = "info")]
    Stat {
        address: String,
        #[arg(long)]
        full_metadata: bool,
    },
    /// Read an object's contents.
    #[command(aliases = ["cat", "get"])]
    Read {
        address: String,
        /// Write output to FILE instead of stdout.
        #[arg(short = 'o', value_name = "FILE")]
        output: Option<String>,
        /// Byte range as START-END (inclusive) or START- for open-ended.
        #[arg(long, value_name = "RANGE")]
        range: Option<String>,
        /// Etag precondition: refuse the read unless the target's
        /// current etag matches. Opaque token from a prior `stat` /
        /// read; mismatch surfaces as `ObjectModified`.
        #[arg(long, value_name = "ETAG")]
        if_match: Option<String>,
    },
    /// Write an object.
    #[command(alias = "put")]
    Write {
        address: String,
        /// Read body from FILE instead of stdin.
        #[arg(short = 'i', value_name = "FILE")]
        input: Option<String>,
        /// Fail if the destination already exists.
        #[arg(long)]
        no_overwrite: bool,
        /// Destination etag precondition: refuse the write unless the
        /// destination's current etag matches (see `read --if-match`).
        /// Mutually exclusive with `--no-overwrite`.
        #[arg(long, value_name = "ETAG")]
        if_match: Option<String>,
        /// Repeatable: KEY=VALUE user-metadata pairs sent with the write.
        #[arg(long, value_name = "KEY=VALUE")]
        metadata: Vec<String>,
        /// Annotation attached to this operation (e.g. checkpoint commit
        /// message on backends that version objects). Backends without
        /// per-operation annotation drop it silently.
        #[arg(long, short = 'm', value_name = "MSG")]
        message: Option<String>,
    },
    /// Delete an object.
    #[command(aliases = ["rm", "remove", "del"])]
    Delete {
        address: String,
        /// Etag precondition (see `read --if-match`).
        #[arg(long, value_name = "ETAG")]
        if_match: Option<String>,
    },
    /// List objects under a prefix, or the current directory when no prefix is given.
    #[command(aliases = ["ls", "ll", "dir"])]
    List {
        prefix: Option<String>,
        #[arg(long)]
        recursive: bool,
        #[arg(long)]
        full_metadata: bool,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        /// Output format: 'human' (one address per line) or 'table' (aligned columns).
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
    /// Copy an object. Copy carries two precondition operands; reach
    /// them with `--if-source` (source-side etag) and `--if-dest`
    /// (destination-side).
    #[command(alias = "copy")]
    Cp {
        src: String,
        dest: String,
        /// Source-side etag precondition: refuse the copy unless the
        /// source's current etag matches. Opaque token from a prior
        /// `stat` / read.
        #[arg(long, value_name = "ETAG", alias = "if-match")]
        if_source: Option<String>,
        /// Destination-side precondition. One of: `overwrite`
        /// (default, clobber unconditionally), `fail` (refuse if the
        /// destination exists), `match:<etag>` (overwrite only when
        /// the destination's current etag matches).
        #[arg(long, value_name = "SPEC")]
        if_dest: Option<String>,
        /// Annotation attached to this operation (see `write --message`).
        #[arg(long, short = 'm', value_name = "MSG")]
        message: Option<String>,
    },
    /// List versions of an object.
    #[command(alias = "versions")]
    ListVersions {
        address: String,
        #[arg(long)]
        max_results: Option<u32>,
        #[arg(long)]
        page_token: Option<String>,
        /// Output format: 'human' (one address per line) or 'table' (aligned columns).
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
    /// Resolve an address to a single pinned version: returns the
    /// addressed version when the URL carries the backend's
    /// version-modifier query, else the current head.
    #[command(alias = "pin-latest")]
    GetLatestVersion { address: String },
    /// Move/rename an object. Rename carries two precondition
    /// operands; reach them with `--if-source` (source-side etag) and
    /// `--if-dest` (destination-side).
    #[command(aliases = ["move", "rename", "ren"])]
    Mv {
        src: String,
        dest: String,
        /// Source-side etag precondition: refuse the move unless the
        /// source's current etag matches.
        #[arg(long, value_name = "ETAG", alias = "if-match")]
        if_source: Option<String>,
        /// Destination-side precondition. One of: `overwrite`
        /// (default), `fail`, or `match:<etag>` (see `cp --if-dest`).
        #[arg(long, value_name = "SPEC")]
        if_dest: Option<String>,
        /// Annotation attached to this operation (see `write --message`).
        #[arg(long, short = 'm', value_name = "MSG")]
        message: Option<String>,
    },
    /// Create a directory.
    #[command(aliases = ["mkdir", "make-dir", "md"])]
    CreateDirectory { address: String },
    /// Remove a directory. Without `--recursive`, fails if the directory
    /// is not empty. With `--recursive`, prompts for confirmation listing
    /// the entries that would be deleted, unless `--yes` is passed.
    /// `--dry-run` enumerates the entries without mutating.
    #[command(aliases = ["rmdir", "remove-dir", "rd"])]
    DeleteDirectory {
        address: String,
        /// Remove the directory and all its descendants.
        #[arg(long)]
        recursive: bool,
        /// Enumerate the entries that would be deleted and exit without mutating.
        #[arg(long)]
        dry_run: bool,
        /// Skip the confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Update user metadata on an object.
    #[command(alias = "set-meta")]
    UpdateMetadata {
        address: String,
        /// Repeatable: KEY=VALUE pairs to set.
        #[arg(long, value_name = "KEY=VALUE")]
        set: Vec<String>,
        /// Repeatable: keys to remove.
        #[arg(long, value_name = "KEY")]
        remove: Vec<String>,
        /// Etag precondition (see `read --if-match`).
        #[arg(long, value_name = "ETAG")]
        if_match: Option<String>,
        /// Allow the backend to emulate metadata updates by rewriting the object.
        #[arg(long)]
        allow_rewrite_emulation: bool,
        /// Annotation attached to this operation (see `write --message`).
        #[arg(long, short = 'm', value_name = "MSG")]
        message: Option<String>,
    },
    /// Check whether the principal can perform OPS on ADDRESS.
    /// OPS is a comma-separated list of: read, write, delete, update_metadata.
    #[command(alias = "access")]
    CheckAccess { address: String, ops: String },
    /// Set the current directory used to resolve relative paths in subsequent
    /// commands. Only meaningful inside the interactive shell — outside of it,
    /// the new directory is discarded as the process exits.
    #[command(alias = "chdir")]
    Cd { address: String },
    /// Print arguments to stdout. Useful for marking sections in scripted
    /// REPL sessions (`ovstorage <<EOF ... EOF`).
    Echo {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        words: Vec<String>,
    },
    /// Interactively configure a backend connection.
    /// Walks the chosen plugin's config + credential schema and verifies the result.
    /// Supplying KIND alone (or no args) runs the wizard; supplying KIND plus
    /// values for every required config field skips the wizard end-to-end
    /// (secrets for the chosen auth method are still prompted at the TTY).
    Connect {
        /// Backend kind id (e.g. `nucleus`, `gcs`, `file`). Omit to pick interactively.
        kind: Option<String>,
        /// Values for the kind's required config fields, in schema declaration order.
        /// Either supply none (run the wizard) or supply all of them (skip the wizard).
        fields: Vec<String>,
        /// Credential method id. Defaults to the kind's first method when the
        /// backend advertises any. Ignored for backends with no credential methods.
        #[arg(long, value_name = "ID")]
        auth: Option<String>,
        /// Display name for the connection. Skipped (left empty) when omitted in
        /// non-interactive mode; prompted by the wizard otherwise.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Surface every config field and walk every credential field individually,
        /// instead of asking only for common fields and picking a credential method.
        /// Wizard-only; cannot be combined with positional field values.
        #[arg(long)]
        advanced: bool,
    },
    /// Drive interactive authentication for an existing connection. Use
    /// when a refresh token expired (the connection sits in `AwaitingAuth`
    /// after startup) or when the user wants to log in again without
    /// rebuilding the connection's config. Surfaces the same
    /// `OpenBrowser` / `DeviceCode` events as `connect`.
    Reauth {
        /// Connection display name (matched against `Library::list_connections`).
        name: String,
    },
    /// Serialize the active configuration (loaded + this session's pending
    /// connections) to a TOML file.
    WriteConfig {
        /// Output path. Defaults to ./ovstorage.toml.
        #[arg(default_value = "ovstorage.toml")]
        path: PathBuf,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
        /// How plaintext secrets typed at `connect` are encoded in the TOML.
        /// Required when there are plaintext credentials to encode; ignored
        /// otherwise. Refs you chose at connect (env/keyring) and refs from the
        /// loaded config pass through unchanged regardless.
        #[arg(long, value_enum)]
        secrets: Option<commands::write_config::SecretsPolicy>,
    },
    /// Watch a directory for changes; emits one JSON event per line.
    WatchDirectory {
        prefix: String,
        #[arg(long)]
        recursive: bool,
        /// Skip metadata-only changes.
        #[arg(long)]
        no_metadata_changes: bool,
        /// Resume from a previously emitted cursor.
        #[arg(long, value_name = "CURSOR")]
        since: Option<String>,
    },
}

// Multi-threaded runtime so background tasks (e.g. the address-roots
// watcher) keep getting polled while the REPL blocks the foreground
// thread on synchronous `inquire` prompts.
#[tokio::main]
async fn main() {
    install_panic_hook();
    let _tracing = match init_tracing_if_requested() {
        Ok(guard) => guard,
        Err(error) if error.code() == ErrorCode::AlreadyExists => ovstorage::TracingGuard::noop(),
        Err(error) => {
            eprintln!("{}: {}", error_code_name(error.code()), error.message());
            std::process::exit(exit_code(error.code()));
        }
    };
    if let Err(error) = run().await {
        eprintln!("{}: {}", error_code_name(error.code()), error.message());
        std::process::exit(exit_code(error.code()));
    }
}

fn init_tracing_if_requested() -> ovstorage::Result<ovstorage::TracingGuard> {
    if tracing_requested_from_env() {
        ovstorage::init_tracing_from_env()
    } else {
        Ok(ovstorage::TracingGuard::noop())
    }
}

fn tracing_requested_from_env() -> bool {
    tracing_requested_from_env_with(|name| std::env::var_os(name))
}

fn tracing_requested_from_env_with(mut var: impl FnMut(&str) -> Option<OsString>) -> bool {
    if env_value_is_nonempty(var("OVSTORAGE_LOG").as_deref())
        || env_value_is_nonempty(var("RUST_LOG").as_deref())
    {
        return true;
    }

    let ovstorage_otlp = var("OVSTORAGE_OTLP");
    if env_value_is_true(var("OTEL_SDK_DISABLED").as_deref())
        || env_value_is_false(ovstorage_otlp.as_deref())
    {
        return false;
    }

    env_value_is_true(ovstorage_otlp.as_deref())
        || env_value_is_nonempty(var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").as_deref())
        || env_value_is_nonempty(var("OTEL_EXPORTER_OTLP_ENDPOINT").as_deref())
}

fn env_value_is_nonempty(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

fn env_value_is_true(value: Option<&OsStr>) -> bool {
    env_value_matches_bool(value, &["1", "true", "yes", "on"])
}

fn env_value_is_false(value: Option<&OsStr>) -> bool {
    env_value_matches_bool(value, &["0", "false", "no", "off"])
}

fn env_value_matches_bool(value: Option<&OsStr>, matches: &[&str]) -> bool {
    value
        .and_then(OsStr::to_str)
        .map(|value| {
            let value = value.to_ascii_lowercase();
            matches.iter().any(|candidate| value == *candidate)
        })
        .unwrap_or(false)
}

/// Install a panic hook that prints the panic to stderr and exits 99
/// (the documented "internal panic" code in `cli.md`). Without this,
/// panics use Rust's default hook and exit with status 101, which
/// operator scripts cannot distinguish from the spec-named exit codes.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|loc| format!(" at {}:{}", loc.file(), loc.line()))
            .unwrap_or_default();
        let message = info
            .payload()
            .downcast_ref::<&'static str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<unknown panic payload>");
        eprintln!("panic{location}: {message}");
        std::process::exit(99);
    }));
}

async fn run() -> ovstorage::Result<()> {
    let cli = Cli::parse();

    let loaded = load_startup_config(cli.no_config, cli.config.as_deref())?;
    let lib = build_library(&loaded)?;
    let mut state = session::SessionState::build(lib, loaded).await?;

    let Some(command) = cli.command else {
        return commands::repl::run(&mut state).await;
    };

    dispatch_with_cancel(command, &mut state).await
}

/// Resolve the startup config according to flag precedence:
/// `--no-config` → empty, else `--config PATH` → parse, else `$OVSTORAGE_CONFIG`
/// → parse, else the default search path. None present is fine; the CLI runs
/// with no pre-configured connections.
fn load_startup_config(
    no_config: bool,
    explicit: Option<&Path>,
) -> ovstorage::Result<LibraryConfig> {
    if no_config {
        return Ok(LibraryConfig::default());
    }
    if let Some(path) = explicit {
        return LibraryConfig::from_toml_path(path);
    }
    if let Some(path) = std::env::var_os("OVSTORAGE_CONFIG") {
        return LibraryConfig::from_toml_path(Path::new(&path));
    }
    Ok(LibraryConfig::from_default_path()?.unwrap_or_default())
}

/// Inner command dispatch; for end-user paths, use `dispatch_with_cancel`.
pub(crate) async fn dispatch(
    command: Command,
    state: &mut session::SessionState,
    cancel: &CancellationToken,
) -> ovstorage::Result<()> {
    match command {
        Command::ListRoutes => commands::connect::list_routes(state)?,
        Command::ListBackends => commands::connect::list_backends(state)?,
        Command::CacheStatus => commands::cache::cache_status(state)?,
        Command::CacheDoctor => commands::cache::cache_doctor(state)?,
        Command::CacheGc => commands::cache::cache_gc(state)?,
        Command::CacheStats => commands::cache::cache_stats(state)?,
        Command::StateStatus => commands::cache::state_status(state)?,
        Command::Doctor { json } => commands::doctor::run(state.library.clone(), json).await?,
        Command::Stat {
            address,
            full_metadata,
        } => commands::files::stat(state, &address, full_metadata, cancel).await?,
        Command::Read {
            address,
            output,
            range,
            if_match,
        } => {
            commands::files::read(
                state,
                &address,
                output.as_deref(),
                range.as_deref(),
                if_match.as_deref(),
                cancel,
            )
            .await?
        }
        Command::Write {
            address,
            input,
            no_overwrite,
            if_match,
            metadata,
            message,
        } => {
            commands::files::write(
                state,
                commands::files::WriteArgs {
                    address,
                    input,
                    no_overwrite,
                    if_match,
                    metadata,
                    message,
                },
                cancel,
            )
            .await?
        }
        Command::Delete { address, if_match } => {
            commands::files::delete(state, &address, if_match.as_deref(), cancel).await?
        }
        Command::List {
            prefix,
            recursive,
            full_metadata,
            max_results,
            page_token,
            format,
        } => {
            commands::directory::list(
                state,
                commands::directory::ListArgs {
                    prefix,
                    recursive,
                    full_metadata,
                    max_results,
                    page_token,
                    format,
                },
                cancel,
            )
            .await?
        }
        Command::Cp {
            src,
            dest,
            if_source,
            if_dest,
            message,
        } => {
            commands::files::cp(
                state,
                &src,
                &dest,
                if_source.as_deref(),
                if_dest.as_deref(),
                message,
                cancel,
            )
            .await?
        }
        Command::ListVersions {
            address,
            max_results,
            page_token,
            format,
        } => {
            commands::files::list_versions(state, &address, max_results, page_token, format, cancel)
                .await?
        }
        Command::GetLatestVersion { address } => {
            commands::files::get_latest_version(state, &address, cancel).await?
        }
        Command::Mv {
            src,
            dest,
            if_source,
            if_dest,
            message,
        } => {
            commands::files::mv(
                state,
                &src,
                &dest,
                if_source.as_deref(),
                if_dest.as_deref(),
                message,
                cancel,
            )
            .await?
        }
        Command::CreateDirectory { address } => {
            commands::directory::create_directory(state, &address, cancel).await?
        }
        Command::DeleteDirectory {
            address,
            recursive,
            dry_run,
            yes,
        } => {
            commands::directory::delete_directory(state, &address, recursive, dry_run, yes, cancel)
                .await?
        }
        Command::UpdateMetadata {
            address,
            set,
            remove,
            if_match,
            allow_rewrite_emulation,
            message,
        } => {
            commands::files::update_metadata(
                state,
                commands::files::UpdateMetadataArgs {
                    address,
                    set,
                    remove,
                    if_match,
                    allow_rewrite_emulation,
                    message,
                },
                cancel,
            )
            .await?
        }
        Command::CheckAccess { address, ops } => {
            commands::files::check_access(state, &address, &ops, cancel).await?
        }
        Command::Cd { address } => commands::directory::cd(state, &address, cancel).await?,
        Command::Echo { words } => println!("{}", words.join(" ")),
        Command::Connect {
            kind,
            fields,
            auth,
            name,
            advanced,
        } => {
            commands::connect::run(
                state,
                commands::connect::Args {
                    kind,
                    fields,
                    auth,
                    name,
                    advanced,
                },
                cancel,
            )
            .await?
        }
        Command::Reauth { name } => commands::connect::reauth(state, &name, cancel).await?,
        Command::WriteConfig {
            path,
            force,
            secrets,
        } => commands::write_config::run(state, &path, force, secrets)?,
        Command::WatchDirectory {
            prefix,
            recursive,
            no_metadata_changes,
            since,
        } => {
            commands::directory::watch_directory(
                state,
                &prefix,
                recursive,
                no_metadata_changes,
                since.as_deref(),
                cancel,
            )
            .await?
        }
    }
    Ok(())
}

/// Run `dispatch` with SIGINT handling: first Ctrl+C cancels the
/// in-flight command cooperatively; a second Ctrl+C within
/// `interrupt::INTERRUPT_WINDOW` force-exits with code 130.
pub(crate) async fn dispatch_with_cancel(
    command: Command,
    state: &mut session::SessionState,
) -> ovstorage::Result<()> {
    let token = CancellationToken::new();
    let mut fut = std::pin::pin!(dispatch(command, state, &token));
    let mut previous: Option<std::time::Instant> = None;
    loop {
        tokio::select! {
            res = &mut fut => return res,
            _ = tokio::signal::ctrl_c() => {
                let now = std::time::Instant::now();
                match interrupt_decision(previous, now) {
                    InterruptDecision::Escalate => std::process::exit(130),
                    InterruptDecision::Arm => {
                        eprintln!(
                            "^C — press Ctrl+C again within {}s to force-exit",
                            crate::interrupt::INTERRUPT_WINDOW.as_secs(),
                        );
                        token.cancel();
                        previous = Some(now);
                    }
                }
            }
        }
    }
}

fn build_library(loaded: &LibraryConfig) -> ovstorage::Result<Arc<Library>> {
    ovstorage::init_auth_substrate(Some(&cli_auth_state_root()?))?;

    let mut builder = Library::builder();
    if let Some(cache) = cache_from_loaded_or_env(loaded.state.as_ref())? {
        builder = builder.with_cache(cache);
    }
    let library = builder.open()?;

    // SAFETY: dlopen runs platform loader hooks; the user/operator controls
    // `OVSTORAGE_PLUGIN_DIR` and the binary's install dir.
    unsafe {
        library.load_plugins_from_dir(None)?;
    }
    Ok(library)
}

fn cli_auth_state_root() -> ovstorage::Result<PathBuf> {
    if let Some(value) = std::env::var_os("OVSTORAGE_AUTH_DIR") {
        return Ok(PathBuf::from(value));
    }
    let tmp = std::env::temp_dir().join(format!("ovstorage-cli-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|error| {
        Error::new(
            ErrorCode::StateRootUnavailable,
            format!("failed to create CLI auth state root: {error}"),
        )
    })?;
    Ok(tmp)
}

pub(crate) fn error_code_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::NotFound => "NotFound",
        ErrorCode::AlreadyExists => "AlreadyExists",
        ErrorCode::PermissionDenied => "PermissionDenied",
        ErrorCode::PreconditionFailed => "PreconditionFailed",
        ErrorCode::Conflict => "Conflict",
        ErrorCode::DirectoryNotEmpty => "DirectoryNotEmpty",
        ErrorCode::Unsupported => "Unsupported",
        ErrorCode::InvalidArgument => "InvalidArgument",
        ErrorCode::IncompatibleType => "IncompatibleType",
        ErrorCode::Locked => "Locked",
        ErrorCode::Cancelled => "Cancelled",
        ErrorCode::DeadlineExceeded => "DeadlineExceeded",
        ErrorCode::Transient => "Transient",
        ErrorCode::ResourceExhausted => "ResourceExhausted",
        ErrorCode::IntegrityFailure => "IntegrityFailure",
        ErrorCode::BrokerUnavailable => "BrokerUnavailable",
        ErrorCode::AuthRequired => "AuthRequired",
        ErrorCode::AuthCancelled => "AuthCancelled",
        ErrorCode::AuthExpired => "AuthExpired",
        ErrorCode::ObjectModified => "ObjectModified",
        ErrorCode::NoRoute => "NoRoute",
        ErrorCode::NotConfigured => "NotConfigured",
        ErrorCode::CredentialUnavailable => "CredentialUnavailable",
        ErrorCode::CredentialExpired => "CredentialExpired",
        _ => "Error",
    }
}

/// Map `ErrorCode` to the operator-facing exit code documented in
/// `docs/crates/ovstorage-cli.md`. Codes not in the spec table fall
/// through to `1` (generic error).
fn exit_code(code: ErrorCode) -> i32 {
    match code {
        ErrorCode::NotFound => 2,
        ErrorCode::PermissionDenied => 3,
        ErrorCode::PreconditionFailed => 4,
        ErrorCode::Conflict => 5,
        ErrorCode::Unsupported => 6,
        ErrorCode::InvalidArgument => 7,
        ErrorCode::Cancelled => 8,
        ErrorCode::DeadlineExceeded => 9,
        ErrorCode::Transient => 10,
        ErrorCode::ResourceExhausted => 11,
        ErrorCode::IntegrityFailure => 12,
        ErrorCode::BrokerUnavailable => 13,
        ErrorCode::AuthRequired => 14,
        ErrorCode::DirectoryNotEmpty => 15,
        ErrorCode::AlreadyExists => 16,
        ErrorCode::IncompatibleType => 17,
        ErrorCode::Locked => 18,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_maps_documented_codes() {
        assert_eq!(exit_code(ErrorCode::NotFound), 2);
        assert_eq!(exit_code(ErrorCode::PermissionDenied), 3);
        assert_eq!(exit_code(ErrorCode::PreconditionFailed), 4);
        assert_eq!(exit_code(ErrorCode::Conflict), 5);
        assert_eq!(exit_code(ErrorCode::Unsupported), 6);
        assert_eq!(exit_code(ErrorCode::InvalidArgument), 7);
        assert_eq!(exit_code(ErrorCode::Cancelled), 8);
        assert_eq!(exit_code(ErrorCode::DeadlineExceeded), 9);
        assert_eq!(exit_code(ErrorCode::Transient), 10);
        assert_eq!(exit_code(ErrorCode::ResourceExhausted), 11);
        assert_eq!(exit_code(ErrorCode::IntegrityFailure), 12);
        assert_eq!(exit_code(ErrorCode::BrokerUnavailable), 13);
        assert_eq!(exit_code(ErrorCode::AuthRequired), 14);
        assert_eq!(exit_code(ErrorCode::DirectoryNotEmpty), 15);
        assert_eq!(exit_code(ErrorCode::AlreadyExists), 16);
        assert_eq!(exit_code(ErrorCode::IncompatibleType), 17);
        assert_eq!(exit_code(ErrorCode::Locked), 18);
    }

    #[test]
    fn exit_code_falls_through_to_one() {
        assert_eq!(exit_code(ErrorCode::Internal), 1);
        assert_eq!(exit_code(ErrorCode::NoRoute), 1);
    }

    #[test]
    fn tracing_is_quiet_without_observability_env() {
        assert!(!tracing_requested(&[]));
    }

    #[test]
    fn tracing_is_requested_by_log_filters() {
        assert!(tracing_requested(&[("OVSTORAGE_LOG", "info")]));
        assert!(tracing_requested(&[("RUST_LOG", "ovstorage=debug")]));
    }

    #[test]
    fn empty_log_filters_do_not_request_tracing() {
        assert!(!tracing_requested(&[("OVSTORAGE_LOG", "")]));
        assert!(!tracing_requested(&[("RUST_LOG", "")]));
    }

    #[test]
    fn tracing_is_requested_by_otlp_env() {
        assert!(tracing_requested(&[("OVSTORAGE_OTLP", "1")]));
        assert!(tracing_requested(&[(
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "http://127.0.0.1:4318/v1/traces",
        )]));
        assert!(tracing_requested(&[(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "http://127.0.0.1:4318",
        )]));
    }

    #[test]
    fn otlp_disable_env_prevents_endpoint_only_tracing() {
        assert!(!tracing_requested(&[
            ("OTEL_SDK_DISABLED", "true"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
        ]));
        assert!(!tracing_requested(&[
            ("OVSTORAGE_OTLP", "0"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
        ]));
    }

    fn tracing_requested(vars: &[(&str, &str)]) -> bool {
        tracing_requested_from_env_with(|name| {
            vars.iter()
                .find(|(candidate, _)| *candidate == name)
                .map(|(_, value)| OsString::from(value))
        })
    }
}
