# ovstorage-cli

## Quick start

From the repo root:

```sh
make dist                # assembles ./dist/ at the repo root
./dist/ovstorage
```

That drops you into the interactive shell with all backend plugins (`file`, `http`, `s3`, `azure`, `gcs`, `opendal`, `nucleus`, `omniverse-storage-service`, `broker-client`) discovered from `dist/plugins/`. From there:

- Type `connect` to interactively set up a backend connection.
- Type `help` to list available commands.
- `quit` (or Ctrl+D) exits.

For one-shot use, pass a subcommand: `./dist/ovstorage list-routes`. Run `./dist/ovstorage --help` for the full subcommand list with flags.

`make dist` builds every workspace (slow on the first run); subsequent runs are incremental. For day-to-day iteration on the CLI itself, build just the binary in-place with `cd ovstorage-core && cargo run -p ovstorage-cli` and point `OVSTORAGE_PLUGIN_DIR` at `../dist/plugins/` so the plugin set you already built is picked up.

## What's next

Once `connect` and the other commands feel familiar, the same operations are available as code:

- **Use it from your app** — [library-rust](../../docs/public/library-rust/README.md), [library-python](../../docs/public/library-python/README.md), [library-cpp](../../docs/public/library-cpp/README.md), or [library-web](../../docs/public/library-web/README.md) (browser/Node via REST). Rust applications drive a composed `Stack` through `Layer` and `LayerExt`; the other bindings expose the same Layer model in their native style.
- **Run a multi-tenant daemon** — [broker-operator](../../docs/public/broker-operator/README.md) for credential isolation, fleet-shared metadata, and policy enforcement.
- **Write a custom backend** — [plugin-storage](../../docs/public/plugin-storage/README.md) (foundation: [plugin-development](../../docs/public/plugin-development/README.md)).

To carry connections from this interactive session into your app, save them to disk first:

```text
> write-config ~/.config/ovstorage/ovstorage.toml --secrets env
```

`--secrets env` prints to stderr the env-var names it derived for the session's
literal credentials — a value already written as `${...}` keeps its own name and
is not listed. Export them before `ovstorage::host::build_stack`, which is where
substitution happens: parsing the TOML succeeds with the variables unset, and
the build then fails with `NotConfigured` naming the credential and the variable
it wanted.

Applications can load the emitted `[ovstorage.layers.*]` graph as a `StackConfig`
and pass it with the installed plugin factories to
`ovstorage::host::build_stack`. Each `library-*` README shows the native entry
point.

## Purpose

`ovstorage-cli` is the `ovstorage` binary — a thin Unix-style command-line client over the [ovstorage](../ovstorage/README.md) public API. Subcommands dispatch through the active Stack plus a small handful of operator-facing diagnostics. The crate is primarily an exerciser for the public API; it is not load-bearing for any other component, and any other binary that wants the same surface (`ovstorage-rest`, ad-hoc deployment scripts) links `ovstorage` directly rather than shelling out to this binary.

The crate exists as a separate Cargo target rather than as a library helper because the diagnostic subcommands (`list-routes`, `list-backends`, `cache-status`, ...) belong to the operator/debug tool inventory; they're invoked from packaging tests, CI gates, and shell scripts where exit codes and stable text output matter more than a Rust API would. They are not part of the normal application-user workflow.

## Public surface

A single binary, `ovstorage`, with subcommands grouped by purpose.

The CLI keeps the same API split as [ovstorage](../ovstorage/README.md): object I/O commands act on addresses, connection / alias commands manage the route table, and diagnostics inspect the process configuration and local state. That split is part of the command contract; new public operations should land in one of these groups rather than as ad-hoc flags on unrelated commands.

The binary implements:

- Object I/O: `stat`, `read`, `write`, `delete` / `rm`, `list`, `list-versions` / `versions`, `get-latest-version` / `pin-latest`, `cp`, `mv`, `create-directory` / `mkdir`, `delete-directory` / `rmdir`, `update-metadata`, `check-access`, `watch-directory`. Hidden aliases match common Unix / DOS muscle memory: `list` accepts `ls` / `ll` / `dir`; `cp` accepts `copy`; `mv` accepts `move` / `rename` / `ren`; `read` accepts `cat` / `get`; `write` accepts `put`; `delete` adds `remove` / `del`; `create-directory` adds `make-dir` / `md`; `delete-directory` adds `remove-dir` / `rd`; `stat` accepts `info`; `cd` accepts `chdir`; `check-access` accepts `access`; `update-metadata` accepts `set-meta`.
- Configuration: `connect` (interactive backend setup), `write-config` (serialize the active session to TOML).
- Diagnostics: `list-routes`, `list-backends`, `cache-status`, `state-status`.
- Interactive: invoking the binary with no subcommand drops into a `rustyline`-backed interactive shell where every subcommand above is available. `quit` (or Ctrl+D) exits; bare `help` lists the available commands; `help <cmd>` and `<cmd> --help` show the same per-subcommand help as one-shot mode. The same in-memory session spans the whole interactive session, so `connect` followed by `write-config` works without re-entering credentials. The interactive shell also exposes `cd <address>` for setting a current directory that resolves relative addresses in subsequent commands; outside it, `cd` returns `InvalidArgument` because the new pwd would be discarded as the process exits.

Configuration is loaded from `--config PATH` (or `$OVSTORAGE_CONFIG`) at startup, falling back to `./ovstorage.toml` then `$XDG_CONFIG_HOME/ovstorage/ovstorage.toml`; pass `--no-config` to skip discovery entirely. The CLI loads plugin factories and constructs the configured `[ovstorage.layers.*]` graph before the first subcommand dispatches.

Several command shapes below are not wired into the parser. Anywhere a flag or subcommand is marked **(not wired)**, the library API exists but the CLI parser does not expose it. See [Implementation gaps](#implementation-gaps) for the list.

### Object I/O subcommands

```text
ovstorage stat <address> [--full-metadata]
ovstorage read <address> [--range <start>-<end>] [-o <local-file>|-] [--if-match <identity>]
ovstorage write <address> [--no-overwrite] [-i <local-file>|-] [--if-match <identity>] [--metadata key=value]...
ovstorage delete <address> [--if-match <identity>]
ovstorage list <prefix> [--recursive] [--full-metadata] [--max-results N] [--page-token TOKEN] [--format human|table]
ovstorage list-versions <address> [--max-results N] [--page-token TOKEN] [--format human|table]
ovstorage get-latest-version <address>                          # returns the current-head ObjectInfo (or the
                                                                #   pinned version if <address> already carries one)
ovstorage pin-latest <address>                                  # alias for `get-latest-version`
ovstorage cp <src> <dest> [--if-match <identity>]
ovstorage mv <src> <dest> [--if-match <identity>]
ovstorage rm <address> [--if-match <identity>]                 # alias for `delete`
ovstorage update-metadata <address> [--set k=v]... [--remove k]... [--if-match <identity>] [-m <message>] [--allow-rewrite-emulation]
ovstorage check-access <address> <ops>                         # ops: comma-separated subset of {read,write,delete,update_metadata}
ovstorage create-directory <address>
ovstorage mkdir <address>                                      # alias for `create-directory`
ovstorage delete-directory <address>
ovstorage rmdir <address>                                      # alias for `delete-directory`
ovstorage watch-directory <prefix> [--recursive] [--no-metadata-changes] [--since <cursor_b64>]
```

`--if-match` accepts a JSON object `{"etag":"...","version":"...","size":N,"mtime":<unix-seconds>}` (any subset of fields). The JSON form is the portable representation across binaries; it's not the form operators are expected to type by hand. `--if-match-from-stat <address>` is the **intended ergonomic shorthand (target, not currently wired)**: in the target design, the CLI reads the address's current identity in-process and uses it as the precondition, so the common "match what I just got" case never requires typing JSON. The flag is not parsed today; today the JSON form is the only spelling — see [Implementation gaps](#implementation-gaps). `stat` itself does not accept `--if-match` because `StatOptions` carries no precondition field — apply preconditions on `read` / `write` / `delete` instead.

Output is line-oriented and stable: `stat` prints one canonical key=value pair per line; `list` and `list-versions` default to one address per line and accept `--format=table` for aligned columns; `watch-directory` prints one event per line as JSON for piping into `jq`. Exit codes track the [ovstorage-plugin](../ovstorage-plugin/README.md) error taxonomy: `0` success, `1` generic failure, `2` `NotFound`, `3` `PermissionDenied`, `4` `PreconditionFailed`, `5` `Conflict`, `6` `Unsupported`, `7` `InvalidArgument`, `8` `Cancelled`, `9` `DeadlineExceeded`, `10` `Transient`, `11` `ResourceExhausted`, `12` `IntegrityFailure`, `13` `BrokerUnavailable`, `14` `AuthRequired`, `15` `DirectoryNotEmpty`, `16` `AlreadyExists`, `17` `IncompatibleType`, `18` `Locked`, `19` `PartialCompletion`, `99` internal panic. All 19 documented codes are mapped; remaining `ErrorCode` variants (Internal, NoRoute family, etc.) fall through to `1`. The panic hook is installed in `main` so an unexpected panic in any handler prints `panic at <file>:<line>: <message>` to stderr and exits `99`.

### Connection-management subcommands (not wired)

The shapes below mirror [ovstorage-plugin](../ovstorage-plugin/README.md) § "Connection-management types" and [ovstorage](../ovstorage/README.md) § "Authentication". Of these, only `list-backends` is wired into the parser; the rest are **not wired** — the library APIs exist, but the CLI does not expose them. `connect` is the only way to introduce a new connection from the binary.

```text
ovstorage list-backends
ovstorage add-connection <kind> --config k=v... --credential k=v... [--persist] [--display-name NAME]    # not wired
ovstorage remove-connection <connection-id>                                                             # not wired
ovstorage update-connection-credentials <connection-id> --credential k=v...                             # not wired
ovstorage list-connections                                                                              # not wired
ovstorage authenticate-connection <connection-id> [--device] [--no-browser]                             # not wired (the standalone subcommand; `connect` now invokes the underlying authenticate_connection inline)
```

### Alias subcommands (not wired)

Mirror [ovstorage-plugin](../ovstorage-plugin/README.md) § "Alias types" and [ovstorage](../ovstorage/README.md) § "Address-root introspection types". None of these are wired into the parser; they are listed here as the CLI shape for these operations.

```text
ovstorage add-alias <from> <to> [--persist] [--visibility visible|hidden|suppressed]    # not wired
ovstorage remove-alias <alias-id>                                                       # not wired
ovstorage list-aliases                                                                  # not wired
ovstorage set-address-visibility <address> visible|hidden|suppressed [--persist]        # not wired
ovstorage list-address-roots [--include-hidden]                                         # not wired
```

### Configuration subcommands

```text
ovstorage connect [--advanced]            # interactive walkthrough: pick a backend, fill in the
                                          # common config fields, choose a credential method,
                                          # authenticate live, push to session
ovstorage reauth <name>                   # drive interactive auth for an existing connection
                                          # (refresh-token expired, or user wants to log in again)
ovstorage write-config [PATH] [--force] [--secrets plaintext|env]
                                          # serialize loaded + connect-pending connections to TOML
```

`connect` consumes the chosen plugin's `StorageBackendKindDescriptor` schema. By default it surfaces only common config fields (those with `advanced = false`) and presents the descriptor's `credential_methods` as a picker — pick e.g. "single sign-on", "static access key", "default credential chain"; only the fields that method needs are prompted. After registering the connection it streams `authenticate_connection` events live: `OpenBrowser` URLs are printed and best-effort handed to the OS browser, `DeviceCode` flows print the verification URL + code, and the run terminates on `Succeeded` / `Failed` / `Cancelled` — or immediately, without any event, when the backend answers `Unsupported` because it has no interactive flow. A `--advanced` flag re-exposes hidden config fields and falls back to walking every credential field one-by-one (the legacy path). The display name prompt comes last and is optional. Plaintext credentials typed at connect are encoded per `write-config --secrets` policy; `${ENV_VAR}` refs round-trip verbatim.

`reauth <name>` reuses the same auth-event plumbing for a connection that's already loaded from `[[connections]]` (or registered programmatically). Use it when the connection is parked in `AwaitingAuth { reason: NeverAuthenticated | RefreshTokenExpired }` after startup, or when the user wants to log in again proactively. `BackendUnreachable` parks (network down, broker offline) do **not** need `reauth`: the dispatcher silently retries on the next request — `reauth` is only for the credential-failure case. A backend with no interactive flow answers `reauth` with `Unsupported`: there is nothing to sign in to. That is `azure`, `gcs`, `s3` and `opendal`, whose credentials arrive with the connection; broker connections on a direct endpoint (any address that is not `http(s)://` — `grpc://`, `grpc+tcp://`, `grpc+tls://`, `unix:/…`, `npipe:/…`), which have no OAuth surface; and `file` and `http`, which have no connection-auth driver at all. Where a credential is what is missing, the way back is one the origin accepts, supplied where the connection gets it (the config, or the `connect` invocation) — `file` needs none at all; `azure`, `gcs` and `s3` additionally promote a parked connection once one of its operations is accepted by the origin.

`write-config` counts a session credential as a reference when it carries a `${IDENT}` the loader would substitute — the same grammar `resolve_env_refs` applies, shared with it rather than reimplemented — and treats everything else as a literal. It requires `--secrets` when any literal is present, and provenance plays no part: the session does not record whether a credential arrived from a loaded `[[connections]]` entry or was typed at `connect`, so a literal loaded from TOML needs the flag like any other and is then encoded per the chosen policy, `--secrets env` rewriting it to an env-var reference rather than preserving it. A value that contains `$` and a brace without forming a reference — `secret${unterminated`, say — is a literal and needs the flag, because that is what the loader would make of it too. An embedded reference like `prefix-${VAR}-suffix` is a genuine reference: the loader substitutes it in place, so it passes through whole under either policy and with no `--secrets` at all — which also means the non-reference part of such a value is written out as it stands, so do not leave secret material beside a reference in one field. Connection slugs are de-duplicated across the output: two connections that sanitize to the same base slug get `-2`, `-3`, ... appended so env-var names never collide. With `--secrets env`, an env-var name is derived (`OVSTORAGE_<KIND>_<SLUG>_<FIELD>`) and printed for the user to export. With `--secrets plaintext`, the literal value is emitted into the TOML and a loud warning is printed.

The output file is created with mode `0600` on Unix via an atomic-rename pattern (write to a sibling `.tmp.<pid>` file with `O_CREAT|O_EXCL|0o600`, then `rename` over the destination). `--force` follows the same pattern, replacing the destination atomically rather than truncating it in place — this guarantees that pre-existing permissive bits or symlinks do not leak credentials on multi-user hosts.

`write-config` serializes the live Stack graph as `[ovstorage.layers.*]` together with the host's state and connection data, so a load → write-config cycle preserves operator-authored settings rather than dropping them on the floor.

For pre-deploy config validation, any `ovstorage --config PATH` subcommand exits non-zero on malformed layer or connection configuration. Startup uses the same `host::build_stack` path as the other Rust hosts, so graph validation, plugin-kind resolution, and connection registration run before command dispatch.

### Diagnostic subcommands

```text
ovstorage list-backends              # backend kinds this stack declares, and runtime-add support
ovstorage list-routes                     # routing table; prints address-roots with backend + visibility
ovstorage cache-status                    # cache root, entries, total/max bytes, staging files
ovstorage state-status                    # state root, live process leases, entry count
ovstorage cache-doctor                    # dry-run recovery: rows examined / reaped / quarantined / missing-CAS counts
ovstorage cache-gc                        # drive cache GC; prints post-pass entry count + total bytes
ovstorage cache-stats                     # cache-status output augmented with live process leases, staging files, max-bytes
```

A successful `list-routes` (or any other subcommand) is itself a config-health probe: every CLI invocation parses the active TOML, resolves secret refs, and builds the configured Stack before dispatching. Failures surface as typed errors before the subcommand body runs.

`list-backends` prints the backend layers the loaded Stack was built with, as `kind`, `display_name`, and `runtime_add`. It is not a catalogue of installed plugins: a kind appears only once the active config declares a layer for it, and that holds for the built-in `file` backend — which needs no plugin artifact — as much as for a kind provided from `OVSTORAGE_PLUGIN_DIR`. A plugin sitting in that directory with no layer declared against it is not listed.

`list-routes` does not show a per-row source (`programmatic`/`env`/`project`/`user`/`machine`); it prints `prefix`, `backend`, and `visibility` only. The source column is tracked under [Implementation gaps](#implementation-gaps).

## Internals

The binary parses arguments through `clap`'s derive macros. Each subcommand maps to one or two `Layer`/`LayerExt` calls plus output formatting; there is no business logic that doesn't already live in the library. The crate's contribution is:

- **Address parsing.** `<address>` arguments are passed through the public address parser ([ovstorage-plugin](../ovstorage-plugin/README.md)); parse errors surface as `InvalidArgument` with the parser's own message. A span-underlined diagnostic is not implemented.
- **Identity parsing.** `--if-match <identity>` accepts the JSON shape `{etag, version, size, mtime}` (any subset; `mtime` is integer Unix seconds). Wired on `read`, `write`, `delete`/`rm`, `cp`, `mv`, `update-metadata`. `stat` does NOT carry `--if-match` because `StatOptions` has no `if_match` field; `delete-directory` does not either (the SPI's `DeleteDirectoryOptions` is a unit struct).
- **Stream handling.** `read` consumes `LayerExt::read_stream` and copies chunks to the destination writer; it never materializes the object body in a `Vec<u8>` on the host. `read -o FILE` writes the streamed chunks to `FILE` through a `BufWriter`. `read -o -` and `write -i -` are explicit stdout / stdin spellings: in both cases `"-"` short-circuits to `std::io::stdout()` / `std::io::stdin()` rather than opening a file literally named `-`. `write` without `-i` (or with `-i -`) wraps stdin in a 64 KiB-chunk iterator and passes `Body::Stream`, so the public-gateway "streaming writes must be true-streaming" rule holds end-to-end on the CLI as well.
- **Directory operations.** `create-directory` (`mkdir`) is an idempotent ensure-directory operation: an existing target directory or flat-store marker returns success, while incompatible non-directory objects still surface a typed backend error. `delete-directory` (`rmdir`) removes only the backend's directory representation; subtree delete is host-side composition (callers walk + bulk-delete themselves). The library treats `<address>` and `<address>/` as the same directory address for these commands and for `list`; `stat` uses the spelling as a hint (`foo` object-first, `foo/` directory-only).
- **watch-directory pretty-printing.** `watch-directory` prints one JSON object per line including `Lapsed` events explicitly so a downstream consumer can re-list when it sees one. The cursor is emitted as base64 in the `cursor_b64` field — `WatchDirectoryCursor` is opaque bytes (`Vec<u8>`) and may carry non-UTF-8 provider tokens, so the CLI accepts and emits base64 to round-trip them losslessly. `--since` takes the same base64 token verbatim.
- **Cancellation.** Every long-running command propagates a `CancellationToken` through to the library. A first Ctrl+C cancels in-flight work cooperatively (exit `8` = `Cancelled`); a second Ctrl+C within 10 seconds force-exits with `130`. The interactive REPL idle prompt follows the same double-tap to clean-exit (saving history). The 10-second window is centralized in `src/interrupt.rs`. Cancelling an idle `watch-directory` leaks one blocking thread until the upstream producer emits one more event; this is acceptable for REPL use and invisible in one-shot mode.
- **Auth event handling.** Documented shape for `authenticate-connection`: prints `OpenBrowser` / `DeviceCode` to stderr; `--no-browser` suppresses the auto-open and prints the URL to stdout for the user to copy. The subcommand is not wired.

The CLI loads ABI-v2 plugin factories before calling `host::build_stack`. Repeated invocations (the typical shell-script case of `ovstorage list ... | xargs ovstorage stat`) each pay one plugin-load cost; users who want amortized cost run their own loop in a single process.

The CLI does not install structured tracing unless observability is explicitly requested via `OVSTORAGE_LOG`, `RUST_LOG`, `OVSTORAGE_OTLP`, or an OTLP endpoint env var. For startup and plugin-load diagnostics, run `OVSTORAGE_LOG=info ./dist/ovstorage`.

## Dependencies

In-workspace: [ovstorage](../ovstorage/README.md) and [ovstorage-cache](../ovstorage-cache/README.md). Backend plugins are loaded at runtime via `dlopen` from `OVSTORAGE_PLUGIN_DIR` (or the platform default), not as Cargo deps; this keeps the CLI binary independent of which plugins ship on a given install.

External: `clap` (derive parser), `inquire` (interactive prompts in `connect`), `rustyline` (interactive shell), `serde_json` (`--if-match` JSON parse, `watch-directory` event encode), `shell-words` (interactive line splitting), `tokio` (current-thread runtime), `toml`, and `url`.

## Threat model

The binary runs as the user. Its optional config adapter reads the standard locations, builds registration calls, and never writes those source files — config edits go through whatever the operator already uses (text editor, configuration-management tool). The binary writes to `state_root` and `cache_root` exactly insofar as the underlying library calls do; nothing in the CLI bypasses the library's redaction or logging guarantees.

`write-config` inlines a literal secret only when `--secrets plaintext` is explicitly passed; the default refusal protects against accidentally committing credentials to disk. With `--secrets env`, every literal is replaced by an `${OVSTORAGE_...}` reference and the secret material stays in the environment. What earns pass-through is a `${IDENT}` the loader would resolve, not the presence of a `$` and a brace, so a literal that merely looks reference-shaped is encoded like any other. One residual remains and cannot be closed here: a value carrying a resolvable reference *among other text* — `AKIA${ACCOUNT_SUFFIX}` — passes through whole, so its literal portion reaches the file with no policy demanded and no warning. That form is indistinguishable from the supported `prefix-${VAR}-suffix`; put the whole secret behind one reference if none of it should be in the file. There is no keyring policy: `write-config` never writes to the secret store, and `[[connections]].credentials` values are strings resolved by `${VAR}` substitution only, so no reference form points at one. A secret-store entry can still be created by a *backend* the CLI loads — a plugin that persists a credential during `connect` or `reauth` reaches the secret store through the host's `secret_put` callback — but nothing in that path is selected by `--secrets`, and none of it round-trips into the TOML.

`cache-status`, `state-status`, and the `cache ...` subcommands read internal counters and never print bytes from cached objects, OAuth tokens, or pre-signed URLs. The status output is structured key=value lines suitable for `grep`-ing in operational dashboards.

## Implementation gaps

Drift between this document and the binary. Rust APIs exist for everything in this list — these are CLI-parser/output gaps only.

- **Connection-management subcommands not wired:** `add-connection`, `remove-connection`, `update-connection-credentials`, `list-connections`, `authenticate-connection`. (`connect` is the only path to add a connection from the CLI.)
- **Alias subcommands not wired:** `add-alias`, `remove-alias`, `list-aliases`, `set-address-visibility`, `list-address-roots`.
- **Address parse errors are not span-underlined.** `address::parse(input)` returns the underlying error's message.
- **`list-routes` lacks the per-row source column.** Doc names a `source` column; impl prints `prefix\tbackend\tvisibility` only.
- **`error_code_name()` collapses tail variants.** Covers 24 distinct names; remaining `ErrorCode` variants (Internal, NoRoute family) collapse to `"Error"`.
- **`--if-match-from-stat <address>` is not wired.** The JSON `--if-match` form is the only spelling the parser accepts today; the ergonomic shorthand described in the Object I/O surface is the intended design, not currently shipped.
- **No conformance tests.** The "Conformance tests" section below describes the intended end-to-end suite; the CLI has unit tests in `commands::write_config` (slug disambiguation, atomic file mode) and `main.rs` (`exit_code`, `parse_if_match`, base64 cursor round-trip).

## Conformance tests

The CLI's job is to faithfully expose the library API; its conformance tests are end-to-end shell-style tests that:

- Verify each subcommand's stable output format (line-oriented, stable key order in `stat`, JSON-per-line in `watch-directory`, exit codes per the table above) is preserved across releases. Output-format regressions break operator scripts and are treated as breaking changes.
- Verify startup config loading rejects malformed TOML, and missing env vars referenced by `[[connections]].credentials`, with one diagnostic per problem on stderr.
- Verify `write-config` round-trips a loaded config (load `foo.toml` → immediate `write-config foo.toml --force` → byte-identical content), and that `--secrets` is required exactly when the session holds a credential carrying no resolvable `${IDENT}` — including one loaded from `[[connections]]`, and including a literal that contains `$` and a brace without forming a reference. Cover both directions: an embedded reference such as `prefix-${VAR}-suffix` must still pass through without the flag.
- Verify `delete-directory` leaves descendants untouched and returns `DirectoryNotEmpty` on real-directory backends; subtree delete is host-side composition and is exercised through the library's own walk + bulk-delete tests rather than a CLI flag.

There is no plugin-conformance work in this crate; plugin behavior is verified at the [ovstorage](../ovstorage/README.md) and per-plugin levels.

## Design constraints

- The CLI is a thin adapter: parse arguments, drive the Stack, format output, map errors to exit codes. Business logic lives in `ovstorage`.
- Stable text formats have golden output pinned before provider-specific options are added; shell users pin these strings.
- `cache-doctor`, `cache-gc`, and `cache-stats` go through public cache diagnostic hooks rather than reading SQLite directly from the CLI crate.
- Destructive commands are opt-in by spelling: `delete-directory` removes only the directory representation; subtree delete is the caller's explicit walk plus `delete` for file entries and `delete-directory` for directory entries. No glob expansion or trailing-slash heuristic enables recursion.
