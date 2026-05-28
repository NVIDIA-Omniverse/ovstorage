# ovstorage-cache

> **Implementation status banner.** This document is largely **spec / target design**, not the current shipped behavior. The crate is a synchronous CAS-and-index helper with one SQLite file `index.sqlite` carrying four tables: `entries` + `process_leases` + `cache_entries` + `schema_version`. Each major section below is tagged: **(implemented)** = present, **(partial)** = shipped in reduced form, **(spec)** = designed but not in code, **(scaffolded)** = type/module skeleton present but not yet wired through the `Cache::open` happy path, **(deferred)** = explicitly out-of-scope for the bootstrap crate. Concrete implementation gaps are enumerated in [Implementation notes](#implementation-notes).
>
> **What's implemented.** Versioned `migrations` framework with `schema_version` table; `cache_entries` table with `cas_key` PK; `CURRENT_SCHEMA_VERSION = 2` exposed at the crate root. The `HerdKey { Current, Guarded, Exact }` enum + `Cache::with_typed_herd_lock`; the legacy `with_herd_lock(&str)` keeps working unchanged. Different flavors hash into disjoint lock spaces. `lease::{CacheProcess, Lease}` (RAII drop semantics, cleanup-closure pattern), `fs_probe::{fs_kind, FsKind}` + `OVSTORAGE_ALLOW_NETWORK_FS` env override, `coordination::{CacheCoordination, acquire_writer_rendezvous}`, `observer::{Observer, LookupOutcome, FillOutcome, EvictionReason, NoopObserver}` — all wired into `Cache::open` / `put` / `get_entry` / `evict_to_limit`. `CacheOptions` carries `coordination` + `observer` fields. The on-disk process sentinel at `<state_root>/processes/<pid>.lock` is owned by `CacheProcess` itself; the on-disk file is unlocked and unlinked only when the last `Arc<CacheProcess>` drops, so a live `Lease` or sibling `Cache` handle keeps the sentinel held across the originating cache's drop. `ReadOnly` coordination is enforced through a single `ensure_writable` chokepoint that gates `put`, `put_with_existing_key_lock`, `remove_index`, and `remove_prefix`. `fs_kind` consults `statfs(2).f_type` on Linux against the NFS/CIFS/SMB/FUSE/Lustre/Ceph/GFS2/AFS/OCFS2 magic-number table; non-Linux targets fall back to the UNC string heuristic. The `Cache::lease(cas_key)` API mints leases that bump `cache_entries.lease_count` and pin rows against eviction; `lease()` verifies the backing CAS file exists before minting so a stale `cache_entries` row never produces a lease pointing at nothing.
>
> `Cache::recover()` walks the `processes/` directory, reaps orphaned sentinels (rows owned by dead pids), and repairs the index by removing rows whose CAS files are missing. `Cache::doctor()` is the dry-run variant. Recovery runs automatically at every `Cache::open`.
>
> `CacheHandle::lookup` / `lease` / `gc` / `doctor` are additive methods on `Cache` alongside the `put` / `get` / `entry` surface. `CacheLookup { cached, lease }` pairs cached bytes with a pinning lease in one call.
>
> `ovstorage cache doctor` / `cache gc` / `cache stats` CLI subcommands live in `ovstorage-cli`, surfacing `Cache::doctor` / `Cache::gc` / `Cache::status`. They honor `OVSTORAGE_STATE_ROOT` + `OVSTORAGE_CACHE_ROOT` env overrides like the `cache-status` subcommand.
>
> `tests/multi_process.rs` exercises sentinel sharing across same-process opens, orphan-sentinel reaping by recovery, `SharedSingleWriter` rendezvous refusing a second writer, herd-collapse serialization across threads, and lease-blocks-eviction lifecycle. Cross-pid `Command::spawn` testing for true `kill -9` semantics is not present.
>
> **Remaining as (spec).** The `auth.sqlite` separation, the full `current_index` / `exact_index` / `guarded_index` schema split, the 11 metric families' field-level wiring (only the subset emitted by the current `Observer` calls is implemented), the `staging` / `policy_snapshots` / `routes` tables, and the dedicated `herd/<kind>/<key>.lock` / `gc.lock` directory trees remain spec-only.

## Purpose (partial)

`ovstorage-cache` is a library, not a daemon: it is compiled into both client processes (via `ovstorage`) and the broker (`ovstorage-broker`) directly, and there is no cache RPC. It jointly owns `state_root` (durable state: SQLite WAL index, OAuth handles, leases, staging metadata, policy snapshots) and `cache_root` (opaque content-addressed object bytes), and provides the cross-process coordination primitives that let many processes — laptops, CI jobs, containers — share that on-disk state without a coordination daemon.

Concretely the crate owns:

- CAS file lifecycle keyed on `content_digest`.
- SQLite WAL index for `current_index`, `exact_index`, `guarded_index`, `cache_entries`, `leases`, `staging`, `policy_snapshots`, `routes`, plus a separate `auth.sqlite` for OAuth tokens.
- `flock` (Linux/macOS) / `LockFileEx` (Windows) for cross-process serialization.
- Three-key herd-collapse (`current` / `guarded` / `exact`) with response-header cross-promotion.
- Atomic staging (write tee → digest → publish into CAS by rename).
- Crash recovery on startup.
- Network-FS refusal for `state_root`, opt-in modes for `cache_root`.

## Public surface [partial — see implementation note below]

The crate is consumed by `ovstorage` (one instance per process configuration) and by `ovstorage-broker` (against the broker's own roots). The two consumers see the same surface; the only differences are which `state_root` / `cache_root` they open against and whether they take the broker-side `cache_coordination` modes for shared scratch. Plugins do not depend on `ovstorage-cache` directly — all plugin interaction with cache state goes through the host (`ovstorage` or `ovstorage-broker`).

The crate's API is an internal Rust API, but it is still a compatibility surface between workspace crates. It must stay small and stable enough that the dispatcher, broker, conformance harness, and bindings do not encode cache internals themselves. The durable shape is:

- **Open / close:** canonicalize roots, validate filesystem policy, create or migrate the two SQLite files, acquire the process sentinel, run bounded recovery, and expose a `CacheHandle`. Current `Cache::open` recovery is the lease-sentinel reap (`Cache::recover` walks `<state_root>/processes/`, drops rows owned by dead pids, and removes `cache_entries` rows whose CAS files are missing) plus a blunt `<cache_root>/staging/` delete-and-recreate sweep. CAS verification is lazy on `Cache::get`. The richer scope advertised in this section ("create or migrate the two SQLite files, acquire the process sentinel, run bounded recovery") is the target shape; today only `index.sqlite` is created/migrated by this crate (`auth.sqlite` is owned by `ovstorage::auth::AuthRefreshLock`). Dropping the handle closes new cache operations but does not invalidate outstanding `Lease` or `LocalDelegate` values.
- **Lookup:** given a `ResolvedTarget`, `policy_partition`, and optional `if_match` etag precondition, return `Hit`, `Miss`, or `Pending` without contacting the backend. A hit always includes a lease and enough `ObjectInfo` to satisfy `materialize`, `read_bytes`, `read_stream`, and cheap `stat` after `get`.
- **Fill coordination:** given the same lookup inputs, create or join exactly one in-flight fetch per herd-collapse key. The host performs the network/plugin read; the cache crate owns the locks, waiters, response-header promotion, abort handoff, staging record, and CAS publish.
- **Commit / abort:** atomically publish staged bytes after digest verification and metadata capture, or discard staging on cancellation/error. Commits are idempotent by `txn_id`; aborts are best-effort because crash recovery owns the final cleanup.
- **Lease / GC:** hand back RAII leases for local files, track process liveness with one sentinel fd per canonical `state_root`, and evict only unleased CAS entries.
- **Auth state:** serialize OAuth refresh (cross-process) and persist keyring handles in `auth.sqlite`; the OAuth protocol itself remains in `ovstorage`. **(implemented)** — `ovstorage::auth::AuthRefreshLock` owns `auth.sqlite` (`refresh_records` for cross-process refresh coordination + `secret_tokens` for credential-cache persistence + `secret_blobs` for `SqliteSecretStorage` BLOB durability), and `ovstorage::auth::cache::AuthDbCredentialPersistence` wires `CredentialCache` durability through those tables plus `SecretStore` (OS keyring) so refresh tokens survive process restarts.
- **Policy and route snapshots:** store the policy and route epochs the host supplies, stamp cache metadata with them for diagnostics and broker-side coordination, but do not turn policy freshness into a library-side cache-hit gate.

Expected error mapping is also part of the surface: filesystem refusal returns `NetworkFilesystemRefused`; an unavailable local state root returns `StateRootUnavailable`; corrupt CAS bytes return `CacheCorrupt`; lock acquisition timeout returns `CacheLockContention`; ambiguous publish state returns `CommitAmbiguous`. Backend precondition failures remain `ObjectModified` / `NotFound` and are not synthesized by the cache unless the mismatch is between cached metadata and a caller-supplied `if_match`.

Implementation note: the crate provides one concrete slice of this design: separate `state_root` / `cache_root`, CAS files under `cache_root/sha256`, SQLite WAL `index.sqlite` with versioned migrations (`entries` + `process_leases` + `cache_entries` + `schema_version` tables), `<state_root>/processes/<pid>.lock` sentinels via `Arc<CacheProcess>`, RAII `Lease` values that bump `cache_entries.lease_count`, staging cleanup on open, atomic temp-file publish, lease-aware LRU eviction by byte cap, typed three-key herd-collapse (`HerdKey::{Current, Guarded, Exact}` via `Cache::with_typed_herd_lock`) plus the legacy opaque `Cache::with_herd_lock`, cache status reporting, index removal by exact key or prefix, CAS verification on read, `Cache::recover` / `Cache::doctor` startup sweep, `CacheCoordination::{HostExclusive, SharedSingleWriter, ReadOnly}` modes (with `O_EXCL` writer-rendezvous file under `cache_root/.writer`), `Observer` callbacks (`LookupOutcome` / `FillOutcome` / `EvictionReason` / `on_crash_recovery` / `on_lease`), and structured `fs_probe::fs_kind` plus the legacy UNC-string check for refusing network roots (with `OVSTORAGE_ALLOW_NETWORK_FS=1` override). `auth.sqlite` is owned by `ovstorage::auth::AuthRefreshLock` (cross-process OAuth refresh coordination via `refresh_records` + credential-cache persistence via `secret_tokens` and `secret_blobs`); the richer split `current_index` / `guarded_index` / `exact_index` families, policy snapshots, the dedicated `herd/`/`auth/`/`gc.lock` directory tree, age-aware GC sweep, and cross-host cache coordination beyond the rendezvous file are not implemented.

## Internals

### Two roots, one library [partial — file layout differs from spec]

> The crate creates `<state_root>/index.sqlite` (single file), `<state_root>/locks/`, `<state_root>/processes/<pid>.lock`, and `<cache_root>/sha256/<aa>/<rest>` plus `<cache_root>/staging/`. There is no `auth.sqlite` *under this crate's ownership* — `ovstorage::auth::AuthRefreshLock` owns it (see [ovstorage](../ovstorage/README.md)). `auth/<backend>.lock`, `herd/<kind>/<key>.lock`, and `gc.lock` directories under `<state_root>` are **(spec)**.

The `ovstorage-cache` crate jointly manages `state_root` and `cache_root`.

**Current layout** (lines marked `# spec` are target only):

```text
<state_root>/
  index.sqlite                        # WAL-mode (cache_entries, entries, process_leases, schema_version)
                                      # spec: also current_index/exact_index/guarded_index/leases/staging/
                                      #       policy_snapshots/routes
  index.sqlite-wal
  index.sqlite-shm
  auth.sqlite                         # owned by ovstorage::auth::AuthRefreshLock (refresh_records,
                                      #  secret_tokens, secret_blobs); not under this crate's ownership
  auth.sqlite-wal
  auth.sqlite-shm
  locks/<sha256>.lock                 # per-key flock for `with_herd_lock`
  processes/<process-id>.lock         # flock'd process sentinel (one fd per process per state_root)
  # spec: auth/<backend>.lock         # flock'd credential-refresh mutex (one per backend)
  # spec: herd/<current|guarded|exact>/<key>.lock
                                      # flock'd herd-collapse sentinel
  # spec: gc.lock                     # flock'd GC mutex

<cache_root>/
  sha256/ab/cd/abcd...                # CAS object bytes
  staging/<txn-id>/...                # temp files; renamed atomically into sha256/
  .writer                             # O_EXCL writer-rendezvous file (SharedSingleWriter mode)
```

Defaults:
- Linux: `state_root = $XDG_STATE_HOME/ovstorage/`; `cache_root = $XDG_CACHE_HOME/ovstorage/`.
- macOS: `state_root = ~/Library/Application Support/ovstorage/`; `cache_root = ~/Library/Caches/com.ovstorage/`.
- Windows: `state_root = %LOCALAPPDATA%\ovstorage\State\`; `cache_root = %LOCALAPPDATA%\ovstorage\Cache\`.

Override via config or `OVSTORAGE_STATE_ROOT` / `OVSTORAGE_CACHE_ROOT`. Two roots = two independent lifecycle policies; operators can `rm -rf` the cache while inactive to free disk without breaking auth or invalidating durable state. Active wipes may cause misses or `CacheCorrupt` but must not corrupt `state_root`.

`cache = None` configures read-through (no byte caching) but keeps the state root.

### Coordination primitives (partial)

> The crate uses per-key `flock` on `<state_root>/locks/<sha256(target)>.lock` plus an in-process `Mutex` per resolved-target string, exposed via `Cache::lock_key` / `Cache::with_herd_lock` / `Cache::with_typed_herd_lock(HerdKey)`. The typed three-key collapse (`HerdKey::{Current, Guarded, Exact}`) and RAII `Lease` values both ship; per-process sentinel via `<state_root>/processes/<pid>.lock` is shared through `Arc<CacheProcess>`; `process_leases(pid, started_unix_ms, state_root)` row is written at `Cache::open` and deleted on `Drop`. OAuth refresh locks, GC mutex, and the access-time queue are **(spec)**.

- **Herd-collapse, three keys** (`current`, `guarded`, `exact`). Each lock lives under `<state_root>/herd/<kind>/<stable-key>.lock`, where `<stable-key>` is a hex digest of the key tuple. The cache never creates herd locks under `cache_root`; `cache_root` may be shared read-only across hosts where flock semantics are not trusted.
- **Lease tracking**: one process-sentinel fd + `flock` per canonical `state_root`, shared by every cache handle in the process through an `Arc<CacheProcess>`. Individual `Lease` values are SQLite rows owned by that process id. A live lease has no time-based maximum: it lasts until the host drops the `Lease` object and removes the SQLite row, or until the owning process exits and the sentinel lock is released. The default 5-minute grace applies only to ambiguous orphan cleanup, not to active reads or returned `LocalDelegate` paths.
- **Credential refresh**: `flock` + SQLite `BEGIN EXCLUSIVE` against `auth/<backend>.lock` + the `refresh_records` row in `auth.sqlite`. The cache crate owns the lock file, the SQLite serialization, and the on-disk token-storage shape (see [SQLite schema](#sqlite-schema-sketch-spec--current-schema-is-much-smaller)); [ovstorage](../ovstorage/README.md) owns the credential flows (OAuth, S3 STS, Azure SAS, etc.) that drive the refresh. The same machinery serializes any backend whose credential is durable and needs single-writer refresh — not just OAuth.
- **GC**: `flock` on `gc.lock`.
- **Hot-path bookkeeping**: in-memory access-time queue, flushed once per second.

#### State machine and lifecycle (spec)

> The crate has no `Pending` / `Filling` / `Verifying` / `Publishing` / `Quarantined` states; `put` does staging-write → atomic rename → SQLite `INSERT … ON CONFLICT … DO UPDATE` synchronously, and `get` re-hashes the CAS file inline. There is no `staging` table, no `txn_id`, no `CommittedElsewhere` outcome, and no quarantine directory.

Each cacheable object moves through a small state machine. The state is split between SQLite rows and files so recovery can reconstruct the truth after a crash.

| State | Durable evidence | Allowed next states | Notes |
|-------|------------------|---------------------|-------|
| `Absent` | no index row points at a live `cas_key` | `Filling`, `Hit` | `Hit` can appear without a local fill when another process published first. |
| `Pending` | herd lock held by another process; no owned staging row | `Hit`, `Miss`, `Cancelled` | Waiters must not touch staging files directly; they observe completion through SQLite/index changes and waiter notification. |
| `Filling` | owned herd lock plus `staging(txn_id, ...)` row plus `<cache_root>/staging/<txn-id>/bytes` | `Verifying`, `Aborted`, `RecoverableDebris` | The host may stream from plugin bytes, redirect bytes, or write-tee bytes. |
| `Verifying` | staging file closed; digest and response identity captured but CAS rename not yet committed | `Publishing`, `Aborted`, `RecoverableDebris` | Digest mismatch is `IntegrityFailure` or `CacheCorrupt` depending on whether bytes came from upstream or local disk. |
| `Publishing` | transaction updates `cache_entries` and one or more index rows, then atomically renames into `sha256/..` if absent | `Hit`, `CommittedElsewhere`, `CommitAmbiguous` | If the CAS file already exists with the same digest, reuse it and drop duplicate staging bytes. |
| `Hit` | index row points at `cas_key`, CAS file hashes to that `cas_key`, and a live lease row protects it | `Evictable`, `Invalidated`, `Quarantined` | A hit is exactness-gated only; policy epochs are diagnostics for library caches. |
| `Evictable` | `lease_count = 0` and no live lease rows reference `cas_key` | `Absent` | GC removes index references before unlinking the CAS file. |
| `Invalidated` | route or current-version rotation removes an index row but CAS may remain referenced elsewhere | `Absent`, `Hit` | Exact historical versions can stay valid after current rotates. |
| `Quarantined` | CAS file failed hash verification and was moved under `cache_root/quarantine/` | `Absent` | All index references to the quarantined key are removed in the same recovery transaction. |

`CommittedElsewhere` is not an error. It is the normal result when two processes race and one publishes a CAS file before the other reaches rename. The loser must verify the existing file hashes to the expected `cas_key`, discard its staging directory, and return a lease on the existing entry.

#### Three-key herd-collapse rules (spec)

> The crate exposes the typed `HerdKey { Current, Guarded, Exact }` enum and `Cache::with_typed_herd_lock`. `current` / `guarded` / `exact` flavors hash into disjoint lock spaces. `policy_partition` is folded into the cache-key string by the caller (`ovstorage` threads it via `routing::cache_key`) so multi-tenant deployments do not collide on the same `ResolvedTarget`. Cross-key promotion, full `if_match`-aware lookup, and a separate SQLite table per flavor remain spec — the typed keys exist but the index is still a single `entries` table.

The cache recognizes exactly three collapse keys:

- `current(resolved_target_hash, policy_partition)` for naked reads/stat-after-read with no populated `if_match`.
- `guarded(resolved_target_hash, identity_hash, policy_partition)` for reads with populated identity fields but no `version`.
- `exact(resolved_target_hash, version, policy_partition)` for reads where `if_match.version` is populated.

`policy_partition` separates callers whose cached bytes must not be shared even when they address the same resolved target. Direct mode normally uses one local partition per user/config profile. Broker-owned caches use the broker's route/tenant partition. `policy_partition` is not a freshness check; it is a storage namespace boundary.

Response headers can move waiters across keys, but never weaken exactness:

- A `current` fill that learns `identity` can satisfy matching `guarded` waiters once all populated identity fields match the response.
- A `current` or `guarded` fill that learns `version` can satisfy matching `exact` waiters for that version.
- If an `exact` fill for the learned version already exists, the weaker fill aborts its body transfer when the transport supports cancellation, hands waiters to the exact fill, and does not publish duplicate bytes.
- If a weaker fill finishes first, it may publish the CAS entry and populate all matching indexes in one transaction; the exact waiter then observes a hit.
- A mismatch on any populated `if_match` field fails the guarded/exact waiter with `ObjectModified { new_identity }`; it does not fall back to current bytes.

The ordering of "weaker" to "stronger" is `current -> guarded -> exact`. Promotion may move waiters only to the same or stronger key. There is no demotion from `exact` to `guarded` or `current`.

#### Locking and transaction order (spec)

Every operation follows one lock order. This prevents deadlocks when a cache miss, OAuth refresh, GC, and process startup collide:

1. Process sentinel for the canonical `state_root` is acquired at open and held for the handle lifetime.
2. Operation-specific file lock: herd key, `auth/<backend>.lock`, or `gc.lock`.
3. SQLite transaction (`BEGIN IMMEDIATE` for index writes, `BEGIN EXCLUSIVE` for OAuth refresh).
4. CAS file handle or staging file handle.

The reverse order is forbidden. In particular, code must not open a CAS file, then wait on SQLite, then wait on a herd lock. Reads that already have a resolved hit may open the CAS file and create a lease inside one short transaction; once the lease row commits, the read can drop SQLite and stream/mmap under the lease.

Lock scope rules:

- Herd locks are held from "I am the elected filler" through commit/abort. They are not held while a waiter simply waits.
- SQLite write transactions are short: update staging progress, insert/delete lease rows, publish index rows, or advance GC. Long network reads happen outside SQLite transactions.
- OAuth refresh holds `auth/<backend>.lock` across the IdP call and the `auth.sqlite` commit because single-use refresh tokens require one in-flight refresh per backend.
- GC holds `gc.lock` while selecting candidates and deleting index rows, but drops it before slow directory sweeps that are not needed for correctness.
- Locks use canonical root paths. Symlinks, case aliases on Windows, and `..` segments must collapse to the same `state_root` before the sentinel path is chosen.

### SQLite schema (sketch) [spec — current schema is much smaller]

> The current schema is one DB file `<state_root>/index.sqlite` with these tables:
>
> ```sql
> CREATE TABLE entries (
>     resolved_target     TEXT PRIMARY KEY NOT NULL,
>     cas_key             TEXT NOT NULL,
>     size                INTEGER NOT NULL,
>     updated_unix_ms     INTEGER NOT NULL,
>     last_access_unix_ms INTEGER NOT NULL
> );
> CREATE TABLE process_leases (
>     pid             INTEGER NOT NULL,
>     started_unix_ms INTEGER NOT NULL,
>     state_root      TEXT NOT NULL,
>     PRIMARY KEY (pid, started_unix_ms)
> );
> ```
>
> The shape also has `cache_entries(cas_key PK, size, created_at, last_access_time, pin_count, lease_count, fetch_redirect_source, verified_at, format_version)` (used by `Cache::lease`, eviction, and recovery) and `schema_version(version, applied_at)`. Every other table below (`current_index`, `exact_index`, `guarded_index`, `processes`, `leases`, `staging`, `policy_snapshots`, `routes`) and every secondary index listed are **(spec)**. Auth-DB tables are owned by `ovstorage::auth::AuthRefreshLock` (`refresh_records`, `secret_tokens`, `secret_blobs`).

**Two SQLite databases** (see [Why two SQLite files](#why-two-sqlite-files-spec--single-file-today)):

- `<state_root>/index.sqlite` — cache, routing, policy, leases, staging. `synchronous = NORMAL`.
- `<state_root>/auth.sqlite` — durable secret/token storage and cross-process refresh coordination for any backend whose credential needs single-writer refresh (OAuth refresh tokens, S3 STS session tokens, Azure SAS handles, etc.). `synchronous = FULL`.

Index DB tables:

- `cache_entries(cas_key PK, size, created_at, last_access_time, pin_count, lease_count, fetch_redirect_source, verified_at, format_version)` — `cas_key` is the SHA-256 of the cached bytes (the cache's content-addressed storage key; see [ovstorage-plugin](../ovstorage-plugin/README.md) for why this is internal and not surfaced as identity). The CAS algorithm is fixed to SHA-256 for the 1.x cache format; BLAKE3 is used for compact internal target hashes only, not as an alternate CAS key.
- `current_index(resolved_target_hash, policy_partition, cas_key, identity_json, version, normalized_address, backend_id, route_epoch, fetched_at, policy_epoch, response_headers_hash, PK(resolved_target_hash, policy_partition))` — drives herd-collapse key `current(resolved_target_hash, policy_partition)` and cheap `stat`-after-`get`. Keyed on **`resolved_target_hash`**, not on `normalized_address`, so a route rebinding (different `backend_id` or `route_epoch`) does not produce false hits against the old target's cached bytes. `normalized_address` and `backend_id` are carried for diagnostics and for operator-facing queries.
- `exact_index(resolved_target_hash, version, policy_partition, cas_key, identity_json, fetched_at, policy_epoch, PK(resolved_target_hash, version, policy_partition))` — drives herd-collapse key `exact(resolved_target_hash, version)` and serves `stat` / `get` requests where `ReadOptions.if_match.version` is populated (the precondition value doubles as the cache-collapse key; URL-level version selection folds into `resolved_target_hash` directly). Multiple rows per target are expected (one per version ever seen). Evictable independently of `current_index` because cache-GC is keyed on `cas_key` via `cache_entries`.
- `guarded_index(resolved_target_hash, identity_hash, policy_partition, cas_key, identity_json, fetched_at, policy_epoch, PK(resolved_target_hash, identity_hash, policy_partition))` — drives herd-collapse key `guarded(resolved_target_hash, identity)` for fetches that pass a `ReadOptions.if_match` without `version` populated. Cleared aggressively when a target's `current_index` row rotates.
- `processes(process_id PK, pid, process_start_time, executable_hash, lock_path, opened_at, last_seen_at)`
- `leases(lease_id PK, cas_key, process_id, created_at, purpose)`
- `staging(txn_id PK, owner_process_id, owner_pid, owner_start_time, key_kind, key_hash, target_cas_key_or_address, started_at, last_progress_at, bytes_written, expected_size, state)`
- `policy_snapshots(broker_id, policy_epoch, fetched_at, payload, PK(broker_id, policy_epoch))`
- `routes(scope, prefix, backend_id, route_epoch, source, source_priority, PK(scope, prefix, source))` — `route_epoch` bumps on every config reload that changes the prefix→backend binding, providing the epoch that `current_index` / `exact_index` / `guarded_index` stamp.

Auth DB tables:

- `refresh_records(backend, last_refresh_unix_ms, last_expires_unix_ms, PK(backend_kind, connection_id))` — cross-process refresh coordination. Holds the timestamp of the last successful refresh and its expiry so concurrent processes can decide whether to skip a refresh round trip. Generic over the credential kind: OAuth, S3 STS, Azure SAS, or any other refresh-shaped credential funnels through here.
- `secret_tokens(backend_id, principal, source_name, expires_at_unix_ms, cred_epoch, persisted_at_unix_ms, …, PK(backend_id, principal))` — durable cache index for the `CredentialCache`. The actual secret bytes live behind a `SecretStorage` handle (default: OS keyring, falling back to the `secret_blobs` table when `LibraryBuilder::with_secret_storage(SecretStorageKind::Database, …)` is selected). The table is named `secret_tokens` rather than `oauth_tokens` deliberately: the column shape is credential-kind agnostic and the same row plumbs S3 STS session keys, Azure SAS strings, and bearer-style tokens just as well as OAuth refresh tokens. `cred_epoch` lets a callback advertise that previously-issued credentials are now suspect (rotation, manual revocation) without dropping the row.
- `secret_blobs(handle, bytes, inserted_unix_ms PK(handle))` — BLOB-backed `SqliteSecretStorage` for platforms without an OS keyring or for deployments that opt into database-resident secret storage. Today **`SqliteSecretStorage` does not encrypt**: the `bytes` column is plaintext, and encryption-at-rest is the operator's responsibility (filesystem FDE, sqlite-encrypt extension, or trusted-environment plaintext). The "host-bound key derived from a per-host secret" wrapper is target design only; the implemented `SecretStorageKind` variants are `OsKeyring` (default), `Database` (this BLOB column, plaintext), and `External(Arc<dyn SecretStorage>)`.

`resolved_target_hash` is `BLAKE3(backend_id || 0x00 || resolved_address)` — a compact 32-byte identifier for a `ResolvedTarget`. The three collapse keys all use this so the cache never keys on the caller-facing address, which can be rewritten by local routes.

`process_id` is a random 128-bit id generated when the first cache handle for a canonical `state_root` opens in the process. The process sentinel is opened at `<state_root>/processes/<process_id>.lock` and stays locked through a shared `Arc<CacheProcess>` until the last `Library`, cache handle, staging guard, or `Lease` that depends on that state root drops. Normal `Lease` drop is exact: it deletes the row and decrements `cache_entries.lease_count`. If a live process leaks a row, the cache over-retains that CAS entry until process exit; this is diagnostics-only and not grounds for age-based eviction.

Indexes (the hot paths the library issues on every request must not be a table scan):

- `cache_entries(last_access_time)` — LRU-order eviction scans.
- `cache_entries(lease_count, last_access_time)` — "oldest idle entry" for GC.
- `current_index(cas_key)` — reverse lookup during eviction (which targets still point here?).
- `current_index(fetched_at)` — age-based metadata refresh and stale-row cleanup.
- `current_index(backend_id, route_epoch)` — sweep after a route rebinding.
- `exact_index(cas_key)` — reverse lookup during eviction.
- `exact_index(resolved_target_hash)` — enumerate all known versions of a target.
- `guarded_index(resolved_target_hash)` — blanket invalidation on current-version rotation.
- `leases(cas_key)` — "is this entry pinned by any live lease?" pre-check before the process-sentinel sweep.
- `leases(process_id)` — group rows by owning process during startup and GC sweeps.
- `processes(pid, process_start_time)` — diagnostic fallback when a process-sentinel probe is indeterminate.
- `staging(owner_pid, owner_start_time)` — startup sweep of dead stagers.
- `staging(last_progress_at)` — ambiguous unlocked staging cleanup after the 5-minute grace.
- `policy_snapshots(broker_id, fetched_at)` — newest-first reads.

Page size 4096, auto-vacuum incremental on both DBs.

### Why two SQLite files [spec — single file today]

SQLite `PRAGMA synchronous` is connection-scoped, not table-scoped. The index DB sees thousands of writes per second under load — running it at `FULL` pays an fsync per commit and is unnecessary for cache bookkeeping where losing the last ~1 s of access-time updates is fine. OAuth refresh, by contrast, must never lose a single-use refresh-token rotation: one crash with a fresh refresh token in the page cache but not on disk and the user is logged out forever.

Splitting OAuth into `auth.sqlite` makes the durability contract obviously correct: the auth DB is opened with `synchronous = FULL` and `journal_mode = WAL`, one fsync per OAuth write, and the hot cache path never touches it. Cross-DB consistency is not required — OAuth tokens have no foreign-key relationship with cache or routing state.

Both DBs share the same `state_root` and the same crash-recovery sweep (see [Crash recovery](#crash-recovery-spec--only-staging-cleanup-is-implemented)). Operators back up `state_root` as a unit.

### Schema invariants (spec)

Implementations may rename columns during migrations, but the following invariants are part of the design:

- Every `current_index`, `exact_index`, and `guarded_index` row must reference an existing `cache_entries.cas_key`. Foreign keys are enabled for SQLite connections that mutate index rows.
- `cache_entries.lease_count` is a denormalized count of live `leases` rows. A recovery sweep may recompute it from `leases`; normal lease create/drop updates both in the same transaction.
- `cache_entries.pin_count` is reserved for explicit user/operator pins. It is not a substitute for `lease_count`; pins survive process death, leases do not.
- `identity_json` is the canonical serialization of the cached entry's identity fields (`etag`, `version`, `size`, `mtime`): absent fields omitted, keys sorted, time values normalized to UTC nanoseconds, no backend-specific metadata mixed in. `identity_hash` is BLAKE3 over that canonical serialization.
- `identity_json.version`, when present, must equal `exact_index.version` for exact rows. If a backend reports a version in headers, exact and current rows carry the same canonical identity record for that fetch.
- `resolved_target_hash` is always derived after routing from `ResolvedTarget`; caller-facing aliases and `normalized_address` never participate in hit identity.
- `route_epoch` records the route table epoch that produced the `ResolvedTarget`. Route rebinding does not delete historical exact rows immediately, but it prevents false current hits because the new resolved target hashes differently when the backend id or resolved address changes.
- `policy_epoch` is a stamp, not a library-side authorization gate. It exists for diagnostics, broker-owned cache coordination, and policy-snapshot cleanup.
- `staging.state` is one of `filling`, `verifying`, `publishing`, `aborting`. No committed staging row remains after successful publish; recovery treats leftover rows according to the state machine above.
- `auth.sqlite` contains OAuth state only. No route, cache, lease, or policy table may be added to it; otherwise the durability split stops being meaningful.

Migrations are monotonic and root-local. Opening a newer schema with an older binary fails with a typed compatibility error; opening an older schema runs the migration while holding `gc.lock` plus a SQLite exclusive transaction, before recovery starts. Migrations must not require scanning `cache_root` except for explicit format migrations, because operators are allowed to wipe `cache_root` independently.

### Crash recovery [spec — only staging cleanup is implemented]

> `Cache::open` deletes and recreates `<cache_root>/staging/` (a blunt sweep, not a per-row decision); there is no CAS verification sweep, no lease sweep, no index repair, no migration step, no quarantine directory, and no `gc.lock`. CAS verification is lazy in `Cache::get` — a verification failure deletes the corrupt CAS file plus its `entries`/`cache_entries` rows in one transaction, emits `EvictionReason::Corrupt`, and turns the read into a miss so the next call self-heals via refetch. `Cache::recover` reaps `cache_entries` rows whose `cas_key` no longer references any `entries` row. Schema migrations refuse to open an `index.sqlite` whose recorded version is newer than `CURRENT_SCHEMA_VERSION` (typed `Unsupported` error). CAS publish uses `fs::hard_link` so two writers racing on identical bytes both observe success without overwriting an already-good file. `remove_index` and `remove_prefix` capture the affected `cas_key`s, then prune `cache_entries` rows + unlink the CAS file when no other `entries` row references them and no leases/pins are held.

At process startup, `ovstorage-cache` opens the state DB and runs recovery before it reports the cache handle as ready. Recovery is bounded so application startup is predictable; any sweep can resume in a later startup or background GC pass. Correctness must not depend on finishing the optional full sweep.

1. **Root and DB sanity.** Canonicalize roots, verify they still satisfy filesystem policy, open `index.sqlite` and `auth.sqlite` with their required PRAGMAs, enable foreign keys, and run migrations if needed.
2. **CAS verification sweep.** Re-hash a capped batch of CAS files. A file whose path digest and byte digest disagree is moved into `cache_root/quarantine/<timestamp>/`, all index references to that `cas_key` are removed in one transaction, and a `CacheCorrupt` event is emitted. Missing CAS files referenced by SQLite are treated the same way minus quarantine.
3. **Staging sweep.** Rows whose process sentinel proves the owner is dead get their staging dirs unlinked immediately. Rows whose herd/staging lock is held are preserved regardless of age. Rows whose owner cannot be proven alive or dead are ambiguous debris and are removed only after `last_progress_at + 5 minutes`.
4. **Lease sweep.** Lease rows are grouped by `process_id` and checked against the owning process sentinel. If the sentinel is locked by another process, every row owned by that process is live regardless of wall-clock age. If the sweep can acquire the sentinel, the owner is dead; it deletes that process's lease rows, decrements the affected `cache_entries.lease_count` values, removes the `processes` row, and unlinks the sentinel lock file. If the sentinel probe is indeterminate, PID/start-time is used only as a diagnostic fallback; rows are preserved until the 5-minute ambiguous-orphan grace has elapsed and are cleaned only when the owner cannot be proven alive.
5. **Index repair.** Recompute denormalized `lease_count` for touched CAS keys, delete index rows that reference missing entries, and clear guarded rows for targets whose current identity no longer matches.
6. **GC of expired entries.** Enforce age cap first, then size cap. GC deletes index references and lease-free `cache_entries` rows before unlinking the CAS file, so a crash between DB update and unlink produces harmless unreferenced bytes rather than dangling DB rows.

Crash points have explicit outcomes:

- Crash before staging row commit: the staging directory is untracked debris and is removed by directory sweep after the grace period.
- Crash after staging row commit but before publish: the row proves ownership and is removed only when the owner is dead or ambiguous beyond grace.
- Crash after CAS rename but before index commit: the CAS file is unreferenced and may be adopted by a later fill with the same digest or removed by GC.
- Crash after index commit but before staging cleanup: the committed row is authoritative; cleanup removes only the duplicate staging bytes.
- Crash during OAuth refresh: `auth.sqlite` is the durable record; after restart, the refresh path re-reads the row under `auth/<backend>.lock` before deciding whether to call the IdP again.

### Network filesystem handling [partial — Linux statfs probe shipped; macOS/Windows still UNC heuristic]

> Linux consults `statfs(2).f_type` and matches against the NFS / CIFS / SMB / SMB2 / FUSE / AFS / Lustre / Ceph / GFS2 / OCFS2 magic-number table; unknown magic numbers map to `FsKind::Local` so a normal `/mnt/...` path does not fall through to the UNC string check. macOS and Windows fall back to the legacy UNC heuristic (`looks_like_network_unc`); per-platform probes are not implemented. `OVSTORAGE_ALLOW_NETWORK_FS=1` overrides the refusal regardless of probe result. The check is gated behind `CacheOptions::refuse_network_filesystems` (default `false`).

Both `state_root` and `cache_root` are designed around assumptions that network filesystems routinely violate: SQLite WAL requires reliable `fsync` on a single-host page cache, `flock`/`LockFileEx` advisory locks must serialize across contending processes on the same node, and atomic `rename` must be atomic with respect to all readers. NFSv3, SMB with opportunistic locking, Lustre, and most HPC parallel filesystems break at least one of these.

**Detection.** At startup the library probes the filesystem underlying each root:

- Linux: `statfs(2).f_type` against a known list (`NFS_SUPER_MAGIC`, `SMB_SUPER_MAGIC`, `CIFS_MAGIC_NUMBER`, `LUSTRE_SUPER_MAGIC`, `CEPH_SUPER_MAGIC`, `GFS2_MAGIC`, `FUSE_SUPER_MAGIC`).
- macOS: `statfs(2).f_fstypename` against `nfs`, `smbfs`, `afpfs`, `webdav`, `fuse`.
- Windows: `GetDriveTypeW` == `DRIVE_REMOTE`, plus `GetVolumeInformationW` flags.
- FUSE on any platform is treated as unknown/unsafe (it could be anything).

**Default policy.** Refusal is opt-in via `CacheOptions::refuse_network_filesystems = true` (default `false`); each binary that runs the cache (the library, the broker, the REST gateway) sets the option according to its threat model. The table below shows the policy *with refusal enabled*; with refusal off (today's default) network roots open and the host eats whatever fsync/locking lossiness the filesystem brings:

| Root | Detected FS | Behavior with refusal enabled |
|------|-------------|------------------|
| `state_root` | local | open normally |
| `state_root` | network/FUSE | **refuse**; log error pointing at `OVSTORAGE_STATE_ROOT`, local default, and override env var |
| `cache_root` | local | open in `host-exclusive` mode |
| `cache_root` | network/FUSE | open in **`read-only`** mode and log a warning; any writable mode requires explicit `writer_identity` in config |

**Error message shape** (state root on NFS):

```text
error: state_root "/home/alice/.local/state/ovstorage" is on an NFS filesystem
         which does not support the advisory locking and fsync semantics
         ovstorage relies on.

       Fix one of:
         - point OVSTORAGE_STATE_ROOT at a local filesystem
           (default: $XDG_STATE_HOME/ovstorage)
         - set OVSTORAGE_ALLOW_NETWORK_FS=1 to override at your own risk
           (data loss and cross-host corruption possible)

       cache_root may remain on shared storage with cache_coordination="shared-single-writer"
       and an explicit writer_identity (see "HPC / fleet guidance" in ovstorage-cache.md).
```

**`cache_coordination` modes** (exactly one per process; applies to `cache_root` only):

| Mode | Writers | Cross-host safety | Intended use |
|------|---------|-------------------|--------------|
| `host-exclusive` | all processes on this host may write; flock coordinates | none (single host assumed) | local SSD / NVMe cache, default for local `cache_root` |
| `shared-single-writer` | exactly one process in the whole fleet, identified by `writer_identity`, may write; all other processes are read-only | enforced by `writer_identity` rendezvous file in `cache_root/.writer` | shared scratch with one designated warming node |
| `read-only` | none | trivially safe | non-writer nodes against a `shared-single-writer` cache; default for any network-FS `cache_root` |

`host-exclusive` is the only mode that matches the kernel-level flock semantics we rely on; the other two are byte-level contracts enforced by the library, with CAS-key reverification (re-hash the bytes against the on-disk filename) on every open to catch any violation.

**`writer_identity`** is a required-when-writable string (e.g., `"node-7.cluster.local:pid-12345"` or a systemd-managed constant like `"cache-warmer"`) written to `<cache_root>/.writer` at startup under an O_EXCL create. A second process attempting to acquire writer identity against a non-matching or concurrently-held `.writer` fails with `CacheLockContention` — the fleet has lost its invariant and requires operator intervention.

**HPC / fleet guidance.**

- Preferred layout: `state_root` on node-local disk (`/tmp/ovstorage-$UID` or `$XDG_STATE_HOME`), `cache_root` on shared scratch with `cache_coordination = "shared-single-writer"` and `writer_identity = "<one-node>"` on the warming node; `cache_coordination = "read-only"` on every other node.
- Shared caches across hosts are always read through digest verification; no flock can protect a cross-host race, so stale-read correctness comes from SHA-256 reverification at lease acquisition regardless of coordination mode.
- Container / k8s guidance: emptyDir volume for `state_root`, PVC (local-SSD storageClass) for a local `cache_root`, or a shared PVC for a `shared-single-writer` fleet cache with the writer identity driven by the Pod name. Avoid NFS/EFS PVCs for `state_root` on pain of refused startup.

**Override.** `OVSTORAGE_ALLOW_NETWORK_FS=1` forces both roots open regardless of detection, with a very loud warning logged at startup and in every tracing span's `fs_risk = "network"` attribute. Supported for experimentation and for filesystems we failed to autodetect; not supported for production. The override does not change `cache_coordination`; a writable network `cache_root` still needs `shared-single-writer` plus `writer_identity`.

### Cache-hit validity [spec — current API has no `if_match` / identity / version surface]

> `Cache::get` is keyed by an opaque `resolved_target: &str` only; it does not know about `if_match`, etag, `version`, `policy_partition`, route epoch, or policy epoch. Every behavior described below — exactness gating, guarded vs current decision, range slicing, write-populates-cache rules — is **(spec)**.

The library's local cache has one validity concern: **data exactness**. Do the cached bytes match the caller's `if_match` etag (or `IfDestExists::MatchEtag(etag)` on writes)? If no etag was supplied, any cached bytes for the address are eligible. That's the whole rule.

In particular, a cache hit doesn't depend on whether the broker-issued redirect that originally fetched the bytes is still fresh, whether the broker is reachable right now, or whether the caller's broker-side authorization has changed since the fetch. Once bytes are in the local cache, they live on local disk and the library can serve them without a network round-trip. A broker can refuse to mediate *new* fetches for an unauthorized caller, but it has no way to reach into a client's local cache to invalidate or re-gate already-fetched bytes.

Redirect expiry, on its own, doesn't invalidate cached bytes. In brokered mode, an expired redirect just means the *next uncached fetch* needs a new redirect; cached reads are unaffected. Direct mode has no redirect to expire.

**Broker-side caches are different.** The broker maintains its own small-object byte cache and metadata cache for downstream clients, and those *do* run a per-client authorization check on every hit: the broker doesn't serve cached bytes to a client whose current authorization doesn't cover them. The broker's lease mechanics and the policy-epoch / grace-window mechanics in the host authz layer apply to the broker's caches, not to the library's.

**Underlying principle.** A library cache hit is a local disk read. Anything that requires rechecking authorization against a remote service is a *broker-side* concern. (The library does keep leases on cache entries — see [Coordination primitives](#coordination-primitives-partial) — but those are RAII-bound SQLite rows tied to a process-sentinel lock that prevents eviction of in-use files, unrelated to authorization.)

Exactness decision table:

| Caller precondition | Eligible index | Hit condition | Miss/failure condition |
|---------------------|----------------|---------------|------------------------|
| `if_match = None` or all fields empty | `current_index` | row exists, CAS file verifies, same `policy_partition` | no row, missing/corrupt CAS, or route resolution changed |
| `if_match.version = Some(v)` | `exact_index` | row for `(resolved_target_hash, v, policy_partition)`, CAS verifies, all other populated fields match stored identity | no exact row is a miss; stored identity mismatch is `ObjectModified` |
| `if_match` populated without version | `guarded_index`, then `current_index` if identity matches | stored identity contains every populated field and values match exactly | mismatch is `ObjectModified`; absent row is a miss |
| Range read | same as above | range slices verified CAS bytes after whole-object exactness passes | invalid range is `InvalidArgument`; no partial-object cache identity exists |

The cache stores whole-object bytes only in this design. A range read can be served from a whole-object hit; a range miss fetches according to host policy but may publish only a complete object with a complete identity. Partial-body redirects, HTTP 206 responses, and streaming truncation must not create `cache_entries` rows unless the host also obtains and verifies the complete object.

Write-populates-cache follows the same exactness rules. A successful write may publish the teed bytes into CAS and update `current_index` plus `exact_index` when the `WriteResult.info.identity.version` is known. A failed or ambiguous write never publishes bytes as current. If the backend accepts a write but does not return enough identity to prove exactness, the cache may store the CAS entry for deduplication but must not create a hit-producing index row until a later `stat` or read supplies identity.

Route and policy changes affect library cache hits differently:

- Route rebinding changes the `ResolvedTarget` or `route_epoch`; new calls resolve to a new `resolved_target_hash` and do not hit stale current rows for the old target.
- Policy epoch changes are recorded on rows and spans but do not invalidate library-side hits. In broker-owned caches, the broker performs its own authorization check before it asks this crate to serve bytes.
- Redirect expiry invalidates redirect reuse, not CAS byte validity.
- Version-selected `ObjectAddress` values plus an `if_match` etag must resolve to exact keys or fail; the cache must not reinterpret exact-version reads as guarded/current lookups.

### Observability and operations [spec — no metrics or tracing emitted]

> The crate emits zero metrics and zero tracing spans. It depends only on `fs2`, `ovstorage-plugin`, `rusqlite`, and `sha2`; there is no `tracing` or metrics crate dependency. The `ovstorage cache-doctor` / `cache-gc` / `cache-stats` CLI subcommands **are** wired in `ovstorage-cli` (see [`ovstorage-cli` § Diagnostic subcommands](../ovstorage-cli/README.md#diagnostic-subcommands)) — they expose `Cache::doctor` / `Cache::gc` / `Cache::status`. The metric families listed below are **(spec)**.

`ovstorage-cache` emits metrics and tracing through the host's observability sink; it does not open sockets, start exporters, or own a runtime. Library processes inherit the opt-in client metrics surface from [ovstorage](../ovstorage/README.md); brokers inherit their own always-on broker metrics surface.

Required metric families:

- `ovstorage_cache_lookup_total{result="hit|miss|pending|corrupt", key_kind, mode}`
- `ovstorage_cache_fill_total{result="committed|joined|aborted|error", key_kind}`
- `ovstorage_cache_fill_wait_seconds_bucket{key_kind}`
- `ovstorage_cache_bytes{state="cas|staging|quarantine"}`
- `ovstorage_cache_entries{state="indexed|leased|pinned|orphaned"}`
- `ovstorage_cache_gc_total{result="evicted|skipped_leased|skipped_pinned|error"}`
- `ovstorage_cache_recovery_total{action="staging_removed|lease_reaped|cas_quarantined|index_repaired"}`
- `ovstorage_cache_lock_wait_seconds_bucket{lock_kind}`
- `ovstorage_cache_sqlite_busy_total{db="index|auth"}`
- `ovstorage_auth_refresh_total{result="rotated|reused|error"}`
- `ovstorage_network_fs_refusal_total{root="state|cache", fs_kind}`

Required tracing attributes on cache spans:

- `state_root.hash` and `cache_root.hash`, never raw paths by default.
- `resolved_target_hash`, `backend_id`, `route_epoch`, `policy_epoch`, and `policy_partition.hash`.
- `cache.key_kind`, `cache.hit`, `cache.cas_key.prefix` (first 12 hex chars only), `cache.lease_id.hash`.
- `cache.fs_risk = "local|network|unknown"` and `cache.coordination`.
- `cache.recovery.action` for startup/background sweeps.

Logs and errors must redact query strings, authorization headers, cookie headers, OAuth material, and full local paths unless an operator enables debug path logging. CAS keys are not secrets, but full keys still create durable access fingerprints, so user-facing logs print a short prefix by default.

Operational expectations:

- `ovstorage cache doctor` can run the same recovery checks in dry-run mode and report counts without mutating state.
- `ovstorage cache gc --max-bytes ...` drives the same GC path as background GC; there is no separate cleanup algorithm.
- `ovstorage cache stats` reports bytes by CAS/staging/quarantine, rows by table, leases by live/dead/ambiguous process state, and filesystem-risk classification.
- Manual deletion of `cache_root` is supported while no process is actively using that root. Deletion during active use can produce misses or `CacheCorrupt`, but must not corrupt `state_root` or auth; active wipes are recoverable operational failures, not state loss.
- Manual deletion of `state_root` logs the user out and discards coordination state; it is a supported recovery action but not a cache-clearing operation.

## Dependencies [implemented — minus `blake3` and `tokio`]

> Actual `Cargo.toml` deps: `fs2`, `ovstorage-plugin`, `rusqlite`, `sha2`. No `blake3`, no `winapi` (UNC string detection only), no `zeroize` direct dep, no `tokio`.

In-workspace: `ovstorage-plugin` (types, error taxonomy).

External (target — notable): `rusqlite` (SQLite WAL driver), `fs2` / `winapi` (advisory locks), `blake3` (target-hash for collapse keys), `sha2` (CAS-key digest), `zeroize` (used via `SecretBytes` from `ovstorage-plugin`), `tokio` (host-supplied async runtime; the crate itself does not own the runtime).

## Threat model

`ovstorage-cache` sits inside the trust boundary of whichever process loads it (the library process in Direct mode, the broker process in Brokered mode). It does not itself authenticate callers — it trusts the host to have already done so.

**Secret handling on disk.** The `secret_tokens` table stores **secret-storage handles, not credential bytes**: the actual bytes (OAuth refresh tokens, S3 STS session keys, Azure SAS handles, bearer tokens, etc.) live behind a `SecretStorage` indirection. The default storage backend is the OS keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service / `kwallet`); `auth.sqlite` keeps `(backend_id, principal, expires_at_unix_ms, cred_epoch, …)` rows that point at the keyring entry. Platforms without a keyring — or deployments that opt into database-resident secret storage via `LibraryBuilder::with_secret_storage(SecretStorageKind::Database, …)` — fall back to the `secret_blobs` table in `auth.sqlite`, encrypted with a host-bound key. The fallback is flagged as a known weakening of the threat model and requires explicit operator opt-in. Cache CAS bytes never contain credential material — provider replies are filtered against the response-parsing rules in [ovstorage-plugin](../ovstorage-plugin/README.md) before any byte is staged.

**`cache_root` content.** Cache files are byte-identical copies of objects fetched on the caller's behalf; whoever can read `cache_root` can read those objects. Operators rely on filesystem permissions on `cache_root` (default `0700` on POSIX) for that boundary; the cache crate does not encrypt at rest.

**`state_root` content.** Beyond the keyring handles described above, `state_root` may contain policy snapshots, route metadata, and the herd-collapse / lease bookkeeping. None of that is sensitive on its own, but it does fingerprint what the caller has been reading; operators with that concern protect `state_root` with the same filesystem-ownership model as `cache_root`.

## Conformance tests [spec — current test count: 7]

> The crate ships exactly 7 in-file unit tests covering: round-trip + reopen, prefix removal, corruption detection, byte-cap LRU eviction, staging cleanup on open + status reporting, network-root refusal (UNC string), and in-process herd-lock serialization. None of the multi-process / cross-key promotion / crash matrix / OAuth / filesystem-coverage / observability tests below exist.

This crate's conformance surface:

**Multi-process coordination**
- Herd-collapse `exact`: N processes race for the same address with the same `if_match.version`; one fetch reaches the backend.
- Herd-collapse `guarded`: N processes race for the same address with the same `if_match` identity fields and no version-selecting field; one fetch.
- Herd-collapse `current`: N processes race for naked `read_*(address)` with no precondition; one fetch.
- Cross-key promotion: process A starts a `current(...)` fetch; once response headers arrive, process B's `guarded(...)` request (same target, same identity B learned out of band) joins A's in-flight fetch instead of issuing its own.
- Cross-key abort: process A starts `current(...)`; concurrently process B started `exact(...)` for a version A also learns from headers. A aborts its body transfer, hands its waiters to B, and the backend sees one fetch.
- Lease cleanup on SIGKILL: killing a process with live leases releases its process sentinel; the next startup or GC sweep deletes that process's lease rows and can evict unreferenced CAS files.
- Lease fd budget: one process acquires many cache leases and opens only one lease-liveness sentinel fd for that `state_root`.
- Process-sentinel sharing: multiple `Library` handles in one process and one canonical `state_root` share one sentinel.
- `LocalDelegate` lifetime: dropping a `Library` while a `LocalDelegate` survives keeps the sentinel live and prevents eviction.
- Lease drop exactness: dropping a `Lease` deletes its row, decrements `lease_count`, and allows later GC once no other row references the CAS key.
- Live-process leak policy: an intentionally leaked lease row owned by a still-running process over-retains the cache entry until process exit; GC must not expire it by age.
- Live leases have no wall-clock expiry: a row owned by a live process sentinel is not evicted solely because the row is older than the 5-minute ambiguous-orphan grace.
- OAuth refresh race on near-expiry token.
- Staging cleanup on SIGKILL mid-commit.
- Ambiguous unlocked staging cleanup waits until `last_progress_at + 5 minutes`; locked staging is preserved regardless of age.
- Lock-order stress: one workload interleaves cache fills, GC, OAuth refresh, and startup recovery without deadlock; lock wait metrics identify the contended lock.
- Commit race: two elected fillers reach the same CAS digest; one publishes, the other verifies existing bytes and returns `CommittedElsewhere` behavior without corrupting indexes.
- Crash matrix: kill at every state-machine transition (`filling`, `verifying`, `publishing`, post-index/pre-cleanup) and verify recovery outcome.

**State-vs-cache separation**
- `cache = None` works (read-through) while `state_root` continues to coordinate.
- `state_root` corruption recovery: deleting and recreating reauthorizes cleanly.
- `cache_root` wipe does not invalidate OAuth tokens.
- `auth.sqlite` contains no cache/index tables and `index.sqlite` contains no token material.
- Schema downgrade refusal and upgrade migration are both typed and recoverable.

**Library-side cache validity**
- Cache hit + data exact + broker reachable: serves from cache without contacting broker.
- Cache hit + data exact + broker unreachable: serves from cache (library does not consult broker on hits).
- Cache hit + `if_match` mismatch: re-fetches (or fails if upstream unreachable, per the cache-miss path).
- Cache miss + broker unreachable: fails with `BrokerUnavailable`.
- Versioned exactness: multiple `exact_index` rows for one target survive current-version rotation and serve only matching `if_match.version`.
- Guarded mismatch: a cached current row whose identity disagrees with a populated non-version field returns `ObjectModified` for a guarded read, not stale bytes.
- Range hit: range reads slice complete-object cached bytes and do not create partial CAS entries.
- Policy epoch change: library cache hit remains a hit; broker-owned cache hit still goes through broker authorization before serving.
- Redirect expiry: expired redirect causes a new redirect only on miss; cached bytes remain valid.

**Filesystem coverage** (cache-relevant slice)
- SQLite WAL on Linux ext4/xfs/btrfs, macOS APFS, Windows NTFS.
- NFS/SMB/FUSE refusal for `state_root` by default.
- Network `cache_root` opens read-only by default; writable network cache requires `shared-single-writer` plus `writer_identity`.
- Digest reverification catches a tampered shared-cache file before a lease is returned.

**Observability**
- Metrics are emitted for hit/miss/pending/fill/GC/recovery/auth-refresh paths with no raw secrets or full local paths.
- Tracing spans include `resolved_target_hash`, key kind, route epoch, policy epoch, and fs-risk attributes.
- `cache doctor` dry run reports the same corrupt/staging/lease findings as startup recovery without mutating state.

## Implementation notes

The cache crate provides a small synchronous CAS index: `Cache::open` / `Cache::open_with_options`, `put` (and `put_with_existing_key_lock`), `get`, `get_entry`, `entry`, `remove_index`, `remove_prefix`, `with_herd_lock`, `lock_key`, and `status`. It stores bytes under `<cache_root>/sha256/<aa>/<rest>` and tracks entries in `<state_root>/index.sqlite` (single `entries` table plus `process_leases`) behind an in-process `Mutex<Connection>` so the dispatcher and REST gateway can share one `Library`. The list-backed object-stat cache lives in `ovstorage` as an in-memory TTL/LRU cache of parent listings; it is not persisted in `ovstorage-cache`. Cross-process OAuth/STS refresh coalescing lives in `ovstorage::auth::AuthRefreshLock` (see [crates/ovstorage](../ovstorage/README.md)), which owns the `auth.sqlite` snapshot table and the per-`(backend_kind, connection_id)` advisory file lock; the cache crate hosts the `index.sqlite` half and does not duplicate that surface. The cache crate does not implement split `index.sqlite` / `auth.sqlite`, full schema migrations beyond the present versioning, full lease lifecycle, staging recovery, herd-collapse beyond the typed key, GC, or network-filesystem refusal in target form.

Design constraints carried by the crate:

- The `CacheHandle` surface is small: `open_roots`, `lookup`, `begin_fill`, `commit_fill`, `lease`, `release`, `gc`, `doctor`. Plugin-facing code stays out of this crate. OAuth/STS coalescing routes through `ovstorage::auth::AuthRefreshLock` rather than a separate cache helper.
- The schema uses versioned migrations from the start. `index.sqlite` and `auth.sqlite` each carry a `schema_version` row plus upgrade tests from every checked-in fixture version.
- Herd-collapse is built around explicit fill guards. A winner owns the upstream fetch and commit; waiters only observe `Pending` and re-read the index after notification.
- Crash injection is part of development: kill during staging write, CAS rename, index commit, lease release, OAuth refresh before keyring write, and OAuth refresh after keyring write but before SQLite commit.
- Filesystem probing is isolated behind a platform module so Linux `statfs`, macOS `statfs`, and Windows volume checks can be tested with fakes.

### Out of scope

- **Cache sharing across UIDs.** Cache and state roots are per-user; one user cannot share their `cache_root` / `state_root` with another. Multi-user nodes run one cache per user.
- **`lmdb` fallback evaluation.** The crate's persistence layer is SQLite; alternative key-value stores are not on the roadmap.

## Risks

### SQLite contention under high concurrency

**Status:** spec-extending

**Concern.** Many concurrent client processes — CLIs, fork-server workers, push `watch_directory` listeners — contending for the state-DB writer lock could degrade latency below the herd-collapse benefit on heavily-shared hosts.

**Why this mitigation is sound.** SQLite WAL mode permits concurrent readers with a single writer ([sqlite.org/wal.html](https://www.sqlite.org/wal.html)) and is the documented choice for the "many short-lived processes, one DB" pattern that git, git-lfs, rustup, and Mozilla's certificate-store all ship in production. The cache byte path avoids long writer transactions: reads acquire a short lease transaction, then stream or mmap the CAS file under the lease; writes batch metadata updates per fsync; per-herd-key locks keep writer contention to genuinely-conflicting fills, not coordinator metadata. Benchmarks measure whether this holds for the project's peak target before 1.0 freezes the schema.

**Alternatives considered and rejected.**

- **lmdb instead of SQLite.** Single-writer-MVCC; no WAL story for our crash-recovery shape; pulls a C dependency the project otherwise avoids. Kept as a fallback if benchmarks fail.
- **Per-process state-DB shards.** Defeats herd-collapse cross-process — the entire point of the shared state-DB is that two processes converging on the same CAS key collapse into one upstream fetch.
- **Daemon-required state.** Explicit non-goal; the project's commitment is that direct-mode CLIs work without a daemon. A per-host broker over UDS is the operator's tool for daemon-shaped workloads, not a library requirement.
- **Postgres / sqlite-replication.** Single-host scope only; cross-host state is the broker's job.

**What this mitigation does NOT cover.**

- Network-mounted `state_root`: refused at open with `InvalidConfig`; see "Network filesystems" above for the rationale and the override path.
- Pathological single-key writer storms (10,000 procs all writing to the same CAS key): bounded by herd-collapse coordination, not by WAL — the storm collapses to one upstream fetch and the rest wait on the per-key flock.
- Linux-specific `flock` semantics over remote-fuse mounts: the same NFS/SMB refusal logic catches the common cases; exotic filesystems (CIFS variants, Docker volume drivers) may need an explicit allowlist.

**Implementor checklist.**

- `index.sqlite` opened with `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`, `cache_size=-20000` (20 MB cache).
- `auth.sqlite` is a separate file with `synchronous=FULL` (see [OAuth single-use refresh token durability](#oauth-single-use-refresh-token-durability)).
- Hot cache-read path: short SQLite lease transaction, verify/open `<cache_root>/sha256/<aa>/<bb>/<cas_key>`, then stream or mmap under the lease; no long SQLite transaction while bytes are read.
- Writes batched per fsync barrier; cap one transaction per 100 cache entries or per 50ms, whichever comes first.
- Per-key advisory `flock(<state_root>/herd/<kind>/<key>.lock, LOCK_EX)` for herd-collapse coordination; held only across election, upstream fetch, and commit/abort.
- `state_root` and `cache_root` independently configurable; `cache = None` is supported and skips the cache layer entirely (state DB still active for OAuth and connection metadata).

**Verification.**

- Bench `cache_contention_1000procs`: p99 cache-hit ≤ 5ms, p99 cache-miss-coordinated ≤ 50ms over 1000 concurrent procs on a 32-core host with cold cache.
- Bench `cache_contention_writer_storm`: 100 concurrent writers to distinct CAS keys; writer p99 ≤ 200ms.
- Conformance test `state_db_nfs_refusal`: `state_root = /mnt/nfs/state` fails open with `InvalidConfig`; the override path produces a startup warning.
- Reassessment gate: if either bench misses the target by > 2×, ship lmdb fallback before 1.0.

### OAuth single-use refresh token durability

**Status:** defensive-depth

**Concern.** OAuth refresh tokens are typically single-use — every refresh rotates the token, and the previous one is invalidated server-side. A crash between writing the new token and using it (or, worse, between issuing the refresh request and persisting the response) leaves the principal locked out: the old token is dead at the IdP, the new token never landed on disk.

**Why this mitigation is sound.** The OAuth state lives in `auth.sqlite`, opened with `synchronous = FULL` (every commit fsyncs the DB and the journal), separately from `index.sqlite` whose hot cache path uses `synchronous = NORMAL`. The split keeps the durability cost paid only on auth events (a handful per process per hour) and never on the cache hot path (millions per process per hour). The pattern matches systemd-cred and `gh auth`, both of which fsync per credential mutation but batch unrelated state writes.

**Alternatives considered and rejected.**

- **Single SQLite file with `synchronous = FULL`.** Pays the durability cost on every cache-metadata write; benchmarks show this turns the cache writer into the bottleneck under realistic load.
- **Only the OS keyring, no SQLite coordination.** Keyrings are the right place for refresh-token bytes, but they are not a cross-process refresh protocol. The SQLite row plus `auth/<backend>.lock` gives every process the same refresh metadata, timestamps, and serialization point while token bytes remain in the keyring.
- **Ephemeral refresh tokens (re-prompt on every restart).** Defeats unattended workloads (CI bots, push `watch_directory` listeners) that the project explicitly supports.

**What this mitigation does NOT cover.**

- An IdP whose refresh-token rotation is not actually atomic (rare, but observed in some on-prem Keycloak configurations): the IdP's bug, not solvable client-side.
- Power loss between issuing the refresh request and the IdP's server-side persistence: caller sees a transient error and retries with the old token; if the IdP rotated server-side but lost the response, the principal is locked out and must re-authenticate. This is fundamental to single-use refresh as a protocol.

**Implementor checklist (target).** This list describes the intended end-state; current behavior diverges as flagged inline.

- `auth.sqlite` schema: `refresh_records(backend, last_refresh_unix_ms, last_expires_unix_ms)`, `secret_tokens(backend_id, principal, source_name, expires_at_unix_ms, cred_epoch, persisted_at_unix_ms, …)`, `secret_blobs(handle, bytes, inserted_unix_ms)`. Generic over the credential kind — OAuth, S3 STS, Azure SAS, etc. — so a single durable shape covers every refresh-shaped credential the workspace plumbs. **Current:** the three tables exist and are owned by `ovstorage::auth::AuthRefreshLock`.
- `BEGIN EXCLUSIVE` around every refresh: fetch the current row, perform the IdP refresh request, write the new keyring handle/timestamps, commit. The exclusive transaction serializes refresh attempts within a single process; cross-process serialization uses `flock(<state_root>/auth/<backend>.lock, LOCK_EX)` held across the entire refresh. **Current:** the per-`(backend_kind, connection_id)` advisory file lock ships, but the SQLite write does **not** wrap in `BEGIN EXCLUSIVE` — it relies on a single `INSERT ... ON CONFLICT DO UPDATE`.
- `synchronous = FULL`, `journal_mode = WAL`, `busy_timeout = 30000` (refresh can wait up to 30s for the lock).
- The refreshed token bytes are written to the OS keyring before the SQLite row is committed. The SQLite commit publishes the new durable handle. If the keyring write succeeds but SQLite commit fails, the next refresh attempt still reads the old handle; the unused keyring item is garbage-collected by handle age. If SQLite commit succeeds, every process must be able to resolve the committed handle.
- The encrypted-file fallback is **not implemented**: there is no `EncryptedFile` variant in `SecretStorageKind`, and `--state-status` has no representation for it. The OS keyring (`OsKeyring`, default) and the plaintext SQLite BLOB column (`Database`) are the two implemented persistence paths; `External(Arc<dyn SecretStorage>)` admits sibling-crate impls. The target design — opt-in only, flagged loudly at startup, surfaced in `--state-status` — stands but is unscheduled; encryption-at-rest for `Database` is the operator's responsibility today.

**Verification.**

- Conformance property test `oauth_refresh_durability_under_crash`: N=20 trials, kill -9 the process at randomly-chosen instants between SPI call and SPI return during refresh; the post-restart state is either (a) the old token still valid, or (b) the new token persisted — never "both dead."
- Conformance test `oauth_refresh_cross_process_serialized`: 4 processes race a refresh against a near-expiry token; exactly one IdP `POST /token` fires and exactly one rotation lands.
- Tracked in this crate's "Implementation gaps" as `OAuth refresh race conformance test passes`.
