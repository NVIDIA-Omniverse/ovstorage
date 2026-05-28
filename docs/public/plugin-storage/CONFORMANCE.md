# Plugin Storage Conformance

Behavioral contract for every Storage SPI method. Read once before
implementing a new backend; refer back when an edge case bites.

This document defines **what each method must do**. It does **not** define
the type signatures (those live in `ovstorage-core/crates/ovstorage-plugin/README.md`
section "Plugin SPI") or the capability bits (those live in the same
README's section "Capability vocabulary"). You will need both open while
reading this. The per-backend reference pages in this directory
(`plugin-file.md`, `plugin-s3.md`, `plugin-gcs.md`, `plugin-azure.md`,
`plugin-opendal.md`, `plugin-services-client.md`, `plugin-nucleus.md`,
`plugin-broker.md`, `plugin-http.md`, `plugin-test.md`) each illustrate
one valid branch of the contracts below.

Sections that branch on backend characteristics use the
**"If your backend… then…"** pattern. Pick the branch that matches your
backend; one branch is always correct.

---

## How to read this document

Each method section has the same shape:

- **Contract** — what must be true after a successful return.
- **Edge cases** — corners reality reaches but the type signature doesn't
  capture (trailing slashes, zero-byte bodies, addresses pointing at
  versions, etc.).
- **Branch points** — capabilities-driven choices. Pick one branch.

When a section says *"see Nucleus for an example"* or
*"see S3 for the multipart shape"*, those are illustrations of one valid
branch — your backend doesn't have to match.

---

## Cross-cutting rules

These apply to every method. They are not repeated per-section.

### Method gating: baseline vs optional

The Storage SPI splits methods into two groups:

- **Baseline required methods** have no default implementation; every
  plugin must implement them. The host calls them on every backend
  regardless of any capability bit:
  - `stat`
  - `read`

  These are the universal floor — every backend that exists at all
  can answer "does this address resolve?" (`stat`) and "what bytes
  are here?" (`read`). A backend that cannot serve one of these has
  no business being a backend.

- **Optional methods** have a default `Unsupported` implementation;
  plugins opt in by overriding the default. Each is paired with a
  capability bit so the host fast-paths `Unsupported` without
  invoking the method:
  - `delete` — `supports_delete`
  - `list` — `supports_list`
  - `create_directory` — `supports_create_directory`
  - `delete_directory` — `supports_delete_directory`
  - `write` — `supports_write` (buffered single-shot path)
  - `write_stream` — `supports_write_stream` (chunked path)
  - `write_redirect` — `supports_write_redirect` (presigned-URL
    path; `continue_write` is gated implicitly by the same bit
    since it only runs after a redirect)
  - `list_versions`, `get_latest_version` — `supports_version_listing`
  - `copy` — `supports_server_side_copy`
  - `rename` — `supports_server_side_rename`
  - `update_metadata` — `supports_native_metadata_patch`
  - `check_access` — `supports_access_check`
  - `watch_directory` — `supports_watch_directory`

  `watch_address_roots` is also optional but not directly bit-gated;
  the host's watcher invokes it and exits quietly on `Unsupported`
  for plugins whose root set is static.

The three write bits are independent. A plugin that only supports
streaming uploads sets `supports_write_stream = true` and leaves
`supports_write` / `supports_write_redirect` false; the host's
dispatcher then picks `write_stream` regardless of `size_hint` or
`redirect_size_threshold`. `redirect_size_threshold` only ranks
`write` vs `write_redirect` when both bits are true.

If you don't implement an optional op, leave the default impl in
place and the bit false; the host returns `Unsupported` to callers
without invoking the method. If the bit is true the host expects
the method to behave per this contract — no half-implementations.

A plugin that exposes a single read-only resource per address (e.g.,
the HTTP plugin) advertises `Capabilities::empty()` — every bit
false. The host calls only `stat` and `read`; every other method is
short-circuited at the dispatcher to `Unsupported` before it reaches
the plugin.

Capabilities are immutable for the backend instance's lifetime.
Decide once at `instantiate` time.

Defensive `Unsupported` returns from any method whose capability bit
is false are allowed — the host won't call them anyway, but plugins
that want to fail safely if the host's gating ever drifts may keep
an explicit stub.

**Per-instance backend configuration.** Capabilities reflect the
*specific instance* you're bound to, not the plugin's general
capability list. Many backends expose features that are toggleable
per-bucket / per-mount / per-tenant — versioning being the canonical
example (S3 buckets without versioning enabled, Nucleus mounts
configured without checkpoints). Advertising `supports_version_listing
= true` on a non-versioned bucket would silently violate the contract
("every write produces a version") because no version would actually
appear. Probe at `instantiate` time and reflect what's really there.
If your backend doesn't let you query the relevant configuration
cheaply, it's the operator's responsibility to match the
backend's TOML config to backend reality (an explicit
`enable_versioning = false` knob is fine, and arguably better than a
silent assumption either way).

**Meta-plugins (per-address capability discovery).** A plugin that proxies
to multiple heterogeneous downstream backends — `ovstorage-plugin-broker-client`
is the canonical example — cannot know at `instantiate` time which
capabilities a given address will support, because that depends on which
backend the broker routes to. Such a plugin advertises the **union** of
capabilities its downstream backends might offer, then returns
`Unsupported` from individual method calls when the resolved downstream
can't perform the op. This is the explicit exception to "no
half-implementations": the contract becomes "the method either honors
this section or returns `Unsupported` — never partial work, never
`Internal` for a known capability mismatch." The host treats
`Unsupported` from a method call the same as a false capability bit at
the call site, so callers see consistent behavior either way.

**`wants_list_backed_stat` semantics.** When `wants_list_backed_stat =
true` (and `supports_list = true`), the host may satisfy an
unversioned, non-directory `stat` with `full_metadata = false` from a
cached or freshly fetched one-level parent `list` entry, bypassing
`StorageBackend::stat`. `full_metadata = true`, directory-form
addresses (trailing slash), and version-selected URLs always dispatch
to `StorageBackend::stat`. Set the bit when your backend's `list`
entries already carry the same metadata fields as `stat` (etag,
version, size, mtime), so the parent-list shortcut is metadata-correct
without an extra round trip. Leave it false if `list` returns thinner
entries than `stat` does — the host won't synthesize the missing
fields.

### Address inputs

Every I/O method receives a `ResolvedTarget` containing a
`resolved_address: Url`. The host has already:

- parsed and validated the URL syntax (canonical RFC 3986 form),
- applied any prefix substitution from a matching alias or the route's
  configured `rewrite_to` (e.g. `mybucket:/foo` →
  `https://bucket.s3.amazonaws.com/foo` if the user aliased `mybucket:`
  to that S3 URL).

**The address is the full URL the plugin operates on, not a relative key
under your route prefix.** A plugin instance bound to
`https://bucket.s3.amazonaws.com/` receives calls with
`resolved_address = https://bucket.s3.amazonaws.com/some/key`, *not*
`/some/key`. The route prefix is not stripped — the plugin owns the
translation from URL to its wire protocol's preferred shape (bucket
name + key for S3, Nucleus path string for omni1, etc.). Do that
translation once at the boundary and stash the result.

Returned `ObjectInfo.address` values from `list`, `list_versions`,
`get_latest_version`, and `watch_directory` use the same resolved
address namespace and must stay inside the requested prefix or target
scope. The host projects them back into the caller-facing namespace.
If a returned address escapes that scope, treat it as a plugin bug:
surface `Internal`, not a best-effort filtered child. Display labels
are derived from the parent/child addresses; they are not returned as
separate fields.

**Don't re-parse, re-canonicalize, or re-validate** the URL syntax — the
host has already done it.

The host *does not* re-shape the address beyond alias/rewrite
substitution: case, percent-encoding, query string, and path content all
arrive as the caller specified. Trailing-slash handling is a partial
exception; see the next section.

### Trailing slash conventions

For a few clearly directory-facing methods — `list`, `watch_directory`,
`create_directory`, `delete_directory` — the host normalizes the address
to end with `/` before invoking the plugin. Plugins on those methods can
assume the trailing slash is present.

For everything else, **the address arrives as the caller wrote it**.
File-facing methods (`read`, `write`, `delete`, `copy`, `rename`)
conventionally receive paths without a trailing slash, but the plugin
should not crash if a caller supplies one — translate to your backend's
preferred shape and proceed (or reject with `InvalidArgument` if the
shape is genuinely ambiguous on your backend).

`stat` is the explicit exception — it may receive either form. The
trailing slash is a *hint* the caller wants directory metadata; absent
it, prefer the file shape and fall back to directory. The Nucleus plugin's
dual-probe (`ovstorage-nucleus/crates/ovstorage-plugin-nucleus/src/backend/spi.rs`)
fires both queries in parallel; an alternative is sequential probing or
caching the last-known shape per address. Pick what your backend
supports cheapest. When both probes fail, prefer the file-shape error
in the surfaced result (the file shape is the more common case and
gives a clearer error class for callers); cache the last-known shape
if your backend supports it.

### Cancellation

Every async I/O method takes `cancel: Option<CancellationToken>`. Honor
it before starting any I/O round-trip and at chunk boundaries within a
streaming operation. Cancellation produces `ErrorCode::Cancelled`.

A backend that doesn't honor cancellation is a hang vector for the
broker. Plumb the token; don't ignore it.

See **Cancellation contract** at the end of this document for the
cross-workspace FFI-level reality (the host does not propagate
cancellation across the cdylib boundary today), and what plugin authors
must do to bound their own work in lieu of it.

### Streaming invariants

Read streams (`ReadResult::Stream`) and write streams (`Body::Stream`
into `write_stream`) propagate chunk-by-chunk. **Do not buffer the full
body to a `Vec<u8>` at the plugin boundary.** That's a memory-DoS vector
on the public REST gateway and is forbidden by the project's streaming
invariant. The crate `ovstorage-core/crates/ovstorage-plugin-test`
(section "Streaming seams" in its README) provides
`assert_streaming_invariants` which drives ≥3 chunks of ≥64 MiB at 4 MiB
each and verifies bounded in-flight bytes.

`ReadResult::Bytes` is the small-response shape — fine for sub-threshold
whole-object or ranged reads. Above the threshold the plugin MUST return
`Stream`; never widen the buffer.

If your backend cannot truly stream a write, return `Unsupported` from
`write_stream`. Do **not** disk-spool as a half-measure.

**Write-stream cancellation.** A backend-side error during
`write_stream` — a `BodyStream::next_chunk` returning `Err(_)` —
aborts the upload and the partial body is not committed. Plugins do
not need to handle this explicitly: the chunk-pull error propagates
back through whatever transport carries the stream. In Brokered mode
the broker-side `Write` RPC distinguishes a graceful client half-close
(commit) from an HTTP/2 RST_STREAM(CANCEL) (abort); `broker-client`
raises the cancel signal automatically when its chunk pump captures a
chunk error, dropping the in-flight RPC future to RST_STREAM the
broker. Plugin authors don't see this distinction directly — return
`Err(_)` from the chunk source and the rest happens for you.

### Publish-before-durable

A successful return from `write` / `copy` / `rename` / `update_metadata` /
`delete` / `delete_directory` / `create_directory` is a **durability
contract**: the host treats the response as "this state is observable to
future reads, and it survives a crash now."

The rule: any plugin-side state that signals "this write is done" — an
in-memory cache entry, a "last-known etag" map, a oneshot/channel send
to a background worker, the release of a per-target lock — must happen
**after** the backend has acknowledged durability, never before.

The simplest correct shape is to keep no plugin-side state at all:
await the backend, return. Don't introduce caches, queues, or locks
unless your backend actually requires them.

When you do need them, two real cases from this codebase:

- **Cache writes after success.** If you maintain an in-memory cache,
  insert the new entry only on the `Ok` path of the backend await — not
  before the await. A failed backend write must not leave a stale
  cache entry.

- **Per-target lock around non-atomic publish steps** (file plugin).
  `ovstorage-plugin-file` serializes writers per-path so the
  `try_exists` → `if_match` check → `rename(2)` sequence is atomic.
  The lock is held *across* the `rename` await — releasing it earlier
  would let the next writer's `try_exists` race against the in-flight
  rename. (This is a `tokio::sync::Mutex`; holding a `std::sync::Mutex`
  across `.await` is a separate bug — don't do that.)

- **Multi-stage durability** (file plugin: bytes-then-sidecar). When
  durability lands across multiple commit stages (e.g. file plugin
  commits bytes via `rename(2)`, then writes a user-metadata sidecar
  in a second step), the durability contract still applies to the
  final-stage commit. If the sidecar write fails after the bytes have
  already landed, the right answer is to surface the error to the
  caller — they will see the bytes as committed (`stat` returns the
  new etag/version metadata) but their write call returned non-`Ok`, so they know
  to re-issue the metadata patch. Do not retry the bytes commit; that
  would change the etag/version again and break any concurrent `if_match`
  retry the caller is doing.

The wrong shape, in either case, looks like:

```rust
let _lock = self.locks.acquire(target).await;
let pending = client.send(write_request);   // request dispatched
drop(_lock);                                  // <-- bug
let response = pending.await?;                // might fail
```

Dropping the lock before the await tells the next waiter "previous
write done" while it's still in flight; if `pending.await` then errors,
the next waiter has already started on a state that never materialized.
The fix is to await before dropping. See `ovstorage-plugin-file::write`
(tempfile + `sync_all` + lock + `rename(2)`) for the canonical
sequencing.

### Error code mapping

The host's retry policy and the user-facing error UX both depend on
which code you return. Some common confusions:

| Situation                                | Code                  | Why |
|-----------------------------------------|-----------------------|-----|
| Path doesn't exist                       | `NotFound`            | Triggers idempotent-delete handling, cache eviction. |
| `if_match` mismatch                      | `PreconditionFailed`  | Tells the caller "the object changed under you." |
| Object changed during op                 | `ObjectModified`      | Object changed *during* a streaming operation (typically read; only meaningful when bytes had already flowed when the change was detected). Don't use `ObjectModified` for write-side `if_match` mismatches — those are `PreconditionFailed`, since no work happened. |
| Caller supplied bad input                | `InvalidArgument`     | Won't be retried. |
| Backend can't do this op                 | `Unsupported`         | See *Scope of `Unsupported`* note. Don't conflate with `InvalidArgument`. |
| Caller has no permission                 | `PermissionDenied`    | Distinct from `AuthRequired` (no creds) / `AuthExpired` (creds need refresh). |
| Network blip / 5xx / throttle            | `Transient`           | Host retries with backoff. |
| Plugin bug / unhandled state             | `Internal`            | Last resort; surfaces as "plugin bug" to operators. |

**Scope of `Unsupported`.** This code covers two distinct cases, and
plugins use both:

1. *The op is never available on this backend.* Capability bit is
   false; the host returns `Unsupported` to callers without invoking
   the plugin at all.
2. *The op is generally available, but this specific call can't be
   honored.* Capability bit is true, but the plugin returns
   `Unsupported` because of a particular argument combination — e.g.
   `delete` with `if_match` on a backend whose delete API has no etag
   field, or a `copy` whose `src` and `dst` resolve to different
   downstream backends in `ovstorage-plugin-broker-client`. The op
   itself works fine; *this call* doesn't.

`Unsupported` is the right code for both. Don't reach for
`InvalidArgument` in case 2 — the caller's input is well-formed; it's
the backend that can't carry it.

A common backend-quirk trap: a server returning `INVALID_URI` /
`INVALID_PATH` for *both* malformed paths *and* missing paths. Map to
`NotFound` in the latter case. The Nucleus plugin's `status_to_result`
(`ovstorage-nucleus/crates/ovstorage-plugin-nucleus/src/ops.rs`) peels
`InvalidPath` out of the `InvalidArgument` bucket for exactly this
reason.

**Post-redirect failure mapping.** When a plugin's `continue_write` (or
any path that interprets `RedirectResultBatch`) sees a non-2xx HTTP
status, it MUST decode it into the typed error code, not blanket-
`Transient`. Map 404 → `NotFound`, 412 → `PreconditionFailed` (or
`ObjectModified` if the response indicates the body was partially
observed before the failure), 403 → `PermissionDenied`, 401 →
`AuthRequired` / `AuthExpired`, 409 → `Conflict`. `Transient` is
reserved for connection errors plus retryable server errors (HTTP 429
and 500-599). The host's retry policy depends on this mapping; lumping
412 into `Transient` triggers useless backoff retries on a deterministic
precondition failure.

**gRPC mapping.** gRPC `Internal` is *not* retryable — it means "the
server is broken in a way that more attempts won't fix" and maps to
ovstorage `Internal`, not `Transient`. Connection-level gRPC errors
(`Unavailable`, `DeadlineExceeded` from network blips) are `Transient`.
`INVALID_PATH`/`NotFound` ambiguity is covered separately above.

### Address-modifier rejection

A backend that supports versioning lets the caller pin a specific
historical version with a URL query parameter — e.g.
`s3://bucket/key?versionId=abc123` for S3, `omniverse://.../file?checkpoint=42`
for Nucleus, `gs://bucket/object?generation=12345` for GCS. Such an
address says "address version `abc123` of this object", not "address
the current version".

**The rule:** reject the modifier when your wire protocol can't honor it
on this op; honor it natively when it can. **Never silently degrade an
op on a version to an op on head.**

The trap: a naive plugin reads the URL path, ignores the query string,
and issues the mutation against the head. The caller thinks they
deleted (say) version `abc123`; in reality they just deleted the
current version. The pinned address is silently downgraded to the head
and current data is destroyed. This is the failure mode the rule
exists to prevent — apply the same scrutiny to every mutating op.

Concretely:

- *If the wire honors the modifier on this op* — pass it through. S3's
  `DELETE Blob` accepts `versionId` and deletes that specific version;
  GCS `DELETE` accepts `?generation=`; Azure `DELETE Blob` accepts
  `versionid`. Same for `copy(src)` on backends that take a versioned
  source (S3's `x-amz-copy-source-version-id`, Azure's `x-ms-copy-source`
  with embedded `versionid`).
- *If the wire can't honor the modifier* — reject **before any backend
  call** with `ErrorCode::InvalidArgument` and a message naming the
  modifier and the op. S3's `PutObject` doesn't accept `versionId`;
  Nucleus's `delete2` / `copy2` / `rename2` have no checkpoint field;
  GCS's `PUT` and metadata patch operate on head only. In each of
  those cases, the modifier is silently dropped on the wire — exactly
  the trap above. Reject pre-flight so the caller learns immediately.

Use the shared helper to keep the guards uniform:

```rust
use ovstorage_plugin::reject_pinned_for_mutation;
reject_pinned_for_mutation(&target.resolved_address, "<plugin> <op>", &["versionId"])?;
```

(Defined at `ovstorage-core/crates/ovstorage-plugin/src/url_helpers.rs`.
The Nucleus plugin's `reject_checkpoint` is an older equivalent that
inspects the parsed `NucleusTarget.checkpoint` field directly; both
shapes are fine.)

Per-op guidance:

- `write` / `write_stream` / `write_redirect` — reject if the
  destination is pinned (can't overwrite a frozen version on any
  primary backend).
- `delete` — honor on backends whose wire accepts a version pin
  (S3, GCS, Azure, omnistorage); reject on backends whose wire is
  head-only (Nucleus's `delete2`).
- `rename` — reject if either `src` or `dst` is pinned. Old versions
  have no movable identity, and you can't rename onto one.
- `copy` — reject if `dst` is pinned (copy-to-version is nonsense).
  For `src`, honor it on backends that support copy-from-version
  natively; reject when the wire can't carry the source version.
- `update_metadata` — head-only on every primary backend that exposes
  user-metadata patch; reject if the target address is pinned.
- `delete_directory`, `create_directory` — reject if the address is
  pinned. Directories don't have version-modifier semantics.

Meta-plugins (`ovstorage-plugin-broker-client`) forward the address
verbatim to the broker; the downstream plugin applies its own
guard. Don't strip the modifier and don't reject pre-emptively in the
meta-plugin — let each downstream make its own honor-or-reject call.

### Plugin-boundary hardening patterns

Beyond the per-method contracts, every in-tree plugin enforces three
cross-cutting invariants *before* any backend round-trip. New backends
should adopt the same pattern; the per-backend reference pages spell
out the specific helpers each plugin uses.

**Preconditions are opaque etag strings.** The SPI's precondition
fields are:

- `ReadOptions::if_match`, `DeleteOptions::if_match`,
  `UpdateMetadataOptions::if_match` — `Option<String>` etag.
- `WriteOptions::if_dest`, `CopyOptions::if_dest`,
  `RenameOptions::if_dest` — `IfDestExists` (`Overwrite` / `Fail` /
  `MatchEtag(etag)`).
- `CopyOptions::if_source`, `RenameOptions::if_source` —
  `Option<String>` etag constraining the source.

The etag is opaque to the SPI; its internal structure is the
plugin's choice. The `file` plugin synthesizes `"size:N,mtime:Tms"`;
HTTP-derived backends use the wire `ETag` header value verbatim;
GCS encodes the generation number; the Omniverse Storage Service uses
`ResourceIdentity.encoded_identity`; the broker forwards whatever
string the upstream backend supplied. A plugin that wants to encode
multiple facts into a precondition can do so inside the opaque
string. The host never parses or interprets it.

Backends without an etag-conditional wire (most OpenDAL drivers)
honor `ReadOptions::if_match` and `DeleteOptions::if_match` via
post-stat compare. Backends without any precondition surface
(Nucleus's `delete2` / `copy2` / `rename2`) return `Unsupported`
when the preconditions are populated.

**Inverted byte ranges refused at the plugin boundary.** Every plugin
that honors `ReadOptions::range` checks for `end_inclusive < start`
*before* any wire or I/O call and returns `InvalidArgument`. Lumping
this with backend-side range errors would round-trip a deterministic
caller bug and lose the precise diagnostic. The plugin boundary is the
right place to refuse it — every backend in tree (file, http, S3, GCS,
Azure, OpenDAL, Nucleus, services-client, broker) does so consistently.

**`write_redirect` `size_hint` discipline.** Most cloud plugins refuse
`size_hint = None` at the SPI boundary because their multipart wire
needs total length to compute part offsets (Nucleus's LFT multipart is
the canonical example; S3's multipart can in principle adapt but the
in-tree plugin still requires the hint for cap-management). The broker
plugin is the exception: it forwards `size_hint = None` faithfully
because the broker daemon's `BrokerRoutePolicy::should_redirect_write`
accepts unknown sizes and the single emitted `WriteRedirect` carries
the body via `body_source` rather than a known `Content-Length`. A new
plugin author should make this choice deliberately and document it on
the per-backend page; the trap is silently treating `None` as `0` or
choosing a default chunk count that overflows the backend's part limit.

---

## Per-method contracts

### `stat`

**Contract.** Return current `ObjectInfo` for `target`: `kind`,
identity facts (`etag`, `version`, `size`, `mtime`), checksums when
known, system metadata, optionally `user_metadata` and
`effective_permissions`.

**Edge cases.**

- `opts.full_metadata` is a cost knob, not an inclusion list. `false`
  means *populate whatever you can cheaply* (e.g. fields already on a
  list-entry response, no extra round-trips); `true` means *populate as
  much as you can, regardless of cost*. Callers asking for the cheap
  shape may still receive `user_metadata` / `system_metadata` if your
  backend hands those back for free.
- `effective_permissions: None` means *"didn't compute"* (capability
  `populates_effective_permissions_on_stat = false`).
  `Some(EffectivePermissions::empty())` means *"explicitly denied
  everything"*. Distinct.
- Trailing slash hint: see *Trailing slash conventions* above.

**Branch points.**

- *If your backend distinguishes file vs. directory by path shape (Nucleus,
  filesystems with explicit directories):* probe both and return the one
  that exists. Or pick by trailing-slash hint.
- *If your backend is flat (S3-style):* a non-trailing-slash address
  always names the object; a trailing-slash address names a logical
  directory. To resolve a logical directory: HEAD the optional `dir/`
  marker; if absent (404), issue a bounded list under the prefix
  (for example `max_results: 2`). If the probe returns the marker
  itself, return marker info; otherwise, if any descendant exists,
  return synthetic info for the directory. If the bounded list is
  denied, propagate the permission/auth error rather than guessing.

### `read`

**Contract.** Return one of:

- `ReadResult::Bytes { bytes, info }` — the entire response materialized
  as a small buffer; valid only for whole-object or ranged reads under
  the per-plugin small-response threshold (a few MiB max — the plugin
  chooses).
- `ReadResult::Stream { stream, info }` — bytes flow chunk-by-chunk
  through the host.
- `ReadResult::Redirect(...)` — host fetches from a presigned URL.
- `ReadResult::LocalDelegate(...)` — host reads from a local path under
  lease.

The byte sequence must match the object's current state at the moment of
return (or at the version pinned by the address).

**Edge cases.**

- `opts.if_match` — fail with `ObjectModified` *before* yielding bytes.
  Don't stream half a wrong object then error.
- `opts.range` — follows HTTP/RFC 7233 semantics. Open-ended ranges
  (`start..` with no end) are valid. A range that *partially* extends
  past the end of the object is clamped to the available bytes (HTTP
  206 Partial Content shape). A range that starts at or past the end
  of the object — i.e. has *no* overlap with the object — returns
  `InvalidArgument` (HTTP 416 Range Not Satisfiable). Don't error on
  partial overrun; that would diverge from S3, GCS, Azure, and every
  HTTP-derived backend.
- `opts.range` with `end_inclusive < start` is **inverted** and the
  plugin refuses it at the SPI boundary with `InvalidArgument` before
  any wire call. See *Plugin-boundary hardening patterns* above.
- *Pinned-version address* (`?versionId=X`, `?checkpoint=N`, etc.) —
  return that version's bytes. The address is read-only; mutation guards
  belong on the write paths, not here.

**Branch points.**

- *If your backend issues presigned URLs:* `Redirect` returns the URL
  instead of streaming bytes through the plugin. In broker or REST
  gateway mode the host can forward the URL to the gRPC/HTTP client,
  so bytes flow from the backend straight to the client without
  passing through the host. Set `expires_at` accurately; the host
  validates freshness.
- *If your backend serves files from local disk under a lease:* you
  MUST return `LocalDelegate` (not `Bytes`). Buffering an entire local
  file into a `Vec<u8>` is the same memory-DoS vector as buffering a
  write stream — unbounded by object size. Hold the lease for the
  duration the delegate is alive.
- *Otherwise:* `Stream`. Peak memory should be chunk size × channel
  capacity; never the full object size.

### `write`, `write_stream`, `write_redirect`, `continue_write`

These four are facets of one operation. The host picks which based on
body shape and capabilities.

**Contract.** On `Ok(WriteStep::Done(result))`, the bytes and
`result.info` describe the new persistent state. Reads against the
target must observe this state from now on.

**Edge cases.**

- `opts.if_dest = IfDestExists::MatchEtag(etag)` — precondition;
  fail with `PreconditionFailed` before any bytes commit. The etag
  string is opaque to the SPI; map it to whatever conditional your
  wire carries.
- `IfDestExists::MatchEtag(etag)` against a non-existent target —
  return `NotFound`. The precondition implicitly asserts existence;
  absence is a precondition violation. (Distinct from
  `PreconditionFailed`, which is for *etag-mismatch* on an existing
  target.)
- `opts.if_dest = IfDestExists::Fail` — fail with `Conflict` if the
  destination exists. Distinct from "create with default; fail if
  exists".
- `opts.size_hint` — the host uses this to gate `redirect_size_threshold`
  and may help your multipart logic. Rely on it for *known* sizes;
  for `write_redirect`, decide explicitly whether your backend can
  honor `size_hint = None` (the broker forwards faithfully; most cloud
  plugins refuse). See *Plugin-boundary hardening patterns* for the
  design space.
- `opts.message` — per-operation annotation. See **Versioning model
  decision tree** below for backend-specific handling.
- Zero-byte writes (`size_hint: Some(0)`) skip the redirect path
  entirely; the host calls `write` directly.
- `opts.user_metadata` — see `update_metadata` for the capability
  branching. `write` accepts metadata if your backend stores it; if
  not, reject non-empty `user_metadata` with `Unsupported` (don't
  silently drop).

**Branch points.**

- *If your backend caps single PUTs at N bytes (S3, Nucleus LFT):*
  emit multipart redirects. Each `WriteRedirect` carries its own
  byte-range and headers. The protocol shape (chunk numbering, size
  headers, finalization call) is backend-specific. Examples:
  S3 multipart (UploadPartNumber, CompleteMultipartUpload),
  Nucleus LFT (`Content-Start`, `Multipart-Chunk-Size`,
  finalize via `create_asset(content_id)`).
- *If your backend supports versioning:* see **Versioning model
  decision tree**.
- *If your backend can't truly stream `write_stream`:* return
  `Unsupported`. Do not buffer the full body.

### `delete`

**Contract.** After `Ok(())`, a subsequent `stat` against the same
address returns `NotFound` (modulo a concurrent writer re-creating it).
Conversely, a non-`Ok` return means the object may still exist.

**Edge cases.**

- `delete` against a non-existent target — return `Ok(())`. Many
  backends can't distinguish "deleted just now" from "already gone" and
  return success for both; the SPI mirrors that. The cleaner framing
  is also better for callers: "`Ok` ⇒ `stat` returns `NotFound`" is a
  uniform post-condition. Don't return `NotFound` from `delete`.
- `opts.if_match` — precondition; an opaque etag string. If your
  backend's delete API accepts an etag, use it; on mismatch, return
  `PreconditionFailed`. If your backend's delete API has no etag
  field (Nucleus's omni1 `delete2`), return `Unsupported` when
  `if_match.is_some()` — see *Scope of `Unsupported`* above. Don't
  synthesize CAS by stat-then-delete; that's a race against
  concurrent writers.
- `opts.if_match` against a non-existent target — return `Ok(())` (the
  post-condition holds vacuously and matches `delete`'s idempotent
  shape).
- *Pinned-version address* — honor when the backend wire accepts a
  version pin (S3 `versionId`, GCS `generation`, Azure
  `versionid`, omnistorage equivalent); reject with `InvalidArgument`
  before any backend call when the wire is head-only (Nucleus's
  `delete2`). See **Address-modifier rejection** above.

### `copy`, `rename`

**Contract.** `copy` produces a new object at the destination; `rename`
moves the source to the destination atomically (when possible).

**Edge cases.**

- `opts.if_source` — etag precondition on the *source*. Maps to
  backend source-side conditional headers
  (`x-amz-copy-source-if-match`, `x-ms-source-if-match`,
  `ifSourceGenerationMatch`).
- `opts.if_dest` — `IfDestExists` precondition on the *destination*.
  `Overwrite` replaces; `Fail` refuses if the destination exists;
  `MatchEtag(etag)` refuses unless the destination's current etag
  matches.
- *Pinned-version source* — `copy` accepts (copying out of an old
  version is the canonical "promote a version to a new path" operation).
  `rename` rejects.
- *Pinned-version destination* — both reject with `InvalidArgument`.
- *Cross-backend `src` and `dst`* — for primary plugins (S3, GCS, file,
  Nucleus, etc.) the host's resolver routes both addresses to a single
  backend before invocation; you won't see cross-backend pairs. For
  meta-plugins like `ovstorage-plugin-broker-client` that proxy to a
  remote with multiple backends, the resolved pair *can* span backends.
  Return `Unsupported` in that case — see *Scope of `Unsupported`*
  above. Don't silently fall back to read+write; the caller may have
  picked a server-side primitive for performance.
  Cross-backend detection is the broker's responsibility, not the
  meta-plugin's — `ovstorage-plugin-broker-client` does not re-route;
  it forwards the call and bubbles the broker's `Unsupported` (from
  `Library::copy` / `Library::rename`) back to the host.

**Branch points.**

- *If your backend supports server-side copy:* implement; advertise
  `supports_server_side_copy`. Otherwise leave the bit false; the host
  falls back to read+write.
- *If your backend can't accept etag on copy/rename (Nucleus):* return
  `Unsupported` for any populated `if_source` or non-`Overwrite`
  `if_dest`. Don't strip the precondition.
- *If `rename` is non-atomic* (copy-then-delete fallback): set
  `supports_atomic_rename = false`; surface partial-fail in error
  messages so callers know recovery is on them.
- `opts.message` — see **Versioning model decision tree**.

### `list`

**Contract.** Return a stream of `ObjectInfo` values under the prefix.

**Edge cases.**

- Each `ObjectInfo.address` is a full resolved backend address under
  the requested prefix; the host projects it into the caller-facing
  namespace. Returning an address outside the prefix is an `Internal`
  contract violation.
- `opts.recursive: false` → emit file `ObjectInfo` values and
  directory-kind `ObjectInfo` values for the immediate level. `true`
  → emit the entire subtree, including directory facts the backend
  actually stores or reports (`Directory`, `DirectoryMarker`, or
  `DirectoryInferred`). Flat backends may synthesize inferred ancestor
  directories implied by descendant objects; the host normalizes public
  recursive list results that way after address projection. If the
  backend reports the same address as both a concrete directory fact
  (`Directory` or `DirectoryMarker`) and an inferred prefix, emit only
  the concrete fact.
- `opts.max_results` / `opts.page_token` — pagination is host-driven.
  Your stream yields items; the host stops at `max_results`.

**Branch points.**

- *If your backend has native subdirectories (filesystem):* emit
  directory-kind `ObjectInfo` values on `recursive: false`.
- *If your backend is flat (S3):* emit directory-kind `ObjectInfo`
  values inferred from common prefixes (`foo/bar/.../baz` becomes a
  directory address `foo/` for the prefix `""`).
- *If your backend can't recursively list cheaply* (e.g. Nucleus's
  omni1 `list2` only returns one level per call): leave
  `supports_recursive_list = false`. If a caller invokes `list` with
  `opts.recursive: true` anyway, return `Unsupported` — do **not**
  fan out internally into N one-level calls. That decision belongs to
  the caller (who can budget the round-trips); silently amplifying a
  single SPI call into many backend calls is a cost-attribution
  anti-pattern.

> **Note on `supports_list`.** This is the basic gate: "can the
> backend enumerate keys under a prefix at all?" Some backends can't
> (the HTTP plugin, which only fetches single resources), and they set
> this to `false`. `supports_recursive_list` is the additional
> optimization bit *on top*: a backend that lists one level cheaply
> may or may not also list recursively cheaply. There's no real
> backend that supports recursive but not one-level, so the two bits
> form a hierarchy: `supports_list` gates the op; given `supports_list`,
> `supports_recursive_list` decides whether the host can pass
> `recursive: true` through.

### `list_versions`

**Contract.** Return a stream of `ObjectInfo` values, each with a
version-pinned `ObjectInfo.address`.

**Edge cases.**

- `ObjectInfo.address` is the full backend address for that version,
  including whatever query/form the backend uses as the version pin.
  The host projects only the route prefix.
- `list_versions` always returns the full version history. It does
  **not** filter to a single version when the input address carries a
  version-modifier query param — callers asking "does this version
  exist?" use `stat` (which honors the modifier) or `get_latest_version`
  (which returns the pinned `ObjectInfo` for that version or the
  current head). Don't try to
  compress the list down to one entry as an optimization; it would
  hide the rest of the version history from a caller that legitimately
  wants it.
- `version_list_order: Newest | Oldest | Unordered` — advertise
  accurately. Callers sort if they need a different order.

**Branch points (versioning model).**

The contract is universal: a backend that advertises
`supports_version_listing` must surface **every** mutating write in
`list_versions`, regardless of whether the caller supplied
`opts.message`. How you achieve that depends on the backend:

- *Backend versions automatically (S3 versioning, GCS object
  generations):* nothing to do at the plugin level beyond enabling
  versioning on the backend.
- *Backend has a per-call switch that gates whether a version is
  recorded:* always opt in on every write/copy/rename. The switch is
  the plugin's responsibility; never let `opts.message = None` short-
  circuit it into "skip the version" — that's a wire-format detail
  leaking into SPI semantics.
- *No versioning at all:* leave `supports_version_listing = false`.
  The host gates the call on the bit and won't reach the plugin (per
  *Capability advertisement is the gate*); a call arriving anyway
  would be a host bug.

### `get_latest_version`

**Contract.** Return a single `ObjectInfo` for the version the
input address resolves to. If `target.resolved_address` carries the
backend's version-modifier query param (e.g.
`?versionId=abc123` for S3, `?checkpoint=42` for Nucleus,
`?generation=12345` for GCS), return that pinned version's
`ObjectInfo`. Otherwise return the current head's `ObjectInfo` with a
version-pinned address — the same entry `list_versions` emits for the
head.

This is the read-shaped counterpart to `list_versions` for callers who
only need "what version does this address point at right now?" It
collapses what would otherwise be a `list_versions` paginate-and-pick-
first round trip into a single call, and lets a caller turn an
unversioned URL into a version-pinned URL without enumerating history.

**Capability gate.** `supports_version_listing` — the same bit that
gates `list_versions`. There is no separate
`supports_get_latest_version` bit; if a backend advertises
`supports_version_listing = true` it is also expected to implement
`get_latest_version`.

**Edge cases.**

- *Unversioned bucket / no checkpoints* — return `Unsupported`. A
  backend that advertises `supports_version_listing = true` only
  because the wider configuration permits it but where this particular
  instance has no version history (S3 bucket where versioning was
  never enabled, Nucleus mount with no checkpoints) cannot answer this
  call meaningfully. Per *Per-instance backend configuration*, prefer
  setting the capability bit accurately at `instantiate` time so the
  host doesn't reach the plugin in the first place; if you can't probe
  cheaply, returning `Unsupported` from this method is the right fallback.
- *Pinned address against a non-existent version* — return `NotFound`.
- Address-modifier rejection does **not** apply: this is a read-shaped
  op, the modifier is the whole point. Pass it through and resolve
  against it.

### `create_directory`, `delete_directory`

**Contract.** `create_directory` makes the directory observable to
listings *even when empty*; `delete_directory` removes the explicit
visibility.

On real-directory backends (filesystem, ADLS HNS) these map to
`mkdir`/`rmdir` and the empty/non-empty distinction is enforced by the
backend.

On flat-marker backends (S3 with `dir/` markers, etc.), a directory
can already appear in listings whenever it has children — there's no
explicit empty-directory record to begin with. `create_directory`
writes a marker so the empty directory is still listable; conversely,
`delete_directory` only removes the marker. If children remain, the
directory stays implicitly listable. "Delete" here means "remove the
marker, leaving the prefix to disappear from listings only when its
last child does."

**Edge cases.**

- `create_directory` is **idempotent** — succeeds if the target already
  exists as a directory.
- `delete_directory` is **empty-only**. `DeleteDirectoryOptions` is an
  empty struct — no `recursive` field, no `if_match` field. Plugins
  reject non-empty directories with `DirectoryNotEmpty`. Recursive
  subtree delete is a host / library / caller concern (walk +
  bulk-delete); the SPI does not amplify a single call into N backend
  calls. If a caller wants subtree delete, they list the contents,
  drive `delete` for `File` entries, and drive `delete_directory` for
  directory representations deepest-first, where the cost attribution
  and partial-failure handling are explicit.

**Branch points.**

- *If your backend has real directories (filesystem):* recursively
  create parents on `create_directory`; require empty for
  `delete_directory` (`rmdir(2)` already enforces this).
- *If your backend is flat-marker (S3 with `dir/` markers):* write or
  delete only the marker. Parent inference happens at list time.

### `update_metadata`

**Contract.** Apply additive `user_metadata_set` and removals
`user_metadata_remove`. Return updated `BackendItemInfo`.

**Edge cases.**

- `opts.message` — per-operation annotation, same shape and semantics
  as `WriteOptions::message` / `CopyOptions::message` /
  `RenameOptions::message`. The annotation rides on whichever new
  version this metadata patch creates. Backends that record a version
  on every metadata mutation (S3 versioning, GCS) persist it on that
  version; backends that have no annotation slot at all should follow
  the same rule as `write` (stash as user metadata or discard with a
  code comment — see *What about `opts.message`?* below).

**Branch points.**

- *If your backend stores user metadata natively:* implement; advertise
  `supports_native_metadata_patch = true`.
- *If your backend has no concept of user metadata at all (Nucleus):*
  leave both bits false; `update_metadata` won't be called. For
  `write` / `write_stream` / `write_redirect`, reject non-empty
  `opts.user_metadata` with `Unsupported` rather than silently
  dropping it — see *Scope of `Unsupported`* above. Otherwise
  `--metadata foo=bar` callers would lose data without notice.
- *If your backend mutates metadata by rewriting the object (S3 metadata
  patch via `CopyObject`-onto-self):* set
  `supports_metadata_rewrite_emulation = true` and implement the
  read-merge-write loop **inside the plugin**: read the existing
  metadata, apply `user_metadata_set` / `user_metadata_remove` in
  memory, write the result. The host doesn't drive the loop — its only
  role is gating on `opts.allow_rewrite_emulation`: when that flag is
  `false`, the host returns `Unsupported` to the caller without
  invoking the plugin. This composition is broker-clean: the broker
  forwards a single `update_metadata` SPI call to its plugin, and the
  plugin does the read+write internally without the broker mediating.

### `check_access`

**Contract.** Return which of the requested operations the principal can
perform.

**Edge cases.**

- `check_access` against a missing target returns `NotFound`, not an
  empty `AccessDecision`. This matches the convention many backends use
  (returning `NotFound` for unauthorized-and-untold-which) and gives
  callers a uniform "did the target exist?" answer without an extra
  stat round-trip.

**Branch points.**

- *If your backend has a native ACL-query endpoint:* implement and
  advertise `supports_access_check = true`. The op exists precisely
  because access checks aren't always cheap; if they were, callers
  would just `stat`.
- *Otherwise* (no native endpoint at all): leave
  `supports_access_check = false`. The host doesn't synthesize an
  answer.

### `watch_directory`

**Contract.** Stream `BackendChangeEvent`s describing object/directory
mutations under the prefix. Emit `Lapsed` on any gap or stream restart.

**Edge cases.**

- `Lapsed` is the **loud-gap signal**: when you detect dropped events,
  emit `Lapsed` (with no address) so callers know to re-list. **No
  silent gaps, ever.**
- `opts.recursive: false` — direct children only. `true` — whole
  subtree.
- `opts.since: Option<WatchDirectoryCursor>` — resume from cursor when
  `watch_directory_resumable` is advertised; otherwise emit `Lapsed`
  immediately.
- `BackendChangeEvent::Object` carries a full resolved backend address
  under the watched prefix; the host projects it into the
  caller-facing namespace.

**Branch points.**

- *If your backend has push notifications (S3 events, Nucleus
  `subscribe`):* implement and advertise `supports_watch_directory =
  true`. If your backend supports resumable cursors, also set
  `watch_directory_resumable`.
- *Otherwise:* leave `supports_watch_directory = false`. The SPI does
  not include a polling mode — callers that want polling can drive
  `list` themselves on whatever cadence they choose, which avoids
  having every plugin re-implement the same diff-and-emit loop and
  keeps cost attribution explicit.

### `address_roots`, `watch_address_roots`

**Branch points.**

- *If roots are static (configured in TOML):* leave
  `address_roots_are_dynamic = false`; only `address_roots()` is called,
  once at init.
- *If roots come from server discovery (Nucleus per-principal storage
  mounts; cloud storage mount discovery):* set the bit; implement
  `watch_address_roots` to emit `Snapshot` then `Added` / `Removed` as
  roots change.

---

## Versioning model decision tree

The contract for a backend with `supports_version_listing = true` is:
**every mutating write produces a version, regardless of whether the
caller supplied `opts.message`.** Walk this tree to decide what your
plugin has to do to honor it. (If versioning is *configurable* on
your backend and disabled on this particular instance, see
*Per-instance backend configuration* in the cross-cutting rules —
the bit reflects the instance, not the plugin's general capability.)

1. **Does your backend record a new version on every write
   automatically (S3 versioning, GCS object generations)?**
   → Transparent. Enable versioning on the backend; `list_versions`
   returns what the backend stored.

2. **Does your backend have a per-call switch that gates whether a
   version is recorded?**
   → Always opt in on every mutating write. The switch is the
   plugin's responsibility; the contract is "every write produces a
   version", and the caller's `opts.message` doesn't influence
   *whether* the version is created — only what annotation it carries.

3. **Does your backend have no versioning concept at all?**
   → Leave `supports_version_listing = false`. Don't implement
   `list_versions`.

### What about `opts.message`?

`opts.message` is the version's **commit annotation**, supplied by the
caller. It is *not* a versioning trigger: `message = None` means
"create a version with no annotation", not "skip the version". Where
the backend has a slot for the annotation (a commit-message field on
the version, an "x-ov-message" user-metadata key, etc.), persist it
on the version that gets created. Backends with no annotation slot at
all should either stash it as user metadata or discard it explicitly
with a code comment — see the "Dropping `opts.message` silently"
anti-pattern below.

---

## Anti-patterns

These are real foot-guns lifted from this codebase's history.

- **Buffering write streams to `Vec<u8>` at the plugin boundary.** The
  most-common Memory-DoS vector. Stream chunk-by-chunk; if you can't,
  return `Unsupported`.
- **Silent strip of address modifiers.** `?versionId=N` /
  `?checkpoint=N` on a write op must be rejected. The omni1 wire format
  for `delete2` / `copy2` / `rename2` doesn't carry a version field;
  passing the bare path silently mutates the head.
- **Returning `NotFound` from `delete` for a missing target.** The SPI
  contract for `delete` is "after `Ok(())`, `stat` returns `NotFound`";
  if the target was already gone, that post-condition already holds and
  the right answer is `Ok(())`. Returning `NotFound` would force every
  caller to write the same is-it-already-gone special-case.
- **Acquiring locks across `.send()` / `.await`.** Publishes state to
  observers before durability is confirmed. Land durability first.
- **Returning `Unsupported` to skip implementing a method you've
  advertised.** If you don't intend to implement an op at all, that's
  what the capability bit is for — leave it false and the host won't
  call you. `Unsupported` from a method *is* legitimate, but only for
  *specific call shapes* a true-bit backend can't honor (see *Scope of
  `Unsupported`*); blanket-returning it from every call is a sign the
  capability bit is wrong.
- **Dropping `opts.message` silently when your backend has no
  per-operation annotation concept.** Either store it (probably as
  `user_metadata`-ish) or discard it explicitly with a code comment so
  the next reader knows.
- **Treating `INVALID_URI` / `INVALID_PATH` from a server as
  `InvalidArgument`.** Many backends conflate "malformed path" with
  "path doesn't exist" in their error codes. Map to `NotFound` for
  read/stat/delete contexts; the host's retry policy and the user-
  facing UX both depend on it.
- **Constructing redirect requests with stale credentials.** `expires_at`
  on `RedirectScope` and `ReadRedirect` is a hard contract; the host
  rejects expired redirects before issuing the HTTP call.
- **Silently dropping an unhonored precondition.** If your backend
  has no etag-conditional wire for an operation, return
  `Unsupported` when `if_match` / `if_source` is `Some(_)` or
  `if_dest` is non-`Overwrite`. Don't let the caller's intent
  disappear on the wire.
- **Accepting an inverted `ReadOptions::range` and round-tripping it.**
  `end_inclusive < start` is a deterministic caller bug; the right
  place to refuse is the SPI boundary, not the downstream `Internal`
  surfaced by whichever backend the request reaches.

---

## Test harness

Three harnesses verify your plugin against this contract:

1. **Host-loaded dlopen test** — `ovstorage-core/crates/ovstorage/tests/dlopen_plugin.rs`
   exercises the host loader against `ovstorage-core/examples/plugin-rust/`
   to validate the cdylib + vtable + descriptor wiring. Loading a
   different plugin under the same harness isn't currently a supported
   workflow — write a per-plugin test in the plugin's own crate that
   exercises its SPI methods through the in-process `Backend` API.
2. **In-tree controllable test plugin** — `ovstorage-core/crates/ovstorage-plugin-test`
   (see its README) is used by the host's tests; doesn't run *against*
   your plugin but demonstrates the expected behavior.
3. **Streaming-invariant test** in your own crate's `tests/` —
   mandatory if you expose a `Body::Stream` seam. Helper:
   `ovstorage_plugin_test::streaming::assert_streaming_invariants`.

When a host conformance test is skipped, it cites the missing capability
bit. To enable a test, advertise the capability and implement the
method per this contract.

---

## Cancellation contract

The SPI surface of every `Backend` method takes a
`cancel: Option<CancellationToken>`, and *within* the plugin process you
should honor it as the cross-cutting *Cancellation* rule above
prescribes. The cross-workspace reality, however, is more limited and
plugin authors must plan for it.

**The host does not propagate cancellation across the cdylib FFI
today.** The C ABI vtable signatures carry a
`cancel: *const CancelTokenFFI` slot, but the loader passes
`std::ptr::null()` on every call that the host itself would otherwise
have a cancel token for. When the host-side `CancellationToken` fires,
the in-process Rust SPI methods receive `None` — the FFI boundary
swallows the signal. This is tracked in the workspace's FOLLOWUPS as a
trait-and-vtable change that would need to land atomically across the
core, remote, and broker workspaces.

The consequence for plugin authors:

- **Plugins SHOULD bound their own work with an internal deadline.** A
  remote-backed plugin that hangs on a slow upstream pins the host's
  outer RPC timeout (whatever the caller configured) rather than the
  host's own cancel signal. Wrap any blocking call (network I/O, file
  I/O, IPC, lock acquisition, DNS, …) in `tokio::time::timeout` with a
  deadline shorter than the host's RPC timeout, and return
  `Err(Error::new(Transient, "…"))` on timeout; the host's
  `with_route_retry` will retry `Transient` errors per its retry config.
- **Brokered routes inherit this property.** The `broker-client` plugin
  forwards SPI calls to the upstream broker daemon, which dispatches
  into the same in-process backend plugins; cancellation today relies
  on dropping futures and closing streams. A `StorageBackend::read`
  call against a wedged upstream backend pins the caller's outer
  timeout rather than the host's `CancellationToken`. See
  `plugin-broker.md` section "Cancellation contract" for the wire-level
  details.
- **`drop_plugin` shutdown is bounded.** A clean shutdown drains
  in-flight calls up to a 5-second timeout before freeing the boxed
  plugin state. A plugin that doesn't honor an internal deadline can
  delay shutdown by the full host RPC timeout window.

The risk is bounded by the project's "all plugins first-party" memory:
there are no third-party storage plugins shipping today, so the
mitigation is operator-level (don't deploy a hanging plugin) and
plugin-author discipline (bound your blocking calls). Closing the gap
is a trait-and-vtable change tracked across three workspaces and
deferred from this conformance doc.
