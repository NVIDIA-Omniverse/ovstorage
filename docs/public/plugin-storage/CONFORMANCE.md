# Plugin Storage Conformance

Behavioral contract for every operational `OvStorage_LayerVTable` slot a
storage backend implements. Read once before implementing a new backend;
refer back when an edge case bites. Slot names coincide with the Rust
`Layer` trait method names, so the contracts below apply unchanged
whether you read them against the trait
(`ovstorage-core/ovstorage-layer/src/traits.rs`) or the C vtable.

This document defines **what each slot must do**. It does **not** define
the type signatures (those live in the "Type vocabulary" section of
[`plugin-development/README.md`](../plugin-development/README.md), and in
the shipped `ovstorage_plugin.h` ABI header where an exact signature is
required) or the capability bits (those live in the same guide's
"Capability vocabulary" section). You will need both open while
reading this. The per-backend reference pages in this directory
(`plugin-file.md`, `plugin-s3.md`, `plugin-gcs.md`, `plugin-azure.md`,
`plugin-huggingface.md`, `plugin-opendal.md`,
`plugin-services-client.md`, `plugin-nucleus.md`,
`plugin-broker.md`, `plugin-http.md`, `plugin-test.md`) each illustrate
one valid branch of the contracts below.

Sections that branch on backend characteristics use the
**"If your backend… then…"** pattern. Pick the branch that matches your
backend; one branch is always correct.

## Which version this describes

This document describes the conformance contract in the current source tree,
which is at Layer ABI 19 (`OVSTORAGE_PLUGIN_ABI_V2_VERSION`, the canonical
constant this restates). The ovstorage 0.2.1 artifacts use Layer ABI 15. The
loader requires an exact ABI match, so a plugin built against a different ABI
version is refused rather than run against these rules.

One convention for reading the prose that follows: **"ABI-v2" is the plugin
ABI family, not a release.** Its version number is 19 in the current source
tree and 15 in ovstorage 0.2.1, with a family floor of 5. Nothing here spelled
`v2` refers to the ovstorage package version.

---

## How to read this document

Each slot section has the same shape:

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

These apply to every slot. They are not repeated per-section.

### Slot gating: baseline, optional, and host-owned

The operational vtable slots split into three groups:

- **Baseline required slots** have no default implementation; every
  plugin must implement them. The host calls them on every backend
  regardless of any capability bit:
  - `stat`
  - `read`

  These are the universal floor — every backend that exists at all
  can answer "does this address resolve?" (`stat`) and "what bytes
  are here?" (`read`). A backend that cannot serve one of these has
  no business being a backend.

- **Optional slots** default to `Unsupported` unless noted below, and
  plugins opt in by overriding that default. Each has a corresponding
  capability bit. The `list_stream` default is the compatibility adapter
  noted below rather than `Unsupported`:
  - `delete` — `supports_delete`
  - `list` — `supports_list`
  - `list_stream` — `supports_list_stream` (a native-streaming hint;
    the slot remains callable through its buffered compatibility adapter
    when this bit is false)
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

  `list_address_roots` is also optional but not directly bit-gated;
  it returns a root snapshot plus an optional update stream. A plugin
  whose root set is static returns the snapshot with no stream and
  the host never polls; see the `list_address_roots` section below.

- **Host-owned slots** have a default `Unsupported` implementation,
  but a backend MUST leave that default in place. The host wrapper
  that owns the behavior supplies it when the Stack is composed:
  - `materialize` — `ByteCacheWrapper` and
    `RedirectFollowerWrapper` produce local files; `FileBackend`
    returns the path it already owns.

  A backend MUST NOT implement `materialize`. Local availability is a
  property of the composed Stack, not a backend capability, so there
  is no capability bit for it.

The three write bits are independent. A plugin that only supports
streaming uploads sets `supports_write_stream = true` and leaves
`supports_write` / `supports_write_redirect` false; the host's
dispatcher then picks `write_stream` regardless of `size_hint` or
`redirect_size_threshold`. `redirect_size_threshold` only ranks
`write` vs `write_redirect` when both bits are true.

If you don't implement an optional op, leave the default impl in
place and the bit false; the host returns `Unsupported` to callers
without invoking the slot. `list_stream` is the exception: its Layer
default adapts `list`, so a layer with `supports_list = true` remains
correct but buffered when `supports_list_stream = false`. If an optional
bit is true the host expects the slot to behave per this contract — no
half-implementations.

A plugin that exposes a single read-only resource per address (e.g.,
the HTTP plugin) advertises `Capabilities::empty()` — every bit
false. The host calls only `stat` and `read`; every other op is
short-circuited at the dispatcher to `Unsupported` before it reaches
the plugin.

Capabilities are advertised per root (`RootInfo.capabilities`) and are
immutable for the owning connection's lifetime. Decide once when the
connection is configured (`create_backend` config / `add_connection`).

A Layer must also **self-gate**: an optional slot whose capability bit
is false returns a typed `Unsupported` without performing any backend
work or side effects, even if a host's gating ever drifts. A Layer
owns its own connection routing, so it is the last line of defense for
its own capability contract; the conformance registry's
`capability-gate-<op>-unsupported` scenarios pin exactly this (typed
`Unsupported`, nothing recorded, no side effects).

An address a Layer reaches through its anonymous scheme fallback is
served under exactly that contract, applied by the routing tier rather
than by a connection's bits. The scheme root the Layer publishes for
the fallback projects read-side bits only — list, stat, versions,
access check — and the Layer refuses every mutating slot and
`watch_directory` on such an address locally: typed `Unsupported`,
nothing sent, before any request is built. That is the self-gate
above with one more root to honour it, so a backend needs no
fallback-specific behaviour and the registry needs no new scenario;
the `capability-gate-<op>-unsupported` scenarios already pin the
refusal shape the fallback produces.

**Per-connection backend configuration.** Capabilities reflect the
*specific connection* you're bound to, not the plugin's general
capability list. Many backends expose features that are toggleable
per-bucket / per-mount / per-tenant — versioning being the canonical
example (S3 buckets without versioning enabled, Nucleus mounts
configured without checkpoints). Advertising `supports_version_listing
= true` on a non-versioned bucket would silently violate the contract
("every write produces a version") because no version would actually
appear. Probe when the connection is established and reflect what's
really there.
If your backend doesn't let you query the relevant configuration
cheaply, it's the operator's responsibility to match the
backend's TOML config to backend reality (an explicit
`enable_versioning = false` knob is fine, and arguably better than a
silent assumption either way).

**Meta-plugins (per-address capability discovery).** A plugin that proxies
to multiple heterogeneous downstream backends — `ovstorage-plugin-broker-client`
is the canonical example — cannot know at connection time which
capabilities a given address will support, because that depends on which
backend the broker routes to. Such a plugin advertises the **union** of
capabilities its downstream backends might offer, then returns
`Unsupported` from individual slot calls when the resolved downstream
can't perform the op. This is the explicit exception to "no
half-implementations": the contract becomes "the slot either honors
this section or returns `Unsupported` — never partial work, never
`Internal` for a known capability mismatch." The host treats
`Unsupported` from a slot call the same as a false capability bit at
the call site, so callers see consistent behavior either way.

**`wants_list_backed_stat` semantics.** When `wants_list_backed_stat =
true` (and `supports_list = true`), the host may satisfy an
unversioned, non-directory `stat` with both cost flags clear
(`full_metadata = false`, `versioned_address = false`) from a cached
or freshly fetched one-level parent `list` entry, bypassing the
backend's `stat` slot. A `stat` with `versioned_address` set is answered
from a cached parent listing only when that listing was itself asked
for the pin; a `full_metadata` stat always reaches your `stat`, because
no listing carries the per-object metadata that flag pays for, so a
listing's rows never vouch for it. Neither buys a fresh listing of its
own: the flag pays for this object, not for its directory.
Directory-form addresses (trailing slash) and version-pinned URLs
always dispatch to the backend's `stat`. Set the bit when your
backend's `list` entries already carry the same metadata fields as
`stat` (etag, version, size, mtime, and, where the listing carries a
version id, the same `versioned_address`), so the parent-list shortcut
is metadata-correct without an extra round trip. Leave it false if
`list` returns thinner entries than `stat` does — the host won't
synthesize the missing fields.

### Address inputs

Every operational slot receives a request carrying a resolved
`address: Url`. By the time the call reaches a backend layer, the
Stack above it has already:

- parsed and validated the URL syntax (canonical RFC 3986 form),
- applied any prefix substitution from a matching alias or rewrite
  rule (the alias/rewrite wrappers upstream of your layer — e.g.
  `mybucket:/foo` → `https://bucket.s3.amazonaws.com/foo` if the user
  aliased `mybucket:` to that S3 URL).

**The address is the full URL the plugin operates on — the route
prefix is never stripped to a backend-relative fragment.** A plugin
instance bound to `https://bucket.s3.amazonaws.com/` receives calls
with `address = https://bucket.s3.amazonaws.com/some/key`, *not*
`/some/key`. The plugin owns the translation from URL to its wire
protocol's preferred shape (bucket name + key for S3, Nucleus path
string for omni1, etc.). Do that translation once at the boundary and
stash the result.

Returned `ObjectInfo.address` values from `list`, `list_versions`,
`get_latest_version`, and `watch_directory` use the same resolved
address namespace and must stay inside the requested prefix or target
scope. The host projects them back into the caller-facing namespace.
`ObjectInfo.versioned_address`, when present, is projected the same
way: it is a full resolved backend address whose route prefix the host
rewrites and whose query — the pin — it leaves intact.
If a returned address escapes that scope, treat it as a plugin bug:
surface `Internal`, not a best-effort filtered child. Display labels
are derived from the parent/child addresses; they are not returned as
separate fields.

**Don't re-parse, re-canonicalize, or re-validate** the URL syntax — the
host has already done it.

The host *does* normalize the path before the plugin sees it: escapes
are decoded, runs of `/` collapsed, dot segments resolved, the fragment
dropped, and the result re-encoded once. The host lowercases the scheme
and host and strips a default port. What it does **not** touch is the
trailing slash, in either direction — see the next section — and it does
not reorder or rewrite the query.

A key that cannot be named by a URI path — one containing a dot segment,
a doubled separator, or a literal `/` inside a segment — is
**unaddressable**. A plugin that lists such a key must omit it with a
`warn!`, because any address built for it re-derives to a different
key.

### Trailing slash conventions

**`x` and `x/` name the same node**, and every host-side site that
compares two addresses — the router, the authorization matcher, the
caches, alias projection — treats them as one. Whether the node is a
file or a directory comes from `ObjectKind`, never from the spelling.

The host core does not rewrite the slash to match the slot, so a plugin
on a directory-facing slot — `list`, `watch_directory`,
`create_directory`, `delete_directory` — **must derive its own directory
key** rather than assuming a trailing slash is present. On a flat store
the two spellings may be two distinct objects, which is why the host
preserves what the caller wrote instead of choosing for you.

No layer appends it for you, and in ovstorage 0.2.1 there is no layer kind
that could: deriving the directory key is a rule the plugin must satisfy
itself. A config that declares a layer kind that does not exist — say
`[ovstorage.layers.directory_normalize]` — does not start, since an unknown
layer kind is refused rather than ignored.

For every slot, **the trailing slash arrives as the caller wrote it**.
File-facing slots (`read`, `write`, `delete`, `copy`, `rename`)
conventionally receive paths without a trailing slash, but the plugin
should not crash if a caller supplies one — translate to your backend's
preferred shape and proceed (or reject with `InvalidArgument` if the
shape is genuinely ambiguous on your backend).

`stat` is the explicit exception — it may receive either form. The
trailing slash is a *hint* the caller wants directory metadata; absent
it, prefer the file shape and fall back to directory. The Nucleus plugin's
dual-probe (`ovstorage-nucleus/ovstorage-plugin-nucleus/src/backend/spi.rs`)
fires both queries in parallel; an alternative is sequential probing or
caching the last-known shape per address. Pick what your backend
supports cheapest. When both probes fail, prefer the file-shape error
in the surfaced result (the file shape is the more common case and
gives a clearer error class for callers); cache the last-known shape
if your backend supports it.

### User-metadata keys

**Every backend that stores `user_metadata` MUST accept a key matching
`[a-z_][a-z0-9_]*`** — lowercase ASCII letters, digits and underscores,
with a letter or underscore first. That grammar is the intersection of
what the shipped cloud backends take: Azure requires a C# identifier, S3
takes any HTTP header token and lowercases it, and GCS preserves case.
A plugin whose backend stores user metadata but refuses a name
inside that subset is non-conformant. The rule is about names, not
about whether metadata is stored at all: a backend with no
user-metadata facet keeps rejecting a non-empty map with `Unsupported`,
as the `write` contract says.

A backend may accept more — uppercase, hyphens, dots — and a plugin
passes such names through where its backend keeps them. Callers must
not assume a wider name is portable across routes: the same `write`
can succeed on one branch and be refused on another, or come back
respelled. Per-key, per-value and per-object size and count limits
stay backend-specific and belong on the backend page, not here.

The `ovstorage_` prefix is reserved for host-attested keys —
`ovstorage_modified_by`, stamped by the attribution overlay — and sits
inside the portable subset so no backend refuses the stamp on name
grounds. `is_reserved_metadata_key` matches
the prefix case-insensitively because backends disagree on key case:
S3 lowercases keys on the way in, Azure compares names
case-insensitively, and GCS preserves case and stores `Author` and
`author` as two distinct keys. An attributing host therefore strips a
caller's `OVSTORAGE_Planted` exactly as it strips `ovstorage_planted`,
so no case variant can pose as the host's stamp on a backend that
would fold it into the reserved spelling. A plugin stores what it is
handed; the stripping and the harvest are the host's. A plugin reads
the namespace itself in two places only: the `continue_write`
re-assertion under *`write`, `write_stream`, `write_redirect`,
`continue_write`*, and — where a backend applies metadata in a stage
after the object commits — to classify a failed reserved-key stash as
the host's rather than the caller's, which the `omniverse-storage-service`
page describes.

### Cancellation

Every async operational slot takes `cancel: Option<CancellationToken>`.
Honor it before starting any I/O round-trip and at chunk boundaries
within a streaming operation. Cancellation produces
`ErrorCode::Cancelled`.

A backend that doesn't honor cancellation is a hang vector for the
broker. Plumb the token; don't ignore it.

See **Cancellation contract** at the end of this document for the
FFI-level reality (the ABI-v2 host marshals the token across the
cdylib boundary; cooperative cancellation still only helps when the
plugin honors it), and why plugin authors should bound their own work
regardless.

### Streaming invariants

Read streams (`ReadResult::Stream`) and write streams (`Body::Stream`
into `write_stream`) propagate chunk-by-chunk. **Do not buffer the full
body to a `Vec<u8>` at the plugin boundary.** That's a memory-DoS vector
on the public REST gateway and is forbidden by the project's streaming
invariant. The crate `ovstorage-core/ovstorage-plugin-test`
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

- **Per-target lock around non-atomic publish steps** (built-in file
  backend). The built-in `file` backend serializes writers per-path so
  the `try_exists` → `if_match` check → `rename(2)` sequence is atomic.
  The lock is held *across* the `rename` await — releasing it earlier
  would let the next writer's `try_exists` race against the in-flight
  rename. (This is a `tokio::sync::Mutex`; holding a `std::sync::Mutex`
  across `.await` is a separate bug — don't do that.)

- **Multi-stage durability** (bytes, then a separate metadata commit).
  When durability lands across multiple commit stages (e.g. a backend
  commits bytes, then records the caller's user metadata through a
  separate service in a second step), the durability contract still
  applies to the final-stage commit. If the metadata stage fails after
  the bytes have already landed, the right answer is to surface the
  error to the caller — they will see the bytes as committed (`stat`
  returns the new etag/version metadata) but their write call returned
  non-`Ok`, so they know to re-issue the metadata patch. Do not retry the bytes commit; that
  would change the etag/version again and break any concurrent `if_match`
  retry the caller is doing.

  **Report it as `ErrorCode::PartialCompletion`, carrying
  `ErrorContext::Partial` where your host surface can.** The code exists
  so a caller can tell this
  apart from an operation that did not happen, and the context says which
  stage committed (`completed`), which one did not (`failed`), whether the
  failed stage is known not to have applied (`failed_outcome`), and what
  undoing the committed stage would do (`rollback`). For bytes-then-metadata
  that is `ObjectData` / `UserMetadata` / `DestroysRequestedWork`: rolling
  the write back would destroy the object the caller asked for, so the only
  correct remedy is to re-apply the metadata.

  `rollback` is not a standalone verdict — it is read together with
  `failed_outcome`. Rolling back is unconditionally safe only when `rollback`
  is `RestoresPriorState` AND `failed_outcome` is `NotApplied`; with
  `Unknown` the failed stage may already have taken effect, so undoing the
  committed stage can remove the last surviving copy. Report `NotApplied`
  only when the failing step cannot have left a partial durable mark — a
  single atomic publish or unlink. A step that rewrites a payload in place
  reports `Unknown`, because a truncating write that fails part-way leaves
  neither the old value nor the new.

  **The code must not be reported through a retryable one.** A retryable
  code (`Transient`, `ResourceExhausted`) has a retry Layer replay the whole
  write, which is exactly the bytes-commit retry forbidden above.
  `PartialCompletion` is in `ErrorBucket::Internal` and is never retryable.
  Equally, do not report a code a caller reads as "nothing happened" — that
  invites a rollback over data that is already durable.

  The shape that satisfies this: stage the second commit's payload BEFORE
  taking whatever lock guards the first, publish it after the first commits,
  and let the publish failure propagate rather than unwinding the bytes. The
  in-tree example is the Omniverse storage-service client
  (`plugin-services-client.md`): its write RPC carries no metadata, so the
  object commits first and the caller's `user_metadata` lands through a
  separate metadata-service stash afterwards; a stash failure surfaces as
  `PartialCompletion` with `ObjectData` / `UserMetadata` /
  `DestroysRequestedWork` rather than unwinding the bytes.

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
The fix is to await before dropping. See the built-in `file` backend's
`write` (`ovstorage-core/ovstorage/src/file/`; tempfile + `sync_all` +
lock + `rename(2)`) for the canonical sequencing.

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
| Plugin bug / unhandled state             | `Internal`            | An unhandled state or a genuine bug; surfaces to operators as "plugin bug". |
| Plugin's own fixed local bound hit        | `Internal`            | A deliberate cap on what one call may hold or do, such as a buffered `list` budget. Not `ResourceExhausted`: see below. |

**A plugin's own fixed bound is `Internal`, not `ResourceExhausted`.** The
names point the other way, so this is worth stating: `ResourceExhausted` is one
of the two retryable buckets, and retryability here is exactly bucket
membership. A bound the plugin sets itself — "this buffered `list` call may hold at most N
entries" — is reached identically on every attempt, so a retryable code makes a
host with `RetryWrapper` composed in repeat the whole operation to fail the same
way, N times, paying the full cost each time. Do not carry buffered `list` item
or page budgets onto `list_stream`; that surface is bounded by resident state,
not by refusing a large total traversal. Reserve `ResourceExhausted` for
exhaustion outside this call that can clear on its own: a quota window, a rate
limit, a concurrency slot, a store's own `429`. Use `Internal` for a limit that
is a property of this build, and say in the message which limit was hit and what
the caller can narrow.

A limit the caller supplied — `ReadOptions::max_bytes`, for instance — is a
third case and keeps `ResourceExhausted`: the argument is the caller's to
change, so the code names something they can act on directly.

**Not every in-tree bound follows this rule**, and the page says so rather
than implying uniformity: `copy_rename_fallback`'s buffered-transfer cap is a fixed
local bound by this rule and still answers `ResourceExhausted`, which its
`Layer::copy` contract documents. It carries the same amplification — a retry
re-buffers the whole object — and moving it is a change to that contract rather
than to a plugin, so it is not made here.

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
(`ovstorage-nucleus/ovstorage-plugin-nucleus/src/ops.rs`) peels
`InvalidPath` out of the `InvalidArgument` bucket for exactly this
reason.

**Post-redirect failure mapping.** When a plugin's `continue_write` (or
any path that interprets `RedirectResultBatch`) sees a non-2xx HTTP
status, it MUST decode it into the typed error code, not blanket-
`Transient`. Map 404 → `NotFound`, 412 → `PreconditionFailed` (or
`ObjectModified` if the response indicates the body was partially
observed before the failure), 403 → `PermissionDenied`, 401 →
`AuthRequired` / `AuthExpired`, 409 → `Conflict`, 410 → `NotFound`,
416 → `InvalidArgument`. `Transient` is for connection errors and for
5xx. The host's retry policy depends on this mapping; lumping 412 into
`Transient` triggers useless backoff retries on a deterministic
precondition failure.

Two finer distinctions are **permitted and recommended**, not required,
because they depend on how much the provider's own statuses mean:
408 / 504 → `DeadlineExceeded`, and 429 / 503 → `ResourceExhausted`
rather than the `Transient` the 5xx default would give. Some in-tree
backends draw them and some do not, and both are conformant — a backend
saying it is overloaded is telling you more than "try again", but only
where that is what its 503 actually means.

Which non-2xx statuses reach this mapping depends on **who followed the
redirect**, not on the deployment. There are two routes, and only one of them
checks anything:

- **A redirect follower inside a host stack.** This is the library deployment,
  and it is *also* the broker's own `write` / `write_stream` route and the REST
  gateway, both of which compose the same follower. The follower calls your
  `continue_write` directly with whatever it got. **Nothing is filtered on this
  route.**
- **A remote client driving the redirect protocol itself**, over the broker's
  `continue_write` RPC. Only here does the broker refuse a batch carrying any
  status outside 200..300, as `Transient`, before dispatch.

So "under the broker" does not mean "screened". A caller that issues a plain
`write` to the broker reaches your `continue_write` through the broker's
in-process follower, unscreened, exactly as the library deployment does.

On any follower route, retry is the only thing that can absorb a status before
you see it, and it applies only when **both** conditions hold: the method is
idempotent, and the write body is replayable (buffered, or a seekable file). A
retryable status is exhausted into `Transient` only in that case. `POST` and
`PATCH` redirects are issued once because of the method; a streamed body is
issued once whatever the method, `PUT` included. So a 429 or 5xx arrives here as
a result for you to map whenever either condition fails.

Those two conditions decide only which *retryable* statuses you also have to
handle. A status that is not retryable at all — 404, 412, 403, 401, 409, the
cases this mapping names — is never retried on any write-redirect path, so it
reaches your `continue_write` whatever the method and whatever the body. The
practical rule is to implement the mapping unconditionally and assume nothing
screened it. (Read redirects never reach `continue_write` at all, and are
governed separately: a 403 there can be read as a stale presigned URL and
retried once against a freshly minted redirect.)

Implement the mapping unconditionally, and do not rely on a brokered caller
observing your typed code for a non-2xx redirect.

**At the Layer boundary, treat everything `continue_write` receives except the
address as reported input.** The `RedirectResultBatch`, the
`WriteRedirectBatch` echoed alongside it, and the opaque `continuation` blob
inside that batch are all returned by whoever performed the redirect. The
plugin observed none of them. That party is a follower inside a host stack on
one route and a remote client on another. The broker authenticates the
continuation on its client-driven route as described below, but that is a host
boundary guarantee rather than part of the Layer SPI.

Be precise about what is checked before it reaches you, because on the follower
route the answer is *nothing*:

- **Cardinality is yours to check.** Call
  `validate_redirect_results(&redirects, &results)` at the top of
  `continue_write`, or open-code the equivalent comparison. No follower route
  does it for you — the follower hands the batch straight through. The broker's
  `continue_write` RPC does check it before dispatch, but there the same caller
  supplied *both* sides of the comparison, so even then it constrains only that
  caller's self-consistency. Every first-party plugin performs this check; a
  plugin that skips it and indexes results positionally against redirects will
  mis-handle a mismatched batch.
  An in-process follower may deliberately hand `continue_write` the original
  non-empty redirect batch with an empty result batch after redirect execution
  fails and exhausts its retries. Treat that mismatch as a best-effort
  abandonment notification: never finalize or report success, and release any
  staged provider resources that can be identified safely before returning the
  cardinality error. Backends without staged resources simply reject it like
  any other mismatch. The follower ignores that cleanup result and returns the
  original redirect-execution error to its caller.
- **Status range** — the broker's `continue_write` RPC refuses a batch carrying
  any status outside 200..300. That is the only place it happens; on every
  follower route a non-2xx reaches your `continue_write`, as covered under
  *Post-redirect failure mapping* above.

The broker's client-driven route performs one additional check before either
of those checks or any Stack dispatch. Every `WriteRedirectBatch` the broker
hands to a remote client carries the plugin continuation inside an HMAC-SHA256
envelope. The MAC binds the exact continuation bytes to the parsed request
address. `continue_write` verifies the envelope against its request address and
strips it before calling the Stack, so the plugin sees its original bytes. A
malformed or edited envelope, a continuation issued by a broker with another
key, and a genuine continuation presented for another address all fail closed
as `InvalidArgument` before the plugin runs.

That seal has deliberately narrow scope. It authenticates the continuation
bytes and their address binding; it does not authenticate the redirect list,
the result count, statuses, headers, or bodies. It does not prevent replay of a
genuine continuation to its own address, and it does not bind a principal to
the write. Follower routes — including the broker's own in-Stack follower — and
non-broker hosts add no such seal. The Layer SPI neither supplies a seal nor
tells a plugin that a host verified one. On those routes, no signature binds
the continuation to the operation, and the host's byte-for-byte echo obligation
is an obligation rather than proof. Plugin code must therefore remain correct
for the unsealed routes.

**The address is the only authenticated input available on every route.**
Authorization is decided on the request address. A key, path, upload id, or
precondition read out of the continuation has no SPI-level authentication; the
broker seal is present only on the client-driven broker route. So the resource
your `continue_write` acts on must be **derived from** that address, and where
the shape of the provider's handle makes derivation impossible, the gap must be
stated rather than presented as satisfied by a comparison — see *Derive, don't
compare* below, and the paragraphs on resumable-session handles further down.
A plugin that finalizes whatever object the continuation names is letting an
unsealed caller choose the object, which is the caller choosing its own
authorization.

The invariant is that what your call commits must not be steerable by
caller-supplied data. The mechanism is yours, but be clear about what each one
establishes.

**Derive, don't compare.** Recomputing the object from the request address and
never reading the continuation's copy settles the object selection outright, and
it is the only mechanism that does so on every route. In practice the copy is
usually redundant already: if your `write_redirect` computed it from the
resolved target, `continue_write` can compute the same value from the same
address, and the copy is an echo to stop reading rather than an input to
validate. Whether you then keep emitting it — for a peer instance running a
build older than yours, whatever that is in your deployment — is a
compatibility question, not a security one, as long as nothing reads it back.

Comparing the continuation's object against the address and refusing a mismatch
is weaker, and how much weaker depends on the host boundary. On a follower
route the batch came from the host process and the comparison is a real
assertion about the unmodified batch. The broker's client-driven
`continue_write` RPC authenticates the recorded bytes and their address binding,
so a remote caller cannot rewrite that copy to match another address. A direct
SPI caller or another client-driven host with no equivalent seal can do exactly
that. Use comparison only where derivation is genuinely unavailable, and say in
the code that it is defence in depth outside a sealed boundary. If you do
compare, compare in the namespace your backend resolves in rather than
byte-for-byte — two spellings of one key must not read as two objects.

Making the continuation *unforgeable* does not settle it at all on its own. A
continuation your backend minted, or one you could detect an edit to, stops a
caller altering one — it does not stop a caller presenting a different one. An
untouched, perfectly valid continuation for another object is still a
continuation the caller can hand you. Unforgeability only helps once it is
paired with a binding to the address authorization was decided on, and that
binding is checked here; without the check it moves the forgery out of reach and
leaves the substitution exactly where it was. The broker seal pairs these
properties for its client-driven RPC. Nothing in the SPI makes the blob
tamper-evident for a plugin, so other hosts must add an equivalent boundary or
plugin-owned mechanism to obtain that property.

This page states the invariant and does not prescribe which mechanism you use.
Object selection is the part these settle; the upload id and the preconditions
are covered next.

Some values genuinely cannot come from the address — a server-issued upload id
or resumable-session handle, and the preconditions the original `write`
requested. The continuation is their only carrier, so "re-derive it" is not
available. Two things follow.

Validate what you *can*, and note that the two handle shapes are not alike.

An **upload id travels with a key**. Pin that key to the address and the request
you send commits to the address by construction — you are addressing the
authorized object and the id merely rides along. (Backends also reject an id
that does not belong to the key, but that is a backstop, not the reason it is
safe.)

A **resumable-session handle has no companion to pin**: the session itself names
the object. Be honest about what is available there, because it is less than it
looks — but the two checks usually reached for are not equally weak, and saying
so matters, because a check described as worthless is a check the next reader
deletes.

Comparing the **session URL against the redirect batch** compares two values
from the echoed batch. On an unsealed client-driven route it establishes only
that the caller was self-consistent. The broker seal authenticates a session
URL stored inside the continuation, but not the separate redirect list; the
comparison can then detect a changed list. That protection is still not an SPI
property.

Comparing a **recorded address field against the request address** is different.
The request address is the authenticated side, so this does refuse a genuine,
unmodified continuation minted for another object — substitution on its own does
not get through it. On a route with no tamper-evident boundary, *modification*
defeats it: the SPI does not protect the blob, so a caller that rewrites the
recorded field to the address it is authorized for passes the comparison. The
broker's client-driven RPC refuses that rewrite before dispatch. Keep the
plugin check for every other route, and describe it as what it is — defence in
depth outside the broker seal, not a vacuous comparison.

The only anchors that are *not* caller-supplied are the request address and
state your own backend holds. So resolve the session from one of those, or make
the
blob tamper-evident first, if you want the recorded binding to hold against a
caller that edits it.

**Where neither is available, say so — it is a known gap, not a loophole.** A
provider that issues a session handle naming the object, keeps no lookup from
address to session, and returns nothing to resolve against leaves an adopter
unable to *derive*. Such an adopter satisfies the rule only against an
unmodified continuation, by the address comparison above, and not against a
forged one on an unsealed route — say that precisely rather than claiming either
more or less. State in the code that the checks you keep are defence in depth at
the plugin boundary, pin both the case they catch and the direct-plugin case
they cannot with tests, and raise the gap rather than absorbing it. The brokered
client route closes that forgery case before the plugin runs. What is *not*
acceptable is an adopter that takes the object out of the continuation with no
anchor and no statement.

**Spell out what the unsealed-route residual actually costs**, because it is
wider than a wrong answer to the caller. Where the caller's own request was the
commit, a forged continuation leaves the bytes on the object the *session*
names while your `continue_write` reports the address the *request* names.
Three consequences follow, and the second is the one people miss:

- Anything the host derives from the reported address is wrong for that call.
- **Cache invalidation lands on the reported address, and the object that
  actually changed is not invalidated.** Host caches key invalidation on the
  request address and do not read the returned `WriteResult.info`. Whether that
  becomes a stale *read* depends on what else is composed — a validator-keyed
  byte cache revalidates through an inner stat, so it serves pre-write bytes
  only when that stat is itself answered from a metadata cache still inside its
  TTL. What is left wrong in every composition is the changed object's cached
  metadata entry.
- Metadata bound at session-initiation time — user metadata, any message, and
  broker-set attribution where the host stamps it into user metadata — is
  attached to the object the session names, not to the reported one. So
  attribution is *correct* about who wrote what, and lands on an object the
  report does not mention.

None of this reaches an object the caller could not already write: obtaining the
session required an authorized initiation on it. On a route without the broker
seal or an equivalent, the residual is tamper-evidence and reporting, not
privilege escalation — provided the provider's session handle is unguessable,
which is a property of the provider and not something this contract can
establish for you.

Re-validating the object that the finalize response reports is worth doing where
the response carries it — the in-tree GCS backend re-checks the captured
object's name against the parsed target — but be precise about what it buys,
because it varies by route and the weaker case is the one this passage is about.
Where the captured body came from the provider, it is **detection after the
commit, not prevention**: the object has already been written by the time you
can look. Where the *caller* supplies the captured body, the body remains
untrusted even on the sealed broker route because the seal does not cover
results. On an unsealed route, a caller who also forges the continuation can
forge this check's input in the same breath, so against that case it establishes
nothing. It is a backstop for the anchors above on follower routes, not a
substitute anywhere, and on a backend whose finalize returns no object name it
is not available at all.

On the broker's client-driven RPC, a precondition inside the verified
continuation is provably the one in the batch the broker issued for that
address. It is not proof of freshness or of who presents it: the same genuine
batch can be replayed to the same address, including by another authorized
principal. On follower routes and non-broker hosts, no seal establishes even
that much, so a precondition arriving in the blob is the one the caller is
willing to admit to, not provably the one the original write carried. Do not
build a guarantee another principal depends on out of an unsealed value.

Beyond selecting the resource, these values must never be evidence for anything
your plugin persists, shares, or grants: whether a connection is authenticated,
whether a credential is still valid, quota consumption, principal identity,
recorded metrics. A plugin that promotes a connection to authenticated because a
caller reported a 201 lets any client with write access change
operator-configured state without ever making a request.

What they *may* do is shape the result of this call — the `ObjectInfo` you
return, the ETags you assemble for a completion you have already bound to the
authorized address. Even there, note that "it only misleads the caller" is not
quite true: a host may cache what you return, so a lie can outlive the call and
reach another reader.

The test for a new use: *would this still be true if the caller were lying?* If
a wrong answer selects a resource, or reaches anyone but that caller, get the
fact from the address or from the plugin's own transport.

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
reject_pinned_for_mutation(address, "<plugin> <op>", &["versionId"])?;
```

(`address` is the slot request's resolved URL — in-tree plugins that
keep an internal `ResolvedTarget` pass `&target.resolved_address`.)

(Defined at `ovstorage-core/ovstorage-plugin/src/url_helpers.rs`.
The Nucleus plugin's `reject_checkpoint` predates the shared helper and
inspects the parsed `NucleusTarget.checkpoint` field directly; both
shapes are conformant in 0.2.1, and the shared helper is the one to
reach for in new code.)

Per-op guidance:

- `write` / `write_stream` / `write_redirect` — reject if the
  destination is pinned (can't overwrite a frozen version on any
  primary backend).
- `continue_write` — reject if the address is pinned, for the same
  reason and *also* an authorization one. The object is derived from
  the request address, and deriving it drops the selector, so a
  continuation presented against a pinned address would commit to the
  head while authorization was decided on the frozen-version URL. Apply
  the guard even where your `continue_write` performs no mutation: it
  still reports an address, and reporting a pinned one it did not act
  on is its own defect.
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
- `versioned_address` returned by `stat` / `list` is exactly such a
  pinned address. A caller that turns around and mutates through it
  hits the guards above; that refusal is the contract, not a defect.
  `stat` on an address the caller already pinned echoes the caller's
  pin as `versioned_address` regardless of `opts.versioned_address`.

Meta-plugins (`ovstorage-plugin-broker-client`) forward the address
verbatim to the broker; the downstream plugin applies its own
guard. Don't strip the modifier and don't reject pre-emptively in the
meta-plugin — let each downstream make its own honor-or-reject call.

### Plugin-boundary hardening patterns

Beyond the per-slot contracts, every in-tree plugin enforces three
cross-cutting invariants *before* any backend round-trip. New backends
should adopt the same pattern; the per-backend reference pages spell
out the specific helpers each plugin uses.

**Preconditions use opaque etag strings.** The precondition fields on
the options structs are:

- `ReadOptions::if_match`, `DeleteOptions::if_match`,
  `UpdateMetadataOptions::if_match` — `Option<String>` etag.
- `WriteOptions::if_dest`, `CopyOptions::if_dest`,
  `RenameOptions::if_dest` — `IfDestExists` (`Overwrite` / `Fail` /
  `MatchEtag(etag)`).
- `CopyOptions::if_source`, `RenameOptions::if_source` —
  `Option<String>` etag constraining the source.

The etag token is opaque to the host for comparison; its internal structure is
the plugin's choice. The built-in `file` backend synthesizes
`"size:N,mtime:T"`; GCS encodes the generation number; the Omniverse Storage
Service uses `ResourceIdentity.encoded_identity`; and the broker forwards
whatever string the upstream backend supplied. A plugin that wants to encode
multiple facts into a precondition can do so inside the opaque string. The host
never parses it to decide whether two tokens match. Validator trust is a
separate backend promise carried out of band in `ObjectInfo::etag_strength`.

Backends without an etag-conditional wire (most OpenDAL drivers)
honor `ReadOptions::if_match` and `DeleteOptions::if_match` via
post-stat compare. Backends without any precondition surface
(Nucleus's `delete2` / `copy2` / `rename2`) return `Unsupported`
when the preconditions are populated.

**Etag strength is a declaration, not a computation.** The host cannot infer
whether equal tokens guarantee byte-identical content from a token's spelling.
Derive `ObjectInfo::etag_strength` from what the backend actually promises, not
from a hash-like shape, length, or other string inspection. A weak declaration
does not make the opaque token unusable as a backend precondition; it says only
that consumers cannot use it as proof of byte identity.

Producers receiving an HTTP-derived etag use the shared
`normalize_wire_etag` helper. It removes surrounding quotes and the `W/` marker
from the opaque token while preserving the marker's evidence out of band:
`W/` declares `Weak`, and only a nonempty, syntactically valid quoted entity-tag
declares `Strong`. A bare or malformed unmarked value declares `Unspecified`.
The producer stores the normalized token and declaration together so stat,
read, list, and client-side precondition comparisons use the same spelling.

`Unspecified` is the undeclared zero value. Every consumer treats it as `Weak`
for trust decisions, so omission fails safely. In particular, the byte cache
keys content only on `Strong`; `Weak` and `Unspecified` validators take the
untrusted path.

| Backend | Etag strength declaration |
|---|---|
| `file` | `Weak`: size plus mtime can alias a same-size rewrite within the filesystem clock's granularity. |
| S3 | Derived from the provider's object etag by `normalize_wire_etag`; conformant quoted S3 etags are `Strong`, an explicit `W/` marker is `Weak`, and a bare or malformed value is `Unspecified`. |
| GCS | `Strong` for the numeric object generation used as the etag. |
| Azure | Raw HTTP `ETag` headers use `normalize_wire_etag`: conformant quoted values are `Strong`, an explicit `W/` marker is `Weak`, and a bare or malformed value is `Unspecified`. A nonempty bare typed etag member in List Blobs XML or List Paths JSON is provider-declared `Strong`; an explicit `W/` remains `Weak`. |
| Hugging Face Hub | `Strong` for the provider's content-addressed LFS SHA-256 and Git object IDs. Direct response `ETag` values use `normalize_wire_etag`, including the quoted/weak/bare rules above. |
| Nucleus | `Unspecified`: omni1 exposes an opaque precondition token but does not declare that equality proves byte identity or that a token is never reissued for changed bytes. |
| Omniverse Storage Service client | `Strong` for a present `ResourceIdentity.encoded_identity`: the Storage API contract explicitly marks the identity suitable as a cache key, so one encoded identity is not rebound to different bytes. Different identities may name the same bytes, which does not weaken the one-way strength promise. |
| OpenDAL | Derived from the driver's wire etag by `normalize_wire_etag`, including the quoted/weak/bare rules above. |
| HTTP(S) | Derived from the response `ETag` by `normalize_wire_etag`, including the quoted/weak/bare rules above. |
| Broker client | Transparent: preserves the upstream declaration. |

**A versioned address is a pin, not an identity.**
`ObjectInfo::versioned_address` names *this* version of the object in the
backend's own pin spelling. `None` means the backend does not version this
object, or the caller did not ask and the answer was not free. It is not a
capability (it grants nothing the unpinned address does not), not a durable
key (retention and alias rules decide how long it resolves), and never a
mutation target (see *Address-modifier rejection*). Every directory kind
carries `None`, as do `write`, `update_metadata` and `create_directory`
results. Populate it from what the backend returned for this object — a
version id, a generation, a commit sha, a checkpoint, a server-supplied
`resource_address` — never by deriving it from `etag`.

`StatOptions::versioned_address` and `ListOptions::versioned_address` are
cost knobs with the same shape as `full_metadata`: set, a versioning backend
MUST populate the pin even when that costs a version lookup; clear, a backend
MAY populate it when the answer is free. Over-delivery is allowed in both
directions.

| Backend | `versioned_address` spelling | `stat` cost | `list` cost | `None` cases |
|---|---|---|---|---|
| `file` | none | always `None` | always `None` | the filesystem has no versions |
| S3 | `?versionId=<id>` | free: `x-amz-version-id` rides `HeadObject`. The literal `null` id of an unversioned or suspended bucket is not a pin. | flag set: `ListObjectsV2` becomes `ListObjectVersions` filtered to `IsLatest`; a key whose newest entry is a delete marker is omitted, as `ListObjectsV2` omits it. Each common prefix is verified with one `ListObjectsV2` probe and dropped when it holds no current object, so both listings agree on which directories exist. Needs `s3:ListBucketVersions` (and `s3:ListBucket` for the probes); a connection without them answers the wire's denial rather than falling back. `MaxKeys` counts every version, so pages may be short. Flag clear: `None`. | unversioned or suspended bucket; directories |
| GCS | `?generation=<n>` | free: the generation is on every object resource | free: every list entry carries `generation`, so the pin is populated whether or not the flag is set | directories |
| Azure | `?versionid=<id>` | free: `x-ms-version-id` rides `Get Blob Properties` | flag set: a recursive listing adds `include=versions` kept to the current version (`IsCurrentVersion`); a non-recursive listing keeps its delimiter and issues one `Get Blob Properties` call per blob, whose facts replace the listed entry's, because the service refuses `include=versions` together with a delimiter. Flag clear: `None`. | container versioning disabled; HNS (Data Lake) listings and stats; directories |
| Hugging Face Hub | `?revision=<commit sha>` | flag set: the request carries `expand=true` (the same request `full_metadata` makes) and the pin is `?revision=<lastCommit.id>`. A 40-hex sha the caller already pinned is echoed for free; a ref such as `main` is not a pin and is not echoed. | same as `stat`, per file entry | repository root and directories |
| Nucleus | `?<branch>&<checkpoint>` (native form, e.g. `?&3`) | flag set: one `get_checkpoints` plus one `stat2` at the chosen checkpoint, whose facts are reported; a `?branch&checkpoint` pin is echoed without either | flag set: one `get_checkpoints` plus one `stat2` per file entry | folders; files without checkpoints |
| Omniverse Storage Service client | the server's `VersionInfo.resource_address` verbatim | flag set: one `EnumerateVersions` reports the newest `resource_address` and the entry's facts come from that version's `resource_info`; an address the service rejects as already a version address is echoed. Flag clear: `None`, because `Stat` carries no version. | flag set: one `EnumerateVersions` per file entry with the same fact rule, failing the page on error (the policy the `full_metadata` metadata fetch follows). Flag clear: `None`, because `ListStat` carries no version. | objects with no versions; subfolders |
| OpenDAL | none | always `None` | always `None` | the adapter cannot serve a read at a pinned address |
| HTTP(S) | none | always `None` | no `list` | every answer |
| Broker client | forwarded | transparent: forwards the field and both cost flags untouched | transparent | whatever the downstream plugin answers |

**Inverted byte ranges refused at the plugin boundary.** Every plugin
that honors `ReadOptions::range` checks for `end_inclusive < start`
*before* any wire or I/O call and returns `InvalidArgument`. Lumping
this with backend-side range errors would round-trip a deterministic
caller bug and lose the precise diagnostic. The plugin boundary is the
right place to refuse it — every backend in tree (file, http, S3, GCS,
Azure, OpenDAL, Nucleus, services-client, broker) does so consistently.

**Every redirect declares what its credential authorizes.**
`RedirectScope.credential` is required on both `ReadRedirect` and
`WriteRedirect`, with four values: `None` (no credential; the URL alone
fetches the target), `Request` (authorizes this one request and expires
with the redirect), `Connection` (authorizes the connection at large —
other objects, and time beyond this redirect's expiry), and
`Unspecified` (the plugin forwards a credential it did not construct
and cannot classify).

This is a **declaration, not a computation**, because the host cannot
compute it: an account-wide signature and one scoped to a single blob
are the same shape on the wire, so no header or URL inspection recovers
the difference. Derive it from the branch that constructs the
credential — the auth mode, the signing call — rather than from the
redirect's shape, so the declaration and the credential cannot drift
apart. `RedirectScope` carries `physical_url_prefix`, `operations`,
`expires_at` and `credential`; it has no `Default` and is built by struct
literal, so a plugin that omits `credential` fails to compile. There is no
safe value to fill in mechanically — `Unspecified` is fail-safe but costs a
proxied transfer, as the next paragraph explains.

**`Unspecified` is fail-safe, not neutral**: a host treats it exactly as
`Connection`, so it costs a proxied transfer under a refusing policy.
Declare it honestly when you are copying a header set from upstream —
the in-tree OpenDAL and Omniverse Storage Service plugins both do, for
that reason. Declaring `Request` to keep the redirect path is the
failure this field exists to prevent.

What a host does with the declaration is the **operator's** choice, not
the plugin's: the deciding question is whether the clients are trusted,
which no plugin can know. A host may **lower** a declaration and never
raise one — a redirect declared `Request` that also carries a header
the host cannot account for as addressing or conditioning the request
is treated as `Connection` — so a declaration mistake is paid for in
throughput rather than in disclosure.

**The host validates the request you put in a redirect, before any
network I/O.** The method is checked against a fixed, case-exact
allowlist — `GET` or `HEAD` on a read redirect, `PUT`, `POST` or
`PATCH` on a write. A well-formed verb outside it, *including a
lowercase spelling of a permitted one*, is refused with
`PermissionDenied`; a token that is not a valid HTTP method at all is
refused with `InvalidArgument`. **On a write redirect** — and only
there, because the read path replays your headers unchecked — a
`Content-Length` header you supply must be `1*DIGIT` per RFC 9110:
surrounding whitespace is trimmed, but a sign character — `+123` as
much as `-123` — is refused with `InvalidArgument` rather than reaching
the origin, as is an empty value and a second `Content-Length` header.
Do not read the read path's silence as permission: emit the same bare
digits there, since nothing between you and the origin will correct
them. If your backend needs a verb outside the
allowlist against the origin — a `DELETE` aborting a multipart upload,
say — perform it through your own client rather than by emitting a
redirect for it.

**`write_redirect` `size_hint` discipline.** Most cloud plugins refuse
`size_hint = None` at the plugin boundary because their multipart wire
needs total length to compute part offsets (Nucleus's LFT multipart is
the canonical example; S3's multipart can in principle adapt but the
in-tree plugin still requires the hint for cap-management). The broker
plugin is the exception: it forwards `size_hint = None` faithfully
because the broker daemon applies no size policy of its own — it passes
the request down its stack and leaves the accept-or-refuse decision to
the upstream plugin — and the single emitted `WriteRedirect` carries
the body via `body_source` rather than a known `Content-Length`. A new
plugin author should make this choice deliberately and document it on
the per-backend page; the trap is silently treating `None` as `0` or
choosing a default chunk count that overflows the backend's part limit.

---

## Per-slot contracts

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
- `opts.versioned_address` is the second cost knob and has the same
  shape: `false` means *return the pin if you already have it in hand*;
  `true` means *I will pay — a versioning backend MUST return it for
  every versioned object even if that costs a version lookup*.
  Over-delivery is permitted: a backend that has the pin for free
  returns it under either value. `None` under the flag means the
  backend does not version this object. A `stat` on an address the
  caller already pinned echoes that pin regardless of the flag.
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
  lease. This is a valid `read` result for any Layer whose bytes already
  sit on disk local to the current host; it does not authorize a backend
  to implement the host-owned `materialize` slot.

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
  plugin refuses it at the plugin boundary with `InvalidArgument` before
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
- *If your backend serves files from local disk under a lease:* `read`
  MUST return `LocalDelegate` (not `Bytes`). This applies to the `read`
  result shape only: a backend MUST still leave `materialize` at the
  trait default. Buffering an entire local file into a `Vec<u8>` is the same
  memory-DoS vector as buffering a write stream — unbounded by object
  size. Hold the lease for the duration the delegate is alive.
- *Otherwise:* `Stream`. Peak memory should be chunk size × channel
  capacity; never the full object size.

### `write`, `write_stream`, `write_redirect`, `continue_write`

These four are facets of one operation. The host picks which based on
body shape and capabilities.

**Contract.** On `Ok(WriteStep::Done(result))`, the bytes and
`result.info` describe the new persistent state. Reads against the
target must observe this state from now on.

**One field is exempt, and only on `continue_write`.** An attributing host
overwrites `result.info`'s reserved attribution key with the principal it
authenticated for *that call*, so `ObjectInfo::modified_by` on a
`continue_write` result is an attestation about who performed the finalize,
not a read-back of what the object stores. The two can differ legitimately: a
backend that bound its metadata when the redirect was minted keeps the
minter's identity on the object while the finalize was made by someone else,
a chained host asserts its own principal over an object a deeper host wrote,
and a backend whose attribution write is a separate best-effort step may not
have landed it. A subsequent `stat` is the authority on what the object
stores. Every other field of `result.info`, and every other verb's
`modified_by`, keeps the state semantics above.

**Edge cases.**

- `opts.if_dest = IfDestExists::MatchEtag(etag)` — precondition;
  fail with `PreconditionFailed` before any bytes commit. The etag
  string is opaque to the host; map it to whatever conditional your
  wire carries.
- `IfDestExists::MatchEtag(etag)` against a non-existent target —
  return `NotFound`. The precondition implicitly asserts existence;
  absence is a precondition violation. (Distinct from
  `PreconditionFailed`, which is for *etag-mismatch* on an existing
  target.)
- `opts.if_dest = IfDestExists::Fail` — fail with `AlreadyExists` if
  the destination exists. Distinct from "create with default; fail if
  exists".
- *Missing ancestors* — a write creates its path. A write to `/a/b/c`
  succeeds when `/a/b/` does not exist; creating missing ancestors is
  the backend's job, never the caller's. See **Branch points** below
  for the real-directory versus flat split.
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
  silently drop). Key names follow *User-metadata keys* under
  Cross-cutting rules: every name in the portable subset must be
  accepted, and the reserved `ovstorage_` namespace is the host's.

**`continue_write` must re-assert the host's writer identity on anything it
PERSISTS.** The `WriteRedirectBatch` and `RedirectResultBatch` a
`continue_write` receives arrive from whoever drove the redirect. On an
unsealed route, any `user_metadata` your plugin takes from the continuation and
*writes* at the commit is a value the caller could have rewritten. The broker's
client-driven seal prevents that edit, but it deliberately does not bind a
principal: another principal authorized for the same address can present the
genuine continuation. A host that attributes writes puts its authenticated
principal for the current call in the reserved key `ovstorage_modified_by`, so
the plugin must not treat either an editable or a replayed prior value as the
host's attestation for this finalize call.

Take the value from the request instead:

```rust
// In your Layer, before the request's input is moved:
let attested = ovstorage_plugin::attested_modified_by(&request.extensions);
// Wherever the continuation's metadata is about to be written.
// `user_metadata` here is the `Option<UserMetadata>` you are about to apply:
ovstorage_plugin::reassert_attribution(attested.as_deref(), &mut user_metadata);
```

`attested_modified_by` reads a request extension only a host attribution
overlay sets. **`None` means no host spoke for this request** — the branch
carries no overlay, or the host is passing an upstream host's value through —
and `reassert_attribution` then leaves your metadata untouched. Do not
substitute `ext::PRINCIPAL_ID`, which is present on every brokered request:
whether a write is attributed at all is the host's composition decision, and
deriving it from the principal attributes on branches a host composed not to
attribute.

Where your backend binds the metadata server-side when the redirect is minted
— signed into a presigned URL, or committed as an upload session is created —
the persisted copy is out of the caller's reach and you owe nothing here.

**You do not owe anything for what you REPORT.** The `ObjectInfo` in your
`WriteStep::Done` may be built from whatever the caller handed back — a
continuation, a captured response body, captured headers — so report the
metadata you have and do not try to sanitize the reserved key in it.

An attributing host overwrites that key in your result before promoting it into
`ObjectInfo::modified_by`, and it is the only place every `continue_write`
result passes through, so reports come out right for every backend it
attributes, including ones it has never heard of. Where no host attributes — a
direct Stack, a pass-through host, a branch whose backend kind declares `false`
for `supports_user_metadata` —
nothing overwrites it, and nothing needs to: the reserved key is then attested
by no one, which is the same standing it has for a direct writer that sets it
on an ordinary `write`. What you must not do is *persist* an unasserted value,
which is what the paragraph above is about.

**Branch points.**

- *If your backend caps single PUTs at N bytes (S3, Nucleus LFT):*
  emit multipart redirects. Each `WriteRedirect` carries its own
  byte-range and headers. The protocol shape (chunk numbering, size
  headers, finalization call) is backend-specific. Examples:
  S3 multipart (UploadPartNumber, CompleteMultipartUpload),
  Nucleus LFT (`Content-Start`, `Multipart-Chunk-Size`,
  finalize via `create_asset(content_id)`).
- *If your backend has real directories (filesystem, Nucleus, ADLS
  HNS):* create missing ancestors before the commit. Remember per
  connection which directories you have already created so the
  ancestor call is issued once per directory, not once per file. On
  `NotFound` from the commit, forget the entry, re-create the
  ancestors, and retry the commit once. The ancestor step is a
  precursor, not a precondition: if it fails for a reason other than a
  missing level, let the commit run and report the commit's own answer,
  never the ancestor step's. For `copy` / `rename`
  destinations, which carry no body, create the ancestors lazily after
  a `NotFound`, once the source is known to exist, so a failure for
  another reason leaves no folder behind.
- *If your backend is flat (S3, flat Azure):* nothing to do; keys
  create their own prefixes.
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
  return success for both; the contract mirrors that. The cleaner framing
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
  cross-root `Stack::copy` / `Stack::rename`) back to the host.

**Branch points.**

- *If your backend supports server-side copy:* implement; advertise
  `supports_server_side_copy`. Otherwise leave the bit false; the host
  falls back to read+write.
- *Availability vs mechanism:* `supports_copy` / `supports_rename` say
  the operation can be **attempted**; `supports_server_side_copy` /
  `supports_server_side_rename` say the bytes stay on the server, and
  `supports_atomic_rename` is a guarantee about indivisibility. A
  backend that implements `rename` as its own copy-then-delete sets
  `supports_rename = true` with both `supports_server_side_rename` and
  `supports_atomic_rename` false. Never set a mechanism or guarantee bit
  to describe an emulation.
- *Returning `Unsupported` is how you decline:* a host stack carrying
  `copy_rename_fallback` reads that as "this layer does not perform the
  operation" and emulates it — including when you decline only because
  of a precondition you cannot enforce. That is deliberate: the caller
  gets the semantics it asked for rather than a refusal. Decline with a
  more specific code (`PermissionDenied`, `PreconditionFailed`,
  `IncompatibleType`) whenever the reason is not "I don't do this",
  because those propagate to the caller untouched.
- *If your backend can't accept etag on copy/rename (Nucleus):* return
  `Unsupported` for any populated `if_source` or non-`Overwrite`
  `if_dest`. Don't strip the precondition.
- *If `rename` is non-atomic* (copy-then-delete fallback): set
  `supports_atomic_rename = false`; surface partial-fail in error
  messages so callers know recovery is on them.
- *If a directory rename is refused because the destination directory
  has children:* refuse with `DirectoryNotEmpty`, the same code
  `delete_directory` uses, rather than a retryable one — replaying
  cannot empty the destination. Backends over a native filesystem
  reach this through the kernel's `ENOTEMPTY`; where the platform
  raises `EEXIST` instead, `AlreadyExists` is the correct code and
  this rule does not apply. It does not apply to a destination
  precondition either — an `IfDestExists::Fail` request whose
  destination exists is `AlreadyExists` whatever the destination
  holds — nor to renaming an object onto a directory, which is a
  different refusal.
- `opts.message` — see **Versioning model decision tree**.

### `list` and `list_stream`

**Contract.** `list` is the buffered surface: return a `ListPage` of
`ObjectInfo` values under the prefix. `list_stream` is the unpaged,
pull-based surface: yield each `ObjectInfo` as it becomes available, retaining
only bounded traversal, current-page, and folding state. A native-paginated
backend drives its continuation pages internally and only when downstream
demand advances the stream; a traversal backend advances its own iterator the
same way. Neither streaming implementation materializes the whole prefix.

The ABI-v17 slot uses the established pull-iterator stream shape. See the v17
ABI changelog entry in the shipped `ovstorage_plugin.h` (generated from
`ovstorage-core/ovstorage-plugin/src/ffi/v2/mod.rs`) for its layout and
ownership mechanics rather than duplicating them here.

**Edge cases.**

- Each `ObjectInfo.address` is a full resolved backend address under
  the requested prefix; the host projects it into the caller-facing
  namespace. Returning an address outside the prefix is an `Internal`
  contract violation.
- `opts.versioned_address` follows the `stat` rule per entry. When
  set, a versioning backend switches to whatever enumeration carries
  version ids (S3 `ListObjectVersions` kept to `IsLatest`, Azure
  `include=versions` kept to the current version) or makes one version
  lookup per file entry where the listing itself carries none, and
  returns the pinned address on every file entry; when clear it MAY
  still populate the field where the listing already carries the id
  (GCS generations). Directory-kind entries carry `None`.
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
- `opts.max_results` / `opts.page_token` are buffered-`list` fields. The host's
  `max_results` page window and continuation token apply only to `list`.
  `list_stream` MUST refuse either populated field with `InvalidArgument`; it
  never turns a page window into an early-stopped stream.
- The cancellation token passed when `list_stream` is opened has a watch-style
  lifetime: retain and observe that same token for the stream's entire
  lifetime, including while waiting for the next backend page or traversal
  entry. Cancellation terminates the stream with `Cancelled`; dropping the
  stream releases its walk and all retained resources.
- Pull demand is the backpressure boundary. Do not fetch arbitrarily ahead of
  the consumer or accumulate previously yielded entries. Native pagination is
  optional: a backend can implement bounded streaming from any incremental
  traversal, with or without a resumable store cursor.
- Stopping or dropping a stream promises no resumption. `list_stream` returns
  no cursor, and a later call starts a new walk. A resumable streaming contract
  would require a separate capability, analogous to
  `watch_directory_resumable`; do not interpret `supports_list_stream` or
  `supports_list` as such a promise.
- Ordering is mode-conditional. A **recursive stream from a flat backend** MUST
  yield backend entries in lexicographic byte order by decoded provider key,
  not by the percent-encoded URL serialization; incremental inferred-ancestor
  synthesis depends on that precondition, and a
  regression terminates the stream with `Internal`. A non-recursive stream MAY
  preserve the store's natural per-page emission order — for example, object
  entries followed by inferred common prefixes — and need not be globally
  sorted. In that mode, a flat backend MUST remove a marker/common-prefix
  duplicate within the page that produced it before yielding the page. Native
  real-directory streams have no additional ordering requirement.

**Branch points.**

- *If your backend has native subdirectories (filesystem):* emit
  directory-kind `ObjectInfo` values on `recursive: false`.
- *If your backend is flat (S3):* emit directory-kind `ObjectInfo`
  values inferred from common prefixes (`foo/bar/.../baz` becomes a
  directory address `foo/` for the prefix `""`).
- *If your backend can't recursively list cheaply* (e.g. Nucleus's
  omni1 `list2` only returns one level per call): leave
  `supports_recursive_list = false`. If a caller invokes `list` with
  `opts.recursive: true` anyway, or opens `list_stream` with that option,
  return `Unsupported` — do **not**
  fan out internally into N one-level calls. That decision belongs to
  the caller (who can budget the round-trips); silently amplifying a
  single slot call into many backend calls is a cost-attribution
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

> **Note on `supports_list_stream`.** This bit says the layer implements the
> bounded streaming path above rather than relying on the default adapter that
> calls buffered `list`. It is an optimization/capability hint, not a gate on
> calling `list_stream`, and it does not advertise pagination or resumption.
> A backend does not need a native pagination API to set it: an incremental
> filesystem or service traversal is sufficient.

### `list_versions`

**Contract.** Return a stream of `ObjectInfo` values, each with a
version-pinned `ObjectInfo.address` and `versioned_address =
Some(address)`.

**Edge cases.**

- `ObjectInfo.address` is the full backend address for that version,
  including whatever query/form the backend uses as the version pin.
  The host projects only the route prefix.
- `versioned_address` equals `address` for every entry: the address is
  already the pin. It is populated with no flag — `ListVersionsOptions`
  has none. The one exception is a version id that selects mutable
  content, S3's literal `null`: its entry carries `None`.
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
  leaking into the slot's semantics.
- *No versioning at all:* leave `supports_version_listing = false`.
  The host gates the call on the bit and won't reach the plugin (per
  *Slot gating* above); a call arriving anyway is answered by the
  self-gate: typed `Unsupported`, no side effects.

### `get_latest_version`

**Contract.** Return a single `ObjectInfo` for the version the
input address resolves to. If `target.resolved_address` carries the
backend's version-modifier query param (e.g.
`?versionId=abc123` for S3, `?checkpoint=42` for Nucleus,
`?generation=12345` for GCS), return that pinned version's
`ObjectInfo`. Otherwise return the current head's `ObjectInfo` with a
version-pinned address — the same entry `list_versions` emits for the
head. The returned `versioned_address` is `Some(address)`, except for a
version id that selects mutable content (S3's literal `null`), which
carries `None`.

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
  call meaningfully. Per *Per-connection backend configuration*, prefer
  setting the capability bit accurately when the connection is
  established so the host doesn't reach the plugin in the first place;
  if you can't probe cheaply, returning `Unsupported` from this slot is
  the right fallback.
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
  bulk-delete); the slot does not amplify a single call into N backend
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
`user_metadata_remove`. Return updated `BackendItemInfo`. Key names
follow *User-metadata keys* under Cross-cutting rules: every name in
the portable subset must be accepted, in the set and the removal list
alike.

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
  forwards a single `update_metadata` slot call to its plugin, and the
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
  subtree. The recursive stream is a strict event superset: it includes every
  event the same backend would emit for the corresponding non-recursive watch,
  not alternate directory-rollup events.
- `opts.include_metadata_changes: true` is likewise a strict event superset of
  `false`; enabling it adds metadata events without replacing object events.
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
- *Otherwise:* leave `supports_watch_directory = false`. The contract
  does not include a polling mode — callers that want polling can drive
  `list` themselves on whatever cadence they choose, which avoids
  having every plugin re-implement the same diff-and-emit loop and
  keeps cost attribution explicit.

### `list_address_roots`

**Contract.** Return a `RootInfoSnapshot` of the roots this layer
currently serves, plus an optional update stream.

**Branch points.**

- *If roots are static (configured in TOML):* return the snapshot with
  no update stream (`updates: false`); the host reads it once per
  composition and never polls.
- *If roots come from server discovery (Nucleus per-principal storage
  mounts; cloud storage mount discovery):* return an update stream
  alongside the snapshot and emit `RootInfoChange::Added` /
  `Removed` / `Updated` as roots change. The host keeps the stream
  drained and re-projects routing as changes arrive.

---

## Versioning model decision tree

The contract for a backend with `supports_version_listing = true` is:
**every mutating write produces a version, regardless of whether the
caller supplied `opts.message`.** Walk this tree to decide what your
plugin has to do to honor it. (If versioning is *configurable* on
your backend and disabled on this particular instance, see
*Per-connection backend configuration* in the cross-cutting rules —
the bit reflects the instance, not the plugin's general capability.)

1. **Does your backend record a new version on every write
   automatically (S3 versioning, GCS object generations)?**
   → Transparent. Enable versioning on the backend; `list_versions`
   returns what the backend stored, and `versioned_address` is free on
   `stat`: the id rides the HEAD response.

2. **Does your backend have a per-call switch that gates whether a
   version is recorded?**
   → Always opt in on every mutating write. The switch is the
   plugin's responsibility; the contract is "every write produces a
   version", and the caller's `opts.message` doesn't influence
   *whether* the version is created — only what annotation it carries.

3. **Does your backend have no versioning concept at all?**
   → Leave `supports_version_listing = false`. Don't implement
   `list_versions`. Answer `versioned_address: None` on every slot.

### What about `opts.message`?

`opts.message` is the version's **commit annotation**, supplied by the
caller. It is *not* a versioning trigger: `message = None` means
"create a version with no annotation", not "skip the version". Where
the backend has a native slot for the annotation (a commit-message
field on the version), persist it on the version that gets created.
Backends without one stash it as user metadata under the shared
`MESSAGE_METADATA_KEY`, spelled `x_ov_message`, beside the caller's
keys, where they can keep user metadata at all, so the annotation reads
back the same way on every route. A message the backend cannot store in
that slot as it is, such as one that is not a legal HTTP header value
where metadata travels in `x-amz-meta-*` or `x-ms-meta-*` headers, is
dropped and the call proceeds; refusing the call would turn a droppable
annotation into a hard failure. A caller-supplied entry under that
key wins and the message is dropped: caller metadata is never silently
dropped, while the annotation is droppable by contract. `message`
fills the key only when the call's own map leaves it unset. On a patch
a `user_metadata_set` entry under the key stands; otherwise the message
replaces the object's earlier annotation, and a removal of the key in
the same patch does not prevent that. Which of copy and rename record
the annotation is per backend and stated on the backend page. The name
sits inside the portable subset of
[User-metadata keys](#user-metadata-keys), so every conformant backend
accepts it, and outside the reserved `ovstorage_` namespace, so an
attributing host neither strips it from the caller's map nor harvests
it: the annotation stays visible as an ordinary user-metadata entry. A
backend that can keep neither discards the message explicitly with a
code comment — see the "Dropping `opts.message` silently" anti-pattern
below.

---

## Anti-patterns

These are real foot-guns this codebase has hit while building the in-tree
backends. They are listed as things to avoid in a new plugin, not as defects
present in any shipped ovstorage release.

- **Buffering write streams to `Vec<u8>` at the plugin boundary.** The
  most-common Memory-DoS vector. Stream chunk-by-chunk; if you can't,
  return `Unsupported`.
- **Silent strip of address modifiers.** `?versionId=N` /
  `?checkpoint=N` on a write op must be rejected. The omni1 wire format
  for `delete2` / `copy2` / `rename2` doesn't carry a version field;
  passing the bare path silently mutates the head.
- **Returning `NotFound` from `delete` for a missing target.** The
  contract for `delete` is "after `Ok(())`, `stat` returns `NotFound`";
  if the target was already gone, that post-condition already holds and
  the right answer is `Ok(())`. Returning `NotFound` would force every
  caller to write the same is-it-already-gone special-case.
- **Acquiring locks across `.send()` / `.await`.** Publishes state to
  observers before durability is confirmed. Land durability first.
- **Implementing a host-owned slot in a backend.** A backend MUST leave
  `materialize` at the trait default; implementing it bypasses the
  composed Stack's cache leasing and local-availability contract.
- **Returning `Unsupported` to skip implementing a slot you've
  advertised.** If you don't intend to implement an op at all, that's
  what the capability bit is for — leave it false and the host won't
  call you. `Unsupported` from a slot *is* legitimate, but only for
  *specific call shapes* a true-bit backend can't honor (see *Scope of
  `Unsupported`*); blanket-returning it from every call is a sign the
  capability bit is wrong.
- **Dropping `opts.message` silently when your backend has no
  per-operation annotation concept.** Either store it as user metadata
  under `x_ov_message` (see *What about `opts.message`?*) or discard it
  explicitly with a code comment so the next reader knows.
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
  place to refuse is the plugin boundary, not the downstream `Internal`
  surfaced by whichever backend the request reaches.

---

## Test harness

Three harnesses verify your plugin against this contract:

1. **Registry-as-spec scenario sweep** in your own crate's `tests/` —
   add a dev-dependency on `ovstorage-core/ovstorage-plugin-test` and
   drive the `ScenarioRegistry` against your `Layer` (each first-party
   provider crate's `tests/conformance_scenarios.rs` is the template).
   The sweep drives every scenario your local mocks can prove and
   skips the rest with a concrete reason; pin the driven-name set so
   lost coverage fails loudly. Recorder-backed `expected_calls`
   assertions stay with the test backend.
2. **In-tree controllable test plugin** — `ovstorage-core/ovstorage-plugin-test`
   (see its README) is used by the host's tests; doesn't run *against*
   your plugin but demonstrates the expected behavior. Its ABI-v2
   cdylib export lives in `ovstorage-plugin-test-abi`, whose
   `tests/loaded.rs` re-runs the conformance surface across a real
   `dlopen` — the loader + vtable + manifest wiring proof.
3. **Streaming-invariant test** in your own crate's `tests/` —
   mandatory if you expose a `Body::Stream` seam. Helper:
   `ovstorage_plugin_test::streaming::assert_streaming_invariants`.

When a host conformance test is skipped, it cites the missing capability
bit. To enable a test, advertise the capability and implement the
slot per this contract.

---

## Cancellation contract

Every async operational slot takes
`cancel: Option<CancellationToken>`, and *within* the plugin process you
should honor it as the cross-cutting *Cancellation* rule above
prescribes.

**The ABI-v2 host marshals cancellation across the cdylib FFI, so the token a
loaded plugin receives is real.** A plugin must not treat the token as
guaranteed absent: it can fire mid-operation.

When
the host holds a cancel token for a call, it passes a refcounted
`CancelTokenFFI` handle through the vtable slot; plugin-side, the
`ovstorage_layer_plugin!` runtime bridges it back into a local
`CancellationToken` that fires when the host signals (see the
`ovstorage-plugin` README § Cancellation propagation for the bridge
mechanics, and `race_cancel` for the idiomatic way to observe it).
A pre-canceled token surfacing `ErrorCode::Cancelled` through a loaded
plugin is pinned by the loader regression test.

Cooperative cancellation only helps when the plugin honors it, so the
discipline for plugin authors is:

- **Plugins SHOULD bound their own work with an internal deadline.** A
  remote-backed plugin that ignores the token and hangs on a slow
  upstream pins the host's outer RPC timeout (whatever the caller
  configured) rather than the host's cancel signal. Wrap any blocking
  call (network I/O, file I/O, IPC, lock acquisition, DNS, …) in
  `tokio::time::timeout` with a deadline shorter than the host's RPC
  timeout, and return `Err(Error::new(Transient, "…"))` on timeout;
  the host's retry wrapper will retry `Transient` errors per its retry
  config.
- **Brokered routes amplify the cost of ignoring the token.** The
  `broker-client` plugin forwards slot calls to the upstream broker
  daemon, which dispatches into its own configured Stack; stream
  cancellation rides dropped futures and closed streams. A `read`
  against a wedged upstream backend pins the caller's outer timeout.
  See `plugin-broker.md` section "Cancellation contract" for the
  wire-level details.

The risk is bounded by the project's "all plugins first-party" memory:
no third-party storage plugins ship against ovstorage 0.2.1, so the
mitigation is operator-level (don't deploy a hanging plugin) and
plugin-author discipline (bound your blocking calls).
