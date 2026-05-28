# ovstorage

> The canonical public reference for `ovstorage::Library`, the `Storage`
> trait, and the routing-table types lives in
> [`docs/public/library-rust/README.md`](../../../docs/public/library-rust/README.md).
> This README covers internals, dispatcher behavior, dependencies, threat
> model, conformance tests, and risks.

## Purpose

`ovstorage` is the dispatcher library — the crate that binds a `Library` handle, owns the route table, dispatches to the right `StorageBackend`, consumes the plugin's `ReadResult` / `WriteStep`, optionally consults [ovstorage-cache](../ovstorage-cache/README.md), and feeds [observability](#observability) sinks. The `Storage` trait is async (`#[async_trait]`); every byte-moving method takes a `cancel: Option<CancellationToken>` so callers can abort in-flight work. The library supports static programmatic routes plus in-process direct-mode connection routes, and implements `watch_directory` streams, aliases, visibility, and snapshot management watches. It is the Rust library behind the C and Python shared-library artifacts and what the [bindings](../ovstorage-capi/README.md) link.

The Rust type vocabulary the trait works with — `ObjectAddress`, `ObjectInfo`, `ObjectKind`, `IfDestExists`, `ResolvedTarget`, options structs, the error taxonomy, the capability vocabulary, URL canonicalization rules, `LocalDelegate`, `SecretBytes`, connection/alias/auth types — lives in [ovstorage-plugin](../ovstorage-plugin/README.md). `ovstorage` re-exports those types so existing `use ovstorage::ObjectAddress;` continues to work; the canonical definitions are in the plugin-ABI crate so plugin authors and host code use the same vocabulary.

## Public surface

The crate exports one type that callers see, plus the `Storage` trait it implements.

```text
pub struct Library(/* opaque */);

impl Library {
    pub fn builder() -> LibraryBuilder { /* ... */ }
}

impl LibraryBuilder {
    pub fn open(self) -> Result<Arc<Library>> { /* ... */ }
}

impl Storage for Library { /* every method below */ }
```

Callers construct the handle once at startup (`Library::builder()...open()?`), share it across threads by cheap `Arc` clone, and pass full `ObjectAddress` values to every method. The `Library` matches the route on each call and dispatches to the appropriate plugin instance.

The dispatcher consumes registrations built through `LibraryBuilder` / the public management APIs; programmatic registration remains the source shape every other entry funnels through. The crate ships TOML-shaped config types (`LibraryConfig`, `RouteConfig`, `ConnectionConfig`, `SecretRef`) under `ovstorage::config` so the CLI, daemon, and REST adapters can deserialize the same shape and call the registration APIs without re-implementing the schema; environment-layer and broker config-file precedence still live in those adapters. Broker-delivered configuration enters the table from `broker-client`'s `address_roots` stream rather than through a config-file path.

`LibraryBuilder::open` is the ownership boundary for process-local state. It validates registered static routes, rejects duplicate prefixes, sorts by longest-prefix-first, attaches an optional cache, registers the host-callbacks substrate for any rlib-linked plugins, and returns an `Arc<Library>`. If a required step fails, `open` returns a typed `Error` and no half-open handle escapes.

### The `Storage` trait

> The canonical reference for **the `Storage` trait** lives in
> [`docs/public/library-rust/README.md` § Storage trait](../../../docs/public/library-rust/README.md#storage-trait).

### Listing and paging types

> The canonical reference for **Listing and paging types** lives in
> [`docs/public/library-rust/README.md` § Listing and paging types](../../../docs/public/library-rust/README.md#listing-and-paging-types).

### Change-notification types

> The canonical reference for **Change-notification types** lives in
> [`docs/public/library-rust/README.md` § Change-notification types](../../../docs/public/library-rust/README.md#change-notification-types).

### Address-root introspection types

> The canonical reference for **Address-root introspection types** lives in
> [`docs/public/library-rust/README.md` § Address-root introspection types](../../../docs/public/library-rust/README.md#address-root-introspection-types).

### Routing-table types

> The canonical reference for **Routing-table types** lives in
> [`docs/public/library-rust/README.md` § Routing-table types](../../../docs/public/library-rust/README.md#routing-table-types).
> Conflict resolution and the resolver visibility rules are in
> [Routing dispatch](#routing-dispatch) below.

## Internals

### Method semantics

Every method on `Storage` (signatures above) has runtime behavior the trait declaration doesn't pin down. This subsection covers what each one *does*, beyond its signature.

**`stat`, `read_bytes`, `read_stream`, `materialize`.** Resolves the address through the routing table (see [Routing dispatch](#routing-dispatch)), checks the in-process cache when one is configured, and otherwise calls the plugin's `StorageBackend::read`. The plugin SPI returns one of four `ReadResult` shapes ([ovstorage-plugin](../ovstorage-plugin/README.md)):

- `LocalDelegate` — returned to `materialize` callers verbatim. `read_bytes` and `read_stream` open the file and read from it (chunk-by-chunk in `read_stream`).
- `Bytes { bytes, info }` — returned directly by `read_bytes`; `read_stream` wraps it as a single iterator chunk; `materialize` materializes it into the cache when a cache is configured.
- `Stream { stream, info }` — async chunk-stream (`Pin<Box<dyn futures::Stream<Item = Result<bytes::Bytes>> + Send>>`) for whole-object reads above the per-plugin small-response threshold. `read_stream` returns the stream as-is; `read_bytes` and `materialize` drain it on the runtime via `.next().await`. Peak host memory during a streaming read is bounded by chunk size × the producer's bounded mpsc capacity, never by object size — the memory-DoS substrate.
- `Redirect` — followed in-process by the redirect follower (see [Redirect follower](#redirect-follower)); the streaming follower hands `read_stream` an async stream that pulls chunks from `reqwest::Response::bytes_stream()`, so even multi-GiB redirected reads stay bounded.

Application code never branches on the variant. It calls `read_bytes`, `read_stream`, or `materialize` and the dispatcher picks the right path. `read_raw` is a separate entry that returns the unfollowed `ReadResult` so binding-side gateways (REST, broker `BrokerReadStep`) can re-emit `Redirect` over the wire as `307` and stream `LocalDelegate` files directly.

**Preconditions.** Read / delete / update_metadata carry `if_match: Option<String>` (etag). Write carries `if_dest: IfDestExists` (`Overwrite` / `Fail` / `MatchEtag(etag)`). Copy / rename carry `if_source: Option<String>` (etag) plus `if_dest: IfDestExists`. The dispatcher forwards each etag into the strongest backend-native precondition the backend supports — `If-Match` for HTTP ETags, `x-goog-if-generation-match` for GCS, Storage API `ResourceIdentity`, or the equivalent vendor-specific conditional elsewhere — so the backend validates the caller's observed bytes before committing work. A mismatch fails with `ObjectModified { new_etag }` where the backend can report a replacement etag.

The library never synthesizes the etag — the value on `ObjectInfo.etag` is whatever the backend returned (or, in the file plugin's case, the plugin's own `"size:N,mtime:Tms"` synthesis from filesystem metadata).

**Versioned reads.** Version *selection* lives in the `ObjectAddress`; version *validation* lives in the etag. The library preserves the URL byte-for-byte through routing and hands it to the plugin; the plugin parses the vendor-specific pin syntax (`?versionId=`, `?generation=`, etc.). The library itself never interprets the query string. Used together, the URL selects and the precondition validates. Mismatch fails with `ObjectModified`.

**`write`.** Takes a `Body` covering the three shapes callers can hand to the library: `Body::Bytes(Vec<u8>)` for in-memory data, `Body::LocalFile(PathBuf)` for bytes already on disk, and `Body::Stream(BodyStream)` for chunk-by-chunk streaming uploads (used by the REST gateway and other binding-side streamers). The dispatcher resolves the address, optionally tries the body-less `write_redirect` entry first when `Capabilities.redirect_size_threshold` is met, then falls through to `StorageBackend::write` (buffered) or `write_stream` and consumes the plugin's `WriteStep` ([ovstorage-plugin](../ovstorage-plugin/README.md)). For multipart / multi-stage uploads, `WriteStep::Redirects` carries one or more redirect batches that the in-process follower executes; each batch's `RedirectResultBatch` feeds back through `continue_write` until the plugin returns `WriteStep::Done(WriteResult)`. Streamed bodies that survive a first round of redirects but enter a second round surface `Unsupported` because the stream has already been consumed; multipart uploads against `Body::Stream` are bounded to single-stage flows.

**Cache integration on writes.** Successful writes populate the optional cache when the body is available to the dispatcher as bytes or a local file. A subsequent read of the same object on the same host is a cache hit subject to [ovstorage-cache "Cache-hit validity"](../ovstorage-cache/README.md#cache-hit-validity-spec--current-api-has-no-if_match--identity--version-surface). Staging, streamed teeing, and crash-recovery details become load-bearing once streamed bodies and the full cache state machine land.

`policy_partition` is derived by the host before it calls into `ovstorage-cache`. Direct mode uses the effective local user plus the active config profile; broker-owned caches use the broker route / tenant partition after authn and authz have resolved the principal. Broker `policy_partition` is route/tenant, not principal; per-principal cache serving authorization lives in the broker-owned scope index and freshness-mode check. The cache crate treats the value as an opaque namespace key. `policy_partition` is not an authorization decision and not a freshness epoch; it only prevents callers that must not share cached bytes from colliding on the same `ResolvedTarget`.

**`list`.** Calls the plugin's `StorageBackend::list` and returns `Vec<ObjectInfo>`. `ListOptions { recursive: bool, .. }` chooses between the two listing shapes every backend natively supports. Default `false`: `list("s3://bucket/team/")` returns `ObjectInfo` values for objects directly under `team/` plus `ObjectInfo` values whose `kind.is_directory()` for the `/`-bounded subdirectories one level down — what S3, GCS, and Azure call a `delimiter=/` listing, what ADLS HNS and `file` do natively. With `recursive: true` the listing fans out across the entire subtree and includes visible directory entries: real directories as `Directory`, flat zero-byte slash markers as `DirectoryMarker`, and inferred ancestors implied by descendants as `DirectoryInferred`. The dispatcher does not synthesize one listing shape from the other, but it does normalize flat recursive results so missing inferred ancestors are present after address projection. A UI walking a tree pays per-level latency, a sync tool enumerating a bucket pays nothing extra, and each shape stays a single backend round trip. `/` is fixed as the segment separator; it is not a tunable knob.

A directory entry is whatever the backend natively considers a child container under the listed prefix. On `file`, ADLS HNS, and Perforce that is a real directory with its own mtime, owner, and etag/version fields when the backend has them; on S3, GCS, and Azure flat there is no directory object — the backend reports the URL prefix as a structural fact about the listing — and only `address` and `kind` are meaningful.

**Directory address spelling.** Directory-facing operations are slash-insensitive at the public API boundary. `create_directory("foo")` and `create_directory("foo/")` dispatch to the same canonical directory address, as do `delete_directory("foo")` / `delete_directory("foo/")` and `list("foo")` / `list("foo/")`. The dispatcher appends the slash before query or fragment and returns directory `ObjectInfo` / child list addresses in that canonical slash form.

`stat` is input-guided rather than slash-insensitive. `stat("foo")` first probes exact object `foo`; only if that returns `NotFound` does it probe directory `foo/`. `stat("foo/")` probes only directory `foo/` and never falls back to exact object `foo`. If object `foo` and directory/prefix `foo/` coexist, the caller's spelling decides which one wins. Permission/auth errors from whichever probe is attempted are final. Byte-moving and object-mutating calls (`read_*`, `write`, object `delete`, `copy`, `rename`, `update_metadata`) also keep `foo` and `foo/` distinct object keys.

**Marker folding and inferred-directory stat.**
The dispatcher's `list_page` post-processor (see
`fold_markers_and_infer_subdir_kinds` in
`ovstorage-core/crates/ovstorage/src/routing.rs`) handles marker
folding. On flat backends
(`Capabilities.has_real_directories == false`) and non-recursive
lists, the dispatcher promotes zero-byte `dir/`-keyed objects to
directory `ObjectInfo` values with `kind = ObjectKind::DirectoryMarker`,
folding any matching inferred-directory peer to carry the marker's
mtime / etag / system_metadata, and tags any remaining directory
`ObjectInfo` still marked `File` as `ObjectKind::DirectoryInferred`.
Real-directory backends (`file`, Azure HNS, Nucleus) are
pass-through; plugins are expected to populate `ObjectKind::Directory`
on directory `ObjectInfo` values themselves. Recursive flat-backend
lists keep real marker objects as `DirectoryMarker` and include
inferred ancestors implied by returned descendants as
`DirectoryInferred`; exact duplicate concrete/inferred entries are
folded so the concrete fact (`Directory` or `DirectoryMarker`) wins.
Inferred-directory
`stat` (`ObjectKind::DirectoryInferred` from a bounded prefix-list
probe) is a plugin-side concern (the dispatcher cannot probe a flat
backend without a plugin call).

In a `list`, when a marker `ObjectInfo` address matches an inferred directory `ObjectInfo` address byte-for-byte (S3's `team/` zero-byte object alongside its `team/` common prefix), the dispatcher suppresses the inferred entry and keeps the marker's `ObjectInfo` (mtime, etag, system metadata, user metadata). This is what makes `populates_subdirectory_metadata` true on flat backends that follow the convention — the marker's mtime *is* the directory's mtime, since that is what the backend's own UIs already display. Recursive callers that perform destructive subtree workflows must branch on `ObjectInfo.kind`: delete files with `delete`, and remove directory representations with `delete_directory` in the directory phase.

`stat` on a directory address follows the same visible-directory model as `list`. `ObjectInfo.kind` is `ObjectKind` (`File` / `Directory` / `DirectoryMarker` / `DirectoryInferred`). Real-directory backends return the directory inode's `ObjectInfo` with `kind = ObjectKind::Directory`. Flat backends first check for an explicit marker object; if one exists, they return that marker's `ObjectInfo` with `kind = ObjectKind::DirectoryMarker`. If the marker lookup reports "not found", the plugin may issue one bounded prefix-list probe (`prefix = <directory address>`, for example limit two results) to determine whether the namespace changed or descendants exist. If that probe returns the marker itself, `stat` returns marker info. Otherwise, if the probe finds at least one descendant, `stat` succeeds with an inferred directory `ObjectInfo`: `kind = ObjectKind::DirectoryInferred`, empty etag, and absent user metadata. If the bounded probe proves neither marker nor descendant exists, `stat` returns `NotFound`. If the backend refuses the bounded list because the caller lacks list permission, `stat` returns the corresponding permission/auth error rather than guessing. Backends should not perform an unbounded scan for directory `stat`.

**Full metadata mode.** `StatOptions.full_metadata` and `ListOptions.full_metadata` share the same meaning: spend extra backend calls when needed to return the richest `ObjectInfo` the backend can observe. The default `false` is the cheap path. `list(full_metadata = false)` returns whatever the backend's list response naturally includes: typically address, size, last-modified, sometimes a system etag, sometimes a version identifier. Fields absent from the list response stay `None`. `list(full_metadata = true)` may issue a per-entry `stat` and fill in every etag/version, `system_metadata`, and `user_metadata` field the backend's stat path supports — higher latency by O(N) `stat` cost, in exchange for fuller `ObjectInfo` per entry.

**List-backed object `stat`.** The dispatcher keeps a small, in-memory, TTL-bounded, LRU-bounded cache of one-level list results and may answer exact object `stat` from that parent listing when `StatOptions.full_metadata = false`. This is intentionally an object-only optimization: a successful `stat("s3://bucket/team/a.usd")` can be satisfied by `list("s3://bucket/team/")` because callers that stat one child usually stat more children in the same folder. Directory-form `stat(".../")` is not answered from the parent list cache, because implicit folders and flat-store markers make folder existence harder than object existence.

Eligibility is conservative. The address must be non-directory form, must have no query string or fragment, `full_metadata` must be false, and the route must have `supports_list = true` plus `wants_list_backed_stat = true`. The first bit says the route can list children; the second says the backend wants the dispatcher to use that list as a stat accelerator. Version-selected URLs such as `...?versionId=...` never use the list cache: a versioned object URL will not appear as an entry in an unversioned parent listing, so looking it up there would be a guaranteed false miss. If the parent list fails or does not contain the child, the dispatcher falls back to the exact `StorageBackend::stat` path before trying the slash-form directory fallback for `stat("foo")`. When `full_metadata = true`, the dispatcher bypasses list-backed stat and asks the backend's stat path directly.

Only file entries are cached. Directory-kind list results are deliberately ignored: creating `a/b/c.txt` implicitly creates `a/` and `a/b/` on flat stores, and caching those inferred folders would require provider-specific marker and descendant rules. A cached list entry may carry only the cheap metadata that `list` returned. Callers that need a backend-specific optional metadata key should treat absence the same way they already treat absence on a cheap list entry unless the route's capability promises that key is populated.

Invalidation is coarse by design. Any successful object write, delete, copy destination, rename source/destination, or metadata update dirties the entire immediate parent folder's cached listing. Recursive directory delete additionally dirties cached folders under the removed prefix. Change notifications should follow the same parent-folder dirtying rule instead of patching individual entries: at-least-once feeds can deliver self-notifications late, self-created and remote events can interleave, and client clocks cannot always be trusted enough to sort them perfectly. A notification is a freshness hint, not a proof that an older cached child entry should be resurrected.

**Returned addresses are caller-facing.** The plugin returns each child as an `ObjectInfo` whose address is in the resolved backend namespace and inside the requested prefix ([ovstorage-plugin](../ovstorage-plugin/README.md)). The dispatcher projects that address back into the caller-facing namespace, so an operator reading the result sees URLs in the same form they passed in — not the plugin's internal backend form. A backend-returned address outside the requested scope is an `Internal` backend contract violation. UI labels are derived from the parent and child addresses, not returned as separate fields.

**Paging.** `ListOptions` carries `max_results: Option<u32>` and `page_token: Option<String>`. `Storage::list` returns the unpaged vector for in-process Rust callers. `Library::list_page` applies the same options and returns a finite `ListPage { items, next_page_token }` for bindings and RPC-style callers. The page token is the next zero-based item offset encoded as a string; it is intentionally opaque to callers so backends can replace it with provider-native cursors without changing the public shape.

**`list_versions`.** Resolves the object address once and calls the plugin's `StorageBackend::list_versions`. Each plugin result is an `ObjectInfo` whose address is the backend-native version-pinned address for that version; the dispatcher projects only the route prefix back into the caller's namespace. The full version history is returned regardless of any version-modifier query param on the caller's address — callers asking "does this version exist?" use `stat` (which honors the modifier) or `get_latest_version`. Version order is not normalized by the dispatcher; callers that need a stable order either sort by `ObjectInfo.mtime` / `ObjectInfo.version` themselves or consult `Capabilities.version_list_order` and use the backend's native order when it already matches.

**`get_latest_version`.** Resolves the address and calls the plugin's `StorageBackend::get_latest_version`. When the input already carries a version pin the plugin returns that exact version's `ObjectInfo`; otherwise it returns the current head's `ObjectInfo` with a version-pinned address. The dispatcher projects the returned address the same way `list_versions` does. Capability-gated on `supports_version_listing`; plugins that do not implement it return `Unsupported`. Useful as a one-call "pin to the current head" operation without paging through the full version list.

**`copy`, `rename`.** Resolve both addresses. If both resolve to the same backend instance and the plugin advertises `supports_server_side_copy` / `supports_server_side_rename`, the dispatcher hands both addresses to a single `StorageBackend::copy` / `StorageBackend::rename` call and the backend executes the operation server-side (e.g., S3 `CopyObject`, GCS rewrite). Otherwise the dispatcher executes `read` from `src` followed by `write` to `dest`, then (for `rename`) `delete` of `src` — the same `WriteResult` either way, with the cache populated on the way through. Two-address operations split into per-side authz checks; denial on either side fails before plugin dispatch.

**`create_directory`, `delete_directory`.** Write or remove **whatever the backend uses to represent a directory natively**. On `file`, ADLS HNS, and Perforce that is a real directory inode (`mkdir` / `rmdir`). On S3, GCS, and Azure flat — backends with no native directory concept but a widely-used emulation convention — the plugin writes or removes a zero-byte marker object whose key ends with `/`, the same marker the S3 console, GCS console, and rclone produce. The library does not invent a marker convention of its own; it follows whatever the backend's tooling already uses.

`create_directory` makes the requested directory exist and is idempotent when that directory representation already exists, but "parent creation" depends on the backend's directory model. Real-directory backends create missing parent directories recursively up to the resolved route/root, stopping at the route's configured root/address root and never creating above it. Flat object stores write only the requested marker object: creating `s3://bucket/a/b/c/` writes the `a/b/c/` marker, and the normal prefix-listing rules make `a/` and `a/b/` appear implicitly without additional marker objects. Existing incompatible non-directory objects still surface a typed backend error.

`delete_directory` is **non-recursive**: `DeleteDirectoryOptions` is a unit struct, and only the backend's directory representation is removed. On real-directory backends, a non-empty directory fails with `DirectoryNotEmpty`. On flat backends, the marker is removed and objects under the prefix are unaffected; the directory may still appear in subsequent `list` results because flat backends report a prefix as structurally present whenever any object's key starts with it, marker or no marker.

Subtree delete is host-side composition: callers (or the dispatcher when it owns the workflow on behalf of a higher-level API) walk the subtree with `list(recursive: true)`, issue `delete` for `File` entries, remove nested directory representations deepest-first with `delete_directory`, and finally call `delete_directory` on the requested directory representation. The operation is **not atomic** across the subtree: if a later child delete fails, already-deleted children remain deleted and the caller receives the typed failure with the `ObjectAddress` / `ResolvedTarget` that failed.

**`update_metadata`.** Takes metadata changes inline on `UpdateMetadataOptions`: `user_metadata_set`, `user_metadata_remove`, and an optional `message` annotation that backends with native commit-message support (Nucleus checkpoints, etc.) attach to the update. Keys appearing in both `user_metadata_set` and `user_metadata_remove` fail `InvalidArgument` at the boundary — the update is rejected before the plugin sees it. Backends that patch natively (`supports_native_metadata_patch`) translate the update into the backend's own add/remove API; backends that emulate via rewrite (`supports_metadata_rewrite_emulation`, S3) read the existing metadata, apply the update in memory, and write the result. The dispatcher honors the `allow_rewrite_emulation` flag — set to `false` against an S3-style backend, the call returns `Unsupported` rather than triggering a rewrite. The returned `ObjectInfo` reports explicitly whether the update produced a new `etag`, a new `version`, or new bytes (the rewrite-emulation case). Backends that patch natively typically advance just `etag` and `version`; rewrite-emulation produces a new object version, with the same content-derived size and mtime as before.

**`check_access`.** Resolves the address and asks the route's backend for an access decision. The `file` backend answers from filesystem existence plus the readonly bit: missing files deny read; readonly files deny write and metadata update; readonly files or readonly parents deny delete. Capability `supports_access_check` advertises whether the call works on this route at all. Two-address operations (`copy`, `rename`) remain caller-composed: callers ask `check_access(src, [Read, Delete])` and `check_access(dest, [Write])` and reason about the conjunction themselves.

**`watch_directory`.** Opens a change-notification stream under the given prefix. The dispatcher resolves the prefix, calls `StorageBackend::watch_directory`, projects backend event addresses into caller-facing `ObjectAddress` values, and forwards `Lapsed` events unchanged. Any object event dirties the immediate parent folder in the list-backed-stat cache as a unit. `watch_directory` streams are at-least-once with explicit gap signaling: events are best-effort; ordering within a single object's URL is preserved when the native feed preserves it; total ordering across a prefix is **not** guaranteed; whenever the plugin knows it has dropped events it emits `ChangeEvent::Lapsed { since, cursor }` and the caller is responsible for re-listing if correctness matters. A `watch_directory` stream stays open until the caller drops it. Hard failures surface a typed `Result::Err` and end the stream.

`WatchDirectoryOptions { since: Some(cursor), .. }` resumes from the position the cursor encodes. If the backend can honor the cursor, the stream replays events from there forward. If it cannot — backend doesn't support resume, cursor is too old to be retained, plugin was reloaded — the stream's first event is `ChangeEvent::Lapsed { since: cursor_time, cursor: <fresh> }` and the stream proceeds from "now."

**`capabilities_for(prefix)`** returns the capabilities of the backend behind whichever route covers `prefix`. Capabilities belong to the configured plugin instance (the backend), not to individual objects, so callers look them up once per route — typically at startup, caching the result against the prefix they care about. If a deployment needs finer granularity (per-bucket versioning, per-container hierarchical namespace), the operator configures separate backends with separate route prefixes; each one is a separate route, addressable through `capabilities_for` with its own prefix.

### Routing dispatch

Routing is **prefix-only and longest-prefix wins**. Equal-prefix conflicts are resolved by source priority. The dispatcher computes the routing table from three sources, all producing rows keyed by **absolute `ObjectAddress`**:

1. **Static rows** — programmatic config, env, project, user, machine config. `RouteSource = Static { layer }`.
2. **Connection-contributed rows** — every address returned by an active connection's `StorageBackend::address_roots` ([ovstorage-plugin](../ovstorage-plugin/README.md)) becomes a row. `RouteSource = ConnectionContributed { connection_id }` for direct connections, `BrokerDelivered { broker_principal, connection_id }` for addresses flowing in through a `broker-client` connection.
3. **Alias rows** — every alias produces a row whose `from` is the row's address and whose `to` is an `ObjectAddress` somewhere else in the table. `RouteSource = Alias { to, alias_source }`. Static aliases come from operator config (the `rewrite_to` mechanism makes them first-class rows alongside the others); runtime aliases come from `add_alias`.

Rows have the uniform shape defined above in [Routing-table types](#routing-table-types). Alias rows have `backend_instance: None` (they don't terminate; they redirect). Resolution uses one rule: **longest matching prefix wins**, regardless of source.

**How the resolved URL is built.** The dispatcher does a string-level prefix swap: it replaces the matched route prefix with `rewrite_to` (or leaves the URL alone, when `rewrite_to` is absent). The result is the **resolved URL**, and it's what `ResolvedTarget.resolved_address` carries. The plugin parses the resolved URL with its own scheme-specific parser, so `rewrite_to` must produce a URL the plugin understands — typically a scheme the plugin advertises (`file:`, `s3://`, `gs://`, `azure://`, `https://`).

**How the plugin uses it.** The plugin reads the resolved URL together with its registered backend config (credentials, region, endpoint, and any pinned identifiers like `bucket`, `account`, or `container`). Where both could supply the same fact, the config wins. So `https://files.example.com/path/to/foo` reaching an `s3` plugin with `bucket = "customer-uploads"` and `endpoint = "https://files.example.com"` operates on `customer-uploads` regardless of what the URL host looks like. The registration path rejects routes that contradict their backend config; the same failure surfaces at broker startup and at every `ovstorage-cli --config PATH` invocation.

`broker-client` is the one route shape that typically has no `rewrite_to`. It forwards the caller's canonicalized URL upstream verbatim, and the upstream broker runs the same matching logic against its own routing table.

#### Conflict resolution

Two rows with the *same* address:

- **Static vs. connection-contributed at the same address:** the static row wins. An operator who hard-coded `s3://acme-prod/` in their config has expressed a deliberate preference; a connection contribution does not override it. The contributed row is dropped from the table, and `list_address_roots` returns only the static one.
- **Two connection-contributed rows at the same address:** the connection-add order wins, with a warning emitted on the first observation of the conflict. The losing row is dropped. We expect this to be rare in practice — local connections typically target distinct buckets — but the deterministic tiebreak avoids surprise.
- **An alias and a non-alias row at the same address:** the non-alias row wins. An alias whose `from` collides with an existing route is dropped with a warning. Operators who really want to *replace* a published address with an alias have to remove the original first.
- **Two aliases at the same address:** add-order wins; later one rejected with a typed error if added at runtime, warning if discovered at startup.
- **Two static rows at the same address:** an error today; unchanged.

Different addresses never conflict: longest-match handles them. A static `s3://acme-prod/team-a/` and a contributed `s3://acme-prod/` happily coexist, with `team-a` requests going to the static row's backend and everything else under the bucket going to the contributed row's backend.

#### Resolver rule (visibility and aliases)

Once the longest-matching row is selected, the resolver applies these rules in order:

1. **If the winning row is an `Alias`:** rewrite the caller URL by swapping the alias's `from` prefix for its `to`, and dispatch the request as though the caller had typed `to`. **Single-resolve only:** if the resulting URL also matches an `Alias` row, the request fails with `AliasChainTooLong`. Single-resolve is enforced at `add_alias` time when the target exists (the API rejects an alias whose target is itself an alias) and at resolution time otherwise. Visibility on the *target* row is **ignored** for alias-mediated dispatch.
2. **If the winning row is `Suppressed` and reached by direct match (not via an alias):** the resolver returns `NotConfigured` to the caller. The connection (if any) is not dispatched to. This is what makes "completely hidden and unroutable directly" work: callers who guess the URL get the same response as they would for a totally-unconfigured prefix, while alias-mediated reads continue to dispatch through it normally.
3. **If the winning row is `Visible` or `Hidden`:** dispatch normally. Visibility only affects listing (`list_address_roots`); it does not affect resolution.

A consequence worth naming: **suppression operates on the row that *won* resolution, not on rows that lost.** A `Suppressed` row at `azure://account/internal-secrets/` shadows a `Visible` row at `azure://account/`, so a request for `azure://account/internal-secrets/foo` returns `NotConfigured` rather than falling back to the more general `Visible` row.

A second consequence: **dangling aliases** (rows whose `to` doesn't match any other row at resolution time) return `NotConfigured` to the caller. `add_alias` permits dangling aliases at creation, since an app's first-run wizard can `add_alias("assets://my-app/", to: "file:/tmp/uninitialized/")` before the user has actually picked a directory.

`set_address_visibility` is exact-row only. It takes the `ObjectAddress` of one existing routing-table row and flips that row between `Visible`, `Hidden`, and `Suppressed`; it does not accept wildcard or prefix patterns. Operators who want a whole subtree hidden define a row at that subtree prefix and set visibility on that row.

#### Population and updates

Static rows from `LibraryBuilder` and per-connection
`StorageBackend`-reported `address_roots` are bound at
`add_connection` time (`Library::add_connection_routes`).
`Library::route_epoch()` is monotonic and bumps on every routing
mutation: connection add/remove, alias add/remove, visibility
flip, and every applied frame from a backend's
`watch_address_roots` stream. Backends whose
`Capabilities::address_roots_are_dynamic = true` open the
server-streaming `Backend::watch_address_roots` SPI; the host
spawns a per-connection watcher task that translates each
`AddressRootsChange::Snapshot` / `Added` / `Removed` frame into
route-table mutations under the route lock. The watcher task is
torn down by cancelling its token at `remove_connection` time.
The `broker-client` plugin (REMOTE) wires this through to the
`WatchAddressRoots` gRPC RPC, emitting `Snapshot`-on-subscribe.
Re-subscribe on stream error is **not implemented** — a
stream-error logs and stops bumping `route_epoch` for that
connection until the connection is re-added.

The public `Library::watch_address_roots` stream emits full
`Vec<AddressRoot>` snapshots: one on subscribe, then one after each
route-table mutation. It covers connection-contributed roots, aliases,
visibility changes, and backend dynamic-root updates, so consumers can
replace their local table rather than reason about per-row diffs.

At library init, every row registered through `LibraryBuilder` is bound. Then for every active connection registered by the caller or delivered by a broker, the dispatcher reads the `address_roots: Vec<Url>` field on the `BackendInstance` returned by `StorageBackendFactory::instantiate` and merges those absolute addresses into the table per the rules above. The merge bumps the table-wide `route_epoch` counter ([ovstorage-cache.md "SQLite schema"](../ovstorage-cache/README.md#sqlite-schema-sketch-spec--current-schema-is-much-smaller)) exactly once per init.

For connections whose backend has `address_roots_are_dynamic = true`, the dispatcher opens a `StorageBackend::watch_address_roots(ctx)` stream and applies `AddressRootsChange::Added` / `Removed` / `Snapshot` events to the table as they arrive. Each applied change bumps `route_epoch`. Connections without that capability are called once at connection-add time and not re-polled — their answer is treated as static for the connection's lifetime.

Events that bump `route_epoch`:

- route / connection registration change
- connection add / remove / credentials updated
- `watch_address_roots` event applied (Added / Removed / Snapshot)
- alias add / remove, visibility flip
- plugin reload or backend failure that drops the connection

A connection whose `address_roots` returns an error contributes no rows and is logged; the rest of the table is unaffected. A connection whose `watch_address_roots` stream errors **logs and ends the subscription** — automatic re-subscribe with backoff is **not implemented** today (see `library_helpers.rs::spawn_address_roots_watcher`). The route table for that connection stops bumping `route_epoch` after the stream-error until the connection is re-added.

`broker-client` is the canonical case for `address_roots_are_dynamic = true`: every address the broker publishes for the principal becomes a row with `RouteSource = BrokerDelivered { broker_principal, connection_id }`. Requests matching one of those addresses go through `broker-client`, which translates them into the appropriate broker RPCs.

### Authentication

Authentication is the library-side machinery that hands a plugin valid credentials before the plugin issues a request. Cross-process serialization of refresh races (the `flock` + SQLite `BEGIN EXCLUSIVE` mechanism, and the `auth.sqlite` schema itself) lives in [ovstorage-cache](../ovstorage-cache/README.md); the OS keyring and the keyring-handle row that points to it are how persisted refresh tokens reach the library. Per-plugin specifics — Nucleus's four flows, S3's `aws-config` chain, Azure's `DefaultAzureCredential`, GCS's ADC chain — live in each `plugin-*.md`. Brokered-mode auth — where the broker holds the access token and the library only ever sees `AuthEvent`s — is the broker's concern, not the library's.

#### OAuth flow library API

`OAuthFlow::pkce(BackendId, redirect_base)` and
`OAuthFlow::device(BackendId)` live in `ovstorage::auth::flow`, with
`run() -> BoxStream<Result<AuthEvent>>` driving a loopback
redirect listener (PKCE) or RFC 8628 device-code polling. Wired
into `ovstorage-plugin-broker-client::Factory::authenticate` for
the app→broker leg. Per-user upstream OAuth runs end-to-end:
the `OAuthCredentialProvider` (`auth::oauth_provider`) carries
`build_flow()` + `accept_credential()` methods the broker daemon
drives via its `[oauth_providers.<name>]`-fed
`OAuthProviderRegistry` plus the streaming `Auth` RPC and
`RegisterCredential` round-trip over gRPC. The same machinery
handles multi-tenant SaaS and the render-worker shape — workers
and a coordinator that share a `PrincipalView` at the broker
share the same `(BackendId, PrincipalView)` cache slot.

Test fixtures: `ovstorage::auth::flow::test_support::FakeIdp`
(gated behind the `test-support` feature) is the in-process fake
IdP downstream test crates use; broker tests opt in via
`features = ["test-support"]` in `[dev-dependencies]`.

Any plugin that needs an OAuth flow drives it through the library's `OAuthFlow` API. `broker-client` uses it during `StorageBackendFactory::authenticate` to log a user into the broker; the `nucleus` plugin uses it to drive the SSO and device-flow paths; plugins that need PKCE or device flow against their backend's authorization server reach for the same surface.

```text
pub struct OAuthFlow { /* opaque */ }

impl OAuthFlow {
    pub fn pkce(backend: BackendId, redirect_uri: Url) -> Self { /* ... */ }
    pub fn device(backend: BackendId) -> Self { /* ... */ }

    pub async fn run(self) -> Result<BoxStream<Result<AuthEvent>>, AuthError> { /* ... */ }
}
```

`AuthEvent` ([ovstorage-plugin](../ovstorage-plugin/README.md)) carries the `OpenBrowser { url, expires_at }` / `DeviceCode { user_code, verification_url, expires_at, interval }` / `Progress` / `Succeeded` / `Failed` / `Cancelled` variants the connection-authentication API ([ovstorage-plugin](../ovstorage-plugin/README.md) § "Connection authentication types") emits, so an application consuming a `Library::authenticate_connection` stream sees the same shape regardless of which plugin drove the flow underneath. `Succeeded` populates the same `auth.sqlite` row whether the flow ran inside `Library::authenticate_connection` or was driven directly by a plugin.

#### Credential providers

The `CredentialProvider` trait plus five built-in providers live in
`ovstorage::auth::provider` (`EnvProvider`, `KeyringRefProvider`,
`OsKeyringProvider`, `CallbackCredentialProvider` for closure-driven
external resolvers) and `ovstorage::auth::oauth_provider`
(`OAuthCredentialProvider` for warm refresh-token grants).
Cold-start interactive flows (`OAuthFlow::pkce` / `::device`) are
not driven from `resolve()`; they run host-side via the streaming
`Auth` RPC and land tokens through
`OAuthCredentialProvider::accept_credential`. See
`LibraryBuilder::with_credential_providers` /
`with_credential_callback` for chain registration and
`Library::resolve_credentials` / `Library::set_credential` for the
entry points. Backend-specific provider chains (cloud SDKs,
Nucleus pipeline) remain per-plugin and are not on the trait.

Direct-mode credentials reach the plugin through the `CredentialProvider` trait, which abstracts over concrete sources:

```text
#[async_trait]
pub trait CredentialProvider: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;
    async fn resolve(&self, backend: &BackendId, principal: &PrincipalView) -> Result<ResolvedCredential, CredentialError>;
}

pub struct ResolvedCredential {
    pub bytes:       SecretBundle,
    pub expires_at:  Option<SystemTime>,
    pub source_name: String,                   // for audit / tracing; never carries token bytes
}
```

Generic built-in providers — usable by any plugin regardless of backend kind:

- **Env-var** — reads named environment variables according to the backend's expected schema.
- **Keyring reference** — a caller, CLI adapter, or broker adapter supplies OS-keyring key names rather than inlined secret bytes. The provider reads the keyring entry whose name the registered connection holds; the secret bytes never appear in route or connection metadata.
- **OS keyring** — uses the `keyring` crate against macOS Keychain, Windows Credential Manager, Linux Secret Service / `kwallet`. Persistent-connection state (`ConnectionRequest.persist` in [ovstorage-plugin](../ovstorage-plugin/README.md) § "Connection-management types") writes through this provider.

Backend-specific provider chains — AWS `aws-config`, Azure `DefaultAzureCredential`, GCS Application Default Credentials, Nucleus's keyring + nonce-subscription pipeline, Vault / cloud secret managers loaded as their own backend kinds — are documented in their respective `plugin-*.md` files; each implements the same `CredentialProvider` trait.

URL-prefix → credential-provider mapping is part of the registered backend configuration. The actual TOML schema uses `[[connections]]` / `[[routes]]` (matching `LibraryConfig`); the snippet below is conceptual pseudocode showing the field shape rather than valid TOML:

```toml
# pseudocode — actual TOML uses [[connections]] (see § "Configuration").
[[backend]]
name      = "corp-prod-s3"
kind      = "s3"
profile   = "corp-aws"                # provider-specific selector
endpoint  = "https://s3.us-west-2.amazonaws.com"
```

#### Resolved-credential caching

`ovstorage::auth::cache::CredentialCache` carries `cred_epoch`,
`refresh_skew`, and `static_cred_ttl`; concurrent stampeders
collapse via per-key single-flight. Auto-invalidation on
`PermissionDenied` / `AuthRequired` / `AuthExpired` is wired
through `Library::with_route_retry` in `library_helpers.rs`:
every retryable dispatch site invalidates the
`(BackendId, PrincipalView)` cache entry once on a credential
failure and re-runs the operation a single time before
propagating. `Library::invalidate_credentials` is also available
for callers that want to invalidate eagerly. Durable persistence
to `auth.sqlite` (`secret_tokens` row — the actual keyring
secret bytes, base64-JSON-encoded `SecretBundle`) lives in
`AuthDbCredentialPersistence`; wire it via
`LibraryBuilder::with_credential_persistence(secret_store, refresh_lock)`
so refresh tokens survive process restarts. The cache seeds its
in-process `cred_epoch` from `MAX(secret_tokens.cred_epoch)` at
open so the counter strictly grows across restarts.

The library caches the last-resolved credential per `(backend_id, principal)` keyed on a monotonic `cred_epoch` plus `expires_at` from the provider. The cache layers L1 (in-process `HashMap`) over L2 (`auth.sqlite` + OS keyring) when persistence is wired; without persistence it is in-process only. TTL rules:

- Provider returned `expires_at` → cache until `expires_at − refresh_skew` (default `refresh_skew = 60 s`).
- Provider returned no `expires_at` (raw static secrets from env / keyring references) → cache for `static_cred_ttl` (default `300 s`) so rotation through credential update or broker reload is seen promptly. Zero disables caching.
- STS / IAM-instance-metadata / Azure IMDS / GCS metadata → cache until backend-reported expiry minus `refresh_skew`; on miss, a single in-process mutex serializes the refresh (no flock needed — these are process-local and don't hit the state DB).
- OAuth access tokens are a separate code path: the state DB owns freshness ([ovstorage-cache](../ovstorage-cache/README.md)), and the in-memory cache is a thin read-through mirror sharing the same `expires_at − refresh_skew` rule.

A credential that produces `PermissionDenied`, `AuthRequired`, or `AuthExpired` on use is immediately invalidated from the in-process cache and re-resolved once (bounded by the same single-flight mutex). Repeated failures propagate to the caller without further re-resolution in the same request.

Direct mode does not cache authorization decisions. The library caches credentials and address-root metadata, but every actual I/O operation is authorized by the backend it reaches, and stale cached address roots only populate navigation: reads through a stale row return `AuthRequired` until the connection re-authenticates. Cached-authorization grace windows are a broker-side policy-epoch concept, not a direct-mode library setting.

#### OAuth flows

`OAuthFlow` and `Library::authenticate_connection` drive three flows:

- **PKCE auth-code** (RFC 7636). Default for desktop and CLI logins. The flow opens a loopback listener on `127.0.0.1:<random>`, surfaces `AuthEvent::OpenBrowser { url, expires_at }`, waits for the redirect, exchanges the code, stores the refresh token in the keyring.
- **Device authorization** (RFC 8628). Used when the user can't open a browser on the same host (SSH session, headless server, container shell). The flow surfaces `AuthEvent::DeviceCode { user_code, verification_url, expires_at, interval }`; the user types the code on a different device; the library polls the token endpoint at `interval` until the code is entered or expires.
- **Token exchange** (RFC 8693). Used by the broker, exchanging a workload-identity token for a backend-specific token at the cloud's STS endpoint. The same code path inside `ovstorage` serves both library-mode and broker-mode token exchange.


##### Interactive-auth capability

`LibraryBuilder::interactive_auth_capability(kind)` takes
`impl Into<Option<InteractiveAuthCapability>>` — `None` falls
through to env / config / smart default. The capability is
threaded through `Factory::authenticate(connection, capability, cancel)`
and carried over the broker leg via the
`x-ov-iauth: browser|headless|none` gRPC metadata header
(HPACK-indexed by Tonic's interceptor).
`OAuthCredentialProvider::build_flow(backend, capability) -> Result<OAuthFlow, Error>`
honors the matrix.

The host declares its interactive-auth surface up-front so plugins pick the right OAuth subflow (or fail fast) without round-tripping a useless `OpenBrowser` event. Three values:

- **`InteractiveAuthCapability::None`** — CI, sandboxed services, render workers, locked-down kiosks. **Blocks the interactive-flow entry point only**: plugins' `Factory::authenticate` returns `Err(AuthRequired)` immediately and emits no `AuthEvent`. Does **not** block non-interactive credential resolution — `CredentialCache` hits, the provider chain (including `CallbackCredentialProvider`), and proactive cache pushes via `Library::set_credential` continue to work normally. The external-token-injection pattern explicitly pairs `None` with a `CallbackCredentialProvider` whose closure delegates to a control-plane portal.
- **`InteractiveAuthCapability::Headless`** — SSH session, container shell, remote dev. Host can show URLs and codes for the user to act on a different device, but cannot bind a local 127.0.0.1 redirect listener. OAuth-IDP plugins use device flow (RFC 8628); PKCE is forbidden in this mode.
- **`InteractiveAuthCapability::Browser`** — desktop GUI, terminal on local workstation. Host can both launch a browser and bind a redirect listener. PKCE is preferred; a provider configured `OAuthStrategy::Device` falls through to device flow.

The broker propagates the capability via `x-ov-iauth: <browser|headless|none>` on every RPC; the client-side `AuthorizationInterceptor` attaches it once via Tonic's interceptor surface so HPACK indexing keeps the per-call cost at ~1-2 bytes after the first call on a channel. Absent metadata → `Browser` (default preserves existing behavior). Render-worker scenario: coordinator runs `Browser`; workers run `None` and surface `AuthRequired` cleanly without ever emitting an `OpenBrowser` event.

###### Precedence chain

`Library::open()` resolves the host's effective capability through four sources, highest priority first:

```text
builder > env var > config file > smart default
```

- **Builder** — `Library::builder().interactive_auth_capability(InteractiveAuthCapability::Headless)`. An explicit caller always wins; passing `None` (any `Option<InteractiveAuthCapability>`) is the canonical "fall through" signal.
- **Env var** — `OV_INTERACTIVE_AUTH_CAPABILITY=browser|headless|none` (lowercase; case-insensitive in practice). Read at `open()` time. Invalid values log a `tracing::warn!` and fall through to the next source rather than failing startup — operator typos must not break boot.
- **Config file** — `LibraryConfig::interactive_auth_capability = "browser|headless|none"` (`InteractiveAuthCapabilityToml`). Hosts with a TOML loader forward the parsed value via `LibraryBuilder::with_config_capability(capability)`.
- **Smart default** — derived from OS-level signals (next section). Used when none of the above is set.

###### Smart-default detection

`auth::detect_default_capability(env)` consults, in order:

1. `CI` set to a truthy value (`1`, `true`, `yes`, `on`) → `None`. (GitHub Actions, GitLab CI, Jenkins, CircleCI, Buildkite all set `CI=true`.)
2. `SSH_CONNECTION` or `SSH_CLIENT` set → `Headless`. (Local browser is meaningless from an SSH session; user can still read URLs / codes.)
3. **Linux**: neither `DISPLAY` nor `WAYLAND_DISPLAY` set → `Headless`.
4. **Windows**: `SESSIONNAME` absent or starts with `Services-` (the non-interactive Session 0 shape) → `Headless`.
5. **macOS**: `Browser` (Aqua / Terminal.app is essentially universal).
6. **Otherwise**: `Browser`.

Detection deliberately errs toward the *less capable* mode whenever a positive GUI signal is missing: a wrong `Headless` just asks the user to manually open a URL, while a wrong `Browser` is broken auth on a server. Operators force a specific value via `OV_INTERACTIVE_AUTH_CAPABILITY` when the heuristics misfire (Wayland-only sessions without `WAYLAND_DISPLAY`, Windows servers running interactive RDP, etc.).

The detection helper takes an `EnvSource` trait (production: `StdEnv` wrapping `std::env::var`; tests: `MockEnv` backed by a `HashMap`) so unit tests pin behaviour without mutating real process env.

```text
let lib = Library::builder()
    .interactive_auth_capability(InteractiveAuthCapability::Headless)  // optional override
    .open()?;
```

##### External token injection

`LibraryBuilder::with_credential_callback(name, async |backend, principal| ...)`
registers a closure-driven `CallbackCredentialProvider` on the
chain. `Library::set_credential(backend, principal, credential)`
proactively populates the cache.
`with_credential_cache_durability(InMemoryOnly | Persistent)`
controls whether ephemeral hosts persist credentials.
broker-client's `update_credentials` rotates the bearer in
`DiscoveryState` so the next gRPC call uses the new token without
a 401 round-trip. Bindings: C ABI (`OvCredentialCallback`
continuation pattern), C++ wrapper (`std::future`-based
`CredentialCallback`), Python pyo3 (auto-detects
`asyncio.iscoroutinefunction`).

The customer use case: a locked-down browser-streamed VM with no UI, where credentials are minted by an external portal (across a WebRTC channel) and pushed proactively before expiry. `InteractiveAuthCapability::None` blocks the plugin's interactive entry point; the portal-driven `CallbackCredentialProvider` populates the cache on cache-miss / post-invalidation re-resolve, and `Library::set_credential` handles proactive pushes ahead of expiry.

```text
let portal = PortalClient::connect(...).await?;

let library = Library::builder()
    .interactive_auth_capability(InteractiveAuthCapability::None)
    .with_credential_cache_durability(CredentialCacheDurability::InMemoryOnly)
    .with_credential_callback("portal-fetch", {
        let portal = portal.clone();
        move |backend, principal| {
            let portal = portal.clone();
            async move {
                portal.fetch_token(backend, &principal).await
                    .map_err(|e| CredentialError::backend(format!("portal: {e}")))
            }
        }
    })
    .open()?;

// Background task: pump proactive token pushes from the portal.
tokio::spawn({
    let library = library.clone();
    let portal = portal.clone();
    async move {
        while let Some(push) = portal.next_token_push().await {
            let _ = library.set_credential(push.backend, push.principal, push.credential).await;
        }
    }
});
```

The continuation-callback pattern in the C/C++/Python bindings preserves the async-IO shape across the FFI boundary. `OvCredentialCallback.resolve(userdata, backend_id, principal_id, completion, completion_userdata)` returns immediately; the implementer fires `completion(...)` exactly once when the async work resolves. The Rust internal bridge uses `tokio::sync::oneshot` to bridge the cross-thread completion back into the host's async context. Cancellation is graceful — receiver-drop after `resolve` returned but before `completion` fired causes `Sender::send` to return `Err`, silently discarded.

**Refresh serialization (current).** `AuthRefreshLock::with_refresh` takes a per-`(backend_kind, connection_id)` advisory file lock via `fs2`, re-checks the `refresh_records` snapshot inside the critical section, runs the refresh closure once if stale, and persists the new snapshot before releasing. The current schema does **not** wrap the SQLite write in `BEGIN EXCLUSIVE` — it relies on a single `INSERT ... ON CONFLICT DO UPDATE` plus the file lock. **Target design:** wrap the IdP-call + token-persist in `BEGIN EXCLUSIVE` so refresh-token rotation is durable across a same-host crash; tracked under [implementor checklist](#oauth-refresh-races-causing-single-use-token-consumption-by-two-processes).

**OAuth material is never logged, never in errors, never in traces, never in `cache_root`.** The state DB holds only handles + metadata. The error-mapping layer ([ovstorage-plugin](../ovstorage-plugin/README.md) § "Error model") strips bearer tokens from any HTTP error before the typed error surfaces to the caller.

Interactive auth is never driven implicitly. At `load_config` time the host re-uses the silent path only — a connection with cached address roots whose silent probe fails is parked in `AwaitingAuth` with a stub backend on its cached routes; on subsequent dispatch the silent path retries (gated by a per-connection cooldown). The application decides when to invoke `Library::authenticate_connection`, which returns an `AuthEventStream` so the host can surface `OpenBrowser` / `DeviceCode` / `Progress` events through its own UI.

#### Connection lifecycle scenarios

The five concrete cases an application has to handle:

1. **First-time setup** — `Library::add_connection(request, _)` (or the CLI `connect` wizard) registers the connection, then the application calls `authenticate_connection(id)` and consumes the event stream to drive interactive sign-in. On success the cached top-level address roots are written to `auth.sqlite`. The CLI `connect` subcommand bundles both steps.

2. **Restart with a valid refresh token** — `load_config` calls `add_connection_lazy` per `[[connections]]`. The silent path refreshes the bearer from the OS keyring, `probe` + `instantiate` succeed, the real backend is installed and the cached address roots are refreshed. Application code does nothing.

3. **Restart with an expired refresh token** — silent probe fails with `AuthRequired` / `AuthExpired`. The library installs an `AwaitingAuthStub` on the cached routes and parks the connection in `AwaitingAuth { reason: NeverAuthenticated | RefreshTokenExpired }`. Subsequent dispatch attempts return the typed `AuthRequired` error. The application unblocks by calling `authenticate_connection(id)` and surfacing the resulting event stream — same code path as step 1. The CLI `reauth <name>` subcommand wraps this for the operator.

4. **Restart with a network-error backend** — silent `probe` / `instantiate` fails with a non-auth error (e.g. `BrokerUnavailable`, `Transient`). The library installs the same stub but parks the connection in `AwaitingAuth { reason: BackendUnreachable }`. Application code does nothing — the dispatcher retries the silent path on each new request, gated by a 10s per-connection cooldown to avoid probe-storms. When the network recovers (VPN reconnects, broker comes back up) the next request transparently swaps the stub for the live backend. No interactive auth is needed.

5. **Network recovers but the refresh token is now expired** — same shape as #3. The first post-recovery silent retry succeeds at the network layer but fails at the credential layer; the connection moves from `BackendUnreachable` to `NeverAuthenticated` / `RefreshTokenExpired`. The application drives `authenticate_connection(id)` exactly as in #3.

`Library::authenticate_connection` is the single application-facing entry that triggers a UI-bearing flow. Silent retries (steps 2, 4) happen transparently inside `with_route_retry`. The CLI `reauth <name>` subcommand exists purely as a convenience wrapper for step 3.

#### Substrate modules in `ovstorage::auth`

The mechanisms above are surfaced as three provider-agnostic modules that any plugin can pull in by depending on `ovstorage`:

- `ovstorage::auth::SecretStore` — OS-keyring-backed `(backend_kind, connection_id, field) → SecretBytes` storage. Entries are namespaced as `ovstorage:<service_namespace>:<backend>/<connection>/<field>` so a refresh token persisted by one process is visible to another process running under the same OS user. Missing entries return `Ok(None)`; keyring failures surface as `ErrorCode::CredentialUnavailable`.
- `ovstorage::auth::SecretStorage` — pluggable secret-bytes backend for the credential cache, selected via `LibraryBuilder::with_secret_storage(SecretStorageKind::OsKeyring | Database | External(_))`. `OsKeyringSecretStorage` (default) wraps `SecretStore` for single-host deployments. `SqliteSecretStorage` stores BLOBs in `auth.sqlite::secret_blobs` for multi-host / load-balanced broker deployments where every host shares one DB; encryption-at-rest is the operator's responsibility (filesystem FDE, sqlite-encrypt extension, or trusted-environment plaintext). `External(Arc<dyn SecretStorage>)` admits sibling-crate impls (e.g. a Postgres-backed implementation) without modifying this crate.
- `ovstorage::auth::AuthRefreshLock` — owns `<state_root>/auth.sqlite` (one row per `(backend_kind, connection_id)` recording the last refresh's `refreshed_unix_ms` and `expires_at_unix_ms`) and `<state_root>/locks/auth/<sha256>.lock` (per-`(backend_kind, connection_id)` advisory file lock via `fs2`). `with_refresh(backend_kind, connection_id, freshness_window, refresh_fn)` takes the file lock, re-checks the snapshot inside the critical section, runs the closure exactly once if the snapshot is stale or absent, persists the new snapshot, and releases. Concurrent processes/threads contending on the same `(backend_kind, connection_id)` collapse to a single closure invocation per `freshness_window`.
- `ovstorage::auth::pkce` — `pkce::generate()` returns a 96-character base64url verifier (~64 bytes of `OsRng` entropy) plus its `S256` challenge; `pkce::challenge_for(verifier)` is the bare transform for tests. Plugins driving authorization-code-with-PKCE or device-code flows on top of `AuthEvent::OpenBrowser` / `AuthEvent::DeviceCode` use this rather than re-implementing RFC 7636.

The substrate is provider-agnostic. Whether a given plugin opts in is documented in that plugin's per-crate doc; plugins that stay self-contained may use an in-process `Mutex` for refresh coalescing and forfeit cross-process serialization.

### Redirect follower

A `Redirect` is a pre-signed HTTP request the dispatcher executes directly through its in-process HTTPS client. The library doesn't need a backend-specific plugin to follow it — that's the whole point of the shape, and it's the same shape Direct mode uses (`ReadResult::Redirect`, [ovstorage-plugin](../ovstorage-plugin/README.md)). The broker is just a different *issuer*.

The dispatcher executes `request`, slices the body per `body_source`, parses response headers per `response_parsing`, and for write redirects extracts only the headers listed in `result_capture.headers` and at most `body_max_bytes` of the response body. It never inspects vendor-specific names directly. **The plugin (or broker) is the only component that has to know S3, GCS, Azure, etc. exist.**

**Wire-integrity checksums.**
The streaming-read substrate hands the host an async
`futures::Stream` the dispatcher consumes chunk-by-chunk without
buffering, and `ResponseParsing` carries the
`content_checksum_header` / `content_checksum_algorithm` pair
the plugin populates. The follower's `StreamingVerifier` hashes
chunks inline as they pass through, with bounded host memory: a
mismatch surfaces as `ContentChecksumMismatch` on the final
stream frame. SHA-256, CRC32C, and MD5 are dispatched natively
(GCS `x-goog-hash` multi-value parse + Azure `Content-MD5`);
algorithms outside that set degrade to pass-through (graceful)
so an unknown provider header doesn't reject a read for a
verifier-capability gap.

Some backends ship a per-response checksum header intended to verify the *transfer*: S3 `x-amz-checksum-sha256` when the object was uploaded with one, GCS `x-goog-hash: crc32c=...`, Azure `Content-MD5`, and similar. When the plugin's `ResponseParsing` declares one via `content_checksum_header` + `content_checksum_algorithm`, the dispatcher verifies it against the streamed bytes silently — a mismatch surfaces as `ContentChecksumMismatch` ([ovstorage-plugin](../ovstorage-plugin/README.md) § "Error model"); a successful read just means the bytes match the declared checksum, with nothing further reported. The verified value never lands on `ObjectInfo` as identity, since the check is about transfer correctness, not durable identity.

When the same backend value *also* has lasting use to the caller — S3's `x-amz-checksum-sha256` for downstream verification, GCS's `x-goog-hash` for replication tracking, Azure's `Content-MD5` for legacy compatibility — the plugin can route the header additionally through `checksum_headers`, so the parsed bytes surface in `ObjectInfo.checksums` under the corresponding normalized algorithm string. The dispatcher does nothing further with the value.

**Multipart writes flow as 3–4 batched exchanges over a single `Write` call**, because that's what the plugin emits — see [ovstorage-plugin](../ovstorage-plugin/README.md) for the example. For an S3 multipart upload the plugin emits, in turn: a one-redirect batch for `CreateMultipartUpload` (`BodySource = Empty`, `ResultCapture` capturing the `UploadId` from the response body); an N-redirect batch of `UploadPart` requests (`BodySource = UserBytes { offset, len }` per part, capturing each part's `ETag`); a one-redirect batch for `CompleteMultipartUpload` (`BodySource = Inline { bytes = "<CompleteMultipartUpload>...</CompleteMultipartUpload>" }`); and finally a `WriteResult`. In Direct mode the dispatcher executes each batch's redirects in parallel and feeds `Vec<RedirectResponse>` back into `continue_write`; in Brokered mode the same exchange is carried as `WriteRedirectBatch` / `RedirectResultBatch` on the wire. Single-PUT writes are the trivial case — one batch of one redirect (`BodySource = UserBytes { offset: 0, len: total }`), one result batch, then `WriteResult`.

`scope` has no cumulative byte or request cap by design. The library executes redirects directly against the cloud and refreshes them on demand using the same SQLite + flock pattern used for OAuth ([ovstorage-cache](../ovstorage-cache/README.md)). Redirect scope is over the provider-facing request the backend plugin minted; broker authorization is evaluated over the incoming caller-facing address.

The current broker protocol does not include redirect revocation. Redirects expire by their `expires_at` value; the library rejects expired redirects before issuing follower requests, and the broker controls future access by deciding whether to issue a replacement under the current `policy_epoch`. Byte-stream branches have no separate token to revoke — the stream is alive for the duration of the open RPC and is torn down when the broker decides authorization no longer holds.

Cancellation is threaded through the public byte-moving APIs and the backend SPI calls that mint redirects, but host-side redirect following and local materialization are a known gap: the redirect helper does not take the caller's `CancellationToken` or configure a per-request timeout on its shared HTTPS client. Dropping the caller future releases the caller, but an already-issued follower request can continue until the HTTP client completes or errors.

### Retries and idempotency

Retries are layered, and only one layer retries per logical call. The plugin SPI is the cheap-failure layer: a plugin that hits a `Transient`-class condition (network blip, `429`, `5xx`) returns the typed error immediately and never retries internally. The library / broker layer above it owns the retry policy, so tracing spans and broker diagnostic fields show one logical call with N annotated retry attempts rather than N opaque calls.

**HTTP redirects (Direct mode and library-following-broker-redirect).** The in-process HTTPS client retries idempotent requests — `GET`, `HEAD`, `PUT` of an exact body, `DELETE`, and any plugin-emitted redirect whose `body_source` is `Empty` or `UserBytes { offset, len }` against an unconsumed range — on `Transient`, HTTP 408 / 429 / 502 / 503 / 504, and connect/read errors. Backoff is exponential with jitter (initial 100 ms, cap 30 s, max 5 attempts by default) and honors a `Retry-After` header when present. Non-idempotent redirects — typically the multipart `Complete` step — are not retried; failure surfaces as `Transient` to the caller, which can re-issue the entire write if it chooses. If the final ABI grows an explicit retry hint on `Redirect`, that hint can narrow retryability but cannot make an otherwise non-repeatable body safe to replay.

**gRPC (library ↔ broker).** Standard tonic / hyper retry on `UNAVAILABLE`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED` for unary RPCs and for the open of streaming RPCs. Mid-stream failures are not retried — once `Read`, `Write`, or `WatchDirectory` is open, a failure surfaces to the caller, who decides. `BrokerUnavailable` is the terminal error after the retry budget is exhausted. Hedging is off by default (multiplies diagnostic events and credential issuance for negligible gain in a single-trust-scope broker); operators who want it set `[broker_client.hedge_attempts] = N`.

**Plugin SPI.** Plugins do not retry. They translate backend errors into the [ovstorage-plugin](../ovstorage-plugin/README.md) error taxonomy and return immediately. This keeps observability semantics consistent ("one `StorageBackend::read` call = one broker diagnostic event plus N retries visible in tracing spans on the caller side") and avoids two layers of independently-tuned exponential backoff fighting each other.

**Library-level SPI retry.** Idempotent `StorageBackend` calls dispatched by `Library` are wrapped in `with_route_retry` (`src/retry.rs`): `stat`, `read_*`, `list`, `list_versions`, `watch_directory` (open only), `delete`, `create_directory`, `delete_directory`, `update_metadata`, `check_access`, `copy`, `rename`. `write` retries only when the body is `Body::Bytes` or `Body::LocalFile` (replayable); `Body::Stream` gets a single attempt because the iterator has already been consumed. `continue_write` does not retry (non-idempotent multipart `Complete`). Mid-stream failures after the first chunk surface to the caller. `is_retryable` admits exactly `Transient`, `BrokerUnavailable`, `ResourceExhausted`, `DeadlineExceeded`, `CacheLockContention`, and `AuthorizationLeaseExpired` — `NotFound`, `PermissionDenied`, `PreconditionFailed`, `Conflict`, `Unsupported`, and the other permanent codes pass through immediately. The library retries on `BrokerUnavailable` from *any* plugin, not just `broker-client`; the policy treats "transient backend unreachable" identically regardless of which plugin emits it. `RetryConfig` (`initial_delay_ms`, `max_delay_ms`, `max_attempts`) is per-route under `[routes.retry]` and library-wide under top-level `[retry]`, with spec defaults (100 ms / 30 s / 5 attempts) when omitted. Tests use `fast_config()` (0 ms / 0 ms / 5) to exercise the path at full speed in CI.

When adding a new `Storage` method, decide whether it is idempotent: if yes, wrap the dispatch call with `with_route_retry`; if no, document why and call directly. Don't add retry inside plugins — the library owns the layer.

Defaults are ship-with-the-library; every knob (initial delay, cap, max attempts, hedge count) is configurable per route. A retry-and-idempotency audit verifies the policy holds across every plugin and the broker.

### Shutdown

The library's graceful-close deadline defaults to 30 seconds. Dropping a `Library` handle does not kill the process or forcibly stop unrelated application work; it stops accepting new library operations on that handle, asks in-flight operations to finish, and cancels anything still running at the deadline, subject to the redirect/materialization caveat above. Cache leases held by returned objects remain tied to their `Lease` values, not to this timer; staging left behind by cancelled writes is recovered by [ovstorage-cache](../ovstorage-cache/README.md)'s startup and GC rules.

### Observability

- **Structured tracing**: `init_tracing_from_env()` installs JSON structured logging to stderr and, when `OVSTORAGE_OTLP=1` or standard `OTEL_EXPORTER_OTLP*_ENDPOINT` variables are set, pushes spans through the OTLP HTTP/protobuf exporter. Dispatcher spans include redacted caller-facing addresses, resolved targets, matched route id, and cache decisions.
- **Metrics**: metrics are a broker surface. The library exports traces only; broker metrics are the broker's concern.
- **Health**: any successful CLI subcommand acts as a health probe — startup loading parses the active TOML, resolves env-var/keyring credential refs, and registers `[[connections]]` with the live library before dispatching, so a clean exit means the config is operational. The broker's `grpc.health.v1` surface is the broker's concern.
- **Diagnostic CLI** (`ovstorage` binary, see [ovstorage-cli](../ovstorage-cli/README.md)): the CLI ships `list-routes`, `list-backends`, `cache-status`, `state-status`, plus the `connect` / `write-config` configuration flow. For deployment-tool config validation, any `ovstorage-cli --config PATH` subcommand runs the full registration path and exits non-zero on any failure — no separate validate command needed.

Audit is broker-side; the broker daemon attaches audit-safe diagnostic fields. The library does not emit audit records itself; tracing spans and metrics are its observability surface.

The redaction guarantee is scoped to the `SecretBytes` type itself plus the tracing layer: `SecretBytes`'s `Debug` impl prints `SecretBytes(<redacted>)`, its `Drop` zeroizes the underlying bytes via the `zeroize` crate, and the `serde` impls reject serialization. Presigned URL query strings and `Authorization` / `Cookie` headers are stripped at the [ovstorage-plugin](../ovstorage-plugin/README.md) error-mapping boundary before they can reach tracing or any audit sink. The broker carries an `audit_id` string on each `RequestContext` and threads it into traces and the cross-process `pb::ErrorDetail` shape; there is no separate audit pipeline today — no `AuditRecord` type, no audit sink, and no compile-time `SecretBytes`-rejection mechanism for audit payloads. Such a pipeline (record schema, sink, and a proc-macro derive that fails to compile if a record contains a `SecretBytes` field) is tracked under broker / observability work; the redaction-first design intent is unchanged.

## Dependencies

In-workspace: [ovstorage-plugin](../ovstorage-plugin/README.md), [ovstorage-cache](../ovstorage-cache/README.md). The library registers backend instances through `LibraryBuilder` (rlib-linked factories via `register_backend_factory`, dlopen'd plugins via `register_plugin_path` / `register_plugins_from_dir`). `ovstorage::init_auth_substrate(Some(&path))` provides the host-callbacks substrate; it runs once per process before `Library::builder().open()`.

External (notable): `tokio` + `tokio-util` (async runtime + cancellation tokens), `reqwest` (HTTPS redirect following), `keyring` (OS-keyring-backed `SecretStore`), `rusqlite` + `fs2` (`auth.sqlite` + per-connection advisory file locks), `libloading` (dlopen plugin loader), `tracing` / `tracing-subscriber` / `opentelemetry` / `opentelemetry-otlp` (structured logs and OTLP traces), `parking_lot` (RwLock/Mutex for routes / aliases / connections), `serde` + `toml` (config deserialization), and `zeroize` (secret-bytes hygiene).

## Threat model

The library process is the trust boundary in Direct mode. Credentials in the process can be exfiltrated by anything that can read the process's memory or its OS keyring. Plugins loaded in-process share that trust — they can read credentials, follow OAuth flows, sign requests, and emit network traffic on the app's behalf. **Treat in-process plugins as trusted code, equivalent to your own application.**

In Brokered mode the library never holds long-lived provider secrets; it holds time-bounded redirects issued by the broker. **A compromised library process can exfiltrate redirects for the rest of their lifetime.** The exposure window is the redirect TTL.

**Local route registration as a trust surface.** Routes are local naming concerns; **broker authorization is enforced on the incoming caller-facing address** and the broker only dispatches addresses present in its own address table. Deployments control who can call route / connection registration APIs or edit broker / CLI adapter config that feeds those APIs. ovstorage is single-tenant by design and does not try to defend the routing table against principals who can already mutate it.

**Audit contains no token material (target).** Tracing spans, metrics, and audit records carry the redacted URL only — query strings and `Authorization` / `Cookie` headers are stripped before the record is constructed. *Target design:* the audit pipeline rejects records whose payload would otherwise contain a `SecretBytes` field at compile time. *Current state:* `SecretBytes` redacts in `Debug` (`SecretBytes(<redacted>)`), zeroes on drop, and does not implement `Serialize` — so a record-shape that tries to serialize one fails at runtime — but there is no audit pipeline / `AuditRecord` type / proc-macro derive in the workspace today.

**OAuth tokens leave the library only into the OS keyring (long-lived refresh token), `auth.sqlite` (handle only; never bytes), and the cloud provider's token endpoint over TLS.** The library writes nothing to `cache_root`, nothing to logs, and nothing to standard output beyond progress messages — the redaction guarantee from [ovstorage-plugin](../ovstorage-plugin/README.md)'s `SecretBytes` newtype applies inside every OAuth code path.

**Persistence requires a working OS keyring (current).** `add_connection(persist: true)` ([ovstorage-plugin](../ovstorage-plugin/README.md) § "Connection-management types") returns `ConnectionError::Internal { details: "secret persistence requires an OS keyring on this platform" }` on platforms without one. The implemented `SecretStorageKind` variants today are `OsKeyring` (default), `Database` (a `BLOB` column in `auth.sqlite`; encryption-at-rest is the operator's responsibility — `SqliteSecretStorage` does *not* encrypt), and `External(Arc<dyn SecretStorage>)` for caller-supplied impls. There is **no `EncryptedFile` variant** today — an `encrypted_file` fallback (AES-GCM with a key derived from the user's login token) is target design only.

**Audit records of `add_connection` would contain a credential hash, not the bytes.** *Target design:* compile-time rejection of `SecretBytes` payloads in audit records via a proc-macro derive. *Current state:* there is no `AuditRecord` type or audit pipeline in the workspace; `SecretBytes` redacts in `Debug` and refuses serialization, but the compile-time guarantee is design intent, not shipped.

## Conformance tests

This crate's conformance surface:

**HTTP/HTTPS routing**
- Route at `https://` matches every HTTPS URL; route at `http://` matches every HTTP URL.
- Route at `https://datasets.example.com/` matches that prefix only; other URLs return `NoRoute`.
- No route bound to the `http` plugin: every HTTP/HTTPS URL returns `NoRoute`.
- Non-2xx responses surface as typed errors (`NotFound`, `PermissionDenied`, `Transient`, …), not as body bytes.

**Routing-table merge**
- Merge correctness: with a static row at address `A` and a connection-contributed row at the same `A`, the static row resolves; `list_address_roots` reports only the static row.
- Longest-prefix correctness: with static `s3://b/team-a/` and contributed `s3://b/`, requests under `team-a/` route to the static row's backend; requests elsewhere under the bucket route to the contributed row's backend.
- Address-root-driven mutation: a test connection whose backend has `address_roots_are_dynamic = true` emits `Added` and `Removed` events; the library exposes the corresponding rows in `list_address_roots` and resolves requests through them within one `route_epoch` bump.
- Connection lifecycle: adding a connection produces rows for each address its backend reports, with a single `route_epoch` bump; removing it drops them all, with one bump. Credentials updates do not change the address set unless the backend itself produces a `Snapshot` event.
- Alias resolves once: a request to `assets://corp/foo/bar.bin` that matches `Alias { from: "assets://corp/", to: "s3://internal-bucket/" }` dispatches to the connection serving `s3://internal-bucket/` with the URL `s3://internal-bucket/foo/bar.bin`. Adding a second alias whose `from` is `s3://internal-bucket/` causes the original alias to fail with `AliasChainTooLong` at resolution, *not* to chain through.
- Alias add-time validation: `add_alias({ from, to })` rejects with a typed error if `to` resolves (currently) to another `Alias` row. If `to` is dangling at add time, the alias is accepted; resolution then returns `NotConfigured` until a non-alias row appears at `to`.
- Suppression blocks direct match only: with `Suppressed` row at `s3://internal-bucket/` and `Alias { from: "assets://corp/", to: "s3://internal-bucket/" }` both present: a direct request to `s3://internal-bucket/foo` returns `NotConfigured`; a request to `assets://corp/foo` succeeds and dispatches through the suppressed row's backend.
- Suppression shadows: with `Suppressed` row at `azure://account/internal-secrets/` and `Visible` row at `azure://account/`: a request to `azure://account/internal-secrets/foo` returns `NotConfigured`, *not* dispatched to the visible parent.
- Hidden behaves as visible for resolution: a `Hidden` row resolves and dispatches normally. (Note: `list_address_roots()` takes no opts and unconditionally filters non-`Visible` rows; an `opts.include_hidden` parameter is not implemented.)
- Visibility flip atomicity: `set_address_visibility` flipping a row from `Visible` to `Suppressed` causes new requests to fail with `NotConfigured`; in-flight reads/writes already past the resolver complete normally. The transition bumps `route_epoch`.

**Listing**
- `list_versions` items are emitted in the order the backend's native API produces; the suite verifies the plugin sets `version_list_order` to the matching `Newest` / `Oldest` / `Unordered` value, and that callers passing the stream through a sort pinned to that capability get the order they asked for.
- Paging boundary fidelity: the same prefix listed via repeated `(max_results = N, page_token)` calls produces exactly the same items in the same order as a single unpaged stream consumption, with no duplicates and no skips at the page boundary.
- One-level vs. recursive `list`: `recursive: false` returns file entries under the prefix plus directory entries one level down; `recursive: true` returns the whole subtree, including visible directory entries (`Directory`, `DirectoryMarker`, or `DirectoryInferred`). On flat backends, descendants imply inferred ancestor directories.
- List-backed stat: an unversioned object `stat` under a route with `supports_list = true` and `wants_list_backed_stat = true` can be answered by one parent `list`; sibling stats reuse that cached parent list without re-entering `StorageBackend::stat`.
- List-backed stat eligibility: directory-form addresses, addresses with query strings or fragments, and `StatOptions.full_metadata = true` bypass the list cache and dispatch through the exact `StorageBackend::stat` path.
- List-backed stat invalidation: successful child mutation dirties the whole immediate parent folder cache; host-driven subtree delete walks dirty cached folders under the removed prefix as each child is deleted.

**Directories**
- Directory address spelling: `create_directory`, `delete_directory`, and `list` canonicalize a bare directory argument by appending `/`; `stat("foo")` probes exact object `foo` first and then directory `foo/` only on `NotFound`; `stat("foo/")` probes only the directory spelling.
- Real-directory `create_directory` recursively creates missing ancestors up to the resolved route/root, then creates or validates the requested directory. `delete_directory` keeps `rmdir(2)` semantics on `file`, ADLS HNS-equivalent, and Perforce: a non-empty directory fails with `DirectoryNotEmpty`.
- Flat-backend marker convention (`s3`, `gcs`, `azure` flat): `create_directory` writes only the requested `prefix/` zero-byte marker; parent prefixes appear implicitly because that marker's key has those prefixes. `delete_directory` removes the requested marker only; objects under the prefix are unaffected; the prefix may still appear in subsequent `list` results so long as children exist.
- Host-driven subtree delete: callers walk with `list(recursive: true)`, delete `File` entries with `delete`, remove directory representations deepest-first with `delete_directory`, and finish with `delete_directory` on the requested root; injected child-delete failures surface as typed partial failures and do not claim atomic subtree rollback.
- Marker folding: a one-level `list` of a flat-backend prefix containing both a `prefix/sub/` zero-byte marker and objects `prefix/sub/foo` produces one directory `ObjectInfo` whose metadata carries the marker's mtime / metadata; the marker does not appear as a separate file entry.
- Recursive `list` preserves directory facts: marker objects appear as `DirectoryMarker`, real directories as `Directory`, and inferred prefixes as `DirectoryInferred`. Exact concrete/inferred duplicates at the same address collapse to the concrete fact.
- `stat` on directory addresses: real-directory backends return the directory's `ObjectInfo`; flat backends return the marker's `ObjectInfo` when present, an inferred directory `ObjectInfo` when a bounded prefix-list proves descendants exist without a marker, and `NotFound` only when the backend proves neither marker nor descendants exist. If the marker is absent and the bounded prefix-list is denied, the call returns the backend's permission/auth error because existence cannot be inferred from `HEAD` alone.

**Subscriptions**
- Gap signaling: a test plugin that drops events MUST emit `Lapsed` before resuming normal events. The harness drops events in-band and verifies the signal.
- Ordering within a URL: two consecutive writes to the same URL produce events whose `at` timestamps are non-decreasing in delivery order, when the backend's native feed preserves order. Plugins whose feed cannot preserve order set `watch_directory_kinds` to omit `Modified` and the harness skips this check.
- Recursive vs. one-level watch_directory: `recursive: false` delivers events for direct children only; an event for `prefix/sub/x` is suppressed unless `recursive: true`.
- Resume: for plugins with `watch_directory_resumable: true`, a `watch_directory` opened with `since: <recent cursor>` MUST replay events from that cursor and not start from "now."
- Polling fallback: when enabled, the plugin emits `Lapsed` if the previous polling cycle was longer ago than `watch_directory_max_lag * 2`, and otherwise emits one event per detected `Created` / `Modified` / `Deleted` since the previous cycle.

**Permissions**
- `effective_permissions` field semantics: a plugin emitting the full set, just `READ`, or `EffectivePermissions::empty()` produces decisions consistent with set semantics; unknown bits set by a future-version plugin are tolerated; `None` and `Some(empty)` are distinct.
- `check_access` returns exactly the subset of requested ops the principal is allowed to perform; ops the caller didn't ask about don't appear; `Unsupported` from plugins without `supports_access_check` propagates without the library substituting a synthesized answer.

**Retries**
- Library-side idempotent-request retry: a property test that drops every Nth response in `[1..5]` and requires the call to complete or surface `Transient` after the retry budget; no operation observable side effect occurs more than once for a successful call.
- `Retry-After` honored on 429 / 503: the library waits at least the indicated duration before the next attempt.
- Non-idempotent redirect not retried: a multipart `Complete` redirect whose response is dropped surfaces `Transient` without re-issuing.
- Plugin-internal retries forbidden: an instrumented plugin that returns `Transient` after its first call does so promptly; the suite asserts no internal sleep / backoff is observable.

**Redirect follower**
- Library executes `Redirect.body_source` correctly across all three variants: `Empty` produces a request with no body; `UserBytes { offset, len }` produces a request whose body is exactly that slice of the application's write stream (property test over partial / non-zero offsets); `Inline(bytes)` produces a request whose body is binary-equal to the bytes the plugin supplied. Verified against Direct-mode plugin redirects and brokered redirects so the test is issuer-agnostic.
- Library captures only the headers listed in `Redirect.result_capture.headers` and at most `result_capture.body_max_bytes` of the response body; surplus headers and body bytes are discarded before the `RedirectResponse` is handed back to the plugin.

**Write-populates-cache (both branches, both modes)**
- After a successful `write` of object O on host H, the next `read_*` of O on H is a cache hit (no network read) subject to [ovstorage-cache "Cache-hit validity"](../ovstorage-cache/README.md#cache-hit-validity-spec--current-api-has-no-if_match--identity--version-surface). Verified for Direct mode (inline `write`), Brokered + redirect branch, and Brokered + `AcceptUpload` branch.
- Write-stream is teed into staging *as it streams*: a property test forces the cloud-side write to fail mid-stream and asserts that the staging entry is discarded (no half-written entry leaks into the CAS).

**ObjectAddress vs ResolvedTarget in audit**
- Every audit/trace record carries both the caller-facing `ObjectAddress` and the post-routing `ResolvedTarget`.

**Authentication**
- Auth state state-machine: a test connection transitions correctly through states: fresh → `AwaitingAuth { NeverAuthenticated }` → (call `authenticate_connection`, complete flow) → `Authenticated` → (token expired) → `AwaitingAuth { RefreshTokenExpired }` → (re-auth) → `Authenticated` → (revoke server-side) → `AuthFailed`.
- Silent refresh on startup: a persisted connection with a valid refresh token transitions startup → non-interactive `authenticate` → `Authenticated` without any `AuthEvent` reaching the application.
- Lazy auth on first dispatch: a persisted connection with an expired refresh token loads as `AwaitingAuth` with a stub backend on its cached routes; the first request resolving to one of those routes drives `authenticate_connection` exactly once, swaps the stub for the real backend, and proceeds. Concurrent requests serialise on a per-connection mutex.
- Backend-unreachable parking: a cache-hit connection whose silent probe fails for a non-auth reason loads as `AwaitingAuth { BackendUnreachable }`; subsequent requests retry the silent bring-up after a small cooldown without driving any interactive flow.
- Coalesced auth attempts: two concurrent `authenticate_connection` calls against the same connection produce one plugin invocation; both streams receive the same events.
- Cancellation: dropping the auth stream during `OpenBrowser` causes the plugin's `is_cancelled()` to return true and `cancellation().await` to resolve; the plugin closes its callback listener; subsequent stream consumers see `AuthCancelled`.
- Cache survives restart: a successful `address_roots` is captured; the process restarts; the cache is loaded; addresses appear in `list_address_roots` immediately, before any auth attempt; reads fail with `AuthRequired { connection_id }` carrying the correct id.
- Cache pruning: a cache older than the configured TTL is dropped on startup; the connection loads with empty `current_addresses`.

## Implementation notes

The dispatcher is async and supports static programmatic routes plus in-process direct-mode connection routes created through registered `StorageBackendFactory` instances and dlopen'd plugins (`LibraryBuilder::register_plugin_path` / `register_plugins_from_dir`). It covers longest-prefix routing with caller-facing result addresses, exact segment-aware prefix matching, object operations through `check_access`, paged `list_page`, list-backed stat with provider opt-in, provider `full_metadata` bypass, backend capability gates for optional SPI calls, backend-id-qualified cache keys, cache hits that do not re-enter the backend, cache invalidation for write/delete/copy/rename/metadata/directory delete, watch_directory event dirtying, and the in-process redirect follower (`ReadResult::Redirect`, `WriteStep::Redirects` + `continue_write`). `watch_directory` is a synchronous boxed iterator returned by an async open call. Aliases resolve once, dangling aliases return `NotConfigured`, and exact-row `Suppressed` visibility blocks direct requests while alias-mediated dispatch can still target the suppressed row. Connection/alias watch APIs yield a snapshot iterator; `authenticate_connection` delegates to the registered factory and `file`/`http` demonstrate no-op anonymous auth. Persistent `add_connection`, persistent aliases, and persistent visibility overrides return `Unsupported`.

- `LibraryBuilder` and the internal normalized registration model are the registration surface. Broker and CLI debug configuration loaders call registration APIs; the dispatcher does not grow its own TOML parser or config-layer precedence logic.
- Direct-mode control APIs are local to `Library`. Brokered mode publishes address roots and object I/O through `broker-client`; broker-side backend configuration is edited in broker TOML rather than through `Storage` management calls.
- `ObjectAddress` / `ResolvedTarget` conversion lives in one module. Every public result carries caller-facing addresses; every plugin call receives a full resolved URL.
- Subtree delete is a host-side, best-effort ordered workflow, not a transaction: enumerate with `list(recursive: true)`, delete `File` entries, delete nested directory representations deepest-first, then call `delete_directory` on the requested directory representation. Every failure carries the failed address and leaves already-completed deletes visible.
- All redirect execution runs through one HTTP follower. Direct-mode plugin redirects and broker-issued redirects share request execution, retry, response parsing, and `RedirectResponse` capture code.
- `policy_partition` is threaded through the cache-facing calls from the dispatcher, not from plugins. Plugins do not compute cache partitions.

### Out of scope

- **Multi-hop alias chains.** Single-resolve is enforced; deeper chains surface as `AliasChainTooLong`. Lifting the depth limit is not on the roadmap.
- **Wildcard / prefix-pattern visibility overrides.** `set_address_visibility` takes exact-`ObjectAddress` overrides only.
- **Programmatic creation of `StorageBackendKindDescriptor` outside the plugin SPI.** Applications cannot inject their own backend kinds at runtime; kinds come from loaded plugins, full stop.
- **Transactions spanning multiple objects.** A manifest-commit layer for cross-object atomicity is not part of the surface.
- **Cross-backend replication.** The library does not mirror objects across plugins.
- **Encryption at rest beyond passing provider-native SSE parameters through.** ovstorage does not own a portable encryption-at-rest layer.
- **FUSE mount.** Exposing a `Library` as a FUSE filesystem is not part of the surface.
- **Filesystem adapter (capability-gated) and fsspec / PyArrow-filesystem adapters.** No project-owned adapters wrap `Library` to imitate other filesystem APIs.
- **Dataset / manifest commit layer.** Higher-level dataset semantics on top of object I/O are not part of the surface.
- **Push-callback streaming and Arrow C Stream Interface integration.** Reads use the chunk-iterator surface; no Arrow-stream bridge is provided.

## Risks

### OAuth refresh races causing single-use-token consumption by two processes

**Status:** defensive-depth

**Concern.** Two ovstorage-using processes on the same host (e.g. two CLI invocations, or a CLI plus a long-running fork-server worker) both notice that the access token is near expiry and both try to refresh. With single-use refresh tokens, the second process's refresh request fails — the IdP already invalidated the refresh token — and the principal gets locked out, or worse, both rotations partially succeed and one process ends up with a dead-on-arrival access token.

**Why this mitigation is sound.** Cross-process serialization through two layers: a per-backend `flock(<state_root>/auth/<connection_id>.lock, LOCK_EX)` held across the entire refresh attempt (acquire → check expiry → call IdP → persist → release), and a SQLite `BEGIN EXCLUSIVE` transaction inside `auth.sqlite` that serializes refresh within a single process. The flock pattern is what `gh auth`, `aws sso login`, and Mozilla's `mozregression` all ship in production; SQLite's `BEGIN EXCLUSIVE` is the documented primitive for "exactly one writer at a time even with WAL" ([sqlite.org/lang_transaction.html](https://www.sqlite.org/lang_transaction.html)). The combination means at most one process per host per connection ever holds an open IdP refresh request; the loser of the flock race re-reads the rotated token from `auth.sqlite` after the winner releases.

**Alternatives considered and rejected.**

- **TTL-based debouncing (process A waits N seconds before refresh).** Doesn't solve the race; just shifts when the collision happens.
- **Per-process refresh with optimistic retry.** First process succeeds, second process gets `invalid_grant`, retries, refreshes successfully. Works for two processes, fails badly with three or more (cascade of failures); also burns IdP rate budget.
- **Single shared-memory mutex across processes.** POSIX shared mutexes need a daemon to clean up after crashed holders; flock's kernel-level cleanup on process exit is exactly the right shape.
- **Daemon-mediated refresh.** Same daemon objection as the cache contention discussion — a non-goal for direct-mode CLI workflows.

**What this mitigation does NOT cover.**

- Cross-host refresh races (two machines using the same connection): the project's state model is per-host; cross-host shared connections require the broker, which has its own cross-process serialization story.
- IdP-side rotation losing the response (network partition during the IdP-internal commit): see [OAuth refresh durability](../ovstorage-cache/README.md#oauth-single-use-refresh-token-durability).
- A refresh that hangs the IdP for > 30s: the flock holder blocks every other process for the duration; the other processes time out cleanly and surface `AuthRefreshTimeout` to their callers.

**Implementor checklist.**

`AuthRefreshLock::with_refresh` provides the coalescing primitive;
the checklist below tracks the target. Differences in the current
implementation: lock files live under
`<state_root>/locks/auth/<sha256>.lock` (not
`<state_root>/auth/<connection_id>.lock`); the SQLite write does
NOT use `BEGIN EXCLUSIVE` (single `INSERT ... ON CONFLICT DO UPDATE`
per refresh, retried on `SQLITE_BUSY` / `SQLITE_LOCKED`); `flock`
is acquired blocking with no 30s timeout and `AuthRefreshTimeout`
is not a typed error code; per-connection lock-file GC is not
implemented.

- Per-connection lock file: `<state_root>/auth/<connection_id>.lock`. Created on demand; cleaned up by background GC after 7 days of unuse.
- Lock acquisition uses `flock(fd, LOCK_EX)` (advisory, not mandatory); on failure to acquire, re-read `auth.sqlite` and check whether another process already rotated the token before retrying.
- `BEGIN EXCLUSIVE` around the SPI call to the IdP refresh endpoint and the SQLite write of the new tokens; commit before releasing the flock.
- `flock` timeout: 30 seconds. Beyond that, surface `AuthRefreshTimeout { connection_id }` to the caller; don't silently wait forever.
- Coalescing within a single process: two concurrent `authenticate_connection` calls against the same connection are de-duplicated to one IdP call (conformance covered by the broker's test suite, reused here for direct mode).

**Verification.**

- Conformance property test `oauth_refresh_n_process_race`: N=10 processes race a refresh against a near-expiry token; exactly one IdP `POST /token` request fires across the wire; all 10 processes end with the same rotated access token in their post-refresh `Connection`.
- Conformance test `oauth_refresh_flock_timeout`: process A holds the flock for 60s (simulated slow IdP); process B times out at 30s with `AuthRefreshTimeout` rather than blocking indefinitely.
- Conformance test `oauth_refresh_coalescing`: two concurrent `authenticate_connection` calls on the same connection within one process produce one plugin invocation; both streams receive the same events.
- Tracked under "OAuth refresh race conformance test passes."
