# Layer ownership registry

Which Layer owns a concern is a placement decision, not a naming convention. This file records every placement decision the composed Stack relies on, in present tense, so that a plugin author can answer "does this belong in my backend?" without reading the architecture RFC. It is the routed statement of the rule; `docs/rfcs/0066-layered-architecture.md` § Behavior placement remains the decision record behind it.

Read this before adding a `Capabilities` bit, implementing a Layer slot you have not implemented before, or moving behavior between a backend and a wrapper.

**The operative test is information, not convenience.** A concern belongs to the Layer that can see what the decision needs and that the other Layer cannot see. That test moves boundaries in both directions: watch coalescing moved *into* the backends because only a backend can key on the per-connection contended resource, and directory-key derivation moved into the backends because only a backend knows whether `docs` and `docs/` name one node. Neither move was a mistake corrected — each was the information test applied. So a row here can change, and changing one is a normal reviewable act: edit the row in the same change that moves the code. What is not normal is moving a boundary without editing the row, which is what the parity gate below prevents.

**A row is prohibitive, not descriptive.** Where the "Backend leaves at default" column names slots, a backend Layer does not implement them: it leaves the `Layer` trait default in place, and the host wrapper named in the row supplies the behavior. `Unsupported` from that default is the contract working, not a gap to fill.

## Registry

| Concern | Owner | Kind constant | Backend leaves at default |
|---|---|---|---|
| Alias and caller-to-physical prefix rewriting | `AliasWrapper` (host wrapper) | `ALIAS_KIND` | — |
| URL canonicalization (scheme, punycode, default port, path pipeline) | `Stack` at chain entry plus `address::parse` | — | — |
| Routing across child Layers by URL prefix (longest prefix, then a marked scheme-fallback root for the address's scheme), and connection ops by target name | `Router` (host router) | `ROUTER_KIND` | — |
| Byte caching of `read` results, herd collapse, and cache fill | `ByteCacheWrapper` (host wrapper) | `BYTE_CACHE_KIND` | — |
| Byte-cache invalidation on mutation | `ByteCacheWrapper` (host wrapper) | `BYTE_CACHE_KIND` | — |
| Cache-aside caching of `read` results via the Omniverse Hub, with streaming fill on a miss | `HubCacheWrapper` (host wrapper) | `HUB_CACHE_KIND` | — |
| Producing a local file for a remote object | `ByteCacheWrapper`, `RedirectFollowerWrapper`, and `HubCacheWrapper` (host wrappers) | `BYTE_CACHE_KIND`, `REDIRECT_FOLLOWER_KIND`, `HUB_CACHE_KIND` | `materialize` |
| Range reads served from cache or by bounded read-through | `ByteCacheWrapper` (host wrapper) | `BYTE_CACHE_KIND` | — |
| Metadata caching of `stat`, `list`, `list_versions`, `get_latest_version`, `check_access`, `root_info_for` | `MetadataCacheWrapper` (host wrapper) | `METADATA_CACHE_KIND` | — |
| List-backed `stat` answers from cached parent listings | `MetadataCacheWrapper` (host wrapper) | `METADATA_CACHE_KIND` | — |
| Metadata-cache invalidation and parent-prefix fan-out | `MetadataCacheWrapper` (host wrapper) | `METADATA_CACHE_KIND` | — |
| Watch-driven freshness for cached metadata | `MetadataCacheWrapper` (host wrapper) | `METADATA_CACHE_KIND` | — |
| Idempotent retry and backoff on `Transient` and `ResourceExhausted` | `RetryWrapper` (host wrapper) | `RETRY_KIND` | — |
| Following a `ReadResult::Redirect` or a `WriteStep::Redirects` plan, including the transfer's own HTTP retry | `RedirectFollowerWrapper` (host wrapper) | `REDIRECT_FOLLOWER_KIND` | — |
| Write-protocol selection: whether a body-typed write is attempted redirect-first | `RedirectFollowerWrapper` (host wrapper) | `REDIRECT_FOLLOWER_KIND` | — |
| Part buffering for a followed multipart write redirect | `RedirectFollowerWrapper` (host wrapper) | `REDIRECT_FOLLOWER_KIND` | — |
| `copy` and `rename` composed from read plus write plus delete when the layer below declines | `CopyRenameFallbackWrapper` (host wrapper) | `COPY_RENAME_FALLBACK_KIND` | — |
| Persistent secret storage | host-callback secret store (host, not a Layer) | — | — |
| Listener authentication and authorization | `BuiltinAuthLayer` and auth-capable wrapper Layers, over the ordinary Layer ABI | `BUILTIN_AUTH_KIND` | — |
| Attribution stamping of a write's `user_metadata` | broker attribution wrapper (host wrapper) | `ATTRIBUTION_KIND` | — |
| Local path for an object that already is a local file | `FileBackend` (built-in backend) | `FILE_BACKEND_KIND` | — |
| Directory-key derivation for `list`, `create_directory`, `delete_directory`, `watch_directory` | owning backend Layer (via `address::directory_key`) | — | — |
| Bare-path `stat` fallback to the slash form, and object-versus-directory `stat` behavior | owning backend Layer | — | — |
| Natively supported range reads | owning backend Layer | — | — |
| Server-side same-root `copy` and `rename` | owning backend Layer | — | — |
| Multipart upload state machine across `continue_write` rounds | owning backend Layer | — | — |
| Per-connection auth state, refresh, and interactive flow | owning backend Layer | — | — |
| Address-level routing across several connections of one backend kind, and the per-scheme anonymous fallback for an address on that kind's scheme that no connection serves: the hidden scheme root, the per-bucket anonymous client, the read-only refusal and the instance-metadata refusal | owning backend Layer | — | — |
| Watch coalescing on the contended per-connection resource | owning backend Layer | — | — |
| Remote dispatch to a broker daemon | `BrokerClientLayer` (backend Layer), over the `BrokerClientBackend` transport | — | — |
| `Body::Stream` chunk-by-chunk forwarding | every Layer | — | — |
| Cancellation propagation | every Layer | — | — |

Two of these are one concern split across the boundary, and the split is the trap: **per-connection auth state, refresh, and interactive flow** belong to the owning backend Layer, while **persistent secret storage** belongs to the host secret store. An author who correctly learns that auth lives in the backend will put token persistence there too, and that is wrong: a backend has no place to write a secret that survives the process, and the host callback exists because secret persistence is a deployment decision (SQLite, encrypted file, HSM, broker-mediated). Anonymous fallback is another split concern: the backend Layer owns reaching the address anonymously — the hidden scheme root, the per-bucket client, the read-only and instance-metadata refusals — while the host owns whether that is permitted in this deployment, which is why the broker and the REST gateway carry the grant as a top-level key and stamp it onto the layer rather than letting a layer table decide for a network position it cannot see.

`materialize` is the row that costs the most to get wrong, so it is stated twice. It is a vtable slot so that wrappers and language bridges dispatch uniformly, not because a backend supplies it. `ByteCacheWrapper` returns a cached row under a live lease; `HubCacheWrapper` returns the hub's own local file under a live lease, filling it from `inner`'s `read` on a miss; `RedirectFollowerWrapper` calls `read` and stages the bytes to a local file; `FileBackend` returns the file's own path because the object already is a local file and nothing is copied. A remote backend has no lease to hand back and no eviction accounting, so it leaves the trait default in place and the composed Stack supplies local availability. Local availability is a property of the Stack, not of a backend — which is why there is no `supports_materialize` bit, and why adding one is not a gap to fill.

## Capability bits

Every `bool` on `Capabilities` is registered here. A bit is a claim about one root of one Layer; a wrapper that emulates an operation may raise the availability bit for the root it projects (`CopyRenameFallbackWrapper` raises `supports_copy`), and never raises a mechanism bit (`supports_server_side_copy`).

A new bit is admitted only if all four hold; if any fails, the answer is a wrapper Layer, a result or request-option variant, or nothing.

1. The host cannot synthesize the behavior. Where it can, the bit names the backend-native fast path rather than the outcome — `supports_server_side_copy`, not `supports_copy`.
2. A host code path branches on it.
3. It is fixed for the connection lifetime. Per-composition facts belong in Stack configuration.
4. It is not derivable from a bit that already exists.

| Bit | Claims |
|---|---|
| `supports_if_match_write` | The backend honors an `if_match` precondition on write. |
| `supports_no_overwrite_write` | The backend honors a no-overwrite precondition on write. |
| `supports_native_metadata_patch` | The backend patches user metadata without rewriting the object. |
| `supports_metadata_rewrite_emulation` | The backend emulates a metadata patch by rewriting the object. |
| `writes_are_atomic` | A completed write publishes indivisibly. |
| `supports_copy` | A `copy` naming this root can be attempted (availability, not mechanism). |
| `supports_rename` | A `rename` naming this root can be attempted (availability, not mechanism). |
| `supports_server_side_copy` | The backend copies without routing bytes through the host. |
| `supports_server_side_rename` | The backend renames without routing bytes through the host. |
| `supports_atomic_rename` | The backend's native `rename` is atomic. |
| `has_real_directories` | Directories are first-class nodes rather than key prefixes. |
| `supports_write` | Buffered single-shot `write` is implemented. |
| `supports_write_stream` | `write_stream` is implemented. |
| `supports_write_redirect` | `write_redirect`, and by implication `continue_write`, is implemented. |
| `supports_delete` | `delete` is implemented. |
| `supports_list` | `list` is implemented. |
| `supports_list_stream` | The layer implements `list_stream` natively rather than through the buffered adapter. |
| `wants_list_backed_stat` | The metadata cache may answer an eligible `stat` from a parent listing. |
| `supports_recursive_list` | `list` honors a recursive request. |
| `populates_subdirectory_metadata` | Listed subdirectory entries carry metadata. |
| `supports_create_directory` | `create_directory` is implemented. |
| `supports_delete_directory` | `delete_directory` is implemented. |
| `supports_version_listing` | `list_versions` is implemented. |
| `populates_effective_permissions_on_stat` | `stat` fills the caller's effective permissions. |
| `supports_access_check` | `check_access` is implemented. |
| `supports_watch_directory` | `watch_directory` is implemented. |
| `watch_directory_resumable` | A watch resumes from a prior cursor. |

The set is curated, not an enumeration of `Layer` methods. `stat`, `read`, `continue_write`, `get_latest_version`, and `materialize` deliberately have no bit: the first two are baseline, `continue_write` is implied by `supports_write_redirect`, and `materialize` is host-owned by the registry above.

## How this file is checked

`make lint-layer-ownership` (part of `make verify`) compares this file against the source tree and fails on drift:

1. **Completeness** — every host Layer kind constant declared in `ovstorage/src/layers.rs` and in the standard plugin crates (`ovstorage-plugin-core`, `ovstorage-plugin-cache`, `ovstorage-plugin-http`, `ovstorage-plugin-hub-cache`) appears in the `Kind constant` column. Adding a wrapper to one of those files without a registry row fails. Kinds private to the broker daemon and to the authorization Layers are outside that scope, so this table is not an inventory of every kind constant in the workspace. The reverse direction is checked repo-wide: a `Kind constant` cited here that no Rust source declares fails, so a row cannot go stale.
2. **No host-owned slot in a backend** — for each slot named in the `Backend leaves at default` column, no `impl Layer` block for a backend-role type in a backend plugin crate defines that slot. Both test harness crates are scanned too, because an exemplar teaches the shape it shows. A Layer is treated as backend-role unless the row that names it as owner also names that slot, or unless it declares itself a `Wrapper` or `Router` in its own descriptor. Moving a host-owned slot into a backend fails, and so does an `impl Layer` header the check cannot parse.
3. **Capability-bit parity** — the `Capability bits` table names exactly the `bool` fields of `Capabilities`. Adding a bit without a registry row fails, whatever the bit is called.

Moving a boundary therefore means editing a row in the same change that moves the code, which is the visibility this registry exists to create.
