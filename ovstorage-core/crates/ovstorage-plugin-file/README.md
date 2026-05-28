# plugin-file (`ovstorage-plugin-file`)

> The canonical reference for the `file:` backend's public surface,
> URL format, capability bits, watch semantics, and threat model lives
> in [`docs/public/plugin-storage/plugin-file.md`](../../../docs/public/plugin-storage/plugin-file.md).

## Purpose (crate-local)

The `file:` plugin: the reference implementation of the
[ovstorage-plugin](../ovstorage-plugin/README.md) `Backend` SPI
against the local filesystem. Atomic publish via the temp + fsync +
rename + parent-fsync sequence (Windows equivalents on Windows).

## Contributor notes

This README covers contributor-internal details only. Plugin
authors and operators should read the public reference linked above
for the schemes, descriptor, config keys, URL handling, capability
matrix, and threat model.

### Dependencies

In-workspace: `ovstorage-plugin` (canonical home for the Rust type
vocabulary). Dev tests also use `ovstorage` and `ovstorage-cache`.

External: `async-trait` and `tokio` (`fs`, `io-util`, `rt`, `sync`).
The `sync` feature backs the per-target async mutex used to
serialise concurrent writers in the same process. Native filesystem
watchers and platform xattr bindings are not used.

### Conformance tests

The plugin's conformance surface. The in-crate test suite is
narrower than this list; bullets without a named test are intent
statements, not claims of coverage.

**Plugin-enforced scope (`file` exposed broker-side)**
- Path requests containing `..` are canonicalized by
  `address::join_relative` before reaching the plugin; any survivors
  that resolve outside the configured `root` are rejected with
  `PermissionDenied`. The `rooted_file_backend_rejects_escape_addresses`
  test pins this end-to-end. Coverage of `.`, double-slashes,
  percent-encoded separators, and trailing-dot canonicalization
  sits in the upstream `address::parse` test surface, not the
  plugin's own suite.
- The `.ovstorage-meta` namespace is rejected with
  `PermissionDenied` when written via the public API (covered
  inside the omnibus `file_backend_round_trips_through_library`
  test).
- Symlinks are resolved against the canonical `root`. Symlinks
  pointing outside `root` are rejected with `PermissionDenied`;
  `rooted_file_backend_rejects_symlink_file_escape` pins direct
  object reads, and
  `rooted_file_backend_rejects_recursive_list_symlink_directory_escape`
  pins recursive traversal through a symlinked directory.

**Directories**
- `create_directory` succeeds when the target already exists and
  creates missing ancestors (covered by the omnibus round-trip).
- `delete_directory` returns `DirectoryNotEmpty` when user entries
  remain; subtree recursion is host-side composition rather than a
  plugin flag. Coverage that `.ovstorage-meta` sidecars are ignored
  for the emptiness check is intent, not a dedicated test.

**Identity and preconditions**
- Returned identity contains only `size` and `mtime`; `etag` and
  `version` stay absent even when a cache CAS key exists. The
  omnibus test asserts `size`; an `etag is None` assertion is not
  in place.
- A no-overwrite write loses with `Conflict` when a peer writer has
  already published the destination.
  `no_overwrite_concurrent_writers_only_one_succeeds` spawns four
  concurrent writers against the same address and asserts exactly
  one commits and three observe `Conflict`. Stale-`if_match` is
  exercised through the host library's behavior tests.
- A read returns an `ObjectInfo.identity` derived from the same
  open file handle the bytes come from, so the identity always
  describes the inode whose contents were returned.
  `read_returns_identity_consistent_with_bytes` pins the basic
  shape; race-window coverage against a concurrent rename writer is
  host-level.
- List-backed stat is opted out (`wants_list_backed_stat = false`);
  exact file stats use native filesystem `stat`. Capability bit
  asserted in the omnibus test.

**Streaming writes**
- A failed chunk leaves no destination file (the temp + fsync +
  rename sequence never commits) and no `.tmp` sibling (the
  `TempFileGuard` Drop impl unlinks the staged temp). Pinned by
  `streamed_body_chunk_error_leaves_no_destination_file`, which
  walks the directory and asserts no `.tmp` entries remain.

**Watch**
- Polling watch reports `Created` events for newly-written objects
  and the omnibus polling test
  (`file_backend_polling_watch_reports_created_objects`) pins this.
  `Modified`, `Deleted`, and `MetadataChanged` paths are exercised
  by host-level integration but lack dedicated plugin-crate tests.

**Permissions**
- `effective_permissions` populated from the readonly approximation
  (`READ` only, or the full set). The omnibus test asserts the
  writable-full case; the readonly path lacks a dedicated test.
- Unix special files (FIFOs, sockets, and device nodes) are rejected
  before read/copy opens them, preventing a served root from hanging
  readers on blocking filesystem objects.

The plugin is the reference implementation that every other
plugin's conformance run is compared against; behavior the harness
pins on `file` is what other plugins are required to match where
capabilities allow.
