# Local filesystem plugin (`file`)

The `file:` plugin: the reference implementation of the `Backend`
SPI against the local filesystem. Atomic publish via the temp +
fsync + rename + parent-fsync sequence (Windows equivalents on
Windows). Every conformance test runs against this plugin first;
behavior the test doesn't pin against `file` is behavior other
plugins are not required to provide either.

The plugin does not define a separate exact-reference API.
Exactness flows through the `etag` returned on `ObjectInfo` from
`stat` and reads; for `file` that etag is the synthesized string
`"size:N,mtime:Tms"` the filesystem can produce without hashing
the file.

**Public surface**

- **Schemes**: `file:`.
- **Descriptor**: `kind = "file"`, `display_name = "Local filesystem"`.
- **Config keys**:
  - `root` (required) — filesystem directory this connection may
    serve. Must already exist; the connection's serving identity
    needs read+write permission on it. Non-existent roots, paths
    outside the operator-permitted prefix, or insufficient
    permissions surface `InvalidArgument` at instantiate time.
  - `prefix` (optional) — caller-facing route prefix as a `file:`
    URL; defaults to `file:<root>/`. The prefix must resolve under
    the configured `root`; cross-root rewriting is not supported
    and is rejected with `InvalidArgument` at instantiate time.
- **Credential keys**: none. POSIX / NTFS owns access; no
  application-level credentials are collected.

**URL format**

Per RFC 8089, a `file:` URL has three valid shapes:

- `file:/path` — minimal form, no authority component.
- `file:///path` — empty authority (`localhost` implied);
  equivalent to the minimal form.
- `file://hostname/path` — explicit hostname; only `localhost` and
  the empty hostname are honored.

`file://path` (two slashes, no hostname) is the common mistake: a
strict parser reads `path` as the hostname and leaves the path
component empty. The plugin rejects any non-empty authority that is
not `localhost` (case-insensitive) with `InvalidArgument`, naming
the offending host in the error message.

Windows drive paths use the RFC form `file:///C:/path/to/object`.
UNC paths (`file://server/share/...`) are rejected uniformly by the
same authority check — the first-party `file` plugin does not
serve UNC shares. Percent-encoded characters in the path are
decoded, then the path is checked against the configured canonical
`root_path`.

URL normalization happens **before** the plugin sees the URL: the
host's `address::parse` / `address::join_relative` apply RFC 3986
path resolution, collapsing `..` / `.` / double-slash segments
while preserving every other byte of the path. The plugin then
accepts the canonicalized `file:` URL, takes the percent-decoded
URL key, normalizes backslashes to forward slashes, strips a
Windows drive-letter leading slash (`/C:/...` → `C:/...`), maps to
native separators, **rejects** any `..` components that survived,
rejects the plugin-owned `.ovstorage-meta` namespace, and verifies
the canonical target or nearest existing ancestor resolves under
the configured canonical `root`.

**Internals**

Atomic publish via the temp + fsync + rename + parent-fsync
sequence (Windows equivalents on Windows). Temp files are created
in the destination directory so the final rename is same-filesystem
and atomic. On overwrite, the old file remains visible until the
rename commits. Temp files use the dotted name pattern
`.<basename>.<unix-nanos>.<pid>.<counter>.tmp` (the per-process
atomic counter and pid prevent same-millisecond writers from
colliding on a temp sibling), and `list` / `watch_directory` filter
that pattern out, so partial files never surface to callers. The
temp file is opened with `create_new(true)` in a small retry loop
so duplicate names error out instead of silently truncating a peer
writer's staging file. A `TempFileGuard` Drop impl unlinks the
staged temp on every error path; a successful rename disarms the
guard before commit, so the renamed file survives.

`writes_are_atomic` covers object bytes only — the rename publishes
the byte image as a single inode swap. User-metadata sidecars are
staged at a sibling temp path before the bytes commit and renamed
into place after; a sidecar publish failure surfaces as `Transient`
so the host's retry layer re-issues the whole operation.

Concurrency: every `IfDestExists` precondition re-checks the
destination under a per-target async mutex held across the
precondition check and the final rename. This closes the most
common race — concurrent writers in the same ovstorage process
colliding on the same address. Cross-process races on the same filesystem still
require kernel atomic primitives (Linux `renameat2 RENAME_NOREPLACE`,
Windows `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`) that the
plugin does not invoke. **Operators are responsible for
enforcement**: the host running this plugin (broker / REST gateway)
must run with OS-level write permissions that exclude every other
writer to the served root.

Populates `etag = "size:N,mtime:Tms"` (synthesized from
`std::fs::metadata`) on every `stat` and read response. `version`
is `None` (the filesystem has no per-object version concept; cache
CAS keys are not part of backend identity); `size` and `mtime` are
also populated on `ObjectInfo` for callers that want descriptive
metadata without parsing the etag.

`ReadOptions::if_match`, `DeleteOptions::if_match`, and
`UpdateMetadataOptions::if_match` compare the supplied etag string
against the freshly synthesized etag before the operation. Writes
use `WriteOptions::if_dest`: `IfDestExists::Fail` fails with
`Conflict` if the destination exists; `IfDestExists::MatchEtag(s)`
fails with `ObjectModified` if the destination's current etag
differs.

`UserMetadata` is patchable in place —
`supports_native_metadata_patch = true`. Windows stores it in an
NTFS Alternate Data Stream named `ovstorage.metadata`; non-Windows
builds use a hidden `.ovstorage-meta/` sidecar directory next to
the file. The sidecar is treated as plugin-owned internal state:
`list` hides it, direct user operations under `.ovstorage-meta`
return `PermissionDenied`, copy/rename moves it with the object,
and `update_metadata` stats the target before mutating any sidecar
so a missing path returns `NotFound`.

Canonical scope: the resolved native path, after following symlinks
for existing path components, must remain under the configured
canonical `root`. URL-level normalization collapses `..` / `.` /
double-slash segments before they reach the plugin. Symlinks that
point outside `root` fail with `PermissionDenied` for direct object
operations and for traversal during `list` / `watch_directory`.
Symlinks that resolve to locations still inside `root` are allowed.

Directories are real: `has_real_directories = true`.
`create_directory` is `tokio::fs::create_dir_all` against the
resolved path, so it accepts an existing target directory and
creates missing ancestors. `delete_directory` first scans for
non-internal entries and returns `DirectoryNotEmpty` if any remain.
Subtree recursion is host-side composition, not a plugin flag.
Non-recursive `list` emits directory-kind `ObjectInfo` values for
child directories alongside file `ObjectInfo` values; recursive
`list` walks the subtree and emits both descendant files and real
directories with `ObjectKind::Directory`.

`read` first applies the canonical root gate, then opens a
`tokio::fs::File`, derives the `etag` from the open handle (so the
returned etag describes the same inode whose bytes are read), and
checks `if_match` against that etag. On Unix, FIFOs, sockets, and
device nodes are rejected with `Unsupported` before opening so a
served directory cannot hang a reader on a special file.
Whole-object reads return
`ReadResult::LocalDelegate { path, info, guard: None }` so the host
can stream bytes off the filesystem directly without copying through
the plugin. Ranged reads return `ReadResult::Stream` driven by an
open-then-seek-then-take handle. Permissions advertised via
`populates_effective_permissions_on_stat = true` use a readonly
approximation: readonly entries emit `EffectivePermissions::READ`;
writable entries emit the full set.

Although `file` supports one-level list, it sets
`wants_list_backed_stat = false`. Native filesystem `stat` is cheap
and more precise than enumerating the containing directory, so
public file stats dispatch to the plugin's normal `stat` path.

Capability bits are intentionally narrow: `supports_if_match_write`,
`supports_no_overwrite_write`, `writes_are_atomic`,
`supports_server_side_copy`, `supports_server_side_rename`,
`supports_atomic_rename`, `has_real_directories`, `supports_list`,
`supports_recursive_list`, `supports_native_metadata_patch`,
`populates_subdirectory_metadata`,
`populates_effective_permissions_on_stat`, and
`supports_access_check` are true. `supports_watch_directory` is
**false** — the SPI no longer includes a polling watch mode, and
`file` doesn't have a native push-event source wired up. Version
listing, redirect-based reads/writes, metadata-rewrite emulation,
and broker-managed credentials are not part of the plugin.

`watch_directory` is implemented as an explicit polling stream. The
stream snapshots the watched directory, sleeps for
`max(WatchDirectoryOptions.poll_interval, 10ms)`, diffs the next
snapshot, and emits `Created`, `Modified`, and `Deleted` object
events using full file-backed addresses under the watched prefix.
`MetadataChanged` events are emitted
only when `WatchDirectoryOptions.include_metadata_changes` is true
and the diff detects a change in the sidecar's mtime.
`recursive = false` watches direct children only and ignores
subdirectory entries; `recursive = true` walks the subtree. A
`watch_directory` opened with `since` emits `Lapsed` first because
the polling implementation is not resumable. The cancellation token
passed to `watch_directory` is threaded into the stream and checked
both before and after each poll-interval sleep. Native `inotify` /
`FSEvents` / `ReadDirectoryChangesW` integration is not
implemented.

**Threat model**

In Direct mode the plugin runs in the application process and
inherits its UID; access is whatever the OS already enforces. In
Brokered mode the plugin is loaded broker-side and the broker
enforces principal-aware policy; the plugin itself enforces
canonical scope under the configured `root`. Symlinks that resolve
outside `root` are denied so a user-controlled symlink inside a
served tree cannot expose arbitrary host files.
