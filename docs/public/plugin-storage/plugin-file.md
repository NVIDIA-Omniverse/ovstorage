# Local filesystem backend (`file`)

The `file` backend is **built in** to the library: kind `"file"`
is served natively, in-Stack, with no cdylib to build or load.
There is no `ovstorage-plugin-file` crate to `cargo build` and no
`libovstorage_plugin_file.so` to pass to `load_plugin` — a
`backend_kind = "file"` connection with a `root` config just works
once the library is open. See
[`../configuration.md`](../configuration.md) for the `[ovstorage]` stack
schema and a copyable `file`-backend default config. It reads and writes
the local filesystem,
publishing bytes atomically via the temp + fsync + rename +
parent-fsync sequence (Windows equivalents on Windows). Every
conformance test runs against `file` first; behavior the tests
don't pin against `file` is behavior other backends are not
required to provide either.

The built-in backend does not define a separate exact-reference
API. Exactness flows through the `etag` returned on `ObjectInfo`
from `stat` and reads; for `file` that etag is the synthesized
string `"size:N,mtime:Tms"` the filesystem can produce without
hashing the file.

**Public surface**

- **Schemes**: `file:`.
- **Descriptor**: `kind = "file"`, `display_name = "Local files"`,
  `supports_runtime_add = true`. A gateway's `GET /v1/backend-kinds` reports
  that flag as `true` only once the stack declares a `file` layer for a new
  connection to bind against.
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
  - `confine_to_root` (optional, boolean, default `false`) — when
    `true`, applies a realpath jail so an in-root symlink whose
    target resolves outside `root` is denied with `PermissionDenied`.
    Off by default: operator-configured in-root symlinks may form a
    virtual tree that redirects to real data outside `root` (see the
    *Threat model* and *Canonical scope* sections). Meaningful only
    for Brokered deployments under a privileged service account.
    Leaving it unset means such symlinks are followed.
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
same authority check — the built-in `file` backend does not
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
the resulting path stays under the configured `root` **lexically**
(by name). With the optional `confine_to_root` knob enabled it
additionally requires the canonical target or nearest existing
ancestor to resolve under the canonical `root` (a realpath jail); by
default that realpath check is off so operator-configured in-root
symlinks may redirect to real data outside `root` — see *Canonical
scope* below.

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
into place after; a sidecar publish failure surfaces as
`PartialCompletion`, which is not retryable. The object bytes are
durable at that point, so a retry Layer must not replay the write —
that would change the etag under any concurrent `if_match` retry.
Re-apply the metadata with `update_metadata` instead.

Concurrency: every `IfDestExists` precondition re-checks the
destination under a per-target async mutex held across the
precondition check and the final rename. This closes the most
common race — concurrent writers in the same ovstorage process
colliding on the same address. Cross-process races on the same filesystem still
require kernel atomic primitives (Linux `renameat2 RENAME_NOREPLACE`,
Windows `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`) that the
plugin does not invoke. **Operators are responsible for
enforcement**: the host serving this backend (broker / REST gateway)
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
against the freshly synthesized etag before the operation. A mismatch
on the read fails with `ObjectModified`; on the mutating operations it
fails with `PreconditionFailed`, because nothing was committed. Writes
use `WriteOptions::if_dest`: `IfDestExists::Fail` fails with
`AlreadyExists` if the destination exists; `IfDestExists::MatchEtag(s)`
fails with `PreconditionFailed` if the destination's current etag
differs.

`CopyOptions::if_source` is checked twice: once before the read, which
fails with `PreconditionFailed`, and again after the bytes are staged
and before the destination is committed, which fails with
`ObjectModified` — there the source changed *during* the copy. The
second check narrows that window rather than closing it; the source
lock excludes only writers inside this process.

`UserMetadata` is patchable in place —
`supports_native_metadata_patch = true`. Windows stores it in an
NTFS Alternate Data Stream named `ovstorage.metadata`; non-Windows
builds use a hidden `.ovstorage-meta/` sidecar directory next to
the file. The sidecar is treated as plugin-owned internal state:
`list` hides it, direct user operations under `.ovstorage-meta`
return `InvalidArgument`, copy/rename moves it with the object,
and `update_metadata` stats the target before mutating any sidecar
so a missing path returns `NotFound`.

Canonical scope: the caller-supplied path must stay under the
configured `root` **lexically** (by name). URL-level normalization
collapses `..` / `.` / double-slash segments before they reach the
plugin, and any `..` that survives is rejected, so a caller cannot
name a path outside the served namespace.

**Virtual tree (default).** By default the backend *follows*
operator-configured in-root symlinks, including ones whose target
resolves outside `root`. This lets an operator compose a virtual
tree — symlinks inside the served root that point at where the real
data lives (`served/vdir -> /data/real`). This is safe because there
is **no Layer or public API to create symlinks** through the backend: the
only links in a served tree are ones the operator pre-configured on
disk by explicit intent, so following them reaches only paths the
operator deliberately wired up. It is operator-controlled
indirection, not a path by which an untrusted client can escape to
arbitrary host files.

**`confine_to_root` (opt-in realpath jail).** Setting
`confine_to_root = true` applies a realpath check: the resolved
native path, after following symlinks for existing components, must
remain under the canonical `root`. A direct object operation
(`stat`/`read`/`write`/`delete`/`copy`/`rename`/…) on an in-root
symlink that points outside fails with `PermissionDenied`, and the
recursive `list` / `watch_directory` walkers apply the same check to
every descended entry — an entry whose realpath resolves outside the
root is **omitted** from the listing / change snapshot rather than
enumerated, so a walk through an escaping directory symlink cannot
disclose the outside tree's entry metadata. Use it for deployments
that run the backend under a privileged service account (Brokered
mode) and want defense in depth against a mis-wired on-disk symlink.
Direct mode runs in-process under the app's own UID (no privilege
boundary), so the jail buys nothing there.

The flag is per **root**: it is read from the static
`[ovstorage.root]` / Stack config at instantiation *and* from each
runtime `add_connection` config, so a brokered host can arm the jail
on the connection it adds (a wrong-typed value is rejected on both
paths). A backend serving several connections can mix policies per
contributed root.

Read-side following and write-side commit are independent.
Write-like operations (`write`, `copy`) always commit through a temp
sibling plus `rename`, which *replaces* a final-component symlink
entry rather than following it — so a final-component in-root link
never redirects written bytes regardless of `confine_to_root`. A
*directory* symlink earlier in the path is still followed, so
`write served/vdir/obj` lands in `/data/real/obj` — the intended
virtual tree — unless `confine_to_root` denies the escape.

Directories are real: `has_real_directories = true`.
`create_directory` is `tokio::fs::create_dir_all` against the
resolved path, so it accepts an existing target directory and
creates missing ancestors. `delete_directory` first scans for any
entry other than the `.ovstorage-meta` name, which the removal
clears itself — a directory with its contents, and a link or any
other entry unlinked as itself, since the cleanup classifies the
entry without following a symlink — and returns
`DirectoryNotEmpty` if any remain. That scan is deliberately
narrower than the `list` / `watch_directory` filter: an in-flight
atomic-write temp sibling is hidden from enumeration but is a real
entry the kernel counts, so it blocks the removal and is reported
as `DirectoryNotEmpty` rather than surfacing after the sidecar dir
has already been cleared. `delete_directory` on a directory that
does not exist returns `NotFound`; the call is not idempotent.
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
served directory cannot hang a reader on a special file. An address
that names a directory is refused with `InvalidArgument` and guidance
to use `list`, and `materialize` applies the same guard.
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
`supports_copy`, `supports_rename`, `supports_server_side_copy`,
`supports_server_side_rename`,
`supports_atomic_rename`, `has_real_directories`, `supports_list`,
`supports_recursive_list`, `supports_native_metadata_patch`,
`populates_subdirectory_metadata`,
`populates_effective_permissions_on_stat`, and
`supports_access_check` are true. Version listing, redirect-based
reads/writes, metadata-rewrite emulation, and broker-managed
credentials are not part of the plugin.

`supports_watch_directory` is **false**, and `watch_directory`
nevertheless works. The bit reports the absence of a native
push-event source; the verb is served by polling instead. The two
disagree, so a caller that gates on the capability bit will never
call a verb that would have succeeded — call it anyway, and handle
`Unsupported`.

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

In Direct mode the backend runs in the application process and
inherits its UID; access is whatever the OS already enforces. In
Brokered mode it runs broker-side and the broker enforces
principal-aware policy; the backend itself enforces lexical scope
under the configured `root` (caller paths cannot name their way out
of the served namespace).

Symlinks inside a served tree are **operator state, not client
state**: there is no Layer or public API to create a symlink through the
backend, so the only links present are ones the operator wired up on
disk. Following them is therefore operator-controlled indirection
(the virtual-tree model), not a client-reachable escape — which is
why in-root symlinks that redirect outside `root` are followed by
default. Deployments that nonetheless want the backend to refuse any
symlink escaping `root` (e.g. a Brokered host under a service
account, defending against a mis-configured on-disk link) set
`confine_to_root = true` on the connection to apply the realpath
jail. See *Canonical scope* above.
