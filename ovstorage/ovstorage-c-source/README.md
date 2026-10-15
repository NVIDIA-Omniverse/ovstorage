<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# ovstorage C/C++ source distribution

This directory is the standalone C implementation of the ovstorage ABI. Add
the files under `src/` to your application's build and add `include/` to its
header search path. The project does not ship a precompiled
`libovstorage.a`; consumers compile these sources themselves and may package
the resulting objects into a library owned by their build.

`Makefile.example` and `CMakeLists.txt.example` demonstrate that integration
model. They are examples rather than a separately supported ovstorage build
system.

Shipping source rather than a prebuilt static library is deliberate. A
precompiled object is usable only by a consumer whose platform, C runtime,
libc, and compilation flags agree with the ones it was built under, and those
axes form a cross product rather than a short list: a mismatch on any of them
fails at link, or links and then misbehaves at run time. Compiling these
sources inside the consumer's own build settles every axis the same way that
build already settles it, and it is the reason the integration surface is a
file list rather than a matrix of published binaries. What is meant to keep
this implementation aligned with the Rust one is not a shared binary but the
conformance suite that defines the contract — exercised against the Rust host
today, with shared coverage of this baseline still being extended, and not a
claim that the two are bit-for-bit identical.

## Header inventory

The copied C headers are frozen ABI inputs. Do not edit the copies in this
directory: the repository's header task keeps them byte-identical to their
canonical versions with a copy-and-diff check.

| Header | Provenance and use |
|---|---|
| `include/ovstorage.h` | Hand-maintained C application API compiled together with `src/*.c`. |
| `include/ovstorage_plugin.h` | Byte-copied from the canonical cbindgen-generated plugin and Layer ABI. |
| `include/ovstorage_defaults.h` | Hand-authored declarations for the passthrough and unsupported default Layer vtables. |
| `include/ovstorage.hpp` | Hand-authored, SPDX-licensed, header-only C++20 RAII and coroutine wrapper over `ovstorage.h`. It is not a cbindgen output. |

The C++ wrapper covers every C Layer operation. The cc-test suite derives the
operation set from `ovstorage.h` and requires an instantiated `LayerHandle`
method for each entry, so the two application surfaces cannot drift silently.

The `ovstorage_plugin.h` value-reclamation helpers (`ovstorage_plugin_*_free`
and `ovstorage_plugin_error_get_next_action`) are implemented in
`src/plugin_values.c`, so hosts built from this tree can reclaim every
plugin-ABI value the header documents as receiver-reclaimed.

The `ovstorage_plugin_auth_credential_decode` and
`ovstorage_plugin_auth_credential_free` declarations are plugin-owned SDK
helpers, not imports that a plugin resolves from its host. A C auth plugin
compiles `src/auth_credential.c`, `src/plugin_values.c`, `src/plat.c`, and
`src/utf8.c` into its own cdylib (or compiles the complete `src/*.c` set) so
decode, error cleanup, and free calls bind within that image. Rust hosts do not
promise process-global exports for these functions. The cc-test suite builds
an auth-capable C plugin with this support set under an undefined-symbol link
check, loads it with local symbol visibility, and invokes its decoder probe.

## Toolchain and dependencies

Compile the implementation translation units as C99 or later. On POSIX,
they require the POSIX.1-2008/XSI feature surface and 64-bit file offsets:
`_POSIX_C_SOURCE >= 200809L`, `_XOPEN_SOURCE >= 700`, and
`_FILE_OFFSET_BITS=64`. The private portability header supplies these values
when the build has not already selected them; do not compile with lower
values.

The optional C++ wrapper is async-only: every long-running method returns
`ovstorage::task<T>`, a C++20 coroutine type, and `ovstorage::sync_wait`
drives one from a non-coroutine caller. It therefore requires a C++20
toolchain with working coroutine support — GCC 13+, Clang 17+, or MSVC
19.40+. Both example build files probe that by compiling `ovstorage.hpp` and
report the floor if the compiler cannot. The C sources need only C99, so a
consumer whose C++ toolchain is below the floor can still build and use the
C API. Keep the `.c` files compiled as C and include `ovstorage.hpp` from C++
translation units.

Every callback the wrapper hands to the C API is `noexcept`, and the header
asserts it: the runtime invokes those thunks from C frames, and unwinding an
exception through one is undefined and would skip the dispatch and stream
pumps' own cleanup. An allocation failure inside a thunk is therefore turned
into a failed `ovstorage::Result` for the awaiting coroutine, which is always
resumed, and any payload the callback was handed to release is released
anyway. The one callback the wrapper does not own is the interactive-auth
observer supplied by the caller; an exception from it is reported as an
`Internal` failure naming what was thrown, and the observer is not called
again for that flow.

POSIX builds use the standard C library, pthreads, positioned I/O, and the
platform dynamic-loader API (`dl`, with `-ldl` where the platform requires
it). Win32 builds use the corresponding native thread, loader, and file APIs.
No Rust toolchain is needed to compile this tree.

This source set has no dependency on tokio, libcurl, or openssl and does not
link those libraries. A dynamically loaded plugin can have its own dependency
set; that does not change the dependency guarantee for the dispatcher,
runtime, and built-in file backend shipped here.

## C ABI stability at 1.0

The project is pre-1.0. At 1.0, stability applies to exported C symbols, POD
layouts, enum/status values, callback signatures, ownership rules, and
documented thread/cancellation behavior.

The two surfaces in this tree reach that guarantee differently, because they
are distributed differently:

- `ovstorage.h` is the header for the C implementation shipped beside it.
  Consumers compile the header and `src/*.c` together, so there is no binary
  boundary between them to freeze; its compatibility story is source-level,
  and it is free to evolve with the implementation it declares.
- `ovstorage_plugin.h` is a genuine binary contract. Plugins are prebuilt
  cdylibs the host `dlopen`s at runtime, so host and plugin are compiled
  separately and must agree on layout at the ABI level. It stays generated
  from the `ovstorage-plugin` crate, and a layout change requires a version
  bump.

The struct-extension machinery follows the distribution model, so the two
headers differ here:

- `ovstorage_plugin.h` uses two separate mechanisms, and they are not applied
  to the same structs. The 44 structs that cross the boundary as a
  caller-declared unit — every per-operation `*Options` and `*Request`, the
  manifest, the init result, both vtables, `HostCallbacks`, and the kind
  descriptors — begin with `size_t struct_size`. Callers set it to
  `sizeof(the version they compiled against)`; callees validate the known
  prefix before reading fields, accept larger future structs, and ignore
  unknown tails. Trailing reserved slots are the *second*, narrower
  mechanism: they sit on the `*Request` structs and the vtables, so a new
  field or function slot lands without moving anything. The `*Options`
  structs have no reserved slots (bar the two directory ones) and grow by
  appending a field and bumping `struct_size` — prefix validation is the
  whole guarantee there. Breaking layout or semantic changes require a new
  versioned type or symbol.
- `ovstorage.h`'s public structs carry neither `struct_size` nor reserved
  padding. Header and implementation are always compiled from the same tree,
  so there is no version skew for a size field to detect and no need to
  reserve space for fields that can simply be added. A field a caller does not
  know about cannot exist; a field that changes shape is a compile error --
  the same diagnostic prefix-validation machinery substitutes for on the
  plugin ABI, obtained here for free.

A consumer is of course free to repackage these sources into a shared library
of their own, and that does reintroduce a binary boundary — but it is *their*
boundary, spanning *their* build of the library and *their* callers. They own
its stability: they choose when to rebuild, what to version, and whether to
freeze layouts. This distribution cannot make that guarantee on their behalf
(it does not know which subset they export or when they cut a release), so it
does not charge every consumer for machinery only repackagers need. A
repackager who wants prefix-validated extensibility should add it at their own
surface, where they control both sides of it.

Completed snapshots use visible read-only structs: `OvStorage_Info`,
`OvStorage_Connection`, `OvStorage_AuthEvent`, `OvStorage_RootInfo`, and their
list forms. Pointer fields borrow storage owned by the enclosing snapshot;
list item arrays are contiguous and borrowed from the list. Destroy only an
independently owned snapshot or its enclosing list. `ovstorage_info_clone`
deep-copies an `Info` when it must outlive a borrowed list item.

Live runtime objects remain opaque handles. Buffers and snapshot strings are
copied into allocations released by their documented clear or destroy
function.

The storage plugin ABI is separately versioned from the application C API.
Both use versioned manifests/vtables and exact compatibility checks.

## Declarative Stack configuration

Applications can build the canonical `[ovstorage]` TOML schema directly rather
than reproducing its topology with imperative calls. The C surface owns an
opaque, reusable `OvStorage_StackConfig`; the C++20 wrapper exposes it as the
move-only `ovstorage::StackConfig`.

```c
OvStorage_Registry *registry = ovstorage_registry_create();
OvStorage_StackConfig *config = NULL;
OvStorage_LayerHandle *root = NULL;
OvStorage_Error error = {0};

OvStorage_Status status = ovstorage_stack_config_from_toml_path(
    "app.toml", &config, &error);
if (status == OvStorage_Status_Ok) {
    status = ovstorage_stack_build_from_config(
        config, registry, NULL, &root, &error);
}

ovstorage_layer_handle_destroy(root);
ovstorage_stack_config_destroy(config);
ovstorage_registry_destroy(registry);
ovstorage_error_clear(&error);
```

`ovstorage_stack_config_from_toml_path` applies the `OVSTORAGE__` environment
overlay. `ovstorage_stack_config_from_toml_str` deliberately does not.
`ovstorage_stack_config_from_default_path` tries `./ovstorage.toml`, then the
XDG user config path, and succeeds with a null config when neither exists.
Overlay prefixes and key paths are ASCII case-insensitive; key paths themselves
must be ASCII, values must be UTF-8, and overlapping table paths coalesce.

A parsed config retains literal credential bytes until it is destroyed. The C
loader clears file, overlay, and parser storage before releasing it, but
`${NAME}` references are preferred because only the placeholder remains in the
reusable config.

The registry controls factory resolution. Load trusted plugin cdylibs, register
their factories, and keep the plugin handles alive before building a config
that names those kinds. The config loader performs no directory scan and has
no backend-specific kind list. A config and registry remain reusable after a
blocking or asynchronous build starts.

## Layer config and connection roots

`ovstorage_stack_add_layer_config` records factory-time configuration for any
declared Layer and forwards it through the plugin ABI during Stack build.
Connection configuration remains separate.

The built-in file backend's `create_backend` accepts no Layer config: every
root arrives through a connection (`ovstorage_stack_add_connection` before
build, or `ovstorage_add_connection` at runtime) whose config carries a `root`
string. A configured file Layer fails with `InvalidArgument`, and a backend
with no connections routes nothing (`NoRoute`) rather than admitting every
path.

## User metadata

The file backend stores no user metadata. A `write` whose `user_metadata`
map is non-empty is refused with `Unsupported` before anything touches disk
(a present-but-empty map is accepted), `update_metadata` is `Unsupported`,
`stat` and `list` report an empty map, and the descriptor declares
`supports_user_metadata = false`. A `.ovstorage-meta` directory found on disk
is ordinary content: it is listed, addressable, and blocks `delete_directory`
of its parent with `DirectoryNotEmpty` like any other entry.

`delete_directory` clears an atomic-write staging temp whose writer no longer
holds its advisory lock; a temp whose lock is held is a write in flight and
refuses the removal with `DirectoryNotEmpty`. Every other entry blocks the
removal. A symlink or name-surrogate reparse point at the addressed directory
is refused with `InvalidArgument`, matching the Rust reference.

## Durable credential store

The standalone C host backs the plugin ABI's `secret_get`, `secret_put`, and
`secret_delete` callbacks with a dependency-free, durable plain-file store.
Its scope is one OS user, one auth directory, and one application namespace.
Credentials survive a process restart and are shared by every process for
that user that pins the same auth directory and namespace. Opening the
substrate is lazy: resolving and pinning it performs no file I/O until a
secret callback first uses the store.

`OvStorage_InitAuthSubstrateOptions.credential_namespace` selects the
application namespace. NULL selects `default`; an explicit value is 1–64
bytes of `[A-Za-z0-9._-]` and starts with an ASCII alphanumeric character.
Unrelated applications should choose distinct namespaces so that equal
plugin credential keys cannot collide. Cooperating applications share
credentials by choosing the same namespace.

Call `ovstorage_init_auth_substrate` before loading a plugin to pin the pair.
The pin is one-shot and process-global: repeating the same resolved directory
and namespace is a no-op, while changing either is unsupported. Passing NULL
for the options selects the default directory and namespace; a non-NULL
options struct must set at least one of `auth_dir` or `credential_namespace`.
An explicit empty or relative `auth_dir`, or an empty or relative
`OVSTORAGE_AUTH_DIR`, is invalid and does not pin the substrate: the store
re-opens paths under that directory for the life of the process, so it must
not move with the working directory (the same rule the platform variables
already follow). On Windows that also excludes drive-relative (`C:dir`) and
root-relative (`\dir`) forms: a drive qualifier must be followed by a
separator, or the path must be UNC, which is what the shared
`ovc_path_is_absolute` predicate enforces on every arm.
Every process that is meant to share credentials must pin the same pair.

The auth-directory resolution order is the same as in the Rust hosts:
`OVSTORAGE_AUTH_DIR`, then the platform per-user data directory plus
`ovstorage/auth`, then a user-scoped directory below the process temporary
directory when the environment names no home. The environment override is
the simplest way to pin a deployment or test. Within that directory a
namespace owns these paths:

- `<auth_dir>/c-credentials/<stem>.creds` is the record file.
- `<auth_dir>/c-credentials/<stem>.lock` coordinates readers and writers.
- `<auth_dir>/c-credentials/<stem>.creds.tmp` is transient replacement state.

The stem is the lowercase hexadecimal encoding of the namespace's ASCII
bytes. This injective encoding keeps case-distinct namespaces isolated on
case-insensitive filesystems while leaving namespace comparison case-sensitive.

On POSIX, the auth and `c-credentials` directories are `0700`, store files
are `0600`, and any missing ancestors the host creates on the way are `0700`
too rather than `0777 & ~umask` (a pre-existing ancestor keeps its mode);
opens refuse symlinks and files or directories owned by another user. On Windows, directories and files receive a protected owner-only DACL
and reparse points are refused; a pre-existing directory or file is accepted
only if its owner is the process token's user or the token's default owner
(the built-in Administrators group for an elevated token), because a foreign
owner keeps implicit `READ_CONTROL | WRITE_DAC` no matter what the DACL says,
so it is refused with `EACCES` as on POSIX. These file permissions are the
whole protection for the credentials: the bytes are stored in the clear, as
they are in the Rust store. The store does not put credential values in its
errors or logs.

Every mutation holds the namespace lock, reads and validates the complete
record file, writes a complete replacement to `.creds.tmp`, syncs and closes
that file, atomically replaces `.creds`, and syncs the containing directory.
On Windows every file primitive inside the lock (opening `.creds`, removing a
stale `.creds.tmp`, creating the replacement, and the replacement itself)
retries a transient sharing or access-denied failure, because an antivirus
scanner or the search indexer commonly holds a freshly written file open for a
few milliseconds without write or delete sharing, and a single attempt would
turn that into a spurious `secret_get` or `secret_put` failure under
cross-process contention. The retries share one two-second budget per
operation, so a held file delays an operation by at most two seconds in total
against the ten-second lock timeout other processes are waiting on; once the
budget is spent the failure is reported with the same error a single attempt
would have given. A read-only `.creds.tmp`, or a file whose ACL genuinely
denies the process, spends that budget before the same error is reported. A
failure before replacement leaves the prior record file in place. A
failure to sync the directory after replacement is still reported because
the replacement's crash durability is not guaranteed. The next mutation
removes stale transient state before creating its replacement. A process
crash therefore cannot expose a partially written `.creds` file.

Reads use the same lock, so processes observe a complete file rather than a
partial update. Lock acquisition is bounded at 10 seconds; exceeding that
bound returns `Transient`. The lock file is per namespace, so unrelated
namespaces do not serialize each other.

The v1 file begins with the 16-byte `ovstorage-creds\0` magic, followed by a
little-endian 32-bit format version and record count. Each record contains
four little-endian 32-bit lengths followed by the bytes for `backend_kind`,
`connection_id`, `field`, and credential value, in that order. A trailing
64-bit little-endian FNV-1a checksum covers every preceding byte. The
checksum detects damage; it is not encryption or cryptographic
authentication.

A corrupt, truncated, oversized, or unsupported record file is refused and
reported as `StateRootUnavailable`, with the record-file path and the reason
in the error; a path too long for the message is elided from the left so the
file name and the reason both survive.
The host never resets or overwrites that file during a failed read. Recovery
is an operator action: move the named file aside and authenticate again to
create a fresh store.

Store-owned credential buffers and temporary encoded images are zeroed before
release (`SecureZeroMemory` on Windows). This limits ordinary reuse of freed
memory but makes no promise of forensic secure deletion from memory, storage,
backups, or filesystem snapshots.

Directory, permission, format, and I/O failures surface from `secret_get`,
`secret_put`, or `secret_delete`; persistence failures are never converted to
an in-memory success. There is no in-memory fallback. The C store does **not**
interoperate with the Rust hosts' `auth.sqlite`, even though both stores live
under the same resolved auth directory.

### Test harnesses

Any harness or example that drives the C host without calling
`ovstorage_init_auth_substrate` resolves the real per-user auth directory. It
must set `OVSTORAGE_AUTH_DIR` to a scratch root before loading a plugin,
because the credential store persists anything the run writes. The
`make c-source-examples` gate pins this variable beneath its own temporary
root for every leg it runs: the examples, the embedded `*_TEST_MAIN` suites,
the secret-wipe seam, and the leak contracts.

### Why a plain file rather than sqlite

SQLite and a plain file were both acceptable durable designs. The plain file
fits this store because an application namespace normally holds only a
handful of records, and every required primitive — exclusive create, file
and directory sync, atomic rename-replace, owner-only DACL construction, and
secure zeroing — already exists in this source tree. The sqlite amalgamation
would add roughly a quarter-million lines of third-party C, WAL shared-memory
caveats, and third-party-notice maintenance to a distribution whose
integration surface is deliberately a file list.

## OAuth helper status

`ovstorage-oauth` does not exist today and is not included in this source
distribution. OAuth device-flow and browser-flow helpers for C consumers are
planned for that crate, with delivery tracked by its owning PR. Until that
planned work lands, this source set provides no built-in OAuth flow helper;
applications obtain authentication through a capable plugin or broker, or
supply their own implementation.

## Platform status

POSIX and Win32 source paths compile in CI. The embedded `*_TEST_MAIN` suites,
including the dedicated `credential_store` suite, and the cc-test round-trip /
contract harness run on both platforms; a few cases remain Unix-gated where
they pin POSIX-only facilities: symlink planting and credential-store symlink
assertions (the Win32 `temp_dir` suite plants its own symlinks when Developer
Mode or `SeCreateSymbolicLinkPrivilege` allows it, and skips those legs
otherwise), `chmod` and credential-store mode-bit assertions,
ThreadSanitizer's condvar race, the build-abandon regression's companion
plugin, and the callback-boundary allocation-failure driver (whose leak
assertion interposes `free` and forwards to `__libc_free`, so it is
glibc-only). Both shipped examples build and run through
`CMakeLists.txt.example` on POSIX and Windows. `Makefile.example` uses GNU
make, a POSIX shell, and `cc`-style flags, so Windows consumers use the CMake
example instead.
