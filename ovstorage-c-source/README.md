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

## User-metadata sidecars

User metadata written through the file backend lives in a per-directory
sidecar: `<parent>/.ovstorage-meta/<hex(name)>.meta`, matching the Rust
backend's POSIX layout. Windows deliberately uses the same sidecar files
rather than the Rust backend's NTFS alternate data streams, so
cross-implementation metadata on Windows is not interoperable: metadata
written by this C backend is not visible to the Rust backend on NTFS and
vice versa.

Because the sidecar name hex-encodes the object name, it is roughly twice
the object's own basename length. An object whose basename is long enough
that the encoded sidecar exceeds the filesystem's per-component limit
(`NAME_MAX`, 255 bytes on typical POSIX and NTFS) cannot carry user
metadata. A write or `update_metadata` that sets non-empty metadata on such
an object reports an error. This C backend commits the object bytes first
and writes the sidecar afterward, so a write that fails only on the
over-long sidecar leaves the object bytes committed with no metadata and
returns the sidecar error — a divergence from the Rust reference, which
stages the sidecar before the object rename and so fails with the object
untouched. Objects that carry no user metadata are unaffected: the backend
treats an impossible-to-name sidecar as absent, so `write`, `read`, `stat`,
`delete`, `copy`, and `rename` of a long-named object without metadata all
succeed.

`delete_directory` removes the backend-owned `.ovstorage-meta` directory
and its contents when the enclosing directory is otherwise empty. A
name-surrogate reparse point — a symlink or directory junction — found in
(or standing in for) the sidecar directory is unlinked as the link itself
and never traversed, so a link is not knowingly followed out of the sidecar
namespace; real non-surrogate directory reparse points (cloud placeholders,
ProjFS) are recursed into like ordinary directories, matching Rust's
`remove_dir_all`. This is a best-effort, single-shot check rather than an
absolute guarantee: the classification and the directory open are separate
steps, so a process that swaps a real directory for a symlink in the
window between them could still redirect the cleanup. Rust's `remove_dir_all`
closes that race with `openat`/`O_NOFOLLOW`; hardening this backend the same
way is tracked follow-up work.

## Headless credential-store posture

The default credential store for a headless process is an ephemeral,
in-process keyring. Credentials remain only in memory, are never persisted,
and are zeroed before their storage is released. The Win32 implementation
uses `SecureZeroMemory` for that clearing. Consequently, credentials do not
survive a process restart and the application must authenticate again.

Persistent credential stores are supplied by storage plugins or by an
ovstorage broker deployment; they are not part of the standalone source
runtime's default store.

## OAuth helper status

`ovstorage-oauth` does not exist today and is not included in this source
distribution. OAuth device-flow and browser-flow helpers for C consumers are
planned for that crate, with delivery tracked by its owning PR. Until that
planned work lands, this source set provides no built-in OAuth flow helper;
applications obtain authentication through a capable plugin or broker, or
supply their own implementation.

## Platform status

POSIX and Win32 source paths compile in CI. The embedded `*_TEST_MAIN` suites
and the cc-test round-trip / contract harness run on both platforms; a few
cases remain Unix-gated where they pin POSIX-only facilities: symlink planting,
`chmod` mode bits, ThreadSanitizer's condvar race, the build-abandon
regression's companion plugin, and the callback-boundary allocation-failure
driver (whose leak assertion interposes `free` and forwards to `__libc_free`,
so it is glibc-only). Both shipped examples build and run through
`CMakeLists.txt.example` on POSIX and Windows. `Makefile.example` uses GNU
make, a POSIX shell, and `cc`-style flags, so Windows consumers use the CMake
example instead.
