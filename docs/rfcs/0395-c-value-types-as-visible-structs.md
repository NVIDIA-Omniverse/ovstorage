<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# RFC-0395: expose C snapshot types as visible structs instead of opaque handles

- **Status:** Implemented
- **Depends-on:** RFC-0066 (layered architecture)
- **Supersedes:** —
- **Superseded-by:** —

> At the measured base, `ovstorage.h` declares 174 functions. 80 of them are
> field accessors on eight opaque types whose contents are a completed snapshot.
> That shape exists because a prebuilt Rust cdylib could not expose struct
> layouts to a separately-compiled C caller; the API has shipped as source since
> 0.2, so the constraint is gone. In isolation this RFC makes those eight types
> visible structs, deletes the 80 accessors, and adds one function and one type —
> taking the measured header from 174 declared functions to 95. The landed
> header declares 103 functions after the prerequisite and subsequent
> additive operation work.

## Vocabulary

Four words carry the argument and are used in a specific sense throughout.

- **Snapshot** — a value whose contents are complete when the caller receives
  it and never change afterwards. This is the scope test: a snapshot has no
  live resources, no post-construction mutation, and no consumed-on-use
  semantics. It is the criterion that puts eight types in scope and twelve out.
- **Accessor** — a function whose whole body reads one field of a handle, such
  as `ovstorage_info_size`. These are what this RFC deletes.
- **Owned** — the receiver is responsible for releasing it, by calling the
  type's `_destroy`.
- **Borrowed** — the receiver may read it but must not release it, and must not
  use it after the owner is destroyed.

The eight in-scope types stay **library-allocated and library-freed**: the
caller owns the *handle* and calls `_destroy`, exactly as today. What changes is
that its fields become readable without a function call.

## Context

`ovstorage.h` is 3000 lines, of which 2163 are comment. The declaration bulk is
not operations; it is accessors. Measured on `fc3becd2` by extracting
column-zero function declarations with the link-completeness gate's own regex
(`tools/ovtasks/_c_source_examples.py:58-62`), partitioning by type prefix
longest-first so that `root_info_list_` does not fall into `root_info_`, and
subtracting each type's `_destroy` plus the three `ovstorage_list_*`
*operations*:

| type | accessors | also declared |
| --- | --- | --- |
| `OvStorage_RootInfo` | 25 | `_destroy` |
| `OvStorage_Connection` | 18 | `_destroy` |
| `OvStorage_Info` | 14 | `_destroy` |
| `OvStorage_AuthEvent` | 11 | `_destroy` |
| `OvStorage_List` | 4 | `_destroy`, and 3 list operations |
| `OvStorage_VersionList` | 4 | `_destroy` |
| `OvStorage_ConnectionList` | 2 | `_destroy` |
| `OvStorage_RootInfoList` | 2 | `_destroy` |
| **total** | **80** | |

`OvStorage_RootInfo` is a bodyless forward declaration (`ovstorage.h:256`) and
every one of its fields is reached through a call. Each accessor carries a doc
block, which is where most of those 2163 comment lines go.

The reason is historical. Because the consumer now compiles the header together
with `ovstorage-c-source/src/*.c` from one tree, there is no binary boundary
between them and no version skew to guard against — which is why
`tools/ovtasks/_headers.py:11-27` records that `ovstorage.h` is deliberately
**not** a cbindgen target, while `ovstorage_plugin.h` "has to be" (plugins are
prebuilt cdylibs the host `dlopen`s, a real binary contract). Opaque handles
plus accessors are what a *generated* binding to a prebuilt library needs. This
header is neither.

**The storage is already suitable.** `internal.h:404-430` defines `RootInfo` as
a flat struct of individually `malloc`'d `char *`, deep-copied from the plugin
value at `dispatch.c:1688-1798`. `Info` (`internal.h:157`), `Connection`
(`:365`) and `AuthEvent` (`:390`) are the same kind of flat owned-string struct,
with two complications this RFC handles explicitly: `Info` leads with a refcount
(`:158`) and `AuthEvent` holds an owned `Connection *` (`:399`). Nothing borrows
from plugin state, and `ovstorage.h:251-255` already documents the lifetime —
owned strings are "pre-baked into CStrings", meaning duplicated into the struct
at construction, "so per-field accessors return borrowed pointers valid for the
lifetime of the handle." Exposing the layout publishes a decision the
implementation has already made.

**The pattern already exists in this header.** `OvStorage_AccessDecision`
(`ovstorage.h:329`) and `OvStorage_Bytes` (`:335`) are visible structs with
explicit `_clear` / `_destroy`; `OvStorage_Capabilities` (`:443`) is a visible
struct of scalars needing no destructor at all. This RFC extends an existing
convention rather than introducing one.

Touches the Software Design Document's C/C++ surface section.

**Not in scope:** completing the *operation* surface. `ovstorage.h` exposes 20
Layer operations against 31 operational vtable slots, and the seven with no C
entry point are tracked separately as **#394**. That work is additive and should
land first; this RFC concerns only the value types.

## Decision

**Types whose contents are a completed snapshot become visible structs, and
their per-field accessors are deleted.**

In scope, exactly eight: **`OvStorage_Info`, `OvStorage_RootInfo`,
`OvStorage_Connection`, `OvStorage_AuthEvent`, `OvStorage_List`,
`OvStorage_VersionList`, `OvStorage_ConnectionList`,
`OvStorage_RootInfoList`.**

`ovstorage.h` declares exactly 20 opaque typedefs; the other twelve stay opaque,
each for a stated reason:

| type | why it stays opaque |
| --- | --- |
| `OvStorage_ConfigValue` | **Consumed request input, not a snapshot.** `ovstorage_connection_request_add_config` (`values_conn.c:491-521`) stores the caller's pointer without copying and takes ownership on success. |
| `OvStorage_ConnectionRequest` | Mutable builder carrying a `consumed` flag (`internal.h:362`). |
| `OvStorage_SecretBundle` | Mutable, `consumed` (`internal.h:351`), zeroing destructor. |
| `OvStorage_SecretValue` | Write-only by contract, zeroing destructor. |
| `OvStorage_UpdateMetadataOptions` | Caller-mutated builder with growable capacity (`internal.h:185-192`), rewritten in place by `ovstorage_update_metadata_options_set` (`values.c:719`) and `_remove` (`:765`). |
| `OvStorage_KindDescriptorList` | Slices point into a shared `string_storage` arena with **no NUL terminators** (`internal.h:208-219`); accessors reject interior NULs at read time and return `(ptr, len)`. |
| `OvStorage_LocalDelegate` | Carries a release callback plus opaque context that the destructor invokes (`internal.h:196-201`). A live handle. |
| `OvStorage_Stack`, `OvStorage_LayerHandle`, `OvStorage_Plugin`, `OvStorage_Registry`, `OvStorage_CancelToken` | Live resources: mutexes, condvars, in-flight counts, refcounted registrations keeping cdylibs mapped (`dispatch.c:45-54`). |

### The ownership model

Unchanged from today in one respect and new in another. Unchanged: the struct is
**allocated and freed by the library**, and the caller calls `_destroy` on the
handles it owns. New:

- Fields are **read directly** rather than through a call. String fields are
  NUL-terminated `const char *`; byte fields are pointer-plus-length. Both are
  **borrowed** for the lifetime of the owning struct.
- The caller **must not mutate any field, must not `free()` any field pointer**,
  and must not retain a field pointer past the owning struct's `_destroy`.
- Items reached through any of the four lists are borrowed subobjects. The
  caller must not pass `&list->items[i]` to the item's `_destroy`; doing so
  compiles and frees an interior pointer into the list's contiguous allocation.
- **`memcpy` of one of these structs is wrong.** It produces an alias whose
  fields are freed by the original's destructor. This is visible layout with a
  retained destructor — not value semantics.

### Metadata becomes a public type

`Info`, `Connection` and `RootInfo` all reach their metadata through the private
`ovc_metadata_entry` (`internal.h:128-131`, used at `:167`, `:169`, `:372`,
`:425`). Twelve of the 80 deleted accessors are metadata `_len` / `_key` /
`_value` triples, and they have no direct-field replacement until that type is
public. So this RFC promotes it:

```c
typedef struct OvStorage_MetadataEntry {
    const char *key;    /* NUL-terminated, borrowed from the owning struct */
    const char *value;
} OvStorage_MetadataEntry;
```

Each carrier exposes `const OvStorage_MetadataEntry *user_metadata` plus
`size_t user_metadata_len` (and the `system_metadata` pair on `Info`). This is
the **only public type this RFC adds**, alongside the one function below.

### The struct definitions

Each in-scope struct publishes the field set its `internal.h` definition already
holds — `Info` at `internal.h:157-171`, `Connection` at `:365-383`, `RootInfo`
at `:404-430` — with five mechanical substitutions: `char *` becomes
`const char *`, `char **` becomes `const char *const *`, `uint8_t *` becomes
`const uint8_t *`, `ovc_metadata_entry *` becomes
`const OvStorage_MetadataEntry *`, and `Info`'s leading `ovc_ref_count` is
dropped (see below). `Info` is shown here as the pattern; the other two follow
it exactly and are not reproduced, since the cited definitions are normative.

The const qualification expresses the caller's view, but the public definition
is also the definition used by the C implementation. Builders still allocate
and populate the storage, and the clear/destroy helpers release it through
explicit casts such as `free((void *)info->address)`. Those casts are the
accepted implementation cost of preventing callers from mutating owned fields;
omitting them is a constraint violation and fails the MSVC `/W4 /WX` gate.

```c
typedef struct OvStorage_Info {
    const char *address;
    OvStorage_ObjectKind kind;
    bool has_size;
    uint64_t size;
    bool has_mtime_unix_nanos;
    uint64_t mtime_unix_nanos;
    const char *etag;                 /* NULL when absent */
    const char *version;              /* NULL when absent */
    const OvStorage_MetadataEntry *user_metadata;
    size_t user_metadata_len;
    const OvStorage_MetadataEntry *system_metadata;
    size_t system_metadata_len;
} OvStorage_Info;
```

### Optional fields keep their existing representation

Optional fields are published in **exactly the shape the internal struct already
uses**: a `bool has_x` companion beside a scalar `x`, and a NULL pointer for
absent pointer fields. There is no conversion to a uniform NULL-means-absent
rule, because two current behaviours prove NULL cannot carry the information:

- **`has_size` / `has_mtime_unix_nanos` gate `uint64_t` scalars where 0 is a
  legal value** (`internal.h:161-164`). A pointer cannot express this without
  boxing the scalar.
- **`ovstorage_root_info_icon_data` returns a static empty-icon sentinel**
  (`values_conn.c:1151-1157`) when `has_icon` is true but `icon` is NULL.
  Present-but-empty is *deliberately* distinguishable from absent; one pointer
  cannot express both. As `has_icon` / `icon` / `icon_len` it is exact.

`RootInfo`'s three-level tag chain (`source_kind` → `source_alias_source_kind` →
`source_alias_source_static_layer`) is likewise published as the flat field set
`internal.h:413-424` already holds. No variant structure is redesigned.

**One normalization retires and becomes caller-visible.**
`ovstorage_root_info_display_name` returns `""` when the field is NULL
(`values_conn.c:963-969`) — accessor and field disagree. As a field it is NULL
when absent. `ovstorage.hpp:1235` already routes it through `cstring()`
(`:1063-1066`, NULL → `""`), so the C++ surface is unchanged.

### Lists own contiguous item arrays

```c
typedef struct OvStorage_List {
    const OvStorage_Info *items;   /* len entries, contiguous */
    size_t len;
    const char *next_page_token;   /* NULL when absent */
} OvStorage_List;
```

and likewise `OvStorage_VersionList`, `OvStorage_ConnectionList` and
`OvStorage_RootInfoList` (neither of the latter two has a page token). The list
owns its items; `_destroy` frees them, and `items` is borrowed.

Contiguity loses no representable state: the four builders abort and destroy the
partially-built list on a failed item conversion (`dispatch.c:2409`, `:2453`,
`:5470`, `:5913`), so a NULL item is unreachable and the existing
`items[index] == NULL` guards (`values.c:929`, `:982`) are defensive only.

### `Info` loses its refcount, and gains a clone

`OvStorage_Info` is refcounted today (`ovc_info_retain`, `values.c:163`).
`internal.h:150-156` states why: `item_info` "retains and returns the same
handle, which keeps the accessor allocation-free while preserving the public
owned-handle convention used by the C++ wrapper." So the refcount exists to
serve one seam — `ovstorage_list_item_info` / `ovstorage_version_list_item_info`
(`values.c:935`, `:988`) return an independently owned `Info *` that survives the
list, and return NULL on refcount saturation. Their sibling
`ovstorage_list_item_address` (`values.c:925`) returns a borrowed pointer into
the same element. Two accessors on one element, opposite ownership.

A visible struct cannot carry a refcount safely, because `memcpy` would
duplicate it silently. **So refcounting is removed from both the public contract
and the implementation:**

- Items reached through `list->items[i]` are **borrowed** and die with the list.
- **`OvStorage_Info *ovstorage_info_clone(const OvStorage_Info *)`** is added.
  It deep-copies and returns an owned `Info *`. This is the **only function this
  RFC adds**.

`ovstorage_info_destroy` survives, for a cloned `Info` and for the one delivered
by the `stat` / `read_bytes` callbacks (`ovstorage.h:346`, `:359`).

No `_clone` is added for `RootInfo` or `Connection`. The asymmetry is not
arbitrary: their list item accessors already return **borrowed** pointers today
(`ovstorage_connection_list_item_at` at `values_conn.c:814`,
`ovstorage_root_info_list_item_at` at `:1180`), so making their items borrowed
removes no capability that exists. Only `Info` had an owning item accessor, so
only `Info` needs a replacement for it. See open question 2.

### `AuthEvent` becomes a real tagged union

`AuthEvent` **is** a snapshot: `dispatch.c:1834-1927` deep-copies a fresh public
event from the plugin event, `:3218-3246` hands it to the callback and clears
only the plugin event, and `ovstorage.h:494` transfers ownership to the
callback, which frees it with `ovstorage_auth_event_destroy`. It outlives the
callback.

But its internal struct (`internal.h:390-402`) is **flat**: eleven payload
fields for five payload-bearing variants, no `has_*` flags, absence expressed
only by `kind` not matching, non-active fields reading as zeros. The eleven
accessors exist to hide exactly that, so it is restructured into a union
discriminated by `kind`:

```c
typedef struct OvStorage_AuthEvent {
    OvStorage_AuthEventKind kind;
    union {
        struct { const char *url; uint64_t expires_at_unix_nanos; } open_browser;
        struct { const char *user_code; const char *verification_url;
                 uint64_t expires_at_unix_nanos; uint64_t interval_nanos; } device_code;
        struct { const char *message; } progress;
        struct { const OvStorage_Connection *connection; } succeeded;
        struct { OvStorage_Status code; const char *message; } failed;
        /* Cancelled carries no payload. */
    } as;
} OvStorage_AuthEvent;
```

`succeeded.connection` is a borrowed const view of a separately allocated
connection owned and freed by the event. It must not be passed to
`ovstorage_connection_destroy`; retaining the `const` pointer preserves the
compiler diagnostic that protects that ownership rule today. The internal
field is `OvStorage_Connection *` (`internal.h:399`), the event destructor frees
it at `values_conn.c:833`, and the accessor returns the borrowed const pointer
at `:907-914`.

A `Succeeded` event with no connection is not a reachable state.
`ovc_dispatch_auth_event_from_plugin` destroys the event and returns NULL when
the nested conversion fails (`dispatch.c:1903-1908`). The pump then suppresses
delivery, cancels the stream, and reports the existing terminal `Internal`
error (`:3230-3243`, `:3261-3268`). The conversion may fail because of OOM or
malformed plugin ABI data, neither of which is an authentication failure, so it
must not be translated into an `AuthEvent::Failed`.

`ovstorage_auth_event_destroy` is tag-dispatched. It switches on `kind` and
releases only the active variant's owned payload: the URL for `OpenBrowser`,
both strings for `DeviceCode`, the message for `Progress`, the nested
connection for `Succeeded`, and the message for `Failed`; `Cancelled` releases
no payload. Every construction path sets `kind` before storing the first owned
payload that an OOM-unwind path can send to the destructor. Implementation
verification constructs and destroys every variant independently and forces
each incremental-construction failure point, proving that the active payload is
released without reading or releasing an overlapping inactive member.

**Reading an inactive union member is undefined behaviour**, where reading an
inactive field of today's flat struct merely returns zero. This is the sharpest
edge in the RFC; see Consequences.

## Consequences

**In isolation, 80 functions are deleted and one function and one type are
added: the measured header goes from 174 declared functions to 95**, along with
the majority of its comment bulk. Because #394 lands first and adds seven
operations, the implementation target after both changes is 102 functions
(`181 - 80 + 1`).

**Plugin C ABI: unchanged.** `ovstorage_plugin.h` is not touched and its 37
functions are unaffected. The consumer-facing option structs never cross the
plugin ABI.

### Three things stop being checked for the caller

Every accessor in the deleted set performs a check that a field read does not.
This is a **semantic** change, not only a syntactic one, and it is the bulk of
the implementation risk.

1. **NULL handles.** Every deleted accessor accepts NULL and returns a
   documented default — `ovstorage_info_size(NULL)` is 0,
   `ovstorage_auth_event_kind(NULL)` is `Cancelled` (`ovstorage.h:2458`).
2. **Indices.** The list item accessors bounds-check (`values.c:925`).
3. **Active variants.** `Connection`'s source and auth payload accessors gate on
   the tag (`values_conn.c:738`, `:773`); so do `RootInfo`'s source and alias
   payloads (`:1012`, `:1043`, `:1106`) and `AuthEvent`'s (`:844`, `:916`). The
   conversion at `dispatch.c:1718` copies optional payload fields independently
   of `source_kind`, so the accessors are actively hiding populated-but-inactive
   fields. For the new `AuthEvent` union this is no longer a wrong answer but
   undefined behaviour.

The library's own contracts are unaffected — every callback documents when its
pointer is NULL — but consumers inherit all three obligations.

### `ovstorage.hpp` is the largest consumer, and its migration is not mechanical

70 of the 101 non-table call sites are in the C++ wrapper. Two decisions belong
to this RFC rather than to the implementer.

**It must gain the NULL guards it does not currently have.** The wrapper's
accessors do no handle checking — `ovstorage.hpp:337` is
`return ovstorage_info_size(handle_);` with `handle_` unguarded, and the same
holds at `:335-336`, `:344-348`, `:1033-1044` and `:1235`. Its string
accessors wrap the *return* in `cstring()` / `string_or_empty()` (`:378`,
`:1063`), which handles a NULL result, not a NULL handle. Across 3717 lines
there are 20 `handle_ == nullptr` tests, all early guards on Layer operations
that return `detail::null_handle_result<T>()`. There are also 22
`handle_ != nullptr` tests: 20 in reset paths and two in `CancelToken::cancel`
and `CancelToken::is_canceled`. Not one value-type accessor guards its handle.
The wrapper is therefore relying on the C accessors' NULL tolerance today, and
its RAII types are move-only — so a moved-from `Info` is reachable, and
`handle_->size` on one compiles and segfaults. **Unlike the accessor deletions,
this is not a compile error**, which makes it the most dangerous part of the
change. The migration extends the wrapper's established early-guard discipline
to every affected value accessor, returning the deleted C accessor's documented
default, and adds tag guards wherever it reads a variant payload — for example
`failed_error_code()` (`:1194`), which today safely returns `Ok` for a
non-`Failed` event.

**`List::info(i)` returns a non-owning view.** Today it is
`Info(ovstorage_list_item_info(handle_, index))` (`:533`, and `:580` for
`VersionList`) — the retained pointer handed straight into an owning RAII `Info`.
Once items are borrowed, `Info(&list->items[i])` would double-free. The
alternative of cloning per item was rejected: it converts the allocation-free
refcount bump `internal.h:150-156` describes into a deep copy of `address`,
`etag`, `version` and both metadata arrays *per item, inside every listing
loop*. So `List::info(i)` returns a borrowed view type that dies with the list,
and callers who need it to outlive the list call an explicit `.clone()` over
`ovstorage_info_clone`. **This is a C++ API break** beyond the mechanical churn:
the return type changes, and code storing the result must adapt.

### The contiguous-item change is not confined to the builders

Making list items inline requires a **clear/destroy split** that does not exist
today. The four destructors currently free each item as its own heap block via
the public destructor (`values.c:908`, `:960`; `values_conn.c:793`, `:1159`), so
after the change they must clear fields in place instead. That means internal
`ovc_info_clear` / `ovc_connection_clear` / `ovc_root_info_clear` helpers, with
each public `_destroy` becoming clear-then-`free`. The same split is what lets
the list allocations own inline items safely; `AuthEvent` keeps its separately
allocated succeeded connection. The four builders (`dispatch.c:2407`, `:2451`,
`:5468`, `:5911`) and their OOM unwind paths change with them.

### Gate and churn

**The link-completeness gate needs a mechanical edit.**
`tools/ovtasks/_c_source_examples.py:102-146` enforces exact set-and-count
equality between column-zero declarations in `ovstorage.h` and
`OVSTORAGE_API_REF(...)` entries in `completeness.c` — currently 174 on each
side. A separate invocation checks 37 declarations in `ovstorage_plugin.h`
against 37 `OVSTORAGE_PLUGIN_API_REF(...)` entries; this RFC does not touch that
table. 80 application entries go and one arrives. Note the gate gives **no
coverage for this RFC's actual risk**: it compares symbol *sets*, never
ordering, struct layouts, or whether an accessor's *implementation* was left
behind after its declaration disappeared. Removing the definitions is a review
obligation, not a gated one.

**Consumer churn, by grepping the exact 80-name deletion set:**

| site | call sites |
| --- | --- |
| `ovstorage-c-source/include/ovstorage.hpp` | 70 |
| `ovstorage-core/ovstorage-c-source-cc-test` C TUs (`roundtrip_c.c` 6, `streams_c.c` 4, `stack_build_parked_c.c` 1) | 11 |
| `ovstorage-c-source/examples/c_roundtrip.c` | 6 |
| `ovstorage-c-source/src/dispatch.c` disabled self-test | 14 |
| `completeness.c` table entries | 80 |
| C producers (`ovstorage-core/ovstorage/tests/csrc`, `ovstorage-core/ovstorage-python/tests/csrc`) | 0 |

The 14 `dispatch.c` sites are inside the `OVC_DISPATCH_TEST_MAIN` block
(`dispatch.c:6112-7867`). No repository build defines that preprocessor symbol,
so these calls are outside the compile-error safety net. The implementation
must migrate them by inspection alongside the compiled consumers.

**Unaffected:** broker, REST, CLI, services and the Python binding have zero
`ovstorage_*` C-symbol hits; Python is pyo3 over the Rust core and never
includes this header.

**Migration for C consumers is mostly mechanical and loud.** Every deleted
accessor is a compile error with an obvious direct-field replacement —
`ovstorage_root_info_display_name(r)` becomes `r->display_name`. The exceptions
are the ownership flip on `list_item_info`; `display_name` returning NULL rather
than `""`; the NULL-handle, index and active-variant checks the caller now owns;
and the `AuthEvent` union paths, where
`ovstorage_auth_event_device_code_user_code(e)` becomes
`e->as.device_code.user_code`. The list ownership flip is silent rather than
loud: retaining the existing `ovstorage_info_destroy` call on
`&list->items[i]` compiles and frees an interior pointer.

**Two capabilities are deliberately dropped:** `Info` refcount sharing (replaced
by an explicit deep copy) and the empty-icon sentinel (replaced by the
`has_icon` / `icon` / `icon_len` triple, which is strictly more expressive).

**This is a breaking API change**, which 0.x permits with a stated reason. It
lands after the 0.3 issue burn-down, and after #394.

## Alternatives considered

**Route operations through the Layer vtable and delete the `ovstorage_*`
operation functions.** This was the original shape of this proposal and it is
**rejected on evidence**, recorded here because it keeps being re-proposed — an
integrator hit the gap #394 tracks and reasonably asked why the wrappers exist
at all.

The premise was that the operations are declared twice — once as vtable slots,
once as free functions — so source distribution makes the duplication
unnecessary. The code refutes it. The free functions are not declarations; they
are the host implementation: the first 6111 lines of `dispatch.c`, before its
1756-line disabled self-test. Calling a slot directly means taking over:

- **The quiesce.** `in_flight` is incremented only inside
  `ovc_dispatch_operation_create` (`dispatch.c:512-514`), and
  `ovstorage_layer_handle_destroy` blocks on `while (handle->in_flight != 0)`
  (`:933`) before invoking `vtable->drop`. A direct slot call is invisible to
  that counter, so Stack destruction tears the Layer down underneath it. There
  is no public way to participate.
- **The synchronous prologue.** `ovc_dispatch_invocation_retain` (`:526-540`)
  holds a second reference because a Layer may invoke `on_complete`
  synchronously and keep using its state before returning from the slot.
- **ABI-heap marshaling.** Stamp `struct_size`, zero `_reserved[8]`, and copy
  the address into an owned, never-null, non-NUL-terminated
  `OvStoragePlugin_Str` the callee adopts.
- **Cancel-token minting** (`:4261`), refcounted with clone/drop slots.
- **Post-submit request zeroing** (`:4265`), because the v2 handshake moves
  nested allocations into the Layer. Getting this wrong is #383.
- **Thread-pool offload** (`ovc_runtime_submit`), which is what makes it safe
  for the caller to free its arguments on return.
- **Stream collection.** `read_bytes` assembles a stream the `read` slot only
  returns a handle for, with the pump registered on the handle so
  `layer_handle_destroy` can cancel it (`:930-931`).

Nor are the surfaces congruent. There are 31 operational slots plus `drop`
(`ovstorage_plugin.h:3096-3150`) against 20 C operations — `stat`, `read_bytes`,
`read_stream`, `read_local_file`, `write`, `delete`, `copy`, `rename`,
`update_metadata`, `check_access`, `list`, `list_versions`,
`list_address_roots`, `list_connections`, `create_directory`,
`delete_directory`, `add_connection`, `remove_connection`,
`update_connection_credentials`, `authenticate_connection` — and neither is a
subset of the other. Deleting the operation functions would not remove
duplication; it would relocate threading, quiesce, marshaling and stream pumping
into every consumer. **The real defect behind the complaint is the seven missing
entry points, which #394 fixes additively.**

**Represent every optional field as a NULL pointer.** Unsound: it cannot express
an optional `uint64_t` where 0 is legal (`has_size`, `has_mtime_unix_nanos`,
`last_probed`), and it collapses the icon's present-but-empty case into absent.

**Keep `Info` opaque.** Safest — no `memcpy` hazard, no API break, retain
semantics preserved. Rejected because it costs 14 of the 80 accessors and forces
`List` and `VersionList` to stay opaque too (their item getters are the retain
seam), leaving the most-used type accessor-only.

**Make `Info` visible with an opaque leading header field**, keeping the
refcount. Rejected: it publishes a struct that must not be copied without any
means of enforcing that, and preserves a refcount whose only purpose was the
seam this RFC removes.

**Clone per item in `List::info()`.** Rejected — see the `ovstorage.hpp`
section; it puts a deep copy in every listing loop to preserve a C++ signature.

**Expose lists as `const T *const *items`**, matching today's pointer-array
storage. Rejected: double indirection in the public surface and a per-item NULL
check the contiguous form does not need. `Connection`'s `char **addresses`
(`internal.h:369-370`) is the one place double indirection is unavoidable: an
array of NUL-terminated strings has no flatter representation. It retains that
pointer-array shape, const-qualified as `const char *const *`.

**Publish `AuthEvent`'s flat struct as-is**, deleting 11 accessors with no
internal change. Rejected: it publishes the variant footgun the accessors hide —
reading `device_code.user_code` on an `OpenBrowser` event would return NULL
rather than being visibly wrong.

**Do nothing.** Defensible: the header works and this fixes no defect. Rejected
because the accessor bulk is pure cost — it is the first thing every C consumer
reads, and it exists for a constraint removed a release ago.

## Open questions

1. **Does any consumer rely on the opacity itself** — holding a `RootInfo *`
   across a rebuild and expecting the accessors to reflect new state? The
   deep-copy at `dispatch.c:1688` says no in-tree, but external integrators
   should be asked before this lands.
2. **Should `ovstorage_root_info_clone` and `ovstorage_connection_clone` be
   added for symmetry with `ovstorage_info_clone`?** They preserve no existing
   capability, so they are omitted; adding them later is additive.
3. **Should `OvStorage_KindDescriptorList` follow, behind a public
   `{ const char *ptr; size_t len; }` slice type?** That is the only shape its
   non-NUL-terminated arena admits, and it would lose the accessors'
   interior-NUL rejection. Deferred rather than decided.

---

### Lifecycle

`Proposed` → (flip to `Accepted` in the final commit before this PR merges) →
`Accepted` → (implementation lands, durable detail folded into the Software
Design Document) → `Implemented`. A later RFC may set this one's
**Superseded-by** and move it to `Superseded`. The file never moves — status
lives in this header and the [index](README.md), so links and `Depends-on`
references stay stable for the RFC's whole life.
