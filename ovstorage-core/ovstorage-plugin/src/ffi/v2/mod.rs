// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! ABI-v2: the C ABI projection of the Rust `ovstorage_layer`
//! surface. v2 introduces one operational vtable shared by every Layer
//! ([`LayerVTableV1`]) plus a three-way factory split
//! ([`PluginVTableV1`]).
//!
//! The Layer ABI reuses the shared FFI vocabulary wherever the shapes
//! already match — the [`CancelTokenFFI`] cancellation handle, the
//! pull-based stream primitives ([`StreamStep`] + `next_fn` + `drop_fn`,
//! as in [`AuthEventStream`] / [`BackendChangeStream`]), the
//! [`HostCallbacks`] substrate, every option struct, and the result
//! types ([`ObjectInfo`], [`ReadResult`], [`Connection`], ...). The
//! Layer-specific surface is the Layer vtable, factory split, request
//! envelopes, and introspection/connection-management values.

use super::*;

mod auth_credential;
mod introspect;
mod layer;
mod manifest;
mod request;

pub use auth_credential::*;
pub use introspect::*;
pub use layer::*;
pub use manifest::*;
pub use request::*;

/// ABI version the Layer (v2) plugin contract is generated against. A
/// number space beginning at [`OVSTORAGE_PLUGIN_ABI_V2_FLOOR`]. The host
/// rejects versions below that floor, then validates the exact supported
/// Layer ABI against this constant,
/// rejecting any other `abi_version` — older or unknown-higher — rather
/// than reinterpreting it under the current layout.
///
/// History:
/// - v5: initial Layer ABI — `OvStorage_LayerVTable`, the three-factory
///   split (`create_backend` / `create_wrapper` / `create_router`),
///   and the manifest/init pair carrying `LayerKindDescriptor`s.
/// - v6: `LocalDelegate` gained the trailing nullable
///   `lease: LeaseHandle` field, shifting/growing the inline
///   `ReadResult` layout; [`Extensions`] entries re-typed from the
///   Str/Str `KeyValueList` to the Str/[`Bytes`] [`ExtensionEntry`]
///   list; and `remove_connection` re-keyed from a bare `ConnectionKey`
///   to the request-prefixed [`RemoveConnectionRequest`] so extensions
///   cross that slot too.
/// - v7: the four synchronous introspection slots (`root_info_for`,
///   `list_kinds`, `list_address_roots`, `list_connections`) gained a
///   `*const Extensions` request-context parameter, mirroring the data-op
///   `Request::extensions`. This changes function-pointer signatures (not
///   `struct_size`-detectable), so the bump is a genuine ABI break: the v2
///   loader rejects any stale pre-bump cdylib at load rather than calling it
///   with a mismatched signature.
/// - v8: the three runtime-state introspection slots (`root_info_for`,
///   `list_address_roots`, `list_connections`) became always-async and
///   cancellable, matching the data ops. Each slot now takes a `*const
///   Request` envelope ([`RootInfoForRequest`] / [`ListAddressRootsRequest`]
///   / [`ListConnectionsRequest`]), a nullable `*const CancelTokenFFI`, an
///   [`OnComplete`] callback, and `user_data` — replacing the v7
///   synchronous `*mut Error`-returning shape. The two `list_*` slots'
///   success payload is a new heap envelope ([`ListAddressRootsResult`] /
///   [`ListConnectionsResult`]) pairing the snapshot with its optional
///   change-stream pointer. `list_kinds` stays synchronous: it reports
///   fixed manifest/graph metadata under the trait's no-I/O contract. The
///   function-pointer signatures change (not `struct_size`-detectable), so
///   the v2 loader rejects any stale pre-bump cdylib at load.
/// - v9: every value crossing the ABI — each heap envelope and each
///   [`Str`] / [`Bytes`] / [`List`] buffer nested inside one — is minted and
///   reclaimed on the process-wide operating-system heap
///   ([`abi_alloc`]), which `#[global_allocator]`
///   cannot redirect. The invariant: one heap owns every ABI value, and both
///   binaries name the same one. The Rust global allocator cannot be that
///   heap — it is a per-binary choice, so it resolves to two different heaps
///   whenever a plugin installs jemalloc or mimalloc and its host does not,
///   and whichever side releases a value then uses the wrong one. The OS
///   heap is also the pair the pure-C distribution names, which is what lets
///   a C host and a Rust plugin interchange. Releasing a `SecretBytes` also
///   zeroizes its buffer first, so no plaintext reaches that heap's free
///   list.
///
///   `Error` also gains a `next_action` field, carrying the optional
///   recovery hint that a per-image side table keyed by message pointer
///   could not: the host and each plugin cdylib link their own copy of that
///   static, so a hint one side registered was invisible to the other,
///   leaked on the registering side, and could resurface on a later error
///   once the allocator reused the address. This one is a layout change.
///
///   The remaining struct layouts
///   are unchanged; the bump is what forces the rebuild that carries the
///   allocator choice, which a cdylib bakes in at compile time. The v2
///   loader rejects any pre-bump cdylib at load, and validates the
///   `abi_version` on the manifest, the init result, and the factory vtable
///   alike.
///
/// - v10: `ReadOptions` gained the trailing `max_bytes: Optional<u64>`,
///   growing both `ReadOptions` and the `ReadRequest` that embeds it. The
///   options struct has no reserved tail slots, so the loader rejects v9
///   cdylibs before a read can cross the mismatched layout.
///
/// - v11: `Capabilities` gained `supports_copy` and `supports_rename`,
///   inserted after `writes_are_atomic`, which shifts every field below
///   them. The struct has no reserved tail slots and the insertion is not
///   at the tail, so a v10 cdylib misreads the whole capability block; the
///   loader rejects it at load.
/// - v12: `RedirectScope` gained `credential`, the backend's declaration of
///   what the redirect's credential authorizes. It is appended, but the
///   struct is embedded by value in `ReadRedirect` and `WriteRedirect`, so
///   it grows both of those and a v11 cdylib misreads every field after the
///   scope; the loader rejects it at load.
/// - v13: `ErrorContextV1` gained the `partial` slot carrying
///   `PartialErrorContextV1`, the companion payload for
///   `ErrorCode::PartialCompletion`. The slots are sibling fields rather than
///   a real union, so appending one grows the struct and a v12 cdylib
///   misreads any context it is handed; the loader rejects it at load.
///   `ErrorCode` also gained `PartialCompletion = 40`, which is additive on
///   its own.
/// - v14: [`LayerKindDescriptor`] gained `auth_capable`, the fail-closed
///   discriminator for kinds that may serve as listener auth Layers. The
///   field grows the descriptor, and acceptance is exact-match on
///   `abi_version`, so the loader rejects every pre-v14 cdylib at load.
///   Request context (`ext::AUTH_CREDENTIAL`, `ext::PRINCIPAL_ID`) travels
///   DOWN only; there is no response-side extensions channel. The same bump
///   also publishes `ovstorage_plugin_auth_credential_decode` and
///   `ovstorage_plugin_auth_credential_free` as plugin-owned SDK helpers.
///   Rust plugins link their implementation from `ovstorage-plugin`; C
///   plugins compile the shipped C implementation into their own cdylib.
///   They are not global host exports. Exact-match versioning keeps the
///   helper's wire and value layouts aligned with the v14 host contract.
/// - v15: [`LayerKindDescriptor`] gained `supports_user_metadata`, the backend
///   kind's declaration of whether it accepts the host's attribution stamp in
///   a write's `user_metadata`, and `StorageBackendKindDescriptor` gained the
///   same field. **This one is invisible to `struct_size`**: the new `bool`
///   lands in padding both structs already carried, so no field below it moves
///   and neither struct changes size. Measured on x86_64-unknown-linux-gnu
///   against the generated headers either side of the bump,
///   `LayerKindDescriptor` is 216 bytes at v14 and at v15, with `auth_capable`
///   at offset 144 and `_reserved` at 152 in both, and
///   `StorageBackendKindDescriptor` is 136 bytes in both. Every member is a
///   pointer, `size_t`, `bool` or a 4-byte enum, so the invariance holds
///   wherever those align as they do on the 64-bit targets this ships for.
///   A v14 cdylib therefore passes the `struct_size` check, and the exact
///   `abi_version` match is the only thing that rejects it — load-bearing here
///   rather than belt-and-braces. What it prevents is a host reading a byte a
///   v14 producer never wrote as a Rust `bool`: an indeterminate value where
///   `true` composes an attribution layer over a backend that declared
///   nothing, which is the case this field exists to stop being guessed.
pub const OVSTORAGE_PLUGIN_ABI_V2_VERSION: u32 = 15;

/// The v2 (Layer) **family floor**: the first `abi_version` ever assigned
/// to the Layer ABI line. Loaders route a manifest to the v2 family when
/// `abi_version >= OVSTORAGE_PLUGIN_ABI_V2_FLOOR`; lower values are
/// unsupported. Acceptance is decided by exact match against
/// [`OVSTORAGE_PLUGIN_ABI_V2_VERSION`], so a stale artifact
/// (e.g. a v5 cdylib under a v7 host) fails with `IncompatibleType`
/// instead of being read under the current layout. This constant is frozen
/// at 5; it never moves when the Layer ABI version bumps.
pub const OVSTORAGE_PLUGIN_ABI_V2_FLOOR: u32 = 5;

/// Single extension entry: a UTF-8 [`Str`] key (the extension's
/// registered name) and a raw [`Bytes`] value, mirroring the
/// `ovstorage_layer::Extensions` entry shape (`String` → `Vec<u8>`).
#[repr(C)]
#[derive(Debug)]
pub struct ExtensionEntry {
    pub key: Str,
    pub value: Bytes,
}

unsafe impl Send for ExtensionEntry {}

// `ExtensionEntry` has no `Drop` impl (same rationale as `KeyValuePair`):
// field-by-field auto-drop runs `Str: Drop` / `Bytes: Drop`, and the absence
// of `Drop` lets decoders move the two fields out by value.

/// Per-request cross-cutting extension data, threaded through every
/// Layer operation as `*const Extensions` (NULL = none, the encoding
/// for an empty set). Mirrors `ovstorage_layer::Extensions`: entries
/// carry raw byte values, crossed faithfully so a producer-stamped
/// extension survives every vtable hop. Opaque to foreign code beyond
/// the key/value entries; the host and plugin marshal it at the
/// boundary — the request only lends the pointer for the synchronous
/// slot prologue, so consumers copy the entries and never adopt the
/// allocation.
#[repr(C)]
pub struct Extensions {
    pub entries: List<ExtensionEntry>,
}

unsafe impl Send for Extensions {}

/// Release the buffers owned by an [`ExtensionEntry`] in place. Safe
/// with NULL. Same convention as `ovstorage_plugin_str_free`.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`ExtensionEntry`] produced by an ovstorage call. Double-freeing
/// is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_extension_entry_free(value: *mut ExtensionEntry) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// Reclaim a heap-allocated [`Extensions`]. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_extensions_free(value: *mut Extensions) {
    unsafe {
        if value.is_null() {
            return;
        }
        crate::ffi::abi_alloc::abi_box_free(value);
    }
}
