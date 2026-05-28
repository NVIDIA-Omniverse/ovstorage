// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::Path;

pub mod address;
pub mod cancel;
pub mod ffi;
pub mod log_layer;
pub mod oauth_keyring;
pub mod redact;
pub mod shim;
pub mod subscription;
pub mod thunks;
pub mod trace;
mod types;
pub mod url_helpers;

pub use cancel::{CancelOnDrop, cancel_on_drop, race_cancel};
pub use ovstorage_plugin_macros::ovstorage_plugin;
pub use redact::{REDACTED_QUERY_KEYS, redact_message, redact_url};
pub use tokio_util::sync::CancellationToken;
pub use trace::RedactedUrl;
pub use types::*;
pub use url::Url;
pub use url_helpers::{extract_pinned_value, reject_pinned_for_mutation};

// Migration aid: canonical home for these is `ffi::*`.
pub use ffi::BackendPluginInitResultV1;
pub use ffi::BackendPluginInitV1;
pub use ffi::OVSTORAGE_PLUGIN_ABI_VERSION;
pub use ffi::PluginManifestV1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginManifest {
    pub abi_version: u32,
    pub name: String,
    pub version: String,
    /// Test fixture marker. Production hosts refuse to load
    /// `test_only = true` plugins unless `allow_test_plugins` is
    /// set; older plugins missing this field default to `false`
    /// via the `struct_size` forward-compatibility check.
    pub test_only: bool,
}

pub struct LoadedPlugin {
    _library: libloading::Library,
    manifest: PluginManifest,
}

impl PluginManifest {
    /// Reads and validates a borrowed manifest exported by a plugin binary.
    ///
    /// # Safety
    ///
    /// `raw` must point to a valid `PluginManifestV1` whose `name` and
    /// `version` fields are valid NUL-terminated UTF-8 strings for the
    /// duration of this call.
    pub unsafe fn from_raw(raw: *const PluginManifestV1) -> Result<Self> {
        unsafe {
            if raw.is_null() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "plugin manifest pointer is null",
                ));
            }
            let raw_struct_size = (*raw).struct_size;
            // Forward-compat: any `struct_size` >= the prefix through
            // `version` is accepted; later fields default when not
            // covered.
            const PREFIX_THROUGH_VERSION: usize = std::mem::size_of::<usize>()
                + std::mem::size_of::<u32>()
                + std::mem::size_of::<*const c_char>() * 2;
            if raw_struct_size < PREFIX_THROUGH_VERSION {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "plugin manifest struct_size is too small",
                ));
            }
            let raw = &*raw;
            // Must check OVSTORAGE_PLUGIN_ABI_VERSION; the storage and
            // authz ABIs evolve independently.
            if raw.abi_version != OVSTORAGE_PLUGIN_ABI_VERSION {
                return Err(Error::new(
                    ErrorCode::IncompatibleType,
                    "plugin ABI version is not supported",
                ));
            }
            // Read `test_only` only when the declared `struct_size`
            // covers it; older plugins default to `false`.
            let test_only =
                if raw_struct_size >= PREFIX_THROUGH_VERSION + std::mem::size_of::<bool>() {
                    raw.test_only
                } else {
                    false
                };
            Ok(Self {
                abi_version: raw.abi_version,
                name: read_manifest_string(raw.name, "plugin name")?,
                version: read_manifest_string(raw.version, "plugin version")?,
                test_only,
            })
        }
    }
}

impl LoadedPlugin {
    /// Load a dynamic plugin far enough to validate and copy its manifest.
    ///
    /// This is the 0.1 loader probe — vtable binding is a later step
    /// so the manifest/kind handshake can stabilize first.
    ///
    /// # Safety
    ///
    /// Loading a dynamic library runs platform loader hooks in the
    /// current process. Callers must load only trusted plugin binaries.
    pub unsafe fn load(path: impl AsRef<Path>) -> Result<Self> {
        unsafe {
            let library = libloading::Library::new(path.as_ref()).map_err(|error| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("failed to load plugin library: {error}"),
                )
            })?;
            let manifest = {
                let manifest_symbol: libloading::Symbol<*const PluginManifestV1> = library
                    .get(b"ovstorage_plugin_manifest_v1\0")
                    .map_err(|error| {
                        Error::new(
                            ErrorCode::InvalidArgument,
                            format!("plugin manifest symbol is missing: {error}"),
                        )
                    })?;
                PluginManifest::from_raw(*manifest_symbol)?
            };
            {
                let init_symbol: libloading::Symbol<BackendPluginInitV1> = library
                    .get(b"ovstorage_plugin_init_v1\0")
                    .map_err(|error| {
                        Error::new(
                            ErrorCode::InvalidArgument,
                            format!("plugin init symbol is missing: {error}"),
                        )
                    })?;
                // Probe loader: validates init succeeds and returns a
                // well-formed result. Real hosts hand in a non-null
                // callbacks pointer and bind the factory vtable.
                let init_result = init_symbol(std::ptr::null());
                validate_init_result_header(
                    init_result.struct_size,
                    std::mem::size_of::<BackendPluginInitResultV1>(),
                    init_result.abi_version,
                    init_result.factory_vtable as *const core::ffi::c_void,
                )?;
            }
            Ok(Self {
                _library: library,
                manifest,
            })
        }
    }

    pub fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

unsafe fn read_manifest_string(ptr: *const c_char, field: &str) -> Result<String> {
    unsafe {
        if ptr.is_null() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("{field} pointer is null"),
            ));
        }
        CStr::from_ptr(ptr)
            .to_str()
            .map(|value| value.to_string())
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, format!("{field} is not UTF-8")))
    }
}

/// Validate the shared header fields every plugin domain's init
/// result starts with: `struct_size` (checked `>=` for forward-compat),
/// ABI version (exact equality with [`OVSTORAGE_PLUGIN_ABI_VERSION`]),
/// and a non-null vtable pointer.
///
/// Single-version path. New callers should prefer
/// [`validate_init_result_header_banded`].
pub fn validate_init_result_header(
    actual_struct_size: usize,
    expected_struct_size: usize,
    abi_version: u32,
    vtable_ptr: *const core::ffi::c_void,
) -> Result<()> {
    validate_init_result_header_banded(
        actual_struct_size,
        expected_struct_size,
        abi_version,
        abi_version,
        abi_version,
        vtable_ptr,
    )
}

/// Banded variant of [`validate_init_result_header`]: checks the
/// host's ABI version against the inclusive `[min, max]` band the
/// plugin declares. When the plugin sets `min == max == 0` (legacy,
/// pre-banded), falls back to single-version equality on `abi_version`.
pub fn validate_init_result_header_banded(
    actual_struct_size: usize,
    expected_struct_size: usize,
    abi_version: u32,
    plugin_min_abi_version: u32,
    plugin_max_abi_version: u32,
    vtable_ptr: *const core::ffi::c_void,
) -> Result<()> {
    if actual_struct_size < expected_struct_size {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "plugin init result struct_size is too small",
        ));
    }
    let host_abi = OVSTORAGE_PLUGIN_ABI_VERSION;
    // Pre-banded shim: legacy zero-init falls back to single-version equality.
    let (min, max) = if plugin_min_abi_version == 0 && plugin_max_abi_version == 0 {
        (abi_version, abi_version)
    } else {
        (plugin_min_abi_version, plugin_max_abi_version)
    };
    if host_abi < min || host_abi > max {
        return Err(Error::new(
            ErrorCode::IncompatibleType,
            format!("plugin advertises ABI band [{min}, {max}] but host runs ABI {host_abi}"),
        ));
    }
    if vtable_ptr.is_null() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "plugin init returned a null vtable",
        ));
    }
    Ok(())
}

/// What the plugin's `read` returned.
///
/// `Bytes` is the materialized buffer; plugins MUST return `Stream`
/// for whole-object reads above the per-plugin small-response
/// threshold to avoid the memory-DoS that buffering would
/// re-introduce. `LocalDelegate` is a path the host reads directly;
/// `Redirect` is a presigned HTTP request the host's redirect
/// follower streams chunk-by-chunk.
pub enum ReadResult {
    Bytes {
        bytes: Vec<u8>,
        info: ObjectInfo,
    },
    Stream {
        stream: ReadStream,
        info: ObjectInfo,
    },
    LocalDelegate(LocalDelegate),
    Redirect(ReadRedirect),
}

impl std::fmt::Debug for ReadResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadResult::Bytes { bytes, info } => f
                .debug_struct("Bytes")
                .field("bytes_len", &bytes.len())
                .field("info", info)
                .finish(),
            ReadResult::Stream { info, .. } => {
                f.debug_struct("Stream").field("info", info).finish()
            }
            ReadResult::LocalDelegate(delegate) => {
                f.debug_tuple("LocalDelegate").field(delegate).finish()
            }
            ReadResult::Redirect(redirect) => f.debug_tuple("Redirect").field(redirect).finish(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum WriteStep {
    Done(WriteResult),
    Redirects(WriteRedirectBatch),
}

pub type BackendChangeStream = Box<dyn Iterator<Item = Result<BackendChangeEvent>> + Send>;

/// Server-pushed stream of address-root changes returned by
/// [`shim::Backend::watch_address_roots`]. The first element on
/// subscribe is always a `Snapshot`; subsequent elements are `Added`
/// / `Removed` deltas.
///
/// Async (unlike the iterator-based `BackendChangeStream`) because
/// address-root events are coarse-grained and infrequent — the host
/// parks a per-connection task that only wakes on a pushed frame.
pub type BackendAddressRootsStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<AddressRootsChange>> + Send>>;

/// One frame in a [`BackendAddressRootsStream`]. The host applies
/// them under its route lock and bumps the route epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressRootsChange {
    /// Initial state of the published roots — emitted exactly once at
    /// the start of every subscription; replaces the connection's
    /// route entries wholesale.
    Snapshot(Vec<AddressRoot>),
    /// New roots visible; appended to the route table.
    Added(Vec<AddressRoot>),
    /// Roots no longer visible. In-flight requests against a removed
    /// route surface `ErrorCode::NotConfigured`. The full
    /// `AddressRoot` (not just the address) is echoed so observers
    /// can log display names without a separate lookup.
    Removed(Vec<AddressRoot>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendChangeEvent {
    Object {
        address: Url,
        kind: ChangeKind,
        /// Etag of the object after the change. The opaque
        /// precondition token; round-trips through `if_match`.
        etag: Option<String>,
        /// Backend-specific version identifier when the notification
        /// carries it; `None` on deletes and unversioned backends.
        version: Option<String>,
        /// Object size in bytes when the notification carries it.
        size: Option<u64>,
        /// Last-modified time when the notification carries it.
        mtime: Option<std::time::SystemTime>,
        at: std::time::SystemTime,
        cursor: WatchDirectoryCursor,
    },
    Lapsed {
        since: Option<std::time::SystemTime>,
        cursor: WatchDirectoryCursor,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BackendItemInfo {
    pub kind: ObjectKind,
    pub etag: Option<String>,
    pub version: Option<String>,
    pub size: Option<u64>,
    pub mtime: Option<std::time::SystemTime>,
    pub checksums: ChecksumSet,
    pub effective_permissions: Option<EffectivePermissions>,
    pub system_metadata: Option<SystemMetadata>,
    pub user_metadata: Option<UserMetadata>,
    /// Sibling of [`ObjectInfo::modified_by`] for list/version entries.
    /// Population is opt-in via the parent operation's `full_metadata`
    /// flag. See `ObjectInfo::modified_by` for the full contract.
    pub modified_by: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::raw::c_char;

    static NAME: &[u8] = b"unit-test\0";
    static VERSION: &[u8] = b"0.1.0\0";

    #[test]
    fn manifest_from_raw_validates_and_copies_strings() {
        let raw = PluginManifestV1 {
            struct_size: std::mem::size_of::<PluginManifestV1>(),
            abi_version: OVSTORAGE_PLUGIN_ABI_VERSION,
            name: NAME.as_ptr() as *const c_char,
            version: VERSION.as_ptr() as *const c_char,
            test_only: false,
        };

        let manifest = unsafe { PluginManifest::from_raw(&raw) }.unwrap();
        assert_eq!(manifest.name, "unit-test");
        assert_eq!(manifest.version, "0.1.0");
        assert!(!manifest.test_only);
    }

    #[test]
    fn manifest_from_raw_propagates_test_only_flag() {
        let raw = PluginManifestV1 {
            struct_size: std::mem::size_of::<PluginManifestV1>(),
            abi_version: OVSTORAGE_PLUGIN_ABI_VERSION,
            name: NAME.as_ptr() as *const c_char,
            version: VERSION.as_ptr() as *const c_char,
            test_only: true,
        };
        let manifest = unsafe { PluginManifest::from_raw(&raw) }.unwrap();
        assert!(manifest.test_only);
    }

    #[test]
    fn manifest_from_raw_accepts_old_struct_size_without_test_only() {
        // Older plugins declare a smaller struct_size that doesn't
        // cover `test_only`; the reader must default the field.
        const OLD_SIZE: usize = std::mem::size_of::<usize>()
            + std::mem::size_of::<u32>()
            + std::mem::size_of::<*const c_char>() * 2;
        let raw = PluginManifestV1 {
            struct_size: OLD_SIZE,
            abi_version: OVSTORAGE_PLUGIN_ABI_VERSION,
            name: NAME.as_ptr() as *const c_char,
            version: VERSION.as_ptr() as *const c_char,
            test_only: true, // ignored: struct_size predates this field.
        };
        let manifest = unsafe { PluginManifest::from_raw(&raw) }.unwrap();
        assert_eq!(manifest.name, "unit-test");
        assert!(!manifest.test_only);
    }

    #[test]
    fn init_result_validates_shared_header() {
        let dummy: u8 = 0;
        validate_init_result_header(
            std::mem::size_of::<BackendPluginInitResultV1>(),
            std::mem::size_of::<BackendPluginInitResultV1>(),
            OVSTORAGE_PLUGIN_ABI_VERSION,
            &dummy as *const _ as *const core::ffi::c_void,
        )
        .unwrap();
    }

    #[test]
    fn init_result_rejects_null_vtable() {
        assert_eq!(
            validate_init_result_header(
                std::mem::size_of::<BackendPluginInitResultV1>(),
                std::mem::size_of::<BackendPluginInitResultV1>(),
                OVSTORAGE_PLUGIN_ABI_VERSION,
                std::ptr::null(),
            )
            .unwrap_err()
            .code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn manifest_from_raw_rejects_wrong_abi_version() {
        let raw = PluginManifestV1 {
            struct_size: std::mem::size_of::<PluginManifestV1>(),
            abi_version: OVSTORAGE_PLUGIN_ABI_VERSION + 1,
            name: NAME.as_ptr() as *const c_char,
            version: VERSION.as_ptr() as *const c_char,
            test_only: false,
        };

        assert_eq!(
            unsafe { PluginManifest::from_raw(&raw) }
                .unwrap_err()
                .code(),
            ErrorCode::IncompatibleType
        );
    }

    #[test]
    fn banded_handshake_accepts_host_abi_within_range() {
        let dummy: u8 = 0;
        validate_init_result_header_banded(
            std::mem::size_of::<BackendPluginInitResultV1>(),
            std::mem::size_of::<BackendPluginInitResultV1>(),
            OVSTORAGE_PLUGIN_ABI_VERSION,
            OVSTORAGE_PLUGIN_ABI_VERSION,
            OVSTORAGE_PLUGIN_ABI_VERSION,
            &dummy as *const _ as *const core::ffi::c_void,
        )
        .expect("in-band plugin should be accepted");
    }

    #[test]
    fn banded_handshake_rejects_host_abi_below_band() {
        let dummy: u8 = 0;
        let err = validate_init_result_header_banded(
            std::mem::size_of::<BackendPluginInitResultV1>(),
            std::mem::size_of::<BackendPluginInitResultV1>(),
            OVSTORAGE_PLUGIN_ABI_VERSION + 5,
            OVSTORAGE_PLUGIN_ABI_VERSION + 5,
            OVSTORAGE_PLUGIN_ABI_VERSION + 7,
            &dummy as *const _ as *const core::ffi::c_void,
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::IncompatibleType);
    }

    #[test]
    fn banded_handshake_legacy_zero_min_max_falls_back_to_abi_version() {
        // Pre-banded plugins leave min == max == 0; validator falls
        // back to single-version equality on `abi_version`.
        let dummy: u8 = 0;
        validate_init_result_header_banded(
            std::mem::size_of::<BackendPluginInitResultV1>(),
            std::mem::size_of::<BackendPluginInitResultV1>(),
            OVSTORAGE_PLUGIN_ABI_VERSION,
            0,
            0,
            &dummy as *const _ as *const core::ffi::c_void,
        )
        .expect("legacy zero-init should fall back to abi_version equality");
    }
}
