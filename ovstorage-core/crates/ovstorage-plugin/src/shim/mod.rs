// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Marshalling between crate-root Rust types and their `ffi::T`
//! shadow types.
//!
//! Conversions consume their input in both directions so each
//! `ffi::T` allocation has exactly one ownership home — preventing
//! double-frees by construction.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{Duration, SystemTime};

use crate::ffi;
use crate::{
    AccessDecision, AccessOps, AddressRoot, AddressVisibility, AuthAttempt, AuthEvent, AuthReason,
    BackendChangeEvent, BackendId, BackendItemInfo, Body, BodyStream, ByteRange, CancellationToken,
    Capabilities, ChangeKind, ChangeKindSet, ChecksumAlgorithm, ChecksumSet, ConfigField,
    ConfigFieldKind, ConfigLayer, ConfigValue, Connection, ConnectionAuthState, ConnectionId,
    ConnectionRequest, ConnectionSource, CopyOptions, CreateDirectoryOptions, CredentialField,
    CredentialMethod, DeleteDirectoryOptions, DeleteOptions, EffectivePermissions, EnumSource,
    Error, ErrorCode, ErrorContext, HttpRequest, IfDestExists, InteractiveAuthCapability,
    ListOptions, ListVersionsOptions, LocalDelegate, MtimeFormat, ObjectInfo, ObjectKind,
    ReadOptions, ReadRedirect, ReadResult, ReadStream, RedirectBodySource, RedirectResult,
    RedirectResultBatch, RedirectScope, RenameOptions, ResolvedTarget, ResponseParsing,
    ResultCapture, RouteSource, SecretBundle, SecretBytes, SecretValue, StatOptions,
    StorageBackendKindDescriptor, SystemMetadata, UpdateMetadataOptions, Url, UserMetadata,
    VersionListOrder, WatchDirectoryCursor, WatchDirectoryOptions, WriteOptions, WriteRedirect,
    WriteRedirectBatch, WriteResult, WriteStep,
};

pub mod access;
pub mod address;
pub mod auth;
pub mod capabilities;
pub mod change;
pub mod connection;
pub mod descriptor;
pub mod error;
pub mod identity;
pub mod metadata;
pub mod options;
pub mod payload;
pub mod primitive;
pub mod redirect;

// ---------------------------------------------------------------------
// Plugin SPI traits + host-callback wrapper
// ---------------------------------------------------------------------

/// Process-local storage for the host callbacks pointer.
static REGISTERED_HOST: AtomicPtr<ffi::HostCallbacks> = AtomicPtr::new(std::ptr::null_mut());

/// Stash the host callbacks pointer for the plugin's lifetime; the
/// init thunk calls this once. Reach the value later via [`host`].
///
/// # Safety
///
/// `ptr`, when non-null, must point at an `ffi::HostCallbacks`
/// whose function-pointer fields stay valid for the cdylib's
/// lifetime.
pub unsafe fn register_host(ptr: *const ffi::HostCallbacks) {
    REGISTERED_HOST.store(ptr as *mut ffi::HostCallbacks, Ordering::SeqCst);
}

/// Borrow the registered host callbacks. Returns `None` before init
/// or if the registered pointer is null.
pub fn host() -> Option<HostCallbacks<'static>> {
    let ptr = REGISTERED_HOST.load(Ordering::SeqCst) as *const ffi::HostCallbacks;
    // SAFETY: pointer is valid for the cdylib's lifetime per the host's contract.
    unsafe { HostCallbacks::from_raw(ptr) }
}

/// Safe wrapper over `ffi::HostCallbacks`. Plugin code reaches one
/// via [`host`] after init.
pub struct HostCallbacks<'a> {
    raw: &'a ffi::HostCallbacks,
}

impl<'a> HostCallbacks<'a> {
    /// Wrap a `*const ffi::HostCallbacks`. Returns `None` on null;
    /// plugin thunks treat that as `ErrorCode::InvalidArgument`.
    ///
    /// # Safety
    ///
    /// `raw`, when non-null, must point at a valid
    /// `ffi::HostCallbacks` whose function-pointer fields are valid
    /// for `'a`.
    pub unsafe fn from_raw(raw: *const ffi::HostCallbacks) -> Option<Self> {
        unsafe {
            if raw.is_null() {
                return None;
            }
            Some(Self { raw: &*raw })
        }
    }

    /// Return the kind of host loading the plugin. Unknown future
    /// values fall through as `Library`; prefer `is_broker()` for
    /// forward-compat.
    pub fn host_kind(&self) -> ffi::HostKindV1 {
        match self.raw.host_kind {
            x if x == ffi::HostKindV1::Broker as u32 => ffi::HostKindV1::Broker,
            _ => ffi::HostKindV1::Library,
        }
    }

    /// `true` when the plugin is loaded inside a broker daemon.
    pub fn is_broker(&self) -> bool {
        self.raw.host_kind == ffi::HostKindV1::Broker as u32
    }

    /// Forward a single log event to the host. Silently no-ops if the
    /// host is too old to expose the `log` field (older `struct_size`),
    /// so plugins compiled against a newer header still load against
    /// older hosts.
    pub fn log(&self, level: ffi::LogLevelV1, target: &str, message: &str) {
        // Forward-compat: only call into the slot when the host
        // declared a `struct_size` that covers it.
        let required =
            std::mem::offset_of!(ffi::HostCallbacks, log) + std::mem::size_of::<ffi::HostLogFn>();
        if self.raw.struct_size < required {
            return;
        }
        // ffi::Str's Drop reclaims its buffer as a Vec — correct for owned
        // values but UB for these views over borrowed `&str` slices. Wrap
        // each in ManuallyDrop so the destructor never fires; the
        // borrowed bytes belong to the caller.
        let target_ffi = std::mem::ManuallyDrop::new(ffi::Str {
            ptr: target.as_ptr() as *mut std::os::raw::c_char,
            len: target.len(),
        });
        let message_ffi = std::mem::ManuallyDrop::new(ffi::Str {
            ptr: message.as_ptr() as *mut std::os::raw::c_char,
            len: message.len(),
        });
        // SAFETY: `target` and `message` outlive the call (they're
        // borrows held until this returns); the host treats them as
        // borrowed strings and copies before freeing.
        unsafe {
            (self.raw.log)(
                self.raw.host_state,
                level as u8,
                &*target_ffi,
                &*message_ffi,
            );
        }
    }

    /// Read a secret from the host's OS keyring.
    pub fn keyring_get(
        &self,
        backend_kind: &str,
        connection_id: &ConnectionId,
        field: &str,
    ) -> Result<Option<SecretBytes>, Error> {
        let key = self.build_key(backend_kind, connection_id, field);
        let mut out_value = ffi::Optional::<ffi::SecretBytes>::none();
        // SAFETY: `key` and `out_value` are stack-locals valid for the call.
        let err_ptr = unsafe { (self.raw.keyring_get)(self.raw.host_state, &key, &mut out_value) };
        drop(key);
        Self::check_error(err_ptr)?;
        // SAFETY: host populated `out_value` on success.
        let opt = unsafe {
            primitive::optional_from_ffi::<ffi::SecretBytes, SecretBytes, Error>(out_value, |sb| {
                Ok(descriptor::secret_bytes_from_ffi(sb))
            })
        }?;
        Ok(opt)
    }

    /// Write a secret into the host's OS keyring.
    pub fn keyring_put(
        &self,
        backend_kind: &str,
        connection_id: &ConnectionId,
        field: &str,
        value: &SecretBytes,
    ) -> Result<(), Error> {
        let key = self.build_key(backend_kind, connection_id, field);
        let value_ffi = descriptor::secret_bytes_to_ffi(value.clone());
        // SAFETY: see `keyring_get`.
        let err_ptr = unsafe { (self.raw.keyring_put)(self.raw.host_state, &key, &value_ffi) };
        drop(key);
        drop(value_ffi);
        Self::check_error(err_ptr)
    }

    /// Remove a secret from the host's OS keyring.
    pub fn keyring_delete(
        &self,
        backend_kind: &str,
        connection_id: &ConnectionId,
        field: &str,
    ) -> Result<(), Error> {
        let key = self.build_key(backend_kind, connection_id, field);
        // SAFETY: see `keyring_get`.
        let err_ptr = unsafe { (self.raw.keyring_delete)(self.raw.host_state, &key) };
        drop(key);
        Self::check_error(err_ptr)
    }

    /// Drive the host's per-`(backend_kind, connection_id)` refresh
    /// lock. `refresh_fn` runs at most once — skipped when the
    /// snapshot is fresh inside the critical section.
    pub fn auth_refresh_lock_with_refresh<F>(
        &self,
        backend_kind: &str,
        connection_id: &ConnectionId,
        freshness_window: std::time::Duration,
        refresh_fn: F,
    ) -> Result<(), Error>
    where
        F: FnOnce() -> Result<(), Error>,
    {
        // Trampoline turning `FnOnce<F>` into `extern "C" fn`.
        unsafe extern "C" fn invoke<F>(state: *mut core::ffi::c_void) -> *mut ffi::Error
        where
            F: FnOnce() -> Result<(), Error>,
        {
            unsafe {
                let slot = &mut *(state as *mut Option<F>);
                match slot.take() {
                    Some(f) => match f() {
                        Ok(()) => std::ptr::null_mut(),
                        Err(error) => Box::into_raw(Box::new(error::to_ffi(&error))),
                    },
                    None => {
                        let err = Error::new(
                            ErrorCode::Internal,
                            "host invoked auth_refresh_lock_with_refresh's closure twice",
                        );
                        Box::into_raw(Box::new(error::to_ffi(&err)))
                    }
                }
            }
        }

        let backend_kind_ffi = primitive::str_ref_to_ffi(backend_kind);
        let connection_id_ffi = connection::connection_id_to_ffi(connection_id.clone());
        let mut state: Option<F> = Some(refresh_fn);
        let freshness_window_ms = clamp_duration_to_ms(freshness_window);

        // SAFETY: callback callable for `self.raw`'s lifetime; `state`
        // is a stack-local `Option<F>` valid across the call.
        let err_ptr = unsafe {
            (self.raw.auth_refresh_lock_with_refresh)(
                self.raw.host_state,
                &backend_kind_ffi,
                &connection_id_ffi,
                freshness_window_ms,
                &mut state as *mut _ as *mut core::ffi::c_void,
                invoke::<F>,
            )
        };
        drop(backend_kind_ffi);
        drop(connection_id_ffi);
        Self::check_error(err_ptr)
    }

    fn build_key(
        &self,
        backend_kind: &str,
        connection_id: &ConnectionId,
        field: &str,
    ) -> ffi::KeyringKey {
        ffi::KeyringKey {
            backend_kind: primitive::str_ref_to_ffi(backend_kind),
            connection_id: connection::connection_id_to_ffi(connection_id.clone()),
            field: primitive::str_ref_to_ffi(field),
        }
    }

    /// Consume an `*mut ffi::Error` returned by a host callback.
    /// Null maps to `Ok(())`.
    fn check_error(err_ptr: *mut ffi::Error) -> Result<(), Error> {
        if err_ptr.is_null() {
            return Ok(());
        }
        // SAFETY: non-null `*mut ffi::Error` from a callback is a
        // heap pointer per host/plugin contract.
        let boxed: Box<ffi::Error> = unsafe { Box::from_raw(err_ptr) };
        let inner: ffi::Error = *boxed;
        Err(unsafe { error::from_ffi(inner) })
    }
}

fn clamp_duration_to_ms(duration: std::time::Duration) -> u64 {
    let ms = duration.as_millis();
    if ms > u64::MAX as u128 {
        u64::MAX
    } else {
        ms as u64
    }
}

/// A configured backend instance returned by [`Factory::instantiate`].
///
/// `address_roots` carries per-root capabilities; the host stamps each
/// matching `Route.capabilities` from the corresponding root. Plugins
/// with one cap profile across all roots clone the same `Capabilities`
/// into each entry.
pub struct BackendInstance {
    pub backend_id: BackendId,
    pub backend: Arc<dyn Backend>,
    pub address_roots: Vec<AddressRoot>,
    pub display_name: Option<String>,
    pub auth_state: ConnectionAuthState,
}

/// Plugin-side `Backend` SPI. Plugin authors implement this on a
/// per-instance state struct; the `ovstorage_plugin!` macro emits the
/// vtable thunks.
///
/// Only [`Backend::stat`] and [`Backend::read`] are required (no
/// default impl). Every other method defaults to
/// `Err(ErrorCode::Unsupported)`; the host calls them only when the
/// matching capability bit on the route's `Capabilities` is `true`.
///
/// Capabilities are advertised per `AddressRoot` returned from the
/// factory's `instantiate` (and from `watch_address_roots`); the host
/// gates dispatch on the route's per-root capabilities, not on the
/// backend instance itself. Advertising a `supports_*` bit obliges
/// the plugin to actually implement the gated method — bit-without-
/// implementation surfaces to callers as `Unsupported` at runtime,
/// which is a plugin bug.
///
/// Cancellation: a `Some(token)` whose `is_cancelled()` becomes true
/// mid-operation should abort and return `Err(ErrorCode::Cancelled)`.
/// `None` means "never cancels".
#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    async fn stat(
        &self,
        target: ResolvedTarget,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo, Error>;

    async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult, Error>;

    /// Buffered write. Plugins that always redirect leave this as the
    /// default `Unsupported`. The size-threshold capability is a
    /// host-dispatch hint, not a contract — plugins MUST process
    /// whatever the host calls them with; reserve `Unsupported` for
    /// genuine capability gaps (read-only backend, no auth installed,
    /// method not implemented at all). Wire-size rejections surface
    /// as `ResourceExhausted` / `InvalidArgument`.
    async fn write(
        &self,
        _target: ResolvedTarget,
        _bytes: Vec<u8>,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support buffered write (try write_redirect or write_stream)",
        ))
    }

    /// Streaming write. Same wrong-call semantics as `write`. Default
    /// returns `Unsupported`.
    async fn write_stream(
        &self,
        _target: ResolvedTarget,
        _body: BodyStream,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support streaming write",
        ))
    }

    /// Emit redirects without seeing the body. Returns `WriteStep::
    /// Done` (rare) or `WriteStep::Redirects(batch)` of pre-signed
    /// URLs the host follows. `WriteOptions::size_hint` informs
    /// single-PUT vs. multipart choice; unknown size means a single
    /// redirect with `UserBytes(0, max-allowed)`. Same wrong-call
    /// semantics as `write` — emit a valid `WriteStep` regardless of
    /// `size_hint`; `Unsupported` is reserved for genuine capability
    /// gaps. Default returns `Unsupported`.
    async fn write_redirect(
        &self,
        _target: ResolvedTarget,
        _opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support redirect write",
        ))
    }

    async fn continue_write(
        &self,
        _target: ResolvedTarget,
        _redirects: WriteRedirectBatch,
        _results: RedirectResultBatch,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support redirect write continuation",
        ))
    }

    /// Capability-gated on `supports_delete`. Default is `Unsupported`.
    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<(), Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support delete",
        ))
    }

    /// Capability-gated on `supports_list`. Default is `Unsupported`.
    async fn list(
        &self,
        _prefix: ResolvedTarget,
        _opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support list",
        ))
    }

    async fn list_versions(
        &self,
        _target: ResolvedTarget,
        _opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support version listing",
        ))
    }

    /// Resolve the input to a single version pin: returns the requested
    /// version's canonical address + metadata if `target` already carries a
    /// backend version modifier, else the current head's. Capability-gated on
    /// `supports_version_listing`. Default is `Unsupported`.
    async fn get_latest_version(
        &self,
        _target: ResolvedTarget,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support get_latest_version",
        ))
    }

    async fn watch_directory(
        &self,
        _prefix: ResolvedTarget,
        _opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<crate::BackendChangeStream, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support watch_directory",
        ))
    }

    /// Server-streamed address-root change feed. Plugins whose root
    /// set can change at runtime (e.g. after auth) override this;
    /// static-roots backends keep the default `Unsupported` and the
    /// host's watcher exits quietly.
    ///
    /// Stream contract: emit exactly one `Snapshot` first, then
    /// `Added` / `Removed` deltas. `Err(_)` ends the subscription.
    async fn watch_address_roots(
        &self,
        cancel: Option<CancellationToken>,
    ) -> Result<crate::BackendAddressRootsStream, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support watch_address_roots",
        ))
    }

    /// Capability-gated on `supports_create_directory`. Default is
    /// `Unsupported`.
    async fn create_directory(
        &self,
        _target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support create_directory",
        ))
    }

    /// Capability-gated on `supports_delete_directory`. Default is
    /// `Unsupported`.
    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<(), Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support delete_directory",
        ))
    }

    async fn copy(
        &self,
        _src: ResolvedTarget,
        _dest: ResolvedTarget,
        _opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support server-side copy",
        ))
    }

    async fn rename(
        &self,
        _src: ResolvedTarget,
        _dest: ResolvedTarget,
        _opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<(), Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support server-side rename",
        ))
    }

    async fn update_metadata(
        &self,
        _target: ResolvedTarget,
        _opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support metadata updates",
        ))
    }

    async fn check_access(
        &self,
        _target: ResolvedTarget,
        _ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not support access checks",
        ))
    }
}

/// Plugin-side `Factory` SPI for one storage-backend kind. One
/// factory per cdylib; the plugin macro emits the FFI plumbing.
/// `descriptor` stays sync; other methods are async with the same
/// cancellation contract as [`Backend`].
#[async_trait::async_trait]
pub trait Factory: Send + Sync {
    fn descriptor(&self) -> StorageBackendKindDescriptor;

    async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendInstance, Error>;

    async fn update_credentials(
        &self,
        _connection: &Connection,
        _credentials: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<(), Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Ok(())
    }

    /// Drive the host-side auth flow for `connection`. Plugins consult
    /// `capability` to pick PKCE vs. device flow vs. fail-fast. The
    /// default emits `Succeeded` immediately — only correct for
    /// backends that don't drive an interactive flow.
    async fn authenticate(
        &self,
        connection: Connection,
        _capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<crate::AuthEventStream, Error> {
        let _ = &cancel; // trait default returns synchronously; no async work to cancel.
        Ok(Box::new(std::iter::once(Ok(AuthEvent::Succeeded {
            connection: Box::new(connection),
            credentials: None,
        }))))
    }
}

#[cfg(test)]
mod tests;
