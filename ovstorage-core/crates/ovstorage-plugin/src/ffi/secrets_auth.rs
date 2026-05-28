// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// Secrets + connection request
// ---------------------------------------------------------------------

/// Secret bytes carrier. The FFI struct does NOT zeroize on drop;
/// receivers that consume the value into a non-FFI form zeroize on
/// the way back. Bytes may still need to flow into a downstream call.
#[repr(C)]
#[derive(Debug)]
pub struct SecretBytes {
    pub bytes: Bytes,
}

unsafe impl Send for SecretBytes {}

/// Tag for [`SecretValue`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SecretValueTag {
    Bytes = 0,
    OAuthToken = 1,
    File = 2,
    MtlsCertPair = 3,
    SystemIdentity = 4,
}

/// `SecretValue::OAuthToken` payload.
#[repr(C)]
#[derive(Debug)]
pub struct SecretValueOAuthToken {
    pub token: SecretBytes,
    pub refresh: Optional<SecretBytes>,
    pub expires_at_unix_ms: Optional<i64>,
}

unsafe impl Send for SecretValueOAuthToken {}

/// `SecretValue::MtlsCertPair` payload.
#[repr(C)]
#[derive(Debug)]
pub struct SecretValueMtlsCertPair {
    pub cert_pem: SecretBytes,
    pub key_pem: SecretBytes,
}

unsafe impl Send for SecretValueMtlsCertPair {}

/// One credential value in a [`SecretBundle`].
#[repr(C)]
#[derive(Debug)]
pub struct SecretValue {
    pub tag: SecretValueTag,
    pub bytes: core::mem::MaybeUninit<SecretBytes>,
    pub oauth_token: core::mem::MaybeUninit<SecretValueOAuthToken>,
    pub file: core::mem::MaybeUninit<SecretBytes>,
    pub mtls_cert_pair: core::mem::MaybeUninit<SecretValueMtlsCertPair>,
}

unsafe impl Send for SecretValue {}

impl SecretValue {
    pub fn from_bytes(value: SecretBytes) -> Self {
        Self {
            tag: SecretValueTag::Bytes,
            bytes: core::mem::MaybeUninit::new(value),
            oauth_token: core::mem::MaybeUninit::uninit(),
            file: core::mem::MaybeUninit::uninit(),
            mtls_cert_pair: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_oauth(value: SecretValueOAuthToken) -> Self {
        Self {
            tag: SecretValueTag::OAuthToken,
            bytes: core::mem::MaybeUninit::uninit(),
            oauth_token: core::mem::MaybeUninit::new(value),
            file: core::mem::MaybeUninit::uninit(),
            mtls_cert_pair: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_file(value: SecretBytes) -> Self {
        Self {
            tag: SecretValueTag::File,
            bytes: core::mem::MaybeUninit::uninit(),
            oauth_token: core::mem::MaybeUninit::uninit(),
            file: core::mem::MaybeUninit::new(value),
            mtls_cert_pair: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_mtls_cert_pair(value: SecretValueMtlsCertPair) -> Self {
        Self {
            tag: SecretValueTag::MtlsCertPair,
            bytes: core::mem::MaybeUninit::uninit(),
            oauth_token: core::mem::MaybeUninit::uninit(),
            file: core::mem::MaybeUninit::uninit(),
            mtls_cert_pair: core::mem::MaybeUninit::new(value),
        }
    }

    pub fn system_identity() -> Self {
        Self {
            tag: SecretValueTag::SystemIdentity,
            bytes: core::mem::MaybeUninit::uninit(),
            oauth_token: core::mem::MaybeUninit::uninit(),
            file: core::mem::MaybeUninit::uninit(),
            mtls_cert_pair: core::mem::MaybeUninit::uninit(),
        }
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        unsafe {
            match self.tag {
                SecretValueTag::Bytes => self.bytes.assume_init_drop(),
                SecretValueTag::OAuthToken => self.oauth_token.assume_init_drop(),
                SecretValueTag::File => self.file.assume_init_drop(),
                SecretValueTag::MtlsCertPair => self.mtls_cert_pair.assume_init_drop(),
                SecretValueTag::SystemIdentity => {}
            }
        }
    }
}

/// `(field_name, secret_value)` entry inside a [`SecretBundle`].
#[repr(C)]
#[derive(Debug)]
pub struct SecretBundleEntry {
    pub field: Str,
    pub value: SecretValue,
}

unsafe impl Send for SecretBundleEntry {}

/// Owned secret bundle.
#[repr(C)]
#[derive(Debug)]
pub struct SecretBundle {
    pub entries: List<SecretBundleEntry>,
}

unsafe impl Send for SecretBundle {}

/// Host-declared interactive-auth capability. Discriminants are the
/// ABI contract; adding a variant is a breaking change.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InteractiveAuthCapabilityV1 {
    None = 0,
    Headless = 1,
    Browser = 2,
}

/// Connection-create request. `config` is a flat key/value list;
/// top-level scalars use the matching `ConfigValue` variant, nested
/// values arrive as `ConfigValue::Toml`.
#[repr(C)]
#[derive(Debug)]
pub struct ConnectionRequest {
    pub backend_kind: Str,
    pub config: List<ConnectionConfigEntry>,
    pub credentials: SecretBundle,
    pub persist: bool,
    pub display_name: Optional<Str>,
}

unsafe impl Send for ConnectionRequest {}

/// `(key, ConfigValue)` entry inside a [`ConnectionRequest::config`]
/// list. Iteration order is not preserved.
#[repr(C)]
#[derive(Debug)]
pub struct ConnectionConfigEntry {
    pub key: Str,
    pub value: ConfigValue,
}

unsafe impl Send for ConnectionConfigEntry {}

/// Drop a [`StorageBackendKindDescriptor`]'s nested allocations in
/// place. Safe with NULL. The pointee is caller-owned (the
/// `descriptor` sync slot's out-parameter).
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// descriptor produced by an ovstorage call. Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_storage_backend_kind_descriptor_free(
    value: *mut StorageBackendKindDescriptor,
) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// Drop a [`ConnectionRequest`]'s nested allocations in place. Safe
/// with NULL. The pointee is caller-owned input storage.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`ConnectionRequest`] produced by an ovstorage call.
/// Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_connection_request_free(value: *mut ConnectionRequest) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

// ---------------------------------------------------------------------
// Auth state machine + Connection + AuthEvent
//
// State-machine errors embed inline `(code, message)` rather than the
// full `Error` type; standalone `Error` stays purely return-shaped.
// ---------------------------------------------------------------------

/// Tag for [`AuthReason`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuthReasonTag {
    NeverAuthenticated = 0,
    RefreshTokenExpired = 1,
    RefreshTokenRevoked = 2,
    CredentialsRotated = 3,
    ManuallyRequested = 4,
    BackendUnreachable = 5,
    Unknown = 6,
}

/// Why a connection is awaiting authentication. `Unknown` carries a
/// free-form details string.
#[repr(C)]
#[derive(Debug)]
pub struct AuthReason {
    pub tag: AuthReasonTag,
    pub unknown_details: core::mem::MaybeUninit<Str>,
}

unsafe impl Send for AuthReason {}

impl AuthReason {
    pub fn never_authenticated() -> Self {
        Self {
            tag: AuthReasonTag::NeverAuthenticated,
            unknown_details: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn refresh_token_expired() -> Self {
        Self {
            tag: AuthReasonTag::RefreshTokenExpired,
            unknown_details: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn refresh_token_revoked() -> Self {
        Self {
            tag: AuthReasonTag::RefreshTokenRevoked,
            unknown_details: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn credentials_rotated() -> Self {
        Self {
            tag: AuthReasonTag::CredentialsRotated,
            unknown_details: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn manually_requested() -> Self {
        Self {
            tag: AuthReasonTag::ManuallyRequested,
            unknown_details: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn backend_unreachable() -> Self {
        Self {
            tag: AuthReasonTag::BackendUnreachable,
            unknown_details: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn unknown(details: Str) -> Self {
        Self {
            tag: AuthReasonTag::Unknown,
            unknown_details: core::mem::MaybeUninit::new(details),
        }
    }
}

impl Drop for AuthReason {
    fn drop(&mut self) {
        if let AuthReasonTag::Unknown = self.tag {
            unsafe {
                self.unknown_details.assume_init_drop();
            }
        }
    }
}

/// Inline `(code, message)` pair for state-shaped fields where the
/// owning `Error` cannot be used (it is return-shaped).
#[repr(C)]
#[derive(Debug)]
pub struct AuthAttemptError {
    pub code: ErrorCode,
    pub message: Str,
}

unsafe impl Send for AuthAttemptError {}

/// One auth-attempt record.
#[repr(C)]
#[derive(Debug)]
pub struct AuthAttempt {
    pub at_unix_ms: i64,
    pub error: Optional<AuthAttemptError>,
}

unsafe impl Send for AuthAttempt {}

/// Tag for [`ConnectionAuthState`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectionAuthStateTag {
    Authenticated = 0,
    AwaitingAuth = 1,
    AuthFailed = 2,
    Anonymous = 3,
}

/// `ConnectionAuthState::Authenticated` payload.
#[repr(C)]
#[derive(Debug)]
pub struct ConnectionAuthStateAuthenticated {
    pub last_authenticated_at_unix_ms: i64,
    pub expires_at_unix_ms: Optional<i64>,
}

unsafe impl Send for ConnectionAuthStateAuthenticated {}

/// `ConnectionAuthState::AwaitingAuth` payload.
#[repr(C)]
#[derive(Debug)]
pub struct ConnectionAuthStateAwaitingAuth {
    pub reason: AuthReason,
    pub last_attempt: Optional<AuthAttempt>,
}

unsafe impl Send for ConnectionAuthStateAwaitingAuth {}

/// `ConnectionAuthState::AuthFailed` payload (inline error).
#[repr(C)]
#[derive(Debug)]
pub struct ConnectionAuthStateAuthFailed {
    pub error_code: ErrorCode,
    pub error_message: Str,
    pub attempts: u32,
}

unsafe impl Send for ConnectionAuthStateAuthFailed {}

/// Persisted auth state of a connection.
#[repr(C)]
#[derive(Debug)]
pub struct ConnectionAuthState {
    pub tag: ConnectionAuthStateTag,
    pub authenticated: core::mem::MaybeUninit<ConnectionAuthStateAuthenticated>,
    pub awaiting_auth: core::mem::MaybeUninit<ConnectionAuthStateAwaitingAuth>,
    pub auth_failed: core::mem::MaybeUninit<ConnectionAuthStateAuthFailed>,
}

unsafe impl Send for ConnectionAuthState {}

impl ConnectionAuthState {
    pub fn from_authenticated(value: ConnectionAuthStateAuthenticated) -> Self {
        Self {
            tag: ConnectionAuthStateTag::Authenticated,
            authenticated: core::mem::MaybeUninit::new(value),
            awaiting_auth: core::mem::MaybeUninit::uninit(),
            auth_failed: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn from_awaiting_auth(value: ConnectionAuthStateAwaitingAuth) -> Self {
        Self {
            tag: ConnectionAuthStateTag::AwaitingAuth,
            authenticated: core::mem::MaybeUninit::uninit(),
            awaiting_auth: core::mem::MaybeUninit::new(value),
            auth_failed: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn from_auth_failed(value: ConnectionAuthStateAuthFailed) -> Self {
        Self {
            tag: ConnectionAuthStateTag::AuthFailed,
            authenticated: core::mem::MaybeUninit::uninit(),
            awaiting_auth: core::mem::MaybeUninit::uninit(),
            auth_failed: core::mem::MaybeUninit::new(value),
        }
    }
    pub fn anonymous() -> Self {
        Self {
            tag: ConnectionAuthStateTag::Anonymous,
            authenticated: core::mem::MaybeUninit::uninit(),
            awaiting_auth: core::mem::MaybeUninit::uninit(),
            auth_failed: core::mem::MaybeUninit::uninit(),
        }
    }
}

impl Drop for ConnectionAuthState {
    fn drop(&mut self) {
        unsafe {
            match self.tag {
                ConnectionAuthStateTag::Authenticated => self.authenticated.assume_init_drop(),
                ConnectionAuthStateTag::AwaitingAuth => self.awaiting_auth.assume_init_drop(),
                ConnectionAuthStateTag::AuthFailed => self.auth_failed.assume_init_drop(),
                ConnectionAuthStateTag::Anonymous => {}
            }
        }
    }
}

/// Connection — a configured backend instance plus its auth state.
#[repr(C)]
#[derive(Debug)]
pub struct Connection {
    pub id: ConnectionId,
    pub backend_kind: Str,
    pub display_name: Str,
    pub source: ConnectionSource,
    pub capabilities: Capabilities,
    pub current_addresses: List<Str>,
    pub auth_state: ConnectionAuthState,
    pub last_probed_unix_ms: Optional<i64>,
    pub user_metadata: KeyValueList,
}

unsafe impl Send for Connection {}

/// Drop a [`Connection`]'s nested allocations in place. Safe with
/// NULL. The pointee is caller-owned (input parameter or embedded in
/// `AuthEvent::Succeeded`).
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`Connection`] produced by an ovstorage call. Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_connection_free(value: *mut Connection) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// Tag for [`AuthEvent`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuthEventTag {
    OpenBrowser = 0,
    DeviceCode = 1,
    Progress = 2,
    Succeeded = 3,
    Failed = 4,
    Cancelled = 5,
}

/// `AuthEvent::OpenBrowser` payload.
#[repr(C)]
#[derive(Debug)]
pub struct AuthEventOpenBrowser {
    pub url: Str,
    pub expires_at_unix_ms: i64,
}

unsafe impl Send for AuthEventOpenBrowser {}

/// `AuthEvent::DeviceCode` payload.
#[repr(C)]
#[derive(Debug)]
pub struct AuthEventDeviceCode {
    pub user_code: Str,
    pub verification_url: Str,
    pub expires_at_unix_ms: i64,
    pub interval_ms: u64,
}

unsafe impl Send for AuthEventDeviceCode {}

/// `AuthEvent::Progress` payload.
#[repr(C)]
#[derive(Debug)]
pub struct AuthEventProgress {
    pub message: Str,
}

unsafe impl Send for AuthEventProgress {}

/// `AuthEvent::Failed` payload (inline error).
#[repr(C)]
#[derive(Debug)]
pub struct AuthEventFailed {
    pub error_code: ErrorCode,
    pub error_message: Str,
}

unsafe impl Send for AuthEventFailed {}

/// `AuthEvent::Succeeded` payload — connection plus optional credentials
/// the host should install via `update_credentials`.
#[repr(C)]
#[derive(Debug)]
pub struct AuthEventSucceeded {
    pub connection: Connection,
    pub credentials: Optional<SecretBundle>,
}

unsafe impl Send for AuthEventSucceeded {}

/// One auth-flow event yielded by an [`AuthEventStream`].
#[repr(C)]
#[derive(Debug)]
pub struct AuthEvent {
    pub tag: AuthEventTag,
    pub open_browser: core::mem::MaybeUninit<AuthEventOpenBrowser>,
    pub device_code: core::mem::MaybeUninit<AuthEventDeviceCode>,
    pub progress: core::mem::MaybeUninit<AuthEventProgress>,
    pub succeeded: core::mem::MaybeUninit<AuthEventSucceeded>,
    pub failed: core::mem::MaybeUninit<AuthEventFailed>,
}

unsafe impl Send for AuthEvent {}

impl AuthEvent {
    pub fn from_open_browser(value: AuthEventOpenBrowser) -> Self {
        Self {
            tag: AuthEventTag::OpenBrowser,
            open_browser: core::mem::MaybeUninit::new(value),
            device_code: core::mem::MaybeUninit::uninit(),
            progress: core::mem::MaybeUninit::uninit(),
            succeeded: core::mem::MaybeUninit::uninit(),
            failed: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn from_device_code(value: AuthEventDeviceCode) -> Self {
        Self {
            tag: AuthEventTag::DeviceCode,
            open_browser: core::mem::MaybeUninit::uninit(),
            device_code: core::mem::MaybeUninit::new(value),
            progress: core::mem::MaybeUninit::uninit(),
            succeeded: core::mem::MaybeUninit::uninit(),
            failed: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn from_progress(value: AuthEventProgress) -> Self {
        Self {
            tag: AuthEventTag::Progress,
            open_browser: core::mem::MaybeUninit::uninit(),
            device_code: core::mem::MaybeUninit::uninit(),
            progress: core::mem::MaybeUninit::new(value),
            succeeded: core::mem::MaybeUninit::uninit(),
            failed: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn from_succeeded(value: AuthEventSucceeded) -> Self {
        Self {
            tag: AuthEventTag::Succeeded,
            open_browser: core::mem::MaybeUninit::uninit(),
            device_code: core::mem::MaybeUninit::uninit(),
            progress: core::mem::MaybeUninit::uninit(),
            succeeded: core::mem::MaybeUninit::new(value),
            failed: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn from_failed(value: AuthEventFailed) -> Self {
        Self {
            tag: AuthEventTag::Failed,
            open_browser: core::mem::MaybeUninit::uninit(),
            device_code: core::mem::MaybeUninit::uninit(),
            progress: core::mem::MaybeUninit::uninit(),
            succeeded: core::mem::MaybeUninit::uninit(),
            failed: core::mem::MaybeUninit::new(value),
        }
    }
    pub fn cancelled() -> Self {
        Self {
            tag: AuthEventTag::Cancelled,
            open_browser: core::mem::MaybeUninit::uninit(),
            device_code: core::mem::MaybeUninit::uninit(),
            progress: core::mem::MaybeUninit::uninit(),
            succeeded: core::mem::MaybeUninit::uninit(),
            failed: core::mem::MaybeUninit::uninit(),
        }
    }
}

impl Drop for AuthEvent {
    fn drop(&mut self) {
        unsafe {
            match self.tag {
                AuthEventTag::OpenBrowser => self.open_browser.assume_init_drop(),
                AuthEventTag::DeviceCode => self.device_code.assume_init_drop(),
                AuthEventTag::Progress => self.progress.assume_init_drop(),
                AuthEventTag::Succeeded => self.succeeded.assume_init_drop(),
                AuthEventTag::Failed => self.failed.assume_init_drop(),
                AuthEventTag::Cancelled => {}
            }
        }
    }
}

/// Drop an [`AuthEvent`]'s active payload in place. Safe with NULL.
/// `AuthEvent` is delivered through caller-owned `out_item` storage
/// from `AuthEventStream::next_fn`.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`AuthEvent`] produced by an ovstorage call. Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_auth_event_free(value: *mut AuthEvent) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

// ---------------------------------------------------------------------
