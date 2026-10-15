// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! C plugin-SDK access to the canonical `AuthCredential` wire codec.

use super::*;
use ovstorage_authz_context::{
    AuthCredential as WireAuthCredential, DecodeError, Transport as WireTransport,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use zeroize::Zeroize as _;

/// Tag selecting the active payload in [`AuthCredentialTransport`]. Values
/// match the transport tags in the canonical flat wire format.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuthCredentialTransportTag {
    Tcp = 0,
    Uds = 1,
    NamedPipe = 2,
}

/// TCP transport identity decoded from an auth credential.
#[repr(C)]
#[derive(Debug)]
pub struct AuthCredentialTcp {
    pub peer_addr: Str,
    pub tls_client_cert: Optional<Bytes>,
}

unsafe impl Send for AuthCredentialTcp {}

/// Unix-domain-socket peer credentials decoded from an auth credential.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct AuthCredentialUds {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

/// Windows named-pipe peer identity decoded from an auth credential.
#[repr(C)]
#[derive(Debug)]
pub struct AuthCredentialNamedPipe {
    pub sid: Str,
    pub pid: u32,
}

unsafe impl Send for AuthCredentialNamedPipe {}

/// Tagged transport identity decoded from an auth credential. Read only the
/// payload selected by `tag`.
#[repr(C)]
#[derive(Debug)]
pub struct AuthCredentialTransport {
    pub tag: AuthCredentialTransportTag,
    pub tcp: core::mem::MaybeUninit<AuthCredentialTcp>,
    pub uds: core::mem::MaybeUninit<AuthCredentialUds>,
    pub named_pipe: core::mem::MaybeUninit<AuthCredentialNamedPipe>,
}

unsafe impl Send for AuthCredentialTransport {}

impl AuthCredentialTransport {
    fn tcp(peer_addr: String, tls_client_cert: Option<Vec<u8>>) -> Self {
        Self {
            tag: AuthCredentialTransportTag::Tcp,
            tcp: core::mem::MaybeUninit::new(AuthCredentialTcp {
                peer_addr: crate::marshal::primitive::str_to_ffi(peer_addr),
                tls_client_cert: crate::marshal::primitive::optional_to_ffi(
                    tls_client_cert,
                    crate::marshal::primitive::bytes_to_ffi,
                ),
            }),
            uds: core::mem::MaybeUninit::uninit(),
            named_pipe: core::mem::MaybeUninit::uninit(),
        }
    }

    fn uds(uid: u32, gid: u32, pid: i32) -> Self {
        Self {
            tag: AuthCredentialTransportTag::Uds,
            tcp: core::mem::MaybeUninit::uninit(),
            uds: core::mem::MaybeUninit::new(AuthCredentialUds { uid, gid, pid }),
            named_pipe: core::mem::MaybeUninit::uninit(),
        }
    }

    fn named_pipe(sid: String, pid: u32) -> Self {
        Self {
            tag: AuthCredentialTransportTag::NamedPipe,
            tcp: core::mem::MaybeUninit::uninit(),
            uds: core::mem::MaybeUninit::uninit(),
            named_pipe: core::mem::MaybeUninit::new(AuthCredentialNamedPipe {
                sid: crate::marshal::primitive::str_to_ffi(sid),
                pid,
            }),
        }
    }
}

impl Drop for AuthCredentialTransport {
    fn drop(&mut self) {
        unsafe {
            match self.tag {
                AuthCredentialTransportTag::Tcp => self.tcp.assume_init_drop(),
                AuthCredentialTransportTag::Uds => self.uds.assume_init_drop(),
                AuthCredentialTransportTag::NamedPipe => self.named_pipe.assume_init_drop(),
            }
        }
    }
}

/// One forwarded request-header value. Duplicates and input order are
/// preserved so an auth Layer can reject ambiguous identity metadata.
#[repr(C)]
#[derive(Debug)]
pub struct AuthCredentialForwardedHeader {
    pub name: Str,
    pub value: Str,
}

unsafe impl Send for AuthCredentialForwardedHeader {}

/// Typed view of a decoded `AUTH_CREDENTIAL` extension value.
///
/// `bearer` is secret: plugin code must not log or persist its bytes. It uses
/// the ordinary [`Bytes`] shape so C callers can read it without a second
/// secret-specific wrapper; [`Drop`] zeroizes that buffer before the normal
/// [`Bytes`] destructor returns it to the ABI heap. Release the whole value
/// exactly once with [`ovstorage_plugin_auth_credential_free`].
#[repr(C)]
#[derive(Debug)]
pub struct AuthCredential {
    pub struct_size: usize,
    pub bearer: Optional<Bytes>,
    pub transport: AuthCredentialTransport,
    pub forwarded_headers: List<AuthCredentialForwardedHeader>,
}

unsafe impl Send for AuthCredential {}

impl Drop for AuthCredential {
    fn drop(&mut self) {
        if self.bearer.present {
            // SAFETY: `present` means the slot is initialized. The wipe runs
            // before field drop glue releases the Bytes allocation.
            let bearer = unsafe { self.bearer.value.assume_init_mut() };
            if !bearer.ptr.is_null() {
                // SAFETY: `bearer` owns `len` initialized bytes until its Drop.
                unsafe { std::slice::from_raw_parts_mut(bearer.ptr, bearer.len).zeroize() };
            }
        }
        #[cfg(test)]
        released_bearers::record(self);
    }
}

/// Test-only observation point for the bearer after `Drop` wipes it and
/// before field drop glue releases the owning [`Bytes`] allocation. Reading
/// the allocation after `free` would be undefined; recording here witnesses
/// the public free path without depending on allocator recycling behavior.
#[cfg(test)]
mod released_bearers {
    use std::cell::RefCell;

    thread_local! {
        static RELEASED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(credential: &super::AuthCredential) {
        if !credential.bearer.present {
            return;
        }
        let bearer = unsafe { credential.bearer.value.assume_init_ref() };
        if bearer.ptr.is_null() {
            return;
        }
        // SAFETY: `AuthCredential::drop` calls this before `Optional<Bytes>`
        // field drop glue, so the wiped allocation remains live and owned.
        let contents = unsafe { std::slice::from_raw_parts(bearer.ptr, bearer.len).to_vec() };
        let _ = RELEASED.try_with(|released| released.borrow_mut().push(contents));
    }

    pub(super) fn take() -> Vec<Vec<u8>> {
        RELEASED.with(|released| std::mem::take(&mut *released.borrow_mut()))
    }
}

/// Copy bearer bytes onto the ABI heap, then wipe the codec-owned source before
/// its Rust allocation is released. The ABI copy is wiped by
/// [`AuthCredential::drop`].
fn bearer_to_ffi(mut bearer: Vec<u8>) -> Bytes {
    let bytes = crate::marshal::primitive::bytes_ref_to_ffi(&bearer);
    bearer.zeroize();
    bytes
}

impl From<WireAuthCredential> for AuthCredential {
    fn from(value: WireAuthCredential) -> Self {
        let transport = match value.transport {
            WireTransport::Tcp {
                peer_addr,
                tls_client_cert,
            } => AuthCredentialTransport::tcp(peer_addr, tls_client_cert),
            WireTransport::Uds { uid, gid, pid } => AuthCredentialTransport::uds(uid, gid, pid),
            WireTransport::NamedPipe { sid, pid } => AuthCredentialTransport::named_pipe(sid, pid),
        };
        let forwarded_headers = value
            .forwarded
            .map(|forwarded| forwarded.values)
            .unwrap_or_default();
        Self {
            struct_size: core::mem::size_of::<Self>(),
            bearer: crate::marshal::primitive::optional_to_ffi(value.bearer, bearer_to_ffi),
            transport,
            forwarded_headers: crate::marshal::primitive::list_to_ffi(
                forwarded_headers,
                |(name, value)| AuthCredentialForwardedHeader {
                    name: crate::marshal::primitive::str_to_ffi(name),
                    value: crate::marshal::primitive::str_to_ffi(value),
                },
            ),
        }
    }
}

fn decode_error(error: DecodeError) -> crate::Error {
    let code = match error {
        DecodeError::UnsupportedVersion => crate::ErrorCode::IncompatibleType,
        DecodeError::Truncated
        | DecodeError::BadTag
        | DecodeError::Utf8
        | DecodeError::TrailingData => crate::ErrorCode::InvalidArgument,
    };
    crate::Error::new(code, format!("AuthCredential decode failed: {error}"))
}

fn write_error(err: *mut *mut Error, error: crate::Error) -> FfiStatus {
    if !err.is_null() {
        unsafe {
            std::ptr::write(
                err,
                crate::ffi::abi_alloc::abi_box(crate::marshal::error::to_ffi(&error)),
            )
        };
    }
    FFI_STATUS_ERR
}

/// Decode one canonical `AUTH_CREDENTIAL` extension value for a C auth Layer.
///
/// This is a plugin-owned SDK helper, not a symbol imported from the host. A C
/// auth plugin compiles the shipped `auth_credential.c`, `plugin_values.c`,
/// `plat.c`, and `utf8.c` support sources into its own cdylib; Rust plugins link
/// the corresponding implementation from `ovstorage-plugin`.
///
/// On success, writes an ABI-heap-owned value to `*out`, writes NULL to
/// `*err`, and returns [`FFI_STATUS_OK`]. On failure, writes NULL to `*out`, a
/// typed heap-owned [`Error`] to `*err`, and returns [`FFI_STATUS_ERR`]. The
/// caller releases a successful value with
/// [`ovstorage_plugin_auth_credential_free`] or an error with
/// [`ovstorage_plugin_error_free`]. `bytes` is borrowed for this call only.
///
/// # Safety
///
/// `bytes` must point to `len` readable bytes (NULL is accepted only when
/// `len == 0`). `out` and `err` must be valid writable out-parameters.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_auth_credential_decode(
    bytes: *const u8,
    len: usize,
    out: *mut *mut AuthCredential,
    err: *mut *mut Error,
) -> FfiStatus {
    if !out.is_null() {
        unsafe { std::ptr::write(out, std::ptr::null_mut()) };
    }
    if !err.is_null() {
        unsafe { std::ptr::write(err, std::ptr::null_mut()) };
    }
    if out.is_null() || err.is_null() {
        return write_error(
            err,
            crate::Error::new(
                crate::ErrorCode::InvalidArgument,
                "AuthCredential decode requires non-null out and err parameters",
            ),
        );
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        if bytes.is_null() && len != 0 {
            return Err(crate::Error::new(
                crate::ErrorCode::InvalidArgument,
                "AuthCredential bytes pointer is null with non-zero length",
            ));
        }
        let bytes = if len == 0 {
            &[]
        } else {
            // SAFETY: upheld by this function's caller contract and checked
            // above for the only invalid NULL/length combination.
            unsafe { std::slice::from_raw_parts(bytes, len) }
        };
        WireAuthCredential::decode(bytes)
            .map(AuthCredential::from)
            .map_err(decode_error)
    }));

    match result {
        Ok(Ok(value)) => {
            unsafe { std::ptr::write(out, crate::ffi::abi_alloc::abi_box(value)) };
            FFI_STATUS_OK
        }
        Ok(Err(error)) => write_error(err, error),
        Err(_) => write_error(
            err,
            crate::Error::new(
                crate::ErrorCode::Internal,
                "panic while decoding AuthCredential",
            ),
        ),
    }
}

/// Reclaim a decoded [`AuthCredential`] and all nested ABI buffers. Safe with
/// NULL. The bearer buffer is zeroized before it is released.
///
/// # Safety
///
/// `value`, when non-null, must be a pointer returned by
/// [`ovstorage_plugin_auth_credential_decode`] and not previously freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_auth_credential_free(value: *mut AuthCredential) {
    unsafe { crate::ffi::abi_alloc::abi_box_free(value) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_authz_context::ForwardedHeaders;

    const ABI_ACCOUNTING_CHILD_ENV: &str = "OVSTORAGE_AUTH_CREDENTIAL_ACCOUNTING_CHILD";

    fn credential_sentinel() -> *mut AuthCredential {
        std::ptr::without_provenance_mut(1)
    }

    fn error_sentinel() -> *mut Error {
        std::ptr::without_provenance_mut(2)
    }

    fn in_abi_accounting_child(test_name: &str, body: fn()) {
        if std::env::var_os(ABI_ACCOUNTING_CHILD_ENV).is_some() {
            body();
            return;
        }

        let status =
            std::process::Command::new(std::env::current_exe().expect("current unit-test binary"))
                .args([test_name, "--exact", "--nocapture", "--test-threads=1"])
                .env(ABI_ACCOUNTING_CHILD_ENV, test_name)
                .status()
                .expect("re-execute the unit-test binary for isolated ABI accounting");
        assert!(
            status.success(),
            "isolated ABI-accounting child failed: {status:?}",
        );
    }

    fn decode(value: &WireAuthCredential) -> *mut AuthCredential {
        let encoded = value.encode();
        let mut out = credential_sentinel();
        let mut err = error_sentinel();
        let status = unsafe {
            ovstorage_plugin_auth_credential_decode(
                encoded.as_ptr(),
                encoded.len(),
                &mut out,
                &mut err,
            )
        };
        assert_eq!(status, FFI_STATUS_OK);
        assert!(err.is_null(), "success must clear a reused error pointer");
        assert_ne!(out, credential_sentinel());
        assert!(
            !out.is_null(),
            "success must replace a reused output pointer"
        );
        out
    }

    unsafe fn bytes(value: &Bytes) -> &[u8] {
        unsafe { crate::marshal::primitive::bytes_borrow(value) }
    }

    unsafe fn string(value: &Str) -> &str {
        unsafe { crate::marshal::primitive::str_borrow(value).unwrap() }
    }

    unsafe fn assert_common(actual: &AuthCredential, expected: &WireAuthCredential) {
        assert_eq!(actual.struct_size, core::mem::size_of::<AuthCredential>());
        match expected.bearer.as_deref() {
            Some(expected) => {
                assert!(actual.bearer.present);
                assert_eq!(
                    unsafe { bytes(actual.bearer.value.assume_init_ref()) },
                    expected
                );
            }
            None => assert!(!actual.bearer.present),
        }
        let expected_headers = expected
            .forwarded
            .as_ref()
            .map(|forwarded| forwarded.values.as_slice())
            .unwrap_or_default();
        let actual_headers = unsafe {
            std::slice::from_raw_parts(actual.forwarded_headers.ptr, actual.forwarded_headers.len)
        };
        assert_eq!(actual_headers.len(), expected_headers.len());
        for (actual, (name, value)) in actual_headers.iter().zip(expected_headers) {
            assert_eq!(unsafe { string(&actual.name) }, name);
            assert_eq!(unsafe { string(&actual.value) }, value);
        }
    }

    #[test]
    fn decode_tcp_with_bearer_cert_and_forwarded_headers() {
        let expected = WireAuthCredential {
            bearer: Some(b"secret-token".to_vec()),
            transport: WireTransport::Tcp {
                peer_addr: "10.0.0.4:8443".into(),
                tls_client_cert: Some(vec![0xde, 0xad, 0xbe, 0xef]),
            },
            forwarded: Some(ForwardedHeaders {
                values: vec![
                    ("x-user".into(), "alice".into()),
                    ("x-role".into(), "artist".into()),
                ],
            }),
        };
        let out = decode(&expected);
        let actual = unsafe { &*out };
        unsafe { assert_common(actual, &expected) };
        assert_eq!(actual.transport.tag, AuthCredentialTransportTag::Tcp);
        let tcp = unsafe { actual.transport.tcp.assume_init_ref() };
        assert_eq!(unsafe { string(&tcp.peer_addr) }, "10.0.0.4:8443");
        assert!(tcp.tls_client_cert.present);
        assert_eq!(
            unsafe { bytes(tcp.tls_client_cert.value.assume_init_ref()) },
            [0xde, 0xad, 0xbe, 0xef]
        );
        unsafe { ovstorage_plugin_auth_credential_free(out) };
    }

    #[test]
    fn decode_uds_with_absent_bearer() {
        let expected = WireAuthCredential {
            bearer: None,
            transport: WireTransport::Uds {
                uid: 1000,
                gid: 1001,
                pid: -42,
            },
            forwarded: None,
        };
        let out = decode(&expected);
        let actual = unsafe { &*out };
        unsafe { assert_common(actual, &expected) };
        assert_eq!(actual.transport.tag, AuthCredentialTransportTag::Uds);
        let uds = unsafe { actual.transport.uds.assume_init_ref() };
        assert_eq!((uds.uid, uds.gid, uds.pid), (1000, 1001, -42));
        unsafe { ovstorage_plugin_auth_credential_free(out) };
    }

    #[test]
    fn decode_named_pipe_field_by_field() {
        let expected = WireAuthCredential {
            bearer: Some(vec![0, 1, 0xff]),
            transport: WireTransport::NamedPipe {
                sid: "S-1-5-21-1004336348".into(),
                pid: 4321,
            },
            forwarded: None,
        };
        let out = decode(&expected);
        let actual = unsafe { &*out };
        unsafe { assert_common(actual, &expected) };
        assert_eq!(actual.transport.tag, AuthCredentialTransportTag::NamedPipe);
        let named_pipe = unsafe { actual.transport.named_pipe.assume_init_ref() };
        assert_eq!(unsafe { string(&named_pipe.sid) }, "S-1-5-21-1004336348");
        assert_eq!(named_pipe.pid, 4321);
        unsafe { ovstorage_plugin_auth_credential_free(out) };
    }

    fn assert_decode_error(bytes: &[u8], code: crate::ErrorCode, message: &str) {
        let mut out = credential_sentinel();
        let mut err = error_sentinel();
        let status = unsafe {
            ovstorage_plugin_auth_credential_decode(bytes.as_ptr(), bytes.len(), &mut out, &mut err)
        };
        assert_eq!(status, FFI_STATUS_ERR);
        assert!(out.is_null(), "failure must clear a reused output pointer");
        assert_ne!(err, error_sentinel());
        assert!(
            !err.is_null(),
            "failure must replace a reused error pointer"
        );
        let ffi_error = unsafe { crate::ffi::abi_alloc::abi_unbox(err) };
        let error = unsafe { crate::marshal::error::from_ffi(ffi_error) };
        assert_eq!(error.code(), code);
        assert_eq!(error.message(), message);
    }

    #[test]
    fn every_wire_decode_error_maps_to_a_typed_error() {
        assert_decode_error(
            &[99],
            crate::ErrorCode::IncompatibleType,
            "AuthCredential decode failed: unsupported wire version",
        );
        assert_decode_error(
            &[],
            crate::ErrorCode::InvalidArgument,
            "AuthCredential decode failed: truncated buffer",
        );
        assert_decode_error(
            &[2, 0, 0, 0, 0, 99],
            crate::ErrorCode::InvalidArgument,
            "AuthCredential decode failed: bad transport tag",
        );
        assert_decode_error(
            &[2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0xff],
            crate::ErrorCode::InvalidArgument,
            "AuthCredential decode failed: invalid utf-8 in string field",
        );
        let mut trailing = WireAuthCredential::new(
            None,
            WireTransport::Uds {
                uid: 1,
                gid: 2,
                pid: 3,
            },
        )
        .encode();
        trailing.push(0xff);
        assert_decode_error(
            &trailing,
            crate::ErrorCode::InvalidArgument,
            "AuthCredential decode failed: trailing data after credential",
        );
    }

    #[test]
    fn transport_tags_match_canonical_wire_values() {
        for (transport, expected_tag) in [
            (
                WireTransport::Tcp {
                    peer_addr: String::new(),
                    tls_client_cert: None,
                },
                0,
            ),
            (
                WireTransport::Uds {
                    uid: 0,
                    gid: 0,
                    pid: 0,
                },
                1,
            ),
            (
                WireTransport::NamedPipe {
                    sid: String::new(),
                    pid: 0,
                },
                2,
            ),
        ] {
            let encoded = WireAuthCredential::new(None, transport).encode();
            assert_eq!(encoded[5], expected_tag);
        }
    }

    #[test]
    fn free_reclaims_and_zeroizes_decoded_credential() {
        in_abi_accounting_child(
            "ffi::v2::auth_credential::tests::free_reclaims_and_zeroizes_decoded_credential",
            free_reclaims_and_zeroizes_decoded_credential_body,
        );
    }

    fn free_reclaims_and_zeroizes_decoded_credential_body() {
        const BEARER_LEN: usize = 128;

        let _ = released_bearers::take();
        let expected = WireAuthCredential {
            bearer: Some(vec![0xa5; BEARER_LEN]),
            transport: WireTransport::Tcp {
                peer_addr: "10.0.0.4:8443".into(),
                tls_client_cert: Some(vec![0xde, 0xad, 0xbe, 0xef]),
            },
            forwarded: Some(ForwardedHeaders {
                values: vec![("x-user".into(), "alice".into())],
            }),
        };
        let before = crate::ffi::abi_alloc::abi_live_bytes();
        let out = decode(&expected);
        assert!(
            crate::ffi::abi_alloc::abi_live_bytes() > before,
            "decoding must allocate the credential and its nested ABI buffers",
        );

        unsafe { ovstorage_plugin_auth_credential_free(out) };

        assert_eq!(
            crate::ffi::abi_alloc::abi_live_bytes(),
            before,
            "free must reclaim the credential and every nested ABI allocation",
        );
        let released = released_bearers::take();
        assert_eq!(released.len(), 1, "the free path must release one bearer");
        assert_eq!(released[0].len(), BEARER_LEN);
        assert!(
            released[0].iter().all(|byte| *byte == 0),
            "bearer plaintext reached the ABI allocator: {:02x?}",
            released[0],
        );
    }

    #[test]
    fn free_is_null_safe() {
        unsafe { ovstorage_plugin_auth_credential_free(std::ptr::null_mut()) };
    }
}
