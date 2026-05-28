// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub fn auth_reason_to_ffi(value: AuthReason) -> ffi::AuthReason {
    match value {
        AuthReason::NeverAuthenticated => ffi::AuthReason::never_authenticated(),
        AuthReason::RefreshTokenExpired => ffi::AuthReason::refresh_token_expired(),
        AuthReason::RefreshTokenRevoked => ffi::AuthReason::refresh_token_revoked(),
        AuthReason::CredentialsRotated => ffi::AuthReason::credentials_rotated(),
        AuthReason::ManuallyRequested => ffi::AuthReason::manually_requested(),
        AuthReason::BackendUnreachable => ffi::AuthReason::backend_unreachable(),
        AuthReason::Unknown { details } => ffi::AuthReason::unknown(primitive::str_to_ffi(details)),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::AuthReason`] produced by
/// [`auth_reason_to_ffi`].
pub unsafe fn auth_reason_from_ffi(value: ffi::AuthReason) -> Result<AuthReason, Error> {
    unsafe {
        match value.tag {
            ffi::AuthReasonTag::NeverAuthenticated => {
                std::mem::forget(value);
                Ok(AuthReason::NeverAuthenticated)
            }
            ffi::AuthReasonTag::RefreshTokenExpired => {
                std::mem::forget(value);
                Ok(AuthReason::RefreshTokenExpired)
            }
            ffi::AuthReasonTag::RefreshTokenRevoked => {
                std::mem::forget(value);
                Ok(AuthReason::RefreshTokenRevoked)
            }
            ffi::AuthReasonTag::CredentialsRotated => {
                std::mem::forget(value);
                Ok(AuthReason::CredentialsRotated)
            }
            ffi::AuthReasonTag::ManuallyRequested => {
                std::mem::forget(value);
                Ok(AuthReason::ManuallyRequested)
            }
            ffi::AuthReasonTag::BackendUnreachable => {
                std::mem::forget(value);
                Ok(AuthReason::BackendUnreachable)
            }
            ffi::AuthReasonTag::Unknown => {
                let details = std::ptr::read(value.unknown_details.as_ptr());
                std::mem::forget(value);
                Ok(AuthReason::Unknown {
                    details: primitive::str_from_ffi(details)?,
                })
            }
        }
    }
}

pub fn auth_attempt_to_ffi(value: AuthAttempt) -> ffi::AuthAttempt {
    ffi::AuthAttempt {
        at_unix_ms: primitive::system_time_to_unix_ms(value.at),
        error: primitive::optional_to_ffi(value.error, |error| ffi::AuthAttemptError {
            code: error::code_to_ffi(error.code()),
            message: primitive::str_to_ffi(error.message().to_owned()),
        }),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::AuthAttempt`] produced by
/// [`auth_attempt_to_ffi`].
pub unsafe fn auth_attempt_from_ffi(value: ffi::AuthAttempt) -> Result<AuthAttempt, Error> {
    unsafe {
        let at = primitive::system_time_from_unix_ms(value.at_unix_ms);
        let error = primitive::optional_from_ffi(value.error, |attempt_error| {
            let message = primitive::str_from_ffi(attempt_error.message)?;
            Ok::<_, Error>(Error::new(
                error::code_from_ffi(attempt_error.code),
                message,
            ))
        })?;
        Ok(AuthAttempt { at, error })
    }
}

pub fn connection_auth_state_to_ffi(value: ConnectionAuthState) -> ffi::ConnectionAuthState {
    match value {
        ConnectionAuthState::Authenticated {
            last_authenticated_at,
            expires_at,
        } => ffi::ConnectionAuthState::from_authenticated(ffi::ConnectionAuthStateAuthenticated {
            last_authenticated_at_unix_ms: primitive::system_time_to_unix_ms(last_authenticated_at),
            expires_at_unix_ms: primitive::optional_to_ffi(
                expires_at,
                primitive::system_time_to_unix_ms,
            ),
        }),
        ConnectionAuthState::AwaitingAuth {
            reason,
            last_attempt,
        } => ffi::ConnectionAuthState::from_awaiting_auth(ffi::ConnectionAuthStateAwaitingAuth {
            reason: auth_reason_to_ffi(reason),
            last_attempt: primitive::optional_to_ffi(last_attempt, auth_attempt_to_ffi),
        }),
        ConnectionAuthState::AuthFailed { error, attempts } => {
            ffi::ConnectionAuthState::from_auth_failed(ffi::ConnectionAuthStateAuthFailed {
                error_code: error::code_to_ffi(error.code()),
                error_message: primitive::str_to_ffi(error.message().to_owned()),
                attempts,
            })
        }
        ConnectionAuthState::Anonymous => ffi::ConnectionAuthState::anonymous(),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ConnectionAuthState`].
pub unsafe fn connection_auth_state_from_ffi(
    value: ffi::ConnectionAuthState,
) -> Result<ConnectionAuthState, Error> {
    unsafe {
        let state = match value.tag {
            ffi::ConnectionAuthStateTag::Authenticated => {
                let payload = std::ptr::read(value.authenticated.as_ptr());
                std::mem::forget(value);
                let expires_at = primitive::optional_from_ffi::<i64, SystemTime, Error>(
                    payload.expires_at_unix_ms,
                    |ms| Ok(primitive::system_time_from_unix_ms(ms)),
                )?;
                ConnectionAuthState::Authenticated {
                    last_authenticated_at: primitive::system_time_from_unix_ms(
                        payload.last_authenticated_at_unix_ms,
                    ),
                    expires_at,
                }
            }
            ffi::ConnectionAuthStateTag::AwaitingAuth => {
                let payload = std::ptr::read(value.awaiting_auth.as_ptr());
                std::mem::forget(value);
                let reason = auth_reason_from_ffi(payload.reason)?;
                let last_attempt = primitive::optional_from_ffi(payload.last_attempt, |a| {
                    auth_attempt_from_ffi(a)
                })?;
                ConnectionAuthState::AwaitingAuth {
                    reason,
                    last_attempt,
                }
            }
            ffi::ConnectionAuthStateTag::AuthFailed => {
                let payload = std::ptr::read(value.auth_failed.as_ptr());
                std::mem::forget(value);
                let message = primitive::str_from_ffi(payload.error_message)?;
                ConnectionAuthState::AuthFailed {
                    error: Error::new(error::code_from_ffi(payload.error_code), message),
                    attempts: payload.attempts,
                }
            }
            ffi::ConnectionAuthStateTag::Anonymous => {
                std::mem::forget(value);
                ConnectionAuthState::Anonymous
            }
        };
        Ok(state)
    }
}

pub fn connection_to_ffi(value: Connection) -> ffi::Connection {
    ffi::Connection {
        id: connection::connection_id_to_ffi(value.id),
        backend_kind: primitive::str_to_ffi(value.backend_kind),
        display_name: primitive::str_to_ffi(value.display_name),
        source: connection::connection_source_to_ffi(value.source),
        capabilities: capabilities::capabilities_to_ffi(value.capabilities),
        current_addresses: primitive::list_to_ffi(
            value.current_addresses,
            address::object_address_to_ffi,
        ),
        auth_state: connection_auth_state_to_ffi(value.auth_state),
        last_probed_unix_ms: primitive::optional_to_ffi(
            value.last_probed,
            primitive::system_time_to_unix_ms,
        ),
        user_metadata: primitive::key_value_list_to_ffi(value.user_metadata),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::Connection`].
pub unsafe fn connection_from_ffi(value: ffi::Connection) -> Result<Connection, Error> {
    unsafe {
        let id_ffi = value.id;
        let backend_kind_ffi = value.backend_kind;
        let display_name_ffi = value.display_name;
        let source_ffi = value.source;
        let capabilities_ffi = value.capabilities;
        let current_addresses_ffi = value.current_addresses;
        let auth_state_ffi = value.auth_state;
        let last_probed_ffi = value.last_probed_unix_ms;
        let user_metadata_ffi = value.user_metadata;

        let id = connection::connection_id_from_ffi(id_ffi);
        let backend_kind = primitive::str_from_ffi(backend_kind_ffi);
        let display_name = primitive::str_from_ffi(display_name_ffi);
        let source = connection::connection_source_from_ffi(source_ffi);
        let capabilities = capabilities::capabilities_from_ffi(capabilities_ffi);
        let current_addresses = primitive::list_from_ffi(current_addresses_ffi, |a| {
            address::object_address_from_ffi(a)
        });
        let auth_state = connection_auth_state_from_ffi(auth_state_ffi);
        let last_probed =
            primitive::optional_from_ffi::<i64, SystemTime, Error>(last_probed_ffi, |ms| {
                Ok(primitive::system_time_from_unix_ms(ms))
            });
        let user_metadata = primitive::key_value_list_from_ffi(user_metadata_ffi);

        Ok(Connection {
            id: id?,
            backend_kind: backend_kind?,
            display_name: display_name?,
            source: source?,
            capabilities: capabilities?,
            current_addresses: current_addresses?,
            auth_state: auth_state?,
            last_probed: last_probed?,
            user_metadata: user_metadata?,
        })
    }
}

pub fn auth_event_to_ffi(value: AuthEvent) -> ffi::AuthEvent {
    match value {
        AuthEvent::OpenBrowser { url, expires_at } => {
            ffi::AuthEvent::from_open_browser(ffi::AuthEventOpenBrowser {
                url: primitive::str_to_ffi(url),
                expires_at_unix_ms: primitive::system_time_to_unix_ms(expires_at),
            })
        }
        AuthEvent::DeviceCode {
            user_code,
            verification_url,
            expires_at,
            interval,
        } => ffi::AuthEvent::from_device_code(ffi::AuthEventDeviceCode {
            user_code: primitive::str_to_ffi(user_code),
            verification_url: primitive::str_to_ffi(verification_url),
            expires_at_unix_ms: primitive::system_time_to_unix_ms(expires_at),
            interval_ms: clamp_duration_to_ms(interval),
        }),
        AuthEvent::Progress { message } => ffi::AuthEvent::from_progress(ffi::AuthEventProgress {
            message: primitive::str_to_ffi(message),
        }),
        AuthEvent::Succeeded {
            connection,
            credentials,
        } => ffi::AuthEvent::from_succeeded(ffi::AuthEventSucceeded {
            connection: connection_to_ffi(*connection),
            credentials: primitive::optional_to_ffi(credentials, descriptor::secret_bundle_to_ffi),
        }),
        AuthEvent::Failed { error } => ffi::AuthEvent::from_failed(ffi::AuthEventFailed {
            error_code: error::code_to_ffi(error.code()),
            error_message: primitive::str_to_ffi(error.message().to_owned()),
        }),
        AuthEvent::Cancelled => ffi::AuthEvent::cancelled(),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::AuthEvent`].
pub unsafe fn auth_event_from_ffi(value: ffi::AuthEvent) -> Result<AuthEvent, Error> {
    unsafe {
        let event = match value.tag {
            ffi::AuthEventTag::OpenBrowser => {
                let payload = std::ptr::read(value.open_browser.as_ptr());
                std::mem::forget(value);
                AuthEvent::OpenBrowser {
                    url: primitive::str_from_ffi(payload.url)?,
                    expires_at: primitive::system_time_from_unix_ms(payload.expires_at_unix_ms),
                }
            }
            ffi::AuthEventTag::DeviceCode => {
                let payload = std::ptr::read(value.device_code.as_ptr());
                std::mem::forget(value);
                let user_code = primitive::str_from_ffi(payload.user_code);
                let verification_url = primitive::str_from_ffi(payload.verification_url);
                AuthEvent::DeviceCode {
                    user_code: user_code?,
                    verification_url: verification_url?,
                    expires_at: primitive::system_time_from_unix_ms(payload.expires_at_unix_ms),
                    interval: Duration::from_millis(payload.interval_ms),
                }
            }
            ffi::AuthEventTag::Progress => {
                let payload = std::ptr::read(value.progress.as_ptr());
                std::mem::forget(value);
                AuthEvent::Progress {
                    message: primitive::str_from_ffi(payload.message)?,
                }
            }
            ffi::AuthEventTag::Succeeded => {
                let payload = std::ptr::read(value.succeeded.as_ptr());
                std::mem::forget(value);
                let connection = connection_from_ffi(payload.connection)?;
                let credentials =
                    primitive::optional_from_ffi::<ffi::SecretBundle, SecretBundle, Error>(
                        payload.credentials,
                        |b| descriptor::secret_bundle_from_ffi(b),
                    )?;
                AuthEvent::Succeeded {
                    connection: Box::new(connection),
                    credentials,
                }
            }
            ffi::AuthEventTag::Failed => {
                let payload = std::ptr::read(value.failed.as_ptr());
                std::mem::forget(value);
                let message = primitive::str_from_ffi(payload.error_message)?;
                AuthEvent::Failed {
                    error: Error::new(error::code_from_ffi(payload.error_code), message),
                }
            }
            ffi::AuthEventTag::Cancelled => {
                std::mem::forget(value);
                AuthEvent::Cancelled
            }
        };
        Ok(event)
    }
}

fn clamp_duration_to_ms(duration: Duration) -> u64 {
    let ms = duration.as_millis();
    if ms > u64::MAX as u128 {
        u64::MAX
    } else {
        ms as u64
    }
}

/// Host-side adapter that turns a plugin-emitted
/// [`ffi::AuthEventStream`] into a Rust iterator over
/// `Result<crate::AuthEvent>`.
///
/// Holds the FFI stream by value; on drop, the FFI stream's
/// `drop_fn` runs (via `ffi::AuthEventStream: Drop`), so plugin
/// state is released even if the host stops mid-iteration.
/// Once `next` has yielded `Ended` or `Failed`, subsequent calls
/// return `None`.
pub struct AuthEventStream {
    inner: ffi::AuthEventStream,
    finished: bool,
}

impl AuthEventStream {
    /// Wrap an `ffi::AuthEventStream` exported by a plugin.
    ///
    /// # Safety
    ///
    /// `inner` must satisfy the `ffi::AuthEventStream` contract:
    /// `state` valid for the lifetime of `next_fn` / `drop_fn`,
    /// `next_fn` populates `out_item` exactly when it returns
    /// `Yielded` and `out_error` exactly when it returns
    /// `Failed`.
    pub unsafe fn from_ffi(inner: ffi::AuthEventStream) -> Self {
        Self {
            inner,
            finished: false,
        }
    }
}

impl Iterator for AuthEventStream {
    type Item = Result<AuthEvent, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let mut item = std::mem::MaybeUninit::<ffi::AuthEvent>::uninit();
        let mut error = std::mem::MaybeUninit::<ffi::Error>::uninit();
        // SAFETY: caller of `from_ffi` asserted the stream
        // contract; calling `next_fn` with valid out-pointers
        // is part of that contract.
        let step = unsafe {
            (self.inner.next_fn)(self.inner.state, item.as_mut_ptr(), error.as_mut_ptr())
        };
        match step {
            ffi::StreamStep::Yielded => {
                // SAFETY: `Yielded` means `out_item` was written.
                let item = unsafe { item.assume_init() };
                Some(unsafe { auth_event_from_ffi(item) })
            }
            ffi::StreamStep::Ended => {
                self.finished = true;
                None
            }
            ffi::StreamStep::Failed => {
                self.finished = true;
                // SAFETY: `Failed` means `out_error` was written.
                let error = unsafe { error.assume_init() };
                Some(Err(unsafe { error::from_ffi(error) }))
            }
        }
    }
}

/// Map `InteractiveAuthCapability` to its closed-discriminant FFI
/// shadow. Discriminants are pinned (`None=0, Headless=1, Browser=2`)
/// and form the wire ABI for the capability parameter on
/// `Factory::authenticate`.
pub fn interactive_auth_capability_to_ffi(
    value: crate::InteractiveAuthCapability,
) -> ffi::InteractiveAuthCapabilityV1 {
    match value {
        crate::InteractiveAuthCapability::None => ffi::InteractiveAuthCapabilityV1::None,
        crate::InteractiveAuthCapability::Headless => ffi::InteractiveAuthCapabilityV1::Headless,
        crate::InteractiveAuthCapability::Browser => ffi::InteractiveAuthCapabilityV1::Browser,
    }
}

/// Inverse of [`interactive_auth_capability_to_ffi`]. Closed
/// discriminants make this infallible.
pub fn interactive_auth_capability_from_ffi(
    value: ffi::InteractiveAuthCapabilityV1,
) -> crate::InteractiveAuthCapability {
    match value {
        ffi::InteractiveAuthCapabilityV1::None => crate::InteractiveAuthCapability::None,
        ffi::InteractiveAuthCapabilityV1::Headless => crate::InteractiveAuthCapability::Headless,
        ffi::InteractiveAuthCapabilityV1::Browser => crate::InteractiveAuthCapability::Browser,
    }
}
