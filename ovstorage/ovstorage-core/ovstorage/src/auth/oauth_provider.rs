// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OAuth-driving `CredentialProvider` for per-user upstream OAuth.
//!
//! Two paths:
//!
//! - **Warm continuation** (`resolve()`): hydrate a persisted
//!   `secret_tokens` row + keyring blob; refresh-token-grant if expired.
//! - **Cold start**: NOT driven from `resolve()` — `AuthEvent::Succeeded`
//!   carries no token bytes. The host SDK runs [`OAuthFlow::pkce`] /
//!   [`OAuthFlow::device`] and lands tokens via
//!   [`OAuthCredentialProvider::accept_credential`].
//!
//! Cache key: `(BackendId, PrincipalView)`. This provider adds no retry
//! loop of its own: a wire-level failure of the token endpoint surfaces
//! as `CredentialError::Backend` carrying `ErrorCode::Transient` for the
//! caller to deal with. Resolution through this provider is host-driven
//! rather than dispatch-driven, so handling that error is the host's
//! business. The plugin-side refresh under `ConnectionSet::recover` is
//! the other shape: it runs during dispatch, where a retry Layer can
//! enclose it.
//! Nothing invalidates the `CredentialCache` in response to an error;
//! that recovery belongs to the connection owner,
//! `ConnectionSet::recover` in `ovstorage-plugin`, per RFC-0066
//! § "Data-path recovery for hosts without a UI".

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ovstorage_plugin::{
    BackendId, Error, ErrorCode, InteractiveAuthCapability, SecretBundle, SecretBytes, SecretValue,
};
use serde::Deserialize;

use super::flow::{OAuthEndpoints, OAuthFlow, read_oauth_response_body};
use super::provider::{CredentialError, CredentialProvider, PrincipalView, ResolvedCredential};
use super::{AuthRefreshLock, PersistedSecretToken, SecretStore};

/// Cold-start strategy when no persisted refresh token is usable.
#[derive(Clone, Debug)]
pub enum OAuthStrategy {
    /// PKCE auth-code with a loopback redirect listener at
    /// `redirect_base` (typically `http://127.0.0.1`).
    Pkce { redirect_base: url::Url },
    /// RFC 8628 device-authorisation.
    Device,
}

pub struct OAuthCredentialProvider {
    name: String,
    endpoints: OAuthEndpoints,
    http: Arc<reqwest::Client>,
    secret_store: Arc<dyn SecretStore>,
    refresh_lock: Arc<AuthRefreshLock>,
    backend_kind: String,
    strategy: OAuthStrategy,
    interactive_disabled: bool,
    #[cfg(test)]
    persistence_order_hook: std::sync::Mutex<Option<std::sync::mpsc::Sender<PersistenceTestEvent>>>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistenceTestEvent {
    UpdateLockAttempt,
    PersistLocked,
}

/// Opaque reference to one committed OAuth access-token generation.
///
/// Credential consumers may use the non-secret keyring handle for one
/// request and return the lease when that request rejects the token. The
/// provider keeps the durable generation private so its persistence scheme
/// can change without exposing version bookkeeping to callers.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedOAuthCredentialLease {
    keyring_handle: String,
    cred_epoch: u64,
}

impl ResolvedOAuthCredentialLease {
    /// Non-secret keyring handle for the committed access token.
    pub fn keyring_handle(&self) -> &str {
        &self.keyring_handle
    }
}

impl std::fmt::Debug for ResolvedOAuthCredentialLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedOAuthCredentialLease")
            .field("keyring_handle", &self.keyring_handle)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OAuthCredentialProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthCredentialProvider")
            .field("name", &self.name)
            .field("backend_kind", &self.backend_kind)
            .field("interactive_disabled", &self.interactive_disabled)
            .finish_non_exhaustive()
    }
}

impl OAuthCredentialProvider {
    fn lease_from_persisted(persisted: PersistedSecretToken) -> ResolvedOAuthCredentialLease {
        ResolvedOAuthCredentialLease {
            keyring_handle: persisted.secret_handle,
            cred_epoch: persisted.cred_epoch,
        }
    }

    /// `name` is the trace identity (`ResolvedCredential::source_name`)
    /// — must NOT contain token bytes. `backend_kind` is matched
    /// against `BackendId.0`.
    pub fn new(
        name: impl Into<String>,
        backend_kind: impl Into<String>,
        endpoints: OAuthEndpoints,
        secret_store: Arc<dyn SecretStore>,
        refresh_lock: Arc<AuthRefreshLock>,
        strategy: OAuthStrategy,
    ) -> Self {
        Self {
            name: name.into(),
            endpoints,
            // OAuth POST bodies carry authorization codes, PKCE verifiers,
            // device codes, and refresh tokens. Never let an IdP redirect
            // those bodies to another origin or downgrade them to plaintext.
            http: Arc::new(
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .no_proxy()
                    .connect_timeout(Duration::from_secs(10))
                    .timeout(Duration::from_secs(30))
                    .build()
                    .expect("the default OAuth HTTP client must build"),
            ),
            secret_store,
            refresh_lock,
            backend_kind: backend_kind.into(),
            strategy,
            interactive_disabled: false,
            #[cfg(test)]
            persistence_order_hook: std::sync::Mutex::new(None),
        }
    }

    /// Override the OAuth HTTP client. Callers are responsible for retaining a
    /// no-redirect, no-proxy, and bounded-time policy so credential-bearing
    /// POST bodies cannot be replayed to a redirect target or cleartext local
    /// proxy and cannot park a broker request indefinitely.
    pub fn with_http_client(mut self, http: Arc<reqwest::Client>) -> Self {
        self.http = http;
        self
    }

    /// No-op retained for broker call-site compatibility; the provider
    /// always surfaces `Unavailable` on cold-start cache miss.
    pub fn with_interactive_disabled(mut self, disabled: bool) -> Self {
        self.interactive_disabled = disabled;
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn backend_kind(&self) -> &str {
        &self.backend_kind
    }

    /// Keyring field containing this provider's persisted access token. The
    /// broker passes this non-secret handle to credential-aware backends so
    /// they can load the authenticated principal's token through host
    /// callbacks without placing bearer bytes in request extensions.
    pub fn access_keyring_handle(&self) -> String {
        format!("oauth/{}", self.name)
    }

    /// Return the access-token handle recorded in durable state, refreshing an
    /// expired credential first when possible.
    ///
    /// Hosts pass this non-secret reference to a trusted credential consumer.
    /// Reading the committed handle, rather than recomputing it, keeps a
    /// durable row whose handle differs from the current host namespace usable
    /// until the next successful refresh or explicit replacement migrates it.
    /// The keyring entry is checked before this method returns. This prevents
    /// fresh durable metadata with missing access material from bypassing a
    /// retained refresh token; the owning backend performs the request's
    /// subsequent keyring read to consume the bearer.
    ///
    /// # Errors
    ///
    /// Returns durable-state, keyring, refresh-grant, and unavailable
    /// credential errors from resolving the committed reference.
    pub async fn resolve_access_keyring_handle(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<String, CredentialError> {
        self.resolve_access_keyring_handle_lease(backend, principal)
            .await
            .map(|lease| lease.keyring_handle)
    }

    /// Resolve an opaque lease for the committed access token.
    ///
    /// The lease lets an owning backend conditionally invalidate a rejected
    /// token without exposing the durable epoch or deleting a newer credential
    /// registered concurrently.
    ///
    /// # Errors
    ///
    /// Returns the same durable-state, keyring, refresh-grant, and unavailable
    /// credential errors as [`Self::resolve_access_keyring_handle`].
    pub async fn resolve_access_keyring_handle_lease(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<ResolvedOAuthCredentialLease, CredentialError> {
        let persisted = self.load_persisted_token(backend, principal)?;
        let access = self
            .secret_store
            .get(&backend.0, &principal.id, &persisted.secret_handle)
            .map_err(CredentialError::Backend)?;
        if access.is_some() && self.persisted_access_is_usable(&persisted)? {
            return Ok(Self::lease_from_persisted(persisted));
        }
        match self.refresh_warm_continuation(backend, principal).await {
            Ok(Some(_)) => {
                let committed = self.load_persisted_token(backend, principal)?;
                return Ok(Self::lease_from_persisted(committed));
            }
            Ok(None) => {}
            Err(CredentialError::Backend(error))
                if matches!(
                    error.code(),
                    ErrorCode::AuthExpired | ErrorCode::AuthRequired
                ) => {}
            Err(error) => return Err(error),
        }
        Err(CredentialError::Unavailable {
            details: format!(
                "OAuthCredentialProvider({}): no warm token; cold-start must be driven via accept_credential",
                self.name
            ),
        })
    }

    /// Invalidate the committed access token after the owning backend rejects
    /// it, marking the retained durable row stale while preserving any refresh
    /// token so the next [`Self::resolve`] can drive a refresh grant.
    ///
    /// The durable update and delete share the same cross-process
    /// per-principal guard as credential persistence. An invalidation
    /// therefore cannot delete access material committed concurrently by
    /// registration or refresh.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::Unavailable`] when no credential for this
    /// provider is committed, or a backend error when durable state or the OS
    /// keyring cannot be read or updated.
    pub async fn invalidate_access_token(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<(), CredentialError> {
        let lease = Self::lease_from_persisted(self.load_persisted_token(backend, principal)?);
        let _ = self
            .invalidate_access_token_if_lease(backend, principal, &lease)
            .await?;
        Ok(())
    }

    /// Invalidate a rejected access token only while `lease` still identifies
    /// the committed credential version.
    ///
    /// Returns `Ok(false)` when the credential disappeared, belongs to another
    /// provider, or another registration or refresh has already committed a
    /// newer version. In those cases no keyring or durable state is changed.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::Unavailable`] when the backend does not
    /// match, or a backend error when durable state or the OS keyring cannot be
    /// read, updated, or rolled back.
    pub async fn invalidate_access_token_if_lease(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
        lease: &ResolvedOAuthCredentialLease,
    ) -> Result<bool, CredentialError> {
        if backend.0 != self.backend_kind {
            return Err(CredentialError::Unavailable {
                details: format!(
                    "OAuthCredentialProvider({}): not configured for backend {:?}",
                    self.name, backend
                ),
            });
        }
        let _update_guard = self
            .refresh_lock
            .lock_for_async(&backend.0, &principal.id)
            .await
            .map_err(CredentialError::Backend)?;
        let Some(persisted) = self
            .refresh_lock
            .load_secret_token(&backend.0, &principal.id)
            .map_err(CredentialError::Backend)?
        else {
            return Ok(false);
        };
        if persisted.source_name != self.name
            || persisted.cred_epoch != lease.cred_epoch
            || persisted.secret_handle != lease.keyring_handle
        {
            return Ok(false);
        }
        let mut invalidated = persisted.clone();
        invalidated.cred_epoch = self
            .refresh_lock
            .max_secret_cred_epoch()
            .map_err(CredentialError::Backend)?
            .saturating_add(1);
        invalidated.expires_at_unix_ms = Some(0);
        // Make the durable row stale before removing access bytes. Handle
        // resolution can then never treat a missing secret as a usable
        // credential, and the retained refresh token drives the next
        // resolution. A failure between the two writes is fail-safe: the row
        // is already stale, so the leftover access bytes are never served.
        self.refresh_lock
            .store_secret_token(&backend.0, &principal.id, &invalidated)
            .map_err(CredentialError::Backend)?;
        self.secret_store
            .delete(&backend.0, &principal.id, &persisted.secret_handle)
            .map_err(CredentialError::Backend)?;
        Ok(true)
    }

    /// Whether this provider is configured with a device-authorization
    /// endpoint and can serve a browser-capable remote caller without a
    /// daemon-local PKCE redirect listener.
    pub fn supports_device_flow(&self) -> bool {
        matches!(&self.strategy, OAuthStrategy::Device)
    }

    pub fn endpoints(&self) -> &OAuthEndpoints {
        &self.endpoints
    }

    /// Build the flow matching the host's `capability`:
    /// `None` → `Err(AuthRequired)`; `Headless` → device flow only for a
    /// device-configured provider; `Browser` → honors `self.strategy`.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::AuthRequired`] — `capability` is
    ///   [`InteractiveAuthCapability::None`]; the host cannot drive a
    ///   PKCE or device flow.
    /// - [`ErrorCode::Unsupported`] — a headless host requests a PKCE-only
    ///   provider. Its authorization endpoint is not a device endpoint; the
    ///   host must run PKCE elsewhere and register the resulting credential.
    pub fn build_flow(
        &self,
        backend: BackendId,
        capability: InteractiveAuthCapability,
    ) -> Result<OAuthFlow, Error> {
        match capability {
            InteractiveAuthCapability::None => Err(Error::new(
                ErrorCode::AuthRequired,
                format!(
                    "OAuthCredentialProvider({}): host declared no interactive auth \
                     capability; cannot drive PKCE or device flow",
                    self.name
                ),
            )),
            InteractiveAuthCapability::Headless
                if matches!(&self.strategy, OAuthStrategy::Device) =>
            {
                let flow = OAuthFlow::device(backend);
                Ok(flow
                    .with_endpoints(self.endpoints.clone())
                    .with_http_client((*self.http).clone()))
            }
            InteractiveAuthCapability::Headless => Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "OAuthCredentialProvider({}): PKCE-only provider cannot run headless; run \
                     PKCE on a browser-capable client and register the credential",
                    self.name
                ),
            )),
            InteractiveAuthCapability::Browser => {
                let flow = match &self.strategy {
                    OAuthStrategy::Pkce { redirect_base } => {
                        OAuthFlow::pkce(backend, redirect_base.clone())
                    }
                    OAuthStrategy::Device => OAuthFlow::device(backend),
                };
                Ok(flow
                    .with_endpoints(self.endpoints.clone())
                    .with_http_client((*self.http).clone()))
            }
        }
    }

    /// Persist a credential resolved out-of-band by the host SDK.
    /// The next [`Self::resolve`] for `(backend, principal)` reads it
    /// from the warm path. This replaces the registered credential: when
    /// `refresh_token` is absent, any refresh token from an earlier
    /// registration is deleted. Refresh-grant responses use a separate merge
    /// path because providers commonly omit an unchanged refresh token. An
    /// absent `expires_at` denotes an opaque token with no recorded expiry; it
    /// remains usable until the owning backend invalidates the credential.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — `access_token` or
    ///   `refresh_token` is not UTF-8.
    /// - [`ErrorCode::CredentialUnavailable`] — the secret store rejects
    ///   a token write.
    /// - [`ErrorCode::StateRootUnavailable`] / [`ErrorCode::Transient`]
    ///   — the `secret_tokens` row commit in `auth.sqlite` fails.
    pub async fn accept_credential(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
        access_token: Vec<u8>,
        refresh_token: Option<Vec<u8>>,
        expires_at: Option<SystemTime>,
    ) -> Result<(), Error> {
        if access_token.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "OAuthCredentialProvider({}): access_token must not be empty",
                    self.name
                ),
            ));
        }
        let access_token_str = String::from_utf8(access_token).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "OAuthCredentialProvider({}): access_token must be UTF-8",
                    self.name
                ),
            )
        })?;
        let refresh_token_str = match refresh_token {
            Some(bytes) => Some(String::from_utf8(bytes).map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "OAuthCredentialProvider({}): refresh_token must be UTF-8",
                        self.name
                    ),
                )
            })?),
            None => None,
        };
        let token = MintedToken {
            access_token: access_token_str,
            refresh_token: refresh_token_str,
            expires_at,
        };
        self.persist_replacement_token(&token, backend, principal)
            .await
            .map_err(|err| match err {
                CredentialError::Backend(error) => error,
                other => Error::new(ErrorCode::Internal, format!("{other:?}")),
            })
    }
}

#[async_trait]
impl CredentialProvider for OAuthCredentialProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn resolve(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<ResolvedCredential, CredentialError> {
        let persisted = self.load_persisted_token(backend, principal)?;
        match self
            .try_warm_continuation(&persisted, backend, principal)
            .await
        {
            Ok(Some((resolved, _))) => return Ok(resolved),
            Ok(None) => { /* expired + no refresh -> cold start */ }
            Err(CredentialError::Backend(err))
                if matches!(err.code(), ErrorCode::AuthExpired | ErrorCode::AuthRequired) =>
            {
                // Refresh-token grant rejected; fall through to cold start.
            }
            Err(other) => return Err(other),
        }
        Err(CredentialError::Unavailable {
            details: format!(
                "OAuthCredentialProvider({}): no warm token; cold-start must be driven via accept_credential",
                self.name
            ),
        })
    }
}

impl OAuthCredentialProvider {
    fn load_persisted_token(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<PersistedSecretToken, CredentialError> {
        if backend.0 != self.backend_kind {
            return Err(CredentialError::Unavailable {
                details: format!(
                    "OAuthCredentialProvider({}): not configured for backend {:?}",
                    self.name, backend
                ),
            });
        }
        let persisted = self
            .refresh_lock
            .load_secret_token(&backend.0, &principal.id)
            .map_err(CredentialError::Backend)?
            .ok_or_else(|| CredentialError::Unavailable {
                details: format!(
                    "OAuthCredentialProvider({}): no warm token; cold-start must be driven via accept_credential",
                    self.name
                ),
            })?;
        if persisted.source_name != self.name {
            return Err(CredentialError::Unavailable {
                details: format!(
                    "OAuthCredentialProvider({}): durable token belongs to provider {}; re-authentication is required",
                    self.name, persisted.source_name,
                ),
            });
        }
        Ok(persisted)
    }

    fn persisted_expires_at(
        &self,
        persisted: &PersistedSecretToken,
    ) -> Result<Option<SystemTime>, CredentialError> {
        persisted
            .expires_at_unix_ms
            .map(|ms| {
                u64::try_from(ms)
                    .ok()
                    .and_then(|ms| UNIX_EPOCH.checked_add(Duration::from_millis(ms)))
                    .ok_or_else(|| {
                        CredentialError::Backend(Error::new(
                            ErrorCode::Internal,
                            format!(
                                "OAuthCredentialProvider({}): persisted token expiry is out of range",
                                self.name
                            ),
                        ))
                    })
            })
            .transpose()
    }

    fn persisted_access_is_usable(
        &self,
        persisted: &PersistedSecretToken,
    ) -> Result<bool, CredentialError> {
        Ok(self
            .persisted_expires_at(persisted)?
            .is_none_or(|at| at > SystemTime::now() + Duration::from_secs(60)))
    }

    async fn try_warm_continuation(
        &self,
        persisted: &PersistedSecretToken,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<Option<(ResolvedCredential, String)>, CredentialError> {
        let access_now = self
            .secret_store
            .get(&backend.0, &principal.id, &persisted.secret_handle)
            .map_err(CredentialError::Backend)?;
        let expires_at = self.persisted_expires_at(persisted)?;
        let access_is_usable =
            expires_at.is_none_or(|at| at > SystemTime::now() + Duration::from_secs(60));
        if let Some(access) = &access_now
            && access_is_usable
        {
            let refresh_now = self
                .secret_store
                .get(
                    &backend.0,
                    &principal.id,
                    &format!("{}/refresh", persisted.secret_handle),
                )
                .map_err(CredentialError::Backend)?;
            return Ok(Some((
                ResolvedCredential {
                    bytes: bundle_with_access_refresh(access.clone(), refresh_now, expires_at),
                    expires_at,
                    source_name: self.name.clone(),
                },
                persisted.secret_handle.clone(),
            )));
        }
        self.refresh_warm_continuation(backend, principal).await
    }

    /// Refresh a stale or incomplete credential while holding the same
    /// cross-process slot guard used by registration. Waiters re-read the
    /// committed row after acquiring the guard, so rotating refresh tokens
    /// are redeemed only once and every waiter observes that result.
    async fn refresh_warm_continuation(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<Option<(ResolvedCredential, String)>, CredentialError> {
        let _update_guard = self
            .refresh_lock
            .lock_for_async(&backend.0, &principal.id)
            .await
            .map_err(CredentialError::Backend)?;
        let persisted = self.load_persisted_token(backend, principal)?;
        let access_now = self
            .secret_store
            .get(&backend.0, &principal.id, &persisted.secret_handle)
            .map_err(CredentialError::Backend)?;
        let refresh_now = self
            .secret_store
            .get(
                &backend.0,
                &principal.id,
                &format!("{}/refresh", persisted.secret_handle),
            )
            .map_err(CredentialError::Backend)?;
        let expires_at = self.persisted_expires_at(&persisted)?;
        let access_is_usable =
            expires_at.is_none_or(|at| at > SystemTime::now() + Duration::from_secs(60));
        if let Some(access) = &access_now
            && access_is_usable
        {
            return Ok(Some((
                ResolvedCredential {
                    bytes: bundle_with_access_refresh(
                        access.clone(),
                        refresh_now.clone(),
                        expires_at,
                    ),
                    expires_at,
                    source_name: self.name.clone(),
                },
                persisted.secret_handle.clone(),
            )));
        }
        let Some(refresh) = refresh_now else {
            return Ok(None);
        };
        let refresh_str = std::str::from_utf8(&refresh.0).map_err(|_| {
            CredentialError::Backend(Error::new(
                ErrorCode::Internal,
                format!(
                    "OAuthCredentialProvider({}): persisted refresh token is not UTF-8",
                    self.name
                ),
            ))
        })?;
        let mut token = self.refresh_token_grant(refresh_str).await?;
        if token.refresh_token.is_none() && persisted.secret_handle != self.access_keyring_handle()
        {
            // A durable row may reference another valid namespace, such as
            // after a state-root relocation. Preserve its refresh token while
            // the access token and row move to the current scoped handles.
            token.refresh_token = Some(refresh_str.to_string());
        }
        self.persist_token_locked(
            &token,
            backend,
            principal,
            MissingRefreshToken::PreserveExisting,
        )?;
        let resolved_refresh = token
            .refresh_token
            .as_ref()
            .map(|value| SecretBytes(value.clone().into_bytes()))
            .or(Some(refresh));
        let bundle = bundle_with_access_refresh(
            SecretBytes(token.access_token.clone().into_bytes()),
            resolved_refresh,
            token.expires_at,
        );
        Ok(Some((
            ResolvedCredential {
                bytes: bundle,
                expires_at: token.expires_at,
                source_name: self.name.clone(),
            },
            self.access_keyring_handle(),
        )))
    }

    async fn refresh_token_grant(
        &self,
        refresh_token: &str,
    ) -> Result<MintedToken, CredentialError> {
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", self.endpoints.client_id.as_str()),
        ];
        let response = self
            .http
            .post(self.endpoints.token_endpoint.as_str())
            .form(&form)
            .send()
            .await
            .map_err(|err| {
                CredentialError::Backend(Error::new(
                    ErrorCode::Transient,
                    format!(
                        "OAuthCredentialProvider({}): refresh-token POST failed: {err}",
                        self.name
                    ),
                ))
            })?;
        let status = response.status();
        let operation = format!("OAuthCredentialProvider({}): refresh-token", self.name);
        let body = read_oauth_response_body(response, &operation)
            .await
            .map_err(CredentialError::Backend)?;
        if !status.is_success() {
            let oauth_error = serde_json::from_slice::<OAuthErrorResponse>(&body).ok();
            let code = if status.as_u16() == 401
                || (status.as_u16() == 400
                    && oauth_error
                        .as_ref()
                        .is_some_and(|response| response.error == "invalid_grant"))
            {
                ErrorCode::AuthExpired
            } else {
                ErrorCode::Transient
            };
            return Err(CredentialError::Backend(Error::new(
                code,
                format!(
                    "OAuthCredentialProvider({}): refresh-token grant returned HTTP {}: {}",
                    self.name,
                    status.as_u16(),
                    ovstorage_plugin::provider_error::oauth_error_detail(&body)
                ),
            )));
        }
        let parsed: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
            CredentialError::Backend(Error::new(
                ErrorCode::Internal,
                format!(
                    "OAuthCredentialProvider({}): refresh-token JSON parse failed: {err}",
                    self.name
                ),
            ))
        })?;
        MintedToken::from_response(parsed)
    }

    async fn persist_replacement_token(
        &self,
        token: &MintedToken,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<(), CredentialError> {
        self.persist_token(
            token,
            backend,
            principal,
            MissingRefreshToken::DeleteExisting,
        )
        .await
    }

    async fn persist_token(
        &self,
        token: &MintedToken,
        backend: &BackendId,
        principal: &PrincipalView,
        missing_refresh: MissingRefreshToken,
    ) -> Result<(), CredentialError> {
        // Serialize the complete keyring/sqlite replacement, including its
        // snapshots and rollback, across every process sharing this state
        // root. Without this guard, a failed writer could restore a stale
        // snapshot over a credential committed by a concurrent writer.
        #[cfg(test)]
        Self::signal_test_hook(
            &self.persistence_order_hook,
            PersistenceTestEvent::UpdateLockAttempt,
        );
        let _update_guard = self
            .refresh_lock
            .lock_for_async(&backend.0, &principal.id)
            .await
            .map_err(CredentialError::Backend)?;
        self.persist_token_locked(token, backend, principal, missing_refresh)
    }

    fn persist_token_locked(
        &self,
        token: &MintedToken,
        backend: &BackendId,
        principal: &PrincipalView,
        missing_refresh: MissingRefreshToken,
    ) -> Result<(), CredentialError> {
        #[cfg(test)]
        Self::signal_test_hook(
            &self.persistence_order_hook,
            PersistenceTestEvent::PersistLocked,
        );
        if token.access_token.is_empty() {
            return Err(CredentialError::Backend(Error::new(
                ErrorCode::CredentialUnavailable,
                format!(
                    "OAuthCredentialProvider({}): token response contained an empty access_token",
                    self.name
                ),
            )));
        }
        let secret_handle = format!("oauth/{}", self.name);
        // The access token and the refresh token beside it are one generation.
        // Written separately, a failure or a crash between them leaves a
        // reader holding a pair that never existed — a rotated refresh token
        // against the previous access token, or the reverse. One call so the
        // store commits them together or not at all.
        let refresh_field = format!("{secret_handle}/refresh");
        let access = SecretBytes(token.access_token.clone().into_bytes());
        let mut fields: Vec<(&str, &SecretBytes)> = vec![(secret_handle.as_str(), &access)];
        let refresh = token
            .refresh_token
            .as_ref()
            .map(|value| SecretBytes(value.clone().into_bytes()));
        if let Some(refresh) = &refresh {
            fields.push((refresh_field.as_str(), refresh));
        }
        self.secret_store
            .put_many(&backend.0, &principal.id, &fields)
            .map_err(CredentialError::Backend)?;
        // A registration that replaces a credential without supplying a
        // refresh token must not leave the previous refresh token installed
        // beside the new access token. Writers are serialized by the caller's
        // update guard, so this cannot race a concurrent registration.
        if refresh.is_none() && matches!(missing_refresh, MissingRefreshToken::DeleteExisting) {
            self.secret_store
                .delete(&backend.0, &principal.id, &refresh_field)
                .map_err(CredentialError::Backend)?;
        }
        let next_epoch = self
            .refresh_lock
            .max_secret_cred_epoch()
            .map_err(CredentialError::Backend)?
            .saturating_add(1);
        let inserted_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
            .unwrap_or_default();
        let expires_at_unix_millis = token.expires_at.map(|t| {
            t.duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
                .unwrap_or_default()
        });
        let row = PersistedSecretToken {
            cred_epoch: next_epoch,
            inserted_unix_ms,
            expires_at_unix_ms: expires_at_unix_millis,
            secret_handle,
            source_name: self.name.clone(),
        };
        self.refresh_lock
            .store_secret_token(&backend.0, &principal.id, &row)
            .map_err(CredentialError::Backend)?;
        Ok(())
    }

    #[cfg(test)]
    fn signal_test_hook(
        hook: &std::sync::Mutex<Option<std::sync::mpsc::Sender<PersistenceTestEvent>>>,
        event: PersistenceTestEvent,
    ) {
        if let Some(sender) = hook
            .lock()
            .expect("OAuth persistence test-hook lock poisoned")
            .as_ref()
        {
            let _ = sender.send(event);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MissingRefreshToken {
    /// A cold-start or explicitly registered credential replaces the prior
    /// identity, including removal of an omitted refresh token.
    DeleteExisting,
    /// OAuth refresh responses may omit an unchanged refresh token.
    PreserveExisting,
}

struct MintedToken {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<SystemTime>,
}

impl MintedToken {
    fn from_response(resp: TokenResponse) -> Result<Self, CredentialError> {
        let expires_at = resp
            .expires_in
            .map(|seconds| {
                SystemTime::now()
                    .checked_add(Duration::from_secs(seconds))
                    .ok_or_else(|| {
                        CredentialError::Backend(Error::new(
                            ErrorCode::CredentialUnavailable,
                            "OAuth refresh response expires_in is out of range",
                        ))
                    })
            })
            .transpose()?;
        Ok(Self {
            access_token: resp.access_token,
            refresh_token: resp.refresh_token,
            expires_at,
        })
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OAuthErrorResponse {
    error: String,
}

fn bundle_with_access_refresh(
    access: SecretBytes,
    refresh: Option<SecretBytes>,
    expires_at: Option<SystemTime>,
) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "oauth".into(),
        SecretValue::OAuthToken {
            token: access,
            refresh,
            expires_at,
        },
    );
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SqliteSecretStore;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    fn temp_root() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn sqlite_store(temp: &TempDir) -> Arc<dyn SecretStore> {
        Arc::new(crate::auth::SqliteSecretStore::open(temp.path()).expect("open sqlite store"))
    }

    #[test]
    fn refresh_response_rejects_unrepresentable_expiry() {
        let error = match MintedToken::from_response(TokenResponse {
            access_token: "access".into(),
            refresh_token: None,
            expires_in: Some(u64::MAX),
        }) {
            Ok(_) => panic!("an unrepresentable expiry must be rejected"),
            Err(error) => error,
        };
        match error {
            CredentialError::Backend(error) => {
                assert_eq!(error.code(), ErrorCode::CredentialUnavailable)
            }
            other => panic!("unexpected credential error: {other:?}"),
        }
    }

    fn endpoints() -> OAuthEndpoints {
        OAuthEndpoints {
            authorization_endpoint: url::Url::parse("https://idp.example/authorize").unwrap(),
            token_endpoint: url::Url::parse("https://idp.example/token").unwrap(),
            client_id: "test-client".into(),
            scope: Some("openid".into()),
        }
    }

    async fn one_shot_token_endpoint(
        status: u16,
        extra_headers: Vec<(String, String)>,
        body: String,
    ) -> (url::Url, oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint =
            url::Url::parse(&format!("http://{}/token", listener.local_addr().unwrap())).unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut content_length = None;
            loop {
                let mut chunk = [0u8; 1024];
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if content_length.is_none()
                    && let Some(header_end) =
                        request.windows(4).position(|part| part == b"\r\n\r\n")
                {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    content_length = headers.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    });
                }
                if let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                    && request.len() >= header_end + 4 + content_length.unwrap_or_default()
                {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request).into_owned();
            let _ = request_tx.send(request);
            let reason = if status == 200 {
                "OK"
            } else {
                "Temporary Redirect"
            };
            let mut response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (name, value) in extra_headers {
                response.push_str(&format!("{name}: {value}\r\n"));
            }
            response.push_str("\r\n");
            response.push_str(&body);
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        (endpoint, request_rx)
    }

    async fn single_use_token_endpoint() -> (url::Url, oneshot::Receiver<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint =
            url::Url::parse(&format!("http://{}/token", listener.local_addr().unwrap())).unwrap();
        let (count_tx, count_rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut count = 0;
            while let Ok(Ok((mut socket, _))) =
                tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
            {
                count += 1;
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0u8; 1024];
                    let read = socket.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or_default();
                    if request.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                let (status, body) = if count == 1 {
                    (
                        "200 OK",
                        serde_json::json!({
                            "access_token": "single-flight-access",
                            "expires_in": 3600
                        })
                        .to_string(),
                    )
                } else {
                    (
                        "400 Bad Request",
                        serde_json::json!({ "error": "invalid_grant" }).to_string(),
                    )
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
            }
            let _ = count_tx.send(count);
        });
        (endpoint, count_rx)
    }

    #[tokio::test]
    async fn provider_falls_through_for_unmatched_backend() {
        let temp = temp_root();
        let secret_store: Arc<dyn SecretStore> =
            Arc::new(SqliteSecretStore::open(temp.path()).unwrap());
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            endpoints(),
            secret_store,
            refresh_lock,
            OAuthStrategy::Device,
        );
        let err = provider
            .resolve(&BackendId("s3".into()), &PrincipalView::new("u-1"))
            .await
            .unwrap_err();
        match err {
            CredentialError::Unavailable { .. } => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn build_flow_none_capability_errors_fast() {
        let temp = temp_root();
        let secret_store: Arc<dyn SecretStore> =
            Arc::new(SqliteSecretStore::open(temp.path()).unwrap());
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            endpoints(),
            secret_store,
            refresh_lock,
            OAuthStrategy::Device,
        );
        let result =
            provider.build_flow(BackendId("nucleus".into()), InteractiveAuthCapability::None);
        let err = match result {
            Ok(_) => panic!("None capability must error fast"),
            Err(e) => e,
        };
        assert_eq!(err.code(), ErrorCode::AuthRequired);
    }

    #[tokio::test]
    async fn build_flow_headless_rejects_pkce_only_strategy() {
        let temp = temp_root();
        let secret_store: Arc<dyn SecretStore> =
            Arc::new(SqliteSecretStore::open(temp.path()).unwrap());
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            endpoints(),
            secret_store,
            refresh_lock,
            OAuthStrategy::Pkce {
                redirect_base: url::Url::parse("http://127.0.0.1").unwrap(),
            },
        );
        let error = match provider.build_flow(
            BackendId("nucleus".into()),
            InteractiveAuthCapability::Headless,
        ) {
            Ok(_) => panic!("a PKCE authorization endpoint is not a device endpoint"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert!(error.message().contains("PKCE-only"));
    }

    #[tokio::test]
    async fn build_flow_headless_uses_a_device_configured_provider() {
        let temp = temp_root();
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            endpoints(),
            sqlite_store(&temp),
            Arc::new(AuthRefreshLock::open(temp.path()).unwrap()),
            OAuthStrategy::Device,
        );

        let flow = provider
            .build_flow(
                BackendId("nucleus".into()),
                InteractiveAuthCapability::Headless,
            )
            .expect("a device-configured provider supports a headless host");

        assert!(flow.is_device());
        assert!(!flow.is_pkce());
    }

    #[tokio::test]
    async fn build_flow_browser_uses_pkce_when_strategy_pkce() {
        let temp = temp_root();
        let secret_store: Arc<dyn SecretStore> =
            Arc::new(SqliteSecretStore::open(temp.path()).unwrap());
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            endpoints(),
            secret_store,
            refresh_lock,
            OAuthStrategy::Pkce {
                redirect_base: url::Url::parse("http://127.0.0.1").unwrap(),
            },
        );
        let flow = provider
            .build_flow(
                BackendId("nucleus".into()),
                InteractiveAuthCapability::Browser,
            )
            .expect("Browser capability must succeed");
        assert!(flow.is_pkce(), "Browser+PkceStrategy must use PKCE");
    }

    #[tokio::test]
    async fn build_flow_browser_uses_device_when_strategy_device() {
        let temp = temp_root();
        let secret_store: Arc<dyn SecretStore> =
            Arc::new(SqliteSecretStore::open(temp.path()).unwrap());
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            endpoints(),
            secret_store,
            refresh_lock,
            OAuthStrategy::Device,
        );
        let flow = provider
            .build_flow(
                BackendId("nucleus".into()),
                InteractiveAuthCapability::Browser,
            )
            .expect("Browser capability must succeed");
        assert!(
            flow.is_device(),
            "Browser+DeviceStrategy must use device flow"
        );
    }

    #[tokio::test]
    async fn provider_returns_unavailable_with_no_warm_token() {
        let temp = temp_root();
        let secret_store: Arc<dyn SecretStore> =
            Arc::new(SqliteSecretStore::open(temp.path()).unwrap());
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            endpoints(),
            secret_store,
            refresh_lock,
            OAuthStrategy::Device,
        );
        let err = provider
            .resolve(&BackendId("nucleus".into()), &PrincipalView::new("u-2"))
            .await
            .unwrap_err();
        match err {
            CredentialError::Unavailable { .. } => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn accept_credential_persists_metadata_row() {
        // Asserts state through `load_secret_token`. The store round trip
        // itself is covered by `tests/secret_store_sqlite.rs`.
        let temp = temp_root();
        let secret_store: Arc<dyn SecretStore> =
            Arc::new(SqliteSecretStore::open(temp.path()).unwrap());
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend_id = BackendId("nucleus".into());
        let principal = PrincipalView::new("u-accept");
        let access = b"access-token-bytes".to_vec();
        let refresh = Some(b"refresh-token-bytes".to_vec());
        let expires_at = SystemTime::now() + Duration::from_secs(3_600);

        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            endpoints(),
            secret_store,
            refresh_lock.clone(),
            OAuthStrategy::Device,
        );
        provider
            .accept_credential(&backend_id, &principal, access, refresh, Some(expires_at))
            .await
            .expect("accept_credential should persist");
        let row = refresh_lock
            .load_secret_token(&backend_id.0, &principal.id)
            .expect("load_secret_token should not error")
            .expect("secret_tokens row should exist after accept_credential");
        assert_eq!(row.source_name, "oauth-test");
        assert_eq!(row.secret_handle, "oauth/oauth-test");
        assert!(row.expires_at_unix_ms.is_some());
    }

    #[tokio::test]
    async fn fresh_metadata_with_missing_access_refreshes_from_retained_token() {
        let (token_endpoint, request) = one_shot_token_endpoint(
            200,
            Vec::new(),
            serde_json::json!({
                "access_token": "recovered-access",
                "expires_in": 3600
            })
            .to_string(),
        )
        .await;
        let temp = temp_root();
        let secret_store = sqlite_store(&temp);
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend = BackendId("nucleus".into());
        let principal = PrincipalView::new("u-handle-only");
        let mut refresh_endpoints = endpoints();
        refresh_endpoints.token_endpoint = token_endpoint;
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            refresh_endpoints,
            Arc::clone(&secret_store),
            Arc::clone(&refresh_lock),
            OAuthStrategy::Device,
        );
        provider
            .accept_credential(
                &backend,
                &principal,
                b"access-token".to_vec(),
                Some(b"retained-refresh".to_vec()),
                Some(SystemTime::now() + Duration::from_secs(3_600)),
            )
            .await
            .unwrap();
        secret_store
            .delete(&backend.0, &principal.id, "oauth/oauth-test")
            .unwrap();

        assert_eq!(
            provider
                .resolve_access_keyring_handle(&backend, &principal)
                .await
                .unwrap(),
            "oauth/oauth-test",
            "missing access material must recover through the retained refresh token"
        );
        assert!(
            request
                .await
                .expect("missing access material drives one refresh grant")
                .contains("refresh_token=retained-refresh")
        );
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, "oauth/oauth-test")
                .unwrap()
                .expect("refreshed access material is persisted")
                .as_bytes(),
            b"recovered-access"
        );
    }

    #[tokio::test]
    async fn accepted_credential_without_expiry_resolves_from_warm_path() {
        let temp = temp_root();
        let secret_store = sqlite_store(&temp);
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend = BackendId("nucleus".into());
        let principal = PrincipalView::new("u-no-expiry");
        let provider = OAuthCredentialProvider::new(
            "oauth-no-expiry",
            "nucleus",
            endpoints(),
            secret_store,
            refresh_lock,
            OAuthStrategy::Device,
        );

        provider
            .accept_credential(&backend, &principal, b"opaque-access".to_vec(), None, None)
            .await
            .expect("credential without recorded expiry should persist");
        let resolved = provider
            .resolve(&backend, &principal)
            .await
            .expect("credential without recorded expiry should remain usable");

        assert!(resolved.expires_at.is_none());
        match resolved.bytes.fields.get("oauth") {
            Some(SecretValue::OAuthToken {
                token,
                refresh,
                expires_at,
            }) => {
                assert_eq!(token.as_bytes(), b"opaque-access");
                assert!(refresh.is_none());
                assert!(expires_at.is_none());
            }
            other => panic!("expected resolved OAuth token, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalidation_preserves_refresh_and_forces_the_next_resolution_to_refresh() {
        let (token_endpoint, request) = one_shot_token_endpoint(
            200,
            Vec::new(),
            serde_json::json!({
                "access_token": "refreshed-access",
                "expires_in": 3600
            })
            .to_string(),
        )
        .await;
        let temp = temp_root();
        let secret_store = sqlite_store(&temp);
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend = BackendId("nucleus".into());
        let principal = PrincipalView::new("u-invalidate-access");
        let mut refresh_endpoints = endpoints();
        refresh_endpoints.token_endpoint = token_endpoint;
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            refresh_endpoints,
            Arc::clone(&secret_store),
            Arc::clone(&refresh_lock),
            OAuthStrategy::Device,
        );
        provider
            .accept_credential(
                &backend,
                &principal,
                b"rejected-access".to_vec(),
                Some(b"usable-refresh".to_vec()),
                Some(SystemTime::now() + Duration::from_secs(3_600)),
            )
            .await
            .unwrap();
        let handle = provider.access_keyring_handle();

        provider
            .invalidate_access_token(&backend, &principal)
            .await
            .expect("backend rejection invalidates access material");

        assert!(
            secret_store
                .get(&backend.0, &principal.id, &handle)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, &format!("{handle}/refresh"),)
                .unwrap()
                .expect("invalidation retains the refresh token")
                .as_bytes(),
            b"usable-refresh"
        );
        let invalidated = refresh_lock
            .load_secret_token(&backend.0, &principal.id)
            .unwrap()
            .expect("invalidation retains durable metadata");
        assert_eq!(invalidated.secret_handle, handle);
        assert_eq!(invalidated.expires_at_unix_ms, Some(0));

        assert_eq!(
            provider
                .resolve_access_keyring_handle(&backend, &principal)
                .await
                .expect("the retained refresh token restores rejected access"),
            handle
        );
        assert!(
            request
                .await
                .expect("access invalidation must drive the refresh endpoint")
                .contains("refresh_token=usable-refresh")
        );
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, &handle)
                .unwrap()
                .expect("refreshed access token is committed")
                .as_bytes(),
            b"refreshed-access"
        );
        let refreshed = refresh_lock
            .load_secret_token(&backend.0, &principal.id)
            .unwrap()
            .expect("refresh commits durable metadata");
        assert!(
            refreshed.cred_epoch > invalidated.cred_epoch,
            "refresh must advance beyond the invalidated credential lease"
        );
        assert!(
            refreshed.expires_at_unix_ms.is_some_and(|expires| {
                expires
                    > SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as i64
            }),
            "refresh must replace the stale expiry with a usable one"
        );
        assert_eq!(
            provider
                .resolve_access_keyring_handle(&backend, &principal)
                .await
                .expect("a second resolution must use the warm credential"),
            handle,
            "the one-shot token endpoint is gone, so success proves no repeated refresh"
        );
    }

    #[tokio::test]
    async fn concurrent_stale_resolutions_redeem_a_single_use_refresh_token_once() {
        let (token_endpoint, request_count) = single_use_token_endpoint().await;
        let temp = temp_root();
        let secret_store = sqlite_store(&temp);
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend = BackendId("nucleus".into());
        let principal = PrincipalView::new("u-single-flight-refresh");
        let mut refresh_endpoints = endpoints();
        refresh_endpoints.token_endpoint = token_endpoint;
        let provider = Arc::new(OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            refresh_endpoints,
            Arc::clone(&secret_store),
            refresh_lock,
            OAuthStrategy::Device,
        ));
        provider
            .accept_credential(
                &backend,
                &principal,
                b"expired-access".to_vec(),
                Some(b"single-use-refresh".to_vec()),
                Some(SystemTime::now() - Duration::from_secs(120)),
            )
            .await
            .unwrap();

        let first = provider.resolve_access_keyring_handle(&backend, &principal);
        let second = provider.resolve_access_keyring_handle(&backend, &principal);
        let (first, second) = tokio::join!(first, second);

        assert_eq!(first.unwrap(), provider.access_keyring_handle());
        assert_eq!(second.unwrap(), provider.access_keyring_handle());
        assert_eq!(
            request_count
                .await
                .expect("token endpoint reports request count"),
            1,
            "concurrent stale resolutions must redeem a rotating refresh token once"
        );
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, &provider.access_keyring_handle(),)
                .unwrap()
                .unwrap()
                .as_bytes(),
            b"single-flight-access"
        );
    }

    #[tokio::test]
    async fn stale_rejection_does_not_invalidate_a_newer_registration() {
        let temp = temp_root();
        let secret_store = sqlite_store(&temp);
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend = BackendId("nucleus".into());
        let principal = PrincipalView::new("u-stale-rejection");
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            endpoints(),
            Arc::clone(&secret_store),
            Arc::clone(&refresh_lock),
            OAuthStrategy::Device,
        );
        provider
            .accept_credential(
                &backend,
                &principal,
                b"old-access".to_vec(),
                Some(b"old-refresh".to_vec()),
                Some(SystemTime::now() + Duration::from_secs(3_600)),
            )
            .await
            .unwrap();
        let rejected = provider
            .resolve_access_keyring_handle_lease(&backend, &principal)
            .await
            .unwrap();
        provider
            .accept_credential(
                &backend,
                &principal,
                b"new-access".to_vec(),
                Some(b"new-refresh".to_vec()),
                Some(SystemTime::now() + Duration::from_secs(3_600)),
            )
            .await
            .unwrap();

        assert!(
            !provider
                .invalidate_access_token_if_lease(&backend, &principal, &rejected)
                .await
                .unwrap(),
            "a rejection for an older epoch must not invalidate its replacement"
        );
        let handle = provider.access_keyring_handle();
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, &handle)
                .unwrap()
                .unwrap()
                .as_bytes(),
            b"new-access"
        );
        assert!(
            refresh_lock
                .load_secret_token(&backend.0, &principal.id)
                .unwrap()
                .unwrap()
                .expires_at_unix_ms
                .is_some_and(|expiry| expiry > 0)
        );
    }

    #[tokio::test]
    async fn renamed_provider_does_not_reuse_another_providers_durable_slot() {
        let temp = temp_root();
        let secret_store = sqlite_store(&temp);
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend = BackendId("http".into());
        let principal = PrincipalView::new("u-provider-switch");
        let old_provider = OAuthCredentialProvider::new(
            "provider-a",
            "http",
            endpoints(),
            Arc::clone(&secret_store),
            Arc::clone(&refresh_lock),
            OAuthStrategy::Device,
        );
        old_provider
            .accept_credential(
                &backend,
                &principal,
                b"provider-a-access".to_vec(),
                None,
                None,
            )
            .await
            .unwrap();
        let new_provider = OAuthCredentialProvider::new(
            "provider-b",
            "http",
            endpoints(),
            secret_store,
            refresh_lock,
            OAuthStrategy::Device,
        );

        let error = new_provider
            .resolve(&backend, &principal)
            .await
            .unwrap_err();

        assert!(matches!(error, CredentialError::Unavailable { .. }));
    }

    #[tokio::test]
    async fn accept_credential_replaces_absent_refresh_token() {
        let temp = temp_root();
        let secret_store = sqlite_store(&temp);
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend = BackendId("nucleus".into());
        let principal = PrincipalView::new("u-replace");
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            endpoints(),
            secret_store.clone(),
            refresh_lock,
            OAuthStrategy::Device,
        );

        provider
            .accept_credential(
                &backend,
                &principal,
                b"account-a-access".to_vec(),
                Some(b"account-a-refresh".to_vec()),
                Some(SystemTime::now() + Duration::from_secs(3_600)),
            )
            .await
            .expect("account A credential should persist");
        provider
            .accept_credential(
                &backend,
                &principal,
                b"account-b-access".to_vec(),
                None,
                Some(SystemTime::now() + Duration::from_secs(3_600)),
            )
            .await
            .expect("account B credential should replace account A");

        let access = secret_store
            .get(&backend.0, &principal.id, "oauth/oauth-test")
            .unwrap()
            .expect("replacement access token should exist");
        assert_eq!(access.as_bytes(), b"account-b-access");
        assert!(
            secret_store
                .get(&backend.0, &principal.id, "oauth/oauth-test/refresh")
                .unwrap()
                .is_none(),
            "an omitted replacement refresh token must delete account A's token"
        );
    }

    #[tokio::test]
    async fn credential_replacement_waits_for_the_principal_update_guard() {
        let temp = temp_root();
        let secret_store = sqlite_store(&temp);
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend = BackendId("nucleus".into());
        let principal = PrincipalView::new("u-replacement-serialized");
        let provider = Arc::new(OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            endpoints(),
            Arc::clone(&secret_store),
            Arc::clone(&refresh_lock),
            OAuthStrategy::Device,
        ));
        provider
            .accept_credential(
                &backend,
                &principal,
                b"account-a-access".to_vec(),
                Some(b"account-a-refresh".to_vec()),
                None,
            )
            .await
            .unwrap();
        let prior_row = refresh_lock
            .load_secret_token(&backend.0, &principal.id)
            .unwrap()
            .expect("the initial credential has durable metadata");

        let update_guard = refresh_lock
            .lock_for(&backend.0, &principal.id)
            .expect("test owns the credential update guard");
        let (order_tx, order_rx) = std::sync::mpsc::channel();
        *provider
            .persistence_order_hook
            .lock()
            .expect("persistence-order test-hook lock") = Some(order_tx);
        let update_provider = Arc::clone(&provider);
        let update_backend = backend.clone();
        let update_principal = principal.clone();
        let update = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(update_provider.accept_credential(
                &update_backend,
                &update_principal,
                b"account-b-access".to_vec(),
                Some(b"account-b-refresh".to_vec()),
                None,
            ))
        });
        assert_eq!(
            order_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("replacement reaches the update guard"),
            PersistenceTestEvent::UpdateLockAttempt,
            "the update guard must be attempted before any persistence snapshot"
        );
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, "oauth/oauth-test")
                .unwrap()
                .unwrap()
                .as_bytes(),
            b"account-a-access"
        );
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, "oauth/oauth-test/refresh")
                .unwrap()
                .unwrap()
                .as_bytes(),
            b"account-a-refresh"
        );
        assert_eq!(
            refresh_lock
                .load_secret_token(&backend.0, &principal.id)
                .unwrap(),
            Some(prior_row),
            "the durable snapshot must also remain untouched while the guard is held"
        );
        assert!(
            matches!(
                order_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "the snapshot hook must not run before the replacement acquires the update guard"
        );

        drop(update_guard);
        assert_eq!(
            order_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("replacement snapshots state after acquiring the guard"),
            PersistenceTestEvent::PersistLocked
        );
        update.join().unwrap().unwrap();
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, "oauth/oauth-test")
                .unwrap()
                .unwrap()
                .as_bytes(),
            b"account-b-access"
        );
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, "oauth/oauth-test/refresh")
                .unwrap()
                .unwrap()
                .as_bytes(),
            b"account-b-refresh"
        );
    }

    #[tokio::test]
    async fn resolve_refresh_path_preserves_refresh_token_omitted_by_idp() {
        let (token_endpoint, request) = one_shot_token_endpoint(
            200,
            Vec::new(),
            serde_json::json!({
                "access_token": "refreshed-access",
                "expires_in": 3600
            })
            .to_string(),
        )
        .await;
        let temp = temp_root();
        let secret_store = sqlite_store(&temp);
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend = BackendId("nucleus".into());
        let principal = PrincipalView::new("u-refresh-merge");
        let mut refresh_endpoints = endpoints();
        refresh_endpoints.token_endpoint = token_endpoint;
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            refresh_endpoints,
            secret_store.clone(),
            refresh_lock,
            OAuthStrategy::Device,
        );
        provider
            .accept_credential(
                &backend,
                &principal,
                b"initial-access".to_vec(),
                Some(b"rotating-refresh".to_vec()),
                Some(SystemTime::now() - Duration::from_secs(120)),
            )
            .await
            .expect("initial credential should persist");

        let resolved = provider
            .resolve(&backend, &principal)
            .await
            .expect("expired access token should drive the refresh grant");
        let request = request.await.expect("refresh request should reach the IdP");
        assert!(request.contains("grant_type=refresh_token"));
        assert!(request.contains("refresh_token=rotating-refresh"));
        match resolved.bytes.fields.get("oauth") {
            Some(SecretValue::OAuthToken { token, refresh, .. }) => {
                assert_eq!(token.as_bytes(), b"refreshed-access");
                assert_eq!(
                    refresh
                        .as_ref()
                        .expect("resolved credential retains the usable refresh token")
                        .as_bytes(),
                    b"rotating-refresh"
                );
            }
            other => panic!("expected refreshed OAuth token, got {other:?}"),
        }
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, "oauth/oauth-test")
                .unwrap()
                .expect("refreshed access token must persist")
                .as_bytes(),
            b"refreshed-access"
        );

        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, "oauth/oauth-test/refresh")
                .unwrap()
                .expect("omitted refresh grant token must preserve the prior token")
                .as_bytes(),
            b"rotating-refresh"
        );
    }

    #[tokio::test]
    async fn resolve_refresh_rejects_an_oversized_token_response() {
        let oversized = "x".repeat(crate::auth::flow::MAX_OAUTH_RESPONSE_BODY_BYTES + 1);
        let (token_endpoint, request) = one_shot_token_endpoint(200, Vec::new(), oversized).await;
        let temp = temp_root();
        let secret_store = sqlite_store(&temp);
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend = BackendId("nucleus".into());
        let principal = PrincipalView::new("u-refresh-oversized");
        let mut refresh_endpoints = endpoints();
        refresh_endpoints.token_endpoint = token_endpoint;
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            refresh_endpoints,
            secret_store,
            refresh_lock,
            OAuthStrategy::Device,
        );
        provider
            .accept_credential(
                &backend,
                &principal,
                b"expired-access".to_vec(),
                Some(b"refresh-secret".to_vec()),
                Some(SystemTime::now() - Duration::from_secs(120)),
            )
            .await
            .expect("expired credential should persist");

        let error = provider
            .resolve(&backend, &principal)
            .await
            .expect_err("an oversized refresh response must be rejected");
        let error = match error {
            CredentialError::Backend(error) => error,
            other => {
                panic!("oversized response returned an unexpected credential error: {other:?}")
            }
        };
        assert_eq!(error.code(), ErrorCode::ResourceExhausted);
        assert!(
            error
                .message()
                .contains(&crate::auth::flow::MAX_OAUTH_RESPONSE_BODY_BYTES.to_string())
        );
        let request = request.await.expect("refresh request should reach the IdP");
        assert!(request.contains("refresh_token=refresh-secret"));
    }

    #[tokio::test]
    async fn refresh_grant_suppresses_idp_error_body() {
        let (token_endpoint, request) = one_shot_token_endpoint(
            400,
            Vec::new(),
            serde_json::json!({
                "error": "invalid_grant",
                "error_description": "super-secret-idp-diagnostic"
            })
            .to_string(),
        )
        .await;
        let temp = temp_root();
        let mut refresh_endpoints = endpoints();
        refresh_endpoints.token_endpoint = token_endpoint;
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            refresh_endpoints,
            sqlite_store(&temp),
            Arc::new(AuthRefreshLock::open(temp.path()).unwrap()),
            OAuthStrategy::Device,
        );

        let error = match provider.refresh_token_grant("refresh-secret").await {
            Ok(_) => panic!("an invalid grant must fail"),
            Err(CredentialError::Backend(error)) => error,
            Err(other) => panic!("unexpected credential error: {other:?}"),
        };

        assert_eq!(error.code(), ErrorCode::AuthExpired);
        // The redaction chokepoint keeps the allowlisted code token — the only
        // usable diagnostic — and drops everything else in the body.
        assert!(error.message().contains("invalid_grant"));
        assert!(!error.message().contains("super-secret-idp-diagnostic"));
        assert!(
            request
                .await
                .expect("refresh request should reach the IdP")
                .contains("refresh_token=refresh-secret")
        );
    }

    #[tokio::test]
    async fn oauth_http_client_does_not_follow_token_post_redirects() {
        let redirect_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirect_url = format!("http://{}/leaked", redirect_target.local_addr().unwrap());
        let (token_endpoint, request) =
            one_shot_token_endpoint(307, vec![("Location".into(), redirect_url)], String::new())
                .await;
        let temp = temp_root();
        let secret_store = sqlite_store(&temp);
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend = BackendId("nucleus".into());
        let principal = PrincipalView::new("u-no-redirect");
        let mut redirect_endpoints = endpoints();
        redirect_endpoints.token_endpoint = token_endpoint;
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            redirect_endpoints,
            secret_store,
            refresh_lock,
            OAuthStrategy::Device,
        );
        provider
            .accept_credential(
                &backend,
                &principal,
                b"expired-access".to_vec(),
                Some(b"must-not-leak".to_vec()),
                Some(SystemTime::now() - Duration::from_secs(120)),
            )
            .await
            .expect("expired credential should persist");

        let error = provider
            .resolve(&backend, &principal)
            .await
            .expect_err("a token-endpoint redirect must not be followed");
        match error {
            CredentialError::Backend(error) => {
                assert_eq!(error.code(), ErrorCode::Transient)
            }
            other => panic!("unexpected credential error: {other:?}"),
        }
        let request = request.await.expect("the configured endpoint was called");
        assert!(request.contains("refresh_token=must-not-leak"));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), redirect_target.accept())
                .await
                .is_err(),
            "the OAuth client must not resend a token POST to the redirect target"
        );
    }

    #[tokio::test]
    async fn accept_credential_rejects_empty_access_without_mutating_prior_credential() {
        let temp = temp_root();
        let secret_store = sqlite_store(&temp);
        let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let backend = BackendId("nucleus".into());
        let principal = PrincipalView::new("u-empty");
        let provider = OAuthCredentialProvider::new(
            "oauth-test",
            "nucleus",
            endpoints(),
            secret_store.clone(),
            refresh_lock.clone(),
            OAuthStrategy::Device,
        );
        provider
            .accept_credential(
                &backend,
                &principal,
                b"account-a-access".to_vec(),
                Some(b"account-a-refresh".to_vec()),
                None,
            )
            .await
            .expect("initial credential should persist");
        let row_before = refresh_lock
            .load_secret_token(&backend.0, &principal.id)
            .unwrap()
            .expect("initial metadata row should exist");

        let error = provider
            .accept_credential(
                &backend,
                &principal,
                Vec::new(),
                Some(b"account-b-refresh".to_vec()),
                None,
            )
            .await
            .expect_err("empty access tokens must be rejected");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.message().contains("must not be empty"));
        assert_eq!(
            refresh_lock
                .load_secret_token(&backend.0, &principal.id)
                .unwrap(),
            Some(row_before),
            "a rejected registration must not advance the credential row"
        );
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, "oauth/oauth-test")
                .unwrap()
                .expect("prior access token should remain")
                .as_bytes(),
            b"account-a-access"
        );
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, "oauth/oauth-test/refresh")
                .unwrap()
                .expect("prior refresh token should remain")
                .as_bytes(),
            b"account-a-refresh"
        );
    }
}
