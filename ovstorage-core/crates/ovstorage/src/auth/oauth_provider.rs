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
//! Cache key: `(BackendId, PrincipalView)`. Provider does NOT retry
//! transient HTTP — the library's `with_route_retry` and
//! `CredentialCache` invalidation drive retries.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ovstorage_plugin::{
    BackendId, Error, ErrorCode, InteractiveAuthCapability, SecretBundle, SecretBytes, SecretValue,
};
use serde::Deserialize;

use super::flow::{OAuthEndpoints, OAuthFlow};
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
    secret_store: Arc<SecretStore>,
    refresh_lock: Arc<AuthRefreshLock>,
    backend_kind: String,
    strategy: OAuthStrategy,
    interactive_disabled: bool,
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
    /// `name` is the trace identity (`ResolvedCredential::source_name`)
    /// — must NOT contain token bytes. `backend_kind` is matched
    /// against `BackendId.0`.
    pub fn new(
        name: impl Into<String>,
        backend_kind: impl Into<String>,
        endpoints: OAuthEndpoints,
        secret_store: Arc<SecretStore>,
        refresh_lock: Arc<AuthRefreshLock>,
        strategy: OAuthStrategy,
    ) -> Self {
        Self {
            name: name.into(),
            endpoints,
            http: Arc::new(reqwest::Client::new()),
            secret_store,
            refresh_lock,
            backend_kind: backend_kind.into(),
            strategy,
            interactive_disabled: false,
        }
    }

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

    pub fn endpoints(&self) -> &OAuthEndpoints {
        &self.endpoints
    }

    /// Build the flow matching the host's `capability`:
    /// `None` → `Err(AuthRequired)`; `Headless` → device flow regardless
    /// of `self.strategy` (no loopback listener possible); `Browser` →
    /// honors `self.strategy`.
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
            InteractiveAuthCapability::Headless => {
                let flow = OAuthFlow::device(backend);
                Ok(flow
                    .with_endpoints(self.endpoints.clone())
                    .with_http_client((*self.http).clone()))
            }
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
    /// from the warm path.
    pub async fn accept_credential(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
        access_token: Vec<u8>,
        refresh_token: Option<Vec<u8>>,
        expires_at: Option<SystemTime>,
    ) -> Result<(), Error> {
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
        self.persist_token(&token, backend, principal)
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
        if backend.0 != self.backend_kind {
            return Err(CredentialError::Unavailable {
                details: format!(
                    "OAuthCredentialProvider({}): not configured for backend {:?}",
                    self.name, backend
                ),
            });
        }

        if let Some(persisted) = self
            .refresh_lock
            .load_secret_token(&backend.0, &principal.id)
            .map_err(CredentialError::Backend)?
        {
            match self
                .try_warm_continuation(&persisted, backend, principal)
                .await
            {
                Ok(Some(resolved)) => return Ok(resolved),
                Ok(None) => { /* expired + no refresh -> cold start */ }
                Err(CredentialError::Backend(err))
                    if matches!(err.code(), ErrorCode::AuthExpired | ErrorCode::AuthRequired) =>
                {
                    // Refresh-token grant rejected; fall through to cold start.
                }
                Err(other) => return Err(other),
            }
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
    async fn try_warm_continuation(
        &self,
        persisted: &PersistedSecretToken,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<Option<ResolvedCredential>, CredentialError> {
        let access_now = self
            .secret_store
            .get(&backend.0, &principal.id, &persisted.keyring_handle)
            .map_err(CredentialError::Backend)?;
        let refresh_now = self
            .secret_store
            .get(
                &backend.0,
                &principal.id,
                &format!("{}/refresh", persisted.keyring_handle),
            )
            .map_err(CredentialError::Backend)?;
        let expires_at = persisted
            .expires_at_unix_ms
            .map(|ms| UNIX_EPOCH + Duration::from_millis(ms as u64));
        if let (Some(access), Some(at)) = (&access_now, expires_at)
            && at > SystemTime::now() + Duration::from_secs(60)
        {
            return Ok(Some(ResolvedCredential {
                bytes: bundle_with_access_refresh(access.clone(), refresh_now.clone(), at),
                expires_at: Some(at),
                source_name: self.name.clone(),
            }));
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
        let token = self.refresh_token_grant(refresh_str).await?;
        self.persist_token(&token, backend, principal).await?;
        let bundle = bundle_from_token(&token);
        Ok(Some(ResolvedCredential {
            bytes: bundle,
            expires_at: token.expires_at,
            source_name: self.name.clone(),
        }))
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
        if !response.status().is_success() {
            let status = response.status();
            let body = response.bytes().await.unwrap_or_default();
            let body_str = String::from_utf8_lossy(&body);
            let code = if status.as_u16() == 401
                || (status.as_u16() == 400 && body_str.contains("invalid_grant"))
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
                    body_str
                ),
            )));
        }
        let body = response.bytes().await.map_err(|err| {
            CredentialError::Backend(Error::new(
                ErrorCode::Transient,
                format!(
                    "OAuthCredentialProvider({}): refresh-token body read failed: {err}",
                    self.name
                ),
            ))
        })?;
        let parsed: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
            CredentialError::Backend(Error::new(
                ErrorCode::Internal,
                format!(
                    "OAuthCredentialProvider({}): refresh-token JSON parse failed: {err}",
                    self.name
                ),
            ))
        })?;
        Ok(MintedToken::from_response(parsed))
    }

    async fn persist_token(
        &self,
        token: &MintedToken,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<(), CredentialError> {
        if token.access_token.is_empty() {
            return Ok(());
        }
        let keyring_handle = format!("oauth/{}", self.name);
        self.secret_store
            .put(
                &backend.0,
                &principal.id,
                &keyring_handle,
                &SecretBytes(token.access_token.clone().into_bytes()),
            )
            .map_err(CredentialError::Backend)?;
        if let Some(refresh) = &token.refresh_token {
            self.secret_store
                .put(
                    &backend.0,
                    &principal.id,
                    &format!("{}/refresh", keyring_handle),
                    &SecretBytes(refresh.clone().into_bytes()),
                )
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
            keyring_handle,
            source_name: self.name.clone(),
        };
        self.refresh_lock
            .store_secret_token(&backend.0, &principal.id, &row)
            .map_err(CredentialError::Backend)?;
        Ok(())
    }
}

struct MintedToken {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<SystemTime>,
}

impl MintedToken {
    fn from_response(resp: TokenResponse) -> Self {
        let expires_at = resp
            .expires_in
            .map(|secs| SystemTime::now() + Duration::from_secs(secs));
        Self {
            access_token: resp.access_token,
            refresh_token: resp.refresh_token,
            expires_at,
        }
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

fn bundle_from_token(token: &MintedToken) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "oauth".into(),
        SecretValue::OAuthToken {
            token: SecretBytes(token.access_token.clone().into_bytes()),
            refresh: token
                .refresh_token
                .as_ref()
                .map(|r| SecretBytes(r.clone().into_bytes())),
            expires_at: token.expires_at,
        },
    );
    bundle
}

fn bundle_with_access_refresh(
    access: SecretBytes,
    refresh: Option<SecretBytes>,
    expires_at: SystemTime,
) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "oauth".into(),
        SecretValue::OAuthToken {
            token: access,
            refresh,
            expires_at: Some(expires_at),
        },
    );
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_root() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn endpoints() -> OAuthEndpoints {
        OAuthEndpoints {
            authorization_endpoint: url::Url::parse("https://idp.example/authorize").unwrap(),
            token_endpoint: url::Url::parse("https://idp.example/token").unwrap(),
            client_id: "test-client".into(),
            scope: Some("openid".into()),
        }
    }

    #[tokio::test]
    async fn provider_falls_through_for_unmatched_backend() {
        let temp = temp_root();
        let secret_store = Arc::new(SecretStore::new());
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
        let secret_store = Arc::new(SecretStore::new());
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
    async fn build_flow_headless_uses_device_even_with_pkce_strategy() {
        let temp = temp_root();
        let secret_store = Arc::new(SecretStore::new());
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
                InteractiveAuthCapability::Headless,
            )
            .expect("Headless capability must succeed");
        assert!(flow.is_device(), "Headless must use device flow");
        assert!(!flow.is_pkce(), "Headless must NOT use PKCE");
    }

    #[tokio::test]
    async fn build_flow_browser_uses_pkce_when_strategy_pkce() {
        let temp = temp_root();
        let secret_store = Arc::new(SecretStore::new());
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
        let secret_store = Arc::new(SecretStore::new());
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
        let secret_store = Arc::new(SecretStore::new());
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
        // Asserts state through `load_secret_token`; OS keyring is a
        // no-op on Linux/WSL so we can't exercise the resolve() warm
        // path here. Full keyring round-trip lives in
        // `auth::cache::tests::cache_round_trip_persists_across_drop`.
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        let temp = temp_root();
        let secret_store = Arc::new(SecretStore::new());
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
        assert_eq!(row.keyring_handle, "oauth/oauth-test");
        assert!(row.expires_at_unix_ms.is_some());
    }
}
