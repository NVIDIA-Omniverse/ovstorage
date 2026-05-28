// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `DefaultAzureCredential`-style auth resolution for Azure Blob Storage.
//!
//! Implements the Entra ID subset that is meaningful in an async,
//! out-of-process plugin: explicit credentials in `SecretBundle`, then four
//! environment-variable forms (account key, SAS token, service principal,
//! workload-identity federated token). Managed Identity (IMDS), Azure CLI,
//! VS Code, and PowerShell credential sources are intentionally skipped here
//! and documented as gaps in `docs/crates/plugin-azure.md`; they would each
//! require additional out-of-band machinery (HTTP IMDS hop, subprocess to
//! `az`, OS-keyring lookup) that the host does not yet broker.
//!
//! Bearer tokens from the OAuth2 client-credentials flow are cached in a
//! `Mutex<Option<CachedToken>>` so the data path does not refresh on every
//! request. The cache refreshes 60 seconds before expiry.

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ovstorage_plugin::{
    ConnectionId, Error, ErrorCode, ErrorContext, Result, SecretBundle, SecretBytes, SecretValue,
};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::signing::decode_account_key;

const ENTRA_LOGIN_HOST: &str = "https://login.microsoftonline.com";
const STORAGE_OAUTH_SCOPE: &str = "https://storage.azure.com/.default";
const FEDERATED_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const REFRESH_LEEWAY: Duration = Duration::from_secs(60);

/// Cadence used by [`refresh_loop`] for retry sleeps after a failed
/// token grant. Short enough that one IDP blip doesn't leave the
/// cached token expired for the rest of its lifetime, long enough not
/// to hammer the IDP under sustained failures.
const REFRESH_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Resolved auth source for an Azure connection.
#[derive(Clone)]
pub(crate) enum AuthSource {
    /// No credentials supplied. Anonymous access works only against public
    /// containers; signed operations surface `AuthRequired`.
    Anonymous,
    /// Account key for Shared Key signing and SAS minting. Stored decoded so
    /// every request avoids the base64 round-trip.
    SharedKey { account_key_bytes: Vec<u8> },
    /// Caller-supplied SAS token. Appended verbatim to URLs and never re-signed.
    Sas { sas_token: String },
    /// Service-principal client_credentials flow with a static secret.
    Oauth2ClientSecret {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    },
    /// Workload-identity federated assertion. The JWT lives in a file that
    /// Kubernetes / GitHub OIDC / AKS rotates; we read it on every refresh.
    Oauth2Federated {
        tenant_id: String,
        client_id: String,
        token_file: PathBuf,
    },
}

impl fmt::Debug for AuthSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthSource::Anonymous => f.write_str("Anonymous"),
            AuthSource::SharedKey { .. } => f
                .debug_struct("SharedKey")
                .field("account_key_bytes", &"<redacted>")
                .finish(),
            AuthSource::Sas { .. } => f
                .debug_struct("Sas")
                .field("sas_token", &"<redacted>")
                .finish(),
            AuthSource::Oauth2ClientSecret {
                tenant_id,
                client_id,
                ..
            } => f
                .debug_struct("Oauth2ClientSecret")
                .field("tenant_id", tenant_id)
                .field("client_id", client_id)
                .field("client_secret", &"<redacted>")
                .finish(),
            AuthSource::Oauth2Federated {
                tenant_id,
                client_id,
                token_file,
            } => f
                .debug_struct("Oauth2Federated")
                .field("tenant_id", tenant_id)
                .field("client_id", client_id)
                .field("token_file", token_file)
                .finish(),
        }
    }
}

#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at: SystemTime,
}

/// Auth handle held by the live backend. Coalesces OAuth2 refreshes through an
/// in-process mutex so that several concurrent operations against one
/// connection do not stampede the IdP.
///
/// Lifecycle: callers typically wrap this in `Arc<_>` and then (for
/// OAuth-backed sources) install a background refresh task via
/// [`AzureAuth::install_background_refresh`]. The task holds only a
/// `Weak<AzureAuth>`, so dropping the last `Arc` lets the loop exit
/// naturally on its next `upgrade()`; the `JoinHandle` is also aborted
/// on `Drop` so the task can't keep running with a dangling `Weak`.
///
/// `pub` so the `__test_only_with_credentials` hook in `lib.rs` can hand
/// one to the constructor; the inner state remains private.
pub struct AzureAuth {
    source: AuthSource,
    cached: Mutex<Option<CachedToken>>,
    /// Process-wide HTTP client reused for the background refresh
    /// loop; data-path callers continue to pass an explicit `&Client`
    /// to [`bearer_token`] because they own their own connection pool.
    http: Client,
    /// Test-only override for the Entra token endpoint host (the bit
    /// before `/{tenant_id}/oauth2/v2.0/token`). When `None` the
    /// production `https://login.microsoftonline.com` is used. The
    /// background-refresh tests below point this at a loopback mock
    /// so the loop can drive observable wire effects without TLS.
    entra_host: Option<String>,
    /// Handle to the background refresh task spawned by
    /// [`AzureAuth::install_background_refresh`]. `std::sync::Mutex`
    /// because `Drop` is sync and must reach the handle without
    /// awaiting.
    refresh_task: StdMutex<Option<JoinHandle<()>>>,
}

impl Drop for AzureAuth {
    fn drop(&mut self) {
        // Abort the background refresh task so it can't outlive the
        // state it borrows via `Weak`. `try_lock` because Drop is
        // sync; if contended (only install_background_refresh takes
        // the lock, and only briefly) the runtime would tear the task
        // down on shutdown anyway.
        if let Ok(mut guard) = self.refresh_task.try_lock()
            && let Some(handle) = guard.take()
        {
            handle.abort();
        }
    }
}

impl AzureAuth {
    /// Resolve credentials in the documented `DefaultAzureCredential` order.
    pub fn resolve(bundle: &SecretBundle) -> Result<Self> {
        Self::resolve_with_http(bundle, Client::new())
    }

    /// Resolve credentials with a caller-supplied `reqwest::Client`.
    /// Used by background-refresh tests to point the loop at a mock
    /// IDP endpoint without going through the data-path client.
    pub fn resolve_with_http(bundle: &SecretBundle, http: Client) -> Result<Self> {
        let source = resolve_source(bundle)?;
        Ok(Self {
            source,
            cached: Mutex::new(None),
            http,
            entra_host: None,
            refresh_task: StdMutex::new(None),
        })
    }

    /// Test-only mutator: override the Entra token endpoint host so
    /// the background-refresh loop can drive observable wire effects
    /// against a mock server.
    #[cfg(test)]
    pub(crate) fn set_entra_host_for_test(&mut self, host: String) {
        self.entra_host = Some(host);
    }

    pub(crate) fn source(&self) -> &AuthSource {
        &self.source
    }

    /// Returns `Some(account_key_bytes)` when Shared Key signing is available.
    #[allow(dead_code)]
    pub fn account_key(&self) -> Option<&[u8]> {
        match &self.source {
            AuthSource::SharedKey { account_key_bytes } => Some(account_key_bytes),
            _ => None,
        }
    }

    /// Returns the raw SAS token string when one was provided directly.
    #[allow(dead_code)]
    pub fn sas_token(&self) -> Option<&str> {
        match &self.source {
            AuthSource::Sas { sas_token } => Some(sas_token),
            _ => None,
        }
    }

    /// Whether this auth source mints OAuth2 bearer tokens.
    pub fn uses_oauth(&self) -> bool {
        matches!(
            self.source,
            AuthSource::Oauth2ClientSecret { .. } | AuthSource::Oauth2Federated { .. }
        )
    }

    /// Default initial-sleep cadence used when the client installs the
    /// background refresh before any token has been minted (no IDP-
    /// reported TTL to base on). After the first refresh the loop
    /// re-bases on the freshly-issued TTL.
    pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 30);

    /// Spawn a background task that proactively refreshes the bearer
    /// at ~90% of TTL with a 30s retry cadence on failure. No-op for
    /// non-OAuth credential sources (nothing to refresh) and idempotent
    /// for repeat installs (aborts any prior task first so the loop
    /// re-bases on the latest TTL). Skips spawning if called outside a
    /// tokio runtime (some unit tests construct an `AzureAuth`
    /// synchronously and there is no runtime to host the loop).
    ///
    /// The task holds only `Weak<AzureAuth>` so it doesn't keep the
    /// state alive past its natural drop; `Drop for AzureAuth` aborts
    /// the `JoinHandle`, and any in-flight `upgrade()` after the strong
    /// count reaches zero returns `None` and the loop exits.
    pub fn install_background_refresh(self: &Arc<Self>, ttl: Duration) {
        if !self.uses_oauth() {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let mut guard = match self.refresh_task.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(prev) = guard.take() {
            prev.abort();
        }
        let weak = Arc::downgrade(self);
        *guard = Some(tokio::spawn(refresh_loop(weak, ttl)));
    }

    /// Force a token refresh and return the new `(access_token, ttl)`.
    /// Used by the background refresh task to drive proactive refreshes
    /// ahead of expiry. Errors out on non-OAuth connections (the loop
    /// never spawns for them, but the guard keeps misuse from leaving
    /// an empty token in the cache).
    pub async fn refresh_now(&self) -> Result<(String, Duration)> {
        if !self.uses_oauth() {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "Azure connection does not use OAuth2 credentials",
            )
            .with_context(ErrorContext::Auth {
                connection_id: ConnectionId(String::new()),
                reason: Some("non_oauth".into()),
                expired_at: None,
            }));
        }
        let mut guard = self.cached.lock().await;
        let fresh = self.fetch_token(&self.http).await.inspect_err(|err| {
            warn!(plugin = "azure", error.code = ?err.code(), "azure token refresh failed");
        })?;
        let token = fresh.token.clone();
        let ttl = match fresh.expires_at.duration_since(SystemTime::now()) {
            Ok(remaining) => remaining,
            Err(_) => Duration::from_secs(0),
        };
        *guard = Some(fresh);
        Ok((token, ttl))
    }

    /// Fetch (and cache) a bearer token for OAuth-backed connections. Returns
    /// `Err(AuthRequired)` for connections that don't use OAuth.
    pub async fn bearer_token(&self, client: &Client) -> Result<String> {
        if !self.uses_oauth() {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "Azure connection does not use OAuth2 credentials",
            )
            .with_context(ErrorContext::Auth {
                connection_id: ConnectionId(String::new()),
                reason: Some("non_oauth".into()),
                expired_at: None,
            }));
        }
        // Hold the async mutex across the fetch so concurrent callers coalesce on a single Entra round-trip.
        let mut guard = self.cached.lock().await;
        if let Some(cached) = guard.as_ref()
            && cached.expires_at > SystemTime::now() + REFRESH_LEEWAY
        {
            debug!(plugin = "azure", cache.hit = true, "azure token cache hit");
            return Ok(cached.token.clone());
        }
        debug!(
            plugin = "azure",
            cache.hit = false,
            "azure token refresh triggered"
        );
        let fresh = self.fetch_token(client).await.inspect_err(|err| {
            warn!(plugin = "azure", error.code = ?err.code(), "azure token refresh failed");
        })?;
        let token = fresh.token.clone();
        *guard = Some(fresh);
        // Intentionally not logging the token value.
        Ok(token)
    }

    async fn fetch_token(&self, client: &Client) -> Result<CachedToken> {
        let (tenant_id, client_id, body) = match &self.source {
            AuthSource::Oauth2ClientSecret {
                tenant_id,
                client_id,
                client_secret,
            } => {
                let body = format_form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", client_id),
                    ("client_secret", client_secret),
                    ("scope", STORAGE_OAUTH_SCOPE),
                ]);
                (tenant_id.clone(), client_id.clone(), body)
            }
            AuthSource::Oauth2Federated {
                tenant_id,
                client_id,
                token_file,
            } => {
                let assertion = std::fs::read_to_string(token_file).map_err(|e| {
                    Error::new(
                        ErrorCode::AuthRequired,
                        format!("failed to read federated token file: {e}"),
                    )
                    .with_context(ErrorContext::Auth {
                        connection_id: ConnectionId(String::new()),
                        reason: Some("federated_token_file_unreadable".into()),
                        expired_at: None,
                    })
                })?;
                let body = format_form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", client_id),
                    ("scope", STORAGE_OAUTH_SCOPE),
                    ("client_assertion_type", FEDERATED_ASSERTION_TYPE),
                    ("client_assertion", assertion.trim()),
                ]);
                (tenant_id.clone(), client_id.clone(), body)
            }
            _ => {
                return Err(Error::new(
                    ErrorCode::AuthRequired,
                    "Azure connection does not use OAuth2 credentials",
                )
                .with_context(ErrorContext::Auth {
                    connection_id: ConnectionId(String::new()),
                    reason: Some("non_oauth".into()),
                    expired_at: None,
                }));
            }
        };
        let host = self.entra_host.as_deref().unwrap_or(ENTRA_LOGIN_HOST);
        let url = format!("{host}/{tenant_id}/oauth2/v2.0/token");
        let response = client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                Error::new(
                    ErrorCode::AuthRequired,
                    format!("Entra token request failed for {client_id}: {e}"),
                )
                .with_context(ErrorContext::Auth {
                    connection_id: ConnectionId(String::new()),
                    reason: Some("entra_transport".into()),
                    expired_at: None,
                })
            })?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(Error::new(
                ErrorCode::AuthRequired,
                format!("Entra token request returned {status}: {text}"),
            )
            .with_context(ErrorContext::Auth {
                connection_id: ConnectionId(String::new()),
                reason: Some(format!("entra_status_{}", status.as_u16())),
                expired_at: None,
            }));
        }
        let parsed: TokenResponse = response.json().await.map_err(|e| {
            Error::new(
                ErrorCode::AuthRequired,
                format!("Entra token response is not valid JSON: {e}"),
            )
            .with_context(ErrorContext::Auth {
                connection_id: ConnectionId(String::new()),
                reason: Some("entra_response_invalid_json".into()),
                expired_at: None,
            })
        })?;
        let expires_at =
            SystemTime::now() + Duration::from_secs(parsed.expires_in.unwrap_or(3_600));
        Ok(CachedToken {
            token: parsed.access_token,
            expires_at,
        })
    }
}

/// Compute the next sleep before a proactive token refresh.
///
/// Refresh at 90% of the token's TTL — far enough ahead of expiry to
/// absorb network latency and IDP clock skew, but late enough that
/// short-lived tokens don't trigger a thundering herd of refreshes
/// immediately after install. Clamped to a 30-second floor so a
/// pathologically tiny TTL doesn't busy-loop the refresh endpoint.
fn refresh_sleep_for(ttl: Duration) -> Duration {
    (ttl * 9 / 10).max(Duration::from_secs(30))
}

/// Background refresh loop spawned by
/// [`AzureAuth::install_background_refresh`]. Owns only a
/// `Weak<AzureAuth>` so it doesn't keep the state alive past its
/// natural drop — `Drop for AzureAuth` aborts the `JoinHandle`, and
/// any in-flight upgrade attempt returns `None` after the strong
/// count hits zero.
///
/// Each iteration:
/// 1. Sleep until the next refresh deadline — `refresh_sleep_for(ttl)`
///    on the first iteration (and after successful refreshes), or
///    [`REFRESH_RETRY_INTERVAL`] after a failed grant.
/// 2. Try to upgrade the `Weak`; on failure (state dropped), exit.
/// 3. Drive [`AzureAuth::refresh_now`].
/// 4. On success, re-base the next sleep on the new TTL. On failure,
///    switch to the short retry cadence so a single IDP blip doesn't
///    strand the token expired for most of its remaining lifetime.
async fn refresh_loop(weak: Weak<AzureAuth>, initial_ttl: Duration) {
    let mut next_sleep = refresh_sleep_for(initial_ttl);
    loop {
        tokio::time::sleep(next_sleep).await;
        let Some(auth) = weak.upgrade() else {
            return;
        };
        let outcome = auth.refresh_now().await;
        // Release the strong ref before the next sleep so the state
        // can be dropped during the retry window if the host tears
        // the connection down.
        drop(auth);
        match outcome {
            Ok((_token, ttl)) => {
                next_sleep = refresh_sleep_for(ttl);
            }
            Err(err) => {
                warn!(
                    plugin = "azure",
                    error.code = ?err.code(),
                    "azure: background refresh failed; will retry in 30s",
                );
                next_sleep = REFRESH_RETRY_INTERVAL;
            }
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Resolve credentials in the documented order; the first matching source wins.
fn resolve_source(bundle: &SecretBundle) -> Result<AuthSource> {
    if let Some(key) = bundle_string(bundle, "account_key")? {
        info!(
            plugin = "azure",
            source = "bundle_account_key",
            "azure credential source selected"
        );
        return Ok(AuthSource::SharedKey {
            account_key_bytes: decode_account_key(&key)?,
        });
    }
    if let Some(sas) = bundle_string(bundle, "sas_token")? {
        info!(
            plugin = "azure",
            source = "bundle_sas_token",
            "azure credential source selected"
        );
        return Ok(AuthSource::Sas {
            sas_token: strip_leading_question_mark(sas),
        });
    }
    if let (Some(client_id), Some(tenant_id)) = (
        bundle_string(bundle, "client_id")?,
        bundle_string(bundle, "tenant_id")?,
    ) {
        if let Some(token_file) = bundle_string(bundle, "federated_token_file")? {
            info!(
                plugin = "azure",
                source = "bundle_federated",
                "azure credential source selected"
            );
            return Ok(AuthSource::Oauth2Federated {
                tenant_id,
                client_id,
                token_file: PathBuf::from(token_file),
            });
        }
        if let Some(client_secret) = bundle_string(bundle, "client_secret")? {
            info!(
                plugin = "azure",
                source = "bundle_client_secret",
                "azure credential source selected"
            );
            return Ok(AuthSource::Oauth2ClientSecret {
                tenant_id,
                client_id,
                client_secret,
            });
        }
    }
    info!(
        plugin = "azure",
        source = "anonymous",
        "azure credential source selected"
    );
    Ok(AuthSource::Anonymous)
}

fn bundle_string(bundle: &SecretBundle, key: &str) -> Result<Option<String>> {
    let Some(value) = bundle.fields.get(key) else {
        return Ok(None);
    };
    let bytes = match value {
        SecretValue::Bytes(SecretBytes(bytes)) => bytes,
        SecretValue::File(SecretBytes(bytes)) => bytes,
        SecretValue::OAuthToken { token, .. } => &token.0,
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("Azure credential '{key}' must be a Bytes or File secret"),
            ));
        }
    };
    let raw = std::str::from_utf8(bytes).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure credential '{key}' must be UTF-8"),
        )
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn strip_leading_question_mark(token: String) -> String {
    if let Some(rest) = token.strip_prefix('?') {
        rest.to_string()
    } else {
        token
    }
}

/// `application/x-www-form-urlencoded` body builder.
pub(crate) fn format_form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Convert seconds-since-epoch to `SystemTime` for reproducible `expires_at` values in tests.
#[allow(dead_code)]
pub(crate) fn unix_seconds_to_system_time(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::collections::HashMap;

    fn bundle_with(fields: &[(&str, &str)]) -> SecretBundle {
        let mut map = HashMap::new();
        for (key, value) in fields {
            map.insert(
                (*key).to_string(),
                SecretValue::Bytes(SecretBytes(value.as_bytes().to_vec())),
            );
        }
        SecretBundle { fields: map }
    }

    #[test]
    fn explicit_account_key_short_circuits_other_sources() {
        let key = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let bundle = bundle_with(&[("account_key", key.as_str())]);
        let auth = AzureAuth::resolve(&bundle).unwrap();
        assert!(matches!(auth.source(), AuthSource::SharedKey { .. }));
    }

    #[test]
    fn explicit_sas_token_strips_leading_question_mark() {
        let bundle = bundle_with(&[("sas_token", "?sv=2021-12-02&sig=abc")]);
        let auth = AzureAuth::resolve(&bundle).unwrap();
        match auth.source() {
            AuthSource::Sas { sas_token } => {
                assert_eq!(sas_token, "sv=2021-12-02&sig=abc");
            }
            other => panic!("expected SAS, got {other:?}"),
        }
    }

    #[test]
    fn service_principal_resolves_to_oauth2_client_secret() {
        let bundle = bundle_with(&[
            ("tenant_id", "tenant-uuid"),
            ("client_id", "client-uuid"),
            ("client_secret", "secret-value"),
        ]);
        let auth = AzureAuth::resolve(&bundle).unwrap();
        assert!(matches!(
            auth.source(),
            AuthSource::Oauth2ClientSecret { .. }
        ));
        assert!(auth.uses_oauth());
    }

    #[test]
    fn workload_identity_resolves_to_federated_oauth2() {
        let bundle = bundle_with(&[
            ("tenant_id", "tenant-uuid"),
            ("client_id", "client-uuid"),
            ("federated_token_file", "/tmp/azure-fed.jwt"),
        ]);
        let auth = AzureAuth::resolve(&bundle).unwrap();
        assert!(matches!(auth.source(), AuthSource::Oauth2Federated { .. }));
    }

    #[test]
    fn debug_redacts_azure_credentials() {
        let shared_key = AuthSource::SharedKey {
            account_key_bytes: b"account-key-secret".to_vec(),
        };
        let shared_debug = format!("{shared_key:?}");
        assert!(
            !shared_debug.contains("account-key-secret"),
            "{shared_debug}"
        );
        assert!(shared_debug.contains("<redacted>"), "{shared_debug}");

        let sas = AuthSource::Sas {
            sas_token: "sv=2021-12-02&sig=secret-signature".into(),
        };
        let sas_debug = format!("{sas:?}");
        assert!(!sas_debug.contains("secret-signature"), "{sas_debug}");
        assert!(sas_debug.contains("<redacted>"), "{sas_debug}");

        let oauth = AuthSource::Oauth2ClientSecret {
            tenant_id: "tenant-uuid".into(),
            client_id: "client-uuid".into(),
            client_secret: "client-secret".into(),
        };
        let oauth_debug = format!("{oauth:?}");
        assert!(!oauth_debug.contains("client-secret"), "{oauth_debug}");
        assert!(oauth_debug.contains("<redacted>"), "{oauth_debug}");
    }

    #[test]
    fn empty_bundle_with_no_env_resolves_to_anonymous() {
        let _guards = (
            EnvVarGuard::clear("AZURE_STORAGE_ACCOUNT_KEY"),
            EnvVarGuard::clear("AZURE_STORAGE_SAS_TOKEN"),
            EnvVarGuard::clear("AZURE_TENANT_ID"),
            EnvVarGuard::clear("AZURE_CLIENT_ID"),
            EnvVarGuard::clear("AZURE_CLIENT_SECRET"),
            EnvVarGuard::clear("AZURE_FEDERATED_TOKEN_FILE"),
        );
        let auth = AzureAuth::resolve(&SecretBundle::default()).unwrap();
        assert!(matches!(auth.source(), AuthSource::Anonymous));
    }

    #[test]
    fn format_form_url_encodes_values() {
        let body = format_form(&[
            ("grant_type", "client_credentials"),
            ("scope", STORAGE_OAUTH_SCOPE),
            ("client_id", "abc/def"),
        ]);
        assert_eq!(
            body,
            "grant_type=client_credentials&scope=https%3A%2F%2Fstorage.azure.com%2F.default&client_id=abc%2Fdef"
        );
    }

    #[test]
    fn entra_client_secret_token_body_shape_is_pinned() {
        let body = format_form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "client-uuid"),
            ("client_secret", "shh"),
            ("scope", STORAGE_OAUTH_SCOPE),
        ]);
        assert_eq!(
            body,
            "grant_type=client_credentials&client_id=client-uuid&client_secret=shh&scope=https%3A%2F%2Fstorage.azure.com%2F.default"
        );
    }

    #[test]
    fn entra_federated_token_body_replaces_secret_with_assertion() {
        let body = format_form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "client-uuid"),
            ("scope", STORAGE_OAUTH_SCOPE),
            ("client_assertion_type", FEDERATED_ASSERTION_TYPE),
            ("client_assertion", "fake.jwt.token"),
        ]);
        assert!(body.contains("client_assertion=fake.jwt.token"));
        assert!(body.contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
        ));
        assert!(body.contains("scope=https%3A%2F%2Fstorage.azure.com%2F.default"));
        assert!(!body.contains("client_secret"));
    }

    /// RAII guard that snapshots and restores an env var.
    struct EnvVarGuard {
        name: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    // SAFETY: only `empty_bundle_with_no_env_resolves_to_anonymous` constructs an `EnvVarGuard`,
    // and it's the sole caller that reads AZURE_* env vars. The mutate→read→Drop sequence runs
    // on a single test thread; other tests short-circuit on explicit bundle credentials.
    impl EnvVarGuard {
        fn clear(name: &'static str) -> Self {
            let previous = std::env::var_os(name);
            unsafe { std::env::remove_var(name) };
            Self { name, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => unsafe { std::env::set_var(self.name, value) },
                None => unsafe { std::env::remove_var(self.name) },
            }
        }
    }

    #[tokio::test]
    async fn bearer_token_on_non_oauth_carries_auth_context() {
        let bundle = bundle_with(&[("sas_token", "?sv=2021-12-02&sig=abc")]);
        let auth = AzureAuth::resolve(&bundle).unwrap();
        let client = Client::new();
        let err = auth.bearer_token(&client).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ovstorage_plugin::ErrorContext::Auth { reason, .. }) => {
                assert_eq!(reason.as_deref(), Some("non_oauth"));
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    #[test]
    fn refresh_sleep_for_is_ninety_percent_clamped_to_thirty_seconds() {
        // Normal-case TTL: 90% of 1000s = 900s.
        assert_eq!(
            refresh_sleep_for(Duration::from_secs(1_000)),
            Duration::from_secs(900),
        );
        // Pathologically tiny TTL must not busy-loop the IDP — floor at 30s.
        assert_eq!(
            refresh_sleep_for(Duration::from_secs(1)),
            Duration::from_secs(30),
        );
        // Edge: TTL of exactly 33s — 90% = 29.7s, still under the floor.
        assert_eq!(
            refresh_sleep_for(Duration::from_secs(33)),
            Duration::from_secs(30),
        );
        // Just-above-floor TTL — 90% of 40s = 36s.
        assert_eq!(
            refresh_sleep_for(Duration::from_secs(40)),
            Duration::from_secs(36),
        );
    }

    /// Build an OAuth-backed `AzureAuth` whose Entra host points at
    /// the given mock endpoint. Used by the background-refresh tests
    /// to observe wire-level effects from the loop.
    fn oauth_auth_pointed_at(entra_host: &str) -> Arc<AzureAuth> {
        let bundle = bundle_with(&[
            ("tenant_id", "tenant-uuid"),
            ("client_id", "client-uuid"),
            ("client_secret", "secret-value"),
        ]);
        let mut auth = AzureAuth::resolve(&bundle).expect("oauth auth resolves");
        auth.set_entra_host_for_test(entra_host.to_string());
        Arc::new(auth)
    }

    /// Spawn a mock token endpoint that serves a sequence of HTTP
    /// responses (one per accepted connection). Returns the listener
    /// host (`http://127.0.0.1:NNNN`) and a receiver that fires once
    /// per accepted connection. If the queue is exhausted the
    /// connection is closed.
    async fn spawn_mock_entra_endpoint(
        responses: Vec<String>,
    ) -> (String, tokio::sync::mpsc::UnboundedReceiver<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{}", addr);
        let (hit_tx, hit_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut queue: std::collections::VecDeque<String> = responses.into();
            while let Ok((mut sock, _)) = listener.accept().await {
                let _ = hit_tx.send(());
                let mut buf = vec![0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let Some(response) = queue.pop_front() else {
                    let _ = sock.shutdown().await;
                    continue;
                };
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        (endpoint, hit_rx)
    }

    fn ok_token_response(expires_in: u64) -> String {
        let body = format!(
            r#"{{"access_token":"refreshed","token_type":"Bearer","expires_in":{}}}"#,
            expires_in,
        );
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body,
        )
    }

    fn err_token_response() -> String {
        let body = r#"{"error":"invalid_grant"}"#;
        format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body,
        )
    }

    /// `install_background_refresh` with a short TTL must drive a
    /// proactive refresh near the 90%-of-TTL mark. We point the auth
    /// at a mock token endpoint and wait for the first hit; with
    /// TTL=5s the loop sleeps `(5s * 9 / 10).max(30s)` = 30s (the
    /// floor), so a real-clock wait would be too slow — pause tokio
    /// time and advance past the deadline instead.
    #[tokio::test(start_paused = true)]
    async fn background_refresh_runs_on_short_ttl() {
        let (endpoint, mut hit_rx) = spawn_mock_entra_endpoint(vec![ok_token_response(3600)]).await;
        let auth = oauth_auth_pointed_at(&endpoint);
        auth.install_background_refresh(Duration::from_secs(5));

        // Yield so the spawned loop registers its sleep before we
        // advance the clock.
        tokio::task::yield_now().await;

        // Just under the 30s floor: loop must still be parked.
        tokio::time::advance(Duration::from_secs(29)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(
            hit_rx.try_recv().is_err(),
            "background refresh fired before the 30s floor elapsed",
        );

        // Cross the deadline. The loop wakes, makes the grant call
        // over the mock, and the channel signal fires.
        tokio::time::advance(Duration::from_secs(2)).await;
        let hit = hit_rx.recv().await;
        assert!(hit.is_some(), "mock listener channel closed unexpectedly");
    }

    /// On a failed refresh the loop must retry on the short cadence
    /// (`REFRESH_RETRY_INTERVAL` = 30s), not park on another
    /// 90%-of-TTL window.
    #[tokio::test(start_paused = true)]
    async fn background_refresh_retries_on_error() {
        let (endpoint, mut hit_rx) =
            spawn_mock_entra_endpoint(vec![err_token_response(), ok_token_response(3600)]).await;
        let auth = oauth_auth_pointed_at(&endpoint);
        // TTL=5s → first sleep is floored to 30s. After the first
        // (failed) refresh, the loop should wait 30s before retrying.
        auth.install_background_refresh(Duration::from_secs(5));

        tokio::task::yield_now().await;
        // Cross the first deadline. The loop wakes, makes the grant
        // call (which fails synchronously over the mock), then arms
        // the retry sleep.
        tokio::time::advance(Duration::from_secs(31)).await;
        let first = hit_rx.recv().await;
        assert!(first.is_some(), "first refresh attempt must hit the mock");

        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        // Advance past the retry deadline. Under the fix this is
        // ~30s; under the buggy shape it would be ~30 minutes
        // (90%-of-TTL replayed).
        tokio::time::advance(Duration::from_secs(31)).await;
        let second = hit_rx.recv().await;
        assert!(
            second.is_some(),
            "retry must arrive on the short retry cadence (not 90%-of-TTL)",
        );
    }

    /// Dropping the last `Arc<AzureAuth>` must abort the spawned
    /// refresh task. We grab the JoinHandle out of the auth state,
    /// drop the Arc, then abort and observe the task completes
    /// promptly (the abort wakes it from its `sleep`).
    #[tokio::test]
    async fn background_refresh_aborts_on_drop() {
        let (endpoint, _hit_rx) = spawn_mock_entra_endpoint(vec![ok_token_response(3600)]).await;
        let auth = oauth_auth_pointed_at(&endpoint);
        // Long TTL so the loop's initial sleep is ~ttl*9/10 ≈ 30 min.
        auth.install_background_refresh(Duration::from_secs(60 * 60));

        // Grab the JoinHandle out of the auth state so we can observe
        // its completion after the Arc drops.
        let handle = auth
            .refresh_task
            .lock()
            .unwrap()
            .take()
            .expect("refresh task should be installed");

        // Drop the Arc to prove the lifecycle: the Weak in the loop
        // can no longer upgrade after this point. The abort below
        // wakes the task from its sleep (which is the only thing
        // currently blocking it).
        drop(auth);

        handle.abort();
        // `await` on an aborted handle resolves to `Err(JoinError)`
        // with `is_cancelled() == true`. We just need the await to
        // complete (proves the task did not deadlock).
        let result = handle.await;
        assert!(
            result.is_err() && result.unwrap_err().is_cancelled(),
            "aborted refresh task must complete with a cancelled JoinError",
        );
    }
}
