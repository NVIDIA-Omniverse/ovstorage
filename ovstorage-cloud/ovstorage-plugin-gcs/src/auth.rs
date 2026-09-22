// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! GCS credential discovery and bearer-token caching.
//!
//! Credentials come from the `SecretBundle` only: either an explicit
//! `service_account_key` (`service_account`, `authorized_user`,
//! `external_account`, or `impersonated_service_account` JSON), or an
//! empty bundle which yields `CredentialSource::Anonymous` (no token,
//! unsigned requests). Users who want gcloud-ADC-file or env-var auth wire
//! them in via the library's `SecretRef::File` / `SecretRef::FileJson`
//! TOML mechanism.
//!
//! Service-account creds sign a JWT-bearer assertion and exchange it for
//! an OAuth2 access token at `token_uri`. Authorized-user creds post a
//! `refresh_token` grant. External-account (workload identity federation)
//! creds read a subject token from a file or URL — re-fetched on EVERY
//! exchange, because federation platforms rotate it out from under a
//! running process — exchange it at the STS endpoint, and optionally hop
//! through `iamcredentials.googleapis.com` to impersonate a service
//! account. Impersonated creds mint their source credential's bearer
//! first and make the same impersonation hop. Bearers are cached behind
//! a `Mutex` until `REFRESH_LEEWAY` before `expires_in`.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime};

use ovstorage_plugin::connection::promotion::RefusalEpoch;
use ovstorage_plugin::{
    ConnectionId, Error, ErrorCode, ErrorContext, Result, SecretBundle, SecretValue,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

const SCOPE: &str = "https://www.googleapis.com/auth/devstorage.full_control https://www.googleapis.com/auth/pubsub";
const REFRESH_LEEWAY: Duration = Duration::from_secs(300);
const JWT_LIFETIME_SECS: u64 = 3600;
const USER_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const STS_TOKEN_URL: &str = "https://sts.googleapis.com/v1/token";
/// Scope requested on the federated (pre-impersonation) leg. The federated
/// token's only job is to call `generateAccessToken`, and IAM Credentials
/// requires `cloud-platform`; the storage scopes are requested on the
/// impersonated token instead.
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const STS_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const STS_REQUESTED_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Whether an auth-tagged error reason is the IdP REFUSING the grant, rather
/// than failing to answer it.
///
/// The token endpoint tags every non-2xx grant `token_exchange_http_{status}`
/// (see `decode_token_response`), so the status is the only discriminator
/// there is. 400 (`invalid_grant` / `invalid_client`, e.g. a revoked refresh
/// token) and 401 refuse the credential itself; 429 throttling and 5xx outages
/// are transient and must not count in either direction — with `refresh`
/// unsupported, treating one as a refusal would strand a valid credential.
///
/// `token_exchange_empty` joins them, and it is not a status: a `200` whose
/// `access_token` is absent, null, blank or not a string is a grant that
/// produced no credential, which is definitive however cheerfully it was
/// reported. A body that fails to parse at all is NOT in this set — that is a
/// truncated response or a proxy error page, which is a transport failure.
///
/// The impersonation hop (`impersonation_http_{status}` /
/// `impersonation_empty`, see [`decode_impersonation_response`]) joins with
/// the same status judgment — EXCEPT its 403, which is deliberately absent
/// here: on `iamcredentials` a 403 is a verdict on the principal-to-SA
/// *binding* (often IAM propagation lag minutes after setup), not on the
/// credential, so it must not latch. It still parks `verify` through the
/// driver's wider rejection set, which is why the hop needs its own tag: a
/// `token_exchange_http_403` would be indistinguishable from one served by
/// an IdP proxy on the primary grant, where this taxonomy keeps 403 fully
/// lenient.
///
/// One function because there is one LATCH judgment; the two consumers are
/// [`Authenticator::credential_refused`], which withholds a promotion on it,
/// and `GcsDriver`'s `reason_is_credential_rejection`, whose park set is a
/// superset (it adds `gcs_unauthorized`, `impersonation_http_403`, and every
/// `CredentialUnavailable`). **A reason left off both sets does not fail
/// closed.** `verify` reaches it through the driver's lenient arm — so an
/// unlisted definitive failure commits `Authenticated` instead of parking,
/// and with `refresh` unsupported and `update_connection_credentials`
/// refused, nothing can undo that.
pub(crate) fn reason_is_grant_refusal(reason: &str) -> bool {
    matches!(
        reason,
        "token_exchange_http_400"
            | "token_exchange_http_401"
            | "token_exchange_empty"
            | "impersonation_http_400"
            | "impersonation_http_401"
            | "impersonation_empty"
    )
}

/// [`reason_is_grant_refusal`] against an error's auth context.
fn error_is_grant_refusal(err: &Error) -> bool {
    match err.context() {
        Some(ErrorContext::Auth { reason, .. }) => {
            reason.as_deref().is_some_and(reason_is_grant_refusal)
        }
        _ => false,
    }
}

/// Identity material discovered from the bundle.
#[derive(Clone)]
pub enum CredentialSource {
    ServiceAccount(ServiceAccountKey),
    User(UserCredentials),
    /// Workload identity federation (`external_account` ADC JSON): a
    /// platform-issued subject token exchanged at the STS endpoint,
    /// optionally followed by a service-account impersonation hop.
    ExternalAccount(ExternalAccountCredentials),
    /// `impersonated_service_account` ADC JSON: a source credential's
    /// bearer spent on `iamcredentials.googleapis.com` to mint an
    /// access token for the named service account.
    Impersonated(ImpersonatedCredentials),
    /// No credentials provided — requests go out without an `Authorization`
    /// header. The server decides whether the bucket / object is publicly
    /// accessible.
    Anonymous,
}

impl fmt::Debug for CredentialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialSource::ServiceAccount(key) => {
                f.debug_tuple("ServiceAccount").field(key).finish()
            }
            CredentialSource::User(user) => f.debug_tuple("User").field(user).finish(),
            CredentialSource::ExternalAccount(ea) => {
                f.debug_tuple("ExternalAccount").field(ea).finish()
            }
            CredentialSource::Impersonated(imp) => {
                f.debug_tuple("Impersonated").field(imp).finish()
            }
            CredentialSource::Anonymous => f.write_str("Anonymous"),
        }
    }
}

impl CredentialSource {
    /// True only for credentials capable of producing a V4 RSA signature.
    /// External-account and impersonated credentials hold no private key,
    /// so their reads take the plugin-proxied arm instead of a signed
    /// redirect.
    #[allow(dead_code)]
    pub fn can_sign_urls(&self) -> bool {
        matches!(self, CredentialSource::ServiceAccount(_))
    }
}

#[derive(Clone, Deserialize)]
pub struct ServiceAccountKey {
    pub client_email: String,
    pub private_key: String,
    pub token_uri: String,
    #[serde(default)]
    pub private_key_id: Option<String>,
}

impl fmt::Debug for ServiceAccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountKey")
            .field("client_email", &self.client_email)
            .field("private_key", &"<redacted>")
            .field("token_uri", &self.token_uri)
            .field(
                "private_key_id",
                &redacted_option(self.private_key_id.as_ref()),
            )
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct UserCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    #[serde(default = "default_user_token_uri")]
    pub token_uri: String,
}

impl fmt::Debug for UserCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("token_uri", &self.token_uri)
            .finish()
    }
}

/// `external_account` ADC JSON, the shape written by
/// `gcloud iam workload-identity-pools create-cred-config` and by CI
/// integrations that assemble it by hand.
#[derive(Clone)]
pub struct ExternalAccountCredentials {
    /// Full workload-identity-pool provider resource, e.g.
    /// `//iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/P/providers/V`.
    pub audience: String,
    /// RFC 8693 type of the subject token, e.g.
    /// `urn:ietf:params:oauth:token-type:jwt` for an OIDC id token.
    pub subject_token_type: String,
    pub token_url: String,
    pub subject_source: SubjectTokenSource,
    /// `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/
    /// {email}:generateAccessToken`. Absent means the federated STS token is
    /// itself the bearer (the federated principal holds the bucket grants).
    pub impersonation_url: Option<String>,
    /// Requested impersonated-token lifetime, from the JSON's optional
    /// `service_account_impersonation.token_lifetime_seconds`.
    pub token_lifetime_seconds: Option<u64>,
}

/// Where the platform-issued subject token comes from. Re-fetched on every
/// exchange: federation platforms rotate the token out from under a running
/// process (a projected volume on GKE, a per-request endpoint on GitHub
/// Actions), so caching a read would strand refresh on a stale token.
#[derive(Clone)]
pub enum SubjectTokenSource {
    File {
        path: String,
        format: SubjectTokenFormat,
    },
    Url {
        url: String,
        /// Sent verbatim on the fetch. May carry an authorization header —
        /// treated as secret in every rendering.
        headers: Vec<(String, String)>,
        format: SubjectTokenFormat,
    },
}

#[derive(Clone)]
pub enum SubjectTokenFormat {
    Text,
    /// The source yields a JSON document; the subject token is the named
    /// top-level string field.
    Json {
        field: String,
    },
}

impl fmt::Debug for ExternalAccountCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalAccountCredentials")
            .field("audience", &self.audience)
            .field("subject_token_type", &self.subject_token_type)
            .field("token_url", &self.token_url)
            .field("subject_source", &self.subject_source)
            .field("impersonation_url", &self.impersonation_url)
            .finish()
    }
}

impl fmt::Debug for SubjectTokenSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubjectTokenSource::File { path, .. } => f.debug_tuple("File").field(path).finish(),
            SubjectTokenSource::Url { url, headers, .. } => {
                // The URL's query string is operator-controlled and may carry
                // a token; keep everything up to it. Header VALUES are secret
                // (GitHub's fetch authenticates via one); names are not.
                let visible = url.split_once('?').map_or(url.as_str(), |(base, _)| base);
                f.debug_struct("Url")
                    .field("url", &visible)
                    .field(
                        "headers",
                        &headers
                            .iter()
                            .map(|(name, _)| name.as_str())
                            .collect::<Vec<_>>(),
                    )
                    .finish()
            }
        }
    }
}

/// `impersonated_service_account` ADC JSON, the shape written by
/// `gcloud auth application-default login --impersonate-service-account`.
#[derive(Clone)]
pub struct ImpersonatedCredentials {
    pub impersonation_url: String,
    /// The credential that pays for the `generateAccessToken` call. Parsed
    /// recursively from the JSON's `source_credentials`; nesting another
    /// impersonation inside is rejected at parse time.
    pub source: Box<CredentialSource>,
    pub delegates: Vec<String>,
}

impl fmt::Debug for ImpersonatedCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImpersonatedCredentials")
            .field("impersonation_url", &self.impersonation_url)
            .field("source", &self.source)
            .field("delegates", &self.delegates)
            .finish()
    }
}

fn redacted_option(value: Option<&String>) -> Option<&'static str> {
    value.map(|_| "<redacted>")
}

fn default_user_token_uri() -> String {
    USER_TOKEN_URI.to_string()
}

#[derive(Clone)]
struct CachedToken {
    access_token: String,
    expires_at: SystemTime,
}

/// Per-backend bearer-token cache + credential source.
///
/// Lifecycle: the factory wraps the constructed value in `Arc<_>` and
/// then (when credentials are non-anonymous) installs a background
/// refresh task via [`Authenticator::install_background_refresh`]. The
/// task holds only a `Weak<Authenticator>`, so dropping the last `Arc`
/// lets the loop exit naturally on its next `upgrade()`; the
/// `JoinHandle` is also aborted on `Drop` so the task can't keep
/// running with a dangling `Weak`.
pub struct Authenticator {
    explicit: CredentialSource,
    cached: Mutex<Option<CachedToken>>,
    refresh_lock: AsyncMutex<()>,
    http: reqwest::Client,
    /// Handle to the background refresh task spawned by
    /// [`Authenticator::install_background_refresh`]. `std::sync::Mutex`
    /// (not `tokio::sync::Mutex`) because `Drop` is sync and must be
    /// able to reach the handle without awaiting.
    refresh_task: Mutex<Option<JoinHandle<()>>>,
    /// Advanced when the storage service refuses this connection's bearer.
    ///
    /// The credential is one object, so a refusal answered to anyone signing
    /// through this authenticator condemns it for everyone — including the
    /// Pub/Sub poller, which shares this `Arc` and is therefore SUBJECT to a
    /// condemnation it cannot itself record — its own transport is unwitnessed.
    /// A promotion witness snapshots this before its operation and requires it
    /// unchanged after, which asks "did a refusal land while I ran?" without
    /// caring who provoked it.
    ///
    /// It lives here rather than on the backend because `GcsDriver::verify`
    /// builds an ephemeral authenticator of its own: a probe's refusal is then
    /// the probe's, and parking is what it controls.
    refusals: RefusalEpoch,
    /// Latched when the IdP refuses a grant, cleared by the next grant it
    /// accepts.
    ///
    /// This covers the refusal [`Self::refusals`] cannot see. The
    /// background refresh talks to the IdP rather than to storage, so it
    /// advances no storage epoch however it overlaps an operation in time —
    /// and on failure it keeps the cached bearer, which storage goes on
    /// accepting until that bearer expires. An operation in that window
    /// genuinely sees an acceptance and no refusal, and would promote a
    /// credential the IdP has already refused.
    ///
    /// The cached bearer is deliberately left alone: it still works, and
    /// withholding the promotion is the whole of the response.
    ///
    /// The latch is bounded by that bearer's life rather than by the process's.
    /// A condition that refuses every grant — a revoked key, but also a host
    /// clock skewed far enough that the IdP rejects the JWT's `iat` — holds it
    /// set; but once the cached bearer expires `access_token` starts erroring
    /// and no request is signed at all, so there is nothing left for a stale
    /// latch to withhold.
    credential_refused: AtomicBool,
    /// Set once this connection has warned that a response carried no Google
    /// origin marker. The condition is static per deployment — a front door
    /// either stamps the header or it does not — while the warning site is on
    /// every response, so without this a header-stripping proxy would emit one
    /// line per object in a listing sweep.
    warned_unstamped: AtomicBool,
}

impl Drop for Authenticator {
    fn drop(&mut self) {
        // Abort the background refresh task so it can't outlive the
        // state it borrows via `Weak`. `try_lock` because Drop is
        // sync; if the lock happens to be contended (only
        // `install_background_refresh` takes it, and only briefly) the
        // runtime would abort the task on shutdown anyway.
        if let Ok(mut guard) = self.refresh_task.try_lock()
            && let Some(handle) = guard.take()
        {
            handle.abort();
        }
    }
}

impl Authenticator {
    /// Build an authenticator from the bundle. Empty bundle = `Anonymous`
    /// (unsigned requests, no token). Populated bundle resolves either
    /// `service_account_key` (inline JSON bytes) or `file_path` (path to a
    /// gcloud ADC JSON file) into a `CredentialSource`.
    pub fn new(bundle: &SecretBundle, http: reqwest::Client) -> Result<Self> {
        let explicit = if bundle.fields.is_empty() {
            CredentialSource::Anonymous
        } else if let Some(source) = explicit_service_account(bundle)? {
            source
        } else if let Some(source) = adc_file(bundle)? {
            source
        } else {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "GCS bundle is non-empty but contains no service_account_key or file_path",
            ));
        };
        Ok(Self {
            explicit,
            cached: Mutex::new(None),
            refresh_lock: AsyncMutex::new(()),
            http,
            refresh_task: Mutex::new(None),
            refusals: RefusalEpoch::default(),
            credential_refused: AtomicBool::new(false),
            warned_unstamped: AtomicBool::new(false),
        })
    }

    /// True if a real credential source is available (i.e. not anonymous).
    #[allow(dead_code)]
    pub fn has_eager_credentials(&self) -> bool {
        !matches!(self.explicit, CredentialSource::Anonymous)
    }

    /// How many times the storage service has refused this credential. A
    /// promotion witness snapshots this before its operation and requires it
    /// unchanged after.
    pub(crate) fn refusal_epoch(&self) -> u64 {
        self.refusals.get()
    }

    /// Record that the storage service refused this credential.
    pub(crate) fn note_refusal(&self) {
        self.refusals.bump();
    }

    /// Whether this connection has yet to warn about an unstamped response;
    /// claims the right to warn exactly once.
    pub(crate) fn claim_unstamped_warning(&self) -> bool {
        !self.warned_unstamped.swap(true, Ordering::Relaxed)
    }

    /// Whether the IdP refused this credential's most recent grant and has not
    /// since accepted one.
    pub(crate) fn credential_refused(&self) -> bool {
        self.credential_refused.load(Ordering::Relaxed)
    }

    /// True for connections that should send unsigned requests.
    pub fn is_anonymous(&self) -> bool {
        matches!(self.explicit, CredentialSource::Anonymous)
    }

    /// The fixed credential source set at construction time. There's no
    /// discovery chain anymore — empty bundles are anonymous, populated
    /// bundles carry an explicit service-account or user JSON.
    pub fn resolve_source(&self) -> Result<CredentialSource> {
        if matches!(self.explicit, CredentialSource::Anonymous) {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "GCS connection is anonymous; no credential source to resolve",
            ));
        }
        Ok(self.explicit.clone())
    }

    /// Fetch a valid bearer, reusing the cache while it has more than
    /// [`REFRESH_LEEWAY`] of life. Refreshes coalesce on `refresh_lock`
    /// (one network exchange per process; cross-process coalescing lives
    /// in the host's `AuthRefreshLock`, intentionally not pulled in here).
    /// Returns an empty string for anonymous connections; callers must
    /// skip applying the `Authorization` header when the token is empty.
    pub async fn access_token(&self) -> Result<String> {
        if matches!(self.explicit, CredentialSource::Anonymous) {
            return Ok(String::new());
        }
        if let Some(token) = self.live_cached_token() {
            debug!(plugin = "gcs", cache.hit = true, "gcs token cache hit");
            return Ok(token);
        }
        let _guard = self.refresh_lock.lock().await;
        if let Some(token) = self.live_cached_token() {
            debug!(
                plugin = "gcs",
                cache.hit = true,
                "gcs token cache hit (post-lock)"
            );
            return Ok(token);
        }
        let (token, _ttl) = self.refresh_now_locked().await?;
        Ok(token)
    }

    /// Force a token refresh and return the new `(access_token, ttl)`.
    /// Coalesces with concurrent callers on `refresh_lock`. Used by
    /// the background refresh task to drive proactive refreshes ahead
    /// of expiry. Errors out on anonymous connections (the loop never
    /// spawns for them, but the guard keeps misuse from leaving an
    /// empty token in the cache).
    pub async fn refresh_now(&self) -> Result<(String, Duration)> {
        if matches!(self.explicit, CredentialSource::Anonymous) {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "GCS connection is anonymous; nothing to refresh",
            ));
        }
        let _guard = self.refresh_lock.lock().await;
        self.refresh_now_locked().await
    }

    /// Inner refresh body — caller must hold `refresh_lock`. Dispatches
    /// on the credential source, updates the cache, and returns the
    /// freshly-issued `(access_token, ttl)` pair.
    async fn refresh_now_locked(&self) -> Result<(String, Duration)> {
        debug!(
            plugin = "gcs",
            cache.hit = false,
            "gcs token refresh triggered"
        );
        let source = self.resolve_source()?;
        let outcome = match &source {
            CredentialSource::ServiceAccount(sa) => self.exchange_jwt(sa).await,
            CredentialSource::User(user) => self.exchange_refresh_token(user).await,
            CredentialSource::ExternalAccount(ea) => self.exchange_external_account(ea).await,
            CredentialSource::Impersonated(imp) => self.exchange_impersonated(imp).await,
            CredentialSource::Anonymous => unreachable!("checked above"),
        };
        let response = match outcome {
            Ok(response) => {
                // A grant the IdP accepted clears any earlier refusal: the
                // credential is demonstrably live again.
                self.credential_refused.store(false, Ordering::Relaxed);
                response
            }
            Err(err) => {
                // Only a DEFINITIVE refusal latches. A throttle or an outage is
                // not evidence about the credential, and latching one would
                // withhold every later promotion from a credential that works —
                // `refresh` being `Unsupported`, nothing would ever clear it.
                if error_is_grant_refusal(&err) {
                    self.credential_refused.store(true, Ordering::Relaxed);
                }
                warn!(plugin = "gcs", error.code = ?err.code(), "gcs token refresh failed");
                return Err(err);
            }
        };
        // Intentionally not logging the access_token value.
        let access_token = response.access_token.clone();
        let ttl = Duration::from_secs(response.expires_in.max(REFRESH_LEEWAY.as_secs() + 1));
        let expires_at = SystemTime::now() + ttl;
        *self.cached.lock().unwrap() = Some(CachedToken {
            access_token: access_token.clone(),
            expires_at,
        });
        Ok((access_token, ttl))
    }

    /// Spawn a background task that proactively refreshes the bearer
    /// at ~90% of TTL with a 30s retry cadence on failure. No-op for
    /// anonymous connections (no token to refresh) and idempotent for
    /// repeat installs (aborts any prior task first so the loop
    /// re-bases on the latest TTL).
    ///
    /// The task holds only `Weak<Authenticator>` so it doesn't keep
    /// the state alive past its natural drop. `Drop for Authenticator`
    /// aborts the `JoinHandle`; any in-flight `upgrade()` after the
    /// strong-count hits zero returns `None` and the loop exits.
    ///
    /// `ttl` is the initial sleep — pass the TTL from a known
    /// fresh-token exchange, or [`Self::DEFAULT_REFRESH_INTERVAL`]
    /// when no token has been issued yet (the loop will refresh once
    /// and re-base on the IDP's reported expiry).
    pub fn install_background_refresh(self: &Arc<Self>, ttl: Duration) {
        if matches!(self.explicit, CredentialSource::Anonymous) {
            return;
        }
        // Some tests construct an Authenticator and call this
        // synchronously from a non-tokio context. Skip the spawn in
        // that case — there's no runtime to host the loop.
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

    /// Default initial-sleep cadence used when the factory installs the
    /// background refresh before any token has been minted (so we have
    /// no IDP-reported TTL to base on). After the first refresh the
    /// loop re-bases on the freshly-issued TTL.
    pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 30);

    fn live_cached_token(&self) -> Option<String> {
        let guard = self.cached.lock().unwrap();
        guard.as_ref().and_then(|cached| {
            let now = SystemTime::now();
            match cached.expires_at.duration_since(now) {
                Ok(remaining) if remaining > REFRESH_LEEWAY => Some(cached.access_token.clone()),
                _ => None,
            }
        })
    }

    async fn exchange_jwt(&self, sa: &ServiceAccountKey) -> Result<GrantedToken> {
        self.exchange_jwt_scoped(sa, SCOPE).await
    }

    /// JWT-bearer exchange with a caller-chosen scope. The storage scopes
    /// are the norm; an impersonation SOURCE instead needs `cloud-platform`
    /// to be allowed onto `iamcredentials.googleapis.com`.
    async fn exchange_jwt_scoped(
        &self,
        sa: &ServiceAccountKey,
        scope: &str,
    ) -> Result<GrantedToken> {
        let assertion = build_service_account_jwt_scoped(sa, scope)?;
        let form = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ];
        let response = self
            .http
            .post(&sa.token_uri)
            .form(&form)
            .send()
            .await
            .map_err(map_token_transport)?;
        decode_token_response(response).await
    }

    async fn exchange_refresh_token(&self, user: &UserCredentials) -> Result<GrantedToken> {
        let form = [
            ("grant_type", "refresh_token"),
            ("client_id", user.client_id.as_str()),
            ("client_secret", user.client_secret.as_str()),
            ("refresh_token", user.refresh_token.as_str()),
        ];
        let response = self
            .http
            .post(&user.token_uri)
            .form(&form)
            .send()
            .await
            .map_err(map_token_transport)?;
        decode_token_response(response).await
    }

    /// Workload-identity-federation exchange: subject token → STS federated
    /// token → (optionally) impersonated service-account token.
    async fn exchange_external_account(
        &self,
        ea: &ExternalAccountCredentials,
    ) -> Result<GrantedToken> {
        // With an impersonation hop the federated token only has to reach
        // IAM Credentials; without one it IS the storage bearer and needs
        // the storage scopes directly.
        let scope = if ea.impersonation_url.is_some() {
            CLOUD_PLATFORM_SCOPE
        } else {
            SCOPE
        };
        self.exchange_external_account_scoped(ea, scope).await
    }

    /// [`Self::exchange_external_account`] with a caller-chosen STS scope.
    /// The impersonated-credential path forces `cloud-platform` here: its
    /// external-account SOURCE never impersonates (parse rejects that), so
    /// the natural scope choice above would pick the storage scopes — and a
    /// storage-scoped bearer is refused by `generateAccessToken`.
    async fn exchange_external_account_scoped(
        &self,
        ea: &ExternalAccountCredentials,
        scope: &str,
    ) -> Result<GrantedToken> {
        let subject_token = self.fetch_subject_token(&ea.subject_source).await?;
        let form = [
            ("grant_type", STS_GRANT_TYPE),
            ("audience", ea.audience.as_str()),
            ("scope", scope),
            ("requested_token_type", STS_REQUESTED_TOKEN_TYPE),
            ("subject_token", subject_token.as_str()),
            ("subject_token_type", ea.subject_token_type.as_str()),
        ];
        let response = self
            .http
            .post(&ea.token_url)
            .form(&form)
            .send()
            .await
            .map_err(map_token_transport)?;
        let federated = decode_token_response(response).await?;
        let Some(impersonation_url) = ea.impersonation_url.as_deref() else {
            return Ok(federated);
        };
        self.generate_access_token(
            impersonation_url,
            &federated.access_token,
            ea.token_lifetime_seconds.unwrap_or(JWT_LIFETIME_SECS),
        )
        .await
    }

    /// `impersonated_service_account` exchange: mint the source credential's
    /// bearer, then spend it on the impersonation hop.
    async fn exchange_impersonated(&self, imp: &ImpersonatedCredentials) -> Result<GrantedToken> {
        let source = match imp.source.as_ref() {
            CredentialSource::ServiceAccount(sa) => {
                self.exchange_jwt_scoped(sa, CLOUD_PLATFORM_SCOPE).await?
            }
            CredentialSource::User(user) => self.exchange_refresh_token(user).await?,
            // Forced to cloud-platform: this bearer's only job is the
            // generateAccessToken call below, which refuses storage-scoped
            // callers.
            CredentialSource::ExternalAccount(ea) => {
                self.exchange_external_account_scoped(ea, CLOUD_PLATFORM_SCOPE)
                    .await?
            }
            // parse_credentials_json rejects nested impersonation and an
            // anonymous source cannot be spelled in ADC JSON.
            CredentialSource::Impersonated(_) | CredentialSource::Anonymous => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "GCS impersonated credentials carry an unsupported source",
                ));
            }
        };
        self.generate_access_token_with_delegates(
            &imp.impersonation_url,
            &source.access_token,
            JWT_LIFETIME_SECS,
            &imp.delegates,
        )
        .await
    }

    /// Fetch the platform-issued subject token, fresh on every call.
    /// Failures here are the PLATFORM being unavailable, not the IdP
    /// refusing a grant, so they carry no auth reason and never latch.
    async fn fetch_subject_token(&self, source: &SubjectTokenSource) -> Result<String> {
        let (raw, format, origin) = match source {
            SubjectTokenSource::File { path, format } => {
                let expanded = expand_tilde(path);
                let contents = std::fs::read(&expanded).map_err(|err| {
                    Error::new(
                        ErrorCode::CredentialUnavailable,
                        format!("failed to read GCS subject-token file '{expanded}': {err}"),
                    )
                })?;
                (contents, format, format!("file '{expanded}'"))
            }
            SubjectTokenSource::Url {
                url,
                headers,
                format,
            } => {
                let mut request = self.http.get(url);
                for (name, value) in headers {
                    request = request.header(name, value);
                }
                // `without_url()`: reqwest embeds the full request URL in its
                // transport errors, and this URL's query string is
                // operator-controlled and may carry a token (the same reason
                // the Debug impl truncates it at `?`).
                let response = request.send().await.map_err(|err| {
                    Error::new(
                        ErrorCode::CredentialUnavailable,
                        format!(
                            "GCS subject-token endpoint transport error: {}",
                            err.without_url()
                        ),
                    )
                })?;
                let status = response.status();
                let body = response.bytes().await.unwrap_or_default();
                if !status.is_success() {
                    // The endpoint is not the IdP; its body gets the same
                    // suppression as every other provider body.
                    return Err(Error::new(
                        ErrorCode::CredentialUnavailable,
                        format!(
                            "GCS subject-token endpoint answered HTTP {status}; {} byte body suppressed",
                            body.len()
                        ),
                    ));
                }
                (body.to_vec(), format, "endpoint response".to_string())
            }
        };
        let token = match format {
            SubjectTokenFormat::Text => String::from_utf8(raw)
                .map_err(|_| {
                    Error::new(
                        ErrorCode::CredentialUnavailable,
                        format!("GCS subject token from {origin} is not UTF-8"),
                    )
                })?
                .trim()
                .to_string(),
            SubjectTokenFormat::Json { field } => {
                let value: serde_json::Value = serde_json::from_slice(&raw).map_err(|err| {
                    Error::new(
                        ErrorCode::CredentialUnavailable,
                        format!(
                            "GCS subject token from {origin} is not JSON: {}",
                            crate::error_body::decode_failure(&err, raw.len())
                        ),
                    )
                })?;
                value
                    .get(field)
                    .and_then(|token| token.as_str())
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            }
        };
        if token.is_empty() {
            return Err(Error::new(
                ErrorCode::CredentialUnavailable,
                format!("GCS subject token from {origin} is empty"),
            ));
        }
        Ok(token)
    }

    async fn generate_access_token(
        &self,
        impersonation_url: &str,
        bearer: &str,
        lifetime_seconds: u64,
    ) -> Result<GrantedToken> {
        self.generate_access_token_with_delegates(impersonation_url, bearer, lifetime_seconds, &[])
            .await
    }

    /// The `iamcredentials.googleapis.com` … `:generateAccessToken` hop
    /// shared by external-account impersonation and
    /// `impersonated_service_account` credentials.
    async fn generate_access_token_with_delegates(
        &self,
        impersonation_url: &str,
        bearer: &str,
        lifetime_seconds: u64,
        delegates: &[String],
    ) -> Result<GrantedToken> {
        let mut body = serde_json::json!({
            "scope": SCOPE.split(' ').collect::<Vec<_>>(),
            "lifetime": format!("{lifetime_seconds}s"),
        });
        if !delegates.is_empty() {
            body["delegates"] = serde_json::json!(delegates);
        }
        let response = self
            .http
            .post(impersonation_url)
            .bearer_auth(bearer)
            .json(&body)
            .send()
            .await
            .map_err(map_token_transport)?;
        decode_impersonation_response(response).await
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

/// Cadence used by [`refresh_loop`] for retry sleeps after a failed
/// refresh. Short enough that one IDP blip doesn't leave the token
/// expired for the rest of its lifetime, long enough not to hammer
/// the IDP under sustained failures.
const REFRESH_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Background refresh loop spawned by
/// [`Authenticator::install_background_refresh`]. Owns only a
/// `Weak<Authenticator>` so it doesn't keep the state alive past its
/// natural drop — `Drop for Authenticator` aborts the `JoinHandle`,
/// and any in-flight upgrade attempt returns `None` after the
/// strong-count hits zero.
///
/// Each iteration:
/// 1. Sleep until the next refresh deadline — `refresh_sleep_for(ttl)`
///    on the first iteration (and after successful refreshes), or
///    [`REFRESH_RETRY_INTERVAL`] after a failed grant.
/// 2. Try to upgrade the `Weak`; on failure (state dropped), exit.
/// 3. Drive [`Authenticator::refresh_now`].
/// 4. On grant success, re-base the next sleep on the new TTL. On
///    failure, switch the next sleep to the short retry interval so a
///    single failure doesn't strand the token expired for most of its
///    remaining lifetime.
async fn refresh_loop(weak: Weak<Authenticator>, initial_ttl: Duration) {
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
                    plugin = "gcs",
                    error.code = ?err.code(),
                    "gcs: background refresh failed; will retry in 30s",
                );
                next_sleep = REFRESH_RETRY_INTERVAL;
            }
        }
    }
}

/// The two fields the token exchange uses.
///
/// Deserialized rather than read out of a `serde_json::Value`, and the reason is
/// allocation: serde discards unknown fields as it parses, so a token endpoint
/// answering with a large document costs only these two, where a DOM would cost
/// the whole tree on top of the already-buffered body. The azure sibling's
/// success path is the same shape for the same reason. **Do not replace this
/// with `Value`,** and do not window the body instead — truncating a SUCCESS
/// response does not lose a diagnostic, it loses the bearer, and an
/// operator-supplied IdP proxy returning a JWT access token with group claims
/// is exactly the deployment that would hit it.
///
/// `access_token` is `Value` rather than `String` so that absent, `null` and
/// non-string all arrive as ONE condition — "no usable bearer" — instead of two
/// of them being decode failures that take the lenient arm. That field is the
/// credential itself, so its size is not a bound worth having.
/// A grant that produced a usable bearer — the only shape
/// [`decode_token_response`] hands back, so no caller can see an unvalidated
/// one.
struct GrantedToken {
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: Option<serde_json::Value>,
    /// Accepted as a number or a decimal string: loose OAuth servers emit the
    /// latter alongside a perfectly good bearer, and an unrelated field's type
    /// must not condemn one.
    #[serde(default, deserialize_with = "expires_in_number_or_string")]
    expires_in: u64,
}

fn expires_in_number_or_string<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(number) => Ok(number.as_u64().unwrap_or_default()),
        serde_json::Value::String(text) => Ok(text.parse().unwrap_or_default()),
        _ => Ok(0),
    }
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// Redacted for the same reason as [`TokenResponse`]: this is the type that
/// carries the validated bearer, so it is the one a `{:?}` in an error path
/// would leak.
impl fmt::Debug for GrantedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantedToken")
            .field("access_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

async fn decode_token_response(response: reqwest::Response) -> Result<GrantedToken> {
    let status = response.status();
    // Raw bytes, not `text()`: a lossy decode expands each invalid byte to a
    // three-byte U+FFFD, which would make the suppressed-length report a lie
    // about what the endpoint actually sent.
    let body = response.bytes().await.unwrap_or_default();
    if !status.is_success() {
        // The identity provider's body is subject to the same rule as a storage
        // error body: an OAuth failure echoes `error_description`, which carries
        // the rejected assertion. Only the top-level `error` code escapes.
        let detail = match ovstorage_plugin::provider_error::json_code(&body, "/error") {
            Some(code) => code,
            None => format!(
                "no provider error code; {} byte body suppressed",
                body.len()
            ),
        };
        return Err(Error::new(
            ErrorCode::AuthRequired,
            format!("GCS token exchange failed with HTTP {status}: {detail}"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some(format!("token_exchange_http_{}", status.as_u16())),
            expired_at: None,
        }));
    }
    // The SUCCESS path carries the access token, so its decode failure is the
    // most sensitive one here: `serde_json`'s `Display` can embed a slice of a
    // body that holds a live credential. Report classification and position
    // instead. (Reading the body as an untyped document removes the `invalid
    // type` failure that embedded the offending value verbatim. The sanitizer
    // is what makes redaction a property of the REPORTING rather than of which
    // parse failures happen to be reachable, which is the only claim here worth
    // relying on — the reachable set is a serde implementation detail.)
    // A decode failure stays a lenient `Internal`, deliberately. Only the ONE
    // shape that is definitively a credential failure — a grant that produced no
    // bearer — is tagged below. A truncated body is a transport failure, and a
    // document whose unrelated fields are odd carries a perfectly good bearer;
    // parking permanently on either would strand a working credential, `refresh`
    // being `Unsupported`.
    let parsed: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "GCS token response was not JSON: {}",
                crate::error_body::decode_failure(&err, body.len())
            ),
        )
    })?;

    // An absent, null, non-string or blank bearer is not a credential. Caching
    // one would leave the connection reporting a credential source while
    // `maybe_bearer_auth` silently omits the header, so every request would go
    // out unsigned — and any 200 a public object returned would then look like
    // proof that the credential works. All four shapes are one condition here.
    let access_token = parsed
        .access_token
        .as_ref()
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    if access_token.is_empty() {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "GCS token exchange returned no usable access_token",
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("token_exchange_empty".into()),
            expired_at: None,
        }));
    }
    Ok(GrantedToken {
        access_token,
        expires_in: parsed.expires_in,
    })
}

/// Decode a `generateAccessToken` response. The success shape differs from
/// OAuth (`accessToken` + RFC 3339 `expireTime` instead of `access_token` +
/// `expires_in`), and the reason tags are the hop's own
/// (`impersonation_http_{status}` / `impersonation_empty`): 400/401/empty
/// join [`reason_is_grant_refusal`]'s latch set, while the 403 arm — a
/// verdict on the principal-to-SA binding rather than the credential — must
/// park `verify` without latching, which a shared `token_exchange_*` tag
/// could not express. Body suppression follows the same rules as the OAuth
/// path, because an IAM error `message` echoes the caller's request the way
/// `error_description` echoes an assertion.
async fn decode_impersonation_response(response: reqwest::Response) -> Result<GrantedToken> {
    let status = response.status();
    let body = response.bytes().await.unwrap_or_default();
    if !status.is_success() {
        // IAM errors nest the code (`{"error": {"status": "..."}}`); a
        // front-door proxy may still answer in the flat OAuth shape.
        let detail = ovstorage_plugin::provider_error::json_code(&body, "/error/status")
            .or_else(|| ovstorage_plugin::provider_error::json_code(&body, "/error"))
            .unwrap_or_else(|| {
                format!(
                    "no provider error code; {} byte body suppressed",
                    body.len()
                )
            });
        return Err(Error::new(
            ErrorCode::AuthRequired,
            format!("GCS service-account impersonation failed with HTTP {status}: {detail}"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some(format!("impersonation_http_{}", status.as_u16())),
            expired_at: None,
        }));
    }
    let parsed: ImpersonationResponse = serde_json::from_slice(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "GCS impersonation response was not JSON: {}",
                crate::error_body::decode_failure(&err, body.len())
            ),
        )
    })?;
    let access_token = parsed
        .access_token
        .as_ref()
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .trim()
        .to_string();
    if access_token.is_empty() {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "GCS service-account impersonation returned no usable accessToken",
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("impersonation_empty".into()),
            expired_at: None,
        }));
    }
    // An absent or unparseable expireTime must not condemn a working bearer
    // (the same rule a string expires_in follows): fall back to the
    // requested lifetime's documented default and let the leeway logic cope.
    // A PARSEABLE expireTime is honored even when it is already in the past
    // (clock skew, a stale front-door answer): it clamps to zero rather than
    // riding the fallback, so the caching window stays the leeway minimum
    // instead of an hour of a bearer the server said is dead.
    let expires_in = match parsed.expire_time.as_deref().and_then(|text| {
        time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).ok()
    }) {
        Some(expiry) => {
            let now = time::OffsetDateTime::now_utc();
            u64::try_from((expiry - now).whole_seconds()).unwrap_or(0)
        }
        None => JWT_LIFETIME_SECS,
    };
    Ok(GrantedToken {
        access_token,
        expires_in,
    })
}

#[derive(Deserialize)]
struct ImpersonationResponse {
    #[serde(default, rename = "accessToken")]
    access_token: Option<serde_json::Value>,
    #[serde(default, rename = "expireTime")]
    expire_time: Option<String>,
}

impl fmt::Debug for ImpersonationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImpersonationResponse")
            .field("access_token", &"<redacted>")
            .field("expire_time", &self.expire_time)
            .finish()
    }
}

fn map_token_transport(err: reqwest::Error) -> Error {
    // `without_url()`: reqwest embeds the full request URL in transport
    // errors, and every endpoint that reaches this mapper is
    // operator-controlled (token_uri, token_url, the impersonation URL) —
    // a query string there may carry a secret.
    Error::new(
        ErrorCode::AuthRequired,
        format!("GCS token exchange transport error: {}", err.without_url()),
    )
    .with_context(ErrorContext::Auth {
        connection_id: ConnectionId(String::new()),
        reason: Some("token_transport".into()),
        expired_at: None,
    })
}

/// Mint the JWT bearer assertion per
/// <https://developers.google.com/identity/protocols/oauth2/service-account#jwt-auth>.
fn build_service_account_jwt_scoped(sa: &ServiceAccountKey, scope: &str) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|err| Error::new(ErrorCode::Internal, err.to_string()))?
        .as_secs();
    let claims = JwtClaims {
        iss: sa.client_email.clone(),
        scope: scope.to_string(),
        aud: sa.token_uri.clone(),
        iat: now,
        exp: now + JWT_LIFETIME_SECS,
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = sa.private_key_id.clone();
    let encoding_key =
        jsonwebtoken::EncodingKey::from_rsa_pem(sa.private_key.as_bytes()).map_err(|err| {
            Error::new(
                ErrorCode::CredentialUnavailable,
                format!("GCS service-account private key is not RSA PEM: {err}"),
            )
        })?;
    jsonwebtoken::encode(&header, &claims, &encoding_key).map_err(|err| {
        Error::new(
            ErrorCode::CredentialUnavailable,
            format!("failed to sign GCS service-account JWT: {err}"),
        )
    })
}

#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

fn explicit_service_account(bundle: &SecretBundle) -> Result<Option<CredentialSource>> {
    let Some(value) = bundle.fields.get("service_account_key") else {
        return Ok(None);
    };
    let bytes = match value {
        SecretValue::Bytes(secret) | SecretValue::File(secret) => secret.0.clone(),
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "GCS credential field 'service_account_key' must be secret bytes or a file",
            ));
        }
    };
    let source = parse_credentials_json(&bytes)?;
    Ok(Some(source))
}

fn adc_file(bundle: &SecretBundle) -> Result<Option<CredentialSource>> {
    let Some(value) = bundle.fields.get("file_path") else {
        return Ok(None);
    };
    let bytes = match value {
        SecretValue::Bytes(secret) | SecretValue::File(secret) => &secret.0,
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "GCS credential field 'file_path' must be a text value",
            ));
        }
    };
    let path_text = std::str::from_utf8(bytes).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "GCS credential field 'file_path' must be UTF-8",
        )
    })?;
    let trimmed = path_text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let expanded = expand_tilde(trimmed);
    let contents = std::fs::read(&expanded).map_err(|err| {
        Error::new(
            ErrorCode::NotConfigured,
            format!("failed to read GCS ADC file '{expanded}': {err}"),
        )
    })?;
    Ok(Some(parse_credentials_json(&contents)?))
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = home_dir()
    {
        let mut out = home;
        out.push(rest);
        return out.to_string_lossy().into_owned();
    }
    path.to_string()
}

fn home_dir() -> Option<std::path::PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Some(std::path::PathBuf::from(home));
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return Some(std::path::PathBuf::from(profile));
    }
    let drive = std::env::var_os("HOMEDRIVE")?;
    let path = std::env::var_os("HOMEPATH")?;
    let mut out = std::path::PathBuf::from(drive);
    out.push(path);
    Some(out)
}

/// Parse an ADC JSON blob: `service_account`, `authorized_user`,
/// `external_account`, or `impersonated_service_account`.
pub fn parse_credentials_json(bytes: &[u8]) -> Result<CredentialSource> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("GCS credentials JSON is not valid JSON: {err}"),
        )
    })?;
    parse_credentials_value(value, false)
}

fn parse_credentials_value(value: serde_json::Value, nested: bool) -> Result<CredentialSource> {
    let key_type = value
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("service_account");
    match key_type {
        "service_account" => {
            let key: ServiceAccountKey = serde_json::from_value(value).map_err(|err| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("GCS service-account JSON is missing required fields: {err}"),
                )
            })?;
            Ok(CredentialSource::ServiceAccount(key))
        }
        "authorized_user" => {
            let user: UserCredentials = serde_json::from_value(value).map_err(|err| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("GCS user credentials JSON is missing required fields: {err}"),
                )
            })?;
            Ok(CredentialSource::User(user))
        }
        "external_account" => Ok(CredentialSource::ExternalAccount(parse_external_account(
            value,
        )?)),
        "impersonated_service_account" => {
            if nested {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "GCS impersonated credentials cannot nest another impersonation",
                ));
            }
            let object = value.as_object().ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "GCS impersonated credentials JSON must be an object",
                )
            })?;
            let impersonation_url =
                required_string_field(object, "service_account_impersonation_url")?;
            require_google_endpoint(&impersonation_url, "service_account_impersonation_url")?;
            let source_value = object.get("source_credentials").cloned().ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "GCS impersonated credentials JSON is missing source_credentials",
                )
            })?;
            let source = parse_credentials_value(source_value, true)?;
            // An external-account source that itself impersonates would put
            // two impersonation hops in one credential — the same cycle risk
            // the `nested` guard exists for, spelled differently. Its exchange
            // would also hand this hop a storage-scoped bearer.
            if let CredentialSource::ExternalAccount(ea) = &source
                && ea.impersonation_url.is_some()
            {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "GCS impersonated credentials cannot nest an external_account that itself impersonates",
                ));
            }
            // Fail closed like every other credential field: a silently
            // filtered delegate chain is a DIFFERENT generateAccessToken
            // request — potentially direct impersonation without the
            // intended chain — not a tolerable reading of a malformed file.
            let delegates = match object.get("delegates") {
                None => Vec::new(),
                Some(serde_json::Value::Array(list)) => {
                    let mut delegates = Vec::with_capacity(list.len());
                    for entry in list {
                        let delegate = entry
                            .as_str()
                            .map(str::trim)
                            .filter(|text| !text.is_empty())
                            .ok_or_else(|| {
                                Error::new(
                                    ErrorCode::InvalidArgument,
                                    "GCS impersonated credentials 'delegates' entries must be non-empty strings",
                                )
                            })?;
                        delegates.push(delegate.to_string());
                    }
                    delegates
                }
                Some(_) => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "GCS impersonated credentials 'delegates' must be an array of non-empty strings when present",
                    ));
                }
            };
            Ok(CredentialSource::Impersonated(ImpersonatedCredentials {
                impersonation_url,
                source: Box::new(source),
                delegates,
            }))
        }
        other => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unsupported GCS credentials type '{other}'"),
        )),
    }
}

/// Loopback endpoints pass every gate below: unit tests and local emulators
/// speak plain HTTP on 127.0.0.1, and nothing reachable there is an
/// exfiltration target.
fn url_is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// `token_url` and the impersonation URLs must be Google's own endpoints (or
/// loopback). Unlike a `service_account` private key, an `external_account`
/// JSON is *configuration* in the wider Google ecosystem — documented as
/// non-secret and routinely copied around — and `token_url` is where the
/// locally-read subject token gets POSTed, so accepting an arbitrary host
/// there turns a shared config file into a local-file-read-plus-exfiltrate
/// primitive. Google's own auth libraries validate these fields the same way.
fn require_google_endpoint(url_text: &str, field: &str) -> Result<()> {
    let parsed = url::Url::parse(url_text).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("GCS external-account '{field}' is not a valid URL"),
        )
    })?;
    if url_is_loopback(&parsed) {
        return Ok(());
    }
    let host = parsed.host_str().unwrap_or_default();
    if parsed.scheme() == "https" && (host == "googleapis.com" || host.ends_with(".googleapis.com"))
    {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        format!("GCS external-account '{field}' must be an https *.googleapis.com endpoint"),
    ))
}

/// `credential_source.url` cannot be pinned to Google (GitHub's token
/// endpoint lives on `*.actions.githubusercontent.com`), but it must be
/// https or loopback: the GCE metadata server — plain http on a link-local
/// address — must not become reachable through a credential file, with or
/// without the caller-chosen headers this field carries.
fn require_https_or_loopback(url_text: &str, field: &str) -> Result<()> {
    let parsed = url::Url::parse(url_text).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("GCS external-account '{field}' is not a valid URL"),
        )
    })?;
    if url_is_loopback(&parsed) || parsed.scheme() == "https" {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        format!("GCS external-account '{field}' must be https (or loopback)"),
    ))
}

/// A field that must be a non-empty string WHEN PRESENT. Absence is the
/// caller's business; a present null / non-string / blank value fails closed
/// instead of silently reading as absent — for `service_account_impersonation_url`
/// that silent reading would return the federated token under the wrong
/// identity rather than reject the malformed credential.
fn optional_string_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<&'a str>> {
    match object.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(Some)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "GCS credentials field '{key}' must be a non-empty string when present"
                    ),
                )
            }),
    }
}

fn parse_external_account(value: serde_json::Value) -> Result<ExternalAccountCredentials> {
    let object = value.as_object().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "GCS external-account credentials JSON must be an object",
        )
    })?;
    let audience = required_string_field(object, "audience")?;
    // Workforce (user-identity) federation exchanges carry an extra
    // `options={"userProject":...}` STS parameter this client does not send,
    // so a workforce config would parse fine and then fail every refresh.
    // Reject it up front instead of advertising support.
    if audience.contains("/workforcePools/") || object.contains_key("workforce_pool_user_project") {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "GCS external-account workforce identity federation is not supported; only workload identity pools are",
        ));
    }
    let subject_token_type = required_string_field(object, "subject_token_type")?;
    let token_url = optional_string_field(object, "token_url")?
        .map(str::to_string)
        .unwrap_or_else(|| STS_TOKEN_URL.to_string());
    require_google_endpoint(&token_url, "token_url")?;
    let source_object = object
        .get("credential_source")
        .and_then(|source| source.as_object())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "GCS external-account credentials JSON is missing credential_source",
            )
        })?;
    // The AWS flavor identifies itself with environment_id rather than a
    // distinct type; name it so the operator learns which flavor was
    // rejected rather than just that a file/url was missing.
    if source_object.contains_key("environment_id") {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "GCS external-account AWS credential_source is not supported; only file- and url-sourced subject tokens are",
        ));
    }
    if source_object.contains_key("executable") {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "GCS external-account executable credential_source is not supported; only file- and url-sourced subject tokens are",
        ));
    }
    let format = parse_subject_token_format(source_object)?;
    let subject_source = if let Some(path) = source_object.get("file").and_then(|f| f.as_str()) {
        SubjectTokenSource::File {
            path: path.to_string(),
            format,
        }
    } else if let Some(url) = source_object.get("url").and_then(|u| u.as_str()) {
        require_https_or_loopback(url, "credential_source.url")?;
        let headers = source_object
            .get("headers")
            .and_then(|headers| headers.as_object())
            .map(|headers| {
                headers
                    .iter()
                    .filter_map(|(name, value)| {
                        value.as_str().map(|text| (name.clone(), text.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        SubjectTokenSource::Url {
            url: url.to_string(),
            headers,
            format,
        }
    } else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "GCS external-account credential_source must name a file or a url",
        ));
    };
    let token_lifetime_seconds = object
        .get("service_account_impersonation")
        .and_then(|options| options.get("token_lifetime_seconds"))
        .and_then(|lifetime| lifetime.as_u64());
    let impersonation_url =
        match optional_string_field(object, "service_account_impersonation_url")? {
            None => None,
            Some(url) => {
                require_google_endpoint(url, "service_account_impersonation_url")?;
                Some(url.to_string())
            }
        };
    Ok(ExternalAccountCredentials {
        audience,
        subject_token_type,
        token_url,
        subject_source,
        impersonation_url,
        token_lifetime_seconds,
    })
}

fn parse_subject_token_format(
    source_object: &serde_json::Map<String, serde_json::Value>,
) -> Result<SubjectTokenFormat> {
    let Some(format) = source_object.get("format") else {
        return Ok(SubjectTokenFormat::Text);
    };
    let format_type = format
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("text");
    match format_type {
        "text" => Ok(SubjectTokenFormat::Text),
        "json" => {
            let field = format
                .get("subject_token_field_name")
                .and_then(|name| name.as_str())
                .map(str::to_string)
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "GCS external-account json credential_source format requires subject_token_field_name",
                    )
                })?;
            Ok(SubjectTokenFormat::Json { field })
        }
        other => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unsupported GCS external-account credential_source format '{other}'"),
        )),
    }
}

fn required_string_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String> {
    object
        .get(key)
        .and_then(|value| value.as_str())
        .filter(|text| !text.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("GCS credentials JSON is missing required field '{key}'"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    const SYNTHETIC_PEM: &str = include_str!("../tests/synthetic_rsa_pkcs8.pem");

    fn test_service_account() -> ServiceAccountKey {
        ServiceAccountKey {
            client_email: "tester@example.iam.gserviceaccount.com".into(),
            private_key: SYNTHETIC_PEM.into(),
            token_uri: "https://oauth2.example/token".into(),
            private_key_id: Some("kid-1".into()),
        }
    }

    #[test]
    fn jwt_header_and_claims_match_google_documented_shape() {
        let sa = test_service_account();
        let token = build_service_account_jwt_scoped(&sa, SCOPE).expect("jwt");
        let mut parts = token.split('.');
        let header_b64 = parts.next().expect("header part");
        let payload_b64 = parts.next().expect("payload part");
        let signature_b64 = parts.next().expect("signature part");
        assert!(parts.next().is_none());

        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .expect("base64 header");
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .expect("base64 payload");
        assert!(!signature_b64.is_empty(), "signature segment must be set");

        let header_json: serde_json::Value =
            serde_json::from_slice(&header_bytes).expect("header json");
        assert_eq!(header_json["alg"], "RS256");
        assert_eq!(header_json["typ"], "JWT");
        assert_eq!(header_json["kid"], "kid-1");

        let payload_json: serde_json::Value =
            serde_json::from_slice(&payload_bytes).expect("payload json");
        assert_eq!(payload_json["iss"], sa.client_email.as_str());
        assert_eq!(payload_json["aud"], sa.token_uri.as_str());
        assert_eq!(payload_json["scope"], SCOPE);
        let iat = payload_json["iat"].as_u64().expect("iat");
        let exp = payload_json["exp"].as_u64().expect("exp");
        assert_eq!(exp - iat, JWT_LIFETIME_SECS);
    }

    #[test]
    fn parse_credentials_json_dispatches_on_type() {
        let sa_json = serde_json::json!({
            "type": "service_account",
            "client_email": "x@example.iam",
            "private_key": SYNTHETIC_PEM,
            "token_uri": "https://oauth2.example/token",
        })
        .to_string();
        let source = parse_credentials_json(sa_json.as_bytes()).expect("service account");
        assert!(source.can_sign_urls());

        let user_json = serde_json::json!({
            "type": "authorized_user",
            "client_id": "abc",
            "client_secret": "shh",
            "refresh_token": "rt",
        })
        .to_string();
        let source = parse_credentials_json(user_json.as_bytes()).expect("user creds");
        assert!(!source.can_sign_urls());
    }

    #[test]
    fn debug_redacts_gcs_credentials() {
        let service = CredentialSource::ServiceAccount(ServiceAccountKey {
            client_email: "debug@example.iam.gserviceaccount.com".into(),
            private_key: "-----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----".into(),
            token_uri: "https://oauth2.example/token".into(),
            private_key_id: Some("kid-secret".into()),
        });
        let service_debug = format!("{service:?}");
        assert!(
            !service_debug.contains("BEGIN PRIVATE KEY"),
            "{service_debug}"
        );
        assert!(!service_debug.contains("kid-secret"), "{service_debug}");
        assert!(service_debug.contains("<redacted>"), "{service_debug}");

        let user = CredentialSource::User(UserCredentials {
            client_id: "client-id".into(),
            client_secret: "client-secret".into(),
            refresh_token: "refresh-token".into(),
            token_uri: "https://oauth2.example/token".into(),
        });
        let user_debug = format!("{user:?}");
        assert!(!user_debug.contains("client-secret"), "{user_debug}");
        assert!(!user_debug.contains("refresh-token"), "{user_debug}");
        assert!(user_debug.contains("<redacted>"), "{user_debug}");

        // `GrantedToken` is what carries the validated bearer now, so it is the
        // type whose `{:?}` must not leak it.
        let token = GrantedToken {
            access_token: "access-token".into(),
            expires_in: 3600,
        };
        let token_debug = format!("{token:?}");
        assert!(!token_debug.contains("access-token"), "{token_debug}");
        assert!(token_debug.contains("<redacted>"), "{token_debug}");
    }

    #[test]
    fn parse_credentials_json_rejects_unknown_type() {
        let unknown = serde_json::json!({"type": "gcp_magic_beans"}).to_string();
        let err = parse_credentials_json(unknown.as_bytes()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            err.message().contains("gcp_magic_beans"),
            "the rejected type is the diagnostic: {}",
            err.message()
        );
    }

    fn external_account_json(source: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "type": "external_account",
            "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/v",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": "https://sts.googleapis.com/v1/token",
            "credential_source": source,
        })
    }

    #[test]
    fn parse_external_account_file_and_url_sources() {
        let file = external_account_json(serde_json::json!({"file": "/var/run/token"})).to_string();
        let source = parse_credentials_json(file.as_bytes()).expect("file-sourced");
        assert!(!source.can_sign_urls(), "no RSA key to sign with");
        match source {
            CredentialSource::ExternalAccount(ea) => {
                assert_eq!(ea.token_url, "https://sts.googleapis.com/v1/token");
                assert!(ea.impersonation_url.is_none());
                assert!(matches!(
                    ea.subject_source,
                    SubjectTokenSource::File { ref path, format: SubjectTokenFormat::Text } if path == "/var/run/token"
                ));
            }
            other => panic!("expected ExternalAccount, got {other:?}"),
        }

        let url = external_account_json(serde_json::json!({
            "url": "https://issuer.example/token?audience=x",
            "headers": {"Authorization": "Bearer runner-secret"},
            "format": {"type": "json", "subject_token_field_name": "value"},
        }))
        .to_string();
        match parse_credentials_json(url.as_bytes()).expect("url-sourced") {
            CredentialSource::ExternalAccount(ea) => match ea.subject_source {
                SubjectTokenSource::Url {
                    ref url,
                    ref headers,
                    format: SubjectTokenFormat::Json { ref field },
                } => {
                    assert_eq!(url, "https://issuer.example/token?audience=x");
                    assert_eq!(headers.len(), 1);
                    assert_eq!(field, "value");
                }
                other => panic!("expected Url source, got {other:?}"),
            },
            other => panic!("expected ExternalAccount, got {other:?}"),
        }
    }

    #[test]
    fn parse_external_account_defaults_the_sts_endpoint() {
        let mut json = external_account_json(serde_json::json!({"file": "/var/run/token"}));
        json.as_object_mut().unwrap().remove("token_url");
        match parse_credentials_json(json.to_string().as_bytes()).expect("parses") {
            CredentialSource::ExternalAccount(ea) => assert_eq!(ea.token_url, STS_TOKEN_URL),
            other => panic!("expected ExternalAccount, got {other:?}"),
        }
    }

    #[test]
    fn parse_external_account_rejects_unsupported_source_flavors() {
        for (source, named) in [
            (
                serde_json::json!({"environment_id": "aws1", "regional_cred_verification_url": "https://sts.aws.example"}),
                "AWS",
            ),
            (
                serde_json::json!({"executable": {"command": "/bin/mint-token"}}),
                "executable",
            ),
            (serde_json::json!({}), "file or a url"),
        ] {
            let json = external_account_json(source).to_string();
            let err = parse_credentials_json(json.as_bytes()).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert!(
                err.message().contains(named),
                "'{named}' missing from: {}",
                err.message()
            );
        }
    }

    #[test]
    fn parse_external_account_json_format_requires_a_field_name() {
        let json = external_account_json(serde_json::json!({
            "file": "/var/run/token",
            "format": {"type": "json"},
        }))
        .to_string();
        let err = parse_credentials_json(json.as_bytes()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            err.message().contains("subject_token_field_name"),
            "{}",
            err.message()
        );
    }

    #[test]
    fn parse_impersonated_service_account_with_a_user_source() {
        let json = serde_json::json!({
            "type": "impersonated_service_account",
            "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com:generateAccessToken",
            "delegates": ["chain@p.iam.gserviceaccount.com"],
            "source_credentials": {
                "type": "authorized_user",
                "client_id": "abc",
                "client_secret": "shh",
                "refresh_token": "rt",
            },
        })
        .to_string();
        let source = parse_credentials_json(json.as_bytes()).expect("impersonated");
        assert!(!source.can_sign_urls());
        match source {
            CredentialSource::Impersonated(imp) => {
                assert_eq!(imp.delegates.len(), 1);
                assert!(matches!(*imp.source, CredentialSource::User(_)));
            }
            other => panic!("expected Impersonated, got {other:?}"),
        }
    }

    /// A silently filtered delegate chain is a DIFFERENT impersonation
    /// request; malformed `delegates` must fail closed like every other
    /// credential field.
    #[test]
    fn parse_impersonated_service_account_fails_closed_on_malformed_delegates() {
        for delegates in [
            serde_json::json!("chain@p.iam.gserviceaccount.com"),
            serde_json::Value::Null,
            serde_json::json!(["chain@p.iam.gserviceaccount.com", 42]),
            serde_json::json!(["chain@p.iam.gserviceaccount.com", "  "]),
            serde_json::json!([null]),
        ] {
            let json = serde_json::json!({
                "type": "impersonated_service_account",
                "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/x:generateAccessToken",
                "delegates": delegates,
                "source_credentials": {
                    "type": "authorized_user",
                    "client_id": "abc",
                    "client_secret": "shh",
                    "refresh_token": "rt",
                },
            })
            .to_string();
            let err = parse_credentials_json(json.as_bytes()).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{delegates:?}");
            assert!(
                err.message().contains("delegates"),
                "{delegates:?}: {}",
                err.message()
            );
        }
        // Absent stays fine, and a well-formed chain survives intact.
        let json = serde_json::json!({
            "type": "impersonated_service_account",
            "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/x:generateAccessToken",
            "source_credentials": {
                "type": "authorized_user", "client_id": "a", "client_secret": "b", "refresh_token": "c",
            },
        })
        .to_string();
        parse_credentials_json(json.as_bytes()).expect("absent delegates is valid");
    }

    #[test]
    fn parse_impersonated_service_account_rejects_nested_impersonation() {
        let json = serde_json::json!({
            "type": "impersonated_service_account",
            "service_account_impersonation_url": "https://iamcredentials.googleapis.com/outer",
            "source_credentials": {
                "type": "impersonated_service_account",
                "service_account_impersonation_url": "https://iamcredentials.googleapis.com/inner",
                "source_credentials": {"type": "authorized_user", "client_id": "a", "client_secret": "b", "refresh_token": "c"},
            },
        })
        .to_string();
        let err = parse_credentials_json(json.as_bytes()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("nest"), "{}", err.message());
    }

    /// An external_account JSON is treated as shareable configuration in the
    /// wider Google ecosystem, and its `token_url` is where the locally-read
    /// subject token gets POSTed — so a non-Google (and non-loopback) host
    /// there is a file-exfiltration primitive and must be rejected at parse.
    #[test]
    fn parse_external_account_pins_token_and_impersonation_urls_to_google() {
        for (field, json) in [
            ("token_url", {
                let mut j = external_account_json(serde_json::json!({"file": "/var/run/token"}));
                j["token_url"] = serde_json::json!("https://attacker.example/collect");
                j
            }),
            ("token_url http even on googleapis", {
                let mut j = external_account_json(serde_json::json!({"file": "/var/run/token"}));
                j["token_url"] = serde_json::json!("http://sts.googleapis.com/v1/token");
                j
            }),
            ("service_account_impersonation_url", {
                let mut j = external_account_json(serde_json::json!({"file": "/var/run/token"}));
                j["service_account_impersonation_url"] =
                    serde_json::json!("https://attacker.example/impersonate");
                j
            }),
            ("token_url lookalike suffix", {
                let mut j = external_account_json(serde_json::json!({"file": "/var/run/token"}));
                j["token_url"] = serde_json::json!("https://evilgoogleapis.com/v1/token");
                j
            }),
        ] {
            let err = parse_credentials_json(json.to_string().as_bytes()).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{field}");
            assert!(
                err.message().contains("googleapis.com"),
                "{field}: {}",
                err.message()
            );
        }
        // Loopback stays allowed — that is what the exchange tests and local
        // emulators run against.
        let mut j = external_account_json(serde_json::json!({"file": "/var/run/token"}));
        j["token_url"] = serde_json::json!("http://127.0.0.1:4443/token");
        parse_credentials_json(j.to_string().as_bytes()).expect("loopback token_url is fine");
    }

    /// `credential_source.url` cannot be pinned to Google (GitHub's endpoint
    /// is elsewhere), but the GCE metadata server — plain http on a
    /// link-local address — must not become reachable through a credential
    /// file. https or loopback only.
    #[test]
    fn parse_external_account_rejects_a_plain_http_subject_source() {
        let json = external_account_json(serde_json::json!({
            "url": "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity",
            "headers": {"Metadata-Flavor": "Google"},
        }))
        .to_string();
        let err = parse_credentials_json(json.as_bytes()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("https"), "{}", err.message());
    }

    /// Workforce (user-identity) federation needs an STS `options` parameter
    /// this client does not send; accepting the config and failing every
    /// refresh would be worse than naming the limitation at parse.
    #[test]
    fn parse_external_account_rejects_workforce_credentials() {
        let mut by_audience = external_account_json(serde_json::json!({"file": "/var/run/token"}));
        by_audience["audience"] = serde_json::json!(
            "//iam.googleapis.com/locations/global/workforcePools/pool/providers/v"
        );
        let mut by_field = external_account_json(serde_json::json!({"file": "/var/run/token"}));
        by_field["workforce_pool_user_project"] = serde_json::json!("proj-1");
        for json in [by_audience, by_field] {
            let err = parse_credentials_json(json.to_string().as_bytes()).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert!(err.message().contains("workforce"), "{}", err.message());
        }
    }

    /// A present-but-malformed field must fail closed, not read as absent:
    /// for `service_account_impersonation_url` the absent reading silently
    /// returns the federated token under the WRONG identity instead of
    /// rejecting the credential.
    #[test]
    fn parse_external_account_fails_closed_on_malformed_optional_fields() {
        for (field, value) in [
            ("service_account_impersonation_url", serde_json::json!(42)),
            ("service_account_impersonation_url", serde_json::Value::Null),
            (
                "service_account_impersonation_url",
                serde_json::json!("   "),
            ),
            (
                "token_url",
                serde_json::json!(["https://sts.googleapis.com"]),
            ),
        ] {
            let mut json = external_account_json(serde_json::json!({"file": "/var/run/token"}));
            json[field] = value.clone();
            let err = parse_credentials_json(json.to_string().as_bytes()).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{field}={value}");
            assert!(
                err.message().contains(field),
                "{field}={value}: {}",
                err.message()
            );
        }
    }

    /// The subject-token fetch may authenticate with a header value, and the
    /// source URL's query string is operator-controlled; neither may survive
    /// into a `{:?}` rendering.
    #[test]
    fn debug_redacts_subject_token_source_secrets() {
        let json = external_account_json(serde_json::json!({
            "url": "https://issuer.example/token?bearer=REQUEST-SECRET",
            "headers": {"Authorization": "Bearer HEADER-SECRET"},
            "format": {"type": "json", "subject_token_field_name": "value"},
        }))
        .to_string();
        let source = parse_credentials_json(json.as_bytes()).expect("parses");
        let rendered = format!("{source:?}");
        assert!(!rendered.contains("REQUEST-SECRET"), "{rendered}");
        assert!(!rendered.contains("HEADER-SECRET"), "{rendered}");
        assert!(
            rendered.contains("https://issuer.example/token"),
            "the origin+path stays diagnostic: {rendered}"
        );
    }

    #[tokio::test]
    async fn token_exchange_failure_carries_auth_context() {
        let http_response = http::Response::builder()
            .status(401)
            .body("invalid_grant")
            .unwrap();
        let response = reqwest::Response::from(http_response);
        let err = decode_token_response(response).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ovstorage_plugin::ErrorContext::Auth { reason, .. }) => {
                assert_eq!(reason.as_deref(), Some("token_exchange_http_401"));
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    /// The identity provider's body is subject to the same rule as a storage
    /// error body. `error_description` echoes the rejected assertion, so only
    /// the top-level `error` code may escape into the message.
    #[tokio::test]
    async fn token_exchange_failure_does_not_echo_the_provider_body() {
        let body = r#"{"error":"invalid_grant","error_description":"assertion=eyJhbGciOi.SECRET"}"#;
        let http_response = http::Response::builder().status(401).body(body).unwrap();
        let err = decode_token_response(reqwest::Response::from(http_response))
            .await
            .unwrap_err();
        assert!(
            err.message().contains("invalid_grant"),
            "the OAuth error code is the diagnostic worth keeping: {}",
            err.message()
        );
        for leaked in ["assertion", "eyJhbGciOi", "SECRET", "error_description"] {
            assert!(
                !err.message().contains(leaked),
                "{leaked} survived into the message: {}",
                err.message()
            );
        }
    }

    /// The SUCCESS path is the most sensitive decode in this file: the body
    /// holds a live access token, and `serde_json`'s `Display` can embed a slice
    /// of it.
    ///
    /// What this pins is now narrower than it looks, and saying so is the point.
    /// The body is read as an untyped document, so the `invalid type: string
    /// "…"` failure that used to carry the offending value verbatim is no longer
    /// reachable here; the failures that remain quote nothing. So the leak assertions below cannot fail today; what still bites is
    /// `contains("byte body suppressed")`, which pins that the message reports a
    /// LENGTH rather than content. The leak assertions are kept as the guard
    /// that would catch a future change back to `format!("{err}")`.
    #[tokio::test]
    async fn a_malformed_token_response_does_not_quote_the_body() {
        // Truncated rather than merely odd-typed: a document that still yields a
        // usable bearer is now ACCEPTED (a string `expires_in` must not condemn
        // a working credential), so the redaction path is reached through a body
        // that genuinely cannot be parsed. The secret-shaped strings are still
        // in it, which is the whole point of the test.
        let body = r#"{"access_token":"ya29.LIVE-TOKEN","expires_in":"eyJhbGciOiSECRET""#;
        let http_response = http::Response::builder().status(200).body(body).unwrap();
        let err = decode_token_response(reqwest::Response::from(http_response))
            .await
            .unwrap_err();
        assert!(
            err.message().contains("byte body suppressed"),
            "{}",
            err.message()
        );
        for leaked in ["eyJhbGciOiSECRET", "ya29.LIVE-TOKEN", "access_token"] {
            assert!(
                !err.message().contains(leaked),
                "{leaked} survived into the message: {}",
                err.message()
            );
        }
    }

    /// A body with no recoverable code is reported by length alone, never by
    /// quoting it.
    #[tokio::test]
    async fn a_token_exchange_body_with_no_code_is_reported_by_length() {
        let http_response = http::Response::builder()
            .status(503)
            .body("<html>upstream connect error sig=7hK4wQ2m</html>")
            .unwrap();
        let err = decode_token_response(reqwest::Response::from(http_response))
            .await
            .unwrap_err();
        assert!(
            err.message().contains("byte body suppressed"),
            "{}",
            err.message()
        );
        assert!(!err.message().contains("7hK4wQ2m"), "{}", err.message());
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

    /// Build an `Authenticator` whose user credentials point at the
    /// given token endpoint. Used by the background-refresh tests to
    /// observe wire-level effects from the loop.
    fn user_authenticator(token_endpoint: &str) -> Arc<Authenticator> {
        let mut bundle = SecretBundle::default();
        let creds_json = serde_json::json!({
            "type": "authorized_user",
            "client_id": "loop-id",
            "client_secret": "loop-secret",
            "refresh_token": "rt-1",
            "token_uri": token_endpoint,
        })
        .to_string();
        bundle.fields.insert(
            "service_account_key".into(),
            SecretValue::Bytes(ovstorage_plugin::SecretBytes(creds_json.into_bytes())),
        );
        Arc::new(Authenticator::new(&bundle, reqwest::Client::new()).expect("user authenticator"))
    }

    /// Spawn a mock token endpoint that serves a sequence of HTTP
    /// responses (one per accepted connection). The mock returns the
    /// listener address and a oneshot that fires the first time the
    /// endpoint is hit. Subsequent hits advance through the response
    /// queue; if the queue is exhausted the connection is closed.
    async fn spawn_mock_token_endpoint(
        responses: Vec<String>,
    ) -> (String, tokio::sync::mpsc::UnboundedReceiver<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("http://{}/token", addr);
        let (hit_tx, hit_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut queue: std::collections::VecDeque<String> = responses.into();
            while let Ok((mut sock, _)) = listener.accept().await {
                let _ = hit_tx.send(());
                let mut buf = vec![0u8; 4096];
                // Read request enough to drain (we don't inspect it
                // here; just need to consume so the response is well-
                // formed from the client's POV).
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
    /// proactive refresh near the 90%-of-TTL mark. We point the
    /// authenticator at a mock token endpoint and wait for the first
    /// hit; with TTL=5s the loop sleeps `(5s * 9 / 10).max(30s)` = 30s
    /// (the floor), so a real-clock wait would be too slow — pause
    /// tokio time and advance past the deadline instead.
    ///
    /// Tokio I/O still makes progress under paused time, so the mock
    /// server's accept loop runs without a `resume()` — the channel
    /// signal fires once the loop's sleep deadline is crossed.
    #[tokio::test(start_paused = true)]
    async fn background_refresh_runs_on_short_ttl() {
        let (endpoint, mut hit_rx) = spawn_mock_token_endpoint(vec![ok_token_response(3600)]).await;
        let auth = user_authenticator(&endpoint);
        auth.install_background_refresh(Duration::from_secs(5));

        // Yield so the spawned loop registers its sleep before we
        // advance the clock. Without this the advance happens before
        // sleep is installed and the task still parks the full window.
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
    /// 90%-of-TTL window. We queue two responses — first an error,
    /// then a success — and prove the loop hits the endpoint twice
    /// across two refresh intervals. Under the buggy shape the
    /// second hit wouldn't arrive without an extra 90%-of-TTL window
    /// (~30 min for ttl=3600s).
    ///
    /// We drive this entirely with tokio time paused so the real
    /// clock never has to wait: tokio I/O (the mock TCP server) still
    /// makes progress even with time paused, so a `tokio::time::sleep`
    /// inside the loop parks until we `advance` past its deadline.
    #[tokio::test(start_paused = true)]
    async fn background_refresh_retries_on_error() {
        let (endpoint, mut hit_rx) =
            spawn_mock_token_endpoint(vec![err_token_response(), ok_token_response(3600)]).await;
        let auth = user_authenticator(&endpoint);
        // TTL=5s → first sleep is floored to 30s. After the first
        // (failed) refresh, the loop should wait 30s before retrying.
        auth.install_background_refresh(Duration::from_secs(5));

        // Yield so the loop registers its first sleep before we
        // advance the clock.
        tokio::task::yield_now().await;
        // Cross the first deadline. The loop wakes, makes the grant
        // call (which fails synchronously over the mock), then arms
        // the retry sleep.
        tokio::time::advance(Duration::from_secs(31)).await;
        // hit_rx.recv() under paused time still resolves once the
        // mock server delivers — tokio I/O isn't time-dependent.
        let first = hit_rx.recv().await;
        assert!(first.is_some(), "first refresh attempt must hit the mock");

        // Yield so the loop's failure path can install the
        // REFRESH_RETRY_INTERVAL sleep before we advance again.
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

    /// Dropping the last `Arc<Authenticator>` must abort the spawned
    /// refresh task. We observe this via a sentinel: install a
    /// refresh task with a long initial TTL (so it would never fire
    /// on real time), drop the Arc, and confirm the task finishes
    /// promptly (the abort wakes it from its `sleep`).
    #[tokio::test]
    async fn background_refresh_aborts_on_drop() {
        let (endpoint, _hit_rx) = spawn_mock_token_endpoint(vec![ok_token_response(3600)]).await;
        let auth = user_authenticator(&endpoint);
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

        // Re-install so Drop has something to abort too (mirrors the
        // production lifecycle where install + drop is the norm).
        // We can't easily re-install via the public API after take-ing
        // the handle, so the abort under test is the one we drive
        // explicitly below. Drop the Arc anyway to prove the lifecycle.
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

#[cfg(test)]
mod promotion_latch_tests {
    use super::*;
    use ovstorage_plugin::{SecretBytes, SecretValue};
    use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

    const SYNTHETIC_PEM: &str = include_str!("../tests/synthetic_rsa_pkcs8.pem");
    const TOKEN_OK_BODY: &str = "{\"access_token\": \"synthetic-token\", \"expires_in\": 3600}";

    fn bundle(token_uri: &str) -> SecretBundle {
        let json = serde_json::json!({
            "type": "service_account",
            "client_email": "tester@example.iam.gserviceaccount.com",
            "private_key": SYNTHETIC_PEM,
            "token_uri": format!("{token_uri}/token"),
            "private_key_id": "kid-1",
        })
        .to_string();
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "service_account_key".into(),
            SecretValue::Bytes(SecretBytes(json.into_bytes())),
        );
        bundle
    }

    /// The window the storage refusal epoch cannot see: the background refresh
    /// talks to the IdP, so a grant it refuses advances no storage epoch, and
    /// the cached bearer it keeps goes on being accepted. A refused grant
    /// latches; the next accepted grant clears it.
    #[tokio::test]
    async fn a_refused_grant_latches_until_one_is_accepted() {
        let idp = ScriptedHttpServer::spawn_sequence(vec![
            Some(CannedHttpResponse::json(
                "400 Bad Request",
                "{\"error\": \"invalid_grant\"}",
            )),
            Some(CannedHttpResponse::json("200 OK", TOKEN_OK_BODY)),
        ]);
        let auth =
            Authenticator::new(&bundle(idp.endpoint()), reqwest::Client::new()).expect("build");
        assert!(
            !auth.credential_refused(),
            "a fresh authenticator has heard no refusal"
        );

        let refused = auth.refresh_now().await;
        assert!(refused.is_err(), "control: the scripted grant must fail");
        assert!(
            auth.credential_refused(),
            "a definitively refused grant withholds promotions"
        );

        auth.refresh_now()
            .await
            .expect("the second grant is served");
        assert!(
            !auth.credential_refused(),
            "a grant the IdP accepted clears the latch"
        );
    }

    /// A grant that answers `200` without a usable bearer produced no
    /// credential, so it is definitive: it parks the connection and latches.
    /// Before it was listed, `GcsDriver::verify` took its lenient arm and
    /// committed `Authenticated` for a credential that could sign nothing.
    ///
    /// All four shapes are one condition, because all four leave
    /// `maybe_bearer_auth` sending nothing while the connection still reports a
    /// credential source.
    #[tokio::test]
    async fn a_grant_without_a_usable_bearer_is_a_definitive_refusal() {
        assert!(
            reason_is_grant_refusal("token_exchange_empty"),
            "a missing bearer must park and latch, not take the lenient arm"
        );
        for body in [
            "{\"access_token\": \"\", \"expires_in\": 3600}",
            "{\"access_token\": \"   \", \"expires_in\": 3600}",
            "{\"expires_in\": 3600}",
            "{\"access_token\": null, \"expires_in\": 3600}",
            "{\"access_token\": 12345, \"expires_in\": 3600}",
        ] {
            let idp = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", body));
            let auth =
                Authenticator::new(&bundle(idp.endpoint()), reqwest::Client::new()).expect("build");
            let err = auth.refresh_now().await.expect_err(body);
            assert_eq!(
                err.code(),
                ovstorage_plugin::ErrorCode::AuthRequired,
                "{body}"
            );
            assert!(
                auth.credential_refused(),
                "the grant produced nothing, so no promotion may rest on it: {body}"
            );
        }
    }

    /// The mirror image, and the reason the definitive set is exactly one shape
    /// wide: a body that carries a USABLE bearer must be accepted however its
    /// other fields are spelled, and a body that fails to parse at all is a
    /// transport failure rather than a verdict on the credential. Parking on
    /// either would strand a working credential permanently, `refresh` being
    /// `Unsupported`.
    #[tokio::test]
    async fn a_usable_bearer_survives_an_odd_document() {
        let idp = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            "{\"access_token\": \"synthetic-token\", \"expires_in\": \"3600\"}",
        ));
        let auth =
            Authenticator::new(&bundle(idp.endpoint()), reqwest::Client::new()).expect("build");
        let (token, _ttl) = auth
            .refresh_now()
            .await
            .expect("a string expires_in must not condemn a working bearer");
        assert_eq!(token, "synthetic-token");
        assert!(!auth.credential_refused());
    }

    /// A large document does not cost a large parse, and a bearer inside one is
    /// still returned.
    ///
    /// The success path deserializes into two fields, so serde discards the
    /// padding as it goes; reading the body into a `serde_json::Value` first
    /// would have materialised the whole tree on top of the already-buffered
    /// body, on a loop that runs for every non-anonymous connection against an
    /// operator-supplied `token_uri`.
    ///
    /// Windowing the body was tried instead and is wrong here: truncating a
    /// SUCCESS response does not lose a diagnostic, it loses the credential —
    /// which is why this asserts the token still arrives rather than that the
    /// parse fails.
    #[tokio::test]
    async fn a_large_token_document_still_yields_its_bearer() {
        let padding = "p".repeat(64 * 1024);
        let idp = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            format!(
                "{{\"ignored\": \"{padding}\", \"access_token\": \"ya29.real\", \
                 \"expires_in\": 3600}}"
            ),
        ));
        let auth =
            Authenticator::new(&bundle(idp.endpoint()), reqwest::Client::new()).expect("build");
        let (token, _ttl) = auth
            .refresh_now()
            .await
            .expect("a bearer past 8 KiB of padding is still a bearer");
        assert_eq!(token, "ya29.real");
        assert!(!auth.credential_refused());
    }

    /// A truncated or non-JSON body is a transport failure: it must NOT latch,    /// A truncated or non-JSON body is a transport failure: it must NOT latch,
    /// and it must not park, because nothing about the credential was learned.
    ///
    /// The trade this accepts, stated because nothing else states it: an IdP
    /// proxy that truncates PERSISTENTLY leaves `verify` on its lenient arm, so
    /// the connection reports `Authenticated` while no bearer can ever be
    /// minted. Every operation then fails outright, which is visible, whereas
    /// parking on a transient truncation would be permanent — `refresh` is
    /// `Unsupported`.
    #[tokio::test]
    async fn an_unparseable_token_body_is_not_a_credential_verdict() {
        let idp = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            "{\"access_token\": \"ya29.trunca",
        ));
        let auth =
            Authenticator::new(&bundle(idp.endpoint()), reqwest::Client::new()).expect("build");
        let err = auth.refresh_now().await.expect_err("the body is truncated");
        assert_eq!(err.code(), ovstorage_plugin::ErrorCode::Internal);
        assert!(
            !auth.credential_refused(),
            "a truncated response says nothing about the credential"
        );
    }

    /// A throttle or an outage is not evidence about the credential. Latching
    /// on one would withhold every later promotion from a credential that
    /// works, and with `refresh` unsupported nothing would clear it.
    #[tokio::test]
    async fn a_transient_grant_failure_does_not_latch() {
        for status in ["429 Too Many Requests", "503 Service Unavailable"] {
            let idp = ScriptedHttpServer::spawn(CannedHttpResponse::json(
                status,
                "{\"error\": \"scripted\"}",
            ));
            let auth =
                Authenticator::new(&bundle(idp.endpoint()), reqwest::Client::new()).expect("build");
            assert!(auth.refresh_now().await.is_err(), "control: {status} fails");
            assert!(
                !auth.credential_refused(),
                "{status} is transient and must not latch"
            );
        }
    }

    /// "Must not count in either direction" has a second half that a fresh
    /// authenticator cannot test: a transient failure must not CLEAR a latch
    /// either. An implementation that reset on any completed exchange would pass
    /// the test above unchanged, and would then let a cached bearer promote a
    /// connection whose grant the IdP had already refused.
    #[tokio::test]
    async fn a_transient_grant_failure_does_not_clear_the_latch() {
        let idp = ScriptedHttpServer::spawn_sequence(vec![
            Some(CannedHttpResponse::json(
                "400 Bad Request",
                "{\"error\": \"invalid_grant\"}",
            )),
            Some(CannedHttpResponse::json(
                "503 Service Unavailable",
                "{\"error\": \"scripted\"}",
            )),
            Some(CannedHttpResponse::json("200 OK", TOKEN_OK_BODY)),
        ]);
        let auth =
            Authenticator::new(&bundle(idp.endpoint()), reqwest::Client::new()).expect("build");

        assert!(auth.refresh_now().await.is_err(), "control: the 400 fails");
        assert!(auth.credential_refused(), "a definitive refusal latches");

        assert!(auth.refresh_now().await.is_err(), "control: the 503 fails");
        assert!(
            auth.credential_refused(),
            "an outage says nothing about the credential, so it must not clear \
             a refusal that was definitive"
        );

        auth.refresh_now().await.expect("the third grant is served");
        assert!(
            !auth.credential_refused(),
            "only a grant the IdP accepted clears it"
        );
    }

    /// The warning claim is one-shot per connection, because the condition it
    /// reports is a property of the deployment while its call site is on every
    /// response.
    #[test]
    fn the_unstamped_warning_is_claimed_once() {
        let auth = Authenticator::new(&SecretBundle::default(), reqwest::Client::new())
            .expect("anonymous authenticator");
        assert!(auth.claim_unstamped_warning());
        assert!(!auth.claim_unstamped_warning());
        assert!(!auth.claim_unstamped_warning());
    }

    /// The storage epoch is what a promotion witness compares, so it must move
    /// on a refusal and stay still otherwise (external-account note: the same
    /// witness protocol covers WIF connections because the epoch lives on the
    /// authenticator, not the credential shape).
    ///
    /// Driven through `note_promotion_evidence` rather than by calling
    /// `note_refusal` by hand: the latter would assert `fetch_add`
    /// works, and would pass unchanged if the judgment never called it. This
    /// version fails if `vetoes_promotion`'s call site regresses.
    #[tokio::test]
    async fn only_a_refusal_advances_the_epoch() {
        let idp = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", TOKEN_OK_BODY));
        let auth =
            Authenticator::new(&bundle(idp.endpoint()), reqwest::Client::new()).expect("build");

        for (status, body) in [
            ("200 OK", "{}"),
            ("403 Forbidden", "{}"),
            ("404 Not Found", "{}"),
            ("500 Internal Server Error", "{}"),
        ] {
            let before = auth.refusal_epoch();
            let server = ScriptedHttpServer::spawn(CannedHttpResponse::json(status, body));
            let response = reqwest::get(server.endpoint()).await.expect("served");
            crate::note_promotion_evidence(&auth, true, &response);
            assert_eq!(
                auth.refusal_epoch(),
                before,
                "{status} is not a credential refusal"
            );
        }

        let before = auth.refusal_epoch();
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("401 Unauthorized", "{}"));
        let response = reqwest::get(server.endpoint()).await.expect("served");
        crate::note_promotion_evidence(&auth, true, &response);
        assert_eq!(
            auth.refusal_epoch(),
            before + 1,
            "a 401 is the service refusing this credential"
        );
    }
}

#[cfg(test)]
mod external_account_exchange_tests {
    use super::*;
    use ovstorage_plugin::{SecretBytes, SecretValue};
    use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

    const STS_OK_BODY: &str = "{\"access_token\": \"sts-federated-token\", \"token_type\": \"Bearer\", \"expires_in\": 3599}";

    fn impersonation_ok_body(lifetime_seconds: i64) -> String {
        let expire_time = (time::OffsetDateTime::now_utc()
            + time::Duration::seconds(lifetime_seconds))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339");
        format!("{{\"accessToken\": \"impersonated-token\", \"expireTime\": \"{expire_time}\"}}")
    }

    fn bundle_with_json(json: &serde_json::Value) -> SecretBundle {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "service_account_key".into(),
            SecretValue::Bytes(SecretBytes(json.to_string().into_bytes())),
        );
        bundle
    }

    fn external_account_bundle(
        token_url: &str,
        source: serde_json::Value,
        impersonation_url: Option<&str>,
    ) -> SecretBundle {
        let mut json = serde_json::json!({
            "type": "external_account",
            "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/v",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_url": token_url,
            "credential_source": source,
        });
        if let Some(url) = impersonation_url {
            json["service_account_impersonation_url"] = serde_json::json!(url);
        }
        bundle_with_json(&json)
    }

    fn subject_token_file(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temp subject-token file");
        std::fs::write(file.path(), contents).expect("write subject token");
        file
    }

    /// The direct (no-impersonation) exchange: the STS answer IS the bearer,
    /// and the request carries the token-exchange grant, the subject token
    /// read from the file, and the STORAGE scopes (nothing narrows them —
    /// there is no second hop to carry them instead).
    #[tokio::test]
    async fn a_file_sourced_subject_token_exchanges_at_sts() {
        let file = subject_token_file("github-oidc-jwt");
        let sts = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", STS_OK_BODY));
        let bundle = external_account_bundle(
            sts.endpoint(),
            serde_json::json!({"file": file.path().to_str().unwrap()}),
            None,
        );
        let auth = Authenticator::new(&bundle, reqwest::Client::new()).expect("build");
        let (token, _ttl) = auth.refresh_now().await.expect("exchange");
        assert_eq!(token, "sts-federated-token");
        assert!(!auth.credential_refused());

        let requests = sts.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert!(
            request.contains("urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"),
            "token-exchange grant missing: {request}"
        );
        assert!(
            request.contains("github-oidc-jwt"),
            "subject token missing: {request}"
        );
        assert!(
            request.contains("devstorage.full_control"),
            "storage scope missing on the direct exchange: {request}"
        );
    }

    /// With an impersonation URL the STS leg asks only for cloud-platform,
    /// the hop spends the federated bearer, and the final token/TTL come
    /// from the `generateAccessToken` answer.
    #[tokio::test]
    async fn an_impersonation_hop_spends_the_federated_token() {
        let file = subject_token_file("github-oidc-jwt");
        let sts = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", STS_OK_BODY));
        let iam = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            impersonation_ok_body(1800),
        ));
        let bundle = external_account_bundle(
            sts.endpoint(),
            serde_json::json!({"file": file.path().to_str().unwrap()}),
            Some(iam.endpoint()),
        );
        let auth = Authenticator::new(&bundle, reqwest::Client::new()).expect("build");
        let (token, ttl) = auth.refresh_now().await.expect("exchange");
        assert_eq!(token, "impersonated-token");
        assert!(
            ttl >= Duration::from_secs(1700) && ttl <= Duration::from_secs(1900),
            "expireTime must translate into a ~1800s ttl, got {ttl:?}"
        );

        let sts_request = &sts.requests()[0];
        assert!(
            sts_request.contains("cloud-platform"),
            "the federated leg only needs to reach IAM Credentials: {sts_request}"
        );
        assert!(
            !sts_request.contains("devstorage.full_control"),
            "storage scopes belong to the impersonated token: {sts_request}"
        );
        let iam_request = &iam.requests()[0];
        assert!(
            iam_request.contains("authorization: Bearer sts-federated-token")
                || iam_request.contains("Authorization: Bearer sts-federated-token"),
            "the hop must spend the federated bearer: {iam_request}"
        );
        assert!(
            iam_request.contains("devstorage.full_control"),
            "the impersonated token carries the storage scopes: {iam_request}"
        );
    }

    /// Federation platforms rotate the subject token out from under a running
    /// process; caching the first read would strand every later refresh on a
    /// stale token. Each exchange must carry the file's CURRENT contents.
    #[tokio::test]
    async fn the_subject_token_is_reread_on_every_exchange() {
        let file = subject_token_file("first-token");
        let sts = ScriptedHttpServer::spawn_sequence(vec![
            Some(CannedHttpResponse::json("200 OK", STS_OK_BODY)),
            Some(CannedHttpResponse::json("200 OK", STS_OK_BODY)),
        ]);
        let bundle = external_account_bundle(
            sts.endpoint(),
            serde_json::json!({"file": file.path().to_str().unwrap()}),
            None,
        );
        let auth = Authenticator::new(&bundle, reqwest::Client::new()).expect("build");
        auth.refresh_now().await.expect("first exchange");
        std::fs::write(file.path(), "second-token").expect("rotate subject token");
        auth.refresh_now().await.expect("second exchange");

        let requests = sts.requests();
        assert!(requests[0].contains("first-token"), "{}", requests[0]);
        assert!(
            requests[1].contains("second-token"),
            "the rotated token must be picked up: {}",
            requests[1]
        );
    }

    /// The url-sourced flavor (GitHub Actions): the fetch sends the
    /// configured headers, the subject token is plucked out of the JSON
    /// answer by field name, and the exchange proceeds as usual.
    #[tokio::test]
    async fn a_url_sourced_subject_token_is_fetched_with_headers() {
        let issuer = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            "{\"value\": \"issued-oidc-jwt\", \"count\": 1}",
        ));
        let sts = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", STS_OK_BODY));
        let bundle = external_account_bundle(
            sts.endpoint(),
            serde_json::json!({
                "url": issuer.endpoint(),
                "headers": {"Authorization": "Bearer runner-request-token"},
                "format": {"type": "json", "subject_token_field_name": "value"},
            }),
            None,
        );
        let auth = Authenticator::new(&bundle, reqwest::Client::new()).expect("build");
        let (token, _ttl) = auth.refresh_now().await.expect("exchange");
        assert_eq!(token, "sts-federated-token");

        let issuer_request = &issuer.requests()[0];
        assert!(
            issuer_request.contains("runner-request-token"),
            "the configured header must reach the issuer: {issuer_request}"
        );
        assert!(
            sts.requests()[0].contains("issued-oidc-jwt"),
            "the extracted field is the subject token: {}",
            sts.requests()[0]
        );
    }

    /// A missing subject-token file is the PLATFORM being unavailable, not
    /// the IdP refusing a grant: `CredentialUnavailable`, and no latch —
    /// latching would withhold promotions from a credential nobody refused.
    #[tokio::test]
    async fn a_missing_subject_token_file_does_not_latch() {
        let sts = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", STS_OK_BODY));
        let bundle = external_account_bundle(
            sts.endpoint(),
            serde_json::json!({"file": "/nonexistent/subject-token"}),
            None,
        );
        let auth = Authenticator::new(&bundle, reqwest::Client::new()).expect("build");
        let err = auth.refresh_now().await.expect_err("no file to read");
        assert_eq!(err.code(), ErrorCode::CredentialUnavailable);
        assert!(!auth.credential_refused());
        assert_eq!(sts.hits(), 0, "nothing to exchange, so STS is never asked");
    }

    /// An STS 400 is the IdP refusing the grant — the same latch a refused
    /// refresh-token grant earns.
    #[tokio::test]
    async fn an_sts_refusal_latches() {
        let file = subject_token_file("expired-oidc-jwt");
        let sts = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "400 Bad Request",
            "{\"error\": \"invalid_grant\"}",
        ));
        let bundle = external_account_bundle(
            sts.endpoint(),
            serde_json::json!({"file": file.path().to_str().unwrap()}),
            None,
        );
        let auth = Authenticator::new(&bundle, reqwest::Client::new()).expect("build");
        let err = auth.refresh_now().await.expect_err("scripted refusal");
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        assert!(auth.credential_refused());
    }

    /// The impersonation hop follows the established status judgment: 401
    /// refuses the credential and latches; 403 is a PERMISSION verdict on the
    /// principal-to-SA binding — often IAM propagation lag minutes after
    /// setup — and parking permanently on it would strand a binding that is
    /// about to work. The error still surfaces; only the latch is withheld.
    #[tokio::test]
    async fn impersonation_statuses_follow_the_grant_refusal_vocabulary() {
        for (status, body, expect_latch, expect_reason) in [
            (
                "401 Unauthorized",
                "{\"error\": {\"status\": \"UNAUTHENTICATED\"}}",
                true,
                "impersonation_http_401",
            ),
            (
                "403 Forbidden",
                "{\"error\": {\"status\": \"PERMISSION_DENIED\"}}",
                false,
                "impersonation_http_403",
            ),
        ] {
            let file = subject_token_file("github-oidc-jwt");
            let sts = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", STS_OK_BODY));
            let iam = ScriptedHttpServer::spawn(CannedHttpResponse::json(status, body));
            let bundle = external_account_bundle(
                sts.endpoint(),
                serde_json::json!({"file": file.path().to_str().unwrap()}),
                Some(iam.endpoint()),
            );
            let auth = Authenticator::new(&bundle, reqwest::Client::new()).expect("build");
            let err = auth.refresh_now().await.expect_err(status);
            assert_eq!(err.code(), ErrorCode::AuthRequired, "{status}");
            assert_eq!(auth.credential_refused(), expect_latch, "{status}");
            // The hop's own tag, not token_exchange_*: the driver parks on
            // the 403 while the latch stays clear, a split a shared tag
            // could not express.
            match err.context() {
                Some(ovstorage_plugin::ErrorContext::Auth { reason, .. }) => {
                    assert_eq!(reason.as_deref(), Some(expect_reason), "{status}");
                }
                other => panic!("expected Auth context for {status}, got {other:?}"),
            }
        }
    }

    /// Transport errors on the STS / impersonation endpoints must not leak
    /// the endpoint URL: reqwest embeds the full request URL — query string
    /// included — in its error Display, and these URLs are
    /// operator-controlled.
    #[tokio::test]
    async fn a_token_transport_error_does_not_leak_the_endpoint_url() {
        let file = subject_token_file("github-oidc-jwt");
        // Port 1 refuses immediately; the query value plays the secret.
        // Loopback, so the parse-time endpoint gate admits it.
        let bundle = external_account_bundle(
            "http://127.0.0.1:1/token?api_key=STS-QUERY-SECRET",
            serde_json::json!({"file": file.path().to_str().unwrap()}),
            None,
        );
        let auth = Authenticator::new(&bundle, reqwest::Client::new()).expect("build");
        let err = auth.refresh_now().await.expect_err("nothing listens on :1");
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        assert!(
            !err.message().contains("STS-QUERY-SECRET"),
            "the token_url query survived into the message: {}",
            err.message()
        );
    }

    /// The IAM error body gets the same suppression as every provider body:
    /// the nested status code escapes, the message (which echoes the request)
    /// does not.
    #[tokio::test]
    async fn an_impersonation_error_body_is_reported_by_code_alone() {
        let file = subject_token_file("github-oidc-jwt");
        let sts = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", STS_OK_BODY));
        let iam = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "403 Forbidden",
            "{\"error\": {\"status\": \"PERMISSION_DENIED\", \"message\": \"Permission denied on sa-with-SECRET-name\"}}",
        ));
        let bundle = external_account_bundle(
            sts.endpoint(),
            serde_json::json!({"file": file.path().to_str().unwrap()}),
            Some(iam.endpoint()),
        );
        let auth = Authenticator::new(&bundle, reqwest::Client::new()).expect("build");
        let err = auth.refresh_now().await.expect_err("scripted 403");
        assert!(
            err.message().contains("PERMISSION_DENIED"),
            "{}",
            err.message()
        );
        assert!(
            !err.message().contains("SECRET-name"),
            "the IAM message echoes the request and must not escape: {}",
            err.message()
        );
    }

    /// A 200 impersonation answer with no usable accessToken produced no
    /// credential — the same one-condition rule the OAuth path pins.
    #[tokio::test]
    async fn an_impersonation_grant_without_a_bearer_is_definitive() {
        let file = subject_token_file("github-oidc-jwt");
        let sts = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", STS_OK_BODY));
        let iam = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            "{\"expireTime\": \"2099-01-01T00:00:00Z\"}",
        ));
        let bundle = external_account_bundle(
            sts.endpoint(),
            serde_json::json!({"file": file.path().to_str().unwrap()}),
            Some(iam.endpoint()),
        );
        let auth = Authenticator::new(&bundle, reqwest::Client::new()).expect("build");
        let err = auth.refresh_now().await.expect_err("no bearer");
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        assert!(auth.credential_refused());
    }

    /// An external-account SOURCE inside an impersonated credential must ask
    /// STS for cloud-platform, never the storage scopes: its bearer's only
    /// job is the `generateAccessToken` call, which refuses storage-scoped
    /// callers. (The natural no-impersonation scope choice would pick the
    /// storage scopes here — the regression this pins.)
    #[tokio::test]
    async fn an_external_account_source_is_exchanged_with_cloud_platform_scope() {
        let file = subject_token_file("gke-projected-jwt");
        let sts = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", STS_OK_BODY));
        let iam = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            impersonation_ok_body(3600),
        ));
        let json = serde_json::json!({
            "type": "impersonated_service_account",
            "service_account_impersonation_url": iam.endpoint(),
            "source_credentials": {
                "type": "external_account",
                "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/v",
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "token_url": sts.endpoint(),
                "credential_source": {"file": file.path().to_str().unwrap()},
            },
        });
        let auth =
            Authenticator::new(&bundle_with_json(&json), reqwest::Client::new()).expect("build");
        let (token, _ttl) = auth.refresh_now().await.expect("exchange");
        assert_eq!(token, "impersonated-token");
        let sts_request = &sts.requests()[0];
        assert!(
            sts_request.contains("cloud-platform"),
            "the source bearer must be allowed onto IAM Credentials: {sts_request}"
        );
        assert!(
            !sts_request.contains("devstorage.full_control"),
            "a storage-scoped bearer is refused by generateAccessToken: {sts_request}"
        );
        assert!(
            iam.requests()[0].contains("sts-federated-token"),
            "the federated bearer pays for the hop: {}",
            iam.requests()[0]
        );
    }

    /// The double-impersonation spelling — an external-account source that
    /// itself names an impersonation URL — is rejected at parse, like nested
    /// `impersonated_service_account`.
    #[tokio::test]
    async fn an_impersonating_external_account_source_is_rejected_at_parse() {
        let json = serde_json::json!({
            "type": "impersonated_service_account",
            "service_account_impersonation_url": "https://iamcredentials.googleapis.com/outer",
            "source_credentials": {
                "type": "external_account",
                "audience": "//iam.googleapis.com/x",
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "credential_source": {"file": "/var/run/token"},
                "service_account_impersonation_url": "https://iamcredentials.googleapis.com/inner",
            },
        })
        .to_string();
        let err = parse_credentials_json(json.as_bytes()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("nest"), "{}", err.message());
    }

    /// A PARSEABLE expireTime already in the past clamps the TTL to zero
    /// (the leeway floor takes over) instead of riding the 3600s
    /// absent-field fallback — an hour of caching for a bearer the server
    /// said is dead.
    #[tokio::test]
    async fn a_past_expire_time_does_not_ride_the_default_lifetime() {
        let file = subject_token_file("github-oidc-jwt");
        let sts = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", STS_OK_BODY));
        let iam = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            impersonation_ok_body(-600),
        ));
        let bundle = external_account_bundle(
            sts.endpoint(),
            serde_json::json!({"file": file.path().to_str().unwrap()}),
            Some(iam.endpoint()),
        );
        let auth = Authenticator::new(&bundle, reqwest::Client::new()).expect("build");
        let (_token, ttl) = auth.refresh_now().await.expect("exchange");
        assert!(
            ttl <= REFRESH_LEEWAY + Duration::from_secs(1),
            "a dead bearer must get the minimum caching window, got {ttl:?}"
        );
    }

    /// A transport failure on the subject-token fetch must not leak the
    /// endpoint URL: its query string is operator-controlled and may carry a
    /// token (reqwest embeds the full URL in its error Display by default).
    #[tokio::test]
    async fn a_subject_token_transport_error_does_not_leak_the_url() {
        let sts = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", STS_OK_BODY));
        let bundle = external_account_bundle(
            sts.endpoint(),
            serde_json::json!({
                // Port 1 refuses immediately; the query value plays the secret.
                "url": "http://127.0.0.1:1/token?bearer=URL-QUERY-SECRET",
                "format": {"type": "json", "subject_token_field_name": "value"},
            }),
            None,
        );
        let auth = Authenticator::new(&bundle, reqwest::Client::new()).expect("build");
        let err = auth.refresh_now().await.expect_err("nothing listens on :1");
        assert_eq!(err.code(), ErrorCode::CredentialUnavailable);
        assert!(
            !err.message().contains("URL-QUERY-SECRET"),
            "the operator-controlled query survived into the message: {}",
            err.message()
        );
    }

    /// `impersonated_service_account` ADC: the source credential's grant runs
    /// first, its bearer pays for the hop, and the delegates ride along.
    #[tokio::test]
    async fn impersonated_credentials_mint_the_source_bearer_first() {
        let idp = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            "{\"access_token\": \"source-user-token\", \"expires_in\": 3600}",
        ));
        let iam = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            impersonation_ok_body(3600),
        ));
        let json = serde_json::json!({
            "type": "impersonated_service_account",
            "service_account_impersonation_url": iam.endpoint(),
            "delegates": ["chain@p.iam.gserviceaccount.com"],
            "source_credentials": {
                "type": "authorized_user",
                "client_id": "abc",
                "client_secret": "shh",
                "refresh_token": "rt",
                "token_uri": idp.endpoint(),
            },
        });
        let auth =
            Authenticator::new(&bundle_with_json(&json), reqwest::Client::new()).expect("build");
        let (token, _ttl) = auth.refresh_now().await.expect("exchange");
        assert_eq!(token, "impersonated-token");
        assert_eq!(idp.hits(), 1, "the source grant runs first");
        let iam_request = &iam.requests()[0];
        assert!(
            iam_request.contains("source-user-token"),
            "the source bearer pays for the hop: {iam_request}"
        );
        assert!(
            iam_request.contains("chain@p.iam.gserviceaccount.com"),
            "delegates must ride along: {iam_request}"
        );
    }
}
