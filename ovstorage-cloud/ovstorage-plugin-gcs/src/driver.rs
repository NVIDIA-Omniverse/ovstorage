// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ConnectionAuthDriver` for GCS credentials (RFC-0066).
//!
//! One driver instance is bound to one connection and carries its parsed
//! [`GcsConnectionConfig`]. Like azure — and unlike s3 — there is **no live
//! credential cell**: an [`Authenticator`] is immutable once resolved (its
//! OAuth token cache self-refreshes internally), so `activate` and
//! `identity_gen` keep the trait defaults and the layer rejects
//! `update_connection_credentials` outright — credentials are frozen at add
//! time.
//!
//! Neither credential arm consumes a one-time credential: the
//! service-account arm mints a fresh JWT assertion per grant, and the
//! authorized-user arm's refresh token is REUSABLE (Google does not rotate it
//! on exchange). Both grants are repeatable, so `obtain` is resolution-only
//! (no IdP call) and never returns `WouldConsume`. `refresh` keeps the trait
//! default (`Unsupported`): token freshness is owned by the `Authenticator`,
//! not the `ConnectionSet`.

use std::sync::Arc;

use async_trait::async_trait;

use ovstorage_plugin::connection::{ConnectionAuthDriver, GrantPolicy, Obtained};
use ovstorage_plugin::{
    AuthEventStream, CancellationToken, Connection, Error, ErrorCode, ErrorContext,
    InteractiveAuthCapability, Result, SecretBundle, race_cancel,
};

use crate::auth::Authenticator;
use crate::{GcsBackend, GcsConnectionConfig, build_http_client, validate_credentials};

/// Whether an auth-tagged error reason is a DEFINITIVE credential rejection
/// (parkable) rather than a transient condition. GCS makes the storage-side
/// split native — 401 (`gcs_unauthorized`) is a bad/expired credential while
/// 403 maps to `PermissionDenied` and passes — and the token-endpoint half is
/// [`crate::auth::reason_is_grant_refusal`], which the promotion latch reads
/// too. Delegating rather than restating it makes the subset relation
/// structural: the two cannot drift into disagreeing about which grant
/// failures are definitive.
fn reason_is_credential_rejection(reason: &str) -> bool {
    reason == "gcs_unauthorized" || crate::auth::reason_is_grant_refusal(reason)
}

pub(crate) struct GcsDriver {
    config: GcsConnectionConfig,
}

impl GcsDriver {
    pub(crate) fn new(config: GcsConnectionConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ConnectionAuthDriver for GcsDriver {
    fn backend_kind(&self) -> &str {
        "gcs"
    }

    async fn obtain(
        &self,
        creds: &SecretBundle,
        _policy: GrantPolicy,
        _cancel: Option<CancellationToken>,
    ) -> Result<Obtained> {
        // Both `GrantPolicy` arms behave identically: resolution reads only
        // the bundle (or the local ADC file) — no keyring, no IdP grant —
        // so nothing is consumable and a probe never needs `WouldConsume`.
        // An unreadable ADC file errors here (`NotConfigured`), a
        // deterministic local misconfiguration that parks.
        validate_credentials(creds)?;
        let authenticator = Authenticator::new(creds, build_http_client()?)?;
        if authenticator.is_anonymous() {
            Ok(Obtained::Anonymous)
        } else {
            // The effective bundle IS the input bundle (no rotation). No
            // `expires_at`: OAuth token freshness is owned by the
            // `Authenticator`'s cache + background refresh, so the
            // `ConnectionSet` scheduler stays out of it.
            Ok(Obtained::Bearer {
                credentials: creds.clone(),
                expires_at: None,
            })
        }
    }

    async fn verify(
        &self,
        credentials: &SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let http = build_http_client()?;
        let authenticator = Authenticator::new(credentials, http.clone())?;
        if authenticator.is_anonymous() {
            // Anonymous connections have nothing to prove: unsigned reads
            // either work against the bucket policy or fail per-object at
            // data time.
            return Ok(());
        }
        // Ephemeral backend (built, used once, dropped). Deliberately NO
        // `install_background_refresh` here — the verify path needs one
        // token, not a refresh loop, so nothing is spawned-and-aborted (the
        // waste flagged on the azure port); the layer's durable instance is
        // the one that installs the refresh task.
        let backend = GcsBackend::new(self.config.clone(), http, Arc::new(authenticator));
        // One read-only `objects.list maxResults=1`, judged LENIENTLY on the
        // MAPPED error:
        // - Ok: accepted.
        // - 401 (`gcs_unauthorized`) or a definitive token-endpoint failure
        //   (`crate::auth::reason_is_grant_refusal`: a 400/401 grant refusal,
        //   or a 200 that produced no usable bearer): rejected — the
        //   credential itself is bad.
        // - Everything else (403 `PermissionDenied` from IAM scoping,
        //   token-endpoint 429/5xx, `token_transport`, storage transport
        //   blips, GCS-compatible error shapes): accepted. The credential
        //   was not refuted; authorization scope is a data-path concern.
        let outcome =
            race_cancel(cancel.as_ref(), async { Ok(backend.verify_probe().await) }).await?;
        match outcome {
            Ok(()) => Ok(()),
            Err(error) => {
                let reason = match error.context() {
                    Some(ErrorContext::Auth { reason, .. }) => reason.as_deref().unwrap_or(""),
                    _ => "",
                };
                if reason_is_credential_rejection(reason) {
                    Err(error)
                } else {
                    tracing::debug!(
                        plugin = "gcs",
                        error.code = ?error.code(),
                        reason,
                        "gcs verify: non-credential failure treated as pass"
                    );
                    Ok(())
                }
            }
        }
    }

    async fn interactive(
        &self,
        _connection: Connection,
        _capability: InteractiveAuthCapability,
        _cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        // GCS has no interactive flow; credentials arrive with the connection.
        // `Unsupported` is the code `Layer::authenticate_connection` documents
        // for exactly this — a backend with no flow, as opposed to
        // `AuthRequired`, which is a flow that exists and could not be driven.
        // `ConnectionSet::authenticate` propagates it before the promoting
        // adapter is built, so a parked connection stays parked instead of
        // being reported `Authenticated` on no grant and no probe.
        Err(Error::new(
            ErrorCode::Unsupported,
            "gcs has no interactive authentication flow; supply credentials \
             with the connection",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::{ConfigValue, ErrorCode, SecretBytes, SecretValue};
    use std::collections::HashMap;

    fn test_config() -> GcsConnectionConfig {
        let mut config = HashMap::new();
        config.insert("bucket".into(), ConfigValue::String("bkt".into()));
        crate::__test_only_parse_config(&config).unwrap()
    }

    fn driver() -> GcsDriver {
        GcsDriver::new(test_config())
    }

    /// Only DEFINITIVE refusals park: a storage-side 401 and token-endpoint
    /// 400/401 reject the credential; token-endpoint 429/5xx, transport
    /// failures, and storage 403s are transient/scoped and must pass the
    /// lenient verify — with `refresh` unsupported, parking on a transient
    /// would strand a valid credential until manual remove/re-add.
    #[test]
    fn rejection_is_limited_to_definitive_reasons() {
        assert!(reason_is_credential_rejection("gcs_unauthorized"));
        assert!(reason_is_credential_rejection("token_exchange_http_400"));
        assert!(reason_is_credential_rejection("token_exchange_http_401"));
        for transient in [
            "token_exchange_http_429",
            "token_exchange_http_500",
            "token_exchange_http_503",
            "token_transport",
            "non_oauth",
            "",
        ] {
            assert!(
                !reason_is_credential_rejection(transient),
                "'{transient}' must be treated as transient, not a credential rejection"
            );
        }
    }

    #[tokio::test]
    async fn obtain_with_empty_bundle_is_anonymous() {
        let outcome = driver()
            .obtain(&SecretBundle::default(), GrantPolicy::AllowConsuming, None)
            .await
            .unwrap();
        assert!(matches!(outcome, Obtained::Anonymous));
    }

    #[tokio::test]
    async fn obtain_rejects_unknown_credential_field() {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "not_a_field".into(),
            SecretValue::Bytes(SecretBytes(b"x".to_vec())),
        );
        let err = driver()
            .obtain(&bundle, GrantPolicy::AllowConsuming, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn verify_anonymous_bundle_passes_without_rpc() {
        driver()
            .verify(&SecretBundle::default(), None)
            .await
            .unwrap();
    }

    /// Token freshness is the `Authenticator`'s job; the trait-default
    /// `Unsupported` is what makes the lifecycle park a rejected credential
    /// instead of looping. Pin it.
    #[tokio::test]
    async fn refresh_is_unsupported() {
        let err = driver()
            .refresh(&SecretBundle::default(), None, 0)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    /// GCS has no interactive flow to open, so the honest answer is
    /// `Unsupported` rather than a `Succeeded` event asserting a sign-in that
    /// never happened. The refusal does not depend on the connection's state or
    /// on the host's capability: there is no flow under any of them.
    #[tokio::test]
    async fn interactive_reports_no_flow() {
        use ovstorage_plugin::{
            Capabilities, ConnectionAuthState, ConnectionId, ConnectionSource, UserMetadata,
        };
        let connection = Connection {
            id: ConnectionId("c1".into()),
            backend_kind: "gcs".into(),
            display_name: "gcs".into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: UserMetadata::new(),
        };
        // Every capability, because the claim is that there is no flow under
        // any of them — not that the default happens to be refused.
        for capability in [
            InteractiveAuthCapability::None,
            InteractiveAuthCapability::Headless,
            InteractiveAuthCapability::Browser,
        ] {
            let err = driver()
                .interactive(connection.clone(), capability, None)
                .await
                .err()
                .expect("gcs offers no interactive flow to open");
            assert_eq!(
                err.code(),
                ErrorCode::Unsupported,
                "capability {capability:?} must not change the answer"
            );
        }
    }
}
