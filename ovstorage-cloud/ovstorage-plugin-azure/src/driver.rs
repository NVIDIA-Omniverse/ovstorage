// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ConnectionAuthDriver` for Azure credentials (RFC-0066).
//!
//! One driver instance is bound to one connection and carries its parsed
//! [`AzureConnectionConfig`]. Unlike s3 there is **no live credential cell**:
//! an [`crate::auth::AzureAuth`] is immutable once resolved (OAuth arms
//! self-refresh internally via their background task), so `activate` and
//! `identity_gen` keep the trait defaults and the layer rejects
//! `update_connection_credentials` outright (see
//! [`crate::layer::AzureLayer`]) — credentials are frozen at add time.
//!
//! None of the four credential arms (account key, caller SAS, Entra
//! client-secret, Entra federated) consumes a one-time credential: the OAuth
//! grants are repeatable client-credentials flows, so `obtain` is
//! grant-free (resolution only) and never returns `WouldConsume`. `refresh`
//! keeps the trait default (`Unsupported`): token freshness for the OAuth
//! arms is owned by `AzureAuth`'s internal cache + background refresh, not
//! by the `ConnectionSet`.

use async_trait::async_trait;

use ovstorage_plugin::connection::{ConnectionAuthDriver, GrantPolicy, Obtained};
use ovstorage_plugin::{
    AuthEventStream, CancellationToken, Connection, Error, ErrorCode, ErrorContext,
    InteractiveAuthCapability, Result, SecretBundle, race_cancel,
};

use crate::auth::{AuthSource, AzureAuth};
use crate::backend::AzureBackend;
use crate::client::{entra_reason_is_grant_refusal, is_credential_rejection, map_status_to_error};
use crate::config::AzureConnectionConfig;

pub(crate) struct AzureDriver {
    config: AzureConnectionConfig,
}

impl AzureDriver {
    /// The body of this driver's `verify`, taking the resolved auth rather
    /// than the bundle.
    ///
    /// The seam exists so a test can inject the Entra token host, which
    /// `AzureAuth` only exposes through a `#[cfg(test)]` mutator: driving the
    /// real rejection path end to end is what pins this, and a truth table over
    /// the classifier cannot fail for any reason except editing the classifier.
    async fn verify_resolved(
        &self,
        auth: AzureAuth,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        if matches!(auth.source(), AuthSource::Anonymous) {
            // Anonymous connections have nothing to prove: unsigned reads
            // either work against the container policy or fail per-object at
            // data time.
            return Ok(());
        }
        // Ephemeral backend (built, used once, dropped — its OAuth
        // background-refresh task holds only a Weak and is aborted on drop):
        // one read-only List Blobs maxresults=1, judged LENIENTLY.
        //
        // - 2xx: accepted.
        // - 401, or 403 carrying a credential-rejection `x-ms-error-code`
        //   (`AuthenticationFailed`/`InvalidAuthenticationInfo`), or an Entra
        //   grant REFUSAL (`entra_status_*`): rejected — the credential
        //   itself is bad.
        // - Everything else (RBAC `AuthorizationPermissionMismatch`, scoped
        //   SAS denials, storage/IdP transport blips, Azurite/emulator error
        //   shapes): accepted. The credential was not refuted; authorization
        //   scope is a data-path concern.
        let backend = AzureBackend::with_auth(self.config.clone(), auth)?;
        let outcome =
            race_cancel(cancel.as_ref(), async { Ok(backend.verify_probe().await) }).await?;
        match outcome {
            Ok(response) if response.ok() => Ok(()),
            Ok(response) => {
                let code = response.headers.first("x-ms-error-code");
                if is_credential_rejection(response.status, code) {
                    Err(map_status_to_error(&response, "azure verify"))
                } else {
                    tracing::debug!(
                        plugin = "azure",
                        status = response.status,
                        code,
                        "azure verify: non-credential error treated as pass"
                    );
                    Ok(())
                }
            }
            Err(error) => {
                // `client.send` errors before an HTTP response: an Entra
                // grant outcome or a storage transport failure. Only a REFUSED
                // GRANT or an unreadable federated token file rejects; an
                // unreachable, throttled or erroring IdP or storage endpoint is
                // nobody answering about the credential.
                let reason = match error.context() {
                    Some(ErrorContext::Auth { reason, .. }) => reason.as_deref().unwrap_or(""),
                    _ => "",
                };
                if entra_reason_is_grant_refusal(reason) {
                    Err(error)
                } else {
                    tracing::debug!(
                        plugin = "azure",
                        error.code = ?error.code(),
                        reason,
                        "azure verify: non-credential failure treated as pass"
                    );
                    Ok(())
                }
            }
        }
    }

    pub(crate) fn new(config: AzureConnectionConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ConnectionAuthDriver for AzureDriver {
    fn backend_kind(&self) -> &str {
        "azure"
    }

    async fn obtain(
        &self,
        creds: &SecretBundle,
        _policy: GrantPolicy,
        _cancel: Option<CancellationToken>,
    ) -> Result<Obtained> {
        // Both `GrantPolicy` arms behave identically: resolution reads only
        // the bundle (no keyring, no IdP grant — the OAuth arms defer their
        // repeatable client-credentials grant to verify / the data path), so
        // nothing is consumable and a probe never needs `WouldConsume`.
        crate::config::validate_credential_keys(creds)?;
        let auth = AzureAuth::resolve(creds)?;
        match auth.source() {
            AuthSource::Anonymous => Ok(Obtained::Anonymous),
            // The effective bundle IS the input bundle (no rotation). No
            // `expires_at`: SAS expiry is opaque to the plugin and OAuth
            // token freshness is owned by `AzureAuth`'s background refresh,
            // so the `ConnectionSet` scheduler stays out of it.
            _ => Ok(Obtained::Bearer {
                credentials: creds.clone(),
                expires_at: None,
            }),
        }
    }

    async fn verify(
        &self,
        credentials: &SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.verify_resolved(AzureAuth::resolve(credentials)?, cancel)
            .await
    }

    async fn interactive(
        &self,
        _connection: Connection,
        _capability: InteractiveAuthCapability,
        _cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        // Azure has no interactive flow; credentials arrive with the connection.
        // `Unsupported` is the code `Layer::authenticate_connection` documents
        // for exactly this — a backend with no flow, as opposed to
        // `AuthRequired`, which is a flow that exists and could not be driven.
        // `ConnectionSet::authenticate` propagates it before the promoting
        // adapter is built, so a parked connection stays parked instead of
        // being reported `Authenticated` on no grant and no probe.
        Err(Error::new(
            ErrorCode::Unsupported,
            "azure has no interactive authentication flow; supply credentials \
             with the connection",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::{ConfigValue, ErrorCode, SecretBytes, SecretValue};
    use std::collections::HashMap;

    fn test_config() -> AzureConnectionConfig {
        let mut config = HashMap::new();
        config.insert("account".into(), ConfigValue::String("acct123".into()));
        config.insert("container".into(), ConfigValue::String("assets".into()));
        crate::__test_only_parse_config(&config).unwrap()
    }

    fn driver() -> AzureDriver {
        AzureDriver::new(test_config())
    }

    fn key_bundle() -> SecretBundle {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "account_key".into(),
            SecretValue::Bytes(SecretBytes(
                base64_encode(b"0123456789abcdef0123456789abcdef").into_bytes(),
            )),
        );
        bundle
    }

    fn base64_encode(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[tokio::test]
    async fn obtain_with_account_key_is_bearer_without_expiry() {
        let driver = driver();
        let bundle = key_bundle();
        for policy in [GrantPolicy::AllowConsuming, GrantPolicy::NonConsumingOnly] {
            match driver.obtain(&bundle, policy, None).await.unwrap() {
                Obtained::Bearer {
                    credentials,
                    expires_at,
                } => {
                    assert_eq!(credentials.fields.len(), bundle.fields.len());
                    assert!(expires_at.is_none());
                }
                other => panic!("expected Bearer, got {other:?}"),
            }
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

    /// One rule serves both consumers, because a false park heals itself and a
    /// false pass does not. `note_backend_accepted` promotes a parked
    /// connection on its next accepted operation and nothing gates operations
    /// on `auth_state`, so a wrong park costs one operation. `verify` returning
    /// `Ok` commits `Authenticated` with no path back — `refresh` is
    /// unsupported, credential updates are refused, and a later failure
    /// classifies as `NeedsInteractive`, which does not re-park.
    ///
    /// The code cannot narrow it either: `invalid_client` carries
    /// `AADSTS700211` (a federated credential that has not replicated, which
    /// Microsoft documents as retryable) and `invalid_request` carries
    /// `AADSTS70021`, the permanent half of the same condition.
    #[test]
    fn any_refused_grant_counts_whatever_code_it_carried() {
        for refusal in [
            "federated_token_file_unreadable",
            "entra_status_400",
            "entra_status_401",
            "entra_status_400/invalid_client",
            "entra_status_400/invalid_request",
            "entra_status_400/invalid_grant",
            "entra_status_400/unauthorized_client",
            "entra_status_400/invalid_scope",
            "entra_status_400/temporarily_unavailable",
            "entra_status_400/server_error",
            "entra_status_401/something_new",
        ] {
            assert!(
                entra_reason_is_grant_refusal(refusal),
                "'{refusal}' is a refused grant"
            );
        }
        // An outage is not a refusal: nobody answered about the credential.
        for outage in [
            "entra_status_429",
            "entra_status_500",
            "entra_status_503",
            "entra_status_504",
            "entra_transport",
            "non_oauth",
            "",
        ] {
            assert!(
                !entra_reason_is_grant_refusal(outage),
                "'{outage}' is an outage, not a refusal"
            );
        }
    }

    /// The case the predicate exists for, driven end to end rather than as a
    /// truth table: a rotated client secret makes Entra refuse the grant, and
    /// `verify` must REJECT. Passing it commits `Authenticated` on a dead
    /// credential, which nothing can undo.
    #[tokio::test]
    async fn verify_rejects_a_refused_entra_grant() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let body = r#"{"error":"invalid_client"}"#;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let entra_host = format!("http://{}", listener.local_addr().unwrap());
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\n\
             content-length: {}\r\n\r\n{body}",
            body.len()
        );
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });

        let mut bundle = SecretBundle::default();
        for (key, value) in [
            ("tenant_id", "tenant-uuid"),
            ("client_id", "client-uuid"),
            ("client_secret", "rotated-away"),
        ] {
            bundle.fields.insert(
                key.into(),
                SecretValue::Bytes(SecretBytes(value.as_bytes().to_vec())),
            );
        }

        let mut auth = AzureAuth::resolve(&bundle).expect("oauth auth resolves");
        auth.set_entra_host_for_test(entra_host);
        let error = driver()
            .verify_resolved(auth, None)
            .await
            .expect_err("a refused grant must not verify");
        assert_eq!(error.code(), ErrorCode::AuthRequired);
    }

    #[tokio::test]
    async fn verify_anonymous_bundle_passes_without_rpc() {
        driver()
            .verify(&SecretBundle::default(), None)
            .await
            .unwrap();
    }

    /// Static keys have no ConnectionSet-driven refresh: OAuth freshness is
    /// owned by `AzureAuth`'s internal cache, so the trait default
    /// (`Unsupported`) is what makes the lifecycle park a rejected credential
    /// instead of looping. Pin it.
    #[tokio::test]
    async fn refresh_is_unsupported() {
        let err = driver().refresh(&key_bundle(), None, 0).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    /// Azure has no interactive flow to open, so the honest answer is
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
            backend_kind: "azure".into(),
            display_name: "azure".into(),
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
                .expect("azure offers no interactive flow to open");
            assert_eq!(
                err.code(),
                ErrorCode::Unsupported,
                "capability {capability:?} must not change the answer"
            );
        }
    }
}
