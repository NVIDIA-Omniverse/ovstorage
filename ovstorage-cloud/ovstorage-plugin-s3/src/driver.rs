// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ConnectionAuthDriver` for static AWS SigV4 credentials (RFC-0066).
//!
//! One driver instance is bound to one connection: it carries that
//! connection's parsed [`S3Config`] and shares the live credential cell with
//! the connection's [`crate::backend::S3Backend`], so
//! [`ConnectionAuthDriver::activate`]
//! installing a proven bundle is immediately visible to the backend's SDK
//! clients (identity caching is disabled — every request re-reads the cell).
//!
//! S3 credentials are **static keys** in gen1: `refresh` keeps the trait
//! default (`Unsupported`, so the lifecycle parks instead of looping),
//! `interactive` answers `Unsupported` (credential supply happens with the
//! connection or via `update_connection_credentials`, and there is no flow to
//! open), and `classify` keeps
//! [`ovstorage_plugin::connection::default_classify`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use ovstorage_plugin::connection::{ConnectionAuthDriver, GrantPolicy, Obtained};
use ovstorage_plugin::{
    AuthEventStream, CancellationToken, Connection, Error, ErrorCode, InteractiveAuthCapability,
    Result, SecretBundle,
};

use crate::client::{RefusalEpoch, SharedAwsCredentials, build_http_client, build_s3_client};
use crate::config::S3Config;
use crate::credentials::{self, AwsCredentials};

/// Modeled S3 error codes that prove the *credentials themselves* were
/// rejected. Real S3 surfaces a bad key id / signature as HTTP 403 with one of
/// these codes, so the raw status alone cannot distinguish "bad credentials"
/// from "valid credentials, restricted policy" — the modeled code can.
///
/// Scope of the parking guarantee: only a **cryptographically-rejected**
/// credential parks. A credential that is policy-dead yet cryptographically
/// valid — MFA-required, an SCP/explicit deny, a disabled key on stores that
/// answer plain `AccessDenied`, or S3-compatible endpoints with different
/// error shapes — PASSES verify, reports `Authenticated`, and then fails at
/// the data path. That is the deliberate lenient-verify trade (authorization
/// scope is a data-path concern); driver authors copying this template must
/// not read "parks on dead credentials" as covering the policy-dead case.
const CREDENTIAL_REJECTION_CODES: &[&str] = &[
    "InvalidAccessKeyId",
    "SignatureDoesNotMatch",
    "ExpiredToken",
    "TokenRefreshRequired",
    "InvalidToken",
];

pub(crate) struct S3Driver {
    config: S3Config,
    /// The live credential cell shared with the connection's `S3Backend`
    /// (`S3Backend::with_credentials_cell`). `activate` writes it; the SDK
    /// clients read it per-request.
    live_cell: Arc<Mutex<Option<AwsCredentials>>>,
    /// Identity generation for the verify→activate supersession fence. Static
    /// keys have no identity-changing live path in gen1 (there is no
    /// interactive flow), so this never bumps — the fence is structural, kept so a
    /// future STS/interactive driver inherits correct semantics.
    identity_gen: AtomicU64,
}

impl S3Driver {
    pub(crate) fn new(config: S3Config, live_cell: Arc<Mutex<Option<AwsCredentials>>>) -> Self {
        Self {
            config,
            live_cell,
            identity_gen: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl ConnectionAuthDriver for S3Driver {
    fn backend_kind(&self) -> &str {
        "s3"
    }

    async fn obtain(
        &self,
        creds: &SecretBundle,
        _policy: GrantPolicy,
        _cancel: Option<CancellationToken>,
    ) -> Result<Obtained> {
        // Both `GrantPolicy` arms behave identically: resolving static keys
        // (from the bundle or the AWS shared credentials file) consumes
        // nothing, so a probe never needs `Obtained::WouldConsume`.
        credentials::validate_credential_fields(creds)?;
        match credentials::resolve_bundle(creds)? {
            // Static keys: the effective bundle IS the input bundle (no
            // rotation), and there is no known expiry.
            Some(_) => Ok(Obtained::Bearer {
                credentials: creds.clone(),
                expires_at: None,
            }),
            None => Ok(Obtained::Anonymous),
        }
    }

    async fn verify(
        &self,
        credentials: &SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let Some(resolved) = credentials::resolve_bundle(credentials)? else {
            // Anonymous connections have nothing to prove: an unsigned request
            // either works against the bucket policy or is refused at data
            // time, per operation and per object.
            return Ok(());
        };
        // Ephemeral client (built, used once, dropped): a one-shot cell +
        // provider so nothing touches the live transport state.
        let cell = Arc::new(Mutex::new(Some(resolved)));
        let provider = SharedAwsCredentials::new(cell);
        // A fresh refusal epoch, discarded with the client: this probe's
        // refusal is its own — parking is what it controls — and must not veto
        // a promotion on the durable connection, whose credential it says
        // nothing about.
        let client = build_s3_client(
            &self.config,
            provider,
            build_http_client(),
            RefusalEpoch::default(),
        )?;
        let request = client
            .list_objects_v2()
            .bucket(&self.config.bucket)
            .max_keys(1);
        let request = if self.config.force_request_payer {
            request.request_payer(aws_sdk_s3::types::RequestPayer::Requester)
        } else {
            request
        };
        // One read-only RPC, judged LENIENTLY: only a cryptographic /
        // token-validity rejection fails the verify. A `ListObjectsV2` is used
        // over `HeadBucket` because HEAD responses carry no error body, so the
        // modeled-code discrimination below would be impossible.
        //
        // - 2xx: accepted.
        // - Modeled credential-rejection codes (`InvalidAccessKeyId`,
        //   `SignatureDoesNotMatch`, expired/invalid token) or a raw 401:
        //   rejected — the signature itself is bad.
        // - Everything else (403 `AccessDenied`, `NoSuchBucket`, transport
        //   blips, S3-compatible stores with different error shapes): accepted.
        //   The signature was not refuted; authorization scope is a data-path
        //   concern. A restricted-IAM principal (GetObject-only policy) must
        //   still register; lenient transport handling avoids rejecting it.
        let outcome =
            ovstorage_plugin::race_cancel(cancel.as_ref(), async { Ok(request.send().await) })
                .await?;
        match outcome {
            Ok(_) => Ok(()),
            Err(err) => {
                use aws_sdk_s3::error::ProvideErrorMetadata as _;
                let modeled = err.as_service_error().and_then(|svc| svc.code());
                let raw_status = err.raw_response().map(|resp| resp.status().as_u16());
                let credential_rejection = modeled
                    .map(|code| CREDENTIAL_REJECTION_CODES.contains(&code))
                    .unwrap_or(false)
                    || raw_status == Some(401);
                if credential_rejection {
                    Err(crate::errors::map_sdk_error("s3 verify", err))
                } else {
                    tracing::debug!(
                        plugin = "s3",
                        code = modeled.unwrap_or(""),
                        status = raw_status.unwrap_or(0),
                        "s3 verify: non-credential error treated as pass"
                    );
                    Ok(())
                }
            }
        }
    }

    async fn activate(&self, credentials: &SecretBundle, expected_gen: u64) -> Result<bool> {
        // Install the proven keys onto the live cell, fenced on the identity
        // generation captured at grant start. A skip is not an error: the
        // newer identity already won and the set discards this stale bundle.
        // Report whether the fenced install committed so the set-side commit
        // gates on it rather than re-reading `identity_gen`.
        if self.identity_gen.load(Ordering::Acquire) != expected_gen {
            return Ok(false);
        }
        if let Some(resolved) = credentials::resolve_bundle(credentials)? {
            *self.live_cell.lock().expect("credential mutex poisoned") = Some(resolved);
        }
        Ok(true)
    }

    fn identity_gen(&self) -> u64 {
        self.identity_gen.load(Ordering::Acquire)
    }

    async fn interactive(
        &self,
        _connection: Connection,
        _capability: InteractiveAuthCapability,
        _cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        // Credentials are supplied with the connection or via
        // `update_credentials`, not an interactive flow. `Unsupported` is the
        // code `Layer::authenticate_connection` documents for exactly this — a
        // backend with no flow, as opposed to `AuthRequired`, which is a flow
        // that exists and could not be driven. `ConnectionSet::authenticate`
        // propagates it before the promoting adapter is built, so a parked
        // connection stays parked instead of being reported `Authenticated` on
        // no grant and no probe.
        Err(Error::new(
            ErrorCode::Unsupported,
            "s3 has no interactive authentication flow; supply credentials with \
             the connection",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::connection::default_classify;
    use ovstorage_plugin::{Error, ErrorCode, SecretBytes, SecretValue};

    fn test_config(bucket: &str, endpoint: Option<&str>) -> S3Config {
        let mut config = std::collections::HashMap::new();
        config.insert(
            "bucket".to_string(),
            ovstorage_plugin::ConfigValue::String(bucket.to_string()),
        );
        config.insert(
            "region".to_string(),
            ovstorage_plugin::ConfigValue::String("us-east-1".to_string()),
        );
        if let Some(endpoint) = endpoint {
            config.insert(
                "endpoint".to_string(),
                ovstorage_plugin::ConfigValue::String(endpoint.to_string()),
            );
            config.insert(
                "compatibility_profile".to_string(),
                ovstorage_plugin::ConfigValue::String("custom".to_string()),
            );
            config.insert(
                "force_path_style".to_string(),
                ovstorage_plugin::ConfigValue::Bool(true),
            );
        }
        crate::config::parse_config(&config).unwrap()
    }

    fn driver(bucket: &str, endpoint: Option<&str>) -> S3Driver {
        S3Driver::new(test_config(bucket, endpoint), Arc::new(Mutex::new(None)))
    }

    fn key_bundle(access: &str, secret: &str) -> SecretBundle {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "aws_access_key_id".into(),
            SecretValue::Bytes(SecretBytes(access.as_bytes().to_vec())),
        );
        bundle.fields.insert(
            "aws_secret_access_key".into(),
            SecretValue::Bytes(SecretBytes(secret.as_bytes().to_vec())),
        );
        bundle
    }

    #[tokio::test]
    async fn obtain_with_keys_is_bearer_without_expiry() {
        let driver = driver("bucket", None);
        let bundle = key_bundle("AKIATEST", "secret");
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
        let driver = driver("bucket", None);
        let outcome = driver
            .obtain(&SecretBundle::default(), GrantPolicy::AllowConsuming, None)
            .await
            .unwrap();
        assert!(matches!(outcome, Obtained::Anonymous));
    }

    #[tokio::test]
    async fn obtain_rejects_unknown_credential_field() {
        let driver = driver("bucket", None);
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "not_a_field".into(),
            SecretValue::Bytes(SecretBytes(b"x".to_vec())),
        );
        let err = driver
            .obtain(&bundle, GrantPolicy::AllowConsuming, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn obtain_rejects_incomplete_bundle() {
        let driver = driver("bucket", None);
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "aws_access_key_id".into(),
            SecretValue::Bytes(SecretBytes(b"only-access".to_vec())),
        );
        let err = driver
            .obtain(&bundle, GrantPolicy::AllowConsuming, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
    }

    #[tokio::test]
    async fn verify_anonymous_bundle_passes_without_rpc() {
        // Endpoint is unroutable; an RPC attempt would error, so a pass proves
        // the anonymous short-circuit.
        let driver = driver("bucket", Some("http://127.0.0.1:1"));
        driver.verify(&SecretBundle::default(), None).await.unwrap();
    }

    #[tokio::test]
    async fn verify_transport_failure_is_lenient_pass() {
        // Unroutable endpoint → DispatchFailure (no modeled code, no status):
        // not a credential rejection, so the lenient verify passes.
        let driver = driver("bucket", Some("http://127.0.0.1:1"));
        driver
            .verify(&key_bundle("AKIATEST", "secret"), None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn activate_installs_into_live_cell() {
        let cell = Arc::new(Mutex::new(None));
        let driver = S3Driver::new(test_config("bucket", None), cell.clone());
        let committed = driver
            .activate(&key_bundle("AKIANEW", "next-secret"), 0)
            .await
            .unwrap();
        assert!(committed, "an uncontended activate reports committed");
        let installed = cell.lock().unwrap().clone().unwrap();
        assert_eq!(installed.access_key_id, "AKIANEW");
        assert_eq!(installed.secret_access_key, "next-secret");
    }

    #[tokio::test]
    async fn activate_with_stale_gen_is_discarded() {
        let cell = Arc::new(Mutex::new(None));
        let driver = S3Driver::new(test_config("bucket", None), cell.clone());
        let committed = driver
            .activate(&key_bundle("AKIASTALE", "stale"), 7)
            .await
            .unwrap();
        assert!(!committed, "a stale-fenced activate reports NOT committed");
        assert!(cell.lock().unwrap().is_none(), "stale gen must not install");
    }

    /// S3 has no interactive flow to open, so the honest answer is
    /// `Unsupported` rather than a `Succeeded` event asserting a sign-in that
    /// never happened. The refusal does not depend on the connection's state or
    /// on the host's capability: there is no flow under any of them.
    #[tokio::test]
    async fn interactive_reports_no_flow() {
        use ovstorage_plugin::{
            Capabilities, ConnectionAuthState, ConnectionId, ConnectionSource, UserMetadata,
        };
        let driver = driver("bucket", None);
        let connection = Connection {
            id: ConnectionId("c1".into()),
            backend_kind: "s3".into(),
            display_name: "s3".into(),
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
            let err = driver
                .interactive(connection.clone(), capability, None)
                .await
                .err()
                .expect("s3 offers no interactive flow to open");
            assert_eq!(
                err.code(),
                ErrorCode::Unsupported,
                "capability {capability:?} must not change the answer"
            );
        }
    }

    /// Static keys have no non-interactive refresh: the trait-default
    /// `Unsupported` is what makes the lifecycle PARK a rejected credential
    /// instead of looping refresh attempts. Pin it so a future STS driver
    /// changing this does so deliberately.
    #[tokio::test]
    async fn refresh_is_unsupported_for_static_keys() {
        let driver = driver("bucket", None);
        let err = driver
            .refresh(&key_bundle("AKIATEST", "secret"), None, 0)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[test]
    fn classify_uses_the_default_taxonomy() {
        let driver = driver("bucket", None);
        let auth = Error::new(ErrorCode::AuthRequired, "401");
        assert_eq!(driver.classify(&auth), default_classify(&auth));
        let denied = Error::new(ErrorCode::PermissionDenied, "403");
        assert_eq!(driver.classify(&denied), default_classify(&denied));
    }
}
