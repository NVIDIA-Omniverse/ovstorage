// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ConnectionAuthDriver` for the static Hugging Face bearer token.
//!
//! One driver instance is bound to one connection and shares its live token
//! cell with the connection's [`crate::HfBackend`]: `activate` installing a
//! proven bundle is immediately visible to the backend, whose requests re-read
//! the cell. The token is static — `refresh` keeps the trait default
//! (`Unsupported`, so the lifecycle parks a rejected credential instead of
//! looping) and `interactive` reports that no flow exists.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use ovstorage_plugin::connection::{ConnectionAuthDriver, GrantPolicy, Obtained};
use ovstorage_plugin::{
    AuthEventStream, CancellationToken, Connection, Error, ErrorCode, ErrorContext,
    InteractiveAuthCapability, Result, SecretBundle, SecretBytes, SecretValue, race_cancel,
};
use parking_lot::RwLock;

use crate::{HfConnectionConfig, api, map_reqwest_error, map_status};

/// Deadline on the single verify round-trip; bounded so a stalled endpoint
/// cannot hang a connection add.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// Extract-and-validate the one accepted credential field. `Ok(None)` is an
/// anonymous bundle; any unknown field is refused so a typo cannot silently
/// produce an anonymous connection that reports `Authenticated`.
pub(crate) fn validate_credentials(credentials: &SecretBundle) -> Result<Option<SecretBytes>> {
    let mut token: Option<SecretBytes> = None;
    for (key, value) in &credentials.fields {
        match key.as_str() {
            "token" => {
                let bytes = match value {
                    SecretValue::Bytes(bytes) | SecretValue::File(bytes) => bytes.as_bytes(),
                    _ => {
                        return Err(Error::new(
                            ErrorCode::InvalidArgument,
                            "huggingface credential field 'token' must be secret bytes or a file",
                        ));
                    }
                };
                let text = std::str::from_utf8(bytes).map_err(|_| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "huggingface credential field 'token' must be UTF-8 text",
                    )
                })?;
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    // An empty value (an unset env default) is anonymous, not
                    // an error.
                    continue;
                }
                if trimmed
                    .chars()
                    .any(|ch| ch.is_control() || ch.is_whitespace())
                {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "huggingface credential field 'token' must not contain whitespace or \
                         control characters",
                    ));
                }
                token = Some(SecretBytes(trimmed.as_bytes().to_vec()));
            }
            other => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("unsupported huggingface credential field '{other}'"),
                ));
            }
        }
    }
    Ok(token)
}

/// Whether a mapped error is a DEFINITIVE credential rejection (parkable)
/// rather than a transient or scope condition. Only the storage-side 401
/// (`hf_unauthorized`) qualifies; 403 is `PermissionDenied` (gating/scope) and
/// passes the lenient verify.
fn is_credential_rejection(error: &Error) -> bool {
    matches!(
        error.context(),
        Some(ErrorContext::Auth { reason: Some(reason), .. }) if reason == "hf_unauthorized"
    )
}

pub(crate) struct HfDriver {
    config: HfConnectionConfig,
    http: reqwest::Client,
    /// The live bearer shared with the connection's `HfBackend`. `activate`
    /// writes it; every backend request re-reads it.
    live_token: Arc<RwLock<Option<SecretBytes>>>,
    /// Identity generation for the verify→activate supersession fence. A
    /// static token has no identity-changing live path, so this never bumps —
    /// the fence is structural, kept so a future interactive driver inherits
    /// correct semantics.
    identity_gen: AtomicU64,
}

impl HfDriver {
    pub(crate) fn new(
        config: HfConnectionConfig,
        http: reqwest::Client,
        live_token: Arc<RwLock<Option<SecretBytes>>>,
    ) -> Self {
        Self {
            config,
            http,
            live_token,
            identity_gen: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl ConnectionAuthDriver for HfDriver {
    fn backend_kind(&self) -> &str {
        "huggingface"
    }

    async fn obtain(
        &self,
        creds: &SecretBundle,
        _policy: GrantPolicy,
        _cancel: Option<CancellationToken>,
    ) -> Result<Obtained> {
        // Both `GrantPolicy` arms behave identically: resolving a static
        // token reads only the bundle, consumes nothing, and needs no
        // `WouldConsume` arm.
        match validate_credentials(creds)? {
            None => Ok(Obtained::Anonymous),
            // The effective bundle IS the input bundle (no rotation, no
            // schedule the plugin can see).
            Some(_) => Ok(Obtained::Bearer {
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
        let Some(token) = validate_credentials(credentials)? else {
            // Anonymous connections have nothing to prove: unauthenticated
            // reads either work against public repositories or fail per
            // object at data time.
            return Ok(());
        };
        let text = std::str::from_utf8(token.as_bytes()).map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "huggingface token failed UTF-8 revalidation",
            )
        })?;
        let mut bearer = reqwest::header::HeaderValue::from_str(&format!("Bearer {text}"))
            .map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "huggingface token cannot be carried in a header",
                )
            })?;
        bearer.set_sensitive(true);
        // One read-only whoami round-trip, judged LENIENTLY on the mapped
        // error: only a definitive 401 rejects the credential itself.
        // Everything else (403 scoping, 429, 5xx, transport blips) passes —
        // parking on a transient would strand a valid token until manual
        // remove/re-add, since `refresh` is unsupported.
        let request = self
            .http
            .get(api::whoami_url(&self.config.endpoint))
            .header(reqwest::header::AUTHORIZATION, bearer)
            .timeout(VERIFY_TIMEOUT);
        let outcome = race_cancel(cancel.as_ref(), async { Ok(request.send().await) }).await?;
        match outcome {
            Ok(response) if response.status().is_success() => Ok(()),
            Ok(response) => {
                let status = response.status().as_u16();
                let error = map_status(status, Some(response.headers()), false);
                if is_credential_rejection(&error) {
                    Err(error)
                } else {
                    tracing::debug!(
                        plugin = "huggingface",
                        status,
                        error.code = ?error.code(),
                        "huggingface verify: non-credential failure treated as pass"
                    );
                    Ok(())
                }
            }
            Err(err) => {
                let error = map_reqwest_error(err);
                tracing::debug!(
                    plugin = "huggingface",
                    error.code = ?error.code(),
                    "huggingface verify: transport failure treated as pass"
                );
                Ok(())
            }
        }
    }

    async fn activate(&self, credentials: &SecretBundle, expected_gen: u64) -> Result<bool> {
        // Install the proven token onto the live cell, fenced on the identity
        // generation captured at grant start. A skip is not an error: a newer
        // identity already won and the set discards this stale bundle.
        if self.identity_gen.load(Ordering::Acquire) != expected_gen {
            return Ok(false);
        }
        if let Some(token) = validate_credentials(credentials)? {
            *self.live_token.write() = Some(token);
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
        // No interactive flow exists; credentials arrive with the connection
        // (or via `update_connection_credentials`). `Unsupported` is the code
        // `Layer::authenticate_connection` documents for exactly this, so a
        // parked connection stays parked instead of reporting a sign-in that
        // never happened.
        Err(Error::new(
            ErrorCode::Unsupported,
            "huggingface has no interactive authentication flow; supply a token with \
             the connection",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::ConfigValue;
    use std::collections::HashMap;

    fn test_config() -> HfConnectionConfig {
        let mut config = HashMap::new();
        config.insert("repo_id".into(), ConfigValue::String("acme/demo".into()));
        crate::__test_only_parse_config(&config).unwrap()
    }

    fn driver() -> HfDriver {
        HfDriver::new(
            test_config(),
            crate::build_http_client(false).unwrap(),
            Arc::new(RwLock::new(None)),
        )
    }

    fn token_bundle(token: &str) -> SecretBundle {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "token".into(),
            SecretValue::Bytes(SecretBytes(token.as_bytes().to_vec())),
        );
        bundle
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
    async fn obtain_with_a_token_is_a_bearer_without_expiry() {
        for policy in [GrantPolicy::AllowConsuming, GrantPolicy::NonConsumingOnly] {
            match driver()
                .obtain(&token_bundle("hf_test"), policy, None)
                .await
                .unwrap()
            {
                Obtained::Bearer {
                    credentials,
                    expires_at,
                } => {
                    assert_eq!(credentials.fields.len(), 1);
                    assert!(expires_at.is_none());
                }
                other => panic!("expected Bearer, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn obtain_rejects_unknown_credential_field() {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "password".into(),
            SecretValue::Bytes(SecretBytes(b"x".to_vec())),
        );
        let err = driver()
            .obtain(&bundle, GrantPolicy::AllowConsuming, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn tokens_are_normalized_and_validated() {
        assert!(
            validate_credentials(&SecretBundle::default())
                .unwrap()
                .is_none()
        );
        // An empty value (unset env default) is anonymous.
        assert!(validate_credentials(&token_bundle("  ")).unwrap().is_none());
        let token = validate_credentials(&token_bundle(" hf_abc \n"))
            .unwrap()
            .unwrap();
        assert_eq!(token.as_bytes(), b"hf_abc");
        let err = validate_credentials(&token_bundle("hf abc")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        let err = validate_credentials(&token_bundle("hf\x07abc")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn verify_anonymous_bundle_passes_without_rpc() {
        driver()
            .verify(&SecretBundle::default(), None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn activate_installs_into_live_cell() {
        let cell = Arc::new(RwLock::new(None));
        let driver = HfDriver::new(
            test_config(),
            crate::build_http_client(false).unwrap(),
            cell.clone(),
        );
        let committed = driver.activate(&token_bundle("hf_new"), 0).await.unwrap();
        assert!(committed, "an uncontended activate reports committed");
        assert_eq!(cell.read().as_ref().unwrap().as_bytes(), b"hf_new");
    }

    #[tokio::test]
    async fn activate_with_stale_gen_is_discarded() {
        let cell = Arc::new(RwLock::new(None));
        let driver = HfDriver::new(
            test_config(),
            crate::build_http_client(false).unwrap(),
            cell.clone(),
        );
        let committed = driver.activate(&token_bundle("hf_stale"), 7).await.unwrap();
        assert!(!committed, "a stale-fenced activate reports NOT committed");
        assert!(cell.read().is_none(), "stale gen must not install");
    }

    /// A static token has no non-interactive refresh: the trait-default
    /// `Unsupported` is what makes the lifecycle park a rejected credential
    /// instead of looping. Pin it.
    #[tokio::test]
    async fn refresh_is_unsupported() {
        let err = driver()
            .refresh(&token_bundle("hf_test"), None, 0)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn interactive_reports_no_flow() {
        use ovstorage_plugin::{
            Capabilities, ConnectionAuthState, ConnectionId, ConnectionSource, UserMetadata,
        };
        let connection = Connection {
            id: ConnectionId("c1".into()),
            backend_kind: "huggingface".into(),
            display_name: "huggingface".into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: UserMetadata::new(),
            owning_target: None,
        };
        // Every capability: the claim is that no flow exists under any of
        // them, not that the default happens to be refused.
        for capability in [
            InteractiveAuthCapability::None,
            InteractiveAuthCapability::Headless,
            InteractiveAuthCapability::Browser,
        ] {
            let err = driver()
                .interactive(connection.clone(), capability, None)
                .await
                .err()
                .expect("huggingface offers no interactive flow to open");
            assert_eq!(
                err.code(),
                ErrorCode::Unsupported,
                "capability {capability:?} must not change the answer"
            );
        }
    }

    #[test]
    fn rejection_is_limited_to_the_definitive_401() {
        assert!(is_credential_rejection(&map_status(401, None, false)));
        for lenient in [403, 404, 429, 500, 503] {
            assert!(
                !is_credential_rejection(&map_status(lenient, None, false)),
                "HTTP {lenient} must be treated as lenient, not a credential rejection"
            );
        }
    }
}
