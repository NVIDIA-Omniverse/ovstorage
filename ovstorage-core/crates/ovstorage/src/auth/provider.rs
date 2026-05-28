// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `CredentialProvider` trait + built-in providers.
//!
//! - [`EnvProvider`] — env vars per `backend_kind`.
//! - [`CallbackCredentialProvider`] — async closure for external
//!   token-management (control-plane portals, K8s service-account
//!   fetchers).
//!
//! Backend-specific providers (AWS, Azure, GCS, Nucleus) live in their
//! own crates and implement the same trait.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::time::SystemTime;

use async_trait::async_trait;
use ovstorage_plugin::{BackendId, Error, ErrorCode, SecretBundle, SecretBytes, SecretValue};

/// Principal a credential is resolved for. Used as a hash key in
/// [`CredentialCache`](super::CredentialCache); keep additions
/// backwards-compatible.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrincipalView {
    pub id: String,
}

impl PrincipalView {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

/// Resolved credential bytes plus optional expiry. `expires_at = None`
/// falls back to `static_cred_ttl`. `source_name` is for tracing —
/// MUST NOT contain token bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedCredential {
    pub bytes: SecretBundle,
    pub expires_at: Option<SystemTime>,
    pub source_name: String,
}

/// `Unavailable` falls through to the next provider in the chain.
/// `Backend` short-circuits — a backend-side failure must not silently
/// fall through to a less-trusted provider.
#[derive(Clone, Debug)]
pub enum CredentialError {
    Unavailable { details: String },
    Backend(Error),
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialError::Unavailable { details } => {
                write!(f, "credential unavailable: {details}")
            }
            CredentialError::Backend(err) => write!(f, "{err:?}"),
        }
    }
}

impl std::error::Error for CredentialError {}

impl From<Error> for CredentialError {
    fn from(err: Error) -> Self {
        CredentialError::Backend(err)
    }
}

impl From<CredentialError> for Error {
    fn from(err: CredentialError) -> Self {
        match err {
            CredentialError::Unavailable { details } => {
                Error::new(ErrorCode::CredentialUnavailable, details).with_next_action(
                    "Call library.set_credential(connection_id, principal_id, ...) to \
                 supply credentials, or library.authenticate_connection(connection_id) \
                 to run the interactive authentication flow.",
                )
            }
            CredentialError::Backend(inner) => inner,
        }
    }
}

/// Resolve credential bytes for `(backend, principal)`. Chain consulted
/// in order; first non-`Unavailable` wins; `Backend(Error)` short-
/// circuits.
#[async_trait]
pub trait CredentialProvider: Send + Sync + std::fmt::Debug {
    /// Stable trace identity. MUST NOT contain token bytes.
    fn name(&self) -> &str;

    async fn resolve(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<ResolvedCredential, CredentialError>;
}

/// One env-var → `SecretBundle` field mapping.
#[derive(Clone, Debug)]
pub struct EnvField {
    pub config_key: String,
    pub env_var: String,
}

impl EnvField {
    pub fn new(config_key: impl Into<String>, env_var: impl Into<String>) -> Self {
        Self {
            config_key: config_key.into(),
            env_var: env_var.into(),
        }
    }
}

/// Reads env vars per `backend_kind` schema (e.g. `AWS_*`, `AZURE_*`).
/// Stateless beyond schema; missing vars surface as `Unavailable` so
/// the chain can fall through.
pub struct EnvProvider {
    name: String,
    by_kind: HashMap<String, Vec<EnvField>>,
}

impl fmt::Debug for EnvProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvProvider")
            .field("name", &self.name)
            .field("kinds", &self.by_kind.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl EnvProvider {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            by_kind: HashMap::new(),
        }
    }

    /// `backend_id_or_kind` is matched against `BackendId.0`. Pass the
    /// backend kind (e.g. `"s3"`) for kind-keyed schemas, or the
    /// instance value for instance-keyed schemas.
    pub fn with_schema(
        mut self,
        backend_id_or_kind: impl Into<String>,
        fields: Vec<EnvField>,
    ) -> Self {
        self.by_kind.insert(backend_id_or_kind.into(), fields);
        self
    }
}

#[async_trait]
impl CredentialProvider for EnvProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn resolve(
        &self,
        backend: &BackendId,
        _principal: &PrincipalView,
    ) -> Result<ResolvedCredential, CredentialError> {
        let fields = self
            .by_kind
            .get(&backend.0)
            .ok_or_else(|| CredentialError::Unavailable {
                details: format!("no env schema for backend {:?}", backend),
            })?;
        let mut bundle = SecretBundle::default();
        let mut missing: Vec<String> = Vec::new();
        for field in fields {
            match std::env::var(&field.env_var) {
                Ok(value) => {
                    bundle.fields.insert(
                        field.config_key.clone(),
                        SecretValue::Bytes(SecretBytes(value.into_bytes())),
                    );
                }
                Err(std::env::VarError::NotPresent) => {
                    missing.push(field.env_var.clone());
                }
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(CredentialError::Backend(Error::new(
                        ErrorCode::InvalidArgument,
                        format!("env var {} contains non-UTF-8 data", field.env_var),
                    )));
                }
            }
        }
        if !missing.is_empty() {
            return Err(CredentialError::Unavailable {
                details: format!("env vars not set: {}", missing.join(", ")),
            });
        }
        Ok(ResolvedCredential {
            bytes: bundle,
            expires_at: None,
            source_name: self.name.clone(),
        })
    }
}

/// Closure-driven provider for external token-management. Most hosts
/// use [`crate::LibraryBuilder::with_credential_callback`] instead.
pub struct CallbackCredentialProvider<F, Fut>
where
    F: Fn(BackendId, PrincipalView) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<ResolvedCredential, CredentialError>> + Send + 'static,
{
    name: String,
    callback: F,
}

impl<F, Fut> CallbackCredentialProvider<F, Fut>
where
    F: Fn(BackendId, PrincipalView) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<ResolvedCredential, CredentialError>> + Send + 'static,
{
    pub fn new(name: impl Into<String>, callback: F) -> Self {
        Self {
            name: name.into(),
            callback,
        }
    }
}

impl<F, Fut> fmt::Debug for CallbackCredentialProvider<F, Fut>
where
    F: Fn(BackendId, PrincipalView) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<ResolvedCredential, CredentialError>> + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallbackCredentialProvider")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<F, Fut> CredentialProvider for CallbackCredentialProvider<F, Fut>
where
    F: Fn(BackendId, PrincipalView) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<ResolvedCredential, CredentialError>> + Send + 'static,
{
    fn name(&self) -> &str {
        &self.name
    }

    async fn resolve(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<ResolvedCredential, CredentialError> {
        (self.callback)(backend.clone(), principal.clone()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(kind: &str) -> BackendId {
        BackendId(kind.to_string())
    }

    fn principal() -> PrincipalView {
        PrincipalView::new("test-user")
    }

    #[tokio::test]
    async fn env_provider_returns_unavailable_when_var_unset() {
        let provider = EnvProvider::new("env").with_schema(
            "s3",
            vec![EnvField::new(
                "aws_access_key_id",
                "OVSTORAGE_TEST_UNSET_VAR_VARIABLE_THAT_DOES_NOT_EXIST",
            )],
        );
        let err = provider
            .resolve(&backend("s3"), &principal())
            .await
            .unwrap_err();
        match err {
            CredentialError::Unavailable { .. } => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn env_provider_returns_bundle_when_set() {
        let var = "OVSTORAGE_TEST_ENV_PROVIDER_KEY";
        // SAFETY: env mutation is process-global; var name is unique
        // to this test and no concurrent reader exists.
        unsafe {
            std::env::set_var(var, "rotated-value");
        }
        let provider = EnvProvider::new("env")
            .with_schema("s3", vec![EnvField::new("aws_access_key_id", var)]);
        let resolved = provider
            .resolve(&backend("s3"), &principal())
            .await
            .unwrap();
        unsafe {
            std::env::remove_var(var);
        }
        assert_eq!(resolved.source_name, "env");
        assert!(resolved.expires_at.is_none());
        assert!(resolved.bundle_has("aws_access_key_id"));
    }

    #[tokio::test]
    async fn env_provider_unknown_backend_falls_through() {
        let provider = EnvProvider::new("env");
        let err = provider
            .resolve(&backend("s3"), &principal())
            .await
            .unwrap_err();
        match err {
            CredentialError::Unavailable { .. } => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    impl ResolvedCredential {
        fn bundle_has(&self, key: &str) -> bool {
            self.bytes.fields.contains_key(key)
        }
    }

    #[tokio::test]
    async fn callback_credential_provider_invokes_closure() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = Arc::new(AtomicU32::new(0));
        let provider = {
            let calls = calls.clone();
            CallbackCredentialProvider::new("portal", move |backend, principal| {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(backend.0, "s3");
                    assert_eq!(principal.id, "test-user");
                    let mut bundle = SecretBundle::default();
                    bundle.fields.insert(
                        "access_token".into(),
                        SecretValue::Bytes(SecretBytes(b"portal-mint".to_vec())),
                    );
                    Ok(ResolvedCredential {
                        bytes: bundle,
                        expires_at: None,
                        source_name: "portal".into(),
                    })
                }
            })
        };
        let resolved = provider
            .resolve(&backend("s3"), &principal())
            .await
            .unwrap();
        assert_eq!(provider.name(), "portal");
        assert_eq!(resolved.source_name, "portal");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(resolved.bundle_has("access_token"));
    }

    #[tokio::test]
    async fn callback_credential_provider_propagates_error() {
        let provider = CallbackCredentialProvider::new("fail", |_b, _p| async {
            Err(CredentialError::Backend(Error::new(
                ErrorCode::CredentialUnavailable,
                "portal offline",
            )))
        });
        let err = provider
            .resolve(&backend("s3"), &principal())
            .await
            .unwrap_err();
        match err {
            CredentialError::Backend(_) => {}
            other => panic!("expected Backend, got {other:?}"),
        }
    }
}
