// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Render-worker scenario test.
//!
//! One coordinator + N "workers" that share a `PrincipalView`. The
//! coordinator drives the upstream OAuth flow once via the
//! `OAuthCredentialProvider` (refresh-token grant against a fake
//! IdP). All subsequent worker resolves on the same
//! `(BackendId, PrincipalView)` slot hit the `CredentialCache`'s
//! warm path — the provider is invoked exactly once across the
//! coordinator + workers because the cache shares the slot.
//!
//! The render-worker case is structurally the same as multi-tenant
//! SaaS: one user with many local hosts sharing a `PrincipalView` at
//! the broker. Same machinery handles both.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use ovstorage::auth::{
    AuthRefreshLock, CredentialCache, CredentialCacheConfig, CredentialError, CredentialProvider,
    OAuthCredentialProvider, OAuthEndpoints, OAuthStrategy, PrincipalView, ResolvedCredential,
    SecretStore,
};
use ovstorage_plugin::{BackendId, SecretBundle, SecretBytes, SecretValue};
use url::Url;

/// Counting test provider — emulates the OAuth-driving credential
/// provider's external interface (resolve → ResolvedCredential) while
/// recording how many times the upstream IdP would actually be hit.
/// In production this is `OAuthCredentialProvider`; here we use a
/// counting stub so the test is keyring-independent (the OS keyring
/// on Linux/WSL is a no-op backend, which would defeat the warm-path
/// assertion this test makes about the `CredentialCache`).
#[derive(Debug)]
struct CountingOAuthProvider {
    name: String,
    backend_kind: String,
    upstream_calls: Arc<AtomicU32>,
}

#[async_trait]
impl CredentialProvider for CountingOAuthProvider {
    fn name(&self) -> &str {
        &self.name
    }
    async fn resolve(
        &self,
        backend: &BackendId,
        _principal: &PrincipalView,
    ) -> Result<ResolvedCredential, CredentialError> {
        if backend.0 != self.backend_kind {
            return Err(CredentialError::Unavailable {
                details: format!("not configured for {}", backend.0),
            });
        }
        // Tiny delay widens the stampede window.
        tokio::time::sleep(Duration::from_millis(10)).await;
        self.upstream_calls.fetch_add(1, Ordering::SeqCst);
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "oauth".into(),
            SecretValue::OAuthToken {
                token: SecretBytes("freshly-minted-access".into()),
                refresh: Some(SecretBytes("freshly-minted-refresh".into())),
                expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
            },
        );
        Ok(ResolvedCredential {
            bytes: bundle,
            expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
            source_name: self.name.clone(),
        })
    }
}

#[tokio::test]
async fn render_worker_scenario_shares_cache_across_workers() {
    // Coordinator runs the upstream OAuth flow once; three "workers"
    // share the resulting `PrincipalView` and all resolve through the
    // same `CredentialCache`. The provider's underlying upstream grant
    // runs exactly once across the coordinator + workers because the
    // cache's per-key single-flight collapses concurrent resolves on
    // the same (BackendId, PrincipalView) slot.
    //
    // Same machinery that handles per-user upstream OAuth in the
    // multi-tenant SaaS shape — workers and coordinator share a
    // `PrincipalView` at the broker via shared coordinator-issued
    // credentials, so they hit the same cache slot.
    let upstream_calls = Arc::new(AtomicU32::new(0));
    let provider = Arc::new(CountingOAuthProvider {
        name: "render-worker-test".into(),
        backend_kind: "nucleus".into(),
        upstream_calls: Arc::clone(&upstream_calls),
    });
    let chain: Vec<Arc<dyn CredentialProvider>> = vec![provider];

    let cache = Arc::new(CredentialCache::new(CredentialCacheConfig {
        refresh_skew: Duration::from_secs(60),
        static_cred_ttl: Duration::from_secs(300),
    }));

    let backend = BackendId("nucleus".into());
    let principal = PrincipalView::new("render-user");

    // Launch 4 concurrent resolvers (coordinator + 3 workers) that all
    // hit the same (BackendId, PrincipalView) slot.
    let mut handles = Vec::new();
    for _ in 0..4 {
        let cache = Arc::clone(&cache);
        let chain = chain.clone();
        let backend = backend.clone();
        let principal = principal.clone();
        handles.push(tokio::spawn(async move {
            cache.resolve(&backend, &principal, &chain).await
        }));
    }
    for h in handles {
        let resolved = h.await.unwrap().expect("worker resolve must succeed");
        assert_eq!(resolved.source_name, "render-worker-test");
        assert!(resolved.bytes.fields.contains_key("oauth"));
    }

    // Exactly one upstream OAuth grant: the cache's per-key
    // single-flight collapsed coordinator + 3 workers onto one
    // resolve. Workers reused the cached credential.
    assert_eq!(
        upstream_calls.load(Ordering::SeqCst),
        1,
        "render-worker scenario must serialize OAuth across coordinator + workers"
    );
    // cred_epoch advanced exactly once for the single resolve.
    assert_eq!(cache.cred_epoch(), 1);
}

#[tokio::test]
async fn oauth_provider_falls_through_for_unmatched_backend_in_chain() {
    // Smoke test: OAuthCredentialProvider drops to Unavailable for
    // backends it doesn't own, so chains can mix per-kind providers.
    let temp = tempfile::tempdir().unwrap();
    let secret_store = Arc::new(SecretStore::new());
    let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
    let endpoints = OAuthEndpoints {
        authorization_endpoint: Url::parse("https://idp.example/authorize").unwrap(),
        token_endpoint: Url::parse("https://idp.example/token").unwrap(),
        client_id: "x".into(),
        scope: None,
    };
    let provider = OAuthCredentialProvider::new(
        "chain-fallthrough",
        "nucleus",
        endpoints,
        secret_store,
        refresh_lock,
        OAuthStrategy::Device,
    );
    let err = provider
        .resolve(&BackendId("s3".into()), &PrincipalView::new("u"))
        .await
        .unwrap_err();
    match err {
        CredentialError::Unavailable { .. } => {}
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn worker_without_warm_token_and_interactive_disabled_returns_unavailable() {
    // Worker arriving at a cold cache (no persisted token) with
    // interactive disabled (no UI to drive OAuthFlow::pkce) gets
    // `Unavailable`/`AuthRequired` cleanly. Doesn't hang.
    let temp = tempfile::tempdir().unwrap();
    let secret_store = Arc::new(SecretStore::new());
    let refresh_lock = Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
    let endpoints = OAuthEndpoints {
        authorization_endpoint: Url::parse("https://idp.example/authorize").unwrap(),
        token_endpoint: Url::parse("https://idp.example/token").unwrap(),
        client_id: "worker".into(),
        scope: None,
    };
    let provider = Arc::new(
        OAuthCredentialProvider::new(
            "worker-test",
            "nucleus",
            endpoints,
            secret_store,
            refresh_lock,
            OAuthStrategy::Device,
        )
        .with_interactive_disabled(true),
    );
    let chain: Vec<Arc<dyn CredentialProvider>> = vec![provider];
    let cache = CredentialCache::new(CredentialCacheConfig::default());
    let err = cache
        .resolve(
            &BackendId("nucleus".into()),
            &PrincipalView::new("worker-user"),
            &chain,
        )
        .await
        .expect_err("cold-start with interactive disabled must error");
    match err {
        ovstorage::auth::CredentialError::Unavailable { .. } => {}
        other => panic!("expected Unavailable, got {other:?}"),
    }
}
