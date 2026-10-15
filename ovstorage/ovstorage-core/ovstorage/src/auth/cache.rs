// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-process resolved-credential cache.
//!
//! An in-memory map keyed on `(BackendId, PrincipalView)` with a
//! monotonic `cred_epoch`. No entry outlives the cache value holding it:
//! nothing is written down, so a new cache — in this process or the
//! next — starts empty. Durable secret storage is the host's, through
//! the secret store host callbacks and [`SecretStore`](super::SecretStore).
//!
//! TTL rules follow `ovstorage.md` § "Resolved-credential caching":
//! `expires_at - refresh_skew`, or `static_cred_ttl` when the provider
//! returned no expiry. Zero `static_cred_ttl` disables caching.
//!
//! Concurrent stampeders collapse via per-key `tokio::sync::Mutex`
//! single-flight.
//!
//! **TTL is the only automatic staleness defence here.** Nothing
//! invalidates an entry in response to an error, so a credential
//! revoked or rotated out of band is served until its TTL expires
//! unless a caller intervenes — with [`CredentialCache::invalidate`] to
//! drop the entry, or [`CredentialCache::insert`] to replace it.
//! Error-driven credential recovery — refresh the connection's
//! credentials and retry the operation once — belongs to the connection
//! owner, `ConnectionSet::recover` in `ovstorage-plugin`, per RFC-0066
//! § "Data-path recovery for hosts without a UI". A retry wrapper cannot
//! stand in for it: none holds a reference that could reach a cache, and
//! `ErrorCode::retryable()` admits only the `Transient` and
//! `ResourceExhausted` buckets, which no credential-classed code enters
//! — `PermissionDenied`, `AuthRequired` and `AuthExpired` all bucket as
//! `Permission`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use ovstorage_plugin::BackendId;
use parking_lot::Mutex;
use tokio::sync::Mutex as AsyncMutex;

use super::provider::{CredentialError, CredentialProvider, PrincipalView, ResolvedCredential};

/// TTL knobs. Defaults: `refresh_skew = 60s`, `static_cred_ttl = 300s`.
#[derive(Clone, Debug)]
pub struct CredentialCacheConfig {
    /// Subtracted from `expires_at` so the host refreshes ahead.
    pub refresh_skew: Duration,
    /// TTL when the provider returned no `expires_at`. Zero disables.
    pub static_cred_ttl: Duration,
}

impl Default for CredentialCacheConfig {
    fn default() -> Self {
        Self {
            refresh_skew: Duration::from_secs(60),
            static_cred_ttl: Duration::from_secs(300),
        }
    }
}

/// `(BackendId, PrincipalView) -> ResolvedCredential` cache with TTL,
/// single-flight and a monotonic `cred_epoch`. Process-local.
pub struct CredentialCache {
    config: CredentialCacheConfig,
    state: Mutex<State>,
}

struct State {
    cred_epoch: u64,
    entries: HashMap<Key, Entry>,
    locks: HashMap<Key, Arc<AsyncMutex<()>>>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    backend: BackendId,
    principal: PrincipalView,
}

struct Entry {
    inserted_at: Instant,
    expires_at: Option<SystemTime>,
    value: ResolvedCredential,
}

impl CredentialCache {
    /// Opens an empty cache with `cred_epoch` at zero. The counter is
    /// process-local and starts afresh in each process.
    pub fn new(config: CredentialCacheConfig) -> Self {
        Self {
            config,
            state: Mutex::new(State {
                cred_epoch: 0,
                entries: HashMap::new(),
                locks: HashMap::new(),
            }),
        }
    }

    /// Monotonic counter bumped on resolve + invalidate. Downstream
    /// credential-keyed caches observe this to know when to refresh.
    pub fn cred_epoch(&self) -> u64 {
        self.state.lock().cred_epoch
    }

    /// Drop the cached entry and bump `cred_epoch`. Bumping only on an
    /// actual removal keeps a repeated invalidate from churning
    /// downstream credential-keyed caches.
    ///
    /// # Errors
    ///
    /// Infallible today; the `Result` is retained because callers treat
    /// invalidation as a fallible step.
    pub fn invalidate(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<(), CredentialError> {
        let key = Key {
            backend: backend.clone(),
            principal: principal.clone(),
        };
        let mut state = self.state.lock();
        if state.entries.remove(&key).is_some() {
            state.cred_epoch = state.cred_epoch.saturating_add(1);
        }
        Ok(())
    }

    /// Insert directly, bypassing the chain. Bumps `cred_epoch`. Takes
    /// the per-key single-flight lock to serialize against any
    /// in-flight resolver.
    ///
    /// # Errors
    ///
    /// Infallible today; the `Result` is retained because callers treat
    /// a cache insert as a fallible step.
    pub async fn insert(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
        value: ResolvedCredential,
    ) -> Result<(), CredentialError> {
        let key = Key {
            backend: backend.clone(),
            principal: principal.clone(),
        };
        let lock = {
            let mut state = self.state.lock();
            state
                .locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;
        self.store(&key, value)
    }

    /// Cached entries within TTL skip the chain; stale/absent entries
    /// trigger a single-flight resolve. Chain consulted in order;
    /// first non-`Unavailable` wins; `Backend(Error)` short-circuits.
    ///
    /// # Errors
    ///
    /// - [`CredentialError::Unavailable`] — `chain` is empty, or every
    ///   provider answered `Unavailable`.
    /// - [`CredentialError::Backend`] — a provider short-circuits with
    ///   a backend failure.
    pub async fn resolve(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
        chain: &[Arc<dyn CredentialProvider>],
    ) -> Result<ResolvedCredential, CredentialError> {
        let key = Key {
            backend: backend.clone(),
            principal: principal.clone(),
        };
        if let Some(value) = self.read_fresh(&key) {
            return Ok(value);
        }
        let lock = {
            let mut state = self.state.lock();
            state
                .locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;
        if let Some(value) = self.read_fresh(&key) {
            return Ok(value);
        }
        if chain.is_empty() {
            return Err(CredentialError::Unavailable {
                details: "no credential providers configured".to_string(),
            });
        }
        let mut last_unavailable: Option<String> = None;
        for provider in chain {
            match provider.resolve(backend, principal).await {
                Ok(resolved) => {
                    self.store(&key, resolved.clone())?;
                    return Ok(resolved);
                }
                Err(CredentialError::Unavailable { details }) => {
                    last_unavailable = Some(details);
                    continue;
                }
                Err(CredentialError::Backend(err)) => {
                    return Err(CredentialError::Backend(err));
                }
            }
        }
        Err(CredentialError::Unavailable {
            details: last_unavailable
                .unwrap_or_else(|| "all credential providers returned unavailable".into()),
        })
    }

    fn read_fresh(&self, key: &Key) -> Option<ResolvedCredential> {
        let state = self.state.lock();
        let entry = state.entries.get(key)?;
        if self.is_fresh(entry) {
            Some(entry.value.clone())
        } else {
            None
        }
    }

    fn is_fresh(&self, entry: &Entry) -> bool {
        match entry.expires_at {
            Some(expires) => {
                let cutoff = expires
                    .checked_sub(self.config.refresh_skew)
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                SystemTime::now() < cutoff
            }
            None => {
                if self.config.static_cred_ttl.is_zero() {
                    return false;
                }
                entry.inserted_at.elapsed() < self.config.static_cred_ttl
            }
        }
    }

    fn store(&self, key: &Key, value: ResolvedCredential) -> Result<(), CredentialError> {
        let mut state = self.state.lock();
        state.cred_epoch = state.cred_epoch.saturating_add(1);
        state.entries.insert(
            key.clone(),
            Entry {
                inserted_at: Instant::now(),
                expires_at: value.expires_at,
                value,
            },
        );
        Ok(())
    }
}

impl std::fmt::Debug for CredentialCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.lock();
        f.debug_struct("CredentialCache")
            .field("config", &self.config)
            .field("cred_epoch", &state.cred_epoch)
            .field("entries", &state.entries.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::provider::{EnvField, EnvProvider};
    use async_trait::async_trait;
    use ovstorage_plugin::SecretBundle;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn backend() -> BackendId {
        BackendId("s3".into())
    }

    fn principal() -> PrincipalView {
        PrincipalView::new("u-1")
    }

    #[derive(Debug)]
    struct CountingProvider {
        name: String,
        calls: AtomicU32,
        expires_at: Option<SystemTime>,
    }

    impl CountingProvider {
        fn new(name: &str, expires_at: Option<SystemTime>) -> Self {
            Self {
                name: name.into(),
                calls: AtomicU32::new(0),
                expires_at,
            }
        }
    }

    #[async_trait]
    impl CredentialProvider for CountingProvider {
        fn name(&self) -> &str {
            &self.name
        }
        async fn resolve(
            &self,
            _backend: &BackendId,
            _principal: &PrincipalView,
        ) -> Result<ResolvedCredential, CredentialError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // Tiny delay to widen the stampede window.
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok(ResolvedCredential {
                bytes: SecretBundle::default(),
                expires_at: self.expires_at,
                source_name: self.name.clone(),
            })
        }
    }

    #[tokio::test]
    async fn empty_chain_returns_unavailable() {
        let cache = CredentialCache::new(CredentialCacheConfig::default());
        let err = cache
            .resolve(&backend(), &principal(), &[])
            .await
            .unwrap_err();
        match err {
            CredentialError::Unavailable { .. } => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cache_returns_same_value_within_ttl() {
        let cache = CredentialCache::new(CredentialCacheConfig::default());
        let provider = Arc::new(CountingProvider::new("test", None));
        let chain: Vec<Arc<dyn CredentialProvider>> = vec![provider.clone()];

        let _ = cache
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        let _ = cache
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cache_runs_provider_once_under_stampede() {
        let cache = Arc::new(CredentialCache::new(CredentialCacheConfig::default()));
        let provider = Arc::new(CountingProvider::new("test", None));
        let chain: Vec<Arc<dyn CredentialProvider>> = vec![provider.clone()];

        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let chain = chain.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .resolve(&backend(), &principal(), &chain)
                    .await
                    .unwrap()
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cache_zero_static_ttl_disables_caching() {
        let cfg = CredentialCacheConfig {
            static_cred_ttl: Duration::ZERO,
            ..CredentialCacheConfig::default()
        };
        let cache = CredentialCache::new(cfg);
        let provider = Arc::new(CountingProvider::new("test", None));
        let chain: Vec<Arc<dyn CredentialProvider>> = vec![provider.clone()];

        let _ = cache
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        let _ = cache
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cache_invalidate_drops_entry_and_bumps_epoch() {
        let cache = CredentialCache::new(CredentialCacheConfig::default());
        let provider = Arc::new(CountingProvider::new("test", None));
        let chain: Vec<Arc<dyn CredentialProvider>> = vec![provider.clone()];

        cache
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        let epoch_after_first = cache.cred_epoch();
        cache.invalidate(&backend(), &principal()).unwrap();
        assert_eq!(cache.cred_epoch(), epoch_after_first + 1);
        cache
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cache_chain_falls_through_unavailable() {
        let cache = CredentialCache::new(CredentialCacheConfig::default());
        let unavail = Arc::new(EnvProvider::new("env").with_schema(
            "s3",
            vec![EnvField::new(
                "k",
                "OVSTORAGE_DEFINITELY_NOT_SET_THIS_VAR_DOES_NOT_EXIST",
            )],
        ));
        let counting = Arc::new(CountingProvider::new("counting", None));
        let chain: Vec<Arc<dyn CredentialProvider>> = vec![unavail, counting.clone()];
        let resolved = cache
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        assert_eq!(resolved.source_name, "counting");
        assert_eq!(counting.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cache_honors_expires_at_minus_refresh_skew() {
        // Provider returns `expires_at` very close to now (after subtracting
        // refresh_skew, the entry is already stale -> re-resolves on second call).
        let cfg = CredentialCacheConfig {
            refresh_skew: Duration::from_secs(60),
            static_cred_ttl: Duration::from_secs(300),
        };
        let cache = CredentialCache::new(cfg);
        let near_expiry = SystemTime::now() + Duration::from_secs(30);
        let provider = Arc::new(CountingProvider::new("test", Some(near_expiry)));
        let chain: Vec<Arc<dyn CredentialProvider>> = vec![provider.clone()];

        let _ = cache
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        let _ = cache
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        // Both calls re-resolve because expires_at - refresh_skew is in the past.
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }
}
