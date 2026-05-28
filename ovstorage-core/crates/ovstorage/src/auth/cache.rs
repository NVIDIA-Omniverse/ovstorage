// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Two-layer resolved-credential cache.
//!
//! L1 is an in-process map keyed on `(BackendId, PrincipalView)` with a
//! monotonic `cred_epoch`. L2 is `auth.sqlite` (`secret_tokens` row) +
//! the OS-keyring backed [`OsKeyringSecretStorage`].
//! [`CredentialCache::new`] keeps L1 only;
//! [`CredentialCache::with_persistence`] adds L2.
//!
//! TTL rules follow `ovstorage.md` § "Resolved-credential caching":
//! `expires_at - refresh_skew`, or `static_cred_ttl` when the provider
//! returned no expiry. Zero `static_cred_ttl` disables caching.
//!
//! Concurrent stampeders collapse via per-key `tokio::sync::Mutex`
//! single-flight; the guard covers the L2 round-trip too. Winning
//! resolvers write to both stores under the same lock.
//!
//! Auto-invalidation on `PermissionDenied` / `AuthRequired` /
//! `AuthExpired` is wired into `Library::with_route_retry`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ovstorage_plugin::{BackendId, Error, ErrorCode, SecretBundle, SecretBytes, SecretValue};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;

use super::provider::{CredentialError, CredentialProvider, PrincipalView, ResolvedCredential};
use super::{AuthRefreshLock, PersistedSecretToken, SecretStore};

/// Reserved namespace so cache keyring entries don't collide with
/// real-backend ones.
const KEYRING_NAMESPACE_KIND: &str = "ovstorage-cred-cache";
const KEYRING_FIELD: &str = "resolved";

/// Whether resolved credentials persist across host restarts.
/// `InMemoryOnly` bypasses any wired persistence — the right choice
/// for ephemeral VMs whose credentials come from an external
/// control-plane.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum CredentialCacheDurability {
    /// Round-trip through `auth.sqlite` + configured `SecretStorage`.
    #[default]
    Persistent,
    /// Process memory only.
    InMemoryOnly,
}

/// Pluggable secret-bytes backend for the credential cache. In-tree
/// impl: [`OsKeyringSecretStorage`].
pub trait SecretStorage: Send + Sync {
    fn store(&self, handle: &str, secret: &SecretBytes) -> Result<(), CredentialError>;
    fn lookup(&self, handle: &str) -> Result<Option<SecretBytes>, CredentialError>;
    fn delete(&self, handle: &str) -> Result<(), CredentialError>;
}

/// `SecretStorage` impl that delegates to the OS keyring (default).
pub struct OsKeyringSecretStorage {
    store: Arc<SecretStore>,
}

impl OsKeyringSecretStorage {
    pub fn new(store: Arc<SecretStore>) -> Self {
        Self { store }
    }
}

impl SecretStorage for OsKeyringSecretStorage {
    fn store(&self, handle: &str, secret: &SecretBytes) -> Result<(), CredentialError> {
        self.store
            .put(KEYRING_NAMESPACE_KIND, handle, KEYRING_FIELD, secret)
            .map_err(CredentialError::Backend)
    }

    fn lookup(&self, handle: &str) -> Result<Option<SecretBytes>, CredentialError> {
        self.store
            .get(KEYRING_NAMESPACE_KIND, handle, KEYRING_FIELD)
            .map_err(CredentialError::Backend)
    }

    fn delete(&self, handle: &str) -> Result<(), CredentialError> {
        self.store
            .delete(KEYRING_NAMESPACE_KIND, handle, KEYRING_FIELD)
            .map_err(CredentialError::Backend)
    }
}

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
/// single-flight, monotonic `cred_epoch`, and optional L2 durability.
pub struct CredentialCache {
    config: CredentialCacheConfig,
    state: Mutex<State>,
    persistence: Option<Arc<dyn CredentialPersistence>>,
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
    /// `Some` only on L2 hydration — `Instant` reflects the
    /// post-restart process, so static-TTL freshness needs wall-clock.
    inserted_unix_ms: Option<i64>,
    expires_at: Option<SystemTime>,
    cred_epoch: u64,
    value: ResolvedCredential,
}

/// Durable companion to L1: `secret_tokens` row + keyring blob.
/// Production impl is [`AuthDbCredentialPersistence`]; tests stub.
pub trait CredentialPersistence: Send + Sync {
    fn load(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<Option<PersistedEntry>, CredentialError>;

    fn store(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
        entry: &PersistedEntry,
    ) -> Result<(), CredentialError>;

    fn delete(&self, backend: &BackendId, principal: &PrincipalView)
    -> Result<(), CredentialError>;

    fn max_cred_epoch(&self) -> Result<u64, CredentialError>;
}

/// One credential's durable state: the `secret_tokens` row metadata
/// plus the [`SecretBundle`] that lands in the secret backend.
#[derive(Clone, Debug)]
pub struct PersistedEntry {
    pub cred_epoch: u64,
    pub inserted_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
    pub source_name: String,
    pub bundle: SecretBundle,
}

/// Production [`CredentialPersistence`] — [`AuthRefreshLock`] for the
/// `secret_tokens` row, pluggable [`SecretStorage`] for the bytes.
pub struct AuthDbCredentialPersistence {
    lock: Arc<AuthRefreshLock>,
    secrets: Arc<dyn SecretStorage>,
}

impl AuthDbCredentialPersistence {
    pub fn new(lock: Arc<AuthRefreshLock>, secrets: Arc<dyn SecretStorage>) -> Self {
        Self { lock, secrets }
    }

    /// Convenience wrapper that wires [`OsKeyringSecretStorage`].
    pub fn with_keyring(lock: Arc<AuthRefreshLock>, store: Arc<SecretStore>) -> Self {
        Self::new(lock, Arc::new(OsKeyringSecretStorage::new(store)))
    }

    fn keyring_handle(backend: &BackendId, principal: &PrincipalView) -> String {
        let mut hasher = Sha256::new();
        hasher.update(backend.0.as_bytes());
        hasher.update([0u8]);
        hasher.update(principal.id.as_bytes());
        let digest = hasher.finalize();
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl CredentialPersistence for AuthDbCredentialPersistence {
    fn load(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<Option<PersistedEntry>, CredentialError> {
        let row = self
            .lock
            .load_secret_token(&backend.0, &principal.id)
            .map_err(CredentialError::Backend)?;
        let Some(row) = row else { return Ok(None) };
        let blob = self.secrets.lookup(&row.keyring_handle)?;
        let Some(blob) = blob else {
            // Orphan row (secret missing) → treat as no-cache; the next
            // successful resolve overwrites it.
            return Ok(None);
        };
        let bundle = decode_bundle(blob.as_bytes()).map_err(CredentialError::Backend)?;
        Ok(Some(PersistedEntry {
            cred_epoch: row.cred_epoch,
            inserted_unix_ms: row.inserted_unix_ms,
            expires_at_unix_ms: row.expires_at_unix_ms,
            source_name: row.source_name,
            bundle,
        }))
    }

    fn store(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
        entry: &PersistedEntry,
    ) -> Result<(), CredentialError> {
        let handle = Self::keyring_handle(backend, principal);
        // Secret blob first: SQLite commit publishes the durable handle,
        // so the secret must already be readable when the row appears.
        let blob = encode_bundle(&entry.bundle).map_err(CredentialError::Backend)?;
        self.secrets
            .store(&handle, &SecretBytes(blob.into_bytes()))?;
        let token = PersistedSecretToken {
            cred_epoch: entry.cred_epoch,
            inserted_unix_ms: entry.inserted_unix_ms,
            expires_at_unix_ms: entry.expires_at_unix_ms,
            keyring_handle: handle,
            source_name: entry.source_name.clone(),
        };
        self.lock
            .store_secret_token(&backend.0, &principal.id, &token)
            .map_err(CredentialError::Backend)?;
        Ok(())
    }

    fn delete(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<(), CredentialError> {
        let handle = Self::keyring_handle(backend, principal);
        self.secrets.delete(&handle)?;
        self.lock
            .delete_secret_token(&backend.0, &principal.id)
            .map_err(CredentialError::Backend)?;
        Ok(())
    }

    fn max_cred_epoch(&self) -> Result<u64, CredentialError> {
        self.lock
            .max_secret_cred_epoch()
            .map_err(CredentialError::Backend)
    }
}

impl CredentialCache {
    /// L1-only.
    pub fn new(config: CredentialCacheConfig) -> Self {
        Self {
            config,
            state: Mutex::new(State {
                cred_epoch: 0,
                entries: HashMap::new(),
                locks: HashMap::new(),
            }),
            persistence: None,
        }
    }

    /// L1+L2. Seeds `cred_epoch` from
    /// [`CredentialPersistence::max_cred_epoch`] so it strictly grows
    /// across restarts.
    pub fn with_persistence(
        config: CredentialCacheConfig,
        persistence: Arc<dyn CredentialPersistence>,
    ) -> Result<Self, CredentialError> {
        let initial_epoch = persistence.max_cred_epoch()?;
        Ok(Self {
            config,
            state: Mutex::new(State {
                cred_epoch: initial_epoch,
                entries: HashMap::new(),
                locks: HashMap::new(),
            }),
            persistence: Some(persistence),
        })
    }

    /// Monotonic counter bumped on resolve + invalidate. Downstream
    /// credential-keyed caches observe this to know when to refresh.
    pub fn cred_epoch(&self) -> u64 {
        self.state.lock().cred_epoch
    }

    /// Drop the cached entry and bump `cred_epoch`. Persistence errors
    /// propagate.
    pub fn invalidate(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<(), CredentialError> {
        let key = Key {
            backend: backend.clone(),
            principal: principal.clone(),
        };
        let removed = {
            let mut state = self.state.lock();
            let removed = state.entries.remove(&key).is_some();
            if removed {
                state.cred_epoch = state.cred_epoch.saturating_add(1);
            }
            removed
        };
        if let Some(persistence) = self.persistence.as_ref() {
            persistence.delete(backend, principal)?;
        }
        let _ = removed;
        Ok(())
    }

    /// Insert directly, bypassing the chain. Bumps `cred_epoch`;
    /// commits to L2 when persistence is wired. Takes the per-key
    /// single-flight lock to serialize against any in-flight resolver.
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
        self.store(backend, principal, &key, value)
    }

    /// Cached entries within TTL skip the chain; stale/absent entries
    /// trigger a single-flight resolve. Chain consulted in order;
    /// first non-`Unavailable` wins; `Backend(Error)` short-circuits.
    /// When persistence is wired, L1 miss consults L2 before the chain.
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
        if let Some(persistence) = self.persistence.as_ref()
            && let Some(persisted) = persistence.load(backend, principal)?
            && let Some(value) = self.hydrate_from_l2(&key, persisted)
        {
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
                    self.store(backend, principal, &key, resolved.clone())?;
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
                // L2-hydrated entries use wall-clock; `Instant` reflects
                // the post-restart process, not the original insert.
                if let Some(inserted_ms) = entry.inserted_unix_ms {
                    let now = unix_ms_now();
                    let elapsed_ms = now.saturating_sub(inserted_ms).max(0) as u128;
                    return elapsed_ms < self.config.static_cred_ttl.as_millis();
                }
                entry.inserted_at.elapsed() < self.config.static_cred_ttl
            }
        }
    }

    /// Validate freshness, populate L1, and take `cred_epoch` as a
    /// floor (`max(in_process, persisted)` — hydration never bumps).
    fn hydrate_from_l2(&self, key: &Key, persisted: PersistedEntry) -> Option<ResolvedCredential> {
        let expires_at = persisted.expires_at_unix_ms.and_then(|ms| {
            if ms < 0 {
                None
            } else {
                Some(UNIX_EPOCH + Duration::from_millis(ms as u64))
            }
        });
        let value = ResolvedCredential {
            bytes: persisted.bundle,
            expires_at,
            source_name: persisted.source_name,
        };
        let entry = Entry {
            inserted_at: Instant::now(),
            inserted_unix_ms: Some(persisted.inserted_unix_ms),
            expires_at,
            cred_epoch: persisted.cred_epoch,
            value: value.clone(),
        };
        if !self.is_fresh(&entry) {
            return None;
        }
        let mut state = self.state.lock();
        state.cred_epoch = state.cred_epoch.max(persisted.cred_epoch);
        state.entries.insert(key.clone(), entry);
        Some(value)
    }

    fn store(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
        key: &Key,
        value: ResolvedCredential,
    ) -> Result<(), CredentialError> {
        let inserted_unix_ms = unix_ms_now();
        let expires_at_unix_ms = value
            .expires_at
            .and_then(|expires| expires.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64);
        // L2 first: durable commit MUST precede L1 publish. Otherwise a
        // failed store would leave a fresh L1 entry that subsequent
        // reads return without retrying the chain.
        let new_epoch_if_persisted = if let Some(persistence) = self.persistence.as_ref() {
            let candidate_epoch = self.state.lock().cred_epoch.saturating_add(1);
            let entry = PersistedEntry {
                cred_epoch: candidate_epoch,
                inserted_unix_ms,
                expires_at_unix_ms,
                source_name: value.source_name.clone(),
                bundle: value.bytes.clone(),
            };
            persistence.store(backend, principal, &entry)?;
            Some(candidate_epoch)
        } else {
            None
        };
        let mut state = self.state.lock();
        let cred_epoch = match new_epoch_if_persisted {
            Some(epoch) => {
                state.cred_epoch = state.cred_epoch.max(epoch);
                state.cred_epoch
            }
            None => {
                state.cred_epoch = state.cred_epoch.saturating_add(1);
                state.cred_epoch
            }
        };
        state.entries.insert(
            key.clone(),
            Entry {
                inserted_at: Instant::now(),
                inserted_unix_ms: None,
                expires_at: value.expires_at,
                cred_epoch,
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
            .field("persistence", &self.persistence.is_some())
            .finish()
    }
}

impl Entry {
    #[allow(dead_code)]
    fn cred_epoch(&self) -> u64 {
        self.cred_epoch
    }
}

fn unix_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

// SecretBundle <-> JSON adapter (round-trips through SecretStorage).

#[derive(Serialize, Deserialize)]
struct SerializedBundle {
    fields: Vec<SerializedField>,
}

#[derive(Serialize, Deserialize)]
struct SerializedField {
    key: String,
    value: SerializedValue,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "tag")]
enum SerializedValue {
    Bytes {
        bytes_b64: String,
    },
    OAuthToken {
        token_b64: String,
        refresh_b64: Option<String>,
        expires_at_unix_ms: Option<i64>,
    },
    File {
        bytes_b64: String,
    },
    MtlsCertPair {
        cert_pem_b64: String,
        key_pem_b64: String,
    },
    SystemIdentity,
}

fn encode_bundle(bundle: &SecretBundle) -> Result<String, Error> {
    let mut fields = Vec::with_capacity(bundle.fields.len());
    for (key, value) in &bundle.fields {
        let serialized = match value {
            SecretValue::Bytes(b) => SerializedValue::Bytes {
                bytes_b64: BASE64_STANDARD.encode(b.as_bytes()),
            },
            SecretValue::OAuthToken {
                token,
                refresh,
                expires_at,
            } => SerializedValue::OAuthToken {
                token_b64: BASE64_STANDARD.encode(token.as_bytes()),
                refresh_b64: refresh
                    .as_ref()
                    .map(|r| BASE64_STANDARD.encode(r.as_bytes())),
                expires_at_unix_ms: expires_at
                    .and_then(|e| e.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_millis().min(i64::MAX as u128) as i64),
            },
            SecretValue::File(b) => SerializedValue::File {
                bytes_b64: BASE64_STANDARD.encode(b.as_bytes()),
            },
            SecretValue::MtlsCertPair { cert_pem, key_pem } => SerializedValue::MtlsCertPair {
                cert_pem_b64: BASE64_STANDARD.encode(cert_pem.as_bytes()),
                key_pem_b64: BASE64_STANDARD.encode(key_pem.as_bytes()),
            },
            SecretValue::SystemIdentity => SerializedValue::SystemIdentity,
        };
        fields.push(SerializedField {
            key: key.clone(),
            value: serialized,
        });
    }
    serde_json::to_string(&SerializedBundle { fields })
        .map_err(|err| Error::new(ErrorCode::Internal, format!("encode SecretBundle: {err}")))
}

fn decode_bundle(blob: &[u8]) -> Result<SecretBundle, Error> {
    let parsed: SerializedBundle = serde_json::from_slice(blob)
        .map_err(|err| Error::new(ErrorCode::Internal, format!("decode SecretBundle: {err}")))?;
    let mut bundle = SecretBundle::default();
    for field in parsed.fields {
        let value = match field.value {
            SerializedValue::Bytes { bytes_b64 } => {
                SecretValue::Bytes(SecretBytes(decode_b64(&bytes_b64)?))
            }
            SerializedValue::OAuthToken {
                token_b64,
                refresh_b64,
                expires_at_unix_ms,
            } => SecretValue::OAuthToken {
                token: SecretBytes(decode_b64(&token_b64)?),
                refresh: refresh_b64
                    .map(|r| decode_b64(&r).map(SecretBytes))
                    .transpose()?,
                expires_at: expires_at_unix_ms.and_then(|ms| {
                    if ms < 0 {
                        None
                    } else {
                        Some(UNIX_EPOCH + Duration::from_millis(ms as u64))
                    }
                }),
            },
            SerializedValue::File { bytes_b64 } => {
                SecretValue::File(SecretBytes(decode_b64(&bytes_b64)?))
            }
            SerializedValue::MtlsCertPair {
                cert_pem_b64,
                key_pem_b64,
            } => SecretValue::MtlsCertPair {
                cert_pem: SecretBytes(decode_b64(&cert_pem_b64)?),
                key_pem: SecretBytes(decode_b64(&key_pem_b64)?),
            },
            SerializedValue::SystemIdentity => SecretValue::SystemIdentity,
        };
        bundle.fields.insert(field.key, value);
    }
    Ok(bundle)
}

fn decode_b64(input: &str) -> Result<Vec<u8>, Error> {
    BASE64_STANDARD.decode(input).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("base64 decode in SecretBundle: {err}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::provider::{EnvField, EnvProvider};
    use async_trait::async_trait;
    use ovstorage_plugin::SecretBundle;
    use std::sync::Mutex as StdMutex;
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
        bundle: SecretBundle,
    }

    impl CountingProvider {
        fn new(name: &str, expires_at: Option<SystemTime>) -> Self {
            Self {
                name: name.into(),
                calls: AtomicU32::new(0),
                expires_at,
                bundle: SecretBundle::default(),
            }
        }

        fn with_bundle(mut self, bundle: SecretBundle) -> Self {
            self.bundle = bundle;
            self
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
                bytes: self.bundle.clone(),
                expires_at: self.expires_at,
                source_name: self.name.clone(),
            })
        }
    }

    /// In-memory `CredentialPersistence` for the round-trip and
    /// concurrent-insert tests. Records calls to allow assertions on
    /// store/load activity.
    #[derive(Default)]
    struct InMemoryPersistence {
        rows: StdMutex<HashMap<(String, String), PersistedEntry>>,
        store_calls: AtomicU32,
        load_calls: AtomicU32,
    }

    impl CredentialPersistence for InMemoryPersistence {
        fn load(
            &self,
            backend: &BackendId,
            principal: &PrincipalView,
        ) -> Result<Option<PersistedEntry>, CredentialError> {
            self.load_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .rows
                .lock()
                .unwrap()
                .get(&(backend.0.clone(), principal.id.clone()))
                .cloned())
        }

        fn store(
            &self,
            backend: &BackendId,
            principal: &PrincipalView,
            entry: &PersistedEntry,
        ) -> Result<(), CredentialError> {
            self.store_calls.fetch_add(1, Ordering::SeqCst);
            self.rows
                .lock()
                .unwrap()
                .insert((backend.0.clone(), principal.id.clone()), entry.clone());
            Ok(())
        }

        fn delete(
            &self,
            backend: &BackendId,
            principal: &PrincipalView,
        ) -> Result<(), CredentialError> {
            self.rows
                .lock()
                .unwrap()
                .remove(&(backend.0.clone(), principal.id.clone()));
            Ok(())
        }

        fn max_cred_epoch(&self) -> Result<u64, CredentialError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .values()
                .map(|e| e.cred_epoch)
                .max()
                .unwrap_or(0))
        }
    }

    /// Stub that always errors on `store` — exercises the
    /// "no silent fallback when persistence is unavailable" path.
    struct FailingPersistence;

    impl CredentialPersistence for FailingPersistence {
        fn load(
            &self,
            _backend: &BackendId,
            _principal: &PrincipalView,
        ) -> Result<Option<PersistedEntry>, CredentialError> {
            Ok(None)
        }

        fn store(
            &self,
            _backend: &BackendId,
            _principal: &PrincipalView,
            _entry: &PersistedEntry,
        ) -> Result<(), CredentialError> {
            Err(CredentialError::Backend(Error::new(
                ErrorCode::CredentialUnavailable,
                "keyring unavailable (test stub)",
            )))
        }

        fn delete(
            &self,
            _backend: &BackendId,
            _principal: &PrincipalView,
        ) -> Result<(), CredentialError> {
            Ok(())
        }

        fn max_cred_epoch(&self) -> Result<u64, CredentialError> {
            Ok(0)
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

    fn populated_bundle() -> SecretBundle {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "access_token".into(),
            SecretValue::Bytes(SecretBytes(b"top-secret-access".to_vec())),
        );
        bundle.fields.insert(
            "refresh".into(),
            SecretValue::OAuthToken {
                token: SecretBytes(b"a".to_vec()),
                refresh: Some(SecretBytes(b"r".to_vec())),
                expires_at: Some(SystemTime::now() + Duration::from_secs(3_600)),
            },
        );
        bundle
    }

    #[tokio::test]
    async fn cache_round_trip_persists_across_drop() {
        // Insert into a persistent cache, drop the cache, reopen against the
        // same persistence backend, and confirm the second resolve hits L2
        // without invoking the provider chain again.
        let persistence = Arc::new(InMemoryPersistence::default());
        let provider = Arc::new(
            CountingProvider::new(
                "counting",
                Some(SystemTime::now() + Duration::from_secs(3_600)),
            )
            .with_bundle(populated_bundle()),
        );
        let chain: Vec<Arc<dyn CredentialProvider>> = vec![provider.clone()];

        // Round 1: first cache instance, fresh resolve.
        let cache1 = CredentialCache::with_persistence(
            CredentialCacheConfig::default(),
            persistence.clone() as Arc<dyn CredentialPersistence>,
        )
        .unwrap();
        let resolved = cache1
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        assert_eq!(resolved.source_name, "counting");
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(persistence.store_calls.load(Ordering::SeqCst), 1);
        drop(cache1);

        // Round 2: second cache instance; provider must NOT be called again.
        let cache2 = CredentialCache::with_persistence(
            CredentialCacheConfig::default(),
            persistence.clone() as Arc<dyn CredentialPersistence>,
        )
        .unwrap();
        let resolved = cache2
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        assert_eq!(resolved.source_name, "counting");
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            1,
            "provider must not be re-invoked"
        );
        assert!(persistence.load_calls.load(Ordering::SeqCst) >= 1);
        // Bundle survived the round trip including base64 + variant tagging.
        assert!(resolved.bytes.fields.contains_key("access_token"));
        assert!(resolved.bytes.fields.contains_key("refresh"));
    }

    #[tokio::test]
    async fn cache_cred_epoch_survives_restart() {
        let persistence = Arc::new(InMemoryPersistence::default());
        let provider = Arc::new(
            CountingProvider::new("c", Some(SystemTime::now() + Duration::from_secs(3_600)))
                .with_bundle(populated_bundle()),
        );
        let chain: Vec<Arc<dyn CredentialProvider>> = vec![provider.clone()];

        let cache1 = CredentialCache::with_persistence(
            CredentialCacheConfig::default(),
            persistence.clone() as Arc<dyn CredentialPersistence>,
        )
        .unwrap();
        cache1
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        let epoch_round1 = cache1.cred_epoch();
        assert!(epoch_round1 >= 1);
        drop(cache1);

        let cache2 = CredentialCache::with_persistence(
            CredentialCacheConfig::default(),
            persistence.clone() as Arc<dyn CredentialPersistence>,
        )
        .unwrap();
        // Counter was seeded from max(persistence) -> >= prior epoch.
        assert!(cache2.cred_epoch() >= epoch_round1);
        // L2 hit must NOT bump the counter.
        let before = cache2.cred_epoch();
        cache2
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap();
        assert_eq!(
            cache2.cred_epoch(),
            before,
            "L2 hydration must not bump cred_epoch"
        );
    }

    #[tokio::test]
    async fn cache_persists_under_concurrent_inserts() {
        let persistence = Arc::new(InMemoryPersistence::default());
        let provider = Arc::new(
            CountingProvider::new("c", Some(SystemTime::now() + Duration::from_secs(3_600)))
                .with_bundle(populated_bundle()),
        );
        let chain: Vec<Arc<dyn CredentialProvider>> = vec![provider.clone()];

        let cache = Arc::new(
            CredentialCache::with_persistence(
                CredentialCacheConfig::default(),
                persistence.clone() as Arc<dyn CredentialPersistence>,
            )
            .unwrap(),
        );
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
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            1,
            "single-flight covers L2 too"
        );
        assert_eq!(
            persistence.store_calls.load(Ordering::SeqCst),
            1,
            "exactly one L2 commit"
        );
    }

    #[tokio::test]
    async fn cache_surfaces_persistence_failure_as_error() {
        let provider = Arc::new(
            CountingProvider::new("c", Some(SystemTime::now() + Duration::from_secs(3_600)))
                .with_bundle(populated_bundle()),
        );
        let chain: Vec<Arc<dyn CredentialProvider>> = vec![provider.clone()];

        let cache = CredentialCache::with_persistence(
            CredentialCacheConfig::default(),
            Arc::new(FailingPersistence) as Arc<dyn CredentialPersistence>,
        )
        .unwrap();
        let err1 = cache
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap_err();
        match err1 {
            CredentialError::Backend(error) => {
                assert_eq!(error.code(), ErrorCode::CredentialUnavailable);
            }
            other => panic!("expected Backend(CredentialUnavailable), got {other:?}"),
        }
        // Second resolve must hit the chain again — a failed persistence
        // commit must NOT leave a fresh L1 entry behind.
        let err2 = cache
            .resolve(&backend(), &principal(), &chain)
            .await
            .unwrap_err();
        match err2 {
            CredentialError::Backend(error) => {
                assert_eq!(error.code(), ErrorCode::CredentialUnavailable);
            }
            other => panic!("expected Backend(CredentialUnavailable), got {other:?}"),
        }
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            2,
            "provider should be re-walked after persistence failure"
        );
    }
}
