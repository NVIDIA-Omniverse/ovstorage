// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Substrate for direct-mode provider authentication.
//!
//! Five provider-agnostic pieces. Two of them own the durable state —
//! [`SecretStore`] and [`AuthRefreshLock`], both in `auth.sqlite`;
//! [`pkce`] is a stateless generator and
//! [`CredentialCache`] persists nothing. [`CredentialProvider`] is an
//! extension point, so what an implementation reaches for is its own
//! affair: the built-in [`OAuthCredentialProvider`] persists through
//! the two above, and a callback provider may consult anything at all.
//!
//! - [`SecretStore`]: durable credential bytes keyed by
//!   `(backend_kind, connection_id, field)`, the plugin ABI's own key.
//!   [`SqliteSecretStore`] is the shipping implementation.
//! - [`AuthRefreshLock`]: cross-process refresh-coalescing lock built on
//!   `auth.sqlite` + advisory file locks.
//! - [`pkce`]: PKCE verifier/challenge generator for providers driving
//!   OAuth authorisation-code-with-PKCE or device-code flows.
//! - [`CredentialProvider`]: trait abstracting where credential bytes
//!   for `(backend_id, principal)` come from. See [`provider`] for the
//!   built-ins.
//! - [`CredentialCache`]: in-process resolved-credential cache keyed on
//!   `(BackendId, PrincipalView)` honoring the spec's
//!   `expires_at − refresh_skew` and `static_cred_ttl` rules. See
//!   [`cache`].
//!
//! All five sit underneath the Layer connection-authentication
//! operations.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use fs2::FileExt;
use ovstorage_cache::map_sql;
use ovstorage_plugin::{Error, ErrorCode, Result, SecretBytes};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

pub mod cache;
pub mod capability;
pub mod flow;
pub mod oauth_provider;
pub mod permissions;
pub mod provider;
pub mod sqlite_store;
pub mod state_root;
pub mod upstream;

pub use cache::{CredentialCache, CredentialCacheConfig};
pub use capability::{
    ENV_VAR as INTERACTIVE_AUTH_CAPABILITY_ENV_VAR, EnvSource, MockEnv, StdEnv,
    detect_default_capability, parse_capability_str, read_env_capability,
};
pub use flow::{AuthError, FlowContext, OAuthEndpoints, OAuthFlow};
pub use oauth_provider::{OAuthCredentialProvider, OAuthStrategy, ResolvedOAuthCredentialLease};
pub use provider::{
    CallbackCredentialProvider, CredentialError, CredentialProvider, EnvField, EnvProvider,
    PrincipalView, ResolvedCredential,
};
pub use sqlite_store::SqliteSecretStore;
pub use state_root::{ProcessEnv, StateRootEnv, default_state_root, resolve_state_root};
pub use upstream::{
    authenticate_upstream_for_address, authenticate_upstream_for_address_with_connection,
};

/// Durable credential bytes keyed by `(backend_kind, connection_id, field)`.
///
/// That key is the plugin ABI's own composite key, so the three host
/// callbacks map onto it one-to-one and both credential pipelines — the
/// plugin's, across the ABI, and the host's [`OAuthCredentialProvider`] —
/// address one store.
///
/// The trait exists so the backing store is a deployment choice. One
/// implementation ships, [`SqliteSecretStore`]; a secrets manager that keeps
/// bytes off the machine entirely is the seam's reason for being.
///
/// Per-user isolation comes from `connection_id`, which encodes the backend's
/// server and the user's principal.
pub trait SecretStore: Send + Sync {
    /// Store `secret`; overwrites any current value.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — `secret` is not UTF-8 (encode
    ///   binary secrets as base64 first).
    /// - [`ErrorCode::Transient`] — the store is busy past its retry budget.
    /// - [`ErrorCode::StateRootUnavailable`] — any other storage failure.
    fn put(
        &self,
        backend_kind: &str,
        connection_id: &str,
        field: &str,
        secret: &SecretBytes,
    ) -> Result<()>;

    /// `Ok(None)` for a secret that is not stored.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::Transient`] — the store is busy past its retry budget.
    /// - [`ErrorCode::StateRootUnavailable`] — any other storage failure.
    fn get(
        &self,
        backend_kind: &str,
        connection_id: &str,
        field: &str,
    ) -> Result<Option<SecretBytes>>;

    /// Remove `field`. A secret that is not stored is not an error, so
    /// sign-out is idempotent.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::Transient`] — the store is busy past its retry budget.
    /// - [`ErrorCode::StateRootUnavailable`] — any other storage failure.
    fn delete(&self, backend_kind: &str, connection_id: &str, field: &str) -> Result<()>;

    /// Write several fields of one `(backend_kind, connection_id)` as a unit:
    /// either every field is visible afterwards or none of them is.
    ///
    /// This is what a credential write needs. An access token and the refresh
    /// token beside it are one generation, and a reader that observes the new
    /// access token against the previous refresh token is holding a pair that
    /// never existed.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — any secret is not UTF-8; nothing is
    ///   written.
    /// - [`ErrorCode::Transient`] — the store is busy past its retry budget.
    /// - [`ErrorCode::StateRootUnavailable`] — any other storage failure.
    fn put_many(
        &self,
        backend_kind: &str,
        connection_id: &str,
        fields: &[(&str, &SecretBytes)],
    ) -> Result<()>;
}

/// Per-`(backend_kind, connection_id)` cross-process refresh lock.
///
/// Built on `state_root/auth.sqlite` (last refresh timestamp + expiry)
/// plus advisory file locks under `state_root/locks/auth/`. Two
/// processes that both hit `AuthExpired` on the same connection
/// serialise on the file lock; only one issues the refresh and the
/// second observes the freshly persisted token.
pub struct AuthRefreshLock {
    state_root: PathBuf,
    locks_root: PathBuf,
    conn: Mutex<Connection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRefreshSnapshot {
    pub refreshed_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
}

/// Durable `credential_records` row contents (metadata only; the secret
/// bytes live in the `secrets` table under `secret_handle`). Generic over
/// any secret-token shape — OAuth pairs, API keys, scoped service
/// credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedSecretToken {
    pub cred_epoch: u64,
    pub inserted_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
    pub secret_handle: String,
    pub source_name: String,
}

/// Result of [`AuthRefreshLock::with_refresh`].
pub enum RefreshOutcome<T> {
    /// Held the lock; ran the refresh closure.
    Refreshed(T),
    /// Another process refreshed within `freshness_window`; closure not
    /// called. Snapshot reflects what they wrote.
    Skipped(AuthRefreshSnapshot),
}

impl AuthRefreshLock {
    /// Open or create the auth substrate under `state_root`.
    /// `auth.sqlite` opens with `journal_mode = WAL` + `synchronous = FULL`
    /// — single-use refresh-token rotations must survive a crash.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::StateRootUnavailable`] — `state_root` or the lock
    ///   directory cannot be created, or `auth.sqlite` fails to open or
    ///   migrate.
    /// - [`ErrorCode::Transient`] — `auth.sqlite` is BUSY/LOCKED while
    ///   opening.
    pub fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let state_root = state_root.as_ref().to_path_buf();
        let locks_root = state_root.join("locks").join("auth");
        let conn = open_auth_db(&state_root)?;
        fs::create_dir_all(&locks_root).map_err(map_io)?;
        Ok(Self {
            state_root,
            locks_root,
            conn: Mutex::new(conn),
        })
    }

    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Last refresh observation; does not take the lock.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::Transient`] — `auth.sqlite` stays BUSY/LOCKED past
    ///   the retry budget.
    /// - [`ErrorCode::StateRootUnavailable`] — any other `auth.sqlite`
    ///   failure, or the connection lock is poisoned.
    pub fn snapshot(
        &self,
        backend_kind: &str,
        connection_id: &str,
    ) -> Result<Option<AuthRefreshSnapshot>> {
        crate::retry::with_retry(&SQLITE_RETRY, || {
            self.conn()?
                .query_row(
                    "SELECT refreshed_unix_ms, expires_at_unix_ms
                     FROM refresh_records
                     WHERE backend_kind = ?1 AND connection_id = ?2",
                    params![backend_kind, connection_id],
                    |row| {
                        Ok(AuthRefreshSnapshot {
                            refreshed_unix_ms: row.get(0)?,
                            expires_at_unix_ms: row.get::<_, Option<i64>>(1)?,
                        })
                    },
                )
                .optional()
                .map_err(map_sql)
        })
    }

    /// Run `refresh` exactly once per `freshness_window` across every
    /// process sharing this `state_root`. `Duration::ZERO` always
    /// refreshes.
    ///
    /// # Errors
    ///
    /// - Any error from the `refresh` closure propagates unchanged.
    /// - [`ErrorCode::StateRootUnavailable`] — the advisory lock file
    ///   cannot be opened or locked, any non-retryable `auth.sqlite`
    ///   failure, or the connection lock is poisoned.
    /// - [`ErrorCode::Transient`] — `auth.sqlite` stays BUSY/LOCKED past
    ///   the retry budget.
    pub fn with_refresh<T>(
        &self,
        backend_kind: &str,
        connection_id: &str,
        freshness_window: Duration,
        refresh: impl FnOnce() -> Result<RefreshRecord<T>>,
    ) -> Result<RefreshOutcome<T>> {
        let lock = self.lock_for(backend_kind, connection_id)?;
        if let Some(snapshot) = self.snapshot(backend_kind, connection_id)?
            && !is_stale(&snapshot, freshness_window)
        {
            drop(lock);
            return Ok(RefreshOutcome::Skipped(snapshot));
        }
        let record = refresh()?;
        self.record_refresh(backend_kind, connection_id, record.snapshot.clone())?;
        drop(lock);
        Ok(RefreshOutcome::Refreshed(record.value))
    }

    fn record_refresh(
        &self,
        backend_kind: &str,
        connection_id: &str,
        snapshot: AuthRefreshSnapshot,
    ) -> Result<()> {
        crate::retry::with_retry(&SQLITE_RETRY, || {
            self.conn()?
                .execute(
                    "INSERT INTO refresh_records (
                        backend_kind, connection_id, refreshed_unix_ms, expires_at_unix_ms
                     )
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(backend_kind, connection_id) DO UPDATE SET
                        refreshed_unix_ms = excluded.refreshed_unix_ms,
                        expires_at_unix_ms = excluded.expires_at_unix_ms",
                    params![
                        backend_kind,
                        connection_id,
                        snapshot.refreshed_unix_ms,
                        snapshot.expires_at_unix_ms
                    ],
                )
                .map_err(map_sql)?;
            Ok(())
        })
    }

    /// `Ok(None)` when no row exists. The secret bytes live in the
    /// `secrets` table and are fetched separately via `SecretStore::get`
    /// against `secret_handle`.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::Transient`] — `auth.sqlite` stays BUSY/LOCKED past
    ///   the retry budget.
    /// - [`ErrorCode::StateRootUnavailable`] — any other `auth.sqlite`
    ///   failure, or the connection lock is poisoned.
    pub fn load_secret_token(
        &self,
        backend_id: &str,
        principal: &str,
    ) -> Result<Option<PersistedSecretToken>> {
        crate::retry::with_retry(&SQLITE_RETRY, || {
            self.conn()?
                .query_row(
                    "SELECT cred_epoch, inserted_unix_ms, expires_at_unix_ms,
                            secret_handle, source_name
                     FROM credential_records
                     WHERE backend_id = ?1 AND principal = ?2",
                    params![backend_id, principal],
                    |row| {
                        Ok(PersistedSecretToken {
                            cred_epoch: row.get::<_, i64>(0)?.max(0) as u64,
                            inserted_unix_ms: row.get(1)?,
                            expires_at_unix_ms: row.get::<_, Option<i64>>(2)?,
                            secret_handle: row.get(3)?,
                            source_name: row.get(4)?,
                        })
                    },
                )
                .optional()
                .map_err(map_sql)
        })
    }

    /// Caller MUST land the secret bytes under `secret_handle` before
    /// calling this: this row is the index, and one naming bytes that were
    /// never written reads as a credential that is present but unreadable.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::Transient`] — `auth.sqlite` stays BUSY/LOCKED past
    ///   the retry budget.
    /// - [`ErrorCode::StateRootUnavailable`] — any other `auth.sqlite`
    ///   failure, or the connection lock is poisoned.
    pub fn store_secret_token(
        &self,
        backend_id: &str,
        principal: &str,
        token: &PersistedSecretToken,
    ) -> Result<()> {
        crate::retry::with_retry(&SQLITE_RETRY, || {
            self.conn()?
                .execute(
                    "INSERT INTO credential_records (
                        backend_id, principal, cred_epoch, inserted_unix_ms,
                        expires_at_unix_ms, secret_handle, source_name
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(backend_id, principal) DO UPDATE SET
                        cred_epoch         = excluded.cred_epoch,
                        inserted_unix_ms   = excluded.inserted_unix_ms,
                        expires_at_unix_ms = excluded.expires_at_unix_ms,
                        secret_handle      = excluded.secret_handle,
                        source_name        = excluded.source_name",
                    params![
                        backend_id,
                        principal,
                        token.cred_epoch as i64,
                        token.inserted_unix_ms,
                        token.expires_at_unix_ms,
                        token.secret_handle,
                        token.source_name,
                    ],
                )
                .map_err(map_sql)?;
            Ok(())
        })
    }

    /// No-op when no row exists; caller clears the matching secret
    /// separately.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::Transient`] — `auth.sqlite` stays BUSY/LOCKED past
    ///   the retry budget.
    /// - [`ErrorCode::StateRootUnavailable`] — any other `auth.sqlite`
    ///   failure, or the connection lock is poisoned.
    pub fn delete_secret_token(&self, backend_id: &str, principal: &str) -> Result<()> {
        crate::retry::with_retry(&SQLITE_RETRY, || {
            self.conn()?
                .execute(
                    "DELETE FROM credential_records WHERE backend_id = ?1 AND principal = ?2",
                    params![backend_id, principal],
                )
                .map_err(map_sql)?;
            Ok(())
        })
    }

    /// Highest `cred_epoch` ever committed across all rows; `0` when
    /// the table is empty. [`OAuthCredentialProvider`] reads it to
    /// choose the epoch for the row it is about to write, so stored
    /// epochs strictly grow across restarts.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::Transient`] — `auth.sqlite` stays BUSY/LOCKED past
    ///   the retry budget.
    /// - [`ErrorCode::StateRootUnavailable`] — any other `auth.sqlite`
    ///   failure, or the connection lock is poisoned.
    pub fn max_secret_cred_epoch(&self) -> Result<u64> {
        crate::retry::with_retry(&SQLITE_RETRY, || {
            let conn = self.conn()?;
            let value: Option<i64> = conn
                .query_row(
                    "SELECT MAX(cred_epoch) FROM credential_records",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(map_sql)?
                .flatten();
            Ok(value.unwrap_or(0).max(0) as u64)
        })
    }

    fn lock_for(&self, backend_kind: &str, connection_id: &str) -> Result<AuthRefreshGuard> {
        lock_refresh_file(self.locks_root.join(format!(
            "{}.lock",
            sha256_hex(format!("{backend_kind}\0{connection_id}").as_bytes())
        )))
    }

    async fn lock_for_async(
        &self,
        backend_kind: &str,
        connection_id: &str,
    ) -> Result<AuthRefreshGuard> {
        let path = self.locks_root.join(format!(
            "{}.lock",
            sha256_hex(format!("{backend_kind}\0{connection_id}").as_bytes())
        ));
        tokio::task::spawn_blocking(move || lock_refresh_file(path))
            .await
            .map_err(|error| {
                Error::new(
                    ErrorCode::StateRootUnavailable,
                    format!("auth refresh lock task failed: {error}"),
                )
            })?
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|_| {
            Error::new(
                ErrorCode::StateRootUnavailable,
                "auth.sqlite connection lock is poisoned",
            )
        })
    }

    /// Cached top-level address roots for the connection identity. `Ok(None)`
    /// when no row exists. Used by the lazy bring-up path so a known-good
    /// connection's routes can be installed at startup without a live probe.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::Transient`] — `auth.sqlite` stays BUSY/LOCKED past
    ///   the retry budget.
    /// - [`ErrorCode::StateRootUnavailable`] — any other `auth.sqlite`
    ///   failure, a poisoned connection lock, or a persisted
    ///   `addresses_json` value that no longer parses.
    pub fn load_address_roots(&self, identity_key: &str) -> Result<Option<CachedAddressRoots>> {
        crate::retry::with_retry(&SQLITE_RETRY, || {
            self.conn()?
                .query_row(
                    "SELECT backend_kind, display_name, addresses_json, cached_unix_ms
                     FROM connection_address_roots
                     WHERE identity_key = ?1",
                    params![identity_key],
                    |row| {
                        let addresses_json: String = row.get(2)?;
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            addresses_json,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(map_sql)
        })?
        .map(
            |(backend_kind, display_name, addresses_json, cached_unix_ms)| {
                let addresses: Vec<String> =
                    serde_json::from_str(&addresses_json).map_err(|err| {
                        Error::new(
                            ErrorCode::StateRootUnavailable,
                            format!("connection_address_roots.addresses_json invalid: {err}"),
                        )
                    })?;
                Ok(CachedAddressRoots {
                    backend_kind,
                    display_name,
                    addresses,
                    cached_unix_ms,
                })
            },
        )
        .transpose()
    }

    /// Insert or overwrite the cached address roots for `identity_key`.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::Internal`] — the address list fails to serialize
    ///   as JSON.
    /// - [`ErrorCode::Transient`] — `auth.sqlite` stays BUSY/LOCKED past
    ///   the retry budget.
    /// - [`ErrorCode::StateRootUnavailable`] — any other `auth.sqlite`
    ///   failure, or the connection lock is poisoned.
    pub fn store_address_roots(
        &self,
        identity_key: &str,
        entry: &CachedAddressRoots,
    ) -> Result<()> {
        let addresses_json = serde_json::to_string(&entry.addresses).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("address roots serialization failed: {err}"),
            )
        })?;
        crate::retry::with_retry(&SQLITE_RETRY, || {
            self.conn()?
                .execute(
                    "INSERT INTO connection_address_roots (
                        identity_key, backend_kind, display_name,
                        addresses_json, cached_unix_ms
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(identity_key) DO UPDATE SET
                        backend_kind = excluded.backend_kind,
                        display_name = excluded.display_name,
                        addresses_json = excluded.addresses_json,
                        cached_unix_ms = excluded.cached_unix_ms",
                    params![
                        identity_key,
                        entry.backend_kind,
                        entry.display_name,
                        addresses_json,
                        entry.cached_unix_ms,
                    ],
                )
                .map_err(map_sql)?;
            Ok(())
        })
    }

    /// Drop the cached address roots; missing rows are not an error.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::Transient`] — `auth.sqlite` stays BUSY/LOCKED past
    ///   the retry budget.
    /// - [`ErrorCode::StateRootUnavailable`] — any other `auth.sqlite`
    ///   failure, or the connection lock is poisoned.
    pub fn delete_address_roots(&self, identity_key: &str) -> Result<()> {
        crate::retry::with_retry(&SQLITE_RETRY, || {
            self.conn()?
                .execute(
                    "DELETE FROM connection_address_roots WHERE identity_key = ?1",
                    params![identity_key],
                )
                .map_err(map_sql)?;
            Ok(())
        })
    }
}

/// Open `state_root/auth.sqlite`, creating the directory and every table.
///
/// One function so the database has one schema whichever handle opens it
/// first — [`AuthRefreshLock`] and [`SqliteSecretStore`] hold separate
/// connections to it and either may be the one that creates the file.
///
/// The whole open is inside the retry budget. Every process running as this
/// user now shares one auth database, so two of them starting at once is
/// ordinary rather than exotic, and sqlite answers a concurrent `CREATE TABLE`
/// with BUSY. Before the auth root was unified this was rare enough that the
/// broker guarded it with a process-local mutex; that guard cannot see another
/// process.
fn open_auth_db(state_root: &Path) -> Result<Connection> {
    permissions::create_private_dir(state_root)?;
    let db_path = state_root.join("auth.sqlite");
    crate::retry::with_retry(&SQLITE_RETRY, || {
        let conn = Connection::open(&db_path).map_err(map_sql)?;
        // Before the schema exists and before any secret is written. On an
        // upgrade this is the moment a database left permissive by an earlier
        // release stops being readable by other users on the box, and it has
        // to happen ahead of the first credential write rather than after it.
        permissions::restrict_file_to_owner(&db_path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            CREATE TABLE IF NOT EXISTS refresh_records (
                backend_kind        TEXT NOT NULL,
                connection_id       TEXT NOT NULL,
                refreshed_unix_ms   INTEGER NOT NULL,
                expires_at_unix_ms  INTEGER,
                PRIMARY KEY (backend_kind, connection_id)
            );
            CREATE TABLE IF NOT EXISTS credential_records (
                backend_id          TEXT    NOT NULL,
                principal           TEXT    NOT NULL,
                cred_epoch          INTEGER NOT NULL,
                inserted_unix_ms    INTEGER NOT NULL,
                expires_at_unix_ms  INTEGER,
                secret_handle       TEXT    NOT NULL,
                source_name         TEXT    NOT NULL,
                PRIMARY KEY (backend_id, principal)
            );
            CREATE TABLE IF NOT EXISTS secrets (
                backend_kind     TEXT    NOT NULL,
                connection_id    TEXT    NOT NULL,
                field            TEXT    NOT NULL,
                secret           BLOB    NOT NULL,
                updated_unix_ms  INTEGER NOT NULL,
                PRIMARY KEY (backend_kind, connection_id, field)
            );
            CREATE TABLE IF NOT EXISTS connection_address_roots (
                identity_key       TEXT    PRIMARY KEY NOT NULL,
                backend_kind       TEXT    NOT NULL,
                display_name       TEXT,
                addresses_json     TEXT    NOT NULL,
                cached_unix_ms     INTEGER NOT NULL
            );
            ",
        )
        .map_err(map_sql)?;
        Ok(conn)
    })
}

/// Cached top-level address roots for one connection identity. The cache
/// stores only what's needed to seed the route table at startup; route
/// capabilities are re-derived on first live bring-up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedAddressRoots {
    pub backend_kind: String,
    pub display_name: Option<String>,
    pub addresses: Vec<String>,
    pub cached_unix_ms: i64,
}

/// Stable per-connection cache key derived from `(backend_kind, config,
/// display_name)`. Credentials are NOT included — rotating an OAuth refresh
/// token must not invalidate the cached address roots.
pub fn connection_identity(req: &ovstorage_plugin::ConnectionRequest) -> String {
    ovstorage_plugin::connection::identity::conn_id_from_request(req).0
}

pub struct RefreshRecord<T> {
    pub value: T,
    pub snapshot: AuthRefreshSnapshot,
}

struct AuthRefreshGuard {
    file: File,
}

fn lock_refresh_file(path: PathBuf) -> Result<AuthRefreshGuard> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(map_io)?;
    file.lock_exclusive().map_err(map_io)?;
    Ok(AuthRefreshGuard { file })
}

impl Drop for AuthRefreshGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn is_stale(snapshot: &AuthRefreshSnapshot, freshness_window: Duration) -> bool {
    if freshness_window.is_zero() {
        return true;
    }
    let now = unix_ms();
    let window_ms = freshness_window.as_millis().min(i64::MAX as u128) as i64;
    let age = now.saturating_sub(snapshot.refreshed_unix_ms);
    if age >= window_ms {
        return true;
    }
    if let Some(expires) = snapshot.expires_at_unix_ms {
        return expires <= now;
    }
    false
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Tight budget for SQLite BUSY/LOCKED — auth DB is small and
/// contention resolves in milliseconds.
const SQLITE_RETRY: crate::retry::RetryConfig = crate::retry::RetryConfig {
    initial_delay_ms: 25,
    max_delay_ms: 500,
    max_attempts: 5,
};

fn map_io(err: std::io::Error) -> Error {
    Error::new(ErrorCode::StateRootUnavailable, err.to_string())
}

/// PKCE verifier/challenge generator (RFC 7636 S256). The helper
/// picks 96 url-safe base64 characters (~64 bytes from `OsRng`).
pub mod pkce {
    use super::{Sha256, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use sha2::Digest;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PkceMaterial {
        pub verifier: String,
        pub challenge: String,
        pub challenge_method: &'static str,
    }

    pub fn generate() -> PkceMaterial {
        let mut entropy = [0u8; 64];
        OsRng.fill_bytes(&mut entropy);
        let verifier = URL_SAFE_NO_PAD.encode(entropy);
        let challenge = challenge_for(&verifier);
        PkceMaterial {
            verifier,
            challenge,
            challenge_method: "S256",
        }
    }

    pub fn challenge_for(verifier: &str) -> String {
        let digest = Sha256::digest(verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn pkce_round_trip_matches_rfc_7636_s256() {
        let material = pkce::generate();
        assert_eq!(material.challenge_method, "S256");
        assert!(material.verifier.len() >= 43 && material.verifier.len() <= 128);
        assert_eq!(pkce::challenge_for(&material.verifier), material.challenge);
    }

    #[test]
    fn pkce_challenge_for_known_verifier_matches_rfc_example() {
        // RFC 7636 Appendix B example
        let challenge = pkce::challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn auth_refresh_lock_writes_snapshot_under_freshness_window() {
        let temp = temp_root();
        let lock = AuthRefreshLock::open(temp.path()).unwrap();
        let outcome = lock
            .with_refresh("s3", "conn-1", Duration::from_secs(60), || {
                Ok(RefreshRecord {
                    value: "fresh-token".to_string(),
                    snapshot: AuthRefreshSnapshot {
                        refreshed_unix_ms: unix_ms(),
                        expires_at_unix_ms: Some(unix_ms() + 3_600_000),
                    },
                })
            })
            .unwrap();
        match outcome {
            RefreshOutcome::Refreshed(token) => assert_eq!(token, "fresh-token"),
            RefreshOutcome::Skipped(_) => panic!("expected Refreshed"),
        }

        let outcome = lock
            .with_refresh::<String>("s3", "conn-1", Duration::from_secs(60), || {
                panic!("must not run refresh closure within freshness window")
            })
            .unwrap();
        match outcome {
            RefreshOutcome::Skipped(snapshot) => {
                assert!(snapshot.expires_at_unix_ms.is_some());
            }
            RefreshOutcome::Refreshed(_) => panic!("expected Skipped"),
        }
    }

    #[test]
    fn auth_refresh_lock_runs_again_when_snapshot_is_expired() {
        let temp = temp_root();
        let lock = AuthRefreshLock::open(temp.path()).unwrap();
        lock.with_refresh("gcs", "conn-2", Duration::from_secs(3600), || {
            Ok(RefreshRecord {
                value: 1u32,
                snapshot: AuthRefreshSnapshot {
                    refreshed_unix_ms: unix_ms() - 10_000,
                    expires_at_unix_ms: Some(unix_ms() - 5_000),
                },
            })
        })
        .unwrap();
        let outcome = lock
            .with_refresh("gcs", "conn-2", Duration::from_secs(3600), || {
                Ok(RefreshRecord {
                    value: 2u32,
                    snapshot: AuthRefreshSnapshot {
                        refreshed_unix_ms: unix_ms(),
                        expires_at_unix_ms: Some(unix_ms() + 3_600_000),
                    },
                })
            })
            .unwrap();
        match outcome {
            RefreshOutcome::Refreshed(value) => assert_eq!(value, 2),
            RefreshOutcome::Skipped(_) => panic!("expected Refreshed after expiry"),
        }
    }

    #[test]
    fn auth_refresh_lock_serializes_concurrent_refreshes_across_threads() {
        // Eight threads stampede the same connection. The lock must serialize them
        // and the freshness window means at most one closure runs - the rest
        // observe the snapshot the winner wrote.
        use std::sync::atomic::{AtomicU32, Ordering};
        let temp = temp_root();
        let lock = std::sync::Arc::new(AuthRefreshLock::open(temp.path()).unwrap());
        let runs = std::sync::Arc::new(AtomicU32::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let lock = std::sync::Arc::clone(&lock);
            let runs = std::sync::Arc::clone(&runs);
            handles.push(
                std::thread::Builder::new()
                    .name("ovs-test-auth".into())
                    .spawn(move || {
                        lock.with_refresh::<()>("test", "shared", Duration::from_secs(60), || {
                            runs.fetch_add(1, Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(20));
                            Ok(RefreshRecord {
                                value: (),
                                snapshot: AuthRefreshSnapshot {
                                    refreshed_unix_ms: unix_ms(),
                                    expires_at_unix_ms: Some(unix_ms() + 3_600_000),
                                },
                            })
                        })
                        .unwrap();
                    })
                    .expect("failed to spawn thread"),
            );
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "AuthRefreshLock must coalesce concurrent refreshes within freshness window"
        );
    }

    #[test]
    fn credential_records_round_trip_through_auth_db() {
        let temp = temp_root();
        let lock = AuthRefreshLock::open(temp.path()).unwrap();
        // Empty DB: load misses, max_epoch == 0.
        assert!(lock.load_secret_token("s3", "u-1").unwrap().is_none());
        assert_eq!(lock.max_secret_cred_epoch().unwrap(), 0);

        let token = PersistedSecretToken {
            cred_epoch: 7,
            inserted_unix_ms: unix_ms(),
            expires_at_unix_ms: Some(unix_ms() + 3_600_000),
            secret_handle: "deadbeef".into(),
            source_name: "test-provider".into(),
        };
        lock.store_secret_token("s3", "u-1", &token).unwrap();
        let loaded = lock.load_secret_token("s3", "u-1").unwrap().unwrap();
        assert_eq!(loaded.cred_epoch, 7);
        assert_eq!(loaded.secret_handle, "deadbeef");
        assert_eq!(loaded.source_name, "test-provider");
        assert_eq!(lock.max_secret_cred_epoch().unwrap(), 7);

        // Restart simulation: dropping the lock and reopening sees the row.
        drop(lock);
        let lock = AuthRefreshLock::open(temp.path()).unwrap();
        assert_eq!(lock.max_secret_cred_epoch().unwrap(), 7);
        let still_there = lock.load_secret_token("s3", "u-1").unwrap().unwrap();
        assert_eq!(still_there.source_name, "test-provider");

        lock.delete_secret_token("s3", "u-1").unwrap();
        assert!(lock.load_secret_token("s3", "u-1").unwrap().is_none());
    }

    #[test]
    fn snapshot_returns_persisted_record() {
        let temp = temp_root();
        let lock = AuthRefreshLock::open(temp.path()).unwrap();
        assert!(lock.snapshot("azure", "conn-3").unwrap().is_none());
        lock.with_refresh("azure", "conn-3", Duration::from_secs(60), || {
            Ok(RefreshRecord {
                value: (),
                snapshot: AuthRefreshSnapshot {
                    refreshed_unix_ms: 1_700_000_000_000,
                    expires_at_unix_ms: None,
                },
            })
        })
        .unwrap();
        let snapshot = lock.snapshot("azure", "conn-3").unwrap().unwrap();
        assert_eq!(snapshot.refreshed_unix_ms, 1_700_000_000_000);
        assert_eq!(snapshot.expires_at_unix_ms, None);
    }

    #[test]
    fn connection_identity_is_stable_across_config_reorder() {
        use ovstorage_plugin::{ConfigValue, ConnectionRequest, SecretBundle};
        use std::collections::HashMap;
        let mut config_a = HashMap::new();
        config_a.insert("a".into(), ConfigValue::String("1".into()));
        config_a.insert("b".into(), ConfigValue::Int(2));
        config_a.insert("c".into(), ConfigValue::Bool(true));
        let mut config_b = HashMap::new();
        config_b.insert("c".into(), ConfigValue::Bool(true));
        config_b.insert("b".into(), ConfigValue::Int(2));
        config_b.insert("a".into(), ConfigValue::String("1".into()));
        let req_a = ConnectionRequest {
            backend_kind: "test".into(),
            config: config_a,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: Some("prod".into()),
        };
        let req_b = ConnectionRequest {
            backend_kind: "test".into(),
            config: config_b,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: Some("prod".into()),
        };
        assert_eq!(connection_identity(&req_a), connection_identity(&req_b));
    }

    #[test]
    fn connection_identity_differs_when_display_name_differs() {
        use ovstorage_plugin::{ConnectionRequest, SecretBundle};
        use std::collections::HashMap;
        let req_a = ConnectionRequest {
            backend_kind: "test".into(),
            config: HashMap::new(),
            credentials: SecretBundle::default(),
            persist: false,
            display_name: Some("prod".into()),
        };
        let req_b = ConnectionRequest {
            backend_kind: "test".into(),
            config: HashMap::new(),
            credentials: SecretBundle::default(),
            persist: false,
            display_name: Some("staging".into()),
        };
        assert_ne!(connection_identity(&req_a), connection_identity(&req_b));
    }

    #[test]
    fn address_roots_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let lock = AuthRefreshLock::open(dir.path()).unwrap();
        let entry = CachedAddressRoots {
            backend_kind: "test".into(),
            display_name: Some("prod".into()),
            addresses: vec!["s3://prod/".into(), "s3://staging/".into()],
            cached_unix_ms: 1_800_000_000_000,
        };
        lock.store_address_roots("test:sha256:abc", &entry).unwrap();
        let loaded = lock.load_address_roots("test:sha256:abc").unwrap().unwrap();
        assert_eq!(loaded, entry);
        lock.delete_address_roots("test:sha256:abc").unwrap();
        assert!(
            lock.load_address_roots("test:sha256:abc")
                .unwrap()
                .is_none()
        );
    }
}
