// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential bytes in `auth.sqlite`.
//!
//! The store is keyed by the plugin ABI's own composite key —
//! `(backend_kind, connection_id, field)` — so the three host callbacks map
//! onto rows one-to-one and both credential pipelines address the same table.
//!
//! Neither of the two obvious alternatives works. `secret_tokens` is keyed
//! `(backend_id, principal)`, which carries no field, no persistence id, no
//! client and no discovery URL, so it collapses exactly the connections the
//! credential design keeps apart. And a handle-keyed table can only be
//! addressed by the host pipeline that mints handles: a plugin reaches this
//! store across the ABI with the composite key and has no handle to present,
//! so it would have nowhere to write.

use std::path::Path;
use std::sync::Mutex;

use ovstorage_cache::map_sql;
use ovstorage_plugin::{Error, ErrorCode, Result, SecretBytes};
use rusqlite::{Connection, OptionalExtension, params};

use super::SecretStore;

/// Credential bytes in `auth.sqlite`, keyed by the plugin ABI's composite key.
///
/// Holds its own connection rather than sharing [`super::AuthRefreshLock`]'s.
/// The two are opened against one database and one WAL, so they see each
/// other's commits, but a reader here never waits on a writer there. That
/// separation is load-bearing rather than incidental: the credential
/// publication lock is deliberately held across a store round trip, and the
/// plugin-side lock-order rules require that round trip not run under a lock
/// the read path also takes.
pub struct SqliteSecretStore {
    conn: Mutex<Connection>,
}

impl SqliteSecretStore {
    /// Open the store under `state_root`, creating `auth.sqlite` and the
    /// `secrets` table if they are absent.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::StateRootUnavailable`] — `state_root` cannot be created,
    ///   or `auth.sqlite` fails to open or initialise.
    /// - [`ErrorCode::Transient`] — `auth.sqlite` is BUSY/LOCKED while opening.
    pub fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let conn = super::open_auth_db(state_root.as_ref())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|_| {
            Error::new(
                ErrorCode::StateRootUnavailable,
                "auth.sqlite secret-store connection lock is poisoned",
            )
        })
    }
}

/// The UTF-8 contract, applied before anything is written.
///
/// `secret` is stored as a BLOB, so sqlite itself would carry arbitrary bytes.
/// The restriction is inherited from the secret store, which stored strings, and
/// it is kept on purpose: callers base64 their binary secrets today, and
/// relaxing the contract is a behaviour change with its own call sites to
/// check rather than a free consequence of changing the backing store.
fn checked(secret: &SecretBytes) -> Result<&[u8]> {
    std::str::from_utf8(&secret.0).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "SecretStore values must be UTF-8 (encode binary secrets as base64 first)",
        )
    })?;
    Ok(&secret.0)
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

impl SecretStore for SqliteSecretStore {
    fn put(
        &self,
        backend_kind: &str,
        connection_id: &str,
        field: &str,
        secret: &SecretBytes,
    ) -> Result<()> {
        self.put_many(backend_kind, connection_id, &[(field, secret)])
    }

    fn get(
        &self,
        backend_kind: &str,
        connection_id: &str,
        field: &str,
    ) -> Result<Option<SecretBytes>> {
        crate::retry::with_retry(&super::SQLITE_RETRY, || {
            self.conn()?
                .query_row(
                    "SELECT secret FROM secrets
                     WHERE backend_kind = ?1 AND connection_id = ?2 AND field = ?3",
                    params![backend_kind, connection_id, field],
                    |row| row.get::<_, Vec<u8>>(0).map(SecretBytes),
                )
                .optional()
                .map_err(map_sql)
        })
    }

    fn delete(&self, backend_kind: &str, connection_id: &str, field: &str) -> Result<()> {
        crate::retry::with_retry(&super::SQLITE_RETRY, || {
            self.conn()?
                .execute(
                    "DELETE FROM secrets
                     WHERE backend_kind = ?1 AND connection_id = ?2 AND field = ?3",
                    params![backend_kind, connection_id, field],
                )
                .map_err(map_sql)?;
            Ok(())
        })
    }

    fn put_many(
        &self,
        backend_kind: &str,
        connection_id: &str,
        fields: &[(&str, &SecretBytes)],
    ) -> Result<()> {
        crate::retry::with_retry(&super::SQLITE_RETRY, || {
            let mut guard = self.conn()?;
            let tx = guard.transaction().map_err(map_sql)?;
            let updated = now_unix_ms();
            for (field, secret) in fields {
                // Validated inside the transaction, so a rejected field
                // unwinds the fields already staged beside it. Checking every
                // field up front would refuse the same inputs, but it would
                // make the rollback unreachable and therefore untested -- and
                // the rollback is the guarantee this method exists to give.
                let bytes = checked(secret)?;
                tx.execute(
                    "INSERT INTO secrets (
                        backend_kind, connection_id, field, secret, updated_unix_ms
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(backend_kind, connection_id, field) DO UPDATE SET
                        secret          = excluded.secret,
                        updated_unix_ms = excluded.updated_unix_ms",
                    params![backend_kind, connection_id, field, bytes, updated],
                )
                .map_err(map_sql)?;
            }
            tx.commit().map_err(map_sql)?;
            Ok(())
        })
    }
}
