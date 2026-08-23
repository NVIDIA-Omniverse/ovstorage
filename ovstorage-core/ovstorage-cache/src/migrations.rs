// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Versioned schema migrations.
//!
//! `schema_version` is a single-row table; `migrate` advances it
//! through each `up_vN` in order. Migrations run in a transaction
//! with the version bump as the last statement so a crash leaves the
//! DB at the prior version — a partially-applied schema is impossible.

use rusqlite::{Connection, OptionalExtension, params};

use ovstorage_layer::{Error, ErrorCode, Result};

use crate::errors::map_sql;

/// The on-disk schema version this build produces.
pub const CURRENT_SCHEMA_VERSION: i64 = 2;

/// Idempotent: callers invoke on every `Cache::open`.
pub fn migrate(conn: &Connection) -> Result<()> {
    ensure_schema_version_table(conn)?;
    let mut version = current(conn)?;
    if version > CURRENT_SCHEMA_VERSION {
        return Err(Error::new(
            ErrorCode::Unsupported,
            format!(
                "on-disk schema version {version} is newer than supported {CURRENT_SCHEMA_VERSION}; \
                 upgrade the binary"
            ),
        ));
    }
    while version < CURRENT_SCHEMA_VERSION {
        match version {
            0 => up_v1_seed_initial_schema(conn)?,
            1 => up_v2_add_cache_entries_table(conn)?,
            other => {
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!("no migration registered for version {other}"),
                ));
            }
        }
        version = current(conn)?;
    }
    Ok(())
}

/// Current schema version; `0` for a fresh DB.
pub fn current(conn: &Connection) -> Result<i64> {
    let value: Option<i64> = conn
        .query_row(
            "SELECT version FROM schema_version WHERE rowid = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sql)?;
    Ok(value.unwrap_or(0))
}

fn set_version(conn: &Connection, target: i64) -> Result<()> {
    conn.execute(
        "
        INSERT INTO schema_version (rowid, version) VALUES (1, ?1)
        ON CONFLICT(rowid) DO UPDATE SET version = excluded.version
        ",
        params![target],
    )
    .map_err(map_sql)?;
    Ok(())
}

fn ensure_schema_version_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS schema_version (
            rowid   INTEGER PRIMARY KEY CHECK (rowid = 1),
            version INTEGER NOT NULL
        );
        ",
    )
    .map_err(map_sql)?;
    Ok(())
}

/// v0 → v1: stamp the legacy `entries` + `process_leases` shape as
/// v1. The `ALTER TABLE` adds `last_access_unix_ms` for DBs created
/// before the column existed; tolerated to fail when the column is
/// already there.
fn up_v1_seed_initial_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        BEGIN;
        CREATE TABLE IF NOT EXISTS entries (
            resolved_target TEXT PRIMARY KEY NOT NULL,
            cas_key         TEXT NOT NULL,
            size            INTEGER NOT NULL,
            updated_unix_ms INTEGER NOT NULL,
            last_access_unix_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS process_leases (
            pid             INTEGER NOT NULL,
            started_unix_ms INTEGER NOT NULL,
            state_root      TEXT NOT NULL,
            PRIMARY KEY (pid, started_unix_ms)
        );
        COMMIT;
        ",
    )
    .map_err(map_sql)?;
    let _ = conn.execute(
        "ALTER TABLE entries ADD COLUMN last_access_unix_ms INTEGER NOT NULL DEFAULT 0",
        [],
    );
    conn.execute(
        "
        UPDATE entries
        SET last_access_unix_ms = updated_unix_ms
        WHERE last_access_unix_ms = 0
        ",
        [],
    )
    .map_err(map_sql)?;
    set_version(conn, 1)?;
    Ok(())
}

/// v1 → v2: introduce `cache_entries` (CAS-keyed) alongside
/// `entries` (target-keyed). `cache_entries` is authoritative for
/// `pin_count` / `lease_count` / `verified_at`; existing rows are
/// mirrored over.
fn up_v2_add_cache_entries_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        BEGIN;
        CREATE TABLE IF NOT EXISTS cache_entries (
            cas_key       TEXT PRIMARY KEY NOT NULL,
            size          INTEGER NOT NULL,
            pin_count     INTEGER NOT NULL DEFAULT 0,
            lease_count   INTEGER NOT NULL DEFAULT 0,
            verified_at   INTEGER NOT NULL DEFAULT 0
        );
        COMMIT;
        ",
    )
    .map_err(map_sql)?;
    // INSERT OR IGNORE keeps re-runs harmless.
    conn.execute(
        "
        INSERT OR IGNORE INTO cache_entries (cas_key, size)
        SELECT cas_key, size FROM entries
        ",
        [],
    )
    .map_err(map_sql)?;
    set_version(conn, 2)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn migrate_starts_at_zero_and_advances_to_current() {
        let conn = Connection::open_in_memory().unwrap();
        // `current` needs the table to exist; pre-migrate it does not.
        ensure_schema_version_table(&conn).unwrap();
        assert_eq!(current(&conn).unwrap(), 0);
        migrate(&conn).unwrap();
        assert_eq!(current(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn migrate_is_idempotent_on_repeat() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();
        assert_eq!(current(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn migrate_rejects_newer_schema_version() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        conn.execute(
            "UPDATE schema_version SET version = ?1 WHERE rowid = 1",
            params![CURRENT_SCHEMA_VERSION + 1],
        )
        .unwrap();
        let err = migrate(&conn).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[test]
    fn cache_entries_table_seeds_from_entries() {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema_version_table(&conn).unwrap();
        up_v1_seed_initial_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO entries (resolved_target, cas_key, size, updated_unix_ms, last_access_unix_ms) \
             VALUES ('test://a/x', 'deadbeef', 4, 1, 1)",
            [],
        )
        .unwrap();
        migrate(&conn).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cache_entries WHERE cas_key = 'deadbeef'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
