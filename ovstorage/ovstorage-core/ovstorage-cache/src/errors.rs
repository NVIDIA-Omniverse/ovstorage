// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ovstorage_layer::{Error, ErrorCode};

/// Map a `rusqlite` error to the project error type.
///
/// `SQLITE_BUSY` / `SQLITE_LOCKED` (another process or thread holds the
/// DB/table lock) are transient: backoff + retry typically succeeds. Match on
/// the **primary** result code (`code.code`), not `extended_code` — extended
/// variants such as `BUSY_SNAPSHOT` (517) or `LOCKED_SHAREDCACHE` (262) carry
/// the same primary code but a different integer, so comparing the integer to
/// the primary `SQLITE_BUSY` (5) constant would misclassify them as a fatal
/// `StateRootUnavailable` and defeat retry.
pub fn map_sql(error: rusqlite::Error) -> Error {
    if let rusqlite::Error::SqliteFailure(code, _) = &error
        && matches!(
            code.code,
            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
        )
    {
        return Error::new(ErrorCode::Transient, error.to_string());
    }
    Error::new(ErrorCode::StateRootUnavailable, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sqlite_failure(primary: rusqlite::ErrorCode, extended: i32) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: primary,
                extended_code: extended,
            },
            None,
        )
    }

    #[test]
    fn extended_busy_maps_to_transient() {
        // SQLITE_BUSY_SNAPSHOT = SQLITE_BUSY | (2 << 8) = 517. The old
        // extended_code == SQLITE_BUSY check missed this; the primary-code
        // match catches it.
        let err = map_sql(sqlite_failure(
            rusqlite::ErrorCode::DatabaseBusy,
            rusqlite::ffi::SQLITE_BUSY | (2 << 8),
        ));
        assert_eq!(err.code(), ErrorCode::Transient);
    }

    #[test]
    fn extended_locked_maps_to_transient() {
        let err = map_sql(sqlite_failure(
            rusqlite::ErrorCode::DatabaseLocked,
            rusqlite::ffi::SQLITE_LOCKED | (1 << 8),
        ));
        assert_eq!(err.code(), ErrorCode::Transient);
    }

    #[test]
    fn other_failures_map_to_state_root_unavailable() {
        let err = map_sql(sqlite_failure(
            rusqlite::ErrorCode::ConstraintViolation,
            rusqlite::ffi::SQLITE_CONSTRAINT,
        ));
        assert_eq!(err.code(), ErrorCode::StateRootUnavailable);
    }
}
