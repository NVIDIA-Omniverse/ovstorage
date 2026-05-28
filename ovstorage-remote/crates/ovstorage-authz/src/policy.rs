// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy-epoch state machine. Hosts stamp every request with
//! `current_epoch()`; `check` rejects stale epochs except in
//! `GraceWindow` mode where a previous epoch is honored unless
//! explicitly invalidated. Persisted variant keeps the counter across
//! reloads (broker SIGHUP); in-memory variant is for the REST gateway.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ovstorage_plugin::{Error, ErrorCode, Result};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum PolicyFreshness {
    #[default]
    Strict,
    GraceWindow,
}

pub struct PolicyEpochState {
    current_epoch: AtomicU64,
    invalidated_epochs: Mutex<HashSet<u64>>,
    store: Option<PolicyEpochStore>,
    freshness: PolicyFreshness,
}

impl PolicyEpochState {
    pub fn in_memory(current_epoch: u64, freshness: PolicyFreshness) -> Arc<Self> {
        Arc::new(Self {
            current_epoch: AtomicU64::new(current_epoch),
            invalidated_epochs: Mutex::new(HashSet::new()),
            store: None,
            freshness,
        })
    }

    pub fn open(state_root: PathBuf, freshness: PolicyFreshness) -> Result<Arc<Self>> {
        let (store, current_epoch) = PolicyEpochStore::open(state_root)?;
        Ok(Arc::new(Self {
            current_epoch: AtomicU64::new(current_epoch),
            invalidated_epochs: Mutex::new(HashSet::new()),
            store: Some(store),
            freshness,
        }))
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch.load(Ordering::SeqCst)
    }

    pub fn check(&self, request_epoch: u64) -> Result<()> {
        let current_epoch = self.current_epoch();
        if request_epoch == current_epoch {
            return Ok(());
        }
        if self.freshness == PolicyFreshness::GraceWindow
            && request_epoch + 1 == current_epoch
            && !self
                .invalidated_epochs
                .lock()
                .map_err(|_| Error::new(ErrorCode::Internal, "policy epoch lock is poisoned"))?
                .contains(&request_epoch)
        {
            return Ok(());
        }
        Err(Error::new(
            ErrorCode::PolicyEpochStale,
            format!("policy epoch {request_epoch} is stale; current epoch is {current_epoch}"),
        ))
    }

    pub fn advance(&self) -> Result<u64> {
        let next = self.current_epoch().checked_add(1).ok_or_else(|| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "policy epoch counter is exhausted",
            )
        })?;
        if let Some(store) = &self.store {
            store.write_epoch(next)?;
        }
        self.current_epoch.store(next, Ordering::SeqCst);
        tracing::info!(
            target: "ovstorage.authz.policy",
            policy_epoch = next,
            "policy epoch advanced"
        );
        Ok(next)
    }

    pub fn invalidate(&self, epochs: &[u64]) -> Result<()> {
        let mut invalidated = self
            .invalidated_epochs
            .lock()
            .map_err(|_| Error::new(ErrorCode::Internal, "policy epoch lock is poisoned"))?;
        invalidated.extend(epochs.iter().copied());
        Ok(())
    }
}

struct PolicyEpochStore {
    path: PathBuf,
}

impl PolicyEpochStore {
    fn open(state_root: PathBuf) -> Result<(Self, u64)> {
        fs::create_dir_all(&state_root).map_err(map_io)?;
        let store = Self {
            path: state_root.join("policy_epoch"),
        };
        let epoch = match fs::read_to_string(&store.path) {
            Ok(contents) => parse_policy_epoch(contents.trim())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                store.write_epoch(0)?;
                0
            }
            Err(error) => return Err(map_io(error)),
        };
        Ok((store, epoch))
    }

    fn write_epoch(&self, epoch: u64) -> Result<()> {
        let parent = self.path.parent().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "policy epoch path has no parent directory",
            )
        })?;
        fs::create_dir_all(parent).map_err(map_io)?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let tmp = parent.join(format!("policy_epoch.{}.{}.tmp", std::process::id(), stamp));
        {
            let mut file = fs::File::create(&tmp).map_err(map_io)?;
            writeln!(file, "{epoch}").map_err(map_io)?;
            file.sync_all().map_err(map_io)?;
        }
        fs::rename(&tmp, &self.path).map_err(map_io)
    }
}

fn parse_policy_epoch(value: &str) -> Result<u64> {
    value.parse::<u64>().map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "policy epoch state is not a valid u64",
        )
    })
}

fn map_io(error: std::io::Error) -> Error {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::StateRootUnavailable,
    };
    Error::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grace_window_honors_immediate_previous_epoch() {
        let state = PolicyEpochState::in_memory(5, PolicyFreshness::GraceWindow);
        assert!(state.check(4).is_ok());
    }

    #[test]
    fn grace_window_rejects_two_epochs_old() {
        let state = PolicyEpochState::in_memory(5, PolicyFreshness::GraceWindow);
        let err = state.check(3).expect_err("expected stale-epoch error");
        assert_eq!(err.code(), ErrorCode::PolicyEpochStale);
    }

    #[test]
    fn grace_window_rejects_invalidated_previous_epoch() {
        let state = PolicyEpochState::in_memory(5, PolicyFreshness::GraceWindow);
        state.invalidate(&[4]).unwrap();
        assert!(state.check(4).is_err());
    }

    #[test]
    fn strict_rejects_any_stale_epoch() {
        let state = PolicyEpochState::in_memory(5, PolicyFreshness::Strict);
        assert!(state.check(4).is_err());
        assert!(state.check(3).is_err());
    }

    #[test]
    fn current_epoch_accepted_in_both_modes() {
        let strict = PolicyEpochState::in_memory(5, PolicyFreshness::Strict);
        let grace = PolicyEpochState::in_memory(5, PolicyFreshness::GraceWindow);
        assert!(strict.check(5).is_ok());
        assert!(grace.check(5).is_ok());
    }
}
