// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ovstorage::LocalDelegate;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    pub fn stdio() -> Self {
        Self("stdio".to_string())
    }
}

struct LeaseEntry {
    _delegate: LocalDelegate,
    _expires_at: Instant,
    expiry_task: JoinHandle<()>,
}

impl Drop for LeaseEntry {
    fn drop(&mut self) {
        self.expiry_task.abort();
    }
}

#[derive(Clone)]
pub struct LeaseStore {
    inner: Arc<Mutex<HashMap<(SessionId, PathBuf), LeaseEntry>>>,
}

impl LeaseStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn insert(
        &self,
        session: SessionId,
        path: PathBuf,
        delegate: LocalDelegate,
        ttl: Duration,
    ) -> Instant {
        let expires_at = Instant::now() + ttl;
        let key = (session, path);
        let store = self.clone();
        let key_for_task = key.clone();
        let expiry_task = tokio::spawn(async move {
            tokio::time::sleep(ttl).await;
            let mut guard = store.inner.lock().await;
            guard.remove(&key_for_task);
        });
        let entry = LeaseEntry {
            _delegate: delegate,
            _expires_at: expires_at,
            expiry_task,
        };
        let mut guard = self.inner.lock().await;
        guard.insert(key, entry);
        expires_at
    }

    pub async fn remove(&self, session: SessionId, path: PathBuf) -> bool {
        let mut guard = self.inner.lock().await;
        guard.remove(&(session, path)).is_some()
    }

    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }
}

impl Default for LeaseStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use ovstorage::{ChecksumSet, ObjectInfo, ObjectKind, address};

    use super::*;

    fn dummy_delegate(path: &str) -> LocalDelegate {
        LocalDelegate {
            path: PathBuf::from(path),
            info: ObjectInfo {
                address: address::parse("file:///tmp/test/dummy").unwrap(),
                kind: ObjectKind::File,
                etag: None,
                version: None,
                size: None,
                mtime: None,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
            },
            guard: None,
        }
    }

    #[tokio::test]
    async fn insert_and_remove_one_lease() {
        let store = LeaseStore::new();
        let session = SessionId::stdio();
        let path = PathBuf::from("/tmp/test/a");
        store
            .insert(
                session.clone(),
                path.clone(),
                dummy_delegate("/tmp/test/a"),
                Duration::from_secs(30),
            )
            .await;
        assert_eq!(store.len().await, 1);
        assert!(store.remove(session, path).await);
        assert_eq!(store.len().await, 0);
    }

    #[tokio::test]
    async fn remove_unknown_returns_false() {
        let store = LeaseStore::new();
        assert!(
            !store
                .remove(SessionId::stdio(), PathBuf::from("/never/inserted"))
                .await
        );
    }

    #[tokio::test]
    async fn ttl_expiry_removes_entry() {
        let store = LeaseStore::new();
        let path = PathBuf::from("/tmp/test/short-ttl");
        store
            .insert(
                SessionId::stdio(),
                path,
                dummy_delegate("/tmp/test/short-ttl"),
                Duration::from_millis(50),
            )
            .await;
        assert_eq!(store.len().await, 1);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(store.len().await, 0);
    }

    #[tokio::test]
    async fn reinsert_replaces_prior_entry() {
        let store = LeaseStore::new();
        let session = SessionId::stdio();
        let path = PathBuf::from("/tmp/test/refresh");
        let exp1 = store
            .insert(
                session.clone(),
                path.clone(),
                dummy_delegate("/tmp/test/refresh"),
                Duration::from_secs(60),
            )
            .await;
        let exp2 = store
            .insert(
                session,
                path,
                dummy_delegate("/tmp/test/refresh"),
                Duration::from_secs(120),
            )
            .await;
        assert!(exp2 > exp1);
        assert_eq!(store.len().await, 1);
    }
}
