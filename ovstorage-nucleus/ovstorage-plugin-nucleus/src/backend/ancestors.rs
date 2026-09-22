// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Missing-ancestor creation for the `PathAtBranch`-typed creates.
//!
//! Omni1 `create_asset`, `copy2`, `rename2` and `create_directory` require the
//! destination's parent folder to exist, while every other backend lets a
//! write create its own path. The plugin closes that gap client-side: it
//! creates missing ancestors ahead of the commit and remembers, per
//! connection, which directories it has already created, so the ancestor call
//! is issued once per directory rather than once per file.
//!
//! The set answers exactly one question — "has this connection already created
//! this directory" — and a wrong answer costs one redundant idempotent call: a
//! directory removed by another client surfaces as `NotFound` on the commit,
//! which forgets the entry, re-creates the ancestors and retries once. That
//! is why it is a plain fixed-capacity `HashSet` cleared wholesale when full,
//! with no LRU bookkeeping and no TTL. It is deliberately not a list cache.

use std::collections::HashSet;
use std::sync::Arc;

use nucleus_client::types::{PathAtBranch, PathAtVersion, PathType};

use super::convert::path_at_version;
use ovstorage_plugin::{Error, ErrorCode, Result};

use crate::address::{NucleusTarget, path_is_under_prefix};
use crate::ops::{NucleusOps, status_to_result};

use super::convert::poisoned_state;
use super::spi::{NucleusBackend, directory_path};

/// Directories remembered per connection before the set is cleared wholesale.
pub(crate) const CREATED_DIRS_CAP: usize = 4096;

/// One directory this connection has created, in directory form (one
/// trailing `/`), on one branch.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DirKey {
    pub branch: Option<String>,
    pub dir: String,
}

/// Fixed-capacity set of directories already created on this connection.
pub(crate) struct CreatedDirectories {
    set: HashSet<DirKey>,
    cap: usize,
}

impl CreatedDirectories {
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            set: HashSet::new(),
            cap: cap.max(1),
        }
    }

    pub(crate) fn contains(&self, key: &DirKey) -> bool {
        self.set.contains(key)
    }

    /// A full set is cleared rather than evicted entry by entry: a miss costs
    /// one idempotent call, so eviction accuracy buys nothing.
    pub(crate) fn insert(&mut self, key: DirKey) {
        if !self.set.contains(&key) && self.set.len() >= self.cap {
            self.set.clear();
        }
        self.set.insert(key);
    }

    pub(crate) fn remove(&mut self, key: &DirKey) {
        self.set.remove(key);
    }

    /// Forget `prefix` (directory form) and everything beneath it on `branch`.
    pub(crate) fn remove_subtree(&mut self, branch: &Option<String>, prefix: &str) {
        self.set
            .retain(|key| !(key.branch == *branch && key.dir.starts_with(prefix)));
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.set.len()
    }
}

/// The directory containing `path`, in directory form; `None` for the root.
///
/// `/a/b/c.usd` and `/a/b/c/` both answer `/a/b/`; `/a/` answers `/`.
pub(crate) fn parent_directory(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let cut = trimmed.rfind('/')?;
    Some(trimmed[..=cut].to_string())
}

/// How a directory was found to exist: from the per-connection set, or by
/// live `create_directory` calls made during this ensure.
///
/// A commit that still answers `NotFound` after a live ensure is not
/// staleness — the ancestors were just confirmed — so only `FromCache` earns
/// the forget-and-retry pass. `AlreadyExisted` says the requested directory
/// answered `ALREADY_EXISTS` at the first attempt with no level missing,
/// which names a node of any type; a walk that saw any level missing reports
/// `Created` even if the directory itself was there again on the way down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ensured {
    FromCache,
    Created,
    AlreadyExisted,
    /// The ancestor call failed for a reason other than a missing level, so
    /// nothing is known or remembered; the commit proceeds and answers for
    /// itself.
    Unverified,
}

impl Ensured {
    /// Whether a `NotFound` from the commit may be stale-set staleness worth
    /// one forget, re-ensure and retry. Ancestors confirmed live in this
    /// call cannot be stale.
    pub(crate) fn retry_after_not_found(self) -> bool {
        matches!(self, Ensured::FromCache | Ensured::Unverified)
    }
}

impl NucleusBackend {
    /// Ensure the parent directory of `parsed.path` exists on the server.
    pub(super) async fn ensure_parent_directories(
        &self,
        ops: &Arc<dyn NucleusOps>,
        parsed: &NucleusTarget,
        force: bool,
    ) -> Result<Ensured> {
        match parent_directory(&parsed.path) {
            Some(parent) => {
                self.ensure_directory(ops, &parsed.branch, &parent, force)
                    .await
            }
            None => Ok(Ensured::AlreadyExisted),
        }
    }

    /// The write-path ensure: a precursor, not a precondition. A refusal of
    /// the ancestor call — a principal that may write assets but not create
    /// folders, or any transport fault — does not fail the write; the commit
    /// runs and the server's answer to the operation the caller asked for is
    /// what the caller sees. A level the server reports missing that cannot
    /// be created (above the prefix, or the root) is the one exception: the
    /// write would answer the same `NotFound`, so it surfaces here without
    /// sending the body.
    pub(super) async fn ensure_parent_for_write(
        &self,
        ops: &Arc<dyn NucleusOps>,
        parsed: &NucleusTarget,
    ) -> Result<Ensured> {
        match self.ensure_parent_directories(ops, parsed, false).await {
            Ok(ensured) => Ok(ensured),
            Err(err) if err.code() == ErrorCode::NotFound => Err(err),
            Err(err) => {
                tracing::debug!(
                    plugin = "nucleus",
                    code = ?err.code(),
                    detail = err.message(),
                    "nucleus ancestor call refused; the commit answers for itself"
                );
                Ok(Ensured::Unverified)
            }
        }
    }

    /// Drop the parent of `parsed.path` from the set, so the next ensure
    /// re-issues the call.
    pub(super) fn forget_parent(&self, parsed: &NucleusTarget) -> Result<()> {
        match parent_directory(&parsed.path) {
            Some(parent) => self.forget_directory(&parsed.branch, &parent),
            None => Ok(()),
        }
    }

    /// After a commit answered `NotFound` for a set-answered parent: forget
    /// the entry and re-ensure it live. On return the folder exists — created
    /// here, or by another writer that raced this one on the same stale
    /// entry — so one retry can succeed; whether it was this writer that
    /// created it cannot tell a raced re-creation from an unrelated
    /// `NotFound`, so the caller retries once either way.
    pub(super) async fn recreate_parent(
        &self,
        ops: &Arc<dyn NucleusOps>,
        parsed: &NucleusTarget,
    ) -> Result<()> {
        self.forget_parent(parsed)?;
        self.ensure_parent_directories(ops, parsed, true).await?;
        Ok(())
    }

    /// Whether a copy/rename source exists, asked only after the pair answered
    /// `NotFound`: omni1 gives one status for a missing source and a missing
    /// destination folder, and creating the folder for a source that is not
    /// there would leave an empty tree behind a failed operation. Both
    /// spellings are probed because `x` and `x/` name different nodes on the
    /// wire. A probe failure other than `NotFound`, transport faults
    /// included, does not change the outcome: it answers `true` and the
    /// ensure proceeds, so the pair's own answer is what the caller sees.
    pub(super) async fn source_exists(
        &self,
        ops: &Arc<dyn NucleusOps>,
        source: &NucleusTarget,
    ) -> bool {
        let mut probe = path_at_version(source);
        let mut spellings = vec![source.path.clone()];
        let as_directory = directory_path(&source.path);
        if as_directory != source.path {
            spellings.push(as_directory);
        }
        for spelling in spellings {
            probe.path = spelling;
            let Ok(result) = ops.stat2(probe.clone()).await else {
                return true;
            };
            match status_to_result(result.status, "stat2") {
                Ok(()) => return true,
                Err(err) if err.code() == ErrorCode::NotFound => {}
                Err(_) => return true,
            }
        }
        false
    }

    /// Log a failed recovery attempt. The re-ensure is not the operation the
    /// caller asked for, so its error never replaces the commit's own answer.
    pub(super) fn note_recovery_failure(err: &Error) {
        tracing::debug!(
            plugin = "nucleus",
            code = ?err.code(),
            detail = err.message(),
            "nucleus ancestor re-ensure failed; reporting the commit's answer"
        );
    }

    /// Remember the parent of `parsed.path` once a commit beneath it has
    /// succeeded: a successful write under a path proves it is a folder,
    /// which an `ALREADY_EXISTS` answer alone does not.
    pub(super) fn remember_parent(&self, parsed: &NucleusTarget) -> Result<()> {
        match parent_directory(&parsed.path) {
            Some(parent) => self.remember_directory(&parsed.branch, &parent),
            None => Ok(()),
        }
    }

    pub(super) fn remember_directory(&self, branch: &Option<String>, dir: &str) -> Result<()> {
        self.shared()
            .created_dirs
            .lock()
            .map_err(poisoned_state)?
            .insert(DirKey {
                branch: branch.clone(),
                dir: directory_path(dir),
            });
        Ok(())
    }

    /// Forget `path` and everything beneath it: a folder this connection
    /// deleted or renamed away must not be asserted afterwards.
    pub(super) fn forget_subtree(&self, branch: &Option<String>, path: &str) -> Result<()> {
        self.shared()
            .created_dirs
            .lock()
            .map_err(poisoned_state)?
            .remove_subtree(branch, &directory_path(path));
        Ok(())
    }

    pub(super) fn forget_directory(&self, branch: &Option<String>, dir: &str) -> Result<()> {
        self.shared()
            .created_dirs
            .lock()
            .map_err(poisoned_state)?
            .remove(&DirKey {
                branch: branch.clone(),
                dir: directory_path(dir),
            });
        Ok(())
    }

    /// Confirm that an `ALREADY_EXISTS` answer for `dir` names a directory.
    ///
    /// The slot's idempotent success is for an existing *directory*, which is
    /// then remembered; a file at the path keeps the `AlreadyExists` the
    /// server gave and is never remembered as a folder.
    pub(super) async fn confirm_directory(
        &self,
        ops: &Arc<dyn NucleusOps>,
        branch: &Option<String>,
        dir: &str,
    ) -> Result<()> {
        let dir = directory_path(dir);
        let result = ops
            .stat2(PathAtVersion {
                path: dir.clone(),
                branch: branch.clone(),
                checkpoint: None,
            })
            .await?;
        let is_directory = match status_to_result(result.status, "stat2") {
            Ok(()) => matches!(result.r#type, Some(PathType::Folder | PathType::Mount)),
            // The node exists (the server just said so) but not under the
            // directory spelling: it is a file.
            Err(err) if err.code() == ErrorCode::NotFound => false,
            Err(err) => return Err(err),
        };
        if is_directory {
            self.remember_directory(branch, &dir)?;
            return Ok(());
        }
        Err(Error::new(
            ErrorCode::AlreadyExists,
            "Nucleus create_directory: the path exists and is not a directory",
        ))
    }

    /// Ensure `dir` exists, creating it and any missing ancestors.
    ///
    /// Deepest-first: the directory itself is attempted first, and the walk
    /// climbs only while the server answers `NotFound`, so an existing parent
    /// costs one call and `d` missing levels cost `2d - 1`. `AlreadyExists`
    /// is success. The walk never climbs above the connection's `prefix`.
    /// With `force`, the set is bypassed for `dir` itself; ancestors reached
    /// by the walk are always attempted live because the walk only reaches
    /// them when the server has just said the level below is missing.
    pub(super) async fn ensure_directory(
        &self,
        ops: &Arc<dyn NucleusOps>,
        branch: &Option<String>,
        dir: &str,
        force: bool,
    ) -> Result<Ensured> {
        let dir = directory_path(dir);
        if dir.is_empty() || dir == "/" {
            return Ok(Ensured::AlreadyExisted);
        }
        if !force {
            let cached = self
                .shared()
                .created_dirs
                .lock()
                .map_err(poisoned_state)?
                .contains(&DirKey {
                    branch: branch.clone(),
                    dir: dir.clone(),
                });
            if cached {
                return Ok(Ensured::FromCache);
            }
        }
        let mut stack = vec![dir.clone()];
        let mut climbed: HashSet<String> = HashSet::new();
        let mut target_answered_exists = false;
        while let Some(current) = stack.last().cloned() {
            let response = ops
                .create_directory(PathAtBranch {
                    path: current.clone(),
                    branch: branch.clone(),
                })
                .await?;
            let created = match status_to_result(response.status, "create_directory") {
                Ok(()) => true,
                // Names a node of any type, so it is not remembered as a folder
                // here: a write path remembers its parent once a commit beneath
                // it succeeds, and the public verb after its stat2 confirmation.
                Err(err) if err.code() == ErrorCode::AlreadyExists => {
                    if current == dir {
                        target_answered_exists = true;
                    }
                    false
                }
                Err(err) if err.code() == ErrorCode::NotFound => {
                    // One climb per level: a parent that was just created and
                    // still yields NotFound below it is a server-side fact to
                    // surface, not a reason to loop.
                    if climbed.contains(&current) {
                        return Err(err);
                    }
                    // The root is never created, so a missing top-level folder is
                    // the server's answer to surface, not a reason to try `/`.
                    let Some(parent) = parent_directory(&current).filter(|p| p != "/") else {
                        return Err(err);
                    };
                    if !path_is_under_prefix(&parent, self.prefix()) {
                        return Err(err);
                    }
                    climbed.insert(current);
                    stack.push(parent);
                    continue;
                }
                Err(err) => return Err(err),
            };
            if created {
                tracing::debug!(plugin = "nucleus", dir = %current, "nucleus created directory");
                self.remember_directory(branch, &current)?;
            }
            stack.pop();
        }
        // A level seen missing means the tree was incomplete at this call,
        // even if another writer filled the directory in before the way down.
        Ok(if target_answered_exists && climbed.is_empty() {
            Ensured::AlreadyExisted
        } else {
            Ensured::Created
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_directory_answers_the_directory_form() {
        assert_eq!(parent_directory("/a/b/c.usd").as_deref(), Some("/a/b/"));
        assert_eq!(parent_directory("/a/b/c/").as_deref(), Some("/a/b/"));
        assert_eq!(parent_directory("/a/b/c").as_deref(), Some("/a/b/"));
        assert_eq!(parent_directory("/a/").as_deref(), Some("/"));
        assert_eq!(parent_directory("/a").as_deref(), Some("/"));
        assert_eq!(parent_directory("/"), None);
        assert_eq!(parent_directory(""), None);
    }

    fn key(dir: &str) -> DirKey {
        DirKey {
            branch: None,
            dir: dir.into(),
        }
    }

    #[test]
    fn insert_past_the_cap_clears_the_whole_set() {
        let mut set = CreatedDirectories::with_capacity(2);
        set.insert(key("/a/"));
        set.insert(key("/b/"));
        assert_eq!(set.len(), 2);
        // Re-inserting a member never triggers the clear.
        set.insert(key("/a/"));
        assert_eq!(set.len(), 2);
        set.insert(key("/c/"));
        assert_eq!(set.len(), 1);
        assert!(set.contains(&key("/c/")));
        assert!(!set.contains(&key("/a/")));
    }

    #[test]
    fn remove_forgets_one_entry_and_keys_include_the_branch() {
        let mut set = CreatedDirectories::with_capacity(8);
        set.insert(key("/a/"));
        set.insert(DirKey {
            branch: Some("dev".into()),
            dir: "/a/".into(),
        });
        set.remove(&key("/a/"));
        assert!(!set.contains(&key("/a/")));
        assert!(set.contains(&DirKey {
            branch: Some("dev".into()),
            dir: "/a/".into(),
        }));
    }
}
