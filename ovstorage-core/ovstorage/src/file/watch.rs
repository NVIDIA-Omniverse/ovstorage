// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Polling directory watcher for the built-in `file://` backend.
//!
//! POSIX and NTFS have native change-notification facilities (inotify,
//! `ReadDirectoryChangesW`), but they are platform-specific, bounded by kernel
//! queue limits, and miss events under pressure. The file backend instead
//! re-scans the watched directory on a fixed interval and diffs successive
//! snapshots — slower to observe a change (bounded by one poll interval) but
//! portable and never silently lossy.
//!
//! The watcher is a blocking [`Iterator`] surfaced through the Layer's
//! [`ChangeStream`](crate::ChangeStream) slot: each [`Iterator::next`] sleeps
//! one poll interval (checking the cancel token before and after so a
//! mid-sleep cancellation is observed within one interval), re-scans, and
//! drains the diff. Because `next` blocks, callers drive it from a blocking
//! context (the host runs `ChangeStream` iteration off the async executor).
//!
//! Relocated (modulo import/type paths and a direct [`ChangeEvent`] yield in
//! place of the cdylib's `BackendChangeEvent` + host mapping) from the legacy
//! `ovstorage-plugin-file` cdylib so the built-in backend is feature-complete
//! and the cdylib can be retired.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use url::Url;

use crate::file::metadata;
use crate::{
    CancellationToken, ChangeEvent, ChangeKind, Result, WatchDirectoryCursor,
    WatchDirectoryOptions, address,
};
use ovstorage_layer::io_error;

/// Minimum poll interval. A caller asking for a faster cadence is clamped to
/// this floor so a misconfigured `poll_interval` of zero cannot spin the
/// re-scan loop hot.
const MIN_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Per-entry identity captured on each scan. Change detection compares
/// successive snapshots: an object is `Modified` when `(size, mtime)` differs
/// and `MetadataChanged` when only its sidecar's mtime differs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WatchSnapshotEntry {
    size: u64,
    mtime: Option<SystemTime>,
    /// mtime of the object's user-metadata sidecar, if present. Drives
    /// `MetadataChanged` when `include_metadata_changes` is set.
    metadata_mtime: Option<SystemTime>,
}

/// Blocking, polling directory watcher. Holds the watched directory, the
/// caller-facing base address for relative-key joins, the last snapshot, and a
/// queue of not-yet-emitted [`ChangeEvent`]s.
pub(crate) struct FileChangeStream {
    root: PathBuf,
    base_address: Url,
    recursive: bool,
    include_metadata_changes: bool,
    poll_interval: Duration,
    /// `Some(canonical_root)` when the matched root armed `confine_to_root`, in
    /// which case each snapshot re-jails every descended directory so the walk
    /// cannot enumerate the target of an escaping in-root symlink. `None`
    /// (default) follows symlinks — the virtual-tree model.
    confine_root: Option<PathBuf>,
    snapshot: BTreeMap<Vec<u8>, WatchSnapshotEntry>,
    pending: VecDeque<ChangeEvent>,
    /// Checked before and after each poll sleep; a mid-sleep cancellation is
    /// observed within one poll interval.
    cancel: Option<CancellationToken>,
}

impl FileChangeStream {
    /// Take the initial snapshot of `root` and prime the stream. A non-`None`
    /// `since` cursor cannot be honored by a stateless poller (there is no
    /// durable history to replay from), so the stream opens with a `Lapsed`
    /// event and then reports changes from the initial snapshot forward.
    pub(crate) fn new(
        root: PathBuf,
        base_address: Url,
        opts: WatchDirectoryOptions,
        confine_root: Option<PathBuf>,
        cancel: Option<CancellationToken>,
    ) -> Result<Self> {
        let snapshot =
            scan_watch_directory_snapshot(&root, opts.recursive, confine_root.as_deref())?;
        let mut pending = VecDeque::new();
        if opts.since.is_some() {
            pending.push_back(ChangeEvent::Lapsed {
                since: None,
                cursor: fresh_watch_directory_cursor(),
            });
        }
        Ok(Self {
            root,
            base_address,
            recursive: opts.recursive,
            include_metadata_changes: opts.include_metadata_changes,
            poll_interval: opts.poll_interval.max(MIN_POLL_INTERVAL),
            confine_root,
            snapshot,
            pending,
            cancel,
        })
    }

    fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .map(|token| token.is_cancelled())
            .unwrap_or(false)
    }
}

impl Iterator for FileChangeStream {
    type Item = Result<ChangeEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.is_cancelled() {
                return None;
            }
            if let Some(event) = self.pending.pop_front() {
                return Some(Ok(event));
            }
            std::thread::sleep(self.poll_interval);
            if self.is_cancelled() {
                return None;
            }
            match scan_watch_directory_snapshot(
                &self.root,
                self.recursive,
                self.confine_root.as_deref(),
            ) {
                Ok(next) => match diff_watch_directory_snapshots(
                    &self.snapshot,
                    &next,
                    &self.base_address,
                    self.include_metadata_changes,
                ) {
                    Ok(pending) => {
                        self.pending = pending;
                        self.snapshot = next;
                    }
                    Err(error) => return Some(Err(error)),
                },
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

fn scan_watch_directory_snapshot(
    root: &Path,
    recursive: bool,
    confine_root: Option<&Path>,
) -> Result<BTreeMap<Vec<u8>, WatchSnapshotEntry>> {
    let mut out = BTreeMap::new();
    scan_watch_directory_dir(root, root, recursive, confine_root, &mut out)?;
    Ok(out)
}

fn scan_watch_directory_dir(
    base: &Path,
    current: &Path,
    recursive: bool,
    confine_root: Option<&Path>,
    out: &mut BTreeMap<Vec<u8>, WatchSnapshotEntry>,
) -> Result<()> {
    for entry in fs::read_dir(current).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let path = entry.path();
        if metadata::is_internal_entry(&path) {
            continue;
        }
        // In `confine_to_root` mode re-jail every entry so the poll snapshot
        // cannot observe (and emit change events for) the target of an escaping
        // in-root symlink — mirroring `checked_scope_for`, which would deny a
        // direct op on the same address. Off by default (virtual-tree follow).
        if let Some(canonical_root) = confine_root
            && super::ensure_path_within_root(&path, canonical_root).is_err()
        {
            continue;
        }
        if path.is_dir() {
            if recursive {
                scan_watch_directory_dir(base, &path, recursive, confine_root, out)?;
            }
            continue;
        }
        out.insert(relative_path(base, &path)?, watch_snapshot_entry(&path)?);
    }
    Ok(())
}

fn watch_snapshot_entry(path: &Path) -> Result<WatchSnapshotEntry> {
    let metadata = fs::metadata(path).map_err(io_error)?;
    let metadata_mtime = metadata::metadata_path(path)
        .ok()
        .and_then(|sidecar| fs::metadata(sidecar).ok())
        .and_then(|sidecar| sidecar.modified().ok());
    Ok(WatchSnapshotEntry {
        size: metadata.len(),
        mtime: metadata.modified().ok(),
        metadata_mtime,
    })
}

fn diff_watch_directory_snapshots(
    old: &BTreeMap<Vec<u8>, WatchSnapshotEntry>,
    new: &BTreeMap<Vec<u8>, WatchSnapshotEntry>,
    base_address: &Url,
    include_metadata_changes: bool,
) -> Result<VecDeque<ChangeEvent>> {
    let keys = old
        .keys()
        .chain(new.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut out = VecDeque::new();
    for key in keys {
        match (old.get(&key), new.get(&key)) {
            (None, Some(current)) => out.push_back(change_event(
                base_address,
                key,
                ChangeKind::Created,
                Some(current),
            )?),
            (Some(_), None) => {
                out.push_back(change_event(base_address, key, ChangeKind::Deleted, None)?)
            }
            (Some(previous), Some(current))
                if previous.size != current.size || previous.mtime != current.mtime =>
            {
                out.push_back(change_event(
                    base_address,
                    key,
                    ChangeKind::Modified,
                    Some(current),
                )?);
            }
            (Some(previous), Some(current))
                if include_metadata_changes
                    && previous.metadata_mtime != current.metadata_mtime =>
            {
                out.push_back(change_event(
                    base_address,
                    key,
                    ChangeKind::MetadataChanged,
                    Some(current),
                )?);
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Builds a [`ChangeEvent::Object`] from the post-change snapshot entry.
///
/// `entry = None` represents a delete (the post-change snapshot is absent), in
/// which case the descriptive fields (`etag`/`size`/`mtime`) all collapse to
/// `None`. The file backend has no notion of a backend `version`, so `version`
/// is always `None`. The synthesized etag uses the same `size:N,mtime:nanos`
/// scheme as `stat`, so an etag observed on a change event round-trips through
/// `if_match` against a subsequent `stat`.
///
/// This yields the native [`ChangeEvent`] directly rather than the cdylib's
/// `BackendChangeEvent` + host-side `backend_change_to_change` mapping: the
/// built-in fills the Layer `watch_directory` slot, so there is no FFI hop and
/// no intermediate vocabulary to translate.
fn change_event(
    base_address: &Url,
    relative_key: Vec<u8>,
    kind: ChangeKind,
    entry: Option<&WatchSnapshotEntry>,
) -> Result<ChangeEvent> {
    let (etag, size, mtime) = match entry {
        Some(entry) => (
            Some(watch_etag(entry.size, entry.mtime)),
            Some(entry.size),
            entry.mtime,
        ),
        None => (None, None, None),
    };
    Ok(ChangeEvent::Object {
        address: address::join_relative_bytes(base_address, &relative_key)?,
        kind,
        etag,
        version: None,
        size,
        mtime,
        at: SystemTime::now(),
        cursor: fresh_watch_directory_cursor(),
    })
}

/// Synthesize the same `size:N,mtime:nanos` etag that `stat` reports, so an
/// etag carried on a change event matches the one a follow-up `stat` returns.
/// Delegates to the single canonical implementation in the parent module so
/// the two never drift (round-trip asserted by
/// `watch_directory_change_etag_matches_stat`).
fn watch_etag(size: u64, mtime: Option<SystemTime>) -> String {
    crate::file::synthesize_etag(size, mtime)
}

fn fresh_watch_directory_cursor() -> WatchDirectoryCursor {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    WatchDirectoryCursor(nanos.to_string().into_bytes())
}

/// The watched entry's key: its path relative to the watch base, with `/` as
/// the separator.
///
/// **Bytes, because a filename is bytes.** This backend resolves an address
/// through `Url::to_file_path`, which is byte-exact, so it can open a file
/// whose name is not valid UTF-8 and `address::key` addresses one. A key
/// decoded lossily would collide with every other invalid name in the snapshot
/// map — one file's change reported for another, and an emitted address naming
/// a third — while refusing such a key would drop events for files the backend
/// serves perfectly well.
///
/// # Errors
///
/// - [`crate::ErrorCode::Internal`] — `path` is not under `base`.
fn relative_path(base: &Path, path: &Path) -> Result<Vec<u8>> {
    let rel = path.strip_prefix(base).map_err(|_| {
        crate::Error::new(
            crate::ErrorCode::Internal,
            "scanned path was not under the watched base path",
        )
    })?;
    let mut bytes = rel.as_os_str().as_encoded_bytes().to_vec();
    if cfg!(windows) {
        // `\` separates components here, so it becomes the URI separator. On
        // every other host it is an ordinary byte in a name and must survive as
        // one — rewriting it there named a nested path that does not exist.
        for byte in &mut bytes {
            if *byte == b'\\' {
                *byte = b'/';
            }
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file the backend can open must be a file the watcher can report.
    ///
    /// This backend resolves an address through `Url::to_file_path`, which is
    /// byte-exact, so `x\xFF` and `x\xFE` are two files it serves. Deriving the
    /// snapshot key through a `&str` would make them one key — one change lost
    /// to directory order, and an emitted address naming neither — and
    /// refusing such a key would drop their events entirely.
    #[cfg(unix)]
    #[test]
    fn a_name_that_is_not_utf8_keeps_its_own_key_and_address() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let base = Path::new("/srv/data");
        let first = relative_path(&base.join(OsStr::from_bytes(b"x\xFF")), &base.join("_")).ok();
        assert!(first.is_none(), "the base/path order guard must hold");

        let first = relative_path(base, &base.join(OsStr::from_bytes(b"x\xFF"))).unwrap();
        let second = relative_path(base, &base.join(OsStr::from_bytes(b"x\xFE"))).unwrap();
        assert_eq!(first, b"x\xFF");
        assert_ne!(first, second, "two files must not share one snapshot key");

        // And each addresses its own file.
        let root = address::parse("file:///srv/data/").unwrap();
        let first_address = address::join_relative_bytes(&root, &first).unwrap();
        let second_address = address::join_relative_bytes(&root, &second).unwrap();
        assert_eq!(first_address.as_str(), "file:///srv/data/x%FF");
        assert_ne!(first_address, second_address);
        assert_eq!(address::key(&first_address), b"srv/data/x\xFF");
    }

    /// A literal `\` in a name is a byte, not a separator, off Windows.
    #[cfg(unix)]
    #[test]
    fn a_backslash_in_a_name_is_not_a_separator_off_windows() {
        let base = Path::new("/srv/data");
        assert_eq!(
            relative_path(base, &base.join("a\\b")).unwrap(),
            b"a\\b",
            "rewriting it here would name a nested path that does not exist"
        );
    }
}
