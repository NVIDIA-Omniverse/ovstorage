// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Atomic-write staging for the built-in `file://` backend: the hidden temp
//! sibling an object is written through before a single `rename(2)` publishes
//! it, the matcher that hides such siblings from enumeration, and the advisory
//! lock a writer holds on its temp so a directory removal can tell a write in
//! flight from a temp left by a writer that died.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::errors::map_io;
use crate::{Error, ErrorCode, Result};
use ovstorage_layer::io_error;

/// Monotonic disambiguator for temp-sibling names within this process. Paired
/// with the pid and a high-resolution timestamp so two writers to the same
/// directory never collide on a temp name.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Best-effort drop guard that unlinks a temp sibling when a write fails
/// before it is renamed into place; uses sync `std::fs::remove_file` because
/// `Drop` is sync. Call [`TempFileGuard::commit`] once the rename succeeds to
/// disarm it.
pub(crate) struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    pub(crate) fn arm(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    pub(crate) fn commit(mut self) {
        self.path.take();
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Create a fresh O_CREAT|O_EXCL temp sibling next to `path`, retrying on the
/// (vanishingly rare) name collision so two concurrent writers to the same
/// directory each get a private staging file. Returns the path *and* the open
/// handle so the caller writes through the same fd it exclusively created (see
/// [`super::write_body`]).
///
/// The handle holds the exclusive advisory lock ([`StagingLock`])
/// that tells a `delete_directory` probing the name that its writer is live. A
/// removal that takes the lock first is clearing the name as an orphan, so a
/// busy lock, or a name gone by the time the lock is held, means this attempt
/// lost the name and the loop takes a fresh one. If that removal also took the
/// directory, the fresh attempt fails `NotFound`, which is the outcome a
/// write racing a directory removal reaches anyway.
pub(crate) async fn create_new_temp_sibling(path: &Path) -> Result<(PathBuf, tokio::fs::File)> {
    let mut last_err: Option<io::Error> = None;
    for _ in 0..16 {
        let candidate = temp_sibling(path);
        let file = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .await
        {
            Ok(file) => file.into_std().await,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                last_err = Some(err);
                continue;
            }
            Err(err) => return Err(map_io(err)),
        };
        // Armed from here so an error below leaves no hidden temp behind; the
        // retry arms drop it too, which is harmless where a removal already
        // cleared the name.
        let created = TempFileGuard::arm(candidate.clone());
        match lock_staging_temp(&file).map_err(map_io)? {
            StagingLock::Held => match tokio::fs::symlink_metadata(&candidate).await {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    last_err = Some(err);
                    continue;
                }
                Err(err) => return Err(map_io(err)),
            },
            StagingLock::Busy => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "temp sibling is being cleared by a directory removal",
                ));
                continue;
            }
            StagingLock::Unsupported => {}
        }
        created.commit();
        return Ok((candidate, tokio::fs::File::from_std(file)));
    }
    Err(map_io(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temp sibling",
        )
    })))
}

/// Hidden temp-name pattern (`.<name>.<stamp>.<pid>.<counter>.tmp`) for the
/// object's atomic-write staging file. Recognized and filtered by
/// [`is_atomic_write_temp_sibling`].
pub(crate) fn temp_sibling(path: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_else(|| "object".into());
    path.with_file_name(format!(".{name}.{stamp}.{pid}.{counter}.tmp"))
}

/// True for an in-flight atomic-write staging file, which `list` and
/// `watch_directory` hide and which a caller-supplied URL must not address.
/// The check inspects only the final path component. That covers the staging
/// file the backend itself creates, which is always a leaf, and it is what a
/// directory scan sees; it does not reject a temp-shaped name in an interior
/// position of a caller's address, so the address gate that calls this is
/// final-component-only on this host.
pub(crate) fn is_atomic_write_temp_sibling(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(inner) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    // The staging name is `.{object}.{stamp}.{pid}.{counter}.tmp`, so the three
    // trailing dot-groups are always all-digits. Requiring all three (not just
    // one) keeps a legitimate user file like `.report.1.tmp` — a single
    // trailing digit group — from being mistaken for a temp sibling and hidden
    // from `list`/`watch`.
    let trailing_digit_groups = inner
        .rsplit('.')
        .take_while(|seg| !seg.is_empty() && seg.bytes().all(|byte| byte.is_ascii_digit()))
        .count();
    trailing_digit_groups >= 3
}

/// True for a name this backend's own staging generator can emit, and so the
/// one shape a directory removal may unlink: a leading `.`, an exact-case
/// `.tmp` suffix, exactly three trailing all-digit dot-groups, and a non-empty
/// segment before them. Tighter than [`is_atomic_write_temp_sibling`], which
/// only hides and so may err towards matching; this predicate destroys, so it
/// accepts nothing the generator cannot write. It is the rule the C host's
/// removal applies, so the two hosts agree on every name over one on-disk
/// format: a name either host serves as an object survives the other's
/// removal.
pub(crate) fn is_clearable_staging_temp(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(inner) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let mut groups = inner.rsplitn(4, '.');
    for _ in 0..3 {
        match groups.next() {
            Some(seg) if !seg.is_empty() && seg.bytes().all(|byte| byte.is_ascii_digit()) => {}
            _ => return false,
        }
    }
    groups.next().is_some_and(|leading| !leading.is_empty())
}

/// What taking the exclusive advisory lock on a staging temp found.
///
/// A writer holds this lock on its staging temp from the moment the name
/// exists until the rename that publishes it returns, so the lock is the
/// liveness signal a directory removal reads: held by another handle means a
/// writer is in flight, free means the writer is gone, whatever pid a later
/// process wears. The kernel releases it when the owning process dies, so a
/// writer killed without unwinding leaves the temp free.
pub(crate) enum StagingLock {
    /// This handle holds the lock.
    Held,
    /// Another handle holds it: a live writer, or a removal probing the name.
    Busy,
    /// The filesystem offers no advisory locks, so no handle can hold one.
    Unsupported,
}

/// Try the exclusive staging lock on `file` without blocking.
///
/// Unix takes `flock`, which is advisory and never affects a reader. Windows
/// locks are mandatory, so there the lock covers one byte far past any
/// possible end of file, a range no read or write of the object's bytes can
/// overlap, rather than the whole file std's `try_lock` would take; a reader
/// that finds the published object before the writer's handle closes reads
/// it normally. Writer and probe lock the same range on both platforms.
pub(crate) fn lock_staging_temp(file: &std::fs::File) -> io::Result<StagingLock> {
    match try_lock_staging_range(file) {
        Ok(()) => Ok(StagingLock::Held),
        Err(std::fs::TryLockError::WouldBlock) => Ok(StagingLock::Busy),
        Err(std::fs::TryLockError::Error(e)) if lock_unsupported(&e) => {
            Ok(StagingLock::Unsupported)
        }
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

#[cfg(not(windows))]
fn try_lock_staging_range(file: &std::fs::File) -> std::result::Result<(), std::fs::TryLockError> {
    file.try_lock()
}

#[cfg(windows)]
fn try_lock_staging_range(file: &std::fs::File) -> std::result::Result<(), std::fs::TryLockError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_LOCK_VIOLATION, GetLastError};
    use windows_sys::Win32::Storage::FileSystem::{
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    // Byte 0xFFFF_FFFF_FFFF_FFFE: beyond any file the backend can write, so
    // the mandatory lock never overlaps content a reader touches.
    const STAGING_LOCK_OFFSET_LOW: u32 = 0xFFFF_FFFE;
    const STAGING_LOCK_OFFSET_HIGH: u32 = 0xFFFF_FFFF;

    // SAFETY: an all-zero OVERLAPPED is a valid value.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.Anonymous.Anonymous.Offset = STAGING_LOCK_OFFSET_LOW;
    overlapped.Anonymous.Anonymous.OffsetHigh = STAGING_LOCK_OFFSET_HIGH;
    // SAFETY: the handle is open for the duration of the call, and with
    // LOCKFILE_FAIL_IMMEDIATELY the request never queues, so the stack
    // OVERLAPPED is not referenced after the call returns.
    let locked = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if locked != 0 {
        return Ok(());
    }
    // SAFETY: GetLastError has no preconditions.
    let code = unsafe { GetLastError() };
    if code == ERROR_LOCK_VIOLATION || code == ERROR_IO_PENDING {
        return Err(std::fs::TryLockError::WouldBlock);
    }
    Err(std::fs::TryLockError::Error(io::Error::from_raw_os_error(
        code as i32,
    )))
}

/// True when the error says the lock cannot answer on this filesystem rather
/// than that this attempt failed: no advisory locks at all, as some FUSE and
/// network mounts report, or `EBADF` from an NFS `flock` emulation that wants
/// a descriptor open for writing. The writer's handle is always open for
/// writing, so for it this means staging unlocked; for a probe it means the
/// entry cannot be classified and the removal refuses.
fn lock_unsupported(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::Unsupported {
        return true;
    }
    #[cfg(unix)]
    {
        matches!(
            err.raw_os_error(),
            Some(libc::ENOLCK | libc::EOPNOTSUPP | libc::ENOSYS | libc::EBADF)
        )
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// What probing one staging temp found.
enum StagingProbe {
    /// The name is gone: its writer published or unlinked it since the scan.
    Gone,
    /// Another handle holds the lock: a write in flight.
    Live,
    /// This handle holds the lock; the writer is gone. Carries the handle so
    /// the caller unlinks while nothing else can take the name.
    Orphan(std::fs::File),
    /// The entry cannot be shown to be an orphan: not a regular file, not
    /// openable, or on a filesystem without advisory locks.
    Unclassifiable(&'static str),
}

/// Open, inspect and lock one staging temp, holding a single descriptor.
///
/// The entry is classified without following a link before it is opened, so
/// a symlink, a directory or a fifo wearing the name is never followed,
/// descended into or waited on; the open itself also refuses to follow, and
/// the handle's own type is checked once more, so an entry swapped between
/// the two calls is refused rather than probed.
async fn probe_staging_temp(temp: &Path) -> Result<StagingProbe> {
    match tokio::fs::symlink_metadata(temp).await {
        Ok(kind) if kind.file_type().is_file() => {}
        Ok(_) => return Ok(StagingProbe::Unclassifiable(NOT_A_REGULAR_FILE)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(StagingProbe::Gone),
        Err(e) => return Err(staging_probe_error(e)),
    }
    let file = match open_staging_probe(temp).await {
        Ok(file) => file.into_std().await,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(StagingProbe::Gone),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return Ok(StagingProbe::Unclassifiable(
                "an entry wearing a staging temp name that cannot be opened",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::IsADirectory || open_refused_a_link(&e) => {
            return Ok(StagingProbe::Unclassifiable(NOT_A_REGULAR_FILE));
        }
        Err(e) => return Err(staging_probe_error(e)),
    };
    if !file
        .metadata()
        .map_err(staging_probe_error)?
        .file_type()
        .is_file()
    {
        return Ok(StagingProbe::Unclassifiable(NOT_A_REGULAR_FILE));
    }
    match lock_staging_temp(&file).map_err(staging_probe_error)? {
        StagingLock::Held => Ok(StagingProbe::Orphan(file)),
        StagingLock::Busy => Ok(StagingProbe::Live),
        StagingLock::Unsupported => Ok(StagingProbe::Unclassifiable(
            "a staging temp this filesystem cannot classify as orphaned",
        )),
    }
}

const NOT_A_REGULAR_FILE: &str = "an entry wearing a staging temp name that is not a regular file";

/// Open the probe handle without following a final link. Unix adds
/// `O_NONBLOCK` so a fifo cannot hold the open, and asks for read-write first:
/// NFS emulates `flock` with record locks and refuses an exclusive lock on a
/// descriptor not open for writing. A mode that denies one side falls back to
/// the other, so a copy staged from a read-only or a write-only source is
/// still probed; the lock works on any of the three handles.
async fn open_staging_probe(temp: &Path) -> io::Result<tokio::fs::File> {
    #[cfg(unix)]
    {
        let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK;
        let mut opened = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(flags)
            .open(temp)
            .await;
        for (read, write) in [(true, false), (false, true)] {
            match &opened {
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    opened = tokio::fs::OpenOptions::new()
                        .read(read)
                        .write(write)
                        .custom_flags(flags)
                        .open(temp)
                        .await;
                }
                _ => break,
            }
        }
        opened
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        tokio::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(temp)
            .await
    }
    #[cfg(not(any(unix, windows)))]
    {
        tokio::fs::File::open(temp).await
    }
}

/// Unix reports a no-follow open of a link as `ELOOP`.
fn open_refused_a_link(err: &io::Error) -> bool {
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(libc::ELOOP)
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        false
    }
}

/// Descriptor exhaustion is deterministic for the caller, so it is reported as
/// `ResourceExhausted` rather than the retryable code the generic mapping gives
/// an unknown errno.
fn staging_probe_error(e: io::Error) -> Error {
    #[cfg(unix)]
    if matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) {
        return Error::new(
            ErrorCode::ResourceExhausted,
            "too many open files while probing staging temps",
        );
    }
    io_error(e)
}

fn in_flight_write_refusal() -> Error {
    Error::new(
        ErrorCode::DirectoryNotEmpty,
        "directory holds an in-flight write",
    )
    .with_next_action("wait for the write to finish, then retry the removal")
}

/// A temp the scan saw is gone: its writer published it as the child object
/// or unlinked it. Either way the directory is not the one the scan judged.
fn directory_changed_refusal() -> Error {
    Error::new(
        ErrorCode::DirectoryNotEmpty,
        "directory changed while it was being removed",
    )
    .with_next_action("retry the removal")
}

fn unclassifiable_refusal(what: &str) -> Error {
    Error::new(
        ErrorCode::DirectoryNotEmpty,
        format!("directory holds {what}"),
    )
    .with_next_action(
        "inspect the entry on the host filesystem and remove it once its writer is known to be gone",
    )
}

/// Clear the atomic-write staging temps a directory removal's scan set aside,
/// once each has been shown to belong to no live writer.
///
/// Two passes, one descriptor at a time, so the number of temps a removal can
/// clear is not bounded by the descriptor limit. The first pass probes every
/// temp's [`StagingLock`] and releases it; a write in flight, or an entry the
/// probe cannot classify, refuses the removal before anything is touched. The
/// second pass takes each lock again and unlinks under it. A name is never
/// created twice, so a temp free in the first pass has no writer to become
/// live in the second; a lock found busy there is another removal's probe and
/// is refused the same way.
///
/// A temp the scan saw but the probe no longer finds is refused too, with a
/// retry hint: the way a temp vanishes is its writer's rename publishing it
/// as a child object, so the directory is not the one the scan judged and
/// the scan's verdict does not carry.
///
/// Removal is by path, never through the probe handle. A writer that renames
/// its temp into place between this probe's `open` and its lock leaves the
/// probe holding the published object's inode; the by-path `remove_file` then
/// finds no such name and skips it, where a handle-based delete would destroy
/// the object just published.
///
/// An entry the probe cannot show to be an orphan — of the wrong kind, not
/// openable, or on a filesystem without advisory locks — refuses the removal
/// as the `DirectoryNotEmpty` the kernel would report at `remove_dir`, rather
/// than risk a write in flight or surface a raw errno as retryable.
pub(crate) async fn clear_orphaned_staging_temps(temps: &[PathBuf]) -> Result<()> {
    for temp in temps {
        match probe_staging_temp(temp).await? {
            StagingProbe::Orphan(_) => {}
            StagingProbe::Gone => return Err(directory_changed_refusal()),
            StagingProbe::Live => return Err(in_flight_write_refusal()),
            StagingProbe::Unclassifiable(what) => return Err(unclassifiable_refusal(what)),
        }
    }
    for temp in temps {
        let file = match probe_staging_temp(temp).await? {
            StagingProbe::Orphan(file) => file,
            StagingProbe::Gone => return Err(directory_changed_refusal()),
            StagingProbe::Live => return Err(in_flight_write_refusal()),
            StagingProbe::Unclassifiable(what) => return Err(unclassifiable_refusal(what)),
        };
        clear_readonly_before_unlink(temp, &file).await?;
        match tokio::fs::remove_file(temp).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(directory_changed_refusal());
            }
            Err(e) => return Err(staging_probe_error(e)),
        }
        // Windows completes the unlink at close, which must precede the
        // caller's `remove_dir`.
        drop(file);
    }
    Ok(())
}

/// A copy staged from a read-only source carries `FILE_ATTRIBUTE_READONLY`,
/// which Windows refuses to delete; clear it by path, as the unlink is, so a
/// published object under a renamed name is never touched.
#[cfg(windows)]
async fn clear_readonly_before_unlink(temp: &Path, file: &std::fs::File) -> Result<()> {
    let mut permissions = file.metadata().map_err(staging_probe_error)?.permissions();
    if !permissions.readonly() {
        return Ok(());
    }
    permissions.set_readonly(false);
    match tokio::fs::set_permissions(temp, permissions).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(directory_changed_refusal()),
        Err(e) => Err(staging_probe_error(e)),
    }
}

/// Unix `unlink` needs only directory permissions, so nothing to clear.
#[cfg(not(windows))]
async fn clear_readonly_before_unlink(_temp: &Path, _file: &std::fs::File) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_sibling_matcher_requires_the_full_three_group_shape() {
        // The real atomic-write staging shape: `.{object}.{stamp}.{pid}.{counter}.tmp`.
        assert!(is_atomic_write_temp_sibling(Path::new(
            "/d/.doc.txt.123456789.4242.7.tmp"
        )));
        // An all-numeric object name still has its own three numeric tail groups.
        assert!(is_atomic_write_temp_sibling(Path::new(
            "/d/.12345.123456789.4242.7.tmp"
        )));

        // A legitimate user file with a single trailing digit group must NOT be
        // swallowed (a too-loose `>= 1` matcher would hide it from list/watch).
        assert!(!is_atomic_write_temp_sibling(Path::new("/d/.report.1.tmp")));
        // Two trailing groups is still short of the real shape.
        assert!(!is_atomic_write_temp_sibling(Path::new(
            "/d/.report.1.2.tmp"
        )));
        // Not hidden, no leading dot / not a .tmp.
        assert!(!is_atomic_write_temp_sibling(Path::new(
            "/d/report.1.2.3.tmp"
        )));
        assert!(!is_atomic_write_temp_sibling(Path::new("/d/.report.txt")));
    }

    #[tokio::test]
    async fn a_temp_sibling_is_born_hidden_and_matched_by_its_own_filter() {
        let dir = tempfile::tempdir().unwrap();
        let object = dir.path().join("object.bin");
        let (tmp, _file) = create_new_temp_sibling(&object).await.unwrap();
        assert!(tmp.exists());
        assert!(is_atomic_write_temp_sibling(&tmp));
        assert!(!is_atomic_write_temp_sibling(&object));
    }

    /// A lock that cannot answer is never a raw error: an NFS `flock`
    /// emulation refusing a read-only descriptor with `EBADF`, or a mount with
    /// no advisory locks, reads as unsupported, and contention reads as busy.
    /// On this host a read-only handle locks fine, so the errno mapping is what
    /// the test can pin.
    #[cfg(unix)]
    #[test]
    fn lock_errors_that_cannot_answer_are_never_raw() {
        for errno in [libc::ENOLCK, libc::EOPNOTSUPP, libc::ENOSYS, libc::EBADF] {
            assert!(
                lock_unsupported(&io::Error::from_raw_os_error(errno)),
                "errno {errno} must read as unsupported"
            );
        }
        assert!(!lock_unsupported(&io::Error::from_raw_os_error(
            libc::EACCES
        )));
        assert!(lock_unsupported(&io::Error::from(
            io::ErrorKind::Unsupported
        )));

        let tmp = tempfile::tempdir().unwrap();
        let temp = tmp.path().join(".probe.1.2.3.tmp");
        std::fs::write(&temp, b"x").unwrap();
        let read_only = std::fs::File::open(&temp).unwrap();
        assert!(matches!(
            lock_staging_temp(&read_only).unwrap(),
            StagingLock::Held | StagingLock::Unsupported
        ));
    }

    /// The predicate that may unlink agrees with the C host's removal on every
    /// row, so a name either host serves as an object survives the other's
    /// removal; the hiding matcher is looser and that is fine, since hiding
    /// destroys nothing.
    #[test]
    fn clearable_staging_temp_agrees_with_the_c_host_row_for_row() {
        let rows: &[(&str, bool)] = &[
            // No leading segment: an object on the C host.
            (".2024.01.15.tmp", false),
            (".1.2.3.tmp", false),
            ("..1.2.3.tmp", false),
            // Uppercase suffix: neither generator writes it.
            (".report.1.2.3.TMP", false),
            (".report.1.2.3.Tmp", false),
            (".ovstorage-stage.1.2.3.TMP", false),
            // Both generators' shapes.
            (".report.1.2.3.tmp", true),
            (".ovstorage-stage.1.2.3.tmp", true),
            (".a.b.1.2.3.tmp", true),
            (".1.2.3.4.tmp", true),
            (".12345.123456789.4242.7.tmp", true),
            // Too few digit groups or an empty one.
            (".report.1.2.tmp", false),
            (".report..2.3.tmp", false),
            (".report.1.2.3.txt", false),
            ("report.1.2.3.tmp", false),
        ];
        for (name, clearable) in rows {
            let path = Path::new("/root").join(name);
            assert_eq!(
                is_clearable_staging_temp(&path),
                *clearable,
                "clearable verdict for {name}"
            );
            if *clearable {
                assert!(
                    is_atomic_write_temp_sibling(&path),
                    "every clearable name is also hidden: {name}"
                );
            }
        }
        // The hiding matcher keeps its looser reach; only the removal tightens.
        assert!(is_atomic_write_temp_sibling(Path::new(
            "/root/.2024.01.15.tmp"
        )));
    }
}
