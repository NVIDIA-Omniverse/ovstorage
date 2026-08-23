// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! User-metadata sidecar machinery for the built-in `file://` backend.
//!
//! The SPI's `ObjectInfo.user_metadata` has no native home on a POSIX or NTFS
//! filesystem, so the file backend persists it in a sidecar adjacent to each
//! object:
//!
//! - **Unix**: a `.ovstorage-meta/<hex(name)>.meta` file in the object's parent
//!   directory.
//! - **Windows**: an NTFS alternate data stream `name:ovstorage.metadata`.
//!
//! The sidecar payload is a newline-delimited `hex(key)=hex(value)` table, hex
//! so that arbitrary bytes (including `=` and newlines) round-trip losslessly.
//!
//! These helpers are path-based and were relocated verbatim (modulo
//! import/type paths) from the legacy `ovstorage-plugin-file` cdylib so the
//! built-in backend is feature-complete and the cdylib can be retired.

#[cfg(windows)]
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Error, ErrorCode, Result, UserMetadata};
use ovstorage_layer::io_error;
use ovstorage_layer::{ErrorContext, PartialStage, RollbackEffect, StageOutcome};

/// Monotonic disambiguator for temp-sibling names within this process. Paired
/// with the pid and a high-resolution timestamp so two writers to the same
/// directory never collide on a temp name.
pub(crate) static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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

/// Temp-name pattern (`<name>.<stamp>.<pid>.<counter>.tmp`) for staging a
/// sidecar next to its final path.
///
/// **Not** matched by [`is_atomic_write_temp_sibling`], which requires a
/// leading dot this name does not have; that matcher is for the object temp.
/// A sidecar temp is hidden from listings by living inside the metadata
/// directory, which [`is_metadata_dir`] filters.
fn sidecar_temp(final_path: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let name = final_path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_else(|| "sidecar".into());
    final_path.with_file_name(format!("{name}.{stamp}.{pid}.{counter}.tmp"))
}

/// Outcome of staging a user-metadata sidecar alongside an object write: the
/// sidecar is written to a temp file (or marked for removal) before the object
/// bytes commit, then published with [`publish_staged_user_metadata`] after.
pub(crate) enum StagedSidecar {
    Remove,
    Rename {
        tmp: PathBuf,
        final_path: PathBuf,
        guard: TempFileGuard,
    },
}

/// Stage the sidecar for `path` to a temp file without publishing it. Empty
/// metadata stages a removal of any existing sidecar. The temp file is guarded
/// so a failure before [`publish_staged_user_metadata`] cleans it up.
pub(crate) async fn stage_user_metadata(
    path: &Path,
    metadata: &UserMetadata,
) -> Result<StagedSidecar> {
    let final_path = metadata_path(path)?;
    if metadata.is_empty() {
        return Ok(StagedSidecar::Remove);
    }
    if let Some(parent) = final_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(io_error)?;
    }
    let tmp = sidecar_temp(&final_path);
    let lines = encode_metadata(metadata);
    tokio::fs::write(&tmp, lines).await.map_err(io_error)?;
    let guard = TempFileGuard::arm(tmp.clone());
    Ok(StagedSidecar::Rename {
        tmp,
        final_path,
        guard,
    })
}

/// Publish a sidecar staged by [`stage_user_metadata`].
///
/// The bytes are already durable by the time this runs, so a failed publish is
/// a partial completion, not a failed write: it surfaces as
/// `ErrorCode::PartialCompletion` carrying [`ErrorContext::Partial`], which
/// names the object data as committed and the user metadata as the stage that
/// did not apply. The remedy differs by stage and is carried in `next_action`:
/// re-apply the patch after a failed publish, clear the stale keys after a
/// failed removal.
///
/// It must not surface as a retryable code. `ErrorBucket::Transient` would
/// have a retry Layer replay the whole write, which re-commits the bytes and
/// changes the etag — breaking any concurrent `if_match` retry the caller is
/// running. `docs/public/plugin-storage/CONFORMANCE.md` forbids that by name
/// under multi-stage durability, and this backend is the rule's cited example.
pub(crate) async fn publish_staged_user_metadata(path: &Path, staged: StagedSidecar) -> Result<()> {
    match staged {
        StagedSidecar::Remove => {
            let final_path = metadata_path(path)?;
            match metadata_exists(&final_path).await {
                Ok(false) => {}
                Ok(true) => {
                    // Same stage, same classification: overwriting an object
                    // that had a sidecar with no metadata must clear it, and
                    // failing to clear it after the bytes committed leaves the
                    // object carrying the PREVIOUS write's metadata. Mapping
                    // this through `io_error` would surface a retryable code on
                    // some errno values and have a retry Layer replay the
                    // committed write.
                    match tokio::fs::remove_file(final_path).await {
                        Ok(()) => {}
                        // The probe and the unlink are separate syscalls and
                        // the per-target lock only excludes writers in THIS
                        // process, so the sidecar can vanish in between. ENOENT
                        // means someone else already removed it — exactly the
                        // state this stage wanted.
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => return Err(partial_sidecar_error(err, SidecarStage::Remove)),
                    }
                }
                // A probe error (permissions, stale NFS handle, …) means we
                // cannot determine whether a sidecar exists. If one does, it
                // will survive with the previous write's metadata attached to
                // the new object — the same post-commit partial-completion
                // shape as a failed unlink.
                Err(err) => return Err(partial_sidecar_error(err, SidecarStage::Remove)),
            }
            Ok(())
        }
        StagedSidecar::Rename {
            tmp,
            final_path,
            guard,
        } => match tokio::fs::rename(&tmp, &final_path).await {
            Ok(()) => {
                guard.commit();
                Ok(())
            }
            Err(err) => Err(partial_sidecar_error(err, SidecarStage::Publish)),
        },
    }
}

/// The operator instruction for each sidecar stage. Shared so the two
/// constructors cannot drift.
fn stage_next_action(stage: SidecarStage) -> &'static str {
    match stage {
        SidecarStage::Publish => {
            "The object bytes are committed and readable, and the sidecar still \
             holds whatever it held before this write. Re-apply the user \
             metadata with update_metadata. Do not re-issue the write, which \
             would change the etag."
        }
        SidecarStage::Transfer => {
            "The destination object is committed and readable, but its user \
             metadata did not come across from the source — the source still \
             has it. The destination sidecar may have been truncated part-way, \
             so read it with a full-metadata stat before trusting it, then copy \
             the source's keys over with update_metadata. Do not re-issue the \
             copy, which would change the destination's etag."
        }
        SidecarStage::Relocate => {
            "The destination object is committed and readable, but its user \
             metadata could not be moved across from the source. The move is a \
             single rename(2), so the destination sidecar is untouched and may \
             still hold the keys of an object this rename overwrote, while the \
             source's keys survive at the source pathname — where the next \
             object created there would be read with them. Read the \
             destination's user metadata with a full-metadata stat and \
             reconcile it with update_metadata, then clear the residue at the \
             source pathname the way a failed delete cleanup is cleared. Do \
             not re-issue the rename, which would change the destination's \
             etag."
        }
        SidecarStage::SourceResidue => {
            "The destination object is committed and readable and carries the \
             source's user metadata. What failed is the removal of the \
             now-duplicate sidecar at the vacated source pathname, so the next \
             object created at that address would be read with the renamed \
             object's keys. This error ends the operation, so any x-ov-message \
             the call asked for was not recorded — re-apply it with \
             update_metadata if it is wanted. Then clear the source pathname's \
             keys: stat the source address, and if an object is there strip \
             them with update_metadata's removal list, otherwise a delete on \
             that address clears the orphan. Stat and delete are two calls, so \
             do that while nothing else is writing to the source address. Do \
             not re-issue the rename, whose source no longer exists."
        }
        SidecarStage::DeleteClear => {
            "The object is gone, but its user-metadata sidecar could not be \
             cleared, so those keys survive at that pathname and the next \
             object created there is read with them — including the removed \
             object's ovstorage-modified-by attribution. Once whatever blocked \
             the sidecar is cleared, stat that address: if an object is there, \
             strip the survivors with update_metadata's removal list; if \
             nothing is there, a delete on the address clears the orphan, \
             because delete runs its cleanup even with no object to unlink. Do \
             not re-issue the delete without that stat — a replacement object \
             created in the meantime would be removed — and because the stat \
             and the delete are two calls, do this while nothing else is \
             writing to the address. Note also that delete_directory on an \
             absent directory reports NotFound without reaching the cleanup, \
             so the delete is the route for a removed directory too."
        }
        SidecarStage::StaleClear => {
            "The destination object is committed and readable, but the source \
             carried no user metadata and the overwritten object's sidecar \
             could not be cleared, so the destination now presents the PREVIOUS \
             object's keys — including its ovstorage-modified-by attribution. \
             Read the surviving keys with a full-metadata stat, then remove \
             them with update_metadata's removal list. Do not re-issue the copy \
             or rename, which would change the destination's etag without \
             clearing anything."
        }
        SidecarStage::SourceProbe => {
            "The destination object is committed and readable, but whether the \
             source carried user metadata could not be determined, so the \
             destination sidecar was left untouched and may still hold the \
             overwritten object's keys. Read the destination's user metadata \
             with a full-metadata stat and reconcile it with update_metadata — \
             adding the keys the destination should carry, removing any \
             survivors that are not wanted, or both. After a copy the source \
             object is still there to compare against; after a rename it is \
             not, and only its sidecar remains at the vacated source pathname. \
             Do not re-issue the copy or rename, which would change the \
             destination's etag."
        }
        SidecarStage::Annotate => {
            "The destination object is committed and readable and its user \
             metadata came across from the source; only the operation's \
             x-ov-message annotation failed to record. That write rewrites the \
             whole sidecar in place, so the transferred keys may have been \
             truncated with it. Read the destination's user metadata with a \
             full-metadata stat and reconcile it with update_metadata — \
             re-adding the message if it is still wanted. After a copy the \
             source is still there to compare against; after a rename it is \
             not, and the destination's own keys are the only record. Do not \
             re-issue the copy or rename, which would change the destination's \
             etag."
        }
        SidecarStage::Remove => {
            "The object bytes are committed and readable, but the previous \
             write's user metadata is still attached to them — this write \
             carried none and the stale sidecar could not be cleared. Read the \
             surviving keys with a full-metadata stat, then remove them with \
             update_metadata's removal list. Clearing every key unlinks the \
             same sidecar path that just failed and so needs whatever blocked \
             it cleared first; removing only some rewrites the file instead \
             and may succeed either way. Do not re-issue the write, which \
             would change the etag without clearing anything."
        }
    }
}

/// Re-code a metadata-stage failure that ran AFTER the object bytes committed.
///
/// `copy` and `rename` commit the destination with `rename(2)` and only then
/// carry the sidecar across, so a failure there is the same multi-stage
/// durability case as a failed sidecar publish — and it must not surface as a
/// retryable code. `io_error` maps most errnos to `Transient`, which would have
/// a retry Layer replay a copy or rename whose destination is already
/// committed.
///
/// Takes the already-mapped [`Error`] rather than an `io::Error` because these
/// helpers return `Result<()>`; the original message is preserved and only the
/// code and context are replaced.
///
/// `delete` and `delete_directory` use it too, with `SidecarStage::DeleteClear`.
/// No bytes commit there, but the shape is the same one: the stage the caller
/// asked for is durably done and a subordinate metadata stage is not.
/// [`SidecarStage::commit_summary`] is what keeps the message honest about
/// which of the two it is.
pub(crate) fn into_post_commit_partial(err: Error, stage: SidecarStage) -> Error {
    Error::new(
        ErrorCode::PartialCompletion,
        format!(
            "user metadata sidecar {} failed {}: {}",
            stage.as_str(),
            stage.commit_summary(),
            err.message(),
        ),
    )
    .with_context(ErrorContext::Partial {
        completed: PartialStage::ObjectData,
        failed: PartialStage::UserMetadata,
        failed_outcome: stage.failed_outcome(),
        rollback: RollbackEffect::DestroysRequestedWork,
    })
    .with_next_action(stage_next_action(stage))
}

fn partial_sidecar_error(err: std::io::Error, stage: SidecarStage) -> Error {
    // The two stages need different remedies. `Remove` is reached only when
    // the caller supplied NO metadata (`stage_user_metadata` maps an empty map
    // to it), so there is nothing to re-apply — the hazard is the PREVIOUS
    // write's sidecar surviving onto the new object, including its
    // `ovstorage-modified-by`. Telling an operator to re-apply metadata there
    // would have them do nothing while stale attribution persisted.
    let next_action = stage_next_action(stage);
    Error::new(
        ErrorCode::PartialCompletion,
        format!(
            "user metadata sidecar {} failed {}: {err}",
            stage.as_str(),
            stage.commit_summary(),
        ),
    )
    .with_context(ErrorContext::Partial {
        completed: PartialStage::ObjectData,
        failed: PartialStage::UserMetadata,
        failed_outcome: stage.failed_outcome(),
        rollback: RollbackEffect::DestroysRequestedWork,
    })
    .with_next_action(next_action)
}

/// A sidecar helper's failure tagged with the stage that produced it.
///
/// The direction of the remedy is a property of which branch inside the helper
/// failed, not of which helper the caller invoked: one `copy_metadata_file`
/// call can fail mirroring the source's keys onto the destination (remedy: add
/// them) or fail clearing the overwritten object's stale keys (remedy: remove
/// them). Returning a bare `Result<()>` erases that, so the call site cannot
/// pick a stage without guessing. The helpers tag the failure at the branch and
/// [`SidecarFailure::into_partial`] converts it once the caller has confirmed
/// the bytes are already committed.
pub(crate) struct SidecarFailure {
    error: Error,
    stage: SidecarStage,
}

impl SidecarFailure {
    fn new(error: Error, stage: SidecarStage) -> Self {
        Self { error, stage }
    }

    /// Re-code the tagged failure as a post-commit [`ErrorCode::PartialCompletion`].
    pub(crate) fn into_partial(self) -> Error {
        into_post_commit_partial(self.error, self.stage)
    }
}

/// Which direction a stage's remedy points. Getting it backwards tells an
/// operator to write keys that are already there, or to delete keys they asked
/// for; `each_sidecar_stage_asks_for_the_matching_remedy` asserts on this
/// rather than on the wording.
#[cfg(test)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RemedyDirection {
    /// Keys the caller wanted are missing: apply them.
    Add,
    /// Keys the caller did not want survived: remove them.
    Remove,
    /// Which of the two applies cannot be told from the error alone: compare
    /// the two sides and reconcile.
    Reconcile,
}

/// Which sidecar stage failed. Stages carry opposite remedies — one asks the
/// caller to apply metadata, another to remove it — so they are a type rather
/// than a string, and both the remedy and the durable outcome hang off the
/// type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum SidecarStage {
    /// Renaming a freshly staged sidecar into place. The caller supplied
    /// metadata that did not land.
    Publish,
    /// Clearing a stale sidecar because this write carried no metadata. The
    /// caller supplied none, and the PREVIOUS write's keys survived.
    Remove,
    /// Mirroring a source sidecar onto the destination of a `copy` after the
    /// destination bytes committed. The source is known to carry keys; the
    /// object arrived and its metadata did not follow.
    Transfer,
    /// Moving a source sidecar onto the destination of a `rename` after the
    /// destination bytes committed. One `rename(2)`, so on failure neither
    /// side moved: the source keys are stranded at a pathname whose object is
    /// gone, and the destination sidecar is whatever the overwritten object
    /// left.
    ///
    /// Unreachable on Windows, where the sidecar is an NTFS alternate data
    /// stream that rides with the file its own rename moves, so
    /// [`move_metadata_file`] has nothing to do. The variant stays in the enum
    /// on every platform anyway: nothing outside this crate can see it — it is
    /// reported as [`PartialStage::UserMetadata`] like every other stage — so
    /// gating it would buy no compatibility and would put a `cfg` on every
    /// exhaustive match and on the all-stages tests that exist to stop a stage
    /// inheriting another's remedy.
    #[cfg_attr(windows, allow(dead_code))]
    Relocate,
    /// Clearing a deleted object's or directory's sidecar after the object
    /// itself was removed. The keys survive at a pathname that now has no
    /// object, so the next object created there inherits them.
    DeleteClear,
    /// Removing the source sidecar of a `rename` after the keys were already
    /// copied to the destination, on the cross-device path where one
    /// `rename(2)` is not available. The destination holds the bytes and the
    /// keys; what survives is a duplicate at the vacated source pathname. It
    /// ends the operation, so a requested `x-ov-message` never runs.
    ///
    /// Unreachable on Windows for the same reason as [`SidecarStage::Relocate`].
    #[cfg_attr(windows, allow(dead_code))]
    SourceResidue,
    /// Clearing the overwritten object's sidecar on a `copy` or `rename` whose
    /// source carries no metadata. The destination keeps the PREVIOUS object's
    /// keys.
    StaleClear,
    /// Determining whether the source carries a sidecar at all. The destination
    /// sidecar was never touched, so it may still hold the overwritten
    /// object's keys — and whether the source had any is unknown.
    SourceProbe,
    /// Stashing `opts.message` as `x-ov-message` after the sidecar transfer
    /// already succeeded. The transferred keys are the collateral, not the
    /// subject.
    Annotate,
}

impl SidecarStage {
    fn as_str(self) -> &'static str {
        match self {
            SidecarStage::Publish => "publish",
            SidecarStage::Remove => "remove",
            SidecarStage::Transfer => "transfer",
            SidecarStage::Relocate => "relocate",
            SidecarStage::DeleteClear => "delete-clear",
            SidecarStage::SourceResidue => "source-residue",
            SidecarStage::StaleClear => "stale-clear",
            SidecarStage::SourceProbe => "source-probe",
            SidecarStage::Annotate => "annotate",
        }
    }

    /// How the message names the stage that already committed. Every other
    /// stage runs after bytes landed; `DeleteClear` runs after the object was
    /// unlinked, where there are no bytes to speak of.
    fn commit_summary(self) -> &'static str {
        match self {
            SidecarStage::DeleteClear => "with the object already absent",
            SidecarStage::Publish
            | SidecarStage::Remove
            | SidecarStage::Transfer
            | SidecarStage::Relocate
            | SidecarStage::SourceResidue
            | SidecarStage::StaleClear
            | SidecarStage::SourceProbe
            | SidecarStage::Annotate => "after bytes commit",
        }
    }

    /// Whether the failed stage left a durable mark.
    ///
    /// `NotApplied` is claimed only where the failing step is a single atomic
    /// syscall — `rename(2)` into place, `unlink(2)`, or a probe that writes
    /// nothing — so the sidecar is bit-for-bit what it was. The stages that end
    /// in `tokio::fs::write` are `Unknown`: that call truncates before it
    /// writes, so ENOSPC or EIO part-way leaves the sidecar truncated or empty.
    /// Claiming `NotApplied` there would have a caller that trusts the field
    /// skip repair on metadata that was in fact destroyed.
    fn failed_outcome(self) -> StageOutcome {
        match self {
            SidecarStage::Publish
            | SidecarStage::Remove
            | SidecarStage::Relocate
            | SidecarStage::DeleteClear
            | SidecarStage::SourceResidue
            | SidecarStage::StaleClear
            | SidecarStage::SourceProbe => StageOutcome::NotApplied,
            SidecarStage::Transfer | SidecarStage::Annotate => StageOutcome::Unknown,
        }
    }

    /// Which way this stage's remedy points. Exists to be asserted, not called.
    #[cfg(test)]
    fn remedy_direction(self) -> RemedyDirection {
        match self {
            SidecarStage::Publish | SidecarStage::Transfer => RemedyDirection::Add,
            SidecarStage::Remove
            | SidecarStage::StaleClear
            | SidecarStage::DeleteClear
            | SidecarStage::SourceResidue => RemedyDirection::Remove,
            SidecarStage::SourceProbe | SidecarStage::Annotate | SidecarStage::Relocate => {
                RemedyDirection::Reconcile
            }
        }
    }
}

/// Encode a metadata map as the newline-delimited `hex(key)=hex(value)` sidecar
/// payload, sorted by key for deterministic output.
fn encode_metadata(metadata: &UserMetadata) -> String {
    let mut lines = String::new();
    let mut pairs: Vec<_> = metadata.iter().collect();
    pairs.sort_by_key(|(left, _)| *left);
    for (key, value) in pairs {
        lines.push_str(&hex_encode(key.as_bytes()));
        lines.push('=');
        lines.push_str(&hex_encode(value.as_bytes()));
        lines.push('\n');
    }
    lines
}

/// Read the user-metadata sidecar for `path`. A missing sidecar yields empty
/// metadata. A *structurally* malformed sidecar — a line without `=`, or
/// invalid hex — surfaces `CacheCorrupt`; sidecar bytes that aren't valid UTF-8
/// fail earlier in `read_to_string` and propagate as an IO error rather than
/// `CacheCorrupt`.
///
/// Only a genuine `NotFound` collapses to empty: any other read failure
/// (permission, transient IO, non-UTF-8) propagates rather than masquerading as
/// "no metadata". Otherwise a transient read in `update_metadata`'s
/// read→merge→write would read empty and then erase the existing sidecar.
pub(crate) async fn read_user_metadata(path: &Path) -> Result<UserMetadata> {
    let metadata_path = metadata_path(path)?;
    let text = match tokio::fs::read_to_string(metadata_path).await {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(UserMetadata::new()),
        Err(err) => return Err(io_error(err)),
    };
    let mut out = UserMetadata::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::new(
                ErrorCode::CacheCorrupt,
                "file metadata sidecar contains a malformed line",
            ));
        };
        out.insert(hex_decode_string(key)?, hex_decode_string(value)?);
    }
    Ok(out)
}

/// Write `metadata` to the sidecar for `path`. Empty metadata removes any
/// existing sidecar. This is the minimal (non-atomic) write the
/// `update_metadata` path needs; the atomic temp-sibling staging variant is
/// Task A3.
pub(crate) async fn write_user_metadata(path: &Path, metadata: &UserMetadata) -> Result<()> {
    let metadata_path = metadata_path(path)?;
    if metadata.is_empty() {
        match metadata_exists(&metadata_path).await {
            Ok(false) => {}
            Ok(true) => {
                tokio::fs::remove_file(metadata_path)
                    .await
                    .map_err(io_error)?;
            }
            Err(e) => return Err(io_error(e)),
        }
        return Ok(());
    }
    if let Some(parent) = metadata_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(io_error)?;
    }
    let lines = encode_metadata(metadata);
    tokio::fs::write(metadata_path, lines)
        .await
        .map_err(io_error)
}

/// Sidecar path for `path`'s user metadata.
pub(crate) fn metadata_path(path: &Path) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let name = path.file_name().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "metadata is only supported for named filesystem entries",
            )
        })?;
        let parent = path.parent().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "metadata is only supported for entries with a parent directory",
            )
        })?;
        let mut stream_name = OsString::from(name);
        stream_name.push(METADATA_STREAM_SUFFIX);
        Ok(parent.join(stream_name))
    }

    #[cfg(not(windows))]
    {
        let name = path.file_name().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "metadata is only supported for named filesystem entries",
            )
        })?;
        let parent = path.parent().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "metadata is only supported for entries with a parent directory",
            )
        })?;
        // Hex-encode the name's own bytes. A lossy decode first would map every
        // invalid sequence to U+FFFD, so two files the filesystem keeps apart
        // would share one sidecar: user metadata written for one would be
        // returned for the other, across an authorization boundary that treats
        // them as two objects. Names that are valid UTF-8 encode identically
        // either way, so only the aliasing pairs move.
        //
        // `as_encoded_bytes` is documented as unstable across Rust versions,
        // and this value names a file on disk. The exposure is narrow: the
        // encoding is UTF-8 for every name that is valid UTF-8, so a change
        // could only orphan sidecars for Windows names holding unpaired
        // surrogates. That is a smaller surface than the aliasing it replaces,
        // where two nameable files shared one sidecar.
        let encoded = hex_encode(name.as_encoded_bytes());
        Ok(parent
            .join(METADATA_DIR_NAME)
            .join(format!("{encoded}.meta")))
    }
}

/// Mirror the source sidecar onto the destination (used after `copy`). A
/// missing source sidecar clears any stale destination sidecar.
///
/// Runs after the destination bytes commit, so every failure is tagged with the
/// branch that produced it and the call site converts it with
/// [`SidecarFailure::into_partial`].
pub(crate) async fn copy_metadata_file(
    src: &Path,
    dest: &Path,
) -> std::result::Result<(), SidecarFailure> {
    let src_meta =
        metadata_path(src).map_err(|e| SidecarFailure::new(e, SidecarStage::SourceProbe))?;
    match metadata_exists(&src_meta).await {
        Ok(false) => {
            // The source carries nothing, so anything the destination still
            // holds belongs to the object this copy overwrote — the remedy is
            // a removal, not a mirror.
            return remove_metadata_file(dest)
                .await
                .map_err(|e| SidecarFailure::new(e, SidecarStage::StaleClear));
        }
        Ok(true) => {}
        Err(e) => {
            return Err(SidecarFailure::new(io_error(e), SidecarStage::SourceProbe));
        }
    }
    let transfer = |e: Error| SidecarFailure::new(e, SidecarStage::Transfer);
    let dest_meta = metadata_path(dest).map_err(transfer)?;
    if let Some(parent) = dest_meta.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| transfer(io_error(e)))?;
    }
    let bytes = tokio::fs::read(src_meta)
        .await
        .map_err(|e| transfer(io_error(e)))?;
    tokio::fs::write(dest_meta, bytes)
        .await
        .map_err(|e| transfer(io_error(e)))?;
    Ok(())
}

/// Relocate the source sidecar to the destination (used after `rename`). On
/// Windows the ADS rides with the renamed file, so this is a no-op.
///
/// Runs after the destination bytes commit; failures are tagged the same way as
/// [`copy_metadata_file`]'s.
pub(crate) async fn move_metadata_file(
    src: &Path,
    dest: &Path,
) -> std::result::Result<(), SidecarFailure> {
    #[cfg(windows)]
    {
        let _ = (src, dest);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let src_meta =
            metadata_path(src).map_err(|e| SidecarFailure::new(e, SidecarStage::SourceProbe))?;
        match metadata_exists(&src_meta).await {
            Ok(false) => {
                return remove_metadata_file(dest)
                    .await
                    .map_err(|e| SidecarFailure::new(e, SidecarStage::StaleClear));
            }
            Ok(true) => {}
            Err(e) => {
                return Err(SidecarFailure::new(io_error(e), SidecarStage::SourceProbe));
            }
        }
        let relocate = |e: Error| SidecarFailure::new(e, SidecarStage::Relocate);
        let dest_meta = metadata_path(dest).map_err(relocate)?;
        if let Some(parent) = dest_meta.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| relocate(io_error(e)))?;
        }
        // One `rename(2)` where the filesystem allows it. It is a single atomic
        // step, so there is no window in which both pathnames carry the keys:
        // success leaves nothing at the source for a later object created there
        // to inherit, and failure leaves the destination sidecar bit-for-bit as
        // the overwritten object left it. A copy followed by an unlink has
        // neither property.
        //
        // The object rename succeeding constrains only the two object parents.
        // A `.ovstorage-meta` may independently be a symlink, a bind mount or a
        // separate filesystem — and two directories in different btrfs
        // subvolumes report different devices — so `EXDEV` is reachable and
        // gets the copy path. That path unlinks the source explicitly rather
        // than best-effort: an unlink that fails there strands the keys under a
        // pathname a later object would inherit, which is the caller's business.
        match tokio::fs::rename(&src_meta, &dest_meta).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::CrossesDevices => {
                // Stage to a temp sibling and `rename(2)` THAT into place,
                // rather than writing the destination sidecar directly. The
                // publish stays a single atomic step, so every way this arm can
                // fail before the unlink leaves the destination sidecar exactly
                // as it was — which is what lets the whole arm keep `Relocate`
                // and its `NotApplied`. A direct `write` truncates before it
                // writes, and would need a stage that admits the destination
                // may be half-written.
                let tmp = sidecar_temp(&dest_meta);
                let bytes = tokio::fs::read(&src_meta)
                    .await
                    .map_err(|e| relocate(io_error(e)))?;
                tokio::fs::write(&tmp, bytes)
                    .await
                    .map_err(|e| relocate(io_error(e)))?;
                let guard = TempFileGuard::arm(tmp.clone());
                tokio::fs::rename(&tmp, &dest_meta)
                    .await
                    .map_err(|e| relocate(io_error(e)))?;
                guard.commit();
                match tokio::fs::remove_file(&src_meta).await {
                    Ok(()) => Ok(()),
                    // Someone else cleared it — the state this step wanted.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(SidecarFailure::new(
                        io_error(e),
                        SidecarStage::SourceResidue,
                    )),
                }
            }
            Err(err) => Err(relocate(io_error(err))),
        }
    }
}

/// Remove the sidecar for `path` if present (used after `delete`).
pub(crate) async fn remove_metadata_file(path: &Path) -> Result<()> {
    let metadata_path = metadata_path(path)?;
    match metadata_exists(&metadata_path).await {
        Ok(false) => {}
        Ok(true) => {
            match tokio::fs::remove_file(metadata_path).await {
                Ok(()) => {}
                // The probe and the unlink are separate syscalls and the
                // per-target lock only excludes writers in THIS process, so
                // the sidecar can vanish in between. ENOENT means someone else
                // already removed it — exactly the state this stage wanted.
                // `publish_staged_user_metadata`'s removal arm reads the same
                // way.
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(io_error(err)),
            }
        }
        Err(e) => return Err(io_error(e)),
    }
    Ok(())
}

/// Probe whether a sidecar exists at `path`.
///
/// Returns `Ok(true)` if it exists, `Ok(false)` if it does not, and
/// `Err(e)` for any other I/O error (permissions, stale NFS handle, …).
/// Callers that run after bytes have committed must treat `Err` as a partial
/// completion rather than silently skipping the removal.
async fn metadata_exists(path: &Path) -> io::Result<bool> {
    match tokio::fs::metadata(path).await {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        // A name the filesystem cannot hold answers the question as
        // definitively as ENOENT: nothing can be stored there, so nothing is.
        // Sidecar names are the hex-doubled object name, so a legal object
        // name can produce an over-long sidecar name; reporting that as an
        // undeterminable probe would make every delete of such an object fail
        // forever over a sidecar that cannot exist.
        Err(e) if e.kind() == io::ErrorKind::InvalidFilename => Ok(false),
        Err(e) => Err(e),
    }
}

/// Remove whatever occupies the per-directory `.ovstorage-meta` name before
/// removing an otherwise-empty directory (used by `delete_directory`).
///
/// The probe is `symlink_metadata`, so it classifies the entry itself rather
/// than what it resolves to, and the removal is chosen from that
/// classification:
///
/// - a real directory — on Unix the sidecar the backend created, and on either
///   platform one placed there from outside — is removed with its contents;
/// - a directory-typed link, which on Windows means a directory symlink or a
///   junction, is removed with the directory call, which unlinks the link
///   without following it; the file call refuses such an entry;
/// - anything else — a plain file, a file symlink, a symlink to nothing — is
///   unlinked with the file call;
/// - an absent name is nothing to do.
///
/// No arm follows a name-surrogate link, so a removal cannot reach through one
/// into a target tree. A Windows reparse point that is *not* a name surrogate —
/// a cloud or ProjFS placeholder — is a real directory to this classification
/// and is recursed into, which is the arm it wants: the directory call refuses a
/// placeholder that still holds children, and that refusal is what would make
/// the directory undeletable. The C host makes the same call for the same
/// reason. This is the classification both pure-C hosts already make — POSIX with
/// `lstat`, Win32 with `FindFirstFileW` and the name-surrogate reparse tag —
/// including the split between the two removal calls, which exists for the
/// Windows case alone.
///
/// The entry kinds not named above (a FIFO, a socket, a device node) take the
/// file call, which is what unlinks them; the classification is "directory or
/// not", not an enumeration of every type a filesystem can hold.
///
/// A probe that cannot answer (permissions, a stale handle) is an error rather
/// than an assumed absence: reporting the name as clear when it is not would
/// leave the `remove_dir` that follows refusing over an entry nothing cleared,
/// which is the same policy [`metadata_exists`] states for object sidecars.
pub(crate) async fn remove_directory_metadata_dir(path: &Path) -> Result<()> {
    let metadata_dir = path.join(METADATA_DIR_NAME);
    let occupant = match tokio::fs::symlink_metadata(&metadata_dir).await {
        Ok(occupant) => occupant,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_error(e)),
    };
    // `symlink_metadata` reports a symlink's own type, so `is_dir` is false for
    // every link, including a Windows one the kernel treats as a directory —
    // which `is_directory_link` picks up so it reaches the directory call.
    let removed = if occupant.is_dir() {
        tokio::fs::remove_dir_all(&metadata_dir).await
    } else if is_directory_link(&occupant) {
        tokio::fs::remove_dir(&metadata_dir).await
    } else {
        tokio::fs::remove_file(&metadata_dir).await
    };
    match removed {
        Ok(()) => Ok(()),
        // Something else won the race to clear the name; the postcondition the
        // caller needs is that the name is gone, and it is.
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_error(e)),
    }
}

/// True for a link the kernel counts as a directory, which the file removal
/// call refuses and the directory one unlinks without following: a Windows
/// directory symlink or junction. A POSIX symlink carries no such distinction —
/// `unlink` takes every link there — so this is false on those platforms.
#[cfg(windows)]
fn is_directory_link(occupant: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::FileTypeExt;
    occupant.file_type().is_symlink_dir()
}

#[cfg(not(windows))]
fn is_directory_link(_occupant: &std::fs::Metadata) -> bool {
    false
}

/// Name of the per-directory sidecar dir that holds Unix user-metadata files.
pub(crate) const METADATA_DIR_NAME: &str = ".ovstorage-meta";

/// NTFS alternate-data-stream suffix that carries a Windows object's user
/// metadata, appended to the object's file name by [`metadata_path`]. The
/// Windows analogue of [`METADATA_DIR_NAME`] for the internal-path gate.
#[cfg(windows)]
pub(crate) const METADATA_STREAM_SUFFIX: &str = ":ovstorage.metadata";

fn is_metadata_dir(path: &Path) -> bool {
    path.file_name()
        .map(|name| name == METADATA_DIR_NAME)
        .unwrap_or(false)
}

/// True for filesystem entries the backend manages internally and must never
/// surface as user-visible objects in a `list`/`watch` enumeration: the
/// metadata sidecar dir and the atomic-write temp siblings. This inspects only
/// the final path component, which is all a directory scan needs; the
/// addressability gate that walks every component is [`is_internal_path`].
pub(crate) fn is_internal_entry(path: &Path) -> bool {
    is_metadata_dir(path) || is_atomic_write_temp_sibling(path)
}

/// True for the entry name a directory removal clears itself, so an emptiness
/// scan may ignore it: `.ovstorage-meta`, which
/// [`remove_directory_metadata_dir`] deletes immediately before the `remove_dir`
/// call.
///
/// This matches the name, and the cleanup clears the name for every entry kind
/// it can classify as a directory or not: the sidecar directory the backend
/// created, which is the case the scan is written for, and equally an occupant
/// the backend did not create — a plain file, or a link, which is unlinked as
/// the entry it is. So skipping the name here does not leave the `remove_dir`
/// that follows refusing over an entry nothing cleared. What the cleanup cannot
/// clear it reports, rather than passing a surviving entry to `remove_dir`. The
/// address gate
/// [`is_internal_path`] rejects a caller URL naming this component, so an
/// occupant other than the sidecar directory arrives from outside the backend
/// rather than through a `write` or a `create_directory`. That gate compares
/// the component as spelled here, which is the same comparison this predicate
/// makes, so the two agree about what an occupant is.
///
/// Deliberately narrower than [`is_internal_entry`]: an atomic-write temp
/// sibling is hidden from `list`/`watch` because it is not yet an object, but it
/// is a real directory entry that the kernel counts, so `remove_dir` refuses
/// while one is present. A scan that skipped it would call the directory empty,
/// destroy the sidecar dir, and then fail the removal — reporting a condition
/// the caller can do nothing about as though the directory were empty. Between
/// this predicate and the cleanup that clears the one name it skips, the
/// backend's notion of "empty" matches the kernel's for the entries the API can
/// create. The scan, the cleanup's probe and its removal are separate calls, so
/// an entry that appears or changes kind between them is decided by the kernel
/// at `remove_dir`, which is where the honest `DirectoryNotEmpty` comes from.
pub(crate) fn is_cleared_by_directory_removal(path: &Path) -> bool {
    is_metadata_dir(path)
}

/// True if `path` *addresses or traverses* backend-internal storage that a
/// caller-supplied URL must never reach: the `.ovstorage-meta` sidecar
/// namespace (at any depth) on Unix, the `:ovstorage.metadata` NTFS
/// alternate-data-stream suffix on Windows, or an atomic-write temp sibling.
/// Unlike [`is_internal_entry`] — which inspects only the final component for
/// scan filtering — this walks every component so a caller cannot address e.g.
/// `…/.ovstorage-meta/<hex>.meta` (Unix) or `…/foo.txt:ovstorage.metadata`
/// (Windows) directly to forge or corrupt another object's sidecar. The
/// internal writers bypass the address gate (they build sidecar paths via
/// [`metadata_path`] and hit `tokio::fs` directly), so this only constrains
/// caller spelling.
pub(crate) fn is_internal_path(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == METADATA_DIR_NAME)
        || is_atomic_write_temp_sibling(path)
        || addresses_metadata_stream(path)
}

/// Windows: true if any path component carries the [`METADATA_STREAM_SUFFIX`]
/// NTFS stream marker (`<name>:ovstorage.metadata`). The Windows sidecar has no
/// `.ovstorage-meta` component, so [`is_internal_path`] needs this to stay
/// symmetric with the Unix sidecar-dir check. `to_string_lossy` keeps a
/// non-UTF-8 component from slipping the ASCII suffix past the check.
#[cfg(windows)]
fn addresses_metadata_stream(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .contains(METADATA_STREAM_SUFFIX)
    })
}

#[cfg(not(windows))]
fn addresses_metadata_stream(_path: &Path) -> bool {
    false
}

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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode_string(value: &str) -> Result<String> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::new(
            ErrorCode::CacheCorrupt,
            "file metadata sidecar has invalid hex",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let chars: Vec<_> = value.as_bytes().to_vec();
    for pair in chars.chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        bytes.push((high << 4) | low);
    }
    String::from_utf8(bytes).map_err(|_| {
        Error::new(
            ErrorCode::CacheCorrupt,
            "file metadata sidecar is not valid UTF-8",
        )
    })
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::new(
            ErrorCode::CacheCorrupt,
            "file metadata sidecar has invalid hex",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every stage, so a stage added without a remedy of its own cannot inherit
    /// another's by sharing an arm.
    const ALL_STAGES: [SidecarStage; 9] = [
        SidecarStage::Publish,
        SidecarStage::Remove,
        SidecarStage::Transfer,
        SidecarStage::Relocate,
        SidecarStage::DeleteClear,
        SidecarStage::SourceResidue,
        SidecarStage::StaleClear,
        SidecarStage::SourceProbe,
        SidecarStage::Annotate,
    ];

    /// The sibling of the services client's cause-to-remedy assertion, and it
    /// exists because the sidecar stages ask for OPPOSITE things: publish and
    /// transfer want metadata applied, remove and stale-clear want surviving
    /// keys deleted. Swapping two hints tells an operator to delete keys they
    /// asked for, or to re-write keys that are already there.
    ///
    /// Asserted first on the typed remedy, which is the part a rewrite cannot
    /// satisfy by accident. The hint checks below ARE substring checks, kept
    /// because they pin the direction each text must state; they are the weaker
    /// half and would not catch a hint that said the right words about the
    /// wrong stage.
    #[test]
    fn each_sidecar_stage_asks_for_the_matching_remedy() {
        use std::collections::BTreeSet;

        assert_eq!(
            SidecarStage::Publish.remedy_direction(),
            RemedyDirection::Add,
        );
        assert_eq!(
            SidecarStage::Transfer.remedy_direction(),
            RemedyDirection::Add,
        );
        assert_eq!(
            SidecarStage::Remove.remedy_direction(),
            RemedyDirection::Remove,
        );
        assert_eq!(
            SidecarStage::StaleClear.remedy_direction(),
            RemedyDirection::Remove,
        );
        assert_eq!(
            SidecarStage::SourceProbe.remedy_direction(),
            RemedyDirection::Reconcile,
        );
        assert_eq!(
            SidecarStage::Annotate.remedy_direction(),
            RemedyDirection::Reconcile,
        );
        assert_eq!(
            SidecarStage::Relocate.remedy_direction(),
            RemedyDirection::Reconcile,
        );
        assert_eq!(
            SidecarStage::DeleteClear.remedy_direction(),
            RemedyDirection::Remove,
        );
        assert_eq!(
            SidecarStage::SourceResidue.remedy_direction(),
            RemedyDirection::Remove,
        );

        // No two stages may share a hint: a stage whose remedy is another's is
        // the inversion this type exists to prevent.
        let hints: BTreeSet<&str> = ALL_STAGES.into_iter().map(stage_next_action).collect();
        assert_eq!(hints.len(), ALL_STAGES.len(), "two stages share a hint");

        for stage in ALL_STAGES {
            let hint = stage_next_action(stage);
            match stage.remedy_direction() {
                // The caller's keys are missing, so ask for them to be applied
                // and never for a removal.
                RemedyDirection::Add => {
                    assert!(
                        hint.contains("Re-apply the user") || hint.contains("keys over"),
                        "{stage:?} must ask for the metadata to be applied: {hint}",
                    );
                    assert!(
                        !hint.contains("removal list"),
                        "{stage:?} must not ask for a removal: {hint}",
                    );
                }
                // The caller supplied none, so the survivors must go and the
                // hint must not send the operator to re-apply anything.
                RemedyDirection::Remove => {
                    assert!(
                        hint.contains("removal list"),
                        "{stage:?} must ask for a removal: {hint}",
                    );
                    assert!(
                        !hint.contains("Re-apply the user"),
                        "{stage:?} must not ask for the metadata to be applied: {hint}",
                    );
                }
                // Neither direction is known, so the hint must send the
                // operator to compare the two sides before acting.
                RemedyDirection::Reconcile => {
                    assert!(
                        hint.contains("reconcile"),
                        "{stage:?} must ask for a comparison first: {hint}",
                    );
                }
            }
            // None may recommend the destructive action. For the write stages
            // a replay re-commits the bytes and moves the etag under any
            // concurrent `if_match` retry; for `DeleteClear` it would remove
            // whatever object has since been created at the address.
            assert!(
                hint.contains("Do not re-issue"),
                "{stage:?} does not steer away from re-issuing: {hint}",
            );
        }

        let publish = partial_sidecar_error(std::io::Error::other("x"), SidecarStage::Publish);
        let remove = partial_sidecar_error(std::io::Error::other("x"), SidecarStage::Remove);
        // Both stages classify identically, which is why they share a helper.
        for err in [&publish, &remove] {
            assert_eq!(err.code(), ErrorCode::PartialCompletion);
            assert!(!err.code().retryable());
        }
    }

    /// `not_applied` is the field a caller or a Layer trusts to skip repair, so
    /// it may be claimed only where the failing step cannot have half-written
    /// the sidecar. The stages that end in `tokio::fs::write` — which truncates
    /// before it writes — must report `Unknown`; claiming `NotApplied` there
    /// tells a caller nothing was touched on an object whose metadata may have
    /// been destroyed.
    #[test]
    fn only_atomic_stages_claim_the_failed_stage_left_no_mark() {
        for stage in ALL_STAGES {
            let expected = match stage {
                // rename(2) into place / unlink(2) / a probe that writes nothing.
                SidecarStage::Publish
                | SidecarStage::Remove
                | SidecarStage::Relocate
                | SidecarStage::DeleteClear
                | SidecarStage::SourceResidue
                | SidecarStage::StaleClear
                | SidecarStage::SourceProbe => StageOutcome::NotApplied,
                // `tokio::fs::write` on the destination sidecar.
                SidecarStage::Transfer | SidecarStage::Annotate => StageOutcome::Unknown,
            };
            assert_eq!(stage.failed_outcome(), expected, "{stage:?}");

            let err = into_post_commit_partial(Error::new(ErrorCode::Transient, "x"), stage);
            assert_eq!(err.code(), ErrorCode::PartialCompletion);
            let Some(ErrorContext::Partial {
                failed_outcome,
                rollback,
                ..
            }) = err.context()
            else {
                panic!("{stage:?} lost its partial context");
            };
            assert_eq!(*failed_outcome, expected, "{stage:?} context");
            assert_eq!(
                *rollback,
                RollbackEffect::DestroysRequestedWork,
                "{stage:?}"
            );
        }
    }

    /// Clearing a stale sidecar runs at the same commit stage as publishing a
    /// new one, so it is classified the same way: a partial completion, never
    /// retryable. Overwriting an object that had a sidecar with no metadata
    /// must clear it, and failing to clear it after the bytes committed leaves
    /// the object carrying the previous write's metadata. Mapping through
    /// `io_error` would surface a retryable code on some errno values and have
    /// a retry Layer replay the committed write.
    ///
    /// Unix-only: on Windows the sidecar is an NTFS alternate data stream
    /// rather than a file in a directory, so the directory-at-the-sidecar-path
    /// trick below cannot be created at all.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn a_sidecar_removal_failure_is_also_a_partial_completion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let object = dir.path().join("object.usd");
        let sidecar = metadata_path(&object).expect("sidecar path");
        std::fs::create_dir_all(sidecar.parent().expect("sidecar parent"))
            .expect("create sidecar dir");
        // A DIRECTORY at the sidecar path: `metadata_exists` sees something
        // there, and `remove_file` then fails with EISDIR. Deterministic, and
        // unlike a chmod it behaves the same when the suite runs as root.
        std::fs::create_dir(&sidecar).expect("create sidecar as a directory");

        let err = publish_staged_user_metadata(&object, StagedSidecar::Remove)
            .await
            .expect_err("removing a directory with remove_file must fail");

        assert_eq!(err.code(), ErrorCode::PartialCompletion);
        assert!(!err.code().retryable());
        match err.context() {
            Some(ErrorContext::Partial {
                completed, failed, ..
            }) => {
                assert_eq!(*completed, PartialStage::ObjectData);
                assert_eq!(*failed, PartialStage::UserMetadata);
            }
            other => panic!("expected a Partial context, got {other:?}"),
        }
    }

    /// The sidecar publish is the second commit stage: the object bytes are
    /// already renamed into place when it runs. Its failure must therefore be
    /// a partial completion, and must NOT be retryable — a retry Layer
    /// replaying the whole write re-commits the bytes and changes the etag,
    /// which `CONFORMANCE.md` forbids under multi-stage durability, and this
    /// backend is that rule's cited example.
    #[tokio::test]
    async fn a_sidecar_publish_failure_is_a_non_retryable_partial_completion() {
        // A `tmp` that was never created makes the publishing rename fail with
        // ENOENT without racing anything or needing a real staged write.
        let dir = tempfile::tempdir().expect("tempdir");
        let object = dir.path().join("object.usd");
        let tmp = dir.path().join("never-created.tmp");
        let final_path = dir.path().join("object.usd.meta");
        let staged = StagedSidecar::Rename {
            tmp: tmp.clone(),
            final_path,
            guard: TempFileGuard::arm(tmp),
        };

        let err = publish_staged_user_metadata(&object, staged)
            .await
            .expect_err("renaming a missing temp file must fail");

        assert_eq!(err.code(), ErrorCode::PartialCompletion);
        assert!(
            !err.code().retryable(),
            "a retryable code has a retry Layer replay the write, which \
             re-commits the bytes and changes the etag",
        );
        match err.context() {
            Some(ErrorContext::Partial {
                completed,
                failed,
                failed_outcome,
                rollback,
            }) => {
                assert_eq!(*completed, PartialStage::ObjectData);
                assert_eq!(*failed, PartialStage::UserMetadata);
                // The rename never happened, so no part of the sidecar is
                // visible to a reader.
                assert_eq!(*failed_outcome, StageOutcome::NotApplied);
                assert_eq!(*rollback, RollbackEffect::DestroysRequestedWork);
            }
            other => panic!("expected a Partial context, got {other:?}"),
        }
    }

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

    #[test]
    fn internal_path_rejects_sidecar_namespace_at_any_depth() {
        // The sidecar dir itself and anything addressed under it.
        assert!(is_internal_path(Path::new("/root/.ovstorage-meta")));
        assert!(is_internal_path(Path::new(
            "/root/.ovstorage-meta/abc.meta"
        )));
        assert!(is_internal_path(Path::new(
            "/root/sub/.ovstorage-meta/deadbeef.meta"
        )));
        // Atomic-write temp siblings are internal too.
        assert!(is_internal_path(Path::new(
            "/root/.doc.txt.123456789.4242.7.tmp"
        )));

        // Ordinary user paths are addressable.
        assert!(!is_internal_path(Path::new("/root/doc.txt")));
        assert!(!is_internal_path(Path::new("/root/sub/doc.txt")));
        // A substring match must not trip the component check.
        assert!(!is_internal_path(Path::new(
            "/root/.ovstorage-meta-notes.txt"
        )));
    }

    // The Windows sidecar is an NTFS alternate data stream
    // `<name>:ovstorage.metadata`, which carries no `.ovstorage-meta` component.
    // The gate must still reject it so a caller can't address a sidecar stream
    // directly to forge another object's metadata — symmetric with the Unix
    // check in `internal_path_rejects_sidecar_namespace_at_any_depth`.
    #[cfg(windows)]
    #[test]
    fn internal_path_rejects_windows_metadata_stream() {
        assert!(is_internal_path(Path::new(
            r"C:\root\foo.txt:ovstorage.metadata"
        )));
        assert!(is_internal_path(Path::new(
            r"C:\root\sub\bar.bin:ovstorage.metadata"
        )));
        // Ordinary Windows paths (no stream suffix) remain addressable.
        assert!(!is_internal_path(Path::new(r"C:\root\foo.txt")));
        assert!(!is_internal_path(Path::new(r"C:\root\sub\bar.bin")));
    }

    /// Two files the filesystem keeps apart must not share one sidecar.
    ///
    /// The sidecar is user metadata, and the address matcher treats the two
    /// names as two objects — so a shared sidecar returns one object's metadata
    /// for the other across an authorization boundary. Deriving the sidecar
    /// name from a lossy decode is what collapsed them: both invalid sequences
    /// became U+FFFD and hex-encoded identically.
    #[cfg(unix)]
    #[test]
    fn two_names_the_filesystem_distinguishes_get_two_sidecars() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let parent = Path::new("/data");
        let first = metadata_path(&parent.join(OsStr::from_bytes(b"x\xFF"))).unwrap();
        let second = metadata_path(&parent.join(OsStr::from_bytes(b"x\xFE"))).unwrap();
        assert_ne!(
            first, second,
            "two distinct filenames must not share one sidecar"
        );

        // A name that is valid UTF-8 keeps the sidecar it already has, so no
        // existing metadata is orphaned by the derivation.
        assert_eq!(
            metadata_path(&parent.join("report.txt")).unwrap(),
            parent
                .join(METADATA_DIR_NAME)
                .join(format!("{}.meta", hex_encode(b"report.txt")))
        );
    }
}
