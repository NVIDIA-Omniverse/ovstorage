// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Owner-only access to the auth directory and its database.
//!
//! This is the whole of the protection the credential store offers against
//! the threat model it was ruled against: another OS user on the same box,
//! and the bytes not landing in a backup or disk image someone else can read.
//! The secret store did not provide it — on Linux it resolved to kernel
//! keyutils, and the standalone C host had no store at all — and nothing
//! under `auth/` set a mode before the bytes moved into sqlite.
//!
//! Two cases, and the second is the one that bites. Creating a fresh
//! directory owner-only is straightforward. But an operator who already runs
//! with `OVSTORAGE_AUTH_DIR` has a directory and an `auth.sqlite` created at
//! whatever the umask was, commonly `0755` and `0644`, and this release is
//! the one that starts writing credential *bytes* into that file. Opening it
//! without correcting the mode would publish them. So both paths harden, and
//! they harden before the schema is created or a secret is written.

use std::path::Path;

use ovstorage_plugin::Result;
// Only the unix arm raises these directly; the Windows arm has its own
// imports inside `windows_impl`, so an ungated import here is unused there
// and `-D warnings` refuses it.
#[cfg(unix)]
use ovstorage_plugin::{Error, ErrorCode};

/// Create `dir` if absent and make it reachable only by its owner.
///
/// # Errors
///
/// - [`ovstorage_plugin::ErrorCode::StateRootUnavailable`] — the directory
///   cannot be created, or its permissions cannot be read or set.
pub(super) fn create_private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        if !dir.exists() {
            // The parents first, at the umask's mode. `DirBuilder::mode`
            // carries to every component `recursive(true)` creates, so
            // building the whole path in one call would also tighten
            // `/var/lib/ovstorage` or a fresh `~/.local` to 0700 — ordinary
            // data directories this change has no mandate to narrow.
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent).map_err(super::map_io)?;
            }
            // The leaf is created 0700 rather than created-then-chmod'd:
            // between the two there is a window in which it is traversable,
            // and a process that wins it can open a handle that survives the
            // chmod.
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .map_err(super::map_io)?;
            return Ok(());
        }
        // Pre-existing. Before touching its mode, establish that it is ours
        // and is a directory rather than a link to one.
        //
        // This matters because the no-home fallback puts the auth directory
        // under the shared temporary directory at a name derived from the
        // user id — fully predictable, in a world-writable place. Anyone can
        // create it first. Left unchecked, a symlink planted there is
        // followed by both the `set_permissions` below and the database open
        // that follows, so an attacker chooses a directory the victim owns,
        // has it narrowed to `0700`, and has `auth.sqlite` created inside it.
        // `symlink_metadata` does not follow, so the link is seen as a link.
        //
        // The home-directory paths cannot be attacked this way — their parent
        // is already the user's own — but the check is cheap and refusing a
        // directory owned by someone else is right on every path.
        let metadata = std::fs::symlink_metadata(dir).map_err(super::map_io)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::new(
                ErrorCode::StateRootUnavailable,
                format!(
                    "the auth directory {} is a symbolic link; refusing to follow it, \
                     because doing so would apply owner-only permissions to, and write \
                     credentials into, whatever it points at",
                    dir.display()
                ),
            ));
        }
        if metadata.uid() != unsafe { libc::getuid() } {
            return Err(Error::new(
                ErrorCode::StateRootUnavailable,
                format!(
                    "the auth directory {} is owned by uid {} rather than this user; \
                     refusing to store credentials in a directory another account controls",
                    dir.display(),
                    metadata.uid()
                ),
            ));
        }
        let current = std::fs::metadata(dir).map_err(super::map_io)?.permissions();
        if current.mode() & 0o777 != 0o700 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(super::map_io)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        if !dir.exists() {
            std::fs::create_dir_all(dir).map_err(super::map_io)?;
        }
        windows_impl::restrict_to_owner(dir)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir_all(dir).map_err(super::map_io)?;
        Ok(())
    }
}

/// Make `path` readable and writable only by its owner.
///
/// Called before the database is populated, and on every open rather than
/// only on the one that creates it, so a file left permissive by an earlier
/// release is corrected rather than inherited.
///
/// # Errors
///
/// - [`ovstorage_plugin::ErrorCode::StateRootUnavailable`] — the file's
///   permissions cannot be read or set.
pub(super) fn restrict_file_to_owner(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let current = std::fs::metadata(path)
            .map_err(super::map_io)?
            .permissions();
        if current.mode() & 0o777 != 0o600 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(super::map_io)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        windows_impl::restrict_to_owner(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;

    use ovstorage_plugin::{Error, ErrorCode, Result};
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
        SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    /// Windows has no umask, so an owner-only ACL is real code rather than a
    /// mode argument.
    ///
    /// The trustee is read back off the object itself rather than from the
    /// process token. The object was just created by this process, so its
    /// owner already *is* the account to grant — and reading it needs only the
    /// `Win32_Security*` surface this crate already enables for
    /// `file::owner`, where the same call shape is in use.
    ///
    /// The DACL is applied as protected. Without that the object keeps
    /// inheriting its parent's entries, so an inherited "Users" grant would
    /// survive the single entry added here and the result would read as
    /// owner-only while granting more.
    pub(super) fn restrict_to_owner(path: &Path) -> Result<()> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);

        let mut owner: PSID = std::ptr::null_mut();
        let mut descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated; `owner` points into `descriptor`,
        // which the call allocates on success and which is freed below.
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor as *mut _ as *mut _,
            )
        };
        if status != ERROR_SUCCESS || owner.is_null() {
            return Err(Error::new(
                ErrorCode::StateRootUnavailable,
                format!("failed to read the owner of {}", path.display()),
            ));
        }

        let result = apply_owner_only(&wide, owner, path);
        // SAFETY: `descriptor` was LocalAlloc'd by the call above, and
        // `owner` points inside it, so neither is used after this.
        unsafe { LocalFree(descriptor as HLOCAL) };
        result
    }

    fn apply_owner_only(wide: &[u16], owner: PSID, path: &Path) -> Result<()> {
        let mut access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: SET_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: owner as *mut u16,
            },
        };

        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: one initialised entry in, a LocalAlloc'd ACL out, freed on
        // every path below.
        let status = unsafe { SetEntriesInAclW(1, &mut access, std::ptr::null_mut(), &mut acl) };
        if status != ERROR_SUCCESS {
            return Err(Error::new(
                ErrorCode::StateRootUnavailable,
                format!("failed to build an owner-only ACL for {}", path.display()),
            ));
        }

        // SAFETY: `wide` is NUL-terminated and `acl` is the ACL just built.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        // SAFETY: `acl` came from `SetEntriesInAclW`, which LocalAlloc's it.
        unsafe { LocalFree(acl as HLOCAL) };

        if status != ERROR_SUCCESS {
            return Err(Error::new(
                ErrorCode::StateRootUnavailable,
                format!("failed to apply an owner-only ACL to {}", path.display()),
            ));
        }
        Ok(())
    }
}
