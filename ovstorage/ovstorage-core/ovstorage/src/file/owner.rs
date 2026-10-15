// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Best-effort owner resolution and special-file rejection for the built-in
//! [`FileBackend`](super::FileBackend).
//!
//! Ported from the legacy `ovstorage-plugin-file` cdylib so the built-in
//! native backend can surface a `modified_by` attribution and refuse to read
//! special filesystem objects (fifos, sockets, devices) without the cdylib.

use std::path::Path;

use crate::Result;

/// Reject special filesystem objects (named pipes, sockets, block/char
/// devices) before the backend would otherwise `open()`/`read()` them.
/// Reading a fifo or device node blocks (or worse), so this is a guard, not a
/// correctness check. Inspects the already-fetched `Metadata` (the caller's
/// single `stat`) rather than re-statting, and never opens the object itself.
#[cfg(unix)]
pub(crate) fn reject_special_file(metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;

    use crate::{Error, ErrorCode};

    let kind = metadata.file_type();
    if kind.is_fifo() || kind.is_socket() || kind.is_block_device() || kind.is_char_device() {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "cannot read special filesystem objects",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn reject_special_file(_metadata: &std::fs::Metadata) -> Result<()> {
    Ok(())
}

/// Owner-as-best-effort modifier. POSIX `st_uid` and Windows DACL
/// owner are *owner*, not strictly *modifier* — neither kernel
/// records the principal of the last `write()`. On most single-user
/// systems they coincide. The broker overrides this in brokered mode
/// via the attribution layer; in direct-library mode this is what
/// surfaces.
#[cfg(unix)]
pub(crate) fn modified_by_for_path(_path: &Path, meta: &std::fs::Metadata) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    Some(resolve_uid(meta.uid()))
}

#[cfg(windows)]
pub(crate) fn modified_by_for_path(path: &Path, _meta: &std::fs::Metadata) -> Option<String> {
    windows_owner::resolve(path)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn modified_by_for_path(_path: &Path, _meta: &std::fs::Metadata) -> Option<String> {
    None
}

/// Resolve a POSIX uid to a username via `getpwuid_r`, falling back to
/// `uid:N` if the entry is missing (containers without `/etc/passwd`,
/// NSS misconfiguration, etc.) so the field is never empty. Cached
/// per-process: uids are stable for a process lifetime.
#[cfg(unix)]
pub(crate) fn resolve_uid(uid: u32) -> String {
    use std::collections::HashMap;
    let cache = UID_CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    if let Some(name) = cache.lock().expect("uid cache poisoned").get(&uid) {
        return name.clone();
    }
    let resolved = lookup_uid(uid).unwrap_or_else(|| format!("uid:{uid}"));
    cache
        .lock()
        .expect("uid cache poisoned")
        .insert(uid, resolved.clone());
    resolved
}

#[cfg(unix)]
static UID_CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u32, String>>> =
    std::sync::OnceLock::new();

#[cfg(unix)]
fn lookup_uid(uid: u32) -> Option<String> {
    let mut buf = vec![0u8; 1024];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    loop {
        let rc = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        let cstr = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
        return cstr.to_str().ok().map(String::from);
    }
}

/// Resolve the file's NTFS owner SID to `DOMAIN\username` (or to the
/// stringified SID when name lookup fails — common on orphaned ACLs
/// from removed AD accounts). Mirrors the Unix `resolve_uid` fallback
/// pattern: never returns an empty string when an owner SID exists.
#[cfg(windows)]
mod windows_owner {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::Path;

    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{LookupAccountSidW, OWNER_SECURITY_INFORMATION, PSID};

    pub(super) fn resolve(path: &Path) -> Option<String> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);

        let mut sid: PSID = std::ptr::null_mut();
        let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();

        let rc = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut sid,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd as *mut _ as *mut _,
            )
        };

        if rc != ERROR_SUCCESS || sid.is_null() {
            // `sd` is only populated on success; nothing to free.
            return None;
        }

        let resolved = lookup_name(sid).or_else(|| sid_to_string(sid));

        // SAFETY: GetNamedSecurityInfoW allocates `sd` with LocalAlloc on success.
        unsafe {
            LocalFree(sd as HLOCAL);
        }

        resolved
    }

    fn lookup_name(sid: PSID) -> Option<String> {
        let mut name_len: u32 = 0;
        let mut domain_len: u32 = 0;
        let mut sid_use: i32 = 0;
        // Probe call: returns 0 with ERROR_INSUFFICIENT_BUFFER and fills the lengths.
        unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid,
                std::ptr::null_mut(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut domain_len,
                &mut sid_use,
            );
        }
        if name_len == 0 {
            return None;
        }

        let mut name_buf = vec![0u16; name_len as usize];
        let mut domain_buf = vec![0u16; domain_len as usize];
        let rc = unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid,
                name_buf.as_mut_ptr(),
                &mut name_len,
                domain_buf.as_mut_ptr(),
                &mut domain_len,
                &mut sid_use,
            )
        };
        if rc == 0 {
            return None;
        }

        let name = OsString::from_wide(&name_buf[..name_len as usize])
            .to_string_lossy()
            .into_owned();
        let domain = OsString::from_wide(&domain_buf[..domain_len as usize])
            .to_string_lossy()
            .into_owned();
        if domain.is_empty() {
            Some(name)
        } else {
            Some(format!("{domain}\\{name}"))
        }
    }

    fn sid_to_string(sid: PSID) -> Option<String> {
        let mut s: *mut u16 = std::ptr::null_mut();
        let rc = unsafe { ConvertSidToStringSidW(sid, &mut s) };
        if rc == 0 || s.is_null() {
            return None;
        }
        // Walk to the NUL terminator; ConvertSidToStringSidW guarantees one.
        let mut len = 0;
        while unsafe { *s.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: pointer + length validated above.
        let slice = unsafe { std::slice::from_raw_parts(s, len) };
        let result = OsString::from_wide(slice).to_string_lossy().into_owned();
        unsafe {
            LocalFree(s as HLOCAL);
        }
        Some(result)
    }
}
