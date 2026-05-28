// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network-filesystem detection. Network filesystems claim flock
//! support but lie; refusing them keeps the herd-collapse and lease
//! invariants intact. `OVSTORAGE_ALLOW_NETWORK_FS=1` overrides.

use std::path::Path;

/// Result of a backing-filesystem probe. Refusal lives at the call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsKind {
    /// Local filesystem (ext4, btrfs, xfs, apfs, NTFS, ReFS, ...).
    Local,
    /// Networked filesystem (NFS, SMB/CIFS, AFS, WebDAV, sshfs,
    /// FUSE-over-network).
    Network,
    /// Detection was not possible; caller falls back to the UNC
    /// string heuristic.
    Unknown,
}

/// Probe the path's backing filesystem.
///
/// Linux consults `statfs(2).f_type` against the magic number table
/// for known networked filesystems (NFS, CIFS, FUSE, Lustre, Ceph,
/// GFS2, AFS, OCFS2). Other targets fall back to the UNC string
/// heuristic, returning `Unknown` for everything else.
pub fn fs_kind(path: &Path) -> FsKind {
    if looks_like_network_unc(path) {
        return FsKind::Network;
    }
    platform::fs_kind(path)
}

/// Detect Windows-style `\\server\share` and POSIX `//server/share`
/// UNC paths by string inspection.
pub fn looks_like_network_unc(path: &Path) -> bool {
    let value = path.to_string_lossy();
    value.starts_with("\\\\") || value.starts_with("//")
}

#[cfg(target_os = "linux")]
mod platform {
    use super::FsKind;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const NFS_MAGIC: i64 = 0x6969;
    const CIFS_MAGIC: i64 = 0xff534d42_u32 as i64;
    const SMB_MAGIC: i64 = 0x517B;
    const SMB2_MAGIC: i64 = 0xfe534d42_u32 as i64;
    const FUSE_MAGIC: i64 = 0x65735546;
    const AFS_MAGIC: i64 = 0x5346414f;
    const LUSTRE_MAGIC: i64 = 0x0BD00BD0;
    const CEPH_MAGIC: i64 = 0x00C36400;
    const GFS2_MAGIC: i64 = 0x01161970;
    const OCFS2_MAGIC: i64 = 0x7461636f;

    pub fn fs_kind(path: &Path) -> FsKind {
        let probe_path = if path.exists() {
            path.to_path_buf()
        } else {
            match path.parent() {
                Some(parent) if parent.as_os_str().is_empty() => return FsKind::Unknown,
                Some(parent) => parent.to_path_buf(),
                None => return FsKind::Unknown,
            }
        };
        let Ok(c_path) = CString::new(probe_path.as_os_str().as_bytes()) else {
            return FsKind::Unknown;
        };
        let mut buf = unsafe { std::mem::zeroed::<libc::statfs>() };
        let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut buf) };
        if rc != 0 {
            return FsKind::Unknown;
        }
        let f_type = buf.f_type as i64;
        match f_type {
            NFS_MAGIC | CIFS_MAGIC | SMB_MAGIC | SMB2_MAGIC | FUSE_MAGIC | AFS_MAGIC
            | LUSTRE_MAGIC | CEPH_MAGIC | GFS2_MAGIC | OCFS2_MAGIC => FsKind::Network,
            _ => FsKind::Local,
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::FsKind;
    use std::path::Path;

    pub fn fs_kind(_path: &Path) -> FsKind {
        FsKind::Unknown
    }
}

/// `OVSTORAGE_ALLOW_NETWORK_FS=<non-empty>` forces callers to allow
/// network filesystems regardless of [`fs_kind`]'s result.
pub fn allow_network_fs_override() -> bool {
    std::env::var_os("OVSTORAGE_ALLOW_NETWORK_FS")
        .map(|value| !value.is_empty())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn unc_detection_catches_double_slash_prefix() {
        assert!(looks_like_network_unc(&PathBuf::from("//server/share")));
        assert!(looks_like_network_unc(&PathBuf::from(r"\\server\share")));
        assert!(!looks_like_network_unc(&PathBuf::from("/server/share")));
        assert!(!looks_like_network_unc(&PathBuf::from("/home/user/cache")));
    }

    #[test]
    fn fs_kind_returns_network_for_unc_paths() {
        assert_eq!(fs_kind(&PathBuf::from("//host/share")), FsKind::Network);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fs_kind_returns_local_for_temp_dir_on_linux() {
        let temp = tempfile::tempdir().unwrap();
        assert_eq!(fs_kind(temp.path()), FsKind::Local);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn fs_kind_returns_unknown_for_local_paths_off_linux() {
        let temp = tempfile::tempdir().unwrap();
        assert_eq!(fs_kind(temp.path()), FsKind::Unknown);
    }
}
