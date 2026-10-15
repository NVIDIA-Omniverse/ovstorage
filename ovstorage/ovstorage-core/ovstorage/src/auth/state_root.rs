// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Where the auth substrate lives on disk.
//!
//! One resolver for every host. The credential store is only useful if two
//! processes running as one OS user address the same directory: a broker and a
//! CLI must find each other's refresh tokens, and a process must find its own
//! after a restart. Each host resolving its own root defeats both, and the
//! resolution is the same question every time, so it is answered once here.
//!
//! Resolution order:
//!
//! 1. `OVSTORAGE_AUTH_DIR`, which always wins.
//! 2. The platform per-user data directory, plus `ovstorage/auth`.
//! 3. A user-scoped directory under the process temporary directory, when the
//!    environment names no home.
//!
//! Hosts with a configuration file resolve an explicit `auth.state_root` ahead
//! of all three; that precedence lives with the host, because this function
//! sees no configuration.

use std::ffi::OsString;
use std::path::PathBuf;

/// The environment [`resolve_state_root`] reads.
///
/// Taken by injection rather than read from `std::env` directly because two
/// hosts cache their resolved root in a process-global. A test that mutates
/// the process environment therefore passes or fails depending on what ran
/// before it in the same process, which is not a property a test should have.
pub trait StateRootEnv {
    /// The value of environment variable `key`, if set.
    fn var(&self, key: &str) -> Option<OsString>;

    /// The current user's home directory, if the environment names one.
    ///
    /// Callers must not trust this to be usable: [`resolve_state_root`] puts
    /// it through the same absolute-and-non-empty filter as the environment
    /// variables, because `HOME=""` is a real thing a service manager does.
    fn home_dir(&self) -> Option<PathBuf>;
}

/// [`StateRootEnv`] backed by the process environment.
///
/// Named and public so a host that wants the standard resolution against a
/// non-standard environment can compose the two.
pub struct ProcessEnv;

impl StateRootEnv for ProcessEnv {
    fn var(&self, key: &str) -> Option<OsString> {
        std::env::var_os(key)
    }

    fn home_dir(&self) -> Option<PathBuf> {
        #[cfg(windows)]
        {
            std::env::var_os("USERPROFILE").map(PathBuf::from)
        }
        #[cfg(not(windows))]
        {
            std::env::var_os("HOME").map(PathBuf::from)
        }
    }
}

/// The auth state root for this user, resolved against the process
/// environment.
///
/// This is [`resolve_state_root`] against [`ProcessEnv`]. It computes a path
/// and does not create it; [`super::AuthRefreshLock::open`] is the one place
/// the directory and the database are created, so that the directory mode is
/// set in the same place as the database mode.
///
/// Infallible: every arm of the resolution ends at a path, and the last one
/// is the process temporary directory. Returning a `Result` here would
/// document an error that cannot occur and put a `?` on six call sites for
/// nothing.
pub fn default_state_root() -> PathBuf {
    resolve_state_root(&ProcessEnv)
}

/// The auth state root for `env`, per the order documented on this module.
pub fn resolve_state_root(env: &dyn StateRootEnv) -> PathBuf {
    if let Some(value) = env.var("OVSTORAGE_AUTH_DIR") {
        return PathBuf::from(value);
    }
    match platform_data_dir(env) {
        Some(data) => data.join("ovstorage").join("auth"),
        None => temp_fallback().join("auth"),
    }
}

/// The root for an environment that names no home at all.
///
/// Scoped to the user, not the process. The temporary directory is shared by
/// every account on the host, so a fixed name there is created `0700` by
/// whoever starts first and every other user then fails to open it. The
/// process id would avoid that too, and is the wrong answer twice over: a
/// per-process root evaporates on restart, which is the defect this whole
/// resolver exists to remove, and process ids are recycled, so a later
/// process inheriting a dead one's id would adopt its stale `auth.sqlite`
/// and its advisory locks.
///
/// On Windows the temporary directory is already per-user, so the plain name
/// is user-scoped there without help.
fn temp_fallback() -> PathBuf {
    #[cfg(unix)]
    {
        // SAFETY: `getuid` reads the calling process's real user id. It takes
        // no arguments, touches no memory, and cannot fail.
        let uid = unsafe { libc::getuid() };
        std::env::temp_dir().join(format!("ovstorage-{uid}"))
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join("ovstorage")
    }
}

/// The per-user data directory, or the process temporary directory when the
/// environment names no home.
///
/// The temporary fallback keeps a daemon started without `HOME` coming up
/// rather than failing at startup, matching the sibling resolver for the
/// broker's zero-config sandbox directory. Such a process gets a root that
/// does not outlive it, which is the pre-existing behaviour for every host and
/// is strictly better than refusing to start.
fn platform_data_dir(env: &dyn StateRootEnv) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(local) = absolute_var(env, "LOCALAPPDATA") {
            return Some(local);
        }
        if let Some(home) = absolute_home(env) {
            return Some(home.join("AppData").join("Local"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = absolute_home(env) {
            return Some(home.join("Library").join("Application Support"));
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(data) = absolute_var(env, "XDG_DATA_HOME") {
            return Some(data);
        }
        if let Some(home) = absolute_home(env) {
            return Some(home.join(".local").join("share"));
        }
    }
    None
}

/// The home directory, held to the same standard as the variables.
///
/// `HOME=""` and a relative `HOME` are both things a service manager or a
/// stripped environment produces, and either would put the credential
/// database at a path that moves with the working directory. The C host
/// applies this same filter, so accepting a bad `HOME` here would also make
/// the two resolvers disagree about a directory they are supposed to share.
fn absolute_home(env: &dyn StateRootEnv) -> Option<PathBuf> {
    let home = env.home_dir()?;
    home.is_absolute().then_some(home)
}

/// `key`'s value, but only when it is set, non-empty and absolute.
///
/// The XDG base-directory spec requires an absolute path and says a relative
/// value must be ignored; it treats an empty value as unset. Both rules matter
/// here for the same reason: honouring either would put the credential store
/// at a path that moves with the working directory. `LOCALAPPDATA` gets the
/// same treatment, which the spec does not demand but which costs nothing and
/// refuses the same broken input.
#[cfg(any(windows, all(unix, not(target_os = "macos"))))]
fn absolute_var(env: &dyn StateRootEnv, key: &str) -> Option<PathBuf> {
    let value = env.var(key)?;
    let path = PathBuf::from(value);
    path.is_absolute().then_some(path)
}
