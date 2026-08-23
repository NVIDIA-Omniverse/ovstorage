// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The auth state root resolves to one durable per-user path shared by every
//! host, and `OVSTORAGE_AUTH_DIR` still wins over it.
//!
//! Resolution is tested against an injected environment rather than the
//! process environment. Two of the six hosts cache their resolved root in a
//! process-global, so a test that mutates `std::env` passes or fails depending
//! on what ran before it in the same process.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;

use ovstorage::auth::{StateRootEnv, resolve_state_root};

struct FakeEnv {
    vars: HashMap<String, OsString>,
    home: Option<PathBuf>,
}

impl FakeEnv {
    /// An environment with a home directory and none of the override
    /// variables set — the shape that must resolve to the platform default.
    fn with_home(home: &std::path::Path) -> Self {
        Self {
            vars: HashMap::new(),
            home: Some(home.to_path_buf()),
        }
    }

    fn set(mut self, key: &str, value: impl Into<OsString>) -> Self {
        self.vars.insert(key.to_string(), value.into());
        self
    }
}

impl StateRootEnv for FakeEnv {
    fn var(&self, key: &str) -> Option<OsString> {
        self.vars.get(key).cloned()
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.home.clone()
    }
}

/// The variable each platform reads for its per-user data directory, and the
/// value that points it at `base`. Kept beside the tests that need it so the
/// Windows arm exercises the same resolution the Windows CI job runs, rather
/// than falling through an unset variable to a path no assertion describes.
fn platform_data_home(base: &std::path::Path) -> (&'static str, PathBuf) {
    #[cfg(windows)]
    {
        ("LOCALAPPDATA", base.join("AppData").join("Local"))
    }
    #[cfg(target_os = "macos")]
    {
        // macOS reads no data-home variable; the default is derived from the
        // home directory alone. Naming `HOME` keeps the tuple shape uniform.
        ("HOME", base.to_path_buf())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        ("XDG_DATA_HOME", base.join(".local").join("share"))
    }
}

#[test]
fn override_env_var_wins_over_the_platform_default() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let env = FakeEnv::with_home(home.path())
        .set("OVSTORAGE_AUTH_DIR", tmp.path().as_os_str().to_owned());
    assert_eq!(resolve_state_root(&env), tmp.path());
}

#[test]
fn the_platform_default_is_a_per_user_path_not_a_temp_dir() {
    let home = tempfile::tempdir().unwrap();
    let (var, value) = platform_data_home(home.path());
    let env = FakeEnv::with_home(home.path()).set(var, value.into_os_string());

    let root = resolve_state_root(&env);

    // Positive assertions: the path is under this user's home and carries the
    // expected tail. "Not under /tmp" would also pass for a path that is wrong
    // in some other way.
    assert!(
        root.starts_with(home.path()),
        "{root:?} is not under {:?}",
        home.path()
    );
    assert!(root.ends_with("ovstorage/auth"), "{root:?}");

    // And it does not vary with the process id, which is what made the six
    // per-host defaults unshareable.
    assert!(
        !root
            .to_string_lossy()
            .contains(&std::process::id().to_string()),
        "{root:?} still encodes the process id"
    );
}

#[test]
fn every_host_resolves_the_same_path_from_one_environment() {
    // The property the secret store's flat service id was silently providing: a
    // broker and a CLI running as one OS user address the same store. There is
    // one resolver now, so this asserts it is stable rather than per-caller.
    let home = tempfile::tempdir().unwrap();
    let (var, value) = platform_data_home(home.path());
    let first = FakeEnv::with_home(home.path()).set(var, value.clone().into_os_string());
    let second = FakeEnv::with_home(home.path()).set(var, value.into_os_string());

    assert_eq!(resolve_state_root(&first), resolve_state_root(&second));
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn a_relative_xdg_data_home_falls_back_rather_than_resolving_against_the_cwd() {
    // The XDG spec requires an absolute path and says a relative one must be
    // ignored. Honouring it would put the credential store somewhere that
    // moves with the working directory.
    let home = tempfile::tempdir().unwrap();
    let env = FakeEnv::with_home(home.path()).set("XDG_DATA_HOME", "relative/data");

    let root = resolve_state_root(&env);

    assert!(
        root.starts_with(home.path()),
        "a relative XDG_DATA_HOME must fall back to the home directory, got {root:?}"
    );
    assert!(root.ends_with("ovstorage/auth"), "{root:?}");
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn an_empty_xdg_data_home_is_treated_as_unset() {
    // The XDG spec treats an empty value the same as an absent one. An empty
    // string is not absolute, so this rides the same fallback, but it is
    // asserted separately because it arrives by a different route: a shell
    // exporting an unset variable rather than a misconfigured one.
    let home = tempfile::tempdir().unwrap();
    let env = FakeEnv::with_home(home.path()).set("XDG_DATA_HOME", "");

    let root = resolve_state_root(&env);

    assert!(root.starts_with(home.path()), "{root:?}");
    assert!(root.ends_with("ovstorage/auth"), "{root:?}");
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn an_empty_home_is_treated_as_unset() {
    // `HOME=""` is what a service manager with a stripped environment hands a
    // daemon. Joined naively it yields `.local/share/ovstorage/auth`, putting
    // the credential database wherever the process happens to be running.
    let env = FakeEnv {
        vars: HashMap::new(),
        home: Some(PathBuf::from("")),
    };

    let root = resolve_state_root(&env);

    assert!(
        root.is_absolute(),
        "an empty HOME must not yield a relative credential path, got {root:?}"
    );
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn a_relative_home_is_treated_as_unset() {
    let env = FakeEnv {
        vars: HashMap::new(),
        home: Some(PathBuf::from("relative/home")),
    };

    let root = resolve_state_root(&env);

    assert!(root.is_absolute(), "{root:?}");
}

#[test]
fn the_no_home_fallback_is_scoped_to_the_user() {
    // The temporary directory is shared by every account on the host, so a
    // fixed name under it is created 0700 by whoever starts first and every
    // other user then fails to open it.
    let env = FakeEnv {
        vars: HashMap::new(),
        home: None,
    };

    let root = resolve_state_root(&env);

    assert!(root.starts_with(std::env::temp_dir()), "{root:?}");
    #[cfg(unix)]
    {
        // SAFETY: `getuid` takes no arguments, reads process state, cannot fail.
        let uid = unsafe { libc::getuid() };
        assert!(
            root.to_string_lossy().contains(&uid.to_string()),
            "the fallback must be scoped to the user: {root:?}"
        );
    }
}

#[test]
fn the_no_home_fallback_is_stable_across_processes() {
    // Scoping by process id would separate users too, and is the wrong answer
    // twice over: a per-process root evaporates on restart — the defect this
    // whole resolver exists to remove — and process ids are recycled, so a
    // later process inheriting a dead one's id would adopt its stale
    // `auth.sqlite` and its advisory locks.
    let env = FakeEnv {
        vars: HashMap::new(),
        home: None,
    };

    let root = resolve_state_root(&env);

    assert!(
        !root
            .to_string_lossy()
            .contains(&std::process::id().to_string()),
        "the fallback must not encode the process id: {root:?}"
    );
}

#[test]
fn resolution_survives_an_environment_with_no_home_directory() {
    // A daemon started with no HOME must still come up. The sibling that
    // already resolves a per-user data directory in this workspace
    // (`ovstorage-broker`'s zero-config sandbox) falls back to the process
    // temporary directory for exactly this case; this resolver matches it
    // rather than inventing a second answer.
    let env = FakeEnv {
        vars: HashMap::new(),
        home: None,
    };

    let root = resolve_state_root(&env);

    assert!(
        root.starts_with(std::env::temp_dir()),
        "{root:?} is not under the process temporary directory"
    );
}
