// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The auth directory and its database are readable only by their owner.
//!
//! This is the whole of the threat model the credential store is defended
//! against — another OS user on a shared box, and the bytes not landing in a
//! backup or a disk image readable by someone else. The secret store never
//! provided it and nothing under `auth/` set a mode before.
//!
//! Both cases are covered deliberately. Securing a freshly created directory
//! is the easy half and the half a test writes by accident; the dangerous
//! half is an operator who already has an `OVSTORAGE_AUTH_DIR` from a release
//! that created it at the default umask, because that is the one where real
//! credentials are about to start being written into an already-permissive
//! file.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use ovstorage::auth::{AuthRefreshLock, SecretStore, SqliteSecretStore};

fn mode_of(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_new_auth_directory_and_database_are_owner_only() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("auth");

    let _lock = AuthRefreshLock::open(&root).unwrap();

    assert_eq!(mode_of(&root), 0o700, "auth directory must be owner-only");
    assert_eq!(
        mode_of(&root.join("auth.sqlite")),
        0o600,
        "auth.sqlite must be owner-only"
    );
}

#[test]
fn an_existing_permissive_directory_and_database_are_corrected() {
    // The upgrade path, and the one that matters. A release that created this
    // directory at the default umask left it `0755` with a `0644` database.
    // Credential bytes are about to move into that file, so opening it without
    // correcting the mode would publish them to every user on the box.
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("auth");
    fs::create_dir_all(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    let db = root.join("auth.sqlite");
    fs::write(&db, b"").unwrap();
    fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();

    let _lock = AuthRefreshLock::open(&root).unwrap();

    assert_eq!(
        mode_of(&root),
        0o700,
        "an existing group/world-readable auth directory must be corrected"
    );
    assert_eq!(
        mode_of(&db),
        0o600,
        "an existing group/world-readable auth.sqlite must be corrected"
    );
}

#[test]
fn the_secret_store_hardens_the_same_paths() {
    // The store opens the same database and may be the handle that creates it,
    // so it owes the same guarantee. Asserted separately rather than assumed
    // from the refresh lock's test: these are two independent open paths.
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("auth");

    let _store = SqliteSecretStore::open(&root).unwrap();

    assert_eq!(mode_of(&root), 0o700);
    assert_eq!(mode_of(&root.join("auth.sqlite")), 0o600);
}

#[test]
fn a_secret_written_through_the_store_lands_in_an_owner_only_file() {
    // End to end rather than on the empty database: the mode must still hold
    // once WAL has been engaged and a row actually written, which is when the
    // bytes are really there to protect.
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("auth");
    let store = SqliteSecretStore::open(&root).unwrap();
    store
        .put(
            "nucleus",
            "c1",
            "refresh_token",
            &ovstorage::SecretBytes(b"tok".to_vec()),
        )
        .unwrap();

    assert_eq!(mode_of(&root.join("auth.sqlite")), 0o600);
    assert_eq!(mode_of(&root), 0o700);
}

#[test]
fn creating_the_auth_directory_does_not_tighten_its_parents() {
    // `DirBuilder::mode` carries to every component `recursive(true)` creates,
    // so building the whole path in one call also narrows the parents. For
    // `/var/lib/ovstorage/broker/auth` that locks a sibling service or an
    // admin out of `/var/lib/ovstorage`, and on a fresh account it does the
    // same to `~/.local`. Only the leaf is ours to tighten.
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("a").join("b").join("auth");

    let _lock = AuthRefreshLock::open(&root).unwrap();

    assert_eq!(mode_of(&root), 0o700, "the leaf must be owner-only");
    let a = parent.path().join("a");
    let b = a.join("b");
    assert_ne!(
        mode_of(&a),
        0o700,
        "{a:?} is an ordinary parent directory and must keep the umask's mode"
    );
    assert_ne!(mode_of(&b), 0o700, "{b:?} likewise");
}

#[test]
fn a_symlinked_auth_directory_is_refused_rather_than_followed() {
    // The no-home fallback puts the auth directory under the shared temporary
    // directory at a name derived from the user id — fully predictable, in a
    // world-writable place, so anyone can create it first. Followed, a link
    // planted there gets the target narrowed to 0700 and `auth.sqlite`
    // written inside it, both chosen by whoever planted it.
    let parent = tempfile::tempdir().unwrap();
    let target = parent.path().join("target");
    fs::create_dir(&target).unwrap();
    let link = parent.path().join("auth");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let error = match AuthRefreshLock::open(&link) {
        Ok(_) => panic!("a symlinked auth directory must be refused"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ovstorage::ErrorCode::StateRootUnavailable);

    assert!(
        !target.join("auth.sqlite").exists(),
        "nothing may be written through the link"
    );
    assert_ne!(
        mode_of(&target),
        0o700,
        "the link target's mode must not be changed"
    );
}

#[test]
fn an_ordinary_owned_directory_is_still_accepted() {
    // The good input for the guard above. Red-green on a refusal gives you the
    // hostile case and never asks whether the honest one still works.
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("auth");
    fs::create_dir(&root).unwrap();

    assert!(
        AuthRefreshLock::open(&root).is_ok(),
        "a directory this user owns must be accepted"
    );

    assert_eq!(mode_of(&root), 0o700);
}
