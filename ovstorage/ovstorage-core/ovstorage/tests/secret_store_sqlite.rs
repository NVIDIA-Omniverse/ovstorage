// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential bytes live in `auth.sqlite`, keyed by the plugin ABI's own
//! `(backend_kind, connection_id, field)`.

use ovstorage::SecretBytes;
use ovstorage::auth::{SecretStore, SqliteSecretStore};

fn store(root: &std::path::Path) -> SqliteSecretStore {
    SqliteSecretStore::open(root).expect("open the secret store")
}

#[test]
fn a_secret_survives_the_store_that_wrote_it() {
    // The property the secret store provided and the per-process auth directory
    // destroyed: a secret written by one process is readable by the next. It
    // is asserted directly rather than assumed, because every other guarantee
    // in this store is worthless without it.
    let root = tempfile::tempdir().unwrap();
    {
        let first = store(root.path());
        first
            .put(
                "nucleus",
                "conn-1",
                "refresh_token",
                &SecretBytes(b"tok".to_vec()),
            )
            .unwrap();
    }
    let reopened = store(root.path());
    assert_eq!(
        reopened.get("nucleus", "conn-1", "refresh_token").unwrap(),
        Some(SecretBytes(b"tok".to_vec()))
    );
}

#[test]
fn two_stores_on_one_root_see_each_others_writes() {
    // A broker and a CLI running as one OS user, both live at once. This is
    // the scenario the credential design exists for and the one the six
    // per-process auth directories made unreachable.
    let root = tempfile::tempdir().unwrap();
    let broker = store(root.path());
    let cli = store(root.path());

    broker
        .put(
            "nucleus",
            "conn-1",
            "refresh_token",
            &SecretBytes(b"a".to_vec()),
        )
        .unwrap();

    assert_eq!(
        cli.get("nucleus", "conn-1", "refresh_token").unwrap(),
        Some(SecretBytes(b"a".to_vec()))
    );
}

#[test]
fn a_missing_secret_reads_as_none_rather_than_an_error() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        store(root.path())
            .get("nucleus", "absent", "refresh_token")
            .unwrap(),
        None
    );
}

#[test]
fn each_field_of_a_connection_is_addressed_separately() {
    // The key is the ABI's `(backend_kind, connection_id, field)`. A store
    // that collapsed the field would let an identity binding overwrite the
    // refresh token beside it.
    let root = tempfile::tempdir().unwrap();
    let store = store(root.path());
    store
        .put(
            "nucleus",
            "c1",
            "refresh_token",
            &SecretBytes(b"refresh".to_vec()),
        )
        .unwrap();
    store
        .put(
            "nucleus",
            "c1",
            "identity_binding",
            &SecretBytes(b"binding".to_vec()),
        )
        .unwrap();

    assert_eq!(
        store.get("nucleus", "c1", "refresh_token").unwrap(),
        Some(SecretBytes(b"refresh".to_vec()))
    );
    assert_eq!(
        store.get("nucleus", "c1", "identity_binding").unwrap(),
        Some(SecretBytes(b"binding".to_vec()))
    );
}

#[test]
fn connections_of_the_same_backend_do_not_share_a_secret() {
    // `connection_id` encodes the server plus the user's principal, so two
    // connections collapsing onto one row would hand one account's refresh
    // token to another.
    let root = tempfile::tempdir().unwrap();
    let store = store(root.path());
    store
        .put(
            "nucleus",
            "c1",
            "refresh_token",
            &SecretBytes(b"one".to_vec()),
        )
        .unwrap();
    store
        .put(
            "nucleus",
            "c2",
            "refresh_token",
            &SecretBytes(b"two".to_vec()),
        )
        .unwrap();

    assert_eq!(
        store.get("nucleus", "c1", "refresh_token").unwrap(),
        Some(SecretBytes(b"one".to_vec()))
    );
    assert_eq!(
        store.get("nucleus", "c2", "refresh_token").unwrap(),
        Some(SecretBytes(b"two".to_vec()))
    );
}

#[test]
fn a_put_overwrites_the_previous_secret() {
    let root = tempfile::tempdir().unwrap();
    let store = store(root.path());
    store
        .put(
            "nucleus",
            "c1",
            "refresh_token",
            &SecretBytes(b"old".to_vec()),
        )
        .unwrap();
    store
        .put(
            "nucleus",
            "c1",
            "refresh_token",
            &SecretBytes(b"new".to_vec()),
        )
        .unwrap();

    assert_eq!(
        store.get("nucleus", "c1", "refresh_token").unwrap(),
        Some(SecretBytes(b"new".to_vec()))
    );
}

#[test]
fn delete_removes_only_the_named_field() {
    let root = tempfile::tempdir().unwrap();
    let store = store(root.path());
    store
        .put(
            "nucleus",
            "c1",
            "refresh_token",
            &SecretBytes(b"refresh".to_vec()),
        )
        .unwrap();
    store
        .put(
            "nucleus",
            "c1",
            "identity_binding",
            &SecretBytes(b"binding".to_vec()),
        )
        .unwrap();

    store.delete("nucleus", "c1", "refresh_token").unwrap();

    assert_eq!(store.get("nucleus", "c1", "refresh_token").unwrap(), None);
    assert_eq!(
        store.get("nucleus", "c1", "identity_binding").unwrap(),
        Some(SecretBytes(b"binding".to_vec())),
        "deleting one field must not disturb its sibling"
    );
}

#[test]
fn deleting_an_absent_secret_is_not_an_error() {
    // Sign-out runs against whatever is there. Refusing on a missing row
    // would make an idempotent operation fail on its second call.
    let root = tempfile::tempdir().unwrap();
    store(root.path())
        .delete("nucleus", "absent", "refresh_token")
        .unwrap();
}

#[test]
fn a_non_utf8_secret_is_still_refused() {
    // The keyring stored strings, so this restriction existed for its sake and
    // sqlite's BLOB column could now carry the bytes. It is kept deliberately:
    // callers base64 binary secrets today, and relaxing the contract is a
    // behaviour change with its own callers to check.
    let root = tempfile::tempdir().unwrap();
    let error = store(root.path())
        .put(
            "nucleus",
            "c1",
            "refresh_token",
            &SecretBytes(vec![0xff, 0xfe]),
        )
        .expect_err("non-UTF-8 secrets must be refused");
    assert_eq!(error.code(), ovstorage::ErrorCode::InvalidArgument);
}

#[test]
fn a_multi_field_write_is_all_or_nothing() {
    // `put_many` exists so the host's two-field credential write cannot be
    // interrupted between the access token and the refresh token beside it.
    // The refusal is driven through the same non-UTF-8 guard `put` uses, so
    // the second field fails after the first has been staged.
    let root = tempfile::tempdir().unwrap();
    let store = store(root.path());
    let good = SecretBytes(b"access".to_vec());
    let bad = SecretBytes(vec![0xff, 0xfe]);

    let error = store
        .put_many(
            "nucleus",
            "c1",
            &[("oauth/idp", &good), ("oauth/idp/refresh", &bad)],
        )
        .expect_err("a rejected field must fail the whole write");
    assert_eq!(error.code(), ovstorage::ErrorCode::InvalidArgument);

    assert_eq!(
        store.get("nucleus", "c1", "oauth/idp").unwrap(),
        None,
        "the first field must not survive a failed multi-field write"
    );
    assert_eq!(
        store.get("nucleus", "c1", "oauth/idp/refresh").unwrap(),
        None
    );
}

#[test]
fn a_multi_field_write_commits_every_field_together() {
    let root = tempfile::tempdir().unwrap();
    let store = store(root.path());
    let access = SecretBytes(b"access".to_vec());
    let refresh = SecretBytes(b"refresh".to_vec());

    store
        .put_many(
            "nucleus",
            "c1",
            &[("oauth/idp", &access), ("oauth/idp/refresh", &refresh)],
        )
        .unwrap();

    assert_eq!(
        store.get("nucleus", "c1", "oauth/idp").unwrap(),
        Some(access)
    );
    assert_eq!(
        store.get("nucleus", "c1", "oauth/idp/refresh").unwrap(),
        Some(refresh)
    );
}

#[test]
fn a_multi_field_write_replaces_a_previous_generation_atomically() {
    // A rotation overwrites both fields. The point of the transaction is that
    // no reader observes the new access token beside the old refresh token.
    let root = tempfile::tempdir().unwrap();
    let store = store(root.path());
    let first = SecretBytes(b"v1".to_vec());
    let second = SecretBytes(b"v2".to_vec());
    store
        .put_many(
            "nucleus",
            "c1",
            &[("oauth/idp", &first), ("oauth/idp/refresh", &first)],
        )
        .unwrap();
    store
        .put_many(
            "nucleus",
            "c1",
            &[("oauth/idp", &second), ("oauth/idp/refresh", &second)],
        )
        .unwrap();

    assert_eq!(
        store.get("nucleus", "c1", "oauth/idp").unwrap(),
        Some(second.clone())
    );
    assert_eq!(
        store.get("nucleus", "c1", "oauth/idp/refresh").unwrap(),
        Some(second)
    );
}
