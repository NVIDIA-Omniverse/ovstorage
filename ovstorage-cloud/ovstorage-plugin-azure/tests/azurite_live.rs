// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Round-trip coverage against a live Azurite, Microsoft's own Blob Storage
//! emulator.
//!
//! Every other Azure suite in this crate answers from a fixture this
//! repository also wrote. That is enough to pin what the plugin *sends*, and
//! it can say nothing about whether Azure agrees: both halves derive their
//! canonicalization from one reading of the spec, so a misreading verifies
//! against itself. Azurite is the independent half — it computes Shared Key
//! and service-SAS signatures from its own implementation and answers 403 the
//! way the service does.
//!
//! Two signature paths reach it here, and only one of them any in-tree
//! fixture checks:
//!
//! - **Shared Key**, on `write` / `stat` / `list` / `delete`. The plugin signs
//!   these itself, and the emulator's path-style endpoint puts the account in
//!   the URI as well as in the canonicalized resource.
//! - **The service SAS**, on `read`. The plugin's read path mints a presigned
//!   URL and returns without touching the wire, so the URL's signature is
//!   never exercised by construction — nothing short of a service that
//!   verifies it can tell a correct SAS from one that merely parses. This
//!   suite fetches the minted URL and compares the bytes.
//!
//! The suite is skipped unless `OVSTORAGE_AZURITE_ENDPOINT` names a running
//! emulator, so a developer without Docker still runs `cargo test`.
//! `OVSTORAGE_REQUIRE_AZURITE` turns the skip into a failure, which is what CI
//! sets: a suite that silently returns early is indistinguishable from one
//! that passed.

mod support;

use std::time::{SystemTime, UNIX_EPOCH};

use ovstorage_plugin::{
    ConfigValue, DeleteOptions, ErrorCode, ListOptions, ObjectKind, ReadOptions, ReadResult,
    StatOptions, WriteOptions,
};

/// Azurite's published development account. Created by
/// `tools/ovtasks/azurite.py start`, which is the only thing that knows how to
/// bring the emulator up; the container it makes is named here because a test
/// binary cannot read the fixture module.
const ACCOUNT: &str = "devstoreaccount1";
const ACCOUNT_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
const CONTAINER: &str = "ovstorage";

fn endpoint() -> Option<String> {
    match std::env::var("OVSTORAGE_AZURITE_ENDPOINT") {
        Ok(value) if !value.trim().is_empty() => Some(value.trim_end_matches('/').to_string()),
        _ if std::env::var_os("OVSTORAGE_REQUIRE_AZURITE").is_some() => {
            panic!("OVSTORAGE_REQUIRE_AZURITE requires OVSTORAGE_AZURITE_ENDPOINT")
        }
        _ => None,
    }
}

/// A backend pointed at the live emulator, signing with its development key.
///
/// Through the public `blob_endpoint` key rather than the `__test_only_*`
/// endpoint override, because the account path segment is exactly what an
/// operator configuring a real emulator or reverse proxy writes, and it is
/// what has to reach the signer.
fn build_backend(endpoint: &str) -> std::sync::Arc<ovstorage_plugin_azure::AzureBackend> {
    support::build_backend_from_config_with_key(
        support::config_map(
            ACCOUNT,
            CONTAINER,
            &[(
                "blob_endpoint",
                ConfigValue::String(format!("{endpoint}/{ACCOUNT}")),
            )],
        ),
        ACCOUNT_KEY,
    )
}

/// A prefix no other run of this suite can collide with. The fixture creates
/// one container per job and re-running against a warm emulator is supported,
/// so isolation has to come from the key space.
fn run_prefix() -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after Unix epoch")
        .as_nanos();
    format!("live/{}-{nonce}", std::process::id())
}

#[tokio::test]
async fn shared_key_round_trip_against_live_azurite() {
    let Some(endpoint) = endpoint() else {
        return;
    };
    let backend = build_backend(&endpoint);
    let prefix = run_prefix();
    let key = format!("{prefix}/round-trip.txt");
    let expected = b"ovstorage reached a live Azurite".to_vec();

    // Each of these is signed by the plugin and verified by Azurite. A
    // canonicalization the plugin got wrong fails here as a 403, whatever the
    // in-tree fixtures agree about.
    let write = backend
        .write(
            support::target(ACCOUNT, CONTAINER, &key),
            expected.clone(),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("Put Blob must be signed the way Azure verifies");
    assert!(
        write.info.etag.is_some(),
        "a committed blob must report the validator Azurite returned, got {:?}",
        write.info,
    );

    let info = backend
        .stat(
            support::target(ACCOUNT, CONTAINER, &key),
            StatOptions::default(),
            None,
        )
        .await
        .expect("Get Blob Properties must be signed the way Azure verifies");
    assert_eq!(info.kind, ObjectKind::File);
    assert_eq!(
        info.size,
        Some(expected.len() as u64),
        "stat must report the size Azurite stored",
    );

    let listed = backend
        .list(
            support::target(ACCOUNT, CONTAINER, &format!("{prefix}/")),
            ListOptions::default(),
            None,
        )
        .await
        .expect("List Blobs must be signed the way Azure verifies");
    assert!(
        listed
            .iter()
            .any(|entry| entry.address.path().ends_with("round-trip.txt")),
        "the written blob must appear under its own prefix; listing returned {:?}",
        listed
            .iter()
            .map(|e| e.address.as_str())
            .collect::<Vec<_>>(),
    );

    backend
        .delete(
            support::target(ACCOUNT, CONTAINER, &key),
            DeleteOptions::default(),
            None,
        )
        .await
        .expect("Delete Blob must be signed the way Azure verifies");

    let err = backend
        .stat(
            support::target(ACCOUNT, CONTAINER, &key),
            StatOptions::default(),
            None,
        )
        .await
        .expect_err("a deleted blob must not stat");
    assert_eq!(
        err.code(),
        ErrorCode::NotFound,
        "Azurite's 404 must map to NotFound, got {err:?}",
    );
}

#[tokio::test]
async fn a_minted_service_sas_is_honoured_by_live_azurite() {
    let Some(endpoint) = endpoint() else {
        return;
    };
    let backend = build_backend(&endpoint);
    let key = format!("{}/presigned.txt", run_prefix());
    let expected = b"a service SAS this repository did not verify itself".to_vec();

    backend
        .write(
            support::target(ACCOUNT, CONTAINER, &key),
            expected.clone(),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("stage the blob the redirect will address");

    let result = backend
        .read(
            support::target(ACCOUNT, CONTAINER, &key),
            ReadOptions::default(),
            None,
        )
        .await
        .expect("read mints a redirect without touching the wire");
    let ReadResult::Redirect(redirect) = result else {
        panic!("the azure backend reads by redirect; got {result:?}");
    };

    // Fetched exactly as minted. A SAS whose canonicalized resource does not
    // match what Azurite derives from the URL comes back 403, and one whose
    // `spr` excluded plain HTTP would too — neither is observable without a
    // service that checks.
    let mut request = reqwest::Client::new().request(
        redirect
            .request
            .method
            .parse()
            .expect("the redirect names an HTTP method"),
        &redirect.request.url,
    );
    for (name, value) in &redirect.request.headers {
        request = request.header(name, value);
    }
    let response = request.send().await.expect("reach the emulator");
    assert!(
        response.status().is_success(),
        "Azurite refused the minted SAS with {}: {}",
        response.status(),
        response.text().await.unwrap_or_default(),
    );
    assert_eq!(
        response.bytes().await.expect("read the redirected body"),
        expected,
        "the redirected read must return the bytes that were written",
    );

    backend
        .delete(
            support::target(ACCOUNT, CONTAINER, &key),
            DeleteOptions::default(),
            None,
        )
        .await
        .expect("clean up the staged blob");
}
