// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker-boundary behavior for sealed client-driven write continuations.

use ovstorage::{
    ErrorCode, RedirectResult, RedirectResultBatch, StatOptions, WriteRedirectBatch, WriteStep,
};
use ovstorage_plugin_test::Recorder;
use std::path::Path;

use super::*;
use crate::test_utils::recording_test_broker;

const TEST_ROOT: &str = "test://demo/";

fn backend_config(continue_write_loops: i64) -> HashMap<String, ConfigValue> {
    HashMap::from([
        (
            "test_redirect_url".to_string(),
            ConfigValue::String("https://redirect.test.example".into()),
        ),
        (
            "test_continue_write_loops".to_string(),
            ConfigValue::Int(continue_write_loops),
        ),
    ])
}

fn configured_broker_toml(key_path: Option<&Path>) -> String {
    let continuation_seal = key_path.map_or_else(String::new, |path| {
        let path = path
            .to_string_lossy()
            .replace('\\', "/")
            .replace('"', "\\\"");
        format!(
            r#"[continuation_seal]
key_path = "{path}"

"#
        )
    });
    format!(
        r#"{continuation_seal}[listener]
bind = "127.0.0.1:0"
auth = "anonymous"

[ovstorage]
root = "router"

[ovstorage.layers.router]
children = ["test"]

[ovstorage.layers.test]
kind = "test"

[[ovstorage.connections]]
backend_kind = "test"

[ovstorage.connections.config]
test_root = "{TEST_ROOT}"
test_redirect_url = "https://redirect.test.example"
test_continue_write_loops = 1
"#
    )
}

async fn build_configured_broker(key_path: Option<&Path>) -> Broker {
    ensure_test_plugin_env();
    let config = crate::parse_broker_config(&configured_broker_toml(key_path))
        .expect("continuation-seal test config parses");
    crate::build_broker_from_config(&config)
        .await
        .expect("continuation-seal test broker builds")
}

fn object(name: &str) -> Url {
    address::join_relative(&Url::parse(TEST_ROOT).unwrap(), name).unwrap()
}

fn successful_results(batch: &WriteRedirectBatch) -> RedirectResultBatch {
    RedirectResultBatch {
        results: batch
            .redirects
            .iter()
            .map(|_| RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: Vec::new(),
            })
            .collect(),
    }
}

fn envelope_inner(batch: &WriteRedirectBatch) -> Vec<u8> {
    assert!(
        batch
            .continuation
            .starts_with(crate::continuation_seal::CONTINUATION_SEAL_TAG.as_bytes()),
        "broker egress must carry the versioned continuation envelope"
    );
    let inner =
        batch.continuation[crate::continuation_seal::CONTINUATION_SEAL_HEADER_LEN..].to_vec();
    assert_eq!(
        batch.continuation.len(),
        inner.len() + crate::continuation_seal::CONTINUATION_SEAL_HEADER_LEN,
        "the compact envelope must add only its fixed-size authenticated header"
    );
    inner
}

fn assert_no_continue_write(recorder: &Recorder) {
    assert_eq!(
        recorder.count_method("continue_write"),
        0,
        "an invalid seal must be refused before plugin dispatch"
    );
}

async fn assert_not_committed(broker: &Broker, address: Url) {
    let error = broker
        .stat(&default_context(), address, StatOptions::default())
        .await
        .expect_err("a refused continuation must not commit an object");
    assert_eq!(error.code(), ErrorCode::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn sealed_round_trip_commits_and_is_observable() {
    let (broker, recorder) = recording_test_broker(backend_config(1)).await;
    let address = object("accepted.bin");
    let batch = broker
        .write_redirect(&default_context(), address.clone(), WriteOptions::default())
        .await
        .expect("broker emits the initial redirect batch");
    let inner = envelope_inner(&batch);
    let plugin_continuation: serde_json::Value =
        serde_json::from_slice(&inner).expect("inner continuation is test-plugin JSON");
    assert_eq!(plugin_continuation["key"], "accepted.bin");

    let step = broker
        .continue_write(
            &default_context(),
            address.clone(),
            batch.clone(),
            successful_results(&batch),
        )
        .await
        .expect("the broker accepts its own sealed continuation");
    let WriteStep::Done(done) = step else {
        panic!("one-round test upload must complete");
    };
    assert_eq!(done.info.address, address);
    assert_eq!(recorder.count_method("continue_write"), 1);

    let observed = broker
        .stat(&default_context(), address.clone(), StatOptions::default())
        .await
        .expect("completed redirected write is visible through the broker");
    assert_eq!(observed.address, address);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_multi_round_continuation_is_resealed_and_accepted() {
    const EXPECTED_ROUNDS: i64 = 3;

    let (broker, recorder) = recording_test_broker(backend_config(EXPECTED_ROUNDS)).await;
    let address = object("multi-round.bin");
    let mut batch = broker
        .write_redirect(&default_context(), address.clone(), WriteOptions::default())
        .await
        .expect("broker emits the first redirect batch");

    for round in 1..=EXPECTED_ROUNDS {
        envelope_inner(&batch);
        let step = broker
            .continue_write(
                &default_context(),
                address.clone(),
                batch.clone(),
                successful_results(&batch),
            )
            .await
            .expect("each broker-sealed round is accepted");

        if round < EXPECTED_ROUNDS {
            let WriteStep::Redirects(next) = step else {
                panic!("redirected write completed early on round {round} of {EXPECTED_ROUNDS}");
            };
            batch = next;
        } else {
            let WriteStep::Done(done) = step else {
                panic!("redirected write returned an extra round after round {EXPECTED_ROUNDS}");
            };
            assert_eq!(done.info.address, address);
        }
    }

    assert_eq!(
        recorder.count_method("continue_write"),
        EXPECTED_ROUNDS as usize
    );
    broker
        .stat(&default_context(), address, StatOptions::default())
        .await
        .expect("multi-round completion commits the object");
}

#[tokio::test(flavor = "multi_thread")]
async fn edited_inner_continuation_is_refused_before_plugin_dispatch() {
    let (broker, recorder) = recording_test_broker(backend_config(1)).await;
    let address = object("tampered.bin");
    let mut batch = broker
        .write_redirect(&default_context(), address.clone(), WriteOptions::default())
        .await
        .expect("broker emits the initial redirect batch");
    let inner = envelope_inner(&batch);
    let mut plugin_continuation: serde_json::Value =
        serde_json::from_slice(&inner).expect("inner continuation is test-plugin JSON");
    plugin_continuation
        .as_object_mut()
        .expect("test-plugin continuation is an object")
        .remove("loops_remaining")
        .expect("test-plugin continuation carries the loop state");
    batch.continuation.splice(
        crate::continuation_seal::CONTINUATION_SEAL_HEADER_LEN..,
        serde_json::to_vec(&plugin_continuation).unwrap(),
    );

    let error = broker
        .continue_write(
            &default_context(),
            address.clone(),
            batch.clone(),
            successful_results(&batch),
        )
        .await
        .expect_err("editing the inner continuation without its MAC is refused");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains("continuation seal"));
    assert_no_continue_write(&recorder);
    assert_not_committed(&broker, address).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn continuation_substituted_to_another_address_is_refused() {
    let (broker, recorder) = recording_test_broker(backend_config(1)).await;
    let issued_for = object("a");
    let substituted = object("b");
    let batch = broker
        .write_redirect(
            &default_context(),
            issued_for.clone(),
            WriteOptions::default(),
        )
        .await
        .expect("broker emits a continuation bound to a");

    let error = broker
        .continue_write(
            &default_context(),
            substituted.clone(),
            batch.clone(),
            successful_results(&batch),
        )
        .await
        .expect_err("a continuation sealed for a must not be accepted for b");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains("continuation seal"));
    assert_no_continue_write(&recorder);
    assert_not_committed(&broker, issued_for).await;
    assert_not_committed(&broker, substituted).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_plugin_continuation_is_refused_without_leaking_blob_bytes() {
    const SENTINEL: &str = "raw-plugin-continuation-do-not-echo";

    let (broker, recorder) = recording_test_broker(backend_config(1)).await;
    let address = object("unsealed.bin");
    let mut batch = broker
        .write_redirect(&default_context(), address.clone(), WriteOptions::default())
        .await
        .expect("broker emits the initial redirect batch");
    batch.continuation = format!(
        r#"{{"key":"unsealed.bin","bytes":"","loops_remaining":0,"sentinel":"{SENTINEL}"}}"#
    )
    .into_bytes();

    let error = broker
        .continue_write(
            &default_context(),
            address.clone(),
            batch.clone(),
            successful_results(&batch),
        )
        .await
        .expect_err("raw plugin continuation bytes must not cross the broker boundary");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains("continuation seal"));
    assert!(!error.message().contains(SENTINEL));
    assert_no_continue_write(&recorder);
    assert_not_committed(&broker, address).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reload_accepts_a_continuation_issued_before_the_broker_swap() {
    ensure_test_plugin_env();
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let config_path = root.join("broker.toml");
    std::fs::write(&config_path, configured_broker_toml(None)).unwrap();

    let broker = crate::build_broker_from_config_file(&config_path)
        .await
        .expect("initial broker builds from the reload config");
    let controller = crate::LifecycleController::new(crate::broker_handle(broker), Vec::new())
        .with_config_path(config_path.clone())
        .expect("lifecycle controller accepts the reload config");
    let before = controller.current_broker();
    let address = object("across-reload.bin");
    let batch = before
        .write_redirect(&default_context(), address.clone(), WriteOptions::default())
        .await
        .expect("the pre-reload broker issues a sealed continuation");

    controller.reload().await.expect("broker reload succeeds");
    let after = controller.current_broker();
    assert!(
        !Arc::ptr_eq(&before, &after),
        "reload must install a newly built broker"
    );
    let step = after
        .continue_write(
            &default_context(),
            address.clone(),
            batch.clone(),
            successful_results(&batch),
        )
        .await
        .expect("the replacement broker accepts the pre-reload continuation");
    let WriteStep::Done(done) = step else {
        panic!("one-round test upload must complete after reload");
    };
    assert_eq!(done.info.address, address);

    std::fs::remove_dir_all(root).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn brokers_configured_with_one_key_path_accept_each_others_continuations() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let key_path = root.join("continuation-seal.key");
    std::fs::write(&key_path, [0x6b; 32]).unwrap();
    let issuer = build_configured_broker(Some(&key_path)).await;
    let continuer = build_configured_broker(Some(&key_path)).await;
    let address = object("shared-key.bin");
    let batch = issuer
        .write_redirect(&default_context(), address.clone(), WriteOptions::default())
        .await
        .expect("the issuing replica emits a sealed continuation");

    let step = continuer
        .continue_write(
            &default_context(),
            address.clone(),
            batch.clone(),
            successful_results(&batch),
        )
        .await
        .expect("a replica using the same configured key accepts the continuation");
    let WriteStep::Done(done) = step else {
        panic!("one-round shared-key upload must complete");
    };
    assert_eq!(done.info.address, address);

    std::fs::remove_dir_all(root).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn brokers_with_default_random_keys_refuse_each_others_continuations() {
    let issuer = build_configured_broker(None).await;
    let foreign = build_configured_broker(None).await;
    let address = object("isolated-default-keys.bin");
    let batch = issuer
        .write_redirect(&default_context(), address.clone(), WriteOptions::default())
        .await
        .expect("the issuing broker emits a sealed continuation");

    let error = foreign
        .continue_write(
            &default_context(),
            address,
            batch.clone(),
            successful_results(&batch),
        )
        .await
        .expect_err("independently generated default keys must stay isolated");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains("continuation seal"));
}
