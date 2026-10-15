// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Two-principal isolation through the broker.
//!
//! The broker gathers each caller's credential at one seam
//! (`Broker::credential_req`, setting `ext::AUTH_CREDENTIAL`); the per-listener
//! auth layer resolves it to a principal and stamps `ext::PRINCIPAL_ID` DOWN, so
//! the in-stack metadata-cache wrapper scopes its fills per principal.
//! These tests mirror the core-side `stack_list_scopes_metadata_fills_by_principal`
//! but at the broker / [`RequestContext`] level with distinct Uds peer
//! credentials resolving to distinct `uid:{uid}` principals: one principal's
//! metadata fills must never serve another's — the other pays a fresh backend
//! hit. They cover the two per-principal-scoped fill paths: the **list** fill
//! and the **continue_write** follow-up stat.
//!
//! Observability comes from the `test` fixture backend's per-method counters
//! (`test://demo/__test_meta/method_calls.json`); reading that introspection
//! object bumps only the `read` counter, so `list` / `stat` counts stay a clean
//! signal.

use ovstorage::MetadataCacheConfig;
use ovstorage_authz_context::{AuthCredential, Transport};

use super::*;

/// A request context whose Uds peer credential resolves, in the built-in auth
/// layer, to a distinct `uid:{uid}` principal per `uid`.
fn ctx(uid: u32) -> RequestContext {
    RequestContext {
        credential: Some(AuthCredential::new(
            None,
            Transport::Uds {
                uid,
                gid: uid,
                pid: 0,
            },
        )),
        audit_id: None,
    }
}

/// Read the `test` backend's per-method counters through the composed Stack.
/// The introspection read bumps only `read`, leaving `list` / `stat` clean.
async fn method_counters(stack: &ovstorage::Stack, counter: &str) -> u64 {
    use ovstorage::{Layer, ReadRequest, ReadResult, Request};
    let probe = address::parse("test://demo/__test_meta/method_calls.json").unwrap();
    let read = stack
        .read(
            Request::new(ReadRequest {
                address: probe,
                options: Default::default(),
            }),
            None,
        )
        .await
        .expect("read test counters");
    let bytes = match read {
        ReadResult::Bytes { bytes, .. } => bytes,
        other => panic!("expected Bytes for the counter probe, got {other:?}"),
    };
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("counters json parses");
    json[counter].as_u64().expect("counter is a u64")
}

/// A `list` fill under alice's principal serves alice's later stat from cache,
/// but bob — a different `ctx.principal` — is not served alice's listing and
/// pays a fresh backend stat. Proves `credential_req` scopes the in-stack
/// metadata cache per principal on the **list** path.
#[tokio::test(flavor = "multi_thread")]
async fn broker_list_fill_is_scoped_per_principal() {
    let stack = BrokerStackFixture::new()
        .test_backend(HashMap::new())
        .metadata_cache(Arc::new(
            MetadataCache::new(&MetadataCacheConfig::default()),
        ))
        .build_stack()
        .await;
    let broker = Broker::new(stack.clone());

    let prefix = Url::parse("test://demo/").unwrap();
    let object = address::join_relative(&prefix, "scoped.txt").unwrap();
    // The object must exist so the listing carries it as a File item.
    broker
        .write(
            &ctx(1001),
            object.clone(),
            Body::Bytes(b"scoped bytes".to_vec()),
            WriteOptions::default(),
        )
        .await
        .unwrap();

    // alice lists the prefix: one backend list, filling alice's scope.
    broker
        .list(&ctx(1001), prefix.clone(), Default::default())
        .await
        .unwrap();
    assert_eq!(method_counters(&stack, "list").await, 1);
    let stat_after_list = method_counters(&stack, "stat").await;

    // alice's stat is served from her list-filled scope: no backend stat.
    broker
        .stat(&ctx(1001), object.clone(), StatOptions::default())
        .await
        .unwrap();
    assert_eq!(
        method_counters(&stack, "stat").await,
        stat_after_list,
        "alice's stat must be served from her own list fill"
    );
    assert_eq!(method_counters(&stack, "list").await, 1);

    // bob is a different principal: he is not served alice's listing and pays a
    // fresh backend stat under his own (empty) scope.
    broker
        .stat(&ctx(1002), object, StatOptions::default())
        .await
        .unwrap();
    assert_eq!(
        method_counters(&stack, "stat").await,
        stat_after_list + 1,
        "bob must not be served alice's cached listing"
    );

    drop(broker);
}

/// The backend-emitted write-redirect protocol finalizes through the stack:
/// alice's `write_redirect` → executed redirect targets → `continue_write`
/// commits the object as it traverses the in-stack metadata-cache wrapper (no
/// host-side redirect manufacturing — the `test` backend emits the batch). A
/// stat after that finalize fills only the actor's scope: alice's later stat
/// hits, but bob — a different `ctx.principal` — is not served alice's fill and
/// pays a fresh backend stat. Proves `credential_req` scopes the metadata cache
/// per principal on the **continue_write** path, closing the cross-principal
/// leak.
#[tokio::test(flavor = "multi_thread")]
async fn broker_continue_write_stat_is_scoped_per_principal() {
    // `test_redirect_url` + a single multipart part make `write_redirect` emit
    // a real backend batch that `continue_write` finalizes in one step; the
    // bytes flow through the redirect URL (never fetched at this broker-unit
    // level), so the plugin commits an empty placeholder object.
    let mut test_cfg = HashMap::new();
    test_cfg.insert(
        "test_redirect_url".into(),
        ConfigValue::String("file:///tmp/ovstorage-cw-scope-unused/".into()),
    );
    test_cfg.insert("test_multipart_parts".into(), ConfigValue::Int(1));
    let stack = BrokerStackFixture::new()
        .test_backend(test_cfg)
        .metadata_cache(Arc::new(
            MetadataCache::new(&MetadataCacheConfig::default()),
        ))
        .build_stack()
        .await;
    let broker = Broker::new(stack.clone());

    let prefix = Url::parse("test://demo/").unwrap();
    let object = address::join_relative(&prefix, "cw.txt").unwrap();

    // alice drives the backend-emitted protocol to finalize the object.
    let batch = broker
        .write_redirect(&ctx(1001), object.clone(), WriteOptions::default())
        .await
        .unwrap();
    let results = RedirectResultBatch {
        results: batch
            .redirects
            .iter()
            .map(|_| ovstorage::RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: Vec::new(),
            })
            .collect(),
    };
    let step = broker
        .continue_write(&ctx(1001), object.clone(), batch, results)
        .await
        .unwrap();
    assert!(
        matches!(step, ovstorage::WriteStep::Done(_)),
        "single-part continue_write finalizes in one step"
    );

    // The finalize invalidated the wrapper's entries for this address; alice's
    // first stat pays a fresh backend stat and fills her scope.
    let stat_before = method_counters(&stack, "stat").await;
    broker
        .stat(&ctx(1001), object.clone(), StatOptions::default())
        .await
        .unwrap();
    let stat_after_alice_fill = method_counters(&stack, "stat").await;
    assert_eq!(
        stat_after_alice_fill,
        stat_before + 1,
        "alice's post-finalize stat pays one backend stat and fills her scope"
    );

    // alice's next stat is served from her own fill: no backend stat.
    broker
        .stat(&ctx(1001), object.clone(), StatOptions::default())
        .await
        .unwrap();
    assert_eq!(
        method_counters(&stack, "stat").await,
        stat_after_alice_fill,
        "alice's stat stays served from her own fill"
    );

    // bob is a different principal: not served alice's fill, pays a fresh stat.
    broker
        .stat(&ctx(1002), object, StatOptions::default())
        .await
        .unwrap();
    assert_eq!(
        method_counters(&stack, "stat").await,
        stat_after_alice_fill + 1,
        "bob must not be served alice's continue_write-path fill"
    );

    drop(broker);
}
