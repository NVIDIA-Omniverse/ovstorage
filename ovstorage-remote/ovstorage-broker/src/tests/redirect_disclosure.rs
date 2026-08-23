// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The operator's `redirect_credential_disclosure`, at the broker's out-edge.
//!
//! Whether a redirect may be handed to the client is a property of the
//! deployment, not of the credential: a broker is sometimes a central
//! configuration point for clients already inside the trust boundary. So the
//! decision is the operator's, and the code's job is only to tell a
//! request-scoped credential from a broader one — which it cannot do by
//! inspection, since an account-wide signature and an object-scoped one are the
//! same shape on the wire. The minting backend declares it.
//!
//! These tests drive the `test` backend's `test_redirect_credential` knob,
//! which is exactly that declaration, and assert what the broker does with each
//! value on each path.

use super::*;
use ovstorage::RedirectResult;

/// The binding constraint, asserted where both real call sites live.
///
/// The maintainer's requirement is that the policy be **consistent between
/// reads and writes** — symmetry is the constraint, not the default value — so
/// the thing that must not drift is `Broker::guard_read_redirect` against
/// `Broker::write_batch_is_delegable`. Those are two separately written
/// functions with different return types and different error codes, and this
/// crate is the only one that can call both: `ovstorage-plugin-http` has no
/// dependency on any broker crate, so a symmetry test living there could only
/// compare the shared predicate against itself.
///
/// Both settings are walked, because "symmetric" has to hold under `allow`
/// too — a policy that opts in on one path only is exactly the asymmetry this
/// pins against.
#[tokio::test(flavor = "multi_thread")]
async fn the_read_and_write_guards_agree_on_every_declaration() {
    use ovstorage::{
        AccessOps, HttpRequest, ReadRedirect, RedirectBodySource, RedirectCredential,
        RedirectScope, ResponseParsing, ResultCapture, WriteRedirect,
    };

    fn scope(credential: RedirectCredential) -> RedirectScope {
        RedirectScope {
            physical_url_prefix: "https://storage.example/".into(),
            operations: AccessOps {
                read: true,
                write: true,
                ..AccessOps::default()
            },
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(300),
            credential,
        }
    }
    fn request() -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            url: "https://storage.example/object".into(),
            // Inert, so this measures the declaration rather than the backstop.
            headers: vec![("content-type".into(), "text/plain".into())],
        }
    }

    for disclose in [false, true] {
        let broker = BrokerStackFixture::new()
            .test_backend(HashMap::new())
            .redirect_disclosure(disclose)
            .build_broker()
            .await;

        for credential in [
            RedirectCredential::Unspecified,
            RedirectCredential::None,
            RedirectCredential::Request,
            RedirectCredential::Connection,
        ] {
            let read = ReadRedirect {
                request: request(),
                response_parsing: ResponseParsing::default(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(300),
                scope: scope(credential),
                audit_id: "symmetry".into(),
                policy_epoch: 0,
            };
            let batch = WriteRedirectBatch {
                continuation: Vec::new(),
                redirects: vec![WriteRedirect {
                    request: HttpRequest {
                        method: "PUT".into(),
                        ..request()
                    },
                    body_source: RedirectBodySource::UserBytes { offset: 0, len: 0 },
                    result_capture: ResultCapture::default(),
                    expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(300),
                    scope: scope(credential),
                    audit_id: "symmetry".into(),
                    policy_epoch: 0,
                }],
            };

            let read_allows = broker.guard_read_redirect(&read).is_ok();
            let write_allows = broker.write_batch_is_delegable(&batch);
            assert_eq!(
                read_allows,
                write_allows,
                "read and write guards disagreed for {credential:?} with \
                 redirect_credential_disclosure = {}",
                if disclose { "allow" } else { "refuse" }
            );
            // Anti-vacuity: if both guards allowed everything under both
            // settings the equality above would hold while proving nothing.
            assert_eq!(
                read_allows,
                disclose
                    || matches!(
                        credential,
                        RedirectCredential::None | RedirectCredential::Request
                    ),
                "the guards agreed, but not on the expected answer for {credential:?}"
            );
        }

        // The header backstop, on both guards. The rows above use inert headers
        // and so measure only the declaration axis; a write path that passed
        // `&[]` instead of the redirect's own headers would leave every one of
        // them green. This row declares `Request` and attaches an ambient
        // credential, so the only thing that can refuse it is the demotion.
        let credentialed = vec![("Authorization".to_string(), "Bearer wide".to_string())];
        let read = ReadRedirect {
            request: HttpRequest {
                headers: credentialed.clone(),
                ..request()
            },
            response_parsing: ResponseParsing::default(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(300),
            scope: scope(RedirectCredential::Request),
            audit_id: "backstop".into(),
            policy_epoch: 0,
        };
        let batch = WriteRedirectBatch {
            continuation: Vec::new(),
            redirects: vec![WriteRedirect {
                request: HttpRequest {
                    method: "PUT".into(),
                    headers: credentialed,
                    ..request()
                },
                body_source: RedirectBodySource::UserBytes { offset: 0, len: 0 },
                result_capture: ResultCapture::default(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(300),
                scope: scope(RedirectCredential::Request),
                audit_id: "backstop".into(),
                policy_epoch: 0,
            }],
        };
        assert_eq!(
            broker.guard_read_redirect(&read).is_ok(),
            broker.write_batch_is_delegable(&batch),
            "the guards disagreed on a Request declaration demoted by its headers"
        );
        assert_eq!(
            broker.write_batch_is_delegable(&batch),
            disclose,
            "an ambient credential header must demote a `Request` declaration              under `refuse`, and `allow` must still hand it over"
        );

        // The batch quantifier. Every batch above holds one redirect, where
        // `all` and `any` are indistinguishable — and `any` would hand over a
        // batch containing a connection-wide redirect. This one is mixed.
        let mut mixed = batch.clone();
        mixed.redirects[0].scope = scope(RedirectCredential::Request);
        mixed.redirects[0].request.headers.clear();
        let mut wide = mixed.redirects[0].clone();
        wide.scope = scope(RedirectCredential::Connection);
        mixed.redirects.push(wide);
        assert_eq!(mixed.redirects.len(), 2, "the mixed batch must hold both");
        assert_eq!(
            broker.write_batch_is_delegable(&mixed),
            disclose,
            "a batch is delegable only if EVERY redirect in it is; one              connection-wide member must withhold the whole batch under `refuse`"
        );

        drop(broker);
    }
}

/// The declaration a `test`-backend connection mints its redirects with.
fn backend_declaring(credential: &str, parts: i64) -> HashMap<String, ConfigValue> {
    HashMap::from([
        (
            "test_redirect_url".to_string(),
            ConfigValue::String("https://redirect.test.example".into()),
        ),
        (
            "test_redirect_credential".to_string(),
            ConfigValue::String(credential.into()),
        ),
        ("test_multipart_parts".to_string(), ConfigValue::Int(parts)),
    ])
}

fn test_object(name: &str) -> Url {
    address::join_relative(&Url::parse("test://demo/").unwrap(), name).unwrap()
}

/// The write path had no gate at all before this policy existed, so this is the
/// case the operator-visible behaviour change is about.
///
/// `Unsupported` and not `PermissionDenied`: it is the one code the client-side
/// redirect follower turns into a body write through the broker, so the write
/// still completes — proxied — instead of aborting on every client that has not
/// been updated. The assertion is on the code specifically for that reason, and
/// changing it to a "better" name is the regression this pins.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_scoped_write_redirect_is_refused_under_the_default() {
    let broker = BrokerStackFixture::new()
        .test_backend(backend_declaring("connection", 2))
        .build_broker()
        .await;

    let error = broker
        .write_redirect(
            &default_context(),
            test_object("wide.bin"),
            WriteOptions::default(),
        )
        .await
        .expect_err("a connection-scoped write redirect must not be handed over");
    assert_eq!(error.code(), ErrorCode::Unsupported);

    drop(broker);
}

/// The same backend, the same redirect, one operator key different. Without
/// this arm the refusal above would be satisfied by a broker that refuses
/// everything.
#[tokio::test(flavor = "multi_thread")]
async fn the_operator_can_opt_in_to_the_same_write_redirect() {
    let broker = BrokerStackFixture::new()
        .test_backend(backend_declaring("connection", 2))
        .redirect_disclosure(true)
        .build_broker()
        .await;

    let batch = broker
        .write_redirect(
            &default_context(),
            test_object("wide.bin"),
            WriteOptions::default(),
        )
        .await
        .expect("`allow` hands over the batch the default refuses");
    assert_eq!(batch.redirects.len(), 2);

    drop(broker);
}

/// A redirect scoped to the redirected request is handed over under **both**
/// settings. These are the reason redirects exist, and a policy that withheld
/// them would cost every deployment the redirect path in exchange for nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_scoped_write_redirect_is_handed_over_under_the_default() {
    let broker = BrokerStackFixture::new()
        .test_backend(backend_declaring("request", 2))
        .build_broker()
        .await;

    let batch = broker
        .write_redirect(
            &default_context(),
            test_object("narrow.bin"),
            WriteOptions::default(),
        )
        .await
        .expect("a request-scoped redirect is delegable under the default");
    assert_eq!(batch.redirects.len(), 2);

    drop(broker);
}

/// `Unspecified` is fail-safe, not neutral.
///
/// It is the zero discriminant and the value a backend that copies a header set
/// it did not mint honestly declares — the services client and OpenDAL both do.
/// A host that treated "did not say" as "nothing to worry about" would disclose
/// precisely the credentials nobody could classify.
#[tokio::test(flavor = "multi_thread")]
async fn an_unspecified_declaration_is_refused_rather_than_waved_through() {
    let broker = BrokerStackFixture::new()
        .test_backend(backend_declaring("unspecified", 1))
        .build_broker()
        .await;

    let error = broker
        .write_redirect(
            &default_context(),
            test_object("unknown.bin"),
            WriteOptions::default(),
        )
        .await
        .expect_err("an unclassified credential must not be handed over");
    assert_eq!(error.code(), ErrorCode::Unsupported);

    drop(broker);
}

/// The second-round exit, which a first-round-only gate would miss.
///
/// A multi-round upload can return a further batch from `continue_write`, and
/// that batch has not been handed over yet. Round one was forwarded *because*
/// it declared a request-scoped credential, so the client holds nothing broader
/// than one object; refusing a later round that declares `connection` therefore
/// prevents a real disclosure rather than closing a door the client is already
/// through.
///
/// The fixture makes rounds differ in declaration by rebuilding the backend
/// between them, which no in-tree backend does — for all of them the
/// declaration is a property of the connection's auth mode. That is the point:
/// this gate exists for a plugin that changes mechanism mid-upload, and only a
/// fixture that changes mechanism mid-upload can exercise it.
#[tokio::test(flavor = "multi_thread")]
async fn a_later_round_declaring_a_broader_credential_is_refused() {
    // Round one: request-scoped, so the batch is handed over.
    let permissive = BrokerStackFixture::new()
        .test_backend({
            let mut config = backend_declaring("request", 1);
            config.insert("test_continue_write_loops".into(), ConfigValue::Int(2));
            config
        })
        .build_broker()
        .await;
    let address = test_object("multi.bin");
    let batch = permissive
        .write_redirect(&default_context(), address.clone(), WriteOptions::default())
        .await
        .expect("round one is request-scoped and delegable");
    assert_eq!(batch.redirects.len(), 1);

    // The same upload, continued against a broker whose backend now declares
    // the broader credential: the second round is refused, and hard, because
    // there is no graceful answer mid-upload.
    let hardened = BrokerStackFixture::new()
        .test_backend({
            let mut config = backend_declaring("connection", 1);
            config.insert("test_continue_write_loops".into(), ConfigValue::Int(2));
            config
        })
        .build_broker()
        .await;
    let results = RedirectResultBatch {
        results: batch
            .redirects
            .iter()
            .map(|_| RedirectResult {
                status_code: 200,
                captured_headers: vec![("etag".into(), "abc".into())],
                captured_body: vec![],
            })
            .collect(),
    };
    let error = hardened
        .continue_write(&default_context(), address, batch, results)
        .await
        .expect_err("a later round declaring a broader credential must be refused");
    assert_eq!(error.code(), ErrorCode::PermissionDenied);

    drop(permissive);
    drop(hardened);
}

/// The read path answers with the same declaration and the same key.
///
/// The stock broker's follower runs `follow_reads = true`, so it fetches the
/// bytes itself and the client gets a stream — the refusal is invisible and
/// costs a proxied transfer, not a read outage. What this asserts is that the
/// client does **not** get the redirect.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_scoped_read_redirect_is_served_as_bytes_not_handed_over() {
    let (responder, redirect_kv) = ovstorage_plugin_test::start_responder_with_redirect(vec![
        ovstorage_plugin_test::Route::new(
            "GET",
            "/",
            ovstorage_plugin_test::ScriptedResponse::ok(b"redirected bytes"),
        ),
    ])
    .expect("loopback responder binds");
    let config = HashMap::from([
        (redirect_kv.0.to_string(), redirect_kv.1),
        (
            "test_redirect_credential".to_string(),
            ConfigValue::String("connection".into()),
        ),
    ]);

    let broker = BrokerStackFixture::new()
        .test_backend(config)
        .build_broker()
        .await;

    match broker
        .read(
            &default_context(),
            test_object("redirected.bin"),
            ReadOptions::default(),
        )
        .await
        .expect("a refused read redirect still reads")
    {
        BrokerReadOutcome::Redirect(_) => {
            panic!("a connection-scoped read redirect was handed to the client")
        }
        BrokerReadOutcome::Bytes { .. } | BrokerReadOutcome::Stream { .. } => {}
    }
    assert!(
        !responder.captures().is_empty(),
        "the broker must have fetched the bytes itself; an empty capture list means \
         the fixture never redirected and this test proved nothing"
    );

    drop(broker);
    drop(responder);
}

/// `Broker::read`'s own out-edge guard, with nothing upstream that could also
/// catch the redirect.
///
/// The stock-graph read test above passes as soon as *something* withholds the
/// redirect, and the follower gets there first — so on its own it says nothing
/// about the broker's copy of the check. The layer graph is operator config and
/// can omit the follower entirely; this builds exactly that graph, which is the
/// case the second enforcement point exists for.
///
/// There are no bytes in reach here — the layer that would have fetched them is
/// not in the graph — so this refuses rather than degrading, and with
/// `PermissionDenied` rather than the `Unsupported` the write path uses, because
/// there is no read-side fallback for a client to take.
#[tokio::test(flavor = "multi_thread")]
async fn the_broker_refuses_a_read_redirect_when_no_follower_is_in_the_graph() {
    let (responder, redirect_kv) = ovstorage_plugin_test::start_responder_with_redirect(vec![
        ovstorage_plugin_test::Route::new(
            "GET",
            "/",
            ovstorage_plugin_test::ScriptedResponse::ok(b"bytes nobody should reach"),
        ),
    ])
    .expect("loopback responder binds");
    let config = HashMap::from([
        (redirect_kv.0.to_string(), redirect_kv.1),
        (
            "test_redirect_credential".to_string(),
            ConfigValue::String("connection".into()),
        ),
    ]);

    let broker = BrokerStackFixture::new()
        .test_backend(config)
        .without_a_follower()
        .build_broker()
        .await;

    let error = broker
        .read(
            &default_context(),
            test_object("no-follower.bin"),
            ReadOptions::default(),
        )
        .await
        .expect_err("with no follower to fetch the bytes, the guard must refuse");
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert!(
        responder.captures().is_empty(),
        "the broker fetched the object anyway; this graph has no follower, so a \
         non-empty capture list means the fixture is not the shape the test needs"
    );

    drop(broker);
    drop(responder);
}

/// The same follower-less graph, request-scoped: the broker forwards it.
/// Without this arm the refusal above would be satisfied by a graph that simply
/// cannot serve redirects at all.
#[tokio::test(flavor = "multi_thread")]
async fn the_broker_forwards_a_request_scoped_redirect_with_no_follower_present() {
    let (responder, redirect_kv) = ovstorage_plugin_test::start_responder_with_redirect(vec![
        ovstorage_plugin_test::Route::new(
            "GET",
            "/",
            ovstorage_plugin_test::ScriptedResponse::ok(b"delegable bytes"),
        ),
    ])
    .expect("loopback responder binds");
    let config = HashMap::from([
        (redirect_kv.0.to_string(), redirect_kv.1),
        (
            "test_redirect_credential".to_string(),
            ConfigValue::String("request".into()),
        ),
    ]);

    let broker = BrokerStackFixture::new()
        .test_backend(config)
        .without_a_follower()
        .build_broker()
        .await;

    match broker
        .read(
            &default_context(),
            test_object("no-follower-narrow.bin"),
            ReadOptions::default(),
        )
        .await
        .expect("a request-scoped redirect is delegable under the default")
    {
        BrokerReadOutcome::Redirect(_) => {}
        other => panic!("expected the redirect to be forwarded, got {other:?}"),
    }

    drop(broker);
    drop(responder);
}

/// The oversize follow arm, which is the arm whose behaviour actually changed.
///
/// This is the shape the stock broker runs: `follow_reads = true` with a size
/// cap. Every other test here exercises the *pass-through* arm
/// (`follow_reads = false`), so without this one the arm that changed had no
/// direct coverage and the neighbouring arm was standing in for it.
///
/// What changed: an oversize read whose redirect the policy will not delegate
/// used to return `PermissionDenied`. The follower is holding an open, already
/// credentialed stream at that point and was discarding it. It now serves those
/// bytes. The size cap decides what is worth putting in the byte cache, not
/// what is readable — so a connection whose redirects are non-delegable must not
/// lose reads above the cap, which for the shipped broker is 1 MiB.
#[tokio::test(flavor = "multi_thread")]
async fn an_oversize_non_delegable_read_serves_bytes_instead_of_refusing() {
    let body = vec![b'x'; 4096];
    let (responder, redirect_kv) = ovstorage_plugin_test::start_responder_with_redirect(vec![
        ovstorage_plugin_test::Route::new(
            "GET",
            "/",
            ovstorage_plugin_test::ScriptedResponse::ok(&body),
        ),
    ])
    .expect("loopback responder binds");
    let config = HashMap::from([
        (redirect_kv.0.to_string(), redirect_kv.1),
        (
            "test_redirect_credential".to_string(),
            ConfigValue::String("connection".into()),
        ),
    ]);

    let cache_root = unique_temp_dir();
    let broker = BrokerStackFixture::new()
        .test_backend(config)
        .byte_cache(std::sync::Arc::new(
            ovstorage_cache::Cache::open(ovstorage_cache::CacheConfig {
                state_root: cache_root.join("state"),
                cache_root: cache_root.join("cache"),
            })
            .unwrap(),
        ))
        // A byte cache plus a cap is what puts the single follower into
        // `follow_reads = true`. The cap is far below the object, so this read
        // takes the oversize branch rather than the follow-and-tee one.
        .follow_cap(Some(64))
        .build_broker()
        .await;

    let outcome = broker
        .read(
            &default_context(),
            test_object("oversize.bin"),
            ReadOptions::default(),
        )
        .await
        .expect("an oversize non-delegable read must serve bytes, not refuse");

    let served = match outcome {
        BrokerReadOutcome::Bytes { bytes, .. } => bytes.len(),
        BrokerReadOutcome::Stream { stream, .. } => {
            use futures::StreamExt;
            let mut stream = stream;
            let mut total = 0usize;
            while let Some(chunk) = stream.next().await {
                total += chunk.expect("the served stream must not error").len();
            }
            total
        }
        BrokerReadOutcome::Redirect(_) => {
            panic!("a connection-scoped redirect was handed to the client")
        }
    };
    assert_eq!(served, body.len(), "the whole object must be served");
    assert!(
        !responder.captures().is_empty(),
        "the follower must have fetched the object; an empty capture list means \
         the fixture never redirected and this test proved nothing"
    );

    drop(broker);
    drop(responder);
}
