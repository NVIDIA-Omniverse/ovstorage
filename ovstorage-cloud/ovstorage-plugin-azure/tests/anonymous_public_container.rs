// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What an anonymous Azure connection can serve against a public container.
//!
//! Azure containers carry a public-access level, and it has two useful values:
//! *blob* permits an anonymous read of a blob but **not** enumeration, while
//! *container* permits both. So "anonymous read works and anonymous list does
//! not" is a configuration an operator deliberately chooses here, not an edge
//! case — and the plugin has to be able to issue the list in order for the
//! service to be the one that decides.
//!
//! It can, and always could: [`AzureClient::send`]'s `AuthSource::Anonymous`
//! arm simply adds no `Authorization` header, and the only operations that
//! branch on anonymity are the delegated-write pair — `write_redirect`, which
//! needs a SAS to delegate, and `continue_write`, which only runs after one.
//!
//! These tests pin that, because the property is easy to lose and costs
//! nothing to hold here: azure's anonymity is a no-op branch in one hand-rolled
//! client, whereas the s3 sibling reaches its store through an SDK that wants a
//! credentials provider and so has to construct an unsigned client explicitly.
//! A plugin in that shape can lose anonymous `list` by omission. This one
//! cannot, and nothing in this file changes azure behaviour.

use ovstorage_plugin::{
    ErrorCode, ListOptions, ObjectKind, RedirectResult, RedirectResultBatch, SecretBundle,
    StatOptions,
};

mod support;
use support::{
    Capture, CapturedRequest, FakeAzure, ProbeResponse, build_backend_with_endpoint,
    spawn_capture_server, spawn_fake_azure, spawn_stat_probe_server, target,
};

const ACCOUNT: &str = "acct";
const CONTAINER: &str = "bkt";

/// One blob and one virtual directory, the two arms of the plugin's list
/// mapping.
const PUBLIC_LIST_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="http://127.0.0.1/" ContainerName="bkt">
  <Prefix>assets/</Prefix>
  <Delimiter>/</Delimiter>
  <Blobs>
    <Blob>
      <Name>assets/teapot.usd</Name>
      <Properties>
        <Last-Modified>Fri, 02 Jan 2026 03:04:05 GMT</Last-Modified>
        <Etag>0x9A1F2B</Etag>
        <Content-Length>2048</Content-Length>
      </Properties>
    </Blob>
    <BlobPrefix>
      <Name>assets/textures/</Name>
    </BlobPrefix>
  </Blobs>
  <NextMarker />
</EnumerationResults>"#;

/// Build an anonymous backend against a loopback fixture. An empty
/// `SecretBundle` resolves to `AuthSource::Anonymous` from the bundle alone —
/// `azure::auth::resolve_source` reads no environment — so this is
/// deterministic wherever the suite runs.
fn anonymous_backend(endpoint: &str) -> std::sync::Arc<ovstorage_plugin_azure::AzureBackend> {
    let mut config = std::collections::HashMap::new();
    config.insert(
        "account".into(),
        ovstorage_plugin::ConfigValue::String(ACCOUNT.into()),
    );
    config.insert(
        "container".into(),
        ovstorage_plugin::ConfigValue::String(CONTAINER.into()),
    );
    let parsed =
        ovstorage_plugin_azure::__test_only_parse_config(&config).expect("parse azure config");
    let parsed =
        ovstorage_plugin_azure::__test_only_with_endpoint_override(parsed, endpoint.to_string())
            .expect("endpoint override");
    std::sync::Arc::new(
        ovstorage_plugin_azure::__test_only_with_credentials(parsed, SecretBundle::default())
            .expect("anonymous backend init"),
    )
}

fn only_request(capture: &Capture) -> CapturedRequest {
    let mut requests = capture.snapshot();
    assert_eq!(requests.len(), 1, "exactly one request was issued");
    requests.remove(0)
}

/// A *container*-level public container answers the enumeration, and the
/// plugin issues it with no `Authorization` header.
#[tokio::test]
async fn an_anonymous_connection_lists_a_public_container() {
    let (endpoint, capture) = spawn_stat_probe_server(ProbeResponse::ok(PUBLIC_LIST_BODY));
    let backend = anonymous_backend(&endpoint);

    let items = backend
        .list(
            target(ACCOUNT, CONTAINER, "assets/"),
            ListOptions::default(),
            None,
        )
        .await
        .expect("an anonymous list of a container-public container must succeed");

    let listing = only_request(&capture);
    assert!(
        !listing.has_header("authorization"),
        "an anonymous list must carry no Authorization header; got: {}",
        listing.raw
    );
    let line = listing.raw.split("\r\n").next().unwrap_or("");
    assert!(
        line.contains("restype=container"),
        "container scope: {line}"
    );
    assert!(line.contains("comp=list"), "enumeration: {line}");
    assert!(line.contains("prefix=assets%2F"), "prefix-scoped: {line}");
    assert!(line.contains("delimiter=%2F"), "one level: {line}");

    assert_eq!(items.len(), 2, "one blob and one virtual directory");
    let blob = items
        .iter()
        .find(|item| item.address.as_str().ends_with("assets/teapot.usd"))
        .expect("the blob is returned under its own address");
    assert_eq!(blob.kind, ObjectKind::File);
    assert_eq!(blob.size, Some(2048));
    assert!(blob.mtime.is_some(), "Last-Modified is carried through");
    let directory = items
        .iter()
        .find(|item| item.address.as_str().ends_with("assets/textures/"))
        .expect("the BlobPrefix is returned as a directory");
    assert_eq!(directory.kind, ObjectKind::DirectoryInferred);
}

/// The control: with a Shared Key the identical operation against the identical
/// fixture DOES sign. Without it, "no Authorization header" would also pass
/// against a build where signing had been removed for every connection.
#[tokio::test]
async fn a_shared_key_connection_still_signs_its_list() {
    let (endpoint, capture) = spawn_stat_probe_server(ProbeResponse::ok(PUBLIC_LIST_BODY));
    let backend = build_backend_with_endpoint(ACCOUNT, CONTAINER, &endpoint);

    backend
        .list(
            target(ACCOUNT, CONTAINER, "assets/"),
            ListOptions::default(),
            None,
        )
        .await
        .expect("a Shared Key list must succeed");

    let authorization = only_request(&capture)
        .header_value("authorization")
        .expect("a Shared Key list is signed");
    assert!(
        authorization.starts_with("SharedKey "),
        "Shared Key, not something else: {authorization}"
    );
}

/// `stat` on a public blob is an unsigned `Get Blob Properties` HEAD, and the
/// metadata comes back parsed.
///
/// The responder is written here rather than reusing `spawn_capture_server`,
/// which answers `202` with no blob headers — enough to assert what a request
/// carried, not enough to assert what came back.
#[tokio::test]
async fn an_anonymous_connection_stats_a_public_blob() {
    let fake = spawn_blob_properties_server();
    let backend = anonymous_backend(&fake.endpoint);

    let info = backend
        .stat(
            target(ACCOUNT, CONTAINER, "assets/teapot.usd"),
            StatOptions::default(),
            None,
        )
        .await
        .expect("an anonymous stat of a public blob must succeed");

    let head = only_request(&fake.capture);
    assert!(
        !head.has_header("authorization"),
        "an anonymous stat must carry no Authorization header; got: {}",
        head.raw
    );
    assert!(
        head.raw.starts_with("HEAD /bkt/assets/teapot.usd"),
        "a plain HEAD on the blob: {}",
        head.raw.split("\r\n").next().unwrap_or("")
    );
    assert_eq!(info.kind, ObjectKind::File);
    assert_eq!(info.size, Some(2048));
    assert_eq!(info.etag.as_deref(), Some("0x9A1F2B"));
    assert!(info.mtime.is_some(), "Last-Modified is carried through");
}

/// A loopback fixture answering one `Get Blob Properties` the way Azure does,
/// built on the shared `spawn_fake_azure` rather than a private listener.
///
/// `signer: None` because this file's whole subject is a request that carries
/// no `Authorization` header: a signing fixture answers 403 to an unsigned
/// request, which is the opposite of what these tests assert. With no signer
/// every request is recorded `SharedKeyVerdict::NotChecked` and handed to the
/// responder, and the assertion that matters — the absence of the header — is
/// read off the raw request, which needs no key to judge.
fn spawn_blob_properties_server() -> FakeAzure {
    spawn_fake_azure("anonymous-blob-properties", None, |_raw| {
        "HTTP/1.1 200 OK\r\n\
         Connection: close\r\n\
         x-ms-request-id: 5e4d6c0e-201e-0042-3a1f-1f0b7c000000\r\n\
         x-ms-blob-type: BlockBlob\r\n\
         ETag: \"0x9A1F2B\"\r\n\
         Last-Modified: Fri, 02 Jan 2026 03:04:05 GMT\r\n\
         Content-Type: model/vnd.usd\r\n\
         Content-Length: 2048\r\n\r\n"
            .to_string()
    })
}

/// A *blob*-level public container permits the anonymous read but refuses the
/// enumeration, and Azure — not the plugin — is what refuses it. The plugin's
/// contract here is that the request reaches the service at all and the
/// service's own verdict is what the caller sees, carrying the provider error
/// code Azure names it with.
///
/// The status Azure attaches to that refusal could not be verified from this
/// environment, so the test drives both plausible statuses and asserts what the
/// plugin makes of each rather than asserting which one Azure sends.
///
/// The provider codes below are placeholders chosen to be distinguishable, not
/// researched claims about what Azure returns — `map_status_to_error` branches
/// on the status line alone, so the code is carried into the message and
/// decides nothing. Deliberately NOT used: `AuthorizationPermissionMismatch`,
/// whose meaning in this crate is "the caller was identified and then found to
/// be scoped" (`client.rs`, `AUTHORIZATION_SCOPE_CODES`) — the one property an
/// anonymous request cannot have — and `AuthenticationFailed`, which
/// `CREDENTIAL_REJECTION_CODES` reads as a refused credential.
///
/// **Note what the `404` arm shows**, because it is the operationally
/// important half: an anonymous enumeration refused that way reaches the caller
/// as `NotFound`. Azure declines to disclose that a container exists to a
/// principal not permitted to enumerate it, so "the listing was refused" and
/// "the container is not there" are the same answer on the wire and the plugin
/// cannot separate them. The `x-ms-error-code` in the message is the only thing
/// that distinguishes them, which is why the assertion below is on it.
#[tokio::test]
async fn a_container_that_forbids_anonymous_listing_is_refused_by_the_service() {
    for (status, reason, code, expected) in [
        (
            403u16,
            "Forbidden",
            "PublicAccessNotPermitted",
            ErrorCode::PermissionDenied,
        ),
        (
            404u16,
            "Not Found",
            "ContainerNotFound",
            ErrorCode::NotFound,
        ),
    ] {
        let (endpoint, capture) = spawn_stat_probe_server(
            ProbeResponse::failure(status, reason, String::new())
                .with_header(format!("x-ms-error-code: {code}")),
        );
        let backend = anonymous_backend(&endpoint);

        let err = backend
            .list(
                target(ACCOUNT, CONTAINER, "assets/"),
                ListOptions::default(),
                None,
            )
            .await
            .expect_err("the service refuses the enumeration");

        assert_eq!(
            capture.snapshot().len(),
            1,
            "the plugin issued the request rather than refusing it locally"
        );
        assert_eq!(err.code(), expected, "status {status}: {err}");
        assert!(
            err.message().contains(code),
            "the provider error code is the only thing separating a refused \
             enumeration from an absent container: {}",
            err.message()
        );
    }
}

/// `continue_write` self-gates on an anonymous connection, and this is the only
/// thing standing between a fabricated continuation and a reported write that
/// never happened.
///
/// An anonymous connection withholds `supports_write_redirect`, and
/// `continue_write` has no bit of its own — `CONFORMANCE.md` gates it
/// implicitly by the same one, since it only runs after a redirect. A withheld
/// bit in front of a slot that still runs is the half-measure the self-gate
/// rule forbids outright.
///
/// **The batch is minted by a CREDENTIALED backend and then presented to the
/// anonymous one**, which is the reachable shape: on the broker's client-driven
/// `ContinueWrite` route the whole batch is echoed back by a remote caller, and
/// nothing stops that caller presenting a well-formed one. It has to be
/// well-formed to test anything — a hand-built batch with no redirects is
/// refused by `validate_redirect_results`' cardinality check before control
/// reaches the guard, so it would pin `InvalidArgument` rather than the
/// refusal, and its "no request issued" assertion would hold on both sides.
///
/// With a real single-`Put Blob` batch the arm below the guard commits from
/// `results.results.first()`'s captured headers and contacts no store at all,
/// so removing the guard returns `WriteStep::Done` for a blob nobody wrote.
#[tokio::test]
async fn continue_write_is_refused_on_an_anonymous_connection() {
    let (endpoint, capture, _counter) = spawn_capture_server();
    // Under Azure's 256 MiB staged threshold, so `write_redirect` emits the
    // single-`Put Blob` form whose response is itself the commit.
    let minted = build_backend_with_endpoint(ACCOUNT, CONTAINER, &endpoint)
        .write_redirect(
            target(ACCOUNT, CONTAINER, "assets/teapot.usd"),
            ovstorage_plugin::WriteOptions {
                size_hint: Some(2048),
                ..ovstorage_plugin::WriteOptions::default()
            },
            None,
        )
        .await
        .expect("a credentialed connection mints the batch");
    assert_eq!(minted.redirects.len(), 1, "the single-Put Blob form");

    let results = RedirectResultBatch {
        results: vec![RedirectResult {
            status_code: 201,
            captured_headers: vec![
                ("etag".into(), "\"fabricated\"".into()),
                (
                    "last-modified".into(),
                    "Fri, 02 Jan 2026 03:04:05 GMT".into(),
                ),
            ],
            captured_body: Vec::new(),
        }],
    };

    let before = capture.snapshot().len();
    let err = anonymous_backend(&endpoint)
        .continue_write(
            target(ACCOUNT, CONTAINER, "assets/teapot.usd"),
            minted,
            results,
            None,
            None,
        )
        .await
        .expect_err("an anonymous connection issues no unsigned mutation");

    assert_eq!(
        err.code(),
        ErrorCode::Unsupported,
        "the withheld capability's own code, not a complaint about the batch: {err}"
    );
    assert_eq!(
        capture.snapshot().len(),
        before,
        "and it refused before doing anything further"
    );
}
