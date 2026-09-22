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
//!
//! The second half of the file is the anonymous **scheme fallback**: the same
//! unsigned wire, reached without any connection at all when the layer table
//! grants `anonymous_fallback = ["azure"]`. Those tests drive the whole
//! `Layer` rather than a bare backend, because the fallback is a routing fact
//! the layer owns. The ambient-credential test among them runs in a filtered
//! child process that owns its environment, so no `set_var` can race another
//! test's client construction in this binary.

use std::process::Command;

use ovstorage_plugin::{
    Body, ConfigValue, ContinueWriteRequest, CopyOptions, CopyRequest, CreateDirectoryOptions,
    CreateDirectoryRequest, DeleteDirectoryOptions, DeleteDirectoryRequest, DeleteOptions,
    DeleteRequest, ErrorCode, LayerHandle, ListOptions, ObjectKind, RedirectResult,
    RedirectResultBatch, RenameOptions, RenameRequest, Request, SecretBundle, StatOptions,
    StatRequest, UpdateMetadataOptions, UpdateMetadataRequest, WatchDirectoryOptions,
    WatchDirectoryRequest, WriteOptions, WriteRedirectBatch, WriteRequest, address,
};

mod support;
use support::{
    Capture, CapturedRequest, FakeAzure, ProbeResponse, build_backend_with_endpoint, capture_logs,
    fallback_layer, spawn_capture_server, spawn_fake_azure, spawn_stat_probe_server, target,
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
/// anonymous one**, which is the reachable shape for a direct SPI caller or an
/// unsealed host. The broker authenticates the continuation on its client-driven
/// route but does not bind it to a principal, so a genuine same-address batch is
/// not an authentication substitute there either. The batch has to be
/// well-formed to test anything — a hand-built batch with no redirects is
/// refused by `validate_redirect_results`' cardinality check before control
/// reaches the guard, so it would pin `InvalidArgument` rather than the refusal,
/// and its "no request issued" assertion would hold on both sides.
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

// === The anonymous scheme fallback on the wire ===

const FALLBACK_BUILT: &str = "anonymous fallback backend built";

/// Set in the child process that owns the ambient-credential environment.
const CHILD_MODE: &str = "OVSTORAGE_AZURE_FALLBACK_ENV_CHILD";
/// The parent's fake blob endpoint, handed to the child.
const CHILD_ENDPOINT: &str = "OVSTORAGE_AZURE_FALLBACK_ENV_ENDPOINT";
/// Printed by the child once its assertions have actually run, so a filter
/// matching no test — libtest exits 0 — cannot pass the parent vacuously.
const FALLBACK_ENV_SENTINEL: &str = "FALLBACK_ENV_ASSERTED";

fn addr(account: &str, container: &str, key: &str) -> ovstorage_plugin::Url {
    address::parse(&format!("azure://{account}/{container}/{key}")).unwrap()
}

async fn layer_stat(
    layer: &LayerHandle,
    address: ovstorage_plugin::Url,
) -> ovstorage_plugin::Result<ovstorage_plugin::ObjectInfo> {
    layer
        .stat(
            Request::new(StatRequest {
                address,
                options: StatOptions::default(),
            }),
            None,
        )
        .await
}

/// Every mutating slot's shape, so the refusal tests drive each one the same
/// way and a slot added to the trait has an obvious place to be listed.
async fn every_mutation(
    layer: &LayerHandle,
    source: ovstorage_plugin::Url,
    destination: ovstorage_plugin::Url,
) -> Vec<(&'static str, ovstorage_plugin::Result<()>)> {
    let write = |body: Body| WriteRequest {
        address: source.clone(),
        body,
        options: WriteOptions::default(),
    };
    vec![
        (
            "write",
            layer
                .write(Request::new(write(Body::Bytes(b"hello".to_vec()))), None)
                .await
                .map(|_| ()),
        ),
        (
            "write_stream",
            layer
                .write_stream(Request::new(write(Body::Bytes(b"hello".to_vec()))), None)
                .await
                .map(|_| ()),
        ),
        (
            "write_redirect",
            layer
                .write_redirect(
                    Request::new(WriteRequest {
                        address: source.clone(),
                        body: Body::Bytes(Vec::new()),
                        options: WriteOptions {
                            size_hint: Some(2048),
                            ..WriteOptions::default()
                        },
                    }),
                    None,
                )
                .await
                .map(|_| ()),
        ),
        (
            "continue_write",
            layer
                .continue_write(
                    Request::new(ContinueWriteRequest {
                        address: source.clone(),
                        redirects: WriteRedirectBatch {
                            continuation: Vec::new(),
                            redirects: Vec::new(),
                        },
                        results: RedirectResultBatch {
                            results: Vec::new(),
                        },
                    }),
                    None,
                )
                .await
                .map(|_| ()),
        ),
        (
            "delete",
            layer
                .delete(
                    Request::new(DeleteRequest {
                        address: source.clone(),
                        options: DeleteOptions::default(),
                    }),
                    None,
                )
                .await,
        ),
        (
            "copy",
            layer
                .copy(
                    Request::new(CopyRequest {
                        source: source.clone(),
                        destination: destination.clone(),
                        options: CopyOptions::default(),
                    }),
                    None,
                )
                .await
                .map(|_| ()),
        ),
        (
            "rename",
            layer
                .rename(
                    Request::new(RenameRequest {
                        source: source.clone(),
                        destination: destination.clone(),
                        options: RenameOptions::default(),
                    }),
                    None,
                )
                .await,
        ),
        (
            "create_directory",
            layer
                .create_directory(
                    Request::new(CreateDirectoryRequest {
                        address: source.clone(),
                        options: CreateDirectoryOptions::default(),
                    }),
                    None,
                )
                .await
                .map(|_| ()),
        ),
        (
            "delete_directory",
            layer
                .delete_directory(
                    Request::new(DeleteDirectoryRequest {
                        address: source.clone(),
                        options: DeleteDirectoryOptions,
                    }),
                    None,
                )
                .await,
        ),
        (
            "update_metadata",
            layer
                .update_metadata(
                    Request::new(UpdateMetadataRequest {
                        address: source.clone(),
                        options: UpdateMetadataOptions::default(),
                    }),
                    None,
                )
                .await
                .map(|_| ()),
        ),
        (
            "watch_directory",
            layer
                .watch_directory(
                    Request::new(WatchDirectoryRequest {
                        prefix: source.clone(),
                        options: WatchDirectoryOptions::default(),
                    }),
                    None,
                )
                .await
                .map(|_| ()),
        ),
    ]
}

/// A fallback read of a container no connection serves is the same unsigned
/// `HEAD` an anonymous connection sends, with the account and container taken
/// from the address. The control for "unsigned" is
/// `a_shared_key_connection_still_signs_its_list` above: the identical
/// fixture DOES see an `Authorization` header when a Shared Key is present.
#[tokio::test]
async fn a_fallback_read_of_an_unconfigured_container_leaves_unsigned() {
    let fake = spawn_blob_properties_server();
    let layer = fallback_layer(&fake.endpoint, &[]).await;

    let info = layer_stat(&layer, addr(ACCOUNT, CONTAINER, "assets/teapot.usd"))
        .await
        .expect("the fallback stats a public blob");
    assert_eq!(info.kind, ObjectKind::File);
    assert_eq!(info.size, Some(2048));

    let head = only_request(&fake.capture);
    assert!(
        !head.has_header("authorization"),
        "a fallback read must carry no Authorization header; got: {}",
        head.raw
    );
    assert_eq!(head.path(), "/bkt/assets/teapot.usd");
    assert!(head.raw.starts_with("HEAD "), "{}", head.request_line());
}

/// The child half of
/// [`a_fallback_read_carries_no_authorization_and_no_sig_even_with_azure_env_set`]:
/// runs in a subprocess born with every Azure credential variable set, so no
/// `set_var` races another test's client construction in this process. The
/// parent asserts the wire; in a plain test run this returns at once.
#[tokio::test]
async fn anonymous_fallback_env_child() {
    if std::env::var(CHILD_MODE).is_err() {
        return;
    }
    let endpoint = std::env::var(CHILD_ENDPOINT).expect("the parent hands over its endpoint");
    for var in [
        "AZURE_STORAGE_ACCOUNT_KEY",
        "AZURE_STORAGE_SAS_TOKEN",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "AZURE_FEDERATED_TOKEN_FILE",
    ] {
        assert!(
            std::env::var_os(var).is_some(),
            "the parent must set {var} for this run to prove anything"
        );
    }
    // The fake lives in the parent process; this child only reaches it.
    let layer = fallback_layer(&endpoint, &[]).await;
    layer_stat(&layer, addr(ACCOUNT, CONTAINER, "assets/teapot.usd"))
        .await
        .expect("the fallback stats a public blob with ambient credentials present");
    println!("{FALLBACK_ENV_SENTINEL}");
}

/// The fallback resolves an EMPTY credential bundle, and the resolver reads
/// nothing else: with every Azure credential variable set in the process
/// environment, the wire still carries no `Authorization` header and no SAS
/// `sig`. This is the property the fallback exists to hold — an operator's
/// ambient identity is never spent on a node they did not configure. Driven
/// in a subprocess born with all of those set; the parent reads the wire the
/// child produced.
#[test]
fn a_fallback_read_carries_no_authorization_and_no_sig_even_with_azure_env_set() {
    let fake = spawn_blob_properties_server();

    let output = Command::new(std::env::current_exe().expect("current integration test"))
        .arg("anonymous_fallback_env_child")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MODE, "1")
        .env(CHILD_ENDPOINT, &fake.endpoint)
        .env("AZURE_STORAGE_ACCOUNT_KEY", "MDEyMzQ1Njc4OWFiY2RlZg==")
        .env("AZURE_STORAGE_SAS_TOKEN", "sv=2024-01-01&sr=c&sig=ambient")
        .env("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000001")
        .env("AZURE_CLIENT_SECRET", "ambient-secret")
        .env("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000002")
        .env("AZURE_FEDERATED_TOKEN_FILE", "/nonexistent/token")
        .output()
        .expect("run the fallback env child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "fallback env child failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        stdout.contains(FALLBACK_ENV_SENTINEL),
        "the child must reach its assertions\nstdout:\n{stdout}"
    );

    let head = only_request(&fake.capture);
    assert!(
        !head.has_header("authorization"),
        "ambient credentials must never reach the wire; got: {}",
        head.raw
    );
    assert_eq!(head.query_param("sig"), None, "no SAS: {}", head.target());
    assert_eq!(head.query_param("sv"), None, "no SAS: {}", head.target());
    assert!(
        !head.raw.contains("ambient"),
        "nothing from the environment appears on the wire: {}",
        head.raw
    );
}

/// Every mutating slot, and `watch_directory`, is refused on a fallback
/// address with the read-only refusal — before any request is built, so the
/// fixture sees nothing.
#[tokio::test]
async fn a_fallback_refuses_every_mutation_without_touching_the_wire() {
    let (endpoint, _capture, hits) = spawn_capture_server();
    let layer = fallback_layer(&endpoint, &[]).await;

    let outcomes = every_mutation(
        &layer,
        addr(ACCOUNT, CONTAINER, "assets/teapot.usd"),
        addr(ACCOUNT, CONTAINER, "assets/copy.usd"),
    )
    .await;
    assert_eq!(outcomes.len(), 11, "every mutating slot is driven");
    for (slot, outcome) in outcomes {
        let err = outcome.expect_err(slot);
        assert_eq!(err.code(), ErrorCode::Unsupported, "{slot}: {err}");
        assert_eq!(
            err.message(),
            "this address is reached through the anonymous azure:// fallback, which is read-only",
            "{slot}"
        );
        let next = err
            .next_action()
            .unwrap_or_else(|| panic!("{slot}: the refusal says what to do"));
        assert!(
            next.contains("azure://acct/bkt/"),
            "{slot}: the next action names the node root: {next}"
        );
        assert!(
            !next.contains("teapot"),
            "{slot}: never the caller's path: {next}"
        );
    }
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no refusal reached the wire"
    );
}

/// `copy` and `rename` resolve BOTH addresses before anything runs. With one
/// end on a configured connection and the other on the fallback, the
/// refusal is the fallback's — not the cross-connection one, and not after a
/// read of the source.
#[tokio::test]
async fn a_copy_from_a_configured_root_into_a_fallback_root_is_refused_before_any_read() {
    let (endpoint, _capture, hits) = spawn_capture_server();
    let layer = fallback_layer(&endpoint, &[]).await;
    let mut config = std::collections::HashMap::new();
    config.insert("account".into(), ConfigValue::String(ACCOUNT.into()));
    config.insert("container".into(), ConfigValue::String("alpha".into()));
    config.insert(
        "__test_endpoint".into(),
        ConfigValue::String(endpoint.clone()),
    );
    layer
        .add_connection(
            Request::new(ovstorage_plugin::LayerConnectionRequest {
                target: "azure".into(),
                connection: ovstorage_plugin::ConnectionRequest {
                    backend_kind: "azure".into(),
                    config,
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("an anonymous connection adds without a verify");
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);

    let configured = addr(ACCOUNT, "alpha", "x.usd");
    let fallen_back = addr(ACCOUNT, "beta", "y.usd");
    for (label, source, destination) in [
        (
            "configured -> fallback",
            configured.clone(),
            fallen_back.clone(),
        ),
        (
            "fallback -> configured",
            fallen_back.clone(),
            configured.clone(),
        ),
    ] {
        let copy = layer
            .copy(
                Request::new(CopyRequest {
                    source: source.clone(),
                    destination: destination.clone(),
                    options: CopyOptions::default(),
                }),
                None,
            )
            .await
            .map(|_| ());
        let rename = layer
            .rename(
                Request::new(RenameRequest {
                    source: source.clone(),
                    destination: destination.clone(),
                    options: RenameOptions::default(),
                }),
                None,
            )
            .await;
        for (slot, outcome) in [("copy", copy), ("rename", rename)] {
            let err = outcome.expect_err(slot);
            assert_eq!(err.code(), ErrorCode::Unsupported, "{label} {slot}: {err}");
            assert!(
                err.message().contains("anonymous azure:// fallback"),
                "{label} {slot}: the fallback's refusal, not the cross-connection one: {}",
                err.message()
            );
            assert!(
                err.next_action()
                    .is_some_and(|next| next.contains("azure://acct/beta/")),
                "{label} {slot}: names the fallback node: {:?}",
                err.next_action()
            );
        }
    }
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "refused before any read of the source"
    );
}

/// One anonymous backend per `(account, container)`, each request reaching
/// its own container path on the wire. The first-touch log line is the
/// observable record of a build, so it doubles as the count of backends.
#[tokio::test]
async fn account_and_container_come_from_the_address() {
    let logs = capture_logs();
    let fake = spawn_blob_properties_server();
    let layer = fallback_layer(&fake.endpoint, &[]).await;

    for (account, container, key) in [
        (ACCOUNT, "alpha", "one.usd"),
        (ACCOUNT, "beta", "two.usd"),
        (ACCOUNT, "alpha", "three.usd"),
        ("other", "gamma", "four.usd"),
    ] {
        layer_stat(&layer, addr(account, container, key))
            .await
            .unwrap_or_else(|err| panic!("{account}/{container}/{key}: {err}"));
    }

    let paths = fake
        .capture
        .snapshot()
        .iter()
        .map(|request| request.path().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            "/alpha/one.usd",
            "/beta/two.usd",
            "/alpha/three.usd",
            "/gamma/four.usd"
        ]
    );
    let built = logs.containing(FALLBACK_BUILT);
    assert_eq!(
        built.len(),
        3,
        "two containers on one account, one on another: {built:#?}"
    );
    assert_eq!(
        built
            .iter()
            .filter(|line| line.contains("azure://acct"))
            .count(),
        2
    );
    assert_eq!(
        built
            .iter()
            .filter(|line| line.contains("azure://other"))
            .count(),
        1
    );
}

/// `anonymous_fallback_max_backends` bounds the resident set: with a bound of
/// one, touching a second container evicts the first, and touching the first
/// again builds it again. The control with the default bound builds each
/// container once.
#[tokio::test]
async fn cached_backends_are_bounded() {
    let fake = spawn_blob_properties_server();
    let sequence = ["alpha", "beta", "alpha"];

    let logs = capture_logs();
    let bounded = fallback_layer(
        &fake.endpoint,
        &[("anonymous_fallback_max_backends", ConfigValue::Int(1))],
    )
    .await;
    for container in sequence {
        layer_stat(&bounded, addr(ACCOUNT, container, "x.usd"))
            .await
            .unwrap();
    }
    assert_eq!(
        logs.containing(FALLBACK_BUILT).len(),
        3,
        "a bound of one rebuilds alpha after beta evicted it"
    );

    let logs = capture_logs();
    let unbounded = fallback_layer(&fake.endpoint, &[]).await;
    for container in sequence {
        layer_stat(&unbounded, addr(ACCOUNT, container, "x.usd"))
            .await
            .unwrap();
    }
    assert_eq!(
        logs.containing(FALLBACK_BUILT).len(),
        2,
        "under the default bound each container is built once"
    );
}

/// `anonymous_fallback_mints_per_minute` bounds how many backends may be built
/// per sliding minute. Past it a miss is `ResourceExhausted` (retryable) and
/// reaches no wire; a cached node keeps answering.
#[tokio::test]
async fn the_mint_budget_answers_resource_exhausted() {
    let fake = spawn_blob_properties_server();
    let layer = fallback_layer(
        &fake.endpoint,
        &[("anonymous_fallback_mints_per_minute", ConfigValue::Int(1))],
    )
    .await;

    layer_stat(&layer, addr(ACCOUNT, "alpha", "x.usd"))
        .await
        .expect("the first build is within budget");
    let err = layer_stat(&layer, addr(ACCOUNT, "beta", "x.usd"))
        .await
        .expect_err("the second build is over budget");
    assert_eq!(err.code(), ErrorCode::ResourceExhausted);
    assert_eq!(
        err.message(),
        "anonymous fallback mint budget exhausted; retry later"
    );
    assert!(err.code().retryable());
    assert!(err.next_action().is_some());
    layer_stat(&layer, addr(ACCOUNT, "alpha", "y.usd"))
        .await
        .expect("a cached node is not a mint");
    assert_eq!(
        fake.capture.snapshot().len(),
        2,
        "alpha twice; beta never reached the wire"
    );
}

/// The first touch of a node logs the origin it was reached at, and nothing
/// of the caller's path. A second touch is a cache hit and logs nothing.
#[tokio::test]
async fn first_touch_logs_the_origin_and_not_the_key() {
    let logs = capture_logs();
    let fake = spawn_blob_properties_server();
    let layer = fallback_layer(&fake.endpoint, &[]).await;

    layer_stat(&layer, addr(ACCOUNT, CONTAINER, "secret/path.usd"))
        .await
        .unwrap();
    let built = logs.containing(FALLBACK_BUILT);
    assert_eq!(built.len(), 1, "{built:#?}");
    assert!(
        built[0].contains("azure://acct"),
        "the origin: {}",
        built[0]
    );
    assert!(built[0].contains("scheme=\"azure\""), "{}", built[0]);
    for withheld in ["secret", "path.usd"] {
        assert!(
            !built[0].contains(withheld),
            "the key is not the operator's to read: {}",
            built[0]
        );
    }

    layer_stat(&layer, addr(ACCOUNT, CONTAINER, "other/key.usd"))
        .await
        .unwrap();
    assert_eq!(
        logs.containing(FALLBACK_BUILT).len(),
        1,
        "a cache hit logs no build"
    );
}

/// A SAS-bearing address authenticates itself, so the fallback never answers
/// it: the miss is the byte-identical `NoRoute`, and nothing reaches the wire.
/// A version id alone is carried, not a credential, and still routes.
#[tokio::test]
async fn a_sas_query_falls_through_to_no_route() {
    let fake = spawn_blob_properties_server();
    let layer = fallback_layer(&fake.endpoint, &[]).await;
    for query in [
        "sv=2024-01-01&sr=b&sp=r&sig=abc%2Fdef",
        "sig=abc",
        "snapshot=2026-01-01T00:00:00Z",
    ] {
        let err = layer_stat(
            &layer,
            address::parse(&format!("azure://{ACCOUNT}/{CONTAINER}/k.usd?{query}")).unwrap(),
        )
        .await
        .expect_err(query);
        assert_eq!(err.code(), ErrorCode::NoRoute, "{query}");
        assert_eq!(err.message(), "no route matches address", "{query}");
    }
    assert!(
        fake.capture.snapshot().is_empty(),
        "nothing reached the wire"
    );

    layer_stat(
        &layer,
        address::parse(&format!("azure://{ACCOUNT}/{CONTAINER}/k.usd?versionid=7")).unwrap(),
    )
    .await
    .expect("a version id routes through the fallback");
    let head = only_request(&fake.capture);
    assert_eq!(head.query_param("versionid").as_deref(), Some("7"));
}

/// The root a fallback-served address resolves to is the scheme root, and it
/// advertises no mutation: what the layer refuses, the root withholds, so a
/// host's capability self-gate and the layer's refusal agree.
#[tokio::test]
async fn the_fallback_root_withholds_write_and_delete() {
    let (endpoint, _capture, hits) = spawn_capture_server();
    let layer = fallback_layer(&endpoint, &[]).await;
    let root = layer
        .root_info_for(
            &addr(ACCOUNT, CONTAINER, "assets/teapot.usd"),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .expect("a fallback-served address has a root");
    assert_eq!(root.root.as_str(), "azure:///");
    assert_eq!(root.connection_id, None);
    assert_eq!(root.visibility, ovstorage_plugin::AddressVisibility::Hidden);
    let caps = &root.capabilities;
    assert!(!caps.supports_write);
    assert!(!caps.supports_write_stream);
    assert!(!caps.supports_write_redirect);
    assert!(!caps.supports_delete);
    assert!(!caps.supports_copy);
    assert!(!caps.supports_server_side_copy);
    assert!(!caps.supports_rename);
    assert!(!caps.supports_create_directory);
    assert!(!caps.supports_delete_directory);
    assert!(!caps.supports_native_metadata_patch);
    assert!(!caps.supports_watch_directory);
    assert!(caps.supports_list);
    assert!(caps.supports_list_stream);
    assert!(caps.supports_recursive_list);
    assert!(caps.supports_version_listing);
    assert!(
        !caps.has_real_directories,
        "the fallback assumes a flat namespace"
    );
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
}
