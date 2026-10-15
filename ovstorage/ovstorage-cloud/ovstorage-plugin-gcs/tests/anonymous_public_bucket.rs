// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What an anonymous GCS connection can serve against a public bucket.
//!
//! A GCS bucket that grants `roles/storage.objectViewer` to `allUsers` answers
//! an unauthenticated `GET /storage/v1/b/<bucket>/o` (list) and
//! `GET /storage/v1/b/<bucket>/o/<object>` (stat); granting only
//! `storage.objects.get` and not `storage.objects.list` gives the familiar
//! read-yes / list-no shape, and there it is Google that refuses, not the
//! plugin.
//!
//! The plugin can issue both, and always could: `MaybeBearerAuth` skips the
//! `Authorization` header when the token is empty, and `Authenticator`
//! returns an empty token for `CredentialSource::Anonymous`.
//!
//! **Scope, because the conformance suite already covers most of this.**
//! `tests/conformance_scenarios.rs` drives EVERY scenario through
//! `anonymous_layer()`, so `drive_stat_basic_objectinfo` and
//! `drive_list_one_level_vs_recursive` already prove an anonymous connection
//! lists and stats and that the entries come back parsed. What they do not
//! assert is the WIRE FORM — that the request carries no `Authorization`
//! header — which is the property a plugin loses when anonymity becomes a fork
//! in client construction rather than a no-op at the header. That is what
//! these two tests add, and they are deliberately thin because of it.
//!
//! The property is easy to lose and costs nothing to hold here:
//! gcs's anonymity is a no-op branch in one hand-rolled client, whereas the s3
//! sibling reaches its store through an SDK that wants a credentials provider
//! and so has to construct an unsigned client explicitly. A plugin in that
//! shape can lose anonymous `list` by omission. This one cannot, and nothing in
//! this file changes gcs behaviour.
//!
//! The control for "no `Authorization` header" is
//! `layer_connection_lifecycle.rs::add_connection_authenticates_on_verify_pass`,
//! which asserts `authorization: bearer synthetic-token` on a credentialed
//! storage RPC against the same fixture shape. Without a positive somewhere, an
//! absence assertion would also hold on a build that signed nothing at all.
//!
//! The second half of this file drives the same wire assertions through the
//! **anonymous `gs://` scheme fallback**: a layer granted
//! `anonymous_fallback = ["gs"]` and no connection at all, reached through
//! `GcsLayer` rather than a hand-built backend. The property under test is the
//! same absence, plus the two things the fallback adds on top of a configured
//! anonymous connection — every mutating slot is refused before the wire, and
//! the ambient Google credential environment is never consulted. The latter
//! runs in a filtered child process that owns its environment, so no
//! `set_var` can race another test's client construction.

use std::collections::HashMap;
use std::process::{Command, Output};

use ovstorage_plugin::{
    BackendFactory, BackendId, Body, ConfigValue, ConnectionRequest, ContinueWriteRequest,
    CopyOptions, CopyRequest, CreateDirectoryOptions, CreateDirectoryRequest,
    DeleteDirectoryOptions, DeleteDirectoryRequest, DeleteOptions, DeleteRequest, ErrorCode,
    LayerConfig, LayerConnectionRequest, LayerHandle, ListOptions, ListRequest, ObjectInfo,
    ObjectKind, ReadOptions, ReadRequest, ReadResult, RedirectCredential, RedirectResultBatch,
    RenameOptions, RenameRequest, Request, ResolvedTarget, SecretBundle, StatOptions, StatRequest,
    UpdateMetadataOptions, UpdateMetadataRequest, Url, WatchDirectoryOptions,
    WatchDirectoryRequest, WriteOptions, WriteRedirectBatch, WriteRequest, address,
};
use ovstorage_plugin_gcs::{GcsBackend, GcsLayerFactory};
use ovstorage_plugin_test::scripted_http::{CannedHttpResponse, ScriptedHttpServer};

const BUCKET: &str = "bkt";

/// One object and one prefix, the two arms of the plugin's list mapping.
const PUBLIC_LIST_BODY: &str = r#"{
  "kind": "storage#objects",
  "items": [
    {
      "name": "assets/teapot.usd",
      "size": "2048",
      "etag": "CJmh8gE=",
      "generation": "1735786445000000",
      "updated": "2026-01-02T03:04:05.000Z",
      "contentType": "model/vnd.usd"
    }
  ],
  "prefixes": ["assets/textures/"]
}"#;

const PUBLIC_OBJECT_BODY: &str = r#"{
  "kind": "storage#object",
  "name": "assets/teapot.usd",
  "size": "2048",
  "etag": "CJmh8gE=",
  "generation": "1735786445000000",
  "updated": "2026-01-02T03:04:05.000Z",
  "contentType": "model/vnd.usd"
}"#;

async fn backend_with(endpoint: &str, credentials: SecretBundle) -> GcsBackend {
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(BUCKET.into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
    let request = ConnectionRequest {
        backend_kind: "gcs".into(),
        config,
        credentials,
        persist: false,
        display_name: None,
    };
    let config =
        ovstorage_plugin_gcs::__test_only_parse_config(&request.config).expect("parse gcs config");
    ovstorage_plugin_gcs::__test_only_backend(config, request.credentials).expect("build backend")
}

/// An empty `SecretBundle` is `CredentialSource::Anonymous`.
async fn anonymous_backend(endpoint: &str) -> GcsBackend {
    backend_with(endpoint, SecretBundle::default()).await
}

fn target(key: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId(format!("gcs:gs://{BUCKET}/")),
        resolved_address: address::parse(&format!("gs://{BUCKET}/{key}")).expect("parse address"),
    }
}

fn has_authorization(raw: &str) -> bool {
    raw.to_lowercase().contains("\r\nauthorization: ")
}

/// A public bucket answers the listing, and the plugin issues it with no
/// `Authorization` header.
#[tokio::test]
async fn an_anonymous_connection_lists_a_public_bucket() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", PUBLIC_LIST_BODY));
    let backend = anonymous_backend(server.endpoint()).await;

    let items = backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect("an anonymous list of a public bucket must succeed");

    let requests = server.requests();
    assert_eq!(requests.len(), 1, "exactly one listing was issued");
    let listing = &requests[0];
    assert!(
        !has_authorization(listing),
        "an anonymous list must carry no Authorization header; got: {listing}"
    );
    let line = listing.split("\r\n").next().unwrap_or("");
    assert!(
        line.starts_with("GET /storage/v1/b/bkt/o?"),
        "the JSON API objects.list endpoint: {line}"
    );
    assert!(line.contains("prefix=assets%2F"), "prefix-scoped: {line}");
    assert!(line.contains("delimiter=%2F"), "one level: {line}");

    assert_eq!(items.len(), 2, "one object and one prefix");
    let object = items
        .iter()
        .find(|item| item.address.as_str() == "gs://bkt/assets/teapot.usd")
        .expect("the object is returned under its own address");
    assert_eq!(object.kind, ObjectKind::File);
    assert_eq!(object.size, Some(2048));
    assert!(object.mtime.is_some(), "`updated` is carried through");
    let directory = items
        .iter()
        .find(|item| item.address.as_str() == "gs://bkt/assets/textures/")
        .expect("the prefix is returned as a directory");
    assert_eq!(directory.kind, ObjectKind::DirectoryInferred);
}

/// `stat` on a public object is an unsigned `objects.get`, and the metadata
/// comes back parsed.
#[tokio::test]
async fn an_anonymous_connection_stats_a_public_object() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", PUBLIC_OBJECT_BODY));
    let backend = anonymous_backend(server.endpoint()).await;

    let info = backend
        .stat(target("assets/teapot.usd"), StatOptions::default(), None)
        .await
        .expect("an anonymous stat of a public object must succeed");

    let requests = server.requests();
    assert_eq!(requests.len(), 1, "one metadata GET, no fallback probe");
    assert!(
        !has_authorization(&requests[0]),
        "an anonymous stat must carry no Authorization header; got: {}",
        requests[0]
    );
    assert!(
        requests[0].starts_with("GET /storage/v1/b/bkt/o/assets%2Fteapot.usd"),
        "the object-metadata endpoint: {}",
        requests[0].split("\r\n").next().unwrap_or("")
    );

    assert_eq!(info.kind, ObjectKind::File);
    assert_eq!(info.size, Some(2048));
    assert!(info.mtime.is_some(), "`updated` is carried through");
}

// === the anonymous gs:// scheme fallback ===

/// A bucket no connection in these tests is ever configured for.
const FALLBACK_BUCKET: &str = "public-bkt";
const FALLBACK_OBJECT: &str = "assets/teapot.usd";

/// Set in the child process that owns the ambient-credential environment;
/// its value selects the slot the child drives.
const CHILD_MODE: &str = "OVSTORAGE_GCS_FALLBACK_ENV_CHILD";
/// The parent's scripted storage endpoint, handed to the child.
const CHILD_ENDPOINT: &str = "OVSTORAGE_GCS_FALLBACK_ENV_ENDPOINT";
/// Printed by the child once its assertions have actually run, so a filter
/// matching no test — libtest exits 0 — cannot pass the parent vacuously.
const FALLBACK_ENV_SENTINEL: &str = "FALLBACK_ENV_ASSERTED";

const SYNTHETIC_PEM: &str = include_str!("synthetic_rsa_pkcs8.pem");

fn fallback_layer_config(endpoint: &str) -> LayerConfig {
    let mut config = LayerConfig::new();
    config.insert(
        "anonymous_fallback".into(),
        ConfigValue::Toml("anonymous_fallback = [\"gs\"]\n".into()),
    );
    config.insert(
        "anonymous_fallback_endpoint".into(),
        ConfigValue::String(endpoint.into()),
    );
    config
}

/// A `GcsLayer` granted the `gs` fallback and holding no connection, pointed
/// at `endpoint`.
async fn fallback_layer(endpoint: &str) -> LayerHandle {
    GcsLayerFactory::default()
        .create_backend("gcs", &fallback_layer_config(endpoint), None)
        .await
        .expect("a granted layer builds")
}

fn fallback_address(key: &str) -> Url {
    address::parse(&format!("gs://{FALLBACK_BUCKET}/{key}")).expect("parse address")
}

async fn layer_stat(layer: &LayerHandle, address: Url) -> ovstorage_plugin::Result<ObjectInfo> {
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

async fn layer_read(layer: &LayerHandle, address: Url) -> ovstorage_plugin::Result<ReadResult> {
    layer
        .read(
            Request::new(ReadRequest {
                address,
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
}

/// What an unsigned public-download redirect looks like: the plain object URL
/// under the endpoint, no signature in the query, no `Authorization` header,
/// and a scope that promises no credential.
fn assert_unsigned_download_redirect(result: ReadResult, endpoint: &str) {
    let ReadResult::Redirect(redirect) = result else {
        panic!("an anonymous read is a redirect to the public download URL, got {result:?}");
    };
    assert_eq!(redirect.request.method, "GET");
    assert_eq!(
        redirect.request.url,
        format!("{endpoint}/{FALLBACK_BUCKET}/assets%2Fteapot.usd"),
        "the public download URL names the bucket and the encoded object"
    );
    assert!(
        !redirect
            .request
            .url
            .to_lowercase()
            .contains("x-goog-signature"),
        "no V4 signature: {}",
        redirect.request.url
    );
    assert!(
        redirect
            .request
            .headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("authorization")),
        "no Authorization header: {:?}",
        redirect.request.headers
    );
    assert_eq!(redirect.scope.credential, RedirectCredential::None);
}

/// The fallback serves `stat` and `list` of an unconfigured bucket, and both
/// go out with no `Authorization` header. The credentialed control is
/// `layer_connection_lifecycle.rs::add_connection_authenticates_on_verify_pass`,
/// which sees `authorization: bearer synthetic-token` on the same fixture.
#[tokio::test]
async fn a_fallback_read_of_an_unconfigured_bucket_leaves_unsigned() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", PUBLIC_OBJECT_BODY));
    let layer = fallback_layer(server.endpoint()).await;

    let info = layer_stat(&layer, fallback_address(FALLBACK_OBJECT))
        .await
        .expect("a fallback stat of a public object succeeds");
    assert_eq!(info.kind, ObjectKind::File);
    assert_eq!(info.size, Some(2048));

    let requests = server.requests();
    assert_eq!(requests.len(), 1, "one metadata GET");
    assert!(
        !has_authorization(&requests[0]),
        "a fallback stat must carry no Authorization header; got: {}",
        requests[0]
    );
    assert!(
        requests[0].starts_with("GET /storage/v1/b/public-bkt/o/assets%2Fteapot.usd"),
        "the object-metadata endpoint for the address's own bucket: {}",
        requests[0].split("\r\n").next().unwrap_or("")
    );
}

/// The listing arm of the same property.
#[tokio::test]
async fn a_fallback_list_of_an_unconfigured_bucket_leaves_unsigned() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", PUBLIC_LIST_BODY));
    let layer = fallback_layer(server.endpoint()).await;

    let page = layer
        .list(
            Request::new(ListRequest {
                prefix: fallback_address("assets/"),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .expect("a fallback list of a public bucket succeeds");
    assert_eq!(page.items.len(), 2, "one object and one prefix");
    assert_eq!(
        page.items[0].address.as_str(),
        "gs://public-bkt/assets/teapot.usd"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        !has_authorization(&requests[0]),
        "a fallback list must carry no Authorization header; got: {}",
        requests[0]
    );
    let line = requests[0].split("\r\n").next().unwrap_or("");
    assert!(
        line.starts_with("GET /storage/v1/b/public-bkt/o?"),
        "the JSON API objects.list endpoint: {line}"
    );
    assert!(line.contains("prefix=assets%2F"), "prefix-scoped: {line}");
}

/// `read` under the fallback mints the public download URL: unsigned, naming
/// the bucket and object, promising no credential, and fetching nothing.
#[tokio::test]
async fn a_fallback_read_builds_the_public_download_url_unsigned() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", PUBLIC_OBJECT_BODY));
    let layer = fallback_layer(server.endpoint()).await;

    let result = layer_read(&layer, fallback_address(FALLBACK_OBJECT))
        .await
        .expect("a fallback read mints a redirect");
    assert_unsigned_download_redirect(result, server.endpoint());
    assert_eq!(server.hits(), 0, "a read mints a URL and fetches nothing");
}

/// The child half of the ambient-credential tests. Runs only when the parent
/// set [`CHILD_MODE`]; in a plain test run it returns at once.
///
/// The environment is the child's from birth — `GOOGLE_APPLICATION_CREDENTIALS`
/// names a real service-account file whose `token_uri` is a parent-owned IdP —
/// so the assertions here are about what the fallback does when a credential
/// is there for the taking. The parent asserts the wire.
#[tokio::test]
async fn anonymous_fallback_env_child() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    let endpoint = std::env::var(CHILD_ENDPOINT).expect("the parent hands over its endpoint");
    assert!(
        std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS").is_some(),
        "the child is born with the ambient credential set"
    );
    let layer = fallback_layer(&endpoint).await;
    match mode.as_str() {
        "stat" => {
            let info = layer_stat(&layer, fallback_address(FALLBACK_OBJECT))
                .await
                .expect("a fallback stat succeeds with the ambient credential ignored");
            assert_eq!(info.size, Some(2048));
        }
        "read" => {
            let result = layer_read(&layer, fallback_address(FALLBACK_OBJECT))
                .await
                .expect("a fallback read mints a redirect");
            assert_unsigned_download_redirect(result, &endpoint);
        }
        other => panic!("unknown child mode {other}"),
    }
    println!("{FALLBACK_ENV_SENTINEL}");
}

/// An ambient ADC environment the fallback must never consult: a directory
/// holding a service-account file (its `token_uri` at `idp`) named by both
/// `GOOGLE_APPLICATION_CREDENTIALS` and `CLOUDSDK_CONFIG`.
fn ambient_credential_dir(idp: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let json = serde_json::json!({
        "type": "service_account",
        "client_email": "ambient@example.iam.gserviceaccount.com",
        "private_key": SYNTHETIC_PEM,
        "token_uri": format!("{idp}/token"),
        "private_key_id": "kid-ambient",
    })
    .to_string();
    std::fs::write(
        dir.path().join("application_default_credentials.json"),
        json,
    )
    .expect("write ambient credential");
    dir
}

fn child_command(mode: &str, endpoint: &str, credential_dir: &std::path::Path) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("current integration test"));
    command
        .arg("anonymous_fallback_env_child")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MODE, mode)
        .env(CHILD_ENDPOINT, endpoint)
        .env(
            "GOOGLE_APPLICATION_CREDENTIALS",
            credential_dir.join("application_default_credentials.json"),
        )
        .env("CLOUDSDK_CONFIG", credential_dir);
    command
}

fn assert_child_succeeded(output: &Output) {
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
}

/// With `GOOGLE_APPLICATION_CREDENTIALS` naming a usable service-account file,
/// a fallback stat still goes out unsigned and the IdP is never contacted: the
/// fallback's credential is a literal empty bundle, not a discovery chain.
#[test]
fn a_fallback_read_leaves_unsigned_with_ambient_credential_env_set() {
    let idp = ScriptedHttpServer::spawn(CannedHttpResponse::json(
        "200 OK",
        "{\"access_token\": \"ambient-token\", \"expires_in\": 3600}",
    ));
    let storage = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", PUBLIC_OBJECT_BODY));
    let credentials = ambient_credential_dir(idp.endpoint());

    let output = child_command("stat", storage.endpoint(), credentials.path())
        .output()
        .expect("run the fallback env child");
    assert_child_succeeded(&output);

    assert_eq!(idp.hits(), 0, "the ambient credential is never exchanged");
    let requests = storage.requests();
    assert_eq!(requests.len(), 1, "one metadata GET: {requests:?}");
    assert!(
        !has_authorization(&requests[0]),
        "a fallback stat carries no Authorization header even with ADC set; got: {}",
        requests[0]
    );
}

/// The redirect arm of the same property: with the ambient credential set, the
/// minted download URL is still the unsigned public one, and nothing — neither
/// the IdP nor storage — is contacted while minting it.
#[test]
fn a_fallback_read_carries_no_authorization_even_with_google_application_credentials_set() {
    let idp = ScriptedHttpServer::spawn(CannedHttpResponse::json(
        "200 OK",
        "{\"access_token\": \"ambient-token\", \"expires_in\": 3600}",
    ));
    let storage = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", PUBLIC_OBJECT_BODY));
    let credentials = ambient_credential_dir(idp.endpoint());

    let output = child_command("read", storage.endpoint(), credentials.path())
        .output()
        .expect("run the fallback env child");
    assert_child_succeeded(&output);

    assert_eq!(idp.hits(), 0, "the ambient credential is never exchanged");
    assert_eq!(storage.hits(), 0, "a read mints a URL and fetches nothing");
}

fn assert_fallback_refusal<T>(slot: &str, result: ovstorage_plugin::Result<T>) {
    let err = match result {
        Err(err) => err,
        Ok(_) => panic!("{slot} on a fallback-served address must be refused"),
    };
    assert_eq!(err.code(), ErrorCode::Unsupported, "{slot}: {err:?}");
    assert_eq!(
        err.message(),
        "this address is reached through the anonymous gs:// fallback, which is read-only",
        "{slot}"
    );
    assert!(
        err.next_action()
            .is_some_and(|action| action.contains(&format!("gs://{FALLBACK_BUCKET}/"))),
        "{slot}: the guidance names the bucket root: {:?}",
        err.next_action()
    );
}

/// Every mutating slot, and `watch_directory`, is refused on a fallback-served
/// address before any request is built: the store's hit count does not move.
#[tokio::test]
async fn a_fallback_refuses_every_mutation_without_touching_the_wire() {
    let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", PUBLIC_OBJECT_BODY));
    let layer = fallback_layer(server.endpoint()).await;
    let object = fallback_address(FALLBACK_OBJECT);
    let sibling = fallback_address("assets/copy.usd");
    let directory = fallback_address("assets/");

    assert_fallback_refusal(
        "write",
        layer
            .write(
                Request::new(WriteRequest {
                    address: object.clone(),
                    body: Body::Bytes(b"teapot".to_vec()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await,
    );
    assert_fallback_refusal(
        "write_stream",
        layer
            .write_stream(
                Request::new(WriteRequest {
                    address: object.clone(),
                    body: Body::Bytes(b"teapot".to_vec()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await,
    );
    assert_fallback_refusal(
        "write_redirect",
        layer
            .write_redirect(
                Request::new(WriteRequest {
                    address: object.clone(),
                    body: Body::Bytes(b"teapot".to_vec()),
                    options: WriteOptions {
                        size_hint: Some(6),
                        ..WriteOptions::default()
                    },
                }),
                None,
            )
            .await,
    );
    assert_fallback_refusal(
        "continue_write",
        layer
            .continue_write(
                Request::new(ContinueWriteRequest {
                    address: object.clone(),
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
            .await,
    );
    assert_fallback_refusal(
        "delete",
        layer
            .delete(
                Request::new(DeleteRequest {
                    address: object.clone(),
                    options: DeleteOptions::default(),
                }),
                None,
            )
            .await,
    );
    assert_fallback_refusal(
        "copy",
        layer
            .copy(
                Request::new(CopyRequest {
                    source: object.clone(),
                    destination: sibling.clone(),
                    options: CopyOptions::default(),
                }),
                None,
            )
            .await,
    );
    assert_fallback_refusal(
        "rename",
        layer
            .rename(
                Request::new(RenameRequest {
                    source: object.clone(),
                    destination: sibling.clone(),
                    options: RenameOptions::default(),
                }),
                None,
            )
            .await,
    );
    assert_fallback_refusal(
        "create_directory",
        layer
            .create_directory(
                Request::new(CreateDirectoryRequest {
                    address: directory.clone(),
                    options: CreateDirectoryOptions::default(),
                }),
                None,
            )
            .await,
    );
    assert_fallback_refusal(
        "delete_directory",
        layer
            .delete_directory(
                Request::new(DeleteDirectoryRequest {
                    address: directory.clone(),
                    options: DeleteDirectoryOptions,
                }),
                None,
            )
            .await,
    );
    assert_fallback_refusal(
        "update_metadata",
        layer
            .update_metadata(
                Request::new(UpdateMetadataRequest {
                    address: object.clone(),
                    options: UpdateMetadataOptions::default(),
                }),
                None,
            )
            .await,
    );
    assert_fallback_refusal(
        "watch_directory",
        layer
            .watch_directory(
                Request::new(WatchDirectoryRequest {
                    prefix: directory,
                    options: WatchDirectoryOptions::default(),
                }),
                None,
            )
            .await,
    );

    assert_eq!(server.hits(), 0, "no refused slot reached the wire");
    // Control: the read side of the same address is served.
    layer_stat(&layer, object)
        .await
        .expect("stat on the same address is served");
    assert_eq!(server.hits(), 1);
}

/// `copy` and `rename` resolve both ends before anything runs, so a fallback
/// destination (or source) is refused before the configured source is read.
#[tokio::test]
async fn a_copy_from_a_configured_root_into_a_fallback_root_is_refused_before_any_read() {
    let configured =
        ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", PUBLIC_OBJECT_BODY));
    let fallback_store =
        ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", PUBLIC_OBJECT_BODY));
    let layer = fallback_layer(fallback_store.endpoint()).await;
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String("cfg".into()));
    config.insert(
        "endpoint".into(),
        ConfigValue::String(configured.endpoint().into()),
    );
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "gcs".into(),
                connection: ConnectionRequest {
                    backend_kind: "gcs".into(),
                    config,
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("an anonymous connection adds with no RPC");
    assert_eq!(configured.hits(), 0);

    let configured_object = address::parse("gs://cfg/assets/teapot.usd").unwrap();
    let fallback_object = fallback_address(FALLBACK_OBJECT);
    for (source, destination) in [
        (configured_object.clone(), fallback_object.clone()),
        (fallback_object.clone(), configured_object.clone()),
    ] {
        assert_fallback_refusal(
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
                .await,
        );
        assert_fallback_refusal(
            "rename",
            layer
                .rename(
                    Request::new(RenameRequest {
                        source,
                        destination,
                        options: RenameOptions::default(),
                    }),
                    None,
                )
                .await,
        );
    }
    assert_eq!(configured.hits(), 0, "the configured source was never read");
    assert_eq!(
        fallback_store.hits(),
        0,
        "the fallback end was never touched"
    );

    // Control: a copy wholly within the configured bucket reaches its store.
    let _ = layer
        .copy(
            Request::new(CopyRequest {
                source: configured_object,
                destination: address::parse("gs://cfg/assets/copy.usd").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await;
    assert!(
        configured.hits() >= 1,
        "the refusal is specific to the fallback end"
    );
}
