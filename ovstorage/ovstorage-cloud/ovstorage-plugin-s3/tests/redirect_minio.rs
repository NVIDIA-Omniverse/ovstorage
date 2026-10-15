// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MinIO conformance for the redirected write path.
//!
//! The `minio` compatibility profile is advertised as supported, so the
//! presigned PUT this plugin mints must survive a strict origin's signature
//! check after the host follower replays it. That is an end-to-end property of
//! two crates — the plugin signs, the host sends — and neither crate's own
//! suite can see it: the plugin's fixtures answer canned responses without
//! verifying, and the host's fixtures are `wiremock`, which ignores `Host`.
//!
//! So this suite composes the real `RedirectFollower` over the real `S3Layer`
//! and points both at [`FakeMinio`], which recomputes the signature the way
//! MinIO does. A divergence between the header set signed into the URL and the
//! header set that reaches the wire is a 403 here, exactly as reported.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ovstorage::{
    Body, CancellationToken, ChecksumSet, ConfigValue, Connection, ContinueWriteRequest, Error,
    ErrorCode, IfDestExists, Layer, LayerConfig, LayerConnectionRequest, LayerHandle,
    LayerKindDescriptor, LayerType, ObjectInfo, ObjectKind, Request, Result, SecretBundle,
    SecretBytes, SecretValue, Url, WrapperFactory, WriteOptions, WriteRedirect, WriteRedirectBatch,
    WriteRequest, WriteResult, WriteStep, address,
};
use ovstorage_plugin::{BackendFactory, ConnectionRequest, RedirectBodySource, UserMetadata};
use ovstorage_plugin_http::RedirectFollowerWrapperFactory;
use ovstorage_plugin_s3::S3LayerFactory;

mod support;
use support::minio_sigv4::{ACCESS_KEY, BUCKET, FakeMinio, REGION, SECRET_KEY, send_raw};

// === Composition ===

fn credentials_with_secret(secret: &str) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "aws_access_key_id".into(),
        SecretValue::Bytes(SecretBytes(ACCESS_KEY.as_bytes().to_vec())),
    );
    bundle.fields.insert(
        "aws_secret_access_key".into(),
        SecretValue::Bytes(SecretBytes(secret.as_bytes().to_vec())),
    );
    bundle
}

fn credentials() -> SecretBundle {
    credentials_with_secret(SECRET_KEY)
}

/// An `S3Layer` with one authenticated connection pointed at `fake`, under the
/// `minio` compatibility profile with path-style addressing — the configuration
/// the reporter used.
async fn s3_layer_against(fake: &FakeMinio) -> LayerHandle {
    s3_layer_against_with_credentials(fake, credentials()).await
}

async fn s3_layer_against_with_secret(fake: &FakeMinio, secret: &str) -> LayerHandle {
    s3_layer_against_with_credentials(fake, credentials_with_secret(secret)).await
}

async fn s3_layer_against_with_credentials(
    fake: &FakeMinio,
    credentials: SecretBundle,
) -> LayerHandle {
    let layer = S3LayerFactory::default()
        .create_backend("s3", &LayerConfig::new(), None)
        .await
        .expect("create s3 backend");
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(BUCKET.into()));
    config.insert("region".into(), ConfigValue::String(REGION.into()));
    config.insert(
        "endpoint".into(),
        ConfigValue::String(fake.endpoint().to_string()),
    );
    config.insert(
        "compatibility_profile".into(),
        ConfigValue::String("minio".into()),
    );
    config.insert("force_path_style".into(), ConfigValue::Bool(true));
    let connection: Connection = layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "s3".into(),
                connection: ConnectionRequest {
                    backend_kind: "s3".into(),
                    config,
                    credentials,
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("add_connection");
    assert!(
        matches!(
            connection.auth_state,
            ovstorage::ConnectionAuthState::Authenticated { .. }
        ),
        "the fake must accept the verify probe, got {:?}",
        connection.auth_state
    );
    layer
}

/// The real host follower over `inner` — the wrapper whose replay is under test.
async fn follower_over(inner: LayerHandle) -> LayerHandle {
    RedirectFollowerWrapperFactory
        .create_wrapper("follower", &LayerConfig::new(), inner, None)
        .await
        .expect("create redirect_follower")
}

fn object_address(key: &str) -> Url {
    address::parse(&format!("s3://{BUCKET}/{key}")).expect("parse address")
}

/// Fail with the fake's own rejection reasons, which name the divergent header
/// rather than leaving a bare 403 to be guessed at.
fn assert_no_rejections(fake: &FakeMinio, context: &str) {
    let rejections = fake.rejections();
    assert!(
        rejections.is_empty(),
        "{context}: the fake rejected {} request(s): {rejections:#?}",
        rejections.len(),
    );
}

// === The buffered presigned PUT ===

#[tokio::test]
async fn follower_write_bytes_survives_minio_presign_verification() {
    // `RedirectFollower -> PluginBackend("s3")` driving a buffered
    // `write(bytes)` against a MinIO-faithful verifier. The presign and the
    // credentials are exercised by the read tests above, so a failure here
    // isolates to the replay.
    let fake = FakeMinio::spawn();
    let stack = follower_over(s3_layer_against(&fake).await).await;

    let payload = b"redirected-through-the-follower".to_vec();
    let result = stack
        .write(
            Request::new(WriteRequest {
                address: object_address("redirect-obj.bin"),
                body: Body::Bytes(payload.clone()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await;

    assert_no_rejections(&fake, "buffered write(bytes)");
    result.expect("the redirected PUT must verify against MinIO");
    assert_eq!(
        fake.object("redirect-obj.bin"),
        Some(payload),
        "the origin must have stored exactly the bytes written"
    );
    // The PUT really went through the redirect, not a direct SDK write.
    let put = fake
        .requests()
        .into_iter()
        .find(|request| request.method == "PUT")
        .expect("a PUT reached the origin");
    assert!(put.presigned, "the PUT must be the presigned redirect");
}

/// A message that cannot travel as an `x-amz-meta-*` header value is dropped
/// rather than refused: the redirected write still verifies and stores the
/// bytes, and no annotation header reaches the origin. The annotation is
/// droppable by contract; a request-construction failure surfacing as
/// `Internal` would turn it into a hard failure on the default S3 write route.
#[tokio::test]
async fn follower_write_drops_a_message_that_cannot_travel_as_a_header() {
    let fake = FakeMinio::spawn();
    let stack = follower_over(s3_layer_against(&fake).await).await;

    let payload = b"annotated-through-the-follower".to_vec();
    let result = stack
        .write(
            Request::new(WriteRequest {
                address: object_address("unstorable-note.bin"),
                body: Body::Bytes(payload.clone()),
                options: WriteOptions {
                    message: Some("line one\r\nx-amz-meta-injected: yes".into()),
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await;

    assert_no_rejections(&fake, "write(bytes) with an unstorable message");
    result.expect("a message that cannot be carried is dropped, not refused");
    assert_eq!(fake.object("unstorable-note.bin"), Some(payload));
    let put = fake
        .requests()
        .into_iter()
        .find(|request| request.method == "PUT")
        .expect("a PUT reached the origin");
    assert!(put.presigned, "the PUT must be the presigned redirect");
    assert!(
        put.header("x-amz-meta-x_ov_message").is_none(),
        "the unstorable annotation must not reach the origin"
    );
    assert!(
        put.header("x-amz-meta-injected").is_none(),
        "no header is smuggled in through the message"
    );
}

#[tokio::test]
async fn follower_write_surfaces_provider_error_code_on_presign_rejection() {
    let fake = FakeMinio::spawn();
    let layer = s3_layer_against_with_secret(&fake, "intentionally-wrong-secret").await;
    let stack = follower_over(layer).await;

    let error = stack
        .write(
            Request::new(WriteRequest {
                address: object_address("rejected-redirect.bin"),
                body: Body::Bytes(b"small redirected payload".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("the presigned PUT must fail signature verification");

    assert_eq!(error.code(), ErrorCode::PermissionDenied, "{error}");
    let message = error.message();
    assert!(
        message.contains("SignatureDoesNotMatch"),
        "the sanitized provider code must be surfaced: {message}"
    );
    assert!(
        message.contains("403"),
        "the origin status must be surfaced: {message}"
    );

    let rejections = fake.rejections();
    assert!(
        !rejections.is_empty(),
        "the 403 must come from the fake's presigned-request verifier"
    );
    assert!(
        rejections.iter().any(|reason| reason.contains(ACCESS_KEY)),
        "the fixture rejection must contain the access key signing marker: {rejections:#?}"
    );
    for reason in &rejections {
        // The diagnostic is XML-escaped before it reaches the follower. Check
        // the exact on-wire spelling as well as the fixture's raw record so a
        // verbatim-body leak fails this test.
        let escaped = reason.replace('&', "&amp;").replace('<', "&lt;");
        assert!(
            !message.contains(reason.as_str()) && !message.contains(escaped.as_str()),
            "the raw signature-verification reason must not leak: {message}"
        );
    }
    assert!(
        !message.contains(ACCESS_KEY),
        "the access key id must not leak: {message}"
    );
}

#[tokio::test]
async fn follower_write_stream_with_size_hint_survives_minio_presign_verification() {
    // The second failing row of the report: a known-size `write_stream` takes
    // the same buffered redirect path as `write`.
    let fake = FakeMinio::spawn();
    let stack = follower_over(s3_layer_against(&fake).await).await;

    let payload = b"streamed-with-a-known-size".to_vec();
    let result = stack
        .write_stream(
            Request::new(WriteRequest {
                address: object_address("streamed-obj.bin"),
                body: Body::Bytes(payload.clone()),
                options: WriteOptions {
                    size_hint: Some(payload.len() as u64),
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await;

    assert_no_rejections(&fake, "write_stream with size_hint");
    result.expect("the redirected PUT must verify against MinIO");
    assert_eq!(fake.object("streamed-obj.bin"), Some(payload));
}

// === Multipart part PUTs ===

/// A layer that hands the follower a pre-built batch. Tests can either finish
/// synthetically or delegate `continue_write` to the real S3 layer, while
/// replaying genuine `UploadPart` URLs with a small body.
struct ReplayRedirectBatch {
    batch: WriteRedirectBatch,
    continuation_layer: Option<LayerHandle>,
}

#[async_trait]
impl Layer for ReplayRedirectBatch {
    fn name(&self) -> &str {
        "replay-one-redirect"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "replay-one-redirect".into(),
            layer_type: LayerType::Backend,
            display_name: "replay-one-redirect".into(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: false,
            auth_capable: false,
            supports_user_metadata: true,
        }
    }

    async fn write_redirect(
        &self,
        _request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        Ok(self.batch.clone())
    }

    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        if let Some(layer) = &self.continuation_layer {
            return layer.continue_write(request, cancel).await;
        }
        // Surface a non-2xx part upload as an error rather than a silent Done,
        // so a rejected signature fails the test at the assertion that names it.
        for result in &request.input.results.results {
            if !(200..300).contains(&result.status_code) {
                return Err(Error::new(
                    ErrorCode::PermissionDenied,
                    format!(
                        "part upload answered {}: {}",
                        result.status_code,
                        String::from_utf8_lossy(&result.captured_body),
                    ),
                ));
            }
        }
        Ok(WriteStep::Done(WriteResult {
            info: ObjectInfo {
                etag_strength: Default::default(),
                address: request.input.address,
                kind: ObjectKind::File,
                etag: Some("multipart-etag".into()),
                version: None,
                size: None,
                mtime: None,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
                versioned_address: None,
            },
        }))
    }
}

/// Ask the real S3 layer for a multipart batch by declaring a size above
/// `MULTIPART_REDIRECT_THRESHOLD_BYTES` (100 MiB). Nothing is uploaded here —
/// only the presigned `UploadPart` URLs are minted.
async fn multipart_batch(layer: &LayerHandle, key: &str) -> WriteRedirectBatch {
    layer
        .write_redirect(
            Request::new(WriteRequest {
                address: object_address(key),
                body: Body::Bytes(Vec::new()),
                options: WriteOptions {
                    size_hint: Some(200 * 1024 * 1024),
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await
        .expect("write_redirect must return a multipart batch")
}

#[tokio::test]
async fn multipart_part_presign_survives_minio_verification() {
    // A full ≥100 MiB end-to-end multipart is out of scope: the threshold is
    // hardcoded, and a body that large spools past the follower's replay
    // threshold onto the streaming (reqwest) arm anyway — a different code
    // path. What matters here is that an `UploadPart` presign replayed by the
    // follower verifies, so replay part 1 with a small body.
    let fake = FakeMinio::spawn();
    let layer = s3_layer_against(&fake).await;
    let batch = multipart_batch(&layer, "big.bin").await;
    assert!(
        batch.redirects.len() >= 2,
        "a 200 MiB write must plan multiple parts, got {}",
        batch.redirects.len()
    );
    for redirect in &batch.redirects {
        assert!(
            redirect.result_capture.body_max_bytes > 0,
            "minted UploadPart redirect must capture an error body"
        );
    }

    let payload = b"part-one!".to_vec();
    let mut redirect = batch.redirects[0].clone();
    redirect.body_source = RedirectBodySource::UserBytes {
        offset: 0,
        len: payload.len() as u64,
    };
    assert!(
        redirect.request.url.contains("partNumber=1"),
        "expected an UploadPart URL, got {}",
        redirect.request.url
    );

    let stack = follower_over(Arc::new(ReplayRedirectBatch {
        batch: WriteRedirectBatch {
            continuation: Vec::new(),
            redirects: vec![redirect],
        },
        continuation_layer: None,
    }))
    .await;
    let result = stack
        .write(
            Request::new(WriteRequest {
                address: object_address("big.bin"),
                body: Body::Bytes(payload),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await;

    assert_no_rejections(&fake, "multipart part PUT");
    result.expect("the presigned UploadPart must verify against MinIO");
}

#[tokio::test]
async fn truncated_multipart_error_body_still_aborts_the_upload() {
    let fake = FakeMinio::spawn_truncating_upload_part_error();
    let layer = s3_layer_against(&fake).await;
    let mut batch = multipart_batch(&layer, "truncated-error.bin").await;
    assert!(batch.redirects.len() >= 2, "expected multiple parts");
    for redirect in &batch.redirects {
        assert!(
            redirect.result_capture.body_max_bytes > 0,
            "minted UploadPart redirect must capture an error body"
        );
    }

    let payload = b"part-one!".to_vec();
    batch.redirects.truncate(1);
    batch.redirects[0].body_source = RedirectBodySource::UserBytes {
        offset: 0,
        len: payload.len() as u64,
    };

    let replay: LayerHandle = Arc::new(ReplayRedirectBatch {
        batch,
        continuation_layer: Some(layer),
    });
    let mut follower_config = LayerConfig::new();
    follower_config.insert("max_attempts".into(), ConfigValue::Int(2));
    follower_config.insert("initial_delay_ms".into(), ConfigValue::Int(0));
    follower_config.insert("max_delay_ms".into(), ConfigValue::Int(0));
    let stack = RedirectFollowerWrapperFactory
        .create_wrapper("follower", &follower_config, replay, None)
        .await
        .expect("create redirect_follower");

    let error = stack
        .write(
            Request::new(WriteRequest {
                address: object_address("truncated-error.bin"),
                body: Body::Bytes(payload),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("truncated response framing must fail the write");

    assert_eq!(
        error.code(),
        ErrorCode::Transient,
        "the original response-body transport error must be preserved: {error}"
    );
    assert_no_rejections(&fake, "truncated multipart error response");

    let requests = fake.requests();
    let upload_part_attempts = requests
        .iter()
        .filter(|request| {
            request.method == "PUT"
                && request.presigned
                && request.query.contains("uploadId=")
                && request.query.contains("partNumber=")
                && request.status == 403
        })
        .count();
    assert_eq!(
        upload_part_attempts, 2,
        "the follower must exhaust its configured retries before cleanup: {requests:#?}"
    );
    assert!(
        requests.iter().any(|request| {
            request.method == "DELETE"
                && !request.presigned
                && request.query.contains("uploadId=fake-upload-id")
                && request.status == 204
        }),
        "the real S3 continuation must abort the multipart upload: {requests:#?}"
    );
    assert!(
        !requests
            .iter()
            .any(|request| { request.method == "POST" && request.query.contains("uploadId=") }),
        "a failed multipart upload must not be completed: {requests:#?}"
    );
}

// === Construction-level guard ===

/// The signed-header names in a presigned URL's `X-Amz-SignedHeaders`.
fn signed_headers(url: &str) -> Vec<String> {
    let parsed = Url::parse(url).expect("presigned URL parses");
    parsed
        .query_pairs()
        .find(|(name, _)| name == "X-Amz-SignedHeaders")
        .map(|(_, value)| value.split(';').map(str::to_string).collect())
        .unwrap_or_default()
}

/// Every signed header must be replayable: either the follower derives it from
/// the URL (`host`) or the plugin echoed it into `request.headers`. A name in
/// neither set is unreplayable by construction, and no traffic is needed to
/// catch that divergence.
fn assert_signed_headers_are_replayable(redirect: &WriteRedirect, context: &str) {
    let echoed: Vec<String> = redirect
        .request
        .headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect();
    let signed = signed_headers(&redirect.request.url);
    assert!(
        !signed.is_empty(),
        "{context}: a presigned URL must sign at least `host`"
    );
    for name in &signed {
        assert!(
            name == "host" || echoed.contains(name),
            "{context}: signed header '{name}' is neither derived from the URL \
             nor echoed for replay (signed: {signed:?}, echoed: {echoed:?})"
        );
    }
}

#[tokio::test]
async fn every_signed_header_is_echoed_into_the_redirect() {
    let fake = FakeMinio::spawn();
    let layer = s3_layer_against(&fake).await;

    let single = |options: WriteOptions, key: &'static str| {
        let layer = layer.clone();
        async move {
            layer
                .write_redirect(
                    Request::new(WriteRequest {
                        address: object_address(key),
                        body: Body::Bytes(Vec::new()),
                        options,
                    }),
                    None,
                )
                .await
                .expect("write_redirect")
        }
    };

    // Plain PUT: `host` only.
    let plain = single(
        WriteOptions {
            size_hint: Some(16),
            ..WriteOptions::default()
        },
        "plain.bin",
    )
    .await;
    assert_signed_headers_are_replayable(&plain.redirects[0], "plain put");

    // `if_dest: Fail` signs `if-none-match`.
    let create_only = single(
        WriteOptions {
            size_hint: Some(16),
            if_dest: IfDestExists::Fail,
            ..WriteOptions::default()
        },
        "create-only.bin",
    )
    .await;
    assert_signed_headers_are_replayable(&create_only.redirects[0], "if_dest: Fail");

    // `if_dest: MatchEtag` signs `if-match`.
    let conditional = single(
        WriteOptions {
            size_hint: Some(16),
            if_dest: IfDestExists::MatchEtag("etag-1".into()),
            ..WriteOptions::default()
        },
        "conditional.bin",
    )
    .await;
    assert_signed_headers_are_replayable(&conditional.redirects[0], "if_dest: MatchEtag");

    // User metadata signs one `x-amz-meta-*` per entry.
    let mut metadata = UserMetadata::new();
    metadata.insert("Project".into(), "redline".into());
    metadata.insert("stage".into(), "conformance".into());
    let annotated = single(
        WriteOptions {
            size_hint: Some(16),
            user_metadata: Some(metadata),
            if_dest: IfDestExists::MatchEtag("etag-2".into()),
            ..WriteOptions::default()
        },
        "annotated.bin",
    )
    .await;
    assert_signed_headers_are_replayable(&annotated.redirects[0], "metadata + if_dest");

    // Every part of a multipart batch, not just the first.
    let batch = multipart_batch(&layer, "multi.bin").await;
    for (index, redirect) in batch.redirects.iter().enumerate() {
        assert_signed_headers_are_replayable(redirect, &format!("multipart part {}", index + 1));
    }
}

// === Negative control ===

#[tokio::test]
async fn fake_minio_rejects_a_tampered_host() {
    // Everything above is only meaningful if the fake can actually say no. Take
    // a genuine presigned PUT, replay it with the port stripped from `Host`, and
    // confirm the 403. Without this, a verifier that silently degraded to
    // accepting anything would leave the whole suite green and worthless.
    let fake = FakeMinio::spawn();
    let layer = s3_layer_against(&fake).await;
    let batch = layer
        .write_redirect(
            Request::new(WriteRequest {
                address: object_address("tampered.bin"),
                body: Body::Bytes(Vec::new()),
                options: WriteOptions {
                    size_hint: Some(4),
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await
        .expect("write_redirect");
    let redirect = &batch.redirects[0];

    let url = Url::parse(&redirect.request.url).expect("presigned URL parses");
    let host = url.host_str().expect("host").to_string();
    let port = url.port_or_known_default().expect("port");
    let target = match url.query() {
        Some(query) => format!("{}?{}", url.path(), query),
        None => url.path().to_string(),
    };

    // Control: the authority the signature covers is accepted.
    let mut headers = vec![("Host".to_string(), format!("{host}:{port}"))];
    headers.extend(redirect.request.headers.iter().cloned());
    let (status, body) = send_raw(
        fake.endpoint(),
        &redirect.request.method,
        &target,
        &headers,
        b"data",
    );
    assert_eq!(status, 200, "the signed authority must verify: {body}");

    // Tamper: same bytes, port dropped from Host.
    headers[0].1 = host;
    let (status, body) = send_raw(
        fake.endpoint(),
        &redirect.request.method,
        &target,
        &headers,
        b"data",
    );
    assert_eq!(
        status, 403,
        "a Host missing the signed port must be rejected"
    );
    assert!(
        body.contains("SignatureDoesNotMatch"),
        "the rejection must be a signature mismatch: {body}"
    );
    assert_eq!(
        fake.rejections().len(),
        1,
        "the rejection must be recorded for diagnosis"
    );
}
