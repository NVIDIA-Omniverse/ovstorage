// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Multipart write state-machine fixture; `Initiate`/`Complete` served by an in-process listener.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ovstorage_plugin::{
    BackendId, ConfigValue, ErrorCode, IfDestExists, RedirectResult, RedirectResultBatch,
    WriteOptions, address,
};
use ovstorage_plugin::{ResolvedTarget, WriteStep};
use ovstorage_plugin_s3::{AwsCredentials, S3Backend};
use ovstorage_plugin_test::{CapturedRequest, Responder, Route, ScriptedResponse};

const INITIATE_PATH: &str = "/bkt/big.bin?uploads";
const UPLOAD_ID_QUERY: &str = "uploadId=UPLOAD-FIXTURE";
const INITIATE_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <InitiateMultipartUploadResult>\
        <Bucket>bkt</Bucket><Key>big.bin</Key>\
        <UploadId>UPLOAD-FIXTURE</UploadId>\
    </InitiateMultipartUploadResult>";

fn xml_response(status: u16, body: &str) -> ScriptedResponse {
    ScriptedResponse {
        status,
        headers: vec![("content-type".into(), "application/xml".into())],
        body: body.as_bytes().to_vec(),
    }
}

fn empty_response(status: u16) -> ScriptedResponse {
    ScriptedResponse {
        status,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn spawn_s3_fixture(complete_response: Option<ScriptedResponse>, serve_abort: bool) -> Responder {
    let mut routes = vec![Route::new(
        "POST",
        INITIATE_PATH,
        xml_response(200, INITIATE_BODY),
    )];
    if let Some(response) = complete_response {
        // The SDK prepends `x-id=CompleteMultipartUpload` before `uploadId`.
        // The Initiate route above wins first-match for its `?uploads` path.
        routes.push(Route::new("POST", "/bkt/big.bin?", response));
    }
    if serve_abort {
        // The SDK prepends `x-id=AbortMultipartUpload` before `uploadId`.
        routes.push(Route::new("DELETE", "/bkt/big.bin?", empty_response(204)));
    }
    Responder::start(routes).expect("start S3 fixture")
}

async fn wait_for_request(
    fixture: &Responder,
    predicate: impl Fn(&CapturedRequest) -> bool,
) -> bool {
    for _ in 0..100 {
        if fixture.captures().iter().any(&predicate) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test]
async fn write_returns_redirect_batch_then_continue_write_completes() {
    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <CompleteMultipartUploadResult>\
            <Bucket>bkt</Bucket><Key>big.bin</Key>\
            <ETag>\"final-etag\"</ETag>\
        </CompleteMultipartUploadResult>";
    let fixture = spawn_s3_fixture(Some(xml_response(200, body)), false);
    let endpoint = format!("http://{}", fixture.addr());

    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String("bkt".into()));
    config.insert("region".into(), ConfigValue::String("us-east-1".into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint));
    config.insert(
        "compatibility_profile".into(),
        ConfigValue::String("custom".into()),
    );
    config.insert("force_path_style".into(), ConfigValue::Bool(true));
    let parsed = ovstorage_plugin_s3::__test_only_parse_config(&config).expect("parse config");
    let credentials = AwsCredentials {
        access_key_id: "AKIATESTFIXTURE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,
    };
    let backend = Arc::new(S3Backend::with_credentials(parsed, credentials).expect("backend init"));

    let target = ResolvedTarget {
        backend_id: BackendId("s3:s3://bkt/".into()),
        resolved_address: address::parse("s3://bkt/big.bin").unwrap(),
    };

    // Above the 100 MiB multipart-redirect threshold; size_hint drives part planning.
    let body_bytes_len = 128 * 1024 * 1024_u64;
    let body_bytes = vec![0xABu8; body_bytes_len as usize];
    let opts = WriteOptions {
        size_hint: Some(body_bytes.len() as u64),
        ..WriteOptions::default()
    };
    let batch = backend
        .write_redirect(target.clone(), opts, None)
        .await
        .expect("write_redirect should return a multipart batch");
    assert!(batch.redirects.len() >= 2, "expected multiple parts");
    assert!(
        !batch.continuation.is_empty(),
        "continuation must be non-empty"
    );

    let results: Vec<RedirectResult> = batch
        .redirects
        .iter()
        .enumerate()
        .map(|(idx, _)| RedirectResult {
            status_code: 200,
            captured_headers: vec![("etag".into(), format!("\"part-etag-{}\"", idx + 1))],
            captured_body: Vec::new(),
        })
        .collect();
    let result_batch = RedirectResultBatch { results };

    let next = backend
        .continue_write(target, batch, result_batch, None)
        .await
        .expect("continue_write should return Done");
    let result = match next {
        WriteStep::Done(result) => result,
        WriteStep::Redirects(_) => panic!("expected Done after final part batch"),
    };
    assert_eq!(result.info.etag.as_deref(), Some("final-etag"));
    assert_eq!(result.info.size, Some(body_bytes.len() as u64));
}

#[tokio::test]
async fn continue_write_aborts_multipart_when_part_etag_is_missing() {
    let fixture = spawn_s3_fixture(None, true);
    let endpoint = format!("http://{}", fixture.addr());

    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String("bkt".into()));
    config.insert("region".into(), ConfigValue::String("us-east-1".into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint));
    config.insert(
        "compatibility_profile".into(),
        ConfigValue::String("custom".into()),
    );
    config.insert("force_path_style".into(), ConfigValue::Bool(true));
    let parsed = ovstorage_plugin_s3::__test_only_parse_config(&config).expect("parse config");
    let credentials = AwsCredentials {
        access_key_id: "AKIATESTFIXTURE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,
    };
    let backend = Arc::new(S3Backend::with_credentials(parsed, credentials).expect("backend init"));

    let target = ResolvedTarget {
        backend_id: BackendId("s3:s3://bkt/".into()),
        resolved_address: address::parse("s3://bkt/big.bin").unwrap(),
    };

    let body_bytes_len = 128 * 1024 * 1024_u64;
    let opts = WriteOptions {
        size_hint: Some(body_bytes_len),
        ..WriteOptions::default()
    };
    let batch = backend
        .write_redirect(target.clone(), opts, None)
        .await
        .expect("write_redirect should return a multipart batch");
    assert!(batch.redirects.len() >= 2);

    // Second result missing ETag header simulates a proxy race; the orphan upload must be aborted.
    let results: Vec<RedirectResult> = batch
        .redirects
        .iter()
        .enumerate()
        .map(|(idx, _)| RedirectResult {
            status_code: 200,
            captured_headers: if idx == 0 {
                vec![("etag".into(), "\"part-etag-1\"".into())]
            } else {
                Vec::new()
            },
            captured_body: Vec::new(),
        })
        .collect();
    let result_batch = RedirectResultBatch { results };

    let err = backend
        .continue_write(target, batch, result_batch, None)
        .await
        .expect_err("missing ETag must surface as an error");
    assert!(
        err.to_string().contains("ETag"),
        "expected ETag error, got: {err}"
    );

    assert!(
        wait_for_request(&fixture, |request| {
            request.method == "DELETE" && request.path.contains(UPLOAD_ID_QUERY)
        })
        .await,
        "AbortMultipartUpload (DELETE ?uploadId=) must fire when a part is missing an ETag; \
         captures: {:?}",
        fixture.captures(),
    );
}

/// S3 can answer `CompleteMultipartUpload` with HTTP 200 carrying an embedded
/// `<Error>` envelope. `InvalidPart` is a terminal commit failure, so it must
/// surface as `ObjectModified` — not a retryable `Transient` (the regression
/// that arose from mapping the raw 200 status). The orphaned upload is aborted.
#[tokio::test]
async fn complete_multipart_upload_200_error_envelope_maps_object_modified() {
    // HTTP 200 with an `<Error>` body — the S3 "200 OK error" quirk.
    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <Error>\
            <Code>InvalidPart</Code>\
            <Message>One or more of the specified parts could not be found</Message>\
            <RequestId>fixture-req</RequestId>\
            <HostId>fixture-host</HostId>\
        </Error>";
    let fixture = spawn_s3_fixture(Some(xml_response(200, body)), true);
    let endpoint = format!("http://{}", fixture.addr());

    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String("bkt".into()));
    config.insert("region".into(), ConfigValue::String("us-east-1".into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint));
    config.insert(
        "compatibility_profile".into(),
        ConfigValue::String("custom".into()),
    );
    config.insert("force_path_style".into(), ConfigValue::Bool(true));
    let parsed = ovstorage_plugin_s3::__test_only_parse_config(&config).expect("parse config");
    let credentials = AwsCredentials {
        access_key_id: "AKIATESTFIXTURE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,
    };
    let backend = Arc::new(S3Backend::with_credentials(parsed, credentials).expect("backend init"));

    let target = ResolvedTarget {
        backend_id: BackendId("s3:s3://bkt/".into()),
        resolved_address: address::parse("s3://bkt/big.bin").unwrap(),
    };

    let body_bytes_len = 128 * 1024 * 1024_u64;
    let opts = WriteOptions {
        size_hint: Some(body_bytes_len),
        ..WriteOptions::default()
    };
    let batch = backend
        .write_redirect(target.clone(), opts, None)
        .await
        .expect("write_redirect should return a multipart batch");
    assert!(batch.redirects.len() >= 2);

    // All parts report success with an ETag, so the flow reaches Complete.
    let results: Vec<RedirectResult> = batch
        .redirects
        .iter()
        .enumerate()
        .map(|(idx, _)| RedirectResult {
            status_code: 200,
            captured_headers: vec![("etag".into(), format!("\"part-etag-{}\"", idx + 1))],
            captured_body: Vec::new(),
        })
        .collect();
    let result_batch = RedirectResultBatch { results };

    let err = backend
        .continue_write(target, batch, result_batch, None)
        .await
        .expect_err("CompleteMultipartUpload 200 <Error> must surface as an error");
    assert_eq!(
        err.code(),
        ErrorCode::ObjectModified,
        "InvalidPart must map to ObjectModified (terminal), not Transient; got: {err}"
    );

    assert!(
        wait_for_request(&fixture, |request| {
            request.method == "DELETE" && request.path.contains(UPLOAD_ID_QUERY)
        })
        .await,
        "the orphaned upload must be aborted after a failed Complete; captures: {:?}",
        fixture.captures(),
    );
}

/// No-overwrite on the multipart path: a large no-overwrite write hits the
/// `IfDestExists::Fail` contract at CompleteMultipartUpload time — the 412
/// on the `If-None-Match: *` complete must surface the documented
/// `AlreadyExists` (not `PreconditionFailed`), and the conditional must
/// actually ride the Complete request on the wire.
#[tokio::test]
async fn no_overwrite_complete_multipart_412_maps_already_exists() {
    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <Error>\
            <Code>PreconditionFailed</Code>\
            <Message>At least one of the pre-conditions you specified did not hold</Message>\
            <RequestId>fixture-req</RequestId>\
        </Error>";
    let fixture = spawn_s3_fixture(Some(xml_response(412, body)), true);
    let endpoint = format!("http://{}", fixture.addr());

    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String("bkt".into()));
    config.insert("region".into(), ConfigValue::String("us-east-1".into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint));
    config.insert(
        "compatibility_profile".into(),
        ConfigValue::String("custom".into()),
    );
    config.insert("force_path_style".into(), ConfigValue::Bool(true));
    let parsed = ovstorage_plugin_s3::__test_only_parse_config(&config).expect("parse config");
    let credentials = AwsCredentials {
        access_key_id: "AKIATESTFIXTURE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,
    };
    let backend = Arc::new(S3Backend::with_credentials(parsed, credentials).expect("backend init"));

    let target = ResolvedTarget {
        backend_id: BackendId("s3:s3://bkt/".into()),
        resolved_address: address::parse("s3://bkt/big.bin").unwrap(),
    };

    let body_bytes_len = 128 * 1024 * 1024_u64;
    let opts = WriteOptions {
        size_hint: Some(body_bytes_len),
        if_dest: IfDestExists::Fail,
        ..WriteOptions::default()
    };
    let batch = backend
        .write_redirect(target.clone(), opts, None)
        .await
        .expect("write_redirect should return a multipart batch");
    assert!(batch.redirects.len() >= 2);

    // All parts report success, so the flow reaches the conditional Complete.
    let results: Vec<RedirectResult> = batch
        .redirects
        .iter()
        .enumerate()
        .map(|(idx, _)| RedirectResult {
            status_code: 200,
            captured_headers: vec![("etag".into(), format!("\"part-etag-{}\"", idx + 1))],
            captured_body: Vec::new(),
        })
        .collect();
    let result_batch = RedirectResultBatch { results };

    let err = backend
        .continue_write(target, batch, result_batch, None)
        .await
        .expect_err("the no-overwrite Complete must refuse");
    assert_eq!(
        err.code(),
        ErrorCode::AlreadyExists,
        "the If-None-Match: * 412 at Complete is the exists-refusal; got: {err}"
    );
    assert!(
        fixture.captures().iter().any(|request| {
            request.method == "POST"
                && request.path.contains(UPLOAD_ID_QUERY)
                && request.header("if-none-match") == Some("*")
        }),
        "the Complete request must carry If-None-Match: * on the wire",
    );
}

/// Substitution, not modification: a caller holding a *genuine* multipart
/// continuation minted for `big.bin` presents it against the request address
/// `victim.bin`. Under the broker's client-driven `ContinueWrite` RPC the whole
/// batch is echoed back by the remote caller, while the address is the value
/// authorization was decided on — so `CompleteMultipartUpload` must name the
/// authorized key and never the one recorded in the blob.
#[tokio::test]
async fn continue_write_commits_to_the_authorized_key_not_the_continuations() {
    let complete_body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <CompleteMultipartUploadResult>\
            <Bucket>bkt</Bucket><Key>victim.bin</Key>\
            <ETag>\"final-etag\"</ETag>\
        </CompleteMultipartUploadResult>";
    // Both completion paths are served, so the test distinguishes *which* the
    // plugin chose rather than passing because one of them 404s.
    let routes = vec![
        Route::new("POST", INITIATE_PATH, xml_response(200, INITIATE_BODY)),
        Route::new("POST", "/bkt/victim.bin?", xml_response(200, complete_body)),
        Route::new("POST", "/bkt/big.bin?", xml_response(200, complete_body)),
        Route::new("DELETE", "/bkt/", empty_response(204)),
    ];
    let fixture = Responder::start(routes).expect("start S3 fixture");
    let endpoint = format!("http://{}", fixture.addr());

    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String("bkt".into()));
    config.insert("region".into(), ConfigValue::String("us-east-1".into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint));
    config.insert(
        "compatibility_profile".into(),
        ConfigValue::String("custom".into()),
    );
    config.insert("force_path_style".into(), ConfigValue::Bool(true));
    let parsed = ovstorage_plugin_s3::__test_only_parse_config(&config).expect("parse config");
    let credentials = AwsCredentials {
        access_key_id: "AKIATESTFIXTURE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,
    };
    let backend = Arc::new(S3Backend::with_credentials(parsed, credentials).expect("backend init"));

    let minted_for = ResolvedTarget {
        backend_id: BackendId("s3:s3://bkt/".into()),
        resolved_address: address::parse("s3://bkt/big.bin").unwrap(),
    };
    let authorized = ResolvedTarget {
        backend_id: BackendId("s3:s3://bkt/".into()),
        resolved_address: address::parse("s3://bkt/victim.bin").unwrap(),
    };

    let opts = WriteOptions {
        size_hint: Some(128 * 1024 * 1024_u64),
        ..WriteOptions::default()
    };
    let batch = backend
        .write_redirect(minted_for, opts, None)
        .await
        .expect("write_redirect should return a multipart batch");
    assert!(batch.redirects.len() >= 2, "expected multiple parts");

    let results: Vec<RedirectResult> = batch
        .redirects
        .iter()
        .enumerate()
        .map(|(idx, _)| RedirectResult {
            status_code: 200,
            captured_headers: vec![("etag".into(), format!("\"part-etag-{}\"", idx + 1))],
            captured_body: Vec::new(),
        })
        .collect();
    let result_batch = RedirectResultBatch { results };

    let step = backend
        .continue_write(authorized, batch, result_batch, None)
        .await
        .expect("continue_write should complete against the authorized key");
    let result = match step {
        WriteStep::Done(result) => result,
        WriteStep::Redirects(_) => panic!("expected Done after the final part batch"),
    };
    assert_eq!(result.info.address.as_str(), "s3://bkt/victim.bin");

    let completes: Vec<String> = fixture
        .captures()
        .iter()
        .filter(|request| request.method == "POST" && request.path.contains(UPLOAD_ID_QUERY))
        .map(|request| request.path.clone())
        .collect();
    assert!(
        !completes.is_empty(),
        "CompleteMultipartUpload must have been sent; captures: {:?}",
        fixture.captures()
    );
    assert!(
        completes
            .iter()
            .all(|path| path.starts_with("/bkt/victim.bin")),
        "CompleteMultipartUpload must name the authorized key, not the continuation's; got {completes:?}"
    );
}

/// `?versionId=` is dropped when the key is derived, so a continuation
/// presented against a version-pinned address would commit to the head while
/// authorization was decided on the frozen-version URL. `write`,
/// `write_stream` and `write_redirect` all refuse such an address; so must
/// `continue_write`.
#[tokio::test]
async fn continue_write_refuses_a_version_pinned_address() {
    let fixture = spawn_s3_fixture(None, false);
    let endpoint = format!("http://{}", fixture.addr());

    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String("bkt".into()));
    config.insert("region".into(), ConfigValue::String("us-east-1".into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint));
    config.insert(
        "compatibility_profile".into(),
        ConfigValue::String("custom".into()),
    );
    config.insert("force_path_style".into(), ConfigValue::Bool(true));
    let parsed = ovstorage_plugin_s3::__test_only_parse_config(&config).expect("parse config");
    let credentials = AwsCredentials {
        access_key_id: "AKIATESTFIXTURE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,
    };
    let backend = Arc::new(S3Backend::with_credentials(parsed, credentials).expect("backend init"));

    let target = ResolvedTarget {
        backend_id: BackendId("s3:s3://bkt/".into()),
        resolved_address: address::parse("s3://bkt/big.bin").unwrap(),
    };
    let opts = WriteOptions {
        size_hint: Some(128 * 1024 * 1024_u64),
        ..WriteOptions::default()
    };
    let batch = backend
        .write_redirect(target, opts, None)
        .await
        .expect("write_redirect should return a multipart batch");
    let results = RedirectResultBatch {
        results: batch
            .redirects
            .iter()
            .enumerate()
            .map(|(idx, _)| RedirectResult {
                status_code: 200,
                captured_headers: vec![("etag".into(), format!("\"part-etag-{}\"", idx + 1))],
                captured_body: Vec::new(),
            })
            .collect(),
    };

    let pinned = ResolvedTarget {
        backend_id: BackendId("s3:s3://bkt/".into()),
        resolved_address: address::parse("s3://bkt/big.bin?versionId=frozen").unwrap(),
    };
    let err = backend
        .continue_write(pinned, batch, results, None)
        .await
        .expect_err("a version-pinned address must be refused");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

/// The commit is not the only thing derivation has to move. Mint for `big.bin`,
/// continue against `victim.bin`, and force a part failure: the `DELETE` must
/// name the authorized key.
///
/// The negative half — that no `DELETE` names `big.bin` — is belt and braces
/// rather than the mechanism. `MultipartContinuation::key` is
/// `#[serde(skip_deserializing)]`, so an abort that read the continuation would
/// send an *empty* key, not the minted one. What the positive assertion pins is
/// that the derived key reaches the abort at all.
#[tokio::test]
async fn continue_write_aborts_against_the_authorized_key_not_the_continuations() {
    let routes = vec![
        Route::new("POST", INITIATE_PATH, xml_response(200, INITIATE_BODY)),
        Route::new("DELETE", "/bkt/", empty_response(204)),
    ];
    let fixture = Responder::start(routes).expect("start S3 fixture");
    let endpoint = format!("http://{}", fixture.addr());

    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String("bkt".into()));
    config.insert("region".into(), ConfigValue::String("us-east-1".into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint));
    config.insert(
        "compatibility_profile".into(),
        ConfigValue::String("custom".into()),
    );
    config.insert("force_path_style".into(), ConfigValue::Bool(true));
    let parsed = ovstorage_plugin_s3::__test_only_parse_config(&config).expect("parse config");
    let credentials = AwsCredentials {
        access_key_id: "AKIATESTFIXTURE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,
    };
    let backend = Arc::new(S3Backend::with_credentials(parsed, credentials).expect("backend init"));

    let minted_for = ResolvedTarget {
        backend_id: BackendId("s3:s3://bkt/".into()),
        resolved_address: address::parse("s3://bkt/big.bin").unwrap(),
    };
    let authorized = ResolvedTarget {
        backend_id: BackendId("s3:s3://bkt/".into()),
        resolved_address: address::parse("s3://bkt/victim.bin").unwrap(),
    };
    let opts = WriteOptions {
        size_hint: Some(128 * 1024 * 1024_u64),
        ..WriteOptions::default()
    };
    let batch = backend
        .write_redirect(minted_for, opts, None)
        .await
        .expect("write_redirect should return a multipart batch");

    // Second part reports no ETag, which drives the abort path.
    let results: Vec<RedirectResult> = batch
        .redirects
        .iter()
        .enumerate()
        .map(|(idx, _)| RedirectResult {
            status_code: 200,
            captured_headers: if idx == 0 {
                vec![("etag".into(), "\"part-etag-1\"".into())]
            } else {
                Vec::new()
            },
            captured_body: Vec::new(),
        })
        .collect();

    backend
        .continue_write(authorized, batch, RedirectResultBatch { results }, None)
        .await
        .expect_err("missing ETag must surface as an error");

    assert!(
        wait_for_request(&fixture, |request| {
            request.method == "DELETE" && request.path.starts_with("/bkt/victim.bin")
        })
        .await,
        "the abort must target the authorized key; captures: {:?}",
        fixture.captures(),
    );
    assert!(
        !fixture
            .captures()
            .iter()
            .any(|request| request.method == "DELETE" && request.path.starts_with("/bkt/big.bin")),
        "no abort may target the continuation's key; captures: {:?}",
        fixture.captures(),
    );
}
