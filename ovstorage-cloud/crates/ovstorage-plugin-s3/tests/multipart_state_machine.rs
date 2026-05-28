// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Multipart write state-machine fixture; `Initiate`/`Complete` served by an in-process listener.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use ovstorage_plugin::{
    BackendId, ConfigValue, RedirectResult, RedirectResultBatch, WriteOptions, address,
};
use ovstorage_plugin::{ResolvedTarget, WriteStep, shim::Backend};
use ovstorage_plugin_s3::{AwsCredentials, S3Backend};

fn spawn_s3_fixture<F: FnOnce() + Send + 'static>(f: F) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("ovs-test-s3".into())
        .spawn(f)
        .expect("failed to spawn thread")
}

#[tokio::test]
async fn write_returns_redirect_batch_then_continue_write_completes() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{}", addr);

    spawn_s3_fixture(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let mut buf = [0u8; 65536];
            let len = match stream.read(stream_clone(&mut buf)) {
                Ok(len) => len,
                Err(_) => continue,
            };
            let request = String::from_utf8_lossy(&buf[..len]).to_string();
            let response = if request.contains("?uploads") && request.starts_with("POST ") {
                let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                    <InitiateMultipartUploadResult>\
                        <Bucket>bkt</Bucket><Key>big.bin</Key>\
                        <UploadId>UPLOAD-FIXTURE</UploadId>\
                    </InitiateMultipartUploadResult>";
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body,
                )
            } else if request.contains("uploadId=UPLOAD-FIXTURE") && request.starts_with("POST ") {
                let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                    <CompleteMultipartUploadResult>\
                        <Bucket>bkt</Bucket><Key>big.bin</Key>\
                        <ETag>\"final-etag\"</ETag>\
                    </CompleteMultipartUploadResult>";
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body,
                )
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
            };
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            drop(stream);
        }
    });

    thread::sleep(Duration::from_millis(50));

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

fn stream_clone(buf: &mut [u8]) -> &mut [u8] {
    buf
}

#[tokio::test]
async fn continue_write_aborts_multipart_when_part_etag_is_missing() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{}", addr);
    let abort_count = Arc::new(AtomicUsize::new(0));
    let abort_count_for_thread = abort_count.clone();

    spawn_s3_fixture(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let mut buf = [0u8; 65536];
            let len = match stream.read(stream_clone(&mut buf)) {
                Ok(len) => len,
                Err(_) => continue,
            };
            let request = String::from_utf8_lossy(&buf[..len]).to_string();
            let response = if request.contains("?uploads") && request.starts_with("POST ") {
                let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                    <InitiateMultipartUploadResult>\
                        <Bucket>bkt</Bucket><Key>big.bin</Key>\
                        <UploadId>UPLOAD-FIXTURE</UploadId>\
                    </InitiateMultipartUploadResult>";
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body,
                )
            } else if request.starts_with("DELETE ") && request.contains("uploadId=UPLOAD-FIXTURE")
            {
                abort_count_for_thread.fetch_add(1, Ordering::SeqCst);
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_string()
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
            };
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            drop(stream);
        }
    });

    thread::sleep(Duration::from_millis(50));

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

    thread::sleep(Duration::from_millis(50));
    assert!(
        abort_count.load(Ordering::SeqCst) >= 1,
        "AbortMultipartUpload (DELETE ?uploadId=) must fire when a part is missing an ETag",
    );
}
