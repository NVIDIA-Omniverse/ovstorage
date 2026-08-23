// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What an anonymous S3 connection can serve, and how it fails when it cannot.
//!
//! S3 authenticates by SigV4 signature; a request carrying none is evaluated as
//! the anonymous principal, so every action a bucket grants to `*` is servable
//! unsigned. The two that matter for browsing a public bucket are
//! `ListObjectsV2` and `HeadObject`; these tests drive both against a loopback
//! fake and assert on **what came back**, not merely that the call did not
//! error. The last test covers the other side of the line — the mutations an
//! anonymous connection still refuses, and how.
//!
//! Three properties are pinned here, and each has a control:
//!
//! 1. the request really leaves unsigned (control:
//!    [`a_credentialed_connection_still_signs_its_list`], the same fixture and
//!    the same operation with credentials, which must carry `Authorization`);
//! 2. the honest answer is parsed and returned (asserted field by field, so a
//!    fake that answered `200` with nothing would fail);
//! 3. a bucket that refuses the unsigned list — public-read, private-list,
//!    which is an ordinary configuration — surfaces as something an operator
//!    can act on, and specifically not as a credential problem.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ovstorage_plugin::{
    AccessOps, BackendId, BodyStream, ConfigValue, CopyOptions, CreateDirectoryOptions,
    DeleteDirectoryOptions, DeleteOptions, ErrorCode, ListOptions, ObjectKind, RedirectResultBatch,
    RenameOptions, ResolvedTarget, StatOptions, UpdateMetadataOptions, WriteOptions,
    WriteRedirectBatch, address,
};
use ovstorage_plugin_s3::{AwsCredentials, S3Backend};

const BUCKET: &str = "bkt";

/// A `ListObjectsV2` answer with one object and one common prefix. Both arms of
/// the plugin's list mapping (`Contents` → `File`, `CommonPrefixes` →
/// `DirectoryInferred`) are exercised by it.
/// `LIST_ITEM_CEILING` in the backend: the 100,000-entry budget plus one full
/// 1000-key page. Private there, so the fixture restates it; the tests that use
/// it assert on the message, which carries the backend's own number.
const LIST_ITEM_CEILING_ENTRIES: usize = 101_000;

const LIST_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
    <Name>bkt</Name><Prefix>assets/</Prefix><Delimiter>/</Delimiter>\
    <KeyCount>2</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>\
    <Contents><Key>assets/teapot.usd</Key>\
    <LastModified>2026-01-02T03:04:05.000Z</LastModified>\
    <ETag>&quot;9a1f2b&quot;</ETag><Size>2048</Size>\
    <StorageClass>STANDARD</StorageClass></Contents>\
    <CommonPrefixes><Prefix>assets/textures/</Prefix></CommonPrefixes>\
    </ListBucketResult>";

/// Page one of a truncated listing: one object, `IsTruncated`, and the token
/// that reaches page two.
const FIRST_PAGE_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
    <Name>bkt</Name><Prefix>assets/</Prefix><Delimiter>/</Delimiter>\
    <KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>true</IsTruncated>\
    <NextContinuationToken>PAGE2TOKEN</NextContinuationToken>\
    <Contents><Key>assets/first.usd</Key>\
    <LastModified>2026-01-02T03:04:05.000Z</LastModified>\
    <ETag>&quot;p1&quot;</ETag><Size>1</Size></Contents>\
    </ListBucketResult>";

/// A page that claims truncation and offers nothing to resume from.
const TRUNCATED_NO_TOKEN_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
    <Name>bkt</Name><Prefix>assets/</Prefix><Delimiter>/</Delimiter>\
    <KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>true</IsTruncated>\
    <Contents><Key>assets/first.usd</Key>\
    <LastModified>2026-01-02T03:04:05.000Z</LastModified>\
    <ETag>&quot;p1&quot;</ETag><Size>1</Size></Contents>\
    </ListBucketResult>";

/// The `max-keys` value on a captured request line.
///
/// Parsed to a number rather than substring-matched: `max-keys=1000` contains
/// `max-keys=1`, so `contains` silently passes a widened page size for a
/// request that asked for one key.
fn max_keys_of(raw: &str) -> Option<u64> {
    let line = raw.lines().next()?;
    let query = line.split('?').nth(1)?.split_whitespace().next()?;
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("max-keys="))
        .and_then(|value| value.parse().ok())
}

/// A page of `n` synthetic objects, optionally truncated with `token`.
///
/// Keys are unique per page so the walk accumulates rather than deduplicating,
/// which is what makes the entry budget the thing under test.
fn bulk_page(n: usize, token: Option<&str>) -> String {
    use std::sync::atomic::{AtomicUsize, Ordering as O};
    static PAGE: AtomicUsize = AtomicUsize::new(0);
    let page = PAGE.fetch_add(1, O::SeqCst);
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Name>bkt</Name><Prefix>assets/</Prefix>",
    );
    body.push_str(&format!(
        "<IsTruncated>{}</IsTruncated>",
        if token.is_some() { "true" } else { "false" }
    ));
    if let Some(token) = token {
        body.push_str(&format!(
            "<NextContinuationToken>{token}</NextContinuationToken>"
        ));
    }
    for i in 0..n {
        body.push_str(&format!(
            "<Contents><Key>assets/p{page}-{i}.usd</Key>\
             <LastModified>2026-01-02T03:04:05.000Z</LastModified>\
             <ETag>&quot;e{i}&quot;</ETag><Size>1</Size></Contents>"
        ));
    }
    body.push_str("</ListBucketResult>");
    body
}

/// One page of an A -> B -> A cycle, parameterised by the token it hands back.
fn cycle_page(token: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Name>bkt</Name><Prefix>assets/</Prefix><Delimiter>/</Delimiter>\
         <KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>true</IsTruncated>\
         <NextContinuationToken>{token}</NextContinuationToken>\
         <Contents><Key>assets/first.usd</Key>\
         <LastModified>2026-01-02T03:04:05.000Z</LastModified>\
         <ETag>&quot;p1&quot;</ETag><Size>1</Size></Contents>\
         </ListBucketResult>"
    )
}

/// Page two: the object a single-page listing would have lost.
const SECOND_PAGE_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
    <Name>bkt</Name><Prefix>assets/</Prefix><Delimiter>/</Delimiter>\
    <KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>\
    <Contents><Key>assets/second.usd</Key>\
    <LastModified>2026-01-02T03:04:06.000Z</LastModified>\
    <ETag>&quot;p2&quot;</ETag><Size>2</Size></Contents>\
    </ListBucketResult>";

const ACCESS_DENIED_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <Error><Code>AccessDenied</Code><Message>Access Denied</Message>\
    <RequestId>TESTREQ</RequestId></Error>";

/// What S3 answers for a bucket that does not exist — a refusal of a different
/// kind, which the anonymous restatement must leave alone.
const NO_SUCH_BUCKET_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>\
    <RequestId>TESTREQ</RequestId></Error>";

// === Loopback fixture ===

#[derive(Clone)]
struct CapturedRequest {
    raw: String,
}

impl CapturedRequest {
    fn request_line(&self) -> &str {
        self.raw.split("\r\n").next().unwrap_or("")
    }

    fn has_header(&self, name: &str) -> bool {
        let needle = format!("\r\n{}: ", name.to_lowercase());
        self.raw.to_lowercase().contains(&needle)
    }

    fn header_value(&self, name: &str) -> Option<String> {
        let lower = self.raw.to_lowercase();
        let needle = format!("\r\n{}: ", name.to_lowercase());
        let start = lower.find(&needle)? + needle.len();
        let after = &self.raw[start..];
        let end = after.find("\r\n").unwrap_or(after.len());
        Some(after[..end].to_string())
    }
}

/// How the fake answers. One variant per store configuration under test.
#[derive(Clone, Copy)]
enum Answer {
    /// A bucket that grants the anonymous principal what it asked for.
    Public,
    /// A bucket that grants anonymous `GetObject` but not `ListBucket` — the
    /// configuration that must produce an honest, actionable refusal.
    Refuse(u16),
    /// A store that answers every request with the same truncated page and the
    /// same `NextContinuationToken` — the shape a non-AWS S3-compatible server
    /// can present, and the one an unguarded continuation loop never leaves.
    ConstantToken,
    /// Pages of `n` synthetic objects each, truncated for ever — a store with
    /// more entries than one call is allowed to hold.
    EndlessPages(usize),
    /// EMPTY pages, truncated for ever, with a fresh token each time. Grows no
    /// entries at all, so the entry budget never trips.
    EndlessEmptyPages,
    /// Exactly three pages of `n` objects, then a complete final page. A
    /// legitimate multi-page listing that must SUCCEED.
    ThreeRealPages(usize),
    /// 1000-key pages until the listing is COMPLETE at just over the entry
    /// budget, the last one carrying no token. The store has nothing left to
    /// send, so the budget must not discard what is already in hand.
    CompletesJustOverTheEntryBudget,
    /// The same walk, but the final page ignores `MaxKeys` and answers with
    /// 2000 keys — a COMPLETE listing past the ceiling, which is the shape a
    /// budget checked only on the fetching edge would hand on.
    CompletesPastTheCeiling,
    /// ONE response, past the ceiling on its own, with no token. The store
    /// ignores `max-keys` entirely, which is the peer the ceiling exists for.
    OneOversizePage,
    /// A page that claims truncation and offers nothing to resume from.
    TruncatedWithoutToken,
    /// `A` then `B` then `A` again — a cycle a single-step comparison misses.
    TokenCycle,
    /// A truncated first page carrying `NextContinuationToken`, then a final
    /// page. `ListObjectsV2` answers at most 1000 keys, so this is what any
    /// prefix larger than that looks like.
    TwoPages,
    /// `404` to a `HEAD`, and a normal listing to anything else — a directory
    /// with no zero-byte marker object, which is what this backend's own `list`
    /// hands back as `DirectoryInferred`.
    MissingThenListed,
    /// `404` to a `HEAD`, `401` to anything else — the directory probe refused
    /// with the other status the refusal arm accepts, so the reason it reports
    /// is the store's own rather than a fabricated one.
    MissingThenUnauthorized,
    /// `404` to a `HEAD`, `403` to anything else. This is what a
    /// public-read/private-list bucket answers a `stat` of a `key/` address:
    /// the marker object is genuinely absent, and the directory probe that
    /// follows is refused. It is the only shape that reaches
    /// `flat_directory_probe`'s error mapping.
    MissingThenRefused,
}

struct Fixture {
    endpoint: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    served: Arc<AtomicUsize>,
}

impl Fixture {
    fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().expect("capture poisoned").clone()
    }

    fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

fn read_http_request(stream: &mut TcpStream) -> Option<String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut request = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => {
                request.extend_from_slice(&buf[..len]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                assert!(
                    request.len() <= 65536,
                    "fake S3 request exceeded capture limit"
                );
            }
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(_) => return None,
        }
    }
    (!request.is_empty()).then(|| String::from_utf8_lossy(&request).to_string())
}

fn spawn_fake_s3(answer: Answer) -> Fixture {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let endpoint = format!("http://{}", listener.local_addr().expect("local addr"));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let served = Arc::new(AtomicUsize::new(0));
    let requests_for_thread = requests.clone();
    let served_for_thread = served.clone();

    thread::Builder::new()
        .name("ovs-test-s3-anonymous".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(raw) = read_http_request(&mut stream) else {
                    continue;
                };
                requests_for_thread
                    .lock()
                    .expect("capture poisoned")
                    .push(CapturedRequest { raw: raw.clone() });
                served_for_thread.fetch_add(1, Ordering::SeqCst);

                let response = match answer {
                    Answer::Refuse(status) => {
                        let (reason, body) = match status {
                            404 => ("Not Found", NO_SUCH_BUCKET_BODY),
                            401 => ("Unauthorized", ACCESS_DENIED_BODY),
                            _ => ("Forbidden", ACCESS_DENIED_BODY),
                        };
                        format!(
                            "HTTP/1.1 {status} {reason}\r\nConnection: close\r\n\
                             x-amz-request-id: TESTREQ\r\n\
                             Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body,
                        )
                    }
                    Answer::ConstantToken => format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                         x-amz-request-id: TESTREQ\r\n\
                         Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                        FIRST_PAGE_BODY.len(),
                        FIRST_PAGE_BODY,
                    ),
                    Answer::EndlessPages(n) => {
                        // A fresh token every time, so the walk never stops on
                        // the repeat guard — only the budget can end this.
                        let token = format!("P{}", served_for_thread.load(Ordering::SeqCst));
                        let body = bulk_page(n, Some(&token));
                        format!(
                            "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                             x-amz-request-id: TESTREQ\r\n\
                             Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body,
                        )
                    }
                    Answer::ThreeRealPages(n) => {
                        // The counter is incremented before this runs, so
                        // `seen` is 1 on the first request: pages 1..=3 are
                        // truncated and the fourth completes the listing.
                        let seen = served_for_thread.load(Ordering::SeqCst);
                        let body = if seen < 4 {
                            bulk_page(n, Some(&format!("P{seen}")))
                        } else {
                            bulk_page(n, None)
                        };
                        format!(
                            "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                             x-amz-request-id: TESTREQ\r\n\
                             Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body,
                        )
                    }
                    Answer::CompletesJustOverTheEntryBudget => {
                        // 101 pages of 1000 is 101,000 entries, one page past
                        // the 100,000-entry budget — and the last page offers
                        // no token, so the listing is complete.
                        let seen = served_for_thread.load(Ordering::SeqCst);
                        let body = if seen < 101 {
                            bulk_page(1000, Some(&format!("C{seen}")))
                        } else {
                            bulk_page(1000, None)
                        };
                        format!(
                            "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                             x-amz-request-id: TESTREQ\r\n\
                             Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body,
                        )
                    }
                    Answer::CompletesPastTheCeiling => {
                        // 100 conforming pages, then one oversize final page:
                        // 102,000 entries with nothing left to fetch.
                        let seen = served_for_thread.load(Ordering::SeqCst);
                        let body = if seen < 101 {
                            bulk_page(1000, Some(&format!("O{seen}")))
                        } else {
                            bulk_page(2000, None)
                        };
                        format!(
                            "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                             x-amz-request-id: TESTREQ\r\n\
                             Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body,
                        )
                    }
                    Answer::OneOversizePage => {
                        let body = bulk_page(LIST_ITEM_CEILING_ENTRIES + 1, None);
                        format!(
                            "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                             x-amz-request-id: TESTREQ\r\n\
                             Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body,
                        )
                    }
                    Answer::EndlessEmptyPages => {
                        let token = format!("E{}", served_for_thread.load(Ordering::SeqCst));
                        let body = bulk_page(0, Some(&token));
                        format!(
                            "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                             x-amz-request-id: TESTREQ\r\n\
                             Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body,
                        )
                    }
                    Answer::TruncatedWithoutToken => format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                         x-amz-request-id: TESTREQ\r\n\
                         Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                        TRUNCATED_NO_TOKEN_BODY.len(),
                        TRUNCATED_NO_TOKEN_BODY,
                    ),
                    Answer::TokenCycle => {
                        // Holding A -> hand out B. Everything else — the first
                        // request, which holds no token, and the one holding B —
                        // hands out A, which is what closes the cycle on the
                        // third response.
                        let body = if raw.contains("continuation-token=CYCLE_A") {
                            cycle_page("CYCLE_B")
                        } else {
                            cycle_page("CYCLE_A")
                        };
                        format!(
                            "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                             x-amz-request-id: TESTREQ\r\n\
                             Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body,
                        )
                    }
                    Answer::TwoPages => {
                        let body = if raw.contains("continuation-token=") {
                            SECOND_PAGE_BODY
                        } else {
                            FIRST_PAGE_BODY
                        };
                        format!(
                            "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                             x-amz-request-id: TESTREQ\r\n\
                             Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body,
                        )
                    }
                    Answer::MissingThenListed if raw.starts_with("HEAD ") => {
                        "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\
                         x-amz-request-id: TESTREQ\r\nContent-Length: 0\r\n\r\n"
                            .to_string()
                    }
                    Answer::MissingThenListed => format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                         x-amz-request-id: TESTREQ\r\n\
                         Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                        LIST_BODY.len(),
                        LIST_BODY,
                    ),
                    Answer::MissingThenUnauthorized if raw.starts_with("HEAD ") => {
                        "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\
                         x-amz-request-id: TESTREQ\r\nContent-Length: 0\r\n\r\n"
                            .to_string()
                    }
                    Answer::MissingThenUnauthorized => format!(
                        "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\
                         x-amz-request-id: TESTREQ\r\n\
                         Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                        ACCESS_DENIED_BODY.len(),
                        ACCESS_DENIED_BODY,
                    ),
                    Answer::MissingThenRefused if raw.starts_with("HEAD ") => {
                        "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\
                         x-amz-request-id: TESTREQ\r\nContent-Length: 0\r\n\r\n"
                            .to_string()
                    }
                    Answer::MissingThenRefused => format!(
                        "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\
                         x-amz-request-id: TESTREQ\r\n\
                         Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                        ACCESS_DENIED_BODY.len(),
                        ACCESS_DENIED_BODY,
                    ),
                    Answer::Public if raw.starts_with("HEAD ") => "HTTP/1.1 200 OK\r\n\
                         Connection: close\r\n\
                         x-amz-request-id: TESTREQ\r\n\
                         ETag: \"9a1f2b\"\r\n\
                         Last-Modified: Fri, 02 Jan 2026 03:04:05 GMT\r\n\
                         Content-Type: model/vnd.usd\r\n\
                         Content-Length: 2048\r\n\r\n"
                        .to_string(),
                    Answer::Public => format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                         x-amz-request-id: TESTREQ\r\n\
                         Content-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                        LIST_BODY.len(),
                        LIST_BODY,
                    ),
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                drop(stream);
            }
        })
        .expect("spawn fake S3");

    thread::sleep(Duration::from_millis(50));
    Fixture {
        endpoint,
        requests,
        served,
    }
}

/// The connection config every backend in this file is built from: a
/// path-style custom profile pointed at a loopback fixture.
fn raw_config(endpoint: &str) -> HashMap<String, ConfigValue> {
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(BUCKET.into()));
    config.insert("region".into(), ConfigValue::String("us-east-1".into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
    config.insert(
        "compatibility_profile".into(),
        ConfigValue::String("custom".into()),
    );
    config.insert("force_path_style".into(), ConfigValue::Bool(true));
    config
}

fn config(endpoint: &str) -> ovstorage_plugin_s3::S3Config {
    ovstorage_plugin_s3::__test_only_parse_config(&raw_config(endpoint)).expect("parse config")
}

fn anonymous_backend(endpoint: &str) -> S3Backend {
    S3Backend::anonymous(config(endpoint)).expect("anonymous backend init")
}

/// An anonymous backend whose connection config names an SQS queue, so a
/// `watch_directory` refusal is about the anonymity rather than about the
/// missing queue.
fn anonymous_backend_watching(endpoint: &str) -> S3Backend {
    let mut raw = raw_config(endpoint);
    raw.insert(
        "sqs_queue_url".into(),
        ConfigValue::String("http://127.0.0.1:1/queue/assets".into()),
    );
    let parsed = ovstorage_plugin_s3::__test_only_parse_config(&raw).expect("parse config");
    S3Backend::anonymous(parsed).expect("anonymous backend init")
}

fn credentialed_backend(endpoint: &str) -> S3Backend {
    S3Backend::with_credentials(
        config(endpoint),
        AwsCredentials {
            access_key_id: "AKIATESTFIXTURE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        },
    )
    .expect("credentialed backend init")
}

fn target(key: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId(format!("s3:s3://{BUCKET}/")),
        resolved_address: address::parse(&format!("s3://{BUCKET}/{key}")).expect("parse address"),
    }
}

// === The good input: a public bucket answers ===

/// The operation the owner reported: listing a public bucket with no
/// credentials. Asserts the whole round trip — an unsigned `ListObjectsV2` on
/// the wire, and the parsed entries coming back.
#[tokio::test]
async fn an_anonymous_connection_lists_a_public_bucket() {
    let fake = spawn_fake_s3(Answer::Public);
    let backend = anonymous_backend(&fake.endpoint);

    let items = backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect("an anonymous list of a public bucket must succeed");

    // (1) The request went out unsigned. `a_credentialed_connection_still_signs_its_list`
    // is the control: the same assertion inverted, on the same fixture.
    let requests = fake.requests();
    assert_eq!(requests.len(), 1, "exactly one ListObjectsV2 was issued");
    let listing = &requests[0];
    assert!(
        !listing.has_header("authorization"),
        "an anonymous list must carry no Authorization header; got: {}",
        listing.raw
    );
    for signed_marker in [
        "x-amz-signature",
        "x-amz-credential",
        "x-amz-security-token",
    ] {
        assert!(
            !listing.raw.to_lowercase().contains(signed_marker),
            "an anonymous list must carry no {signed_marker}; got: {}",
            listing.raw
        );
    }
    // (2) It is the ListObjectsV2 a public-bucket browse needs: prefix-scoped
    // and delimited, so the caller gets one directory level.
    let line = listing.request_line();
    assert!(
        line.starts_with("GET /bkt/?"),
        "path-style bucket GET: {line}"
    );
    assert!(line.contains("list-type=2"), "ListObjectsV2: {line}");
    assert!(line.contains("prefix=assets%2F"), "prefix-scoped: {line}");
    assert!(line.contains("delimiter=%2F"), "one level: {line}");

    // (3) The answer was parsed, not merely received.
    assert_eq!(items.len(), 2, "one object and one common prefix");
    let object = items
        .iter()
        .find(|item| item.address.as_str() == "s3://bkt/assets/teapot.usd")
        .expect("the object entry is returned under its own address");
    assert_eq!(object.kind, ObjectKind::File);
    assert_eq!(object.size, Some(2048));
    assert_eq!(object.etag.as_deref(), Some("9a1f2b"));
    assert!(object.mtime.is_some(), "LastModified is carried through");
    let directory = items
        .iter()
        .find(|item| item.address.as_str() == "s3://bkt/assets/textures/")
        .expect("the common prefix is returned as a directory");
    assert_eq!(directory.kind, ObjectKind::DirectoryInferred);
}

/// `stat` on a public object: an unsigned `HeadObject`, with the metadata it
/// returns asserted field by field.
#[tokio::test]
async fn an_anonymous_connection_stats_a_public_object() {
    let fake = spawn_fake_s3(Answer::Public);
    let backend = anonymous_backend(&fake.endpoint);

    let info = backend
        .stat(target("assets/teapot.usd"), StatOptions::default(), None)
        .await
        .expect("an anonymous stat of a public object must succeed");

    let requests = fake.requests();
    assert_eq!(requests.len(), 1, "one HeadObject, no fallback probe");
    let head = &requests[0];
    assert!(
        !head.has_header("authorization"),
        "an anonymous stat must carry no Authorization header; got: {}",
        head.raw
    );
    assert_eq!(
        head.request_line(),
        "HEAD /bkt/assets/teapot.usd HTTP/1.1",
        "a plain HEAD on the object"
    );

    assert_eq!(info.kind, ObjectKind::File);
    assert_eq!(info.size, Some(2048));
    assert_eq!(info.etag.as_deref(), Some("9a1f2b"));
    assert!(info.mtime.is_some(), "Last-Modified is carried through");
}

/// A listing walks to the end of the bucket, not to the end of the first
/// `ListObjectsV2` response.
///
/// This is a correctness bug rather than a shortfall, and it bites credentialed
/// connections identically — it is only reachable anonymously now because
/// anonymous `list` works at all. `S3Layer::list` asks for the full set and
/// paginates host-side; the metadata cache's `find_in_page` then treats an
/// absent entry in a page with no next token as an authoritative `NotFound`. So
/// a truncated answer did not merely hide objects, it reported them missing.
#[tokio::test]
async fn a_listing_follows_the_continuation_token_to_the_end() {
    let fake = spawn_fake_s3(Answer::TwoPages);
    let backend = anonymous_backend(&fake.endpoint);

    let items = backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect("both pages are fetched");

    let addresses: Vec<&str> = items.iter().map(|item| item.address.as_str()).collect();
    assert_eq!(
        addresses,
        vec!["s3://bkt/assets/first.usd", "s3://bkt/assets/second.usd"],
        "the second page's object must be present, and in order"
    );

    let requests = fake.requests();
    assert_eq!(requests.len(), 2, "one request per page");
    assert!(
        !requests[0].request_line().contains("continuation-token"),
        "the first request carries no token: {}",
        requests[0].request_line()
    );
    assert!(
        requests[1]
            .request_line()
            .contains("continuation-token=PAGE2TOKEN"),
        "the second resumes from the token the first returned: {}",
        requests[1].request_line()
    );
}

/// A store that will not advance its listing gets an ERROR, not a short answer.
///
/// This is the rule the whole walk exists to keep: `S3Backend::list` returns a
/// bare `Vec<ObjectInfo>` with no truncation signal, and the metadata cache
/// reads a page with no next token as authoritative — so returning what was
/// read would convert a misbehaving store into a confident `NotFound` for an
/// object that exists. That is the defect the pagination fix removed, and
/// answering `Ok` on the defensive path would have reintroduced it.
///
/// Not a hypothetical server: `endpoint_url` and `force_path_style` come from a
/// compatibility profile, so the thing answering is frequently MinIO, Ceph RGW,
/// R2 or B2 rather than S3.
///
/// Written as a bounded wait because the failure being pinned is "does not
/// return", and a hanging test is indistinguishable from a slow suite.
#[tokio::test]
async fn a_store_that_repeats_its_token_fails_the_listing_rather_than_shortening_it() {
    let fake = spawn_fake_s3(Answer::ConstantToken);
    let backend = anonymous_backend(&fake.endpoint);

    let err = tokio::time::timeout(
        Duration::from_secs(10),
        backend.list(target("assets/"), ListOptions::default(), None),
    )
    .await
    .expect("the walk must terminate, not spin on a repeated token")
    .expect_err("and it must not answer Ok with a partial listing");

    assert_eq!(
        err.code(),
        ErrorCode::Transient,
        "the store's answer is at fault, and a retry can succeed: {err}"
    );
    assert!(
        err.message().contains("partial listing"),
        "the message says what was refused and why: {}",
        err.message()
    );
    assert_eq!(
        fake.requests().len(),
        2,
        "the repeat is caught on the response that repeats it"
    );
}

/// A store that claims truncation but hands back nothing to resume from is the
/// same failure in the other direction, and must not be read as complete.
#[tokio::test]
async fn a_truncated_page_with_no_token_fails_the_listing() {
    let fake = spawn_fake_s3(Answer::TruncatedWithoutToken);
    let backend = anonymous_backend(&fake.endpoint);

    let err = tokio::time::timeout(
        Duration::from_secs(10),
        backend.list(target("assets/"), ListOptions::default(), None),
    )
    .await
    .expect("terminates")
    .expect_err("a truncated listing with no way to continue is not a complete one");

    assert_eq!(err.code(), ErrorCode::Transient, "{err}");
    assert!(
        err.message().contains("no continuation token"),
        "the message names which way the store misbehaved: {}",
        err.message()
    );
    assert_eq!(fake.requests().len(), 1);
}

/// A multi-step cycle defeats a "differs from the previous token" check, which
/// is why the walk remembers every token it has followed.
#[tokio::test]
async fn a_token_cycle_longer_than_one_step_is_still_caught() {
    let fake = spawn_fake_s3(Answer::TokenCycle);
    let backend = anonymous_backend(&fake.endpoint);

    let err = tokio::time::timeout(
        Duration::from_secs(10),
        backend.list(target("assets/"), ListOptions::default(), None),
    )
    .await
    .expect("an A -> B -> A cycle must terminate")
    .expect_err("and fail rather than shorten");

    assert_eq!(err.code(), ErrorCode::Transient, "{err}");
    assert_eq!(
        fake.requests().len(),
        3,
        "A, then B, then the response that returns to A"
    );
}

/// **The good path.** A listing that legitimately spans several pages
/// completes, and returns every entry from every page.
///
/// This is the half a cap most often breaks, and the half a cap tested only by
/// tripping it never covers: a budget applied per page rather than to the
/// accumulated total, or a walk that stops at the first truncated response,
/// fails here while the refusal test below still passes — the control that
/// lowers `LIST_ITEM_BUDGET` to 10 shows it.
///
/// What it does NOT pin, because 200 entries is nowhere near the boundary: `>`
/// versus `>=`, or where in the loop the checks sit. Both are green at this
/// size. The boundary is pinned by the two tests below it instead: a walk the
/// store completes may finish over the budget, up to `LIST_ITEM_CEILING`, and
/// is refused past it.
#[tokio::test]
async fn a_multi_page_listing_completes_and_returns_every_page() {
    let fake = spawn_fake_s3(Answer::ThreeRealPages(50));
    let backend = anonymous_backend(&fake.endpoint);

    let items = backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect("a legitimate multi-page listing must succeed");

    assert_eq!(
        items.len(),
        200,
        "three truncated pages of 50 plus a final page of 50"
    );
    assert_eq!(fake.requests().len(), 4, "one request per page");
    // Distinct keys, so nothing was folded away or double-counted.
    let unique: std::collections::HashSet<&str> =
        items.iter().map(|item| item.address.as_str()).collect();
    assert_eq!(unique.len(), 200, "every entry is a distinct object");
}

/// A store with more entries than one call may hold is refused, and refused as
/// `Internal` — the code this project gives a plugin's own fixed local bound,
/// which is what a budget is.
///
/// The second assertion is the load-bearing one: it pins the *bucket*, not the
/// spelling. Retryability here is exactly bucket membership, and a budget is
/// reached identically on every attempt, so moving this refusal back into a
/// retryable bucket would have a stack with `RetryWrapper` composed in re-walk
/// the whole prefix to fail the same way — five times, by the shipped broker
/// graph's default. That is the amplification this assertion exists to keep
/// out, and it reddens for a plausible-looking code just as it would for an
/// implausible one.
///
/// The fixture hands back a FRESH token every response, so the repeat guard
/// cannot end this walk. Only the budget can, which is what makes this a test
/// of the budget rather than of the guard beside it.
#[tokio::test]
async fn a_listing_over_the_entry_budget_is_refused_rather_than_truncated() {
    let fake = spawn_fake_s3(Answer::EndlessPages(1000));
    let backend = anonymous_backend(&fake.endpoint);

    let err = tokio::time::timeout(
        Duration::from_secs(60),
        backend.list(target("assets/"), ListOptions::default(), None),
    )
    .await
    .expect("the budget must end the walk, not a timeout")
    .expect_err("and it must refuse rather than return what it had");

    assert_eq!(
        err.code(),
        ErrorCode::Internal,
        "a fixed local bound, reported as the backend giving up rather than as \
         a shortage that clears: {err}"
    );
    assert!(
        !err.code().retryable(),
        "and it must NOT be retryable — the same request reaches the same \
         budget every time, so a retry re-walks the whole prefix to fail \
         identically: {err}"
    );
    assert!(
        err.message().contains("budget"),
        "the message names the limit that was hit: {}",
        err.message()
    );
    assert!(
        err.message().contains("narrow the prefix"),
        "and tells the operator what to do instead: {}",
        err.message()
    );
    // ~100 pages of 1000, not an unbounded walk.
    assert!(
        fake.requests().len() <= 105,
        "the walk stopped near the budget, not far past it: {}",
        fake.requests().len()
    );
}

/// A listing the store has already declared COMPLETE is returned, even when it
/// finished one page past the entry budget.
///
/// The budgets sit on the edge that would fetch another page, so the question
/// they ask is "may this walk continue", not "is what I hold too large". A
/// budget placed after the fold instead would refuse 101,000 entries the store
/// had no more to add to — discarding an in-hand result while saving nothing,
/// since the memory is already allocated by the time either check runs.
///
/// What this does NOT do, and the distinction is the whole of the remaining
/// gap: it does not make a prefix larger than the budget listable. A flat
/// directory of 150,000 children is still refused at ~100,000, because such a
/// store is still offering a token when the check runs.
#[tokio::test]
async fn a_complete_listing_just_over_the_entry_budget_is_returned() {
    let fake = spawn_fake_s3(Answer::CompletesJustOverTheEntryBudget);
    let backend = anonymous_backend(&fake.endpoint);

    let items = tokio::time::timeout(
        Duration::from_secs(120),
        backend.list(target("assets/"), ListOptions::default(), None),
    )
    .await
    .expect("the walk must terminate")
    .expect("a complete listing must not be discarded for being over the budget");

    assert_eq!(items.len(), 101_000, "every entry from every page");
    assert_eq!(
        fake.requests().len(),
        101,
        "one request per page, and no more"
    );
}

/// Completeness is not a licence to hand on an arbitrarily large response.
///
/// The budget on the fetching edge asks "may this walk continue", which a store
/// answering one enormous FINAL page never fails — it has nothing left to
/// fetch. `LIST_ITEM_CEILING` is the bound that still applies there. Without it
/// a store ignoring `MaxKeys` gets its whole answer folded, returned, and then
/// re-allocated twice more by `S3Layer::list`, which is the exhaustion the
/// budget exists to prevent.
#[tokio::test]
async fn a_complete_listing_past_the_ceiling_is_refused() {
    let fake = spawn_fake_s3(Answer::CompletesPastTheCeiling);
    let backend = anonymous_backend(&fake.endpoint);

    let err = tokio::time::timeout(
        Duration::from_secs(120),
        backend.list(target("assets/"), ListOptions::default(), None),
    )
    .await
    .expect("the ceiling must end the walk, not a timeout")
    .expect_err("a complete listing past the ceiling is still refused");

    assert_eq!(err.code(), ErrorCode::Internal, "{err}");
    assert!(!err.code().retryable(), "a fixed local bound: {err}");
    assert!(
        err.message().contains("ceiling"),
        "the message distinguishes the ceiling from the budget: {}",
        err.message()
    );
}

/// A caller's own bound is not a bound on the store, so the ceiling applies to
/// the single-request branch too.
///
/// `max_results` makes `list` issue exactly one request and stop, so the walk's
/// budgets never come into it — but the request parameter only binds a store
/// that honours it. One that does not overruns a bounded caller exactly as it
/// overruns an unbounded one, and the answer must not be an oversize `Vec`
/// handed back as if the bound had held.
#[tokio::test]
async fn a_bounded_request_is_refused_when_one_response_passes_the_ceiling() {
    let fake = spawn_fake_s3(Answer::OneOversizePage);
    let backend = anonymous_backend(&fake.endpoint);

    let err = backend
        .list(
            target("assets/"),
            ListOptions {
                max_results: Some(500),
                ..ListOptions::default()
            },
            None,
        )
        .await
        .expect_err("a bounded request is still bounded by what one call may hold");

    assert_eq!(err.code(), ErrorCode::Internal, "{err}");
    assert!(!err.code().retryable(), "a fixed local bound: {err}");
    assert!(
        err.message().contains("ceiling"),
        "the message names the ceiling rather than a budget: {}",
        err.message()
    );
    assert_eq!(
        fake.requests().len(),
        1,
        "and it stopped at the one response"
    );
}

/// A store that pages for ever without ever returning an entry is refused too.
///
/// This is the hole an entry budget alone leaves, and it is not theoretical:
/// empty pages grow nothing, so the entry budget never trips while the loop
/// spins and `seen_tokens` grows. The page budget is what ends it. Without
/// that second budget this test does not fail — it hangs, which is why the
/// wait is bounded.
#[tokio::test]
async fn a_store_that_pages_without_progress_is_refused() {
    let fake = spawn_fake_s3(Answer::EndlessEmptyPages);
    let backend = anonymous_backend(&fake.endpoint);

    let err = tokio::time::timeout(
        Duration::from_secs(120),
        backend.list(target("assets/"), ListOptions::default(), None),
    )
    .await
    .expect("the page budget must end the walk, not a timeout")
    .expect_err("and refuse rather than answer an empty listing as complete");

    assert_eq!(
        err.code(),
        ErrorCode::Internal,
        "a fixed local bound — on round trips rather than memory: {err}"
    );
    assert!(
        !err.code().retryable(),
        "and non-retryable for the same reason as the entry budget: the store \
         answers the same way on every attempt: {err}"
    );
    assert!(
        err.message().contains("without completing"),
        "the message distinguishes no-progress from too-large: {}",
        err.message()
    );
    // An empty listing returned as `Ok` would be the worst outcome here: it
    // reads as "this prefix has nothing in it", which `find_in_page` turns
    // into an authoritative `NotFound` for every object under it.
}

/// Every listing request asks for S3's 1000-key maximum, so one response is a
/// bounded term for a conforming store rather than whatever it felt like
/// sending. Nothing else in the suite pins this.
#[tokio::test]
async fn a_listing_request_pins_the_page_size_to_the_service_maximum() {
    let fake = spawn_fake_s3(Answer::ThreeRealPages(50));
    let backend = anonymous_backend(&fake.endpoint);

    backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect("listing succeeds");

    let requests = fake.requests();
    assert!(!requests.is_empty(), "the walk issued requests");
    for raw in &requests {
        assert_eq!(
            max_keys_of(&raw.raw),
            Some(1000),
            "every page request pins the page size"
        );
    }
}

/// A caller that asked for a bounded page still gets one request.
///
/// It asked for a bounded page, so walking the whole prefix on its behalf would
/// be both the wrong answer and an unbounded one. Note it cannot resume:
/// `list` returns `Vec<ObjectInfo>` and hands back no continuation token, so a
/// bounded request is one page and nothing more.
#[tokio::test]
async fn a_bounded_listing_stays_a_single_request() {
    let fake = spawn_fake_s3(Answer::TwoPages);
    let backend = anonymous_backend(&fake.endpoint);

    let items = backend
        .list(
            target("assets/"),
            ListOptions {
                max_results: Some(1),
                ..ListOptions::default()
            },
            None,
        )
        .await
        .expect("one page");

    assert_eq!(fake.requests().len(), 1, "max_results means one request");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].address.as_str(), "s3://bkt/assets/first.usd");
    // `max_results` NARROWS the page size. Asserted because the pin is a
    // `min`, and a `max` there would silently widen every bounded request to
    // 1000 while every other assertion in this test still held.
    assert_eq!(
        max_keys_of(&fake.requests()[0].raw),
        Some(1),
        "a bounded request narrows the page size rather than widening it"
    );
}

/// `max_results` above the service maximum is clamped to it, not passed through.
///
/// The pin is what stops a caller asking a compat store for a 50-million-key
/// response and getting `Ok` with all of it, above the budget and without ever
/// reaching a check — a bounded call breaks out before the budgets run.
#[tokio::test]
async fn a_bounded_listing_cannot_ask_for_more_than_the_service_maximum() {
    let fake = spawn_fake_s3(Answer::TwoPages);
    let backend = anonymous_backend(&fake.endpoint);

    backend
        .list(
            target("assets/"),
            ListOptions {
                max_results: Some(50_000_000),
                ..ListOptions::default()
            },
            None,
        )
        .await
        .expect("one page");

    assert_eq!(
        max_keys_of(&fake.requests()[0].raw),
        Some(1000),
        "clamped to the service maximum, not passed through"
    );
}

/// The control for both tests above: with credentials, the identical operation
/// against the identical fixture DOES sign. Without this, "no Authorization
/// header" would also pass against a fixture that never saw a request, or a
/// build where signing had been removed for everyone.
#[tokio::test]
async fn a_credentialed_connection_still_signs_its_list() {
    let fake = spawn_fake_s3(Answer::Public);
    let backend = credentialed_backend(&fake.endpoint);

    backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect("a credentialed list must succeed");

    let requests = fake.requests();
    assert_eq!(requests.len(), 1);
    let authorization = requests[0]
        .header_value("authorization")
        .expect("a credentialed list is signed");
    assert!(
        authorization.starts_with("AWS4-HMAC-SHA256"),
        "SigV4, not something else: {authorization}"
    );
}

// === The honest failure: public read, private list ===

/// A bucket that allows anonymous `GetObject` but not `ListBucket` answers the
/// unsigned list with `403`. That must reach the operator as a policy fact
/// about anonymous access — not as "this backend cannot list" and not as "your
/// credentials are wrong".
#[tokio::test]
async fn a_refused_anonymous_list_names_the_unsigned_request() {
    let fake = spawn_fake_s3(Answer::Refuse(403));
    let backend = anonymous_backend(&fake.endpoint);

    let err = backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect_err("a bucket that denies anonymous ListBucket refuses");

    assert_eq!(fake.served(), 1, "the request was actually attempted");
    assert_eq!(
        err.code(),
        ErrorCode::PermissionDenied,
        "a policy refusal, not a missing capability: {err}"
    );
    let message = err.message().to_lowercase();
    assert!(
        message.contains("unsigned") && message.contains("anonymous"),
        "the message must say why the store refused: {message}"
    );
    let next_action = err
        .next_action()
        .expect("an operator-actionable remedy is attached");
    assert!(
        next_action.contains("credentials") && next_action.contains("public-access"),
        "the remedy must name both repairs, and must not send an operator to \
         edit a bucket policy that may not be the control refusing: {next_action}"
    );
}

/// A `401` on an anonymous connection must not become `AuthRequired`.
///
/// `AuthRequired` is read by machinery that assumes a credential exists: the
/// host classifies it `NeedsInteractive` and points the caller at a flow
/// `S3Driver::interactive` answers `Unsupported`, and the broker-client driver
/// classifies it
/// `RecoverableCredential` when it holds a silent grant, spending a token
/// refresh and a retry on a byte-identical unsigned request. Both statuses are
/// the same fact about public access, so both collapse to the same answer.
#[tokio::test]
async fn a_401_on_an_anonymous_connection_is_not_a_credential_problem() {
    let fake = spawn_fake_s3(Answer::Refuse(401));
    let backend = anonymous_backend(&fake.endpoint);

    let err = backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect_err("a 401 is still a refusal");

    assert_eq!(fake.served(), 1);
    assert_ne!(
        err.code(),
        ErrorCode::AuthRequired,
        "there is no credential to refresh: {err}"
    );
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert!(
        err.context().is_none(),
        "the Auth context goes with it: it names a connection whose credential \
         is in question, and there is none"
    );
}

/// The control for the two above: the SAME statuses on a CREDENTIALED
/// connection keep their original meanings. Without this, the collapse to
/// `PermissionDenied` could have been applied to every connection and both
/// tests would still be green.
#[tokio::test]
async fn a_credentialed_401_is_still_auth_required() {
    let fake = spawn_fake_s3(Answer::Refuse(401));
    let backend = credentialed_backend(&fake.endpoint);

    let err = backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect_err("a 401 fails");

    assert_eq!(
        err.code(),
        ErrorCode::AuthRequired,
        "a credentialed 401 still drives the host's credential recovery: {err}"
    );
    assert!(
        err.context().is_some(),
        "and it still carries the Auth context that names the connection"
    );
}

/// `map_store_error` is reached from four sites, and driving `list` alone
/// witnesses one of them. `stat` of an object covers the `head_object` site and
/// `list_versions` covers its own; the directory probe needs a fixture of its
/// own and gets one in
/// [`a_refused_directory_probe_is_not_reported_as_an_absent_directory`],
/// because a `403` there arrives only after a `404` to the `HEAD`.
#[tokio::test]
async fn every_unsigned_operation_restates_a_refusal_the_same_way() {
    let fake = spawn_fake_s3(Answer::Refuse(403));
    let backend = anonymous_backend(&fake.endpoint);

    let object = backend
        .stat(target("assets/teapot.usd"), StatOptions::default(), None)
        .await
        .expect_err("a refused HeadObject");
    let versions = backend
        .list_versions(
            target("assets/teapot.usd"),
            ovstorage_plugin::ListVersionsOptions::default(),
            None,
        )
        .await
        .expect_err("a refused ListObjectVersions");

    for (operation, err) in [("stat", &object), ("list_versions", &versions)] {
        assert_eq!(
            err.code(),
            ErrorCode::PermissionDenied,
            "{operation}: {err}"
        );
        assert!(
            err.message().to_lowercase().contains("unsigned"),
            "{operation} must be restated like `list`: {}",
            err.message()
        );
    }
    assert!(fake.served() >= 2, "both operations reached the store");
}

/// The fourth `map_store_error` site. `stat` of a `key/` address HEADs the
/// zero-byte marker, gets `404`, and falls back to a bounded prefix list to
/// decide whether the directory exists by inference. On a public-read /
/// private-list bucket that list is refused — and the caller must be told the
/// listing was refused, not that the directory is absent, because those call
/// for opposite actions.
#[tokio::test]
async fn a_refused_directory_probe_is_not_reported_as_an_absent_directory() {
    let fake = spawn_fake_s3(Answer::MissingThenRefused);
    let backend = anonymous_backend(&fake.endpoint);

    let err = backend
        .stat(target("assets/textures/"), StatOptions::default(), None)
        .await
        .expect_err("the probe is refused");

    assert_eq!(fake.served(), 2, "the HEAD and then the probe list");
    assert_eq!(
        err.code(),
        ErrorCode::PermissionDenied,
        "not NotFound — the directory's existence was never established: {err}"
    );
    assert!(
        err.message().to_lowercase().contains("unsigned"),
        "restated like every other unsigned refusal: {}",
        err.message()
    );
}

/// `check_access` on an anonymous connection. A successful probe says the
/// caller may read; it says nothing about writing, and on this connection shape
/// the answer for writing is known without asking.
#[tokio::test]
async fn check_access_does_not_infer_write_permission_from_a_readable_object() {
    let fake = spawn_fake_s3(Answer::Public);
    let backend = anonymous_backend(&fake.endpoint);

    let read_only = backend
        .check_access(
            target("assets/teapot.usd"),
            AccessOps {
                read: true,
                ..AccessOps::default()
            },
            None,
        )
        .await
        .expect("the probe succeeds");
    assert!(read_only.allowed, "a public object is readable");
    assert!(!read_only.denied_ops.read);

    let with_write = backend
        .check_access(
            target("assets/teapot.usd"),
            AccessOps {
                read: true,
                write: true,
                delete: true,
                update_metadata: true,
            },
            None,
        )
        .await
        .expect("the probe succeeds");
    assert!(!with_write.allowed, "not everything asked for is permitted");
    assert!(
        !with_write.denied_ops.read,
        "reading is still allowed — only the mutations are denied"
    );
    assert!(with_write.denied_ops.write);
    assert!(with_write.denied_ops.delete);
    assert!(with_write.denied_ops.update_metadata);
    assert!(
        with_write
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("anonymous")),
        "the reason names the connection shape: {:?}",
        with_write.reason
    );
}

/// The bucket-root arm. An anonymous caller essentially never holds
/// `s3:GetBucketPolicyStatus`, so probing with it would report a fully public
/// bucket unreadable. The bounded `ListObjectsV2` asks the question that is
/// meaningful for this connection shape.
#[tokio::test]
async fn check_access_probes_a_bucket_root_with_a_bounded_listing() {
    let fake = spawn_fake_s3(Answer::Public);
    let backend = anonymous_backend(&fake.endpoint);

    let decision = backend
        .check_access(
            target(""),
            AccessOps {
                read: true,
                ..AccessOps::default()
            },
            None,
        )
        .await
        .expect("the probe succeeds");

    assert!(decision.allowed, "a listable public bucket is readable");
    let requests = fake.requests();
    assert_eq!(requests.len(), 1);
    let line = requests[0].request_line();
    assert!(
        line.contains("list-type=2"),
        "a listing, not a policy read: {line}"
    );
    assert!(line.contains("max-keys=1"), "bounded to one key: {line}");
    assert!(
        !requests[0].raw.contains("policyStatus"),
        "GetBucketPolicyStatus is not the anonymous probe: {}",
        requests[0].raw
    );
}

/// Every remedy this plugin offers an anonymous connection must be one the
/// operator can actually carry out.
///
/// `S3Layer::update_connection_credentials` refuses an anonymous-to-credentialed
/// update outright, so "configure credentials on this connection" is advice that
/// cannot be followed. Nothing but this test keeps it out: the strings are
/// hand-written at three sites in three modules, and no other assertion reads
/// more than one of them.
#[tokio::test]
async fn no_remedy_tells_an_operator_to_add_credentials_to_this_connection() {
    let fake = spawn_fake_s3(Answer::Refuse(403));
    let backend = anonymous_backend(&fake.endpoint);

    let refused_list = backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect_err("refused");
    let refused_write = backend
        .write(
            target("assets/new.usd"),
            b"bytes".to_vec(),
            WriteOptions::default(),
            None,
        )
        .await
        .expect_err("refused");
    let watch_backend = anonymous_backend_watching("http://127.0.0.1:1");
    let refused_watch = watch_backend
        .watch_directory(
            target("assets/"),
            ovstorage_plugin::WatchDirectoryOptions::default(),
            Duration::from_secs(1),
            None,
        )
        .await
        .err()
        .expect("refused");

    for (site, err) in [
        ("map_anonymous_refusal", &refused_list),
        ("signed_client", &refused_write),
        ("watch_directory", &refused_watch),
    ] {
        let remedy = err
            .next_action()
            .unwrap_or_else(|| panic!("{site} must offer a remedy"))
            .to_lowercase();
        assert!(
            remedy.contains("remove and re-add"),
            "{site} must send the operator to remove and re-add the connection: {remedy}"
        );
        for forbidden in [
            "on this connection",
            "on the connection",
            "to this connection",
            "to the connection",
        ] {
            assert!(
                !remedy.contains(forbidden),
                "{site} must not tell the operator to attach credentials to a \
                 connection that refuses them (found {forbidden:?}): {remedy}"
            );
        }
    }
}

/// A malformed address is named as such by every mutation slot, on an anonymous
/// connection as much as a credentialed one — with one documented exception.
///
/// Seven mutation slots get their refusal from `signed_client()`, which they
/// reach only after `parse_object_target`, so they answer `InvalidArgument` for
/// a bad address. Three carry a hoisted guard of their own, and the question is
/// where it sits relative to that parse. It sits AFTER, so nine of the ten
/// agree; the tenth cannot, for a structural reason given below.
///
/// The Layer contract's self-gate rule does not decide this: it asks for a
/// typed `Unsupported` "without performing any backend work or side effects",
/// and parsing an address is neither. Consistency across the ten slots decides
/// it. What the rule does require is that nothing be decoded, buffered or sent
/// before the refusal, which is what the guards' position delivers and what
/// [`mutations_on_an_anonymous_connection_are_refused_without_a_request`] pins.
///
/// **The exception is `write_stream`**, whose address parse happens later
/// inside `stream_write`, so its guard necessarily precedes it. Pinned here
/// rather than left to be discovered.
///
/// Nothing reaches the wire: the endpoint is a port nothing listens on, so a
/// request would surface as a transport error rather than as a typed refusal.
#[tokio::test]
async fn a_malformed_address_is_named_by_every_mutation_slot() {
    let backend = anonymous_backend("http://127.0.0.1:1");
    // An empty key: `parse_object_target` refuses it as `InvalidArgument`.
    let bucket_root = target("");

    let body = BodyStream::from_iter(
        vec![Ok::<Vec<u8>, ovstorage_plugin::Error>(b"bytes".to_vec())].into_iter(),
    );
    let write_stream = backend
        .write_stream(bucket_root.clone(), body, WriteOptions::default(), None)
        .await
        .expect_err("refused");
    assert_eq!(
        write_stream.code(),
        ErrorCode::Unsupported,
        "the documented exception: write_stream's address parse happens later, \
         inside stream_write, so its guard necessarily precedes it: {write_stream}"
    );

    let update_metadata = backend
        .update_metadata(
            bucket_root.clone(),
            UpdateMetadataOptions {
                allow_rewrite_emulation: true,
                ..UpdateMetadataOptions::default()
            },
            None,
        )
        .await
        .expect_err("refused");
    assert_eq!(
        update_metadata.code(),
        ErrorCode::InvalidArgument,
        "update_metadata names the address: {update_metadata}"
    );

    let continue_write = backend
        .continue_write(
            bucket_root.clone(),
            WriteRedirectBatch {
                redirects: Vec::new(),
                continuation: b"not a continuation".to_vec(),
            },
            RedirectResultBatch {
                results: Vec::new(),
            },
            None,
        )
        .await
        .expect_err("refused");
    assert_eq!(
        continue_write.code(),
        ErrorCode::InvalidArgument,
        "continue_write names the address: {continue_write}"
    );

    // The seven that reach `signed_client()` through their client accessor are
    // the reason the three above sit where they do, so a sample is driven here
    // rather than assumed to agree.
    let delete = backend
        .delete(bucket_root.clone(), DeleteOptions::default(), None)
        .await
        .expect_err("refused");
    assert_eq!(delete.code(), ErrorCode::InvalidArgument, "{delete}");
    let write = backend
        .write(
            bucket_root.clone(),
            b"bytes".to_vec(),
            WriteOptions::default(),
            None,
        )
        .await
        .expect_err("refused");
    assert_eq!(write.code(), ErrorCode::InvalidArgument, "{write}");
    let copy = backend
        .copy(
            bucket_root.clone(),
            bucket_root.clone(),
            CopyOptions::default(),
            None,
        )
        .await
        .expect_err("refused");
    assert_eq!(copy.code(), ErrorCode::InvalidArgument, "{copy}");

    // `write_stream`'s guard is not first either — `reject_pinned_for_mutation`
    // beats it. So the exception above is narrow: the guard sits after the
    // pinned-address check and before the address parse, which is simply where
    // `stream_write` puts that parse.
    let pinned = target("assets/teapot.usd?versionId=abc");
    let pinned_stream = BodyStream::from_iter(
        vec![Ok::<Vec<u8>, ovstorage_plugin::Error>(b"bytes".to_vec())].into_iter(),
    );
    let pinned_write_stream = backend
        .write_stream(pinned.clone(), pinned_stream, WriteOptions::default(), None)
        .await
        .expect_err("refused");
    assert_eq!(
        pinned_write_stream.code(),
        ErrorCode::InvalidArgument,
        "a pinned address is named even by write_stream: {pinned_write_stream}"
    );

    // `delete` is the counter-case, and it is not an inconsistency: it has no
    // pinned-address rejection at all, because deleting one version by
    // `?versionId=` is a supported operation. So the anonymity refusal is the
    // first thing wrong with this request, and `Unsupported` is the right
    // answer. Asserted so that adding a pinned check to `delete` — which would
    // be a behaviour change, not a tidy-up — cannot pass unnoticed.
    let pinned_delete = backend
        .delete(pinned, DeleteOptions::default(), None)
        .await
        .expect_err("refused");
    assert_eq!(
        pinned_delete.code(),
        ErrorCode::Unsupported,
        "delete accepts a version pin, so anonymity is the first fault: {pinned_delete}"
    );
}

/// The other half of the bucket-root arm, and the residual it carries: a
/// public-read / private-list bucket answers the bounded listing with `403`, so
/// the ROOT reports unreadable even though every object under it reads.
///
/// Pinned rather than fixed. Answering "may I read the root" exactly would need
/// a probe S3 does not offer, and the alternative — `GetBucketPolicyStatus` —
/// understates a wider half of the space. A future change here should know it
/// is choosing between two understatements.
#[tokio::test]
async fn check_access_on_a_private_list_bucket_root_reports_unreadable() {
    let fake = spawn_fake_s3(Answer::Refuse(403));
    let backend = anonymous_backend(&fake.endpoint);

    let decision = backend
        .check_access(
            target(""),
            AccessOps {
                read: true,
                ..AccessOps::default()
            },
            None,
        )
        .await
        .expect("a refusal is a decision, not an error");

    assert_eq!(fake.served(), 1, "the bounded listing was issued");
    assert!(
        !decision.allowed,
        "the root reports unreadable — the residual this test exists to name"
    );
    assert!(decision.denied_ops.read);
    assert!(
        decision
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("403")),
        "the reason carries the status: {:?}",
        decision.reason
    );
}

/// The credentialed control for both `check_access` changes. Both are gated on
/// `is_anonymous`, and without this nothing drives the other side: every
/// pre-existing `check_access` test passes `AccessOps::default()` against an
/// object, so inverting or dropping either condition would leave a credentialed
/// connection reporting mutations denied, or probing a bucket root with a
/// listing, and the whole suite would stay green.
#[tokio::test]
async fn a_credentialed_check_access_is_unchanged_by_either_anonymous_fork() {
    let fake = spawn_fake_s3(Answer::Public);
    let backend = credentialed_backend(&fake.endpoint);

    let decision = backend
        .check_access(
            target("assets/teapot.usd"),
            AccessOps {
                read: true,
                write: true,
                delete: true,
                update_metadata: true,
            },
            None,
        )
        .await
        .expect("the probe succeeds");
    assert!(
        decision.allowed,
        "a credentialed probe still answers allowed for every requested op"
    );
    assert!(!decision.denied_ops.write);
    assert!(!decision.denied_ops.delete);
    assert!(!decision.denied_ops.update_metadata);
    assert!(decision.reason.is_none());

    let root = spawn_fake_s3(Answer::Public);
    let root_backend = credentialed_backend(&root.endpoint);
    root_backend
        .check_access(
            target(""),
            AccessOps {
                read: true,
                ..AccessOps::default()
            },
            None,
        )
        .await
        .expect("the bucket probe succeeds");
    let line = root.requests()[0].request_line().to_string();
    assert!(
        line.contains("policyStatus"),
        "a credentialed bucket root is still probed with GetBucketPolicyStatus: {line}"
    );
    assert!(
        !line.contains("list-type=2"),
        "and not with the anonymous connection's bounded listing: {line}"
    );
}

/// The anonymous object arm reaches the store, and its refusal and not-found
/// answers are the ones the release note describes.
#[tokio::test]
async fn an_anonymous_check_access_of_an_object_asks_the_store() {
    let refused = spawn_fake_s3(Answer::Refuse(403));
    let decision = anonymous_backend(&refused.endpoint)
        .check_access(
            target("assets/teapot.usd"),
            AccessOps {
                read: true,
                ..AccessOps::default()
            },
            None,
        )
        .await
        .expect("a refusal is a decision, not an error");
    assert_eq!(refused.served(), 1, "the HEAD was actually issued");
    assert!(!decision.allowed);
    assert!(decision.denied_ops.read);

    let missing = spawn_fake_s3(Answer::Refuse(404));
    let err = anonymous_backend(&missing.endpoint)
        .check_access(
            target("assets/gone.usd"),
            AccessOps {
                read: true,
                ..AccessOps::default()
            },
            None,
        )
        .await
        .expect_err("a target that does not exist is an error, not a decision");
    assert_eq!(err.code(), ErrorCode::NotFound, "{err}");
}

/// `check_access` asks about the resource the address names. A pinned address
/// pins the probe; without the `versionId` the HEAD asks after the current head
/// instead, which is a different object and answers `NotFound` whenever a
/// delete marker is current although the pinned version still exists.
#[tokio::test]
async fn a_pinned_check_access_probes_the_pinned_version() {
    let fake = spawn_fake_s3(Answer::Public);
    anonymous_backend(&fake.endpoint)
        .check_access(
            target("assets/teapot.usd?versionId=v1"),
            AccessOps {
                read: true,
                ..AccessOps::default()
            },
            None,
        )
        .await
        .expect("the probe succeeds");

    let requests = fake.requests();
    assert_eq!(requests.len(), 1, "one HEAD");
    let line = requests[0].request_line();
    assert!(line.starts_with("HEAD "), "an object arm probe: {line}");
    assert!(
        line.contains("versionId=v1"),
        "and it carries the pin the address named: {line}"
    );
}

/// A `key/` address with no marker object is exactly what this backend's own
/// `list` returns as `DirectoryInferred`. Answering the bare HEAD's 404 would
/// report an address this backend just handed out as absent, so the same
/// bounded prefix probe `stat` runs decides it.
#[tokio::test]
async fn check_access_of_a_marker_less_directory_is_not_reported_missing() {
    let fake = spawn_fake_s3(Answer::MissingThenListed);
    let decision = anonymous_backend(&fake.endpoint)
        .check_access(
            target("assets/"),
            AccessOps {
                read: true,
                ..AccessOps::default()
            },
            None,
        )
        .await
        .expect("an inferred directory is a decision, not a NotFound");
    assert!(decision.allowed, "and it is readable");
    assert!(!decision.denied_ops.read);
    let requests = fake.requests();
    assert_eq!(
        requests.len(),
        2,
        "the HEAD, then the bounded prefix probe: {:?}",
        requests
            .iter()
            .map(|r| r.request_line())
            .collect::<Vec<_>>()
    );
    assert!(
        requests[1].request_line().contains("list-type=2"),
        "the fallback is the same bounded listing stat uses: {}",
        requests[1].request_line()
    );

    // A store answering the probe with 401 still reads as 403 on an ANONYMOUS
    // connection, and that is deliberate rather than a lost status: the
    // unsigned-refusal restatement collapses 401 into `PermissionDenied` before
    // this code sees it, because there is no credential for an operator to fix.
    // The refusal arm reports whatever the classified error says, so the same
    // code reports a real 401 on a credentialed connection.
    let unauthorized = spawn_fake_s3(Answer::MissingThenUnauthorized);
    let decision = anonymous_backend(&unauthorized.endpoint)
        .check_access(
            target("assets/"),
            AccessOps {
                read: true,
                ..AccessOps::default()
            },
            None,
        )
        .await
        .expect("a refused probe is a decision, not an error");
    assert!(!decision.allowed);
    assert_eq!(
        decision.reason.as_deref(),
        Some("S3 returned HTTP 403"),
        "an anonymous 401 is restated as a permission refusal before it is \
         classified, so the verdict says 403"
    );

    // And when the prefix probe is refused rather than empty, the answer is the
    // access question — may not enumerate — rather than "does not exist".
    let refused = spawn_fake_s3(Answer::MissingThenRefused);
    let decision = anonymous_backend(&refused.endpoint)
        .check_access(
            target("assets/"),
            AccessOps {
                read: true,
                ..AccessOps::default()
            },
            None,
        )
        .await
        .expect("a refused probe is a decision, not an error");
    assert!(!decision.allowed);
    assert!(decision.denied_ops.read);
}

/// The guard clause: a refusal is restated, and nothing else is. Without it a
/// `404` for a bucket that does not exist would be reported as a public-access
/// problem, sending an operator to edit a policy on a bucket that is not there.
#[tokio::test]
async fn a_non_refusal_is_not_restated_as_a_public_access_problem() {
    let fake = spawn_fake_s3(Answer::Refuse(404));
    let backend = anonymous_backend(&fake.endpoint);

    let err = backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect_err("a 404 fails the list");

    assert_eq!(fake.served(), 1);
    assert_eq!(err.code(), ErrorCode::NotFound, "{err}");
    assert!(
        !err.message().to_lowercase().contains("unsigned"),
        "a missing bucket is not a public-access problem: {}",
        err.message()
    );
    assert!(err.next_action().is_none());
}

/// An anonymous refusal must not move the connection's refusal epoch. There is
/// no credential to condemn, and the promotion witness reads the epoch.
///
/// This is the assertion that reddens if someone moves
/// `.interceptor(PromotionEvidence …)` up into the shared `s3_config_builder`,
/// which is exactly the seam the two client constructors now share.
#[tokio::test]
async fn an_anonymous_refusal_records_no_evidence_about_a_credential() {
    let fake = spawn_fake_s3(Answer::Refuse(403));
    let backend = anonymous_backend(&fake.endpoint);
    assert_eq!(
        ovstorage_plugin_s3::__test_only_refusal_epoch(&backend),
        0,
        "control: nothing has happened yet"
    );

    backend
        .list(target("assets/"), ListOptions::default(), None)
        .await
        .expect_err("refused");

    assert_eq!(fake.served(), 1, "the 403 was actually received");
    assert_eq!(
        ovstorage_plugin_s3::__test_only_refusal_epoch(&backend),
        0,
        "an unsigned request's refusal condemns no credential"
    );
}

// === What an anonymous connection still refuses, and how ===

/// Mutations are refused locally, before any request, and the refusal says the
/// connection is anonymous rather than claiming the backend cannot mutate.
///
/// **This test is the enumeration.** The refusal lives in `signed_client()`,
/// which three operations do not reach until after they have done work —
/// `write_stream` buffers a part of the body, `update_metadata` issues a
/// `HeadObject`, and `continue_write`'s single-`PutObject` arm commits from the
/// caller's own result batch and touches no client at all. Each carries a
/// hoisted guard, and a guard placed by hand at N sites proves nothing about
/// site N+1, so every mutating operation is driven here.
///
/// The endpoint is a port nothing listens on, so a refusal that reached the
/// wire would surface as a transport failure instead — which is what makes
/// "no request was issued" observable here.
#[tokio::test]
async fn mutations_on_an_anonymous_connection_are_refused_without_a_request() {
    let backend = anonymous_backend("http://127.0.0.1:1");
    let mut failures: Vec<(&str, ErrorCode, String)> = Vec::new();

    let write = backend
        .write(
            target("assets/new.usd"),
            b"bytes".to_vec(),
            WriteOptions::default(),
            None,
        )
        .await
        .expect_err("anonymous write is refused");
    failures.push(("write", write.code(), write.message().to_string()));

    let delete = backend
        .delete(target("assets/teapot.usd"), DeleteOptions::default(), None)
        .await
        .expect_err("anonymous delete is refused");
    failures.push(("delete", delete.code(), delete.message().to_string()));

    let copy = backend
        .copy(
            target("assets/teapot.usd"),
            target("assets/copy.usd"),
            CopyOptions::default(),
            None,
        )
        .await
        .expect_err("anonymous copy is refused");
    failures.push(("copy", copy.code(), copy.message().to_string()));

    let rename = backend
        .rename(
            target("assets/teapot.usd"),
            target("assets/moved.usd"),
            RenameOptions::default(),
            None,
        )
        .await
        .expect_err("anonymous rename is refused");
    failures.push(("rename", rename.code(), rename.message().to_string()));

    let create_directory = backend
        .create_directory(
            target("assets/new/"),
            CreateDirectoryOptions::default(),
            None,
        )
        .await
        .expect_err("anonymous create_directory is refused");
    failures.push((
        "create_directory",
        create_directory.code(),
        create_directory.message().to_string(),
    ));

    let update_metadata = backend
        .update_metadata(
            target("assets/teapot.usd"),
            UpdateMetadataOptions {
                allow_rewrite_emulation: true,
                ..UpdateMetadataOptions::default()
            },
            None,
        )
        .await
        .expect_err("anonymous update_metadata is refused");
    failures.push((
        "update_metadata",
        update_metadata.code(),
        update_metadata.message().to_string(),
    ));

    let delete_directory = backend
        .delete_directory(target("assets/textures/"), DeleteDirectoryOptions, None)
        .await
        .expect_err("anonymous delete_directory is refused");
    failures.push((
        "delete_directory",
        delete_directory.code(),
        delete_directory.message().to_string(),
    ));

    // `size_hint` must be set: without one `write_redirect` refuses earlier for
    // an unrelated reason (no advertised Content-Length), which would leave the
    // anonymity check untested rather than exempt.
    let write_redirect = backend
        .write_redirect(
            target("assets/new.usd"),
            WriteOptions {
                size_hint: Some(16),
                ..WriteOptions::default()
            },
            None,
        )
        .await
        .expect_err("anonymous write_redirect is refused");
    failures.push((
        "write_redirect",
        write_redirect.code(),
        write_redirect.message().to_string(),
    ));

    // A body whose first chunk is an error. `write_stream` must refuse for
    // anonymity BEFORE it consumes the stream: with the guard the caller gets
    // `Unsupported`, without it the stream is drained and the source error is
    // what surfaces. A well-formed body could not tell the two apart, because
    // the buffered part would then reach `put_object_inline` and be refused
    // there — with the same message, and 8 MiB of the caller's bytes already
    // accepted.
    let body = BodyStream::from_iter(
        vec![Err::<Vec<u8>, ovstorage_plugin::Error>(
            ovstorage_plugin::Error::new(
                ErrorCode::Transient,
                "the stream must not be consumed at all",
            ),
        )]
        .into_iter(),
    );
    let write_stream = backend
        .write_stream(
            target("assets/streamed.usd"),
            body,
            WriteOptions::default(),
            None,
        )
        .await
        .expect_err("anonymous write_stream is refused");
    failures.push((
        "write_stream",
        write_stream.code(),
        write_stream.message().to_string(),
    ));

    // The single-`PutObject` continuation: a caller hands back its own "the PUT
    // succeeded" result and the plugin would otherwise commit it, reaching no
    // client and issuing nothing. Under the broker the whole batch arrives from
    // a remote caller.
    //
    // The continuation blob is deliberately junk. The guard must fire before it
    // is decoded, and `Unsupported` + "anonymous" distinguishes that from the
    // `InvalidArgument` a decode failure would produce — so this asserts the
    // ORDER, not merely the refusal.
    let continue_write = backend
        .continue_write(
            target("assets/new.usd"),
            WriteRedirectBatch {
                redirects: Vec::new(),
                continuation: b"not a continuation".to_vec(),
            },
            RedirectResultBatch {
                results: Vec::new(),
            },
            None,
        )
        .await
        .expect_err("anonymous continue_write is refused");
    failures.push((
        "continue_write",
        continue_write.code(),
        continue_write.message().to_string(),
    ));

    // Not a mutation, but the same question and the same answer: there is no
    // credential to be wrong, so the code is `Unsupported` and not
    // `AuthRequired`. The connection config carries an `sqs_queue_url`, because
    // without one the refusal comes from the missing config instead and says
    // nothing about anonymity.
    let watch_backend = anonymous_backend_watching("http://127.0.0.1:1");
    let watch = watch_backend
        .watch_directory(
            target("assets/"),
            ovstorage_plugin::WatchDirectoryOptions::default(),
            Duration::from_secs(1),
            None,
        )
        .await
        .err()
        .expect("anonymous watch_directory is refused");
    failures.push(("watch_directory", watch.code(), watch.message().to_string()));

    for (operation, code, message) in failures {
        assert_eq!(
            code,
            ErrorCode::Unsupported,
            "{operation} must be Unsupported on an anonymous connection, got {code:?}: {message}"
        );
        assert!(
            message.contains("anonymous"),
            "{operation} must say the connection is anonymous: {message}"
        );
    }
}
