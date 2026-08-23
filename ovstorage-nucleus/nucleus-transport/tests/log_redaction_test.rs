// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end check that no credential reaches a `tracing` event the
//! transports emit.
//!
//! The qualifier is load-bearing. This installs a `tracing` subscriber and
//! nothing else, so a record written through the `log` crate is invisible to
//! it — including the one the websocket library writes at TRACE, which renders
//! the whole HTTP upgrade request and therefore the unredacted connect URL. A
//! deployment whose subscriber both installs the `log` bridge and admits that
//! target sees that record; this file cannot fail on it, and no assertion here
//! should be read as covering it.
//!
//! The unit tests in `redact` prove the helper transforms a string. They say
//! nothing about whether the transports call it, which is the property that
//! actually keeps a token out of a log — a helper can be correct and every
//! call site can still pass the raw value.
//!
//! So this captures the events the transports really emit, through a global
//! subscriber, and asserts on their rendered fields. The subscriber has to be
//! global rather than thread-local: `connect` moves its work onto the
//! plugin-wide IO runtime, so a `with_default` guard on the test thread would
//! capture nothing and every assertion here would pass vacuously.
//! `the_capture_harness_observes_transport_events` is the control against that,
//! and `assert_redacted` refuses an empty event list for the same reason.
//!
//! The capture renders an event's own fields and the fields of every span it
//! sits inside, because a deployment's subscriber prints an event's span
//! context alongside the event. Without the span walk, a credential recorded
//! as a span field reaches a real log while passing every assertion here.
//!
//! The transports in this crate emit bare events and open no spans, so the
//! only span these tests exercise is the synthetic one in
//! `the_capture_harness_observes_span_fields`. The walk is what keeps the
//! suite honest if a span is introduced here later; it says nothing about the
//! spans in the plugin crate, which this binary does not link.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use futures::{SinkExt, StreamExt};
use nucleus_transport::{ConnLibTransport, SowsTransport, Transport};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::set_global_default;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::{LookupSpan, Registry};

/// A synthetic stand-in for a credential. Not a token in any format — its only
/// job is to be a string that must never appear in a captured event.
const SENTINEL: &str = "sentinel-value-that-must-not-be-logged";

type Captured = Arc<Mutex<Vec<String>>>;

struct CaptureLayer(Captured);

struct FieldWriter(String);

impl Visit for FieldWriter {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={:?}", field.name(), value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push_str(&format!(" {}={}", field.name(), value));
    }
}

/// A span's recorded fields, rendered once and kept for the events beneath it.
struct SpanFields(String);

impl<S> Layer<S> for CaptureLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut writer = FieldWriter(String::new());
        attrs.record(&mut writer);
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanFields(writer.0));
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        // Render before taking the lock. `record` runs arbitrary `Debug` and
        // `Display` impls, and one that emits an event while this span is
        // entered would re-enter `on_event` on this thread and read the
        // extensions this thread holds for write.
        let mut writer = FieldWriter(String::new());
        values.record(&mut writer);
        if let Some(span) = ctx.span(id) {
            let mut extensions = span.extensions_mut();
            match extensions.get_mut::<SpanFields>() {
                Some(fields) => fields.0.push_str(&writer.0),
                // Absent only if `on_new_span` did not run for this span.
                // Inserting keeps a late-filled field observable; dropping it
                // would hide a credential and leave every assertion green.
                None => extensions.insert(SpanFields(writer.0)),
            }
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let mut writer = FieldWriter(String::new());
        // `conn_id` counters are per-module statics, so ConnLib and SOWS both
        // issue a connection 0. The target is what separates them, and
        // `(target, conn_id)` is unique for the process.
        writer
            .0
            .push_str(&format!(" target={}", event.metadata().target()));
        event.record(&mut writer);
        // Also render the fields of every span the event sits inside. A
        // credential recorded as a span field — `#[instrument(fields(url =
        // %url))]`, or `span!(.., url = %url)` — reaches a deployment's
        // subscriber but is not a field of the event itself, so an event-only
        // capture would show none of it and every assertion here would hold
        // while the URL was being printed in production.
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope {
                if let Some(fields) = span.extensions().get::<SpanFields>() {
                    writer.0.push_str(&fields.0);
                }
            }
        }
        self.0.lock().unwrap().push(writer.0);
    }
}

fn captured() -> &'static Captured {
    static CAPTURED: OnceLock<Captured> = OnceLock::new();
    CAPTURED.get_or_init(|| {
        let sink: Captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Registry::default().with(CaptureLayer(Arc::clone(&sink)));
        set_global_default(subscriber).expect("no other global subscriber in this test binary");
        sink
    })
}

/// Install the capture subscriber. Every test must call this **before** it
/// connects: the subscriber is global and installed on first use, so a test
/// that only reaches it via `snapshot` afterwards emits its events into no
/// subscriber at all and then asserts over an empty list.
fn install_capture() {
    let _ = captured();
}

/// Every event captured so far, copied out.
///
/// Deliberately not a drain: tests run concurrently against one global sink,
/// and a drain in one test would delete the events another is about to assert
/// on, turning a real leak into an empty-and-therefore-quiet result. Callers
/// select their own connection's events with `events_for`.
fn snapshot() -> Vec<String> {
    captured().lock().unwrap().clone()
}

/// The path for one test connection, distinct from every other in this binary.
///
/// A path is needed at all because a query spliced directly onto the authority
/// — `ws://host:port?k=v` — is not a valid HTTP request target: the connect
/// fails before any URL is logged, so the path is what keeps these tests
/// exercising redaction rather than an early error.
///
/// It is a *unique* path because `events_for` identifies a connection by
/// `host:port` plus path, and the capture sink outlives every connection in the
/// binary. An ephemeral port identifies a connection only while it stays bound;
/// once released and re-bound by another test, that test's `events_for` also
/// selects the earlier connection's events, which sit in the sink forever. A
/// counter is unique for the whole run, so each connection's events stay its
/// own however the operating system recycles ports.
///
/// The trailing separator keeps one path from being a prefix of another:
/// `events_for` matches on a substring, and `/connection-1` occurs inside
/// `/connection-10`.
///
/// Each value goes to exactly one caller, which is also why
/// `the_capture_harness_observes_span_fields` uses one as a bare marker to
/// pick its own event out of the shared sink.
fn unique_path() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("/connection-{}/", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// A websocket server that accepts one connection and then does nothing. The
/// handshake is all these tests need; no frames are exchanged.
async fn accepting_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let path = unique_path();
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = tokio_tungstenite::accept_async(stream).await;
            std::future::pending::<()>().await;
        }
    });
    format!("ws://127.0.0.1:{port}{path}")
}

/// A server that closes every connection without answering the handshake, so
/// a connect attempt fails. Exercises the `error!` arm, which logs the URL
/// just as the success arms do.
///
/// The refusal comes from closing an accepted connection, and the listener
/// stays bound while the test runs. Two other shapes do not work:
///
/// - Binding a port and dropping the listener refuses the connect, but it hands
///   the port back to the ephemeral pool while this test is still running, so a
///   concurrent `accepting_server` can take it and answer the handshake this
///   arm needs to fail.
/// - Holding a bound socket that never calls `accept` refuses nothing at all:
///   the kernel completes the TCP handshake from the listen backlog, and the
///   websocket handshake then blocks forever waiting for a response.
///
/// Accepting and closing gives both properties at once — the client sees the
/// connection torn down, and the port stays bound for as long as this test is
/// running. It is released when the test returns and its runtime drops, which
/// is why `unique_path` rather than the port is what identifies a connection's
/// events in a sink that outlives it.
async fn refusing_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let path = unique_path();
    tokio::spawn(async move {
        loop {
            // An accept error must not free the port, whatever its cause:
            // returning here would drop the listener while the test still
            // runs. The yield keeps a persistent error from spinning against
            // the other tests sharing this runtime.
            match listener.accept().await {
                Ok((stream, _)) => drop(stream),
                Err(_) => tokio::task::yield_now().await,
            }
        }
    });
    format!("ws://127.0.0.1:{port}{path}")
}

/// Events from `base`'s connection only.
///
/// The capture sink is global, so every test in this binary writes to it and
/// tests run concurrently. Selecting by `host:port` plus the connection's
/// unique path keeps each assertion about its own connection; without it a
/// passing test could be reading another test's events.
fn events_for(events: &[String], base: &str) -> Vec<String> {
    let authority = base.trim_start_matches("ws://");
    events
        .iter()
        .filter(|e| e.contains(authority))
        .cloned()
        .collect()
}

/// The value `CaptureLayer` rendered for `name`, if the event carries it.
///
/// Covers both an event's own fields and the pseudo-fields the layer
/// synthesizes, such as `target`. The first occurrence wins, so a value
/// appended later from a span's fields cannot displace the event's own.
///
/// Values are compared whole rather than by substring, so `conn_id=1` does not
/// match `conn_id=10`. Only for names whose values contain no space.
fn field_word(event: &str, name: &str) -> Option<String> {
    let rest = event.split(&format!(" {name}=")).nth(1)?;
    Some(rest.split(' ').next()?.to_string())
}

/// The `conn_id` the transport assigned to `base`'s connection.
///
/// The request and response `trace!` sites carry `conn_id` and no URL, so a
/// connection's path cannot select them. The connect events carry both, which
/// makes `conn_id` the bridge from a URL to the events that name only an id.
fn conn_id_for(events: &[String], base: &str) -> String {
    let mut ids: Vec<String> = events_for(events, base)
        .iter()
        .filter_map(|e| field_word(e, "conn_id"))
        .collect();
    ids.sort();
    ids.dedup();
    assert_eq!(
        ids.len(),
        1,
        "expected exactly one conn_id for this connection, found {ids:?}"
    );
    ids.remove(0)
}

/// Events one transport module emitted for its connection `conn_id`.
///
/// The target is part of the key because each transport module owns a private
/// connection counter, so ConnLib and SOWS both issue a connection 0. `conn_id`
/// alone would span the two.
fn events_for_conn(events: &[String], target: &str, conn_id: &str) -> Vec<String> {
    events
        .iter()
        .filter(|e| {
            field_word(e, "target").as_deref() == Some(target)
                && field_word(e, "conn_id").as_deref() == Some(conn_id)
        })
        .cloned()
        .collect()
}

fn assert_redacted(all: &[String], base: &str, context: &str) {
    // The negative runs over the WHOLE capture. `SENTINEL` is a constant of this
    // file that only these tests splice into a URL, so a wider scope adds no
    // false positives, and a credential that leaked into an event carrying
    // neither the authority nor a `conn_id` is caught by nothing narrower. The
    // cost is that one transport's leak also reddens the other's tests, which is
    // noise on a genuine failure rather than a false alarm.
    for event in all {
        assert!(
            !event.contains(SENTINEL),
            "{context}: a credential reached a tracing event: {event}"
        );
    }
    // The positive checks stay scoped: they ask whether THIS connection
    // exercised the redaction, which another connection's events could
    // otherwise answer.
    let events = events_for(all, base);
    assert!(
        !events.is_empty(),
        "{context}: captured no events for this connection, so this proves nothing"
    );
    let url_events: Vec<_> = events.iter().filter(|e| e.contains("url=")).collect();
    assert!(
        !url_events.is_empty(),
        "{context}: no event carried a `url` field, so the redaction was never exercised"
    );
    for event in url_events {
        assert!(
            event.contains("access_token=REDACTED"),
            "{context}: a url field lost its redaction marker: {event}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connlib_connect_does_not_log_a_url_credential() {
    install_capture();
    let base = accepting_server().await;

    let transport = ConnLibTransport::connect(&format!("{base}?access_token={SENTINEL}")).await;
    assert!(transport.is_ok(), "the good connection must still succeed");

    assert_redacted(&snapshot(), &base, "connlib success");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_connlib_connect_does_not_log_a_url_credential() {
    install_capture();
    let base = refusing_server().await;

    let transport = ConnLibTransport::connect(&format!("{base}?access_token={SENTINEL}")).await;
    assert!(
        transport.is_err(),
        "a server that closes the connection must fail the handshake"
    );

    assert_redacted(&snapshot(), &base, "connlib failure");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sows_connect_does_not_log_a_url_credential() {
    install_capture();
    let base = accepting_server().await;

    let transport = SowsTransport::connect(&format!("{base}?access_token={SENTINEL}")).await;
    assert!(transport.is_ok(), "the good connection must still succeed");

    assert_redacted(&snapshot(), &base, "sows success");
}

/// The good input. Redaction must not disturb the URL a Nucleus deployment
/// actually advertises, which carries no query string at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_url_without_a_credential_is_logged_intact() {
    install_capture();
    let base = accepting_server().await;

    let transport = ConnLibTransport::connect(&base).await;
    assert!(transport.is_ok(), "the good connection must still succeed");

    let events = events_for(&snapshot(), &base);
    let url_events: Vec<_> = events.iter().filter(|e| e.contains("url=")).collect();
    assert!(!url_events.is_empty(), "no event carried a `url` field");
    for event in url_events {
        assert!(
            event.contains(&base),
            "a benign url was altered, costing diagnostic value: {event}"
        );
        assert!(
            !event.contains("REDACTED"),
            "a benign url was redacted: {event}"
        );
    }
}

/// A websocket server that records the HTTP request target it was asked for.
///
/// Returns the connect URL and a slot that holds the raw target once the
/// handshake completes. `accept_hdr_async` is what makes the target visible:
/// `accept_async` answers the upgrade without ever showing the request to the
/// server, which is why nothing here could previously observe it.
/// The callback's error type is `ErrorResponse`, fixed by the handshake trait
/// this closure implements, so its size is not ours to reduce.
#[allow(clippy::result_large_err)]
fn observing_server() -> (
    impl std::future::Future<Output = String>,
    Arc<Mutex<Option<String>>>,
) {
    let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let recorder = Arc::clone(&seen);
    let serve = async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let path = unique_path();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let callback = |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                                res: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    *recorder.lock().unwrap() = Some(req.uri().to_string());
                    Ok(res)
                };
                let _ = tokio_tungstenite::accept_hdr_async(stream, callback).await;
                std::future::pending::<()>().await;
            }
        });
        format!("ws://127.0.0.1:{port}{path}")
    };
    (serve, seen)
}

/// Poll `seen` until the handshake has recorded a target.
///
/// The recorder is filled on the server task, so a bare read races the
/// handshake. Failing on timeout rather than returning `None` keeps a missed
/// handshake from reading as a passing assertion.
async fn recorded_target(seen: &Arc<Mutex<Option<String>>>) -> String {
    for _ in 0..600 {
        if let Some(target) = seen.lock().unwrap().clone() {
            return target;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the server never recorded a request target, so this proves nothing");
}

/// The PR's central safety claim: redaction changes the logged copy of a URL
/// and not the URL handed to the websocket client.
///
/// Every other test in this file holds whichever way that goes. A refactor
/// passing the redacted string to `connect_async` would still complete the
/// handshake against a server that ignores its request target, and the logged
/// URL is redacted either way — so the whole suite would stay green while the
/// transport connected with `access_token=REDACTED` and every request failed
/// against a real Nucleus.
///
/// Asserting on the target the server actually received is what pins it, and
/// it is asserted for both transports because each builds its own connect
/// call.
#[tokio::test(flavor = "multi_thread")]
async fn the_url_sent_to_the_server_keeps_its_credential() {
    install_capture();

    let (serve, seen) = observing_server();
    let base = serve.await;
    let url = format!("{base}?access_token={SENTINEL}");
    let transport = ConnLibTransport::connect(&url).await;
    assert!(transport.is_ok(), "the good connection must still succeed");
    let target = recorded_target(&seen).await;
    assert!(
        target.contains(&format!("access_token={SENTINEL}")),
        "connlib handed a redacted URL to the websocket client: `{target}`"
    );
    assert!(
        !target.contains("REDACTED"),
        "connlib handed a redacted URL to the websocket client: `{target}`"
    );
    // The other half of the claim: the logged copy IS redacted. Asserting only
    // the wire form would pass if redaction were removed altogether.
    assert_redacted(&snapshot(), &base, "connlib wire url");

    let (serve, seen) = observing_server();
    let base = serve.await;
    let url = format!("{base}?access_token={SENTINEL}");
    let transport = SowsTransport::connect(&url).await;
    assert!(transport.is_ok(), "the good connection must still succeed");
    let target = recorded_target(&seen).await;
    assert!(
        target.contains(&format!("access_token={SENTINEL}")),
        "sows handed a redacted URL to the websocket client: `{target}`"
    );
    assert!(
        !target.contains("REDACTED"),
        "sows handed a redacted URL to the websocket client: `{target}`"
    );
    assert_redacted(&snapshot(), &base, "sows wire url");
}

/// A websocket server that answers one request, echoing `echo` into the
/// response body so the response-side `trace!` site has a credential to leak.
async fn echoing_server(echo: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let path = unique_path();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
            return;
        };
        let (mut sink, mut stream) = ws.split();
        if let Some(Ok(Message::Binary(data))) = stream.next().await {
            let json_end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            let req: serde_json::Value = serde_json::from_slice(&data[..json_end]).unwrap();
            let id = req["id"].as_u64().unwrap();
            let body =
                serde_json::to_vec(&serde_json::json!({"id": id, "fin": true, "secret": echo}))
                    .unwrap();
            let _ = sink.send(Message::Binary(body)).await;
        }
        std::future::pending::<()>().await;
    });
    format!("ws://127.0.0.1:{port}{path}")
}

/// The request and response `trace!` sites report body lengths, not bodies.
///
/// The two halves of this test scope differently, on purpose.
///
/// The negative assertion runs over the WHOLE capture. Those events carry
/// `conn_id`, `id`, `method` and lengths and no authority, so selecting by
/// authority would discard every one of them and the assertion would pass
/// having inspected nothing. A sentinel unique to this test is what makes the
/// wider scope safe: no other test uses this string, and the constant is
/// local to this function.
///
/// The premise checks are scoped to this connection's `conn_id`. They ask
/// whether a request and a response event fired, and any test that sent a
/// request could satisfy that over the shared sink — leaving the premise true
/// while this test's own request path went unexercised. Holding today because
/// only one test sends is a property of the file's contents, not of the
/// assertion.
///
/// Both directions are covered in one connection: the sentinel goes out in
/// `params` and comes back in the response body.
#[tokio::test(flavor = "multi_thread")]
async fn connlib_request_and_response_bodies_stay_out_of_events() {
    const BODY_SENTINEL: &str = "sentinel-connlib-body-must-not-be-logged";

    install_capture();
    let url = echoing_server(BODY_SENTINEL).await;

    let transport = ConnLibTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send(
            "ignored",
            "hello",
            serde_json::json!({ "secret": BODY_SENTINEL }),
            None,
        )
        .await
        .unwrap();
    // Bounded because the echo server runs in a detached task whose panic is
    // swallowed: without a timeout a framing mistake in the server wedges this
    // test forever instead of failing it, and `cargo test` imposes no deadline.
    let raw = tokio::time::timeout(std::time::Duration::from_secs(30), sub.recv_raw())
        .await
        .expect("the echo server never answered; it most likely panicked")
        .unwrap();

    // The premise: the credential really did travel in both directions. Without
    // this the test could pass because nothing was ever sent.
    assert!(
        String::from_utf8_lossy(&raw.json).contains(BODY_SENTINEL),
        "the server did not echo the sentinel, so nothing was at risk"
    );

    let all = snapshot();
    let mine = events_for_conn(&all, "nucleus_transport::connlib", &conn_id_for(&all, &url));
    // `json_len` pins the body-carrying sites. `received response` on its own
    // also matches the unknown-request site, which reports no lengths and is
    // not a place a body could leak.
    assert!(
        mine.iter()
            .any(|e| e.contains("sending request") && e.contains(" json_len=")),
        "no `sending request` event for this connection, so this proves nothing"
    );
    assert!(
        mine.iter()
            .any(|e| e.contains("received response") && e.contains(" json_len=")),
        "no `received response` event for this connection, so this proves nothing"
    );
    for event in &all {
        assert!(
            !event.contains(BODY_SENTINEL),
            "a request or response body reached a tracing event: {event}"
        );
    }
}

/// A websocket server that answers one SOWS request, echoing the `params` it
/// was sent back inside the response body.
///
/// SOWS frames are binary and positional, so this has to build them by hand.
/// The request the client sends is `REQUEST_SEND` (1), the id as four
/// little-endian bytes, `"{interface}.{method}"`, a NUL, the parameter length as
/// four little-endian bytes, then the parameter bytes. The response the read
/// loop expects is `RESPONSE_SEND` (1), the same id as four little-endian bytes,
/// a `last` byte, the result length as four little-endian bytes, then the result
/// JSON — the loop slices `payload = data[5..]`, `payload[0]` as `last`,
/// `payload[1..5]` as the length and `payload[5..5 + len]` as the body.
///
/// Echoing the parameters rather than a constant is what makes one assertion
/// cover both directions: the sentinel can only come back if it really went out
/// on the wire, so a request path that never sent it fails the premise instead
/// of passing quietly.
async fn sows_echoing_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let path = unique_path();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
            return;
        };
        let (mut sink, mut stream) = ws.split();
        if let Some(Ok(Message::Binary(data))) = stream.next().await {
            assert_eq!(data[0], 1, "expected a REQUEST_SEND frame");
            let id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            let method_end = 5 + data[5..].iter().position(|&b| b == 0).unwrap();
            let params_start = method_end + 1 + 4;
            let params_len = u32::from_le_bytes([
                data[method_end + 1],
                data[method_end + 2],
                data[method_end + 3],
                data[method_end + 4],
            ]) as usize;
            let params: serde_json::Value =
                serde_json::from_slice(&data[params_start..params_start + params_len]).unwrap();

            let result = serde_json::to_vec(&serde_json::json!({ "echoed": params })).unwrap();
            let mut frame = Vec::new();
            frame.push(1u8); // RESPONSE_SEND
            frame.extend_from_slice(&id.to_le_bytes());
            frame.push(1u8); // last
            frame.extend_from_slice(&(result.len() as u32).to_le_bytes());
            frame.extend_from_slice(&result);
            let _ = sink.send(Message::Binary(frame)).await;
        }
        std::future::pending::<()>().await;
    });
    format!("ws://127.0.0.1:{port}{path}")
}

/// The SOWS request and response `trace!` sites report body lengths, not bodies.
///
/// ConnLib's equivalent says nothing about this transport: each builds its own
/// frame and logs at its own site, so restoring `params = %params_preview` on
/// the SOWS send site, or a body field on its receive site, leaves every other
/// test in this binary green. SOWS is also where the higher-value payloads are
/// — by `sows.rs`'s own account `Tokens.auth_with_api_token` and
/// `Credentials.auth` carry a literal API token and a username/password payload
/// in `params`.
///
/// The two halves scope differently, for the reasons the ConnLib test sets out.
/// The negative runs over the WHOLE capture, because these events carry
/// `conn_id`, `id`, `method` and lengths and no authority — selecting by
/// authority would discard every one of them and the assertion would pass
/// having inspected nothing. A sentinel local to this test is what makes the
/// wider scope safe. The premise checks stay scoped to this connection's
/// `conn_id` under the SOWS target, so another test's request cannot satisfy
/// them on this test's behalf.
#[tokio::test(flavor = "multi_thread")]
async fn sows_request_and_response_bodies_stay_out_of_events() {
    const BODY_SENTINEL: &str = "sentinel-sows-body-must-not-be-logged";

    install_capture();
    let url = sows_echoing_server().await;

    let transport = SowsTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send(
            "Tokens",
            "auth_with_api_token",
            serde_json::json!({ "secret": BODY_SENTINEL }),
            None,
        )
        .await
        .unwrap();
    // Bounded because the echo server runs in a detached task whose panic is
    // swallowed: without a timeout a framing mistake in the server wedges this
    // test forever instead of failing it, and `cargo test` imposes no deadline.
    let raw = tokio::time::timeout(std::time::Duration::from_secs(30), sub.recv_raw())
        .await
        .expect("the echo server never answered; it most likely panicked")
        .unwrap();

    // The premise: the credential really did travel in both directions. The
    // server echoes what it was sent, so this fails if the request never
    // carried the sentinel as well as if the response never came back.
    assert!(
        String::from_utf8_lossy(&raw.json).contains(BODY_SENTINEL),
        "the server did not echo the sentinel, so nothing was at risk"
    );

    let all = snapshot();
    let mine = events_for_conn(&all, "nucleus_transport::sows", &conn_id_for(&all, &url));
    // The send site reports `params_len`, not ConnLib's `json_len`; pinning the
    // wrong name would make this premise unsatisfiable and the leak assertion
    // would never be reached.
    assert!(
        mine.iter()
            .any(|e| e.contains("sending request") && e.contains(" params_len=")),
        "no `sending request` event for this connection, so this proves nothing"
    );
    // `json_len` pins the body-carrying receive site. The module's other
    // response events — `response for unknown request`, `received remote error
    // for request` — report no body length and are not places a body could
    // leak, and only this site spells its message `received response`.
    assert!(
        mine.iter()
            .any(|e| e.contains("received response") && e.contains(" json_len=")),
        "no `received response` event for this connection, so this proves nothing"
    );
    for event in &all {
        assert!(
            !event.contains(BODY_SENTINEL),
            "a request or response body reached a tracing event: {event}"
        );
    }
}

/// A websocket server that completes the handshake and then sends one text
/// frame.
///
/// Both read loops match `Binary`, `Ping`, `Pong`, `Close`/end-of-stream and
/// the error case before their catch-all, so a text frame is what actually
/// reaches the unexpected-message arm — the same shape a server-sent auth
/// envelope takes when it is not binary.
async fn text_sending_server(text: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let path = unique_path();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
            return;
        };
        let _ = ws.send(Message::Text(text.to_string())).await;
        std::future::pending::<()>().await;
    });
    format!("ws://127.0.0.1:{port}{path}")
}

/// Poll the capture until `target`'s connection for `base` has logged the
/// unexpected-message warning, and return the capture that carried it.
///
/// The warning is emitted on the transport's read loop, so a bare read races
/// it. Panicking on timeout rather than returning what was captured so far is
/// what keeps "the event never arrived" from reading as a passing test: the
/// leak assertion is trivially true over a capture that never saw the arm run.
async fn capture_with_unexpected_message(target: &str, base: &str) -> Vec<String> {
    for _ in 0..600 {
        let all = snapshot();
        let conn_id = conn_id_for(&all, base);
        if events_for_conn(&all, target, &conn_id)
            .iter()
            .any(|e| e.contains("unexpected websocket message type"))
        {
            return all;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("`{target}` never logged an unexpected websocket message, so this proves nothing");
}

/// The unexpected-message arms report the variant and the length, not the
/// payload.
///
/// Nothing else in this binary drives either arm: every other test sends binary
/// frames or none at all. So reintroducing `{msg:?}` there would print a
/// server-sent authentication envelope in its text form while the whole suite
/// stayed green.
///
/// Both transports are covered because each read loop has its own arm and its
/// own logging site, and each gets its own server so that `conn_id_for` sees
/// exactly one connection per authority.
#[tokio::test(flavor = "multi_thread")]
async fn an_unexpected_websocket_message_payload_stays_out_of_events() {
    const TEXT_SENTINEL: &str = "sentinel-websocket-text-must-not-be-logged";

    install_capture();

    let base = text_sending_server(TEXT_SENTINEL).await;
    let _transport = ConnLibTransport::connect(&base).await.unwrap();
    let all = capture_with_unexpected_message("nucleus_transport::connlib", &base).await;
    // The negative runs over the whole capture, as the body tests do: the
    // sentinel is local to this test, and a payload that leaked into an event
    // carrying neither the authority nor a `conn_id` is caught by nothing
    // narrower.
    for event in &all {
        assert!(
            !event.contains(TEXT_SENTINEL),
            "an unexpected websocket payload reached a tracing event: {event}"
        );
    }

    let base = text_sending_server(TEXT_SENTINEL).await;
    let _transport = SowsTransport::connect(&base).await.unwrap();
    let all = capture_with_unexpected_message("nucleus_transport::sows", &base).await;
    for event in &all {
        assert!(
            !event.contains(TEXT_SENTINEL),
            "an unexpected websocket payload reached a tracing event: {event}"
        );
    }
}

/// The SOWS failure arm, which logs the URL just as its success arms do.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_sows_connect_does_not_log_a_url_credential() {
    install_capture();
    let base = refusing_server().await;

    let transport = SowsTransport::connect(&format!("{base}?access_token={SENTINEL}")).await;
    assert!(
        transport.is_err(),
        "a server that closes the connection must fail the handshake"
    );

    assert_redacted(&snapshot(), &base, "sows failure");
}

/// The control for the span half of the capture.
///
/// A subscriber configured the way a deployment configures one prints an
/// event's span context, so a credential recorded as a span field reaches the
/// log without ever being a field of an event. A capture that read only
/// `event.record` would show none of it and every assertion in this file would
/// still hold. This asserts the capture sees a span field, so that blind spot
/// fails loudly rather than quietly.
#[tokio::test(flavor = "multi_thread")]
async fn the_capture_harness_observes_span_fields() {
    const SPAN_SENTINEL: &str = "sentinel-span-field-must-be-observable";

    install_capture();
    let span = tracing::info_span!("outer", secret = SPAN_SENTINEL);
    let marker = {
        let _entered = span.enter();
        let marker = unique_path();
        tracing::info!(marker = %marker, "an event with no secret of its own");
        marker
    };

    let mine: Vec<_> = snapshot()
        .into_iter()
        .filter(|e| e.contains(&marker))
        .collect();
    assert_eq!(
        mine.len(),
        1,
        "expected exactly one event carrying this marker, found {mine:?}"
    );
    assert!(
        mine[0].contains(SPAN_SENTINEL),
        "the capture cannot see span fields, so a credential recorded on a span \
         would pass every assertion in this file: {}",
        mine[0]
    );
}

/// The control for the capture harness itself. If the global subscriber were
/// not installed, or the layer never ran, `snapshot` would return empty here *and*
/// in every test above — and `assert_redacted` would be asserting over nothing.
#[tokio::test(flavor = "multi_thread")]
async fn the_capture_harness_observes_transport_events() {
    install_capture();
    let base = accepting_server().await;

    let _ = ConnLibTransport::connect(&base).await;

    let events = events_for(&snapshot(), &base);
    // Match the rendered `message` field, not a bare `connect`. Every selected
    // event contains this connection's path, and `/connection-0/` contains
    // `connect`, so a bare substring is true of every element by construction
    // and the control would reduce to `!events.is_empty()`.
    assert!(
        events.iter().any(|e| e.contains("message=connected")),
        "the harness captured no `connected` event, so it cannot witness a leak: {events:?}"
    );
}
