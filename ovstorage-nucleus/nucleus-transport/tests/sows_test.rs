// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use nucleus_transport::{SowsTransport, Transport};

const RESPONSE_ERROR: u8 = 0;
const RESPONSE_SEND: u8 = 1;
const RESPONSE_DONE: u8 = 5;

fn build_response_send(id: u32, last: u8, result_json: &[u8], blob: Option<&[u8]>) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.push(RESPONSE_SEND);
    frame.extend_from_slice(&id.to_le_bytes());
    frame.push(last);
    frame.extend_from_slice(&(result_json.len() as u32).to_le_bytes());
    frame.extend_from_slice(result_json);
    if let Some(b) = blob {
        frame.extend_from_slice(b);
    }
    frame
}

fn build_response_done(id: u32) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5);
    frame.push(RESPONSE_DONE);
    frame.extend_from_slice(&id.to_le_bytes());
    frame
}

fn build_response_error(id: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(RESPONSE_ERROR);
    frame.extend_from_slice(&id.to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn extract_request_id(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[1], data[2], data[3], data[4]])
}

async fn bind_test_server() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{addr}");
    (listener, url)
}

async fn accept_ws(
    listener: TcpListener,
) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
    let (stream, _) = listener.accept().await.unwrap();
    tokio_tungstenite::accept_async(stream).await.unwrap()
}

fn expect_binary(msg: Message) -> Vec<u8> {
    match msg {
        Message::Binary(data) => data.to_vec(),
        other => panic!("expected binary frame, got {other:?}"),
    }
}

#[tokio::test]
async fn test_sows_send_recv() {
    let (listener, url) = bind_test_server().await;

    let server = tokio::spawn(async move {
        let mut ws = accept_ws(listener).await;

        let data = expect_binary(ws.next().await.unwrap().unwrap());
        assert_eq!(data[0], 1);
        let id = extract_request_id(&data);

        let json = br#"{"result":"ok"}"#;
        ws.send(Message::Binary(build_response_send(id, 1, json, None)))
            .await
            .unwrap();
        ws.send(Message::Binary(build_response_done(id)))
            .await
            .unwrap();
    });

    let transport = SowsTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send("TestIface", "call", json!({"key": "value"}), None)
        .await
        .unwrap();

    let raw = sub.recv_raw().await.unwrap();
    assert_eq!(raw.json, br#"{"result":"ok"}"#);
    assert!(raw.blob.is_none());

    server.await.unwrap();
}

#[tokio::test]
async fn test_sows_streaming() {
    let (listener, url) = bind_test_server().await;

    let server = tokio::spawn(async move {
        let mut ws = accept_ws(listener).await;

        let data = expect_binary(ws.next().await.unwrap().unwrap());
        let id = extract_request_id(&data);

        for i in 0..3 {
            let json = format!(r#"{{"seq":{i}}}"#);
            ws.send(Message::Binary(build_response_send(
                id,
                0,
                json.as_bytes(),
                None,
            )))
            .await
            .unwrap();
        }
        ws.send(Message::Binary(build_response_done(id)))
            .await
            .unwrap();
    });

    let transport = SowsTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send("TestIface", "stream", json!({}), None)
        .await
        .unwrap();

    for i in 0..3 {
        let raw = sub.recv_raw().await.unwrap();
        let expected = format!(r#"{{"seq":{i}}}"#);
        assert_eq!(raw.json, expected.as_bytes());
    }

    server.await.unwrap();
}

#[tokio::test]
async fn test_sows_error_response() {
    let (listener, url) = bind_test_server().await;

    let server = tokio::spawn(async move {
        let mut ws = accept_ws(listener).await;

        let data = expect_binary(ws.next().await.unwrap().unwrap());
        let id = extract_request_id(&data);

        let mut payload = Vec::new();
        payload.extend_from_slice(&42u16.to_le_bytes());
        payload.extend_from_slice(b"test error");

        ws.send(Message::Binary(build_response_error(id, &payload)))
            .await
            .unwrap();
    });

    let transport = SowsTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send("TestIface", "fail", json!({}), None)
        .await
        .unwrap();

    let err = sub.recv_raw().await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("42"), "expected error code 42 in: {msg}");
    assert!(
        msg.contains("test error"),
        "expected 'test error' in: {msg}"
    );

    server.await.unwrap();
}

#[tokio::test]
async fn test_sows_error_no_details() {
    let (listener, url) = bind_test_server().await;

    let server = tokio::spawn(async move {
        let mut ws = accept_ws(listener).await;

        let data = expect_binary(ws.next().await.unwrap().unwrap());
        let id = extract_request_id(&data);

        ws.send(Message::Binary(build_response_error(id, &[])))
            .await
            .unwrap();
    });

    let transport = SowsTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send("TestIface", "fail", json!({}), None)
        .await
        .unwrap();

    let err = sub.recv_raw().await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("no details"),
        "expected 'no details' in: {msg}"
    );

    server.await.unwrap();
}

#[tokio::test]
async fn test_sows_stop() {
    let (listener, url) = bind_test_server().await;

    let server = tokio::spawn(async move {
        let mut ws = accept_ws(listener).await;

        let data = expect_binary(ws.next().await.unwrap().unwrap());
        assert_eq!(data[0], 1);
        let id = extract_request_id(&data);

        let stop = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for stop frame")
            .unwrap()
            .unwrap();
        let stop_data = expect_binary(stop);

        assert_eq!(stop_data[0], 0, "expected REQUEST_STOP");
        let stop_id = extract_request_id(&stop_data);
        assert_eq!(stop_id, id);
    });

    let transport = SowsTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send("TestIface", "call", json!({}), None)
        .await
        .unwrap();

    sub.stop().await;
    server.await.unwrap();
}

#[tokio::test]
async fn test_sows_connection_close() {
    let (listener, url) = bind_test_server().await;

    let server = tokio::spawn(async move {
        let mut ws = accept_ws(listener).await;

        let _data = expect_binary(ws.next().await.unwrap().unwrap());

        let _ = ws.send(Message::Close(None)).await;
    });

    let transport = SowsTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send("TestIface", "call", json!({}), None)
        .await
        .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(5), sub.recv_raw()).await;
    let err = result
        .expect("timed out waiting for close error")
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("close"), "expected close error in: {msg}");

    server.await.unwrap();
}

#[tokio::test]
async fn test_sows_truncated_frame_terminates_subscription() {
    let (listener, url) = bind_test_server().await;

    let server = tokio::spawn(async move {
        let mut ws = accept_ws(listener).await;

        let data = expect_binary(ws.next().await.unwrap().unwrap());
        let id = extract_request_id(&data);

        let mut frame = Vec::new();
        frame.push(RESPONSE_SEND);
        frame.extend_from_slice(&id.to_le_bytes());
        frame.push(0);
        frame.extend_from_slice(&100u32.to_le_bytes());
        frame.extend_from_slice(b"only-three-bytes");
        ws.send(Message::Binary(frame)).await.unwrap();
    });

    let transport = SowsTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send("TestIface", "call", json!({}), None)
        .await
        .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(5), sub.recv_raw()).await;
    let err = result
        .expect("timed out waiting for terminal error after truncated frame")
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("malformed"), "expected 'malformed' in: {msg}");

    server.await.unwrap();
}

#[tokio::test]
async fn test_sows_short_frame_ignored() {
    let (listener, url) = bind_test_server().await;

    let server = tokio::spawn(async move {
        let mut ws = accept_ws(listener).await;

        let data = expect_binary(ws.next().await.unwrap().unwrap());
        let id = extract_request_id(&data);

        // Frame shorter than 5 bytes — should be silently ignored by the client.
        ws.send(Message::Binary(vec![0xFF, 0x01, 0x02]))
            .await
            .unwrap();

        let json = br#"{"valid":true}"#;
        ws.send(Message::Binary(build_response_send(id, 1, json, None)))
            .await
            .unwrap();
        ws.send(Message::Binary(build_response_done(id)))
            .await
            .unwrap();
    });

    let transport = SowsTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send("TestIface", "call", json!({}), None)
        .await
        .unwrap();

    let raw = sub.recv_raw().await.unwrap();
    assert_eq!(raw.json, br#"{"valid":true}"#);

    server.await.unwrap();
}
