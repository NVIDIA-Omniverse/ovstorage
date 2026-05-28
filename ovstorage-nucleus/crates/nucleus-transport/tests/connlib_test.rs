// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;

use futures::{SinkExt, StreamExt};
use nucleus_transport::{ConnLibTransport, Transport};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

type WsStream = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

async fn start_connlib_server<F, Fut>(handler: F) -> String
where
    F: FnOnce(WsStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        handler(ws).await;
    });
    format!("ws://127.0.0.1:{port}")
}

fn parse_connlib_json(data: &[u8]) -> serde_json::Value {
    let json_end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    serde_json::from_slice(&data[..json_end]).unwrap()
}

fn make_response(id: u64, fin: bool) -> Vec<u8> {
    serde_json::to_vec(&json!({"id": id, "fin": fin})).unwrap()
}

fn make_response_with_blob(id: u64, fin: bool, blob: &[u8]) -> Vec<u8> {
    let json_bytes = serde_json::to_vec(&json!({"id": id, "fin": fin})).unwrap();
    let mut frame = Vec::with_capacity(json_bytes.len() + 1 + blob.len());
    frame.extend_from_slice(&json_bytes);
    frame.push(0);
    frame.extend_from_slice(blob);
    frame
}

#[tokio::test]
async fn test_connlib_send_recv() {
    let url = start_connlib_server(|ws| async move {
        let (mut sink, mut stream) = ws.split();
        if let Some(Ok(Message::Binary(data))) = stream.next().await {
            let req = parse_connlib_json(&data);
            let id = req["id"].as_u64().unwrap();
            assert_eq!(req["command"], "hello");

            sink.send(Message::Binary(make_response(id, true)))
                .await
                .unwrap();
        }
    })
    .await;

    let transport = ConnLibTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send("ignored", "hello", json!({}), None)
        .await
        .unwrap();

    let raw = sub.recv_raw().await.unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&raw.json).unwrap();
    assert!(resp["fin"].as_bool().unwrap());
    assert!(raw.blob.is_none());
}

#[tokio::test]
async fn test_connlib_streaming() {
    let url = start_connlib_server(|ws| async move {
        let (mut sink, mut stream) = ws.split();
        if let Some(Ok(Message::Binary(data))) = stream.next().await {
            let id = parse_connlib_json(&data)["id"].as_u64().unwrap();

            for _ in 0..3 {
                sink.send(Message::Binary(make_response(id, false)))
                    .await
                    .unwrap();
            }
            sink.send(Message::Binary(make_response(id, true)))
                .await
                .unwrap();
        }
    })
    .await;

    let transport = ConnLibTransport::connect(&url).await.unwrap();
    let sub = transport
        .send("ignored", "stream", json!({}), None)
        .await
        .unwrap();

    let items: Vec<_> = sub.collect().await;
    assert_eq!(items.len(), 4);
    for item in &items {
        assert!(item.is_ok());
    }
}

#[tokio::test]
async fn test_connlib_stop() {
    let (stop_frame_tx, stop_frame_rx) = tokio::sync::oneshot::channel::<serde_json::Value>();

    let url = start_connlib_server(|ws| async move {
        let (mut sink, mut stream) = ws.split();
        if let Some(Ok(Message::Binary(data))) = stream.next().await {
            let id = parse_connlib_json(&data)["id"].as_u64().unwrap();

            sink.send(Message::Binary(make_response(id, false)))
                .await
                .unwrap();

            if let Some(Ok(Message::Binary(stop_data))) = stream.next().await {
                let _ = stop_frame_tx.send(parse_connlib_json(&stop_data));
            }
        }
    })
    .await;

    let transport = ConnLibTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send("ignored", "subscribe", json!({}), None)
        .await
        .unwrap();

    let _ = sub.recv_raw().await.unwrap();
    let original_id = sub.id();
    sub.stop().await;

    let stop_frame = tokio::time::timeout(std::time::Duration::from_secs(2), stop_frame_rx)
        .await
        .expect("timed out waiting for stop frame")
        .expect("server handler dropped without sending");

    assert_eq!(stop_frame["command"], "stop");
    assert_eq!(stop_frame["subscription_id"].as_u64().unwrap(), original_id);
}

#[tokio::test]
async fn test_connlib_binary_blob() {
    let expected_blob = b"hello binary world";

    let url = start_connlib_server(|ws| async move {
        let (mut sink, mut stream) = ws.split();
        if let Some(Ok(Message::Binary(data))) = stream.next().await {
            let id = parse_connlib_json(&data)["id"].as_u64().unwrap();
            let frame = make_response_with_blob(id, true, b"hello binary world");
            sink.send(Message::Binary(frame)).await.unwrap();
        }
    })
    .await;

    let transport = ConnLibTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send("ignored", "get_blob", json!({}), None)
        .await
        .unwrap();

    let raw = sub.recv_raw().await.unwrap();
    assert_eq!(raw.blob.as_deref(), Some(expected_blob.as_slice()));
}

#[tokio::test]
async fn test_connlib_connection_close() {
    let url = start_connlib_server(|ws| async move {
        let (mut sink, mut stream) = ws.split();
        let _ = stream.next().await;
        let _ = sink.send(Message::Close(None)).await;
    })
    .await;

    let transport = ConnLibTransport::connect(&url).await.unwrap();
    let mut sub = transport
        .send("ignored", "ping", json!({}), None)
        .await
        .unwrap();

    let result = sub.recv_raw().await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("closed") || err_msg.contains("ConnectionClosed"),
        "unexpected error: {err_msg}"
    );
}

#[tokio::test]
async fn test_connlib_server_error() {
    let url = start_connlib_server(|ws| async move {
        let (_, mut stream) = ws.split();
        let _ = stream.next().await;
        let _ = stream.next().await;
    })
    .await;

    let transport = ConnLibTransport::connect(&url).await.unwrap();
    let mut sub1 = transport
        .send("ignored", "req1", json!({}), None)
        .await
        .unwrap();
    let mut sub2 = transport
        .send("ignored", "req2", json!({}), None)
        .await
        .unwrap();

    let r1 = sub1.recv_raw().await;
    let r2 = sub2.recv_raw().await;
    assert!(r1.is_err(), "expected error for sub1, got: {r1:?}");
    assert!(r2.is_err(), "expected error for sub2, got: {r2:?}");
}
