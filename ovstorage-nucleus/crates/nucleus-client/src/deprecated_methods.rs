// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Helpers for deprecated Nucleus IDL methods that have no non-deprecated replacement:
// - `create` with `type=Channel`: create_asset/object/directory are hardcoded per
//   path type and reject PathTypeCode; only deprecated `create` makes Channels.
// - `read` for channel subscriptions: only the `read` code path handles the
//   Nucleus channel protocol; subscribe_read_* hits the wrong server handler.
// - `update` for channel messaging: update_object requires an object_id that
//   channels lack; update_asset is asset-only.
// - `delete` recursive: delete2 only works on empty folders.
//
// These bypass the type-safe generated API via Transport::send and MUST track
// the IDL. Return types are still codegen-emitted (type gen ignores deprecation).

use anyhow::{Context, Result};
use nucleus_transport::{Subscription, Transport};

use crate::types::{DeletedPath, StatusType, UploadResult};

/// Create a path with an optional PathTypeCode (only path that creates Channels).
pub async fn create(
    client: &impl Transport,
    uri: &str,
    content: Option<Vec<u8>>,
    path_type: Option<u32>,
) -> Result<UploadResult> {
    tracing::debug!(uri = %uri, path_type = ?path_type, "deprecated create");
    let mut params = serde_json::json!({ "uri": uri });
    if let Some(pt) = path_type {
        params["type"] = serde_json::json!(pt);
    }
    let mut sub = client.send("Connection", "create", params, content).await?;
    let (result, _) = sub.recv::<UploadResult>().await?;
    Ok(result)
}

/// Subscribe to a path and stream ReadResults (only path for channel subscriptions).
pub async fn read(client: &impl Transport, uri: &str) -> Result<Subscription> {
    tracing::debug!(uri = %uri, "deprecated read");
    let params = serde_json::json!({ "uri": uri });
    client.send("Connection", "read", params, None).await
}

/// Write content to a path (only path for channel messaging).
pub async fn update(
    client: &impl Transport,
    uri: &str,
    content: Option<Vec<u8>>,
) -> Result<UploadResult> {
    tracing::debug!(uri = %uri, content_len = content.as_ref().map(|c| c.len()), "deprecated update");
    let params = serde_json::json!({ "uri": uri });
    let mut sub = client.send("Connection", "update", params, content).await?;
    let (result, _) = sub.recv::<UploadResult>().await?;
    Ok(result)
}

/// Recursively delete a path (delete2 only handles empty folders).
pub async fn delete(client: &impl Transport, uri: &str) -> Result<Vec<DeletedPath>> {
    tracing::debug!(uri = %uri, "deprecated delete");
    let params = serde_json::json!({ "uri": uri });
    let mut sub = client.send("Connection", "delete", params, None).await?;
    let mut results = Vec::new();
    loop {
        match sub.recv::<DeletedPath>().await {
            Ok((path, _)) => {
                if matches!(path.status, StatusType::Done) {
                    return Ok(results);
                }
                results.push(path);
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "delete({uri}) stream ended after {} paths without StatusType::Done",
                        results.len()
                    )
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_transport::{RawResponse, Subscription, Transport};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use tokio::sync::mpsc;

    struct MockTransport {
        responses: std::sync::Mutex<Option<Vec<Result<RawResponse>>>>,
    }

    impl MockTransport {
        fn new(responses: Vec<Result<RawResponse>>) -> Self {
            Self {
                responses: std::sync::Mutex::new(Some(responses)),
            }
        }
    }

    impl Transport for MockTransport {
        async fn send(
            &self,
            _interface: &str,
            _method: &str,
            _params: serde_json::Value,
            _binary: Option<Vec<u8>>,
        ) -> Result<Subscription> {
            let responses = self
                .responses
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| anyhow::anyhow!("MockTransport::send called twice"))?;
            let (tx, rx) = mpsc::channel(responses.len().max(1));
            for r in responses {
                tx.send(r).await.unwrap();
            }
            drop(tx);
            let (stop_tx, _stop_rx) = mpsc::channel(4);
            let finished = Arc::new(AtomicBool::new(false));
            Ok(Subscription::new(rx, 1, stop_tx, finished))
        }
    }

    fn raw(json: &str) -> Result<RawResponse> {
        Ok(RawResponse {
            json: json.as_bytes().to_vec(),
            blob: None,
        })
    }

    #[tokio::test]
    async fn delete_returns_ok_when_done_terminator_received() {
        let transport = MockTransport::new(vec![
            raw(r#"{"uri":"/a","status":"OK"}"#),
            raw(r#"{"uri":"/b","status":"OK"}"#),
            raw(r#"{"status":"DONE"}"#),
        ]);
        let result = delete(&transport, "/foo").await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].uri.as_deref(), Some("/a"));
        assert_eq!(result[1].uri.as_deref(), Some("/b"));
    }

    #[tokio::test]
    async fn delete_returns_err_when_stream_closes_before_done() {
        let transport = MockTransport::new(vec![raw(r#"{"uri":"/a","status":"OK"}"#)]);
        let err = delete(&transport, "/foo").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("delete(/foo)"), "missing context: {msg}");
        assert!(msg.contains("after 1 paths"), "missing count: {msg}");
    }

    #[tokio::test]
    async fn delete_returns_err_on_malformed_json() {
        let transport = MockTransport::new(vec![raw("{not-json")]);
        let err = delete(&transport, "/foo").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("delete(/foo)"), "missing context: {msg}");
        assert!(msg.contains("after 0 paths"), "missing count: {msg}");
    }

    #[tokio::test]
    async fn delete_returns_err_on_transport_error_before_done() {
        let transport = MockTransport::new(vec![
            raw(r#"{"uri":"/a","status":"OK"}"#),
            Err(anyhow::anyhow!("connection lost")),
        ]);
        let err = delete(&transport, "/foo").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("delete(/foo)"), "missing context: {msg}");
        assert!(msg.contains("connection lost"), "missing root cause: {msg}");
    }
}
