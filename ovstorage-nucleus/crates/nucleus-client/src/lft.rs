// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use anyhow::{Result, bail};

const LFT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const LFT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const LFT_ERROR_BODY_MAX_BYTES: usize = 4096;

/// Parse an LFT generate-content-id response into `(numeric, string)`.
pub(crate) fn parse_generate_response(body: &serde_json::Value) -> Result<(u64, String)> {
    let content_id_str = body
        .get("content_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            tracing::warn!("LFT response missing content_id");
            anyhow::anyhow!("LFT response missing content_id")
        })?;

    let content_id = match body.get("content_id_numeric").and_then(|v| v.as_u64()) {
        Some(n) => n,
        None => content_id_str.parse::<u64>().map_err(|e| {
            anyhow::anyhow!(
                "LFT content_id {content_id_str:?} is not numeric and content_id_numeric is missing: {e}"
            )
        })?,
    };

    Ok((content_id, content_id_str))
}

#[derive(Debug)]
pub struct LftUploadInfo {
    pub content_id: u64,
    pub content_id_str: String,
    pub upload_url: String,
    pub headers: Vec<(String, String)>,
}

pub struct LftClient {
    lft_address: String,
    pub threshold: u64,
    connection_id: String,
    connection_id_signature: Option<String>,
    /// Connlib session token; sent as `Authorization-Token`.
    connlib_token: Option<String>,
    /// JWT access token; sent as `Authorization: Bearer`.
    access_token: Option<String>,
    username: Option<String>,
    /// Server-advertised multipart part size (`Auth.multipart_chunk_size`).
    /// Sent verbatim as the `Multipart-Chunk-Size` header on every part PUT;
    /// the server divides `Content-Start` by this to derive the part number.
    multipart_chunk_size: u64,
    http: reqwest::Client,
}

impl LftClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lft_address: String,
        threshold: u64,
        connection_id: String,
        connection_id_signature: Option<String>,
        connlib_token: Option<String>,
        access_token: Option<String>,
        username: Option<String>,
        multipart_chunk_size: u64,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(LFT_CONNECT_TIMEOUT)
            .timeout(LFT_REQUEST_TIMEOUT)
            .build()
            .map_err(|err| {
                anyhow::anyhow!("failed to build LFT reqwest::Client (TLS init): {err}")
            })?;
        Ok(Self::with_client(
            lft_address,
            threshold,
            connection_id,
            connection_id_signature,
            connlib_token,
            access_token,
            username,
            multipart_chunk_size,
            http,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_client(
        lft_address: String,
        threshold: u64,
        connection_id: String,
        connection_id_signature: Option<String>,
        connlib_token: Option<String>,
        access_token: Option<String>,
        username: Option<String>,
        multipart_chunk_size: u64,
        http: reqwest::Client,
    ) -> Self {
        Self {
            lft_address,
            threshold,
            connection_id,
            connection_id_signature,
            connlib_token,
            access_token,
            username,
            multipart_chunk_size,
            http,
        }
    }

    pub fn should_use_lft(&self, size: u64) -> bool {
        self.threshold > 0 && size > self.threshold
    }

    /// Server-advertised multipart part size, used to compute part count and
    /// fill the `Multipart-Chunk-Size` header.
    pub fn chunk_size(&self) -> u64 {
        self.multipart_chunk_size
    }

    /// Build the per-part header set for one LFT PUT in a multipart upload.
    /// All parts share `Content-ID` + `Multipart-Chunk-Size`; only `Content-Start`
    /// changes per part. Server derives part number as
    /// `Content-Start / Multipart-Chunk-Size + 1`.
    pub fn part_headers(
        &self,
        content_id_str: &str,
        content_id_numeric: u64,
        byte_offset: u64,
        omniverse_path: &str,
    ) -> Vec<(String, String)> {
        let mut headers = self.auth_headers();
        headers.push(("Content-ID".into(), content_id_str.to_string()));
        headers.push(("Content-Start".into(), byte_offset.to_string()));
        headers.push((
            "Multipart-Chunk-Size".into(),
            self.multipart_chunk_size.to_string(),
        ));
        headers.push(("X-OV-URI".into(), omniverse_path.to_string()));
        if content_id_numeric > 0 {
            headers.push(("Content-ID-Numeric".into(), content_id_numeric.to_string()));
        }
        headers
    }

    pub fn auth_headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![("X-OV-Connection-ID".into(), self.connection_id.clone())];
        if let Some(ref token) = self.connlib_token {
            headers.push(("Authorization-Token".into(), token.clone()));
        }
        if let Some(ref token) = self.access_token {
            headers.push(("Authorization".into(), format!("Bearer {token}")));
        }
        if let Some(ref sig) = self.connection_id_signature {
            headers.push(("Connection-Token".into(), self.connection_id.clone()));
            headers.push(("Connection-Signature".into(), sig.clone()));
        }
        if let Some(ref user) = self.username {
            headers.push(("X-OV-Username".into(), user.clone()));
        }
        headers
    }

    fn apply_headers(
        req: reqwest::RequestBuilder,
        headers: &[(String, String)],
    ) -> reqwest::RequestBuilder {
        let mut req = req;
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        req
    }

    /// Generate a content ID and return the upload URL + headers for a PUT.
    pub async fn generate_upload(&self, path: &str) -> Result<LftUploadInfo> {
        tracing::debug!(
            path,
            redirect.kind = "lft_upload",
            "LFT generate content ID request"
        );

        let url = format!("{}/content/", self.lft_address);

        let body = serde_json::json!({"path": path});
        let generate_req = self.http.post(&url).header("X-OV-URI", path).json(&body);
        let generate_req = Self::apply_headers(generate_req, &self.auth_headers());

        let resp = generate_req.send().await.map_err(|e| {
            tracing::warn!(error = %e, "LFT generate content ID request failed");
            anyhow::anyhow!("LFT generate content ID request failed: {e:#}")
        })?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body_bytes = resp.bytes().await.unwrap_or_default();
            let total_len = body_bytes.len();
            let truncated = total_len > LFT_ERROR_BODY_MAX_BYTES;
            let snippet_bytes = if truncated {
                &body_bytes[..LFT_ERROR_BODY_MAX_BYTES]
            } else {
                &body_bytes[..]
            };
            let snippet = String::from_utf8_lossy(snippet_bytes);
            tracing::warn!(
                status = %status,
                body_bytes = total_len,
                truncated = truncated,
                "LFT generate content ID request failed"
            );
            if truncated {
                bail!(
                    "LFT generate content ID returned HTTP {status} (body truncated to {} bytes of {}): {snippet}",
                    LFT_ERROR_BODY_MAX_BYTES,
                    total_len
                );
            }
            bail!("LFT generate content ID returned HTTP {status}: {snippet}");
        }
        let body: serde_json::Value = resp.json().await?;

        let (content_id, content_id_str) = parse_generate_response(&body)?;
        let upload_url = format!("{}/content/", self.lft_address);
        tracing::debug!(content_id, redirect.kind = "lft_upload", redirect.target = %upload_url, "LFT content ID issued");

        let mut headers = self.auth_headers();
        headers.push(("Content-ID".into(), content_id_str.clone()));
        headers.push(("Content-Start".into(), "0".into()));
        headers.push(("X-OV-URI".into(), path.to_string()));
        if content_id > 0 {
            headers.push(("Content-ID-Numeric".into(), content_id.to_string()));
        }

        Ok(LftUploadInfo {
            content_id,
            content_id_str,
            upload_url,
            headers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CHUNK: u64 = 5 * 1024 * 1024;

    fn make_client(threshold: u64) -> LftClient {
        LftClient::new(
            "http://localhost".into(),
            threshold,
            "conn-id".into(),
            None,
            None,
            None,
            None,
            TEST_CHUNK,
        )
        .unwrap()
    }

    #[test]
    fn should_use_lft_zero_threshold_returns_false() {
        let client = make_client(0);
        assert!(!client.should_use_lft(500));
    }

    #[test]
    fn should_use_lft_size_below_threshold_returns_false() {
        let client = make_client(1000);
        assert!(!client.should_use_lft(500));
    }

    #[test]
    fn should_use_lft_size_above_threshold_returns_true() {
        let client = make_client(1000);
        assert!(client.should_use_lft(1500));
    }

    #[test]
    fn should_use_lft_size_equal_threshold_returns_false() {
        let client = make_client(1000);
        assert!(!client.should_use_lft(1000));
    }

    #[test]
    fn should_use_lft_zero_size_returns_false() {
        let client = make_client(1000);
        assert!(!client.should_use_lft(0));
    }

    #[test]
    fn chunk_size_returns_configured_value() {
        let client = make_client(0);
        assert_eq!(client.chunk_size(), TEST_CHUNK);
    }

    #[test]
    fn part_headers_carry_offset_and_chunk_size() {
        let client = make_client(0);
        let headers = client.part_headers("cid-99", 99, 5 * 1024 * 1024, "/some/path");
        let lookup = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(lookup("Content-ID"), Some("cid-99"));
        assert_eq!(lookup("Content-Start"), Some("5242880"));
        assert_eq!(
            lookup("Multipart-Chunk-Size"),
            Some(TEST_CHUNK.to_string().as_str())
        );
        assert_eq!(lookup("X-OV-URI"), Some("/some/path"));
        assert_eq!(lookup("Content-ID-Numeric"), Some("99"));
        assert_eq!(lookup("X-OV-Connection-ID"), Some("conn-id"));
    }

    #[test]
    fn part_headers_omits_numeric_id_when_zero() {
        let client = make_client(0);
        let headers = client.part_headers("opaque-cid", 0, 0, "/path");
        assert!(headers.iter().all(|(k, _)| k != "Content-ID-Numeric"));
    }

    #[test]
    fn auth_headers_minimal() {
        let client = make_client(0);
        let headers = client.auth_headers();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "X-OV-Connection-ID");
        assert_eq!(headers[0].1, "conn-id");
    }

    #[test]
    fn auth_headers_with_connlib_token() {
        let client = LftClient::new(
            "http://localhost".into(),
            0,
            "conn-id".into(),
            None,
            Some("tok123".into()),
            None,
            None,
            TEST_CHUNK,
        )
        .unwrap();
        let headers = client.auth_headers();
        let auth_token = headers.iter().find(|(k, _)| k == "Authorization-Token");
        assert!(auth_token.is_some());
        assert_eq!(auth_token.unwrap().1, "tok123");
    }

    #[test]
    fn auth_headers_with_access_token() {
        let client = LftClient::new(
            "http://localhost".into(),
            0,
            "conn-id".into(),
            None,
            None,
            Some("bearer-tok".into()),
            None,
            TEST_CHUNK,
        )
        .unwrap();
        let headers = client.auth_headers();
        let auth = headers.iter().find(|(k, _)| k == "Authorization");
        assert!(auth.is_some());
        assert_eq!(auth.unwrap().1, "Bearer bearer-tok");
    }

    #[test]
    fn auth_headers_with_connection_signature() {
        let client = LftClient::new(
            "http://localhost".into(),
            0,
            "conn-id".into(),
            Some("sig-abc".into()),
            None,
            None,
            None,
            TEST_CHUNK,
        )
        .unwrap();
        let headers = client.auth_headers();
        let conn_token = headers.iter().find(|(k, _)| k == "Connection-Token");
        let conn_sig = headers.iter().find(|(k, _)| k == "Connection-Signature");
        assert!(conn_token.is_some());
        assert_eq!(conn_token.unwrap().1, "conn-id");
        assert!(conn_sig.is_some());
        assert_eq!(conn_sig.unwrap().1, "sig-abc");
    }

    #[test]
    fn auth_headers_with_username() {
        let client = LftClient::new(
            "http://localhost".into(),
            0,
            "conn-id".into(),
            None,
            None,
            None,
            Some("testuser".into()),
            TEST_CHUNK,
        )
        .unwrap();
        let headers = client.auth_headers();
        let user = headers.iter().find(|(k, _)| k == "X-OV-Username");
        assert!(user.is_some());
        assert_eq!(user.unwrap().1, "testuser");
    }

    #[test]
    fn auth_headers_all_fields() {
        let client = LftClient::new(
            "http://localhost".into(),
            0,
            "conn-id".into(),
            Some("sig".into()),
            Some("connlib-tok".into()),
            Some("access-tok".into()),
            Some("user".into()),
            TEST_CHUNK,
        )
        .unwrap();
        let headers = client.auth_headers();
        assert!(headers.iter().any(|(k, _)| k == "X-OV-Connection-ID"));
        assert!(headers.iter().any(|(k, _)| k == "Authorization-Token"));
        assert!(headers.iter().any(|(k, _)| k == "Authorization"));
        assert!(headers.iter().any(|(k, _)| k == "Connection-Token"));
        assert!(headers.iter().any(|(k, _)| k == "Connection-Signature"));
        assert!(headers.iter().any(|(k, _)| k == "X-OV-Username"));
    }

    #[test]
    fn parse_generate_response_both_fields() {
        let body = serde_json::json!({
            "content_id": "99999",
            "content_id_numeric": 42
        });
        let (numeric, string) = parse_generate_response(&body).unwrap();
        assert_eq!(numeric, 42);
        assert_eq!(string, "99999");
    }

    #[test]
    fn parse_generate_response_string_only() {
        let body = serde_json::json!({
            "content_id": "12345"
        });
        let (numeric, string) = parse_generate_response(&body).unwrap();
        assert_eq!(numeric, 12345);
        assert_eq!(string, "12345");
    }

    #[test]
    fn parse_generate_response_missing() {
        let body = serde_json::json!({});
        assert!(parse_generate_response(&body).is_err());
    }

    #[test]
    fn parse_generate_response_non_numeric_string_no_numeric_field_errors() {
        let body = serde_json::json!({
            "content_id": "opaque-abc-not-numeric"
        });
        let err = parse_generate_response(&body).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("opaque-abc-not-numeric"), "missing id: {msg}");
        assert!(
            msg.contains("content_id_numeric is missing"),
            "missing reason: {msg}"
        );
    }

    #[test]
    fn parse_generate_response_string_overflow_no_numeric_field_errors() {
        let body = serde_json::json!({
            "content_id": "99999999999999999999999999"
        });
        assert!(parse_generate_response(&body).is_err());
    }

    #[test]
    fn parse_generate_response_numeric_field_overrides_string() {
        let body = serde_json::json!({
            "content_id": "abc-not-numeric",
            "content_id_numeric": 7
        });
        let (numeric, string) = parse_generate_response(&body).unwrap();
        assert_eq!(numeric, 7);
        assert_eq!(string, "abc-not-numeric");
    }

    #[tokio::test]
    async fn generate_upload_truncates_large_error_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body: String = "x".repeat(10 * 1024);
                let resp = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let client = LftClient::with_client(
            format!("http://{addr}"),
            0,
            "conn".into(),
            None,
            None,
            None,
            None,
            TEST_CHUNK,
            http,
        );
        let err = client.generate_upload("/foo").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("HTTP 500"), "missing status: {msg}");
        assert!(
            msg.contains("body truncated"),
            "no truncation marker: {msg}"
        );
        let x_count = msg.chars().filter(|c| *c == 'x').count();
        assert!(
            x_count <= LFT_ERROR_BODY_MAX_BYTES,
            "snippet exceeds cap: {x_count} > {LFT_ERROR_BODY_MAX_BYTES}"
        );
    }

    #[tokio::test]
    async fn generate_upload_request_timeout_fires() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _kept = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(60)).await;
        });

        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        let client = LftClient::with_client(
            format!("http://{addr}"),
            0,
            "conn".into(),
            None,
            None,
            None,
            None,
            TEST_CHUNK,
            http,
        );
        let start = std::time::Instant::now();
        let err = client.generate_upload("/foo").await.unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "timeout did not fire: {elapsed:?}"
        );
        let msg = format!("{err:#}");
        assert!(
            msg.contains("LFT generate content ID"),
            "missing op context: {msg}"
        );
    }
}
