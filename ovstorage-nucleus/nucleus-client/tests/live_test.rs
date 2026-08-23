// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use nucleus_client::types::StatusType;
use nucleus_client::{Connection, NucleusClient};

fn nucleus_url() -> Option<String> {
    let hosts = std::env::var("NUCLEUS_HOSTS").ok()?;
    let first = hosts.split(',').next()?.trim();
    let (host, port) = first.rsplit_once(':').unwrap_or((first, "3333"));
    Some(format!("ws://{}:{}", host, port))
}

#[tokio::test]
#[ignore = "requires NUCLEUS_HOSTS"]
async fn test_connect_and_auth() {
    let url = nucleus_url().expect("NUCLEUS_HOSTS must be set");
    let username = std::env::var("NUCLEUS_USERNAME").unwrap_or_else(|_| "omniverse".to_string());
    let password = std::env::var("NUCLEUS_PASSWORD").unwrap_or_else(|_| "omniverse".to_string());

    let client = NucleusClient::connect(&url)
        .await
        .expect("failed to connect");
    let auth = client
        .auth(
            nucleus_client::types::VERSION.into(),
            None,
            Some(username),
            Some(password),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("failed to auth");
    assert!(!auth.username.is_empty());
}

#[tokio::test]
#[ignore = "requires NUCLEUS_HOSTS"]
async fn test_stat_and_list() {
    let url = nucleus_url().expect("NUCLEUS_HOSTS must be set");
    let username = std::env::var("NUCLEUS_USERNAME").unwrap_or_else(|_| "omniverse".to_string());
    let password = std::env::var("NUCLEUS_PASSWORD").unwrap_or_else(|_| "omniverse".to_string());

    let client = NucleusClient::connect(&url)
        .await
        .expect("failed to connect");
    client
        .auth(
            nucleus_client::types::VERSION.into(),
            None,
            Some(username),
            Some(password),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("failed to auth");

    let mut sub = client
        .list2("/".into(), None, None, None)
        .await
        .expect("failed to list root");
    let (result, _): (nucleus_client::types::List2Response, _) =
        sub.recv().await.expect("failed to recv list response");
    assert_eq!(result.status, StatusType::OK);
}

#[tokio::test]
#[ignore = "requires NUCLEUS_HOSTS"]
async fn test_write_and_read_roundtrip() {
    use nucleus_client::types::{PathAtBranch, PathAtVersion, ReadAssetVersionResult};

    let url = nucleus_url().expect("NUCLEUS_HOSTS must be set");
    let username = std::env::var("NUCLEUS_USERNAME").unwrap_or_else(|_| "omniverse".to_string());
    let password = std::env::var("NUCLEUS_PASSWORD").unwrap_or_else(|_| "omniverse".to_string());

    let client = NucleusClient::connect(&url)
        .await
        .expect("failed to connect");
    client
        .auth(
            nucleus_client::types::VERSION.into(),
            None,
            Some(username),
            Some(password),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("failed to auth");

    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = format!("/Tests/live_test_roundtrip_{pid}_{nanos}.txt");
    let content = b"hello from live test";

    let inner: anyhow::Result<()> = async {
        let write_result = client
            .create_asset(
                PathAtBranch {
                    path: path.clone(),
                    branch: None,
                },
                Some(content.to_vec()),
                None,
                Some(true),
                None,
            )
            .await?;
        if write_result.status != StatusType::OK {
            anyhow::bail!("create_asset returned {:?}", write_result.status);
        }

        let mut sub = client
            .read_asset_version(
                PathAtVersion {
                    path: path.clone(),
                    branch: None,
                    checkpoint: None,
                },
                None,
            )
            .await?;
        let (result, blob): (ReadAssetVersionResult, _) = sub.recv().await?;
        if result.status != StatusType::OK {
            anyhow::bail!("read_asset_version returned {:?}", result.status);
        }
        if result.uri_redirection.is_none() {
            let data = blob.unwrap_or_default();
            if data != content {
                anyhow::bail!("payload mismatch");
            }
        }
        Ok(())
    }
    .await;

    let _ = client
        .delete2(vec![PathAtVersion {
            path: path.clone(),
            branch: None,
            checkpoint: None,
        }])
        .await;

    inner.expect("roundtrip failed");
}
