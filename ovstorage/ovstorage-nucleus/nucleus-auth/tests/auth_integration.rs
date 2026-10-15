// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use nucleus_auth::AuthClient;
use nucleus_auth::generated::{Credentials, Profiles, Tokens, credentials as cred_meta};
use nucleus_auth::types::AuthStatus;
use nucleus_discovery::DiscoveryClient;
use nucleus_discovery::generated::DiscoverySearch;

fn nucleus_host() -> String {
    std::env::var("NUCLEUS_HOSTS")
        .unwrap_or_else(|_| "localhost:3333".to_string())
        .split(',')
        .next()
        .unwrap_or("localhost:3333")
        .trim()
        .to_string()
}

fn test_username() -> String {
    std::env::var("NUCLEUS_USERNAME").unwrap_or_else(|_| "omniverse".to_string())
}

fn test_password() -> String {
    std::env::var("NUCLEUS_PASSWORD").unwrap_or_else(|_| "omniverse".to_string())
}

async fn discover_auth_url(host: &str) -> String {
    let discovery_url = nucleus_discovery::discovery_url(host);
    let discovery = DiscoveryClient::connect(&discovery_url)
        .await
        .unwrap_or_else(|e| panic!("Failed to connect to discovery at {discovery_url}: {e:#}"));

    let transports = nucleus_discovery::supported_transports::<AuthClient>();
    let query = nucleus_discovery::make_query(
        cred_meta::ORIGIN,
        cred_meta::INTERFACE,
        Some(cred_meta::capabilities()),
        Some("external"),
        &transports,
    );
    let result = discovery.find(query).await.expect("Discovery query failed");

    assert!(result.found, "Discovery did not find the auth endpoint");

    let transport = result
        .transport
        .as_ref()
        .expect("No transport in discovery result");
    nucleus_discovery::url_from_transport(transport)
        .expect("Could not build auth URL from transport params")
}

async fn connect_auth() -> AuthClient {
    let host = nucleus_host();
    let auth_url = discover_auth_url(&host).await;
    AuthClient::connect(&auth_url)
        .await
        .unwrap_or_else(|e| panic!("Failed to connect to auth at {auth_url}: {e:#}"))
}

// ============================================================================
// Credentials
// ============================================================================

#[tokio::test]
#[ignore = "requires NUCLEUS_HOSTS"]
async fn test_auth_valid_credentials() {
    let client = connect_auth().await;
    let result = Credentials::auth(&client, test_username(), test_password(), None, None)
        .await
        .expect("Credentials::auth failed");

    assert_eq!(result.status, AuthStatus::OK);
    assert!(
        result.access_token.as_ref().is_some_and(|t| !t.is_empty()),
        "Expected a non-empty access token"
    );
}

#[tokio::test]
#[ignore = "requires NUCLEUS_HOSTS"]
async fn test_auth_invalid_credentials() {
    let client = connect_auth().await;
    let result = Credentials::auth(
        &client,
        test_username(),
        "wrong_password_that_should_never_match".to_string(),
        None,
        None,
    )
    .await
    .expect("Credentials::auth call failed");

    assert_ne!(result.status, AuthStatus::OK);
}

// ============================================================================
// Tokens
// ============================================================================

#[tokio::test]
#[ignore = "requires NUCLEUS_HOSTS"]
async fn test_refresh_token() {
    let client = connect_auth().await;

    let auth_result = Credentials::auth(&client, test_username(), test_password(), None, None)
        .await
        .expect("Credentials::auth failed");
    assert_eq!(auth_result.status, AuthStatus::OK);

    let refresh_token = auth_result
        .refresh_token
        .expect("No refresh token in auth response");

    let refresh_result = client
        .refresh(refresh_token, None)
        .await
        .expect("Tokens::refresh failed");

    assert_eq!(refresh_result.status, AuthStatus::OK);
    assert!(
        refresh_result
            .access_token
            .as_ref()
            .is_some_and(|t| !t.is_empty()),
        "Expected a non-empty access token after refresh"
    );
}

#[tokio::test]
#[ignore = "requires NUCLEUS_HOSTS"]
async fn test_subscribe_returns_subscribed() {
    let client = connect_auth().await;
    let mut sub = client.subscribe().await.expect("Tokens::subscribe failed");

    let (first, _): (nucleus_auth::types::Auth, _) = sub
        .recv()
        .await
        .expect("Failed to receive subscribe response");

    assert_eq!(first.status, AuthStatus::Subscribed);
    assert!(
        first.nonce.as_ref().is_some_and(|n| !n.is_empty()),
        "Expected a non-empty nonce in subscribe response"
    );
}

// ============================================================================
// Profiles
// ============================================================================

#[tokio::test]
#[ignore = "requires NUCLEUS_HOSTS"]
async fn test_get_profile() {
    let client = connect_auth().await;

    let auth_result = Credentials::auth(&client, test_username(), test_password(), None, None)
        .await
        .expect("Credentials::auth failed");
    assert_eq!(auth_result.status, AuthStatus::OK);

    let result = Profiles::get(&client, test_username())
        .await
        .expect("Profiles::get failed");

    assert_eq!(result.status, AuthStatus::OK);
}
