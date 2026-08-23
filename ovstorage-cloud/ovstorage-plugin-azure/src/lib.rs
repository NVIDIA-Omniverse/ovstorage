// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

mod auth;
mod avro_changefeed;
mod backend;
mod cleartext;
mod client;
mod config;
mod convert;
mod driver;
mod error_body;
mod layer;
mod parse;
mod signing;
mod subscription;

use std::collections::HashMap;

use ovstorage_plugin::{ConfigValue, ConnectionRequest, Result, SecretBundle};

pub use crate::auth::AzureAuth;
pub use crate::backend::AzureBackend;
pub use crate::config::AzureConnectionConfig;
use crate::config::BACKEND_KIND;
pub use crate::layer::AzureLayerFactory;

/// Test-only parser hook; not part of the published surface.
#[doc(hidden)]
pub fn __test_only_parse_config(
    config: &HashMap<String, ConfigValue>,
) -> Result<AzureConnectionConfig> {
    AzureConnectionConfig::from_request(&ConnectionRequest {
        backend_kind: BACKEND_KIND.into(),
        config: config.clone(),
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    })
}

/// Test-only constructor hook; lets integration tests build a backend
/// from a parsed config and an explicit credentials bundle (typically
/// `SecretBundle::default()` for anonymous access against a fake
/// server).
#[doc(hidden)]
pub fn __test_only_with_credentials(
    config: AzureConnectionConfig,
    credentials: SecretBundle,
) -> Result<AzureBackend> {
    let auth = AzureAuth::resolve(&credentials)?;
    AzureBackend::with_auth(config, auth)
}

/// Test-only mutator hook; overrides the data-path base URL so the
/// backend issues requests at a capture-style fake HTTP server
/// instead of `https://<account>.blob.<suffix>/...`. Used by the
/// integration tests in `tests/precondition.rs` to observe headers
/// and query parameters without needing TLS.
///
/// # Errors
///
/// [`ErrorCode::InvalidArgument`] if `base_url` is not an absolute
/// `http`/`https` URL, or carries a query string, fragment or userinfo —
/// the same shapes the public `blob_endpoint` / `dfs_endpoint` keys reject.
/// Reporting that rather than aborting keeps this hook usable from a caller
/// that wants to assert the rejection, and matches the fallible shape of
/// the sibling `__test_only_parse_config`.
#[doc(hidden)]
pub fn __test_only_with_endpoint_override(
    mut config: AzureConnectionConfig,
    base_url: String,
) -> Result<AzureConnectionConfig> {
    // Normalized through the same constructor the supported endpoint keys
    // use, so the hook cannot install a shape those keys would refuse.
    config.test_endpoint_override = Some(crate::config::AzureEndpoint::parse(
        &base_url,
        "__test_endpoint",
    )?);
    Ok(config)
}

ovstorage_plugin::ovstorage_layer_plugin!(backend, AzureLayerFactory::default);

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::BackendFactory;
    use ovstorage_plugin::{
        ConnectionAuthState, ErrorCode, LayerConnectionRequest, Request, SecretBytes, SecretValue,
        address,
    };
    use std::collections::HashMap;

    #[test]
    fn descriptor_reports_native_azure_schema() {
        let descriptor = BackendFactory::descriptor(&AzureLayerFactory::default());
        assert_eq!(descriptor.kind, "azure");
        assert_eq!(descriptor.display_name, "Azure Blob Storage");
        assert!(descriptor.accepts_connections);

        let config_keys = descriptor
            .config_schema
            .iter()
            .map(|field| field.key.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            config_keys,
            [
                "account",
                "container",
                "endpoint_suffix",
                "blob_endpoint",
                "dfs_endpoint",
                "hierarchical_namespace",
                "change_feed_enabled",
                "change_feed_segment_lag_seconds",
                "change_feed_poll_interval_seconds"
            ]
        );

        let credential_keys = descriptor
            .credential_schema
            .iter()
            .map(|field| field.key.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            credential_keys,
            [
                "account_key",
                "sas_token",
                "client_id",
                "client_secret",
                "tenant_id",
                "federated_token_file",
            ]
        );
    }

    async fn layer_with_connection(
        request: ConnectionRequest,
    ) -> Result<(ovstorage_plugin::LayerHandle, ovstorage_plugin::Connection)> {
        let layer = AzureLayerFactory::default()
            .create_backend("azure", &ovstorage_plugin::LayerConfig::new(), None)
            .await?;
        let connection = layer
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "azure".into(),
                    connection: request,
                }),
                None,
            )
            .await?;
        Ok((layer, connection))
    }

    #[tokio::test]
    async fn add_connection_reports_flat_vs_hns_capabilities() {
        let (layer, connection) = layer_with_connection(connection_request(false))
            .await
            .unwrap();
        assert!(matches!(
            connection.auth_state,
            ConnectionAuthState::Anonymous
        ));
        let flat_root = layer
            .root_info_for(
                &address::parse("azure://acct123/assets/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap();
        assert!(!flat_root.capabilities.has_real_directories);
        assert!(flat_root.capabilities.supports_list);
        assert!(flat_root.capabilities.supports_native_metadata_patch);
        assert!(flat_root.capabilities.supports_version_listing);
        assert!(!flat_root.capabilities.supports_server_side_rename);
        assert_eq!(flat_root.root.as_str(), "azure://acct123/assets/");

        let (layer, _) = layer_with_connection(connection_request(true))
            .await
            .unwrap();
        let hns_root = layer
            .root_info_for(
                &address::parse("azure://acct123/assets/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap();
        assert!(hns_root.capabilities.has_real_directories);
        assert!(hns_root.capabilities.supports_list);
        assert!(hns_root.capabilities.supports_server_side_rename);
        assert!(hns_root.capabilities.supports_atomic_rename);
    }

    #[tokio::test]
    async fn add_connection_reports_change_feed_watch_capabilities() {
        let (layer, _) = layer_with_connection(connection_request_with_change_feed(false, true))
            .await
            .unwrap();
        let root = layer
            .root_info_for(
                &address::parse("azure://acct123/assets/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap();
        let caps = &root.capabilities;
        assert!(caps.supports_watch_directory);
        assert!(caps.watch_directory_kinds.created);
        assert!(!caps.watch_directory_kinds.modified);
        assert!(caps.watch_directory_kinds.deleted);
        assert!(caps.watch_directory_kinds.metadata_changed);
        assert!(!caps.watch_directory_resumable);
        assert_eq!(
            caps.watch_directory_max_lag,
            Some(std::time::Duration::from_secs(120))
        );

        let (layer, _) = layer_with_connection(connection_request_with_change_feed(true, true))
            .await
            .unwrap();
        let hns_root = layer
            .root_info_for(
                &address::parse("azure://acct123/assets/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap();
        assert!(!hns_root.capabilities.supports_watch_directory);
    }

    #[tokio::test]
    async fn invalid_config_is_rejected_deterministically() {
        let mut request = connection_request(false);
        request
            .config
            .insert("root".into(), ConfigValue::String("unused".into()));
        let error = match layer_with_connection(request).await {
            Ok(_) => panic!("expected unknown-config rejection"),
            Err(err) => err,
        };
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.message().contains("root"));

        let mut request = connection_request(false);
        request
            .config
            .insert("account".into(), ConfigValue::String("Upper".into()));
        let error = match layer_with_connection(request).await {
            Ok(_) => panic!("expected uppercase-account rejection"),
            Err(err) => err,
        };
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.message().contains("account"));
    }

    #[tokio::test]
    async fn hidden_change_feed_endpoint_override_is_loopback_only() {
        let mut request = connection_request_with_change_feed(false, true);
        request.config.insert(
            "__test_change_feed_endpoint".into(),
            ConfigValue::String("https://storage.invalid.example".into()),
        );
        let err = match layer_with_connection(request.clone()).await {
            Ok(_) => panic!("expected non-loopback endpoint rejection"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("loopback"));

        request.config.insert(
            "__test_change_feed_endpoint".into(),
            ConfigValue::String("http://127.0.0.1:10000".into()),
        );
        layer_with_connection(request.clone())
            .await
            .expect("loopback test endpoint should be accepted");

        request.credentials.fields.insert(
            "sas_token".into(),
            SecretValue::Bytes(SecretBytes(b"sig=fake".to_vec())),
        );
        let err = match layer_with_connection(request).await {
            Ok(_) => panic!("expected credential-bearing test endpoint rejection"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("anonymous"));
    }

    /// The data-path override mirrors the change-feed override's loopback
    /// guard, and additionally admits ONLY the `account_key` credential shape
    /// (SharedKey signs an HMAC; SAS/OAuth secrets are bearer-style and would
    /// travel to the endpoint verbatim). Pin both refusal branches — this is
    /// the guard that keeps a credential from leaking to a test endpoint.
    #[tokio::test]
    async fn hidden_data_endpoint_override_is_loopback_and_shared_key_only() {
        // (a) non-loopback endpoint → rejected.
        let mut request = connection_request(false);
        request.config.insert(
            "__test_endpoint".into(),
            ConfigValue::String("https://storage.invalid.example".into()),
        );
        let err = match layer_with_connection(request.clone()).await {
            Ok(_) => panic!("expected non-loopback endpoint rejection"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("loopback"));

        // (b) loopback + bearer-style credential (SAS) → rejected (the
        // bearer-leak guard).
        request.config.insert(
            "__test_endpoint".into(),
            ConfigValue::String("http://127.0.0.1:1".into()),
        );
        request.credentials.fields.insert(
            "sas_token".into(),
            SecretValue::Bytes(SecretBytes(b"sig=fake".to_vec())),
        );
        let err = match layer_with_connection(request.clone()).await {
            Ok(_) => panic!("expected bearer-credential test endpoint rejection"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("Shared Key"));

        // (c) loopback + account_key → accepted (HMAC signature only; the
        // unroutable endpoint makes the lenient verify pass without I/O).
        request.credentials.fields.clear();
        use base64::Engine as _;
        let key =
            base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef0123456789abcdef");
        request.credentials.fields.insert(
            "account_key".into(),
            SecretValue::Bytes(SecretBytes(key.into_bytes())),
        );
        layer_with_connection(request.clone())
            .await
            .expect("loopback Shared Key test endpoint should be accepted");

        // (d) loopback anonymous → accepted.
        request.credentials.fields.clear();
        layer_with_connection(request)
            .await
            .expect("loopback anonymous test endpoint should be accepted");
    }

    #[test]
    fn azure_address_parser_extracts_account_container_key() {
        // url::Url normalizes RFC 3986 dot-segments, so `a//../b.txt` canonicalizes to `a/b.txt` before parsing.
        let address =
            ovstorage_plugin::address::parse("azure://acct123/assets/a//../b.txt?versionid=7")
                .unwrap();
        let parsed = config::AzureAddress::parse(&address).unwrap();
        assert_eq!(parsed.account, "acct123");
        assert_eq!(parsed.container, "assets");
        assert_eq!(parsed.key, "a/b.txt");
    }

    fn connection_request(hierarchical_namespace: bool) -> ConnectionRequest {
        connection_request_with_change_feed(hierarchical_namespace, false)
    }

    fn connection_request_with_change_feed(
        hierarchical_namespace: bool,
        change_feed_enabled: bool,
    ) -> ConnectionRequest {
        let mut config = HashMap::new();
        config.insert("account".into(), ConfigValue::String("acct123".into()));
        config.insert("container".into(), ConfigValue::String("assets".into()));
        config.insert(
            "hierarchical_namespace".into(),
            ConfigValue::Bool(hierarchical_namespace),
        );
        config.insert(
            "change_feed_enabled".into(),
            ConfigValue::Bool(change_feed_enabled),
        );
        ConnectionRequest {
            backend_kind: "azure".into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        }
    }
}
