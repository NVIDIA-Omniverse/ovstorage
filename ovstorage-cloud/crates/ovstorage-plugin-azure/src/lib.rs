// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

mod auth;
mod avro_changefeed;
mod backend;
mod client;
mod config;
mod convert;
mod parse;
mod signing;
mod subscription;

use std::sync::Arc;

use ovstorage_plugin::shim;
use ovstorage_plugin::{
    AddressRoot, AddressVisibility, BackendId, CancellationToken, ConfigLayer, ConnectionAuthState,
    ConnectionRequest, Result, RouteSource, SecretBundle, StorageBackendKindDescriptor,
    UserMetadata, race_cancel,
};

pub use crate::auth::AzureAuth;
pub use crate::backend::AzureBackend;
pub use crate::config::AzureConnectionConfig;
use crate::config::{BACKEND_KIND, azure_config_schema, azure_credential_schema};
use std::collections::HashMap;

use ovstorage_plugin::ConfigValue;

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
#[doc(hidden)]
pub fn __test_only_with_endpoint_override(
    mut config: AzureConnectionConfig,
    base_url: String,
) -> AzureConnectionConfig {
    config.test_endpoint_override = Some(base_url);
    config
}

pub struct AzureBackendFactory;

impl AzureBackendFactory {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AzureBackendFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl shim::Factory for AzureBackendFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: BACKEND_KIND.into(),
            display_name: "Azure Blob Storage".into(),
            description: Some(
                "Native Azure Blob Storage and ADLS Gen2 backend with Shared Key signing, Service SAS redirects, Entra OAuth2 token caching, and staged-commit block uploads"
                    .into(),
            ),
            config_schema: azure_config_schema(),
            credential_schema: azure_credential_schema(),
            credential_methods: config::azure_credential_methods(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        race_cancel(cancel.as_ref(), async move {
            let config = AzureConnectionConfig::from_request(request)?;
            let auth = AzureAuth::resolve(&request.credentials)?;
            let backend = AzureBackend::new(config.clone(), auth)?;
            let backend = Arc::new(backend);
            let capabilities = backend.capabilities();
            let address_root = config.address_root.clone();
            let display_name = request.display_name.clone().or_else(|| {
                Some(format!(
                    "Azure Blob Storage {}/{}",
                    config.account, config.container
                ))
            });
            let backend_id = BackendId(format!(
                "azure:{}:{}/{}",
                config.endpoint_suffix, config.account, config.container
            ));
            Ok(shim::BackendInstance {
                backend_id,
                backend,
                address_roots: vec![AddressRoot {
                    address: address_root,
                    display_name: None,
                    backend_kind: "azure".into(),
                    connection_id: None,
                    capabilities,
                    source: RouteSource::Static {
                        layer: ConfigLayer::Programmatic,
                    },
                    visibility: AddressVisibility::Visible,
                    user_metadata: UserMetadata::new(),
                }],
                display_name,
                auth_state: ConnectionAuthState::Anonymous,
            })
        })
        .await
    }

    async fn update_credentials(
        &self,
        _connection: &ovstorage_plugin::Connection,
        credentials: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        race_cancel(cancel.as_ref(), async move {
            AzureAuth::resolve(&credentials).map(|_| ())
        })
        .await
    }
}

ovstorage_plugin::ovstorage_plugin!(AzureBackendFactory::default);

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use ovstorage_plugin::shim::{Backend as _, Factory as _};
    use ovstorage_plugin::{ConfigValue, ErrorCode, SecretBytes, SecretValue};
    use std::collections::HashMap;

    #[test]
    fn descriptor_reports_native_azure_schema() {
        let descriptor = AzureBackendFactory::new().descriptor();
        assert_eq!(descriptor.kind, "azure");
        assert_eq!(descriptor.display_name, "Azure Blob Storage");
        assert!(descriptor.supports_runtime_add);

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

    #[tokio::test]
    async fn instantiate_reports_flat_vs_hns_capabilities() {
        let flat = AzureBackendFactory::new()
            .instantiate(&connection_request(false), None)
            .await
            .unwrap();
        let flat_root = &flat.address_roots[0];
        assert!(!flat_root.capabilities.has_real_directories);
        assert!(flat_root.capabilities.supports_list);
        assert!(flat_root.capabilities.supports_native_metadata_patch);
        assert!(flat_root.capabilities.supports_version_listing);
        assert!(!flat_root.capabilities.supports_server_side_rename);
        assert_eq!(flat_root.address.as_str(), "azure://acct123/assets/");

        let hns = AzureBackendFactory::new()
            .instantiate(&connection_request(true), None)
            .await
            .unwrap();
        let hns_root = &hns.address_roots[0];
        assert!(hns_root.capabilities.has_real_directories);
        assert!(hns_root.capabilities.supports_list);
        assert!(hns_root.capabilities.supports_server_side_rename);
        assert!(hns_root.capabilities.supports_atomic_rename);
    }

    #[tokio::test]
    async fn instantiate_reports_change_feed_watch_capabilities() {
        let watched = AzureBackendFactory::new()
            .instantiate(&connection_request_with_change_feed(false, true), None)
            .await
            .unwrap();
        let caps = &watched.address_roots[0].capabilities;
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

        let hns = AzureBackendFactory::new()
            .instantiate(&connection_request_with_change_feed(true, true), None)
            .await
            .unwrap();
        assert!(!hns.address_roots[0].capabilities.supports_watch_directory);
    }

    #[tokio::test]
    async fn invalid_config_is_rejected_deterministically() {
        let mut request = connection_request(false);
        request
            .config
            .insert("root".into(), ConfigValue::String("unused".into()));
        let error = match AzureBackendFactory::new().instantiate(&request, None).await {
            Ok(_) => panic!("expected unknown-config rejection"),
            Err(err) => err,
        };
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.message().contains("root"));

        let mut request = connection_request(false);
        request
            .config
            .insert("account".into(), ConfigValue::String("Upper".into()));
        let error = match AzureBackendFactory::new().instantiate(&request, None).await {
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
        let err = match AzureBackendFactory::new().instantiate(&request, None).await {
            Ok(_) => panic!("expected non-loopback endpoint rejection"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("loopback"));

        request.config.insert(
            "__test_change_feed_endpoint".into(),
            ConfigValue::String("http://127.0.0.1:10000".into()),
        );
        AzureBackendFactory::new()
            .instantiate(&request, None)
            .await
            .expect("loopback test endpoint should be accepted");

        request.credentials.fields.insert(
            "sas_token".into(),
            SecretValue::Bytes(SecretBytes(b"sig=fake".to_vec())),
        );
        let err = match AzureBackendFactory::new().instantiate(&request, None).await {
            Ok(_) => panic!("expected credential-bearing test endpoint rejection"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("anonymous"));
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
