// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// The layer's data-path slots nest an AWS SDK operation future inside the
// promotion witness's task-local scope inside the connection set's recovery
// loop, and rustc's default query depth of 128 is reached while laying out the
// resulting anonymous future. A compile-time knob only; it changes no generated
// code.
#![recursion_limit = "256"]
#![doc = include_str!("../README.md")]

mod backend;
mod client;
mod config;
mod convert;
mod credentials;
mod driver;
mod errors;
mod layer;
mod multipart;
mod subscription;

use std::collections::HashMap;

use ovstorage_plugin::{ConfigValue, Result};

pub use backend::{S3Backend, s3_capabilities};
pub use config::{CompatibilityProfile, S3Config};
pub use credentials::AwsCredentials;
pub use layer::S3LayerFactory;

/// Test-only parser hook; not part of the published surface.
#[doc(hidden)]
pub fn __test_only_parse_config(config: &HashMap<String, ConfigValue>) -> Result<S3Config> {
    config::parse_config(config)
}

/// Test-only reader for the connection's refusal epoch; not part of the
/// published surface. Exposed so an integration test can assert that an
/// unsigned request's refusal records no evidence about a credential.
#[doc(hidden)]
pub fn __test_only_refusal_epoch(backend: &S3Backend) -> u64 {
    backend.refusal_epoch()
}

ovstorage_plugin::ovstorage_layer_plugin!(backend, S3LayerFactory::default);

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::BackendFactory;
    use ovstorage_plugin::{
        BackendId, ConnectionAuthState, ConnectionRequest, ErrorCode, LayerConnectionRequest,
        Request, ResolvedTarget, SecretBundle, SecretBytes, SecretValue, StatOptions, address,
    };

    #[test]
    fn descriptor_reports_native_s3_schema() {
        let descriptor = BackendFactory::descriptor(&S3LayerFactory::default());
        assert_eq!(descriptor.kind, "s3");
        assert_eq!(descriptor.display_name, "S3-compatible object store");
        assert!(descriptor.accepts_connections);

        let config_keys = descriptor
            .config_schema
            .iter()
            .map(|field| field.key.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            config_keys,
            vec![
                "bucket",
                "region",
                "endpoint",
                "compatibility_profile",
                "profile",
                "force_path_style",
                "force_request_payer",
                "sqs_queue_url",
                "sqs_max_messages",
                "sqs_wait_seconds",
                "sqs_visibility_timeout",
            ]
        );
        assert!(descriptor.config_schema[0].required);
        assert!(descriptor.config_schema[1].required);

        let credential_keys = descriptor
            .credential_schema
            .iter()
            .map(|field| field.key.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            credential_keys,
            vec![
                "aws_access_key_id",
                "aws_secret_access_key",
                "aws_session_token",
                "file_path",
                "profile",
            ]
        );
    }

    async fn layer_with_connection(
        request: ConnectionRequest,
    ) -> (ovstorage_plugin::LayerHandle, ovstorage_plugin::Connection) {
        let layer = S3LayerFactory::default()
            .create_backend("s3", &ovstorage_plugin::LayerConfig::new(), None)
            .await
            .unwrap();
        let connection = layer
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "s3".into(),
                    connection: request,
                }),
                None,
            )
            .await
            .unwrap();
        (layer, connection)
    }

    #[tokio::test]
    async fn add_connection_returns_native_backend_with_aws_capabilities() {
        let request = request_with_credentials("assets");
        let (layer, connection) = layer_with_connection(request).await;

        assert_eq!(connection.current_addresses.len(), 1);
        assert_eq!(connection.current_addresses[0].as_str(), "s3://assets/");
        // Credentials verify against an unroutable endpoint: the lenient
        // verify treats a transport failure as a pass.
        assert!(matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ));
        let root = layer
            .root_info_for(
                &address::parse("s3://assets/file.txt").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap();
        assert!(root.capabilities.supports_list);
        assert!(!root.capabilities.supports_watch_directory);
        assert!(root.capabilities.wants_list_backed_stat);
        assert!(root.capabilities.supports_version_listing);
        assert_eq!(
            root.capabilities.version_list_order,
            Some(ovstorage_plugin::VersionListOrder::Newest)
        );
        assert!(!root.capabilities.has_real_directories);
    }

    /// Anonymous (no-credentials) connections are read-only, and "read" spans
    /// everything an unsigned request can ask a public bucket: listing and
    /// stat as well as `read`. The advertisement must carry those and none of
    /// the mutation bits, which the credential-less path refuses before the
    /// wire.
    ///
    /// This asserts through `root_info_for`, so it also covers the wiring from
    /// `anonymous_capabilities` out to what a caller sees — the unit test in
    /// `backend::tests` pins the set itself.
    #[tokio::test]
    async fn add_connection_anonymous_advertises_read_only_capabilities() {
        let request = request_with_bucket("public-assets");
        let (layer, connection) = layer_with_connection(request).await;

        assert!(matches!(
            connection.auth_state,
            ConnectionAuthState::Anonymous
        ));
        let root = layer
            .root_info_for(
                &address::parse("s3://public-assets/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap();
        let caps = &root.capabilities;
        assert!(!caps.supports_write);
        assert!(!caps.supports_write_stream);
        assert!(!caps.supports_write_redirect);
        assert!(!caps.supports_delete);
        assert!(caps.supports_list, "a public bucket is listable unsigned");
        assert!(caps.supports_recursive_list);
        assert!(caps.wants_list_backed_stat);
        assert!(!caps.supports_server_side_copy);
        assert!(!caps.supports_server_side_rename);
        assert!(caps.supports_version_listing);
        assert_eq!(
            caps.version_list_order,
            Some(ovstorage_plugin::VersionListOrder::Newest)
        );
        assert!(!caps.supports_create_directory);
        assert!(!caps.supports_delete_directory);
        assert!(!caps.supports_metadata_rewrite_emulation);
        assert!(caps.supports_access_check);
        assert!(!caps.supports_watch_directory);
    }

    #[tokio::test]
    async fn add_connection_enables_watch_when_sqs_queue_is_configured() {
        let mut request = request_with_credentials("assets");
        request.config.insert(
            "sqs_queue_url".into(),
            ConfigValue::String("https://sqs.us-east-1.amazonaws.com/123/assets-watch".into()),
        );
        let (layer, _connection) = layer_with_connection(request).await;
        let root = layer
            .root_info_for(
                &address::parse("s3://assets/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap();
        let capabilities = &root.capabilities;
        assert!(capabilities.supports_watch_directory);
        assert!(!capabilities.watch_directory_resumable);
        assert_eq!(
            capabilities.watch_directory_max_lag,
            Some(std::time::Duration::from_secs(60))
        );
        assert!(capabilities.watch_directory_kinds.created);
        assert!(capabilities.watch_directory_kinds.modified);
        assert!(capabilities.watch_directory_kinds.deleted);
        assert!(capabilities.watch_directory_kinds.metadata_changed);
    }

    #[test]
    fn parser_extracts_s3_bucket_and_key() {
        // `address::parse` canonicalises the URL: RFC 3986 dot-segments are
        // resolved and the authority (bucket) is lowercased. Bucket matching is
        // case-insensitive, so the mixed-case configured bucket still matches.
        let address = address::parse("s3://Bucket/a//../c.?versionId=null#fragment").unwrap();
        let parts = config::parse_s3_address(&address, "Bucket").unwrap();
        assert_eq!(parts.bucket, "bucket");
        assert_eq!(parts.key, "a/c.");
    }

    /// The backend's second-line bucket defense (behind the layer's routing).
    #[tokio::test]
    async fn object_io_rejects_wrong_bucket_before_signing() {
        let mut config = HashMap::new();
        config.insert("bucket".into(), ConfigValue::String("bucket".into()));
        config.insert("region".into(), ConfigValue::String("us-east-1".into()));
        // A dead loopback endpoint. The address check below rejects before any
        // request is built, so this changes no outcome — it keeps a unit test
        // from being one edit away from talking to real AWS, now that an
        // anonymous backend carries a working SDK client.
        config.insert(
            "endpoint".into(),
            ConfigValue::String("http://127.0.0.1:1".into()),
        );
        let backend = S3Backend::anonymous(config::parse_config(&config).unwrap()).unwrap();
        let target = ResolvedTarget {
            backend_id: BackendId("s3:s3://bucket/".into()),
            resolved_address: address::parse("s3://other/path/object.txt").unwrap(),
        };
        let err = backend
            .stat(target, StatOptions::default(), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// Layer routing: an address outside every connection's root is `NoRoute`.
    #[tokio::test]
    async fn layer_routes_only_connected_roots() {
        let request = request_with_bucket("bucket");
        let (layer, _connection) = layer_with_connection(request).await;
        let err = layer
            .stat(
                Request::new(ovstorage_plugin::StatRequest {
                    address: address::parse("s3://other/object.txt").unwrap(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NoRoute);
    }

    #[tokio::test]
    async fn remove_connection_tears_down_routes() {
        use ovstorage_plugin::ConnectionKey;
        let request = request_with_bucket("bucket");
        let (layer, connection) = layer_with_connection(request).await;
        layer
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "s3".into(),
                    id: connection.id.clone(),
                }),
                None,
            )
            .await
            .unwrap();
        let err = layer
            .root_info_for(
                &address::parse("s3://bucket/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NoRoute);
        assert!(
            layer
                .list_connections(&ovstorage_plugin::Extensions::new(), None)
                .await
                .unwrap()
                .0
                .connections
                .is_empty()
        );
    }

    fn request_with_bucket(bucket: &str) -> ConnectionRequest {
        let mut config = HashMap::new();
        config.insert("bucket".into(), ConfigValue::String(bucket.into()));
        config.insert("region".into(), ConfigValue::String("us-east-1".into()));
        // Unroutable endpoint: unit tests must never reach a real service.
        // The driver's lenient verify treats connection-refused as a pass.
        config.insert(
            "endpoint".into(),
            ConfigValue::String("http://127.0.0.1:1".into()),
        );
        config.insert(
            "compatibility_profile".into(),
            ConfigValue::String("custom".into()),
        );
        config.insert("force_path_style".into(), ConfigValue::Bool(true));
        ConnectionRequest {
            backend_kind: "s3".into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        }
    }

    /// `request_with_bucket` plus static credentials, so the connection is
    /// credentialed (non-anonymous) and advertises the full capability set.
    fn request_with_credentials(bucket: &str) -> ConnectionRequest {
        let mut request = request_with_bucket(bucket);
        request.credentials.fields.insert(
            "aws_access_key_id".into(),
            SecretValue::Bytes(SecretBytes(b"AKIATESTFIXTURE".to_vec())),
        );
        request.credentials.fields.insert(
            "aws_secret_access_key".into(),
            SecretValue::Bytes(SecretBytes(
                b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec(),
            )),
        );
        request
    }

    #[tokio::test]
    async fn identical_empty_credential_configs_produce_distinct_connections() {
        // Per-layer counter must keep byte-identical empty-credential
        // connections on distinct ConnectionIds and both routable.
        let layer = S3LayerFactory::default()
            .create_backend("s3", &ovstorage_plugin::LayerConfig::new(), None)
            .await
            .unwrap();
        let mut ids = Vec::new();
        for _ in 0..2 {
            let connection = layer
                .add_connection(
                    Request::new(LayerConnectionRequest {
                        target: "s3".into(),
                        connection: request_with_bucket("shared"),
                    }),
                    None,
                )
                .await
                .unwrap();
            ids.push(connection.id);
        }
        assert_ne!(ids[0], ids[1]);
        let (snapshot, _) = layer
            .list_connections(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        assert_eq!(snapshot.connections.len(), 2);
    }
}
