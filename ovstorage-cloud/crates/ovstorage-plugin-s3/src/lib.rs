// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

mod backend;
mod config;
mod convert;
mod credentials;
mod http;
mod multipart;
mod sigv4;
mod subscription;
mod xml;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ovstorage_plugin::shim;
use ovstorage_plugin::{
    AddressRoot, AddressVisibility, AuthEvent, AuthEventStream, BackendId, CancellationToken,
    ConfigField, ConfigLayer, ConfigValue, Connection, ConnectionAuthState, ConnectionRequest,
    Error, ErrorCode, InteractiveAuthCapability, Result, RouteSource, SecretBundle, SecretValue,
    StorageBackendKindDescriptor, UserMetadata,
};
use sha2::{Digest, Sha256};

pub use backend::{S3Backend, s3_capabilities};
pub use config::{CompatibilityProfile, S3Config};
pub use credentials::AwsCredentials;

/// Test-only parser hook; not part of the published surface.
#[doc(hidden)]
pub fn __test_only_parse_config(config: &HashMap<String, ConfigValue>) -> Result<S3Config> {
    config::parse_config(config)
}

/// Factory for the native S3 backend kind.
//
// Instance map is keyed by config+credential fingerprint plus a
// per-call counter; the counter prevents two `instantiate` calls
// with byte-identical config + empty credentials from colliding on
// the same slot (which would silently misroute `update_credentials`).
pub struct S3BackendFactory {
    instances: Mutex<HashMap<String, Arc<S3Backend>>>,
    next_instance_counter: AtomicU64,
}

impl S3BackendFactory {
    pub fn new() -> Self {
        Self {
            instances: Mutex::new(HashMap::new()),
            next_instance_counter: AtomicU64::new(0),
        }
    }
}

impl Default for S3BackendFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl shim::Factory for S3BackendFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "s3".into(),
            display_name: "S3-compatible object store".into(),
            description: Some(
                "Native S3 / S3-compatible backend with hand-rolled SigV4 and AWS credential chain"
                    .into(),
            ),
            config_schema: config_schema_with_visible_options(),
            credential_schema: config::credential_schema(),
            credential_methods: config::credential_methods(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        let _ = &cancel; // synchronous body, nothing to interrupt.
        let config = config::parse_config(&request.config)?;
        let address_root = config.address_root.clone();
        let bucket_for_display = config.bucket.clone();
        let counter = self.next_instance_counter.fetch_add(1, Ordering::Relaxed);
        let backend_kind_for_id = format!(
            "s3:{}:{counter}",
            config_fingerprint(&config, &request.credentials)
        );

        let credentials_attempt =
            if let Some(path) = string_field(&request.credentials, "file_path")? {
                let profile = string_field(&request.credentials, "profile")?
                    .unwrap_or_else(|| "default".to_string());
                Some(credentials::from_aws_credentials_file(&path, &profile)?)
            } else {
                credentials::from_bundle(&request.credentials)?
            };

        let backend = match credentials_attempt {
            Some(credentials) => Arc::new(S3Backend::with_credentials(config, credentials)?),
            None => Arc::new(S3Backend::anonymous(config)?),
        };
        self.instances
            .lock()
            .expect("S3 instance map poisoned")
            .insert(backend_kind_for_id.clone(), backend.clone());
        let capabilities = crate::backend::s3_capabilities_for_config(Some(backend.config()));
        Ok(shim::BackendInstance {
            backend_id: BackendId(backend_kind_for_id),
            backend,
            address_roots: vec![AddressRoot {
                address: address_root,
                display_name: None,
                backend_kind: "s3".into(),
                connection_id: None,
                capabilities,
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }],
            display_name: request
                .display_name
                .clone()
                .or_else(|| Some(format!("S3 {}", bucket_for_display))),
            auth_state: ConnectionAuthState::Anonymous,
        })
    }

    async fn update_credentials(
        &self,
        connection: &Connection,
        credentials: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // synchronous body, nothing to interrupt.
        validate_credential_fields(&credentials)?;
        let resolved = credentials::from_bundle(&credentials)?.ok_or_else(|| {
            Error::new(
                ErrorCode::AuthRequired,
                "update_credentials requires aws_access_key_id and aws_secret_access_key",
            )
        })?;
        let bucket = lookup_bucket(connection)?;
        let instance = self.unique_instance_for_bucket(&bucket)?;
        instance.store_credentials(resolved);
        Ok(())
    }

    async fn authenticate(
        &self,
        connection: Connection,
        _capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let _ = &cancel; // synchronous body, nothing to interrupt.
        // Credentials are resolved at instantiate time from the SecretBundle
        // (which the library populated from TOML SecretRefs). Anonymous
        // backends stay anonymous. Nothing to re-resolve here.
        Ok(Box::new(std::iter::once(Ok(AuthEvent::Succeeded {
            connection: Box::new(connection),
            credentials: None,
        }))))
    }
}

impl S3BackendFactory {
    fn unique_instance_for_bucket(&self, bucket: &str) -> Result<Arc<S3Backend>> {
        let map = self.instances.lock().expect("S3 instance map poisoned");
        let mut matches: Vec<Arc<S3Backend>> = Vec::new();
        for instance in map.values() {
            if instance.config().bucket == bucket {
                matches.push(instance.clone());
            }
        }
        match matches.len() {
            0 => Err(Error::new(
                ErrorCode::NotFound,
                format!("no S3 backend instance is registered for bucket '{bucket}'"),
            )),
            1 => Ok(matches.remove(0)),
            _ => Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "multiple S3 backend instances share bucket '{bucket}'; cannot disambiguate from connection alone"
                ),
            )),
        }
    }
}

fn config_fingerprint(config: &S3Config, credentials: &SecretBundle) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"v2\0");
    hasher.update(config.bucket.as_bytes());
    hasher.update(b"\0");
    hasher.update(config.region.as_bytes());
    hasher.update(b"\0");
    hasher.update(config.endpoint.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"\0");
    hasher.update(config.profile_name.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"\0");
    hasher.update(config.compatibility.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update([config.force_path_style as u8]);
    hasher.update([config.force_request_payer as u8]);
    hasher.update(b"\0watch\0");
    hasher.update(config.sqs_queue_url.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"\0");
    hasher.update(config.sqs_max_messages.to_le_bytes());
    hasher.update(config.sqs_wait_seconds.to_le_bytes());
    hasher.update(config.sqs_visibility_timeout.to_le_bytes());
    hasher.update(b"\0cred\0");
    for key in ["aws_access_key_id", "aws_session_token"] {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        if let Some(bytes) = credential_identity_bytes(credentials, key) {
            hasher.update(bytes);
        }
        hasher.update(b"\0");
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn credential_identity_bytes<'a>(bundle: &'a SecretBundle, key: &str) -> Option<&'a [u8]> {
    match bundle.fields.get(key)? {
        SecretValue::Bytes(b) | SecretValue::File(b) => Some(&b.0),
        _ => None,
    }
}

fn string_field(bundle: &SecretBundle, key: &str) -> Result<Option<String>> {
    let Some(value) = bundle.fields.get(key) else {
        return Ok(None);
    };
    let bytes = match value {
        SecretValue::Bytes(b) | SecretValue::File(b) => &b.0,
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("S3 credential field '{key}' must be a Bytes secret"),
            ));
        }
    };
    let text = std::str::from_utf8(bytes).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("S3 credential field '{key}' must be UTF-8 text"),
        )
    })?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn validate_credential_fields(bundle: &SecretBundle) -> Result<()> {
    for key in bundle.fields.keys() {
        if !credentials::known_credential_field(key) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("S3 credential field '{key}' is not part of the descriptor schema"),
            ));
        }
    }
    Ok(())
}

fn lookup_bucket(connection: &Connection) -> Result<String> {
    if let Some(addr) = connection.current_addresses.first()
        && let Ok(parts) = config::parse_s3_address(addr, "")
    {
        return Ok(parts.bucket);
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        "S3 connection has no resolvable bucket address",
    ))
}

fn config_schema_with_visible_options() -> Vec<ConfigField> {
    config::config_schema()
}

ovstorage_plugin::ovstorage_plugin!(S3BackendFactory::default);

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use ovstorage_plugin::shim::{Backend as _, Factory as _};
    use ovstorage_plugin::{BackendId, ResolvedTarget, SecretBundle, StatOptions, address};

    #[test]
    fn descriptor_reports_native_s3_schema() {
        let descriptor = S3BackendFactory::new().descriptor();
        assert_eq!(descriptor.kind, "s3");
        assert_eq!(descriptor.display_name, "S3-compatible object store");
        assert!(descriptor.supports_runtime_add);

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

    #[tokio::test]
    async fn instantiate_returns_native_backend_with_aws_capabilities() {
        let request = request_with_bucket("assets");
        let instance = S3BackendFactory::new()
            .instantiate(&request, None)
            .await
            .unwrap();

        let root = &instance.address_roots[0];
        assert_eq!(root.address.as_str(), "s3://assets/");
        assert!(instance.backend_id.0.starts_with("s3:"));
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

    #[tokio::test]
    async fn instantiate_enables_watch_when_sqs_queue_is_configured() {
        let mut request = request_with_bucket("assets");
        request.config.insert(
            "sqs_queue_url".into(),
            ConfigValue::String("https://sqs.us-east-1.amazonaws.com/123/assets-watch".into()),
        );
        let instance = S3BackendFactory::new()
            .instantiate(&request, None)
            .await
            .unwrap();
        let capabilities = &instance.address_roots[0].capabilities;
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
        // url::Url normalises RFC 3986 dot-segments and preserves authority case.
        let address = address::parse("s3://Bucket/a//../c.?versionId=null#fragment").unwrap();
        let parts = config::parse_s3_address(&address, "Bucket").unwrap();
        assert_eq!(parts.bucket, "Bucket");
        assert_eq!(parts.key, "a/c.");
    }

    #[tokio::test]
    async fn object_io_rejects_wrong_bucket_before_signing() {
        let request = request_with_bucket("bucket");
        let instance = S3BackendFactory::new()
            .instantiate(&request, None)
            .await
            .unwrap();
        let target = ResolvedTarget {
            backend_id: BackendId("s3:s3://bucket/".into()),
            resolved_address: address::parse("s3://other/path/object.txt").unwrap(),
        };
        let err = instance
            .backend
            .stat(target, StatOptions::default(), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn update_credentials_rejects_unknown_field_keys() {
        use ovstorage_plugin::SecretBytes;
        let factory = S3BackendFactory::new();
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "not_a_field".into(),
            SecretValue::Bytes(SecretBytes(b"x".to_vec())),
        );
        let connection = Connection {
            id: ovstorage_plugin::ConnectionId("c1".into()),
            backend_kind: "s3".into(),
            display_name: "s3".into(),
            source: ovstorage_plugin::ConnectionSource::Runtime { persisted: false },
            capabilities: s3_capabilities(),
            current_addresses: vec![address::parse("s3://b/").unwrap()],
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: ovstorage_plugin::UserMetadata::new(),
        };
        let err = factory
            .update_credentials(&connection, bundle, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    fn request_with_bucket(bucket: &str) -> ConnectionRequest {
        let mut config = HashMap::new();
        config.insert("bucket".into(), ConfigValue::String(bucket.into()));
        config.insert("region".into(), ConfigValue::String("us-east-1".into()));
        ConnectionRequest {
            backend_kind: "s3".into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        }
    }

    #[tokio::test]
    async fn two_instances_with_same_bucket_have_distinct_backend_ids() {
        let factory = S3BackendFactory::new();
        let mut a = request_with_bucket("shared");
        a.config.insert(
            "endpoint".into(),
            ConfigValue::String("http://endpoint-a:9000".into()),
        );
        a.config.insert(
            "compatibility_profile".into(),
            ConfigValue::String("custom".into()),
        );
        a.config
            .insert("force_path_style".into(), ConfigValue::Bool(true));
        let mut b = request_with_bucket("shared");
        b.config.insert(
            "endpoint".into(),
            ConfigValue::String("http://endpoint-b:9000".into()),
        );
        b.config.insert(
            "compatibility_profile".into(),
            ConfigValue::String("custom".into()),
        );
        b.config
            .insert("force_path_style".into(), ConfigValue::Bool(true));
        let inst_a = factory.instantiate(&a, None).await.unwrap();
        let inst_b = factory.instantiate(&b, None).await.unwrap();
        assert_ne!(
            inst_a.backend_id, inst_b.backend_id,
            "differing endpoints must not collide on the same cache key"
        );
    }

    #[tokio::test]
    async fn update_credentials_refuses_when_bucket_is_ambiguous() {
        use ovstorage_plugin::SecretBytes;
        let factory = S3BackendFactory::new();
        let mut a = request_with_bucket("shared");
        a.config.insert(
            "endpoint".into(),
            ConfigValue::String("http://endpoint-a:9000".into()),
        );
        a.config.insert(
            "compatibility_profile".into(),
            ConfigValue::String("custom".into()),
        );
        a.config
            .insert("force_path_style".into(), ConfigValue::Bool(true));
        let mut b = request_with_bucket("shared");
        b.config.insert(
            "endpoint".into(),
            ConfigValue::String("http://endpoint-b:9000".into()),
        );
        b.config.insert(
            "compatibility_profile".into(),
            ConfigValue::String("custom".into()),
        );
        b.config
            .insert("force_path_style".into(), ConfigValue::Bool(true));
        factory.instantiate(&a, None).await.unwrap();
        factory.instantiate(&b, None).await.unwrap();

        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "aws_access_key_id".into(),
            SecretValue::Bytes(SecretBytes(b"AKIDEXAMPLE".to_vec())),
        );
        bundle.fields.insert(
            "aws_secret_access_key".into(),
            SecretValue::Bytes(SecretBytes(b"secret".to_vec())),
        );
        let connection = Connection {
            id: ovstorage_plugin::ConnectionId("c1".into()),
            backend_kind: "s3".into(),
            display_name: "s3".into(),
            source: ovstorage_plugin::ConnectionSource::Runtime { persisted: false },
            capabilities: s3_capabilities(),
            current_addresses: vec![address::parse("s3://shared/").unwrap()],
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: ovstorage_plugin::UserMetadata::new(),
        };
        let err = factory
            .update_credentials(&connection, bundle, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn identical_empty_credential_configs_produce_distinct_backend_ids() {
        // Per-call counter must keep byte-identical empty-cred instantiates from colliding.
        let factory = S3BackendFactory::new();
        let req_a = request_with_bucket("shared");
        let req_b = request_with_bucket("shared");
        let inst_a = factory.instantiate(&req_a, None).await.unwrap();
        let inst_b = factory.instantiate(&req_b, None).await.unwrap();
        assert_ne!(
            inst_a.backend_id, inst_b.backend_id,
            "identical-config empty-cred instantiates must not collide",
        );
        assert_eq!(
            factory
                .instances
                .lock()
                .expect("S3 instance map poisoned")
                .len(),
            2,
            "the second instantiate must NOT overwrite the first's slot"
        );
    }

    #[tokio::test]
    async fn distinct_credentials_produce_distinct_backend_ids_for_same_config() {
        use ovstorage_plugin::SecretBytes;
        let factory = S3BackendFactory::new();
        let mut a = request_with_bucket("shared");
        a.credentials.fields.insert(
            "aws_access_key_id".into(),
            SecretValue::Bytes(SecretBytes(b"AKIA-PRINCIPAL-A".to_vec())),
        );
        a.credentials.fields.insert(
            "aws_secret_access_key".into(),
            SecretValue::Bytes(SecretBytes(b"secret-a".to_vec())),
        );
        let mut b = request_with_bucket("shared");
        b.credentials.fields.insert(
            "aws_access_key_id".into(),
            SecretValue::Bytes(SecretBytes(b"AKIA-PRINCIPAL-B".to_vec())),
        );
        b.credentials.fields.insert(
            "aws_secret_access_key".into(),
            SecretValue::Bytes(SecretBytes(b"secret-b".to_vec())),
        );
        let inst_a = factory.instantiate(&a, None).await.unwrap();
        let inst_b = factory.instantiate(&b, None).await.unwrap();
        assert_ne!(
            inst_a.backend_id, inst_b.backend_id,
            "different principals on the same bucket must not share a cached backend",
        );
    }

    #[tokio::test]
    async fn distinct_session_tokens_produce_distinct_backend_ids() {
        use ovstorage_plugin::SecretBytes;
        let factory = S3BackendFactory::new();
        let access = SecretValue::Bytes(SecretBytes(b"AKIA-SHARED-ID".to_vec()));
        let secret = SecretValue::Bytes(SecretBytes(b"shared-secret".to_vec()));
        let mut a = request_with_bucket("shared");
        a.credentials
            .fields
            .insert("aws_access_key_id".into(), access.clone());
        a.credentials
            .fields
            .insert("aws_secret_access_key".into(), secret.clone());
        a.credentials.fields.insert(
            "aws_session_token".into(),
            SecretValue::Bytes(SecretBytes(b"sts-session-A".to_vec())),
        );
        let mut b = request_with_bucket("shared");
        b.credentials
            .fields
            .insert("aws_access_key_id".into(), access);
        b.credentials
            .fields
            .insert("aws_secret_access_key".into(), secret);
        b.credentials.fields.insert(
            "aws_session_token".into(),
            SecretValue::Bytes(SecretBytes(b"sts-session-B".to_vec())),
        );
        let inst_a = factory.instantiate(&a, None).await.unwrap();
        let inst_b = factory.instantiate(&b, None).await.unwrap();
        assert_ne!(
            inst_a.backend_id, inst_b.backend_id,
            "different STS sessions on the same access key must not share a cached backend",
        );
    }
}
