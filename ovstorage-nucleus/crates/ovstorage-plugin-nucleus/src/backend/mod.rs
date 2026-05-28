// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native Nucleus backend module.
//!
//! - `factory` — `NucleusBackendFactory` + `NucleusShared` lifecycle owner
//! - `spi` — `NucleusBackend` and the `shim::Backend` trait impl
//! - `convert` — pure-data conversions between omni1 wire types and SPI types
//! - `watch` — sync `Iterator` adapter over the async `subscribe_list` pump

mod convert;
mod factory;
mod spi;
mod watch;

pub use factory::NucleusBackendFactory;
pub use spi::NucleusBackend;

#[cfg(test)]
mod tests {
    use super::factory::NucleusBackendFactory;
    use super::spi::native_capabilities;
    use std::collections::HashMap;

    use ovstorage_plugin::shim::Factory as _;
    use ovstorage_plugin::{
        AuthEvent, BackendId, ConfigLayer, ConfigValue, ConnectionAuthState, ConnectionId,
        ConnectionRequest, ConnectionSource, ErrorCode, InteractiveAuthCapability, ReadOptions,
        ResolvedTarget, Result, SecretBundle, SecretBytes, SecretValue, Url, UserMetadata,
    };

    use crate::address::{NUCLEUS_KIND, parse_nucleus_address};

    fn request(server: &str) -> ConnectionRequest {
        let mut config = HashMap::new();
        config.insert("server".into(), ConfigValue::String(server.into()));
        ConnectionRequest {
            backend_kind: NUCLEUS_KIND.into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        }
    }

    fn target(address: &str) -> ResolvedTarget {
        ResolvedTarget {
            backend_id: BackendId("test".into()),
            resolved_address: Url::parse(address).unwrap(),
        }
    }

    fn synthetic_connection(roots: &[Url], _creds: SecretBundle) -> ovstorage_plugin::Connection {
        ovstorage_plugin::Connection {
            id: ConnectionId("test-conn".into()),
            backend_kind: NUCLEUS_KIND.into(),
            display_name: "test".into(),
            source: ConnectionSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            capabilities: native_capabilities(),
            current_addresses: roots.to_vec(),
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: UserMetadata::new(),
        }
    }

    #[test]
    fn descriptor_reports_nucleus_kind_and_native_shape() {
        let descriptor = NucleusBackendFactory::new().descriptor();
        assert_eq!(descriptor.kind, "nucleus");
        assert_eq!(descriptor.display_name, "Nucleus");
        assert!(descriptor.supports_runtime_add);
        assert!(
            descriptor
                .config_schema
                .iter()
                .any(|field| field.key == "server")
        );
        assert!(
            descriptor
                .config_schema
                .iter()
                .any(|field| field.key == "endpoint")
        );
        assert!(
            descriptor
                .config_schema
                .iter()
                .any(|field| field.key == "prefix")
        );
        assert!(
            descriptor
                .config_schema
                .iter()
                .any(|field| field.key == "use_lft")
        );
    }

    #[tokio::test]
    async fn instantiate_uses_same_root_and_capabilities() {
        let instance = NucleusBackendFactory::new()
            .instantiate(&request("nucleus.local"), None)
            .await
            .unwrap();
        assert_eq!(instance.address_roots.len(), 1);
        let root = &instance.address_roots[0];
        assert_eq!(
            root.address,
            Url::parse("omniverse://nucleus.local/").unwrap()
        );
        assert!(root.capabilities.supports_list);
        assert!(root.capabilities.wants_list_backed_stat);
    }

    #[test]
    fn checkpoint_selector_parses_native_forms_deterministically() {
        let native =
            parse_nucleus_address(&Url::parse("omniverse://srv/Users/alice/foo.usd?&3").unwrap())
                .unwrap();
        assert_eq!(native.path, "/Users/alice/foo.usd");
        assert_eq!(native.branch, None);
        assert_eq!(native.checkpoint, Some(3));

        let named = parse_nucleus_address(
            &Url::parse("omniverse://srv/Users/alice/foo.usd?main&42").unwrap(),
        )
        .unwrap();
        assert_eq!(named.branch.as_deref(), Some("main"));
        assert_eq!(named.checkpoint, Some(42));

        let query_key = parse_nucleus_address(
            &Url::parse("omniverse://srv/Users/alice/foo.usd?checkpoint=9").unwrap(),
        )
        .unwrap();
        assert_eq!(query_key.checkpoint, Some(9));
    }

    #[test]
    fn invalid_checkpoint_selector_is_rejected() {
        let error =
            parse_nucleus_address(&Url::parse("omniverse://srv/Users/alice/foo.usd?&abc").unwrap())
                .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn object_io_returns_auth_required_before_session_install() {
        let factory = NucleusBackendFactory::new();
        let instance = factory.instantiate(&request("srv"), None).await.unwrap();
        let error = instance
            .backend
            .read(
                target("omniverse://srv/Users/alice/foo.usd"),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::AuthRequired);
    }

    #[tokio::test]
    async fn authenticate_with_api_token_drives_real_handshake_and_fails_on_unreachable_host() {
        // Hitting a real Nucleus is the integration-test workspace's job; here we just
        // verify the api-token path surfaces `Failed { Transient }` instead of synthesizing `Succeeded`.
        let factory = NucleusBackendFactory::new();
        let mut request = request("nucleus.invalid");
        request.credentials.fields.insert(
            "api_token".into(),
            SecretValue::Bytes(SecretBytes(b"abc".to_vec())),
        );
        let instance = factory.instantiate(&request, None).await.unwrap();
        let urls: Vec<Url> = instance
            .address_roots
            .iter()
            .map(|r| r.address.clone())
            .collect();
        let connection = synthetic_connection(&urls, request.credentials);

        let events: Vec<_> = factory
            .authenticate(connection, InteractiveAuthCapability::Browser, None)
            .await
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            events.len(),
            2,
            "expected Progress then Failed; got {events:?}"
        );
        assert!(matches!(events[0], AuthEvent::Progress { .. }));
        match &events[1] {
            AuthEvent::Failed { error } => {
                assert_eq!(error.code(), ErrorCode::Transient);
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticate_with_username_password_drives_real_handshake_and_fails_on_unreachable_host()
     {
        let factory = NucleusBackendFactory::new();
        let mut request = request("nucleus.invalid");
        request.credentials.fields.insert(
            "username".into(),
            SecretValue::Bytes(SecretBytes(b"alice".to_vec())),
        );
        request.credentials.fields.insert(
            "password".into(),
            SecretValue::Bytes(SecretBytes(b"hunter2".to_vec())),
        );
        let instance = factory.instantiate(&request, None).await.unwrap();
        let urls: Vec<Url> = instance
            .address_roots
            .iter()
            .map(|r| r.address.clone())
            .collect();
        let connection = synthetic_connection(&urls, request.credentials);

        let events: Vec<_> = factory
            .authenticate(connection, InteractiveAuthCapability::Browser, None)
            .await
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            events.len(),
            2,
            "expected Progress then Failed; got {events:?}"
        );
        assert!(matches!(events[0], AuthEvent::Progress { .. }));
        match &events[1] {
            AuthEvent::Failed { error } => {
                assert_eq!(error.code(), ErrorCode::Transient);
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// Synchronous Credentials.auth does not need a browser; verifies all capability modes work.
    #[tokio::test]
    async fn authenticate_with_username_password_runs_under_capability_none() {
        let factory = NucleusBackendFactory::new();
        let mut request = request("nucleus.invalid");
        request.credentials.fields.insert(
            "username".into(),
            SecretValue::Bytes(SecretBytes(b"alice".to_vec())),
        );
        request.credentials.fields.insert(
            "password".into(),
            SecretValue::Bytes(SecretBytes(b"hunter2".to_vec())),
        );
        let instance = factory.instantiate(&request, None).await.unwrap();
        let urls: Vec<Url> = instance
            .address_roots
            .iter()
            .map(|r| r.address.clone())
            .collect();
        let connection = synthetic_connection(&urls, request.credentials);

        let events: Vec<_> = factory
            .authenticate(connection, InteractiveAuthCapability::None, None)
            .await
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], AuthEvent::Progress { .. }));
        assert!(matches!(events[1], AuthEvent::Failed { .. }));
    }

    /// Without creds AND without an interactive capability, no path can drive a
    /// handshake — surface the legacy `AuthRequired` failure event.
    #[tokio::test]
    async fn authenticate_without_credentials_under_capability_none_emits_auth_required() {
        let factory = NucleusBackendFactory::new();
        let instance = factory.instantiate(&request("srv"), None).await.unwrap();
        let urls: Vec<Url> = instance
            .address_roots
            .iter()
            .map(|r| r.address.clone())
            .collect();
        let connection = synthetic_connection(&urls, SecretBundle::default());

        let events: Vec<_> = factory
            .authenticate(connection, InteractiveAuthCapability::None, None)
            .await
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            AuthEvent::Failed { error } => {
                assert_eq!(error.code(), ErrorCode::AuthRequired);
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// Without creds but with an interactive capability, the dispatch should
    /// drive the URL+nonce-poll handshake (which will fail against the
    /// unreachable test host but emits the same Progress→Failed shape as the
    /// explicit `interactive_auth` marker path).
    #[tokio::test]
    async fn authenticate_without_credentials_with_capability_drives_interactive_handshake() {
        let factory = NucleusBackendFactory::new();
        let instance = factory
            .instantiate(&request("nucleus.invalid"), None)
            .await
            .unwrap();
        let urls: Vec<Url> = instance
            .address_roots
            .iter()
            .map(|r| r.address.clone())
            .collect();
        let connection = synthetic_connection(&urls, SecretBundle::default());

        let events: Vec<_> = factory
            .authenticate(connection, InteractiveAuthCapability::Browser, None)
            .await
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert!(
            events.len() >= 2,
            "expected handshake events, got {events:?}"
        );
        assert!(matches!(events[0], AuthEvent::Progress { .. }));
        assert!(matches!(events.last().unwrap(), AuthEvent::Failed { .. }));
    }
}

#[cfg(test)]
mod spi_tests {
    use super::factory::NucleusBackendFactory;
    use super::spi::{NucleusBackend, NucleusContinuation, encode_nucleus_continuation};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use ovstorage_plugin::shim::{Backend as _, Factory as _};
    use ovstorage_plugin::{
        AccessOps, BackendChangeEvent, BackendId, ChangeKind, ConfigValue, ConnectionRequest,
        CopyOptions, CreateDirectoryOptions, DeleteOptions, ErrorCode, HttpRequest, IfDestExists,
        ListOptions, ListVersionsOptions, ObjectKind, ReadOptions, ReadResult, RedirectBodySource,
        RedirectResult, RedirectResultBatch, RedirectScope, RenameOptions, ResolvedTarget,
        ResultCapture, SecretBundle, StatOptions, Url, WatchDirectoryOptions, WriteOptions,
        WriteRedirect, WriteRedirectBatch, WriteStep,
    };
    use serde_json::json;

    use ovstorage_plugin::address as plugin_address;

    use crate::address::NUCLEUS_KIND;
    use crate::handshake::NucleusSession;
    use crate::ops::{NucleusOps, RuntimeOps};
    use crate::test_support::{CannedResponse, MockTransport, RawFrame};
    use std::sync::atomic::{AtomicU64, Ordering};

    async fn factory_with_mock() -> (
        NucleusBackendFactory,
        Arc<NucleusBackend>,
        Arc<MockTransport>,
    ) {
        let factory = NucleusBackendFactory::new();
        let mut config = HashMap::new();
        config.insert("server".into(), ConfigValue::String("srv".into()));
        let request = ConnectionRequest {
            backend_kind: NUCLEUS_KIND.into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        };
        let instance = factory.instantiate(&request, None).await.unwrap();
        let backend: Arc<NucleusBackend> = {
            // SAFETY: the factory always produces an `Arc<NucleusBackend>` from `instantiate`.
            let raw = Arc::into_raw(instance.backend) as *const NucleusBackend;
            unsafe { Arc::from_raw(raw) }
        };

        let mock = Arc::new(MockTransport::new());
        let ops: Arc<dyn NucleusOps> = Arc::new(RuntimeOps::new(MockTransportHandle {
            inner: Arc::clone(&mock),
        }));
        let installed =
            factory.install_ops_for_testing(&instance.address_roots.first().unwrap().address, ops);
        assert!(installed);

        (factory, backend, mock)
    }

    /// `Arc` wrapper so the handle inside `RuntimeOps` shares state with the test inspector.
    struct MockTransportHandle {
        inner: Arc<MockTransport>,
    }

    impl nucleus_transport::Transport for MockTransportHandle {
        fn descriptors() -> Vec<nucleus_transport::TransportDescriptor> {
            MockTransport::descriptors()
        }

        fn send(
            &self,
            interface: &str,
            method: &str,
            params: serde_json::Value,
            binary: Option<Vec<u8>>,
        ) -> impl std::future::Future<Output = anyhow::Result<nucleus_transport::Subscription>> + Send
        {
            self.inner.send(interface, method, params, binary)
        }
    }

    fn target(address: &str) -> ResolvedTarget {
        ResolvedTarget {
            backend_id: BackendId("test".into()),
            resolved_address: Url::parse(address).unwrap(),
        }
    }

    /// Stat probes both file and folder shapes in parallel. Each non-trailing-slash
    /// stat call therefore produces two requests; tests enqueue this canned response
    /// to absorb the folder probe so the file probe drives the assertions.
    fn folder_probe_invalid_uri() -> CannedResponse {
        CannedResponse {
            interface: "Connection".into(),
            method: "stat2".into(),
            frames: vec![RawFrame::from_json(&json!({"status": "INVALID_URI"}))],
        }
    }

    #[tokio::test]
    async fn stat_translates_stat2_response_to_object_info() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "stat2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "type": "asset",
                "uri": "/Users/alice/foo.usd",
                "etag": "etag-1",
                "size": 1024,
                "modified_date_seconds": 1700000000,
                "transaction_id": "tx-9",
            }))],
        });
        mock.enqueue(folder_probe_invalid_uri());

        let info = backend
            .stat(
                target("omniverse://srv/Users/alice/foo.usd"),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(info.etag.as_deref(), Some("etag-1"));
        assert_eq!(info.size, Some(1024));
        assert_eq!(info.version.as_deref(), Some("tx-9"));

        let recorded = mock.requests();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].interface, "Connection");
        assert_eq!(recorded[0].method, "stat2");
        assert_eq!(
            recorded[0].params,
            json!({"path": {"path": "/Users/alice/foo.usd"}})
        );
        assert_eq!(
            recorded[1].params,
            json!({"path": {"path": "/Users/alice/foo.usd/"}})
        );
    }

    #[tokio::test]
    async fn stat_tags_folder_path_type_as_directory_kind() {
        // Nucleus has native directory inodes — `Stat2Result.type =
        // "folder"` is authoritative. The dispatcher's marker-fold
        // runs on `list`, not `stat`, so the kind must be set here
        // or a direct stat caller would see `ObjectKind::File` for a
        // real directory.
        //
        // Unannotated addresses (no trailing slash) probe both file
        // and folder shapes in parallel. The file probe fails with
        // INVALID_URI, the folder probe succeeds — its `type: folder`
        // payload must surface as `ObjectKind::Directory`.
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(folder_probe_invalid_uri());
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "stat2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "type": "folder",
                "uri": "/Users/alice/Library",
                "transaction_id": "tx-folder",
            }))],
        });

        let info = backend
            .stat(
                target("omniverse://srv/Users/alice/Library"),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(info.kind, ovstorage_plugin::ObjectKind::Directory);
    }

    #[tokio::test]
    async fn stat_tags_mount_path_type_as_directory_kind() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(folder_probe_invalid_uri());
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "stat2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "type": "mount",
                "uri": "/Projects/Foo",
                "transaction_id": "tx-mount",
            }))],
        });
        let info = backend
            .stat(
                target("omniverse://srv/Projects/Foo"),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(info.kind, ovstorage_plugin::ObjectKind::Directory);
    }

    #[tokio::test]
    async fn stat_maps_unauthenticated_status_to_auth_required() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "stat2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "UNAUTHENTICATED",
            }))],
        });
        let err = backend
            .stat(
                target("omniverse://srv/Users/alice/foo.usd"),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
    }

    #[tokio::test]
    async fn stat_maps_not_exist_status_to_not_found() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "stat2".into(),
            frames: vec![RawFrame::from_json(&json!({"status": "NOT_EXIST"}))],
        });
        let err = backend
            .stat(
                target("omniverse://srv/Users/alice/missing.usd"),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn read_returns_inline_bytes_with_etag_and_size() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "read_asset_version".into(),
            frames: vec![RawFrame::from_json_with_blob(
                &json!({"status": "OK", "etag": "v1", "size": 5}),
                b"hello".to_vec(),
            )],
        });

        let result = backend
            .read(
                target("omniverse://srv/Users/alice/foo.usd"),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap();

        match result {
            ReadResult::Bytes { bytes, info } => {
                assert_eq!(bytes, b"hello");
                assert_eq!(info.size, Some(5));
                assert_eq!(info.etag.as_deref(), Some("v1"));
            }
            other => panic!("expected Bytes, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_passes_message_through_to_create_asset() {
        // `--message "first cut"` ⇒ omni1 create_asset request carries the
        // user-supplied message verbatim. Without this, Nucleus drops the
        // checkpoint message entirely.
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "create_asset".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "etag": "e",
                "transaction_id": 1,
            }))],
        });
        backend
            .write(
                target("omniverse://srv/Users/alice/foo.usd"),
                b"data".to_vec(),
                WriteOptions {
                    message: Some("first cut".into()),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let recorded = mock.requests();
        assert_eq!(recorded[0].method, "create_asset");
        assert_eq!(recorded[0].params["message"], json!("first cut"));
    }

    #[tokio::test]
    async fn write_default_message_is_empty_string() {
        // No `message` set ⇒ wire still carries `"message": ""` so Nucleus
        // creates a checkpoint with an empty annotation. This is the
        // behaviour Bug C established.
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "create_asset".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "etag": "e",
                "transaction_id": 1,
            }))],
        });
        backend
            .write(
                target("omniverse://srv/Users/alice/foo.usd"),
                b"data".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
        let recorded = mock.requests();
        assert_eq!(recorded[0].params["message"], json!(""));
    }

    #[tokio::test]
    async fn copy_passes_message_through_to_copy2() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "copy2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "ts": {},
                "responses": ["OK"],
            }))],
        });
        backend
            .copy(
                target("omniverse://srv/Users/alice/a.usd"),
                target("omniverse://srv/Users/alice/b.usd"),
                CopyOptions {
                    message: Some("dup for review".into()),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let recorded = mock.requests();
        assert_eq!(
            recorded[0].params["paths_to_copy"][0]["message"],
            json!("dup for review")
        );
    }

    #[tokio::test]
    async fn rename_passes_message_through_to_rename2() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "rename2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "ts": {},
                "responses": ["OK"],
            }))],
        });
        backend
            .rename(
                target("omniverse://srv/Users/alice/old.usd"),
                target("omniverse://srv/Users/alice/new.usd"),
                RenameOptions {
                    message: Some("rename for clarity".into()),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        let recorded = mock.requests();
        assert_eq!(
            recorded[0].params["paths_to_rename"][0]["message"],
            json!("rename for clarity")
        );
    }

    #[tokio::test]
    async fn write_creates_asset_with_overwrite_when_no_if_match() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "create_asset".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "etag": "new-etag",
                "transaction_id": 7,
            }))],
        });

        let result = backend
            .write(
                target("omniverse://srv/Users/alice/foo.usd"),
                b"hello".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();

        let recorded = mock.requests();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, "create_asset");
        assert_eq!(
            recorded[0].params["path"],
            json!({"path": "/Users/alice/foo.usd"})
        );
        assert_eq!(recorded[0].params["overwrite"], json!(true));
        assert_eq!(result.info.etag.as_deref(), Some("new-etag"));
        assert_eq!(result.info.version.as_deref(), Some("7"));
    }

    #[tokio::test]
    async fn write_with_if_match_routes_through_update_asset() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "update_asset".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "etag": "v2",
            }))],
        });

        let opts = WriteOptions {
            if_dest: IfDestExists::MatchEtag("v1".into()),
            ..Default::default()
        };
        backend
            .write(
                target("omniverse://srv/Users/alice/foo.usd"),
                b"hi".to_vec(),
                opts,
                None,
            )
            .await
            .unwrap();

        let recorded = mock.requests();
        assert_eq!(recorded[0].method, "update_asset");
        assert_eq!(recorded[0].params["etag"], json!("v1"));
    }

    #[tokio::test]
    async fn write_redirect_without_lft_returns_unsupported() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let err = backend
            .write_redirect(
                target("omniverse://srv/Users/alice/big.bin"),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn continue_write_completes_via_create_asset() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "create_asset".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "etag": "lft-etag",
                "transaction_id": 42,
            }))],
        });

        let cont = NucleusContinuation {
            path: "/Users/alice/big.bin".into(),
            branch: None,
            content_id: 12345,
            if_match_etag: None,
            no_overwrite: false,
            message: None,
        };
        let batch = synthetic_batch(&cont, "http://lft.invalid/content/");
        let results = synthetic_success_result();

        let step = backend
            .continue_write(
                target("omniverse://srv/Users/alice/big.bin"),
                batch,
                results,
                None,
            )
            .await
            .unwrap();

        let recorded = mock.requests();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, "create_asset");
        assert_eq!(recorded[0].params["content_id"], json!(12345));
        assert!(
            recorded[0]
                .params
                .get("content")
                .is_none_or(|v| v.is_null()),
            "create_asset should not carry inline content; got {}",
            recorded[0].params
        );
        match step {
            WriteStep::Done(result) => {
                assert_eq!(result.info.etag.as_deref(), Some("lft-etag"));
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn continue_write_completes_via_update_asset() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "update_asset".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "etag": "v2",
            }))],
        });

        let cont = NucleusContinuation {
            path: "/Users/alice/big.bin".into(),
            branch: None,
            content_id: 999,
            if_match_etag: Some("v1".into()),
            no_overwrite: false,
            message: None,
        };
        let batch = synthetic_batch(&cont, "http://lft.invalid/content/");
        let results = synthetic_success_result();

        backend
            .continue_write(
                target("omniverse://srv/Users/alice/big.bin"),
                batch,
                results,
                None,
            )
            .await
            .unwrap();

        let recorded = mock.requests();
        assert_eq!(recorded[0].method, "update_asset");
        assert_eq!(recorded[0].params["etag"], json!("v1"));
        assert_eq!(recorded[0].params["content_id"], json!(999));
    }

    #[tokio::test]
    async fn continue_write_propagates_redirect_failure() {
        let (_factory, backend, mock) = factory_with_mock().await;
        // No mock enqueued: an unexpected create_asset would panic on empty queue.
        let cont = NucleusContinuation {
            path: "/Users/alice/big.bin".into(),
            branch: None,
            content_id: 7,
            if_match_etag: None,
            no_overwrite: false,
            message: None,
        };
        let batch = synthetic_batch(&cont, "http://lft.invalid/content/");
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 503,
                captured_headers: Vec::new(),
                captured_body: Vec::new(),
            }],
        };

        let err = backend
            .continue_write(
                target("omniverse://srv/Users/alice/big.bin"),
                batch,
                results,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Transient);
        assert_eq!(
            mock.requests().len(),
            0,
            "create_asset must not be called on redirect failure"
        );
    }

    #[tokio::test]
    async fn read_with_uri_redirection_returns_redirect() {
        let (factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "read_asset_version".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "uri_redirection": "https://lft.invalid/content/1234",
            }))],
        });
        let lft_client = Arc::new(
            nucleus_client::LftClient::new(
                "https://lft.invalid".into(),
                0,
                "conn-id-test".into(),
                None,
                Some("connlib-tok".into()),
                None,
                None,
                5 * 1024 * 1024,
            )
            .unwrap(),
        );
        let installed = factory.install_lft_client_for_testing(
            &plugin_address::parse("omniverse://srv/").unwrap(),
            lft_client,
        );
        assert!(installed);

        let result = backend
            .read(
                target("omniverse://srv/Users/alice/big.bin"),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap();
        match result {
            ReadResult::Redirect(redirect) => {
                assert_eq!(redirect.request.method, "GET");
                assert_eq!(redirect.request.url, "https://lft.invalid/content/1234");
                let header_keys: Vec<_> = redirect
                    .request
                    .headers
                    .iter()
                    .map(|(k, _)| k.as_str())
                    .collect();
                assert!(header_keys.contains(&"X-OV-Connection-ID"));
                assert!(header_keys.contains(&"Authorization-Token"));
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    fn synthetic_lft_client(chunk_size: u64) -> Arc<nucleus_client::LftClient> {
        Arc::new(
            nucleus_client::LftClient::new(
                "http://lft.invalid".into(),
                0,
                "conn-id".into(),
                None,
                Some("tok".into()),
                None,
                None,
                chunk_size,
            )
            .unwrap(),
        )
    }

    fn synthetic_lft_info(content_id: u64) -> nucleus_client::LftUploadInfo {
        nucleus_client::LftUploadInfo {
            content_id,
            content_id_str: content_id.to_string(),
            upload_url: "http://lft.invalid/content/".into(),
            headers: Vec::new(),
        }
    }

    fn parsed_target(path: &str) -> crate::address::NucleusTarget {
        crate::address::NucleusTarget {
            server: "srv".into(),
            path: path.into(),
            branch: None,
            checkpoint: None,
        }
    }

    fn content_start_of(headers: &[(String, String)]) -> u64 {
        headers
            .iter()
            .find(|(k, _)| k == "Content-Start")
            .map(|(_, v)| v.parse::<u64>().expect("Content-Start must be numeric"))
            .expect("Content-Start header must be present on every part")
    }

    #[tokio::test]
    async fn build_lft_redirect_batch_emits_single_part_when_size_below_chunk() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let lft = synthetic_lft_client(5 * 1024 * 1024);
        let info = synthetic_lft_info(42);
        let parsed = parsed_target("/Users/alice/small.bin");
        let batch = backend
            .build_lft_redirect_batch(&parsed, &WriteOptions::default(), &lft, &info, 1024 * 1024)
            .unwrap();
        assert_eq!(batch.redirects.len(), 1);
        assert_eq!(content_start_of(&batch.redirects[0].request.headers), 0);
        assert_eq!(
            batch.redirects[0].body_source,
            RedirectBodySource::UserBytes {
                offset: 0,
                len: 1024 * 1024,
            }
        );
    }

    #[tokio::test]
    async fn build_lft_redirect_batch_splits_above_chunk_with_correct_offsets() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let chunk = 5 * 1024 * 1024_u64;
        let lft = synthetic_lft_client(chunk);
        let info = synthetic_lft_info(42);
        let parsed = parsed_target("/Users/alice/big.bin");
        let total = 12 * 1024 * 1024_u64;
        let batch = backend
            .build_lft_redirect_batch(&parsed, &WriteOptions::default(), &lft, &info, total)
            .unwrap();
        assert_eq!(batch.redirects.len(), 3);
        let expected = [
            (0_u64, 5 * 1024 * 1024_u64),
            (5 * 1024 * 1024, 5 * 1024 * 1024),
            (10 * 1024 * 1024, 2 * 1024 * 1024),
        ];
        for (i, (offset, len)) in expected.iter().enumerate() {
            assert_eq!(
                batch.redirects[i].body_source,
                RedirectBodySource::UserBytes {
                    offset: *offset,
                    len: *len,
                },
                "part {i}",
            );
            assert_eq!(
                content_start_of(&batch.redirects[i].request.headers),
                *offset,
                "part {i}: Content-Start mismatch",
            );
            // Same Content-ID across all parts is the protocol contract.
            assert_eq!(
                batch.redirects[i]
                    .request
                    .headers
                    .iter()
                    .find(|(k, _)| k == "Content-ID")
                    .map(|(_, v)| v.as_str()),
                Some("42"),
            );
        }
    }

    #[tokio::test]
    async fn write_redirect_returns_unsupported_when_size_hint_missing() {
        let (factory, backend, _mock) = factory_with_mock().await;
        let lft = synthetic_lft_client(5 * 1024 * 1024);
        let installed = factory.install_lft_client_for_testing(
            &plugin_address::parse("omniverse://srv/").unwrap(),
            lft,
        );
        assert!(installed);
        let err = backend
            .write_redirect(
                target("omniverse://srv/Users/alice/big.bin"),
                WriteOptions {
                    size_hint: None,
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
        assert!(
            err.message().contains("size_hint"),
            "error message should mention size_hint, got {:?}",
            err.message()
        );
    }

    #[tokio::test]
    async fn continue_write_validates_every_part_status() {
        let (_factory, backend, mock) = factory_with_mock().await;
        // Three parts all 200; finalization should fire exactly once.
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "create_asset".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "etag": "lft-etag",
                "transaction_id": 1,
            }))],
        });

        let cont = NucleusContinuation {
            path: "/Users/alice/multi.bin".into(),
            branch: None,
            content_id: 7,
            if_match_etag: None,
            no_overwrite: false,
            message: None,
        };
        let mut batch = synthetic_batch(&cont, "http://lft.invalid/content/");
        let single = batch.redirects[0].clone();
        batch.redirects = vec![single.clone(), single.clone(), single];
        let results = RedirectResultBatch {
            results: vec![
                RedirectResult {
                    status_code: 200,
                    captured_headers: Vec::new(),
                    captured_body: Vec::new(),
                };
                3
            ],
        };

        backend
            .continue_write(
                target("omniverse://srv/Users/alice/multi.bin"),
                batch,
                results,
                None,
            )
            .await
            .unwrap();
        assert_eq!(mock.requests().len(), 1);
        assert_eq!(mock.requests()[0].method, "create_asset");
    }

    #[tokio::test]
    async fn continue_write_propagates_failure_with_part_index() {
        let (_factory, backend, mock) = factory_with_mock().await;
        let cont = NucleusContinuation {
            path: "/Users/alice/multi.bin".into(),
            branch: None,
            content_id: 7,
            if_match_etag: None,
            no_overwrite: false,
            message: None,
        };
        let mut batch = synthetic_batch(&cont, "http://lft.invalid/content/");
        let single = batch.redirects[0].clone();
        batch.redirects = vec![single.clone(), single.clone(), single];
        let results = RedirectResultBatch {
            results: vec![
                RedirectResult {
                    status_code: 200,
                    captured_headers: Vec::new(),
                    captured_body: Vec::new(),
                },
                RedirectResult {
                    status_code: 503,
                    captured_headers: Vec::new(),
                    captured_body: Vec::new(),
                },
                RedirectResult {
                    status_code: 200,
                    captured_headers: Vec::new(),
                    captured_body: Vec::new(),
                },
            ],
        };
        let err = backend
            .continue_write(
                target("omniverse://srv/Users/alice/multi.bin"),
                batch,
                results,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Transient);
        assert!(
            err.message().contains("part 2"),
            "error should name the failing part: {:?}",
            err.message()
        );
        assert_eq!(
            mock.requests().len(),
            0,
            "create_asset must not run when any part failed",
        );
    }

    fn synthetic_batch(cont: &NucleusContinuation, url: &str) -> WriteRedirectBatch {
        let expires = SystemTime::now() + Duration::from_secs(60);
        WriteRedirectBatch {
            continuation: encode_nucleus_continuation(cont),
            redirects: vec![WriteRedirect {
                request: HttpRequest {
                    method: "PUT".into(),
                    url: url.into(),
                    headers: Vec::new(),
                },
                body_source: RedirectBodySource::UserBytes { offset: 0, len: 0 },
                result_capture: ResultCapture::default(),
                expires_at: expires,
                scope: RedirectScope {
                    physical_url_prefix: url.into(),
                    operations: AccessOps {
                        write: true,
                        ..AccessOps::default()
                    },
                    expires_at: expires,
                },
                audit_id: "test-audit".into(),
                policy_epoch: 0,
            }],
        }
    }

    fn synthetic_success_result() -> RedirectResultBatch {
        RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: Vec::new(),
            }],
        }
    }

    #[tokio::test]
    async fn delete_routes_through_delete2() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "delete2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "responses": ["OK"],
            }))],
        });

        backend
            .delete(
                target("omniverse://srv/Users/alice/foo.usd"),
                DeleteOptions::default(),
                None,
            )
            .await
            .unwrap();

        let recorded = mock.requests();
        assert_eq!(recorded[0].method, "delete2");
        assert_eq!(
            recorded[0].params["paths_to_delete"],
            json!([{"path": "/Users/alice/foo.usd"}])
        );
    }

    #[tokio::test]
    async fn list_translates_directory_entries_into_subdirectories_and_objects() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "list2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "DONE",
                "entries": [
                    {"path": "/Users/alice/sub", "path_type": "folder"},
                    {"path": "/Users/alice/foo.usd", "path_type": "asset", "size": 17, "etag": "e1"},
                ],
            }))],
        });

        let items = backend
            .list(
                target("omniverse://srv/Users/alice/"),
                ListOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].address.as_str(), "omniverse://srv/Users/alice/sub");
        assert_eq!(items[0].kind, ObjectKind::Directory);
        assert_eq!(
            items[1].address.as_str(),
            "omniverse://srv/Users/alice/foo.usd"
        );
        assert_eq!(items[1].kind, ObjectKind::File);
        assert_eq!(items[1].size, Some(17));
        assert_eq!(items[1].etag.as_deref(), Some("e1"));
    }

    #[tokio::test]
    async fn list_versions_maps_get_checkpoints_to_pinned_addresses() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "get_checkpoints".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "checkpoints": [
                    {"status": "OK", "checkpoint_id": 3, "message": "third"},
                    {"status": "OK", "checkpoint_id": 1, "message": "first"},
                ],
            }))],
        });

        let versions = backend
            .list_versions(
                target("omniverse://srv/Users/alice/foo.usd"),
                ListVersionsOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(
            versions[0].address.as_str(),
            "omniverse://srv/Users/alice/foo.usd?&3"
        );
        assert_eq!(versions[0].version.as_deref(), Some("3"));
    }

    #[tokio::test]
    async fn check_access_filters_to_authenticated_principal_only() {
        let (factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "get_acl_resolved".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "ts": {},
                "responses": [
                    {
                        "status": "OK",
                        "acl": {
                            "alice": {"acl": ["read"], "path": "/"},
                            "writers": {"acl": ["write"], "path": "/"}
                        }
                    }
                ]
            }))],
        });
        let root = plugin_address::parse("omniverse://srv/").unwrap();
        factory.install_session_for_testing(
            &root,
            NucleusSession {
                access_token: "at".into(),
                refresh_token: None,
                tokens_url: "wss://srv/tokens".into(),
                principal: "alice".into(),
            },
        );

        let decision = backend
            .check_access(
                target("omniverse://srv/Users/alice/foo.usd"),
                AccessOps {
                    read: true,
                    write: true,
                    delete: false,
                    update_metadata: false,
                },
                None,
            )
            .await
            .unwrap();
        assert!(
            !decision.allowed,
            "alice has only read; write must be denied: {decision:?}"
        );
        assert!(!decision.denied_ops.read);
        assert!(decision.denied_ops.write);
    }

    #[tokio::test]
    async fn check_access_denies_when_principal_unknown() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "get_acl_resolved".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "ts": {},
                "responses": [
                    {
                        "status": "OK",
                        "acl": {
                            "alice": {"acl": ["read", "write"], "path": "/"}
                        }
                    }
                ]
            }))],
        });

        let decision = backend
            .check_access(
                target("omniverse://srv/Users/alice/foo.usd"),
                AccessOps {
                    read: true,
                    write: true,
                    delete: false,
                    update_metadata: false,
                },
                None,
            )
            .await
            .unwrap();
        assert!(!decision.allowed);
        assert!(decision.denied_ops.read);
        assert!(decision.denied_ops.write);
        assert_eq!(
            decision.reason.as_deref(),
            Some("nucleus principal unknown")
        );
    }

    #[tokio::test]
    async fn copy_routes_through_copy2_with_paired_paths() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "copy2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "ts": {},
                "responses": ["OK"],
            }))],
        });

        backend
            .copy(
                target("omniverse://srv/Users/alice/foo.usd"),
                target("omniverse://srv/Users/alice/foo-copy.usd"),
                CopyOptions::default(),
                None,
            )
            .await
            .unwrap();

        let recorded = mock.requests();
        assert_eq!(recorded[0].method, "copy2");
        // `message: ""` is required: omitting it tells Nucleus to skip the
        // checkpoint, so list-versions never sees the rename/copy.
        assert_eq!(
            recorded[0].params["paths_to_copy"],
            json!([{
                "src": {"path": "/Users/alice/foo.usd"},
                "dst": {"path": "/Users/alice/foo-copy.usd"},
                "message": ""
            }])
        );
    }

    #[tokio::test]
    async fn rename_routes_through_rename2_with_paired_paths() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "rename2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "ts": {},
                "responses": ["OK"],
            }))],
        });

        backend
            .rename(
                target("omniverse://srv/Users/alice/old.usd"),
                target("omniverse://srv/Users/alice/new.usd"),
                RenameOptions::default(),
                None,
            )
            .await
            .unwrap();

        let recorded = mock.requests();
        assert_eq!(recorded[0].method, "rename2");
    }

    // Checkpoint-guard tests: omni1's PathAtBranch-typed write/delete/rename
    // ops have no version field, so the plugin's `reject_checkpoint` guard
    // refuses mutating ops on a `?checkpoint=N` address before silently
    // operating on the head. Read-side ops (stat/read/cp source) go through
    // path_at_version and accept the version selector; covered separately.

    fn checkpoint_target() -> ResolvedTarget {
        target("omniverse://srv/Users/alice/foo.usd?checkpoint=1")
    }

    fn checkpoint_assert_invalid(err: ovstorage_plugin::Error, op_label: &str) {
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            err.message().contains("checkpoint"),
            "{op_label}: error should mention checkpoint, got {:?}",
            err.message()
        );
    }

    #[tokio::test]
    async fn write_rejects_checkpoint_address() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let err = backend
            .write(
                checkpoint_target(),
                b"data".to_vec(),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        checkpoint_assert_invalid(err, "write");
    }

    #[tokio::test]
    async fn write_stream_rejects_checkpoint_address() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let stream = ovstorage_plugin::BodyStream::from_iter(std::iter::empty());
        let err = backend
            .write_stream(checkpoint_target(), stream, WriteOptions::default(), None)
            .await
            .unwrap_err();
        checkpoint_assert_invalid(err, "write_stream");
    }

    #[tokio::test]
    async fn write_redirect_rejects_checkpoint_address() {
        let (factory, backend, _mock) = factory_with_mock().await;
        let lft = synthetic_lft_client(5 * 1024 * 1024);
        let installed = factory.install_lft_client_for_testing(
            &plugin_address::parse("omniverse://srv/").unwrap(),
            lft,
        );
        assert!(installed);
        let err = backend
            .write_redirect(
                checkpoint_target(),
                WriteOptions {
                    size_hint: Some(1024),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap_err();
        checkpoint_assert_invalid(err, "write_redirect");
    }

    #[tokio::test]
    async fn delete_rejects_checkpoint_address() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let err = backend
            .delete(checkpoint_target(), DeleteOptions::default(), None)
            .await
            .unwrap_err();
        checkpoint_assert_invalid(err, "delete");
    }

    #[tokio::test]
    async fn rename_rejects_checkpoint_source() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let err = backend
            .rename(
                checkpoint_target(),
                target("omniverse://srv/Users/alice/dest.usd"),
                RenameOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        checkpoint_assert_invalid(err, "rename source");
    }

    #[tokio::test]
    async fn rename_rejects_checkpoint_destination() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let err = backend
            .rename(
                target("omniverse://srv/Users/alice/foo.usd"),
                checkpoint_target(),
                RenameOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        checkpoint_assert_invalid(err, "rename destination");
    }

    #[tokio::test]
    async fn copy_rejects_checkpoint_destination() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let err = backend
            .copy(
                target("omniverse://srv/Users/alice/foo.usd"),
                checkpoint_target(),
                CopyOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        checkpoint_assert_invalid(err, "copy destination");
    }

    #[tokio::test]
    async fn copy_allows_checkpoint_source() {
        // Positive control: source with `?checkpoint=1` should reach copy2
        // with the version selector in the source path; only destination
        // is rejected.
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "copy2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "ts": {},
                "responses": ["OK"],
            }))],
        });
        backend
            .copy(
                checkpoint_target(),
                target("omniverse://srv/Users/alice/dest.usd"),
                CopyOptions::default(),
                None,
            )
            .await
            .unwrap();
        let recorded = mock.requests();
        assert_eq!(recorded[0].method, "copy2");
        // Source path carries the checkpoint selector; dst does not.
        let src = &recorded[0].params["paths_to_copy"][0]["src"];
        assert_eq!(src["checkpoint"], json!(1));
    }

    #[tokio::test]
    async fn create_directory_routes_through_create_directory_endpoint() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "create_directory".into(),
            frames: vec![RawFrame::from_json(&json!({"status": "OK", "ts": {}}))],
        });

        backend
            .create_directory(
                target("omniverse://srv/Users/alice/new-folder/"),
                CreateDirectoryOptions::default(),
                None,
            )
            .await
            .unwrap();

        let recorded = mock.requests();
        assert_eq!(recorded[0].method, "create_directory");
        assert_eq!(
            recorded[0].params["path"],
            json!({"path": "/Users/alice/new-folder/"})
        );
    }

    #[tokio::test]
    async fn watch_directory_translates_subscribe_list_events() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "subscribe_list".into(),
            frames: vec![
                RawFrame::from_json(&json!({
                    "status": "OK",
                    "event": "create",
                    "entry": {"path": "/Users/alice/new.usd", "etag": "e1", "size": 9},
                })),
                RawFrame::from_json(&json!({
                    "status": "OK",
                    "event": "delete",
                    "entry": {"path": "/Users/alice/gone.usd"},
                })),
            ],
        });

        let mut stream = backend
            .watch_directory(
                target("omniverse://srv/Users/alice/"),
                WatchDirectoryOptions::default(),
                None,
            )
            .await
            .unwrap();

        let first = stream.next().unwrap().unwrap();
        match first {
            BackendChangeEvent::Object { address, kind, .. } => {
                assert_eq!(address.as_str(), "omniverse://srv/Users/alice/new.usd");
                assert_eq!(kind, ChangeKind::Created);
            }
            other => panic!("expected Object event, got {other:?}"),
        }
        let second = stream.next().unwrap().unwrap();
        match second {
            BackendChangeEvent::Object { address, kind, .. } => {
                assert_eq!(address.as_str(), "omniverse://srv/Users/alice/gone.usd");
                assert_eq!(kind, ChangeKind::Deleted);
            }
            other => panic!("expected Object event, got {other:?}"),
        }
        // Drained subscription surfaces a single Lapsed so the host learns the watch is stale.
        match stream.next().unwrap().unwrap() {
            BackendChangeEvent::Lapsed { .. } => {}
            other => panic!("expected Lapsed, got {other:?}"),
        }
        assert!(stream.next().is_none());
    }

    /// Field values are immaterial; the override bypasses the production refresh path.
    fn synthetic_session() -> NucleusSession {
        NucleusSession {
            access_token: "test-access".into(),
            refresh_token: Some("test-refresh".into()),
            tokens_url: "wss://test.invalid/tokens".into(),
            principal: "test-user".into(),
        }
    }

    /// `TokenExpired` -> `AuthExpired` so both `with_refresh` and the dispatcher's
    /// `with_route_retry` invalidation hook can react.
    #[tokio::test]
    async fn stat_maps_token_expired_to_auth_expired_after_failed_refresh() {
        let (factory, backend, mock) = factory_with_mock().await;
        // Both attempts see TOKEN_EXPIRED so the one-shot retry exhausts.
        // Each attempt fires a parallel file+folder probe -> 4 enqueues total.
        for _ in 0..4 {
            mock.enqueue(CannedResponse {
                interface: "Connection".into(),
                method: "stat2".into(),
                frames: vec![RawFrame::from_json(&json!({"status": "TOKEN_EXPIRED"}))],
            });
        }
        let root = plugin_address::parse("omniverse://srv/").unwrap();
        let original_ops = factory.snapshot_ops_for_testing(&root).unwrap();
        let installed = factory.install_refresh_override_for_testing(
            &root,
            std::sync::Arc::new(move || {
                Ok((
                    std::sync::Arc::clone(&original_ops),
                    None,
                    synthetic_session(),
                ))
            }),
        );
        assert!(installed);

        let err = backend
            .stat(
                target("omniverse://srv/Users/alice/foo.usd"),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthExpired);
        assert_eq!(mock.requests().len(), 4);
        // Epoch bumps because the override "succeeded"; the SPI failure does not roll it back.
        assert_eq!(factory.cred_epoch_for_testing(&root), Some(1));
    }

    /// `TOKEN_EXPIRED` then `OK` -> single retry, second call observes success.
    #[tokio::test]
    async fn stat_succeeds_after_one_shot_refresh_retry() {
        let (factory, backend, mock) = factory_with_mock().await;
        // First attempt: both file + folder probes hit TOKEN_EXPIRED.
        for _ in 0..2 {
            mock.enqueue(CannedResponse {
                interface: "Connection".into(),
                method: "stat2".into(),
                frames: vec![RawFrame::from_json(&json!({"status": "TOKEN_EXPIRED"}))],
            });
        }
        // Retry: file probe gets OK, folder probe gets INVALID_URI.
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "stat2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "type": "asset",
                "uri": "/Users/alice/foo.usd",
                "etag": "etag-1",
                "size": 7,
                "modified_date_seconds": 1700000000,
                "transaction_id": "tx-1",
            }))],
        });
        mock.enqueue(folder_probe_invalid_uri());
        let root = plugin_address::parse("omniverse://srv/").unwrap();
        let original_ops = factory.snapshot_ops_for_testing(&root).unwrap();
        let refresh_count = std::sync::Arc::new(AtomicU64::new(0));
        let counter = std::sync::Arc::clone(&refresh_count);
        let installed = factory.install_refresh_override_for_testing(
            &root,
            std::sync::Arc::new(move || {
                counter.fetch_add(1, Ordering::AcqRel);
                Ok((
                    std::sync::Arc::clone(&original_ops),
                    None,
                    synthetic_session(),
                ))
            }),
        );
        assert!(installed);

        let info = backend
            .stat(
                target("omniverse://srv/Users/alice/foo.usd"),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(info.etag.as_deref(), Some("etag-1"));
        assert_eq!(refresh_count.load(Ordering::Acquire), 1);
        assert_eq!(factory.cred_epoch_for_testing(&root), Some(1));
        assert_eq!(mock.requests().len(), 4);
    }

    /// N racing `stat`s observe `TOKEN_EXPIRED` and collapse to one refresh callback via `refresh_lock`.
    /// The 50ms `std::thread::sleep` in the override gives every task time to queue on the lock
    /// before the first holder bumps `cred_epoch`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_token_expired_collapses_to_single_refresh() {
        let (factory, backend, mock) = factory_with_mock().await;
        const N: usize = 5;
        // Each stat fires parallel file+folder probes. First attempt: 2N
        // TOKEN_EXPIRED responses — any matching stat2 consumes one in
        // FIFO order. Retry: N file-OK keyed on the file path + N
        // folder-INVALID keyed on the folder path. Path-keying makes the
        // retry phase order-independent across the N racing tasks; without
        // it, the test was 50%-flaky because two tasks could both pull
        // INVALID responses by accident.
        let file_path = "/Users/alice/foo.usd";
        let folder_path = "/Users/alice/foo.usd/";
        for _ in 0..(2 * N) {
            mock.enqueue(CannedResponse {
                interface: "Connection".into(),
                method: "stat2".into(),
                frames: vec![RawFrame::from_json(&json!({"status": "TOKEN_EXPIRED"}))],
            });
        }
        for _ in 0..N {
            mock.enqueue_for_path(
                CannedResponse {
                    interface: "Connection".into(),
                    method: "stat2".into(),
                    frames: vec![RawFrame::from_json(&json!({
                        "status": "OK",
                        "type": "asset",
                        "uri": "/x",
                        "etag": "e1",
                        "size": 1,
                        "transaction_id": "1",
                    }))],
                },
                file_path,
            );
            mock.enqueue_for_path(folder_probe_invalid_uri(), folder_path);
        }
        let root = plugin_address::parse("omniverse://srv/").unwrap();
        let original_ops = factory.snapshot_ops_for_testing(&root).unwrap();
        let refresh_count = std::sync::Arc::new(AtomicU64::new(0));
        let counter = std::sync::Arc::clone(&refresh_count);
        let installed = factory.install_refresh_override_for_testing(
            &root,
            std::sync::Arc::new(move || {
                // 50ms is long enough for all N tasks to queue on `refresh_lock`.
                std::thread::sleep(std::time::Duration::from_millis(50));
                counter.fetch_add(1, Ordering::AcqRel);
                Ok((
                    std::sync::Arc::clone(&original_ops),
                    None,
                    synthetic_session(),
                ))
            }),
        );
        assert!(installed);

        let mut joins = Vec::with_capacity(N);
        for _ in 0..N {
            let backend = std::sync::Arc::clone(&backend);
            joins.push(tokio::spawn(async move {
                backend
                    .stat(
                        target("omniverse://srv/Users/alice/foo.usd"),
                        StatOptions::default(),
                        None,
                    )
                    .await
            }));
        }
        for join in joins {
            join.await.unwrap().unwrap();
        }
        assert_eq!(
            refresh_count.load(Ordering::Acquire),
            1,
            "concurrent token-expired should collapse onto a single refresh"
        );
        assert_eq!(factory.cred_epoch_for_testing(&root), Some(1));
    }

    /// Guards the split between `Unauthenticated -> AuthRequired` and `TokenExpired -> AuthExpired`.
    #[tokio::test]
    async fn stat_maps_unauthenticated_status_to_auth_required_distinct_from_expired() {
        let (_factory, backend, mock) = factory_with_mock().await;
        for _ in 0..2 {
            mock.enqueue(CannedResponse {
                interface: "Connection".into(),
                method: "stat2".into(),
                frames: vec![RawFrame::from_json(&json!({"status": "UNAUTHENTICATED"}))],
            });
        }
        let err = backend
            .stat(
                target("omniverse://srv/Users/alice/foo.usd"),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        assert_eq!(mock.requests().len(), 2);
    }

    /// `Unauthenticated` -> `AuthRequired` carries `ErrorContext::Auth { reason: "status_unauthenticated" }`.
    #[tokio::test]
    async fn stat_maps_unauthenticated_with_auth_context_populated() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "stat2".into(),
            frames: vec![RawFrame::from_json(&json!({"status": "UNAUTHENTICATED"}))],
        });
        let err = backend
            .stat(
                target("omniverse://srv/Users/alice/foo.usd"),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ovstorage_plugin::ErrorContext::Auth {
                reason, expired_at, ..
            }) => {
                assert_eq!(reason.as_deref(), Some("status_unauthenticated"));
                assert!(expired_at.is_none());
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    /// `Denied` -> `PermissionDenied` (terminal, no Auth context).
    #[tokio::test]
    async fn stat_maps_denied_status_to_permission_denied_no_context() {
        let (_factory, backend, mock) = factory_with_mock().await;
        for _ in 0..2 {
            mock.enqueue(CannedResponse {
                interface: "Connection".into(),
                method: "stat2".into(),
                frames: vec![RawFrame::from_json(&json!({"status": "DENIED"}))],
            });
        }
        let err = backend
            .stat(
                target("omniverse://srv/Users/alice/foo.usd"),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.context().is_none());
        assert_eq!(mock.requests().len(), 2);
    }

    #[tokio::test]
    async fn instantiate_with_different_prefix_rejects_invalid_argument() {
        let factory = NucleusBackendFactory::new();
        let mut config1 = HashMap::new();
        config1.insert("server".into(), ConfigValue::String("srv".into()));
        let req1 = ConnectionRequest {
            backend_kind: NUCLEUS_KIND.into(),
            config: config1,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        };
        factory.instantiate(&req1, None).await.unwrap();

        let mut config2 = HashMap::new();
        config2.insert("server".into(), ConfigValue::String("srv".into()));
        config2.insert("prefix".into(), ConfigValue::String("/Projects".into()));
        let req2 = ConnectionRequest {
            backend_kind: NUCLEUS_KIND.into(),
            config: config2,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        };
        let err = match factory.instantiate(&req2, None).await {
            Ok(_) => panic!("expected InvalidArgument; got Ok"),
            Err(e) => e,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn read_with_range_returns_unsupported() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let opts = ReadOptions {
            range: Some(ovstorage_plugin::ByteRange {
                start: 0,
                end_inclusive: Some(15),
            }),
            ..Default::default()
        };
        let err = backend
            .read(target("omniverse://srv/Users/alice/foo.usd"), opts, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn delete_with_if_match_returns_unsupported() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let opts = DeleteOptions {
            if_match: Some("v1".into()),
        };
        let err = backend
            .delete(target("omniverse://srv/Users/alice/foo.usd"), opts, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn copy_with_if_match_returns_unsupported() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let opts = CopyOptions {
            if_source: Some("v1".into()),
            ..Default::default()
        };
        let err = backend
            .copy(
                target("omniverse://srv/Users/alice/foo.usd"),
                target("omniverse://srv/Users/alice/bar.usd"),
                opts,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn rename_with_if_match_returns_unsupported() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let opts = RenameOptions {
            if_source: Some("v1".into()),
            ..Default::default()
        };
        let err = backend
            .rename(
                target("omniverse://srv/Users/alice/foo.usd"),
                target("omniverse://srv/Users/alice/bar.usd"),
                opts,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn list_with_page_token_returns_unsupported() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let opts = ListOptions {
            page_token: Some("opaque".into()),
            ..Default::default()
        };
        let err = backend
            .list(target("omniverse://srv/Users/alice/"), opts, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn list_truncates_to_max_results() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "list2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "DONE",
                "entries": [
                    {"path": "/Users/alice/a", "path_type": "asset", "size": 1, "etag": "e1"},
                    {"path": "/Users/alice/b", "path_type": "asset", "size": 1, "etag": "e2"},
                    {"path": "/Users/alice/c", "path_type": "asset", "size": 1, "etag": "e3"},
                ],
            }))],
        });
        let opts = ListOptions {
            max_results: Some(2),
            ..Default::default()
        };
        let items = backend
            .list(target("omniverse://srv/Users/alice/"), opts, None)
            .await
            .unwrap();
        assert_eq!(items.len(), 2);
    }

    #[tokio::test]
    async fn stat_observes_pre_cancelled_token() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let token = ovstorage_plugin::CancellationToken::new();
        token.cancel();
        let err = backend
            .stat(
                target("omniverse://srv/Users/alice/foo.usd"),
                StatOptions::default(),
                Some(token),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn watch_directory_emits_backend_addresses_under_root() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "subscribe_list".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "event": "create",
                "entry": {"path": "/foo.usd", "etag": "e", "size": 1},
            }))],
        });
        let mut stream = backend
            .watch_directory(
                target("omniverse://srv/"),
                WatchDirectoryOptions::default(),
                None,
            )
            .await
            .unwrap();
        match stream.next().unwrap().unwrap() {
            BackendChangeEvent::Object { address, .. } => {
                assert_eq!(address.as_str(), "omniverse://srv/foo.usd");
            }
            other => panic!("expected Object event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn watch_directory_with_since_emits_lapsed_only() {
        let (_factory, backend, _mock) = factory_with_mock().await;
        let opts = WatchDirectoryOptions {
            since: Some(ovstorage_plugin::WatchDirectoryCursor(b"opaque".to_vec())),
            ..Default::default()
        };
        let mut stream = backend
            .watch_directory(target("omniverse://srv/Users/alice/"), opts, None)
            .await
            .unwrap();
        match stream.next().unwrap().unwrap() {
            BackendChangeEvent::Lapsed { .. } => {}
            other => panic!("expected Lapsed, got {other:?}"),
        }
        assert!(stream.next().is_none());
    }

    #[tokio::test]
    async fn watch_directory_non_recursive_drops_descendant_events() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "subscribe_list".into(),
            frames: vec![
                RawFrame::from_json(&json!({
                    "status": "OK",
                    "event": "create",
                    "entry": {"path": "/Users/alice/sub/deep.usd"},
                })),
                RawFrame::from_json(&json!({
                    "status": "OK",
                    "event": "create",
                    "entry": {"path": "/Users/alice/top.usd"},
                })),
            ],
        });
        let mut stream = backend
            .watch_directory(
                target("omniverse://srv/Users/alice/"),
                WatchDirectoryOptions::default(),
                None,
            )
            .await
            .unwrap();
        match stream.next().unwrap().unwrap() {
            BackendChangeEvent::Object { address, .. } => {
                assert_eq!(address.as_str(), "omniverse://srv/Users/alice/top.usd");
            }
            other => panic!("expected Object event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn watch_directory_drops_metadata_events_when_disabled() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "subscribe_list".into(),
            frames: vec![
                RawFrame::from_json(&json!({
                    "status": "OK",
                    "event": "change_acl",
                    "entry": {"path": "/Users/alice/foo.usd"},
                })),
                RawFrame::from_json(&json!({
                    "status": "OK",
                    "event": "create",
                    "entry": {"path": "/Users/alice/bar.usd"},
                })),
            ],
        });
        let opts = WatchDirectoryOptions {
            include_metadata_changes: false,
            ..Default::default()
        };
        let mut stream = backend
            .watch_directory(target("omniverse://srv/Users/alice/"), opts, None)
            .await
            .unwrap();
        match stream.next().unwrap().unwrap() {
            BackendChangeEvent::Object { address, kind, .. } => {
                assert_eq!(address.as_str(), "omniverse://srv/Users/alice/bar.usd");
                assert_eq!(kind, ChangeKind::Created);
            }
            other => panic!("expected Object event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list2_pre_terminal_close_surfaces_transient_error() {
        let (_factory, backend, mock) = factory_with_mock().await;
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "list2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "entries": [{"path": "/Users/alice/a", "path_type": "asset"}],
            }))],
        });
        let err = backend
            .list(
                target("omniverse://srv/Users/alice/"),
                ListOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Transient);
    }

    #[tokio::test]
    async fn re_authenticate_with_no_lft_clears_prior_lft_client() {
        let (factory, backend, mock) = factory_with_mock().await;
        for _ in 0..2 {
            mock.enqueue(CannedResponse {
                interface: "Connection".into(),
                method: "stat2".into(),
                frames: vec![RawFrame::from_json(&json!({"status": "TOKEN_EXPIRED"}))],
            });
        }
        let root = plugin_address::parse("omniverse://srv/").unwrap();
        let lft = Arc::new(
            nucleus_client::LftClient::new(
                "https://lft.invalid".into(),
                0,
                "conn-id".into(),
                None,
                Some("connlib-tok".into()),
                None,
                None,
                5 * 1024 * 1024,
            )
            .unwrap(),
        );
        factory.install_lft_client_for_testing(&root, lft);
        assert!(factory.lft_client_for_testing(&root).is_some());
        let original_ops = factory.snapshot_ops_for_testing(&root).unwrap();
        factory.install_refresh_override_for_testing(
            &root,
            std::sync::Arc::new(move || {
                Ok((
                    std::sync::Arc::clone(&original_ops),
                    None,
                    synthetic_session(),
                ))
            }),
        );
        let _ = backend
            .stat(
                target("omniverse://srv/Users/alice/foo.usd"),
                StatOptions::default(),
                None,
            )
            .await;
        assert!(factory.lft_client_for_testing(&root).is_none());
    }
}
