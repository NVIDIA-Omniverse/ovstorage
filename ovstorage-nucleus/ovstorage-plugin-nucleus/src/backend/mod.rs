// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native Nucleus backend module.
//!
//! - `session` — `NucleusShared` (the live session cell) + handshake
//!   install/refresh machinery
//! - `spi` — `NucleusBackend` object/data operations (inherent methods since
//!   the ABI-v2 port; the `Layer` slots delegate here)
//! - `convert` — pure-data conversions between omni1 wire types and SPI types
//! - `watch` — sync `Iterator` adapter over the async `subscribe_list` pump

mod convert;
pub(crate) mod session;
pub(crate) mod spi;
mod watch;

pub use spi::NucleusBackend;

#[cfg(test)]
mod tests {
    use super::session::NucleusShared;
    use super::spi::{NucleusBackend, native_capabilities};
    use std::collections::HashMap;
    use std::sync::Arc;

    use ovstorage_plugin::connection::ConnectionAuthDriver as _;
    use ovstorage_plugin::{
        AuthEvent, BackendId, ConfigLayer, ConfigValue, ConnectionAuthState, ConnectionId,
        ConnectionRequest, ConnectionSource, ErrorCode, InteractiveAuthCapability, ReadOptions,
        ResolvedTarget, Result, SecretBundle, SecretBytes, SecretValue, Url, UserMetadata,
    };

    use crate::address::{NUCLEUS_KIND, parse_nucleus_address};
    use crate::config::NucleusConfig;
    use crate::driver::NucleusDriver;
    use crate::layer::kind_descriptor;

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

    fn shared_for(request: &ConnectionRequest) -> Arc<NucleusShared> {
        let config = NucleusConfig::from_request(request).unwrap();
        NucleusShared::new(config, request.credentials.clone())
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
        let descriptor = kind_descriptor();
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

    /// The connection's root and capabilities are config-derived: no auth and
    /// no network access is required.
    #[test]
    fn config_derives_root_and_capabilities() {
        let request = request("nucleus.local");
        let shared = shared_for(&request);
        assert_eq!(
            shared.config.root,
            Url::parse("omniverse://nucleus.local/").unwrap()
        );
        let caps = native_capabilities();
        assert!(caps.supports_list);
        assert!(caps.wants_list_backed_stat);
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
        let request = request("srv");
        let backend = NucleusBackend::from_shared(shared_for(&request));
        let error = backend
            .read(
                target("omniverse://srv/Users/alice/foo.usd"),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::AuthRequired);
    }

    // === driver `interactive` credential dispatch ===
    //
    // Hitting a real Nucleus is the integration-test workspace's job; these
    // verify each credential shape drives (and fails) the REAL handshake
    // against an unreachable host instead of synthesizing `Succeeded`.

    /// A bundle carrying BOTH an api_token and username/password material is
    /// refused as ambiguous — precedence would silently drop the pair, the
    /// "succeeds as the wrong shape" hazard the field allowlist prevents.
    #[tokio::test]
    async fn obtain_rejects_ambiguous_multi_shape_bundle() {
        use ovstorage_plugin::connection::{ConnectionAuthDriver as _, GrantPolicy};
        let mut request = request("srv");
        for (key, value) in [("api_token", "tok"), ("username", "u"), ("password", "p")] {
            request.credentials.fields.insert(
                key.into(),
                SecretValue::Bytes(SecretBytes(value.as_bytes().to_vec())),
            );
        }
        let driver = NucleusDriver::new(shared_for(&request));
        let err = driver
            .obtain(&request.credentials, GrantPolicy::AllowConsuming, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("ambiguous"), "{}", err.message());
    }

    /// Presence semantics match `classify_credentials` (empty value ==
    /// absent): a present-but-empty password is HALF a pair, refused up
    /// front — not silently reclassified `Missing` → `AwaitingInteractive`.
    #[tokio::test]
    async fn obtain_treats_empty_password_as_half_pair() {
        use ovstorage_plugin::connection::{ConnectionAuthDriver as _, GrantPolicy};
        let mut request = request("srv");
        request.credentials.fields.insert(
            "username".into(),
            SecretValue::Bytes(SecretBytes(b"alice".to_vec())),
        );
        request
            .credentials
            .fields
            .insert("password".into(), SecretValue::Bytes(SecretBytes(vec![])));
        let driver = NucleusDriver::new(shared_for(&request));
        let err = driver
            .obtain(&request.credentials, GrantPolicy::AllowConsuming, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
    }

    async fn interactive_events(
        request: &ConnectionRequest,
        capability: InteractiveAuthCapability,
    ) -> Vec<AuthEvent> {
        let shared = shared_for(request);
        let driver = NucleusDriver::new(shared);
        let connection = synthetic_connection(
            &[Url::parse(&format!(
                "omniverse://{}/",
                request
                    .config
                    .get("server")
                    .and_then(|v| match v {
                        ConfigValue::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .unwrap()
            ))
            .unwrap()],
            request.credentials.clone(),
        );
        driver
            .interactive(connection, capability, None)
            .await
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap()
    }

    #[tokio::test]
    async fn interactive_with_api_token_drives_real_handshake_and_fails_on_unreachable_host() {
        let mut request = request("nucleus.invalid");
        request.credentials.fields.insert(
            "api_token".into(),
            SecretValue::Bytes(SecretBytes(b"abc".to_vec())),
        );
        let events = interactive_events(&request, InteractiveAuthCapability::Browser).await;
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
    async fn interactive_with_username_password_drives_real_handshake_and_fails_on_unreachable_host()
     {
        let mut request = request("nucleus.invalid");
        request.credentials.fields.insert(
            "username".into(),
            SecretValue::Bytes(SecretBytes(b"alice".to_vec())),
        );
        request.credentials.fields.insert(
            "password".into(),
            SecretValue::Bytes(SecretBytes(b"hunter2".to_vec())),
        );
        let events = interactive_events(&request, InteractiveAuthCapability::Browser).await;
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
    async fn interactive_with_username_password_runs_under_capability_none() {
        let mut request = request("nucleus.invalid");
        request.credentials.fields.insert(
            "username".into(),
            SecretValue::Bytes(SecretBytes(b"alice".to_vec())),
        );
        request.credentials.fields.insert(
            "password".into(),
            SecretValue::Bytes(SecretBytes(b"hunter2".to_vec())),
        );
        let events = interactive_events(&request, InteractiveAuthCapability::None).await;
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], AuthEvent::Progress { .. }));
        assert!(matches!(events[1], AuthEvent::Failed { .. }));
    }

    /// Without creds AND without an interactive capability, no path can drive a
    /// handshake — surface the legacy `AuthRequired` failure event.
    #[tokio::test]
    async fn interactive_without_credentials_under_capability_none_emits_auth_required() {
        let events = interactive_events(&request("srv"), InteractiveAuthCapability::None).await;
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
    async fn interactive_without_credentials_with_capability_drives_interactive_handshake() {
        let events = interactive_events(
            &request("nucleus.invalid"),
            InteractiveAuthCapability::Browser,
        )
        .await;
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
    use super::session::NucleusShared;
    use super::spi::{NucleusBackend, NucleusContinuation, encode_nucleus_continuation};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use ovstorage_plugin::{
        AccessOps, BackendChangeEvent, BackendId, ChangeKind, ConfigValue, ConnectionRequest,
        CopyOptions, CreateDirectoryOptions, DeleteOptions, ErrorCode, HttpRequest, IfDestExists,
        ListOptions, ListVersionsOptions, ObjectKind, ReadOptions, ReadResult, RedirectBodySource,
        RedirectCredential, RedirectResult, RedirectResultBatch, RedirectScope, RenameOptions,
        ResolvedTarget, ResultCapture, SecretBundle, StatOptions, Url, WatchDirectoryOptions,
        WriteOptions, WriteRedirect, WriteRedirectBatch, WriteStep,
    };
    use serde_json::json;

    use crate::address::NUCLEUS_KIND;
    use crate::handshake::NucleusSession;
    use crate::ops::{NucleusOps, RuntimeOps};
    use crate::test_support::{CannedResponse, MockTransport, MockTransportHandle, RawFrame};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Build a backend over a `MockTransport` with mock ops pre-installed on the
    /// shared session cell. The returned
    /// `NucleusShared` is the injection surface the old `*_for_testing`
    /// factory methods wrapped (ops / lft_client / session /
    /// refresh_override / cred_epoch are all reachable on it).
    async fn factory_with_mock() -> (Arc<NucleusShared>, Arc<NucleusBackend>, Arc<MockTransport>) {
        let mut config = HashMap::new();
        config.insert("server".into(), ConfigValue::String("srv".into()));
        let request = ConnectionRequest {
            backend_kind: NUCLEUS_KIND.into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        };
        let parsed = crate::config::NucleusConfig::from_request(&request).unwrap();
        let shared = NucleusShared::new(parsed, SecretBundle::default());
        let backend = Arc::new(NucleusBackend::from_shared(Arc::clone(&shared)));

        let mock = Arc::new(MockTransport::new());
        let ops: Arc<dyn NucleusOps> =
            Arc::new(RuntimeOps::new(MockTransportHandle::new(Arc::clone(&mock))));
        *shared.ops.lock().unwrap() = Some(ops);

        (shared, backend, mock)
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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

    /// Substitution, not modification: a caller holding a genuine continuation
    /// minted for `/Users/alice/big.bin` presents it against the authorized
    /// request address `/Users/bob/victim.bin`. `create_asset` must name the
    /// authorized path, never the one recorded in the blob.
    #[tokio::test]
    async fn continue_write_commits_to_the_authorized_path_not_the_continuations() {
        let (_shared, backend, mock) = factory_with_mock().await;
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
            branch: Some("alice-branch".into()),
            content_id: 12345,
            if_match_etag: None,
            no_overwrite: false,
            message: None,
        };
        let batch = synthetic_batch(&cont, "http://lft.invalid/content/");
        let results = synthetic_success_result();

        backend
            .continue_write(
                target("omniverse://srv/Users/bob/victim.bin"),
                batch,
                results,
                None,
            )
            .await
            .unwrap();

        let recorded = mock.requests();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, "create_asset");
        let params = recorded[0].params.to_string();
        assert!(
            params.contains("/Users/bob/victim.bin"),
            "create_asset must name the authorized path; got {params}"
        );
        assert!(
            !params.contains("/Users/alice/big.bin") && !params.contains("alice-branch"),
            "the continuation's path and branch must not reach create_asset; got {params}"
        );
    }

    /// The typed mapping `CONFORMANCE.md` mandates under *Post-redirect failure
    /// mapping*. 410 and 416 are the two the LFT mapper was missing; the rest
    /// are pinned alongside them so a future edit cannot quietly drop one.
    #[tokio::test]
    async fn continue_write_maps_redirect_failure_statuses_to_typed_codes() {
        for (status, expected) in [
            (401, ErrorCode::AuthRequired),
            (403, ErrorCode::PermissionDenied),
            (404, ErrorCode::NotFound),
            (410, ErrorCode::NotFound),
            (409, ErrorCode::Conflict),
            (412, ErrorCode::PreconditionFailed),
            (416, ErrorCode::InvalidArgument),
            (429, ErrorCode::ResourceExhausted),
            (503, ErrorCode::Transient),
        ] {
            let (_shared, backend, _mock) = factory_with_mock().await;
            let cont = NucleusContinuation {
                path: "/Users/alice/big.bin".into(),
                branch: None,
                content_id: 1,
                if_match_etag: None,
                no_overwrite: false,
                message: None,
            };
            let results = RedirectResultBatch {
                results: vec![RedirectResult {
                    status_code: status,
                    captured_headers: Vec::new(),
                    captured_body: Vec::new(),
                }],
            };
            let err = backend
                .continue_write(
                    target("omniverse://srv/Users/alice/big.bin"),
                    synthetic_batch(&cont, "http://lft.invalid/content/"),
                    results,
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code(), expected, "HTTP {status}");
        }
    }

    /// A `?checkpoint=N` address is refused by `write_redirect`, and finalizing
    /// one would silently commit to the branch head, so `continue_write` refuses
    /// it too now that it derives its target from the request address.
    #[tokio::test]
    async fn continue_write_rejects_a_checkpoint_pinned_address() {
        let (_shared, backend, _mock) = factory_with_mock().await;
        let cont = NucleusContinuation {
            path: "/Users/alice/big.bin".into(),
            branch: None,
            content_id: 12345,
            if_match_etag: None,
            no_overwrite: false,
            message: None,
        };
        let err = backend
            .continue_write(
                target("omniverse://srv/Users/alice/big.bin?checkpoint=7"),
                synthetic_batch(&cont, "http://lft.invalid/content/"),
                synthetic_success_result(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// The path and branch still ride the encoded blob so a peer replica on an
    /// earlier build can decode a continuation minted here, but a value the
    /// caller puts there is unreachable: `decode` never populates the fields.
    #[test]
    fn nucleus_continuation_emits_the_path_but_never_reads_it_back() {
        let cont = NucleusContinuation {
            path: "/Users/alice/big.bin".into(),
            branch: Some("alice-branch".into()),
            content_id: 7,
            if_match_etag: None,
            no_overwrite: false,
            message: None,
        };
        let encoded = encode_nucleus_continuation(&cont);
        // A mirror of the shape an older build parses, not a substring match.
        // Every field the pre-derivation decoder required.
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct LegacyNucleusContinuation {
            path: String,
            branch: Option<String>,
            content_id: u64,
            if_match_etag: Option<String>,
            no_overwrite: bool,
        }
        let legacy: LegacyNucleusContinuation = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(legacy.path, "/Users/alice/big.bin");
        assert_eq!(legacy.branch.as_deref(), Some("alice-branch"));
        assert_eq!(legacy.content_id, 7);

        let decoded = crate::backend::spi::decode_nucleus_continuation(&encoded).unwrap();
        assert_eq!(decoded.path, "");
        assert_eq!(decoded.branch, None);
        assert_eq!(decoded.content_id, 7);
    }

    #[tokio::test]
    async fn continue_write_completes_via_update_asset() {
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (shared, backend, mock) = factory_with_mock().await;
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
        *shared.lft_client.lock().unwrap() = Some(lft_client);

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
        let (shared, backend, _mock) = factory_with_mock().await;
        let lft = synthetic_lft_client(5 * 1024 * 1024);
        *shared.lft_client.lock().unwrap() = Some(lft);
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
                    credential: RedirectCredential::None,
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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

    /// `list` sends the directory form and relativizes against it.
    ///
    /// The slashless spelling is the one that matters: without the directory
    /// form `list2` receives a byte prefix, so a sibling named `docsx` is
    /// returned as a child of `docs`. Both the wire path and the emitted
    /// addresses are asserted, because the same derived value is the base
    /// `list_entry_to_item` relativizes against — getting one right and the
    /// other wrong would emit plausible addresses for the wrong parent.
    #[tokio::test]
    async fn list_sends_the_directory_form_and_relativizes_against_it() {
        for spelling in [
            "omniverse://srv/Users/alice/docs",
            "omniverse://srv/Users/alice/docs/",
        ] {
            let (_shared, backend, mock) = factory_with_mock().await;
            mock.enqueue(CannedResponse {
                interface: "Connection".into(),
                method: "list2".into(),
                frames: vec![RawFrame::from_json(&json!({
                    "status": "DONE",
                    "entries": [
                        {"path": "/Users/alice/docs/a.usd", "path_type": "asset", "size": 1},
                    ],
                }))],
            });

            let items = backend
                .list(target(spelling), ListOptions::default(), None)
                .await
                .unwrap();

            assert_eq!(
                mock.requests()[0].params["path"],
                json!("/Users/alice/docs/"),
                "list({spelling}) must send the directory form, not a byte prefix"
            );
            assert_eq!(items.len(), 1, "{spelling}");
            assert_eq!(
                items[0].address.as_str(),
                "omniverse://srv/Users/alice/docs/a.usd",
                "{spelling}"
            );
        }
    }

    #[tokio::test]
    async fn list_versions_maps_get_checkpoints_to_pinned_addresses() {
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (shared, backend, mock) = factory_with_mock().await;
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
        *shared.session.lock().unwrap() = Some(NucleusSession {
            access_token: "at".into(),
            refresh_token: None,
            tokens_url: "wss://srv/tokens".into(),
            principal: "alice".into(),
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
        assert!(
            !decision.allowed,
            "alice has only read; write must be denied: {decision:?}"
        );
        assert!(!decision.denied_ops.read);
        assert!(decision.denied_ops.write);
    }

    #[tokio::test]
    async fn check_access_denies_when_principal_unknown() {
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (shared, backend, _mock) = factory_with_mock().await;
        let lft = synthetic_lft_client(5 * 1024 * 1024);
        *shared.lft_client.lock().unwrap() = Some(lft);
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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

    /// A slashless directory verb must not address the same-named FILE.
    ///
    /// Nucleus passes the path straight to omni1, and `delete2` takes it
    /// verbatim — so `delete_directory("omniverse://srv/.../docs")` on a server
    /// holding both a file `docs` and a folder `docs/` destroyed the file. The
    /// host does not add the separator (`x` and `x/` are one node, and choosing
    /// for the backend would be choosing which object is destroyed), so the
    /// backend derives it. Every directory verb is asserted here, in both
    /// spellings, because they share one helper and a miss on any of them is
    /// silent.
    #[tokio::test]
    async fn directory_verbs_send_the_directory_form_for_either_spelling() {
        for spelling in [
            "omniverse://srv/Users/alice/docs",
            "omniverse://srv/Users/alice/docs/",
        ] {
            let (_shared, backend, mock) = factory_with_mock().await;
            mock.enqueue(CannedResponse {
                interface: "Connection".into(),
                method: "create_directory".into(),
                frames: vec![RawFrame::from_json(&json!({"status": "OK", "ts": {}}))],
            });
            mock.enqueue(CannedResponse {
                interface: "Connection".into(),
                method: "delete2".into(),
                frames: vec![RawFrame::from_json(
                    &json!({"status": "OK", "responses": ["OK"]}),
                )],
            });

            backend
                .create_directory(target(spelling), CreateDirectoryOptions::default(), None)
                .await
                .unwrap();
            backend
                .delete_directory(
                    target(spelling),
                    ovstorage_plugin::DeleteDirectoryOptions,
                    None,
                )
                .await
                .unwrap();

            let recorded = mock.requests();
            assert_eq!(
                recorded[0].params["path"],
                json!({"path": "/Users/alice/docs/"}),
                "create_directory({spelling}) must address the folder"
            );
            assert_eq!(
                recorded[1].params,
                json!({"paths_to_delete": [{"path": "/Users/alice/docs/"}]}),
                "delete_directory({spelling}) must address the folder, never the file `docs`"
            );
        }
    }

    /// `watch_directory` subscribes to the directory form for either spelling.
    ///
    /// The derived value is used twice — as the subscribed path and as the
    /// `watched_prefix` events are relativized against — so both are asserted:
    /// a slashless subscription would watch a byte prefix and report a sibling
    /// `docsx` as a child.
    #[tokio::test]
    async fn watch_directory_subscribes_to_the_directory_form() {
        for spelling in [
            "omniverse://srv/Users/alice/docs",
            "omniverse://srv/Users/alice/docs/",
        ] {
            let (_shared, backend, mock) = factory_with_mock().await;
            mock.enqueue(CannedResponse {
                interface: "Connection".into(),
                method: "subscribe_list".into(),
                frames: vec![RawFrame::from_json(&json!({
                    "status": "OK",
                    "event": "create",
                    "entry": {"path": "/Users/alice/docs/new.usd", "etag": "e1", "size": 9},
                }))],
            });

            let mut stream = backend
                .watch_directory(target(spelling), WatchDirectoryOptions::default(), None)
                .await
                .unwrap();

            assert_eq!(
                mock.requests()[0].params["path"],
                json!({"path": "/Users/alice/docs/"}),
                "watch_directory({spelling}) must subscribe to the directory form"
            );
            match stream.next().unwrap().unwrap() {
                BackendChangeEvent::Object { address, .. } => assert_eq!(
                    address.as_str(),
                    "omniverse://srv/Users/alice/docs/new.usd",
                    "{spelling}"
                ),
                other => panic!("expected Object event, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn watch_directory_translates_subscribe_list_events() {
        let (_shared, backend, mock) = factory_with_mock().await;
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

    /// Every interactive sign-in — the SSO stream and the api-token /
    /// username-password arms alike — reaches the live cell through an IDENTITY
    /// install and nothing else. Recording the principal there is what keeps a
    /// sign-in from persisting a record that names nobody, which any connection
    /// sharing the key could then adopt.
    #[tokio::test]
    async fn an_identity_install_binds_the_principal_the_server_authenticated() {
        let (shared, _backend, _mock) = factory_with_mock().await;
        assert!(
            shared.binding.current().is_none(),
            "a connection starts bound to nobody",
        );
        let ops = shared.ops.lock().unwrap().clone().unwrap();
        let session = synthetic_session();
        let principal = session.principal.clone();
        assert!(crate::backend::session::install_handshake_output(
            &shared,
            ops,
            None,
            session,
            SecretBundle::default(),
            crate::backend::session::InstallKind::Identity,
            None,
        ));

        let binding = shared
            .binding
            .current()
            .expect("an identity install records who signed in");
        assert_eq!(binding.subject, principal);
        assert_eq!(binding.issuer, shared.config.server);
        // A record naming nobody would verify against every identity, and the
        // storage layer refuses to write one at all.
        assert!(binding.is_specific());
    }

    /// The generation compare must happen under the same lock an IDENTITY
    /// install holds while it writes the binding and bumps the generation.
    ///
    /// Two independent loads leave a window: a winner that has recorded its
    /// identity but not yet bumped is visible as "another principal, same
    /// generation", so the in-flight refresh returns a false `AuthRequired`
    /// against the connection about to win, and the lifecycle parks it. The
    /// seam runs at the compare point, so a version that samples outside the
    /// lock fails here — no threads and no sleeping, which the previous shape
    /// needed and which could false-pass on a loaded runner.
    #[tokio::test]
    async fn the_refresh_generation_compare_runs_under_the_install_lock() {
        let (shared, _backend, _mock) = factory_with_mock().await;
        let ops = shared.ops.lock().unwrap().clone().unwrap();
        shared
            .binding
            .expect(crate::backend::session::identity_binding(&shared, "alice"));

        let held = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = Arc::clone(&held);
        *shared.observation_gate.lock().unwrap() = Some(Arc::new(
            move |shared: &crate::backend::session::NucleusShared| {
                seen.store(
                    shared.session.try_lock().is_err(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            },
        ));

        let refresh_ops = Arc::clone(&ops);
        *shared.refresh_override.lock().unwrap() = Some(std::sync::Arc::new(move || {
            Ok((
                Arc::clone(&refresh_ops),
                None,
                NucleusSession {
                    principal: "alice".into(),
                    ..synthetic_session()
                },
            ))
        }));

        let _ = crate::backend::session::refresh_under_epoch(
            &shared,
            &SecretBundle::default(),
            0,
            shared
                .identity_gen
                .load(std::sync::atomic::Ordering::Acquire),
        )
        .await;
        *shared.observation_gate.lock().unwrap() = None;

        assert!(
            held.load(std::sync::atomic::Ordering::SeqCst),
            "the session lock is held across the generation compare and the \
             identity check, so a half-applied install is not observable",
        );
    }

    /// A refresh grant returning a DIFFERENT principal is refused before the
    /// session reaches the live cell.
    ///
    /// That a refresh is same-identity is a statement about the provider, not
    /// something this process observes, so it is checked. Were it not, the
    /// other principal's session would go live under the bound connection and
    /// its rotated token would be persisted beside a record it contradicts.
    #[tokio::test]
    async fn a_refresh_that_authenticates_as_someone_else_is_refused() {
        let (shared, _backend, _mock) = factory_with_mock().await;
        let ops = shared.ops.lock().unwrap().clone().unwrap();
        // The connection is bound to alice; the grant will come back as
        // `synthetic_session()`'s principal, which is somebody else.
        shared
            .binding
            .expect(crate::backend::session::identity_binding(&shared, "alice"));
        let session = synthetic_session();
        assert_ne!(session.principal, "alice");
        let installed_ops = Arc::clone(&ops);
        *shared.refresh_override.lock().unwrap() = Some(std::sync::Arc::new(move || {
            Ok((Arc::clone(&installed_ops), None, synthetic_session()))
        }));

        let err = crate::backend::session::refresh_under_epoch(
            &shared,
            &SecretBundle::default(),
            shared.cred_epoch.load(std::sync::atomic::Ordering::Acquire),
            shared
                .identity_gen
                .load(std::sync::atomic::Ordering::Acquire),
        )
        .await
        .expect_err("a refresh as another principal is refused");
        assert_eq!(err.code(), ErrorCode::AuthRequired);

        // The binding survives the refusal, so a retry is refused too, and the
        // credential epoch did not advance on a session that never installed.
        assert_eq!(shared.binding.current().unwrap().subject, "alice");
        assert_eq!(
            shared.cred_epoch.load(std::sync::atomic::Ordering::Acquire),
            0
        );
    }

    /// The same path with the principal the connection is bound to: the
    /// refresh installs, and the established record is neither lost nor
    /// restated.
    #[tokio::test]
    async fn a_same_identity_refresh_installs_and_keeps_the_binding() {
        let (shared, _backend, _mock) = factory_with_mock().await;
        let ops = shared.ops.lock().unwrap().clone().unwrap();
        let principal = synthetic_session().principal;
        shared
            .binding
            .expect(crate::backend::session::identity_binding(
                &shared, &principal,
            ));
        let installed_ops = Arc::clone(&ops);
        *shared.refresh_override.lock().unwrap() = Some(std::sync::Arc::new(move || {
            Ok((Arc::clone(&installed_ops), None, synthetic_session()))
        }));

        let effective = crate::backend::session::refresh_under_epoch(
            &shared,
            &SecretBundle::default(),
            shared.cred_epoch.load(std::sync::atomic::Ordering::Acquire),
            shared
                .identity_gen
                .load(std::sync::atomic::Ordering::Acquire),
        )
        .await
        .unwrap();
        assert!(effective.is_some());
        assert_eq!(shared.binding.current().unwrap().subject, principal);
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

    /// Harness for the recovery pins: a REAL `ConnectionSet` admits an
    /// api-token connection through obtain → verify (the test handshake seam
    /// returns the mock-backed ops) → on_authenticated, then each test drives
    /// ops through `with_recovery`, the exact production loop the layer's
    /// `recover()` uses.
    async fn recovery_harness() -> (
        Arc<NucleusShared>,
        Arc<NucleusBackend>,
        Arc<MockTransport>,
        Arc<ovstorage_plugin::connection::ConnectionSet<crate::driver::NucleusDriver>>,
        ovstorage_plugin::ConnectionId,
    ) {
        let (shared, backend, mock) = factory_with_mock().await;
        let handshake_ops = shared.ops.lock().unwrap().clone().unwrap();
        *shared.handshake_override.lock().unwrap() = Some(std::sync::Arc::new(move || {
            Ok(crate::handshake::HandshakeOutput {
                ops: std::sync::Arc::clone(&handshake_ops),
                lft: None,
                session: synthetic_session(),
            })
        }));
        let set = Arc::new(ovstorage_plugin::connection::ConnectionSet::with_defaults());
        let driver = Arc::new(crate::driver::NucleusDriver::new(Arc::clone(&shared)));
        let id = ovstorage_plugin::ConnectionId("recovery-test".into());
        let connection = ovstorage_plugin::Connection {
            id: id.clone(),
            backend_kind: NUCLEUS_KIND.into(),
            display_name: "recovery".into(),
            source: ovstorage_plugin::ConnectionSource::Runtime { persisted: false },
            capabilities: super::spi::native_capabilities(),
            current_addresses: Vec::new(),
            auth_state: ovstorage_plugin::ConnectionAuthState::AwaitingAuth {
                reason: ovstorage_plugin::AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: ovstorage_plugin::UserMetadata::new(),
        };
        let mut creds = SecretBundle::default();
        creds.fields.insert(
            "api_token".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(b"tok".to_vec())),
        );
        set.add_connection(connection, driver, creds, None)
            .await
            .expect("api-token add authenticates via the handshake seam");
        assert!(
            matches!(
                set.connection(&id).unwrap().auth_state,
                ovstorage_plugin::ConnectionAuthState::Authenticated { .. }
            ),
            "harness connection must be Authenticated"
        );
        (shared, backend, mock, set, id)
    }

    /// `TokenExpired` -> `AuthExpired` classifies as a recoverable credential:
    /// the recovery loop refreshes (epoch bumps) and retries ONCE; a second
    /// `TOKEN_EXPIRED` surfaces as `AuthExpired` — no loop.
    #[tokio::test]
    async fn stat_maps_token_expired_to_auth_expired_after_failed_refresh() {
        let (shared, backend, mock, set, id) = recovery_harness().await;
        // Both attempts see TOKEN_EXPIRED so the one-shot retry exhausts.
        // Each attempt fires a parallel file+folder probe -> 4 enqueues total.
        for _ in 0..4 {
            mock.enqueue(CannedResponse {
                interface: "Connection".into(),
                method: "stat2".into(),
                frames: vec![RawFrame::from_json(&json!({"status": "TOKEN_EXPIRED"}))],
            });
        }
        let original_ops = shared.ops.lock().unwrap().clone().unwrap();
        *shared.refresh_override.lock().unwrap() = Some(std::sync::Arc::new(move || {
            Ok((
                std::sync::Arc::clone(&original_ops),
                None,
                synthetic_session(),
            ))
        }));

        let err = set
            .with_recovery(&id, || {
                backend.stat(
                    target("omniverse://srv/Users/alice/foo.usd"),
                    StatOptions::default(),
                    None,
                )
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthExpired);
        assert_eq!(mock.requests().len(), 4);
        // Epoch bumps because the override "succeeded"; the retry failure does not roll it back.
        assert_eq!(shared.cred_epoch.load(Ordering::Acquire), 1);
    }

    /// `TOKEN_EXPIRED` then `OK` -> single refresh, the retry observes success.
    #[tokio::test]
    async fn stat_succeeds_after_one_shot_refresh_retry() {
        let (shared, backend, mock, set, id) = recovery_harness().await;
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
        let original_ops = shared.ops.lock().unwrap().clone().unwrap();
        let refresh_count = std::sync::Arc::new(AtomicU64::new(0));
        let counter = std::sync::Arc::clone(&refresh_count);
        *shared.refresh_override.lock().unwrap() = Some(std::sync::Arc::new(move || {
            counter.fetch_add(1, Ordering::AcqRel);
            Ok((
                std::sync::Arc::clone(&original_ops),
                None,
                synthetic_session(),
            ))
        }));

        let info = set
            .with_recovery(&id, || {
                backend.stat(
                    target("omniverse://srv/Users/alice/foo.usd"),
                    StatOptions::default(),
                    None,
                )
            })
            .await
            .unwrap();
        assert_eq!(info.etag.as_deref(), Some("etag-1"));
        assert_eq!(refresh_count.load(Ordering::Acquire), 1);
        assert_eq!(shared.cred_epoch.load(Ordering::Acquire), 1);
        assert_eq!(mock.requests().len(), 4);
    }

    /// N racing recovered `stat`s observe `TOKEN_EXPIRED` and collapse onto a
    /// single refresh (the `ConnectionSet` coalesces recoveries per
    /// connection; `refresh_under_epoch`'s epoch re-check is the second belt).
    /// The 50ms `std::thread::sleep` in the override gives every task time to
    /// queue before the first holder bumps `cred_epoch`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_token_expired_collapses_to_single_refresh() {
        let (shared, backend, mock, set, id) = recovery_harness().await;
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
        let original_ops = shared.ops.lock().unwrap().clone().unwrap();
        let refresh_count = std::sync::Arc::new(AtomicU64::new(0));
        let counter = std::sync::Arc::clone(&refresh_count);
        *shared.refresh_override.lock().unwrap() = Some(std::sync::Arc::new(move || {
            // 50ms is long enough for all N tasks to queue on `refresh_lock`.
            std::thread::sleep(std::time::Duration::from_millis(50));
            counter.fetch_add(1, Ordering::AcqRel);
            Ok((
                std::sync::Arc::clone(&original_ops),
                None,
                synthetic_session(),
            ))
        }));

        let mut joins = Vec::with_capacity(N);
        for _ in 0..N {
            let backend = std::sync::Arc::clone(&backend);
            let set = std::sync::Arc::clone(&set);
            let id = id.clone();
            joins.push(tokio::spawn(async move {
                set.with_recovery(&id, || {
                    backend.stat(
                        target("omniverse://srv/Users/alice/foo.usd"),
                        StatOptions::default(),
                        None,
                    )
                })
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
        assert_eq!(shared.cred_epoch.load(Ordering::Acquire), 1);
    }

    /// Guards the split between `Unauthenticated -> AuthRequired` and `TokenExpired -> AuthExpired`.
    #[tokio::test]
    async fn stat_maps_unauthenticated_status_to_auth_required_distinct_from_expired() {
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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
        let (_shared, backend, mock) = factory_with_mock().await;
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

    /// A refresh whose new session advertises no LFT must clear the prior
    /// `LftClient` — a stale client would keep issuing redirects the server
    /// rejects.
    #[tokio::test]
    async fn re_authenticate_with_no_lft_clears_prior_lft_client() {
        let (shared, backend, mock, set, id) = recovery_harness().await;
        for _ in 0..2 {
            mock.enqueue(CannedResponse {
                interface: "Connection".into(),
                method: "stat2".into(),
                frames: vec![RawFrame::from_json(&json!({"status": "TOKEN_EXPIRED"}))],
            });
        }
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
        *shared.lft_client.lock().unwrap() = Some(lft);
        assert!(shared.lft_client.lock().unwrap().is_some());
        let original_ops = shared.ops.lock().unwrap().clone().unwrap();
        *shared.refresh_override.lock().unwrap() = Some(std::sync::Arc::new(move || {
            Ok((
                std::sync::Arc::clone(&original_ops),
                None,
                synthetic_session(),
            ))
        }));
        let _ = set
            .with_recovery(&id, || {
                backend.stat(
                    target("omniverse://srv/Users/alice/foo.usd"),
                    StatOptions::default(),
                    None,
                )
            })
            .await;
        assert!(shared.lft_client.lock().unwrap().is_none());
    }

    /// A parked / never-signed-in connection refuses `write_stream` BEFORE
    /// draining the body: not a single chunk may be buffered for a request
    /// that can only end in `AuthRequired`.
    #[tokio::test]
    async fn write_stream_requires_session_before_draining_body() {
        let (shared, backend, _mock) = factory_with_mock().await;
        *shared.ops.lock().unwrap() = None;
        let consumed = std::sync::Arc::new(AtomicU64::new(0));
        let counter = std::sync::Arc::clone(&consumed);
        let stream = ovstorage_plugin::BodyStream::from_iter((0..8).map(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(vec![0u8; 1024])
        }));
        let err = backend
            .write_stream(
                target("omniverse://srv/Users/alice/big.bin"),
                stream,
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        assert_eq!(consumed.load(Ordering::SeqCst), 0, "no chunk drained");
    }

    /// `size_hint` is advisory, not a memory-safety bound: an understated
    /// hint on the buffered path stops at the LFT threshold instead of
    /// collecting the stream unboundedly.
    #[tokio::test]
    async fn write_stream_with_understated_size_hint_is_bounded() {
        let (shared, backend, _mock) = factory_with_mock().await;
        let lft = Arc::new(
            nucleus_client::LftClient::new(
                "https://lft.invalid".into(),
                4096, // tiny threshold so the ceiling trips after a few chunks
                "conn-id".into(),
                None,
                Some("connlib-tok".into()),
                None,
                None,
                5 * 1024 * 1024,
            )
            .unwrap(),
        );
        *shared.lft_client.lock().unwrap() = Some(lft);
        let consumed = std::sync::Arc::new(AtomicU64::new(0));
        let counter = std::sync::Arc::clone(&consumed);
        // An effectively endless stream whose hint claims it fits below the
        // threshold.
        let stream = ovstorage_plugin::BodyStream::from_iter((0..1_000_000u32).map(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(vec![0u8; 1024])
        }));
        let err = backend
            .write_stream(
                target("omniverse://srv/Users/alice/big.bin"),
                stream,
                WriteOptions {
                    size_hint: Some(16), // wildly understated
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
        let drained = consumed.load(Ordering::SeqCst);
        assert!(
            drained <= 8,
            "buffering must stop at the threshold; drained {drained} KiB chunks"
        );
    }

    fn lft_with_threshold(threshold: u64) -> Arc<nucleus_client::LftClient> {
        Arc::new(
            nucleus_client::LftClient::new(
                "https://lft.invalid".into(),
                threshold,
                "conn-id".into(),
                None,
                Some("connlib-tok".into()),
                None,
                None,
                5 * 1024 * 1024,
            )
            .unwrap(),
        )
    }

    /// A server that advertises `lft_address` but omits `lft_threshold`
    /// (mapped to 0, which `should_use_lft` treats as never-LFT) must get the
    /// DEFAULT inline cap, not a 0-byte ceiling that fails every nonempty
    /// body after its first chunk.
    #[tokio::test]
    async fn write_stream_zero_lft_threshold_uses_default_inline_cap() {
        let (shared, backend, mock) = factory_with_mock().await;
        *shared.lft_client.lock().unwrap() = Some(lft_with_threshold(0));
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "create_asset".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "etag": "e",
                "transaction_id": 1,
            }))],
        });
        let body = vec![0u8; 3 * 1024];
        let stream = ovstorage_plugin::BodyStream::from_iter((0..3).map(|_| Ok(vec![0u8; 1024])));
        backend
            .write_stream(
                target("omniverse://srv/Users/alice/small.bin"),
                stream,
                WriteOptions {
                    size_hint: Some(body.len() as u64),
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .expect("a known-size nonempty stream buffers under the default cap");
        assert_eq!(mock.requests()[0].method, "create_asset");
    }

    /// An excessively large server-advertised threshold must not defeat the
    /// LOCAL memory bound: the drain clamps at the plugin-controlled
    /// `MAX_BUFFERED_WRITE_BYTES` regardless of the hint.
    #[tokio::test]
    async fn write_stream_oversized_server_threshold_is_clamped() {
        let (shared, backend, _mock) = factory_with_mock().await;
        *shared.lft_client.lock().unwrap() = Some(lft_with_threshold(u64::MAX / 2));
        let consumed = std::sync::Arc::new(AtomicU64::new(0));
        let counter = std::sync::Arc::clone(&consumed);
        // Endless 1 MiB chunks with an in-bounds hint (below the huge server
        // threshold, so the buffered path is chosen).
        let stream = ovstorage_plugin::BodyStream::from_iter((0..1_000_000u32).map(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(vec![0u8; 1024 * 1024])
        }));
        let err = backend
            .write_stream(
                target("omniverse://srv/Users/alice/huge.bin"),
                stream,
                WriteOptions {
                    size_hint: Some(1024),
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
        let cap_chunks = (super::spi::MAX_BUFFERED_WRITE_BYTES / (1024 * 1024)) + 2;
        let drained = consumed.load(Ordering::SeqCst);
        assert!(
            drained <= cap_chunks,
            "drain must clamp at MAX_BUFFERED_WRITE_BYTES; drained {drained} MiB chunks"
        );
    }

    /// The routing gate and the drain cap share ONE effective ceiling: an
    /// ACCURATELY hinted body above the local memory bound (but under an
    /// oversized server threshold) routes to the redirect refusal
    /// immediately — zero chunks buffered — instead of draining 64 MiB only
    /// to be rejected with a misleading "hint understated" message.
    #[tokio::test]
    async fn write_stream_accurate_hint_above_local_cap_redirects_immediately() {
        let (shared, backend, _mock) = factory_with_mock().await;
        *shared.lft_client.lock().unwrap() = Some(lft_with_threshold(u64::MAX / 2));
        let consumed = std::sync::Arc::new(AtomicU64::new(0));
        let counter = std::sync::Arc::clone(&consumed);
        let stream = ovstorage_plugin::BodyStream::from_iter((0..4).map(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(vec![0u8; 1024])
        }));
        let err = backend
            .write_stream(
                target("omniverse://srv/Users/alice/big.bin"),
                stream,
                WriteOptions {
                    size_hint: Some(super::spi::MAX_BUFFERED_WRITE_BYTES + 1),
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
        assert!(
            err.message().contains("write_redirect"),
            "refusal must route the caller to the redirect path: {}",
            err.message()
        );
        assert_eq!(
            consumed.load(Ordering::SeqCst),
            0,
            "an above-ceiling accurate hint must not buffer a single chunk"
        );
    }

    /// End-to-end: a single chunk larger than the cap is rejected with
    /// `Unsupported`. This exercises the reject PATH; the overflow-safe
    /// "validate before extend" arithmetic itself — the property distinguishing
    /// it from a check-AFTER-extend — is unit-tested in
    /// `would_exceed_cap_is_overflow_safe`.
    #[tokio::test]
    async fn write_stream_single_chunk_larger_than_cap_is_rejected() {
        let (shared, backend, _mock) = factory_with_mock().await;
        *shared.lft_client.lock().unwrap() = Some(lft_with_threshold(4096));
        let stream =
            ovstorage_plugin::BodyStream::from_iter(std::iter::once(Ok(vec![0u8; 8 * 1024])));
        let err = backend
            .write_stream(
                target("omniverse://srv/Users/alice/one-chunk.bin"),
                stream,
                WriteOptions {
                    size_hint: Some(16),
                    ..WriteOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    /// The failure-path session clear is identity-generation-gated: a clear
    /// armed with a STALE observation (a newer IDENTITY installed since) is a
    /// no-op, so a failed rotation cannot erase a concurrent credential winner.
    #[tokio::test]
    async fn stale_identity_generation_clear_is_a_no_op() {
        use crate::backend::session::{
            InstallKind, clear_session_state_if_identity_unchanged, install_handshake_output,
        };
        let (shared, _backend, mock) = factory_with_mock().await;
        let make_ops = || -> Arc<dyn NucleusOps> {
            Arc::new(RuntimeOps::new(MockTransportHandle::new(Arc::clone(&mock))))
        };
        assert!(install_handshake_output(
            &shared,
            make_ops(),
            None,
            synthetic_session(),
            SecretBundle::default(),
            InstallKind::Identity,
            None,
        ));
        let observed = shared.identity_gen.load(Ordering::Acquire);
        // A newer IDENTITY lands after the observation…
        assert!(install_handshake_output(
            &shared,
            make_ops(),
            None,
            synthetic_session(),
            SecretBundle::default(),
            InstallKind::Identity,
            None,
        ));
        // …so the stale clear must decline.
        assert!(!clear_session_state_if_identity_unchanged(
            &shared, observed
        ));
        assert!(shared.has_session(), "the newer identity survives");
        // A current observation clears normally.
        let current = shared.identity_gen.load(Ordering::Acquire);
        assert!(clear_session_state_if_identity_unchanged(&shared, current));
        assert!(!shared.has_session());
    }

    /// A same-identity background REFRESH landing between the teardown's
    /// observation and its clear must NOT block the clear: it swaps the
    /// transport state without advancing `identity_gen`, so the failed
    /// rotation still tears the old identity down (K5-r3 Finding 2 — a refresh
    /// is not a credential replacement and must not be mistaken for a winner).
    #[tokio::test]
    async fn same_identity_refresh_does_not_block_teardown() {
        use crate::backend::session::{
            InstallKind, clear_session_state_if_identity_unchanged, install_handshake_output,
            refresh_under_epoch,
        };
        let (shared, _backend, mock) = factory_with_mock().await;
        let make_ops = || -> Arc<dyn NucleusOps> {
            Arc::new(RuntimeOps::new(MockTransportHandle::new(Arc::clone(&mock))))
        };
        assert!(install_handshake_output(
            &shared,
            make_ops(),
            None,
            synthetic_session(),
            SecretBundle::default(),
            InstallKind::Identity,
            None,
        ));
        let observed = shared.identity_gen.load(Ordering::Acquire);
        // A same-identity refresh installs a fresh session AFTER the
        // observation — bumps neither `identity_gen`…
        assert!(install_handshake_output(
            &shared,
            make_ops(),
            None,
            synthetic_session(),
            SecretBundle::default(),
            InstallKind::Refresh,
            None,
        ));
        assert_eq!(
            shared.identity_gen.load(Ordering::Acquire),
            observed,
            "a refresh must not advance identity_gen"
        );
        // …so the teardown, fenced on the unchanged identity generation,
        // PROCEEDS and clears the old identity's refreshed session.
        assert!(clear_session_state_if_identity_unchanged(&shared, observed));
        assert!(
            !shared.has_session(),
            "the old identity is torn down despite the intervening refresh"
        );
        assert_eq!(
            shared.identity_gen.load(Ordering::Acquire),
            observed + 1,
            "teardown advances the fence against a late old-identity refresh"
        );
        let current = shared.credentials.lock().unwrap().clone();
        assert!(
            refresh_under_epoch(&shared, &current, 0, observed)
                .await
                .unwrap()
                .is_none(),
            "a refresh carrying the pre-teardown generation cannot resurrect the session"
        );
    }

    /// A staged credential replacement that started on generation G must not
    /// overwrite a newer identity that installed before activation.
    #[tokio::test]
    async fn stale_staged_activation_does_not_replace_newer_identity() {
        use crate::backend::session::{InstallKind, install_handshake_output};
        use ovstorage_plugin::connection::{ConnectionAuthDriver as _, GrantPolicy, Obtained};

        let (shared, _backend, mock) = factory_with_mock().await;
        let staged_ops: Arc<dyn NucleusOps> =
            Arc::new(RuntimeOps::new(MockTransportHandle::new(Arc::clone(&mock))));
        *shared.handshake_override.lock().unwrap() = Some(Arc::new(move || {
            Ok(crate::handshake::HandshakeOutput {
                ops: Arc::clone(&staged_ops),
                lft: None,
                session: NucleusSession {
                    principal: "stale".into(),
                    ..synthetic_session()
                },
            })
        }));
        let driver = crate::driver::NucleusDriver::new(Arc::clone(&shared));
        let expected = driver.identity_gen();
        let mut supplied = SecretBundle::default();
        supplied.fields.insert(
            "api_token".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(b"tok".to_vec())),
        );
        let Obtained::Bearer { credentials, .. } = driver
            .obtain(&supplied, GrantPolicy::AllowConsuming, None)
            .await
            .unwrap()
        else {
            panic!("api-token obtain must produce a staged bearer");
        };

        let winner_ops: Arc<dyn NucleusOps> =
            Arc::new(RuntimeOps::new(MockTransportHandle::new(Arc::clone(&mock))));
        assert!(install_handshake_output(
            &shared,
            winner_ops,
            None,
            NucleusSession {
                principal: "winner".into(),
                ..synthetic_session()
            },
            SecretBundle::default(),
            InstallKind::Identity,
            None,
        ));
        assert!(
            !driver
                .activate_replacing(&credentials, expected)
                .await
                .unwrap(),
            "the stale activation must report that its fenced install was skipped"
        );
        assert_eq!(
            shared.session.lock().unwrap().as_ref().unwrap().principal,
            "winner"
        );
    }

    #[tokio::test]
    async fn non_consuming_probe_refuses_refresh_only_bundle() {
        use ovstorage_plugin::connection::{ConnectionAuthDriver as _, GrantPolicy, Obtained};

        let (shared, _backend, _mock) = factory_with_mock().await;
        *shared.handshake_override.lock().unwrap() = Some(Arc::new(|| {
            panic!("a non-consuming probe must not invoke the refresh handshake")
        }));
        let driver = crate::driver::NucleusDriver::new(shared);
        let credentials =
            ovstorage_plugin::oauth_secret_store::oauth_bundle("", Some("one-time-refresh"), None);

        assert!(matches!(
            driver
                .obtain(&credentials, GrantPolicy::NonConsumingOnly, None)
                .await
                .unwrap(),
            Obtained::WouldConsume
        ));
    }

    /// A refresh may finish its network grant after an interactive winner has
    /// installed. The set-captured generation must fence the stale result out
    /// of every live cell and leave the refresh epoch untouched.
    #[tokio::test]
    async fn refresh_install_is_fenced_by_set_captured_identity_generation() {
        use crate::backend::session::{InstallKind, install_handshake_output, refresh_under_epoch};

        let (shared, _backend, mock) = factory_with_mock().await;
        let initial_ops: Arc<dyn NucleusOps> =
            Arc::new(RuntimeOps::new(MockTransportHandle::new(Arc::clone(&mock))));
        assert!(install_handshake_output(
            &shared,
            initial_ops,
            None,
            NucleusSession {
                principal: "old".into(),
                ..synthetic_session()
            },
            SecretBundle::default(),
            InstallKind::Identity,
            None,
        ));
        let expected = shared.identity_gen.load(Ordering::Acquire);
        let weak = Arc::downgrade(&shared);
        let mock_for_refresh = Arc::clone(&mock);
        *shared.refresh_override.lock().unwrap() = Some(Arc::new(move || {
            let shared = weak.upgrade().unwrap();
            let winner_ops: Arc<dyn NucleusOps> = Arc::new(RuntimeOps::new(
                MockTransportHandle::new(Arc::clone(&mock_for_refresh)),
            ));
            assert!(install_handshake_output(
                &shared,
                winner_ops,
                None,
                NucleusSession {
                    principal: "winner".into(),
                    ..synthetic_session()
                },
                SecretBundle::default(),
                InstallKind::Identity,
                None,
            ));
            let stale_ops: Arc<dyn NucleusOps> = Arc::new(RuntimeOps::new(
                MockTransportHandle::new(Arc::clone(&mock_for_refresh)),
            ));
            Ok((
                stale_ops,
                None,
                NucleusSession {
                    principal: "stale-refresh".into(),
                    ..synthetic_session()
                },
            ))
        }));

        let current = shared.credentials.lock().unwrap().clone();
        let refreshed = refresh_under_epoch(&shared, &current, 0, expected)
            .await
            .unwrap();
        assert!(refreshed.is_none(), "the superseded refresh is discarded");
        assert_eq!(shared.cred_epoch.load(Ordering::Acquire), 0);
        assert_eq!(
            shared.session.lock().unwrap().as_ref().unwrap().principal,
            "winner"
        );
    }

    /// `would_exceed_cap` is the overflow-safe boundary check the buffered
    /// write path applies BEFORE each copy. Exercises the property the
    /// integration test cannot: a `current_len` near `u64::MAX` must report
    /// "exceeds" via `saturating_add` instead of wrapping to a small sum and
    /// admitting the chunk.
    #[test]
    fn would_exceed_cap_is_overflow_safe() {
        use super::spi::would_exceed_cap;
        // Exact-fit and below-cap admit.
        assert!(!would_exceed_cap(0, 4096, 4096));
        assert!(!would_exceed_cap(4095, 1, 4096));
        assert!(!would_exceed_cap(4096, 0, 4096));
        // One byte over the cap rejects.
        assert!(would_exceed_cap(4096, 1, 4096));
        assert!(would_exceed_cap(0, 4097, 4096));
        // The overflow guard: a plain `current_len + chunk_len` would wrap
        // (u64::MAX + 1 == 0, then 0 > cap is false, wrongly ADMITTING the
        // chunk). `saturating_add` pins the sum at u64::MAX so the check
        // correctly reports "exceeds".
        assert!(would_exceed_cap(u64::MAX, 1, 4096));
        assert!(would_exceed_cap(u64::MAX - 100, 1000, 4096));
    }

    fn spi_connection() -> ovstorage_plugin::Connection {
        ovstorage_plugin::Connection {
            id: ovstorage_plugin::ConnectionId("spi-test".into()),
            backend_kind: NUCLEUS_KIND.into(),
            display_name: "spi".into(),
            source: ovstorage_plugin::ConnectionSource::Runtime { persisted: false },
            capabilities: super::spi::native_capabilities(),
            current_addresses: Vec::new(),
            auth_state: ovstorage_plugin::ConnectionAuthState::AwaitingAuth {
                reason: ovstorage_plugin::AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: ovstorage_plugin::UserMetadata::new(),
        }
    }

    /// A failed re-authentication tears the live session down
    /// before the terminal `Failed`, so the previous identity cannot keep
    /// serving (data dispatch gates on session presence, not auth state).
    #[tokio::test]
    async fn interactive_failed_re_auth_clears_installed_session() {
        use ovstorage_plugin::connection::ConnectionAuthDriver as _;
        let (shared, backend, _mock) = factory_with_mock().await;
        assert!(shared.has_session());
        shared.credentials.lock().unwrap().fields.insert(
            "api_token".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(b"tok".to_vec())),
        );
        *shared.handshake_override.lock().unwrap() = Some(std::sync::Arc::new(|| {
            Err(ovstorage_plugin::Error::new(
                ErrorCode::PermissionDenied,
                "re-auth denied by test",
            ))
        }));
        let driver = crate::driver::NucleusDriver::new(Arc::clone(&shared));
        let events = driver
            .interactive(
                spi_connection(),
                ovstorage_plugin::InteractiveAuthCapability::Browser,
                None,
            )
            .await
            .unwrap()
            .collect::<ovstorage_plugin::Result<Vec<_>>>()
            .unwrap();
        assert!(
            matches!(
                events.last(),
                Some(ovstorage_plugin::AuthEvent::Failed { .. })
            ),
            "expected a terminal Failed, got {events:?}"
        );
        assert!(
            !shared.has_session(),
            "a failed re-auth must clear the live session"
        );
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

    /// Interactive-success ordering: the session must already be LIVE when
    /// the terminal `Succeeded` is observable — a host that reacts to
    /// `Succeeded` (the `ConnectionSet`'s `on_authenticated`) must find it
    /// installed, or a completed sign-in would re-handshake and park. Drives
    /// the pump through the handshake seam; the production worker enforces
    /// the same order structurally (`establish_interactive_auth` returns the
    /// output without emitting `Succeeded`, and the worker installs before
    /// forwarding the terminal event).
    #[tokio::test]
    async fn interactive_success_installs_session_before_terminal_succeeded() {
        use ovstorage_plugin::connection::ConnectionAuthDriver as _;
        let (shared, _backend, _mock) = factory_with_mock().await;
        let handshake_ops = shared.ops.lock().unwrap().clone().unwrap();
        *shared.ops.lock().unwrap() = None; // no live session yet
        *shared.handshake_override.lock().unwrap() = Some(std::sync::Arc::new(move || {
            Ok(crate::handshake::HandshakeOutput {
                ops: std::sync::Arc::clone(&handshake_ops),
                lft: None,
                session: synthetic_session(),
            })
        }));
        shared.credentials.lock().unwrap().fields.insert(
            "interactive_auth".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(b"1".to_vec())),
        );
        let driver = crate::driver::NucleusDriver::new(Arc::clone(&shared));
        let mut events = driver
            .interactive(
                spi_connection(),
                ovstorage_plugin::InteractiveAuthCapability::Browser,
                None,
            )
            .await
            .unwrap();
        match events.next().expect("pump emits a terminal event").unwrap() {
            ovstorage_plugin::AuthEvent::Succeeded { credentials, .. } => {
                assert!(
                    shared.has_session(),
                    "the session must be installed before Succeeded is sent"
                );
                let credentials = credentials.expect(
                    "interactive success must hand the effective bundle to ConnectionSet persistence",
                );
                assert!(matches!(
                    credentials.fields.get("oauth"),
                    Some(ovstorage_plugin::SecretValue::OAuthToken {
                        refresh: Some(token),
                        ..
                    }) if token.0 == b"test-refresh"
                ));
            }
            other => panic!("expected Succeeded from the seam pump, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn interactive_success_is_fenced_by_start_generation() {
        use crate::backend::session::{InstallKind, install_handshake_output};
        use ovstorage_plugin::connection::ConnectionAuthDriver as _;

        let (shared, _backend, mock) = factory_with_mock().await;
        let weak = Arc::downgrade(&shared);
        *shared.handshake_override.lock().unwrap() = Some(Arc::new(move || {
            let shared = weak.upgrade().unwrap();
            let winner_ops: Arc<dyn NucleusOps> =
                Arc::new(RuntimeOps::new(MockTransportHandle::new(Arc::clone(&mock))));
            assert!(install_handshake_output(
                &shared,
                winner_ops,
                None,
                NucleusSession {
                    principal: "winner".into(),
                    ..synthetic_session()
                },
                SecretBundle::default(),
                InstallKind::Identity,
                None,
            ));
            let stale_ops: Arc<dyn NucleusOps> =
                Arc::new(RuntimeOps::new(MockTransportHandle::new(Arc::clone(&mock))));
            Ok(crate::handshake::HandshakeOutput {
                ops: stale_ops,
                lft: None,
                session: NucleusSession {
                    principal: "stale".into(),
                    ..synthetic_session()
                },
            })
        }));
        shared.credentials.lock().unwrap().fields.insert(
            "interactive_auth".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(b"1".to_vec())),
        );
        let driver = crate::driver::NucleusDriver::new(Arc::clone(&shared));
        let mut events = driver
            .interactive(
                spi_connection(),
                ovstorage_plugin::InteractiveAuthCapability::Browser,
                None,
            )
            .await
            .unwrap();

        assert!(matches!(
            events.next().unwrap().unwrap(),
            ovstorage_plugin::AuthEvent::Failed { .. }
        ));
        assert_eq!(
            shared.session.lock().unwrap().as_ref().unwrap().principal,
            "winner"
        );
    }
}
