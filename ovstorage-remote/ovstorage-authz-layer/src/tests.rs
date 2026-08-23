// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! [`BuiltinAuthLayer`] tests: the combined authn + authz Layer is exercised in
//! isolation against a recording inner and the moved policy, asserting the
//! resolved-principal stamp DOWN to inner, allow/deny per gated verb, the JWT
//! and peer/dev authn front-ends, and the atomic policy reload.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ovstorage::layers::ALIAS_KIND;
use ovstorage::wrappers::ext;
use ovstorage::{
    AccessDecision, AccessOps, AddressVisibility, AuthEventStream, AuthenticateRequest,
    BackendItemInfo, CancellationToken, Capabilities, ChangeEvent, ChangeStream,
    CheckAccessRequest, ConfigLayer, ConfigValue, Connection, ConnectionId, ConnectionKey,
    ConnectionSnapshot, ConnectionSource, ConnectionUpdateStream, ContinueWriteRequest,
    CopyRequest, CreateDirectoryRequest, DeleteDirectoryRequest, DeleteRequest, Error, ErrorCode,
    Extensions, InteractiveAuthCapability, Layer, LayerConfig, LayerConnectionRequest, LayerHandle,
    LayerKindDescriptor, LayerType, ListPage, ListRequest, ListVersionsRequest, LoadedLayerFactory,
    LocalDelegate, ObjectInfo, RangeReadStrategy, ReadOptions, ReadRequest, ReadResult,
    RenameRequest, Request, Result, RootInfo, RootInfoChange, RootInfoSnapshot,
    RootInfoUpdateStream, RouteSource, SecretBundle, StatOptions, StatRequest,
    UpdateConnectionAttributesRequest, UpdateConnectionCredentialsRequest, UpdateMetadataRequest,
    Url, UserMetadata, VersionPage, WatchDirectoryRequest, WrapperFactory, WriteRedirectBatch,
    WriteRequest, WriteResult, WriteStep,
};
use ovstorage_authz_context::ForwardedHeaders;
use ovstorage_authz_policy::Policy;

use super::{CidrConstraint, ForwardedHeaderConfig, POLICY_CONFIG_KEY, TcpAuthnMode};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn url(value: &str) -> Url {
    ovstorage::address::parse(value).unwrap()
}

fn object_info(address: &Url) -> ObjectInfo {
    ObjectInfo::from((address.clone(), BackendItemInfo::default()))
}

fn test_root(address: &Url) -> RootInfo {
    RootInfo {
        root: address.clone(),
        display_name: None,
        layer_kind: "recorder".to_string(),
        connection_id: None,
        owning_target: None,
        capabilities: Capabilities::empty(),
        range_read_strategy: RangeReadStrategy::default(),
        source: RouteSource::Static {
            layer: ConfigLayer::Programmatic,
        },
        visible: true,
        visibility: AddressVisibility::Visible,
        alias_state: None,
        icon: None,
        user_metadata: UserMetadata::default(),
    }
}

fn policy(toml: &str) -> Arc<Policy> {
    Arc::new(Policy::from_toml(toml).unwrap())
}

// ---------------------------------------------------------------------------
// Recording inner
// ---------------------------------------------------------------------------

/// Inner Layer that records each delegated call (slot + address) and answers
/// with canned success, so a call reaching it is distinguishable from a
/// pre-dispatch deny (which never reaches inner).
#[derive(Default)]
struct RecordingInner {
    calls: Mutex<Vec<(&'static str, Option<String>)>>,
    list_items: Vec<Url>,
    roots: Vec<Url>,
    /// Update-stream changes the recording inner emits from
    /// `list_address_roots`; empty → no stream (the common case), non-empty → a
    /// `Some(stream)` yielding these `RootInfoChange`s (stream-filter test).
    root_updates: Mutex<Vec<Result<RootInfoChange>>>,
    watch_events: Mutex<Vec<Result<ChangeEvent>>>,
    access: Option<AccessDecision>,
    /// The `ext::PRINCIPAL_ID` observed on the most recent `stat` delegation, so
    /// the built-in-auth tests can assert the layer stamped the resolved
    /// principal DOWN to inner.
    stat_principal: Mutex<Option<String>>,
    /// Same observation for the `materialize` (direct-disk) delegation.
    materialize_principal: Mutex<Option<String>>,
    /// The `ext::PRINCIPAL_ID` observed on EVERY delegated verb, keyed by slot —
    /// the allow-side verb matrix asserts each gated verb stamps the resolved
    /// principal DOWN, not only `stat`/`materialize`.
    principals: Mutex<Vec<(&'static str, Option<String>)>>,
    credential_leaks: Mutex<Vec<&'static str>>,
    /// The `(source, destination)` pair observed on each delegated two-address
    /// verb, which `calls` cannot carry because it records one address per call.
    endpoints: Mutex<Vec<(&'static str, String, String)>>,
}

impl RecordingInner {
    fn rec(&self, slot: &'static str, address: Option<&Url>) {
        self.calls
            .lock()
            .unwrap()
            .push((slot, address.map(|u| u.to_string())));
    }

    /// Record BOTH endpoints of a two-address verb.
    ///
    /// `rec` carries one address, which for `copy`/`rename` is the
    /// destination — so the source's delegated spelling had no observer at all.
    /// Kept separate from `calls` so the existing call-count assertions are
    /// unaffected.
    fn note_endpoints(&self, slot: &'static str, source: &Url, destination: &Url) {
        self.endpoints
            .lock()
            .unwrap()
            .push((slot, source.to_string(), destination.to_string()));
    }

    /// The `(source, destination)` pair observed on `slot`'s delegation.
    fn endpoints_of(&self, slot: &str) -> Option<(String, String)> {
        self.endpoints
            .lock()
            .unwrap()
            .iter()
            .find(|(recorded, _, _)| *recorded == slot)
            .map(|(_, source, destination)| (source.clone(), destination.clone()))
    }

    fn saw(&self, slot: &str) -> bool {
        self.calls.lock().unwrap().iter().any(|(s, _)| *s == slot)
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    /// Record the `ext::PRINCIPAL_ID` the layer stamped onto a delegated verb.
    fn note_principal(&self, slot: &'static str, cx: &Extensions) {
        if cx.get(ext::AUTH_CREDENTIAL).is_some() {
            self.credential_leaks.lock().unwrap().push(slot);
        }
        let principal = cx
            .get(ext::PRINCIPAL_ID)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
        self.principals.lock().unwrap().push((slot, principal));
    }

    /// The principal observed on `slot`'s delegation, or `None` if `slot` was
    /// never reached. The inner tuple distinguishes "reached, no stamp" (`Some(
    /// None)`) from "not reached" (`None`).
    fn principal_for(&self, slot: &str) -> Option<Option<String>> {
        self.principals
            .lock()
            .unwrap()
            .iter()
            .find(|(s, _)| *s == slot)
            .map(|(_, p)| p.clone())
    }
}

#[async_trait]
impl Layer for RecordingInner {
    fn name(&self) -> &str {
        "recorder"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            display_name: "recorder".to_string(),
            kind: "recorder".to_string(),
            layer_type: LayerType::Backend,
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: true,
            auth_capable: false,
            supports_user_metadata: true,
        }
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        self.rec("root_info_for", Some(url));
        Ok(test_root(url))
    }

    fn list_kinds(&self, _cx: &Extensions) -> Result<Vec<LayerKindDescriptor>> {
        self.rec("list_kinds", None);
        Ok(vec![self.descriptor()])
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        self.note_principal("list_address_roots", _cx);
        self.rec("list_address_roots", None);
        let queued = std::mem::take(&mut *self.root_updates.lock().unwrap());
        let updates: Option<RootInfoUpdateStream> = if queued.is_empty() {
            None
        } else {
            Some(Box::pin(futures::stream::iter(queued)))
        };
        Ok((
            RootInfoSnapshot {
                roots: self.roots.iter().map(test_root).collect(),
                updates: updates.is_some(),
            },
            updates,
        ))
    }

    async fn list_connections(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        self.note_principal("list_connections", _cx);
        self.rec("list_connections", None);
        Ok((
            ConnectionSnapshot {
                connections: Vec::new(),
                updates: false,
            },
            None,
        ))
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        *self.stat_principal.lock().unwrap() = request
            .extensions
            .get(ext::PRINCIPAL_ID)
            .map(|b| String::from_utf8_lossy(b).into_owned());
        self.note_principal("stat", &request.extensions);
        self.rec("stat", Some(&request.input.address));
        Ok(object_info(&request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.note_principal("read", &request.extensions);
        self.rec("read", Some(&request.input.address));
        Ok(ReadResult::Bytes {
            bytes: Vec::new(),
            info: object_info(&request.input.address),
        })
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        *self.materialize_principal.lock().unwrap() = request
            .extensions
            .get(ext::PRINCIPAL_ID)
            .map(|b| String::from_utf8_lossy(b).into_owned());
        self.note_principal("materialize", &request.extensions);
        self.rec("materialize", Some(&request.input.address));
        Ok(LocalDelegate {
            path: std::path::PathBuf::from("/dev/null"),
            info: object_info(&request.input.address),
            guard: None,
        })
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.note_principal("write", &request.extensions);
        self.rec("write", Some(&request.input.address));
        Ok(WriteResult {
            info: object_info(&request.input.address),
        })
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.note_principal("write_stream", &request.extensions);
        self.rec("write_stream", Some(&request.input.address));
        Ok(WriteResult {
            info: object_info(&request.input.address),
        })
    }

    async fn write_redirect(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        self.note_principal("write_redirect", &request.extensions);
        self.rec("write_redirect", Some(&request.input.address));
        Ok(WriteRedirectBatch {
            continuation: Vec::new(),
            redirects: Vec::new(),
        })
    }

    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        self.note_principal("continue_write", &request.extensions);
        self.rec("continue_write", Some(&request.input.address));
        Ok(WriteStep::Done(WriteResult {
            info: object_info(&request.input.address),
        }))
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.note_principal("delete", &request.extensions);
        self.rec("delete", Some(&request.input.address));
        Ok(())
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        self.note_principal("copy", &request.extensions);
        self.rec("copy", Some(&request.input.destination));
        self.note_endpoints("copy", &request.input.source, &request.input.destination);
        Ok(WriteStep::Done(WriteResult {
            info: object_info(&request.input.destination),
        }))
    }

    async fn rename(
        &self,
        request: Request<RenameRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.note_principal("rename", &request.extensions);
        self.rec("rename", Some(&request.input.destination));
        self.note_endpoints("rename", &request.input.source, &request.input.destination);
        Ok(())
    }

    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        self.note_principal("update_metadata", &request.extensions);
        self.rec("update_metadata", Some(&request.input.address));
        Ok(BackendItemInfo::default())
    }

    async fn check_access(
        &self,
        request: Request<CheckAccessRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        self.note_principal("check_access", &request.extensions);
        self.rec("check_access", Some(&request.input.address));
        Ok(self.access.clone().unwrap_or(AccessDecision {
            allowed: true,
            denied_ops: AccessOps::default(),
            reason: None,
        }))
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        self.note_principal("list", &request.extensions);
        self.rec("list", Some(&request.input.prefix));
        Ok(ListPage {
            items: self.list_items.iter().map(object_info).collect(),
            next_page_token: None,
        })
    }

    async fn list_versions(
        &self,
        request: Request<ListVersionsRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        self.note_principal("list_versions", &request.extensions);
        self.rec("list_versions", Some(&request.input.address));
        Ok(VersionPage {
            items: vec![object_info(&request.input.address)],
            next_page_token: None,
        })
    }

    async fn get_latest_version(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.note_principal("get_latest_version", &request.extensions);
        self.rec("get_latest_version", Some(&request.input.address));
        Ok(object_info(&request.input.address))
    }

    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        self.note_principal("create_directory", &request.extensions);
        self.rec("create_directory", Some(&request.input.address));
        Ok(BackendItemInfo::default())
    }

    async fn delete_directory(
        &self,
        request: Request<DeleteDirectoryRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.note_principal("delete_directory", &request.extensions);
        self.rec("delete_directory", Some(&request.input.address));
        Ok(())
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        self.note_principal("watch_directory", &request.extensions);
        self.rec("watch_directory", Some(&request.input.prefix));
        let events = std::mem::take(&mut *self.watch_events.lock().unwrap());
        Ok(Box::new(events.into_iter()))
    }

    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        self.rec("add_connection", None);
        Ok(canned_connection(&request.input.connection.backend_kind))
    }

    async fn remove_connection(
        &self,
        _key: Request<ConnectionKey>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.rec("remove_connection", None);
        Ok(())
    }

    async fn update_connection_attributes(
        &self,
        request: Request<UpdateConnectionAttributesRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        self.note_principal("update_connection_attributes", &request.extensions);
        self.rec("update_connection_attributes", None);
        Ok(canned_connection(ALIAS_KIND))
    }

    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        self.note_principal("update_connection_credentials", &request.extensions);
        self.rec("update_connection_credentials", None);
        Ok(canned_connection("test"))
    }

    async fn authenticate_connection(
        &self,
        request: Request<AuthenticateRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        self.note_principal("authenticate_connection", &request.extensions);
        self.rec("authenticate_connection", None);
        Ok(Box::new(std::iter::empty()))
    }
}

fn canned_connection(backend_kind: &str) -> Connection {
    Connection {
        id: ConnectionId("conn-1".to_string()),
        backend_kind: backend_kind.to_string(),
        display_name: backend_kind.to_string(),
        source: ConnectionSource::Runtime { persisted: false },
        capabilities: Capabilities::empty(),
        current_addresses: Vec::new(),
        auth_state: ovstorage::ConnectionAuthState::Anonymous,
        last_probed: None,
        user_metadata: UserMetadata::default(),
    }
}

// ---------------------------------------------------------------------------
// BuiltinAuthLayer scaffold
//
// The built-in combined auth layer resolves a principal from the request's
// `ext::AUTH_CREDENTIAL` (placeholder authn for this task), evaluates the fresh
// policy (no epoch), and on allow stamps `ext::PRINCIPAL_ID` DOWN to inner. The
// deny path returns `PermissionDenied` and never reaches inner.
// ---------------------------------------------------------------------------

use arc_swap::ArcSwap;
use ovstorage::wrappers::ext::AUTH_CREDENTIAL;
use ovstorage_authz_context::{AuthCredential, Transport};

use serde_json::json;

use super::authn::jwt::{JwtConfig, resolve_jwt};
use super::{
    BUILTIN_AUTH_KIND, BuiltinAuthLayer, BuiltinAuthLayerFactory, BuiltinAuthn, ListenerAuth,
    compose_listener_auth_stack_with_factories, registered_plugin_auth_kinds,
};

const PLUGIN_AUTH_KIND: &str = "test-plugin-auth";
const PLUGIN_AUTH_ALLOW: &str = "test.plugin-auth.allow";
const PLUGIN_AUTH_PRINCIPAL: &str = "test:plugin-principal";

struct PluginAuthGateFactory {
    auth_capable: bool,
    stamp_principal: bool,
}

impl PluginAuthGateFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            display_name: PLUGIN_AUTH_KIND.to_string(),
            kind: PLUGIN_AUTH_KIND.to_string(),
            layer_type: LayerType::Wrapper,
            description: Some("test listener auth gate".to_string()),
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: false,
            supports_user_metadata: false,
            auth_capable: self.auth_capable,
        }
    }
}

#[async_trait]
impl WrapperFactory for PluginAuthGateFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor()
    }

    async fn create_wrapper(
        &self,
        name: &str,
        _config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(Arc::new(PluginAuthGateLayer {
            name: name.to_string(),
            descriptor: self.descriptor(),
            inner,
            stamp_principal: self.stamp_principal,
        }))
    }
}

struct PluginAuthGateLayer {
    name: String,
    descriptor: LayerKindDescriptor,
    inner: LayerHandle,
    /// Whether the fixture honors the documented auth-wrapper contract and
    /// stamps `ext::PRINCIPAL_ID` DOWN before delegating. `false` models a
    /// non-conformant plugin the host boundary must fail closed on.
    stamp_principal: bool,
}

impl PluginAuthGateLayer {
    fn gate(&self, extensions: &Extensions) -> Result<()> {
        if extensions.get(PLUGIN_AUTH_ALLOW) == Some(b"yes".as_slice()) {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::PermissionDenied,
                "test plugin auth denied request",
            ))
        }
    }

    fn stamp(&self, extensions: &mut Extensions) {
        if self.stamp_principal {
            extensions.insert(
                ext::PRINCIPAL_ID.to_string(),
                PLUGIN_AUTH_PRINCIPAL.as_bytes().to_vec(),
            );
        }
    }
}

#[async_trait]
impl Layer for PluginAuthGateLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    fn list_kinds(&self, cx: &Extensions) -> Result<Vec<LayerKindDescriptor>> {
        self.gate(cx)?;
        let mut cx = cx.clone();
        self.stamp(&mut cx);
        self.inner.list_kinds(&cx).map(|mut kinds| {
            kinds.insert(0, self.descriptor());
            kinds
        })
    }

    async fn stat(
        &self,
        mut request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.gate(&request.extensions)?;
        self.stamp(&mut request.extensions);
        // A hostile or naive wrapper may try to walk around its supplied
        // child. The host boundary is intentionally opaque, so the only
        // reachable handle remains the credential-stripping one.
        let delegated = self.inner.inner_layer().unwrap_or(&self.inner);
        delegated.stat(request, cancel).await
    }
}

/// An allow-anything policy for `uid:7`, the placeholder-authn identity a UDS
/// peer with `uid = 7` resolves to.
const UID7_ALL: &str = r#"
    [[policy]]
    id = "uid7-all"
    effect = "allow"
    principal = "uid:7"
    operations = ["*"]
    prefix = "file:/root/"
"#;

/// A request carrying `ext::AUTH_CREDENTIAL` (encoded wire form), the material a
/// host stamps for the built-in auth layer to decode.
fn auth_request<T>(credential: &AuthCredential, input: T) -> Request<T> {
    let mut extensions = Extensions::new();
    extensions.insert(AUTH_CREDENTIAL.to_string(), credential.encode());
    Request { extensions, input }
}

fn uds_credential(uid: u32) -> AuthCredential {
    AuthCredential::new(
        None,
        Transport::Uds {
            uid,
            gid: uid,
            pid: 100,
        },
    )
}

fn builtin_layer(inner: Arc<RecordingInner>, policy: Arc<Policy>) -> BuiltinAuthLayer {
    builtin_layer_with_jwt(inner, policy, None)
}

fn builtin_layer_with_jwt(
    inner: Arc<RecordingInner>,
    policy: Arc<Policy>,
    jwt: Option<JwtConfig>,
) -> BuiltinAuthLayer {
    let tcp = jwt
        .map(TcpAuthnMode::JwtVerify)
        .unwrap_or(TcpAuthnMode::Anonymous);
    BuiltinAuthLayer::new(
        BUILTIN_AUTH_KIND,
        inner as LayerHandle,
        Arc::new(ArcSwap::from_pointee((*policy).clone())),
        BuiltinAuthn::new(tcp, PeerConfig::default()),
    )
}

#[tokio::test]
async fn builtin_auth_uds_allow_stamps_resolved_principal_on_inner() {
    let inner = Arc::new(RecordingInner::default());
    let l = builtin_layer(inner.clone(), policy(UID7_ALL));

    l.stat(
        auth_request(
            &uds_credential(7),
            StatRequest {
                address: url("file:/root/a"),
                options: StatOptions::default(),
            },
        ),
        None,
    )
    .await
    .unwrap();

    assert!(inner.saw("stat"), "allow must reach inner");
    assert_eq!(
        inner.stat_principal.lock().unwrap().as_deref(),
        Some("uid:7"),
        "the resolved principal is stamped DOWN to inner"
    );
    assert!(
        inner.credential_leaks.lock().unwrap().is_empty(),
        "the raw auth credential must be consumed before delegation"
    );
}

#[tokio::test]
async fn builtin_auth_deny_all_blocks_and_inner_untouched() {
    let inner = Arc::new(RecordingInner::default());
    // Empty policy = deny-all: even a well-formed credential is rejected.
    let l = builtin_layer(inner.clone(), policy(""));

    let err = l
        .stat(
            auth_request(
                &uds_credential(7),
                StatRequest {
                    address: url("file:/root/a"),
                    options: StatOptions::default(),
                },
            ),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert_eq!(inner.call_count(), 0, "deny must not reach inner");
}

/// A `materialize` (direct-disk) request for `uid = 7` against `file:/root/a`.
fn uid7_materialize() -> Request<ReadRequest> {
    auth_request(
        &uds_credential(7),
        ReadRequest {
            address: url("file:/root/a"),
            options: ReadOptions::default(),
        },
    )
}

#[tokio::test]
async fn builtin_auth_materialize_allow_stamps_resolved_principal_on_inner() {
    // The direct-disk verb is gated exactly like `read`: an allowed principal
    // passes through and inner sees the stamped `ext::PRINCIPAL_ID`.
    let inner = Arc::new(RecordingInner::default());
    let l = builtin_layer(inner.clone(), policy(UID7_ALL));

    l.materialize(uid7_materialize(), None).await.unwrap();

    assert!(inner.saw("materialize"), "allow must reach inner");
    assert_eq!(
        inner.materialize_principal.lock().unwrap().as_deref(),
        Some("uid:7"),
        "the resolved principal is stamped DOWN to inner on materialize"
    );
}

#[tokio::test]
async fn builtin_auth_materialize_deny_blocks_and_inner_untouched() {
    // A `materialize` denied by policy returns PermissionDenied and never reaches
    // inner — closing the direct-disk path around the `read` gate.
    let inner = Arc::new(RecordingInner::default());
    let l = builtin_layer(inner.clone(), policy(""));

    let err = l.materialize(uid7_materialize(), None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert_eq!(inner.call_count(), 0, "deny must not reach inner");
}

/// A `stat` for uid 7 against `file:/root/a`. Shared by the reload tests, which
/// exercise the same principal before and after a policy swap.
fn uid7_stat() -> Request<StatRequest> {
    auth_request(
        &uds_credential(7),
        StatRequest {
            address: url("file:/root/a"),
            options: StatOptions::default(),
        },
    )
}

#[tokio::test]
async fn builtin_auth_reload_swaps_policy_and_revokes() {
    let inner = Arc::new(RecordingInner::default());
    let l = builtin_layer(inner.clone(), policy(UID7_ALL));

    // Under the initial allow-all-for-uid-7 policy the principal reaches inner.
    l.stat(uid7_stat(), None).await.unwrap();
    assert!(inner.saw("stat"), "initial policy allows uid 7");

    // Swap in an empty (deny-all) policy; the same principal is now denied on the
    // next request without any epoch involved.
    l.reload("").unwrap();
    let err = l.stat(uid7_stat(), None).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        inner.call_count(),
        1,
        "the post-reload deny must not reach inner"
    );
}

#[tokio::test]
async fn builtin_auth_reload_rejects_bad_toml_and_keeps_prior_policy() {
    let inner = Arc::new(RecordingInner::default());
    let l = builtin_layer(inner.clone(), policy(UID7_ALL));

    // A syntactically invalid document fails to parse; reload returns Err and
    // must NOT swap the live policy.
    let err = l.reload("this is not = = valid toml [[[").unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);

    // The prior allow policy is unchanged: uid 7 is still allowed.
    l.stat(uid7_stat(), None).await.unwrap();
    assert!(inner.saw("stat"), "prior policy survives a failed reload");
}

#[tokio::test]
async fn builtin_auth_factory_builds_layer_from_config_policy() {
    let mut config = LayerConfig::new();
    config.insert(
        POLICY_CONFIG_KEY.to_string(),
        ConfigValue::Toml(UID7_ALL.to_string()),
    );
    let factory = BuiltinAuthLayerFactory::new();
    let inner = Arc::new(RecordingInner::default());
    let handle = factory
        .create_wrapper(
            BUILTIN_AUTH_KIND,
            &config,
            inner.clone() as LayerHandle,
            None,
        )
        .await
        .unwrap();

    // uid 7 (allowed) reaches inner; uid 9 (no rule) is denied.
    handle
        .stat(
            auth_request(
                &uds_credential(7),
                StatRequest {
                    address: url("file:/root/a"),
                    options: StatOptions::default(),
                },
            ),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        handle
            .stat(
                auth_request(
                    &uds_credential(9),
                    StatRequest {
                        address: url("file:/root/a"),
                        options: StatOptions::default(),
                    }
                ),
                None,
            )
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
}

#[tokio::test]
async fn listener_auth_composer_preserves_builtin_handle_and_reload() {
    let mut config = LayerConfig::new();
    config.insert(
        POLICY_CONFIG_KEY.to_string(),
        ConfigValue::Toml(UID7_ALL.to_string()),
    );
    let inner = Arc::new(RecordingInner::default());
    let composed = compose_listener_auth_stack_with_factories(
        "listener-auth",
        BUILTIN_AUTH_KIND,
        &config,
        inner.clone() as LayerHandle,
        &[],
        None,
    )
    .await
    .unwrap();

    assert_eq!(composed.auth_layer.kind(), BUILTIN_AUTH_KIND);
    composed.stack.stat(uid7_stat(), None).await.unwrap();
    assert!(inner.saw("stat"), "the built-in route reaches inner");

    composed.auth_layer.reload_policy("").unwrap();
    let error = composed.stack.stat(uid7_stat(), None).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        inner.call_count(),
        1,
        "the retained built-in handle reloads the policy used by the Stack"
    );
}

#[tokio::test]
async fn listener_auth_composer_builds_auth_capable_plugin_root_and_gates() {
    let factories = vec![LoadedLayerFactory::Wrapper(Arc::new(
        PluginAuthGateFactory {
            auth_capable: true,
            stamp_principal: true,
        },
    ))];
    let inner = Arc::new(RecordingInner::default());
    let composed = compose_listener_auth_stack_with_factories(
        "listener-auth",
        PLUGIN_AUTH_KIND,
        &LayerConfig::new(),
        inner.clone() as LayerHandle,
        &factories,
        None,
    )
    .await
    .unwrap();

    assert_eq!(composed.stack.descriptor().kind, PLUGIN_AUTH_KIND);
    assert_eq!(composed.auth_layer.kind(), PLUGIN_AUTH_KIND);

    let error = composed
        .stack
        .stat(
            Request::new(StatRequest {
                address: url("file:/root/a"),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(inner.call_count(), 0, "plugin deny must not reach inner");

    let error = composed
        .auth_layer
        .authorize_list_backend_kinds(&Extensions::new())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PermissionDenied);

    let mut allowed = Extensions::new();
    allowed.insert(PLUGIN_AUTH_ALLOW.to_string(), b"yes".to_vec());
    composed
        .auth_layer
        .authorize_list_backend_kinds(&allowed)
        .unwrap();
    assert!(inner.saw("list_kinds"));
}

#[tokio::test]
async fn plugin_listener_auth_boundary_strips_credentials_and_passes_down_stamped_principal() {
    let factories = vec![LoadedLayerFactory::Wrapper(Arc::new(
        PluginAuthGateFactory {
            auth_capable: true,
            stamp_principal: true,
        },
    ))];
    let inner = Arc::new(RecordingInner::default());
    let composed = compose_listener_auth_stack_with_factories(
        "listener-auth",
        PLUGIN_AUTH_KIND,
        &LayerConfig::new(),
        inner.clone() as LayerHandle,
        &factories,
        None,
    )
    .await
    .unwrap();

    // The host-owned boundary below the wrapper, not plugin cooperation,
    // confines the raw credential above the storage graph; the wrapper's
    // DOWN-stamped principal is the copy that crosses it.
    let mut extensions = Extensions::new();
    extensions.insert(PLUGIN_AUTH_ALLOW.to_string(), b"yes".to_vec());
    extensions.insert(AUTH_CREDENTIAL.to_string(), b"opaque-secret".to_vec());
    composed
        .stack
        .stat(
            Request {
                extensions,
                input: StatRequest {
                    address: url("file:/root/a"),
                    options: StatOptions::default(),
                },
            },
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        inner.principal_for("stat"),
        Some(Some(PLUGIN_AUTH_PRINCIPAL.to_string())),
        "the plugin's DOWN-stamped principal reaches the layers below the boundary"
    );
    assert!(
        inner.credential_leaks.lock().unwrap().is_empty(),
        "the host boundary must remove raw credentials below plugin auth"
    );
}

#[tokio::test]
async fn plugin_listener_auth_delegation_without_principal_stamp_fails_closed() {
    let factories = vec![LoadedLayerFactory::Wrapper(Arc::new(
        PluginAuthGateFactory {
            auth_capable: true,
            stamp_principal: false,
        },
    ))];
    let inner = Arc::new(RecordingInner::default());
    let composed = compose_listener_auth_stack_with_factories(
        "listener-auth",
        PLUGIN_AUTH_KIND,
        &LayerConfig::new(),
        inner.clone() as LayerHandle,
        &factories,
        None,
    )
    .await
    .unwrap();
    let mut extensions = Extensions::new();
    extensions.insert(PLUGIN_AUTH_ALLOW.to_string(), b"yes".to_vec());

    let error = composed
        .stack
        .stat(
            Request {
                extensions,
                input: StatRequest {
                    address: url("file:/root/a"),
                    options: StatOptions::default(),
                },
            },
            None,
        )
        .await
        .expect_err("a delegation without the DOWN-stamped principal must fail closed");
    assert_eq!(error.code(), ErrorCode::Internal);
    assert!(error.message().contains(PLUGIN_AUTH_KIND));
    assert!(
        error
            .message()
            .contains("delegated without stamping a principal")
    );
    assert_eq!(
        inner.call_count(),
        0,
        "the boundary check runs before the delegation reaches inner"
    );
}

/// Connection management is config-time and ungated under `builtin-auth` —
/// `BuiltinAuthLayer` auto-delegates it through the `Layer::inner_layer`
/// default without a principal stamp — and the plugin route must not
/// diverge: a wrapper that only stamps the data path keeps connection
/// re-crediting and interactive backend auth. The host boundary still
/// confines the raw listener credential on these slots.
#[tokio::test]
async fn plugin_listener_auth_connection_management_is_ungated_and_credential_stripped() {
    let factories = vec![LoadedLayerFactory::Wrapper(Arc::new(
        PluginAuthGateFactory {
            auth_capable: true,
            // The gate fixture stamps only the slots it decorates (`stat`,
            // `list_kinds`); management auto-delegates unstamped, the shape
            // a wrapper following the data-path contract naturally has.
            stamp_principal: true,
        },
    ))];
    let inner = Arc::new(RecordingInner::default());
    let composed = compose_listener_auth_stack_with_factories(
        "listener-auth",
        PLUGIN_AUTH_KIND,
        &LayerConfig::new(),
        inner.clone() as LayerHandle,
        &factories,
        None,
    )
    .await
    .unwrap();

    let key = || ConnectionKey {
        target: "recorder".into(),
        id: ConnectionId("c1".into()),
    };
    let mut extensions = Extensions::new();
    extensions.insert(AUTH_CREDENTIAL.to_string(), b"opaque-secret".to_vec());

    composed
        .stack
        .update_connection_attributes(
            Request {
                extensions: extensions.clone(),
                input: UpdateConnectionAttributesRequest {
                    key: key(),
                    patch: ovstorage::AttributePatch::default(),
                },
            },
            None,
        )
        .await
        .expect("ungated management must delegate without a principal stamp");
    composed
        .stack
        .update_connection_credentials(
            Request {
                extensions: extensions.clone(),
                input: UpdateConnectionCredentialsRequest {
                    key: key(),
                    credentials: ovstorage::SecretBundle::default(),
                },
            },
            None,
        )
        .await
        .expect("ungated management must delegate without a principal stamp");
    let _events = composed
        .stack
        .authenticate_connection(
            Request {
                extensions,
                input: AuthenticateRequest {
                    key: key(),
                    capability: ovstorage::InteractiveAuthCapability::default(),
                    auto_open_browser: false,
                },
            },
            None,
        )
        .await
        .expect("interactive backend auth must survive plugin listener auth");

    for slot in [
        "update_connection_attributes",
        "update_connection_credentials",
        "authenticate_connection",
    ] {
        assert_eq!(
            inner.principal_for(slot),
            Some(None),
            "{slot} reaches inner ungated, with no stamp required"
        );
    }
    assert!(
        inner.credential_leaks.lock().unwrap().is_empty(),
        "the host boundary must still strip raw credentials on management slots"
    );
}

#[tokio::test]
async fn listener_auth_composer_rejects_non_auth_capable_and_unknown_kinds() {
    let factories = vec![LoadedLayerFactory::Wrapper(Arc::new(
        PluginAuthGateFactory {
            auth_capable: false,
            stamp_principal: true,
        },
    ))];

    let error = compose_listener_auth_stack_with_factories(
        "listener-auth",
        PLUGIN_AUTH_KIND,
        &LayerConfig::new(),
        Arc::new(RecordingInner::default()),
        &factories,
        None,
    )
    .await
    .err()
    .expect("non-auth-capable wrapper must fail closed");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains(PLUGIN_AUTH_KIND));
    assert!(error.message().contains("auth-capable wrapper"));

    let error = compose_listener_auth_stack_with_factories(
        "listener-auth",
        "missing-auth",
        &LayerConfig::new(),
        Arc::new(RecordingInner::default()),
        &factories,
        None,
    )
    .await
    .err()
    .expect("unknown auth kind must fail closed");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains("missing-auth"));
    assert!(error.message().contains("no loaded layer factory"));
}

#[tokio::test]
async fn duplicate_listener_auth_kinds_use_the_last_registered_factory() {
    let later_auth_capable = vec![
        LoadedLayerFactory::Wrapper(Arc::new(PluginAuthGateFactory {
            auth_capable: false,
            stamp_principal: true,
        })),
        LoadedLayerFactory::Wrapper(Arc::new(PluginAuthGateFactory {
            auth_capable: true,
            stamp_principal: true,
        })),
    ];
    assert!(
        registered_plugin_auth_kinds(&later_auth_capable).contains(PLUGIN_AUTH_KIND),
        "the effective, later auth-capable override is admitted"
    );
    let composed = compose_listener_auth_stack_with_factories(
        "listener-auth",
        PLUGIN_AUTH_KIND,
        &LayerConfig::new(),
        Arc::new(RecordingInner::default()),
        &later_auth_capable,
        None,
    )
    .await
    .expect("the effective auth-capable override composes");
    assert!(composed.stack.descriptor().auth_capable);

    let later_ineligible = vec![
        LoadedLayerFactory::Wrapper(Arc::new(PluginAuthGateFactory {
            auth_capable: true,
            stamp_principal: true,
        })),
        LoadedLayerFactory::Wrapper(Arc::new(PluginAuthGateFactory {
            auth_capable: false,
            stamp_principal: true,
        })),
    ];
    assert!(
        !registered_plugin_auth_kinds(&later_ineligible).contains(PLUGIN_AUTH_KIND),
        "an earlier eligible factory cannot bypass a later ineligible override"
    );
    let error = compose_listener_auth_stack_with_factories(
        "listener-auth",
        PLUGIN_AUTH_KIND,
        &LayerConfig::new(),
        Arc::new(RecordingInner::default()),
        &later_ineligible,
        None,
    )
    .await
    .err()
    .expect("the effective non-auth-capable override must fail closed");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains("auth-capable wrapper"));
}

#[tokio::test]
async fn plugin_listener_auth_reload_policy_is_informative() {
    let auth = ListenerAuth::plugin(
        PLUGIN_AUTH_KIND.to_string(),
        Arc::new(RecordingInner::default()),
    );

    let error = auth.reload_policy("unused").unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unsupported);
    assert!(error.message().contains(PLUGIN_AUTH_KIND));
    assert!(error.message().contains("no policy hot-reload"));
    assert!(error.message().contains("SIGHUP rebuilds the host"));
}

// ---------------------------------------------------------------------------
// BuiltinAuthLayer JWT authn
//
// `resolve_jwt` validates an OIDC bearer JWT against the layer's configured
// JWKS and maps claims → `ResolvedPrincipal` (ported from REST `jwt.rs`). The
// layer's `Tcp` + bearer branch routes through it; `Uds`/`NamedPipe` peer
// transports stay placeholder. Tests validate offline against an in-memory
// HS256 JWKS (the same approach REST's JWT tests use — no live IdP).
// ---------------------------------------------------------------------------

use jsonwebtoken::jwk::JwkSet;

const TEST_SECRET: &[u8] = b"test-secret-bytes-bytes-bytes-bytes!";
const TEST_KID: &str = "test-key";
const TEST_ISSUER: &str = "https://issuer.test";
const TEST_AUDIENCE: &str = "ovstorage-auth";

/// A single-key HS256 JWKS for `(TEST_KID, TEST_SECRET)`, deserialized into the
/// `jsonwebtoken` `JwkSet` the layer validates against.
fn test_jwks() -> JwkSet {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let value = json!({
        "keys": [{
            "kty": "oct",
            "kid": TEST_KID,
            "alg": "HS256",
            "k": URL_SAFE_NO_PAD.encode(TEST_SECRET),
        }]
    });
    serde_json::from_value(value).unwrap()
}

fn test_jwt_config() -> JwtConfig {
    JwtConfig::from_jwks(
        TEST_ISSUER.to_string(),
        TEST_AUDIENCE.to_string(),
        test_jwks(),
    )
}

fn jwt_timestamp(offset_seconds: i64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    now.saturating_add(offset_seconds).max(0) as u64
}

/// Mint an HS256 JWT for `claims`, signed under `TEST_SECRET` with header `kid`.
fn sign_jwt(claims: &serde_json::Value, kid: &str) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_secret(TEST_SECRET),
    )
    .unwrap()
}

/// A valid claims set (`sub = alice`, current `iss`/`aud`/`exp`/`nbf`) merged
/// with `overrides` — object fields in `overrides` replace/extend the base, so a
/// test can flip a single claim (e.g. a wrong `iss`, an empty `sub`).
fn claims(overrides: serde_json::Value) -> serde_json::Value {
    let mut base = json!({
        "sub": "alice",
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "exp": jwt_timestamp(3600),
        "nbf": jwt_timestamp(-60),
    });
    if let (Some(base), Some(overrides)) = (base.as_object_mut(), overrides.as_object()) {
        for (key, value) in overrides {
            base.insert(key.clone(), value.clone());
        }
    }
    base
}

fn valid_token() -> String {
    sign_jwt(&claims(json!({})), TEST_KID)
}

fn tcp_bearer_credential(token: &str) -> AuthCredential {
    AuthCredential::new(
        Some(token.as_bytes().to_vec()),
        Transport::Tcp {
            peer_addr: "203.0.113.7:443".to_string(),
            tls_client_cert: None,
        },
    )
}

/// Allow-anything policy for `alice`, the subject of the valid test JWT.
const ALICE_ALL: &str = r#"
    [[policy]]
    id = "alice-all"
    effect = "allow"
    principal = "alice"
    operations = ["*"]
    prefix = "file:/root/"
"#;

fn stat_req_input() -> StatRequest {
    StatRequest {
        address: url("file:/root/a"),
        options: StatOptions::default(),
    }
}

#[test]
fn resolve_jwt_maps_claims_to_principal() {
    let token = sign_jwt(
        &claims(json!({ "name": "Alice Example", "groups": "eng" })),
        TEST_KID,
    );
    let principal = resolve_jwt(token.as_bytes(), &test_jwt_config()).unwrap();
    assert_eq!(principal.id, "alice");
    assert_eq!(principal.display_name.as_deref(), Some("Alice Example"));
    assert_eq!(
        principal.attributes.get("jwt.issuer").map(String::as_str),
        Some(TEST_ISSUER)
    );
    assert_eq!(
        principal.attributes.get("jwt.audience").map(String::as_str),
        Some(TEST_AUDIENCE)
    );
    assert_eq!(
        principal.attributes.get("groups").map(String::as_str),
        Some("eng")
    );
}

#[test]
fn resolve_jwt_prefers_preferred_username_when_name_absent() {
    let token = sign_jwt(&claims(json!({ "preferred_username": "al" })), TEST_KID);
    let principal = resolve_jwt(token.as_bytes(), &test_jwt_config()).unwrap();
    assert_eq!(principal.display_name.as_deref(), Some("al"));
}

#[test]
fn resolve_jwt_empty_sub_is_rejected() {
    // `sub` present but empty: `required_spec_claims` passes on presence, so the
    // non-empty check in `principal_from_claims` is what rejects it.
    let token = sign_jwt(&claims(json!({ "sub": "  " })), TEST_KID);
    assert_eq!(
        resolve_jwt(token.as_bytes(), &test_jwt_config())
            .unwrap_err()
            .code(),
        ErrorCode::AuthRequired
    );
}

#[test]
fn resolve_jwt_expired_is_rejected() {
    let token = sign_jwt(&claims(json!({ "exp": jwt_timestamp(-3600) })), TEST_KID);
    assert_eq!(
        resolve_jwt(token.as_bytes(), &test_jwt_config())
            .unwrap_err()
            .code(),
        ErrorCode::AuthRequired
    );
}

#[test]
fn resolve_jwt_wrong_issuer_is_rejected() {
    let token = sign_jwt(&claims(json!({ "iss": "https://evil.test" })), TEST_KID);
    assert_eq!(
        resolve_jwt(token.as_bytes(), &test_jwt_config())
            .unwrap_err()
            .code(),
        ErrorCode::AuthRequired
    );
}

#[test]
fn resolve_jwt_wrong_audience_is_rejected() {
    let token = sign_jwt(&claims(json!({ "aud": "someone-else" })), TEST_KID);
    assert_eq!(
        resolve_jwt(token.as_bytes(), &test_jwt_config())
            .unwrap_err()
            .code(),
        ErrorCode::AuthRequired
    );
}

#[test]
fn resolve_jwt_unknown_kid_is_rejected() {
    // The signing kid is not present in the JWKS → no key resolves.
    let token = sign_jwt(&claims(json!({})), "other-kid");
    assert_eq!(
        resolve_jwt(token.as_bytes(), &test_jwt_config())
            .unwrap_err()
            .code(),
        ErrorCode::AuthRequired
    );
}

#[test]
fn resolve_jwt_malformed_token_is_rejected() {
    assert_eq!(
        resolve_jwt(b"not-a-jwt", &test_jwt_config())
            .unwrap_err()
            .code(),
        ErrorCode::AuthRequired
    );
}

// ---------------------------------------------------------------------------
// JWT algorithm-confusion
//
// The accepted signature algorithms are derived from the RESOLVED KEY's family,
// never from the attacker-controlled token header. A bearer with `alg: HS256`
// whose `kid` resolves to an RSA key must be rejected with a clean auth error —
// never dispatched to the HMAC verify arm against an RSA key (which would call
// `DecodingKey::as_bytes()` → `unreachable!()` and panic).
//
// The RSA keypair below is a fixed 2048-bit test key (private PEM + the JWK
// `n`/`e` public components); it authenticates the RS256 happy path and backs
// the confusion tokens.
// ---------------------------------------------------------------------------

const RSA_KID: &str = "rsa-test-key";
const RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDSLDxsVp1/QoMw
DTQpIsoPr3HWkSzDjUeH9j7RkIH8lF4udeDoDNmWU+iDeDADdGW7nTGP3pcHxOcU
0A83mNB6TU9t2wg+jYbXdEHpQecLN7+Jst616vOpRyZlv8yuowHrBSMFBGN2jpj/
ThOB6z1Ajl/MUF1UEidZnkXuM7dDWq8+2kTqtziLvaMXbH5RXB4If3JM11Eem9jA
NFcnnJJcrxaAoEycTb+Ny+UMEm3qjHyjUcMxaaiRjF/tWiIFiROc1Ff0twHdRhzk
S6vvsDoS8ljmcdoEE90FRub/52ODhKIj2oOwdeQl5PJ0b2r4pRnOvUfZwteKrcDX
L3MraDSzAgMBAAECggEABrHJBOxnXN/Z/ORWxn6osAI3Ho4GPn5YCnEiBBvVwB1b
uKAhl1KddafbjqB76whAm07A/uOorOMtNyD/cxZngZXH02h4JUHtyxwVY2Apg1Z1
v+WWKXY/56LwCqqm0uM3UuyZdnXy0xpsrikm/urmyxEd5QykRGLFpRmhAZrdGgSR
HwdhwcfYaBFCTY1xFu2hkCL/z0lXPOl1wm6TXnrGRGQguFv+mUZ0dtttPqVJU/C3
Nvq8pKgd0d3sPN8D4saZu1iGnjGsYnV3JLG/957c4fc0QkX38xXvJKxtn2ZUJi7+
bTQkebzZtBi+meJ45O0jFF0Mj/gWbA3yzvMC7KPvZQKBgQD8aArfT/NIjktFaIWc
GHzi4HBe6rZjKp24wuZ+lCopOvT7jmMjKJlvhHJ3P/h21hByu+4hkPZETpjBjaGw
QD6sYqctrGr5L/HJN4jw2g2EcHRAIvvzTIsz0QWKlU3Vj1CfveXP3PdISDQjluQy
Q2DOiktqokwOhlMV9sdxBrOshwKBgQDVKkNAbSH5sFm7deh14+ueRhjFOt33y1Cj
GWhcCJtXJTwlT3nuvPjWCbsInV+vrcXI0nxjdsjPQyrKm+cys2M8X3yyv3ZVTrwv
mcPv9LqfdXmX0Nx1NjrSNlTS12H+tw1drPPx1SvmILeHWn/nqLFge60LYutsmCUX
yezGpZyNdQKBgA94jRoM+3t6BVEWzAG6WoVJfnnC5zUC2rIFeD1P9ZmbXILCwn7Y
MTdtpdp7WE5oZo+xxzHVgdLEAobymHOGLJFCZr7c752ge7B6r/EbXHK+tdFsk4bh
LTMa370T07aAV0/DQv/PqnSKwG9iA1C1YoymW2MI2aKWRyd0fdsGryKnAoGATMIG
K3ngxRdyiGVBysnCu2CEZOj4qtTkeYaZpKJYxX2b9ddzkbssY25nkgeRQCJz2Qeq
UOqiDrgh/Yk8LG6aKlA8B+WXx8otS3q0KoDWfrr/iOJlsDNR5QY5bx6to9nojzXL
NebMAvb+/1dgPVvqW1LNkg8RtS3oFXPZtgJGqE0CgYBaDSqBanEyeSAScnOx264L
7dBboHIoJ/oRhXhFjQ2QbyyBZF40Xa7wp7lPrS1TG6mWzJhn/TIaO5JGWUU1XO1v
AHgxFxphMUEyWvJmoc5MmSqK7RRTUAEjqKUe6PpCO4MssNbBGOlRPT0rjVfB1rxT
pYk2KfgAJb85xyyNao00MA==
-----END PRIVATE KEY-----";
const RSA_N: &str = "0iw8bFadf0KDMA00KSLKD69x1pEsw41Hh_Y-0ZCB_JReLnXg6AzZllPog3gwA3Rlu50xj96XB8TnFNAPN5jQek1PbdsIPo2G13RB6UHnCze_ibLeterzqUcmZb_MrqMB6wUjBQRjdo6Y_04Tges9QI5fzFBdVBInWZ5F7jO3Q1qvPtpE6rc4i72jF2x-UVweCH9yTNdRHpvYwDRXJ5ySXK8WgKBMnE2_jcvlDBJt6ox8o1HDMWmokYxf7VoiBYkTnNRX9LcB3UYc5Eur77A6EvJY5nHaBBPdBUbm_-djg4SiI9qDsHXkJeTydG9q-KUZzr1H2cLXiq3A1y9zK2g0sw";
const RSA_E: &str = "AQAB";

/// A single-key RSA JWKS for `(RSA_KID, RSA_N/RSA_E)`.
fn rsa_jwks() -> JwkSet {
    let value = json!({
        "keys": [{
            "kty": "RSA",
            "kid": RSA_KID,
            "alg": "RS256",
            "use": "sig",
            "n": RSA_N,
            "e": RSA_E,
        }]
    });
    serde_json::from_value(value).unwrap()
}

fn rsa_jwt_config() -> JwtConfig {
    JwtConfig::from_jwks(
        TEST_ISSUER.to_string(),
        TEST_AUDIENCE.to_string(),
        rsa_jwks(),
    )
}

/// Mint an RS256 JWT signed with the test RSA private key.
fn sign_rs256(claims: &serde_json::Value, kid: Option<&str>) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = kid.map(str::to_string);
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM.as_bytes()).unwrap(),
    )
    .unwrap()
}

/// Forge an `alg: HS256` JWT (signed under an arbitrary HMAC secret) — the
/// algorithm-confusion payload. `kid` selects whether it targets the RSA key by
/// id or relies on the single-key no-`kid` fallback.
fn forge_hs256(claims: &serde_json::Value, kid: Option<&str>) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = kid.map(str::to_string);
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_secret(b"attacker-chosen-secret"),
    )
    .unwrap()
}

#[test]
fn resolve_jwt_rsa_key_validates_rs256_token() {
    // Positive direction: a genuine RS256 token against the RSA JWKS key still
    // authenticates and resolves the expected principal.
    let token = sign_rs256(&claims(json!({})), Some(RSA_KID));
    let principal = resolve_jwt(token.as_bytes(), &rsa_jwt_config()).unwrap();
    assert_eq!(principal.id, "alice");
}

#[test]
fn resolve_jwt_hs256_over_rsa_key_is_rejected_not_panicked() {
    // Negative direction (the DoS): `alg: HS256` with a `kid` resolving to the
    // RSA key. The accepted-algorithm set is derived from the RSA key family, so
    // HS256 is out-of-family → a clean `AuthRequired`. The test reaching this
    // assertion at all is the proof it did not panic (the pre-fix path would
    // rely on library internals to avoid dispatching to the HMAC verify arm).
    let token = forge_hs256(&claims(json!({})), Some(RSA_KID));
    let err = resolve_jwt(token.as_bytes(), &rsa_jwt_config()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthRequired);
}

#[test]
fn resolve_jwt_hs256_no_kid_single_rsa_key_is_rejected_not_panicked() {
    // Same confusion via the single-key no-`kid` resolution path: the lone RSA
    // key is selected, and an `alg: HS256` header is still rejected cleanly.
    let token = forge_hs256(&claims(json!({})), None);
    let err = resolve_jwt(token.as_bytes(), &rsa_jwt_config()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthRequired);
}

// ---------------------------------------------------------------------------
// JWKS key rotation
//
// The layer holds the JWKS behind an `ArcSwap` refreshed by a background task,
// with an unknown-`kid` backstop: an incoming bearer whose `kid` is absent from
// the current snapshot triggers an out-of-band refetch, so the client's retry
// after the rotated set lands succeeds — no operator SIGHUP required. This
// exercises the end-to-end HTTP refetch path against a mock JWKS server that can
// be swapped from key A to key B.
// ---------------------------------------------------------------------------

const KEY_A_SECRET: &[u8] = b"rotation-key-a-secret-bytes-bytes!!!";
const KEY_A_KID: &str = "rotation-key-a";
const KEY_B_SECRET: &[u8] = b"rotation-key-b-secret-bytes-bytes!!!";
const KEY_B_KID: &str = "rotation-key-b";

/// A single-key HS256 JWKS document (JSON string) for `(kid, secret)`.
fn hs256_jwks_json(kid: &str, secret: &[u8]) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    json!({
        "keys": [{
            "kty": "oct",
            "kid": kid,
            "alg": "HS256",
            "k": URL_SAFE_NO_PAD.encode(secret),
        }]
    })
    .to_string()
}

/// Mint an HS256 JWT for `claims` under `secret` with header `kid`.
fn sign_jwt_with(claims: &serde_json::Value, kid: &str, secret: &[u8]) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_secret(secret),
    )
    .unwrap()
}

/// Stand up a minimal HTTP JWKS server on an ephemeral port serving the body
/// currently held in `body` (swappable to rotate keys). Returns the URL to fetch
/// from. The server loops for the lifetime of the test process.
async fn spawn_jwks_server(body: std::sync::Arc<ArcSwap<String>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let payload = body.load_full();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                // Drain the request so the client's write completes before we
                // reply; the exact bytes are irrelevant (single JWKS endpoint).
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload,
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });
    format!("http://{addr}/jwks.json")
}

#[tokio::test]
async fn jwks_unknown_kid_triggers_refresh_and_accepts_rotated_key() {
    // Server initially serves key A only.
    let body = std::sync::Arc::new(ArcSwap::from_pointee(hs256_jwks_json(
        KEY_A_KID,
        KEY_A_SECRET,
    )));
    let url = spawn_jwks_server(std::sync::Arc::clone(&body)).await;

    let cfg = JwtConfig::fetch(TEST_ISSUER.to_string(), TEST_AUDIENCE.to_string(), &url)
        .await
        .unwrap();

    // A bearer signed with key B (a `kid` the current JWKS does not contain).
    let token_b = sign_jwt_with(&claims(json!({})), KEY_B_KID, KEY_B_SECRET);

    // First resolve: unknown kid → AuthRequired, and the backstop fires a
    // background refetch.
    let err = resolve_jwt(token_b.as_bytes(), &cfg).unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthRequired);

    // Rotate the server to serve key B.
    body.store(std::sync::Arc::new(hs256_jwks_json(
        KEY_B_KID,
        KEY_B_SECRET,
    )));

    // Poll (bounded) until the background refetch lands and the key-B token
    // validates. The refetch was triggered by the unknown-kid resolve above; a
    // second notify keeps the loop from waiting on the 300s TTL if the first
    // wake raced the server rotation.
    let mut accepted = false;
    for _ in 0..40 {
        if let Ok(principal) = resolve_jwt(token_b.as_bytes(), &cfg) {
            assert_eq!(principal.id, "alice");
            accepted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        accepted,
        "rotated key-B token was not accepted after the background JWKS refetch"
    );
}

#[tokio::test]
async fn jwks_failed_refetch_retains_previous_set_then_recovers() {
    // A transient IdP outage (a failed/malformed refetch) must NOT blank the
    // JWKS: the previous set is retained so already-issued tokens keep validating.
    let body = std::sync::Arc::new(ArcSwap::from_pointee(hs256_jwks_json(
        KEY_A_KID,
        KEY_A_SECRET,
    )));
    let url = spawn_jwks_server(std::sync::Arc::clone(&body)).await;
    let cfg = JwtConfig::fetch(TEST_ISSUER.to_string(), TEST_AUDIENCE.to_string(), &url)
        .await
        .unwrap();

    // Baseline: a key-A token validates against the initial set.
    let token_a = sign_jwt_with(&claims(json!({})), KEY_A_KID, KEY_A_SECRET);
    assert_eq!(resolve_jwt(token_a.as_bytes(), &cfg).unwrap().id, "alice");

    // The endpoint starts serving a malformed body, so any refetch now fails at
    // JSON parse (an IdP hiccup / bad deploy).
    body.store(std::sync::Arc::new("}{ not valid json".to_string()));

    // A key-B bearer (unknown kid) fires the out-of-band refetch, which fails
    // against the malformed body.
    let token_b = sign_jwt_with(&claims(json!({})), KEY_B_KID, KEY_B_SECRET);
    assert_eq!(
        resolve_jwt(token_b.as_bytes(), &cfg).unwrap_err().code(),
        ErrorCode::AuthRequired
    );

    // Let the background refetch run and fail; the previous (key-A) set must be
    // retained, so the key-A token still validates.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        resolve_jwt(token_a.as_bytes(), &cfg).unwrap().id,
        "alice",
        "a failed refetch must retain the previous JWKS, not blank it"
    );

    // The IdP recovers and rotates to key B; the unknown-kid backstop now lands
    // the new set and the key-B token is accepted.
    body.store(std::sync::Arc::new(hs256_jwks_json(
        KEY_B_KID,
        KEY_B_SECRET,
    )));
    let mut accepted = false;
    for _ in 0..40 {
        if let Ok(principal) = resolve_jwt(token_b.as_bytes(), &cfg) {
            assert_eq!(principal.id, "alice");
            accepted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        accepted,
        "key-B token not accepted after the IdP recovered and rotated"
    );
}

#[tokio::test]
async fn builtin_auth_tcp_bearer_validates_jwt_and_stamps_sub() {
    let inner = Arc::new(RecordingInner::default());
    let l = builtin_layer_with_jwt(inner.clone(), policy(ALICE_ALL), Some(test_jwt_config()));

    l.stat(
        auth_request(&tcp_bearer_credential(&valid_token()), stat_req_input()),
        None,
    )
    .await
    .unwrap();

    assert!(inner.saw("stat"), "a valid JWT reaches inner");
    assert_eq!(
        inner.stat_principal.lock().unwrap().as_deref(),
        Some("alice"),
        "the JWT `sub` is stamped DOWN to inner as the principal"
    );
}

#[tokio::test]
async fn builtin_auth_tcp_invalid_jwt_is_auth_required() {
    let inner = Arc::new(RecordingInner::default());
    let l = builtin_layer_with_jwt(inner.clone(), policy(ALICE_ALL), Some(test_jwt_config()));

    let err = l
        .stat(
            auth_request(&tcp_bearer_credential("garbage-token"), stat_req_input()),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthRequired);
    assert_eq!(inner.call_count(), 0, "an invalid JWT never reaches inner");
}

#[tokio::test]
async fn builtin_auth_tcp_without_jwt_config_falls_through_to_anonymous() {
    // No JWT config: a `Tcp` bearer resolves anonymous, so an anonymous-allow
    // policy admits it (the bearer bytes are not treated as an identity).
    let toml = r#"
        [[policy]]
        id = "anon-all"
        effect = "allow"
        principal = "anonymous"
        operations = ["*"]
        prefix = "file:/root/"
    "#;
    let inner = Arc::new(RecordingInner::default());
    let l = builtin_layer_with_jwt(inner.clone(), policy(toml), None);

    l.stat(
        auth_request(&tcp_bearer_credential(&valid_token()), stat_req_input()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        inner.stat_principal.lock().unwrap().as_deref(),
        Some("anonymous")
    );
}

#[test]
fn jwt_params_parse_is_all_or_nothing() {
    // No keys → no JWT authn.
    assert!(
        super::jwt_params_from_config(&LayerConfig::new())
            .unwrap()
            .is_none()
    );

    // A partial set is a config error (a half-configured validator would admit
    // every bearer as anonymous).
    let mut partial = LayerConfig::new();
    partial.insert(
        super::JWT_ISSUER_CONFIG_KEY.to_string(),
        ConfigValue::String(TEST_ISSUER.to_string()),
    );
    assert_eq!(
        super::jwt_params_from_config(&partial).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );

    // All three present → parsed.
    let mut full = LayerConfig::new();
    full.insert(
        super::JWT_ISSUER_CONFIG_KEY.to_string(),
        ConfigValue::String(TEST_ISSUER.to_string()),
    );
    full.insert(
        super::JWT_AUDIENCE_CONFIG_KEY.to_string(),
        ConfigValue::String(TEST_AUDIENCE.to_string()),
    );
    full.insert(
        super::JWT_JWKS_URL_CONFIG_KEY.to_string(),
        ConfigValue::String("https://issuer.test/jwks".to_string()),
    );
    assert!(super::jwt_params_from_config(&full).unwrap().is_some());
}

// ---------------------------------------------------------------------------
// BuiltinAuthLayer peer/dev authn
//
// `resolve_peer` maps already-gathered transport peer credentials
// (`Transport::{Uds, NamedPipe}`) to a `ResolvedPrincipal`, ported from the
// broker's `GrpcAuthnMode::{DevCurrentUser, PeerCred}` principal construction.
// The layer's `Uds`/`NamedPipe` branch routes through it. `dev_current_user`
// mode overrides the peer creds with the host's current OS user (a local-dev
// convenience).
// ---------------------------------------------------------------------------

use super::PEER_DEV_CURRENT_USER_CONFIG_KEY;
use super::authn::peer::{PeerConfig, resolve_peer};

/// The host's current OS user, computed the same way `current_principal` does,
/// so a `dev_current_user` assertion is deterministic without mutating env.
fn current_os_user() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "local".into())
}

fn named_pipe_credential(sid: &str, pid: u32) -> AuthCredential {
    AuthCredential::new(
        None,
        Transport::NamedPipe {
            sid: sid.to_string(),
            pid,
        },
    )
}

/// Allow-anything policy for `sid:S-1-5-21-1`, the identity a named-pipe peer
/// with that SID resolves to under `peer_cred`.
const SID_ALL: &str = r#"
    [[policy]]
    id = "sid-all"
    effect = "allow"
    principal = "sid:S-1-5-21-1"
    operations = ["*"]
    prefix = "file:/root/"
"#;

#[test]
fn resolve_peer_uds_maps_uid_and_records_creds() {
    let principal = resolve_peer(
        &Transport::Uds {
            uid: 7,
            gid: 8,
            pid: 100,
        },
        &PeerConfig::default(),
    )
    .unwrap();
    assert_eq!(principal.id, "uid:7");
    assert!(principal.display_name.is_none());
    assert_eq!(
        principal.attributes.get("uid").map(String::as_str),
        Some("7")
    );
    assert_eq!(
        principal.attributes.get("gid").map(String::as_str),
        Some("8")
    );
    assert_eq!(
        principal.attributes.get("pid").map(String::as_str),
        Some("100")
    );
}

#[test]
fn resolve_peer_named_pipe_maps_sid_and_records_creds() {
    let principal = resolve_peer(
        &Transport::NamedPipe {
            sid: "S-1-5-21-1".to_string(),
            pid: 42,
        },
        &PeerConfig::default(),
    )
    .unwrap();
    assert_eq!(principal.id, "sid:S-1-5-21-1");
    assert_eq!(
        principal.attributes.get("sid").map(String::as_str),
        Some("S-1-5-21-1")
    );
    assert_eq!(
        principal.attributes.get("pid").map(String::as_str),
        Some("42")
    );
}

#[test]
fn resolve_peer_named_pipe_empty_sid_is_anonymous() {
    // Client-SID gathering is deferred, so an empty SID resolves to anonymous
    // (an anonymous-configured named-pipe listener still functions) rather than
    // failing closed.
    let principal = resolve_peer(
        &Transport::NamedPipe {
            sid: "   ".to_string(),
            pid: 42,
        },
        &PeerConfig::default(),
    )
    .unwrap();
    assert_eq!(principal.id, "anonymous");
}

#[test]
fn resolve_peer_uds_missing_cred_sentinel_is_anonymous() {
    // A `uid == u32::MAX` sentinel (host `SO_PEERCRED` yielded nothing) carries
    // no identity: it resolves to anonymous, so a broad `uid:*` policy glob
    // cannot match a credential-less caller.
    let principal = resolve_peer(
        &Transport::Uds {
            uid: u32::MAX,
            gid: u32::MAX,
            pid: 0,
        },
        &PeerConfig::default(),
    )
    .unwrap();
    assert_eq!(principal.id, "anonymous");
}

#[test]
fn resolve_peer_dev_current_user_overrides_transport_creds() {
    let cfg = PeerConfig {
        dev_current_user: true,
    };
    // Even a UDS peer with a concrete uid resolves to the host's current user.
    let principal = resolve_peer(
        &Transport::Uds {
            uid: 999,
            gid: 999,
            pid: 1,
        },
        &cfg,
    )
    .unwrap();
    assert_eq!(principal.id, current_os_user());
    assert!(
        principal.attributes.is_empty(),
        "dev-current-user carries no peer attributes"
    );
}

#[test]
fn peer_config_parse_defaults_off_and_reads_bool() {
    assert!(
        !super::peer_config_from_config(&LayerConfig::new())
            .unwrap()
            .dev_current_user
    );

    let mut on = LayerConfig::new();
    on.insert(
        PEER_DEV_CURRENT_USER_CONFIG_KEY.to_string(),
        ConfigValue::Bool(true),
    );
    assert!(
        super::peer_config_from_config(&on)
            .unwrap()
            .dev_current_user
    );

    // A wrong-typed value is a config error, not a silent default.
    let mut bad = LayerConfig::new();
    bad.insert(
        PEER_DEV_CURRENT_USER_CONFIG_KEY.to_string(),
        ConfigValue::String("yes".to_string()),
    );
    assert_eq!(
        super::peer_config_from_config(&bad).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}

#[tokio::test]
async fn builtin_auth_named_pipe_routes_through_peer_resolver() {
    let inner = Arc::new(RecordingInner::default());
    let l = builtin_layer(inner.clone(), policy(SID_ALL));

    l.stat(
        auth_request(&named_pipe_credential("S-1-5-21-1", 42), stat_req_input()),
        None,
    )
    .await
    .unwrap();

    assert!(
        inner.saw("stat"),
        "an allowed named-pipe peer reaches inner"
    );
    assert_eq!(
        inner.stat_principal.lock().unwrap().as_deref(),
        Some("sid:S-1-5-21-1"),
        "the resolved SID principal is stamped DOWN to inner"
    );
}

#[tokio::test]
async fn builtin_auth_factory_enables_dev_current_user() {
    // With `dev_current_user`, a UDS peer resolves to the host's current OS
    // user, not `uid:{uid}` — the local-dev shape the broker's DevCurrentUser
    // listener produced.
    let current = current_os_user();
    let toml = format!(
        r#"
        [[policy]]
        id = "dev-all"
        effect = "allow"
        principal = "{current}"
        operations = ["*"]
        prefix = "file:/root/"
    "#
    );
    let mut config = LayerConfig::new();
    config.insert(POLICY_CONFIG_KEY.to_string(), ConfigValue::Toml(toml));
    config.insert(
        PEER_DEV_CURRENT_USER_CONFIG_KEY.to_string(),
        ConfigValue::Bool(true),
    );

    let factory = BuiltinAuthLayerFactory::new();
    let inner = Arc::new(RecordingInner::default());
    let handle = factory
        .create_wrapper(
            BUILTIN_AUTH_KIND,
            &config,
            inner.clone() as LayerHandle,
            None,
        )
        .await
        .unwrap();

    handle
        .stat(auth_request(&uds_credential(999), stat_req_input()), None)
        .await
        .unwrap();
    assert_eq!(
        inner.stat_principal.lock().unwrap().as_deref(),
        Some(current.as_str()),
        "dev_current_user stamps the host user, ignoring the peer uid"
    );
}

// ---------------------------------------------------------------------------
// Gated-verb deny/allow MATRIX
//
// The layer gates every data verb, the two per-principal introspection slots,
// and the two credential-establishing slots; a dropped or renamed override
// silently becomes an authz bypass (the trait default auto-delegates to the
// *unauthorized* inner). A green suite must therefore exercise EVERY gated verb
// on both the deny and the allow side, plus the multi-check decomposition of
// `copy` (Read+Write) and `rename` (Read+Delete+Write) — dropping any single
// component check must be caught.
// ---------------------------------------------------------------------------

use ovstorage::{
    Body, CopyOptions, CreateDirectoryOptions, DeleteDirectoryOptions, DeleteOptions, ListOptions,
    ListVersionsOptions, RedirectResultBatch, RenameOptions, UpdateMetadataOptions,
    WatchDirectoryOptions, WriteOptions,
};

const GATE_ADDR: &str = "file:/root/a";
const GATE_SRC: &str = "file:/root/src";
const GATE_DST: &str = "file:/root/dst";
const GATE_DIR: &str = "file:/root/d/";
const GATE_PREFIX: &str = "file:/root/";

fn read_input() -> ReadRequest {
    ReadRequest {
        address: url(GATE_ADDR),
        options: ReadOptions::default(),
    }
}

fn write_input() -> WriteRequest {
    WriteRequest {
        address: url(GATE_ADDR),
        body: Body::Bytes(Vec::new()),
        options: WriteOptions::default(),
    }
}

fn continue_write_input() -> ContinueWriteRequest {
    ContinueWriteRequest {
        address: url(GATE_ADDR),
        redirects: WriteRedirectBatch {
            continuation: Vec::new(),
            redirects: Vec::new(),
        },
        results: RedirectResultBatch {
            results: Vec::new(),
        },
    }
}

fn delete_input() -> DeleteRequest {
    DeleteRequest {
        address: url(GATE_ADDR),
        options: DeleteOptions::default(),
    }
}

fn copy_input() -> CopyRequest {
    CopyRequest {
        source: url(GATE_SRC),
        destination: url(GATE_DST),
        options: CopyOptions::default(),
    }
}

fn rename_input() -> RenameRequest {
    RenameRequest {
        source: url(GATE_SRC),
        destination: url(GATE_DST),
        options: RenameOptions::default(),
    }
}

fn update_metadata_input() -> UpdateMetadataRequest {
    UpdateMetadataRequest {
        address: url(GATE_ADDR),
        options: UpdateMetadataOptions::default(),
    }
}

fn check_access_input() -> CheckAccessRequest {
    CheckAccessRequest {
        address: url(GATE_ADDR),
        operations: AccessOps::default(),
    }
}

fn list_input() -> ListRequest {
    ListRequest {
        prefix: url(GATE_PREFIX),
        options: ListOptions::default(),
    }
}

fn list_versions_input() -> ListVersionsRequest {
    ListVersionsRequest {
        address: url(GATE_ADDR),
        options: ListVersionsOptions::default(),
    }
}

fn create_directory_input() -> CreateDirectoryRequest {
    CreateDirectoryRequest {
        address: url(GATE_DIR),
        options: CreateDirectoryOptions::default(),
    }
}

fn delete_directory_input() -> DeleteDirectoryRequest {
    DeleteDirectoryRequest {
        address: url(GATE_DIR),
        options: DeleteDirectoryOptions,
    }
}

fn watch_directory_input() -> WatchDirectoryRequest {
    WatchDirectoryRequest {
        prefix: url(GATE_PREFIX),
        options: WatchDirectoryOptions::default(),
    }
}

fn connection_key() -> ConnectionKey {
    ConnectionKey {
        target: "backend".to_string(),
        id: ConnectionId("conn-1".to_string()),
    }
}

fn update_connection_credentials_input() -> UpdateConnectionCredentialsRequest {
    UpdateConnectionCredentialsRequest {
        key: connection_key(),
        credentials: SecretBundle::default(),
    }
}

fn authenticate_input() -> AuthenticateRequest {
    AuthenticateRequest {
        key: connection_key(),
        capability: InteractiveAuthCapability::Headless,
        auto_open_browser: false,
    }
}

fn upstream_auth_request<T>(input: T, address: &str) -> Request<T> {
    let mut request = auth_request(&uds_credential(7), input);
    ext::insert_upstream_auth_address(
        &mut request.extensions,
        &Url::parse(address).expect("test upstream address parses"),
    );
    request
}

/// A fresh deny-all layer (empty policy) and its recording inner.
fn deny_all_pair() -> (Arc<RecordingInner>, BuiltinAuthLayer) {
    let inner = Arc::new(RecordingInner::default());
    let layer = builtin_layer(inner.clone(), policy(""));
    (inner, layer)
}

/// An allow-anything-for-uid-7 policy on the GLOBAL (`*`) prefix — unlike
/// `UID7_ALL` (rooted at `file:/root/`) this also matches the address-less
/// introspection slots (`list_address_roots` / `list_connections`), whose
/// `evaluate(None)` a prefixed rule never matches.
const UID7_ALL_GLOBAL: &str = r#"
    [[policy]]
    id = "uid7-all-global"
    effect = "allow"
    principal = "uid:7"
    operations = ["*"]
    prefix = "*"
"#;

/// A fresh allow-anything-for-uid-7 layer and its recording inner.
fn allow_all_pair() -> (Arc<RecordingInner>, BuiltinAuthLayer) {
    let inner = Arc::new(RecordingInner::default());
    let layer = builtin_layer(inner.clone(), policy(UID7_ALL_GLOBAL));
    (inner, layer)
}

/// The credential-carrying `Extensions` a sync introspection slot receives (the
/// synchronous analogue of `auth_request`).
fn auth_cx(credential: &AuthCredential) -> Extensions {
    let mut extensions = Extensions::new();
    extensions.insert(AUTH_CREDENTIAL.to_string(), credential.encode());
    extensions
}

#[tokio::test]
async fn deny_all_blocks_every_gated_verb_without_reaching_inner() {
    // A fresh deny-all pair per verb pinpoints a single leak to its verb rather
    // than masking it behind an earlier one.
    macro_rules! deny_async {
        ($method:ident, $input:expr) => {{
            let (inner, layer) = deny_all_pair();
            // `.err()` (not `.unwrap_err()`): some verbs' Ok type (e.g. the
            // `watch_directory` stream) is not `Debug`.
            let err = layer
                .$method(auth_request(&uds_credential(7), $input), None)
                .await
                .err()
                .unwrap_or_else(|| panic!("{} must return a deny error", stringify!($method)));
            assert_eq!(
                err.code(),
                ErrorCode::PermissionDenied,
                "{} must deny under a deny-all policy",
                stringify!($method)
            );
            assert_eq!(
                inner.call_count(),
                0,
                "{} deny must not reach inner",
                stringify!($method)
            );
        }};
    }

    deny_async!(stat, stat_req_input());
    deny_async!(read, read_input());
    deny_async!(materialize, read_input());
    deny_async!(write, write_input());
    deny_async!(write_stream, write_input());
    deny_async!(write_redirect, write_input());
    deny_async!(continue_write, continue_write_input());
    deny_async!(delete, delete_input());
    deny_async!(copy, copy_input());
    deny_async!(rename, rename_input());
    deny_async!(update_metadata, update_metadata_input());
    deny_async!(check_access, check_access_input());
    deny_async!(list, list_input());
    deny_async!(list_versions, list_versions_input());
    deny_async!(get_latest_version, read_input());
    deny_async!(create_directory, create_directory_input());
    deny_async!(delete_directory, delete_directory_input());
    deny_async!(watch_directory, watch_directory_input());
    deny_async!(
        update_connection_credentials,
        update_connection_credentials_input()
    );
    deny_async!(authenticate_connection, authenticate_input());

    // The two per-principal introspection slots take `&Extensions` rather than
    // a `Request`; their Ok type is not `Debug`, so inspect the error via
    // `.err()` rather than `.unwrap_err()`.
    let (inner, layer) = deny_all_pair();
    assert_eq!(
        layer
            .list_address_roots(&auth_cx(&uds_credential(7)), None)
            .await
            .err()
            .map(|err| err.code()),
        Some(ErrorCode::PermissionDenied)
    );
    assert_eq!(
        inner.call_count(),
        0,
        "list_address_roots deny must not reach inner"
    );

    let (inner, layer) = deny_all_pair();
    assert_eq!(
        layer
            .list_connections(&auth_cx(&uds_credential(7)), None)
            .await
            .err()
            .map(|err| err.code()),
        Some(ErrorCode::PermissionDenied)
    );
    assert_eq!(
        inner.call_count(),
        0,
        "list_connections deny must not reach inner"
    );
}

#[tokio::test]
async fn allow_all_reaches_inner_and_stamps_principal_on_every_gated_verb() {
    macro_rules! allow_async {
        ($slot:literal, $method:ident, $input:expr) => {{
            let (inner, layer) = allow_all_pair();
            // `let _ =` discards the (possibly `#[must_use]`) return, e.g. the
            // `watch_directory` stream — the assertion is on the inner-observed
            // stamp, not the return value.
            let _ = layer
                .$method(auth_request(&uds_credential(7), $input), None)
                .await
                .unwrap();
            assert_eq!(
                inner.principal_for($slot),
                Some(Some("uid:7".to_string())),
                "{} must reach inner with the resolved principal stamped DOWN",
                $slot
            );
            assert!(
                inner.credential_leaks.lock().unwrap().is_empty(),
                "{} must consume the raw auth credential before delegation",
                $slot
            );
        }};
    }

    allow_async!("stat", stat, stat_req_input());
    allow_async!("read", read, read_input());
    allow_async!("materialize", materialize, read_input());
    allow_async!("write", write, write_input());
    allow_async!("write_stream", write_stream, write_input());
    allow_async!("write_redirect", write_redirect, write_input());
    allow_async!("continue_write", continue_write, continue_write_input());
    allow_async!("delete", delete, delete_input());
    allow_async!("copy", copy, copy_input());
    allow_async!("rename", rename, rename_input());
    allow_async!("update_metadata", update_metadata, update_metadata_input());
    allow_async!("check_access", check_access, check_access_input());
    allow_async!("list", list, list_input());
    allow_async!("list_versions", list_versions, list_versions_input());
    allow_async!("get_latest_version", get_latest_version, read_input());
    allow_async!(
        "create_directory",
        create_directory,
        create_directory_input()
    );
    allow_async!(
        "delete_directory",
        delete_directory,
        delete_directory_input()
    );
    allow_async!("watch_directory", watch_directory, watch_directory_input());
    allow_async!(
        "update_connection_credentials",
        update_connection_credentials,
        update_connection_credentials_input()
    );
    allow_async!(
        "authenticate_connection",
        authenticate_connection,
        authenticate_input()
    );

    let (inner, layer) = allow_all_pair();
    layer
        .list_address_roots(&auth_cx(&uds_credential(7)), None)
        .await
        .unwrap();
    assert_eq!(
        inner.principal_for("list_address_roots"),
        Some(Some("uid:7".to_string())),
        "list_address_roots must reach inner with the principal stamped"
    );

    let (inner, layer) = allow_all_pair();
    layer
        .list_connections(&auth_cx(&uds_credential(7)), None)
        .await
        .unwrap();
    assert_eq!(
        inner.principal_for("list_connections"),
        Some(Some("uid:7".to_string())),
        "list_connections must reach inner with the principal stamped"
    );
}

#[tokio::test]
async fn credential_slots_authorize_against_upstream_auth_address_when_present() {
    const ADDRESS_POLICY: &str = r#"
        [[policy]]
        id = "uid7-update-allowed-upstream"
        effect = "allow"
        principal = "uid:7"
        operations = ["update_connection_credentials"]
        prefix = "s3://allowed/"
    "#;

    macro_rules! assert_address_scoped {
        ($slot:literal, $method:ident, $input:expr) => {{
            let inner = Arc::new(RecordingInner::default());
            let layer = builtin_layer(inner.clone(), policy(ADDRESS_POLICY));
            let _ = layer
                .$method(upstream_auth_request($input, "s3://allowed/object"), None)
                .await
                .unwrap();
            assert_eq!(
                inner.principal_for($slot),
                Some(Some("uid:7".to_string())),
                "{} must use the allowed upstream address and stamp the principal",
                $slot
            );
            assert!(
                inner.credential_leaks.lock().unwrap().is_empty(),
                "{} must not delegate the raw auth credential",
                $slot
            );

            let inner = Arc::new(RecordingInner::default());
            let layer = builtin_layer(inner.clone(), policy(ADDRESS_POLICY));
            let error = layer
                .$method(upstream_auth_request($input, "s3://denied/object"), None)
                .await
                .err()
                .unwrap_or_else(|| panic!("{} must deny the unmatched address", $slot));
            assert_eq!(error.code(), ErrorCode::PermissionDenied);
            assert_eq!(
                inner.call_count(),
                0,
                "{} address-scoped deny must not reach inner",
                $slot
            );
        }};
    }

    assert_address_scoped!(
        "update_connection_credentials",
        update_connection_credentials,
        update_connection_credentials_input()
    );
    assert_address_scoped!(
        "authenticate_connection",
        authenticate_connection,
        authenticate_input()
    );
}

/// Allow uid:7 everything under `file:/root/` EXCEPT `op` (a later same-prefix
/// deny rule wins the tie for the listed operation). Drops exactly one of a
/// decomposed verb's component checks.
fn allow_all_except(op: &str) -> Arc<Policy> {
    policy(&format!(
        r#"
        [[policy]]
        id = "base-allow"
        effect = "allow"
        principal = "uid:7"
        operations = ["*"]
        prefix = "file:/root/"

        [[policy]]
        id = "deny-{op}"
        effect = "deny"
        principal = "uid:7"
        operations = ["{op}"]
        prefix = "file:/root/"
    "#
    ))
}

#[tokio::test]
async fn rename_denies_when_any_decomposed_check_is_denied() {
    // rename = Read(src) + Delete(src) + Write(dst). Denying any single
    // component must deny the whole rename before inner — so a dropped Delete(src)
    // check (the easy one to forget) is caught.
    for op in ["read", "delete", "write"] {
        let inner = Arc::new(RecordingInner::default());
        let layer = builtin_layer(inner.clone(), allow_all_except(op));
        let err = layer
            .rename(auth_request(&uds_credential(7), rename_input()), None)
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            ErrorCode::PermissionDenied,
            "rename must deny when its {op} component is denied"
        );
        assert_eq!(
            inner.call_count(),
            0,
            "rename deny ({op}) must not reach inner"
        );
    }
}

#[tokio::test]
async fn copy_denies_when_any_decomposed_check_is_denied() {
    // copy = Read(src) + Write(dst); dropping either component check is a bypass.
    for op in ["read", "write"] {
        let inner = Arc::new(RecordingInner::default());
        let layer = builtin_layer(inner.clone(), allow_all_except(op));
        let err = layer
            .copy(auth_request(&uds_credential(7), copy_input()), None)
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            ErrorCode::PermissionDenied,
            "copy must deny when its {op} component is denied"
        );
        assert_eq!(
            inner.call_count(),
            0,
            "copy deny ({op}) must not reach inner"
        );
    }
}

// ---------------------------------------------------------------------------
// watch_directory per-event visibility filter
//
// The WatchDirectory pre-check gates opening the stream; each emitted `Object`
// event is then re-evaluated for `Read` against the policy snapshot captured at
// stream open. Denied `Object` events are dropped; `Lapsed` and `Err` items pass
// through unfiltered.
// ---------------------------------------------------------------------------

fn object_event(address: &str) -> ChangeEvent {
    ChangeEvent::Object {
        address: url(address),
        kind: ovstorage::ChangeKind::Modified,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        at: std::time::SystemTime::now(),
        cursor: ovstorage::WatchDirectoryCursor::default(),
    }
}

fn lapsed_event() -> ChangeEvent {
    ChangeEvent::Lapsed {
        since: None,
        cursor: ovstorage::WatchDirectoryCursor::default(),
    }
}

#[tokio::test]
async fn watch_directory_filters_denied_object_events_but_passes_lapsed_and_err() {
    // watch_directory allowed on the prefix; Read allowed under `pub/`, denied
    // (no matching rule) under `priv/`.
    let policy_toml = r#"
        [[policy]]
        id = "watch"
        effect = "allow"
        principal = "uid:7"
        operations = ["watch_directory"]
        prefix = "file:/root/"

        [[policy]]
        id = "read-pub"
        effect = "allow"
        principal = "uid:7"
        operations = ["read"]
        prefix = "file:/root/pub/"
    "#;
    let inner = Arc::new(RecordingInner::default());
    *inner.watch_events.lock().unwrap() = vec![
        Ok(object_event("file:/root/pub/a")),
        Ok(object_event("file:/root/priv/b")),
        Ok(lapsed_event()),
        Err(ovstorage::Error::new(
            ErrorCode::Internal,
            "watch backend hiccup",
        )),
    ];
    let layer = builtin_layer(inner.clone(), policy(policy_toml));

    let stream = layer
        .watch_directory(
            auth_request(
                &uds_credential(7),
                WatchDirectoryRequest {
                    prefix: url("file:/root/"),
                    options: WatchDirectoryOptions::default(),
                },
            ),
            None,
        )
        .await
        .unwrap();
    let events: Vec<Result<ChangeEvent>> = stream.collect();

    // The denied `priv/` Object is filtered; the allowed Object, the Lapsed, and
    // the Err all survive.
    assert_eq!(
        events.len(),
        3,
        "the denied Object must be dropped and the other three pass"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            Ok(ChangeEvent::Object { address, .. }) if address.as_str().contains("/pub/a")
        )),
        "the read-allowed Object must survive"
    );
    assert!(
        !events.iter().any(|event| matches!(
            event,
            Ok(ChangeEvent::Object { address, .. }) if address.as_str().contains("/priv/")
        )),
        "the read-denied Object must be filtered out"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Ok(ChangeEvent::Lapsed { .. }))),
        "Lapsed carries no address and must pass through"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Err(err) if err.code() == ErrorCode::Internal)),
        "an Err item must pass through unfiltered"
    );
}

// ---------------------------------------------------------------------------
// JWT fail-closed on an absent/blank bearer
//
// When JWT authn IS configured, a `Tcp` credential with no bearer (or a blank
// one) is `AuthRequired` — never silently anonymous. A `Tcp` credential on a
// listener with NO JWT config still resolves to anonymous.
// ---------------------------------------------------------------------------

/// A `Tcp` credential carrying no bearer at all (the material a JWT listener
/// must reject fail-closed).
fn tcp_no_bearer_credential() -> AuthCredential {
    AuthCredential::new(
        None,
        Transport::Tcp {
            peer_addr: "203.0.113.7:443".to_string(),
            tls_client_cert: None,
        },
    )
}

#[tokio::test]
async fn builtin_auth_tcp_jwt_configured_missing_bearer_is_auth_required() {
    let inner = Arc::new(RecordingInner::default());
    let l = builtin_layer_with_jwt(inner.clone(), policy(ALICE_ALL), Some(test_jwt_config()));

    let err = l
        .stat(
            auth_request(&tcp_no_bearer_credential(), stat_req_input()),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthRequired);
    assert_eq!(
        inner.call_count(),
        0,
        "a JWT listener with no bearer must reject before inner"
    );
}

#[tokio::test]
async fn builtin_auth_tcp_jwt_configured_blank_bearer_is_auth_required() {
    // A whitespace-only bearer carries no token; it must be treated as missing
    // (fail-closed), not passed to the JWT validator as an empty string.
    let inner = Arc::new(RecordingInner::default());
    let l = builtin_layer_with_jwt(inner.clone(), policy(ALICE_ALL), Some(test_jwt_config()));

    let err = l
        .stat(
            auth_request(&tcp_bearer_credential("   "), stat_req_input()),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthRequired);
    assert_eq!(inner.call_count(), 0);
}

#[tokio::test]
async fn builtin_auth_tcp_no_jwt_config_no_bearer_is_anonymous() {
    // No JWT config: a bearer-less `Tcp` credential resolves anonymous, so an
    // anonymous-allow policy admits it (an explicitly anonymous TCP listener).
    let toml = r#"
        [[policy]]
        id = "anon-all"
        effect = "allow"
        principal = "anonymous"
        operations = ["*"]
        prefix = "file:/root/"
    "#;
    let inner = Arc::new(RecordingInner::default());
    let l = builtin_layer_with_jwt(inner.clone(), policy(toml), None);

    l.stat(
        auth_request(&tcp_no_bearer_credential(), stat_req_input()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        inner.stat_principal.lock().unwrap().as_deref(),
        Some("anonymous")
    );
}

// ---------------------------------------------------------------------------
// root_info_for is gated
//
// `root_info_for` is overridden with the same root-visibility predicate
// `list_address_roots` uses. A denied prefix returns `NoRoute` (the same error
// an absent route yields) rather than `PermissionDenied`, so a caller cannot
// probe hidden-route existence. An allowed principal gets the `RootInfo`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn root_info_for_denied_returns_no_route_not_permission_denied() {
    let inner = Arc::new(RecordingInner::default());
    // Deny-all: uid:7 has neither Read nor List, so the root is not visible.
    let layer = builtin_layer(inner.clone(), policy(""));

    let err = layer
        .root_info_for(&url("file:/root/a"), &auth_cx(&uds_credential(7)), None)
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        ErrorCode::NoRoute,
        "a hidden root must be indistinguishable from an absent one"
    );
    assert_eq!(inner.call_count(), 0, "a denied probe must not reach inner");
}

#[tokio::test]
async fn root_info_for_allowed_returns_root_info() {
    let inner = Arc::new(RecordingInner::default());
    // UID7_ALL allows every op under `file:/root/`, so Read makes the root visible.
    let layer = builtin_layer(inner.clone(), policy(UID7_ALL));

    let root = layer
        .root_info_for(&url("file:/root/a"), &auth_cx(&uds_credential(7)), None)
        .await
        .unwrap();
    assert_eq!(root.root.as_str(), url("file:/root/a").as_str());
    assert!(inner.saw("root_info_for"), "an allowed probe reaches inner");
}

// ---------------------------------------------------------------------------
// list_address_roots update stream is filtered
//
// The initial snapshot is filtered per root; the returned update stream must be
// filtered with the SAME principal + policy snapshot, or a later change leaks a
// hidden root. A change containing a visible + a hidden root yields only the
// visible one.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_address_roots_update_stream_filters_hidden_roots() {
    use futures::StreamExt as _;

    // uid:7 may introspect roots (list_address_roots on any address) and Read
    // under `pub/`, but has no rule for `priv/` — so `priv/` is hidden.
    let policy_toml = r#"
        [[policy]]
        id = "roots-introspect"
        effect = "allow"
        principal = "uid:7"
        operations = ["list_address_roots"]
        prefix = "*"

        [[policy]]
        id = "read-pub"
        effect = "allow"
        principal = "uid:7"
        operations = ["read"]
        prefix = "file:/root/pub/"
    "#;
    let inner = Arc::new(RecordingInner::default());
    // The inner emits one Added change carrying a visible + a hidden root.
    *inner.root_updates.lock().unwrap() = vec![Ok(RootInfoChange::Added(vec![
        test_root(&url("file:/root/pub/")),
        test_root(&url("file:/root/priv/")),
    ]))];
    let layer = builtin_layer(inner.clone(), policy(policy_toml));

    let (_snapshot, updates) = layer
        .list_address_roots(&auth_cx(&uds_credential(7)), None)
        .await
        .unwrap();
    let updates = updates.expect("inner supplied an update stream");
    let changes: Vec<Result<RootInfoChange>> = updates.collect().await;

    assert_eq!(changes.len(), 1, "the single Added change survives");
    match changes.into_iter().next().unwrap().unwrap() {
        RootInfoChange::Added(roots) => {
            assert_eq!(roots.len(), 1, "the hidden root is filtered out");
            assert!(
                roots[0].root.as_str().contains("/pub/"),
                "only the read-visible root survives, got {}",
                roots[0].root.as_str()
            );
        }
        other => panic!("expected an Added change, got {other:?}"),
    }
}

/// Route visibility and the per-URL probe must agree about one root.
///
/// `list_address_roots` filters with `is_root_visible`, which reaches
/// `Policy::is_allowed` directly, while `root_info_for` gates on the same
/// predicate after this layer canonicalized. If canonicalization lived at the
/// layer's gate rather than inside `Policy`, only the second would resolve a
/// non-canonical root spelling — so a root the policy hides would be enumerated
/// by the listing and reported absent by the probe, which is worse than either
/// answer alone: it tells a caller the route exists and then denies it exists.
///
/// The fixture root is spelled so it canonicalizes INTO the hidden scope, which
/// is the direction that leaks.
#[tokio::test]
async fn a_hidden_root_is_hidden_from_the_listing_and_the_probe_alike() {
    let policy_toml = r#"
        [[policy]]
        id = "roots-introspect"
        effect = "allow"
        principal = "uid:7"
        operations = ["list_address_roots"]
        prefix = "*"

        [[policy]]
        id = "read-root"
        effect = "allow"
        principal = "uid:7"
        operations = ["read"]
        prefix = "file:/root/"

        [[policy]]
        id = "deny-private"
        effect = "deny"
        principal = "uid:7"
        operations = ["*"]
        prefix = "file:/root/private/"
    "#;

    let raw = Url::parse("file:/root/public%2F%2E%2E%2Fprivate/x").unwrap();
    assert_eq!(
        ovstorage::address::parse("file:/root/public%2F%2E%2E%2Fprivate/x")
            .unwrap()
            .path(),
        "/root/private/x",
        "the fixture must canonicalize into the denied scope, or it proves nothing"
    );

    let inner = Arc::new(RecordingInner {
        roots: vec![raw.clone()],
        ..RecordingInner::default()
    });
    let layer = builtin_layer(inner.clone(), policy(policy_toml));

    let (snapshot, _) = layer
        .list_address_roots(&auth_cx(&uds_credential(7)), None)
        .await
        .unwrap();
    assert!(
        snapshot.roots.is_empty(),
        "the listing must not enumerate a root the policy hides, got {:?}",
        snapshot
            .roots
            .iter()
            .map(|root| root.root.as_str())
            .collect::<Vec<_>>()
    );

    let probe = layer
        .root_info_for(&raw, &auth_cx(&uds_credential(7)), None)
        .await;
    assert_eq!(
        probe.err().map(|error| error.code()),
        Some(ErrorCode::NoRoute),
        "the probe must hide it too, and with the same code an absent route yields"
    );
}

#[tokio::test]
async fn list_address_roots_update_stream_emits_empty_snapshot() {
    use futures::StreamExt as _;

    // A `Snapshot` is a full-state replacement: an all-hidden (post-filter empty)
    // snapshot must still be emitted so a consumer that saw a visible
    // root converges to "no visible roots" instead of retaining it forever. Only
    // empty *incremental* deltas are dropped.
    let policy_toml = r#"
        [[policy]]
        id = "roots-introspect"
        effect = "allow"
        principal = "uid:7"
        operations = ["list_address_roots"]
        prefix = "*"

        [[policy]]
        id = "read-pub"
        effect = "allow"
        principal = "uid:7"
        operations = ["read"]
        prefix = "file:/root/pub/"
    "#;
    let inner = Arc::new(RecordingInner::default());
    // First a visible snapshot, then an all-hidden snapshot (only `priv/`, which
    // uid:7 cannot see) — the second must survive as `Snapshot([])`.
    *inner.root_updates.lock().unwrap() = vec![
        Ok(RootInfoChange::Snapshot(vec![test_root(&url(
            "file:/root/pub/",
        ))])),
        Ok(RootInfoChange::Snapshot(vec![test_root(&url(
            "file:/root/priv/",
        ))])),
    ];
    let layer = builtin_layer(inner.clone(), policy(policy_toml));

    let (_snapshot, updates) = layer
        .list_address_roots(&auth_cx(&uds_credential(7)), None)
        .await
        .unwrap();
    let updates = updates.expect("inner supplied an update stream");
    let changes: Vec<Result<RootInfoChange>> = updates.collect().await;

    assert_eq!(
        changes.len(),
        2,
        "both snapshots survive — the empty one is not dropped"
    );
    match changes[0].as_ref().unwrap() {
        RootInfoChange::Snapshot(roots) => {
            assert_eq!(roots.len(), 1, "first snapshot keeps the visible root");
            assert!(roots[0].root.as_str().contains("/pub/"));
        }
        other => panic!("expected a Snapshot, got {other:?}"),
    }
    match changes[1].as_ref().unwrap() {
        RootInfoChange::Snapshot(roots) => {
            assert!(
                roots.is_empty(),
                "the all-hidden snapshot is emitted as Snapshot([]), got {roots:?}"
            );
        }
        other => panic!("expected an empty Snapshot, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// JWT/auth config parses fail-closed
//
// A present-but-wrong-typed `jwt_*` value, and a present-but-empty one, are
// config errors rather than a silent `None` that disables JWT authn. (The
// unknown-`auth.config`-key case lives in `auth_config_tests`.)
// ---------------------------------------------------------------------------

#[test]
fn jwt_wrong_typed_value_is_rejected() {
    // A present non-string `jwt_issuer` (here an integer) must be a config error,
    // not silently ignored (which would disable JWT authn).
    let mut config = LayerConfig::new();
    config.insert(
        super::JWT_ISSUER_CONFIG_KEY.to_string(),
        ConfigValue::Int(3),
    );
    assert_eq!(
        super::jwt_params_from_config(&config).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}

#[test]
fn jwt_empty_value_is_rejected() {
    // A present but blank `jwt_issuer` must be rejected with a clear config error
    // rather than passing presence and failing later with an opaque JWKS error.
    let mut config = LayerConfig::new();
    config.insert(
        super::JWT_ISSUER_CONFIG_KEY.to_string(),
        ConfigValue::String("   ".to_string()),
    );
    assert_eq!(
        super::jwt_params_from_config(&config).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}

fn tcp_credential(
    peer_addr: &str,
    bearer: Option<Vec<u8>>,
    cert: Option<Vec<u8>>,
    forwarded: Option<ForwardedHeaders>,
) -> AuthCredential {
    AuthCredential {
        bearer,
        forwarded,
        transport: Transport::Tcp {
            peer_addr: peer_addr.to_string(),
            tls_client_cert: cert,
        },
    }
}

#[test]
fn trusted_unsigned_jwt_requires_allowlisted_peer() {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
    let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"alice","role":"artist"}"#);
    let token = format!("{header}.{payload}.proxy-signature").into_bytes();
    let authn = BuiltinAuthn::new(
        TcpAuthnMode::TrustedUnsignedJwt {
            trusted_peers: vec![CidrConstraint::parse("10.0.0.0/8").unwrap()],
            claims: Default::default(),
        },
        PeerConfig::default(),
    );

    let principal = authn
        .resolve(Some(&tcp_credential(
            "10.2.3.4:443",
            Some(token.clone()),
            None,
            None,
        )))
        .unwrap();
    assert_eq!(principal.id, "alice");
    assert_eq!(
        principal.attributes.get("role"),
        Some(&"artist".to_string())
    );

    let err = authn
        .resolve(Some(&tcp_credential(
            "192.0.2.4:443",
            Some(token.clone()),
            None,
            None,
        )))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthRequired);

    let mapped = authn
        .resolve(Some(&tcp_credential(
            "[::ffff:10.2.3.4]:443",
            Some(token),
            None,
            None,
        )))
        .unwrap();
    assert_eq!(mapped.id, "alice");
}

/// Build a `trusted_unsigned_jwt` layer config the way a listener host does:
/// operator `authn_mode` (+ optional claim checks) plus the host-injected
/// trusted-peer CIDR list.
fn unsigned_jwt_layer_config(issuer: Option<&str>, audience: Option<&str>) -> LayerConfig {
    let mut config = LayerConfig::new();
    config.insert(
        super::AUTHN_MODE_CONFIG_KEY.to_string(),
        ConfigValue::String("trusted_unsigned_jwt".to_string()),
    );
    if let Some(issuer) = issuer {
        config.insert(
            super::JWT_ISSUER_CONFIG_KEY.to_string(),
            ConfigValue::String(issuer.to_string()),
        );
    }
    if let Some(audience) = audience {
        config.insert(
            super::JWT_AUDIENCE_CONFIG_KEY.to_string(),
            ConfigValue::String(audience.to_string()),
        );
    }
    super::configure_trusted_proxy(&mut config, true, &["10.0.0.0/8".to_string()]).unwrap();
    config
}

fn unsigned_jwt_token(claims: serde_json::Value) -> Vec<u8> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    format!("{header}.{payload}.proxy-signature").into_bytes()
}

#[tokio::test]
async fn trusted_unsigned_jwt_config_enforces_issuer_and_audience() {
    // The operator's `jwt_issuer`/`jwt_audience` must reach the runtime claim
    // check: a token the proxy signature-verified for a DIFFERENT relying party
    // in the same IdP is rejected here (confused-deputy defense in depth).
    let authn = super::authn_from_config(&unsigned_jwt_layer_config(
        Some("https://issuer.test"),
        Some("ovstorage"),
    ))
    .await
    .unwrap();

    let accepted = authn
        .resolve(Some(&tcp_credential(
            "10.2.3.4:443",
            Some(unsigned_jwt_token(serde_json::json!({
                "sub": "alice",
                "iss": "https://issuer.test",
                "aud": "ovstorage"
            }))),
            None,
            None,
        )))
        .unwrap();
    assert_eq!(accepted.id, "alice");

    let error = authn
        .resolve(Some(&tcp_credential(
            "10.2.3.4:443",
            Some(unsigned_jwt_token(serde_json::json!({
                "sub": "alice",
                "iss": "https://issuer.test",
                "aud": "some-other-service"
            }))),
            None,
            None,
        )))
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::AuthRequired);
    assert!(error.message().contains("audience"), "{}", error.message());
}

#[tokio::test]
async fn trusted_unsigned_jwt_config_without_claim_checks_accepts_any_issuer_and_audience() {
    // Compatibility: a config that names only the mode keeps resolving tokens,
    // deferring `iss`/`aud` entirely to the upstream verifier.
    let authn = super::authn_from_config(&unsigned_jwt_layer_config(None, None))
        .await
        .unwrap();
    let principal = authn
        .resolve(Some(&tcp_credential(
            "10.2.3.4:443",
            Some(unsigned_jwt_token(serde_json::json!({
                "sub": "alice",
                "iss": "https://anything.test",
                "aud": "some-other-service"
            }))),
            None,
            None,
        )))
        .unwrap();
    assert_eq!(principal.id, "alice");
}

#[tokio::test]
async fn trusted_unsigned_jwt_rejects_a_jwks_url() {
    // This mode verifies no signature, so a JWKS would sit unused. Reject it
    // rather than let an operator believe signatures are checked here.
    let mut config = unsigned_jwt_layer_config(Some("https://issuer.test"), Some("ovstorage"));
    config.insert(
        super::JWT_JWKS_URL_CONFIG_KEY.to_string(),
        ConfigValue::String("https://issuer.test/jwks".to_string()),
    );
    let Err(error) = super::authn_from_config(&config).await else {
        panic!("a jwks url must be rejected in trusted_unsigned_jwt mode");
    };
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(
        error.message().contains(super::JWT_JWKS_URL_CONFIG_KEY),
        "{}",
        error.message()
    );
}

#[test]
fn cidr_masks_a_non_byte_aligned_ipv6_prefix() {
    // A `/65` prefix splits byte 8 of the address: the mask keeps only that
    // byte's high bit. Round prefixes (`/64`, `/128`) would pass even with a
    // byte-granular mask, so this pins the partial-byte arithmetic.
    let cidr = CidrConstraint::parse("2001:db8::/65").unwrap();
    // Inside: the 65th bit (byte 8, high bit) is 0, matching the base.
    assert!(cidr.contains("2001:db8::1".parse().unwrap()));
    assert!(cidr.contains("2001:db8::7fff:ffff:ffff:ffff".parse().unwrap()));
    // Boundary: flipping exactly the 65th bit leaves the prefix.
    assert!(!cidr.contains("2001:db8:0:0:8000::".parse().unwrap()));
    assert!(!cidr.contains("2001:db8:0:0:ffff:ffff:ffff:ffff".parse().unwrap()));
    // A base whose host bits are set still matches on the prefix alone.
    let offset = CidrConstraint::parse("2001:db8:0:0:8000::1/65").unwrap();
    assert!(offset.contains("2001:db8:0:0:ffff::".parse().unwrap()));
    assert!(!offset.contains("2001:db8::1".parse().unwrap()));
}

#[test]
fn trusted_forwarded_headers_require_identity_and_allowlisted_peer() {
    let authn = BuiltinAuthn::new(
        TcpAuthnMode::TrustedForwardedHeaders {
            trusted_peers: vec![CidrConstraint::parse("2001:db8::/32").unwrap()],
            headers: ForwardedHeaderConfig {
                identity_header: "x-authenticated-user".into(),
                claim_headers: HashMap::from([("team".into(), "x-authenticated-team".into())]),
            },
        },
        PeerConfig::default(),
    );
    let credential = tcp_credential(
        "[2001:db8::5]:443",
        None,
        None,
        Some(ForwardedHeaders {
            values: vec![
                ("x-authenticated-user".into(), "  alice  ".into()),
                ("x-authenticated-team".into(), "rendering".into()),
            ],
        }),
    );
    let principal = authn.resolve(Some(&credential)).unwrap();
    assert_eq!(principal.id, "alice");
    assert_eq!(
        principal.attributes.get("team"),
        Some(&"rendering".to_string())
    );

    let duplicate = tcp_credential(
        "[2001:db8::5]:443",
        None,
        None,
        Some(ForwardedHeaders {
            values: vec![
                ("x-authenticated-user".into(), "alice".into()),
                ("x-authenticated-user".into(), "mallory".into()),
            ],
        }),
    );
    assert_eq!(
        authn.resolve(Some(&duplicate)).unwrap_err().code(),
        ErrorCode::AuthRequired
    );

    let missing = tcp_credential("[2001:db8::5]:443", None, None, None);
    assert_eq!(
        authn.resolve(Some(&missing)).unwrap_err().code(),
        ErrorCode::AuthRequired
    );

    let untrusted = tcp_credential(
        "[2001:db9::5]:443",
        None,
        None,
        Some(ForwardedHeaders {
            values: vec![("x-authenticated-user".into(), "alice".into())],
        }),
    );
    assert_eq!(
        authn.resolve(Some(&untrusted)).unwrap_err().code(),
        ErrorCode::AuthRequired
    );
}

#[test]
fn mtls_uses_stable_sha256_certificate_principal() {
    let authn = BuiltinAuthn::new(TcpAuthnMode::Mtls, PeerConfig::default());
    let principal = authn
        .resolve(Some(&tcp_credential(
            "127.0.0.1:443",
            None,
            Some(b"cert".to_vec()),
            None,
        )))
        .unwrap();
    assert_eq!(
        principal.id,
        "mtls:sha256:06298432e8066b29e2223bcc23aa9504b56ae508fabf3435508869b9c3190e22"
    );

    assert_eq!(
        authn
            .resolve(Some(&tcp_credential("127.0.0.1:443", None, None, None)))
            .unwrap_err()
            .code(),
        ErrorCode::AuthRequired
    );
}

// ---------------------------------------------------------------------------
// The trailing-slash deny bypass
// ---------------------------------------------------------------------------

/// Allow the whole root, deny the `docs` subtree. Both prefixes are spelled the
/// way an operator writes a directory rule: with a trailing slash.
const UID7_ALLOW_ROOT_DENY_DOCS: &str = r#"
    [[policy]]
    id = "uid7-root-allow"
    effect = "allow"
    principal = "uid:7"
    operations = ["*"]
    prefix = "file:/root/"

    [[policy]]
    id = "uid7-docs-deny"
    effect = "deny"
    principal = "uid:7"
    operations = ["*"]
    prefix = "file:/root/docs/"
"#;

/// `BuiltinAuthLayer` → recording inner, the broker's composition order.
async fn bypass_pair() -> (Arc<RecordingInner>, BuiltinAuthLayer) {
    let inner = Arc::new(RecordingInner::default());
    let layer = BuiltinAuthLayer::new(
        BUILTIN_AUTH_KIND,
        inner.clone() as LayerHandle,
        Arc::new(ArcSwap::from_pointee(
            (*policy(UID7_ALLOW_ROOT_DENY_DOCS)).clone(),
        )),
        BuiltinAuthn::new(TcpAuthnMode::Anonymous, PeerConfig::default()),
    );
    (inner, layer)
}

#[tokio::test]
async fn slashless_delete_directory_is_denied_like_its_slashed_spelling() {
    // The trailing-slash deny bypass, inverted. This test was committed asserting the
    // defect: `is_prefix_of` required the address to START WITH the whole
    // prefix, so a deny on `file:///root/docs/` could not match
    // `file:///root/docs` — one byte shorter. The broad allow won, and the
    // backend deleted the denied subtree.
    //
    // Authorization now matches on decoded path SEGMENTS and drops one trailing
    // empty segment, so a rule written `…/docs/` covers the node `…/docs` and
    // both spellings reach the same decision. Nothing about the trailing slash
    // is normalized to get there — the address still says what the caller
    // wrote.
    //
    // The assertion is on whether INNER WAS REACHED, not on returned data: for
    // `list` the authz layer post-filters items with `Operation::Stat`, which
    // would hide a bypass behind an empty page. `delete_directory` is
    // unfiltered and destructive, so it is the honest probe.
    let (inner, layer) = bypass_pair().await;

    let error = layer
        .delete_directory(
            auth_request(
                &uds_credential(7),
                DeleteDirectoryRequest {
                    address: url("file:/root/docs"),
                    options: Default::default(),
                },
            ),
            None,
        )
        .await
        .expect_err("the slashless spelling must be denied");

    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert!(
        inner.calls.lock().unwrap().is_empty(),
        "the backend must not be reached at all, got {:?}",
        inner.calls.lock().unwrap()
    );
}

#[tokio::test]
async fn slash_spelled_delete_directory_is_denied() {
    // The control for the test above, run against the same policy and the same
    // composition. Without it, the bypass result proves nothing: it could be a
    // policy that simply never denies anything.
    let (inner, layer) = bypass_pair().await;

    let error = layer
        .delete_directory(
            auth_request(
                &uds_credential(7),
                DeleteDirectoryRequest {
                    address: url("file:/root/docs/"),
                    options: Default::default(),
                },
            ),
            None,
        )
        .await
        .expect_err("the slash spelling matches the deny");

    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        inner.call_count(),
        0,
        "a denied request must not reach the backend"
    );
}

// ---------------------------------------------------------------------------
// Authorization matches decoded URL components, not serialized strings
//
// RED until the component matcher lands. Each case decodes to exactly the
// backend key that the control spelling is denied for, so allowing it hands the
// caller the denied object.
// ---------------------------------------------------------------------------

const UID7_ALLOW_ROOT_DENY_PRIVATE: &str = r#"
    [[policy]]
    id = "uid7-root-allow"
    effect = "allow"
    principal = "uid:7"
    operations = ["*"]
    prefix = "file:/root/"

    [[policy]]
    id = "uid7-private-deny"
    effect = "deny"
    principal = "uid:7"
    operations = ["*"]
    prefix = "file:/root/private"
"#;

fn encoding_pair() -> (Arc<RecordingInner>, BuiltinAuthLayer) {
    let inner = Arc::new(RecordingInner::default());
    let layer = BuiltinAuthLayer::new(
        BUILTIN_AUTH_KIND,
        inner.clone() as LayerHandle,
        Arc::new(ArcSwap::from_pointee(
            (*policy(UID7_ALLOW_ROOT_DENY_PRIVATE)).clone(),
        )),
        BuiltinAuthn::new(TcpAuthnMode::Anonymous, PeerConfig::default()),
    );
    (inner, layer)
}

async fn stat_verdict(spelling: &str) -> (Option<ErrorCode>, bool) {
    let (inner, layer) = encoding_pair();
    let result = layer
        .stat(
            auth_request(
                &uds_credential(7),
                StatRequest {
                    address: url(spelling),
                    options: StatOptions::default(),
                },
            ),
            None,
        )
        .await;
    (result.err().map(|e| e.code()), inner.saw("stat"))
}

#[tokio::test]
async fn deny_covers_every_spelling_that_reaches_the_denied_key() {
    // The control: the plain spelling is denied.
    assert_eq!(
        stat_verdict("file:/root/private/secret.txt").await,
        (Some(ErrorCode::PermissionDenied), false),
        "control: the plain spelling must be denied"
    );

    // Spellings that decode to exactly the denied key. Verified against
    // `address::key` rather than asserted, so the test cannot drift into
    // comparing unrelated addresses.
    let denied_key = ovstorage::address::key(&url("file:/root/private/secret.txt"));
    for spelling in [
        // Encoded separator: the boundary byte after the prefix is '%'.
        "file:/root/private%2Fsecret.txt",
        // Redundant encoding of an unreserved character — no separator at all.
        "file:/root/%70rivate/secret.txt",
        // Encoded traversal. `address::parse` canonicalizes, which decodes the
        // separators and then resolves the dot segment, so this arrives at the
        // matcher spelled exactly like the control and needs no rule of its own.
        "file:/root/public%2F%2E%2E%2Fprivate%2Fsecret.txt",
    ] {
        assert_eq!(
            ovstorage::address::key(&url(spelling)),
            denied_key,
            "{spelling} must decode to the denied key, or the test proves nothing"
        );
        assert_eq!(
            stat_verdict(spelling).await,
            (Some(ErrorCode::PermissionDenied), false),
            "{spelling} reaches the denied object and must be denied"
        );
    }
}

#[tokio::test]
async fn deny_does_not_widen_to_a_sibling_that_merely_decodes_similarly() {
    // `%78` is 'x', so this decodes to `root/privatex/…` — a different node.
    // Decoding must not turn segment-wise containment into substring matching.
    let (_, allowed) = stat_verdict("file:/root/private%78/other.txt").await;
    assert!(
        allowed,
        "a sibling whose name merely starts with the denied name must be allowed"
    );
}

/// Reaching the auth layer below the `Stack` boundary must not bypass the deny.
///
/// `Stack::root()` is public API, so a caller can take the root layer and drive
/// it directly — below the only place that would otherwise have canonicalized
/// the request. Every other layer degrades to a cache miss or a `NoRoute` under
/// an unnormalized address; this one would degrade to a bypass, which is why
/// the auth layer canonicalizes its own input rather than trusting the chain.
#[tokio::test]
async fn deny_holds_for_an_address_that_never_passed_the_stack_boundary() {
    // Each fixture is `Url::parse`d, not `address::parse`d: this is the
    // spelling a caller below the boundary supplies, with no canonicalization
    // applied.
    //
    // The first two rows are the ones that give the test its power. The segment
    // matcher — `segments_with_host_semantics_widened` in
    // `ovstorage-authz-policy`'s `rules.rs`, reached from `scope_covers` —
    // decodes each segment and rejoins with `/` before splitting, so a
    // bare `%2F` becomes a real separator inside the matcher itself and is
    // denied whether or not this layer canonicalizes — that row is kept because
    // it is the reported spelling, not because it discriminates. A dot segment
    // hidden behind an encoded separator and a doubled separator both survive
    // the matcher intact (`["root","public","..","private","secret.txt"]` and
    // `["root","","private","secret.txt"]`, neither of which the deny scope
    // `["root","private"]` prefixes), so they are denied only once the layer
    // canonicalizes. Verified red with both of the layer's canonicalization
    // points removed — `check`'s evaluation-side call and the
    // `canonicalize_delegated` rewrite in `authorize`. Either one alone still
    // denies these, which is the redundancy those two points are for.
    //
    // The discrimination is host-dependent, and only in the safe direction: on
    // Windows the matcher folds `\` and runs `normalize_decoded_path` over
    // `file:` scopes, which resolves the dot segment and the doubled separator
    // inside the matcher too, so these rows would stay green there even with
    // both guards gone. The red was measured on Linux, which is where the
    // suite runs.
    for raw_path in [
        "/root/public%2F%2E%2E%2Fprivate%2Fsecret.txt",
        "/root//private/secret.txt",
        "/root/private%2Fsecret.txt",
    ] {
        let raw = Url::parse(&format!("file:{raw_path}")).unwrap();
        assert_eq!(
            raw.path(),
            raw_path,
            "the fixture must reach the layer unnormalized, or it proves nothing"
        );

        let (inner, layer) = encoding_pair();
        let result = layer
            .stat(
                auth_request(
                    &uds_credential(7),
                    StatRequest {
                        address: raw,
                        options: StatOptions::default(),
                    },
                ),
                None,
            )
            .await;

        assert_eq!(
            result.err().map(|e| e.code()),
            Some(ErrorCode::PermissionDenied),
            "{raw_path} reaches the denied object and must be denied"
        );
        assert!(
            !inner.saw("stat"),
            "{raw_path} was denied and must not reach inner"
        );
    }
}

/// The gate and the backend must judge the same bytes.
///
/// Canonicalizing only the copy handed to the policy authorizes one node and
/// delegates another. `file:/root/private%2F..%2Fpublic/x.txt` evaluates as
/// `file:/root/public/x.txt` and is allowed — correctly, that is the node it
/// names — while the backend receives a spelling the policy never saw. What
/// that costs depends on the backend: a flat object store derives its key from
/// the address it was handed, so `s3://b/private%2F..%2Fpublic/x` becomes the
/// literal key `private/../public/x`, which a `deny s3://b/private/` covers and
/// the gate did not. The property under test is the one that holds for every
/// backend — inner receives the address that was judged — so the fixture uses
/// the layer's own `file:` policy and asserts the spelling, not a key.
///
/// The allow is genuine and not a default: `UID7_ALLOW_ROOT_DENY_PRIVATE`
/// grants `uid:7` everything under `file:/root/`.
#[tokio::test]
async fn an_allowed_request_is_delegated_in_the_spelling_that_was_authorized() {
    let raw = Url::parse("file:/root/private%2F..%2Fpublic/x.txt").unwrap();
    let canonical = ovstorage::address::parse("file:/root/private%2F..%2Fpublic/x.txt").unwrap();
    assert_eq!(
        canonical.path(),
        "/root/public/x.txt",
        "the fixture must canonicalize out of the denied scope, or the allow below is not the interesting one"
    );

    let (inner, layer) = encoding_pair();
    layer
        .stat(
            auth_request(
                &uds_credential(7),
                StatRequest {
                    address: raw,
                    options: StatOptions::default(),
                },
            ),
            None,
        )
        .await
        .expect("the canonical address is under the allowed root");

    assert_eq!(
        inner.calls.lock().unwrap().as_slice(),
        [("stat", Some(canonical.to_string()))],
        "inner must receive the address the policy judged, not the raw one"
    );
}

/// The raw spelling used by the delegation tests, and the node it names.
///
/// It carries an encoded separator and a dot segment, so it survives
/// `Url::parse` intact and is rewritten only by `canonicalize`.
const RAW_UNDER_ALLOW: &str = "file:/root/private%2F..%2Fpublic/x.txt";
const CANONICAL_UNDER_ALLOW: &str = "file:///root/public/x.txt";

/// `copy` and `rename` do not route through `authorize`, so their endpoint
/// rewrites are separate code and need separate cover.
///
/// Both verbs run `check_metered` directly — once per decomposed operation —
/// and rewrite `source` and `destination` themselves. Deleting either rewrite
/// leaves every other test in this file green while reopening the split on that
/// endpoint, and the `source` endpoint had no observer at all until
/// `note_endpoints` was added: `RecordingInner::rec` carries one address per
/// call and for these two verbs that address is the destination.
#[tokio::test]
async fn both_endpoints_of_copy_and_rename_are_delegated_as_authorized() {
    let raw = || Url::parse(RAW_UNDER_ALLOW).unwrap();
    let expected = (
        CANONICAL_UNDER_ALLOW.to_string(),
        CANONICAL_UNDER_ALLOW.to_string(),
    );

    let (inner, layer) = encoding_pair();
    layer
        .copy(
            auth_request(
                &uds_credential(7),
                CopyRequest {
                    source: raw(),
                    destination: raw(),
                    options: CopyOptions::default(),
                },
            ),
            None,
        )
        .await
        .expect("the canonical endpoints are under the allowed root");
    assert_eq!(
        inner.endpoints_of("copy"),
        Some(expected.clone()),
        "copy must delegate both endpoints in the spelling it authorized"
    );

    let (inner, layer) = encoding_pair();
    layer
        .rename(
            auth_request(
                &uds_credential(7),
                RenameRequest {
                    source: raw(),
                    destination: raw(),
                    options: RenameOptions::default(),
                },
            ),
            None,
        )
        .await
        .expect("the canonical endpoints are under the allowed root");
    assert_eq!(
        inner.endpoints_of("rename"),
        Some(expected),
        "rename must delegate both endpoints in the spelling it authorized"
    );
}

/// `root_info_for` takes `&Url` from the trait, so its rewrite is a local clone
/// rather than an in-place edit — a third distinct shape, and the one where
/// forgetting to pass the clone on is easiest.
///
/// It gates on `is_root_visible` rather than `Policy::evaluate`, so it does not
/// share the `authorize` path either.
#[tokio::test]
async fn root_info_for_delegates_the_spelling_it_judged() {
    let (inner, layer) = encoding_pair();
    layer
        .root_info_for(
            &Url::parse(RAW_UNDER_ALLOW).unwrap(),
            &auth_request(&uds_credential(7), ()).extensions,
            None,
        )
        .await
        .expect("the canonical address is under the allowed root");

    assert_eq!(
        inner.calls.lock().unwrap().as_slice(),
        [("root_info_for", Some(CANONICAL_UNDER_ALLOW.to_string()))],
        "root_info_for must delegate the address its visibility check judged"
    );
}

/// An empty path segment must not defeat a deny on `file:`.
///
/// The plain spelling is the bug: `/root//private/secret` opens the same file
/// as `/root/private/secret` on POSIX, while a matcher comparing path segments
/// sees a different path. That makes the matcher finer than the backend, which
/// is the direction that bypasses rather than over-denies, and it needs no
/// encoding to reach — it is a string anyone can type.
///
/// The `%2F` row is listed only because it arrives at the same address once the
/// path is decoded, not because encoding is the mechanism.
///
/// The sibling assertions are on a storage scheme, and they pin what the rule
/// does and does not touch there: the collapse is uniform, so `s3://b/d//x` and
/// `s3://b/d/x` reach one key, while `s3://b/docs` and `s3://b/docs/` stay two.
#[tokio::test]
async fn deny_covers_empty_segment_spellings_on_file() {
    let denied_key = ovstorage::address::key(&url("file:/root/private/secret.txt"));
    for spelling in [
        "file:/root//private/secret.txt",
        "file:/root///private/secret.txt",
        "file:/root/%2Fprivate/secret.txt",
    ] {
        assert_eq!(
            ovstorage::address::key(&url(spelling)),
            denied_key,
            "{spelling} must reach the denied key, or the test proves nothing"
        );
        assert_eq!(
            stat_verdict(spelling).await,
            (Some(ErrorCode::PermissionDenied), false),
            "{spelling} reaches the denied object and must be denied"
        );
    }

    // The rule is uniform, so the storage schemes collapse too. What stays
    // distinct is the trailing slash, which is the point of the address model.
    assert_eq!(
        ovstorage::address::key(&url("s3://b/d//x")),
        ovstorage::address::key(&url("s3://b/d/x"))
    );
    assert_ne!(
        ovstorage::address::key(&url("s3://b/docs")),
        ovstorage::address::key(&url("s3://b/docs/"))
    );
}

/// The `WatchDirectory` decision is a function of `(principal, prefix)` and is
/// **invariant in `WatchDirectoryOptions::recursive`**.
///
/// This is a tripwire for a design decision made elsewhere. The cache's
/// notification drain falls back to watching narrower *prefixes* when a root
/// watch is refused, and the obvious alternative — retry the same prefix
/// non-recursively, as a smaller ask — would be dead code here: the policy
/// engine is never handed the options, so both spellings reach the identical
/// rule and get the identical answer. The in-tree backends agree, treating
/// `recursive` as a post-hoc event filter over one upstream subscription rather
/// than as part of what is requested.
///
/// If someone makes authorization recursion-sensitive, this test fails, and the
/// cache's fallback should be revisited to retry the narrower ask before
/// recording a refusal.
#[tokio::test]
async fn watch_authorization_does_not_depend_on_recursion() {
    let allowing = r#"
        [[policy]]
        id = "watch"
        effect = "allow"
        principal = "uid:7"
        operations = ["watch_directory"]
        prefix = "file:/root/sub/"
    "#;
    // Same policy, same prefix, both spellings of `recursive`.
    for recursive in [true, false] {
        let inner = Arc::new(RecordingInner::default());
        let layer = builtin_layer(inner.clone(), policy(allowing));
        let allowed = layer
            .watch_directory(
                auth_request(
                    &uds_credential(7),
                    WatchDirectoryRequest {
                        prefix: url("file:/root/sub/"),
                        options: WatchDirectoryOptions {
                            recursive,
                            ..Default::default()
                        },
                    },
                ),
                None,
            )
            .await;
        assert!(
            allowed.is_ok(),
            "a granted prefix must be granted with recursive={recursive}"
        );

        // And a prefix with no matching rule is refused either way, so the test
        // is not merely observing that everything is allowed.
        let inner = Arc::new(RecordingInner::default());
        let layer = builtin_layer(inner.clone(), policy(allowing));
        let refused = layer
            .watch_directory(
                auth_request(
                    &uds_credential(7),
                    WatchDirectoryRequest {
                        prefix: url("file:/root/"),
                        options: WatchDirectoryOptions {
                            recursive,
                            ..Default::default()
                        },
                    },
                ),
                None,
            )
            .await;
        assert_eq!(
            refused.err().map(|error| error.code()),
            Some(ErrorCode::PermissionDenied),
            "an ungranted prefix must be refused with recursive={recursive}"
        );
    }
}
