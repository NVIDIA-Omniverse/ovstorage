// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end coverage for [`ovstorage::host::build_stack`] —
//! the generic `StackConfig` → `Arc<Stack>` builder CLI/MCP compose their
//! stack with. Drives the built Stack through the ergonomic [`LayerExt`] verbs.
//! Also covers `StackBuilder::build_with_cancel` aborting a router whose
//! child parks during initial root discovery.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Notify;

use ovstorage::ext::LayerExt;
use ovstorage::host::build_stack;
use ovstorage::layers::ROUTER_KIND;
use ovstorage_plugin_core::{
    AliasWrapperFactory, CopyRenameFallbackWrapperFactory, RouterFactoryImpl,
};
// NOTE: the `Layer` trait itself is deliberately NOT imported at file scope —
// its inherent-signature `stat`/`read`/`list_address_roots` would make the
// `LayerExt` calls in the tests above ambiguous. The parking double below
// implements it by path.
use ovstorage::{
    BackendFactory, Body, CancellationToken, ConnectionConfig, Error, ErrorCode, Extensions,
    LayerConfig, LayerHandle, LayerKindDescriptor, LayerSpec, LayerTable, LayerType,
    LoadedLayerFactory, ReadOptions, Result, RootInfoSnapshot, RootInfoUpdateStream, Stack,
    StackConfig, StatOptions, Url, WriteOptions,
};

fn core_plugin_factories() -> Vec<LoadedLayerFactory> {
    vec![
        LoadedLayerFactory::Router(Arc::new(RouterFactoryImpl)),
        LoadedLayerFactory::Wrapper(Arc::new(AliasWrapperFactory::default())),
        LoadedLayerFactory::Wrapper(Arc::new(CopyRenameFallbackWrapperFactory)),
    ]
}

/// (a) A four-layer declared stack — `alias → copy_rename_fallback →
/// router[file] → file` — plus one `file` connection builds a Stack that
/// round-trips a write through `read_bytes`.
#[tokio::test]
async fn declared_stack_round_trips_write_then_read() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Url::from_directory_path(tmp.path()).unwrap();

    let mut layers = HashMap::new();
    layers.insert(
        "alias".to_string(),
        LayerTable {
            inner: Some("copy_rename_fallback".into()),
            ..Default::default()
        },
    );
    layers.insert(
        "copy_rename_fallback".to_string(),
        LayerTable {
            inner: Some("router".into()),
            ..Default::default()
        },
    );
    layers.insert(
        "router".to_string(),
        LayerTable {
            children: vec!["files".into()],
            ..Default::default()
        },
    );
    layers.insert(
        "files".to_string(),
        LayerTable {
            kind: Some("file".into()),
            ..Default::default()
        },
    );

    let config = StackConfig {
        root: Some("alias".into()),
        layers,
        connections: vec![ConnectionConfig {
            backend_kind: "file".into(),
            target: Some("files".into()),
            display_name: Some("workspace".into()),
            config: HashMap::from([("root".into(), toml::Value::String(root.to_string()))]),
            credentials: HashMap::new(),
        }],
    };

    let stack = build_stack(&config, core_plugin_factories()).await.unwrap();

    let addr = root.join("hello.txt").unwrap();
    stack
        .write(
            addr.clone(),
            Body::Bytes(b"round-trip".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        ovstorage::Layer::owning_target_for(stack.as_ref(), &addr, &Extensions::new(), None).await,
        Some("files".into()),
        "router resolution returns the backend instance name, not its `file` kind"
    );
    assert_eq!(
        ovstorage::Layer::owning_target_for(
            stack.as_ref(),
            &Url::parse("https://example.com/unrouted").unwrap(),
            &Extensions::new(),
            None,
        )
        .await,
        None
    );

    let (bytes, _info) = stack
        .read_bytes(addr, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"round-trip");
}

/// (a2) Operator-authored alias/visibility rules in
/// `[ovstorage.layers.<name>]` TOML take effect end-to-end. The config is parsed
/// with [`StackConfig::from_toml_str`] (so the `aliases`/`visibility` arrays go
/// through `config_value_from_toml`) and built with `build_stack`; the built
/// alias wrapper must (1) rewrite a virtual prefix onto its physical target and
/// (2) hide a `suppressed` prefix from `list_address_roots`.
#[tokio::test]
async fn operator_alias_and_visibility_toml_take_effect() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Url::from_directory_path(tmp.path()).unwrap();
    // A physical object the virtual prefix resolves onto.
    std::fs::write(tmp.path().join("hello.txt"), b"aliased").unwrap();

    // The operator config: an `alias` wrapper over the `file` backend, with the
    // rules authored as ordinary nested TOML (no factory injection).
    let toml = format!(
        r#"
[ovstorage]
root = "alias"

[ovstorage.layers.alias]
kind = "alias"
inner = "file"

[[ovstorage.layers.alias.aliases]]
from = "ov:///pub/"
to = "{root}"

[[ovstorage.layers.alias.visibility]]
address = "{root}"
visibility = "suppressed"

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = "{root}"
"#
    );

    let config = StackConfig::from_toml_str(&toml).unwrap();
    let stack = build_stack(&config, core_plugin_factories()).await.unwrap();

    // (1) The virtual prefix resolves onto the physical target: statting through
    // `ov:///pub/…` reaches the file written under the real root, and the result
    // is projected back into the caller's virtual address space.
    let virt = Url::parse("ov:///pub/hello.txt").unwrap();
    let info = stack
        .stat(virt.clone(), StatOptions::default(), None)
        .await
        .expect("operator alias rule did not resolve virtual → physical");
    assert_eq!(info.address.as_str(), "ov:///pub/hello.txt");
    assert_eq!(info.size, Some(b"aliased".len() as u64));

    // (2) The suppressed physical root is hidden; only the synthesized visible
    // alias root is advertised.
    let roots = stack.list_address_roots(None).await.unwrap();
    let root_strs: Vec<&str> = roots.iter().map(|r| r.root.as_str()).collect();
    assert!(
        root_strs.contains(&"ov:///pub/"),
        "alias root should be advertised: {root_strs:?}"
    );
    assert!(
        !root_strs.iter().any(|r| r.starts_with("file:")),
        "suppressed physical root should be hidden: {root_strs:?}"
    );
}

/// (b) An empty config (no layers) builds an `EmptyLayer`-rooted Stack whose
/// operations return `Unsupported`.
#[tokio::test]
async fn empty_stack_is_unsupported() {
    let config = StackConfig::default();
    let stack = build_stack(&config, Vec::new()).await.unwrap();

    let addr = Url::parse("file:///nowhere/obj").unwrap();
    let err = stack
        .stat(addr, StatOptions::default(), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

/// (c) A config that declares `[[ovstorage.connections]]` but no
/// `[ovstorage.layers]` is a mistake, not the empty stack: those connections
/// have no backend layer to attach to. `build_stack` errors rather than
/// silently dropping them.
#[tokio::test]
async fn connections_without_layers_is_an_error() {
    let config = StackConfig {
        root: None,
        layers: HashMap::new(),
        connections: vec![ConnectionConfig {
            backend_kind: "file".into(),
            target: None,
            display_name: None,
            config: HashMap::from([("root".into(), toml::Value::String("/data".into()))]),
            credentials: HashMap::new(),
        }],
    };

    // `Arc<Stack>` is not `Debug`, so `unwrap_err` can't be used directly.
    let err = match build_stack(&config, Vec::new()).await {
        Ok(_) => panic!("expected build_stack to reject connections without layers"),
        Err(err) => err,
    };
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("no [ovstorage.layers]"),
        "unexpected message: {}",
        err.message()
    );
}

const PARKING_KIND: &str = "parking";

/// A backend Layer whose `list_address_roots` parks at a gate until released
/// or cancelled — the seam the core plugin Router's initial root-discovery
/// fan-out awaits during `StackBuilder::build_with_cancel`.
///
/// `entered` is the RV1 rendezvous (signaled at the gate, so the test knows
/// the build is provably parked, no sleeps or timing assumptions — the style
/// of `cross_binary_cancel_mid_flight_via_gate` in `handoff_cross_binary.rs`);
/// the query then races gate release against the token with `tokio::select!`,
/// mirroring the first-party cancel race (see `body_stream_from_read_stream`
/// in `src/wrappers/copy_rename_fallback.rs`), so the cancel arm's code is exactly
/// `ErrorCode::Cancelled`.
struct ParkingBackend {
    gate: Notify,
    entered: Notify,
}

impl ParkingBackend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            gate: Notify::new(),
            entered: Notify::new(),
        })
    }
}

fn parking_descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        display_name: PARKING_KIND.to_string(),
        kind: PARKING_KIND.to_string(),
        layer_type: LayerType::Backend,
        description: None,
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        auth_capable: false,
        supports_user_metadata: true,
    }
}

#[async_trait]
impl ovstorage::Layer for ParkingBackend {
    fn name(&self) -> &str {
        "parked"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        parking_descriptor()
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        self.entered.notify_one();
        match cancel {
            Some(token) => tokio::select! {
                _ = token.cancelled() => {
                    return Err(Error::new(
                        ErrorCode::Cancelled,
                        "root discovery cancelled while parked",
                    ));
                }
                _ = self.gate.notified() => {}
            },
            None => self.gate.notified().await,
        }
        Ok((
            RootInfoSnapshot {
                roots: Vec::new(),
                updates: false,
            },
            None,
        ))
    }
}

/// Hands out the one shared [`ParkingBackend`] so the test keeps a typed
/// handle to its gate (the `SharedBackendFactory` idiom from
/// `tests/wrappers/common.rs`).
struct SharedParkingBackendFactory {
    backend: LayerHandle,
}

#[async_trait]
impl BackendFactory for SharedParkingBackendFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        parking_descriptor()
    }

    async fn create_backend(
        &self,
        _name: &str,
        _config: &LayerConfig,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(self.backend.clone())
    }
}

/// (d) `StackBuilder::build_with_cancel`: a Stack whose router child parks
/// during the Router's initial `list_address_roots` fan-out keeps the build
/// future pending WITHOUT blocking an executor thread (an unrelated spawned
/// task completes on this current-thread runtime while the build is parked),
/// and firing the token resolves the build with `ErrorCode::Cancelled`.
#[tokio::test(flavor = "current_thread")]
async fn build_with_cancel_cancels_parked_router_root_discovery() {
    let backend = ParkingBackend::new();
    let cancel = CancellationToken::new();
    let builder = Stack::builder("router")
        .router_factory(Arc::new(RouterFactoryImpl))
        .backend_factory(Arc::new(SharedParkingBackendFactory {
            backend: backend.clone(),
        }))
        .layer(LayerSpec::router(
            "router",
            ROUTER_KIND,
            vec!["parked".into()],
        ))
        .layer(LayerSpec::backend("parked", PARKING_KIND));
    let build = tokio::spawn({
        let cancel = cancel.clone();
        async move { builder.build_with_cancel(Some(cancel)).await }
    });

    // RV1: the Router's initial root-discovery fan-out has reached the
    // child's gate — the build is provably parked there.
    backend.entered.notified().await;

    // Concurrent progress while parked: with a single executor thread, the
    // unrelated task can only complete if the parked build future yielded
    // rather than blocking the thread.
    let unrelated = tokio::spawn(async { "unrelated progress" });
    assert_eq!(
        unrelated.await.expect("unrelated task panicked"),
        "unrelated progress",
        "an unrelated task must complete while the build is parked"
    );
    assert!(
        !build.is_finished(),
        "the build must still be parked at the child's gate (nothing released it)"
    );

    // RV2: fire the token — the parked discovery resolves and the build
    // surfaces the cancellation. (`Stack` is not `Debug`, so `expect_err`
    // can't be used directly.)
    cancel.cancel();
    let err = match build.await.expect("build task panicked") {
        Ok(_) => panic!("expected build_with_cancel to surface cancellation"),
        Err(err) => err,
    };
    assert_eq!(err.code(), ErrorCode::Cancelled, "got {err}");
}
