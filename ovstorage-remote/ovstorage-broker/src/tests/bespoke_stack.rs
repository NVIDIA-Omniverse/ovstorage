// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The broker-client host row as an application-owned `Stack`, composed
//! directly via `load_layer_plugin` + `StackBuilder` without a Router:
//!
//! `alias → copy_rename_fallback → byte_cache → metadata_cache →
//!  redirect_follower → retry → BrokerClientBackend`
//!
//! This proves the path an application composes for itself: object operations
//! round-trip end-to-end through the wrapper chain onto the
//! dlopen'd v2 broker-client backend, and a **tier-1 interactive sign-in**
//! drives to a resolved bearer via the layer's `authenticate_connection` called
//! directly on the Stack. Applications that own their Stack sign in against
//! the broker's identity provider through that same operational surface.

use super::*;
use ovstorage::layers::{
    ALIAS_KIND, BYTE_CACHE_KIND, COPY_RENAME_FALLBACK_KIND, METADATA_CACHE_KIND,
    REDIRECT_FOLLOWER_KIND, RETRY_KIND, register_default_layer_factories,
};
use ovstorage::{
    AuthEvent, AuthenticateRequest, ConnectionAuthState, ConnectionKey, InteractiveAuthCapability,
    Layer, LayerConnectionRequest, LayerSpec, MetadataCache, MetadataCacheConfig, ReadOptions,
    ReadRequest, ReadResult, Request, RootInfoChange, Stack, StatOptions, StatRequest,
    WriteOptions, WriteRequest,
};
use ovstorage_cache::{Cache, CacheConfig};
use ovstorage_plugin_cache::{ByteCacheWrapperFactory, MetadataCacheWrapperFactory};
use ovstorage_plugin_core::{
    AliasWrapperFactory, CopyRenameFallbackWrapperFactory, RetryWrapperFactory,
};
use ovstorage_plugin_http::RedirectFollowerWrapperFactory;

use crate::test_utils::workspace_plugin_dir;

/// Load ONLY the broker-client cdylib (dlopen) and return its `broker` backend
/// factory — the forward-path entry an app uses to compose a bespoke Stack.
fn load_broker_backend_factory() -> std::sync::Arc<dyn ovstorage::BackendFactory> {
    let stem = if cfg!(target_os = "windows") {
        "ovstorage_plugin_broker.dll".to_string()
    } else if cfg!(target_os = "macos") {
        "libovstorage_plugin_broker.dylib".to_string()
    } else {
        "libovstorage_plugin_broker.so".to_string()
    };
    let so = workspace_plugin_dir().join(stem);
    // SAFETY: integration test loading a cdylib built into the workspace fixture
    // dir by this crate's build.rs.
    let factories =
        unsafe { ovstorage::load_layer_plugin(&so, true) }.expect("load broker-client cdylib");
    for factory in factories {
        if let ovstorage::LoadedLayerFactory::Backend(backend) = factory
            && backend.descriptor().kind == "broker"
        {
            return backend;
        }
    }
    panic!("broker-client cdylib exposed no `broker` backend factory");
}

/// Compose the RFC broker-client host row DIRECTLY via `StackBuilder`: the six
/// wrappers in landed order over the dlopen'd `BrokerClientBackend`, no Router
/// (`retry`'s inner links straight to the `broker` backend layer). The default
/// wrapper + backend factories are registered from `default_layer_factories()`;
/// the broker backend factory is the dlopen'd one.
async fn bespoke_broker_stack(broker_address: &str, credentials: SecretBundle) -> Stack {
    let broker = load_broker_backend_factory();
    let mut config = HashMap::new();
    config.insert(
        "address".into(),
        ConfigValue::String(broker_address.to_string()),
    );
    // The `with_cache` wrapper factories carry an already-open cache and override
    // the cacheless defaults, so the byte_cache/metadata_cache specs need no
    // self-provisioning config beyond the `partition`.
    let cache_root = unique_temp_dir();
    std::fs::create_dir_all(&cache_root).unwrap();
    let byte_cache = Arc::new(
        Cache::open(CacheConfig {
            state_root: cache_root.join("state"),
            cache_root: cache_root.join("cache"),
        })
        .expect("open byte cache"),
    );
    let metadata_cache = Arc::new(MetadataCache::new(&MetadataCacheConfig::default()));
    let mut byte_cache_spec = LayerSpec::wrapper("byte_cache", BYTE_CACHE_KIND, "metadata_cache");
    byte_cache_spec
        .config
        .insert("partition".into(), ConfigValue::String("bespoke".into()));
    register_default_layer_factories(Stack::builder("alias"))
        .backend_factory(broker)
        .wrapper_factory(Arc::new(AliasWrapperFactory::default()))
        .wrapper_factory(Arc::new(CopyRenameFallbackWrapperFactory))
        .wrapper_factory(Arc::new(ByteCacheWrapperFactory::with_cache(byte_cache)))
        .wrapper_factory(Arc::new(MetadataCacheWrapperFactory::with_cache(
            metadata_cache,
        )))
        .wrapper_factory(Arc::new(RedirectFollowerWrapperFactory))
        .wrapper_factory(Arc::new(RetryWrapperFactory))
        .layer(LayerSpec::wrapper(
            "alias",
            ALIAS_KIND,
            "copy_rename_fallback",
        ))
        .layer(LayerSpec::wrapper(
            "copy_rename_fallback",
            COPY_RENAME_FALLBACK_KIND,
            "byte_cache",
        ))
        .layer(byte_cache_spec)
        .layer(LayerSpec::wrapper(
            "metadata_cache",
            METADATA_CACHE_KIND,
            "redirect_follower",
        ))
        .layer(LayerSpec::wrapper(
            "redirect_follower",
            REDIRECT_FOLLOWER_KIND,
            "retry",
        ))
        .layer(LayerSpec::wrapper("retry", RETRY_KIND, "broker"))
        .layer(LayerSpec::backend("broker", "broker"))
        .connection(LayerConnectionRequest {
            target: "broker".into(),
            connection: ConnectionRequest {
                backend_kind: "broker".into(),
                config,
                credentials,
                persist: false,
                display_name: Some("broker".into()),
            },
        })
        .build()
        .await
        .expect("build bespoke broker-client app Stack")
}

/// Serve a FULL OIDC discovery document pointing at `idp_base`'s endpoints on a
/// loopback port. `FakeIdp`'s own `/.well-known` is an issuer-only stub, but the
/// broker-client's `fetch_oidc_config` needs `token_endpoint` +
/// `authorization_endpoint`, so publish a complete doc referencing the fake
/// IdP's real `/authorize` + `/token`. Returns `(discovery_url, shutdown)`.
fn spawn_oidc_discovery_doc(idp_base: &str) -> (String, tokio::sync::oneshot::Sender<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}/.well-known/openid-configuration");
    let doc = serde_json::json!({
        "issuer": idp_base,
        "token_endpoint": format!("{idp_base}/token"),
        "authorization_endpoint": format!("{idp_base}/authorize"),
        "device_authorization_endpoint": format!("{idp_base}/device_authorization"),
    })
    .to_string();
    let (shutdown, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::Builder::new()
        .name("ovs-oidc-doc".into())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                return;
            };
            runtime.block_on(async move {
                let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
                    return;
                };
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        accept = listener.accept() => {
                            if let Ok((mut sock, _)) = accept {
                                let body = doc.clone();
                                tokio::spawn(async move {
                                    let mut buf = [0u8; 2048];
                                    let _ = sock.read(&mut buf).await;
                                    let response = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                                        body.len(),
                                        body
                                    );
                                    let _ = sock.write_all(response.as_bytes()).await;
                                    let _ = sock.shutdown().await;
                                });
                            }
                        }
                    }
                }
            });
        })
        .expect("spawn oidc-doc server");
    (url, shutdown)
}

/// Simulate the host SDK's browser hop: GET the loopback callback with a fake
/// `code`, so the broker-client's PKCE listener exchanges it at the IdP's
/// `/token`. Mirrors `oauth_three_tier::simulate_browser_pkce_callback`.
async fn simulate_browser_pkce_callback(open_browser_url: &str) {
    let parsed = url::Url::parse(open_browser_url).expect("OpenBrowser URL parses");
    let mut redirect_uri = String::new();
    let mut state = String::new();
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "redirect_uri" => redirect_uri = value.into_owned(),
            "state" => state = value.into_owned(),
            _ => {}
        }
    }
    let redirect_url = format!("{redirect_uri}?code=fake-code&state={state}");
    tokio::spawn(async move {
        let _ = reqwest::get(&redirect_url).await;
    });
}

/// Object ops round-trip through the bespoke wrapper-chain Stack onto the
/// dlopen'd v2 broker-client backend (anonymous direct-gRPC broker).
#[tokio::test(flavor = "multi_thread")]
async fn bespoke_app_stack_round_trips_object_ops() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker = Arc::new(Broker::new(file_broker_stack(&root).await));
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();

    let stack = bespoke_broker_stack(&server.endpoint_url(), SecretBundle::default()).await;

    let object =
        address::join_relative(&prefix, &format!("bespoke-{}.txt", unique_suffix())).unwrap();
    let payload = b"bespoke app-stack round-trip bytes".to_vec();
    stack
        .write(
            Request::new(WriteRequest {
                address: object.clone(),
                body: Body::Bytes(payload.clone()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect("write through the bespoke Stack");

    let read = stack
        .read(
            Request::new(ReadRequest {
                address: object.clone(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("read through the bespoke Stack");
    match read {
        ReadResult::Bytes { bytes, .. } => assert_eq!(bytes, payload),
        ReadResult::LocalDelegate(local) => {
            assert_eq!(std::fs::read(&local.path).unwrap(), payload)
        }
        ReadResult::Stream { mut stream, .. } => {
            use futures::StreamExt as _;
            let mut got = Vec::new();
            while let Some(chunk) = stream.next().await {
                got.extend_from_slice(&chunk.expect("stream chunk"));
            }
            assert_eq!(got, payload);
        }
        other => panic!("unexpected read result: {other:?}"),
    }

    let info = stack
        .stat(
            Request::new(StatRequest {
                address: object.clone(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect("stat through the bespoke Stack");
    assert_eq!(info.size, Some(payload.len() as u64));

    drop(stack);
    shutdown_test_server(server).await;
    remove_dir_all_retry(root).unwrap();
}

/// Tier-1 interactive sign-in on the bespoke Stack: a credential-less broker
/// connection parks awaiting auth, then `authenticate_connection` (PKCE/browser)
/// drives the broker's identity-provider flow to a resolved bearer and
/// authenticates the connection.
#[tokio::test(flavor = "multi_thread")]
async fn bespoke_app_stack_drives_tier1_interactive_signin() {
    use ovstorage::auth::flow::test_support::FakeIdp;

    let idp = FakeIdp::start_with_token("tier1-forward-path-bearer").await;
    let (oidc_url, _oidc_shutdown) = spawn_oidc_discovery_doc(&idp.base_url);

    // Daemon: anonymous broker over a file backend, plus an HTTP discovery
    // listener publishing the gRPC endpoint AND an auth-config pointing at the
    // fake IdP (via the OIDC doc above).
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let broker = Arc::new(Broker::new(file_broker_stack(&root).await));
    let grpc = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let grpc_endpoint = grpc.endpoint_url();

    let mut clients = std::collections::BTreeMap::new();
    clients.insert(
        "default".to_string(),
        crate::discovery::BrokerAuthClientDocument {
            client_id: idp.client_id.clone(),
            scope: Some("openid".into()),
        },
    );
    let discovery_config = crate::discovery::BrokerDiscoveryConfig {
        name: "test".into(),
        services: vec![crate::discovery::BrokerDiscoveryService {
            service_type: "ovstorage-broker".into(),
            endpoint: grpc_endpoint.clone(),
        }],
        auth_config: Some(crate::discovery::BrokerAuthConfigDocument {
            openid_configuration: oidc_url,
            clients,
        }),
        bind: None,
        broker_endpoint: None,
    };
    let disco_state =
        crate::discovery::BrokerDiscoveryState::new(discovery_config, grpc_endpoint.clone());
    let disco =
        crate::discovery::spawn_broker_discovery_http_listener(disco_state, "127.0.0.1:0").unwrap();

    // App bespoke Stack: credential-less broker connection to the HTTP discovery
    // URL → parks awaiting interactive sign-in.
    let stack = bespoke_broker_stack(&disco.base_url(), SecretBundle::default()).await;

    let (snapshot, _updates) = stack
        .list_connections(&ovstorage::Extensions::new(), None)
        .await
        .expect("list_connections");
    let connection = snapshot
        .connections
        .into_iter()
        .next()
        .expect("one broker connection");
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "a credential-less broker connection parks awaiting sign-in, got {:?}",
        connection.auth_state
    );

    // Drive tier-1 interactive sign-in via the layer's authenticate_connection.
    let mut events = stack
        .authenticate_connection(
            Request::new(AuthenticateRequest {
                key: ConnectionKey {
                    target: "broker".into(),
                    id: connection.id.clone(),
                },
                capability: InteractiveAuthCapability::Browser,
                auto_open_browser: false,
            }),
            None,
        )
        .await
        .expect("authenticate_connection opens the interactive flow");

    // First event is OpenBrowser; simulate the browser hop, then drain to
    // Succeeded (the PKCE listener exchanges the code at the fake IdP's /token).
    let first = events
        .next()
        .expect("first auth event")
        .expect("auth event ok");
    let browser_url = match first {
        AuthEvent::OpenBrowser { url, .. } => url,
        other => panic!("expected OpenBrowser, got {other:?}"),
    };
    simulate_browser_pkce_callback(browser_url.as_str()).await;

    let mut saw_succeeded = false;
    for event in events.by_ref() {
        match event.expect("auth event ok") {
            AuthEvent::Succeeded { .. } => {
                saw_succeeded = true;
                break;
            }
            AuthEvent::Failed { error } => panic!("interactive sign-in failed: {error}"),
            _ => {}
        }
    }
    assert!(
        saw_succeeded,
        "the interactive flow must reach Succeeded with a resolved bearer"
    );
    drop(events);

    // The connection is authenticated on the Stack after the sign-in.
    let (after, _updates) = stack
        .list_connections(&ovstorage::Extensions::new(), None)
        .await
        .expect("list_connections");
    let connection = after
        .connections
        .into_iter()
        .find(|c| c.id == connection.id)
        .expect("connection still present");
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "the broker connection is authenticated after interactive sign-in, got {:?}",
        connection.auth_state
    );

    drop(stack);
    shutdown_test_server(grpc).await;
    let _ = disco;
    remove_dir_all_retry(root).unwrap();
}

/// End-to-end wiring of the N1 v2 FFI update-stream bridge to a bespoke Stack
/// client: the broker's published address roots reach the client through the
/// dlopen'd broker-client backend, and the client advertises a LIVE
/// `RootInfoUpdateStream` — its background root-watcher opens the broker's
/// `WatchAddressRoots` RPC and republishes onto that stream.
///
/// NOTE: a SIGHUP-driven root *delta* cannot be observed end-to-end today
/// because the broker daemon's `watch_address_roots` is snapshot-once
/// (`grpc.rs`: "Snapshot-once today; deltas land when the route table can
/// mutate at runtime") and discards the Stack's update stream
/// (`broker.rs::list_address_roots` drops `_updates`). The client bridge below
/// is ready to consume deltas the instant the daemon emits them; wiring that
/// server-side emission is a broker-daemon follow-up, not the client port.
#[tokio::test(flavor = "multi_thread")]
async fn bespoke_app_stack_receives_broker_roots_over_the_live_update_bridge() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker = Arc::new(Broker::new(file_broker_stack(&root).await));
    let server = spawn_broker_grpc_tcp_listener(broker, "127.0.0.1:0".parse().unwrap()).unwrap();

    let stack = bespoke_broker_stack(&server.endpoint_url(), SecretBundle::default()).await;

    let (snapshot, updates) = stack
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .expect("list_address_roots");
    assert!(
        snapshot.updates,
        "the Stack client advertises live root updates (the N1 FFI bridge)"
    );
    assert!(
        snapshot.roots.iter().any(|root| root.root == prefix),
        "the broker-published file root propagated to the client, got {:?}",
        snapshot
            .roots
            .iter()
            .map(|root| root.root.as_str())
            .collect::<Vec<_>>()
    );

    // Exercise the LIVE republish, not just the initial snapshot: the broker
    // daemon is snapshot-once, so the client's background root-watcher opens
    // `WatchAddressRoots`, receives one `Snapshot` frame, and republishes it
    // through the bridge (`apply_backend_roots_change` -> `rebuild_and_notify`)
    // onto this update stream. The watcher spins up its own OS thread, tokio
    // runtime, and RPC, so that republish lands well after this subscription —
    // drain the stream until the republished Snapshot arrives.
    use futures::StreamExt as _;
    let mut updates = updates.expect("the Stack client exposes a RootInfoUpdateStream");
    let republished = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match updates.next().await {
                Some(Ok(RootInfoChange::Snapshot(roots))) => break roots,
                // A self-limiting `Lagged` resync (Err) or a non-Snapshot delta:
                // keep draining. `None` = the bridge dropped its sender.
                Some(_) => continue,
                None => panic!("root update stream closed before republishing a snapshot"),
            }
        }
    })
    .await
    .expect("client republishes the broker address-root snapshot over the live bridge");
    assert!(
        republished.iter().any(|root| root.root == prefix),
        "the republished Snapshot carries the broker file root, got {:?}",
        republished
            .iter()
            .map(|root| root.root.as_str())
            .collect::<Vec<_>>()
    );

    drop(stack);
    shutdown_test_server(server).await;
    remove_dir_all_retry(root).unwrap();
}
