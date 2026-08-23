// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A host's cancellation token is an EXIT from a wedged connection apply.
//!
//! Applying a declared `[[ovstorage.connections]]` through a Router waits for
//! the route-table catch-up that makes the address routable. A backend that
//! commits the mutation and then never answers the root re-query holds that
//! wait until the catch-up's own 30-second deadline. A host that supplies a
//! token gets out on cancellation instead, and this asserts the difference in
//! wall-clock terms: the build returns in a fraction of that bound.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ovstorage::{
    BackendFactory, CancellationToken, Capabilities, Connection, ConnectionAuthState,
    ConnectionConfig, ConnectionId, ConnectionSource, ConnectionUpdateStream, Extensions, Layer,
    LayerConfig, LayerConnectionRequest, LayerHandle, LayerKindDescriptor, LayerTable, LayerType,
    LoadedLayerFactory, Request, Result, RootInfoSnapshot, RootInfoUpdateStream, StackConfig, Url,
    UserMetadata,
};
use ovstorage_plugin_core::RouterFactoryImpl;

/// The wedge is deliberately narrow: root discovery answers normally while the
/// Stack instantiates, so the build reaches the connection loop, and only the
/// catch-up that follows the committed mutation hangs. A backend that hung from
/// the start would wedge layer construction instead and prove a different
/// thing.
const WEDGE_KIND: &str = "wedge";

/// How long a cancelled build is allowed to take. Far below the library's
/// 30-second child-root-query bound, so passing cannot mean "the bound fired".
const PROMPT: Duration = Duration::from_secs(5);

/// Fails the test rather than hanging it when cancellation does not take: long
/// enough that a slow machine cannot trip it, short enough to sit under the
/// bound a token-less build would wait out.
const GIVE_UP: Duration = Duration::from_secs(10);

struct WedgeBackend {
    wedged: AtomicBool,
}

#[async_trait]
impl Layer for WedgeBackend {
    fn name(&self) -> &str {
        WEDGE_KIND
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        wedge_descriptor()
    }

    fn owned_targets(&self) -> Vec<String> {
        vec![WEDGE_KIND.to_string()]
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        if self.wedged.load(Ordering::SeqCst) {
            // Never answers, and never observes the token either — a foreign
            // child whose only exit is the caller giving up on it.
            std::future::pending::<()>().await;
        }
        Ok((
            RootInfoSnapshot {
                roots: Vec::new(),
                updates: false,
            },
            None,
        ))
    }

    async fn list_connections(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(
        ovstorage::ConnectionSnapshot,
        Option<ConnectionUpdateStream>,
    )> {
        Ok((
            ovstorage::ConnectionSnapshot {
                connections: Vec::new(),
                updates: false,
            },
            None,
        ))
    }

    async fn add_connection(
        &self,
        _request: Request<LayerConnectionRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        // Commit, then wedge: the catch-up the Router runs next is the wait
        // under test, and it only exists because a mutation landed.
        self.wedged.store(true, Ordering::SeqCst);
        Ok(Connection {
            id: ConnectionId(WEDGE_KIND.to_string()),
            backend_kind: WEDGE_KIND.to_string(),
            display_name: WEDGE_KIND.to_string(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: vec![Url::parse("wedge://host/").unwrap()],
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: UserMetadata::new(),
        })
    }
}

struct WedgeFactory;

#[async_trait]
impl BackendFactory for WedgeFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        wedge_descriptor()
    }

    async fn create_backend(
        &self,
        _name: &str,
        _config: &LayerConfig,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(Arc::new(WedgeBackend {
            wedged: AtomicBool::new(false),
        }))
    }
}

fn wedge_descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        kind: WEDGE_KIND.to_string(),
        layer_type: LayerType::Backend,
        display_name: WEDGE_KIND.to_string(),
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

/// A Router over the wedging backend, with one declared connection targeting it.
fn wedging_stack_config() -> StackConfig {
    StackConfig {
        root: Some("router".into()),
        layers: HashMap::from([
            (
                "router".to_string(),
                LayerTable {
                    kind: Some("router".into()),
                    children: vec![WEDGE_KIND.into()],
                    ..LayerTable::default()
                },
            ),
            (
                WEDGE_KIND.to_string(),
                LayerTable {
                    kind: Some(WEDGE_KIND.into()),
                    ..LayerTable::default()
                },
            ),
        ]),
        connections: vec![ConnectionConfig {
            backend_kind: WEDGE_KIND.into(),
            target: Some(WEDGE_KIND.into()),
            display_name: Some("wedged".into()),
            config: HashMap::new(),
            credentials: HashMap::new(),
        }],
    }
}

fn wedge_factories() -> Vec<LoadedLayerFactory> {
    vec![
        LoadedLayerFactory::Router(Arc::new(RouterFactoryImpl)),
        LoadedLayerFactory::Backend(Arc::new(WedgeFactory)),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_the_host_token_exits_a_wedged_connection_apply() {
    let cancel = CancellationToken::new();
    let fired = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        fired.cancel();
    });

    let started = Instant::now();
    let outcome = tokio::time::timeout(
        GIVE_UP,
        ovstorage::host::build_stack_with_cancel(
            &wedging_stack_config(),
            wedge_factories(),
            Some(cancel),
        ),
    )
    .await;
    let elapsed = started.elapsed();

    let result = outcome.unwrap_or_else(|_| {
        panic!(
            "the build did not return within {GIVE_UP:?} of a fired token — the wedged \
             connection apply is waiting out the child-root-query bound instead"
        )
    });
    // The mutation committed on the child, so the answer is ambiguity, not
    // `Cancelled`: what the token buys is an exit, not a different outcome.
    let error = result
        .err()
        .expect("a wedged catch-up cannot report success");
    assert_eq!(error.code(), ovstorage::ErrorCode::CommitAmbiguous);
    assert!(
        elapsed < PROMPT,
        "the build took {elapsed:?}; a cancelled wait must return promptly, well under the \
         child-root-query bound"
    );
}
