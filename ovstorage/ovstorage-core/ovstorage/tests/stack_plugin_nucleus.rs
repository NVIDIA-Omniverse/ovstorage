// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end proof of the ABI-v2 **nucleus cdylib** through a native Stack.
//!
//! Gated on `OVSTORAGE_NUCLEUS_PLUGIN_SO_OVERRIDE` (hard error under
//! `OVSTORAGE_REQUIRE_TEST_PLUGINS`, else skip — matching `mixed_layer_stack.rs`).

use std::collections::HashMap;

use ovstorage::{
    ConfigValue, ConnectionAuthState, ConnectionKey, ConnectionRequest, ErrorCode, Layer,
    LayerConnectionRequest, Request, SecretBundle, StatOptions, StatRequest, address,
};

mod support;

fn staged_nucleus_cdylib() -> Option<std::path::PathBuf> {
    match std::env::var_os("OVSTORAGE_NUCLEUS_PLUGIN_SO_OVERRIDE") {
        Some(path) => Some(std::path::PathBuf::from(path)),
        None => {
            assert!(
                std::env::var("OVSTORAGE_REQUIRE_TEST_PLUGINS").as_deref() != Ok("1"),
                "OVSTORAGE_NUCLEUS_PLUGIN_SO_OVERRIDE unset but OVSTORAGE_REQUIRE_TEST_PLUGINS \
                 demands the staged nucleus cdylib"
            );
            eprintln!("skipping: OVSTORAGE_NUCLEUS_PLUGIN_SO_OVERRIDE unset");
            None
        }
    }
}

/// The shipped cdylib's Layer thunks end-to-end, outside the bridge: load
/// via the v2 layer-plugin loader (the Stack-native path nucleus connections
/// actually use), build the layer, and drive the lifecycle slots through the
/// loaded ABI-v2 artifact — a credential-less add PARKS (`AwaitingAuth`, not
/// an error), the config-derived root publishes, a stat through the loaded
/// thunks refuses with `AuthRequired` (no session), and removal tears the
/// route down. This is what keeps a miswired factory or vtable thunk in the
/// production artifact from hiding behind the in-process `cfg(test)` suite.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loaded_nucleus_layer_thunks_drive_the_lifecycle_stack_natively() {
    let Some(so) = staged_nucleus_cdylib() else {
        return;
    };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");

    // SAFETY: dlopening a first-party plugin staged by the test harness.
    let factories = unsafe { ovstorage::load_layer_plugin(&so, true) }
        .expect("load the nucleus cdylib as a v2 layer plugin");
    let stack =
        ovstorage::host::build_stack(&support::linear_stack_config("nucleus", &[]), factories)
            .await
            .expect("build nucleus Stack");

    let connection = stack
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "nucleus".into(),
                connection: ConnectionRequest {
                    backend_kind: "nucleus".into(),
                    config: HashMap::from([(
                        "server".into(),
                        ConfigValue::String("nucleus.local".into()),
                    )]),
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("a credential-less add parks rather than erroring");
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "nucleus has no anonymous data path; expected AwaitingAuth, got {:?}",
        connection.auth_state
    );
    assert_eq!(
        connection.current_addresses[0].as_str(),
        "omniverse://nucleus.local/",
        "the config-derived root publishes through the loaded thunks"
    );
    let (roots, _) = stack
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .expect("list roots");
    assert!(
        roots
            .roots
            .iter()
            .any(|root| root.root.as_str() == "omniverse://nucleus.local/"),
        "root visible in the loaded layer's snapshot: {:?}",
        roots.roots
    );

    let err = stack
        .stat(
            Request::new(StatRequest {
                address: address::parse("omniverse://nucleus.local/Users/alice/foo.usd").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("no session installed — object I/O must refuse");
    assert_eq!(err.code(), ErrorCode::AuthRequired);

    stack
        .remove_connection(
            Request::new(ConnectionKey {
                target: "nucleus".into(),
                id: connection.id.clone(),
            }),
            None,
        )
        .await
        .expect("remove through the loaded thunks");
    let (roots, _) = stack
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .expect("list roots after removal");
    assert!(
        roots.roots.is_empty(),
        "removal tears the route down: {:?}",
        roots.roots
    );
}
