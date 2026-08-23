// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authentication event and host-callback contracts on the Stack-native test Layer.

use std::collections::HashMap;
use std::sync::Arc;

use ovstorage::{
    AuthEvent, AuthenticateRequest, ConfigValue, ConnectionKey, ConnectionRequest,
    InteractiveAuthCapability, Layer, LayerConnectionRequest, LayerSpec, Request, SecretBundle,
    Stack,
};
use ovstorage_plugin_test::TestLayerFactory;

async fn authenticate(knobs: &[(&str, ConfigValue)]) -> Vec<AuthEvent> {
    // This suite verifies the host-callback plumbing, not where the secrets
    // land. `None` is deliberate: the substrate is process-global and
    // set-once, so a harness that named its own directory would refuse a
    // second Stack built in the same process. Hermeticity comes from
    // `OVSTORAGE_AUTH_DIR`, which the test recipes pin away from the
    // developer's real auth directory and `lint-auth-test-root` keeps pinned.
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let stack = Stack::builder("test")
        .backend_factory(Arc::new(TestLayerFactory::default()))
        .layer(LayerSpec::backend("test", "test"))
        .build()
        .await
        .expect("build test Stack");
    let mut config = HashMap::from([(
        "test_root".into(),
        ConfigValue::String("test://auth-events/".into()),
    )]);
    for (key, value) in knobs {
        config.insert((*key).into(), value.clone());
    }
    let connection = stack
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "test".into(),
                connection: ConnectionRequest {
                    backend_kind: "test".into(),
                    config,
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("add test connection");
    stack
        .authenticate_connection(
            Request::new(AuthenticateRequest {
                key: ConnectionKey {
                    target: "test".into(),
                    id: connection.id,
                },
                capability: InteractiveAuthCapability::None,
                auto_open_browser: false,
            }),
            None,
        )
        .await
        .expect("authenticate connection")
        .map(|event| event.expect("auth event"))
        .collect()
}

#[tokio::test]
async fn authenticate_progress_then_succeeds() {
    let events = authenticate(&[(
        "test_auth_flow",
        ConfigValue::String("progress-then-succeed".into()),
    )])
    .await;
    assert!(matches!(
        events.as_slice(),
        [AuthEvent::Progress { .. }, AuthEvent::Succeeded { .. }]
    ));
}

#[tokio::test]
async fn authenticate_drives_host_keyring_and_refresh_lock_callbacks() {
    let events =
        authenticate(&[("test_auth_drives_host_callbacks", ConfigValue::Bool(true))]).await;
    assert!(matches!(events.as_slice(), [AuthEvent::Succeeded { .. }]));
}

#[tokio::test]
async fn authenticate_emits_cancelled_event() {
    let events = authenticate(&[("test_auth_flow", ConfigValue::String("cancel".into()))]).await;
    assert!(matches!(events.as_slice(), [AuthEvent::Cancelled]));
}

#[tokio::test]
async fn authenticate_emits_device_code_then_succeeds() {
    let events = authenticate(&[(
        "test_auth_flow",
        ConfigValue::String("device-code-then-succeed".into()),
    )])
    .await;
    assert!(matches!(
        events.as_slice(),
        [AuthEvent::DeviceCode { .. }, AuthEvent::Succeeded { .. }]
    ));
    let AuthEvent::DeviceCode {
        user_code,
        verification_url,
        ..
    } = &events[0]
    else {
        unreachable!()
    };
    assert!(!user_code.is_empty());
    assert!(verification_url.starts_with("https://"));
}
