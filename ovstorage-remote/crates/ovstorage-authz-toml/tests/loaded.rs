// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end dlopen-through-`LoadedAuthzPlugin` integration test.

use std::collections::HashMap;
use std::path::PathBuf;

use ovstorage_authz::{
    AuthzEffect, AuthzPlugin, AuthzRequest, LoadedAuthzPlugin, Operation, Principal,
};
use ovstorage_plugin::{ConfigValue, address};

const SO_PATH: &str = env!("OVSTORAGE_AUTHZ_PLUGIN_TOML_SO");

fn principal(id: &str) -> Principal {
    Principal {
        id: id.into(),
        display_name: None,
        attributes: HashMap::new(),
        valid_until: None,
        source: "test".into(),
    }
}

fn request_for(p: &str, op: Operation, addr: &str) -> AuthzRequest {
    AuthzRequest {
        principal: principal(p),
        operation: op,
        address: Some(address::parse(addr).unwrap()),
        policy_epoch: 0,
        audit_id: None,
    }
}

#[tokio::test]
async fn loaded_plugin_round_trip_configure_authorize_filter() {
    let path = PathBuf::from(SO_PATH);
    assert!(
        path.exists(),
        "cdylib not present at {} — did `cargo build -p ovstorage-authz-toml` run?",
        path.display(),
    );

    // SAFETY: we trust the in-tree cdylib produced by our own build.
    let plugin = unsafe { LoadedAuthzPlugin::open(&path) }
        .expect("LoadedAuthzPlugin::open should succeed against the cdylib");

    assert_eq!(plugin.manifest().name, "ovstorage-authz-toml");

    let policy_toml = r#"
[[policy]]
id = "allow-root"
effect = "allow"
principal = "alice"
operations = ["read"]
prefix = "file:/root/"

[[policy]]
id = "deny-secret"
effect = "deny"
principal = "alice"
operations = ["read"]
prefix = "file:/root/secret/"
"#
    .to_string();

    let mut config = HashMap::new();
    config.insert("policy".to_string(), ConfigValue::Toml(policy_toml));

    plugin
        .configure(config, None)
        .await
        .expect("configure should succeed against a valid policy TOML");

    let allow = plugin
        .authorize(&request_for("alice", Operation::Read, "file:/root/a.txt"))
        .await
        .unwrap();
    assert_eq!(allow.effect, AuthzEffect::Allow);
    assert_eq!(allow.explanation.as_deref(), Some("allow-root"));

    // longer prefix wins over shorter overlapping prefix
    let deny = plugin
        .authorize(&request_for(
            "alice",
            Operation::Read,
            "file:/root/secret/leak.txt",
        ))
        .await
        .unwrap();
    assert_eq!(deny.effect, AuthzEffect::Deny);
    assert_eq!(deny.explanation.as_deref(), Some("deny-secret"));

    let addresses = vec![
        address::parse("file:/root/a.txt").unwrap(),
        address::parse("file:/root/secret/leak.txt").unwrap(),
        address::parse("file:/other/").unwrap(), // no rule matches → default-deny
    ];
    let request = request_for("alice", Operation::Read, "file:/root/");
    let decisions = plugin
        .filter_list_batch(&request, &addresses)
        .await
        .unwrap();
    assert_eq!(decisions.len(), 3);
    assert_eq!(decisions[0].effect, AuthzEffect::Allow);
    assert_eq!(decisions[1].effect, AuthzEffect::Deny);
    assert_eq!(decisions[2].effect, AuthzEffect::Deny);
}

#[tokio::test]
async fn loaded_plugin_authorize_before_configure_returns_not_configured() {
    let path = PathBuf::from(SO_PATH);
    let plugin = unsafe { LoadedAuthzPlugin::open(&path) }.unwrap();

    let err = plugin
        .authorize(&request_for("alice", Operation::Read, "file:/root/a.txt"))
        .await
        .unwrap_err();
    assert!(
        err.message().contains("not configured"),
        "expected 'not configured' message, got {}",
        err.message()
    );
}

#[tokio::test]
async fn loaded_plugin_rejects_negative_decision_ttl_max_seconds() {
    let path = PathBuf::from(SO_PATH);
    let plugin = unsafe { LoadedAuthzPlugin::open(&path) }.unwrap();

    let mut config = HashMap::new();
    config.insert("decision_ttl_max_seconds".to_string(), ConfigValue::Int(-1));

    let err = plugin
        .configure(config, None)
        .await
        .expect_err("negative TTL must be rejected");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("non-negative"),
        "expected non-negative message, got {}",
        err.message()
    );
}

#[tokio::test]
async fn loaded_plugin_rejects_wrong_typed_decision_ttl_max_seconds() {
    let path = PathBuf::from(SO_PATH);
    let plugin = unsafe { LoadedAuthzPlugin::open(&path) }.unwrap();

    let mut config = HashMap::new();
    config.insert(
        "decision_ttl_max_seconds".to_string(),
        ConfigValue::String("60".into()),
    );

    let err = plugin
        .configure(config, None)
        .await
        .expect_err("wrong-typed TTL must be rejected");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("integer"),
        "expected integer-type message, got {}",
        err.message()
    );
}

#[tokio::test]
async fn loaded_plugin_rejects_wrong_typed_policy_field() {
    let path = PathBuf::from(SO_PATH);
    let plugin = unsafe { LoadedAuthzPlugin::open(&path) }.unwrap();

    let mut config = HashMap::new();
    config.insert("policy".to_string(), ConfigValue::Int(123));

    let err = plugin
        .configure(config, None)
        .await
        .expect_err("wrong-typed policy must be rejected");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("policy"),
        "expected policy-related message, got {}",
        err.message()
    );
}

#[tokio::test]
async fn loaded_plugin_decision_ttl_round_trips_to_decision() {
    let path = PathBuf::from(SO_PATH);
    let plugin = unsafe { LoadedAuthzPlugin::open(&path) }.unwrap();

    let policy_toml = r#"
[[policy]]
id = "allow-alice"
effect = "allow"
principal = "alice"
operations = ["read"]
prefix = "file:/root/"
"#
    .to_string();

    let mut config = HashMap::new();
    config.insert("policy".to_string(), ConfigValue::Toml(policy_toml));
    config.insert("decision_ttl_max_seconds".to_string(), ConfigValue::Int(45));

    plugin.configure(config, None).await.unwrap();

    let allow = plugin
        .authorize(&request_for("alice", Operation::Read, "file:/root/a.txt"))
        .await
        .unwrap();
    assert_eq!(allow.effect, AuthzEffect::Allow);
    assert_eq!(allow.decision_ttl, Some(std::time::Duration::from_secs(45)));

    let deny = plugin
        .authorize(&request_for("bob", Operation::Read, "file:/elsewhere/x"))
        .await
        .unwrap();
    assert_eq!(deny.effect, AuthzEffect::Deny);
    assert_eq!(deny.decision_ttl, Some(std::time::Duration::from_secs(45)));
}

#[tokio::test]
async fn loaded_plugin_handles_concurrent_authorize_calls() {
    let path = PathBuf::from(SO_PATH);
    let plugin = std::sync::Arc::new(unsafe { LoadedAuthzPlugin::open(&path) }.unwrap());

    let policy_toml = r#"
[[policy]]
id = "allow-alice"
effect = "allow"
principal = "alice"
operations = ["read"]
prefix = "file:/root/"
"#
    .to_string();
    let mut config = HashMap::new();
    config.insert("policy".to_string(), ConfigValue::Toml(policy_toml));
    plugin.configure(config, None).await.unwrap();

    let mut handles = Vec::with_capacity(32);
    for _ in 0..32 {
        let p = plugin.clone();
        handles.push(tokio::spawn(async move {
            p.authorize(&request_for("alice", Operation::Read, "file:/root/a.txt"))
                .await
        }));
    }

    for handle in handles {
        let decision = handle.await.unwrap().unwrap();
        assert_eq!(decision.effect, AuthzEffect::Allow);
        assert_eq!(decision.explanation.as_deref(), Some("allow-alice"));
    }
}

#[tokio::test]
async fn loaded_plugin_drops_cleanly_after_in_flight_calls() {
    let path = PathBuf::from(SO_PATH);
    let plugin = unsafe { LoadedAuthzPlugin::open(&path) }.unwrap();

    let policy_toml = r#"
[[policy]]
id = "allow-alice"
effect = "allow"
principal = "alice"
operations = ["read"]
prefix = "file:/root/"
"#
    .to_string();
    let mut config = HashMap::new();
    config.insert("policy".to_string(), ConfigValue::Toml(policy_toml));
    plugin.configure(config, None).await.unwrap();

    for _ in 0..16 {
        let decision = plugin
            .authorize(&request_for("alice", Operation::Read, "file:/root/a.txt"))
            .await
            .unwrap();
        assert_eq!(decision.effect, AuthzEffect::Allow);
    }

    let start = std::time::Instant::now();
    drop(plugin);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "drop must not exceed the in-flight drain timeout"
    );
}
