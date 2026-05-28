// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-only fixture helpers. The build script populates an
//! `OUT_DIR/test-plugins/` dir with the cdylibs broker tests dlopen and
//! exports the path as `OVSTORAGE_BROKER_TEST_PLUGIN_DIR`.

#![cfg(test)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use std::sync::Arc;

use ovstorage::{ConfigValue, ConnectionRequest, Library, SecretBundle, Storage as _};

pub(crate) fn workspace_plugin_dir() -> PathBuf {
    PathBuf::from(env!("OVSTORAGE_BROKER_TEST_PLUGIN_DIR"))
}

/// Builder extension. `Library::builder().<extra>...open_with_test_plugins()`
/// wires the cached broker test substrate, opens, and dlopens every fixture
/// plugin in one chain. Replaces the old `with_test_plugins().open().unwrap()`.
pub(crate) trait BuilderTestExt {
    fn open_with_test_plugins(self) -> Arc<Library>;
}

impl BuilderTestExt for ovstorage::LibraryBuilder {
    fn open_with_test_plugins(self) -> Arc<Library> {
        // OVSTORAGE_AUTH_DIR must be set before substrate init so the
        // cached production-path substrate lands under our tempdir.
        ensure_test_plugin_env();
        let (secret_store, refresh_lock) = crate::cached_broker_substrate()
            .expect("test substrate init failed (OVSTORAGE_AUTH_DIR unwritable?)");
        let library = self
            .with_credential_persistence(secret_store.clone(), refresh_lock.clone())
            // `allow_test_plugins(true)` is required by core's `test_only`
            // plugin manifest gate.
            .allow_test_plugins(true)
            .open()
            .expect("library open");
        // SAFETY: integration test pointing at workspace target.
        unsafe {
            library
                .load_plugins_from_dir(Some(&workspace_plugin_dir()))
                .expect("dlopen test plugins");
        }
        library
    }
}

/// Register the file plugin via the dlopen path so per-test plumbing
/// matches production.
pub(crate) async fn add_file_connection(library: &Library, root: &Path) {
    let mut config = HashMap::new();
    config.insert(
        "root".into(),
        ConfigValue::String(root.to_string_lossy().into_owned()),
    );
    library
        .add_connection(
            ConnectionRequest {
                backend_kind: "file".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
            None,
        )
        .await
        .expect("file connection registration failed");
}

/// Register the test plugin against `test://demo/`.
pub(crate) async fn add_test_connection(
    library: &Library,
    extra_config: HashMap<String, ConfigValue>,
) {
    let mut config = extra_config;
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://demo/".into()),
    );
    library
        .add_connection(
            ConnectionRequest {
                backend_kind: "test".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
            None,
        )
        .await
        .expect("test connection registration failed");
}

/// Poll `__test_meta/method_calls.json` until `counter == target` or
/// 15s elapses (tolerates `cargo test --workspace` pressure).
pub(crate) async fn wait_until_test_counter_eq(library: &Library, counter: &str, target: u64) {
    let probe = ovstorage::address::parse("test://demo/__test_meta/method_calls.json")
        .expect("meta address");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if let Ok((bytes, _)) = library
            .read_bytes(probe.clone(), Default::default(), None)
            .await
        {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if json[counter].as_u64() == Some(target) {
                    return;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("test plugin counter '{counter}' did not reach {target} within 15 seconds");
}

/// Set `OVSTORAGE_PLUGIN_DIR` + auth dir once per test process so
/// production-path builders discover the fixture cdylibs.
pub(crate) fn ensure_test_plugin_env() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("OVSTORAGE_PLUGIN_DIR", workspace_plugin_dir()) };
        let auth_root =
            std::env::temp_dir().join(format!("ovstorage-broker-test-auth-{}", std::process::id()));
        std::fs::create_dir_all(&auth_root).unwrap();
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("OVSTORAGE_AUTH_DIR", &auth_root) };
        unsafe { std::env::set_var("OVSTORAGE_ALLOW_TEST_PLUGINS", "1") };
    });
}
