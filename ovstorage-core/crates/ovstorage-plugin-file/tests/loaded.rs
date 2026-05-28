// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end C-ABI exercise of the file plugin loaded via `dlopen`.

use std::collections::HashMap;
use std::sync::Arc;

use ovstorage::Library;
use ovstorage::Storage as _;
use ovstorage::auth::{AuthRefreshLock, SecretStore};
use ovstorage_plugin::{
    Body, ConfigValue, ConnectionRequest, DeleteOptions, ListOptions, ObjectKind, ReadOptions,
    SecretBundle, StatOptions, WriteOptions, address,
};

const PLUGIN_PATH: &str = env!("OVSTORAGE_PLUGIN_FILE_SO");

fn auth_substrate() -> (Arc<SecretStore>, Arc<AuthRefreshLock>, tempfile::TempDir) {
    let temp = tempfile::tempdir().expect("auth tempdir");
    let store = Arc::new(SecretStore::new());
    let lock = Arc::new(AuthRefreshLock::open(temp.path()).expect("auth refresh lock"));
    (store, lock, temp)
}

#[tokio::test]
async fn dlopen_file_plugin_drives_full_object_round_trip() {
    let root = tempfile::tempdir().expect("connection root tempdir");
    let (_store, _lock, auth_state) = auth_substrate();

    let library = Library::open(Some(auth_state.path())).expect("library open");
    // SAFETY: integration test loading our own file plugin cdylib.
    unsafe {
        library.load_plugin(PLUGIN_PATH).expect("load_plugin");
    }

    let mut config: HashMap<String, ConfigValue> = HashMap::new();
    config.insert(
        "root".into(),
        ConfigValue::String(root.path().to_string_lossy().into_owned()),
    );

    let request = ConnectionRequest {
        backend_kind: "file".into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: Some("file-plugin-loaded-test".into()),
    };
    let connection = library
        .add_connection(request, None)
        .await
        .expect("add_connection");
    let route_prefix = connection
        .current_addresses
        .first()
        .cloned()
        .expect("connection should expose at least one address root");

    let object_address =
        address::join_relative(&route_prefix, "hello.txt").expect("compose object address");

    let payload = b"hello from dlopen'd file plugin".to_vec();
    library
        .write(
            object_address.clone(),
            Body::Bytes(payload.clone()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("write succeeds");

    let info = library
        .stat(object_address.clone(), StatOptions::default(), None)
        .await
        .expect("stat returns the freshly-written object");
    assert_eq!(info.size, Some(payload.len() as u64));

    let (bytes, _info) = library
        .read_bytes(object_address.clone(), ReadOptions::default(), None)
        .await
        .expect("read_bytes succeeds");
    assert_eq!(bytes, payload);

    let listing = library
        .list(route_prefix.clone(), ListOptions::default(), None)
        .await
        .expect("list returns the object root");
    let names: Vec<&str> = listing.iter().map(|item| item.address.as_str()).collect();
    assert!(
        names.iter().any(|name| name.ends_with("/hello.txt")),
        "list should include hello.txt: got {names:?}"
    );
    assert!(
        listing
            .iter()
            .any(|item| item.address.as_str().ends_with("/hello.txt")
                && item.kind == ObjectKind::File),
        "list should mark hello.txt as a file: got {listing:?}"
    );

    library
        .delete(object_address.clone(), DeleteOptions::default(), None)
        .await
        .expect("delete succeeds");

    let stat_after_delete = library
        .stat(object_address, StatOptions::default(), None)
        .await;
    let err = stat_after_delete.expect_err("stat should fail after delete");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::NotFound);
}
