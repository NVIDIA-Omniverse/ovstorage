// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn broker_unix_socket_round_trips_with_peer_cred() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::new(broker_library));
    let socket_path = root.join("broker.sock");
    let mut listener = test_listener_config(BrokerAuthnMode::PeerCred);
    listener.bind = socket_path.to_string_lossy().into_owned();
    // Some sandboxes deny bind(AF_UNIX); treat PermissionDenied as skip.
    let server = match spawn_broker_grpc_unix_socket_listener(broker, &socket_path, &listener) {
        Ok(server) => server,
        Err(error) if error.code() == ErrorCode::PermissionDenied => {
            eprintln!("skipping broker_unix_socket_round_trips_with_peer_cred: {error}");
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        Err(error) => panic!("spawn unix-socket listener: {error}"),
    };
    broker_round_trip(&prefix, &server.endpoint_url()).await;
    shutdown_test_server(server).await;
    remove_dir_all_retry(root).unwrap();
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn broker_named_pipe_round_trips_with_peer_cred() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let broker_library = Library::builder().open_with_test_plugins();
    add_file_connection(&broker_library, &root).await;
    let broker = Arc::new(Broker::new(broker_library));
    let pipe_name = format!("ovstorage-test-{}", unique_suffix());
    let mut listener = test_listener_config(BrokerAuthnMode::PeerCred);
    listener.bind = format!("pipe:{pipe_name}");
    let server = spawn_broker_grpc_named_pipe_listener(broker, &pipe_name, &listener).unwrap();
    broker_round_trip(&prefix, &server.endpoint_url()).await;
    shutdown_test_server(server).await;
    remove_dir_all_retry(root).unwrap();
}
