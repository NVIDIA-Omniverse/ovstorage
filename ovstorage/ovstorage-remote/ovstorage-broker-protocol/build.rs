// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc is available");
    // Single-threaded build script: safe to set process env.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    // Pin `compile_well_known_types(false)` so an upstream default flip can't silently pull in
    // `prost-types` — the broker schema deliberately uses none.
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_well_known_types(false)
        .compile_protos(
            &[
                "proto/ovstorage/v2/broker.proto",
                "proto/grpc/health/v1/health.proto",
            ],
            &["proto"],
        )
        .expect("broker protobuf generation succeeds");

    println!("cargo:rerun-if-changed=proto/ovstorage/v2/broker.proto");
    println!("cargo:rerun-if-changed=proto/grpc/health/v1/health.proto");
}
