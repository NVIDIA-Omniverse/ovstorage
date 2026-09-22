// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc is available");
    // Single-threaded build script: safe to set process env.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    // Plain prost_build: the hub speaks a hand-rolled length-prefixed
    // protobuf protocol over TCP, not gRPC, so there is no tonic service
    // surface to generate.
    prost_build::compile_protos(
        &["proto/nvidia/omniverse/hub/v1alpha/hub.proto"],
        &["proto"],
    )
    .expect("hub protobuf generation succeeds");

    println!("cargo:rerun-if-changed=proto/nvidia/omniverse/hub/v1alpha/hub.proto");
}
