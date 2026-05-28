// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;

/// Canonical protos for the Storage API live in
/// `ovstorage-services/apis/storage-api/proto/` — these are the
/// in-repo vendored contracts (`ovstorage-services/` is treated as
/// vendored source-of-truth; modify upstream and re-sync, never edit
/// in place).
const STORAGE_ROOT: &str = "../../../ovstorage-services/apis/storage-api/proto";

/// The notifications consumer proto lives in a sibling api dir.
const NOTIF_ROOT: &str = "../../../ovstorage-services/apis/notifications-api/consumer/protos";

const STORAGE_SERVICES: &[(&str, &[&str])] = &[
    (
        "capabilities-v1alpha",
        &["nvidia/omniverse/storage/capabilities/v1alpha/capabilities.proto"],
    ),
    (
        "fileobject-v1alpha",
        &[
            "nvidia/omniverse/storage/fileobject/v1alpha/fileobject.proto",
            "nvidia/omniverse/storage/fileobject/v1alpha/fileobject_service.proto",
        ],
    ),
    (
        "filefolder-v1alpha",
        &["nvidia/omniverse/storage/filefolder/v1alpha/filefolder_service.proto"],
    ),
    (
        "metadata-v1alpha",
        &["nvidia/omniverse/storage/metadata/v1alpha/metadata.proto"],
    ),
    (
        "versioning-v1alpha",
        &["nvidia/omniverse/storage/versioning/v1alpha/versioning.proto"],
    ),
];

const NOTIF_SERVICES: &[(&str, &[&str])] = &[(
    "notifications-v1beta",
    &["nvidia/omniverse/notifications/consumer/v1beta/event_consumer.proto"],
)];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    unsafe {
        env::set_var(
            "PROTOC",
            protoc_bin_vendored::protoc_bin_path().expect("protoc not found"),
        );
        env::set_var(
            "PROTOC_INCLUDE",
            protoc_bin_vendored::include_path().expect("protoc include path not found"),
        );
    }

    compile_set(&out_dir, STORAGE_ROOT, STORAGE_SERVICES)?;
    compile_set(&out_dir, NOTIF_ROOT, NOTIF_SERVICES)?;

    println!("cargo:rerun-if-changed={STORAGE_ROOT}");
    println!("cargo:rerun-if-changed={NOTIF_ROOT}");
    Ok(())
}

fn compile_set(
    out_dir: &std::path::Path,
    root: &str,
    services: &[(&str, &[&str])],
) -> Result<(), Box<dyn std::error::Error>> {
    for (subdir, _) in services {
        std::fs::create_dir_all(out_dir.join(subdir))?;
    }
    for (subdir, files) in services {
        let dir = out_dir.join(subdir);
        let proto_paths: Vec<String> = files.iter().map(|f| format!("{root}/{f}")).collect();
        tonic_prost_build::configure()
            .build_client(true)
            // Server stubs cost <1% of the proto crate's binary size and
            // unlock tonic-server-based integration tests in plugin crates.
            .build_server(true)
            .build_transport(true)
            .compile_well_known_types(true)
            .bytes(".")
            .out_dir(&dir)
            .compile_protos(&proto_paths, &[root.to_string()])?;
    }
    Ok(())
}
