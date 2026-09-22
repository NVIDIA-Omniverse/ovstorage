// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structural parity between this crate's first-party protocol schema and
//! the hub repository's own.
//!
//! The wire format consists of message structure, field numbers, and enum
//! values — nothing else; comments and headers never reach the wire. This
//! test therefore compares protoc *descriptor sets* (emitted without source
//! info, so lexical differences vanish) rather than file bytes: any drift
//! that could break wire compatibility fails it, and nothing that cannot
//! does. The comparison needs the omni-hub checkout next to this
//! repository; without one the test reports itself skipped and passes,
//! exactly like the live hub tier.

use std::path::{Path, PathBuf};
use std::process::Command;

const PROTO_RELATIVE: &str = "nvidia/omniverse/hub/v1alpha/hub.proto";

/// Compiles `root/`[`PROTO_RELATIVE`] to a descriptor set and returns its
/// bytes. Source info is deliberately not requested, so comments and
/// whitespace do not participate.
fn descriptor_set(protoc: &Path, root: &Path, out: &Path) -> Vec<u8> {
    let status = Command::new(protoc)
        .arg(format!("--descriptor_set_out={}", out.display()))
        .arg("-I")
        .arg(root)
        .arg(PROTO_RELATIVE)
        .status()
        .expect("protoc runs");
    assert!(status.success(), "protoc failed for {}", root.display());
    std::fs::read(out).expect("the descriptor set was written")
}

#[test]
fn the_schema_is_structurally_identical_to_the_hubs() {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ours = crate_root.join("proto");
    let theirs = crate_root
        .join("../../../omni-hub/hub-rpc/proto")
        .canonicalize()
        .ok();
    let Some(theirs) = theirs.filter(|root| root.join(PROTO_RELATIVE).is_file()) else {
        eprintln!(
            "skipping descriptor parity: no omni-hub checkout with {PROTO_RELATIVE} \
             next to this repository"
        );
        return;
    };

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc is available");
    let scratch = tempfile::tempdir().expect("tempdir");
    let our_set = descriptor_set(&protoc, &ours, &scratch.path().join("ours.bin"));
    let their_set = descriptor_set(&protoc, &theirs, &scratch.path().join("theirs.bin"));
    assert_eq!(
        our_set, their_set,
        "this crate's schema drifted structurally from the hub's — messages, \
         field numbers, enum values, or file options no longer agree, which \
         is exactly what breaks wire compatibility"
    );
}
