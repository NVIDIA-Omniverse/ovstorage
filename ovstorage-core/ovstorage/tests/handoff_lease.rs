// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `materialize` lease crossing over the ABI-v2 vtable.
//!
//! A `LocalDelegate` can carry an opaque RAII `guard` that pins its
//! backing file against reclamation (e.g. the `ByteCacheWrapper` eviction
//! lease) for as long as the delegate — or any clone of it — is held.
//! The guard crosses the vtable intact: `local_delegate_to_ffi` encodes it
//! and the far side reconstructs it, so a materialize result crossing an
//! `export_handle` / `import_handle` boundary keeps its pin. These tests pin
//! the contract over the genuinely foreign path
//! (`import_handle_force_foreign`): the lease
//! crosses, still pins while the delegate lives, releases the
//! producer-side pin exactly when the last delegate drops, and — being a
//! sub-handle — survives its parent import being dropped first.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use ovstorage::{
    CancellationToken, ChecksumSet, Layer, LayerKindDescriptor, LayerType, LocalDelegate,
    ObjectInfo, ObjectKind, ReadOptions, ReadRequest, Request, Result, Url, export_handle,
};
use ovstorage_plugin::import_handle_force_foreign;

const ADDRESS: &str = "mem://data/object.bin";
const DELEGATE_PATH: &str = "/var/cache/ov/object.bin";

fn object_info(address: Url) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: None,
        version: None,
        size: Some(0),
        mtime: None,
        checksums: ChecksumSet::new(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

/// Flips its flag on drop — stands in for a cache eviction lease so a test
/// can observe the producer-side pin being released across the bridge.
struct PinToken(Arc<AtomicBool>);

impl Drop for PinToken {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Producer layer whose `materialize` returns a delegate optionally
/// carrying a [`PinToken`] guard, so a test can watch the pin cross and
/// release.
struct MaterializeProbe {
    /// When set, `materialize` mints a guard holding a [`PinToken`] that
    /// flips this flag on drop; when `None`, a guard-less delegate.
    released: Option<Arc<AtomicBool>>,
}

#[async_trait]
impl Layer for MaterializeProbe {
    fn name(&self) -> &str {
        "materialize-probe"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "materialize-probe".to_string(),
            layer_type: LayerType::Backend,
            display_name: "lease crossing probe".to_string(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: false,
            auth_capable: false,
            supports_user_metadata: true,
        }
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        let guard = self
            .released
            .as_ref()
            .map(|flag| Arc::new(PinToken(flag.clone())) as Arc<dyn Send + Sync>);
        Ok(LocalDelegate {
            path: DELEGATE_PATH.into(),
            info: object_info(request.input.address),
            guard,
        })
    }
}

fn materialize_request() -> Request<ReadRequest> {
    Request::new(ReadRequest {
        address: Url::parse(ADDRESS).unwrap(),
        options: ReadOptions::default(),
    })
}

/// A materialize result crosses a forced-foreign import with its lease
/// intact: the far side reconstructs a guard, the pin stays held while the
/// delegate lives, and dropping the delegate releases the producer-side
/// pin (early-drop) — the crossed lease is really wired to the producer's
/// guard, not a decode artifact.
#[tokio::test]
async fn materialize_crosses_a_pinned_delegate_and_early_drop_releases_it() {
    let released = Arc::new(AtomicBool::new(false));
    let handle = export_handle(Arc::new(MaterializeProbe {
        released: Some(released.clone()),
    }));
    let imported = unsafe { import_handle_force_foreign(handle) }.expect("forced-foreign import");

    let delegate = imported
        .materialize(materialize_request(), None)
        .await
        .expect("materialize across the bridge");
    assert_eq!(delegate.path.to_str(), Some(DELEGATE_PATH));
    assert!(
        delegate.guard.is_some(),
        "the lease must cross the bridge as a reconstructed guard"
    );
    assert!(
        !released.load(Ordering::SeqCst),
        "the producer-side pin stays held while the delegate lives"
    );

    drop(delegate);
    assert!(
        released.load(Ordering::SeqCst),
        "dropping the last delegate must release the producer-side pin"
    );
}

/// The lease is a sub-handle independent of the parent import:
/// dropping the imported layer first does not release the pin — only
/// dropping the delegate does, in either order.
#[tokio::test]
async fn lease_outlives_the_parent_import_drop() {
    let released = Arc::new(AtomicBool::new(false));
    let handle = export_handle(Arc::new(MaterializeProbe {
        released: Some(released.clone()),
    }));
    let imported = unsafe { import_handle_force_foreign(handle) }.expect("forced-foreign import");

    let delegate = imported
        .materialize(materialize_request(), None)
        .await
        .expect("materialize across the bridge");

    // Drop the parent import while the delegate — and its lease — live on.
    drop(imported);
    assert!(
        !released.load(Ordering::SeqCst),
        "the lease sub-handle outlives the parent import: pin still held"
    );

    drop(delegate);
    assert!(
        released.load(Ordering::SeqCst),
        "dropping the delegate releases the pin independently of the parent"
    );
}

/// A guard-less delegate crosses without minting a spurious lease: the
/// empty case stays the NULL sentinel and decodes back to `guard: None`
/// (symmetric with the empty-`Extensions` encoding).
#[tokio::test]
async fn guardless_delegate_crosses_without_a_lease() {
    let handle = export_handle(Arc::new(MaterializeProbe { released: None }));
    let imported = unsafe { import_handle_force_foreign(handle) }.expect("forced-foreign import");

    let delegate = imported
        .materialize(materialize_request(), None)
        .await
        .expect("materialize across the bridge");
    assert!(
        delegate.guard.is_none(),
        "a delegate with no pin must cross as the NULL lease sentinel"
    );
}
