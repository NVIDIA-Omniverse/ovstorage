// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Characterization: the host-side vtable-consumer path
//! (`LoadedV2Layer`, `ovstorage/src/loaded_v2.rs`) has **no other** dedicated
//! tests — `mixed_layer_stack.rs` drives only
//! `stat`/`read`/`write`
//! plus the `list_address_roots`/`list_connections`/`add_connection` bridge.
//! This suite pins the FFI behavior of the generic foreign-vtable consumer
//! (`ForeignVtableLayer`, `ovstorage-plugin/src/consume_v2.rs`) at every
//! remaining slot, exercising each in isolation across the FFI boundary.
//!
//! Every test drives the loaded backend Layer **directly** (via
//! `create_backend`, not through a Router/Stack) so each vtable slot crosses
//! the FFI boundary in isolation — the `mini-v2` cdylib ships cheap scripted
//! implementations of the slots exercised here (see
//! `ovstorage-plugin-test-layer`).
//!
//! The two cdylibs are workspace members, so `cargo test --workspace`
//! (i.e. `make test` / `make test-ci`) builds them into the target profile
//! dir. When run via plain `cargo test -p ovstorage` they may be absent, in
//! which case the tests skip (hard error under
//! `OVSTORAGE_REQUIRE_TEST_PLUGINS`).

use std::sync::Arc;

use ovstorage::{
    AccessOps, AttributePatch, AuthEvent, AuthenticateRequest, BackendFactory, CheckAccessRequest,
    ConfigValue, ConnectionId, ConnectionKey, ConnectionRequest, CopyOptions, CopyRequest,
    CreateDirectoryOptions, CreateDirectoryRequest, DeleteDirectoryOptions, DeleteDirectoryRequest,
    DeleteOptions, DeleteRequest, ErrorCode, InteractiveAuthCapability, Layer, LayerConfig,
    LayerConnectionRequest, LayerKindDescriptor, LayerSpec, LayerType, ListOptions, ListRequest,
    ListVersionsOptions, ListVersionsRequest, LoadedLayerFactory, ObjectKind, ReadOptions,
    ReadRequest, RedirectResultBatch, RenameOptions, RenameRequest, Request, RouterFactory,
    SecretBundle, Stack, UpdateConnectionAttributesRequest, UpdateConnectionCredentialsRequest,
    UpdateMetadataOptions, UpdateMetadataRequest, Url, WatchDirectoryOptions,
    WatchDirectoryRequest, WrapperFactory, WriteOptions, WriteRedirectBatch, WriteRequest,
    WriteStep,
};
use ovstorage_plugin::consume_v2::{ForeignVtableLayer, KindsFallback};
use ovstorage_plugin::ffi;

mod plugin_locator;

use plugin_locator::plugin_so;

/// Load the `mini-v2` cdylib's factory set, or `None` to skip (absent cdylib).
fn load_mini_v2() -> Option<Vec<LoadedLayerFactory>> {
    let so = plugin_so("ovstorage_plugin_test_layer")?;
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    Some(unsafe { ovstorage::load_layer_plugin(&so, true) }.expect("load v2 plugin"))
}

fn find_backend(factories: &[LoadedLayerFactory]) -> Arc<dyn BackendFactory> {
    factories
        .iter()
        .find_map(|factory| match factory {
            LoadedLayerFactory::Backend(backend) => Some(backend.clone()),
            _ => None,
        })
        .expect("mini-v2 advertises a backend factory")
}

fn find_wrapper(factories: &[LoadedLayerFactory]) -> Arc<dyn WrapperFactory> {
    factories
        .iter()
        .find_map(|factory| match factory {
            LoadedLayerFactory::Wrapper(wrapper) => Some(wrapper.clone()),
            _ => None,
        })
        .expect("mini-v2 advertises a wrapper factory")
}

fn find_router(factories: &[LoadedLayerFactory]) -> Arc<dyn RouterFactory> {
    factories
        .iter()
        .find_map(|factory| match factory {
            LoadedLayerFactory::Router(router) => Some(router.clone()),
            _ => None,
        })
        .expect("mini-v2 advertises a router factory")
}

/// Create a loaded backend Layer rooted at `root`.
async fn backend_layer(root: &str) -> Arc<dyn Layer> {
    let factories = load_mini_v2().expect("cdylib present");
    let mut config = LayerConfig::new();
    config.insert("root".into(), ConfigValue::String(root.into()));
    find_backend(&factories)
        .create_backend("v2", &config, None)
        .await
        .expect("create mini-v2 backend")
}

async fn put(layer: &Arc<dyn Layer>, address: &str, payload: &[u8]) {
    layer
        .write(
            Request::new(WriteRequest {
                address: Url::parse(address).unwrap(),
                body: ovstorage::Body::Bytes(payload.to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("write {address}: {e}"));
}

/// Every scripted operational slot forwards its request/response faithfully
/// across the FFI vtable. Drives each `LoadedV2Layer` slot not already covered
/// by `mixed_layer_stack.rs` (which handles `stat`/`read`/`write` and the
/// `list_address_roots`/`list_connections`/`add_connection` bridge).
#[tokio::test]
async fn loaded_v2_forwards_operational_slots() {
    if load_mini_v2().is_none() {
        eprintln!("skipping loaded_v2 slots: mini-v2 cdylib not built");
        return;
    }
    let layer = backend_layer("mini://slots/").await;

    // Identity + introspection slots.
    assert_eq!(layer.name(), "v2", "cached name from the `name` slot");
    assert_eq!(
        layer.descriptor().kind,
        "mini-v2",
        "descriptor slot decodes the live kind"
    );
    assert_eq!(
        layer.owned_targets(),
        vec!["v2".to_string()],
        "owned_targets crosses the FFI (accepts_connections → [name])"
    );
    let root_info = layer
        .root_info_for(
            &Url::parse("mini://slots/obj.bin").unwrap(),
            &ovstorage::Extensions::new(),
            None,
        )
        .await
        .expect("root_info_for");
    assert_eq!(root_info.layer_kind, "mini-v2");
    let kinds: Vec<String> = layer
        .list_kinds(&ovstorage::Extensions::new())
        .expect("list_kinds")
        .into_iter()
        .map(|k| k.kind)
        .collect();
    assert_eq!(kinds, vec!["mini-v2".to_string()]);

    // Seed an object for the metadata / copy / version slots.
    let payload = b"loaded-v2 characterization payload".to_vec();
    put(&layer, "mini://slots/obj.bin", &payload).await;

    // write_stream (the mini backend delegates to `write`).
    layer
        .write_stream(
            Request::new(WriteRequest {
                address: Url::parse("mini://slots/streamed.bin").unwrap(),
                body: ovstorage::Body::Bytes(b"streamed".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect("write_stream");

    // materialize → a real local path the host reads.
    let delegate = layer
        .materialize(
            Request::new(ReadRequest {
                address: Url::parse("mini://slots/obj.bin").unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("materialize");
    let materialized = std::fs::read(&delegate.path).expect("read materialized path");
    assert_eq!(materialized, payload, "materialized bytes round-trip");
    assert_eq!(delegate.info.size, Some(payload.len() as u64));
    let _ = std::fs::remove_file(&delegate.path);

    // copy → WriteStep::Done, then the destination is readable.
    let step = layer
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("mini://slots/obj.bin").unwrap(),
                destination: Url::parse("mini://slots/copy.bin").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .expect("copy");
    match step {
        WriteStep::Done(result) => {
            assert_eq!(result.info.size, Some(payload.len() as u64))
        }
        other => panic!("expected WriteStep::Done, got {other:?}"),
    }

    // rename → source gone, destination present.
    layer
        .rename(
            Request::new(RenameRequest {
                source: Url::parse("mini://slots/copy.bin").unwrap(),
                destination: Url::parse("mini://slots/renamed.bin").unwrap(),
                options: RenameOptions::default(),
            }),
            None,
        )
        .await
        .expect("rename");
    assert_eq!(
        layer
            .get_latest_version(
                Request::new(ReadRequest {
                    address: Url::parse("mini://slots/copy.bin").unwrap(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err()
            .code(),
        ErrorCode::NotFound,
        "rename removed the source"
    );

    // update_metadata → BackendItemInfo.
    let item = layer
        .update_metadata(
            Request::new(UpdateMetadataRequest {
                address: Url::parse("mini://slots/obj.bin").unwrap(),
                options: UpdateMetadataOptions::default(),
            }),
            None,
        )
        .await
        .expect("update_metadata");
    assert_eq!(item.size, Some(payload.len() as u64));

    // check_access → AccessDecision.
    let decision = layer
        .check_access(
            Request::new(CheckAccessRequest {
                address: Url::parse("mini://slots/obj.bin").unwrap(),
                operations: AccessOps::default(),
            }),
            None,
        )
        .await
        .expect("check_access");
    assert!(decision.allowed);

    // list_versions → VersionPage.
    let versions = layer
        .list_versions(
            Request::new(ListVersionsRequest {
                address: Url::parse("mini://slots/obj.bin").unwrap(),
                options: ListVersionsOptions::default(),
            }),
            None,
        )
        .await
        .expect("list_versions");
    assert_eq!(versions.items.len(), 1);

    // get_latest_version → ObjectInfo.
    let latest = layer
        .get_latest_version(
            Request::new(ReadRequest {
                address: Url::parse("mini://slots/obj.bin").unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("get_latest_version");
    assert_eq!(latest.size, Some(payload.len() as u64));

    // create_directory → BackendItemInfo (Directory), delete_directory → ().
    let dir = layer
        .create_directory(
            Request::new(CreateDirectoryRequest {
                address: Url::parse("mini://slots/dir/").unwrap(),
                options: CreateDirectoryOptions::default(),
            }),
            None,
        )
        .await
        .expect("create_directory");
    assert_eq!(dir.kind, ObjectKind::Directory);
    layer
        .delete_directory(
            Request::new(DeleteDirectoryRequest {
                address: Url::parse("mini://slots/dir/").unwrap(),
                options: DeleteDirectoryOptions,
            }),
            None,
        )
        .await
        .expect("delete_directory");

    // probe → Connection.
    let mut probe_config = std::collections::HashMap::new();
    probe_config.insert(
        "root".to_string(),
        ConfigValue::String("mini://probed/".into()),
    );
    let probed = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "v2".into(),
                connection: ConnectionRequest {
                    backend_kind: "mini-v2".into(),
                    config: probe_config,
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("probe");
    assert!(
        probed
            .current_addresses
            .iter()
            .any(|a| a.as_str() == "mini://probed/")
    );

    // remove_connection → () (unit-result decode; the id need not exist).
    layer
        .remove_connection(
            Request::new(ConnectionKey {
                target: "v2".into(),
                id: ConnectionId("absent".into()),
            }),
            None,
        )
        .await
        .expect("remove_connection");

    // update_connection_credentials / update_connection_attributes → Connection.
    let creds_conn = layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "v2".into(),
                    id: ConnectionId("conn-a".into()),
                },
                credentials: SecretBundle::default(),
            }),
            None,
        )
        .await
        .expect("update_connection_credentials");
    assert_eq!(creds_conn.id.0, "conn-a");
    let attrs_conn = layer
        .update_connection_attributes(
            Request::new(UpdateConnectionAttributesRequest {
                key: ConnectionKey {
                    target: "v2".into(),
                    id: ConnectionId("conn-b".into()),
                },
                patch: AttributePatch::default(),
            }),
            None,
        )
        .await
        .expect("update_connection_attributes");
    assert_eq!(attrs_conn.id.0, "conn-b");

    // authenticate_connection → AuthEventStream; drain the scripted event.
    let mut events = layer
        .authenticate_connection(
            Request::new(AuthenticateRequest {
                key: ConnectionKey {
                    target: "v2".into(),
                    id: ConnectionId("conn-c".into()),
                },
                capability: InteractiveAuthCapability::None,
                auto_open_browser: false,
            }),
            None,
        )
        .await
        .expect("authenticate_connection");
    let first = events
        .next()
        .expect("one auth event")
        .expect("auth event ok");
    assert!(
        matches!(first, AuthEvent::Progress { .. }),
        "expected a Progress event, got {first:?}"
    );
}

/// The slots the `mini-v2` backend leaves at the trait's `Unsupported` default
/// still cross the FFI faithfully: the request marshals, the plugin returns the
/// typed `Unsupported`, and the host decodes it (rather than crashing). Pins
/// the request-builder path for these slots.
#[tokio::test]
async fn loaded_v2_unimplemented_slots_surface_unsupported() {
    if load_mini_v2().is_none() {
        eprintln!("skipping loaded_v2 unsupported slots: mini-v2 cdylib not built");
        return;
    }
    let layer = backend_layer("mini://unsupp/").await;
    let url = || Url::parse("mini://unsupp/obj").unwrap();
    let write = || WriteRequest {
        address: url(),
        body: ovstorage::Body::Bytes(Vec::new()),
        options: WriteOptions::default(),
    };

    assert_eq!(
        layer
            .write_redirect(Request::new(write()), None)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported,
    );
    assert_eq!(
        layer
            .continue_write(
                Request::new(ovstorage::ContinueWriteRequest {
                    address: url(),
                    redirects: WriteRedirectBatch {
                        continuation: Vec::new(),
                        redirects: Vec::new(),
                    },
                    results: RedirectResultBatch {
                        results: Vec::new(),
                    },
                }),
                None,
            )
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported,
    );
    assert_eq!(
        layer
            .delete(
                Request::new(DeleteRequest {
                    address: url(),
                    options: DeleteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported,
    );
    assert_eq!(
        layer
            .list(
                Request::new(ListRequest {
                    prefix: url(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unsupported,
    );
    // `watch_directory` yields a `ChangeStream` (not `Debug`), so match rather
    // than `unwrap_err`.
    let watch = layer
        .watch_directory(
            Request::new(WatchDirectoryRequest {
                prefix: url(),
                options: WatchDirectoryOptions::default(),
            }),
            None,
        )
        .await;
    match watch {
        Ok(_) => panic!("watch_directory unexpectedly succeeded"),
        Err(err) => assert_eq!(err.code(), ErrorCode::Unsupported),
    }
}

/// When the loaded layer's `descriptor()` slot returns a descriptor the host
/// cannot decode (an ill-formed-UTF-8 `display_name`),
/// `ForeignVtableLayer::descriptor()` uses the producer-supplied
/// `KindsFallback` rather than panicking or surfacing the undecodable value
/// (`consume_v2.rs`). The plugin loader derives that fallback from the plugin's
/// first advertised manifest kind (`loaded_v2.rs`); this test supplies the
/// equivalent (`mini-v2`) directly, because the malformed handle is minted by
/// a dedicated `#[no_mangle]` export
/// (`ovstorage_test_export_malformed_descriptor`) that injects the ill-formed
/// bytes at the FFI boundary — no invalid Rust `String` is ever constructed.
/// The descriptor's `kind` is a *valid, distinct* `mini-v2-live`, so a
/// hypothetical successful decode would be observably different from the
/// fallback.
#[tokio::test]
async fn loaded_v2_descriptor_decode_failure_falls_back() {
    let Some(so) = plugin_so("ovstorage_plugin_test_layer") else {
        eprintln!("skipping descriptor fallback: mini-v2 cdylib not built");
        return;
    };
    // The malformed-descriptor export lives outside the plugin manifest/init
    // handshake (a plain `#[no_mangle]` symbol), so `dlopen` the cdylib and
    // resolve it directly (mirrors `handoff_cross_binary.rs`).
    // SAFETY: our own workspace-built test cdylib.
    //
    // Pinned in `ManuallyDrop` for the process lifetime, matching production
    // policy (`HostPluginV2::library`, `ovstorage/src/loaded_v2.rs`) and the two
    // fixtures in `handoff_cross_binary.rs`.
    //
    // Defence, not a live hazard here: this test drives only the synchronous
    // `descriptor` slot (plus `name` at import), so it opens no async slot call,
    // mints no `CallPin`, and can reach no `retire_off_thread` — the teardown
    // below genuinely runs in place on this thread. The pin is for the next
    // person who adds an async op to this test, at which point a producer
    // teardown can be carried onto a detached `ovs-layer-retire` thread and
    // still be executing inside this image when the scope ends. Pinning costs
    // one mapping and removes the trap; the alternative is a `dlclose` that
    // unmaps running text.
    let library = std::mem::ManuallyDrop::new(
        unsafe { libloading::Library::new(&so) }.expect("dlopen mini-v2 cdylib"),
    );
    type ExportFn = unsafe extern "C" fn(*mut ffi::LayerHandle) -> i32;
    // SAFETY: `mini-v2` exports this symbol with this exact signature.
    let export = *unsafe {
        library
            .get::<ExportFn>(b"ovstorage_test_export_malformed_descriptor\0")
            .expect("resolve ovstorage_test_export_malformed_descriptor")
    };
    let mut handle = std::mem::MaybeUninit::<ffi::LayerHandle>::uninit();
    // SAFETY: `handle` is a valid, writable slot for the call.
    let rc = unsafe { export(handle.as_mut_ptr()) };
    assert_eq!(rc, 0, "malformed-descriptor export failed");
    // SAFETY: `export` returned 0, so it initialized `handle`.
    let handle = unsafe { handle.assume_init() };

    // The handle carries the cdylib's own (foreign) vtable, so wrapping it
    // drives the producer's malformed `descriptor` slot. Supply the fallback
    // the loader would otherwise derive from the manifest's first kind.
    let fallback: KindsFallback = Box::new(|| {
        Some(LayerKindDescriptor {
            kind: "mini-v2".to_string(),
            layer_type: LayerType::Backend,
            display_name: "Mini v2 test backend".to_string(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: true,
            auth_capable: false,
            supports_user_metadata: true,
        })
    });
    let layer = ForeignVtableLayer::from_handle_with_fallback(handle, None, Some(fallback))
        .expect("import malformed-descriptor handle");

    let descriptor = layer.descriptor();
    assert_eq!(
        descriptor.kind, "mini-v2",
        "decode failure must use the supplied fallback (the loader's manifest first kind)"
    );
    assert_ne!(
        descriptor.kind, "mini-v2-live",
        "a successful decode would have surfaced the live (undecodable) kind"
    );

    // Drop the imported layer, running the cdylib's `drop` slot. The cdylib
    // itself stays mapped (see the `ManuallyDrop` above) — a bare import
    // carries no keep-alive pin on the producer, so nothing here can prove the
    // producer is done executing.
    drop(layer);
}

/// A v2 plugin wrapper composes over a *loaded* child: the host
/// exports the built child behind its own `LAYER_VTABLE` (`export_handle`)
/// and the plugin imports it as a foreign child (`import_child`) — a foreign
/// vtable child that `downcast_loaded_v2` does not resolve, so it drives the
/// import path rather than a same-image downcast. The write/read
/// round-trip proves the full triple-hop chain: host stack → plugin wrapper
/// → plugin-side foreign wrap → host-exported child → plugin backend.
#[tokio::test]
async fn v2_wrapper_composition_over_loaded_child_works() {
    let Some(factories) = load_mini_v2() else {
        eprintln!("skipping v2 wrapper composition: mini-v2 cdylib not built");
        return;
    };
    let mut backend_spec = LayerSpec::backend("back", "mini-v2");
    backend_spec
        .config
        .insert("root".into(), ConfigValue::String("mini://compose/".into()));

    let stack = Stack::builder("wrap")
        .backend_factory(find_backend(&factories))
        .wrapper_factory(find_wrapper(&factories))
        .layer(LayerSpec::wrapper("wrap", "mini-wrapper", "back"))
        .layer(backend_spec)
        .build()
        .await
        .expect("v2 wrapper over a loaded child builds");

    let url = Url::parse("mini://compose/obj.bin").unwrap();
    let payload = b"crossed the wrapper bridge".to_vec();
    stack
        .write(
            Request::new(WriteRequest {
                address: url.clone(),
                body: ovstorage::Body::Bytes(payload.clone()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect("write through the wrapped stack");
    let read = stack
        .read(
            Request::new(ReadRequest {
                address: url,
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("read through the wrapped stack");
    match read {
        ovstorage::ReadResult::Bytes { bytes, .. } => assert_eq!(bytes, payload),
        other => panic!("expected buffered bytes, got {other:?}"),
    }
}

/// The router analogue of [`v2_wrapper_composition_over_loaded_child_works`]:
/// construction over a loaded child now succeeds, and the `owned_targets`
/// aggregation crosses the plugin router → foreign child → plugin backend
/// chain (the mini-router has no dispatch logic of its own to drive).
#[tokio::test]
async fn v2_router_composition_over_loaded_child_works() {
    let Some(factories) = load_mini_v2() else {
        eprintln!("skipping v2 router composition: mini-v2 cdylib not built");
        return;
    };
    let mut backend_spec = LayerSpec::backend("back", "mini-v2");
    backend_spec
        .config
        .insert("root".into(), ConfigValue::String("mini://compose/".into()));

    let stack = Stack::builder("route")
        .backend_factory(find_backend(&factories))
        .router_factory(find_router(&factories))
        .layer(LayerSpec::router(
            "route",
            "mini-router",
            vec!["back".into()],
        ))
        .layer(backend_spec)
        .build()
        .await
        .expect("v2 router over a loaded child builds");

    assert_eq!(
        stack.root().owned_targets(),
        vec!["back".to_string()],
        "owned_targets aggregates across router → foreign child → backend"
    );
}
