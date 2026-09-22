// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side halves of the conformance scenarios: capability gating, the
//! write-plan commit point
//! (`continue_write -> Done`, never `write_redirect`), the retry
//! wrapper's never-replay rule for `continue_write`, and the default
//! wrappers' pass-through of protocol slots (resting on the
//! mechanically safe `inner_layer()` delegation).
//! The plugin-side halves live in the harness crate's
//! `tests/conformance_contracts.rs`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::StreamExt as _;
use ovstorage::ext::LayerExt;
use ovstorage::{
    BackendFactory as _, Body, CancellationToken, ConfigValue, ContinueWriteRequest, DeleteOptions,
    ErrorCode, Extensions, Layer, LayerConfig, LayerHandle, LayerKindDescriptor, ListOptions,
    ListPage, ListRequest, ListStream, ReadOptions, ReadRequest, RedirectResult,
    RedirectResultBatch, Request, Result, StatOptions, StatRequest, Url, WrapperFactory as _,
    WriteOptions, WriteRedirectBatch, WriteRequest, WriteStep, address,
};
use ovstorage_plugin_cache::{ByteCacheWrapperFactory, MetadataCacheWrapperFactory};
use ovstorage_plugin_core::{CopyRenameFallbackWrapperFactory, RetryWrapperFactory};
use ovstorage_plugin_http::RedirectFollowerWrapperFactory;
use ovstorage_plugin_test::{
    ConformanceReport, ObservedCall, Recorder, ScenarioRegistry, ScenarioRunner, TestLayerFactory,
};

const ROOT: &str = "test://protocol/";

fn address_of(key: &str) -> Url {
    address::parse(&format!("{ROOT}{key}")).unwrap()
}

fn base_config(knobs: &[(&str, ConfigValue)]) -> LayerConfig {
    let mut config = HashMap::new();
    config.insert("test_root".into(), ConfigValue::String(ROOT.into()));
    for (key, value) in knobs {
        config.insert((*key).into(), value.clone());
    }
    config
}

async fn test_layer(knobs: &[(&str, ConfigValue)]) -> (LayerHandle, Recorder) {
    let factory = TestLayerFactory::default();
    let layer = factory
        .create_backend("test", &base_config(knobs), None)
        .await
        .expect("create test layer");
    let root = address::parse(ROOT).unwrap();
    let recorder = factory.recorder_for(&root).expect("recorder is wired");
    (layer, recorder)
}

/// Probe calls (`stat`) interleave with the protocol under test; drop
/// them before matching the scenario's `expected_calls`.
fn without_probes(recorder: &Recorder) -> Vec<ObservedCall> {
    recorder
        .snapshot()
        .into_iter()
        .filter(|call| call.method_name() != "stat")
        .collect()
}

fn all_ok_results(batch: &WriteRedirectBatch) -> RedirectResultBatch {
    RedirectResultBatch {
        results: batch
            .redirects
            .iter()
            .map(|_| RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: Vec::new(),
            })
            .collect(),
    }
}

/// Protocol-slot contract: the mutation commits at
/// `continue_write -> Done`, not at `write_redirect` — before the
/// continuation completes the object must not exist.
#[tokio::test]
async fn write_redirect_commits_only_at_continue_write_done() {
    let (layer, recorder) = test_layer(&[(
        "test_redirect_url",
        ConfigValue::String("https://redirect.invalid/".into()),
    )])
    .await;
    let address = address_of("staged.bin");
    recorder.clear();

    let batch = layer
        .write_redirect(
            Request::new(WriteRequest {
                address: address.clone(),
                body: Body::Bytes(Vec::new()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect("write_redirect returns the plan");

    // Not committed yet: the address must not resolve.
    let err = layer
        .stat(
            Request::new(StatRequest {
                address: address.clone(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("write_redirect must not commit the mutation");
    assert_eq!(err.code(), ErrorCode::NotFound, "{err}");

    let results = all_ok_results(&batch);
    let step = layer
        .continue_write(
            Request::new(ContinueWriteRequest {
                address: address.clone(),
                redirects: batch,
                results,
            }),
            None,
        )
        .await
        .expect("continue_write completes the plan");
    assert!(matches!(step, WriteStep::Done(_)), "expected Done");

    // Committed now.
    layer
        .stat(
            Request::new(StatRequest {
                address,
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect("continue_write -> Done commits the mutation");

    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();
    report
        .push(runner.verify_recorded("write-redirect-commits-on-done", without_probes(&recorder)));
    assert!(report.ok(), "{}", report.render_human());
}

/// Protocol-slot contract: nothing is observable at the address while the
/// write is mid-flight.
///
/// `write-redirect-commits-on-done` covers the single-round-trip shape. This
/// covers the multi-step one: `continue_write` returning `Redirects` means
/// more transfers remain, and the address must still not resolve. The
/// distinction matters because a host may take a shortcut on a redirect step
/// exactly because it believes the address is unchanged — the byte cache
/// leaves its availability index alone there — so a plugin that made partial
/// content observable would leave that host naming a validator for an object
/// that has since become something else.
///
/// No shipping backend returns `Redirects` from `continue_write` today: S3
/// emits all its parts in one batch and Azure commits directly. The contract
/// is therefore exercised only here, which is precisely why it needs a
/// scenario rather than a comment.
#[tokio::test]
async fn continue_write_redirects_step_commits_nothing() {
    let (layer, recorder) = test_layer(&[
        (
            "test_redirect_url",
            ConfigValue::String("https://redirect.invalid/".into()),
        ),
        // Two loops: the first `continue_write` returns `Redirects`, the
        // second returns `Done`.
        ("test_continue_write_loops", ConfigValue::Int(2)),
        ("test_multipart_parts", ConfigValue::Int(2)),
    ])
    .await;
    let address = address_of("multipart.bin");
    recorder.clear();

    let batch = layer
        .write_redirect(
            Request::new(WriteRequest {
                address: address.clone(),
                body: Body::Bytes(Vec::new()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect("write_redirect returns the plan");

    let results = all_ok_results(&batch);
    let step = layer
        .continue_write(
            Request::new(ContinueWriteRequest {
                address: address.clone(),
                redirects: batch,
                results,
            }),
            None,
        )
        .await
        .expect("continue_write returns the next batch");
    let WriteStep::Redirects(next) = step else {
        panic!("expected a mid-flight Redirects step; the scenario needs one to mean anything");
    };

    // The contract under test: still mid-flight, so nothing exists yet.
    let err = layer
        .stat(
            Request::new(StatRequest {
                address: address.clone(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("a mid-flight redirect step must not make the object observable");
    assert_eq!(err.code(), ErrorCode::NotFound, "{err}");

    let results = all_ok_results(&next);
    let step = layer
        .continue_write(
            Request::new(ContinueWriteRequest {
                address: address.clone(),
                redirects: next,
                results,
            }),
            None,
        )
        .await
        .expect("continue_write completes the plan");
    assert!(matches!(step, WriteStep::Done(_)), "expected Done");

    // Committed only now.
    layer
        .stat(
            Request::new(StatRequest {
                address,
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect("continue_write -> Done commits the mutation");

    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();
    report.push(runner.verify_recorded(
        "write-redirect-nothing-observable-mid-flight",
        without_probes(&recorder),
    ));
    assert!(report.ok(), "{}", report.render_human());
}

/// Protocol-slot contract: the retry wrapper never replays
/// `continue_write` — an injected transient failure surfaces and the
/// slot runs exactly once.
#[tokio::test]
async fn retry_wrapper_never_replays_continue_write() {
    let (inner, recorder) = test_layer(&[
        (
            "test_redirect_url",
            ConfigValue::String("https://redirect.invalid/".into()),
        ),
        (
            "test_inject_error_on",
            ConfigValue::String("continue_write".into()),
        ),
        (
            "test_inject_error_code",
            ConfigValue::String("Transient".into()),
        ),
    ])
    .await;
    let wrapped = RetryWrapperFactory
        .create_wrapper("retry", &LayerConfig::new(), inner, None)
        .await
        .expect("wrap with retry");
    let address = address_of("replayed.bin");
    recorder.clear();

    let batch = wrapped
        .write_redirect(
            Request::new(WriteRequest {
                address: address.clone(),
                body: Body::Bytes(Vec::new()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect("write_redirect returns the plan");
    let results = all_ok_results(&batch);
    let err = wrapped
        .continue_write(
            Request::new(ContinueWriteRequest {
                address,
                redirects: batch,
                results,
            }),
            None,
        )
        .await
        .expect_err("injected Transient must surface unretried");
    assert_eq!(err.code(), ErrorCode::Transient, "{err}");
    assert_eq!(
        recorder.count_method("continue_write"),
        1,
        "retry must never replay continue_write"
    );

    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();
    report.push(runner.verify_with_failure(
        "retry-never-replays-continue-write",
        without_probes(&recorder),
        Some(("continue_write".into(), err.code())),
    ));
    assert!(report.ok(), "{}", report.render_human());
}

/// Protocol-slot contract: default-stack wrappers that don't own
/// the write-plan protocol forward `write_redirect` untouched to the
/// inner layer (the `inner_layer()` delegation).
#[tokio::test]
async fn protocol_slots_pass_through_default_wrappers() {
    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();

    let cache_dir = tempfile::tempdir().expect("cache tempdir");
    let state_dir = tempfile::tempdir().expect("state tempdir");
    let mut byte_cache_config = LayerConfig::new();
    byte_cache_config.insert(
        "cache_root".into(),
        ConfigValue::String(cache_dir.path().to_string_lossy().into_owned()),
    );
    byte_cache_config.insert(
        "state_root".into(),
        ConfigValue::String(state_dir.path().to_string_lossy().into_owned()),
    );

    for (label, wrapper_config, factory) in [
        (
            "retry",
            LayerConfig::new(),
            Box::new(RetryWrapperFactory) as Box<dyn ovstorage::WrapperFactory>,
        ),
        (
            "byte_cache",
            byte_cache_config,
            Box::new(ByteCacheWrapperFactory::default()),
        ),
        (
            "metadata_cache",
            LayerConfig::new(),
            Box::new(MetadataCacheWrapperFactory::default()),
        ),
        (
            "hub_cache",
            LayerConfig::new(),
            Box::new(ovstorage_plugin_hub_cache::HubCacheWrapperFactory),
        ),
    ] {
        let (inner, recorder) = test_layer(&[(
            "test_redirect_url",
            ConfigValue::String("https://redirect.invalid/".into()),
        )])
        .await;
        let wrapped = factory
            .create_wrapper(label, &wrapper_config, inner, None)
            .await
            .unwrap_or_else(|err| panic!("wrap with {label}: {err}"));
        recorder.clear();

        wrapped
            .write_redirect(
                Request::new(WriteRequest {
                    address: address_of("pass-through.bin"),
                    body: Body::Bytes(Vec::new()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_or_else(|err| panic!("{label} must forward write_redirect: {err}"));
        report
            .push(runner.verify_recorded("protocol-slots-pass-through", without_probes(&recorder)));
    }

    assert!(report.ok(), "{}", report.render_human());
    assert_eq!(report.passed(), 4);
}

struct NativeListProbe {
    buffered_calls: AtomicUsize,
    stream_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl Layer for NativeListProbe {
    fn name(&self) -> &str {
        "native-list-probe"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        TestLayerFactory::default().descriptor()
    }

    async fn list(
        &self,
        _request: Request<ListRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        self.buffered_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ListPage {
            items: Vec::new(),
            next_page_token: None,
        })
    }

    async fn list_stream(
        &self,
        _request: Request<ListRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ListStream> {
        self.stream_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Box::pin(futures::stream::empty()))
    }
}

/// Wrappers with no listing semantics must forward the native stream slot
/// itself. Relying on `Layer`'s default would call buffered `list` and silently
/// discard the inner layer's bounded streaming implementation.
#[tokio::test]
async fn transparent_wrappers_preserve_native_list_streams() {
    for (label, factory) in [
        (
            "copy_rename_fallback",
            Box::new(CopyRenameFallbackWrapperFactory) as Box<dyn ovstorage::WrapperFactory>,
        ),
        (
            "redirect_follower",
            Box::new(RedirectFollowerWrapperFactory),
        ),
    ] {
        let probe = Arc::new(NativeListProbe {
            buffered_calls: AtomicUsize::new(0),
            stream_calls: AtomicUsize::new(0),
        });
        let inner: LayerHandle = probe.clone();
        let wrapped = factory
            .create_wrapper(label, &LayerConfig::new(), inner, None)
            .await
            .unwrap_or_else(|error| panic!("wrap with {label}: {error}"));

        let entries = wrapped
            .list_stream(
                Request::new(ListRequest {
                    prefix: address_of(""),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{label} list_stream open: {error}"))
            .collect::<Vec<_>>()
            .await;

        assert!(
            entries.is_empty(),
            "the fixture starts with an empty prefix"
        );
        assert_eq!(
            probe.stream_calls.load(Ordering::SeqCst),
            1,
            "{label} must delegate the native streaming slot"
        );
        assert_eq!(
            probe.buffered_calls.load(Ordering::SeqCst),
            0,
            "{label} must not materialize the buffered listing"
        );
    }
}

/// Sync-metadata no-I/O conformance: the four structural introspection
/// slots — `name`, `descriptor`, `owned_targets`, and `list_kinds` — report
/// fixed manifest/topology metadata and must resolve from a plain non-async
/// context with **no ambient tokio runtime**. That is the practical proof of
/// the no-I/O contract: entering a runtime or performing I/O from these slots
/// would require an executor that this thread deliberately does not provide.
/// The three runtime-state queries (`root_info_for` / `list_address_roots` /
/// `list_connections`) are async and are exercised by the async tests above.
///
/// A plain `#[test]` runs with no `#[tokio::test]` reactor. First-party layers
/// are built inside a scoped runtime whose `block_on` only enters the runtime
/// for the construction closure; the handles are then driven from this thread,
/// where `Handle::try_current()` is `Err`.
#[test]
fn sync_metadata_slots_resolve_off_runtime() {
    let build_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build scoped runtime for layer construction");

    let bare = build_rt.block_on(async {
        TestLayerFactory::default()
            .create_backend("test", &base_config(&[]), None)
            .await
            .expect("create bare test layer")
    });
    // A pure wrapper exercises the delegating default bodies: `list_kinds`
    // unions self with inner, `owned_targets` forwards to inner.
    let wrapped = build_rt.block_on(async {
        let inner = TestLayerFactory::default()
            .create_backend("test", &base_config(&[]), None)
            .await
            .expect("create inner test layer");
        RetryWrapperFactory
            .create_wrapper("retry", &LayerConfig::new(), inner, None)
            .await
            .expect("wrap inner with retry")
    });

    // Back on the plain thread: no reactor is installed here, so any attempt
    // by a structural slot to enter a runtime or block on I/O would fault.
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "structural-slot checks must run with no ambient tokio runtime"
    );

    let cx = Extensions::new();
    for (label, layer) in [("bare backend", &bare), ("retry-wrapped", &wrapped)] {
        assert!(!layer.name().is_empty(), "{label}: name() off-runtime");
        // descriptor()/owned_targets() must return without entering a runtime.
        let _ = layer.descriptor();
        let _ = layer.owned_targets();
        let kinds = layer
            .list_kinds(&cx)
            .unwrap_or_else(|err| panic!("{label}: list_kinds off-runtime: {err}"));
        assert!(
            !kinds.is_empty(),
            "{label}: list_kinds reports at least the layer's own kind"
        );
    }

    // The wrapper's union reports strictly more kinds than a bare leaf,
    // proving the delegating default body ran off-runtime too.
    assert!(
        wrapped.list_kinds(&cx).expect("wrapped list_kinds").len()
            > bare.list_kinds(&cx).expect("bare list_kinds").len(),
        "pure wrapper unions its own kind with inner's off-runtime"
    );
}

/// Type-mismatch handling through the ergonomic host edge: [`LayerExt`] canonicalizes
/// directory addresses to trailing-slash form (`address::to_directory`)
/// before the backend sees them, while object ops arrive slash-free —
/// the type-mismatch contracts must hold across that spelling
/// difference. Driving the `LayerHandle` directly (as
/// `conformance_contracts.rs` does) masks a backend that keys the two
/// spellings differently, which surfaced as `NotFound` instead of the
/// typed `InvalidArgument`.
#[tokio::test]
async fn type_mismatch_contracts_hold_through_layer_ext() {
    use ovstorage::{CreateDirectoryOptions, DeleteDirectoryOptions, ListOptions};

    let (layer, _) = test_layer(&[("test_caps", ConfigValue::String("full".into()))]).await;

    // create_directory reaches the backend as `subdir/`; the bare
    // object-op delete must still see a directory, not NotFound.
    LayerExt::create_directory(
        &*layer,
        address_of("subdir"),
        CreateDirectoryOptions::default(),
        None,
    )
    .await
    .expect("create_directory");
    let err = LayerExt::delete(
        &*layer,
        address_of("subdir"),
        DeleteOptions::default(),
        None,
    )
    .await
    .expect_err("delete on a directory must be a type mismatch");
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.message().contains("use delete_directory"), "{err}");

    // delete_directory on a file reaches the backend as
    // `plain.txt/`; the mismatch must fold back onto the stored object.
    LayerExt::write(
        &*layer,
        address_of("plain.txt"),
        Body::Bytes(b"bytes".to_vec()),
        WriteOptions::default(),
        None,
    )
    .await
    .expect("seed write");
    let err = LayerExt::delete_directory(
        &*layer,
        address_of("plain.txt"),
        DeleteDirectoryOptions,
        None,
    )
    .await
    .expect_err("delete_directory on a file must be a type mismatch");
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.message().contains("use delete()"), "{err}");
    LayerExt::stat(
        &*layer,
        address_of("plain.txt"),
        StatOptions::default(),
        None,
    )
    .await
    .expect("the mismatched file must survive the refused delete_directory");

    // list on a file (canonicalized to `plain.txt/`).
    let err = LayerExt::list_page(
        &*layer,
        address_of("plain.txt"),
        ListOptions::default(),
        None,
    )
    .await
    .expect_err("list on a file must be a type mismatch");
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.message().contains("not a directory"), "{err}");

    // And the slashed directory spelling stays usable end-to-end:
    // delete_directory on the (empty) explicit directory succeeds.
    LayerExt::delete_directory(&*layer, address_of("subdir"), DeleteDirectoryOptions, None)
        .await
        .expect("delete_directory on an empty directory succeeds");
}

/// `materialize` is host-owned (`docs/public/plugin-storage/OWNERSHIP.md`):
/// a remote backend leaves the trait default in place and the composed
/// Stack supplies local availability. Composing the real
/// `RedirectFollowerWrapper` over the harness backend must therefore stage
/// a readable local file, and the only call the backend observes is `read`.
#[tokio::test]
async fn materialize_over_a_default_backend_is_served_by_the_host_wrapper() {
    let (layer, recorder) = test_layer(&[]).await;
    let address = address_of("staged.txt");
    LayerExt::write(
        &*layer,
        address.clone(),
        Body::Bytes(b"staged-bytes".to_vec()),
        WriteOptions::default(),
        None,
    )
    .await
    .expect("seed write");

    let stack = RedirectFollowerWrapperFactory
        .create_wrapper("follower", &LayerConfig::new(), layer.clone(), None)
        .await
        .expect("compose the host materialize wrapper");
    recorder.clear();

    let local = stack
        .materialize(
            Request::new(ReadRequest {
                address,
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("the host wrapper stages the object");
    let staged = std::fs::read(&local.path).expect("staged file readable");
    assert_eq!(staged, b"staged-bytes");
    std::fs::remove_file(&local.path).ok();

    // The backend never sees `materialize`: it leaves the slot at its
    // default, so the wrapper reaches it through `read`.
    let recorded: Vec<&str> = without_probes(&recorder)
        .iter()
        .map(|call| call.method_name())
        .collect();
    assert_eq!(
        recorded,
        vec!["read"],
        "a host-served materialize must reach the backend only as `read`"
    );
}

/// A bare backend leaves `materialize` at the Layer default. The host wrapper
/// supplies local staging when the composition requires it.
#[tokio::test]
async fn materialize_without_a_cache_or_redirect_wrapper_is_unsupported() {
    let (layer, recorder) = test_layer(&[]).await;
    recorder.clear();

    let err = layer
        .materialize(
            Request::new(ReadRequest {
                address: address_of("bare.txt"),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("a bare backend must not materialize locally");
    assert_eq!(err.code(), ErrorCode::Unsupported, "{err}");

    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();
    report.push(runner.verify_recorded(
        "materialize-unsupported-without-cache",
        without_probes(&recorder),
    ));
    assert!(report.ok(), "{}", report.render_human());
}
