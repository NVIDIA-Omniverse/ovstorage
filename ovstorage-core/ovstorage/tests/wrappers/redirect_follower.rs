// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `RedirectFollowerWrapper` behavior: read-redirect following, write-redirect
//! orchestration (single/multi round, body replay), fallbacks, and address
//! normalization.

use std::collections::VecDeque;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use ovstorage::layers::{BYTE_CACHE_KIND, REDIRECT_FOLLOWER_KIND, RETRY_KIND};
use ovstorage::{
    AccessOps, Body, BodyStream, CancellationToken, ConfigValue, ContinueWriteRequest, Error,
    ErrorCode, Extensions, HttpRequest, Layer, LayerConfig, LayerHandle, LayerKindDescriptor,
    LayerSpec, LayerType, ReadRedirect, ReadRequest, ReadResult, RedirectBodySource,
    RedirectCredential, RedirectResultBatch, RedirectScope, Request, ResponseParsing, Result,
    ResultCapture, Stack, StatRequest, Url, WrapperFactory, WriteOptions, WriteRedirect,
    WriteRedirectBatch, WriteRequest, WriteResult, WriteStep,
};
use ovstorage_plugin_cache::ByteCacheWrapperFactory;
use ovstorage_plugin_core::RetryWrapperFactory;
use ovstorage_plugin_http::RedirectFollowerWrapperFactory;

use crate::common::*;

const PROXY_CHILD_MODE: &str = "OVSTORAGE_REDIRECT_PROXY_TEST_CHILD";
/// Cleared in the child before it builds a client. `REQUEST_METHOD` is not a
/// proxy variable: hyper-util treats its mere presence as "running as a CGI
/// script" and then disables proxying entirely (the httpoxy mitigation), so an
/// ambient value would silently turn every assertion below into a no-proxy run.
const PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "REQUEST_METHOD",
];

fn proxy_child_command() -> Command {
    let mut command = Command::new(std::env::current_exe().expect("current integration test"));
    command
        .arg("redirect_follower::proxy_environment_child")
        .arg("--exact")
        .arg("--nocapture")
        .env(PROXY_CHILD_MODE, "1");
    for key in PROXY_ENV_KEYS {
        command.env_remove(key);
    }
    command
}

fn assert_proxy_child_succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "proxy child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// A write-path probe backend for `RedirectFollowerWrapper` tests. Its
/// `write_redirect` either declines (`Unsupported`, exercising the fallback) or
/// returns a configured batch; `continue_write` pops the next scripted
/// `WriteStep`. `write`/`write_stream` succeed and count calls so the fallback
/// path is observable.
struct WriteProbe {
    read_calls: AtomicUsize,
    write_calls: AtomicUsize,
    write_stream_calls: AtomicUsize,
    write_redirect_calls: AtomicUsize,
    /// `Request.extensions` last observed on `write_redirect` / `continue_write`,
    /// so a test can assert both halves of one redirect write see the same map.
    redirect_ext: Mutex<Option<Extensions>>,
    continue_ext: Mutex<Option<Extensions>>,
    /// Every `RedirectResultBatch` handed back on `continue_write`, so a test
    /// can assert what the follower captured off the wire.
    continue_results: Mutex<Vec<RedirectResultBatch>>,
    plan: WritePlan,
}

#[allow(clippy::large_enum_variant)]
enum WritePlan {
    /// `write_redirect` returns `Unsupported`; the wrapper falls back.
    Unsupported,
    /// `write_redirect` returns `batch`; `continue_write` pops from `steps`.
    Redirect {
        batch: WriteRedirectBatch,
        steps: Mutex<VecDeque<WriteStep>>,
    },
}

impl WriteProbe {
    fn unsupported() -> Arc<Self> {
        Arc::new(Self {
            read_calls: AtomicUsize::new(0),
            write_calls: AtomicUsize::new(0),
            write_stream_calls: AtomicUsize::new(0),
            write_redirect_calls: AtomicUsize::new(0),
            redirect_ext: Mutex::new(None),
            continue_ext: Mutex::new(None),
            continue_results: Mutex::new(Vec::new()),
            plan: WritePlan::Unsupported,
        })
    }

    fn redirect(batch: WriteRedirectBatch, steps: VecDeque<WriteStep>) -> Arc<Self> {
        Arc::new(Self {
            read_calls: AtomicUsize::new(0),
            write_calls: AtomicUsize::new(0),
            write_stream_calls: AtomicUsize::new(0),
            write_redirect_calls: AtomicUsize::new(0),
            redirect_ext: Mutex::new(None),
            continue_ext: Mutex::new(None),
            continue_results: Mutex::new(Vec::new()),
            plan: WritePlan::Redirect {
                batch,
                steps: Mutex::new(steps),
            },
        })
    }
}

#[async_trait]
impl Layer for WriteProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ovstorage::ObjectInfo> {
        let mut info = object_info(request.input.address, 4);
        info.etag = Some("etag-write".into());
        Ok(info)
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        let mut info = object_info(request.input.address, 4);
        info.etag = Some("etag-write".into());
        Ok(ReadResult::Bytes {
            bytes: b"old!".to_vec(),
            info,
        })
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.write_calls.fetch_add(1, Ordering::SeqCst);
        Ok(WriteResult {
            info: object_info(request.input.address, 0),
        })
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.write_stream_calls.fetch_add(1, Ordering::SeqCst);
        Ok(WriteResult {
            info: object_info(request.input.address, 0),
        })
    }

    async fn write_redirect(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        self.write_redirect_calls.fetch_add(1, Ordering::SeqCst);
        *self.redirect_ext.lock().unwrap() = Some(request.extensions);
        match &self.plan {
            WritePlan::Unsupported => Err(Error::new(
                ErrorCode::Unsupported,
                "backend does not redirect writes",
            )),
            WritePlan::Redirect { batch, .. } => Ok(batch.clone()),
        }
    }

    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        *self.continue_ext.lock().unwrap() = Some(request.extensions);
        self.continue_results
            .lock()
            .unwrap()
            .push(request.input.results);
        match &self.plan {
            WritePlan::Unsupported => Err(Error::new(
                ErrorCode::Unsupported,
                "backend does not redirect writes",
            )),
            WritePlan::Redirect { steps, .. } => {
                steps.lock().unwrap().pop_front().ok_or_else(|| {
                    Error::new(ErrorCode::Internal, "continue_write script exhausted")
                })
            }
        }
    }
}

/// A backend that stamps a fixed *physical* address (different from the caller
/// URL) into every result's `info.address`, and declines `write_redirect`
/// (`Unsupported`). Lets a test observe that `RedirectFollowerWrapper`
/// re-projects `info.address` back to the caller-facing URL on the read
/// pass-through arm and the write/write_stream Unsupported-fallback arms.
struct DivergentAddressBackend {
    physical: Url,
}

#[async_trait]
impl Layer for DivergentAddressBackend {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn read(
        &self,
        _request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        Ok(ReadResult::Bytes {
            bytes: b"body".to_vec(),
            info: object_info(self.physical.clone(), 4),
        })
    }

    async fn write(
        &self,
        _request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        Ok(WriteResult {
            info: object_info(self.physical.clone(), 4),
        })
    }

    async fn write_stream(
        &self,
        _request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        Ok(WriteResult {
            info: object_info(self.physical.clone(), 4),
        })
    }

    async fn write_redirect(
        &self,
        _request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not redirect writes",
        ))
    }
}

/// A `ReadRedirect` pointing at `url`, fresh for 60s — mirrors the helper in
/// `src/redirect.rs`'s test module.
fn read_redirect_to(url: String) -> ReadRedirect {
    let physical_url_prefix = url.clone();
    ReadRedirect {
        request: HttpRequest {
            method: "GET".into(),
            url,
            headers: Vec::new(),
        },
        response_parsing: ResponseParsing::default(),
        expires_at: SystemTime::now() + Duration::from_secs(60),
        scope: RedirectScope {
            physical_url_prefix,
            operations: AccessOps {
                read: true,
                ..Default::default()
            },
            expires_at: SystemTime::now() + Duration::from_secs(60),
            credential: RedirectCredential::None,
        },
        audit_id: String::new(),
        policy_epoch: 0,
    }
}

/// A `WriteRedirect` issuing `PUT url` with `body_source`, fresh for 60s.
fn write_redirect_put(url: String, body_source: RedirectBodySource) -> WriteRedirect {
    let physical_url_prefix = url.clone();
    WriteRedirect {
        request: HttpRequest {
            method: "PUT".into(),
            url,
            headers: Vec::new(),
        },
        body_source,
        result_capture: ResultCapture::default(),
        expires_at: SystemTime::now() + Duration::from_secs(60),
        scope: RedirectScope {
            physical_url_prefix,
            operations: AccessOps {
                write: true,
                ..Default::default()
            },
            expires_at: SystemTime::now() + Duration::from_secs(60),
            credential: RedirectCredential::None,
        },
        audit_id: String::new(),
        policy_epoch: 0,
    }
}

/// Compose `outer_kind` above `inner_kind` above the shared `backend`
/// (`outer → inner → backend`), so a test can exercise how two wrappers
/// interact (e.g. `RedirectFollower → Retry → backend`). Both factories are
/// registered; the kinds must differ.
async fn build_two_wrapper_stack(
    outer_kind: &str,
    outer_factory: Arc<dyn WrapperFactory>,
    outer_config: LayerConfig,
    inner_kind: &str,
    inner_factory: Arc<dyn WrapperFactory>,
    inner_config: LayerConfig,
    backend: LayerHandle,
) -> Result<Stack> {
    let mut outer_spec = LayerSpec::wrapper("outer", outer_kind, "inner");
    outer_spec.config = outer_config;
    let mut inner_spec = LayerSpec::wrapper("inner", inner_kind, "backend");
    inner_spec.config = inner_config;
    Stack::builder("outer")
        .wrapper_factory(outer_factory)
        .wrapper_factory(inner_factory)
        .backend_factory(Arc::new(SharedBackendFactory { backend }))
        .layer(outer_spec)
        .layer(inner_spec)
        .layer(LayerSpec::backend("backend", PROBE_KIND))
        .build()
        .await
}

const EXTENSION_STRIPPING_KIND: &str = "extension-stripping";

struct ExtensionStrippingWrapper {
    name: String,
    inner: LayerHandle,
}

#[async_trait]
impl Layer for ExtensionStrippingWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        wrapper_descriptor(EXTENSION_STRIPPING_KIND)
    }

    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.inner.write(Request::new(request.input), cancel).await
    }
}

struct ExtensionStrippingWrapperFactory;

#[async_trait]
impl WrapperFactory for ExtensionStrippingWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        wrapper_descriptor(EXTENSION_STRIPPING_KIND)
    }

    async fn create_wrapper(
        &self,
        name: &str,
        _config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(Arc::new(ExtensionStrippingWrapper {
            name: name.to_string(),
            inner,
        }))
    }
}

fn wrapper_descriptor(kind: &str) -> LayerKindDescriptor {
    LayerKindDescriptor {
        kind: kind.to_string(),
        layer_type: LayerType::Wrapper,
        display_name: kind.to_string(),
        description: None,
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        auth_capable: false,
        supports_user_metadata: false,
    }
}

async fn build_capture_boundary_stack(
    cache_config: LayerConfig,
    backend: LayerHandle,
) -> Result<Stack> {
    let mut cache = LayerSpec::wrapper("cache", BYTE_CACHE_KIND, "boundary");
    cache.config = cache_config;
    Stack::builder("cache")
        .wrapper_factory(Arc::new(ByteCacheWrapperFactory::default()))
        .wrapper_factory(Arc::new(ExtensionStrippingWrapperFactory))
        .wrapper_factory(Arc::new(RedirectFollowerWrapperFactory))
        .backend_factory(Arc::new(SharedBackendFactory { backend }))
        .layer(cache)
        .layer(LayerSpec::wrapper(
            "boundary",
            EXTENSION_STRIPPING_KIND,
            "follower",
        ))
        .layer(LayerSpec::wrapper(
            "follower",
            REDIRECT_FOLLOWER_KIND,
            "backend",
        ))
        .layer(LayerSpec::backend("backend", PROBE_KIND))
        .build()
        .await
}

/// A `redirect_follower` [`LayerConfig`] carrying the read-asymmetry knobs.
fn follower_config(follow_reads: bool, max_bytes: Option<i64>) -> LayerConfig {
    let mut config = LayerConfig::new();
    config.insert("follow_reads".into(), ConfigValue::Bool(follow_reads));
    if let Some(cap) = max_bytes {
        config.insert("follow_reads_max_bytes".into(), ConfigValue::Int(cap));
    }
    config
}

fn byte_cache_config(dir: &std::path::Path) -> LayerConfig {
    std::fs::create_dir_all(dir.join("cache")).unwrap();
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let mut config = LayerConfig::new();
    config.insert(
        "cache_root".into(),
        ConfigValue::String(dir.join("cache").to_string_lossy().into_owned()),
    );
    config.insert(
        "state_root".into(),
        ConfigValue::String(dir.join("state").to_string_lossy().into_owned()),
    );
    config
}

// ---------------------------------------------------------------------------
// RedirectFollowerWrapper
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proxy_environment_child() {
    if std::env::var_os(PROXY_CHILD_MODE).is_none() {
        return;
    }
    let backend = ProbeBackend::redirecting(read_redirect_to(
        "http://origin.invalid/redirected-object".into(),
    ));
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend,
        LayerConfig::new(),
    )
    .await
    .unwrap();
    let result = stack.read(read_request("probe://obj"), None).await.unwrap();
    assert_eq!(collect(result).await, b"redirected-through-proxy");
}

#[test]
fn redirect_follower_uses_the_process_http_proxy() {
    use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

    let proxy = ScriptedHttpServer::spawn(CannedHttpResponse::new(
        "200 OK",
        "redirected-through-proxy",
    ));
    let mut command = proxy_child_command();
    command.env("HTTP_PROXY", proxy.endpoint());
    let output = command.output().expect("run redirect proxy child");
    assert_proxy_child_succeeded(&output);

    assert_eq!(proxy.hits(), 1);
    let request = &proxy.requests()[0];
    assert!(
        request.starts_with("GET http://origin.invalid/redirected-object HTTP/1.1"),
        "redirect follower proxy must receive an absolute-form URI: {request}"
    );
}

#[tokio::test]
async fn redirect_follower_passes_through_non_redirect() {
    let backend = ProbeBackend::flaky(0, ErrorCode::Transient, b"plain-bytes");
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend,
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let result = stack.read(read_request("probe://obj"), None).await.unwrap();
    assert!(matches!(result, ReadResult::Bytes { .. }));
    assert_eq!(collect(result).await, b"plain-bytes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_follows_read_redirect() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/obj"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"redirected-bytes".to_vec()))
        .mount(&server)
        .await;

    let redirect = read_redirect_to(format!("{}/obj", server.uri()));
    let backend = ProbeBackend::redirecting(redirect);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let result = stack.read(read_request("probe://obj"), None).await.unwrap();
    // The follower streams the post-redirect body regardless of the inner
    // result shape.
    assert!(matches!(result, ReadResult::Stream { .. }));
    assert_eq!(collect(result).await, b"redirected-bytes");
    // The redirect pointer is fetched exactly once; the follow is a separate
    // HTTP fetch, not a re-read of the backend.
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirected_read_mtime_matches_backend_stat() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const LAST_MODIFIED: &str = "Sun, 06 Nov 1994 08:49:37 GMT";
    let expected_mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/obj"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Last-Modified", LAST_MODIFIED)
                .set_body_bytes(b"redirected-bytes".to_vec()),
        )
        .mount(&server)
        .await;

    let redirect = read_redirect_to(format!("{}/obj", server.uri()));
    let backend = ProbeBackend::redirecting_with_stat_mtime(redirect, expected_mtime);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend,
        LayerConfig::new(),
    )
    .await
    .unwrap();
    let request = read_request("probe://obj");

    let stat = stack
        .stat(
            Request::new(StatRequest {
                address: request.input.address.clone(),
                options: Default::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let read = stack.read(request, None).await.unwrap();
    let read_mtime = match read {
        ReadResult::Stream { info, .. } => info.mtime,
        other => panic!("expected redirected stream, got {other:?}"),
    };

    assert_eq!(read_mtime, stat.mtime);
    assert_eq!(read_mtime, Some(expected_mtime));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_materializes_by_following_read_redirect() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/obj"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"redirected-bytes".to_vec()))
        .mount(&server)
        .await;

    let redirect = read_redirect_to(format!("{}/obj", server.uri()));
    let backend = ProbeBackend::redirecting(redirect);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // The backend exposes the object only as a `read` `Redirect` (its
    // materialize is Unsupported); the wrapper must follow the redirect and
    // stage the result to a local file, rather than delegate materialize
    // straight through.
    let local = stack
        .materialize(read_request("probe://obj"), None)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&local.path).unwrap(), b"redirected-bytes");
}

/// A ranged `materialize` that falls back to following a redirect stages the
/// **requested slice**, not the whole object.
///
/// The fallback arm re-issues the read and follows the redirect itself, so it
/// has to carry the caller's range across. Backends deliberately leave `Range`
/// out of the signature — the S3 plugin validates it and discards it on the
/// contract that the host injects it before following — and
/// `send_streaming_request` injects it only when the range is `Some`. So an arm
/// that drops the range does not fail: it quietly stages the entire object and
/// reports info describing it, which is wrong bytes rather than an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ranged_materialize_fallback_stages_only_the_requested_range() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // Only a correctly-ranged request is answered. An unranged one falls
    // through to a 500, so dropping the range fails loudly here rather than
    // silently returning the whole object — the mock is what isolates the
    // behaviour under test.
    Mock::given(method("GET"))
        .and(path("/obj"))
        .and(header("range", "bytes=4-9"))
        .respond_with(
            ResponseTemplate::new(206)
                .insert_header("content-range", "bytes 4-9/16")
                .set_body_bytes(b"ected-".to_vec()),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/obj"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    // `follow_reads = false` is what makes this exercise the arm under test:
    // with the default `true`, `self.read` follows the redirect itself and
    // materialize never reaches its own follow. The shipped REST gateway pins
    // exactly this value, so it is also the realistic shape.
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        ProbeBackend::redirecting(read_redirect_to(format!("{}/obj", server.uri()))),
        follower_config(false, None),
    )
    .await
    .unwrap();

    let mut request = read_request("probe://obj");
    request.input.options.range = Some(ovstorage::ByteRange {
        start: 4,
        end_inclusive: Some(9),
    });

    let local = stack
        .materialize(request, None)
        .await
        .expect("a ranged materialize must stage the requested slice");
    assert_eq!(
        std::fs::read(&local.path).unwrap(),
        b"ected-",
        "the staged file must hold the requested range, not the whole object"
    );
}

#[tokio::test]
async fn redirect_follower_falls_back_when_write_redirect_unsupported() {
    let backend = WriteProbe::unsupported();
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(b"data".to_vec()),
        options: WriteOptions::default(),
    });
    stack.write(request, None).await.unwrap();
    // write_redirect was attempted, then the wrapper fell back to `write`.
    assert_eq!(backend.write_redirect_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_drives_single_round_write_redirect() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/upload", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 4 },
        )],
    };
    let mut steps = VecDeque::new();
    // The backend reports a *physical* address; the wrapper must re-project it
    // to the caller-facing URL on the redirect-Done arm.
    steps.push_back(WriteStep::Done(WriteResult {
        info: object_info(Url::parse("physical://upstream/obj").unwrap(), 4),
    }));
    let backend = WriteProbe::redirect(batch, steps);

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe:///obj").unwrap(),
        body: Body::Bytes(b"data".to_vec()),
        options: WriteOptions::default(),
    });
    let result = stack.write(request, None).await.unwrap();
    // Normalized back to the caller URL, not the backend's physical address.
    assert_eq!(result.info.address, Url::parse("probe:///obj").unwrap());
    // Redirect path taken (not the body-typed fallback).
    assert_eq!(backend.write_redirect_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, b"data");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_write_through_survives_redirect_follower() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/upload", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 4 },
        )],
    };
    let mut info = object_info(Url::parse("probe:///obj").unwrap(), 4);
    info.etag = Some("etag-write".into());
    let backend = WriteProbe::redirect(
        batch,
        VecDeque::from([WriteStep::Done(WriteResult { info })]),
    );
    let tmp = tempfile::tempdir().unwrap();
    let stack = build_two_wrapper_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::default()),
        byte_cache_config(tmp.path()),
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        LayerConfig::new(),
        backend.clone(),
    )
    .await
    .unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("probe:///obj").unwrap(),
                body: Body::Bytes(b"data".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    let read = stack
        .read(read_request("probe:///obj"), None)
        .await
        .unwrap();
    assert_eq!(collect(read).await, b"data");
    assert_eq!(
        backend.read_calls.load(Ordering::SeqCst),
        0,
        "the buffered write must populate the post-write cache"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_write_through_survives_extension_stripping_boundary() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/upload", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 4 },
        )],
    };
    let mut info = object_info(Url::parse("probe:///obj").unwrap(), 4);
    info.etag = Some("etag-write".into());
    let backend = WriteProbe::redirect(
        batch,
        VecDeque::from([WriteStep::Done(WriteResult { info })]),
    );
    let tmp = tempfile::tempdir().unwrap();
    let stack = build_capture_boundary_stack(byte_cache_config(tmp.path()), backend.clone())
        .await
        .unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("probe:///obj").unwrap(),
                body: Body::Bytes(b"data".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    let read = stack
        .read(read_request("probe:///obj"), None)
        .await
        .unwrap();
    assert_eq!(collect(read).await, b"data");
    assert_eq!(
        backend.read_calls.load(Ordering::SeqCst),
        0,
        "the buffered write must populate the cache across the boundary"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_replays_body_across_multi_round_write_redirect() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    for part in ["/part0", "/part1"] {
        Mock::given(method("PUT"))
            .and(path(part))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
    }

    let batch1 = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/part0", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 3 },
        )],
    };
    let batch2 = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/part1", server.uri()),
            RedirectBodySource::UserBytes { offset: 3, len: 3 },
        )],
    };
    let mut steps = VecDeque::new();
    steps.push_back(WriteStep::Redirects(batch2));
    steps.push_back(WriteStep::Done(WriteResult {
        info: object_info(Url::parse("probe://obj").unwrap(), 6),
    }));
    let backend = WriteProbe::redirect(batch1, steps);

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(b"abcdef".to_vec()),
        options: WriteOptions::default(),
    });
    stack.write(request, None).await.unwrap();

    let mut requests = server.received_requests().await.unwrap();
    requests.sort_by(|a, b| a.url.path().cmp(b.url.path()));
    assert_eq!(requests.len(), 2);
    // The full body is replayed each round and sliced by the batch's
    // UserBytes offset/len.
    assert_eq!(requests[0].body, b"abc");
    assert_eq!(requests[1].body, b"def");
}

#[tokio::test]
async fn redirect_follower_falls_through_to_retry_on_unsupported_write_redirect() {
    // Production composition `RedirectFollower → Retry → backend`. The backend
    // declines `write_redirect` (`Unsupported`), so the follower falls back to
    // `self.inner.write` — which is the `RetryWrapper`, NOT the backend
    // directly — and the buffered write is retried through it.
    let backend = FlakyWriteBackend::new(2);
    let stack = build_two_wrapper_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        LayerConfig::new(),
        RETRY_KIND,
        Arc::new(RetryWrapperFactory),
        retry_config(5),
        backend.clone(),
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(b"payload".to_vec()),
        options: WriteOptions::default(),
    });
    stack.write(request, None).await.unwrap();
    // The redirect probe was attempted once (and declined); the buffered write
    // then succeeded only because the retry layer sat in the fallback path.
    assert_eq!(backend.write_redirects.load(Ordering::SeqCst), 1);
    assert_eq!(backend.writes.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn redirect_follower_write_stream_falls_back_when_unsupported() {
    // `write_stream` Unsupported fallback must call `inner.write_stream`, not
    // `inner.write`.
    let backend = WriteProbe::unsupported();
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(b"data".to_vec()),
        options: WriteOptions::default(),
    });
    stack.write_stream(request, None).await.unwrap();
    assert_eq!(backend.write_redirect_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.write_stream_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_write_stream_drives_redirect() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/upload", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 4 },
        )],
    };
    let mut steps = VecDeque::new();
    steps.push_back(WriteStep::Done(WriteResult {
        info: object_info(Url::parse("probe://obj").unwrap(), 4),
    }));
    let backend = WriteProbe::redirect(batch, steps);

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(b"data".to_vec()),
        options: WriteOptions::default(),
    });
    stack.write_stream(request, None).await.unwrap();
    // Redirect path taken via write_stream (not the body-typed fallback).
    assert_eq!(backend.write_redirect_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.write_stream_calls.load(Ordering::SeqCst), 0);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, b"data");
}

#[tokio::test]
async fn redirect_follower_skips_write_redirect_for_zero_byte_body() {
    // A known 0-byte write must skip `write_redirect` entirely and fall back to
    // the body-typed slot.
    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: Vec::new(),
    };
    let backend = WriteProbe::redirect(batch, VecDeque::new());
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(Vec::new()),
        options: WriteOptions::default(),
    });
    stack.write(request, None).await.unwrap();
    assert_eq!(backend.write_redirect_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_propagates_extensions_across_write_redirect() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/upload", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 4 },
        )],
    };
    let mut steps = VecDeque::new();
    steps.push_back(WriteStep::Done(WriteResult {
        info: object_info(Url::parse("probe://obj").unwrap(), 4),
    }));
    let backend = WriteProbe::redirect(batch, steps);

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // Carry a request-context extension across the logical write.
    let mut request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(b"data".to_vec()),
        options: WriteOptions::default(),
    });
    request.extensions.insert("tenant", b"acme".to_vec());
    stack.write(request, None).await.unwrap();

    // The probe (`write_redirect`) and every `continue_write` round must see the
    // same, non-empty extensions — the two halves of one logical write.
    let redirect_ext = backend.redirect_ext.lock().unwrap().clone();
    let continue_ext = backend.continue_ext.lock().unwrap().clone();
    assert!(redirect_ext.is_some(), "write_redirect never observed");
    assert!(continue_ext.is_some(), "continue_write never observed");
    assert_eq!(redirect_ext, continue_ext);
    let ext = redirect_ext.unwrap();
    assert!(!ext.is_empty());
    assert_eq!(ext.get("tenant"), Some(b"acme".as_slice()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_missing_local_file_fails_before_upload() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/upload", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 1 },
        )],
    };
    let backend = WriteProbe::redirect(batch, VecDeque::new());
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend,
        LayerConfig::new(),
    )
    .await
    .unwrap();
    let missing = tempfile::tempdir().unwrap().path().join("missing.bin");

    let error = stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("probe://missing.bin").unwrap(),
                body: Body::LocalFile(missing),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("a missing local source must fail the redirect write");
    assert_eq!(error.code(), ErrorCode::NotFound);
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(
        requests.is_empty(),
        "missing source must fail before an HTTP PUT, got {} request(s)",
        requests.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_reopens_local_file_across_multi_round_write_redirect() {
    use std::io::Write as _;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    for part in ["/part0", "/part1"] {
        Mock::given(method("PUT"))
            .and(path(part))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
    }

    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"abcdef").unwrap();
    file.flush().unwrap();
    let path = file.path().to_path_buf();

    // Each round re-opens the file from the start (offset 0), so a second round
    // succeeds only because the body was re-opened — a consumed stream could
    // not feed it (see the Body::Stream test below).
    let batch1 = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/part0", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 6 },
        )],
    };
    let batch2 = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/part1", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 6 },
        )],
    };
    let mut steps = VecDeque::new();
    steps.push_back(WriteStep::Redirects(batch2));
    steps.push_back(WriteStep::Done(WriteResult {
        info: object_info(Url::parse("probe://obj").unwrap(), 6),
    }));
    let backend = WriteProbe::redirect(batch1, steps);

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::LocalFile(path),
        options: WriteOptions::default(),
    });
    stack.write(request, None).await.unwrap();

    let mut requests = server.received_requests().await.unwrap();
    requests.sort_by(|a, b| a.url.path().cmp(b.url.path()));
    assert_eq!(requests.len(), 2);
    // The file is re-opened and streamed in full each round.
    assert_eq!(requests[0].body, b"abcdef");
    assert_eq!(requests[1].body, b"abcdef");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_errors_on_second_round_for_consumed_stream() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/part0"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    // A streaming body is consumed by the first round; a second redirect round
    // has nothing to replay and must error.
    let batch1 = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/part0", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 6 },
        )],
    };
    let batch2 = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/part1", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 6 },
        )],
    };
    let mut steps = VecDeque::new();
    steps.push_back(WriteStep::Redirects(batch2));
    let backend = WriteProbe::redirect(batch1, steps);

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: stream_body(b"abcdef"),
        options: WriteOptions::default(),
    });
    let error = stack.write_stream(request, None).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unsupported);
    assert!(
        error.to_string().contains("streaming body"),
        "unexpected error message: {error}"
    );
    // The first round did stream the body to the origin before the second
    // round found the stream consumed.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, b"abcdef");
}

#[tokio::test]
async fn redirect_follower_normalizes_divergent_address_to_caller() {
    // `info.address` must use the caller-facing URL on every terminal read/write
    // success variant. This backend reports a physical address instead, so the
    // wrapper's uniform normalization is observable (an echo-the-caller backend
    // would make every stamp a no-op). Covers the read pass-through arm and the
    // write/write_stream Unsupported-fallback arms (the redirect arms are covered
    // by the single-/multi-round redirect tests, which now also use a divergent
    // address).
    let caller = Url::parse("probe:///obj").unwrap();
    let physical = Url::parse("physical://upstream/obj").unwrap();
    let backend = Arc::new(DivergentAddressBackend {
        physical: physical.clone(),
    });
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // Read pass-through arm.
    let read = stack
        .read(read_request("probe:///obj"), None)
        .await
        .unwrap();
    match read {
        ReadResult::Bytes { info, .. } => assert_eq!(info.address, caller),
        other => panic!("unexpected read result: {other:?}"),
    }

    // write Unsupported-fallback arm.
    let write = stack
        .write(
            Request::new(WriteRequest {
                address: caller.clone(),
                body: Body::Bytes(b"body".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(write.info.address, caller);

    // write_stream Unsupported-fallback arm.
    let write_stream = stack
        .write_stream(
            Request::new(WriteRequest {
                address: caller.clone(),
                body: Body::Bytes(b"body".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(write_stream.info.address, caller);
}

/// A backend whose `read` answers with a scripted sequence of redirects —
/// each backend re-entry (the follower's re-mint) pops the next one.
struct SequencedRedirectBackend {
    redirects: Mutex<VecDeque<ReadRedirect>>,
    reads: AtomicUsize,
}

impl SequencedRedirectBackend {
    fn new(redirects: Vec<ReadRedirect>) -> Arc<Self> {
        Arc::new(Self {
            redirects: Mutex::new(redirects.into()),
            reads: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl Layer for SequencedRedirectBackend {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn read(
        &self,
        _request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let redirect = self
            .redirects
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted redirect available");
        Ok(ReadResult::Redirect(redirect))
    }
}

/// `read_redirect_to`, already expired — replaying it must fail; the follower
/// has to re-mint instead.
fn expired_read_redirect_to(url: String) -> ReadRedirect {
    let mut redirect = read_redirect_to(url);
    redirect.expires_at = SystemTime::now() - Duration::from_secs(60);
    redirect.scope.expires_at = redirect.expires_at;
    redirect
}

#[tokio::test]
async fn redirect_follower_re_mints_an_expired_redirect() {
    // An attempt that outlives `expires_at` must re-invoke the backend
    // for a FRESH redirect instead of replaying the stale URL (or failing
    // with `RedirectExpired`).
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("object.bin");
    std::fs::write(&target, b"fresh bytes").unwrap();
    let file_url = Url::from_file_path(&target).unwrap().to_string();

    let backend = SequencedRedirectBackend::new(vec![
        expired_read_redirect_to(file_url.clone()),
        read_redirect_to(file_url),
    ]);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let result = stack
        .read(read_request("probe:///object.bin"), None)
        .await
        .unwrap();
    assert_eq!(collect(result).await, b"fresh bytes");
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "the expired redirect was re-minted from the backend, not replayed"
    );
}

#[tokio::test]
async fn redirect_follower_re_mints_a_rejected_presign() {
    // Rejected as invalid: an origin 403 on an unexpired
    // presign re-acquires a fresh redirect once before surfacing.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stale"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/fresh"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"re-minted".as_slice()))
        .mount(&server)
        .await;

    let backend = SequencedRedirectBackend::new(vec![
        read_redirect_to(format!("{}/stale", server.uri())),
        read_redirect_to(format!("{}/fresh", server.uri())),
    ]);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let result = stack
        .read(read_request("probe:///object.bin"), None)
        .await
        .unwrap();
    assert_eq!(collect(result).await, b"re-minted");
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "the rejected presign was re-minted once"
    );
}

// --- mid-stream resume: scripted origin that can die mid-body ---------------

/// One scripted HTTP response: `content_length` is advertised, `body` is what
/// actually gets written — a shorter body then a dropped connection is how a
/// mid-stream failure is simulated (reqwest surfaces the truncation as a
/// stream error).
struct OriginScript {
    status: u16,
    etag: Option<&'static str>,
    content_length: u64,
    body: Vec<u8>,
    /// When set, the origin ENFORCES `If-Match` (like presigned S3/GCS): the
    /// request head must carry the exact RFC 7232 quoted form
    /// (`if-match: "<value>"`) or the scripted response is replaced by a 412 —
    /// pinning that validators are re-quoted at the wire, not sent stripped.
    require_if_match: Option<&'static str>,
}

impl Default for OriginScript {
    fn default() -> Self {
        Self {
            status: 200,
            etag: None,
            content_length: 0,
            body: Vec::new(),
            require_if_match: None,
        }
    }
}

/// Serve scripted responses per path, capturing each request head (verbatim,
/// including `Range`/`If-Match` headers) for assertions. One response per
/// connection; connections close after the body.
async fn spawn_scripted_origin(
    mut routes: std::collections::HashMap<&'static str, VecDeque<OriginScript>>,
) -> (u16, Arc<Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_task = captured.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match socket.read(&mut byte).await {
                    Ok(1) => head.push(byte[0]),
                    _ => break,
                }
            }
            let head = String::from_utf8_lossy(&head).to_string();
            let path = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();
            let mut script = routes
                .get_mut(path.as_str())
                .and_then(|queue| queue.pop_front())
                .expect("scripted response available for path");
            if let Some(required) = script.require_if_match {
                let needle = format!("if-match: \"{required}\"");
                if !head.to_ascii_lowercase().contains(&needle) {
                    script = OriginScript {
                        status: 412,
                        ..OriginScript::default()
                    };
                }
            }
            captured_task.lock().unwrap().push(head.clone());
            let script = script;
            let mut response = format!(
                "HTTP/1.1 {} SCRIPTED\r\ncontent-length: {}\r\nconnection: close\r\n",
                script.status, script.content_length
            );
            if let Some(etag) = script.etag {
                response.push_str(&format!("etag: \"{etag}\"\r\n"));
            }
            // A real origin always sends a `Content-Range` on a 206; derive an
            // aligned one from the request's `Range: bytes=<from>-` so the resume
            // guard (which rejects a 206 without a parseable, aligned
            // Content-Range) accepts it. `content_length` is the partial
            // body length, so the range is `from..from+len`.
            if script.status == 206 {
                let from = head
                    .to_ascii_lowercase()
                    .split("range: bytes=")
                    .nth(1)
                    .and_then(|rest| rest.split('-').next())
                    .and_then(|start| start.trim().parse::<u64>().ok())
                    .unwrap_or(0);
                let len = script.content_length;
                let last = from + len.saturating_sub(1);
                let total = from + len;
                response.push_str(&format!("content-range: bytes {from}-{last}/{total}\r\n"));
            }
            response.push_str("\r\n");
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.write_all(&script.body).await;
            let _ = socket.flush().await;
            // Dropping the socket here aborts the connection; a body shorter
            // than content-length surfaces as a mid-stream client error.
        }
    });
    (port, captured)
}

const RESUME_PAYLOAD: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

#[tokio::test]
async fn redirect_follower_resumes_a_mid_stream_failure_with_a_range() {
    // A stream that dies after some bytes is resumed by reissuing the
    // redirected request with `Range` at the next unread byte and the first
    // response's validator as `If-Match`; the caller sees one continuous,
    // complete stream.
    let (port, captured) = spawn_scripted_origin(std::collections::HashMap::from([(
        "/obj",
        VecDeque::from([
            OriginScript {
                status: 200,
                etag: Some("v1"),
                content_length: RESUME_PAYLOAD.len() as u64,
                body: RESUME_PAYLOAD[..10].to_vec(),
                require_if_match: None,
            },
            OriginScript {
                status: 206,
                etag: Some("v1"),
                content_length: (RESUME_PAYLOAD.len() - 10) as u64,
                body: RESUME_PAYLOAD[10..].to_vec(),
                // The origin ENFORCES the validator: an unquoted (or absent)
                // If-Match answers 412, so this test fails if the resume
                // sends the stored quote-stripped form on the wire.
                require_if_match: Some("v1"),
            },
        ]),
    )]))
    .await;

    let backend =
        ProbeBackend::redirecting(read_redirect_to(format!("http://127.0.0.1:{port}/obj")));
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend,
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let result = stack
        .read(read_request("probe:///object.bin"), None)
        .await
        .unwrap();
    assert_eq!(collect(result).await, RESUME_PAYLOAD);

    let requests = captured.lock().unwrap().clone();
    assert_eq!(requests.len(), 2);
    let resume_head = requests[1].to_ascii_lowercase();
    assert!(
        resume_head.contains("range: bytes=10-"),
        "the resume must pick up at the next unread byte: {resume_head}"
    );
    assert!(
        resume_head.contains("if-match"),
        "the resume must carry the first response's validator: {resume_head}"
    );
}

#[tokio::test]
async fn redirect_follower_refuses_to_splice_object_versions_on_resume() {
    // The origin answering the resume with 412 (If-Match failed — the
    // object changed mid-read) surfaces a typed ObjectModified instead of
    // stitching bytes from two versions.
    let (port, _captured) = spawn_scripted_origin(std::collections::HashMap::from([(
        "/obj",
        VecDeque::from([
            OriginScript {
                status: 200,
                etag: Some("v1"),
                content_length: RESUME_PAYLOAD.len() as u64,
                body: RESUME_PAYLOAD[..10].to_vec(),
                require_if_match: None,
            },
            OriginScript {
                status: 412,
                etag: Some("v2"),
                content_length: 0,
                body: Vec::new(),
                require_if_match: None,
            },
        ]),
    )]))
    .await;

    let backend =
        ProbeBackend::redirecting(read_redirect_to(format!("http://127.0.0.1:{port}/obj")));
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend,
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let result = stack
        .read(read_request("probe:///object.bin"), None)
        .await
        .unwrap();
    let ReadResult::Stream { mut stream, .. } = result else {
        panic!("redirect follow yields a stream");
    };
    use futures::StreamExt as _;
    let mut received = Vec::new();
    let mut error = None;
    while let Some(item) = stream.next().await {
        match item {
            Ok(chunk) => received.extend_from_slice(&chunk),
            Err(err) => {
                error = Some(err);
                break;
            }
        }
    }
    assert_eq!(received, &RESUME_PAYLOAD[..10]);
    let error = error.expect("the refused resume surfaces an error");
    assert_eq!(
        error.code(),
        ErrorCode::ObjectModified,
        "splicing refusal is typed: {error}"
    );
}

#[tokio::test]
async fn redirect_follower_re_mints_mid_stream_when_the_presign_is_rejected() {
    // A resume attempt whose presign the origin rejects (403)
    // re-acquires a fresh redirect from the backend and completes against
    // the new target.
    let (port, captured) = spawn_scripted_origin(std::collections::HashMap::from([
        (
            "/stale",
            VecDeque::from([
                OriginScript {
                    status: 200,
                    etag: Some("v1"),
                    content_length: RESUME_PAYLOAD.len() as u64,
                    body: RESUME_PAYLOAD[..10].to_vec(),
                    require_if_match: None,
                },
                OriginScript {
                    status: 403,
                    etag: None,
                    content_length: 0,
                    body: Vec::new(),
                    require_if_match: None,
                },
            ]),
        ),
        (
            "/fresh",
            VecDeque::from([OriginScript {
                status: 206,
                etag: Some("v1"),
                content_length: (RESUME_PAYLOAD.len() - 10) as u64,
                body: RESUME_PAYLOAD[10..].to_vec(),
                require_if_match: None,
            }]),
        ),
    ]))
    .await;

    let backend = SequencedRedirectBackend::new(vec![
        read_redirect_to(format!("http://127.0.0.1:{port}/stale")),
        read_redirect_to(format!("http://127.0.0.1:{port}/fresh")),
    ]);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let result = stack
        .read(read_request("probe:///object.bin"), None)
        .await
        .unwrap();
    assert_eq!(collect(result).await, RESUME_PAYLOAD);
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "the rejected mid-stream presign was re-minted from the backend"
    );
    let requests = captured.lock().unwrap().clone();
    assert_eq!(requests.len(), 3);
    assert!(
        requests[2]
            .to_ascii_lowercase()
            .contains("range: bytes=10-"),
        "the re-minted resume still picks up at the next unread byte"
    );
}

#[tokio::test]
async fn redirect_follower_mint_budget_is_once_per_read_across_phases() {
    // The 403 re-mint budget is ONCE PER READ, shared between the header
    // phase and mid-stream resumes: after the header phase consumed it
    // (initial presign rejected 403 -> minted -> streamed), a later
    // mid-stream 403 surfaces instead of minting again. Time-based expiry
    // re-mints are separate and unaffected.
    let (port, _captured) = spawn_scripted_origin(std::collections::HashMap::from([
        (
            "/stale",
            VecDeque::from([OriginScript {
                status: 403,
                etag: None,
                content_length: 0,
                body: Vec::new(),
                require_if_match: None,
            }]),
        ),
        (
            "/fresh",
            VecDeque::from([
                OriginScript {
                    status: 200,
                    etag: Some("v1"),
                    content_length: RESUME_PAYLOAD.len() as u64,
                    body: RESUME_PAYLOAD[..10].to_vec(),
                    require_if_match: None,
                },
                OriginScript {
                    status: 403,
                    etag: None,
                    content_length: 0,
                    body: Vec::new(),
                    require_if_match: None,
                },
            ]),
        ),
    ]))
    .await;

    let backend = SequencedRedirectBackend::new(vec![
        read_redirect_to(format!("http://127.0.0.1:{port}/stale")),
        read_redirect_to(format!("http://127.0.0.1:{port}/fresh")),
        // A third mint target that must NEVER be requested.
        read_redirect_to(format!("http://127.0.0.1:{port}/never")),
    ]);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let result = stack
        .read(read_request("probe:///object.bin"), None)
        .await
        .unwrap();
    let ReadResult::Stream { mut stream, .. } = result else {
        panic!("redirect follow yields a stream");
    };
    use futures::StreamExt as _;
    let mut received = Vec::new();
    let mut error = None;
    while let Some(item) = stream.next().await {
        match item {
            Ok(chunk) => received.extend_from_slice(&chunk),
            Err(err) => {
                error = Some(err);
                break;
            }
        }
    }
    assert_eq!(received, &RESUME_PAYLOAD[..10]);
    error.expect("the second 403 surfaces instead of minting again");
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "the per-read mint budget was consumed by the header phase; the \
         mid-stream 403 must not mint a third redirect"
    );
}

#[tokio::test]
async fn redirect_follower_retries_a_pre_response_transient_through_the_stack() {
    // A transient origin failure before response headers (503) retries
    // within the follower's header phase — driven through the Stack path,
    // not the lower-level helper.
    let (port, captured) = spawn_scripted_origin(std::collections::HashMap::from([(
        "/obj",
        VecDeque::from([
            OriginScript {
                status: 503,
                etag: None,
                content_length: 0,
                body: Vec::new(),
                require_if_match: None,
            },
            OriginScript {
                status: 200,
                etag: Some("v1"),
                content_length: RESUME_PAYLOAD.len() as u64,
                body: RESUME_PAYLOAD.to_vec(),
                require_if_match: None,
            },
        ]),
    )]))
    .await;

    let backend =
        ProbeBackend::redirecting(read_redirect_to(format!("http://127.0.0.1:{port}/obj")));
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend,
        retry_config(3),
    )
    .await
    .unwrap();

    let result = stack
        .read(read_request("probe:///object.bin"), None)
        .await
        .unwrap();
    assert_eq!(collect(result).await, RESUME_PAYLOAD);
    assert_eq!(captured.lock().unwrap().len(), 2);
}

// --- streamed multipart parts + replay spool --------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_streams_multipart_parts_splitting_straddling_chunks() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    for part in ["/part0", "/part1"] {
        Mock::given(method("PUT"))
            .and(path(part))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
    }

    // One batch with two 3-byte parts. The streaming body arrives as a single
    // 6-byte chunk that straddles the part boundary: the follower splits it
    // (`abc` finishes part 0, `def` is carried into part 1) instead of
    // rejecting the straddle, and sends each part with an explicit
    // Content-Length (the old per-part buffer is gone).
    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![
            write_redirect_put(
                format!("{}/part0", server.uri()),
                RedirectBodySource::UserBytes { offset: 0, len: 3 },
            ),
            write_redirect_put(
                format!("{}/part1", server.uri()),
                RedirectBodySource::UserBytes { offset: 3, len: 3 },
            ),
        ],
    };
    let mut steps = VecDeque::new();
    steps.push_back(WriteStep::Done(WriteResult {
        info: object_info(Url::parse("probe://obj").unwrap(), 6),
    }));
    let backend = WriteProbe::redirect(batch, steps);

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: stream_body(b"abcdef"),
        options: WriteOptions::default(),
    });
    stack.write_stream(request, None).await.unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for req in &requests {
        // Each streamed part carries an explicit Content-Length matching the
        // part's declared length (redirect targets like S3 reject chunked).
        let content_length = req
            .headers
            .get("content-length")
            .expect("streamed part must set Content-Length")
            .to_str()
            .unwrap();
        assert_eq!(content_length, "3");
    }
    let part0 = requests
        .iter()
        .find(|r| r.url.path() == "/part0")
        .expect("part0 request");
    let part1 = requests
        .iter()
        .find(|r| r.url.path() == "/part1")
        .expect("part1 request");
    assert_eq!(part0.body, b"abc");
    assert_eq!(part1.body, b"def");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_rejects_single_stream_surplus_after_empty_chunk() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/upload", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 4 },
        )],
    };
    let backend = WriteProbe::redirect(
        batch,
        VecDeque::from([WriteStep::Done(WriteResult {
            info: object_info(Url::parse("probe://obj").unwrap(), 4),
        })]),
    );
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let chunks: Vec<Result<Vec<u8>>> = vec![Ok(b"data".to_vec()), Ok(Vec::new()), Ok(vec![b'!'])];
    let error = stack
        .write_stream(
            Request::new(WriteRequest {
                address: Url::parse("probe://obj").unwrap(),
                body: Body::Stream(BodyStream::from_iter(chunks.into_iter())),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("a single redirect must reject bytes beyond its declared length");

    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(
        backend.continue_results.lock().unwrap().is_empty(),
        "continue_write must not run after an overlong streamed body",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_spools_large_replay_body() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/upload", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 6 },
        )],
    };
    let mut steps = VecDeque::new();
    steps.push_back(WriteStep::Done(WriteResult {
        info: object_info(Url::parse("probe://obj").unwrap(), 6),
    }));
    let backend = WriteProbe::redirect(batch, steps);

    // A 4-byte spool threshold forces the 6-byte buffered body to spool to a
    // temp file and stream from it (seek + bounded read, instead of being
    // retained + cloned in memory); the received body proves the spooled replay
    // is byte-exact.
    let mut config = LayerConfig::new();
    config.insert(
        "replay_spool_threshold_bytes".into(),
        ovstorage::ConfigValue::Int(4),
    );
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        config,
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(b"abcdef".to_vec()),
        options: WriteOptions::default(),
    });
    stack.write(request, None).await.unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, b"abcdef");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_reopens_spooled_body_across_multi_round_write_redirect() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    for part in ["/part0", "/part1"] {
        Mock::given(method("PUT"))
            .and(path(part))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
    }

    // A 4-byte spool threshold forces the 6-byte buffered body to spool to a
    // temp file; each redirect round must re-read that spool from the start
    // (offset 0). A second round succeeds only because the spool is re-read
    // per round — the whole point of spooling a large replayable body.
    let batch1 = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/part0", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 6 },
        )],
    };
    let batch2 = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/part1", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 6 },
        )],
    };
    let mut steps = VecDeque::new();
    steps.push_back(WriteStep::Redirects(batch2));
    steps.push_back(WriteStep::Done(WriteResult {
        info: object_info(Url::parse("probe://obj").unwrap(), 6),
    }));
    let backend = WriteProbe::redirect(batch1, steps);

    let mut config = LayerConfig::new();
    config.insert(
        "replay_spool_threshold_bytes".into(),
        ovstorage::ConfigValue::Int(4),
    );
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        config,
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(b"abcdef".to_vec()),
        options: WriteOptions::default(),
    });
    stack.write(request, None).await.unwrap();

    let mut requests = server.received_requests().await.unwrap();
    requests.sort_by(|a, b| a.url.path().cmp(b.url.path()));
    assert_eq!(requests.len(), 2);
    // The spool is re-read and streamed in full each round.
    assert_eq!(requests[0].body, b"abcdef");
    assert_eq!(requests[1].body, b"abcdef");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_retries_a_seekable_part_from_the_spool() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // First PUT is a retryable 503, second is 200: the seekable path must
    // re-read the spool and resend the part, proving per-part HTTP retry
    // survives the streamed (non-buffered) seekable upload.
    Mock::given(method("PUT"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/upload", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 6 },
        )],
    };
    let mut steps = VecDeque::new();
    steps.push_back(WriteStep::Done(WriteResult {
        info: object_info(Url::parse("probe://obj").unwrap(), 6),
    }));
    let backend = WriteProbe::redirect(batch, steps);

    let mut config = LayerConfig::new();
    // Force the spool → seekable path, and allow 3 attempts for the retry with
    // zero backoff so the test doesn't sleep.
    config.insert(
        "replay_spool_threshold_bytes".into(),
        ovstorage::ConfigValue::Int(4),
    );
    config.insert("max_attempts".into(), ovstorage::ConfigValue::Int(3));
    config.insert("initial_delay_ms".into(), ovstorage::ConfigValue::Int(0));
    config.insert("max_delay_ms".into(), ovstorage::ConfigValue::Int(0));
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        config,
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(b"abcdef".to_vec()),
        options: WriteOptions::default(),
    });
    stack.write(request, None).await.unwrap();

    let requests = server.received_requests().await.unwrap();
    // Two requests: the 503 then the successful retry, each carrying the full
    // spool body re-read from the start.
    assert_eq!(requests.len(), 2);
    for req in &requests {
        assert_eq!(req.body, b"abcdef");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_seekable_serves_arbitrary_offsets() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    for part in ["/part0", "/part1"] {
        Mock::given(method("PUT"))
            .and(path(part))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
    }

    // Two parts read out-of-order from the spool (part 1's bytes before part
    // 0's), proving the seekable path serves arbitrary offsets — a slice the
    // one-shot streaming path (contiguous/ascending only) could not.
    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![
            write_redirect_put(
                format!("{}/part0", server.uri()),
                RedirectBodySource::UserBytes { offset: 3, len: 3 },
            ),
            write_redirect_put(
                format!("{}/part1", server.uri()),
                RedirectBodySource::UserBytes { offset: 0, len: 3 },
            ),
        ],
    };
    let mut steps = VecDeque::new();
    steps.push_back(WriteStep::Done(WriteResult {
        info: object_info(Url::parse("probe://obj").unwrap(), 6),
    }));
    let backend = WriteProbe::redirect(batch, steps);

    let mut config = LayerConfig::new();
    config.insert(
        "replay_spool_threshold_bytes".into(),
        ovstorage::ConfigValue::Int(4),
    );
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        config,
    )
    .await
    .unwrap();

    let request = Request::new(WriteRequest {
        address: Url::parse("probe://obj").unwrap(),
        body: Body::Bytes(b"abcdef".to_vec()),
        options: WriteOptions::default(),
    });
    stack.write(request, None).await.unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let part0 = requests
        .iter()
        .find(|r| r.url.path() == "/part0")
        .expect("part0 request");
    let part1 = requests
        .iter()
        .find(|r| r.url.path() == "/part1")
        .expect("part1 request");
    // Offset 3 → "def", offset 0 → "abc": arbitrary seek, not stream order.
    assert_eq!(part0.body, b"def");
    assert_eq!(part1.body, b"abc");
}

// ---------------------------------------------------------------------------
// One-tree read/write asymmetry knobs (follow_reads / follow_reads_max_bytes)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn follow_reads_false_with_max_bytes_is_rejected() {
    // The size gate lives inside the follow arm, so `follow_reads_max_bytes` is
    // unreachable with `follow_reads=false` — the factory rejects the
    // contradiction rather than silently ignoring the cap.
    let backend = ProbeBackend::redirecting(read_redirect_to("https://origin.example/obj".into()));
    let result = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend,
        follower_config(false, Some(1024)),
    )
    .await;
    match result {
        Err(error) => assert_eq!(error.code(), ErrorCode::InvalidArgument),
        Ok(_) => panic!("follow_reads=false + follow_reads_max_bytes must be rejected at build"),
    }
}

#[tokio::test]
async fn follow_reads_false_passes_read_redirect_up_unfollowed() {
    // With `follow_reads=false`, a read `Redirect` flows up unfollowed — the
    // host (REST → HTTP 307, broker → forward) surfaces it. No HTTP fetch.
    let redirect = read_redirect_to("https://origin.example/obj".into());
    let backend = ProbeBackend::redirecting(redirect);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        follower_config(false, None),
    )
    .await
    .unwrap();

    let result = stack.read(read_request("probe://obj"), None).await.unwrap();
    match result {
        ReadResult::Redirect(redirect) => {
            assert_eq!(redirect.request.url, "https://origin.example/obj");
        }
        other => panic!("expected an unfollowed Redirect, got {other:?}"),
    }
    // The backend was asked exactly once; the follower did not re-fetch.
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn follow_reads_false_validates_every_host_boundary_constraint() {
    let now = SystemTime::now();
    let mut expired_request = read_redirect_to("https://origin.example/obj".into());
    expired_request.expires_at = now - Duration::from_secs(1);

    let mut expired_scope = read_redirect_to("https://origin.example/obj".into());
    expired_scope.scope.expires_at = now - Duration::from_secs(1);

    let mut unsafe_method = read_redirect_to("https://origin.example/obj".into());
    unsafe_method.request.method = "DELETE".into();

    let mut missing_scope_operation = read_redirect_to("https://origin.example/obj".into());
    missing_scope_operation.scope.operations.read = false;

    let mut outside_scope = read_redirect_to("https://origin.example/allowed/obj".into());
    outside_scope.request.url = "https://origin.example/outside/obj".into();

    for (name, redirect, expected_code) in [
        (
            "request expiry",
            expired_request,
            ErrorCode::RedirectExpired,
        ),
        ("scope expiry", expired_scope, ErrorCode::RedirectExpired),
        ("method", unsafe_method, ErrorCode::PermissionDenied),
        (
            "scope operation",
            missing_scope_operation,
            ErrorCode::PermissionDenied,
        ),
        (
            "URL containment",
            outside_scope,
            ErrorCode::PermissionDenied,
        ),
    ] {
        let backend = ProbeBackend::redirecting(redirect);
        let stack = build_stack(
            REDIRECT_FOLLOWER_KIND,
            Arc::new(RedirectFollowerWrapperFactory),
            backend,
            follower_config(false, None),
        )
        .await
        .unwrap();

        let error = stack
            .read(read_request("probe://obj"), None)
            .await
            .unwrap_err();

        assert_eq!(error.code(), expected_code, "{name}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follow_reads_false_streams_a_credential_bearing_redirect_locally() {
    // The Nucleus LFT shape: the backend mints a read `Redirect` carrying an
    // `Authorization: Bearer` header, and the follower runs with
    // `follow_reads=false` (a broker composed without a byte cache). The
    // credential may not cross the host boundary, so the redirect is not
    // surfaced — but the bytes stay reachable: the follower fetches them
    // locally and returns a `Stream`. The token never reaches the caller.
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/obj"))
        .and(header("Authorization", "Bearer connection-wide-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"lft-bytes".to_vec()))
        .mount(&server)
        .await;

    let mut redirect = read_redirect_to(format!("{}/obj", server.uri()));
    redirect.request.headers.push((
        "Authorization".into(),
        "Bearer connection-wide-secret".into(),
    ));
    let backend = ProbeBackend::redirecting(redirect);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend,
        follower_config(false, None),
    )
    .await
    .unwrap();

    let result = stack.read(read_request("probe://obj"), None).await.unwrap();
    assert!(
        matches!(result, ReadResult::Stream { .. }),
        "a credential-bearing redirect must degrade to a local follow, not a Redirect or an error"
    );
    assert_eq!(collect(result).await, b"lft-bytes");
}

#[tokio::test]
async fn follow_reads_false_still_rejects_an_invalid_credential_bearing_redirect() {
    // The local-follow fallback is not an escape hatch from validity: an
    // expired credential-bearing redirect still fails rather than being
    // fetched.
    let mut redirect = read_redirect_to("https://origin.example/obj".into());
    redirect.expires_at = SystemTime::now() - Duration::from_secs(1);
    redirect
        .request
        .headers
        .push(("Authorization".into(), "Bearer secret".into()));

    let backend = ProbeBackend::redirecting(redirect);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend,
        follower_config(false, None),
    )
    .await
    .unwrap();

    let error = stack
        .read(read_request("probe://obj"), None)
        .await
        .expect_err("an expired redirect must fail before any network I/O");
    assert_eq!(error.code(), ErrorCode::RedirectExpired);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follow_reads_false_still_follows_body_bearing_writes() {
    // The asymmetry: `follow_reads=false` suppresses only read-follow. A
    // body-bearing write against a redirect-emitting backend still drives the
    // write-redirect protocol server-side.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("{}/upload", server.uri()),
            RedirectBodySource::UserBytes { offset: 0, len: 4 },
        )],
    };
    let mut steps = VecDeque::new();
    steps.push_back(WriteStep::Done(WriteResult {
        info: object_info(Url::parse("probe://obj").unwrap(), 4),
    }));
    let backend = WriteProbe::redirect(batch, steps);

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        follower_config(false, None),
    )
    .await
    .unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("probe://obj").unwrap(),
                body: Body::Bytes(b"data".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    // The write-redirect path was driven despite follow_reads=false.
    assert_eq!(backend.write_redirect_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, b"data");
}

#[tokio::test]
async fn follow_reads_false_passes_write_protocol_slots_through() {
    // The bodyless `write_redirect` / `continue_write` protocol slots always
    // pass through the follower to the backend (the follower only drives that
    // protocol internally from its own `write` path), even with
    // follow_reads=false.
    let batch = WriteRedirectBatch {
        continuation: vec![7],
        redirects: vec![write_redirect_put(
            "https://origin.example/upload".into(),
            RedirectBodySource::UserBytes { offset: 0, len: 4 },
        )],
    };
    let mut steps = VecDeque::new();
    steps.push_back(WriteStep::Done(WriteResult {
        info: object_info(Url::parse("probe://obj").unwrap(), 4),
    }));
    let backend = WriteProbe::redirect(batch.clone(), steps);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        follower_config(false, None),
    )
    .await
    .unwrap();

    // write_redirect reaches the backend and returns its batch unchanged (the
    // follower does NOT drive the redirect loop on the explicit slot).
    let returned = stack
        .write_redirect(
            Request::new(WriteRequest {
                address: Url::parse("probe://obj").unwrap(),
                body: Body::Bytes(Vec::new()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(returned.continuation, batch.continuation);
    assert_eq!(returned.redirects.len(), 1);
    assert_eq!(backend.write_redirect_calls.load(Ordering::SeqCst), 1);
    // No body-typed write ran — the slot was a pure pass-through.
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);

    // continue_write likewise passes through to the backend's terminal step.
    let step = stack
        .continue_write(
            Request::new(ContinueWriteRequest {
                address: Url::parse("probe://obj").unwrap(),
                redirects: batch,
                results: RedirectResultBatch {
                    results: Vec::new(),
                },
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(step, WriteStep::Done(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follow_reads_max_bytes_follows_when_object_fits() {
    // A read redirect whose object fits the cap is followed and streamed.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/obj"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"redirected-bytes".to_vec()))
        .mount(&server)
        .await;

    let redirect = read_redirect_to(format!("{}/obj", server.uri()));
    let backend = ProbeBackend::redirecting(redirect);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        // 16-byte body ("redirected-bytes") ≤ 1024 cap.
        follower_config(true, Some(1024)),
    )
    .await
    .unwrap();

    let result = stack.read(read_request("probe://obj"), None).await.unwrap();
    assert!(matches!(result, ReadResult::Stream { .. }));
    assert_eq!(collect(result).await, b"redirected-bytes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follow_reads_max_bytes_returns_redirect_when_object_oversize() {
    // A read redirect whose object exceeds the cap is returned unfollowed
    // (the Content-Length is read from the response headers before any body
    // byte is consumed), so the host forwards the original Redirect.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let big_body = vec![b'x'; 4096];
    Mock::given(method("GET"))
        .and(path("/obj"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(big_body))
        .mount(&server)
        .await;

    let url = format!("{}/obj", server.uri());
    let redirect = read_redirect_to(url.clone());
    let backend = ProbeBackend::redirecting(redirect);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        // 4096-byte body > 16-byte cap.
        follower_config(true, Some(16)),
    )
    .await
    .unwrap();

    let result = stack.read(read_request("probe://obj"), None).await.unwrap();
    match result {
        ReadResult::Redirect(redirect) => assert_eq!(redirect.request.url, url),
        other => panic!("expected an unfollowed Redirect for the oversize object, got {other:?}"),
    }
}

/// Build the oversize + ambient-credential fixture: a 4096-byte object behind a
/// redirect carrying `Authorization`, under a 16-byte follow cap.
async fn oversize_credentialed_redirect_stack(
    disclose: bool,
) -> (wiremock::MockServer, String, ovstorage::Stack) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/obj"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 4096]))
        .mount(&server)
        .await;

    let url = format!("{}/obj", server.uri());
    let mut redirect = read_redirect_to(url.clone());
    redirect.request.headers.push((
        "Authorization".into(),
        "Bearer connection-wide-secret".into(),
    ));
    let mut config = follower_config(true, Some(16));
    if disclose {
        config.insert(
            "disclose_redirect_credentials".into(),
            ConfigValue::Bool(true),
        );
    }
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        ProbeBackend::redirecting(redirect),
        config,
    )
    .await
    .unwrap();
    (server, url, stack)
}

/// An oversize read whose redirect carries an ambient credential withholds the
/// **credential**, not the bytes.
///
/// The credential half is unchanged and is the point: nothing carrying
/// `Authorization` crosses the host boundary. What changed is the other half.
/// This arm used to return `PermissionDenied` while holding an open, already
/// credentialed stream, and discard it — so a connection whose redirects are
/// non-delegable lost every read above the cap. It now serves those bytes,
/// because the size cap decides what is worth caching and not what is readable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversize_credentialed_redirect_withholds_the_credential_not_the_bytes() {
    let (_server, _url, stack) = oversize_credentialed_redirect_stack(false).await;

    let result = stack
        .read(read_request("probe://obj"), None)
        .await
        .expect("the bytes are reachable from here, so the read must not fail closed");

    // The load-bearing assertion: no `Redirect`, so the credential does not
    // cross the boundary. `Bytes` would be equally acceptable on that axis;
    // the arm under test streams.
    let stream = match result {
        ReadResult::Stream { stream, info } => {
            assert_eq!(info.size, Some(4096));
            stream
        }
        ReadResult::Redirect(_) => {
            panic!("the credential-bearing redirect was handed to the caller")
        }
        other => panic!("expected a followed Stream, got {other:?}"),
    };

    use futures::StreamExt;
    let mut stream = stream;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk.expect("the served stream must not error"));
    }
    assert_eq!(body.len(), 4096, "the whole object must be served");
}

/// The same fixture with the operator opting in: the redirect *is* surfaced.
///
/// Without this arm the assertion above is satisfied by a follower that never
/// surfaces anything, and the `disclose_redirect_credentials` key would be
/// unexercised on this path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversize_credentialed_redirect_is_surfaced_when_disclosure_is_allowed() {
    let (_server, url, stack) = oversize_credentialed_redirect_stack(true).await;

    match stack.read(read_request("probe://obj"), None).await.unwrap() {
        ReadResult::Redirect(redirect) => {
            assert_eq!(redirect.request.url, url);
            assert!(
                redirect
                    .request
                    .headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("authorization")),
                "the surfaced redirect must still carry what the backend minted"
            );
        }
        other => panic!("`allow` must surface the oversize redirect, got {other:?}"),
    }
}

#[tokio::test]
async fn follow_reads_max_bytes_oversize_after_remint_surfaces_the_fresh_redirect() {
    // Regression (rebase seam: size gate × re-mint): when the header phase
    // re-mints (the original presign is 403'd), the size gate that declines to
    // follow an oversize object must surface the FRESH redirect, not the caller's
    // already-403'd original — surfacing the stale URL would leak a dead
    // redirect to the client.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/stale"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/fresh"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 4096]))
        .mount(&server)
        .await;

    let fresh_url = format!("{}/fresh", server.uri());
    let backend = SequencedRedirectBackend::new(vec![
        read_redirect_to(format!("{}/stale", server.uri())),
        read_redirect_to(fresh_url.clone()),
    ]);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        // 4096-byte object > 16-byte cap.
        follower_config(true, Some(16)),
    )
    .await
    .unwrap();

    let result = stack
        .read(read_request("probe:///object.bin"), None)
        .await
        .unwrap();
    match result {
        ReadResult::Redirect(redirect) => assert_eq!(
            redirect.request.url, fresh_url,
            "the oversize arm must surface the re-minted redirect, not the 403'd original"
        ),
        other => panic!("expected an unfollowed Redirect, got {other:?}"),
    }
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "the 403'd presign was re-minted once before the size gate declined"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follow_reads_max_bytes_returns_redirect_when_size_unknown() {
    // With a byte cap set, an origin that streams the body without a
    // Content-Length (chunked transfer-encoding) has unknown wire size, so the
    // gate cannot prove it fits and returns the original Redirect unfollowed —
    // the `content_length.is_none()` arm the size-bearing tests never reach,
    // even though the body itself would fit the cap.
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // `Transfer-Encoding: chunked` makes hyper omit Content-Length, so reqwest
    // reports an unknown length even though the body is only 16 bytes.
    Mock::given(method("GET"))
        .and(path("/obj"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("transfer-encoding", "chunked")
                .set_body_bytes(b"redirected-bytes".to_vec()),
        )
        .mount(&server)
        .await;

    let url = format!("{}/obj", server.uri());
    let redirect = read_redirect_to(url.clone());
    let backend = ProbeBackend::redirecting(redirect);
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        // 16-byte body ≤ 1024 cap; only the unknown size forces a Redirect.
        follower_config(true, Some(1024)),
    )
    .await
    .unwrap();

    let result = stack.read(read_request("probe://obj"), None).await.unwrap();
    match result {
        ReadResult::Redirect(redirect) => assert_eq!(redirect.request.url, url),
        other => {
            panic!("expected an unfollowed Redirect for the unknown-size object, got {other:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// Wire-level framing of a followed write redirect
//
// `wiremock` is a real hyper server, so it answers whatever `Host` it is sent
// and never surfaces the value — which makes it blind to the framing headers a
// presigned redirect signs. A presigning origin (S3, MinIO) recomputes the
// canonical request from the wire, so a `Host` that drops the port is a 403,
// not a nicety. These tests read the literal request head off a raw socket.
// ---------------------------------------------------------------------------

/// One request as the origin received it: the literal head (request line plus
/// header lines) and the `Content-Length`-framed body.
#[derive(Clone)]
struct CapturedRequest {
    head: String,
    body: Vec<u8>,
}

impl CapturedRequest {
    /// The value of `name` exactly as it arrived, matched case-insensitively.
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|line| {
            let (found, value) = line.split_once(':')?;
            found
                .trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim())
        })
    }

    /// Every value sent under `name`, in wire order. Distinguishes "sent once"
    /// from "sent twice with the same value", which `header` cannot.
    fn header_values(&self, name: &str) -> Vec<&str> {
        self.head
            .lines()
            .skip(1)
            .filter_map(|line| {
                let (found, value) = line.split_once(':')?;
                found
                    .trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| value.trim())
            })
            .collect()
    }

    /// The request line, e.g. `PUT /upload HTTP/1.1`.
    fn request_line(&self) -> &str {
        self.head.lines().next().unwrap_or_default()
    }
}

/// How the capture origin frames its `200 OK`.
#[derive(Clone, Copy)]
enum OriginReply {
    /// `Content-Length`-framed empty body plus an `ETag`.
    Etag,
    /// `Transfer-Encoding: chunked`, so the body only reaches the caller if the
    /// client de-chunks it.
    Chunked,
}

/// The body the [`OriginReply::Chunked`] origin sends, split across two chunks
/// on the wire so a client that forwards the raw framing is visibly wrong.
const CHUNKED_REPLY_BODY: &[u8] = b"chunk-one/chunk-two";

/// A raw-TCP origin on `127.0.0.1:0`. Serves requests until the client hangs
/// up (keep-alive included), recording each head and body. Returns the port and
/// the shared capture log.
///
/// The accept loop outlives the test; the tokio runtime reaps it at teardown.
async fn spawn_capture_origin(reply: OriginReply) -> (u16, Arc<Mutex<Vec<CapturedRequest>>>) {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let sink = Arc::clone(&sink);
            tokio::spawn(async move { serve_captured_connection(socket, reply, sink).await });
        }
    });
    (port, captured)
}

/// Drain one connection: head, `Content-Length` body, reply, repeat.
async fn serve_captured_connection(
    mut socket: tokio::net::TcpStream,
    reply: OriginReply,
    sink: Arc<Mutex<Vec<CapturedRequest>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut pending: Vec<u8> = Vec::new();
    loop {
        // Head, terminated by the blank line.
        let head_end = loop {
            if let Some(at) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let mut chunk = [0u8; 4096];
            match socket.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => pending.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&pending[..head_end]).into_owned();
        pending.drain(..head_end);

        // Body, framed by Content-Length. The follower's buffered arm always
        // has the bytes in hand, so a chunked request body never arrives here;
        // a missing header means an empty body.
        let length = head
            .lines()
            .skip(1)
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while pending.len() < length {
            let mut chunk = [0u8; 4096];
            match socket.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => pending.extend_from_slice(&chunk[..n]),
            }
        }
        let body: Vec<u8> = pending.drain(..length).collect();
        let close = head.lines().skip(1).any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.trim().eq_ignore_ascii_case("connection")
                    && value.trim().eq_ignore_ascii_case("close")
            })
        });
        sink.lock().unwrap().push(CapturedRequest { head, body });

        let response = match reply {
            OriginReply::Etag => {
                b"HTTP/1.1 200 OK\r\nETag: \"abc123\"\r\nContent-Length: 0\r\n\r\n".to_vec()
            }
            OriginReply::Chunked => {
                let (first, second) = CHUNKED_REPLY_BODY.split_at(9);
                format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                     {:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                    first.len(),
                    String::from_utf8_lossy(first),
                    second.len(),
                    String::from_utf8_lossy(second),
                )
                .into_bytes()
            }
        };
        if socket.write_all(&response).await.is_err() {
            return;
        }
        // Honor `Connection: close`. A client that asks for it may block on
        // read-to-EOF rather than on the response framing, so leaving the
        // socket open would hang it rather than fail it.
        if close {
            let _ = socket.shutdown().await;
            return;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_sends_host_with_port_on_buffered_put() {
    // A presigned PUT signs `host` including a non-default port. The follower
    // must put that same authority on the wire, or a signature-verifying origin
    // answers 403.
    let (port, captured) = spawn_capture_origin(OriginReply::Etag).await;

    let mut redirect = write_redirect_put(
        format!("http://127.0.0.1:{port}/upload"),
        RedirectBodySource::UserBytes { offset: 0, len: 4 },
    );
    // A backend-supplied Host must not retarget the request to another virtual
    // host behind the URL's allowed authority.
    redirect
        .request
        .headers
        .push(("Host".into(), "admin.internal".into()));
    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![redirect],
    };
    let backend = WriteProbe::redirect(
        batch,
        VecDeque::from([WriteStep::Done(WriteResult {
            info: object_info(Url::parse("probe:///obj").unwrap(), 4),
        })]),
    );

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("probe:///obj").unwrap(),
                body: Body::Bytes(b"data".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.write_redirect_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.write_calls.load(Ordering::SeqCst), 0);

    let requests = captured.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "expected exactly one redirected PUT");
    assert_eq!(requests[0].request_line(), "PUT /upload HTTP/1.1");
    assert_eq!(
        requests[0].header("host"),
        Some(format!("127.0.0.1:{port}").as_str()),
        "Host must carry the port the redirect URL names — that is what a \
         presigned redirect signed"
    );
    assert_eq!(requests[0].body, b"data");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_sends_host_with_port_on_buffered_multipart_batch() {
    // The multipart part-PUT arm: several presigned redirects in one batch,
    // each slicing its own range out of the user body. Every part is signed
    // against the same authority, so every part must carry it.
    let (port, captured) = spawn_capture_origin(OriginReply::Etag).await;

    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![
            write_redirect_put(
                format!("http://127.0.0.1:{port}/part1"),
                RedirectBodySource::UserBytes { offset: 0, len: 4 },
            ),
            write_redirect_put(
                format!("http://127.0.0.1:{port}/part2"),
                RedirectBodySource::UserBytes { offset: 4, len: 4 },
            ),
        ],
    };
    let backend = WriteProbe::redirect(
        batch,
        VecDeque::from([WriteStep::Done(WriteResult {
            info: object_info(Url::parse("probe:///obj").unwrap(), 8),
        })]),
    );

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("probe:///obj").unwrap(),
                body: Body::Bytes(b"AAAABBBB".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    let requests = captured.lock().unwrap().clone();
    assert_eq!(requests.len(), 2, "expected one PUT per part");
    // The follower drives a batch in order, so part 1 precedes part 2.
    assert_eq!(requests[0].request_line(), "PUT /part1 HTTP/1.1");
    assert_eq!(requests[1].request_line(), "PUT /part2 HTTP/1.1");
    for request in &requests {
        assert_eq!(
            request.header("host"),
            Some(format!("127.0.0.1:{port}").as_str()),
            "every part PUT must carry the signed authority: {}",
            request.request_line()
        );
    }
    assert_eq!(requests[0].body, b"AAAA");
    assert_eq!(requests[1].body, b"BBBB");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_reads_a_chunked_redirect_response() {
    // An origin is free to answer a PUT with a chunked body (S3 returns XML on
    // several redirect targets). The captured body handed to `continue_write`
    // must be the de-chunked payload, not the wire framing.
    let (port, _captured) = spawn_capture_origin(OriginReply::Chunked).await;

    let batch = WriteRedirectBatch {
        continuation: Vec::new(),
        redirects: vec![write_redirect_put(
            format!("http://127.0.0.1:{port}/upload"),
            RedirectBodySource::UserBytes { offset: 0, len: 4 },
        )],
    };
    let backend = WriteProbe::redirect(
        batch,
        VecDeque::from([WriteStep::Done(WriteResult {
            info: object_info(Url::parse("probe:///obj").unwrap(), 4),
        })]),
    );

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("probe:///obj").unwrap(),
                body: Body::Bytes(b"data".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    let rounds = backend.continue_results.lock().unwrap().clone();
    assert_eq!(rounds.len(), 1, "one redirect round");
    let results = &rounds[0].results;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status_code, 200);
    assert_eq!(
        results[0].captured_body, CHUNKED_REPLY_BODY,
        "the chunked response body must reach continue_write de-chunked"
    );
}

/// A four-byte body declared with a zero-padded length. `0004` and `4` frame the
/// same bytes but are different canonical header values, so a presigned request
/// that signed `0004` only verifies if `0004` is what reaches the origin.
const PADDED_LENGTH: &str = "0004";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_replays_a_signed_content_length_verbatim() {
    let (port, captured) = spawn_capture_origin(OriginReply::Etag).await;

    let mut redirect = write_redirect_put(
        format!("http://127.0.0.1:{port}/upload"),
        RedirectBodySource::UserBytes { offset: 0, len: 4 },
    );
    redirect
        .request
        .headers
        .push(("Content-Length".into(), PADDED_LENGTH.into()));

    let backend = WriteProbe::redirect(
        WriteRedirectBatch {
            continuation: Vec::new(),
            redirects: vec![redirect],
        },
        VecDeque::from([WriteStep::Done(WriteResult {
            info: object_info(Url::parse("probe:///obj").unwrap(), 4),
        })]),
    );

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("probe:///obj").unwrap(),
                body: Body::Bytes(b"data".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    let requests = captured.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "expected exactly one redirected PUT");
    assert_eq!(
        requests[0].header_values("content-length"),
        vec![PADDED_LENGTH],
        "the signed Content-Length must go on the wire exactly once, with the \
         value the redirect declared — re-deriving it from the body rewrites a \
         header the signature covers"
    );
    assert_eq!(requests[0].body, b"data");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_follower_refuses_a_content_length_that_contradicts_the_body() {
    // Replaying a declared length verbatim is only safe if it actually frames
    // the body in hand. A redirect that says five bytes over a four-byte body is
    // unsendable either way, so the follower refuses locally rather than put a
    // self-contradicting request on the wire.
    let (port, captured) = spawn_capture_origin(OriginReply::Etag).await;

    let mut redirect = write_redirect_put(
        format!("http://127.0.0.1:{port}/upload"),
        RedirectBodySource::UserBytes { offset: 0, len: 4 },
    );
    redirect
        .request
        .headers
        .push(("Content-Length".into(), "5".into()));

    let backend = WriteProbe::redirect(
        WriteRedirectBatch {
            continuation: Vec::new(),
            redirects: vec![redirect],
        },
        VecDeque::from([WriteStep::Done(WriteResult {
            info: object_info(Url::parse("probe:///obj").unwrap(), 4),
        })]),
    );

    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let error = stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("probe:///obj").unwrap(),
                body: Body::Bytes(b"data".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("a Content-Length that disagrees with the body must not be sent");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(
        captured.lock().unwrap().is_empty(),
        "the request must be refused before it reaches the origin"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streaming_redirect_replays_a_single_signed_content_length_verbatim() {
    let (port, captured) = spawn_capture_origin(OriginReply::Etag).await;
    let mut redirect = write_redirect_put(
        format!("http://127.0.0.1:{port}/upload"),
        RedirectBodySource::UserBytes { offset: 0, len: 4 },
    );
    redirect
        .request
        .headers
        .push(("Content-Length".into(), PADDED_LENGTH.into()));
    let backend = WriteProbe::redirect(
        WriteRedirectBatch {
            continuation: Vec::new(),
            redirects: vec![redirect],
        },
        VecDeque::from([WriteStep::Done(WriteResult {
            info: object_info(Url::parse("probe:///obj").unwrap(), 4),
        })]),
    );
    let stack = build_stack(
        REDIRECT_FOLLOWER_KIND,
        Arc::new(RedirectFollowerWrapperFactory),
        backend,
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("probe:///obj").unwrap(),
                body: Body::Stream(BodyStream::from_iter(
                    vec![Ok(b"data".to_vec())].into_iter(),
                )),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    let requests = captured.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].header_values("content-length"),
        vec![PADDED_LENGTH]
    );
    assert_eq!(requests[0].body, b"data");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streaming_redirect_rejects_invalid_content_length_before_network_io() {
    for (name, values) in [
        ("duplicate", vec!["4", "4"]),
        ("malformed", vec!["four"]),
        // RFC 9110 Content-Length is `1*DIGIT`; Rust's `u64` parser would
        // otherwise accept the leading sign and pass the value to the origin.
        ("signed", vec!["+4"]),
        ("empty", vec![""]),
        ("mismatch", vec!["5"]),
    ] {
        let (port, captured) = spawn_capture_origin(OriginReply::Etag).await;
        let mut redirect = write_redirect_put(
            format!("http://127.0.0.1:{port}/upload"),
            RedirectBodySource::UserBytes { offset: 0, len: 4 },
        );
        for value in values {
            redirect
                .request
                .headers
                .push(("Content-Length".into(), value.into()));
        }
        let backend = WriteProbe::redirect(
            WriteRedirectBatch {
                continuation: Vec::new(),
                redirects: vec![redirect],
            },
            VecDeque::from([WriteStep::Done(WriteResult {
                info: object_info(Url::parse("probe:///obj").unwrap(), 4),
            })]),
        );
        let stack = build_stack(
            REDIRECT_FOLLOWER_KIND,
            Arc::new(RedirectFollowerWrapperFactory),
            backend,
            LayerConfig::new(),
        )
        .await
        .unwrap();

        let error = stack
            .write(
                Request::new(WriteRequest {
                    address: Url::parse("probe:///obj").unwrap(),
                    body: Body::Stream(BodyStream::from_iter(
                        vec![Ok(b"data".to_vec())].into_iter(),
                    )),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(error.code(), ErrorCode::InvalidArgument, "{name}");
        assert!(
            captured.lock().unwrap().is_empty(),
            "{name} Content-Length reached the origin"
        );
    }
}
