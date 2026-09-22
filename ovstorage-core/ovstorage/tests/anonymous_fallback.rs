// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The anonymous scheme fallback as a whole stack sees it. A backend that
//! publishes a marked scheme root is reached through the shipped wrapper
//! chain (`alias → redirect_follower → retry → router → backend`) for an
//! address on that scheme which no configured prefix serves, introspection
//! names the scheme root itself, and every refusal the tier promises — off
//! by default, a suppressed prefix, a credential-bearing query — is still a
//! refusal at the stack boundary.
//!
//! The backend is an in-process probe standing in for a cloud layer. Like the
//! S3, GCS and Azure layers it publishes roots, routes its own requests
//! through the shared [`RouteTable`] (so its own table carries the second
//! tier), answers `NoRoute` on its own miss, and records the address each
//! request arrives with. It is the shared table in the backend position that
//! these tests pin, not any one backend's fallback arm — those have their own
//! tests beside their layers.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use ovstorage::fallback::{
    SCHEME_FALLBACK_ANONYMOUS, SCHEME_FALLBACK_METADATA_KEY, is_scheme_fallback_root,
    scheme_fallback_root,
};
use ovstorage::{
    AddressVisibility, BackendFactory, CancellationToken, Capabilities, ChecksumSet, ConfigLayer,
    ConfigValue, Error, ErrorCode, Extensions, Layer, LayerConfig, LayerHandle,
    LayerKindDescriptor, LayerSpec, LayerType, ObjectInfo, ObjectKind, RangeReadStrategy,
    ReadOptions, ReadRequest, ReadResult, Request, Result, RootInfo, RootInfoSnapshot,
    RootInfoUpdateStream, RouteSource, RouteTable, Stack, StatOptions, StatRequest, Url,
    UserMetadata,
};
use ovstorage_plugin_core::{AliasWrapperFactory, RetryWrapperFactory, RouterFactoryImpl};
use ovstorage_plugin_http::RedirectFollowerWrapperFactory;

/// The probe's layer kind. It is not a cloud kind on purpose: the tier is a
/// property of the shared table and the marker, and a stack must honour it
/// for whichever backend publishes the root.
const PROBE_KIND: &str = "probe";

/// The scheme under test. One of the closed set the shared constructor
/// admits, so the root these tests publish is byte-for-byte the one a
/// granted cloud layer publishes; the probe serves it in-process.
const SCHEME: &str = "s3";

/// A prefix root the probe serves through the first tier, so every test has
/// a configured authority beside the unconfigured ones and can tell "the
/// fallback answered" from "the chain is broken".
const CONFIGURED_ROOT: &str = "s3://configured/";

const CONTENT: &[u8] = b"served by the scheme fallback";

/// The marked `s3:///` root a granted layer of the probe's kind publishes.
fn marked_scheme_root() -> RootInfo {
    scheme_fallback_root(SCHEME, PROBE_KIND, Capabilities::empty(), None)
        .expect("the scheme is in the closed set")
}

/// A minimal `RootInfo` for a physical root `prefix`, `Visible`/`Static`.
fn prefix_root(prefix: &str) -> RootInfo {
    RootInfo {
        root: Url::parse(prefix).unwrap(),
        display_name: None,
        layer_kind: PROBE_KIND.to_string(),
        connection_id: None,
        owning_target: None,
        capabilities: Capabilities::empty(),
        range_read_strategy: RangeReadStrategy::default(),
        source: RouteSource::Static {
            layer: ConfigLayer::Programmatic,
        },
        visible: true,
        visibility: AddressVisibility::Visible,
        alias_state: None,
        icon: None,
        user_metadata: UserMetadata::default(),
    }
}

fn backend_descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        display_name: PROBE_KIND.to_string(),
        kind: PROBE_KIND.to_string(),
        layer_type: LayerType::Backend,
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

fn object_info(address: Url, size: u64) -> ObjectInfo {
    ObjectInfo {
        etag_strength: Default::default(),
        address,
        kind: ObjectKind::File,
        etag: None,
        version: None,
        size: Some(size),
        mtime: None,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
        versioned_address: None,
    }
}

/// A backend Layer shaped like a cloud layer's routing half: it publishes
/// `roots`, resolves every address through its own [`RouteTable`] built from
/// them, answers `NoRoute` on a miss, and records the address each served
/// request arrives with so a test can prove nothing above rewrote it.
struct SchemeProbe {
    roots: Vec<RootInfo>,
    table: RouteTable<()>,
    received: Mutex<Vec<Url>>,
    stats: AtomicUsize,
    reads: AtomicUsize,
}

impl SchemeProbe {
    fn new(roots: Vec<RootInfo>) -> Arc<Self> {
        let table = RouteTable::build(roots.iter().cloned().map(|root| (root, ())).collect());
        Arc::new(Self {
            roots,
            table,
            received: Mutex::new(Vec::new()),
            stats: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
        })
    }

    fn last_received(&self) -> Url {
        self.received
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("the probe served at least one request")
    }

    fn served(&self) -> usize {
        self.stats.load(Ordering::SeqCst) + self.reads.load(Ordering::SeqCst)
    }

    /// The root serving `url` through the probe's own two-tier table, or the
    /// backend's own `NoRoute`. The Router's table and this one are the same
    /// type, so a graph with no Router still has the second tier here.
    fn route(&self, url: &Url) -> Result<&RootInfo> {
        self.table
            .lookup(url)
            .map(|(root, ())| root)
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))
    }
}

#[async_trait]
impl Layer for SchemeProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor()
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        self.route(url).cloned()
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        Ok((
            RootInfoSnapshot {
                roots: self.roots.clone(),
                updates: false,
            },
            None,
        ))
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let address = request.input.address;
        self.route(&address)?;
        self.stats.fetch_add(1, Ordering::SeqCst);
        self.received.lock().unwrap().push(address.clone());
        Ok(object_info(address, CONTENT.len() as u64))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let address = request.input.address;
        self.route(&address)?;
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.received.lock().unwrap().push(address.clone());
        Ok(ReadResult::Bytes {
            bytes: CONTENT.to_vec(),
            info: object_info(address, CONTENT.len() as u64),
        })
    }
}

/// Hands out the one shared probe so the test keeps a typed handle to it.
struct SharedBackendFactory {
    backend: LayerHandle,
}

#[async_trait]
impl BackendFactory for SharedBackendFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor()
    }

    async fn create_backend(
        &self,
        _name: &str,
        _config: &LayerConfig,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(self.backend.clone())
    }
}

/// The public wrapper chain over a Router with the probe as its one child:
/// `alias → redirect_follower → retry → router → backend`. `alias_config` is
/// the alias layer's table, empty for an unconfigured alias.
async fn routed_stack(backend: Arc<SchemeProbe>, alias_config: LayerConfig) -> Stack {
    let mut alias = LayerSpec::wrapper("alias", "alias", "redirect_follower");
    alias.config = alias_config;
    Stack::builder("alias")
        .router_factory(Arc::new(RouterFactoryImpl))
        .wrapper_factory(Arc::new(AliasWrapperFactory::default()))
        .wrapper_factory(Arc::new(RetryWrapperFactory))
        .wrapper_factory(Arc::new(RedirectFollowerWrapperFactory))
        .backend_factory(Arc::new(SharedBackendFactory { backend }))
        .layer(alias)
        .layer(LayerSpec::wrapper(
            "redirect_follower",
            "redirect_follower",
            "retry",
        ))
        .layer(LayerSpec::wrapper("retry", "retry", "router"))
        .layer(LayerSpec::router(
            "router",
            "router",
            vec!["backend".to_string()],
        ))
        .layer(LayerSpec::backend("backend", PROBE_KIND))
        .build()
        .await
        .expect("the routed stack builds")
}

/// The same wrappers with no Router: `retry`'s inner links straight to the
/// backend, the shape an application composes for a single backend.
async fn wrapped_router_less_stack(backend: Arc<SchemeProbe>) -> Stack {
    Stack::builder("alias")
        .wrapper_factory(Arc::new(AliasWrapperFactory::default()))
        .wrapper_factory(Arc::new(RetryWrapperFactory))
        .wrapper_factory(Arc::new(RedirectFollowerWrapperFactory))
        .backend_factory(Arc::new(SharedBackendFactory { backend }))
        .layer(LayerSpec::wrapper("alias", "alias", "redirect_follower"))
        .layer(LayerSpec::wrapper(
            "redirect_follower",
            "redirect_follower",
            "retry",
        ))
        .layer(LayerSpec::wrapper("retry", "retry", "backend"))
        .layer(LayerSpec::backend("backend", PROBE_KIND))
        .build()
        .await
        .expect("the router-less wrapped stack builds")
}

/// A `Stack` whose root *is* the backend: nothing between the caller and the
/// backend's own table.
async fn bare_backend_stack(backend: Arc<SchemeProbe>) -> Stack {
    Stack::builder("backend")
        .backend_factory(Arc::new(SharedBackendFactory { backend }))
        .layer(LayerSpec::backend("backend", PROBE_KIND))
        .build()
        .await
        .expect("the bare backend stack builds")
}

/// An alias-layer table carrying one visibility override.
fn visibility_config(address: &str, visibility: &str) -> LayerConfig {
    let mut config = LayerConfig::new();
    config.insert(
        "visibility".into(),
        ConfigValue::Toml(format!(
            "[[entry]]\naddress = \"{address}\"\nvisibility = \"{visibility}\"\n"
        )),
    );
    config
}

async fn stat_at(stack: &Stack, address: &str) -> Result<ObjectInfo> {
    stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse(address).unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
}

async fn read_at(stack: &Stack, address: &str) -> Result<ReadResult> {
    stack
        .read(
            Request::new(ReadRequest {
                address: Url::parse(address).unwrap(),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
}

async fn root_info_at(stack: &Stack, address: &str) -> Result<RootInfo> {
    stack
        .root_info_for(&Url::parse(address).unwrap(), &Extensions::new(), None)
        .await
}

async fn listed_roots(stack: &Stack) -> Vec<RootInfo> {
    stack
        .list_address_roots(&Extensions::new(), None)
        .await
        .expect("list_address_roots answers")
        .0
        .roots
}

fn bytes_of(result: ReadResult) -> Vec<u8> {
    match result {
        ReadResult::Bytes { bytes, .. } => bytes,
        other => panic!("the probe answers reads with bytes, got {other:?}"),
    }
}

/// The byte-identical refusal an unrouted address always had.
#[track_caller]
fn assert_no_route(error: &Error, context: &str) {
    assert_eq!(error.code(), ErrorCode::NoRoute, "{context}: {error}");
    assert_eq!(
        error.message(),
        "no route matches address",
        "{context}: the refusal must be the one an unrouted address always had"
    );
}

/// Off by default: with only prefix roots published, an address on the scheme
/// that no prefix serves is the `NoRoute` it always was, at the stack boundary
/// and with the same message, and the backend is never consulted. The
/// configured prefix answers beside it, so the refusal is the table's and not
/// a broken chain.
#[tokio::test]
async fn an_unrouted_address_is_noroute_when_no_scheme_root_is_published() {
    let backend = SchemeProbe::new(vec![prefix_root(CONFIGURED_ROOT)]);
    let stack = routed_stack(backend.clone(), LayerConfig::new()).await;

    let error = stat_at(&stack, "s3://unrouted/x")
        .await
        .expect_err("no prefix serves the authority and nothing is granted");
    assert_no_route(&error, "stat");
    let error = read_at(&stack, "s3://unrouted/x")
        .await
        .expect_err("no prefix serves the authority and nothing is granted");
    assert_no_route(&error, "read");
    let error = root_info_at(&stack, "s3://unrouted/x")
        .await
        .expect_err("introspection misses the same way");
    assert_no_route(&error, "root_info_for");
    assert_eq!(
        backend.served(),
        0,
        "an unrouted address never reaches the backend"
    );

    // The hostless prefix root is not what makes a catch-all: an unmarked
    // `s3:///` beside the configured root still leaves the hosted address
    // unrouted.
    let mut unmarked = prefix_root("s3:///");
    unmarked.visible = false;
    unmarked.visibility = AddressVisibility::Hidden;
    let backend = SchemeProbe::new(vec![prefix_root(CONFIGURED_ROOT), unmarked]);
    let stack = routed_stack(backend.clone(), LayerConfig::new()).await;
    let error = stat_at(&stack, "s3://unrouted/x")
        .await
        .expect_err("an unmarked hostless root is a prefix root, not a catch-all");
    assert_no_route(&error, "stat under an unmarked s3:///");
    assert_eq!(backend.served(), 0);

    // Control: the configured prefix is served through the whole chain.
    stat_at(&stack, "s3://configured/x")
        .await
        .expect("the configured prefix routes through the chain");
    assert_eq!(backend.last_received().as_str(), "s3://configured/x");
}

/// A granted layer's marked scheme root routes a hosted address on the scheme
/// through every shipped wrapper and the Router to the backend, which sees
/// the caller's address unchanged — no wrapper rewrites it, no per-authority
/// root is synthesized — and the result comes back in the caller's spelling.
/// The configured prefix beside it keeps the first tier.
#[tokio::test]
async fn a_marked_scheme_root_reaches_the_backend_through_alias_redirect_follower_retry_and_router()
{
    let backend = SchemeProbe::new(vec![prefix_root(CONFIGURED_ROOT), marked_scheme_root()]);
    let stack = routed_stack(backend.clone(), LayerConfig::new()).await;

    let info = stat_at(&stack, "s3://bucket/x")
        .await
        .expect("the marked scheme root routes the unconfigured authority");
    assert_eq!(
        backend.last_received().as_str(),
        "s3://bucket/x",
        "the backend sees the caller's address unchanged"
    );
    assert_eq!(info.address.as_str(), "s3://bucket/x");
    assert_eq!(backend.stats.load(Ordering::SeqCst), 1);

    let result = read_at(&stack, "s3://bucket/x")
        .await
        .expect("the read takes the same route");
    assert_eq!(backend.last_received().as_str(), "s3://bucket/x");
    assert_eq!(bytes_of(result), CONTENT);
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);

    // Every other authority on the scheme takes the fallback too; a scheme
    // the layer did not publish a root for does not.
    stat_at(&stack, "s3://another-bucket/deep/key")
        .await
        .expect("the fallback is per scheme, not per authority");
    assert_eq!(
        backend.last_received().as_str(),
        "s3://another-bucket/deep/key"
    );
    let error = stat_at(&stack, "gs://bucket/x")
        .await
        .expect_err("the fallback is scheme-exact");
    assert_no_route(&error, "stat on an ungranted scheme");

    // The configured prefix outranks the fallback for its own authority.
    let served = root_info_at(&stack, "s3://configured/x")
        .await
        .expect("the configured prefix routes");
    assert_eq!(served.root.as_str(), CONFIGURED_ROOT);
    assert!(!is_scheme_fallback_root(&served));
}

/// The alias wrapper's advertised-root projection keeps the marked scheme
/// root and marks it `Hidden`, exactly as it keeps any incoming `Hidden` root:
/// routable, unlisted by ordinary clients, and carrying the marker a brokered
/// client reads to decide whether to honour it.
#[tokio::test]
async fn list_address_roots_through_alias_marks_the_scheme_root_hidden_rather_than_dropping_it() {
    let backend = SchemeProbe::new(vec![prefix_root(CONFIGURED_ROOT), marked_scheme_root()]);
    let stack = routed_stack(backend, LayerConfig::new()).await;

    let roots = listed_roots(&stack).await;
    let scheme_root = roots
        .iter()
        .find(|root| root.root.as_str() == "s3:///")
        .unwrap_or_else(|| panic!("the marked scheme root is advertised: {roots:?}"));
    assert!(
        !scheme_root.visible,
        "a routing fact, not a browsable place"
    );
    assert_eq!(scheme_root.visibility, AddressVisibility::Hidden);
    assert_eq!(
        scheme_root
            .user_metadata
            .get(SCHEME_FALLBACK_METADATA_KEY)
            .map(String::as_str),
        Some(SCHEME_FALLBACK_ANONYMOUS),
        "the marker survives the projection"
    );
    assert!(is_scheme_fallback_root(scheme_root));
    assert_eq!(scheme_root.connection_id, None);
    assert_eq!(*scheme_root, marked_scheme_root());

    // The configured root beside it is untouched, and nothing per-authority
    // is synthesized for the fallback.
    let configured = roots
        .iter()
        .find(|root| root.root.as_str() == CONFIGURED_ROOT)
        .expect("the configured root is advertised");
    assert!(configured.visible);
    assert_eq!(configured.visibility, AddressVisibility::Visible);
    assert_eq!(roots.len(), 2, "exactly the two published roots: {roots:?}");
}

/// Introspection on a fallback-served address names the scheme root itself,
/// verbatim: the same `RootInfo` the backend published, with no connection
/// and no per-authority root synthesized on the way up.
#[tokio::test]
async fn root_info_for_returns_the_scheme_root_verbatim() {
    let backend = SchemeProbe::new(vec![prefix_root(CONFIGURED_ROOT), marked_scheme_root()]);
    let stack = routed_stack(backend, LayerConfig::new()).await;

    let info = root_info_at(&stack, "s3://bucket/x")
        .await
        .expect("introspection follows the same route the data path takes");
    assert_eq!(info.root.as_str(), "s3:///");
    assert_eq!(info.connection_id, None);
    assert_eq!(info.owning_target, None);
    assert_eq!(info.visibility, AddressVisibility::Hidden);
    assert!(!info.visible);
    assert_eq!(info, marked_scheme_root(), "verbatim, not re-shaped");

    // Deeper addresses and the versioned query the table carries name the
    // same root; the configured prefix still names its own.
    let deep = root_info_at(&stack, "s3://other/a/b/c?versionId=7")
        .await
        .expect("a carried query still takes the fallback");
    assert_eq!(deep, marked_scheme_root());
    let configured = root_info_at(&stack, "s3://configured/x")
        .await
        .expect("the configured prefix routes");
    assert_eq!(configured.root.as_str(), CONFIGURED_ROOT);
}

/// An operator's `Suppressed` override binds the caller-supplied address
/// before anything routes, so the fallback cannot re-open a subtree the
/// operator denied: the address is the byte-identical `NoRoute`, the backend
/// is never consulted, and the scheme root stays advertised for the
/// authorities the operator did not suppress.
#[tokio::test]
async fn a_suppressed_prefix_is_not_reopened_by_the_fallback() {
    let backend = SchemeProbe::new(vec![prefix_root(CONFIGURED_ROOT), marked_scheme_root()]);
    let stack = routed_stack(
        backend.clone(),
        visibility_config("s3://secret/", "suppressed"),
    )
    .await;

    let error = stat_at(&stack, "s3://secret/x")
        .await
        .expect_err("a suppressed prefix stays refused");
    assert_no_route(&error, "stat under a suppressed prefix");
    let error = read_at(&stack, "s3://secret/x")
        .await
        .expect_err("a suppressed prefix stays refused");
    assert_no_route(&error, "read under a suppressed prefix");
    let error = root_info_at(&stack, "s3://secret/x")
        .await
        .expect_err("introspection does not disclose the suppressed prefix either");
    assert_no_route(&error, "root_info_for under a suppressed prefix");
    assert_eq!(
        backend.served(),
        0,
        "the refusal happens above the Router; the backend is never asked"
    );

    // The grant itself is live for every other authority on the scheme.
    stat_at(&stack, "s3://open/x")
        .await
        .expect("an authority the operator did not suppress takes the fallback");
    assert_eq!(backend.last_received().as_str(), "s3://open/x");

    // Suppressing one authority does not suppress the scheme root: the
    // override covers `s3://secret/`, and `s3:///` is not under it.
    let roots = listed_roots(&stack).await;
    let scheme_root = roots
        .iter()
        .find(|root| root.root.as_str() == "s3:///")
        .unwrap_or_else(|| panic!("the scheme root is still advertised: {roots:?}"));
    assert_eq!(scheme_root.visibility, AddressVisibility::Hidden);
}

/// A presigned or SAS address authenticates itself; an anonymous attempt
/// would discard the authority the caller presented. The second tier is
/// skipped for any query key the table does not carry, so the address is the
/// byte-identical `NoRoute` and the backend is never consulted. The carried
/// version key still takes the fallback.
#[tokio::test]
async fn a_credential_bearing_query_never_takes_the_fallback() {
    let backend = SchemeProbe::new(vec![prefix_root(CONFIGURED_ROOT), marked_scheme_root()]);
    let stack = routed_stack(backend.clone(), LayerConfig::new()).await;

    for address in [
        "s3://b/k?X-Amz-Signature=abc",
        "s3://b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc",
        "s3://b/k?sig=abc",
        "s3://b/k?versionId=1&X-Amz-Signature=abc",
    ] {
        let error = stat_at(&stack, address)
            .await
            .err()
            .unwrap_or_else(|| panic!("{address}: a credential-bearing query must not route"));
        assert_no_route(&error, address);
        let error = read_at(&stack, address)
            .await
            .err()
            .unwrap_or_else(|| panic!("{address}: a credential-bearing query must not route"));
        assert_no_route(&error, address);
        let error = root_info_at(&stack, address)
            .await
            .err()
            .unwrap_or_else(|| panic!("{address}: introspection must not route either"));
        assert_no_route(&error, address);
    }
    assert_eq!(
        backend.served(),
        0,
        "a credential-bearing address never reaches the backend"
    );

    // The version key is the one query the table carries.
    let info = stat_at(&stack, "s3://b/k?versionId=1")
        .await
        .expect("a versioned address still takes the fallback");
    assert_eq!(info.address.as_str(), "s3://b/k?versionId=1");
    assert_eq!(backend.last_received().as_str(), "s3://b/k?versionId=1");
}

/// The second tier belongs to the shared table, not to the Router: a graph
/// with no Router — the backend as the stack root, or the wrappers linked
/// straight to it — routes the hosted address through the backend's own
/// table, and without the marked root that same table misses.
#[tokio::test]
async fn a_router_less_graph_serves_the_fallback_from_the_backend_alone() {
    // The backend as the root: nothing between the caller and its table.
    let backend = SchemeProbe::new(vec![prefix_root(CONFIGURED_ROOT), marked_scheme_root()]);
    let stack = bare_backend_stack(backend.clone()).await;
    let info = stat_at(&stack, "s3://bucket/x")
        .await
        .expect("the backend's own table routes the unconfigured authority");
    assert_eq!(info.address.as_str(), "s3://bucket/x");
    assert_eq!(backend.last_received().as_str(), "s3://bucket/x");
    let result = read_at(&stack, "s3://bucket/x")
        .await
        .expect("the read takes the same route");
    assert_eq!(bytes_of(result), CONTENT);
    let served = root_info_at(&stack, "s3://bucket/x")
        .await
        .expect("the backend names the scheme root");
    assert_eq!(served, marked_scheme_root());

    // The same backend without the marked root: its table misses, and the
    // refusal is the backend's own `NoRoute`.
    let ungranted = SchemeProbe::new(vec![prefix_root(CONFIGURED_ROOT)]);
    let stack = bare_backend_stack(ungranted.clone()).await;
    let error = stat_at(&stack, "s3://bucket/x")
        .await
        .expect_err("a prefix-only table has no second tier to fall to");
    assert_no_route(&error, "bare backend without the marked root");
    assert_eq!(ungranted.served(), 0);

    // The shipped wrappers linked straight to the backend, no Router: the
    // wrappers pass the address through and the backend's table routes it.
    let backend = SchemeProbe::new(vec![prefix_root(CONFIGURED_ROOT), marked_scheme_root()]);
    let stack = wrapped_router_less_stack(backend.clone()).await;
    stat_at(&stack, "s3://bucket/x")
        .await
        .expect("the wrapped router-less graph routes the unconfigured authority");
    assert_eq!(backend.last_received().as_str(), "s3://bucket/x");
    let result = read_at(&stack, "s3://bucket/x")
        .await
        .expect("the read takes the same route");
    assert_eq!(bytes_of(result), CONTENT);
    let served = root_info_at(&stack, "s3://bucket/x")
        .await
        .expect("introspection through the wrappers names the scheme root");
    assert_eq!(served, marked_scheme_root());
    let roots = listed_roots(&stack).await;
    assert!(
        roots
            .iter()
            .any(|root| root.root.as_str() == "s3:///" && is_scheme_fallback_root(root)),
        "the alias projection keeps the marked root without a Router too: {roots:?}"
    );

    // A credential-bearing query is refused by the backend's table the same
    // way the Router's refuses it.
    let error = stat_at(&stack, "s3://b/k?X-Amz-Signature=abc")
        .await
        .expect_err("the backend's table skips its second tier for a presigned address");
    assert_no_route(&error, "presigned address through the router-less graph");
}
