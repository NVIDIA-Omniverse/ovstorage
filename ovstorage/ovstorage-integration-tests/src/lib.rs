// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Application-level integration harness for the shipped routed
//! [`ovstorage::Stack`] API.
//!
//! One `Stack` is composed once per test process (on a shared runtime) over
//! an explicit `alias → redirect_follower → retry → router` Layer chain.
//! The `redirect_follower` is load-bearing, not decoration: the azure and s3
//! backends answer every `read` with a redirect, so a chain without it cannot
//! read a cloud object at all. The chain itself comes from staged plugins:
//! `ovstorage-plugin-core-abi` supplies alias, retry, and router, while
//! `ovstorage-plugin-http-abi` supplies the redirect follower. Only the file
//! backend is built into the host. The supported `make test-integration` and
//! `make test-integration-live` entry points run `make build-test-plugins`
//! first; a direct `cargo test -p ovstorage-integration-tests` is a harness
//! development command and requires that staging step already to have run.
//!
//! Plugin cdylibs are `dlopen`'d from `OVSTORAGE_PLUGIN_DIR`, one backend Layer
//! is composed per available plugin kind, and one connection is registered per
//! configured backend. Each scenario then operates purely by address
//! (`file:/…`, `azure://…`, `s3://…`, `gs://…`) — the same way an app does — and
//! the router picks the backend Layer by URL prefix.
//!
//! ## No `#[ignore]`; skip when unconfigured
//!
//! There is no master gate. Every supported test invocation runs every scenario
//! it can: the credential-free `file` backend always runs (the hermetic gate);
//! a cloud backend runs against a loopback emulator when its dedicated endpoint
//! variable is set, or live when its `OVSTORAGE_<BACKEND>_*` env names a fixture
//! *and* supplies credentials (the credential half may come from the shared
//! `OMNI_STORAGE_SERVICE_*` live env for Azure/S3). A scenario whose
//! backend/access/capability is unconfigured returns early via [`skip`], which
//! prints an unmistakable line on stderr.
//!
//! No LIVE fixture name is compiled in. The only built-in fixture identities
//! are the published development values for loopback emulators.
//!
//! ## The guards that keep a green run honest
//!
//! A runtime-skip model has three failure shapes, and each is a hard failure at
//! app-construction time or at the moment of the skip — never an end-of-suite
//! test, whose execution order libtest does not guarantee:
//!
//! - `OVSTORAGE_REQUIRE_LIVE_BACKENDS=azure,s3` — a listed LIVE target that did NOT
//!   connect fails the run. This is what stops vanished credentials from
//!   turning the live job vacuously green. "Connected" means the connection
//!   authenticated: an `Ok` carrying `AwaitingAuth` is a rejected credential
//!   parked for a re-auth that will never come, and counts as a failure.
//! - `OVSTORAGE_FORBID_LIVE_BACKENDS=azure,s3,gcs,huggingface` — a listed
//!   target the environment supplied a live fixture (and, where the backend
//!   needs one, credentials) for fails the run, at RESOLVE time, before any
//!   connection is constructed. This is what makes the credential-free PR job
//!   provably off the live services, and checking it before connecting is what
//!   stops the hermetic run from doing the live I/O it is about to declare
//!   forbidden. An anonymous-capable backend trips it on the fixture variable
//!   alone.
//! - `OVSTORAGE_REQUIRE_HERMETIC_BACKENDS=file,azure,gcs` — a listed local or
//!   emulator target that did NOT connect fails the run. This is independent
//!   of the live requirement: an emulator can never satisfy a live gate, and a
//!   live credential can never satisfy the hermetic CI gate.
//! - `COVERAGE_BASELINE` — a required target that ran FEWER scenarios than
//!   the fixture is known to support fails the run, even though every one of
//!   those skips was individually "legitimate". Without it, a backend that
//!   connects and then advertises no capabilities retires most of the suite
//!   while CI stays green.
//!
//! The requirement env gates accept a comma-separated list of `backend` or
//! `backend:access` (`azure`, `azure:hns`, `s3:versioned`, `file`).

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ovstorage::ext::LayerExt as _;
use ovstorage::layers::{
    ALIAS_KIND, FILE_BACKEND_KIND, REDIRECT_FOLLOWER_KIND, RETRY_KIND, ROUTER_KIND,
    register_default_layer_factories,
};
use ovstorage::{
    Capabilities, ConfigValue, Connection, ConnectionRequest, DeleteDirectoryOptions,
    DeleteOptions, ErrorCode, LayerConnectionRequest, LayerSpec, ListVersionsOptions,
    ListVersionsRequest, LoadedLayerFactory, ReadOptions, Request, SecretBundle, SecretBytes,
    SecretValue, Stack, StatOptions, Url, WriteOptions, WriteResult, address,
};

pub mod scenarios;

/// Fails the run when a named live target did not connect.
const REQUIRE_LIVE_BACKENDS: &str = "OVSTORAGE_REQUIRE_LIVE_BACKENDS";
/// Fails the run when a named local/emulator target did not connect.
const REQUIRE_HERMETIC_BACKENDS: &str = "OVSTORAGE_REQUIRE_HERMETIC_BACKENDS";
/// Fails the run when a named live target DID connect.
const FORBID_LIVE_BACKENDS: &str = "OVSTORAGE_FORBID_LIVE_BACKENDS";
/// Repository gate: `=1` means a staged plugin set is mandatory.
const REQUIRE_TEST_PLUGINS: &str = "OVSTORAGE_REQUIRE_TEST_PLUGINS";

/// Backend kinds the staged plugin set must provide under
/// [`REQUIRE_TEST_PLUGINS`]. Every cloud backend this suite can address, so a
/// staging step that built only some of them is a failure rather than a
/// backend's worth of invisible `⊘ NO-PLUGIN` skips. `file` is not listed: it
/// is built into the host, not staged.
const REQUIRED_PLUGIN_BACKEND_KINDS: &[&str] = &["azure", "gcs", "huggingface", "s3"];

/// Published, emulator-only identity. These values authorize no real service.
const AZURITE_ACCOUNT: &str = "devstoreaccount1";
const AZURITE_CONTAINER: &str = "ovstorage";
const AZURITE_ACCOUNT_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
const FAKE_GCS_BUCKET: &str = "ovstorage";

/// Which real backend a scenario runs against.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Credential-free local-file backend: the hermetic gate that runs on every
    /// `cargo test`.
    File,
    Azure,
    S3,
    Gcs,
    /// Read-only Hugging Face Hub backend: live-only, anonymous-capable, and
    /// outside the write family — it owns the read-family scenarios instead.
    Huggingface,
}

impl Backend {
    pub fn label(self) -> &'static str {
        match self {
            Backend::File => "file",
            Backend::Azure => "azure",
            Backend::S3 => "s3",
            Backend::Gcs => "gcs",
            Backend::Huggingface => "huggingface",
        }
    }

    /// The `backend_kind` the host knows this backend by — also the name of the
    /// backend Layer instance the Stack composes for it, and therefore the
    /// `LayerConnectionRequest::target` a connection op addresses.
    fn kind(self) -> &'static str {
        match self {
            Backend::File => FILE_BACKEND_KIND,
            Backend::Azure => "azure",
            Backend::S3 => "s3",
            Backend::Gcs => "gcs",
            Backend::Huggingface => "huggingface",
        }
    }
}

/// The per-backend-meaningful target flavor a connection represents.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Access {
    /// Primary target with standard credentials.
    Default,
    /// A versioning-enabled bucket/container, named by the
    /// `OVSTORAGE_*_VERSIONED_*` variables. Versioning is a property of the
    /// fixture rather than of the credentials, so this target exists only when
    /// one is named explicitly; otherwise the version scenarios skip.
    Versioned,
    /// Azure ADLS Gen2 hierarchical-namespace account. Never configured for
    /// S3/GCS (no HNS analog) or the file backend.
    Hns,
}

impl Access {
    pub fn label(self) -> &'static str {
        match self {
            Access::Default => "default",
            Access::Versioned => "versioned",
            Access::Hns => "hns",
        }
    }
}

/// Where a resolved target sends traffic.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    /// The built-in filesystem backend.
    Local,
    /// A loopback service emulator selected by a dedicated endpoint variable.
    Emulator,
    /// A real cloud fixture selected by fixture identity plus credentials.
    Live,
}

impl Origin {
    fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Emulator => "emulator",
            Self::Live => "live",
        }
    }
}

/// A constructed, ready-to-drive connection plus everything a scenario needs to
/// address it through the routed [`Stack`].
pub struct Target {
    pub backend: Backend,
    pub access: Access,
    pub origin: Origin,
    /// Advertised address root, e.g. `azure://acct/container/`, `s3://bucket/`,
    /// `gs://bucket/`, `file:///tmp/…/`. Keys are appended to this.
    pub root: Url,
    pub caps: Capabilities,
    /// The Layer instance name that owns this root's connection, as reported by
    /// [`ovstorage::RootInfo::owning_target`]. Kept for diagnostics and for any
    /// follow-up connection op, which routes by instance name rather than kind.
    pub owning_target: Option<String>,
    stack: Arc<Stack>,
}

impl Target {
    fn alias(&self, access: Access) -> Self {
        Self {
            backend: self.backend,
            access,
            origin: self.origin,
            root: self.root.clone(),
            caps: self.caps.clone(),
            owning_target: self.owning_target.clone(),
            stack: self.stack.clone(),
        }
    }

    /// Build a routed address from a key relative to [`Self::root`].
    pub fn addr(&self, key: &str) -> Url {
        address::join_relative(&self.root, key)
            .unwrap_or_else(|e| panic!("compose address root={} key={key:?}: {e:?}", self.root))
    }

    /// The routed Stack, for ops not covered by the convenience helpers.
    pub fn stack(&self) -> &Arc<Stack> {
        &self.stack
    }

    /// Buffered write of `bytes` to `key`.
    pub async fn put(&self, key: &str, bytes: Vec<u8>) -> ovstorage::Result<WriteResult> {
        self.stack
            .write(
                self.addr(key),
                ovstorage::Body::Bytes(bytes),
                WriteOptions::default(),
                None,
            )
            .await
    }

    /// Buffered read of `key` (content only).
    pub async fn get(&self, key: &str) -> ovstorage::Result<Vec<u8>> {
        self.stack
            .read_bytes(self.addr(key), ReadOptions::default(), None)
            .await
            .map(|(bytes, _)| bytes)
    }

    pub async fn stat(&self, key: &str) -> ovstorage::Result<ovstorage::ObjectInfo> {
        self.stat_with(key, StatOptions::default()).await
    }

    /// `stat` of `key` under caller-chosen options (cost flags such as
    /// `versioned_address`).
    pub async fn stat_with(
        &self,
        key: &str,
        options: StatOptions,
    ) -> ovstorage::Result<ovstorage::ObjectInfo> {
        self.stack.stat(self.addr(key), options, None).await
    }

    pub async fn rm(&self, key: &str) -> ovstorage::Result<()> {
        self.stack
            .delete(self.addr(key), DeleteOptions::default(), None)
            .await
    }
}

/// Process-wide application state: one routed `Stack` and one [`Target`] per
/// configured backend/access.
pub struct AppState {
    pub stack: Arc<Stack>,
    targets: Vec<Target>,
    // Owns the file backend's scratch root for the process lifetime.
    _file_root: FileRoot,
}

impl AppState {
    /// The configured target for `(backend, access)`, or `None` (→ skip).
    pub fn target(&self, backend: Backend, access: Access) -> Option<&Target> {
        let origin = preferred_origin(backend, access);
        self.targets.iter().find(|t| {
            t.backend == backend && t.access == access && origin.is_none_or(|want| t.origin == want)
        })
    }

    /// The first configured target for `backend` whose capabilities satisfy
    /// `pred` (used by directory ops: file's Default vs Azure's HNS target).
    pub fn target_where(
        &self,
        backend: Backend,
        pred: impl Fn(&Capabilities) -> bool,
    ) -> Option<&Target> {
        self.targets
            .iter()
            .filter(|t| preferred_origin(backend, t.access).is_none_or(|want| t.origin == want))
            .find(|t| t.backend == backend && pred(&t.caps))
    }

    /// Whether any target for `backend` is connected.
    pub fn has_backend(&self, backend: Backend) -> bool {
        self.targets.iter().any(|t| t.backend == backend)
    }
}

// === shared runtime + lazily-built app ===

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build shared tokio runtime")
    })
}

/// Drive `fut` to completion on the shared runtime. Used by the generated
/// `#[test]` cases so every scenario shares one `Stack` on one runtime (avoids
/// per-`#[tokio::test]` runtime churn dropping the Stack's background tasks —
/// the Router's root watchers and route-table catch-ups are spawned tasks).
pub fn block_on<F: Future>(fut: F) -> F::Output {
    runtime().block_on(fut)
}

/// The process-wide [`AppState`], built once.
pub async fn app() -> &'static AppState {
    static APP: tokio::sync::OnceCell<AppState> = tokio::sync::OnceCell::const_new();
    APP.get_or_init(build_app).await
}

/// A pure environment-to-connection resolution, before any network I/O.
struct ResolvedRequest {
    backend: Backend,
    access: Access,
    origin: Origin,
    kind: String,
    config: HashMap<String, ConfigValue>,
    credentials: SecretBundle,
}

async fn build_app() -> AppState {
    init_test_tracing();
    // Hard precondition for plugin loading. Process-global and idempotent for
    // `None`, so calling it here is safe however many test binaries share it.
    ovstorage::init_auth_substrate(None).expect("initialize the ovstorage auth substrate");

    let dir = plugin_dir();
    // SAFETY: the staging dir holds only trusted, locally-built plugin cdylibs.
    // `allow_test_plugins: false` makes the loader skip the `test_only` cdylibs
    // (`ovstorage-plugin-test-abi` and friends) staged in the same directory.
    let factories = unsafe { ovstorage::load_layer_plugins_from_dir(&dir, false) }
        .unwrap_or_else(|e| panic!("load layer plugins from {}: {e:?}", dir.display()));
    require_staged_plugins(&dir, &factories);

    let file_root = FileRoot::create();

    // Resolve every (backend, access) request, then connect the distinct ones.
    let mut requests: Vec<ResolvedRequest> = vec![ResolvedRequest {
        backend: Backend::File,
        access: Access::Default,
        origin: Origin::Local,
        kind: FILE_BACKEND_KIND.to_string(),
        config: file_config(file_root.path()),
        credentials: SecretBundle::default(),
    }];
    requests.extend(resolve_emulator_requests());
    for backend in [
        Backend::Azure,
        Backend::S3,
        Backend::Gcs,
        Backend::Huggingface,
    ] {
        for access in [Access::Default, Access::Versioned, Access::Hns] {
            if let Some((kind, config, creds)) = resolve_request(backend, access) {
                requests.push(ResolvedRequest {
                    backend,
                    access,
                    origin: Origin::Live,
                    kind,
                    config,
                    credentials: creds,
                });
            }
        }
    }

    // Before ANY connection is constructed. `add_connection` is not a local
    // bookkeeping call: every cloud backend probes its root during bring-up, so
    // checking the forbid list after connecting would mean a hermetic `make
    // test` on a credentialed developer machine had already issued
    // authenticated list requests against the shared fixture by the time it
    // reported that it was not allowed to.
    forbid_resolved(&requests);

    // A backend Layer only exists for a kind some plugin (or the built-in file
    // backend) actually provides. Composing a Layer for an unstaged kind would
    // fail the whole build; dropping the request instead leaves that backend's
    // scenarios to skip visibly, which is the unconfigured-backend contract.
    let available = available_backend_kinds(&factories);
    requests.retain(|request| {
        let staged = available.contains(&request.kind);
        if !staged {
            eprintln!(
                "⊘ NO-PLUGIN [{}:{}:{}]: no Layer factory for kind {:?} in {}",
                request.backend.label(),
                request.access.label(),
                request.origin.label(),
                request.kind,
                dir.display(),
            );
        }
        staged
    });
    let composed: BTreeSet<String> = requests
        .iter()
        .map(|request| request.kind.clone())
        .collect();

    let stack = Arc::new(build_stack(factories, &composed).await);

    requests.sort_by(|a, b| {
        resolved_request_root(a.backend, &a.config)
            .cmp(&resolved_request_root(b.backend, &b.config))
            .then_with(|| a.origin.cmp(&b.origin))
            .then_with(|| request_dedupe_priority(a.access).cmp(&request_dedupe_priority(b.access)))
    });
    let mut targets: Vec<Target> = Vec::new();
    for resolved in requests {
        // Deduplicate by routed address root, not raw config. HNS uses the
        // same public azure://account/container/ root as the flat Azure target;
        // the hidden hierarchical_namespace flag should not create a duplicate
        // route. HNS is sorted ahead of Default for the same root so same-root
        // aliases use the richer real-directory-capable connection.
        if let Some(root) = resolved_request_root(resolved.backend, &resolved.config)
            && let Some(pos) = targets.iter().position(|t| {
                t.backend == resolved.backend
                    && t.origin == resolved.origin
                    && t.root.as_str() == root
            })
        {
            if !targets.iter().any(|t| {
                t.backend == resolved.backend
                    && t.access == resolved.access
                    && t.origin == resolved.origin
                    && t.root.as_str() == root
            }) {
                targets.push(targets[pos].alias(resolved.access));
            }
            continue;
        }
        let layer_request = LayerConnectionRequest {
            // The Stack composes one backend Layer per kind, named after the
            // kind, so the connection target is that Layer's instance name.
            target: resolved.kind.clone(),
            connection: ConnectionRequest {
                backend_kind: resolved.kind,
                config: resolved.config,
                credentials: resolved.credentials,
                persist: false,
                display_name: Some(format!(
                    "{}:{}:{}",
                    resolved.backend.label(),
                    resolved.access.label(),
                    resolved.origin.label()
                )),
            },
        };
        match ovstorage::Layer::add_connection(&*stack, Request::new(layer_request), None).await {
            Ok(conn) => match auth_state_rejection(&conn.auth_state) {
                None => match into_target(
                    &stack,
                    resolved.backend,
                    resolved.access,
                    resolved.origin,
                    conn,
                )
                .await
                {
                    Ok(target) => targets.push(target),
                    Err(why) => record_connect_failure(
                        resolved.backend,
                        resolved.access,
                        resolved.origin,
                        why,
                    ),
                },
                Some(why) => {
                    record_connect_failure(resolved.backend, resolved.access, resolved.origin, why)
                }
            },
            Err(e) => record_connect_failure(
                resolved.backend,
                resolved.access,
                resolved.origin,
                e.message().to_string(),
            ),
        }
    }

    require_connected(&targets);
    require_baseline_capabilities(&targets);

    AppState {
        stack,
        targets,
        _file_root: file_root,
    }
}

/// The backend kinds a Layer can actually be composed for: the built-in file
/// backend plus every `Backend`-typed factory the plugin scan produced.
fn available_backend_kinds(factories: &[LoadedLayerFactory]) -> BTreeSet<String> {
    let mut kinds = BTreeSet::from([FILE_BACKEND_KIND.to_string()]);
    for factory in factories {
        if matches!(factory, LoadedLayerFactory::Backend(_)) {
            kinds.insert(factory.descriptor().kind);
        }
    }
    kinds
}

fn integration_layer_specs(children: Vec<String>) -> Vec<LayerSpec> {
    vec![
        LayerSpec::wrapper("alias", ALIAS_KIND, "redirect_follower"),
        LayerSpec::wrapper("redirect_follower", REDIRECT_FOLLOWER_KIND, "retry"),
        LayerSpec::wrapper("retry", RETRY_KIND, "router"),
        LayerSpec::router("router", ROUTER_KIND, children),
    ]
}

/// Compose the Stack: the default factories, the loaded plugin factories, the
/// default wrapper chain, and one backend Layer per kind we have a request for.
///
/// Built with NO connections so each one is registered afterwards through
/// `add_connection` — a connection declared at build time would make one bad
/// credential fail the whole composition, taking the credential-free `file`
/// gate down with it. Registering at runtime keeps each failure local and
/// visible (see [`record_connect_failure`]).
async fn build_stack(factories: Vec<LoadedLayerFactory>, kinds: &BTreeSet<String>) -> Stack {
    let mut builder = register_default_layer_factories(Stack::builder("alias"));
    for factory in factories {
        builder = match factory {
            LoadedLayerFactory::Backend(f) => builder.backend_factory(f),
            LoadedLayerFactory::Wrapper(f) => builder.wrapper_factory(f),
            LoadedLayerFactory::Router(f) => builder.router_factory(f),
        };
    }
    // alias → redirect_follower → retry → router. The redirect follower is
    // mandatory for cloud reads and supplies the `materialize` fallback the
    // read_stream_and_materialize scenario needs without a byte cache.
    for spec in integration_layer_specs(kinds.iter().cloned().collect()) {
        builder = builder.layer(spec);
    }
    for kind in kinds {
        builder = builder.layer(LayerSpec::backend(kind.clone(), kind.clone()));
    }
    builder
        .build()
        .await
        .expect("compose the integration-test Stack")
}

/// `OVSTORAGE_REQUIRE_TEST_PLUGINS=1` is the repository's "the staged cdylibs are
/// mandatory" gate. Honoring it here stops a run whose staging step never ran
/// from silently degrading to file-only coverage.
///
/// "Some cdylib loaded" is not that guarantee: the loader also produces wrapper
/// and router factories, and `libovstorage_plugin_http.so` alone would satisfy
/// a non-empty check while every cloud backend fell through to `⊘ NO-PLUGIN`
/// and skipped. What the suite actually needs is a backend Layer factory for
/// each cloud kind it addresses, so that is what is asserted — by kind, naming
/// the ones that are missing.
fn require_staged_plugins(dir: &Path, factories: &[LoadedLayerFactory]) {
    if std::env::var(REQUIRE_TEST_PLUGINS).as_deref() != Ok("1") {
        return;
    }
    let available = available_backend_kinds(factories);
    let missing: Vec<&str> = REQUIRED_PLUGIN_BACKEND_KINDS
        .iter()
        .copied()
        .filter(|kind| !available.contains(*kind))
        .collect();
    assert!(
        missing.is_empty(),
        "{REQUIRE_TEST_PLUGINS}=1 but {} staged in {} provides no backend Layer factory for \
         kind(s) {:?} (loaded backend kinds: {:?}); run `make build-test-plugins`",
        if factories.is_empty() {
            "no plugin cdylib"
        } else {
            "the plugin set"
        },
        dir.display(),
        missing,
        available,
    );
}

fn request_dedupe_priority(access: Access) -> u8 {
    match access {
        Access::Hns => 0,
        Access::Default => 1,
        Access::Versioned => 2,
    }
}

fn resolved_request_root(
    backend: Backend,
    config: &HashMap<String, ConfigValue>,
) -> Option<String> {
    fn string_field<'a>(config: &'a HashMap<String, ConfigValue>, key: &str) -> Option<&'a str> {
        match config.get(key) {
            Some(ConfigValue::String(value)) => Some(value),
            _ => None,
        }
    }

    match backend {
        Backend::File => {
            let root = string_field(config, "root")?;
            Some(format!("file://{}/", root.trim_end_matches('/')))
        }
        Backend::Azure => Some(format!(
            "azure://{}/{}/",
            string_field(config, "account")?,
            string_field(config, "container")?,
        )),
        Backend::S3 => Some(format!("s3://{}/", string_field(config, "bucket")?)),
        Backend::Gcs => Some(format!("gs://{}/", string_field(config, "bucket")?)),
        Backend::Huggingface => {
            let repo_id = string_field(config, "repo_id")?;
            // The same plural mapping the plugin builds its address root from.
            let plural = match string_field(config, "repo_type") {
                None | Some("model") => "models",
                Some("dataset") => "datasets",
                Some("space") => "spaces",
                // Unknown type: no dedupe key rather than a wrong one; the
                // connection itself will refuse the config.
                Some(_) => return None,
            };
            Some(format!("hf://{plural}/{repo_id}/"))
        }
    }
}

async fn into_target(
    stack: &Arc<Stack>,
    backend: Backend,
    access: Access,
    origin: Origin,
    conn: Connection,
) -> Result<Target, String> {
    let connection_id = conn.id.clone();
    let roots = stack.list_address_roots(None).await.map_err(|error| {
        format!(
            "authenticated connection {connection_id:?} could not inspect the routed address \
             table with list_address_roots: {}",
            error.message()
        )
    });
    let (root, owning_target) = target_route(&conn, roots.as_deref().map_err(String::as_str))?;
    Ok(Target {
        backend,
        access,
        origin,
        root,
        caps: conn.capabilities,
        owning_target,
        stack: stack.clone(),
    })
}

/// Resolve the address and owning Layer for one authenticated connection.
///
/// A backend normally echoes its root in `current_addresses`; a composite
/// router may instead publish only a [`ovstorage::RootInfo`] row. Neither
/// source being present is a failed connection setup, not an unconfigured
/// target: returning the diagnostic lets [`build_app`] record it alongside
/// authentication failures and lets [`REQUIRE_LIVE_BACKENDS`] report one
/// actionable cause instead of merely saying the target disappeared.
fn target_route(
    conn: &Connection,
    roots: Result<&[ovstorage::RootInfo], &str>,
) -> Result<(Url, Option<String>), String> {
    let roots = match roots {
        Ok(roots) => roots,
        // A current address is already enough to drive scenarios. Root-table
        // discovery enriches it with owning_target, but losing that diagnostic
        // must not discard an otherwise usable authenticated connection.
        Err(_) if !conn.current_addresses.is_empty() => {
            return Ok((conn.current_addresses[0].clone(), None));
        }
        // With no current address the root table is the only fallback, so its
        // error is the actionable connect failure and must remain intact.
        Err(error) => return Err(error.to_owned()),
    };
    // Prefer the routing table's own row for THIS connection: it carries
    // `owning_target`, the Layer instance name a later connection op must
    // address. Matching by connection id (not by backend label) keeps two
    // connections on the same backend Layer distinguishable.
    let row = roots
        .iter()
        .find(|r| r.connection_id.as_ref() == Some(&conn.id));
    let root = match (conn.current_addresses.first(), row) {
        (Some(root), _) => root.clone(),
        // The connection did not echo a root; fall back to the row the router
        // published for it.
        (None, Some(row)) => row.root.clone(),
        (None, None) => {
            return Err(format!(
                "authenticated connection {:?} ({}) returned no current address and \
                 list_address_roots published no routing row for its connection id; verify \
                 that the backend publishes its root and the router forwards that row",
                conn.id, conn.backend_kind,
            ));
        }
    };
    Ok((root, row.and_then(|r| r.owning_target.clone())))
}

/// Where the harness `dlopen`s plugin cdylibs from.
///
/// `$OVSTORAGE_PLUGIN_DIR` still wins, because `make test-integration-python`
/// uses it to point both legs at one staging dir. But under
/// [`REQUIRE_TEST_PLUGINS`] it must name the SAME directory this binary was
/// built against: an ambient value inherited from another checkout's shell
/// would load that tree's plugins and report their behavior as this checkout's
/// coverage — a green run proving something about code under review nowhere.
/// A tree that genuinely stages elsewhere sets the build-time
/// `OVSTORAGE_INTEGRATION_PLUGIN_DIR_OVERRIDE` (see `build.rs`), which moves
/// the compiled-in default with it, so the two still agree.
fn plugin_dir() -> PathBuf {
    let staged = PathBuf::from(env!("OVSTORAGE_DEFAULT_PLUGIN_DIR"));
    let Some(ambient) = env("OVSTORAGE_PLUGIN_DIR").map(PathBuf::from) else {
        return staged;
    };
    if std::env::var(REQUIRE_TEST_PLUGINS).as_deref() == Ok("1") {
        // Compare resolved paths: `make` passes an absolute path built from
        // `$(CURDIR)`, which is the same directory reached by a symlinked or
        // `..`-relative spelling.
        let resolve = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        assert_eq!(
            resolve(&ambient),
            resolve(&staged),
            "{REQUIRE_TEST_PLUGINS}=1 but OVSTORAGE_PLUGIN_DIR={} is not this build's staging \
             directory {}. Unset it, point it at the staged dir, or rebuild with \
             OVSTORAGE_INTEGRATION_PLUGIN_DIR_OVERRIDE so both agree.",
            ambient.display(),
            staged.display(),
        );
    }
    ambient
}

// === the file backend's scratch root ===

/// Roots left behind by a run older than this are swept at startup.
const STALE_FILE_ROOT_AGE: Duration = Duration::from_secs(60 * 60);

/// Owns the file backend's scratch directory and removes it on drop.
///
/// `Drop` is the ownership statement, but it is NOT the only reclaim path and
/// must not be mistaken for one: the process-wide [`AppState`] lives in a
/// `static` `OnceCell`, and Rust never drops a `static`. So the guard also
/// sweeps roots left by earlier runs when it creates a new one — that is what
/// actually keeps `$TMPDIR` bounded, and it works for a run killed mid-test
/// (where no destructor of any kind would have run).
struct FileRoot(PathBuf);

impl FileRoot {
    fn create() -> Self {
        let parent = std::env::temp_dir().join("ovstorage-integration-tests");
        std::fs::create_dir_all(&parent).expect("create the file-backend scratch parent");
        sweep_stale_file_roots(&parent);
        let dir = parent.join(format!("run-{}-{}", std::process::id(), nanos()));
        std::fs::create_dir_all(&dir).expect("create the file-backend root");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for FileRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Best-effort removal of scratch roots older than [`STALE_FILE_ROOT_AGE`].
///
/// Age-based rather than "everything that is not mine" so two suites running
/// concurrently on a shared machine cannot delete each other's live root.
fn sweep_stale_file_roots(parent: &Path) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .and_then(|t| {
                SystemTime::now()
                    .duration_since(t)
                    .map_err(std::io::Error::other)
            })
            .is_ok_and(|age| age > STALE_FILE_ROOT_AGE);
        if stale {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

fn file_config(root: &Path) -> HashMap<String, ConfigValue> {
    let mut config = HashMap::new();
    config.insert(
        "root".into(),
        ConfigValue::String(root.to_string_lossy().into_owned()),
    );
    config
}

// === env resolution ===

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn env_any(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| env(key))
}

fn bundle(pairs: &[(&str, &str)]) -> SecretBundle {
    let mut b = SecretBundle::default();
    for (k, v) in pairs {
        b.fields.insert(
            (*k).into(),
            SecretValue::Bytes(SecretBytes(v.as_bytes().to_vec())),
        );
    }
    b
}

fn loopback_endpoint(var: &str, raw: String) -> String {
    let parsed = Url::parse(raw.trim())
        .unwrap_or_else(|error| panic!("{var} must be an absolute URL: {error}"));
    let loopback = parsed
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    assert!(
        matches!(parsed.scheme(), "http" | "https") && loopback,
        "{var} must use an HTTP(S) loopback IP endpoint"
    );
    raw.trim_end_matches('/').to_string()
}

/// Resolve dedicated emulator endpoints without consulting ambient cloud
/// fixture identity or credentials.
fn emulator_requests(
    azurite_endpoint: Option<String>,
    fake_gcs_endpoint: Option<String>,
) -> Vec<ResolvedRequest> {
    let mut requests = Vec::new();
    if let Some(endpoint) = azurite_endpoint {
        let endpoint = loopback_endpoint("OVSTORAGE_AZURITE_ENDPOINT", endpoint);
        let mut config = HashMap::new();
        config.insert(
            "account".into(),
            ConfigValue::String(AZURITE_ACCOUNT.to_string()),
        );
        config.insert(
            "container".into(),
            ConfigValue::String(AZURITE_CONTAINER.to_string()),
        );
        config.insert(
            "blob_endpoint".into(),
            ConfigValue::String(format!("{endpoint}/{AZURITE_ACCOUNT}")),
        );
        requests.push(ResolvedRequest {
            backend: Backend::Azure,
            access: Access::Default,
            origin: Origin::Emulator,
            kind: Backend::Azure.kind().to_string(),
            config,
            credentials: bundle(&[("account_key", AZURITE_ACCOUNT_KEY)]),
        });
    }
    if let Some(endpoint) = fake_gcs_endpoint {
        let endpoint = loopback_endpoint("OVSTORAGE_FAKE_GCS_ENDPOINT", endpoint);
        let mut config = HashMap::new();
        config.insert(
            "bucket".into(),
            ConfigValue::String(FAKE_GCS_BUCKET.to_string()),
        );
        config.insert("endpoint".into(), ConfigValue::String(endpoint));
        requests.push(ResolvedRequest {
            backend: Backend::Gcs,
            access: Access::Default,
            origin: Origin::Emulator,
            kind: Backend::Gcs.kind().to_string(),
            config,
            credentials: SecretBundle::default(),
        });
    }
    requests
}

fn resolve_emulator_requests() -> Vec<ResolvedRequest> {
    emulator_requests(
        env("OVSTORAGE_AZURITE_ENDPOINT"),
        env("OVSTORAGE_FAKE_GCS_ENDPOINT"),
    )
}

/// Centralized LIVE env → `(backend_kind, config, credentials)` resolution. Returns
/// `None` when the identifying config or required credentials are absent —
/// which is what makes an unconfigured backend skip rather than fail.
///
/// **Fixture identity is read from the environment and nothing else.** There is
/// no compiled-in account, container, bucket, or region: this crate ships in
/// the public source tree, so a "convenient" default naming a real fixture
/// would publish that fixture's name. It would also be a footgun — a default
/// turns "credentials happen to be in this shell" into live traffic against a
/// shared bucket nobody asked for. Absent fixture env is therefore
/// indistinguishable from absent credentials: both skip, visibly.
///
/// Dedicated emulator endpoints are resolved independently by
/// `resolve_emulator_requests`; setting one never suppresses this ambient
/// live resolution. The per-backend variables are documented in `README.md`. Internal fixture
/// values come from the credential mapper selected by `LIVE_ENV_SCRIPT`; a
/// caller may instead export the same contract directly.
///
/// Hugging Face resolves from the fixture variable alone: the backend is
/// anonymous-capable, so `OVSTORAGE_HUGGINGFACE_REPO_ID`, not a credential, is
/// what makes the target live (and what the forbid list guards against).
pub fn resolve_request(
    backend: Backend,
    access: Access,
) -> Option<(String, HashMap<String, ConfigValue>, SecretBundle)> {
    match backend {
        Backend::File => None,
        Backend::Azure => azure_request(access),
        Backend::S3 => s3_request(access),
        Backend::Gcs => gcs_request(access),
        Backend::Huggingface => huggingface_request(access),
    }
}

fn azure_request(access: Access) -> Option<(String, HashMap<String, ConfigValue>, SecretBundle)> {
    let (account, container) = match access {
        Access::Default => (
            env("OVSTORAGE_AZURE_ACCOUNT")?,
            env("OVSTORAGE_AZURE_CONTAINER")?,
        ),
        // Either half of the versioned fixture may be inherited from the
        // default one (the usual shape is one account, one versioning-enabled
        // container), but naming NEITHER means "this deployment has no
        // versioned Azure fixture": the version scenarios then skip instead of
        // running against a container that does not keep history and failing.
        Access::Versioned => {
            let account = env("OVSTORAGE_AZURE_VERSIONED_ACCOUNT");
            let container = env("OVSTORAGE_AZURE_VERSIONED_CONTAINER");
            if account.is_none() && container.is_none() {
                return None;
            }
            (
                account.or_else(|| env("OVSTORAGE_AZURE_ACCOUNT"))?,
                container.or_else(|| env("OVSTORAGE_AZURE_CONTAINER"))?,
            )
        }
        // HNS is a distinct account (hierarchical namespace is an account-level
        // property), so it never inherits the account — only the container name.
        Access::Hns => (
            env("OVSTORAGE_AZURE_HNS_ACCOUNT")?,
            env("OVSTORAGE_AZURE_HNS_CONTAINER").or_else(|| env("OVSTORAGE_AZURE_CONTAINER"))?,
        ),
    };

    let mut config = HashMap::new();
    config.insert("account".into(), ConfigValue::String(account));
    config.insert("container".into(), ConfigValue::String(container));
    if matches!(access, Access::Hns) {
        config.insert("hierarchical_namespace".into(), ConfigValue::Bool(true));
    }

    let credentials = {
        let account_key = match access {
            Access::Hns => env("OVSTORAGE_AZURE_HNS_ACCOUNT_KEY"),
            _ => env("OVSTORAGE_AZURE_ACCOUNT_KEY")
                .or_else(|| env("OMNI_STORAGE_SERVICE_AZURE_STORAGE_KEY_VERSIONED")),
        };
        if let Some(key) = account_key {
            bundle(&[("account_key", &key)])
        } else {
            let tenant = env_any(&[
                "OVSTORAGE_AZURE_TENANT_ID",
                "OMNI_STORAGE_SERVICE_AZURE_TENANT_ID",
            ])?;
            let client = env_any(&[
                "OVSTORAGE_AZURE_CLIENT_ID",
                "OMNI_STORAGE_SERVICE_AZURE_CLIENT_ID",
            ])?;
            let secret = env_any(&[
                "OVSTORAGE_AZURE_CLIENT_SECRET",
                "OMNI_STORAGE_SERVICE_AZURE_CLIENT_SECRET",
            ])?;
            bundle(&[
                ("tenant_id", &tenant),
                ("client_id", &client),
                ("client_secret", &secret),
            ])
        }
    };
    Some((Backend::Azure.kind().to_string(), config, credentials))
}

fn s3_request(access: Access) -> Option<(String, HashMap<String, ConfigValue>, SecretBundle)> {
    if matches!(access, Access::Hns) {
        return None;
    }
    let bucket = match access {
        // A separate, versioning-enabled bucket; unset means the version
        // scenarios skip rather than run against the unversioned primary.
        Access::Versioned => env("OVSTORAGE_S3_VERSIONED_BUCKET")?,
        _ => env("OVSTORAGE_S3_BUCKET")?,
    };
    let region = env_any(&["OVSTORAGE_S3_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"])?;

    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(bucket));
    config.insert("region".into(), ConfigValue::String(region));

    let access_key = env_any(&[
        "OVSTORAGE_S3_ACCESS_KEY_ID",
        "AWS_ACCESS_KEY_ID",
        "OMNI_STORAGE_SERVICE_AWS_ACCESS_KEY_ID",
    ])?;
    let secret_key = env_any(&[
        "OVSTORAGE_S3_SECRET_ACCESS_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "OMNI_STORAGE_SERVICE_AWS_SECRET_ACCESS_KEY",
    ])?;
    let mut credentials = bundle(&[
        ("aws_access_key_id", &access_key),
        ("aws_secret_access_key", &secret_key),
    ]);
    if let Some(token) = env_any(&["OVSTORAGE_S3_SESSION_TOKEN", "AWS_SESSION_TOKEN"]) {
        credentials.fields.insert(
            "aws_session_token".into(),
            SecretValue::Bytes(SecretBytes(token.into_bytes())),
        );
    }
    Some((Backend::S3.kind().to_string(), config, credentials))
}

fn gcs_request(access: Access) -> Option<(String, HashMap<String, ConfigValue>, SecretBundle)> {
    if matches!(access, Access::Hns) {
        return None;
    }
    let bucket = match access {
        // As with S3: object versioning is a per-bucket setting, so the
        // versioned target has to be named to exist.
        Access::Versioned => env("OVSTORAGE_GCS_VERSIONED_BUCKET")?,
        _ => env("OVSTORAGE_GCS_BUCKET")?,
    };

    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(bucket));

    let credentials = if let Some(key) = env("OVSTORAGE_GCS_SERVICE_ACCOUNT_KEY") {
        bundle(&[("service_account_key", &key)])
    } else {
        let file = env_any(&[
            "OVSTORAGE_GCS_CREDENTIALS_FILE",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ])?;
        bundle(&[("file_path", &file)])
    };
    Some((Backend::Gcs.kind().to_string(), config, credentials))
}

fn huggingface_request(
    access: Access,
) -> Option<(String, HashMap<String, ConfigValue>, SecretBundle)> {
    // One target: the Hub is read-only here, and versions are commits of the
    // same repo, not a second fixture.
    if !matches!(access, Access::Default) {
        return None;
    }
    let repo_id = env("OVSTORAGE_HUGGINGFACE_REPO_ID")?;

    let mut config = HashMap::new();
    config.insert("repo_id".into(), ConfigValue::String(repo_id));
    if let Some(repo_type) = env("OVSTORAGE_HUGGINGFACE_REPO_TYPE") {
        config.insert("repo_type".into(), ConfigValue::String(repo_type));
    }
    if let Some(revision) = env("OVSTORAGE_HUGGINGFACE_REVISION") {
        config.insert("revision".into(), ConfigValue::String(revision));
    }

    // Anonymous is the exercised path; a token only raises rate limits or
    // reaches a gated fixture. The descriptor's `${HF_TOKEN}` default applies
    // to TOML-loaded connections only, so the ambient fallback lives here.
    let credentials = match env_any(&["OVSTORAGE_HUGGINGFACE_TOKEN", "HF_TOKEN"]) {
        Some(token) => bundle(&[("token", &token)]),
        None => SecretBundle::default(),
    };
    Some((Backend::Huggingface.kind().to_string(), config, credentials))
}

// === skip + connect-failure registries ===

#[derive(Clone, Debug)]
struct ConnectFailure {
    backend: Backend,
    access: Access,
    origin: Origin,
    message: String,
}

impl ConnectFailure {
    fn line(&self) -> String {
        format!(
            "✗ CONNECT-FAILED [{}:{}:{}]: {}",
            self.backend.label(),
            self.access.label(),
            self.origin.label(),
            self.message
        )
    }
}

fn connect_failures() -> &'static Mutex<Vec<ConnectFailure>> {
    static FAILS: OnceLock<Mutex<Vec<ConnectFailure>>> = OnceLock::new();
    FAILS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Record a visible skip. libtest has no "skipped" state, so a skipped scenario
/// still reports `ok`; this prints an unmistakable line so a green run can't
/// hide "tested nothing".
///
/// On a target under an enforced `COVERAGE_BASELINE` row this PANICS instead
/// of printing. Every skip in the suite funnels through here — capability
/// gates, missing targets, mid-scenario `Unsupported` — which makes this the
/// one place that can turn "a required backend quietly ran less" into a
/// failure, whatever the reason. It fails the individual case rather than the
/// run so the log names the scenario that vanished; libtest's ordering
/// guarantees do not matter, because the check rides on the skip itself.
///
/// A binding leg whose ABI genuinely cannot express a scenario must NOT route
/// that through here — see `⊘ ABI-LIMITED` in `tests/cpp.rs`, which states the
/// limitation without claiming the backend failed to provide it.
pub fn skip(backend: Backend, access: Access, scenario: &str, why: &str) {
    if let Some(origin) = preferred_origin(backend, access)
        && let Some(row) = baseline_for(backend, access, origin)
        && row.requires(scenario)
    {
        let guard = match origin {
            Origin::Live => REQUIRE_LIVE_BACKENDS,
            Origin::Local | Origin::Emulator => REQUIRE_HERMETIC_BACKENDS,
        };
        panic!(
            "coverage baseline: [{}:{}:{}] {scenario} is required to RUN on this target \
             ({guard} names it), but it skipped: {why}. Either the \
             backend/fixture regressed, or the scenario genuinely no longer applies and \
             COVERAGE_BASELINE in ovstorage-integration-tests/src/lib.rs has to say so.",
            backend.label(),
            access.label(),
            origin.label(),
        );
    }
    eprintln!(
        "⊘ SKIPPED [{}:{}] {scenario}: {why}",
        backend.label(),
        access.label()
    );
}

fn record_connect_failure(backend: Backend, access: Access, origin: Origin, message: String) {
    let failure = ConnectFailure {
        backend,
        access,
        origin,
        message,
    };
    eprintln!("{}", failure.line());
    connect_failures().lock().unwrap().push(failure);
}

/// Why this connection does not count as connected, or `None` if it does.
///
/// `add_connection` returning `Ok` is NOT proof the credentials were accepted.
/// The contract lets a producer accept the request, park the connection as
/// [`ovstorage::ConnectionAuthState::AwaitingAuth`] and answer `Ok` — that is the shape a
/// REJECTED credential takes when the backend expects an interactive or
/// broker-mediated re-auth to follow. Treating that as connected breaks both
/// guards at once: [`REQUIRE_LIVE_BACKENDS`] reports a target that cannot do
/// any I/O as present (so every one of its scenarios fails one-by-one with an
/// auth error instead of the run naming the credential once), and
/// [`FORBID_LIVE_BACKENDS`] reports a live backend that DID receive an ambient
/// credential as absent.
///
/// `Anonymous` is accepted deliberately, not by omission: it is what the
/// credential-free `file` backend reports, and "no principal was needed" is a
/// successfully established connection.
fn auth_state_rejection(state: &ovstorage::ConnectionAuthState) -> Option<String> {
    use ovstorage::ConnectionAuthState as State;
    match state {
        State::Authenticated { .. } | State::Anonymous => None,
        State::AwaitingAuth {
            reason,
            last_attempt,
        } => Some(format!(
            "connection parked as AwaitingAuth (reason: {reason:?}); the credentials were not \
             accepted{}",
            match last_attempt.as_ref().and_then(|a| a.error.as_ref()) {
                Some(e) => format!(": {}", e.message()),
                None => String::new(),
            },
        )),
        State::AuthFailed { error, attempts } => Some(format!(
            "authentication failed after {attempts} attempt(s): {}",
            error.message(),
        )),
    }
}

/// Parse one `backend` / `backend:access` selector from a guard's list.
fn parse_target_selector(var: &str, raw: &str) -> (Backend, Option<Access>) {
    let (backend, access) = raw
        .split_once(':')
        .map_or((raw, None), |(b, a)| (b, Some(a)));
    let backend = match backend {
        "file" => Backend::File,
        "azure" => Backend::Azure,
        "s3" => Backend::S3,
        "gcs" => Backend::Gcs,
        "huggingface" => Backend::Huggingface,
        other => panic!("{var}: unknown backend {other:?}"),
    };
    let access = match access {
        None => None,
        Some("default") => Some(Access::Default),
        Some("versioned") => Some(Access::Versioned),
        Some("hns") => Some(Access::Hns),
        Some(other) => panic!("{var}: unknown target access {other:?}"),
    };
    (backend, access)
}

fn selectors(var: &str) -> Vec<(Backend, Option<Access>)> {
    let Ok(raw) = std::env::var(var) else {
        return Vec::new();
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|name| parse_target_selector(var, name))
        .collect()
}

fn selector_matches(
    selectors: &[(Backend, Option<Access>)],
    backend: Backend,
    access: Access,
) -> bool {
    selectors.iter().any(|(required_backend, required_access)| {
        *required_backend == backend && required_access.is_none_or(|want| want == access)
    })
}

fn preferred_origin_from(
    backend: Backend,
    access: Access,
    live: &[(Backend, Option<Access>)],
    hermetic: &[(Backend, Option<Access>)],
) -> Option<Origin> {
    let live = selector_matches(live, backend, access);
    let hermetic = selector_matches(hermetic, backend, access);
    assert!(
        !(live && hermetic),
        "{REQUIRE_LIVE_BACKENDS} and {REQUIRE_HERMETIC_BACKENDS} both require {}:{}; one scenario cannot validate two origins",
        backend.label(),
        access.label(),
    );
    if live {
        Some(Origin::Live)
    } else if hermetic {
        Some(if backend == Backend::File {
            Origin::Local
        } else {
            Origin::Emulator
        })
    } else {
        None
    }
}

fn preferred_origin(backend: Backend, access: Access) -> Option<Origin> {
    preferred_origin_from(
        backend,
        access,
        &selectors(REQUIRE_LIVE_BACKENDS),
        &selectors(REQUIRE_HERMETIC_BACKENDS),
    )
}

/// Fail app construction when [`REQUIRE_LIVE_BACKENDS`] names a live target
/// that did not connect. A backend-only requirement means its default target
/// must connect, and any attempted target for that backend must not have
/// failed. Checked once the connection table is known, rather than in an
/// end-of-suite test whose execution order libtest does not guarantee.
fn connection_gaps(
    available: &[(Backend, Access, Origin)],
    fails: &[ConnectFailure],
    required: &[(Backend, Option<Access>)],
    origin_for: impl Fn(Backend) -> Origin,
) -> (Vec<String>, Vec<String>) {
    let mut missing = Vec::new();
    let mut failed = Vec::new();
    for (backend, access) in required.iter().copied() {
        let origin = origin_for(backend);
        let required_access = access.unwrap_or(Access::Default);
        if !available.contains(&(backend, required_access, origin)) {
            missing.push(format!(
                "{}:{}:{}",
                backend.label(),
                required_access.label(),
                origin.label()
            ));
        }
        failed.extend(
            fails
                .iter()
                .filter(|f| {
                    f.backend == backend
                        && f.origin == origin
                        && access.is_none_or(|a| f.access == a)
                })
                .map(ConnectFailure::line),
        );
    }
    (missing, failed)
}

fn require_origin_connected(
    targets: &[Target],
    fails: &[ConnectFailure],
    var: &str,
    origin_for: impl Fn(Backend) -> Origin,
) {
    let available = targets
        .iter()
        .map(|target| (target.backend, target.access, target.origin))
        .collect::<Vec<_>>();
    let (missing, failed) = connection_gaps(&available, fails, &selectors(var), origin_for);
    assert!(
        missing.is_empty() && failed.is_empty(),
        "{var}: required target(s) not connected: {}; connect failures: {}",
        missing.join(", "),
        failed.join(" | "),
    );
}

fn require_connected(targets: &[Target]) {
    let fails = connect_failures().lock().unwrap().clone();
    require_origin_connected(targets, &fails, REQUIRE_LIVE_BACKENDS, |_| Origin::Live);
    require_origin_connected(targets, &fails, REQUIRE_HERMETIC_BACKENDS, |backend| {
        if backend == Backend::File {
            Origin::Local
        } else {
            Origin::Emulator
        }
    });
}

/// The inverse guard, and the reason a credential-free PR job can be trusted:
/// fail app construction when [`FORBID_LIVE_BACKENDS`] names a target that the
/// environment supplied a fixture AND credentials for.
///
/// "No cloud credentials are set" is not something a CI job can prove by
/// staying green — a leaked secret in the environment simply makes the run do
/// more, quietly. Asserting on what the environment resolved turns that into a
/// failure.
///
/// Checked on the RESOLVED requests rather than on the connections they would
/// have produced. Connecting first and rejecting afterwards would mean the
/// hermetic run had already authenticated to the very backend it is asserting
/// it never touches — [`resolve_request`] is pure env reads, so this is the
/// last point before any socket is opened. It also makes the guard independent
/// of whether the backend happened to be reachable: a resolved fixture plus a
/// resolved credential is the leak, whether or not the network answered.
fn forbid_resolved(requests: &[ResolvedRequest]) {
    let resolved = forbidden_resolved(requests, &selectors(FORBID_LIVE_BACKENDS));
    assert!(
        resolved.is_empty(),
        "{FORBID_LIVE_BACKENDS}: forbidden target(s) configured: {}. This run was supposed to \
         stay off the live services; the environment named a live fixture (and, where the \
         backend needs one, a credential) for them, so no connection was attempted.",
        resolved.join(", "),
    );
}

fn forbidden_resolved(
    requests: &[ResolvedRequest],
    forbidden: &[(Backend, Option<Access>)],
) -> Vec<String> {
    let mut resolved = Vec::new();
    for (backend, access) in forbidden.iter().copied() {
        resolved.extend(
            requests
                .iter()
                .filter(|request| {
                    request.origin == Origin::Live
                        && request.backend == backend
                        && access.is_none_or(|want| request.access == want)
                })
                .map(|request| {
                    format!(
                        "{}:{}:{}",
                        request.backend.label(),
                        request.access.label(),
                        request.origin.label()
                    )
                }),
        );
    }
    resolved
}

// === live-coverage baseline ===

/// One capability the baseline names, paired with the accessor that reads it,
/// so a violation can print the flag's own name rather than a position.
type CapabilityCheck = (&'static str, fn(&Capabilities) -> bool);

/// `capabilities![supports_write, supports_list]` → `&[CapabilityCheck]`.
///
/// A non-capturing closure coerces to a `fn` pointer in const position, so the
/// table stays a `const` — a reviewer reads field names, not accessor code.
macro_rules! capabilities {
    ($($flag:ident),* $(,)?) => {
        &[$((
            stringify!($flag),
            (|caps: &Capabilities| caps.$flag) as fn(&Capabilities) -> bool,
        )),*]
    };
}

/// What one live target is known to be able to do — the floor a run against it
/// has to clear.
///
/// ## Why a runtime-skip suite needs this
///
/// Every capability gate in `scenarios.rs` turns a missing flag into a PASSING
/// skip, and `REQUIRE_LIVE_BACKENDS` only asserts that a target connected. So
/// a backend that connects, authenticates and then advertises
/// `Capabilities::empty()` retires fifteen scenarios per target and the job
/// stays green: exactly the regression the live suite exists to catch, made
/// invisible by the mechanism that makes the suite portable.
///
/// This table is the explicit statement of what each fixture does today, so
/// "the coverage shrank" is a diff against a reviewable list instead of a
/// number nobody can check. It is enforced two ways:
///
/// - `require_baseline_capabilities` at app-construction time, so a wholesale
///   capability regression is reported once, up front, naming every lost flag.
/// - [`skip`], which PANICS instead of printing when a baselined scenario tries
///   to skip on a required target. That is the general net: it catches a skip
///   for any reason, including ones no capability flag predicts (an
///   `Unsupported` range read, an etag the backend stopped exposing).
///
/// ## Reading and editing a row
///
/// A row lists only what that fixture genuinely supports. `directory_ops` is
/// absent from every flat-store row and `check_access` from Azure's because
/// those are inapplicable, not missing — the point of enumerating scenarios
/// rather than counting them. `Access::Hns` has no row at all: that fixture is
/// optional (an ADLS Gen2 account most deployments do not have), so it is
/// governed by nothing but its own configuration.
///
/// When a scenario legitimately stops applying — a fixture is repointed, a
/// backend drops a feature on purpose — delete it from the row in the same
/// commit, and the deletion is the review conversation.
pub struct TargetBaseline {
    pub backend: Backend,
    pub access: Access,
    pub origin: Origin,
    /// Whether this row also owes the write-family floor,
    /// `CORE_OBJECT_SCENARIOS`, on top of its explicit `scenarios`.
    /// Versioned rows and read-only rows opt out: their whole floor is the
    /// explicit list.
    pub write_family: bool,
    /// Capabilities this fixture is known to advertise. Losing one is a
    /// failure even when no scenario has skipped yet.
    pub capabilities: &'static [CapabilityCheck],
    /// Scenarios that MUST execute against this target — no skips.
    pub scenarios: &'static [&'static str],
    /// Scenarios this target does not owe: the production backend advertises
    /// them but the pinned emulator does not implement them faithfully, or the
    /// backend refuses the verb by contract. Live rows keep this empty.
    pub excluded_scenarios: &'static [&'static str],
}

/// The write family: scenarios every `write_family` row runs. Named once
/// because the writable rows share it; the per-row lists then hold only what
/// makes that fixture different. Read-only rows opt out via
/// `write_family: false` and name their whole floor — the read-family
/// scenarios plus `error_path_not_found`, the one core scenario that applies
/// to a backend that cannot write — in `scenarios` directly.
const CORE_OBJECT_SCENARIOS: &[&str] = &[
    "write_stat_read",
    "delete",
    "list_prefix_delimiter",
    "list_recursive_and_pagination",
    "copy",
    "rename",
    "update_metadata",
    "attribution_round_trip",
    "message_annotation",
    "error_path_not_found",
    "range_read",
    "read_stream_and_materialize",
    "key_encoding",
    "conditional_write",
    "write_stream",
];

/// The floor for every target this suite knows how to configure.
///
/// Transcribed from runs against the named live or emulator fixture, so the
/// rows are what that fixture actually did rather than what a plugin's
/// `capabilities()` was read to promise.
const COVERAGE_BASELINE: &[TargetBaseline] = &[
    TargetBaseline {
        backend: Backend::File,
        access: Access::Default,
        origin: Origin::Local,
        write_family: true,
        capabilities: capabilities![
            supports_write,
            supports_write_stream,
            supports_delete,
            supports_list,
            supports_recursive_list,
            supports_create_directory,
            supports_delete_directory,
            supports_access_check,
            supports_no_overwrite_write,
            supports_if_match_write,
            // The local backend is the suite's only real-directory target when
            // no ADLS Gen2 account is configured, which is the usual case; if
            // this went false, `directory_ops` would run nowhere.
            has_real_directories,
        ],
        scenarios: &["check_access", "directory_ops"],
        // The file backend stores no user metadata: `update_metadata` answers
        // `Unsupported` by contract, and a write that carries a map is refused
        // the same way, so the two scenarios that write user metadata skip
        // here by design too.
        excluded_scenarios: &[
            "update_metadata",
            "attribution_round_trip",
            "message_annotation",
        ],
    },
    TargetBaseline {
        backend: Backend::Azure,
        access: Access::Default,
        origin: Origin::Live,
        write_family: true,
        capabilities: capabilities![
            supports_write,
            supports_write_stream,
            supports_write_redirect,
            supports_delete,
            supports_list,
            supports_recursive_list,
            supports_create_directory,
            supports_delete_directory,
            supports_native_metadata_patch,
            supports_no_overwrite_write,
            supports_if_match_write,
            supports_server_side_copy,
            // Load-bearing beyond the version scenarios: the cleanup guards
            // read this flag to decide whether a tracked address needs its
            // retained versions purged. Losing it turns every live run into a
            // permanent addition to the container.
            supports_version_listing,
        ],
        // `check_access` is absent because the Azure plugin advertises
        // supports_access_check=false; `directory_ops` because a flat container
        // has no real directories.
        scenarios: &["directory_marker_ops"],
        excluded_scenarios: &[],
    },
    TargetBaseline {
        backend: Backend::Azure,
        access: Access::Versioned,
        origin: Origin::Live,
        write_family: false,
        capabilities: capabilities![supports_write, supports_version_listing],
        scenarios: &["list_versions", "get_latest_version"],
        excluded_scenarios: &[],
    },
    TargetBaseline {
        backend: Backend::S3,
        access: Access::Default,
        origin: Origin::Live,
        write_family: true,
        capabilities: capabilities![
            supports_write,
            supports_write_stream,
            supports_write_redirect,
            supports_delete,
            supports_list,
            supports_recursive_list,
            supports_create_directory,
            supports_delete_directory,
            supports_access_check,
            // S3 has no metadata-patch API, so `update_metadata` reaches it
            // only through the rewrite emulation.
            supports_metadata_rewrite_emulation,
            supports_no_overwrite_write,
            supports_if_match_write,
            supports_server_side_copy,
            supports_version_listing,
        ],
        scenarios: &["check_access", "directory_marker_ops"],
        excluded_scenarios: &[],
    },
    TargetBaseline {
        backend: Backend::S3,
        access: Access::Versioned,
        origin: Origin::Live,
        write_family: false,
        capabilities: capabilities![supports_write, supports_version_listing],
        scenarios: &["list_versions", "get_latest_version"],
        excluded_scenarios: &[],
    },
    TargetBaseline {
        backend: Backend::Gcs,
        access: Access::Default,
        origin: Origin::Live,
        write_family: true,
        capabilities: capabilities![
            supports_write,
            supports_write_stream,
            supports_write_redirect,
            supports_delete,
            supports_list,
            supports_recursive_list,
            supports_create_directory,
            supports_delete_directory,
            supports_access_check,
            supports_native_metadata_patch,
            supports_no_overwrite_write,
            supports_if_match_write,
            supports_server_side_copy,
            supports_version_listing,
        ],
        scenarios: &["check_access", "directory_marker_ops"],
        excluded_scenarios: &[],
    },
    TargetBaseline {
        backend: Backend::Gcs,
        access: Access::Versioned,
        origin: Origin::Live,
        write_family: false,
        capabilities: capabilities![supports_write, supports_version_listing],
        scenarios: &["list_versions", "get_latest_version"],
        excluded_scenarios: &[],
    },
    TargetBaseline {
        backend: Backend::Huggingface,
        access: Access::Default,
        origin: Origin::Live,
        write_family: false,
        capabilities: capabilities![
            supports_list,
            supports_recursive_list,
            has_real_directories,
            supports_version_listing,
        ],
        // A read-only row opts out of the write-family floor, so its whole
        // floor is this list — including error_path_not_found, the one core
        // scenario that applies to a backend that cannot write.
        scenarios: &[
            "error_path_not_found",
            "read_only_list_stat_read",
            "read_only_range_read",
            "read_only_version_pinning",
        ],
        excluded_scenarios: &[],
    },
    TargetBaseline {
        backend: Backend::Azure,
        access: Access::Default,
        origin: Origin::Emulator,
        write_family: true,
        capabilities: capabilities![
            supports_write,
            supports_write_stream,
            supports_write_redirect,
            supports_delete,
            supports_list,
            supports_recursive_list,
            supports_create_directory,
            supports_delete_directory,
            supports_native_metadata_patch,
            supports_no_overwrite_write,
            supports_if_match_write,
            supports_server_side_copy,
        ],
        scenarios: &["directory_marker_ops"],
        excluded_scenarios: &[],
    },
    TargetBaseline {
        backend: Backend::Gcs,
        access: Access::Default,
        origin: Origin::Emulator,
        write_family: true,
        capabilities: capabilities![
            supports_write,
            supports_write_stream,
            supports_write_redirect,
            supports_delete,
            supports_list,
            supports_recursive_list,
            supports_create_directory,
            supports_delete_directory,
            supports_native_metadata_patch,
            supports_no_overwrite_write,
            supports_if_match_write,
            supports_server_side_copy,
        ],
        scenarios: &[],
        // The pinned server exercises real JSON request composition,
        // pagination, redirects, reads/writes, copy/rename, range reads, and
        // streaming. It advertises these four production capabilities too,
        // but does not reproduce their service semantics faithfully.
        excluded_scenarios: &[
            "check_access",
            "conditional_write",
            "directory_marker_ops",
            "update_metadata",
        ],
    },
];

impl TargetBaseline {
    /// Whether `scenario` must run against this target. Rows in the write
    /// family also own [`CORE_OBJECT_SCENARIOS`]; versioned and read-only rows
    /// carry only their explicit scenarios.
    fn requires(&self, scenario: &str) -> bool {
        if self.excluded_scenarios.contains(&scenario) {
            return false;
        }
        if self.scenarios.contains(&scenario) {
            return true;
        }
        self.write_family && CORE_OBJECT_SCENARIOS.contains(&scenario)
    }
}

/// Why this target's pinned emulator cannot validate `scenario`.
///
/// The same baseline row decides both whether this skip is allowed and whether
/// it is taken, so the Rust, C++, and anti-vacuity paths cannot disagree.
pub fn scenario_exclusion(target: &Target, scenario: &str) -> Option<&'static str> {
    let row = baseline_for(target.backend, target.access, target.origin)?;
    row.excluded_scenarios.contains(&scenario).then_some(
        "excluded by this target's coverage baseline: the pinned emulator does not implement the \
         production semantic faithfully, or the backend refuses the verb by contract",
    )
}

/// Assert that a runner's actual macro invocation is exactly the scenario
/// floor expressed by [`CORE_OBJECT_SCENARIOS`] and [`COVERAGE_BASELINE`].
///
/// This takes the invocation list as data rather than comparing the baseline
/// to another hand-maintained copy. Both `tests/live.rs` and `tests/cpp.rs`
/// call it from tests emitted by their suite macros, so deleting a case from
/// either runner leaves the baseline naming a case that no test invokes and
/// fails in that runner's own binary.
#[doc(hidden)]
pub fn assert_scenario_contract(actual: &[&str]) {
    let actual_set: BTreeSet<&str> = actual.iter().copied().collect();
    assert_eq!(
        actual_set.len(),
        actual.len(),
        "scenario invocation contains duplicate names: {actual:?}"
    );

    let mut expected: BTreeSet<&str> = CORE_OBJECT_SCENARIOS.iter().copied().collect();
    for row in COVERAGE_BASELINE {
        expected.extend(row.scenarios.iter().copied());
    }
    assert_eq!(
        actual_set,
        expected,
        "runner scenario invocation must exactly match the coverage baseline; only invoked: \
         {:?}; only baselined: {:?}",
        actual_set.difference(&expected).collect::<Vec<_>>(),
        expected.difference(&actual_set).collect::<Vec<_>>(),
    );
}

fn baseline_for(
    backend: Backend,
    access: Access,
    origin: Origin,
) -> Option<&'static TargetBaseline> {
    COVERAGE_BASELINE
        .iter()
        .find(|row| row.backend == backend && row.access == access && row.origin == origin)
}

/// Whether [`REQUIRE_LIVE_BACKENDS`] puts this target under its baseline.
///
/// A bare `azure` selector covers every access of that backend, not just
/// `default`: "azure must be live" and "azure's versioned fixture quietly
/// stopped being named, so the version scenarios evaporated" are the same
/// failure to a reader of a green log. A deployment with no versioned fixture
/// says so by not requiring that backend at all, or by requiring the exact
/// target (`azure:default`).
fn baseline_enforced(backend: Backend, access: Access, origin: Origin) -> bool {
    preferred_origin(backend, access) == Some(origin)
}

/// Fail app construction when a required target stopped advertising a
/// capability its baseline row names.
///
/// Up front and aggregated, for the same reason [`require_connected`] is: one
/// failure listing every lost flag is diagnosable, fifteen scenario failures
/// saying "missing capability supports_write" are noise around a single cause.
fn require_baseline_capabilities(targets: &[Target]) {
    let mut lost = Vec::new();
    for target in targets {
        if !baseline_enforced(target.backend, target.access, target.origin) {
            continue;
        }
        let Some(row) = baseline_for(target.backend, target.access, target.origin) else {
            continue;
        };
        for (name, advertised) in row.capabilities {
            if !advertised(&target.caps) {
                lost.push(format!(
                    "{}:{}:{} no longer advertises {name}",
                    target.backend.label(),
                    target.access.label(),
                    target.origin.label(),
                ));
            }
        }
    }
    assert!(
        lost.is_empty(),
        "coverage baseline: {}. Every scenario gated on those flags would have skipped while the \
         run stayed green. Fix the backend/fixture, or edit COVERAGE_BASELINE in \
         ovstorage-integration-tests/src/lib.rs and say why in the commit.",
        lost.join("; "),
    );
}

// === panic-safe cleanup ===

/// How thoroughly a tracked address has to be reclaimed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Reclaim {
    /// One unpinned delete. Correct for a root that keeps no history.
    Current,
    /// Every version the root retained, not just the current one.
    ///
    /// This is not a refinement, it is the difference between a bounded fixture
    /// and an unbounded one. On a version-enabled Azure container an unpinned
    /// delete removes the CURRENT blob and retains every version of it, while
    /// each write, server-side copy and metadata patch mints another. A suite
    /// that only deletes the current blob therefore leaves permanent residue on
    /// every run, and the container grows for as long as CI runs — which is
    /// what the default Azure target does today, because it is pointed at the
    /// same version-enabled container as the versioned one.
    AllVersions,
}

impl Reclaim {
    /// Objects on a root that can enumerate versions have to be purged by
    /// version, whether or not the *scenario* was about versioning: the
    /// retention is a property of the container, not of the test.
    fn for_objects(caps: &Capabilities) -> Self {
        if caps.supports_version_listing {
            Self::AllVersions
        } else {
            Self::Current
        }
    }
}

/// Best-effort reclaim of one address, including versions a version-enabled
/// root retained. Public because the C++ leg sweeps its own driver's residue.
///
/// Never panics and never fails a test — a cleanup that can fail a run is worse
/// than none, because it converts fixture flakiness into red builds. But a
/// silent net that stopped working is exactly how a fixture starts growing
/// without bound, so anything it could not reclaim goes to stderr.
pub async fn reclaim_object(target: &Target, address: Url) {
    reclaim(&target.stack, address, Reclaim::for_objects(&target.caps)).await
}

/// The directory counterpart of [`reclaim_object`]: `delete_directory`, plus
/// the marker object's version history where the root keeps one.
pub async fn reclaim_directory(target: &Target, dir: Url) {
    reclaim_dir(&target.stack, dir, marker_reclaim(&target.caps)).await
}

/// How a root's directory MARKER has to be reclaimed.
///
/// A real-directory root (file, ADLS Gen2 HNS) backs a directory with an inode:
/// `delete_directory` is the whole reclaim and there is no version history. A
/// flat store backs it with an empty marker BLOB that versions like any other
/// object, so on a version-enabled container `delete_directory` alone leaves
/// one retained version behind per run.
fn marker_reclaim(caps: &Capabilities) -> Reclaim {
    if caps.has_real_directories {
        Reclaim::Current
    } else {
        Reclaim::for_objects(caps)
    }
}

async fn reclaim_dir(stack: &Arc<Stack>, dir: Url, marker: Reclaim) {
    let marker_address = directory_marker_address(&dir);
    let deleted = stack
        .delete_directory(dir.clone(), DeleteDirectoryOptions, None)
        .await;
    report_cleanup(deleted, &dir, "delete_directory");
    if marker == Reclaim::AllVersions {
        // `delete_directory` removed the marker object itself; this reclaims
        // the versions it left.
        reclaim(stack, marker_address, Reclaim::AllVersions).await;
    }
}

async fn reclaim(stack: &Arc<Stack>, address: Url, mode: Reclaim) {
    if mode == Reclaim::Current {
        report_cleanup(
            stack
                .delete(address.clone(), DeleteOptions::default(), None)
                .await,
            &address,
            "delete",
        );
        return;
    }

    // Pass 1: delete every version the service will name. On S3 and GCS this is
    // the whole job — any version, including the live one, can be deleted by
    // id, and going through the unpinned address instead would only add a
    // delete marker (S3) to the history we are trying to remove.
    let first = sweep_versions(stack, &address).await;
    if first.listed > 0 && first.failures.is_empty() {
        return;
    }

    // Two ways to arrive here, both needing the unpinned delete:
    //
    // - Nothing was listed: the root advertises version listing but this
    //   fixture does not retain versions (all three cloud plugins advertise the
    //   flag unconditionally, so the unversioned S3 bucket lands here), or the
    //   object never existed. A plain delete is the right and only reclaim.
    // - A pinned delete was refused: Azure answers 403
    //   `OperationNotAllowedOnRootBlob` for the CURRENT version, which cannot be
    //   deleted by id at all. Removing the root blob demotes it to an ordinary
    //   version, which pass 2 then deletes. Verified against the live fixture.
    report_cleanup(
        stack
            .delete(address.clone(), DeleteOptions::default(), None)
            .await,
        &address,
        "delete",
    );
    if first.listed > 0 {
        for (address, message) in sweep_versions(stack, &address).await.failures {
            eprintln!("⚠ CLEANUP-FAILED delete {address}: {message}");
        }
    }
}

/// What one version-listing pass found and could not remove.
#[derive(Default)]
struct VersionSweep {
    listed: usize,
    failures: Vec<(Url, String)>,
}

/// Upper bound on the version-listing pages one sweep will walk.
///
/// The walk normally ends on the service's own exhausted continuation token;
/// this only bites if a backend keeps handing one back (or hands back the same
/// one forever). That has to be bounded rather than trusted, because the sweep
/// runs from a `Drop` guard on a cleanup thread: an unbounded loop there does
/// not fail a test, it hangs the process after the suite has otherwise
/// finished. The bound is far above anything this suite can mint — the busiest
/// scenario writes a handful of versions to one key, and a page is typically
/// hundreds — so reaching it means the pagination contract is broken, and it
/// says so instead of exiting quietly.
const MAX_VERSION_PAGES: usize = 100;

/// Delete every version-pinned address the root lists for `address`.
///
/// Walks EVERY page. One page is not the history: `list_versions` pages like
/// any other listing, so stopping at the first response silently leaves the
/// tail of a long-lived key's versions in the fixture — the same unbounded
/// growth [`Reclaim::AllVersions`] exists to prevent, just further out.
///
/// Failures are returned rather than printed: the first pass is EXPECTED to
/// fail on Azure's current version, and reporting that would train readers to
/// ignore the line that matters.
async fn sweep_versions(stack: &Arc<Stack>, address: &Url) -> VersionSweep {
    let mut sweep = VersionSweep::default();
    let mut page_token = None;
    for _ in 0..MAX_VERSION_PAGES {
        let page = ovstorage::Layer::list_versions(
            stack.as_ref(),
            Request::new(ListVersionsRequest {
                address: address.clone(),
                options: ListVersionsOptions {
                    page_token: page_token.take(),
                    ..ListVersionsOptions::default()
                },
            }),
            None,
        )
        .await;
        let (items, next_page_token) = match page {
            Ok(page) => (page.items, page.next_page_token),
            Err(e) => {
                if e.code() != ErrorCode::NotFound {
                    eprintln!("⚠ CLEANUP-FAILED list_versions {address}: {}", e.message());
                }
                return sweep;
            }
        };
        for version in items.into_iter().filter(|v| v.version.is_some()) {
            sweep.listed += 1;
            if let Err(e) = stack
                .delete(version.address.clone(), DeleteOptions::default(), None)
                .await
                && e.code() != ErrorCode::NotFound
            {
                sweep
                    .failures
                    .push((version.address, e.message().to_string()));
            }
        }
        match next_page_token {
            // Deleting the entries a page named can itself shorten the listing,
            // so the token — not a computed offset — is what advances.
            Some(token) => page_token = Some(token),
            None => return sweep,
        }
    }
    eprintln!(
        "⚠ CLEANUP-FAILED list_versions {address}: stopped after {MAX_VERSION_PAGES} pages with a \
         continuation token still outstanding; retained versions were left behind"
    );
    sweep
}

/// A cleanup delete that failed for a reason other than "already gone".
fn report_cleanup(result: ovstorage::Result<()>, address: &Url, op: &str) {
    if let Err(e) = result
        && e.code() != ErrorCode::NotFound
    {
        eprintln!("⚠ CLEANUP-FAILED {op} {address}: {}", e.message());
    }
}

/// Run `body` on the shared runtime from a `Drop` impl.
///
/// A fresh thread, because `block_on` inside a runtime context panics and every
/// guard here drops on a test thread that is already inside one.
fn cleanup_blocking<F>(body: F)
where
    F: FnOnce(tokio::runtime::Handle) + Send + 'static,
{
    let handle = runtime().handle().clone();
    let _ = std::thread::spawn(move || body(handle)).join();
}

/// RAII guard that best-effort reclaims tracked addresses on drop, so a
/// scenario that panics mid-run doesn't leak objects — including the versions a
/// version-enabled root kept behind each one.
pub struct TempKeys {
    stack: Arc<Stack>,
    reclaim: Reclaim,
    keys: Vec<Url>,
}

impl TempKeys {
    pub fn new(target: &Target) -> Self {
        Self {
            stack: target.stack.clone(),
            reclaim: Reclaim::for_objects(&target.caps),
            keys: Vec::new(),
        }
    }

    /// Track an address for best-effort cleanup on drop.
    pub fn track(&mut self, addr: Url) {
        self.keys.push(addr);
    }
}

impl Drop for TempKeys {
    fn drop(&mut self) {
        if self.keys.is_empty() {
            return;
        }
        let stack = self.stack.clone();
        let mode = self.reclaim;
        let keys = std::mem::take(&mut self.keys);
        cleanup_blocking(move |handle| {
            handle.block_on(async move {
                for key in keys {
                    reclaim(&stack, key, mode).await;
                }
            });
        });
    }
}

/// RAII guard that best-effort reclaims tracked directories on drop.
pub struct TempDirs {
    stack: Arc<Stack>,
    marker_reclaim: Reclaim,
    dirs: Vec<Url>,
}

impl TempDirs {
    pub fn new(target: &Target) -> Self {
        Self {
            stack: target.stack.clone(),
            marker_reclaim: marker_reclaim(&target.caps),
            dirs: Vec::new(),
        }
    }

    pub fn track(&mut self, addr: Url) {
        self.dirs.push(addr);
    }
}

impl Drop for TempDirs {
    fn drop(&mut self) {
        if self.dirs.is_empty() {
            return;
        }
        let stack = self.stack.clone();
        let marker = self.marker_reclaim;
        let dirs = std::mem::take(&mut self.dirs);
        cleanup_blocking(move |handle| {
            handle.block_on(async move {
                for dir in dirs {
                    reclaim_dir(&stack, dir, marker).await;
                }
            });
        });
    }
}

/// The blob a flat store backs `dir` with: the key plus a trailing `/`.
///
/// Addressed explicitly because version listing is per-object and matches the
/// key exactly — asking for versions of `…/adir` finds nothing, because the
/// marker is named `…/adir/`.
fn directory_marker_address(dir: &Url) -> Url {
    if dir.as_str().ends_with('/') {
        return dir.clone();
    }
    Url::parse(&format!("{dir}/")).unwrap_or_else(|_| dir.clone())
}

/// RAII cleanup for the version scenarios: the pins they read, plus every
/// version behind each tracked base key.
pub struct VersionedTempKeys {
    stack: Arc<Stack>,
    bases: Vec<Url>,
    pinned: Vec<Url>,
}

impl VersionedTempKeys {
    pub fn new(target: &Target) -> Self {
        Self {
            stack: target.stack.clone(),
            bases: Vec::new(),
            pinned: Vec::new(),
        }
    }

    pub fn track_base(&mut self, addr: Url) {
        self.bases.push(addr);
    }

    pub fn track_pinned(&mut self, addr: Url) {
        self.pinned.push(addr);
    }
}

impl Drop for VersionedTempKeys {
    fn drop(&mut self) {
        if self.bases.is_empty() && self.pinned.is_empty() {
            return;
        }
        let stack = self.stack.clone();
        let bases = std::mem::take(&mut self.bases);
        let pinned = std::mem::take(&mut self.pinned);
        cleanup_blocking(move |handle| {
            handle.block_on(async move {
                // Pins first: a pinned address may belong to a base this guard
                // never saw. `reclaim` then finishes the base, which on Azure
                // is the only way to remove the current version at all.
                for address in pinned {
                    let _ = stack.delete(address, DeleteOptions::default(), None).await;
                }
                for base in bases {
                    reclaim(&stack, base, Reclaim::AllVersions).await;
                }
            });
        });
    }
}

// === misc helpers ===

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Per-run unique key prefix so parallel cases / prior runs never collide.
pub fn unique_prefix(scenario: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "ovstorage-it/{scenario}/{}-{}-{n}/",
        std::process::id(),
        nanos(),
    )
}

/// Install a `tracing` subscriber once so plugin events are visible under
/// `--nocapture` (filtered by `RUST_LOG`, defaulting to `warn`).
pub fn init_test_tracing() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::EnvFilter;
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_test_writer()
            .try_init();
    });
}

/// Expand the shared scenario contract into one `#[test]` per
/// `(backend, scenario)`. Every case runs under `cargo test`; an unconfigured
/// backend's cases skip at runtime (see [`skip`]). Each scenario is
/// `async fn(&AppState, Backend)` and picks/gates its own target.
#[macro_export]
macro_rules! app_suite {
    (backends: [$($backend:ident),* $(,)?], scenarios: $scenarios:tt $(,)?) => {
        $( $crate::app_suite!(@backend $backend, $scenarios); )*
        $crate::app_suite!(@contract_test $scenarios);
    };
    (@backend $backend:ident, [$($scenario:ident),* $(,)?]) => {
        #[allow(non_snake_case)]
        mod $backend {
            $(
                #[test]
                fn $scenario() {
                    $crate::block_on(async {
                        let app = $crate::app().await;
                        $crate::scenarios::$scenario(app, $crate::Backend::$backend).await;
                    });
                }
            )*
        }
    };
    (@contract_test [$($scenario:ident),* $(,)?]) => {
        #[test]
        fn scenario_invocation_matches_coverage_baseline() {
            $crate::assert_scenario_contract(&[$(stringify!($scenario)),*]);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage::{
        AddressVisibility, AuthAttempt, AuthReason, ConnectionAuthState, ConnectionId,
        ConnectionSource, Error, RangeReadStrategy, RootInfo, RouteSource,
    };

    fn authenticated_connection(id: &str, current_addresses: Vec<Url>) -> Connection {
        Connection {
            id: ConnectionId(id.into()),
            backend_kind: "test-cloud".into(),
            display_name: "test connection".into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses,
            auth_state: ConnectionAuthState::Authenticated {
                last_authenticated_at: SystemTime::now(),
                expires_at: None,
            },
            last_probed: None,
            user_metadata: Default::default(),
            owning_target: None,
        }
    }

    fn routed_root(id: &str, root: &str, owning_target: &str) -> RootInfo {
        let connection_id = ConnectionId(id.into());
        RootInfo {
            root: Url::parse(root).expect("test root parses"),
            display_name: None,
            layer_kind: ROUTER_KIND.into(),
            connection_id: Some(connection_id.clone()),
            owning_target: Some(owning_target.into()),
            capabilities: Capabilities::empty(),
            range_read_strategy: RangeReadStrategy::default(),
            source: RouteSource::ConnectionContributed { connection_id },
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: None,
            user_metadata: Default::default(),
        }
    }

    #[test]
    fn target_route_uses_the_connections_current_address() {
        let expected = Url::parse("test://current/").unwrap();
        let connection = authenticated_connection("current-id", vec![expected.clone()]);

        let (root, owning_target) = target_route(&connection, Ok(&[])).expect("current address");

        assert_eq!(root, expected);
        assert_eq!(owning_target, None);
    }

    #[test]
    fn target_route_falls_back_to_the_router_row_for_the_connection_id() {
        let connection = authenticated_connection("wanted-id", Vec::new());
        let roots = [
            routed_root("other-id", "test://other/", "other_backend"),
            routed_root("wanted-id", "test://wanted/", "wanted_backend"),
        ];

        let (root, owning_target) =
            target_route(&connection, Ok(&roots)).expect("matching router row");

        assert_eq!(root, Url::parse("test://wanted/").unwrap());
        assert_eq!(owning_target.as_deref(), Some("wanted_backend"));
    }

    #[test]
    fn target_route_explains_a_successful_connection_without_any_route() {
        let connection = authenticated_connection("orphaned-id", Vec::new());

        let error = target_route(&connection, Ok(&[])).expect_err("missing route is a failure");

        assert!(error.contains("orphaned-id"), "{error}");
        assert!(error.contains("no current address"), "{error}");
        assert!(error.contains("no routing row"), "{error}");
        assert!(error.contains("backend publishes its root"), "{error}");
        assert!(error.contains("router forwards that row"), "{error}");
    }

    #[test]
    fn target_route_needs_root_table_success_only_for_the_fallback() {
        let expected = Url::parse("test://current/").unwrap();
        let with_current = authenticated_connection("current-id", vec![expected.clone()]);
        let without_current = authenticated_connection("fallback-id", Vec::new());

        let (root, owning_target) = target_route(
            &with_current,
            Err("list_address_roots failed: router unavailable"),
        )
        .expect("a current address remains usable");
        assert_eq!(root, expected);
        assert_eq!(owning_target, None);

        let error = target_route(
            &without_current,
            Err("list_address_roots failed: router unavailable"),
        )
        .expect_err("fallback needs the root table");
        assert_eq!(error, "list_address_roots failed: router unavailable");
    }

    /// The states this suite is willing to call "connected".
    ///
    /// Pinned here because the live path cannot produce the interesting one on
    /// demand: a rejected credential surfaces as `AwaitingAuth` only when the
    /// backend expects an interactive or broker-mediated re-auth to follow, and
    /// no fixture in CI is configured that way. Without this test the branch
    /// that stops a parked connection from counting as a live target would be
    /// exercised by nothing.
    #[test]
    fn only_authenticated_or_anonymous_counts_as_connected() {
        assert!(
            auth_state_rejection(&ConnectionAuthState::Authenticated {
                last_authenticated_at: SystemTime::now(),
                expires_at: None,
            })
            .is_none()
        );
        // The credential-free file backend.
        assert!(auth_state_rejection(&ConnectionAuthState::Anonymous).is_none());

        let parked = auth_state_rejection(&ConnectionAuthState::AwaitingAuth {
            reason: AuthReason::CredentialsRotated,
            last_attempt: Some(AuthAttempt {
                at: SystemTime::now(),
                error: Some(Error::new(ErrorCode::PermissionDenied, "403 from the STS")),
            }),
        })
        .expect("AwaitingAuth is not a connected target");
        assert!(parked.contains("CredentialsRotated"), "{parked}");
        assert!(parked.contains("403 from the STS"), "{parked}");

        let failed = auth_state_rejection(&ConnectionAuthState::AuthFailed {
            error: Error::new(ErrorCode::PermissionDenied, "bad account key"),
            attempts: 3,
        })
        .expect("AuthFailed is not a connected target");
        assert!(failed.contains("bad account key"), "{failed}");
    }

    /// A version row must not drag in the core object scenarios: the versioned
    /// fixtures are addressed only by the two version scenarios.
    #[test]
    fn version_rows_require_only_version_scenarios() {
        let row =
            baseline_for(Backend::S3, Access::Versioned, Origin::Live).expect("s3:versioned row");
        assert!(row.requires("list_versions"));
        assert!(row.requires("get_latest_version"));
        assert!(!row.requires("write_stat_read"));

        let flat =
            baseline_for(Backend::S3, Access::Default, Origin::Live).expect("s3:default row");
        assert!(flat.requires("write_stat_read"));
        assert!(flat.requires("check_access"));
        // Inapplicable, not missing: a flat bucket has no real directories.
        assert!(!flat.requires("directory_ops"));
        assert!(!flat.requires("list_versions"));
    }

    /// A read-only row owes nothing from the write-family core except what it
    /// names itself — and it names error_path_not_found plus the three read
    /// scenarios.
    #[test]
    fn read_only_rows_require_only_their_read_scenarios() {
        let row = baseline_for(Backend::Huggingface, Access::Default, Origin::Live)
            .expect("huggingface:default row");
        assert!(!row.write_family);
        for name in [
            "error_path_not_found",
            "read_only_list_stat_read",
            "read_only_range_read",
            "read_only_version_pinning",
        ] {
            assert!(row.requires(name), "{name}");
        }
        assert!(!row.requires("write_stat_read"));
        assert!(!row.requires("range_read"));
        assert!(!row.requires("list_versions"));
    }

    /// The read family belongs only to rows that own it explicitly; a
    /// write-family row must not silently inherit it.
    #[test]
    fn write_family_rows_do_not_require_the_read_only_scenarios() {
        let row = baseline_for(Backend::S3, Access::Default, Origin::Live).expect("s3:default row");
        assert!(row.write_family);
        assert!(!row.requires("read_only_list_stat_read"));
        assert!(!row.requires("read_only_range_read"));
        assert!(!row.requires("read_only_version_pinning"));
        assert!(row.requires("error_path_not_found"));
    }

    /// The dedupe key pluralizes the repo type exactly as the plugin's address
    /// root does.
    #[test]
    fn huggingface_request_root_pluralizes_the_repo_type() {
        let mut config = HashMap::new();
        config.insert("repo_id".into(), ConfigValue::String("acme/demo".into()));
        assert_eq!(
            resolved_request_root(Backend::Huggingface, &config).as_deref(),
            Some("hf://models/acme/demo/"),
        );
        config.insert("repo_type".into(), ConfigValue::String("dataset".into()));
        assert_eq!(
            resolved_request_root(Backend::Huggingface, &config).as_deref(),
            Some("hf://datasets/acme/demo/"),
        );
        config.insert("repo_type".into(), ConfigValue::String("space".into()));
        assert_eq!(
            resolved_request_root(Backend::Huggingface, &config).as_deref(),
            Some("hf://spaces/acme/demo/"),
        );
    }

    #[test]
    fn dedicated_endpoints_resolve_emulator_origins_without_ambient_credentials() {
        let requests = emulator_requests(
            Some("http://127.0.0.1:10000".into()),
            Some("http://127.0.0.1:4443".into()),
        );
        assert_eq!(requests.len(), 2);

        let azure = requests
            .iter()
            .find(|request| request.backend == Backend::Azure)
            .expect("Azurite request");
        assert_eq!(azure.origin, Origin::Emulator);
        assert_eq!(azure.access, Access::Default);
        assert_eq!(azure.credentials.fields.len(), 1);
        assert_eq!(
            azure.config.get("blob_endpoint"),
            Some(&ConfigValue::String(
                "http://127.0.0.1:10000/devstoreaccount1".into()
            ))
        );

        let gcs = requests
            .iter()
            .find(|request| request.backend == Backend::Gcs)
            .expect("fake-GCS request");
        assert_eq!(gcs.origin, Origin::Emulator);
        assert!(gcs.credentials.fields.is_empty());
        assert_eq!(
            gcs.config.get("endpoint"),
            Some(&ConfigValue::String("http://127.0.0.1:4443".into()))
        );
    }

    #[test]
    fn live_and_hermetic_requirements_select_distinct_origins() {
        let azure = [(Backend::Azure, None)];
        assert_eq!(
            preferred_origin_from(Backend::Azure, Access::Default, &azure, &[]),
            Some(Origin::Live)
        );
        assert_eq!(
            preferred_origin_from(Backend::Azure, Access::Default, &[], &azure),
            Some(Origin::Emulator)
        );
        assert_eq!(
            preferred_origin_from(
                Backend::File,
                Access::Default,
                &[],
                &[(Backend::File, None)]
            ),
            Some(Origin::Local)
        );
    }

    #[test]
    fn emulator_cannot_satisfy_live_and_live_cannot_satisfy_hermetic() {
        let required = [(Backend::Azure, None)];
        let emulator = [(Backend::Azure, Access::Default, Origin::Emulator)];
        let live = [(Backend::Azure, Access::Default, Origin::Live)];

        let (missing_live, _) = connection_gaps(&emulator, &[], &required, |_| Origin::Live);
        assert_eq!(missing_live, ["azure:default:live"]);

        let (missing_emulator, _) = connection_gaps(&live, &[], &required, |_| Origin::Emulator);
        assert_eq!(missing_emulator, ["azure:default:emulator"]);
    }

    #[test]
    fn forbidden_live_request_is_rejected_even_beside_an_emulator() {
        let mut requests = emulator_requests(Some("http://127.0.0.1:10000".into()), None);
        requests.push(ResolvedRequest {
            backend: Backend::Azure,
            access: Access::Default,
            origin: Origin::Live,
            kind: "azure".into(),
            config: HashMap::new(),
            credentials: bundle(&[("account_key", "ambient-real-key")]),
        });

        assert_eq!(
            forbidden_resolved(&requests, &[(Backend::Azure, None)]),
            ["azure:default:live"]
        );
    }

    #[test]
    fn required_emulators_have_explicit_baseline_rows() {
        for backend in [Backend::Azure, Backend::Gcs] {
            let row = baseline_for(backend, Access::Default, Origin::Emulator)
                .unwrap_or_else(|| panic!("missing emulator baseline for {}", backend.label()));
            assert!(row.requires("write_stat_read"));
        }

        let gcs = baseline_for(Backend::Gcs, Access::Default, Origin::Emulator).unwrap();
        assert_eq!(
            gcs.excluded_scenarios,
            [
                "check_access",
                "conditional_write",
                "directory_marker_ops",
                "update_metadata",
            ]
        );
    }
}
