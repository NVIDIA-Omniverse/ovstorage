// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The generic `[ovstorage.layers.*]` → `Arc<Stack>` builder.
//!
//! [`build_stack`] is the one composition path a bespoke host (CLI, MCP, and
//! later broker/REST) uses to turn its declared [`StackConfig`] into a live
//! [`Stack`]. Unlike the transitional `build_*_stack` helpers in
//! [`crate::layers`], the shape is 100% caller data: the layer graph comes
//! from the config, not a hard-coded wrapper chain.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use crate::fallback::{
    ANONYMOUS_FALLBACK_AVAILABLE_SCHEMES, ANONYMOUS_FALLBACK_KEY, ANONYMOUS_FALLBACK_KINDS,
    ANONYMOUS_FALLBACK_SCHEMES, schemes_for_kind,
};
use crate::{
    CancellationToken, EMPTY_LAYER_KIND, EmptyLayerFactory, Error, ErrorCode,
    LayerConnectionRequest, LayerKindDescriptor, LayerSpec, LayerTable, LayerType,
    LoadedLayerFactory, Result, Stack, StackConfig, StorageBackendKindDescriptor,
    layers::default_layer_factories, stack_config_to_spec,
};

/// Reject an empty `[ovstorage]` stack at server startup.
///
/// A [`StackConfig`] with no `root` or no `[ovstorage.layers]` builds the
/// one-layer [`EmptyLayer`](crate::EmptyLayer) Stack (see [`build_stack`]), which
/// answers every operation with [`ErrorCode::Unsupported`] — a server that serves
/// nothing. The always-on hosts (REST gateway, broker) call this at startup so an
/// operator config that declares no stack **fails fast and exits** rather than
/// binding a listener that rejects every request.
///
/// Returns [`ErrorCode::NotConfigured`] when `config.layers` is empty or `root`
/// is unset; the message points the operator at the configuration guide and the
/// shipped default config.
///
/// # Errors
///
/// - [`ErrorCode::NotConfigured`] — `config.layers` is empty or `root` is
///   unset.
pub fn require_configured_stack(config: &StackConfig) -> Result<()> {
    if config.root.is_none() || config.layers.is_empty() {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            "no [ovstorage.layers] configured — the server refuses to start with an \
             empty stack; declare a stack (see docs/public/configuration.md) or copy \
             the shipped default config",
        ));
    }
    Ok(())
}

/// Build an `Arc<Stack>` from a declared [`StackConfig`] plus any loaded plugin
/// `factories`.
///
/// The sole built-in default factory ([`default_layer_factories`]) is the file
/// backend. `factories` carries dlopened plugin factories (from
/// [`load_layer_plugins_from_dir`](crate::load_layer_plugins_from_dir)) and any
/// native layers explicitly supplied by an embedding host. A config referencing
/// any other kind resolves only when its provider is present.
///
/// An empty `[ovstorage.layers]` ([`stack_config_to_spec`] returns `None`)
/// yields a one-layer Stack rooted at [`EmptyLayer`](crate::EmptyLayer), so a
/// host with no configured stack answers every operation with
/// [`ErrorCode::Unsupported`] uniformly, with no
/// special-casing at the call sites.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the layer graph is invalid (duplicated,
///   missing, referenced by multiple parents, shaped wrongly, or contains a
///   cycle), a declared kind has no registered factory, connections are
///   declared but no layers are configured, or a connection is malformed.
/// - Any error a layer factory returns during instantiation or layer
///   application.
pub async fn build_stack(
    config: &StackConfig,
    factories: Vec<LoadedLayerFactory>,
) -> Result<Arc<Stack>> {
    build_stack_with_cancel(config, factories, None).await
}

/// [`build_stack`], bounded by a caller-supplied cancellation token.
///
/// The token is threaded to
/// [`StackBuilder::build_with_cancel`](crate::StackBuilder::build_with_cancel),
/// so it bounds both layer instantiation and the apply of each declared
/// `[[ovstorage.connections]]`. That apply is the interesting one: a connection
/// applied through a Router waits for the route-table catch-up that makes the
/// address routable, and a backend that never answers that re-query otherwise
/// pins the build until the catch-up's own 30-second deadline. A host that owns
/// its process lifetime hands its shutdown token here and exits the wait the
/// moment it is cancelled.
///
/// # Errors
///
/// The same contract as [`build_stack`], plus [`ErrorCode::Cancelled`] when
/// `cancel` fires during layer instantiation. A connection whose mutation has
/// already committed reports [`ErrorCode::CommitAmbiguous`] instead, because
/// cancelling the wait says nothing about whether the mutation landed.
pub async fn build_stack_with_cancel(
    config: &StackConfig,
    factories: Vec<LoadedLayerFactory>,
    cancel: Option<CancellationToken>,
) -> Result<Arc<Stack>> {
    // The built-in file factory plus the caller's plugin/native factories, one
    // source of truth for both the kind→type map and builder registration.
    let mut all = default_layer_factories();
    all.extend(factories);

    let factory_types: HashMap<String, LayerType> = all
        .iter()
        .map(|factory| {
            let descriptor = factory.descriptor();
            (descriptor.kind, descriptor.layer_type)
        })
        .collect();

    let Some(spec) = stack_config_to_spec(config, &factory_types)? else {
        // No layers configured. Declared connections have no backend layer to
        // attach to, so silently dropping them (the EmptyLayer fallback returns
        // before the connection loop below) would lose an operator's explicit
        // `[[ovstorage.connections]]` with no signal — error instead.
        if !config.connections.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "[[ovstorage.connections]] declared but no [ovstorage.layers] to attach them to",
            ));
        }
        // Truly empty (no layers and no connections): a one-layer Stack rooted
        // at EmptyLayer, so a host with no configured stack answers every
        // operation with Unsupported uniformly.
        let stack = Stack::builder(EMPTY_LAYER_KIND)
            .backend_factory(Arc::new(EmptyLayerFactory))
            .layer(LayerSpec::backend(EMPTY_LAYER_KIND, EMPTY_LAYER_KIND))
            .build_with_cancel(cancel)
            .await?;
        return Ok(Arc::new(stack));
    };

    let mut builder = Stack::builder(spec.root);
    for factory in all {
        builder = match factory {
            LoadedLayerFactory::Backend(f) => builder.backend_factory(f),
            LoadedLayerFactory::Wrapper(f) => builder.wrapper_factory(f),
            LoadedLayerFactory::Router(f) => builder.router_factory(f),
        };
    }
    for layer in spec.layers {
        builder = builder.layer(layer);
    }
    // Resolve each declared connection to a concrete target (default: the
    // backend kind) and materialize its `ConnectionRequest`.
    for connection in &config.connections {
        builder = builder.connection(LayerConnectionRequest {
            target: connection
                .target
                .clone()
                .unwrap_or_else(|| connection.backend_kind.clone()),
            connection: connection.to_connection_request()?,
        });
    }
    Ok(Arc::new(builder.build_with_cancel(cancel).await?))
}

/// A `wrapper`-class [`LayerTable`] of `kind` whose sole `inner` is `inner`.
///
/// The shared building block bespoke hosts (broker, REST gateway) use to emit
/// the linear wrapper rows of their programmatic [`StackConfig`] twins.
pub fn wrapper_layer(kind: &str, inner: &str) -> LayerTable {
    LayerTable {
        kind: Some(kind.to_string()),
        inner: Some(inner.to_string()),
        ..Default::default()
    }
}

/// Guarantee the graph carries a `kind`-kind wrapper layer at its root, injecting
/// one over the current root when absent.
///
/// A host-attested trust-boundary wrapper (e.g. the broker/REST `attribution`
/// overlay) is a *declared* layer, not a force-prepended composer step; a graph
/// that omits it would otherwise start cleanly and silently drop that wrapper's
/// effect. The intended use is for a host to call this after loading config, to
/// structurally guarantee the wrapper — matching how the per-listener auth layer
/// is host-attached rather than trusted to the operator TOML. When no layer of
/// `kind` is present, prepend
/// one over the current root (the injected wrapper's config comes from its
/// registered factory, exactly as a declared one does). A graph that already
/// declares a `kind` layer, or an empty/rootless config, is returned unchanged
/// (the config path refuses the latter upstream via [`require_configured_stack`]).
///
/// `kind` is a parameter so core needs no dependency on any host's wrapper crate
/// (e.g. `ovstorage_authz`'s `ATTRIBUTION_KIND`): the host passes its own kind in.
///
/// **What this guarantees is presence, not position.** The test is whether any
/// layer of `kind` exists anywhere in the graph, so a graph declaring one below a
/// router — on a single branch, say — is returned unchanged and the other
/// branches carry no such wrapper. A host composing a wrapper per branch
/// therefore cannot express its guarantee through this function, and needs one
/// that reasons about branches. The remote hosts' attribution overlay is such a
/// wrapper and uses `ovstorage_authz::ensure_branch_attribution` instead, so no
/// host in this repo calls this today. It stays as the whole-graph form of the
/// same idea, for a wrapper that genuinely wants one instance over the root.
pub fn ensure_root_wrapper(mut config: StackConfig, kind: &str) -> StackConfig {
    let present = config
        .layers
        .iter()
        .any(|(name, table)| table.kind.as_deref().unwrap_or(name.as_str()) == kind);
    if present {
        return config;
    }
    let Some(root) = config.root.clone() else {
        return config;
    };
    let name = injected_wrapper_name(&config, kind);
    config
        .layers
        .insert(name.clone(), wrapper_layer(kind, &root));
    config.root = Some(name);
    config
}

/// A layer name for the injected [`ensure_root_wrapper`] wrapper that does not
/// collide with an existing layer (a graph could name a non-matching-kind layer
/// after the wrapper's kind).
fn injected_wrapper_name(config: &StackConfig, kind: &str) -> String {
    let mut name = kind.to_string();
    let mut i = 1;
    while config.layers.contains_key(&name) {
        name = format!("{kind}_{i}");
        i += 1;
    }
    name
}

/// The `redirect_follower` layer's config key for the redirect credential
/// disclosure policy.
///
/// Hosts stamp it from their own top-level key
/// ([`stamp_redirect_disclosure`]); an operator sets the top-level key
/// instead, so that one setting governs the read and the write path together.
pub const DISCLOSE_REDIRECT_CREDENTIALS_KEY: &str = "disclose_redirect_credentials";

/// The redirect follower's layer kind.
///
/// Spelled here rather than imported from `ovstorage-plugin-http`: a host
/// reaches every plugin through `dlopen`, so the follower crate is a dev
/// dependency of the hosts at most and must not be linked into production
/// dispatch. Each host has a test asserting its shipped graph names this kind,
/// so the two spellings cannot drift apart unnoticed.
pub const REDIRECT_FOLLOWER_LAYER_KIND: &str = "redirect_follower";

/// Stamp a host's redirect credential disclosure policy onto every
/// `redirect_follower` layer in a declared graph.
///
/// The operator sets one top-level key and the follower reads a layer key, so
/// the value has to be carried across. Hosts call this over the graph the
/// operator actually declared, because that graph is what
/// [`build_stack`] loads verbatim — stamping a programmatic twin instead would
/// leave every real deployment unstamped.
///
/// A graph with no follower is not an error: it may route only to backends that
/// never redirect. Each host's own out-edge check is what makes the policy hold
/// in that case, since the layer graph is operator config and can omit the
/// follower entirely.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — a follower layer sets the layer key by
///   hand. Refusing beats silently overriding: two spellings of one policy that
///   disagree is a state an operator cannot debug from the outside.
pub fn stamp_redirect_disclosure(mut config: StackConfig, disclose: bool) -> Result<StackConfig> {
    for (name, table) in config.layers.iter_mut() {
        if table.kind.as_deref().unwrap_or(name.as_str()) != REDIRECT_FOLLOWER_LAYER_KIND {
            continue;
        }
        if table.config.contains_key(DISCLOSE_REDIRECT_CREDENTIALS_KEY) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "layer `{name}` sets `{DISCLOSE_REDIRECT_CREDENTIALS_KEY}` directly; set the \
                     host's top-level `redirect_credential_disclosure` instead, which governs \
                     the read and the write path together"
                ),
            ));
        }
        table.config.insert(
            DISCLOSE_REDIRECT_CREDENTIALS_KEY.to_string(),
            toml::Value::Boolean(disclose),
        );
    }
    Ok(config)
}

#[cfg(test)]
mod redirect_disclosure_key_tests {
    /// The host's stamped key and the follower's read key are one string held
    /// in two crates that deliberately cannot link: a host reaches plugins
    /// through `dlopen`, so the follower crate is a dev-dependency here at
    /// most. Nothing but this test ties the two spellings together.
    ///
    /// The failure it guards is silent in the worst way. The follower ignores
    /// config keys it does not know, so renaming either side alone makes
    /// `stamp_redirect_disclosure` write a key nobody reads: the follower falls
    /// back to refusing, an operator who set `allow` gets their reads proxied,
    /// and nothing anywhere reports a problem. The sibling constant
    /// `REDIRECT_FOLLOWER_LAYER_KIND` got a pinning test in both hosts; this
    /// one, whose failure is quieter, had none.
    #[test]
    fn the_stamped_key_is_the_key_the_follower_reads() {
        assert_eq!(
            super::DISCLOSE_REDIRECT_CREDENTIALS_KEY,
            ovstorage_plugin_http::DISCLOSE_CREDENTIALS_KEY,
            "the host stamps a key the redirect follower does not read, so the \
             operator's disclosure policy silently never reaches it"
        );
    }
}

/// Stamp a host's anonymous fallback grant onto the one backend layer of each
/// kind that owns a granted scheme.
///
/// An address such as `s3://bucket/key` that no configured connection serves
/// misses every route and dies as `NoRoute`. A granted scheme lets the
/// backend layer of the owning kind publish a hidden scheme fallback root and
/// attempt such an address **anonymously**: no credential source is built, so
/// the process's ambient identity is never spent on an address the operator
/// did not configure. Whether that is wanted is a property of the deployment
/// rather than of any connection — a brokered fetch runs from the broker's
/// network position and reaches whatever that position reaches — so the
/// broker and the REST gateway carry it as top-level operator keys
/// (`anonymous_fallback_schemes`, and `anonymous_http_fallback` for `http` and
/// `https`) and stamp it here onto the backend layer that reads the layer key
/// [`ANONYMOUS_FALLBACK_KEY`]. A library, CLI or MCP host sets the layer key
/// directly, like every other layer key.
///
/// Only a non-empty grant is written, and only onto a layer whose kind serves a
/// granted scheme. Every backend factory treats a non-empty layer table as a
/// static connection seed, so stamping an empty array onto a bare
/// `[ovstorage.layers.http]` would turn a routable-but-unconnected backend into
/// a failed connection attempt.
///
/// The carrier is resolved against the **routed** graph, not the declaration
/// table: the layers `root` reaches through `inner` and `children`. The Stack
/// builder instantiates exactly that set, so a `[ovstorage.layers.s3]` table
/// the router's `children` omit is never built, and a grant stamped onto it
/// would publish no fallback root while startup reported success. Such a layer
/// is refused by name instead, and it is not counted when deciding whether the
/// kind has one carrier or two.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — a tier-owning layer sets the layer key by
///   hand. Refusing beats silently overriding: two spellings of one policy that
///   disagree is a state an operator cannot debug from the outside. Checked
///   even when nothing is granted.
/// - [`ErrorCode::InvalidArgument`] — a granted scheme is not a fallback scheme,
///   or is `http`/`https`, whose fallback is not available in this release. The
///   refusal is loud so an operator who wrote `allow` learns it did nothing.
/// - [`ErrorCode::InvalidArgument`] — the graph declares no layer of the kind
///   that owns a granted scheme, so nothing could carry the grant: a silently
///   inert grant is the failure an operator would never notice. Or it declares
///   one that `root` does not reach, which is just as inert and is refused
///   naming the layer. Or `root` reaches more than one, and two scheme roots
///   for one scheme shadow each other silently.
pub fn stamp_anonymous_fallback(
    mut config: StackConfig,
    schemes: &BTreeSet<String>,
) -> Result<StackConfig> {
    let resolved_kind = |name: &str, table: &LayerTable| -> String {
        table.kind.as_deref().unwrap_or(name).to_string()
    };

    // A hand-set layer key on any tier-owning kind is refused before anything
    // else, and regardless of the grant: with an empty grant the two spellings
    // would otherwise disagree in the quietest possible way.
    for (name, table) in &config.layers {
        if schemes_for_kind(&resolved_kind(name, table)).is_empty() {
            continue;
        }
        if table.config.contains_key(ANONYMOUS_FALLBACK_KEY) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "layer `{name}` sets `{ANONYMOUS_FALLBACK_KEY}` directly; set the host's \
                     top-level `anonymous_fallback_schemes` (and `anonymous_http_fallback` for \
                     http and https) instead, which the host stamps onto the graph"
                ),
            ));
        }
    }

    for scheme in schemes {
        if !ANONYMOUS_FALLBACK_SCHEMES.contains(&scheme.as_str()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "`anonymous_fallback_schemes` grants `{scheme}`, which is not a fallback \
                     scheme; the accepted schemes are {}",
                    ANONYMOUS_FALLBACK_AVAILABLE_SCHEMES.join(", ")
                ),
            ));
        }
        if !ANONYMOUS_FALLBACK_AVAILABLE_SCHEMES.contains(&scheme.as_str()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "http anonymous fallback is not available in this release; keep \
                 `anonymous_http_fallback = \"refuse\"`",
            ));
        }
    }

    if schemes.is_empty() {
        return Ok(config);
    }

    let routed = routed_layer_names(&config);
    for (kind, served) in ANONYMOUS_FALLBACK_KINDS {
        let granted: Vec<&str> = served
            .iter()
            .copied()
            .filter(|scheme| schemes.contains(*scheme))
            .collect();
        if granted.is_empty() {
            continue;
        }
        let granted_list = granted
            .iter()
            .map(|scheme| format!("`{scheme}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut declared: Vec<String> = config
            .layers
            .iter()
            .filter(|(name, table)| resolved_kind(name, table) == *kind)
            .map(|(name, _)| name.clone())
            .collect();
        declared.sort();
        // Only a layer the root reaches can carry the grant. The builder
        // instantiates the graph by walking from the root, so a declared layer
        // nothing routes to is never built: a grant stamped onto it publishes
        // no fallback root, and startup would report success over a grant that
        // does nothing. Partitioning also keeps such a layer out of the
        // one-or-two carrier count, so a disconnected duplicate does not
        // refuse an otherwise valid routed carrier.
        let (carriers, unrouted): (Vec<String>, Vec<String>) =
            declared.into_iter().partition(|name| routed.contains(name));
        let backtick_list = |names: &[String]| {
            names
                .iter()
                .map(|name| format!("`{name}`"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let carrier = match (carriers.as_slice(), unrouted.as_slice()) {
            ([], []) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "`anonymous_fallback_schemes` grants {granted_list}, but the graph \
                         declares no layer of kind `{kind}` to carry it: declare \
                         `[ovstorage.layers.{kind}]` and add it to the router's `children`"
                    ),
                ));
            }
            ([], unrouted) => {
                let (noun, verb) = if unrouted.len() == 1 {
                    ("layer", "is")
                } else {
                    ("layers", "are")
                };
                let names = backtick_list(unrouted);
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "`anonymous_fallback_schemes` grants {granted_list}, but {noun} {names} \
                         of kind `{kind}` {verb} declared and not reachable from the graph's \
                         root, so the grant would sit inert: add it to the router's `children` \
                         (or make it the root, or a wrapper's `inner`)"
                    ),
                ));
            }
            ([one], _) => one,
            (many, _) => {
                let names = backtick_list(many);
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "`anonymous_fallback_schemes` grants {granted_list}, but layers {names} \
                         are all of kind `{kind}`: two scheme fallback roots for one scheme \
                         shadow each other silently, so declare exactly one `{kind}` layer"
                    ),
                ));
            }
        };
        let table = config
            .layers
            .get_mut(carrier)
            .expect("carrier name was taken from this graph");
        table.config.insert(
            ANONYMOUS_FALLBACK_KEY.to_string(),
            toml::Value::Array(
                granted
                    .iter()
                    .map(|scheme| toml::Value::String((*scheme).to_string()))
                    .collect(),
            ),
        );
    }
    tracing::info!(schemes = ?schemes, "anonymous fallback granted");
    Ok(config)
}

/// The names of every layer the graph's `root` reaches through `inner` and
/// `children`, transitively.
///
/// This is the set the Stack builder instantiates: it walks from the root and
/// never looks at a declared layer nothing references, so a layer outside this
/// set is dead configuration however valid its table is. A referenced name the
/// graph does not declare is skipped rather than reported, because the builder
/// refuses that graph with its own message; a name already visited is not
/// re-entered, so a cyclic graph terminates here and is refused there too. A
/// graph with no `root` reaches nothing.
fn routed_layer_names(config: &StackConfig) -> BTreeSet<String> {
    let mut routed = BTreeSet::new();
    let mut pending: Vec<&str> = config.root.as_deref().into_iter().collect();
    while let Some(name) = pending.pop() {
        let Some(table) = config.layers.get(name) else {
            continue;
        };
        if !routed.insert(name.to_string()) {
            continue;
        }
        pending.extend(table.inner.as_deref());
        pending.extend(table.children.iter().map(String::as_str));
    }
    routed
}

#[cfg(test)]
mod anonymous_fallback_stamp_tests {
    use super::*;

    /// A router over one backend layer per `(name, kind)` pair.
    fn graph(backends: &[(&str, &str)]) -> StackConfig {
        let declared: Vec<(&str, Option<&str>)> = backends
            .iter()
            .map(|(name, kind)| (*name, Some(*kind)))
            .collect();
        declared_graph(&declared)
    }

    /// A router over one backend layer per `(name, kind)` pair, where a `None`
    /// kind is the short declaration — `[ovstorage.layers.gcs]` with no
    /// `kind =` line — whose kind resolves from the layer's name.
    fn declared_graph(backends: &[(&str, Option<&str>)]) -> StackConfig {
        let mut layers: HashMap<String, LayerTable> = HashMap::new();
        layers.insert(
            "router".into(),
            LayerTable {
                kind: Some("router".into()),
                children: backends
                    .iter()
                    .map(|(name, _)| (*name).to_string())
                    .collect(),
                ..Default::default()
            },
        );
        for (name, kind) in backends {
            layers.insert(
                (*name).to_string(),
                LayerTable {
                    kind: kind.map(str::to_string),
                    ..Default::default()
                },
            );
        }
        StackConfig {
            root: Some("router".into()),
            layers,
            connections: Vec::new(),
        }
    }

    /// [`graph`], except that the backends named in `unrouted` stay declared
    /// but are dropped from the router's `children`: the shape of an operator
    /// who wrote the `[ovstorage.layers.s3]` table and forgot the second half
    /// of the fix. `graph` and `declared_graph` cannot express it, because
    /// they route every declared backend.
    fn graph_leaving_unrouted(backends: &[(&str, &str)], unrouted: &[&str]) -> StackConfig {
        let mut config = graph(backends);
        config
            .layers
            .get_mut("router")
            .expect("graph roots at a router")
            .children
            .retain(|child| !unrouted.contains(&child.as_str()));
        config
    }

    fn grant(schemes: &[&str]) -> BTreeSet<String> {
        schemes.iter().map(|scheme| (*scheme).to_string()).collect()
    }

    fn scheme_array(schemes: &[&str]) -> toml::Value {
        toml::Value::Array(
            schemes
                .iter()
                .map(|scheme| toml::Value::String((*scheme).to_string()))
                .collect(),
        )
    }

    #[test]
    fn stamp_writes_only_non_empty_grants_onto_the_single_layer_of_each_kind() {
        let config = graph(&[
            ("s3", "s3"),
            ("gcs", "gcs"),
            ("azure", "azure"),
            ("http", "http"),
            ("file", "file"),
        ]);
        let layers_before = config.layers.len();

        let stamped = stamp_anonymous_fallback(config, &grant(&["s3", "gs"])).expect("stamps");

        assert_eq!(
            stamped.layers.len(),
            layers_before,
            "no layer added or removed"
        );
        assert_eq!(
            stamped.layers["s3"].config.get(ANONYMOUS_FALLBACK_KEY),
            Some(&scheme_array(&["s3"]))
        );
        assert_eq!(
            stamped.layers["gcs"].config.get(ANONYMOUS_FALLBACK_KEY),
            Some(&scheme_array(&["gs"]))
        );
        // A kind with no granted scheme is left untouched: its factory would
        // read any key at all as a static connection seed.
        for name in ["azure", "http", "file", "router"] {
            assert!(
                stamped.layers[name].config.is_empty(),
                "layer `{name}` must carry no stamped key, got {:?}",
                stamped.layers[name].config
            );
        }
    }

    #[test]
    fn an_empty_grant_writes_nothing_and_still_refuses_a_hand_set_layer_key() {
        let config = graph(&[("http", "http"), ("s3", "s3"), ("file", "file")]);
        let stamped = stamp_anonymous_fallback(config.clone(), &BTreeSet::new())
            .expect("an empty grant is fine");
        assert_eq!(
            stamped, config,
            "an empty grant must leave the graph byte-identical"
        );

        let mut hand_set = config;
        hand_set
            .layers
            .get_mut("s3")
            .unwrap()
            .config
            .insert(ANONYMOUS_FALLBACK_KEY.into(), scheme_array(&["s3"]));
        let error = stamp_anonymous_fallback(hand_set, &BTreeSet::new())
            .expect_err("a hand-set layer key is refused even when nothing is granted");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.to_string().contains("layer `s3`"), "got: {error}");
    }

    #[test]
    fn a_hand_set_anonymous_fallback_layer_key_is_refused_naming_the_top_level_keys() {
        let mut config = graph(&[("s3", "s3")]);
        config
            .layers
            .get_mut("s3")
            .unwrap()
            .config
            .insert(ANONYMOUS_FALLBACK_KEY.into(), scheme_array(&["s3"]));

        let error = stamp_anonymous_fallback(config, &grant(&["s3"]))
            .expect_err("a hand-set layer key must be refused, not silently overridden");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        let message = error.to_string();
        for needle in [
            "layer `s3` sets `anonymous_fallback` directly",
            "anonymous_fallback_schemes",
            "anonymous_http_fallback",
        ] {
            assert!(message.contains(needle), "missing `{needle}` in: {message}");
        }
    }

    #[test]
    fn a_grant_whose_kind_has_no_layer_is_refused_with_the_fix() {
        let error = stamp_anonymous_fallback(graph(&[("file", "file")]), &grant(&["gs"]))
            .expect_err("a grant nothing can carry must fail loud rather than sit inert");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        let message = error.to_string();
        for needle in [
            "grants `gs`",
            "no layer of kind `gcs`",
            "declare `[ovstorage.layers.gcs]`",
            "router's `children`",
        ] {
            assert!(message.contains(needle), "missing `{needle}` in: {message}");
        }
    }

    #[test]
    fn a_grant_whose_kind_has_two_layers_is_refused_naming_them() {
        let error = stamp_anonymous_fallback(
            graph(&[("s3_west", "s3"), ("s3_east", "s3"), ("file", "file")]),
            &grant(&["s3"]),
        )
        .expect_err("two roots for one scheme would shadow each other silently");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        let message = error.to_string();
        for needle in ["`s3_east`", "`s3_west`", "kind `s3`"] {
            assert!(message.contains(needle), "missing `{needle}` in: {message}");
        }
    }

    /// The zero-layer refusal already tells the operator to "add it to the
    /// router's `children`", and this is the case that promise covers: the
    /// table is declared and the `children` entry is missing. The builder
    /// walks from the root, so such a layer is never instantiated, and a grant
    /// stamped onto it would start cleanly and publish nothing.
    #[test]
    fn a_declared_but_unrouted_carrier_is_refused_naming_it() {
        let config = graph_leaving_unrouted(&[("gcs", "gcs"), ("file", "file")], &["gcs"]);
        assert!(
            config.layers.contains_key("gcs")
                && !config.layers["router"].children.iter().any(|c| c == "gcs"),
            "the fixture must declare `gcs` and leave it out of the router's children"
        );

        let error = stamp_anonymous_fallback(config, &grant(&["gs"]))
            .expect_err("a grant stamped onto a layer the root never reaches would sit inert");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        let message = error.to_string();
        for needle in [
            "grants `gs`",
            "layer `gcs` of kind `gcs` is declared and not reachable",
            "router's `children`",
        ] {
            assert!(message.contains(needle), "missing `{needle}` in: {message}");
        }
        assert!(
            !message.contains("declares no layer"),
            "the layer is declared, so the zero-layer wording would misdirect: {message}"
        );
    }

    /// A stray `[ovstorage.layers.s3_old]` left declared but unrouted is dead
    /// configuration, not a second scheme root: the builder never instantiates
    /// it, so it cannot shadow anything. Counting it would refuse a valid
    /// graph with a message about two carriers when there is only one.
    #[test]
    fn a_disconnected_duplicate_does_not_trip_the_two_carrier_refusal() {
        let config = graph_leaving_unrouted(
            &[("s3", "s3"), ("s3_old", "s3"), ("file", "file")],
            &["s3_old"],
        );

        let stamped = stamp_anonymous_fallback(config, &grant(&["s3"]))
            .expect("one routed carrier beside an unrouted twin is one carrier");
        assert_eq!(
            stamped.layers["s3"].config.get(ANONYMOUS_FALLBACK_KEY),
            Some(&scheme_array(&["s3"]))
        );
        assert!(
            stamped.layers["s3_old"].config.is_empty(),
            "the unrouted twin must not be stamped, got {:?}",
            stamped.layers["s3_old"].config
        );
    }

    /// Reachability follows a wrapper's `inner` as well as a router's
    /// `children`: a backend the router reaches only through a wrapper is
    /// routed, and a walk that read `children` alone would refuse the shape
    /// every shipped graph uses.
    #[test]
    fn a_carrier_reached_through_a_wrapper_inner_is_found() {
        let mut layers: HashMap<String, LayerTable> = HashMap::new();
        layers.insert(
            "router".into(),
            LayerTable {
                kind: Some("router".into()),
                children: vec!["retry".into(), "file".into()],
                ..Default::default()
            },
        );
        layers.insert("retry".into(), wrapper_layer("retry", "s3"));
        layers.insert(
            "s3".into(),
            LayerTable {
                kind: Some("s3".into()),
                ..Default::default()
            },
        );
        layers.insert(
            "file".into(),
            LayerTable {
                kind: Some("file".into()),
                ..Default::default()
            },
        );
        let config = StackConfig {
            root: Some("router".into()),
            layers,
            connections: Vec::new(),
        };

        let stamped = stamp_anonymous_fallback(config, &grant(&["s3"]))
            .expect("router -> wrapper(inner = s3) -> s3 routes the carrier");
        assert_eq!(
            stamped.layers["s3"].config.get(ANONYMOUS_FALLBACK_KEY),
            Some(&scheme_array(&["s3"]))
        );
        for name in ["router", "retry", "file"] {
            assert!(
                stamped.layers[name].config.is_empty(),
                "layer `{name}` must carry no stamped key, got {:?}",
                stamped.layers[name].config
            );
        }
    }

    /// The refusal's fix offers "make it the root": a graph whose root is the
    /// backend itself, with no router at all, must therefore be accepted.
    #[test]
    fn the_root_itself_can_carry_the_grant() {
        let mut layers: HashMap<String, LayerTable> = HashMap::new();
        layers.insert(
            "s3".into(),
            LayerTable {
                kind: Some("s3".into()),
                ..Default::default()
            },
        );
        let config = StackConfig {
            root: Some("s3".into()),
            layers,
            connections: Vec::new(),
        };

        let stamped = stamp_anonymous_fallback(config, &grant(&["s3"]))
            .expect("the root is reachable from itself");
        assert_eq!(
            stamped.layers["s3"].config.get(ANONYMOUS_FALLBACK_KEY),
            Some(&scheme_array(&["s3"]))
        );
    }

    /// The short declaration — `[ovstorage.layers.gcs]` with no `kind =` line —
    /// is the shape the configuration examples use, and it takes the arm of
    /// the kind resolution no graph above reaches: every one of them spells
    /// its kind out. A regression that read `kind` alone would stamp nothing
    /// onto, and refuse nothing about, such a layer while those tests stay
    /// green.
    #[test]
    fn a_kind_less_layer_table_carries_the_grant_under_its_name() {
        let stamped = stamp_anonymous_fallback(
            declared_graph(&[("gcs", None), ("file", Some("file"))]),
            &grant(&["gs"]),
        )
        .expect("the kind resolves from the name");
        assert_eq!(
            stamped.layers["gcs"].config.get(ANONYMOUS_FALLBACK_KEY),
            Some(&scheme_array(&["gs"]))
        );
        assert!(
            stamped.layers["file"].config.is_empty(),
            "got {:?}",
            stamped.layers["file"].config
        );
    }

    #[test]
    fn a_hand_set_key_on_a_kind_less_layer_table_is_refused_with_an_empty_grant() {
        let mut config = declared_graph(&[("s3", None)]);
        config
            .layers
            .get_mut("s3")
            .unwrap()
            .config
            .insert(ANONYMOUS_FALLBACK_KEY.into(), scheme_array(&["s3"]));

        let error = stamp_anonymous_fallback(config, &BTreeSet::new())
            .expect_err("a kind-less tier-owning layer is still a tier-owning layer");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.to_string().contains("layer `s3`"), "got: {error}");
    }

    #[test]
    fn a_kind_less_layer_table_counts_toward_the_two_layer_refusal() {
        let error = stamp_anonymous_fallback(
            declared_graph(&[("s3", None), ("s3_east", Some("s3"))]),
            &grant(&["s3"]),
        )
        .expect_err("a kind-less twin shadows the explicit one just the same");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        let message = error.to_string();
        assert!(
            message.contains("layers `s3`, `s3_east` are all of kind `s3`"),
            "got: {message}"
        );
    }

    #[test]
    fn http_and_https_are_refused_in_this_release() {
        for scheme in ["http", "https"] {
            let error = stamp_anonymous_fallback(graph(&[("http", "http")]), &grant(&[scheme]))
                .expect_err("the http tier is not available in this release");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "scheme {scheme}");
            let message = error.to_string();
            assert!(
                message.contains("not available in this release")
                    && message.contains("anonymous_http_fallback = \"refuse\""),
                "scheme {scheme}: {message}"
            );
        }
        // The refusal is not an artefact of the graph lacking a carrier: the
        // same grant beside a valid one is refused for the same reason.
        let error = stamp_anonymous_fallback(
            graph(&[("http", "http"), ("s3", "s3")]),
            &grant(&["s3", "https"]),
        )
        .expect_err("https is refused even beside a valid grant");
        assert!(error.to_string().contains("not available in this release"));
    }

    #[test]
    fn an_unknown_scheme_is_refused() {
        let error = stamp_anonymous_fallback(graph(&[("s3", "s3")]), &grant(&["ftp"]))
            .expect_err("a scheme outside the closed set is refused");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        let message = error.to_string();
        assert!(
            message.contains("grants `ftp`") && message.contains("s3, gs, azure"),
            "got: {message}"
        );
    }

    /// The kind table is spelled in the shared contract rather than read off
    /// the plugin: a host reaches every plugin through `dlopen`, so the http
    /// crate is a dev-dependency here at most. Nothing but this test ties the
    /// `http` row of the table to the kind the plugin actually declares, and a
    /// drift would make a granted http fallback look for a layer that can
    /// never exist.
    #[test]
    fn the_kind_table_matches_the_http_plugin_descriptor() {
        use crate::BackendFactory as _;

        let kind = ovstorage_plugin_http::HttpBackendLayerFactory::default()
            .descriptor()
            .kind;
        assert_eq!(
            schemes_for_kind(&kind),
            ["http", "https"],
            "the fallback kind table does not know the http plugin's kind `{kind}`, so a \
             granted http fallback could never find its carrier layer"
        );
    }
}

/// The backend kinds the graph declares a Layer for — the kinds a router can
/// route, and therefore the only kinds a runtime `add_connection` can bind
/// against on the immutable Stack, independent of whether a startup connection
/// exists. A layer table is a backend when its resolved kind (its `kind`, else
/// its name) matches a loaded plugin or built-in [`LoadedLayerFactory::Backend`]
/// kind. Derived from the graph, NOT the connection list, so a predeclared,
/// routed-but-unconnected backend is still reported runtime-addable.
pub fn graph_backend_kinds(
    config: &StackConfig,
    factories: &[LoadedLayerFactory],
) -> BTreeSet<String> {
    let defaults = default_layer_factories();
    let backend_kinds: BTreeSet<String> = factories
        .iter()
        .chain(defaults.iter())
        .filter_map(|factory| match factory {
            LoadedLayerFactory::Backend(_) => Some(factory.descriptor().kind),
            _ => None,
        })
        .collect();
    config
        .layers
        .iter()
        .filter_map(|(name, table)| {
            let kind = table.kind.as_deref().unwrap_or(name.as_str());
            backend_kinds.contains(kind).then(|| kind.to_string())
        })
        .collect()
}

/// Project every loaded or native backend Layer factory to the
/// discovery-facing [`StorageBackendKindDescriptor`]. A loaded plugin kind wins
/// over a built-in of the same name (it is the factory a connection of that kind
/// would bind against). `routed_kinds` is the set of backend kinds the graph
/// declares a Layer for (a router child — see [`graph_backend_kinds`]), the only
/// kinds a runtime `add_connection` can bind against on the immutable Stack; it
/// gates `supports_runtime_add`.
pub fn discover_backend_kinds(
    factories: &[LoadedLayerFactory],
    routed_kinds: &BTreeSet<String>,
) -> Vec<StorageBackendKindDescriptor> {
    let mut by_kind: BTreeMap<String, StorageBackendKindDescriptor> = BTreeMap::new();
    for factory in factories {
        if matches!(factory, LoadedLayerFactory::Backend(_)) {
            let descriptor = backend_kind_from_layer(&factory.descriptor(), routed_kinds);
            by_kind.entry(descriptor.kind.clone()).or_insert(descriptor);
        }
    }
    for factory in default_layer_factories() {
        if matches!(factory, LoadedLayerFactory::Backend(_)) {
            let descriptor = backend_kind_from_layer(&factory.descriptor(), routed_kinds);
            by_kind.entry(descriptor.kind.clone()).or_insert(descriptor);
        }
    }
    by_kind.into_values().collect()
}

/// Project a backend Layer's kind descriptor to the discovery-facing
/// [`StorageBackendKindDescriptor`]. `supports_runtime_add` is `true` only when
/// the kind both accepts connections and has a router child in the declared
/// graph (`routed_kinds`) — the Stack is immutable, so a new connection can only
/// bind to an already-routed kind, but a routed backend needs no startup
/// connection to be addable later.
fn backend_kind_from_layer(
    descriptor: &LayerKindDescriptor,
    routed_kinds: &BTreeSet<String>,
) -> StorageBackendKindDescriptor {
    debug_assert_eq!(descriptor.layer_type, LayerType::Backend);
    StorageBackendKindDescriptor {
        kind: descriptor.kind.clone(),
        display_name: descriptor.display_name.clone(),
        description: descriptor.description.clone(),
        config_schema: descriptor.config_schema.clone(),
        credential_schema: descriptor.credential_schema.clone(),
        credential_methods: descriptor.credential_methods.clone(),
        icon: descriptor.icon.clone(),
        supports_runtime_add: descriptor.accepts_connections
            && routed_kinds.contains(&descriptor.kind),
        // Forwarded, not recomputed: unlike `supports_runtime_add` this says
        // nothing about the graph, only about what the plugin declared.
        supports_user_metadata: descriptor.supports_user_metadata,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Local stand-in for the hosts' `ATTRIBUTION_KIND` — core carries no
    /// dependency on `ovstorage_authz`, so the tests use a literal wrapper kind.
    const ATTRIBUTION_KIND: &str = "attribution";

    fn backend_layer(kind: &str) -> LayerTable {
        LayerTable {
            kind: Some(kind.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn ensure_root_wrapper_injects_when_absent_and_is_idempotent() {
        // A graph without the wrapper gets one injected at the root; a graph that
        // already declares one is returned unchanged.
        let mut layers: HashMap<String, LayerTable> = HashMap::new();
        layers.insert(
            "router".into(),
            LayerTable {
                kind: Some("router".into()),
                children: vec!["file".into()],
                ..Default::default()
            },
        );
        layers.insert("file".into(), backend_layer("file"));
        let config = StackConfig {
            root: Some("router".into()),
            layers,
            connections: Vec::new(),
        };

        let ensured = ensure_root_wrapper(config, ATTRIBUTION_KIND);
        let root = ensured.root.as_deref().expect("root set");
        let root_layer = ensured.layers.get(root).expect("root layer present");
        assert_eq!(root_layer.kind.as_deref(), Some(ATTRIBUTION_KIND));
        assert_eq!(root_layer.inner.as_deref(), Some("router"));

        // Idempotent: a graph that already carries the wrapper is unchanged.
        let before = ensured.layers.len();
        let again = ensure_root_wrapper(ensured, ATTRIBUTION_KIND);
        assert_eq!(again.root.as_deref(), Some(ATTRIBUTION_KIND));
        assert_eq!(again.layers.len(), before, "no extra layer injected");
    }

    #[test]
    fn ensure_root_wrapper_avoids_name_collision() {
        // A layer NAMED `attribution` but of a different kind already exists: the
        // injected wrapper must take a non-colliding name and still root the graph.
        let mut layers: HashMap<String, LayerTable> = HashMap::new();
        layers.insert(
            ATTRIBUTION_KIND.into(),
            LayerTable {
                kind: Some("file".into()),
                ..Default::default()
            },
        );
        let config = StackConfig {
            root: Some(ATTRIBUTION_KIND.into()),
            layers,
            connections: Vec::new(),
        };

        let ensured = ensure_root_wrapper(config, ATTRIBUTION_KIND);
        let root = ensured.root.as_deref().expect("root set");
        assert_ne!(root, ATTRIBUTION_KIND, "injected name must not collide");
        let root_layer = ensured.layers.get(root).expect("root layer present");
        assert_eq!(root_layer.kind.as_deref(), Some(ATTRIBUTION_KIND));
        assert_eq!(root_layer.inner.as_deref(), Some(ATTRIBUTION_KIND));
    }

    #[test]
    fn graph_backend_kinds_derives_from_graph_not_connections() {
        // A backend layer declared + routed in the graph with NO startup
        // connection is still a routed kind: derived from the graph.
        let mut layers: HashMap<String, LayerTable> = HashMap::new();
        layers.insert(
            "router".into(),
            LayerTable {
                kind: Some("router".into()),
                children: vec!["file".into()],
                ..Default::default()
            },
        );
        layers.insert("file".into(), backend_layer("file"));
        let config = StackConfig {
            root: Some("router".into()),
            layers,
            connections: Vec::new(), // no connection for `file`
        };

        let routed = graph_backend_kinds(&config, &[]);
        assert!(
            routed.contains("file"),
            "routed backend kind must come from the graph, got {routed:?}"
        );
    }

    #[test]
    fn discover_backend_kinds_gates_runtime_add_on_routed_kinds() {
        // The built-in `file` backend is marked runtime-addable only when routed.
        let mut routed = BTreeSet::new();
        routed.insert("file".to_string());
        let descriptors = discover_backend_kinds(&[], &routed);
        let file = descriptors
            .iter()
            .find(|d| d.kind == "file")
            .expect("file kind listed");
        assert!(
            file.supports_runtime_add,
            "a routed backend must be runtime-addable"
        );

        // Unrouted: still listed, but not runtime-addable.
        let descriptors = discover_backend_kinds(&[], &BTreeSet::new());
        let file = descriptors
            .iter()
            .find(|d| d.kind == "file")
            .expect("file kind listed");
        assert!(
            !file.supports_runtime_add,
            "an unrouted backend must NOT be runtime-addable"
        );
    }
}
