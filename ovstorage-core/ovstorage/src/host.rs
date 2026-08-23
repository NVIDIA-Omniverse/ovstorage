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
