// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

//! Shared principal types and the attribution overlay for ovstorage's remote
//! hosts. Authorization is implemented by the in-stack built-in auth Layer
//! (`ovstorage-authz-layer`) over the pure policy engine
//! (`ovstorage-authz-policy`). This crate owns [`Principal`] plus the
//! [`attribution`] helpers and [`AttributionWrapper`] Layer.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::SystemTime;

use ovstorage::{
    Error, ErrorCode, LayerTable, LayerType, LoadedLayerFactory, Result, StackConfig,
    StorageBackendKindDescriptor,
};

pub mod attribution;

pub use attribution::{
    ATTRIBUTION_KEY_MODIFIED_BY, ATTRIBUTION_KIND, AttributionLayer, AttributionStrategy,
    AttributionWrapper, AttributionWrapperFactory, RESERVED_METADATA_PREFIX,
};

/// Which backend kinds declare that a write's `WriteOptions::user_metadata`
/// survives them, and therefore take an attribution wrapper on their router
/// branch.
///
/// The declaration is the plugin's own, read off
/// [`StorageBackendKindDescriptor::supports_user_metadata`] at discovery time.
/// A host cannot answer this question for a backend it has never heard of, so
/// it does not try: a kind that declares nothing carries no wrapper, and the
/// host manufactures no reserved key a backend never said it could keep. That
/// is what makes the attribution module's own invariant hold for a third-party
/// plugin as well as an in-tree one — see [`attribution`].
///
/// **The declaration is per kind, not per root**, so a kind fronting roots that
/// disagree picks one answer for all of them. Declaring support gets the
/// wrapper, and what happens at a root that cannot store the stamp is then that
/// backend's own behaviour: the conformance rule asks it to refuse the write
/// rather than drop the key silently, but this declaration does not enforce
/// that. `omniverse-storage-service` declares support and deviates — it logs
/// and discards a metadata-service failure **when every key that failed is a
/// reserved one**, which is exactly the attribution stamp's case, though a
/// caller's own key failing there still fails the write. `opendal` is the same
/// shape and chose the other way, declining so that no branch of it is stamped
/// rather than accepting a refusal on the drivers that cannot store the key.
///
/// The coarseness is deliberate rather than a gap. Every consumer here runs at
/// stack-build or config-validation time, before any root is resolved, so a
/// per-root answer is not one they could read.
///
/// Placement is the only per-branch control available: one
/// [`AttributionWrapperFactory`] serves a whole process and every wrapper it
/// creates shares the host's single strategy, so a branch that must not stamp
/// omits the layer rather than configuring it differently. The process-wide
/// `passthrough` strategy is the blunter lever — it disables the inbound
/// sanitizer as well as the stamp, on every branch in the process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserMetadataKinds(HashMap<String, bool>);

impl UserMetadataKinds {
    /// The declarations carried by core's built-in factories plus `factories`,
    /// defaults first so a later factory of the same kind wins — the same
    /// precedence [`layer_types`] applies, and for the same reason: this must
    /// classify a graph exactly as `ovstorage::host::build_stack` will build it.
    ///
    /// A wrapper or router factory contributes nothing. Neither owns storage, so
    /// its descriptor's flag is not a claim about any, and a graph asking this
    /// about a non-backend layer has already gone wrong somewhere else.
    #[must_use]
    pub fn from_factories(factories: &[LoadedLayerFactory]) -> Self {
        Self(
            ovstorage::layers::default_layer_factories()
                .iter()
                .chain(factories)
                .map(|factory| factory.descriptor())
                .filter(|descriptor| descriptor.layer_type == LayerType::Backend)
                .map(|descriptor| (descriptor.kind, descriptor.supports_user_metadata))
                .collect(),
        )
    }

    /// The declarations carried by an already-discovered backend kind list, for
    /// a host that composes a graph from the kinds it will serve rather than
    /// from the loaded factory set.
    ///
    /// `kinds` is the whole set. Unlike [`Self::from_factories`], core's
    /// built-ins are not folded in, so a graph naming a built-in backend needs
    /// that kind's descriptor in `kinds` to be classified as
    /// [`ensure_branch_attribution`] would classify it.
    #[must_use]
    pub fn from_backend_kinds(kinds: &[StorageBackendKindDescriptor]) -> Self {
        Self(
            kinds
                .iter()
                .map(|descriptor| (descriptor.kind.clone(), descriptor.supports_user_metadata))
                .collect(),
        )
    }

    /// Declare `kind`'s support directly. For a test fixture or an embedding
    /// host composing a graph for kinds whose descriptors it does not hold.
    #[must_use]
    pub fn with(mut self, kind: impl Into<String>, supports_user_metadata: bool) -> Self {
        self.0.insert(kind.into(), supports_user_metadata);
        self
    }

    /// Whether a router branch fronting `backend_kind` carries an attribution
    /// wrapper.
    ///
    /// False for a kind that declares no support, and false for a kind that
    /// declares nothing at all.
    ///
    /// The three validation callers reach this only through `Graph::is_backend`,
    /// which requires a registered factory, so a kind they ask about has always
    /// declared something. [`attributed_router_layers`] is the exception and it
    /// is deliberate: it emits a graph before any plugin is loaded, so it asks
    /// about kinds its caller may hold no declaration for, and answering `false`
    /// there under-declares a branch that [`ensure_branch_attribution`] then
    /// completes.
    #[must_use]
    pub fn carries_attribution(&self, backend_kind: &str) -> bool {
        self.0.get(backend_kind).copied().unwrap_or(false)
    }
}

/// The attribution wrapper's layer name on `backend_kind`'s branch. Distinct per
/// branch because each branch gets its own instance, and distinct from the
/// backend layer name (`backend_kind`) that it wraps.
pub fn attribution_branch_name(backend_kind: &str) -> String {
    format!("{ATTRIBUTION_KIND}_{backend_kind}")
}

/// The router layer plus one branch per connected `kind`: a backend layer named
/// for the kind, fronted by its own attribution wrapper when `declared` says
/// that kind can carry user metadata. The router's child for a kind is therefore
/// the wrapper when present and the backend layer otherwise.
///
/// `declared` is passed in rather than derived here because this emits a graph
/// from connections alone, before any factory is loaded. The caller passes
/// whatever declarations it holds — often only core's built-ins — and this must
/// agree with what [`ensure_branch_attribution`] will accept from the loaded
/// set. Under-declaring is safe and is the common case; see the note on the
/// hosts' graph builders.
///
/// The router resolves a child by the targets that child owns, and
/// `Layer::owned_targets` delegates through `Layer::inner_layer`, so a wrapped
/// branch still advertises the backend layer's name as its routable target —
/// connection binding, which defaults a connection's target to its backend kind,
/// is unaffected by the interposed wrapper.
///
/// Shared by both remote hosts so the broker's and the gateway's graphs cannot
/// drift from each other.
pub fn attributed_router_layers(
    kinds: &BTreeSet<String>,
    declared: &UserMetadataKinds,
) -> Vec<(String, LayerTable)> {
    // Names are resolved against every name this graph will contain — the backend
    // layer per kind, plus the fixed wrapper names both hosts emit above the router
    // — before any of them is used. The declared-graph path applies the same
    // discipline through `taken_names`/`interposed_name`; without it here, a
    // connection whose kind is literally `attribution_s3` alongside one for `s3`
    // would emit that name twice, a caller collecting into a map would silently
    // keep one, and the graph that survived would be refused for a stacked pair on
    // two backend kinds that are individually fine.
    let mut taken: BTreeSet<String> = kinds.iter().cloned().collect();
    taken.insert(ROUTER_KIND.to_string());
    taken.extend(HOST_GRAPH_LAYER_NAMES.iter().map(|name| name.to_string()));

    let mut wrapper_names: HashMap<&str, String> = HashMap::new();
    for kind in kinds
        .iter()
        .filter(|kind| declared.carries_attribution(kind))
    {
        let mut name = attribution_branch_name(kind);
        let mut suffix = 1;
        while taken.contains(&name) {
            name = format!("{}_{suffix}", attribution_branch_name(kind));
            suffix += 1;
        }
        taken.insert(name.clone());
        wrapper_names.insert(kind.as_str(), name);
    }

    // A backend layer's name must BE its kind — the router binds a connection by
    // matching its target, which defaults to the backend kind, against a child's
    // owned targets — so a kind equal to the router's name or to a host layer's
    // name is a collision no renaming can resolve. It is also unreachable: those
    // names are ovstorage kind strings, and `Stack::builder` refuses two factories
    // of the same kind, so no backend plugin can register one. Asserted rather
    // than assumed, because the failure would be a silently overwritten layer.
    debug_assert!(
        kinds
            .iter()
            .all(|kind| kind != ROUTER_KIND && !is_reserved_host_layer_name(kind)),
        "a connected backend kind collides with a layer name the host emits; \
         `Stack::builder` should have refused the duplicate factory kind first",
    );

    let mut layers = Vec::with_capacity(kinds.len() + wrapper_names.len() + 1);
    layers.push((
        ROUTER_KIND.to_string(),
        LayerTable {
            kind: Some(ROUTER_KIND.to_string()),
            children: kinds
                .iter()
                .map(|kind| {
                    wrapper_names
                        .get(kind.as_str())
                        .cloned()
                        .unwrap_or_else(|| kind.clone())
                })
                .collect(),
            ..Default::default()
        },
    ));
    for kind in kinds {
        if let Some(name) = wrapper_names.get(kind.as_str()) {
            layers.push((
                name.clone(),
                ovstorage::host::wrapper_layer(ATTRIBUTION_KIND, kind),
            ));
        }
        layers.push((
            kind.clone(),
            LayerTable {
                kind: Some(kind.clone()),
                ..Default::default()
            },
        ));
    }
    layers
}

/// The layer names both hosts emit above the router in their default graphs. A
/// generated wrapper name must avoid these too: a connection kind colliding with
/// one of them would otherwise produce two layers with the same name.
/// Whether `name` is one of the layer names a host emits above the router, and so
/// is unavailable to a generated wrapper. Exposed so each host can assert its own
/// graph is covered — the list is hand-maintained here, and a host adding a layer
/// without updating it would reintroduce the collision silently.
pub fn is_reserved_host_layer_name(name: &str) -> bool {
    HOST_GRAPH_LAYER_NAMES.contains(&name)
}

const HOST_GRAPH_LAYER_NAMES: &[&str] = &[
    "alias",
    "copy_rename_fallback",
    "byte_cache",
    "metadata_cache",
    "redirect_follower",
    "retry",
    "upstream_credential",
];

/// The layer kind of a fork, for the graphs this crate emits
/// ([`attributed_router_layers`]). Classifying a *declared* graph asks the
/// registered factories instead — see [`Graph::is_fork`] — because a router kind
/// is not required to be called `router`, and a childless one is still a router.
const ROUTER_KIND: &str = "router";

/// A declared graph plus the layer types its registered factories give each kind.
///
/// The types are what make classification honest. A kind's *name* says nothing:
/// `mini-router` is a router, a childless router still forks, and a wrapper could
/// be named anything at all. Guessing from the name mistook a childless custom
/// router for a backend and let a wrapper be placed above a whole subtree.
struct Graph<'a> {
    config: &'a StackConfig,
    types: &'a HashMap<String, LayerType>,
    declared: &'a UserMetadataKinds,
}

impl<'a> Graph<'a> {
    /// The resolved kind of the layer named `name`: its explicit `kind`, else the
    /// layer name itself (the [`StackConfig`] default).
    fn kind(&self, name: &'a str) -> Option<&'a str> {
        self.config
            .layers
            .get(name)
            .map(|table| table.kind.as_deref().unwrap_or(name))
    }

    /// Whether `name` forks: its kind is registered as a router, or it declares
    /// children. A kind with no registered factory is not a router — the Stack
    /// builder refuses such a graph, and guessing would be how a false accept gets
    /// in.
    fn is_fork(&self, name: &str) -> bool {
        let Some(table) = self.config.layers.get(name) else {
            return false;
        };
        if !table.children.is_empty() {
            return true;
        }
        self.types
            .get(table.kind.as_deref().unwrap_or(name))
            .is_some_and(|layer_type| *layer_type == LayerType::Router)
    }

    /// Whether `name`'s kind is registered as a backend. Says nothing about the
    /// layer's shape; callers that need a leaf establish that themselves, via
    /// [`branch_end`].
    fn is_backend(&self, name: &str) -> bool {
        let Some(table) = self.config.layers.get(name) else {
            return false;
        };
        self.types
            .get(table.kind.as_deref().unwrap_or(name))
            .is_some_and(|layer_type| *layer_type == LayerType::Backend)
    }
}

/// Where a branch starting at `start` ends, walking its linear chain of `inner`
/// links: the terminal layer's name, its resolved kind, and the name of the layer
/// whose `inner` is that terminal (`None` when `start` is itself the terminal).
///
/// The parent matters because the wrapper belongs **directly above the backend**,
/// not somewhere in the branch. A branch may carry wrappers of its own — a
/// per-branch `copy_rename_fallback`, say — and that one fabricates writes and
/// issues them downward through its own `inner`. An instance anywhere above it is
/// outside the fabricated write's path, which is the exact defect the per-branch
/// layout exists to close. So position, not presence, is what counts, here as at
/// the graph root.
///
/// `None` when the chain is not a backend branch at all: it leaves the declared
/// graph, revisits a layer, or reaches a fork. A chain ending at a fork is that
/// fork's problem — its own children are branches and are visited on their own
/// turn — so wrapping it would put one instance above a whole subtree, including
/// subtree branches that must not be stamped.
struct BranchEnd<'a> {
    terminal: &'a str,
    kind: &'a str,
    parent: Option<&'a str>,
}

fn branch_end<'a>(graph: &Graph<'a>, start: &'a str) -> Option<BranchEnd<'a>> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut name = start;
    let mut parent = None;
    loop {
        if !seen.insert(name) {
            return None;
        }
        let kind = graph.kind(name)?;
        if graph.is_fork(name) {
            return None;
        }
        match graph.config.layers[name].inner.as_deref() {
            Some(inner) => {
                parent = Some(name);
                name = inner;
            }
            None => {
                return Some(BranchEnd {
                    terminal: name,
                    kind,
                    parent,
                });
            }
        }
    }
}

/// Every name the graph declares or refers to, whether or not the referent
/// exists. A generated name avoids the *referenced* set and not merely the
/// declared one, so that synthesizing a layer cannot silently adopt a name some
/// dangling `root`, `inner` or `children` entry already points at.
///
/// **This is belt-and-braces, not a demonstrated hazard.** The obvious argument
/// for it — that adopting such a name would resolve a dangling reference and turn
/// a config error into a live route — has not been realizable: a reviewer tried to
/// build that graph and every attempt either double-parented the interposed layer,
/// which `Stack::builder` rejects as referenced more than once, or left the
/// reference in a subtree the builder never walks. Reserving the wider set costs a
/// set union and keeps the emitted name independent of a reference the operator
/// may yet declare, which is worth having on its own.
///
/// `connections[].target` is deliberately NOT in this set. A target does not
/// resolve by layer name: a router matches it against its children's
/// `owned_targets`, and a leaf against its own name. The attribution wrapper
/// accepts no connections and so reports only its inner's target, which means a
/// generated wrapper name can never capture a connection.
fn taken_names(config: &StackConfig) -> BTreeSet<String> {
    let mut taken: BTreeSet<String> = config.layers.keys().cloned().collect();
    for table in config.layers.values() {
        if let Some(inner) = &table.inner {
            taken.insert(inner.clone());
        }
        taken.extend(table.children.iter().cloned());
    }
    if let Some(root) = &config.root {
        taken.insert(root.clone());
    }
    taken
}

/// A layer name for an interposed attribution wrapper over `backend` that
/// collides with nothing the graph declares or refers to.
fn interposed_name(config: &StackConfig, backend: &str) -> String {
    let taken = taken_names(config);
    let mut name = attribution_branch_name(backend);
    let mut suffix = 1;
    while taken.contains(&name) {
        name = format!("{}_{suffix}", attribution_branch_name(backend));
        suffix += 1;
    }
    name
}

/// Whether the attribution layer `name` is where an attribution layer belongs:
/// directly above a backend that can carry the reserved key. An attribution layer
/// is never that backend, so a stack of two does not count as one covering the
/// other.
fn is_well_placed_instance(graph: &Graph<'_>, name: &str) -> bool {
    let Some(inner) = graph.config.layers[name].inner.as_deref() else {
        return false;
    };
    match branch_end(graph, inner) {
        Some(end) => {
            end.terminal == inner
                && graph.is_backend(inner)
                && end.kind != ATTRIBUTION_KIND
                && graph.declared.carries_attribution(end.kind)
        }
        None => false,
    }
}

/// The layer type of every registered kind: core's built-ins plus `factories`.
///
/// Mirrors the map `ovstorage::host::build_stack` builds for itself, defaults
/// first so a later factory of the same kind wins — the pass must classify a graph
/// exactly as the builder will.
///
/// Classifying a graph needs these because a kind's *name* carries no authority: a
/// router need not be called `router`, a childless router still forks, and a
/// backend may be named anything at all.
pub fn layer_types(factories: &[LoadedLayerFactory]) -> HashMap<String, LayerType> {
    ovstorage::layers::default_layer_factories()
        .iter()
        .chain(factories)
        .map(|factory| {
            let descriptor = factory.descriptor();
            (descriptor.kind, descriptor.layer_type)
        })
        .collect()
}

/// Every layer reachable from the root through `inner` and `children`. The Stack
/// builder validates only what it can reach, so this is what separates "the
/// builder will report this better than we can" from "nobody will report it".
fn reachable_layers(config: &StackConfig) -> BTreeSet<&str> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut queue: Vec<&str> = config.root.as_deref().into_iter().collect();
    while let Some(name) = queue.pop() {
        if !seen.insert(name) {
            continue;
        }
        let Some(table) = config.layers.get(name) else {
            continue;
        };
        queue.extend(table.inner.as_deref());
        queue.extend(table.children.iter().map(String::as_str));
    }
    seen
}

/// Refuse a graph that declares a *reachable* attribution layer anywhere but
/// directly above a backend that can carry the reserved key.
///
/// **The host does not move it.** An earlier draft did, and rewriting an
/// operator's declared graph turned out to be a defect generator rather than a
/// convenience: three review rounds each found a fresh way for the rewrite to
/// answer a configuration the Stack builder would have rejected with a working
/// host instead — an undeclared `inner` that emptied the graph, a malformed table
/// whose extra fields vanished, a chain of instances that collapsed onto a
/// connection target and made an unbindable connection bind. Each was fixed by
/// narrowing the rewrite, and none of those was the last one, because the hazard
/// is the rewriting. A pass that only reads cannot cure anything.
///
/// So nothing an operator declared is rewritten or removed, and a misplaced
/// instance stops startup with its own name in the message. The remedy is two
/// edits either way: move the layer, or delete it — and in both cases re-point
/// whatever named it, since deleting a table alone leaves a dangling `root`,
/// `inner` or `children` entry and a second startup failure that says nothing
/// about attribution.
///
/// **Only a reachable instance refuses.** One the graph root cannot reach stamps
/// nothing, and the Stack builder's graph validation walks from the root and will
/// not mention it either, so refusing would take a host down over a table with no
/// effect, during a restart as readily as an upgrade. That one warns. (The builder
/// does still resolve every declared table's *kind*, so an unreachable layer of an
/// unregistered kind is rejected there — it is the shape that goes unchecked, not
/// the kind.)
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — one or more attribution layers are declared
///   somewhere other than directly above a capable backend.
fn refuse_misplaced_instances(graph: &Graph<'_>) -> Result<()> {
    // Without a root there is no reachability to reason about, and the Stack
    // builder refuses a graph with layers and no root. Nothing useful to add.
    if graph.config.root.is_none() {
        return Ok(());
    }
    let reachable = reachable_layers(graph.config);
    let instances = graph
        .config
        .layers
        .iter()
        .filter(|(name, table)| table.kind.as_deref().unwrap_or(name) == ATTRIBUTION_KIND);

    let mut refusals: Vec<(&str, String)> = Vec::new();
    for (name, table) in instances {
        if !reachable.contains(name.as_str()) {
            // Nothing routes through it, so it stamps nothing, wherever it sits.
            // The Stack builder's graph validation walks from the root and will not
            // mention it either. Refusing would take a host down over a table with
            // no effect, during a restart as readily as an upgrade — so say it out
            // loud instead, whether or not it would have been well placed.
            tracing::warn!(
                target: "ovstorage::attribution",
                layer = %name,
                "an attribution layer is declared but unreachable from the graph \
                 root, so it attributes nothing; delete it, or wire it in directly \
                 above a backend whose kind declares user-metadata support",
            );
            continue;
        }
        if is_well_placed_instance(graph, name) {
            continue;
        }
        let remedy = table
            .inner
            .as_deref()
            .and_then(|inner| remedy(graph, inner));
        // Reachable, and where it belongs cannot be worked out: no `inner`, an
        // `inner` naming nothing, a cycle, a kind with no registered factory. The
        // Stack builder rejects the graph and describes the real problem far better
        // than a placement message about its symptom would.
        let Some(remedy) = remedy else {
            continue;
        };
        refusals.push((name.as_str(), remedy));
    }
    if refusals.is_empty() {
        return Ok(());
    }
    refusals.sort_unstable();

    let detail = refusals
        .iter()
        .map(|(name, remedy)| format!("'{name}' {remedy}"))
        .collect::<Vec<_>>()
        .join("; ");
    Err(Error::new(
        ErrorCode::InvalidArgument,
        format!(
            "misplaced attribution layer: {detail}. An attribution layer belongs \
             directly above each backend whose kind declares user-metadata support \
             — so that a copy the backend declines, which the copy/rename fallback \
             emulates by fabricating a write below itself, is still attributed, and \
             so that a kind that declined the host's stamp is not handed one.\n\nThe \
             fix is two edits, not one: delete the layer's table AND re-point \
             whatever named it — `root`, another layer's `inner`, or a router's \
             `children` entry — at the layer it wrapped. Deleting the table alone \
             leaves a dangling reference and a second startup failure that does not \
             mention attribution. An instance is then placed on every branch whose \
             backend kind declares support; declaring them yourself works too, one \
             directly above each such backend."
        ),
    ))
}

/// The fork a chain of `inner` links from `start` reaches, if it reaches one.
/// `None` when the chain terminates at a backend, leaves the declared graph, or
/// revisits a layer.
fn chain_reaches_fork<'a>(graph: &Graph<'a>, start: &'a str) -> Option<&'a str> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut name = start;
    loop {
        if !seen.insert(name) {
            return None;
        }
        let table = graph.config.layers.get(name)?;
        if graph.is_fork(name) {
            return Some(name);
        }
        name = table.inner.as_deref()?;
    }
}

/// What to tell the operator about an instance sitting above `inner`.
///
/// `None` when the branch below does not resolve — a `inner` naming nothing, a
/// cycle. That is a different error, and the Stack builder describes it far better
/// than a placement message about its symptom would.
fn remedy(graph: &Graph<'_>, inner: &str) -> Option<String> {
    // Above a fork — directly, or through wrappers of its own, which is the shape a
    // graph written for the previous layout has. It covers the whole subtree,
    // including branches that must not be stamped, and where it belongs depends on
    // those branches, so name the fork rather than a backend.
    if let Some(fork) = chain_reaches_fork(graph, inner) {
        return Some(format!(
            "sits above the '{fork}' fork and covers every branch under it, \
             including any that must not be stamped; it belongs on the branches \
             below instead"
        ));
    }
    let end = branch_end(graph, inner)?;
    // A terminal that is not a backend means the graph is one the Stack builder
    // refuses anyway — an unregistered kind, or a wrapper with no `inner` — and its
    // message names the real problem. A placement message about the symptom would
    // preempt it and be wrong besides: an unregistered kind may well be a backend
    // whose plugin is simply not installed.
    graph.is_backend(end.terminal).then_some(())?;
    Some(if graph.declared.carries_attribution(end.kind) {
        format!("belongs directly above '{}'", end.terminal)
    } else {
        format!(
            "sits over '{}', whose kind declares no user-metadata support \
             (supports_user_metadata = false); that branch takes no attribution \
             layer at all",
            end.terminal
        )
    })
}

/// Guarantee that every branch which *can* carry attribution has an instance
/// **directly above its backend**, splicing one in where the declared graph does
/// not.
///
/// A branch is a fork's child, or — for a graph whose root chain reaches no fork —
/// the root chain itself. A branch's backend is the layer its chain of `inner`
/// links terminates at. A branch whose backend kind declares no user-metadata
/// support is left alone: the omission there is the design, not an oversight, and
/// an instance would, under the default `user_metadata` strategy, stamp the
/// host's reserved key into writes whose caller asked for none, against a kind
/// that declined to receive it.
///
/// The emitted graph does not depend on layer iteration order: branches are
/// visited in a deterministic order, and each interposed layer is named for the
/// backend it wraps.
///
/// **The test is position, not presence, and that is the whole point.** A
/// presence-anywhere check fails twice over. A graph whose every branch
/// legitimately omits attribution declares none at all, so a root-injecting guard
/// would put one back over the router and restore — for exactly the deployments
/// this layout exists to serve — the stamping the layout removed. And a graph
/// declaring an instance high in a branch, above that branch's own
/// `copy_rename_fallback`, would count as covered while its emulated copies went
/// unattributed.
///
/// The guarantee is two-sided, but only one side writes. An instance declared
/// anywhere other than directly above a capable backend makes this **refuse the
/// graph**, naming the layer. It is not moved: rewriting an operator's declared
/// graph turned out to be a defect generator, because a pass that writes can
/// answer a configuration the Stack builder would have rejected with a working
/// host instead, and a pass that only reads cannot. Otherwise the guarantee would be one-way, and a graph
/// written for the previous layout, one wrapper at the root over the router, would
/// keep it and go on stamping the very branches this exempts.
///
/// An already-correct branch is left untouched, so the result is canonical and
/// running the pass over its own output changes nothing.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the graph declares a reachable attribution
///   layer somewhere other than directly above a capable backend.
pub fn ensure_branch_attribution(
    mut config: StackConfig,
    types: &HashMap<String, LayerType>,
    declared: &UserMetadataKinds,
) -> Result<StackConfig> {
    refuse_misplaced_instances(&Graph {
        config: &config,
        types,
        declared,
    })?;
    // Every fork's children, plus the root chain — which is a branch in its own
    // right whenever it reaches no fork. Collecting both, rather than treating a
    // forkless graph as a special case, keeps a router that nothing routes to from
    // deciding whether the live root branch is covered.
    let mut branches: Vec<String> = Vec::new();
    if let Some(root) = config.root.clone() {
        branches.push(root);
    }
    let mut forks: Vec<String> = config
        .layers
        .keys()
        .filter(|name| {
            Graph {
                config: &config,
                types,
                declared,
            }
            .is_fork(name)
        })
        .cloned()
        .collect();
    // Sorted, because `interposed_name` resolves a collision against the map as
    // it grows: two branches whose generated names collide with each other, or
    // with a layer already squatting one, would otherwise be named according to
    // `HashMap` iteration order and the emitted graph would differ run to run.
    forks.sort();

    for branch in branches {
        let Some((terminal, parent)) = placement(
            &Graph {
                config: &config,
                types,
                declared,
            },
            &branch,
        ) else {
            continue;
        };
        match parent {
            // A root that is itself the backend: the wrapper becomes the new root.
            None => {
                let name = interpose_at_head(&mut config, &terminal);
                config.root = Some(name);
            }
            Some(parent) => interpose_above(&mut config, &parent, &terminal),
        }
    }

    for fork in forks {
        let children = config.layers[&fork].children.clone();
        let mut rewritten = Vec::with_capacity(children.len());
        for child in children {
            let Some((terminal, parent)) = placement(
                &Graph {
                    config: &config,
                    types,
                    declared,
                },
                &child,
            ) else {
                rewritten.push(child);
                continue;
            };
            match parent {
                // The child IS the backend, so the wrapper becomes the child.
                None => rewritten.push(interpose_at_head(&mut config, &terminal)),
                // The branch has wrappers of its own; the instance goes under
                // them, directly over the backend.
                Some(parent) => {
                    interpose_above(&mut config, &parent, &terminal);
                    rewritten.push(child);
                }
            }
        }
        config
            .layers
            .get_mut(&fork)
            .expect("fork layer collected from this map")
            .children = rewritten;
    }
    Ok(config)
}

/// Where a wrapper is needed on the branch at `start`, as `(backend, parent)`.
/// `None` when the branch is not a backend branch, when its backend cannot carry
/// attribution, or when the layer directly above that backend already is one.
fn placement(graph: &Graph<'_>, start: &str) -> Option<(String, Option<String>)> {
    let end = branch_end(graph, start)?;
    // A terminal that is itself an attribution layer is not a backend; wrapping it
    // would stack one instance on another over nothing.
    if !graph.is_backend(end.terminal)
        || end.kind == ATTRIBUTION_KIND
        || !graph.declared.carries_attribution(end.kind)
    {
        return None;
    }
    let covered = end
        .parent
        .and_then(|parent| graph.kind(parent))
        .is_some_and(|kind| kind == ATTRIBUTION_KIND);
    if covered {
        return None;
    }
    Some((end.terminal.to_string(), end.parent.map(str::to_string)))
}

/// Insert a wrapper over `backend` and return its name, for a caller that will
/// re-point a fork's child at it.
fn interpose_at_head(config: &mut StackConfig, backend: &str) -> String {
    let name = interposed_name(config, backend);
    tracing::info!(
        target: "ovstorage::attribution",
        layer = %name,
        backend = %backend,
        "placed an attribution layer over a backend that declared none",
    );
    config.layers.insert(
        name.clone(),
        ovstorage::host::wrapper_layer(ATTRIBUTION_KIND, backend),
    );
    name
}

/// Splice a wrapper between `parent` and its `inner`, `backend`.
fn interpose_above(config: &mut StackConfig, parent: &str, backend: &str) {
    let name = interpose_at_head(config, backend);
    config
        .layers
        .get_mut(parent)
        .expect("parent walked from this map")
        .inner = Some(name);
}

/// Add the shared remote-host wrapper factories and guarantee the listener's
/// auth-free inner stack carries attribution on every branch that can hold it
/// ([`ensure_branch_attribution`]). Broker and REST supply only their attribution
/// strategy and host-specific override factories.
/// # Errors
///
/// - [`ErrorCode::NotConfigured`] — `strategy` is not implemented. Checked here
///   rather than left to wrapper construction, which a graph with no
///   attribution-carrying branch never reaches.
/// - [`ErrorCode::InvalidArgument`] — the graph declares a reachable attribution
///   layer somewhere other than directly above a backend that can carry the
///   reserved key ([`ensure_branch_attribution`]).
pub fn prepare_listener_inner_stack(
    stack_config: StackConfig,
    mut factories: Vec<LoadedLayerFactory>,
    strategy: AttributionStrategy,
    extra_factories: Vec<LoadedLayerFactory>,
) -> Result<(StackConfig, Vec<LoadedLayerFactory>)> {
    // Host-provided factories are deliberate overrides (for example, a broker
    // test or deployment may inject a cache factory that owns an already-open
    // shared cache). Replace a plugin factory of the same kind before handing
    // the set to `build_stack`, whose duplicate-kind rejection remains useful
    // for accidental collisions inside the discovered plugin set.
    for extra in extra_factories {
        let kind = factory_kind(&extra);
        factories.retain(|factory| factory_kind(factory) != kind);
        factories.push(extra);
    }
    // This trust-boundary wrapper is host-owned. Append it after applying
    // plugin overrides so an extra with its reserved kind reaches
    // build_stack's duplicate-kind rejection instead of replacing the host
    // factory silently.
    factories.push(LoadedLayerFactory::Wrapper(Arc::new(
        AttributionWrapperFactory::new(strategy),
    )));
    // Validate the process-wide strategy once, independent of the graph. The
    // strategy's only other check is inside `AttributionWrapperFactory`, which runs
    // when a graph instantiates a wrapper — and a host whose every branch declares
    // no user-metadata support instantiates none. Without this, `external_db` would
    // boot such a host silently on a strategy documented as unimplemented, which is
    // exactly the deployment that composes no wrapper at all.
    AttributionLayer::new(strategy)?;
    let types = layer_types(&factories);
    let declared = UserMetadataKinds::from_factories(&factories);
    Ok((
        ensure_branch_attribution(stack_config, &types, &declared)?,
        factories,
    ))
}

fn factory_kind(factory: &LoadedLayerFactory) -> String {
    match factory {
        LoadedLayerFactory::Backend(factory) => factory.descriptor().kind,
        LoadedLayerFactory::Wrapper(factory) => factory.descriptor().kind,
        LoadedLayerFactory::Router(factory) => factory.descriptor().kind,
    }
}

/// An authenticated caller. Produced host-side by the broker's gRPC-metadata /
/// OAuth relay or REST's JWT/OIDC middleware; the in-stack authz Layer consumes
/// only the `id` (via `ext::PRINCIPAL_ID`), while `attributes`/`source`/
/// `valid_until` are carried for attribution and future attribute-based policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    pub display_name: Option<String>,
    pub attributes: HashMap<String, String>,
    pub valid_until: Option<SystemTime>,
    pub source: String,
}

impl Principal {
    pub fn anonymous() -> Self {
        Self {
            id: "anonymous".into(),
            display_name: None,
            attributes: HashMap::new(),
            valid_until: None,
            source: "anonymous".into(),
        }
    }
}

#[cfg(test)]
mod branch_attribution_tests {
    use super::*;

    fn parse(toml: &str) -> StackConfig {
        StackConfig::from_toml_str(toml).expect("fixture parses")
    }

    /// The pass over a graph it accepts.
    /// The layer types the fixtures' kinds resolve to. Written out rather than
    /// derived, because the point of taking types from the registered factories is
    /// that a kind's NAME does not determine its type — `mini_router` is a router
    /// and `looks_like_router` is not.
    fn types() -> HashMap<String, LayerType> {
        [
            ("router", LayerType::Router),
            ("mini_router", LayerType::Router),
            (ATTRIBUTION_KIND, LayerType::Wrapper),
            ("alias", LayerType::Wrapper),
            ("copy_rename_fallback", LayerType::Wrapper),
            ("retry", LayerType::Wrapper),
            ("redirect_follower", LayerType::Wrapper),
            ("byte_cache", LayerType::Wrapper),
            ("metadata_cache", LayerType::Wrapper),
            ("file", LayerType::Backend),
            ("s3", LayerType::Backend),
            ("gcs", LayerType::Backend),
            ("azure", LayerType::Backend),
            ("nucleus", LayerType::Backend),
            ("opendal", LayerType::Backend),
            ("http", LayerType::Backend),
            ("looks_like_router", LayerType::Backend),
        ]
        .into_iter()
        .map(|(kind, layer_type)| (kind.to_string(), layer_type))
        .collect()
    }

    /// What the fixtures' backend kinds declare about user metadata. Written out
    /// for the same reason [`types`] is: the declaration is the plugin's, and no
    /// property of a kind's name stands in for it. The three that decline mirror
    /// what the in-tree plugins of those kinds declare.
    fn declared() -> UserMetadataKinds {
        let mut declared = UserMetadataKinds::default();
        for (kind, layer_type) in types() {
            if layer_type == LayerType::Backend {
                let supports = !["nucleus", "opendal", "http"].contains(&kind.as_str());
                declared = declared.with(kind, supports);
            }
        }
        declared
    }

    fn accepted(toml: &str) -> StackConfig {
        ensure_branch_attribution(parse(toml), &types(), &declared()).expect("graph is accepted")
    }

    /// The message the pass refuses a graph with.
    fn refused(toml: &str) -> String {
        let error = ensure_branch_attribution(parse(toml), &types(), &declared())
            .expect_err("graph is refused");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        error.message().to_string()
    }

    /// Every graph shape this module reasons about, in one place, so a property
    /// that must hold for all of them can be asserted over all of them.
    const ADVERSARIAL_GRAPHS: &[&str] = &[
        r#"
[ovstorage]
root = "router"
[ovstorage.layers.router]
kind = "router"
children = ["attribution_file"]
[ovstorage.layers.attribution_file]
kind = "attribution"
inner = "file"
[ovstorage.layers.file]
kind = "file"
"#,
        r#"
[ovstorage]
root = "router"
[ovstorage.layers.router]
kind = "router"
children = ["s3", "opendal", "nucleus", "http"]
[ovstorage.layers.s3]
kind = "s3"
[ovstorage.layers.opendal]
kind = "opendal"
[ovstorage.layers.nucleus]
kind = "nucleus"
[ovstorage.layers.http]
kind = "http"
"#,
        r#"
[ovstorage]
root = "attribution"
[ovstorage.layers.attribution]
kind = "attribution"
inner = "alias"
[ovstorage.layers.alias]
kind = "alias"
inner = "router"
[ovstorage.layers.router]
kind = "router"
children = ["s3", "nucleus"]
[ovstorage.layers.s3]
kind = "s3"
[ovstorage.layers.nucleus]
kind = "nucleus"
"#,
        r#"
[ovstorage]
root = "upper"
[ovstorage.layers.upper]
kind = "attribution"
inner = "lower"
[ovstorage.layers.lower]
kind = "attribution"
inner = "nucleus"
[ovstorage.layers.nucleus]
kind = "nucleus"
"#,
        r#"
[ovstorage]
root = "upper"
[ovstorage.layers.upper]
kind = "attribution"
inner = "lower"
[ovstorage.layers.lower]
kind = "attribution"
inner = "s3"
[ovstorage.layers.s3]
kind = "s3"
"#,
        r#"
[ovstorage]
root = "router"
[ovstorage.layers.router]
kind = "router"
children = ["high"]
[ovstorage.layers.high]
kind = "attribution"
inner = "crf"
[ovstorage.layers.crf]
kind = "copy_rename_fallback"
inner = "s3"
[ovstorage.layers.s3]
kind = "s3"
"#,
        r#"
[ovstorage]
root = "outer"
[ovstorage.layers.outer]
kind = "router"
children = ["hop"]
[ovstorage.layers.hop]
kind = "retry"
inner = "inner_router"
[ovstorage.layers.inner_router]
kind = "router"
children = ["s3", "nucleus"]
[ovstorage.layers.s3]
kind = "s3"
[ovstorage.layers.nucleus]
kind = "nucleus"
"#,
        r#"
[ovstorage]
root = "retry"
[ovstorage.layers.retry]
kind = "retry"
inner = "file"
[ovstorage.layers.file]
kind = "file"
[ovstorage.layers.orphan_router]
kind = "router"
children = ["nucleus"]
[ovstorage.layers.nucleus]
kind = "nucleus"
"#,
        r#"
[ovstorage]
root = "file"
[ovstorage.layers.file]
kind = "file"
"#,
        r#"
[ovstorage]
root = "attribution"
[ovstorage.layers.attribution]
kind = "attribution"
inner = "s3_prod"
"#,
        r#"
[ovstorage]
root = "router"
[ovstorage.layers.router]
kind = "router"
children = ["ghost", "loop_a"]
[ovstorage.layers.loop_a]
kind = "attribution"
inner = "loop_b"
[ovstorage.layers.loop_b]
kind = "retry"
inner = "loop_a"
"#,
        r#"
[ovstorage]
root = "a"
[ovstorage.layers.a]
kind = "attribution"
inner = "router"
children = ["ghost"]
[ovstorage.layers.router]
kind = "router"
children = ["file"]
[ovstorage.layers.file]
kind = "file"
"#,
        r#"
[ovstorage]
root = "f1"
[ovstorage.layers.f1]
kind = "router"
children = ["s3"]
[ovstorage.layers.f2]
kind = "router"
children = ["s3_1"]
[ovstorage.layers.attribution_s3]
kind = "retry"
[ovstorage.layers.s3]
kind = "s3"
[ovstorage.layers.s3_1]
kind = "s3"
"#,
        r#"
[ovstorage]
root = "attribution"
[ovstorage.layers.attribution]
kind = "attribution"
inner = "fanout"
[ovstorage.layers.fanout]
kind = "mini_router"
"#,
        r#"
[ovstorage]
root = "looks_like_router"
[ovstorage.layers.looks_like_router]
kind = "looks_like_router"
"#,
        r#"
[ovstorage]
root = "router"
[ovstorage.layers.router]
kind = "router"
children = ["attribution_file"]
[ovstorage.layers.attribution_file]
kind = "attribution"
inner = "file"
[ovstorage.layers.file]
kind = "file"
[ovstorage.layers.old_attribution]
kind = "attribution"
inner = "router"
[ovstorage.layers.stray]
kind = "attribution"
"#,
        r#"
[ovstorage]
root = "high"
[ovstorage.layers.high]
kind = "attribution"
inner = "retry"
[ovstorage.layers.retry]
kind = "retry"
inner = "file"
[ovstorage.layers.file]
kind = "file"
[[ovstorage.connections]]
backend_kind = "file"
target = "high"
"#,
    ];

    /// The whole point of the per-branch layout: a graph whose every branch
    /// legitimately omits attribution declares none at all, and the guarantee
    /// must NOT answer that by putting one back over the router. A presence-
    /// anywhere, inject-at-root guard does exactly that, which would restore
    /// stamping — and with it the `Unsupported` on every Nucleus write — for the
    /// deployment this layout exists to serve.
    #[test]
    fn a_graph_whose_every_branch_declines_attribution_gains_none() {
        let config = accepted(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["nucleus"]

[ovstorage.layers.nucleus]
kind = "nucleus"
"#,
        );

        assert_eq!(config.root.as_deref(), Some("router"));
        assert!(
            !config
                .layers
                .values()
                .any(|table| table.kind.as_deref() == Some(ATTRIBUTION_KIND)),
            "no attribution layer may be injected when every branch declines it"
        );
        assert_eq!(
            config.layers["router"].children,
            vec!["nucleus".to_string()]
        );
    }

    /// A branch that can carry attribution and does not declare it gets a
    /// wrapper interposed between the router and the backend — and its sibling
    /// that cannot carry it is left alone in the same pass.
    #[test]
    fn a_capable_branch_gains_a_wrapper_and_its_sibling_does_not() {
        let config = accepted(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["s3", "opendal"]

[ovstorage.layers.s3]
kind = "s3"

[ovstorage.layers.opendal]
kind = "opendal"
"#,
        );

        let mut children = config.layers["router"].children.clone();
        children.sort();
        assert_eq!(
            children,
            vec!["attribution_s3".to_string(), "opendal".to_string()]
        );
        assert_eq!(config.layers["attribution_s3"].inner.as_deref(), Some("s3"));
        assert_eq!(
            config.layers["attribution_s3"].kind.as_deref(),
            Some(ATTRIBUTION_KIND)
        );
    }

    /// A graph with no fork is one branch from its root, and the guarantee still
    /// applies to it — this is the shape an embedding host composes when it wires
    /// a single backend with no router at all. The wrapper lands directly over
    /// the backend, under the branch's own wrappers, not at the root.
    #[test]
    fn a_forkless_graph_takes_the_wrapper_directly_over_its_backend() {
        let config = accepted(
            r#"
[ovstorage]
root = "retry"

[ovstorage.layers.retry]
kind = "retry"
inner = "file"

[ovstorage.layers.file]
kind = "file"
"#,
        );

        assert_eq!(config.root.as_deref(), Some("retry"));
        assert_eq!(
            config.layers["retry"].inner.as_deref(),
            Some("attribution_file")
        );
        assert_eq!(
            config.layers["attribution_file"].inner.as_deref(),
            Some("file")
        );
    }

    /// The placement that matters most, and the one a branch-head insert gets
    /// wrong: a branch carrying its own `copy_rename_fallback`. That wrapper
    /// fabricates a write and issues it downward, so an instance above it is
    /// outside the write's path exactly as a root instance was. The wrapper goes
    /// UNDER it, directly over the backend.
    #[test]
    fn a_branch_with_its_own_wrappers_takes_the_instance_under_them() {
        let config = accepted(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["branch_fallback"]

[ovstorage.layers.branch_fallback]
kind = "copy_rename_fallback"
inner = "s3"

[ovstorage.layers.s3]
kind = "s3"
"#,
        );

        assert_eq!(
            config.layers["router"].children,
            vec!["branch_fallback".to_string()],
            "the router still forks to the branch head"
        );
        assert_eq!(
            config.layers["branch_fallback"].inner.as_deref(),
            Some("attribution_s3"),
            "the instance is spliced below the fabricating wrapper"
        );
        assert_eq!(config.layers["attribution_s3"].inner.as_deref(), Some("s3"));
    }

    /// ... and a forkless graph terminating at a backend that cannot carry the
    /// key gains nothing, for the same reason the router case does not.
    #[test]
    fn a_forkless_incapable_graph_gains_nothing() {
        let config = accepted(
            r#"
[ovstorage]
root = "retry"

[ovstorage.layers.retry]
kind = "retry"
inner = "nucleus"

[ovstorage.layers.nucleus]
kind = "nucleus"
"#,
        );

        assert_eq!(config.root.as_deref(), Some("retry"));
        assert!(
            !config
                .layers
                .values()
                .any(|table| table.kind.as_deref() == Some(ATTRIBUTION_KIND))
        );
    }

    /// A branch reaching a nested router is not a backend branch: one wrapper
    /// there would front a whole subtree, including subtree branches that must
    /// not be stamped. The nested router's own children take wrappers instead.
    #[test]
    fn a_branch_reaching_a_nested_router_takes_no_wrapper_but_its_children_do() {
        let config = accepted(
            r#"
[ovstorage]
root = "outer"

[ovstorage.layers.outer]
kind = "router"
children = ["hop"]

[ovstorage.layers.hop]
kind = "retry"
inner = "inner_router"

[ovstorage.layers.inner_router]
kind = "router"
children = ["s3", "nucleus"]

[ovstorage.layers.s3]
kind = "s3"

[ovstorage.layers.nucleus]
kind = "nucleus"
"#,
        );

        assert_eq!(config.layers["outer"].children, vec!["hop".to_string()]);
        let mut inner = config.layers["inner_router"].children.clone();
        inner.sort();
        assert_eq!(
            inner,
            vec!["attribution_s3".to_string(), "nucleus".to_string()]
        );
        assert_eq!(
            config
                .layers
                .values()
                .filter(|table| table.kind.as_deref() == Some(ATTRIBUTION_KIND))
                .count(),
            1,
            "exactly one wrapper, on the one branch that can carry it"
        );
    }

    /// A child naming a layer the graph never declares, and a cycle in `inner`
    /// links, are both left exactly as written rather than being wrapped on a
    /// guess. The Stack builder is what rejects them.
    #[test]
    fn an_undeclared_child_and_a_cycle_are_left_alone() {
        let config = accepted(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["ghost", "loop_a"]

[ovstorage.layers.loop_a]
kind = "retry"
inner = "loop_b"

[ovstorage.layers.loop_b]
kind = "retry"
inner = "loop_a"
"#,
        );

        let mut children = config.layers["router"].children.clone();
        children.sort();
        assert_eq!(children, vec!["ghost".to_string(), "loop_a".to_string()]);
        assert!(
            !config
                .layers
                .values()
                .any(|table| table.kind.as_deref() == Some(ATTRIBUTION_KIND))
        );
    }

    /// A pre-existing layer already holding the generated name does not get
    /// clobbered; the interposed wrapper takes a name that is free.
    #[test]
    fn a_name_collision_does_not_clobber_the_existing_layer() {
        let config = accepted(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["s3"]

[ovstorage.layers.attribution_s3]
kind = "retry"

[ovstorage.layers.s3]
kind = "s3"
"#,
        );

        assert_eq!(
            config.layers["attribution_s3"].kind.as_deref(),
            Some("retry"),
            "the operator's layer keeps its name and its kind"
        );
        assert_eq!(
            config.layers["router"].children,
            vec!["attribution_s3_1".to_string()]
        );
        assert_eq!(
            config.layers["attribution_s3_1"].inner.as_deref(),
            Some("s3")
        );
    }

    /// A branch already carrying an instance directly over its backend is left
    /// exactly as the operator wrote it — accepted, and not given a second.
    #[test]
    fn a_branch_already_covered_over_its_backend_is_accepted_untouched() {
        let config = accepted(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["retry"]

[ovstorage.layers.retry]
kind = "retry"
inner = "mine"

[ovstorage.layers.mine]
kind = "attribution"
inner = "s3"

[ovstorage.layers.s3]
kind = "s3"
"#,
        );

        assert_eq!(config.layers["router"].children, vec!["retry".to_string()]);
        assert_eq!(config.layers["retry"].inner.as_deref(), Some("mine"));
        assert_eq!(
            config
                .layers
                .values()
                .filter(|table| table.kind.as_deref() == Some(ATTRIBUTION_KIND))
                .count(),
            1,
            "an operator's correctly-placed layer keeps its own name"
        );
    }

    /// **The shape every existing deployment upgrades from**: one instance at the
    /// root, over the router, with a `nucleus` branch beneath it. Adding
    /// per-branch instances while leaving that one alone would keep stamping the
    /// branch that was exempted, so `nucleus` would go on refusing every write and
    /// the change would have fixed nothing for the configuration that has the
    /// defect.
    ///
    /// The host refuses rather than moving it — see `refuse_misplaced_instances`
    /// — and names both the layer and the backend it belongs above, because the
    /// remedy is a one-line edit either way.
    #[test]
    fn a_root_instance_over_a_router_is_refused_and_named() {
        let message = refused(
            r#"
[ovstorage]
root = "attribution"

[ovstorage.layers.attribution]
kind = "attribution"
inner = "router"

[ovstorage.layers.router]
kind = "router"
children = ["s3", "nucleus"]

[ovstorage.layers.s3]
kind = "s3"

[ovstorage.layers.nucleus]
kind = "nucleus"
"#,
        );

        assert!(
            message.contains("'attribution' sits above the 'router' fork"),
            "the message must name the layer and what it is covering: {message}"
        );
        assert!(
            message.contains("belongs on the branches below"),
            "and must say where it goes instead: {message}"
        );
    }

    /// The realistic upgrade shape: the instance is not directly over the router,
    /// it is over the chain of wrappers that leads to it — which is exactly what
    /// the previous layout's shipped config looked like. Reaching the fork through
    /// wrappers is still sitting above the fork.
    #[test]
    fn a_root_instance_above_the_chain_to_a_router_is_refused_too() {
        let message = refused(
            r#"
[ovstorage]
root = "attribution"

[ovstorage.layers.attribution]
kind = "attribution"
inner = "alias"

[ovstorage.layers.alias]
kind = "alias"
inner = "router"

[ovstorage.layers.router]
kind = "router"
children = ["s3", "nucleus"]

[ovstorage.layers.s3]
kind = "s3"

[ovstorage.layers.nucleus]
kind = "nucleus"
"#,
        );
        assert!(
            message.contains("'attribution' sits above the 'router' fork"),
            "the fork is named even when reached through wrappers: {message}"
        );
    }

    /// Presence is not coverage. A branch declaring attribution ABOVE its own
    /// `copy_rename_fallback` loses every emulated copy, because that wrapper
    /// fabricates its write below itself — the same defect as a root instance, one
    /// level down. Refused for the same reason and with the same remedy.
    #[test]
    fn an_instance_above_a_branchs_own_fallback_is_refused() {
        let message = refused(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["high"]

[ovstorage.layers.high]
kind = "attribution"
inner = "branch_fallback"

[ovstorage.layers.branch_fallback]
kind = "copy_rename_fallback"
inner = "s3"

[ovstorage.layers.s3]
kind = "s3"
"#,
        );
        assert!(
            message.contains("'high' belongs directly above 's3'"),
            "{message}"
        );
    }

    /// Two instances stacked directly on one another: the upper is not covered by
    /// the lower, because an attribution layer is not a backend.
    #[test]
    fn a_stacked_instance_is_refused_and_the_lower_one_is_not() {
        let message = refused(
            r#"
[ovstorage]
root = "upper"

[ovstorage.layers.upper]
kind = "attribution"
inner = "lower"

[ovstorage.layers.lower]
kind = "attribution"
inner = "s3"

[ovstorage.layers.s3]
kind = "s3"
"#,
        );
        assert!(
            message.contains("'upper' belongs directly above 's3'"),
            "{message}"
        );
        assert!(
            !message.contains("'lower'"),
            "the lower instance is exactly where it belongs: {message}"
        );
    }

    /// Declaring an instance directly above a `nucleus`/`opendal`/`http` branch is
    /// the most likely hand-edit after reading "declaring them yourself works too,
    /// one directly above each capable backend" — the operator applies it to every
    /// branch. The message must say that branch takes no layer at all, rather than
    /// pointing them somewhere else to put it.
    #[test]
    fn an_instance_over_an_incapable_backend_is_told_it_belongs_nowhere() {
        let message = refused(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["attribution_nucleus", "attribution_s3"]

[ovstorage.layers.attribution_nucleus]
kind = "attribution"
inner = "nucleus"

[ovstorage.layers.nucleus]
kind = "nucleus"

[ovstorage.layers.attribution_s3]
kind = "attribution"
inner = "s3"

[ovstorage.layers.s3]
kind = "s3"
"#,
        );
        assert!(
            message.contains(
                "'attribution_nucleus' sits over 'nucleus', whose kind declares no \
                              user-metadata support (supports_user_metadata = false); \
                              that branch takes no attribution layer at all"
            ),
            "the operator must be told the branch takes none, not moved: {message}"
        );
        assert!(
            !message.contains("'attribution_s3'"),
            "the correctly-placed sibling must not be named: {message}"
        );
    }

    /// A graph the Stack builder would reject for its own reasons — an undeclared
    /// `inner`, a cycle — is passed through untouched. The builder's message about
    /// the real problem beats a placement message about a symptom, and a pass that
    /// only reads can never turn such a config into a working host.
    #[test]
    fn a_graph_the_builder_rejects_is_passed_through_not_diagnosed() {
        let dangling = accepted(
            r#"
[ovstorage]
root = "attribution"

[ovstorage.layers.attribution]
kind = "attribution"
inner = "s3_prod"
"#,
        );
        assert_eq!(dangling.root.as_deref(), Some("attribution"));
        assert_eq!(dangling.layers.len(), 1);

        let cyclic = accepted(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["loop_a"]

[ovstorage.layers.loop_a]
kind = "attribution"
inner = "loop_b"

[ovstorage.layers.loop_b]
kind = "retry"
inner = "loop_a"
"#,
        );
        assert_eq!(cyclic.layers["loop_a"].inner.as_deref(), Some("loop_b"));
        assert_eq!(cyclic.layers["loop_b"].inner.as_deref(), Some("loop_a"));
    }

    /// Nothing an operator declared is rewritten or removed. Asserted on a graph
    /// the pass ACCEPTS, because that is the only shape where survival is
    /// observable — a refusal returns no config to inspect.
    #[test]
    fn an_operators_own_fields_survive_the_pass() {
        let config = accepted(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["mine"]

[ovstorage.layers.mine]
kind = "attribution"
inner = "file"
some_operator_key = "please-keep-me"

[ovstorage.layers.file]
kind = "file"
"#,
        );

        assert_eq!(config.layers["router"].children, vec!["mine".to_string()]);
        assert_eq!(config.layers["mine"].inner.as_deref(), Some("file"));
        assert!(
            config.layers["mine"]
                .config
                .get("some_operator_key")
                .is_some_and(|value| value.as_str() == Some("please-keep-me")),
            "the pass reads; it does not rewrite what an operator wrote"
        );
    }

    /// And a layer carrying config in the WRONG place is still refused for its
    /// position — the extra keys are neither a licence nor an obstacle.
    #[test]
    fn a_misplaced_layer_carrying_config_is_still_refused() {
        let message = refused(
            r#"
[ovstorage]
root = "mine"

[ovstorage.layers.mine]
kind = "attribution"
inner = "router"
some_operator_key = "please-keep-me"

[ovstorage.layers.router]
kind = "router"
children = ["file"]

[ovstorage.layers.file]
kind = "file"
"#,
        );
        assert!(
            message.contains("'mine' sits above the 'router' fork"),
            "{message}"
        );
    }

    /// A router that nothing routes to must not decide whether the live root
    /// branch is covered. The root chain is a branch in its own right whenever it
    /// reaches no fork, so an orphaned router elsewhere in the graph cannot
    /// silently leave it unstamped.
    #[test]
    fn an_unreachable_router_does_not_disarm_the_live_root_branch() {
        let config = accepted(
            r#"
[ovstorage]
root = "retry"

[ovstorage.layers.retry]
kind = "retry"
inner = "file"

[ovstorage.layers.file]
kind = "file"

[ovstorage.layers.orphan_router]
kind = "router"
children = ["nucleus"]

[ovstorage.layers.nucleus]
kind = "nucleus"
"#,
        );

        assert_eq!(
            config.layers["retry"].inner.as_deref(),
            Some("attribution_file"),
            "the live root branch is covered regardless of the orphan"
        );
        assert_eq!(
            config.layers["attribution_file"].inner.as_deref(),
            Some("file")
        );
        // The orphan keeps its child here only because `nucleus` declines — not
        // because orphans are skipped. Branch collection is not reachability-
        // filtered, so an orphan fronting a CAPABLE backend does get a wrapper.
        // Recorded rather than asserted away: it affects nothing, since nothing
        // routes through it, and the pass warns about the result on a later run.
        assert_eq!(
            config.layers["orphan_router"].children,
            vec!["nucleus".to_string()]
        );

        let capable_orphan = accepted(
            r#"
[ovstorage]
root = "retry"

[ovstorage.layers.retry]
kind = "retry"
inner = "file"

[ovstorage.layers.file]
kind = "file"

[ovstorage.layers.orphan_router]
kind = "router"
children = ["s3"]

[ovstorage.layers.s3]
kind = "s3"
"#,
        );
        assert_eq!(
            capable_orphan.layers["retry"].inner.as_deref(),
            Some("attribution_file"),
            "the live branch is still covered"
        );
        assert_eq!(
            capable_orphan.layers["orphan_router"].children,
            vec!["attribution_s3".to_string()],
            "and an orphan fronting a capable backend is wrapped like any other"
        );
    }

    /// A graph that is nothing but its backend: the wrapper becomes the new root,
    /// named like every other branch instance rather than borrowing a second
    /// naming scheme for the one case that has no parent to splice under.
    #[test]
    fn a_bare_backend_root_becomes_its_own_branch() {
        let config = accepted(
            r#"
[ovstorage]
root = "file"

[ovstorage.layers.file]
kind = "file"
"#,
        );

        assert_eq!(config.root.as_deref(), Some("attribution_file"));
        assert_eq!(
            config.layers["attribution_file"].inner.as_deref(),
            Some("file")
        );
        assert_eq!(
            config.layers["attribution_file"].kind.as_deref(),
            Some(ATTRIBUTION_KIND)
        );
    }

    /// A router kind is not required to be called `router`, and a childless one is
    /// still a router. Classifying by name mistook `mini_router` for a backend, so
    /// an instance above it was accepted and a graph without one had a wrapper put
    /// above a whole subtree. The registered layer type is what decides.
    #[test]
    fn a_custom_router_kind_is_a_fork_not_a_backend() {
        let message = refused(
            r#"
[ovstorage]
root = "attribution"

[ovstorage.layers.attribution]
kind = "attribution"
inner = "fanout"

[ovstorage.layers.fanout]
kind = "mini_router"
"#,
        );
        assert!(
            message.contains("'attribution' sits above the 'fanout' fork"),
            "a childless custom router is still a fork: {message}"
        );

        // And nothing is placed above one when the graph declares no instance.
        let config = accepted(
            r#"
[ovstorage]
root = "fanout"

[ovstorage.layers.fanout]
kind = "mini_router"
"#,
        );
        assert!(
            !config
                .layers
                .values()
                .any(|table| table.kind.as_deref() == Some(ATTRIBUTION_KIND)),
            "a router is not a backend to wrap"
        );
    }

    /// The classifier's map comes from the registered factories in production, and
    /// the tests above write their own. This checks the two they overlap on —
    /// `file` and `attribution` — because those are the only kinds this crate can
    /// construct a factory for.
    ///
    /// **It does not cover the kinds that decline**: this crate cannot construct
    /// their factories, because a plugin crate may not depend on a host-side crate
    /// such as this one and two plugin rlibs in one test binary are a
    /// duplicate-symbol link error under `rust-lld`. Each plugin asserts its own
    /// declaration in its own crate instead. A rename of `nucleus` or `opendal`'s
    /// registered kind is caught by review, not by this test.
    #[test]
    fn the_real_factory_map_agrees_with_the_fixtures() {
        let real = layer_types(&[LoadedLayerFactory::Wrapper(Arc::new(
            AttributionWrapperFactory::new(AttributionStrategy::UserMetadata),
        ))]);

        assert_eq!(
            real.get("file"),
            Some(&LayerType::Backend),
            "core's built-in file backend must be in the map"
        );
        assert_eq!(
            real.get(ATTRIBUTION_KIND),
            Some(&LayerType::Wrapper),
            "and the host-owned attribution wrapper the caller registered"
        );
        let mut checked: Vec<&str> = Vec::new();
        for (kind, layer_type) in types() {
            if let Some(actual) = real.get(&kind) {
                assert_eq!(
                    *actual, layer_type,
                    "the fixture map disagrees with the real one about '{kind}'"
                );
                checked.push(Box::leak(kind.clone().into_boxed_str()));
            }
        }
        checked.sort_unstable();
        assert_eq!(
            checked,
            vec!["attribution", "file"],
            "this test's coverage is exactly these kinds; if that set changes, say \
             so here rather than letting the `if let` quietly widen or narrow it"
        );
    }

    /// A kind with no registered factory is nobody's backend, but saying so is not
    /// this pass's job: the Stack builder refuses that graph naming the kind and
    /// the provider it could not find, which is what an operator needs to read. A
    /// reachable instance over such a kind is passed through.
    ///
    /// Both fixtures put the terminal directly under a ROUTER rather than under an
    /// attribution layer. That matters: with an attribution parent, `placement`
    /// returns early on `covered` and never reaches the backend check, so the
    /// assertion would hold for a reason unrelated to what this test names — which
    /// is exactly how the first version of it passed with the check deleted.
    #[test]
    fn a_terminal_that_is_not_a_backend_is_left_to_the_builder() {
        // Unregistered kind: may well be a backend whose plugin is not installed.
        let unregistered = accepted(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["some_plugin_nobody_loaded"]

[ovstorage.layers.some_plugin_nobody_loaded]
kind = "some_plugin_nobody_loaded"
"#,
        );
        assert_eq!(
            unregistered.layers.len(),
            2,
            "nothing may be spliced over a kind whose plugin is merely absent: {:?}",
            unregistered.layers.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            unregistered.layers["router"].children,
            vec!["some_plugin_nobody_loaded".to_string()]
        );

        // Registered, and definitively not a backend: a wrapper kind as a leaf.
        // The Stack builder rejects it for having no `inner`; this pass must not
        // wrap it and pre-empt that.
        let wrapper_leaf = accepted(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["stray_retry"]

[ovstorage.layers.stray_retry]
kind = "retry"
"#,
        );
        assert_eq!(
            wrapper_leaf.layers.len(),
            2,
            "nothing may be spliced over a registered non-backend: {:?}",
            wrapper_leaf.layers.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            wrapper_leaf.layers["router"].children,
            vec!["stray_retry".to_string()]
        );
    }

    /// The converse, as a standing guard rather than a regression: a BACKEND whose
    /// kind merely looks like a router is a backend. No version of this code has
    /// classified by substring — the point is that none may start, now that the
    /// only correct source is the registered layer type.
    #[test]
    fn a_backend_kind_that_looks_like_a_router_is_still_a_backend() {
        let config = accepted(
            r#"
[ovstorage]
root = "looks_like_router"

[ovstorage.layers.looks_like_router]
kind = "looks_like_router"
"#,
        );
        assert_eq!(
            config.root.as_deref(),
            Some("attribution_looks_like_router")
        );
        assert_eq!(
            config.layers["attribution_looks_like_router"]
                .inner
                .as_deref(),
            Some("looks_like_router")
        );
    }

    /// An instance the graph root cannot reach stamps nothing, and the Stack
    /// builder — which validates only what it can reach — will not mention it
    /// either. Refusing would take a host down over a table with no effect, during
    /// a restart as readily as an upgrade, so it is accepted and warned about.
    ///
    /// This is the direction that bites an operator who moved `root` and left the
    /// old table behind, which is not the upgrade story at all.
    #[test]
    fn an_unreachable_instance_is_accepted_not_refused() {
        let config = accepted(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["attribution_file"]

[ovstorage.layers.attribution_file]
kind = "attribution"
inner = "file"

[ovstorage.layers.file]
kind = "file"

[ovstorage.layers.old_attribution]
kind = "attribution"
inner = "router"

[ovstorage.layers.stray]
kind = "attribution"
"#,
        );
        assert!(config.layers.contains_key("old_attribution"));
        assert!(config.layers.contains_key("stray"));
        assert_eq!(
            config.layers["router"].children,
            vec!["attribution_file".to_string()]
        );
    }

    /// A reachable instance whose placement cannot be worked out is passed through
    /// so the Stack builder can describe the real problem — a dangling `inner`, a
    /// cycle — rather than a placement message about its symptom.
    #[test]
    fn a_reachable_unresolvable_instance_is_left_to_the_builder() {
        let dangling = accepted(
            r#"
[ovstorage]
root = "attribution"

[ovstorage.layers.attribution]
kind = "attribution"
inner = "s3_prod"
"#,
        );
        assert_eq!(dangling.layers.len(), 1);

        let cyclic = accepted(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["loop_a"]

[ovstorage.layers.loop_a]
kind = "attribution"
inner = "loop_b"

[ovstorage.layers.loop_b]
kind = "retry"
inner = "loop_a"
"#,
        );
        assert_eq!(cyclic.layers["loop_a"].inner.as_deref(), Some("loop_b"));
    }

    /// `taken_names` reserves names the graph *refers to* as well as those it
    /// declares. The declared half is covered by the collision tests; this is the
    /// referenced half, where the desired name appears only as a dangling `root`,
    /// `inner` or `child`.
    ///
    /// Worth knowing what this does and does not buy. A reviewer tried to turn the
    /// documented hazard — a synthesized layer resolving a dangling reference and
    /// making a config error into a live route — into a working graph and could
    /// not: any surviving reference either double-parents the interposed layer,
    /// which the Stack builder rejects as referenced more than once, or sits in a
    /// subtree the builder never walks. So this is cheap belt-and-braces, and what
    /// the test pins is the mechanical behaviour: the wrapper takes a free name and
    /// the dangling reference is left exactly as written.
    #[test]
    fn a_generated_name_dodges_names_that_are_only_referenced() {
        for graph in [
            // Dangling child of a live router.
            r#"
[ovstorage]
root = "router"
[ovstorage.layers.router]
kind = "router"
children = ["attribution_s3", "s3"]
[ovstorage.layers.s3]
kind = "s3"
"#,
            // Dangling `inner`.
            r#"
[ovstorage]
root = "router"
[ovstorage.layers.router]
kind = "router"
children = ["hop", "s3"]
[ovstorage.layers.hop]
kind = "retry"
inner = "attribution_s3"
[ovstorage.layers.s3]
kind = "s3"
"#,
            // Dangling `root`.
            r#"
[ovstorage]
root = "attribution_s3"
[ovstorage.layers.router]
kind = "router"
children = ["s3"]
[ovstorage.layers.s3]
kind = "s3"
"#,
        ] {
            let config = accepted(graph);
            assert!(
                !config.layers.contains_key("attribution_s3"),
                "a synthesized layer must not adopt a name the graph refers to:\n{graph}"
            );
            let wrapper = config
                .layers
                .iter()
                .find(|(_, table)| {
                    table.kind.as_deref() == Some(ATTRIBUTION_KIND)
                        && table.inner.as_deref() == Some("s3")
                })
                .map(|(name, _)| name.as_str())
                .unwrap_or_else(|| panic!("no wrapper over s3:\n{graph}"));
            assert_eq!(wrapper, "attribution_s3_1", "{graph}");
        }
    }

    /// A router with no children is still a fork, not a backend of kind
    /// "router" — it must not be wrapped as though it were one.
    #[test]
    fn a_childless_router_is_not_mistaken_for_a_backend() {
        let config = accepted(
            r#"
[ovstorage]
root = "empty_router"

[ovstorage.layers.empty_router]
kind = "router"
"#,
        );

        assert_eq!(config.root.as_deref(), Some("empty_router"));
        assert!(
            !config
                .layers
                .values()
                .any(|table| table.kind.as_deref() == Some(ATTRIBUTION_KIND))
        );
    }

    /// Over every graph shape this module exercises: a graph the pass accepts is
    /// unchanged by a second pass, and a graph it refuses is refused again. Both
    /// halves matter — a pass that converged only on the second run, or that
    /// accepted on the second what it refused on the first, would be a host whose
    /// startup depended on how many times its own config had been normalized.
    #[test]
    fn the_pass_is_stable_over_every_shape_here() {
        for graph in ADVERSARIAL_GRAPHS {
            match ensure_branch_attribution(parse(graph), &types(), &declared()) {
                Ok(once) => {
                    let twice = ensure_branch_attribution(once.clone(), &types(), &declared())
                        .expect("a graph the pass accepts stays accepted");
                    assert_eq!(
                        once.root, twice.root,
                        "root differs on a second pass:\n{graph}"
                    );
                    assert_eq!(
                        once.layers, twice.layers,
                        "layers differ on a second pass:\n{graph}"
                    );
                    assert_eq!(
                        once.connections, twice.connections,
                        "connections differ on a second pass:\n{graph}"
                    );
                }
                Err(first) => {
                    let again = ensure_branch_attribution(parse(graph), &types(), &declared())
                        .expect_err("a graph the pass refuses stays refused");
                    assert_eq!(first.message(), again.message(), "{graph}");
                }
            }
        }
    }

    /// The same property spelled out on one concrete graph, for a reader who wants
    /// to see the shape rather than the corpus.
    #[test]
    fn the_pass_is_idempotent_over_its_own_output() {
        let graph = r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["s3", "nucleus"]

[ovstorage.layers.s3]
kind = "s3"

[ovstorage.layers.nucleus]
kind = "nucleus"
"#;
        let once = accepted(graph);
        let twice =
            ensure_branch_attribution(once.clone(), &types(), &declared()).expect("accepted");
        assert_eq!(once.root, twice.root);
        // Whole tables and the connection list, not a field subset: a change to a
        // layer's kind or config would slip through a narrower comparison.
        assert_eq!(once.layers, twice.layers);
        assert_eq!(once.connections, twice.connections);
    }

    #[test]
    fn the_result_does_not_depend_on_layer_iteration_order() {
        let graph = r#"
[ovstorage]
root = "top"

[ovstorage.layers.top]
kind = "router"
children = ["a", "b", "nucleus", "deep"]

[ovstorage.layers.a]
kind = "retry"
inner = "s3"

[ovstorage.layers.b]
kind = "copy_rename_fallback"
inner = "gcs"

[ovstorage.layers.nucleus]
kind = "nucleus"

[ovstorage.layers.deep]
kind = "router"
children = ["azure", "opendal"]

[ovstorage.layers.s3]
kind = "s3"

[ovstorage.layers.gcs]
kind = "gcs"

[ovstorage.layers.azure]
kind = "azure"

[ovstorage.layers.opendal]
kind = "opendal"
"#;

        fn shape(config: &StackConfig) -> Vec<(String, Option<String>, Vec<String>)> {
            let mut rows: Vec<_> = config
                .layers
                .iter()
                .map(|(name, table)| {
                    let mut children = table.children.clone();
                    children.sort();
                    (name.clone(), table.inner.clone(), children)
                })
                .collect();
            rows.sort();
            rows
        }

        // Two forks whose generated names can collide with each other and with a
        // layer already squatting one of them — the shape that made this
        // order-dependent before the visiting order was pinned.
        let colliding = r#"
[ovstorage]
root = "f1"

[ovstorage.layers.f1]
kind = "router"
children = ["s3"]

[ovstorage.layers.f2]
kind = "router"
children = ["s3_1"]

[ovstorage.layers.attribution_s3]
kind = "retry"

[ovstorage.layers.s3]
kind = "s3"

[ovstorage.layers.s3_1]
kind = "s3"
"#;

        for source in [graph, colliding] {
            let first = shape(&accepted(source));
            for _ in 0..32 {
                assert_eq!(
                    shape(&accepted(source)),
                    first,
                    "emitted graph must not depend on layer iteration order"
                );
            }
        }

        // On the colliding graph specifically: the squatter keeps its name and its
        // kind, and each backend gets its own distinct instance directly above it.
        let config = accepted(colliding);
        assert_eq!(
            config.layers["attribution_s3"].kind.as_deref(),
            Some("retry"),
            "the operator's layer is not clobbered"
        );
        let wrapper_for = |backend: &str| -> String {
            config.layers["f1"]
                .children
                .iter()
                .chain(config.layers["f2"].children.iter())
                .find(|child| config.layers[*child].inner.as_deref() == Some(backend))
                .cloned()
                .unwrap_or_else(|| panic!("no wrapper found over {backend}"))
        };
        let s3 = wrapper_for("s3");
        let s3_1 = wrapper_for("s3_1");
        assert_ne!(s3, s3_1, "each backend gets its own instance");
        for name in [&s3, &s3_1] {
            assert_eq!(
                config.layers[name].kind.as_deref(),
                Some(ATTRIBUTION_KIND),
                "{name} must be an attribution layer"
            );
        }

        // And it is the shape intended, not merely a stable wrong one.
        let config = accepted(graph);
        assert_eq!(config.layers["a"].inner.as_deref(), Some("attribution_s3"));
        assert_eq!(config.layers["b"].inner.as_deref(), Some("attribution_gcs"));
        let mut top = config.layers["top"].children.clone();
        top.sort();
        assert_eq!(
            top,
            vec![
                "a".to_string(),
                "b".to_string(),
                "deep".to_string(),
                "nucleus".to_string()
            ],
            "the nested router and the nucleus branch keep their own names"
        );
        let mut deep = config.layers["deep"].children.clone();
        deep.sort();
        assert_eq!(
            deep,
            vec!["attribution_azure".to_string(), "opendal".to_string()]
        );
    }

    /// `external_db` is documented as unimplemented and as refusing startup. Its
    /// other check runs when a graph instantiates an attribution wrapper — and a
    /// host whose every branch declares no user-metadata support instantiates none,
    /// which is exactly the deployment that composes no wrapper at all. Without the
    /// eager check such a host boots silently on a strategy that attributes
    /// nothing.
    ///
    /// The graph below carries a `nucleus` branch and nothing else, so it is the
    /// shape that used to slip through; the mixed graph is the shape that always
    /// refused, kept so a regression cannot pass by disabling the check entirely.
    #[test]
    fn external_db_refuses_whether_or_not_a_branch_carries_attribution() {
        let deny_listed_only = parse(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["nucleus"]

[ovstorage.layers.nucleus]
kind = "nucleus"
"#,
        );
        let carrying = parse(
            r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["attribution_s3"]

[ovstorage.layers.attribution_s3]
kind = "attribution"
inner = "s3"

[ovstorage.layers.s3]
kind = "s3"
"#,
        );

        for (label, config) in [
            ("no branch carries attribution", deny_listed_only),
            ("a branch carries attribution", carrying),
        ] {
            let error = match prepare_listener_inner_stack(
                config,
                Vec::new(),
                AttributionStrategy::ExternalDb,
                Vec::new(),
            ) {
                Ok(_) => panic!("external_db must refuse: {label}"),
                Err(error) => error,
            };
            assert_eq!(error.code(), ErrorCode::NotConfigured, "{label}");
            assert!(error.message().contains("external_db"), "{label}");
        }

        // And a supported strategy still gets through the same seam.
        prepare_listener_inner_stack(
            parse(
                r#"
[ovstorage]
root = "router"

[ovstorage.layers.router]
kind = "router"
children = ["nucleus"]

[ovstorage.layers.nucleus]
kind = "nucleus"
"#,
            ),
            Vec::new(),
            AttributionStrategy::UserMetadata,
            Vec::new(),
        )
        .map(|_| ())
        .expect("user_metadata is supported");
    }

    /// The emitted-graph path must be as careful with names as the declared-graph
    /// path. A connection whose kind is literally `attribution_s3`, alongside one
    /// for `s3`, would otherwise emit that name twice — a caller collecting into a
    /// map keeps one, the other backend layer vanishes, and the surviving graph is
    /// refused for a stacked pair built from two backend kinds that are each
    /// perfectly valid.
    #[test]
    fn emitted_wrapper_names_never_collide_with_a_backend_kind() {
        let kinds: BTreeSet<String> = ["s3", "attribution_s3", "nucleus"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let layers = attributed_router_layers(&kinds, &declared().with("attribution_s3", true));

        let mut names: Vec<&str> = layers.iter().map(|(name, _)| name.as_str()).collect();
        names.sort_unstable();
        let unique: BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(
            names.len(),
            unique.len(),
            "attributed_router_layers must never emit a name twice: {names:?}"
        );

        let map: HashMap<&str, &LayerTable> = layers.iter().map(|(n, t)| (n.as_str(), t)).collect();
        // Both backend layers survive, with their own kinds.
        assert_eq!(map["s3"].kind.as_deref(), Some("s3"));
        assert_eq!(
            map["attribution_s3"].kind.as_deref(),
            Some("attribution_s3"),
            "the backend kind keeps its own name; the wrapper takes a free one"
        );
        // Each carrying kind is fronted by exactly one wrapper over itself.
        for kind in ["s3", "attribution_s3"] {
            let wrapper = layers
                .iter()
                .find(|(_, t)| {
                    t.kind.as_deref() == Some(ATTRIBUTION_KIND) && t.inner.as_deref() == Some(kind)
                })
                .map(|(name, _)| name.as_str())
                .unwrap_or_else(|| panic!("no wrapper over {kind}"));
            assert!(map["router"].children.iter().any(|c| c == wrapper));
        }
        assert!(
            map["router"].children.iter().any(|c| c == "nucleus"),
            "nucleus is routed to directly"
        );

        // And the whole thing is a graph the guarantee accepts unchanged.
        let mut config = StackConfig {
            root: Some("router".into()),
            layers: layers.into_iter().collect(),
            connections: Vec::new(),
        };
        config.layers.insert(
            "attribution_s3".into(),
            config.layers["attribution_s3"].clone(),
        );
        let after = ensure_branch_attribution(
            config.clone(),
            &{
                let mut t = types();
                t.insert("attribution_s3".into(), LayerType::Backend);
                t
            },
            &declared().with("attribution_s3", true),
        )
        .expect("the emitted graph is accepted");
        assert_eq!(after.layers.len(), config.layers.len());
    }

    /// The graph the operator guide prints as its worked example must be one the
    /// pass accepts unchanged. A documented example a host refuses is worse than no
    /// example, and prose drifts from code exactly here.
    #[test]
    fn the_operator_guides_example_graph_is_accepted_unchanged() {
        let example = r#"
[ovstorage]
root = "alias"

[ovstorage.layers.alias]
inner = "copy_rename_fallback"

[ovstorage.layers.copy_rename_fallback]
inner = "byte_cache"

[ovstorage.layers.byte_cache]
inner = "metadata_cache"

[ovstorage.layers.metadata_cache]
inner = "redirect_follower"

[ovstorage.layers.redirect_follower]
inner = "retry"

[ovstorage.layers.retry]
inner = "router"

[ovstorage.layers.router]
children = ["attribution_s3"]

[ovstorage.layers.attribution_s3]
kind = "attribution"
inner = "s3"

[ovstorage.layers.s3]
kind = "s3"
"#;
        let before = parse(example);
        let after = accepted(example);
        assert_eq!(before.root, after.root);
        assert_eq!(
            before.layers, after.layers,
            "the guide's example must be a fixed point of the pass"
        );
    }

    /// A kind carries the wrapper when — and only when — something declared that
    /// it can. A kind nobody declared for gets no wrapper, which is the whole
    /// difference between asking the plugin and consulting a list the host wrote:
    /// a list has to guess for a kind it has never seen, and the guess that used
    /// to be made here put a stamp on backends that would refuse it.
    #[test]
    fn only_a_declared_kind_carries_a_wrapper() {
        let declared = declared();
        for kind in ["nucleus", "opendal", "http"] {
            assert!(
                !declared.carries_attribution(kind),
                "{kind} declares no user-metadata support and must decline"
            );
        }
        for kind in ["file", "s3", "gcs", "azure"] {
            assert!(
                declared.carries_attribution(kind),
                "{kind} declares user-metadata support and must carry"
            );
        }
        assert!(
            !declared.carries_attribution("some-third-party-kind"),
            "a kind that declared nothing must not be assumed to carry user metadata"
        );
    }

    /// The declarations come off the factories' own descriptors, and only off a
    /// backend's: a wrapper or router owns no storage, so its descriptor's flag
    /// is not a claim about any.
    #[test]
    fn declarations_are_read_from_backend_factory_descriptors() {
        struct StubBackend(bool);

        #[async_trait::async_trait]
        impl ovstorage::BackendFactory for StubBackend {
            fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
                ovstorage::LayerKindDescriptor {
                    kind: "stub".into(),
                    layer_type: LayerType::Backend,
                    display_name: "Stub".into(),
                    description: None,
                    config_schema: Vec::new(),
                    credential_schema: Vec::new(),
                    credential_methods: Vec::new(),
                    icon: None,
                    accepts_connections: true,
                    auth_capable: false,
                    supports_user_metadata: self.0,
                }
            }

            async fn create_backend(
                &self,
                _name: &str,
                _config: &ovstorage::LayerConfig,
                _cancel: Option<ovstorage::CancellationToken>,
            ) -> Result<ovstorage::LayerHandle> {
                Err(Error::new(ErrorCode::Unsupported, "fixture"))
            }
        }

        let carrying = UserMetadataKinds::from_factories(&[LoadedLayerFactory::Backend(Arc::new(
            StubBackend(true),
        ))]);
        assert!(carrying.carries_attribution("stub"));

        let declining = UserMetadataKinds::from_factories(&[LoadedLayerFactory::Backend(
            Arc::new(StubBackend(false)),
        )]);
        assert!(!declining.carries_attribution("stub"));

        // Core's built-in file backend is in the set without being passed in,
        // because `ensure_branch_attribution` must classify a graph exactly as
        // `build_stack` will build it.
        assert!(carrying.carries_attribution("file"));
    }

    /// The kind-list constructor reads the same field, from a descriptor an
    /// embedding host already holds rather than from a loaded factory. Pinned
    /// here because it has no in-tree caller: the field it must read sits beside
    /// `supports_runtime_add` on the same struct, and a constructor reading the
    /// neighbour — or a constant — would compose attribution over the wrong
    /// branches with nothing else in the tree noticing.
    #[test]
    fn declarations_are_read_from_backend_kind_descriptors() {
        fn descriptor(kind: &str, supports_user_metadata: bool) -> StorageBackendKindDescriptor {
            StorageBackendKindDescriptor {
                kind: kind.into(),
                display_name: "Stub".into(),
                description: None,
                config_schema: Vec::new(),
                credential_schema: Vec::new(),
                credential_methods: Vec::new(),
                icon: None,
                // The neighbouring flag, given the opposite value on both
                // descriptors so a constructor reading it fails this test.
                supports_runtime_add: !supports_user_metadata,
                supports_user_metadata,
            }
        }

        let declared = UserMetadataKinds::from_backend_kinds(&[
            descriptor("carrying", true),
            descriptor("declining", false),
        ]);
        assert!(declared.carries_attribution("carrying"));
        assert!(!declared.carries_attribution("declining"));
        // Unlike `from_factories`, this constructor is the whole set: a host
        // composing a graph from the kinds it will serve gets no built-ins it
        // did not pass in.
        assert!(!declared.carries_attribution("file"));
    }
}
