// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Address-translation wrappers: the real
//! `AliasWrapper` and `CopyRenameFallbackWrapper` that replace the
//! [`layers::PassThroughWrapper`](crate::layers) stubs. They implement alias
//! resolution and cross-root transfer as composable [`WrapperFactory`]
//! implementations.
//!
//! A caller-to-physical prefix rewrite is expressed as an
//! `AliasWrapper` `from`→`to` rule, whose `to` output the `Router` below then
//! routes to the owning backend. URL
//! canonicalization (scheme/host/port/encoding) is the `Stack` boundary's job
//! ([`ovstorage_layer::canonicalize`], shared with [`address::parse`]), not a
//! wrapper.
//!
//! - `AliasWrapper` — bounded multi-hop virtual→target rewrite:
//!   resolution follows chains of longest-prefix rules, where each hop
//!   applies only when its rule prefix is strictly more specific than the real
//!   route serving the current address (applied per hop), guarded by a fixed
//!   hop cap ([`MAX_ALIAS_HOPS`]) plus cycle
//!   detection and validated eagerly at build/configuration time. Results
//!   project back through the applied hops in reverse. Address-visibility is
//!   enforced on the caller-supplied address (`Suppressed` ⇒ rejected;
//!   `Hidden`/`Suppressed` ⇒ not advertised — only `Visible` roots/aliases are
//!   listed), and a root is synthesized for every visible alias
//!   (`RouteSource::Alias` + `AliasState::Live`/`Dangling`/`ChainTooLong`).
//!   It is the connection owner (`accepts_connections = true`): its rule state
//!   is a runtime-mutable set of credentialless alias connections managed
//!   through the operational vtable (`add_connection`/`remove_connection`/
//!   `probe`/`list_connections`/`update_connection_attributes`), per the
//!   RFC-0066 model of alias rules as credentialless connections.
//!
//! ## Returned-address projection
//!
//! `AliasWrapper` rewrites the inbound request address
//! (caller→physical) and **reverse-maps address-bearing results of rewritten
//! requests back** (physical→caller) so no lower layer (which can't see the
//! `from`→`to` rules) leaks a physical address: `stat`/`read`/
//! `get_latest_version`/`materialize`/`write`/`write_stream`/`continue_write`/
//! `copy` single addresses, every `list`/`list_versions` item,
//! `watch_directory` change-event addresses, and `root_info_for`/
//! `list_address_roots` root prefixes — matching host dispatch
//! path's caller-space projection (`info.address = addr`). Projection replays
//! exactly the hops the request's forward resolution applied, in reverse — a
//! request that was **not** rewritten is never projected, so a caller
//! addressing a rule's target space directly gets results echoed in its own
//! address space. A `ReadResult::Redirect` carries an external URL
//! and is left unprojected.
//!
//! ## Config model
//!
//! Each wrapper reads its rules from a TOML [`LayerConfig`] fragment
//! ([`ConfigValue::Toml`]) produced by the formal `[ovstorage.layers.*]`
//! schema. Canonical operator TOML authors the arrays under the
//! config key itself:
//!
//! ```toml
//! [[ovstorage.layers.<name>.aliases]]
//! from = "…"
//! to = "…"
//!
//! [[ovstorage.layers.<name>.visibility]]
//! address = "…"
//! visibility = "visible" # | "hidden" | "suppressed"
//! ```
//!
//! `config_value_from_toml` marshals
//! those into `ConfigValue::Toml` fragments whose top-level arrays are `aliases`
//! / `visibility`, which is exactly what [`parse_prefix_rules`] /
//! [`parse_visibility_rules`] deserialize. The legacy inline spelling
//! (`[[rule]]` / `[[entry]]`) stays accepted via `#[serde(alias)]` for
//! hand-built `ConfigValue` fragments.
//! Rule prefixes are parsed with [`address::parse`] so they normalize
//! identically to incoming addresses. Construction-time rules from
//! [`LayerConfig`] use the same shape; runtime rules added through
//! `add_connection` are in-memory only.
//!
//! ## Connection model
//!
//! The wrapper's rule state is one atomically-swapped write-locked rule set
//! ([`RuleSet`]) of `(target, id)`-identified rows; every reader (`resolve`,
//! visibility lookup, alias matching, both `list_address_roots` projection
//! paths) re-reads the current set per operation. Two connection shapes are
//! owned, both under `target = <this wrapper's name>`, discriminated by config
//! keys:
//!
//! - **alias rules** — config `{ from, to }`, a credentialless URL-rewrite
//!   rule (the RFC's canonical alias connection);
//! - **visibility overrides** — config `{ address, visibility }`.
//!
//! **Design decision (RFC left it open): visibility overrides are connections
//! in their own right, not attributes on alias connections.** Rationale: a
//! visibility override applies to an arbitrary address — including a real
//! backend root that has no alias connection to be an attribute of — so a
//! connection is the only shape that covers the general case; it keeps
//! `(target, id)` identity uniform (every mutable rule row is a removable
//! connection); and it carries the full three-category
//! `Visible`/`Hidden`/`Suppressed` value faithfully, which
//! [`AttributePatch::visible`] (a two-state `bool`) cannot express. Alias rows
//! carry no intrinsic visibility field — an alias's advertised visibility is
//! the longest-prefix match over the visibility overrides, exactly as the
//! construction-time catalog already resolves it. A non-`Visible` alias is
//! represented by a visibility override on the alias's `from`.
//! `update_connection_attributes` patches presentation (`display_name`,
//! `user_metadata`) on any owned row and maps `visible: Some(bool)` onto a
//! visibility override's two-state value; reaching `Suppressed` at runtime is
//! an add/remove of a visibility-override connection.
//!
//! Auth ops (`authenticate_connection`/`update_connection_credentials`) on an
//! alias row **delegate** to the downstream auth-bearing backend connection
//! (the "connection-owning wrapper may delegate" contract): the
//! wrapper walks the alias chain to the terminal physical address, identifies
//! the owning connection via `root_info_for`, re-targets the request to that
//! connection, and **re-projects** the response — `AuthEvent::Succeeded`'s
//! `connection` (and the `update_connection_credentials` return) keep the
//! alias's user-facing identity (id, kind, display name, alias-space
//! addresses) while carrying the backend's live auth facts; a
//! backend-referencing `ErrorContext::Auth` on a `Failed`/`Err` also
//! re-projects to the alias id. Delegation addresses the owning layer by its
//! **instance name**, recovered in-band via `Layer::owning_target_for`
//! (connection ops route by name, not descriptor kind, so a backend Layer
//! named differently from its kind is reached correctly). Visibility-override
//! rows remain credentialless (`Unsupported`).

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt as _;
use ovstorage_layer::ordered::{Deferred, Sequenced};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

use crate::layers::{ALIAS_KIND, descriptor};
use crate::routing::fresh_id;
use crate::*;

// ---------------------------------------------------------------------------
// Shared config parsing + rewrite helpers
// ---------------------------------------------------------------------------

/// The `aliases` config value: an array of `{ from, to }` rewrite rules.
///
/// Canonical operator TOML authors the array under the config key itself —
/// `[[ovstorage.layers.<name>.aliases]] from=… to=…` — which
/// `config_value_from_toml` marshals
/// into a `ConfigValue::Toml` whose top-level array is named `aliases`. The
/// legacy inline spelling (`[[rule]]`, used by hand-built `ConfigValue`
/// fragments and older tests) stays accepted through `#[serde(alias)]`.
#[derive(Serialize, Deserialize)]
struct PrefixRuleSet {
    #[serde(default, alias = "rule")]
    aliases: Vec<PrefixRule>,
}

#[derive(Serialize, Deserialize)]
struct PrefixRule {
    from: String,
    to: String,
}

/// The `visibility` config value: an array of `{ address, visibility }`
/// overrides. Canonical operator TOML authors the array under the config key
/// (`[[ovstorage.layers.<name>.visibility]] address=… visibility=…`); the
/// legacy inline spelling (`[[entry]]`) stays accepted through `#[serde(alias)]`.
#[derive(Serialize, Deserialize)]
struct VisibilityRuleSet {
    #[serde(default, alias = "entry")]
    visibility: Vec<VisibilityRule>,
}

#[derive(Serialize, Deserialize)]
struct VisibilityRule {
    address: String,
    visibility: VisibilityKind,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VisibilityKind {
    Visible,
    Hidden,
    Suppressed,
}

impl From<AddressVisibility> for VisibilityKind {
    fn from(visibility: AddressVisibility) -> Self {
        match visibility {
            AddressVisibility::Visible => VisibilityKind::Visible,
            AddressVisibility::Hidden => VisibilityKind::Hidden,
            AddressVisibility::Suppressed => VisibilityKind::Suppressed,
        }
    }
}

impl From<VisibilityKind> for AddressVisibility {
    fn from(kind: VisibilityKind) -> Self {
        match kind {
            VisibilityKind::Visible => AddressVisibility::Visible,
            VisibilityKind::Hidden => AddressVisibility::Hidden,
            VisibilityKind::Suppressed => AddressVisibility::Suppressed,
        }
    }
}

/// Parse `(from, to)` URL-prefix rules from a TOML `LayerConfig` fragment.
/// Absent key ⇒ no rules.
fn parse_prefix_rules(config: &LayerConfig, key: &str) -> Result<Vec<(Url, Url)>> {
    let Some(value) = config.get(key) else {
        return Ok(Vec::new());
    };
    let ConfigValue::Toml(text) = value else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("`{key}` must be a TOML table"),
        ));
    };
    let parsed: PrefixRuleSet = toml::from_str(text).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("`{key}` TOML parse error: {error}"),
        )
    })?;
    parsed
        .aliases
        .into_iter()
        .map(|rule| Ok((parse_url(&rule.from, key)?, parse_url(&rule.to, key)?)))
        .collect()
}

fn parse_visibility_rules(
    config: &LayerConfig,
    key: &str,
) -> Result<Vec<(Url, AddressVisibility)>> {
    let Some(value) = config.get(key) else {
        return Ok(Vec::new());
    };
    let ConfigValue::Toml(text) = value else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("`{key}` must be a TOML table"),
        ));
    };
    let parsed: VisibilityRuleSet = toml::from_str(text).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("`{key}` TOML parse error: {error}"),
        )
    })?;
    // Validated by the caller, which covers both this path and the
    // programmatic one.
    parsed
        .visibility
        .into_iter()
        .map(|entry| Ok((parse_url(&entry.address, key)?, entry.visibility.into())))
        .collect()
}

fn parse_url(text: &str, key: &str) -> Result<Url> {
    // The string boundary is where a config address is refused for carrying a
    // component nothing here reads: an alias rule and a visibility rule are
    // matched on scheme, authority and path, and a fragment never leaves the
    // client at all. [`address::refused_config_component`] is the one predicate
    // every config loader in the workspace shares.
    //
    // **It has to run here rather than in the validators below, and only for
    // the fragment is that a difference that matters.** `address::parse`
    // strips a fragment on the way through `canonicalize`, so a validator
    // holding a `Url` has nothing left to inspect — a post-parse fragment check
    // is a guard that cannot execute. The query refusals in
    // [`validate_alias_rules`] and [`validate_visibility_rules`] stay, and are
    // not a second copy of this one: they cover `AliasWrapperFactory::with_rules`,
    // which takes `Url` values a caller built programmatically and for which no
    // string ever existed.
    //
    // The raw text is not echoed. A query is exactly where a signature or an
    // API key lives, and this message is a startup failure that reaches a log.
    if let Some(component) = address::refused_config_component(text) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "`{key}` address must not carry a {}; an address names a node, and alias and \
                 visibility rules are matched on scheme, authority and path alone. Write it \
                 without the {}",
                component.name(),
                component.name()
            ),
        ));
    }
    // Parse rule/visibility prefixes with the crate's `address::parse` (not bare
    // `Url::parse`) so config prefixes normalize identically to incoming
    // addresses (e.g. authority-with-empty-path → trailing `/`), keeping the
    // string-based prefix matching consistent.
    // The raw text is not echoed here either, and for a reason the query
    // refusal above does not cover. `address::parse` refuses an authority-less
    // URL and withholds the opaque payload on purpose: everything after the
    // scheme is one opaque string with the userinfo inside it, and `Error`'s
    // redactor only recognizes URL-shaped tokens, so it cannot normalize it.
    // Interpolating `text` around that error puts the payload back and defeats
    // the redaction one level down. The config key is the handle that is
    // always safe, and the inner message is already safe to forward.
    address::parse(text)
        .map_err(|error| Error::new(ErrorCode::InvalidArgument, format!("`{key}`: {error}")))
}

/// A fixed hop cap bounds alias-chain resolution. A constant,
/// not a knob: eight hops is far beyond any sane composition, and a knob
/// would make chain validity deployment-dependent.
pub(crate) const MAX_ALIAS_HOPS: usize = 8;

/// How long a root-change notification waits for the inner layer's
/// `list_address_roots` before degrading to a resync nudge.
///
/// Nothing user-facing waits on this — the mutation returned long ago — so the
/// bound exists only to keep one unresponsive inner layer from parking its
/// ticket in the deferred turn order and holding every later alias
/// notification behind it for the wrapper's lifetime. Generous enough that a
/// merely slow remote backend still produces its precise delta rather than a
/// nudge.
const INNER_ROOT_REQUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How specific a scope is — the ONE currency the alias chain compares.
///
/// A newtype with a single constructor, because selection and termination
/// previously ranked on different scales and nothing made that visible.
/// `longest_matching_rule` moved to `address::node_rank` while `walk_chain`
/// still compared `as_str().len()`, so an inner root published as
/// `omniverse://h/team` lost to an alias `from = omniverse://h/team/`: the two
/// name one node, the real route should have interrupted the chain, and
/// `17 >= 18` is false — so the alias applied and the request was rewritten
/// away from the backend that owns it. Reversing the two slash spellings
/// reversed the outcome.
///
/// Byte length cannot be constructed here, so the two cannot drift again.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Specificity((usize, bool));

impl Specificity {
    fn of(url: &Url) -> Self {
        Self(address::node_rank(url))
    }
}

/// The longest-prefix rule matching `addr`, if any.
fn longest_matching_rule<'r>(rules: &'r [(Url, Url)], addr: &Url) -> Option<(&'r Url, &'r Url)> {
    rules
        .iter()
        .filter(|(from, _)| address::is_ancestor_or_self(from, addr))
        .max_by_key(|(from, _)| Specificity::of(from))
        .map(|(from, to)| (from, to))
}

/// The bounded alias-chain walk — THE definition of chain resolution, shared
/// by dispatch ([`AliasWrapper::resolve`]), advertisement ([`chain_terminal`]),
/// and eager validation ([`validate_alias_rules`]) so the specificity/cap
/// rules cannot drift between them. From `start`, the longest matching rule
/// applies per hop only when it is strictly more specific than the real root
/// covering the current address — `root_rank_for` answers with the covering
/// root's [`Specificity`] (`None` when nothing covers it; validation passes
/// `|_| None` because rule-set validity must not depend on live roots) — the
/// specificity rule applied per hop, guarded by [`MAX_ALIAS_HOPS`] and a
/// seen-set. A breach is `AliasChainTooLong`.
///
/// The callback answers in [`Specificity`] rather than a byte length so
/// termination cannot rank on a different scale from the selection above it.
fn walk_chain(
    rules: &[(Url, Url)],
    start: &Url,
    mut root_rank_for: impl FnMut(&Url) -> Option<Specificity>,
) -> Result<ResolvedAddress> {
    let mut current = start.clone();
    let mut hops: Vec<(Url, Url)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    while let Some((from, to)) = longest_matching_rule(rules, &current) {
        if let Some(root_rank) = root_rank_for(&current)
            && root_rank >= Specificity::of(from)
        {
            break;
        }
        // Both chain diagnostics render `RedactedUrl`. `start` here is a
        // caller's dispatch address, so its query is caller-controlled and
        // `Error`'s redactor scrubs only the provider parameter names it
        // knows. The scheme, authority and path are what identify the chain.
        if hops.len() == MAX_ALIAS_HOPS {
            return Err(Error::new(
                ErrorCode::AliasChainTooLong,
                format!(
                    "alias chain from `{}` exceeds the {MAX_ALIAS_HOPS}-hop cap",
                    RedactedUrl(start)
                ),
            ));
        }
        if !seen.insert(current.as_str().to_string()) {
            return Err(Error::new(
                ErrorCode::AliasChainTooLong,
                format!("alias chain from `{}` cycles", RedactedUrl(start)),
            ));
        }
        let (from, to) = (from.clone(), to.clone());
        current = address::replace_prefix(&current, &from, &to)?;
        hops.push((from, to));
    }
    Ok(ResolvedAddress {
        address: current,
        hops,
        // Filled by `AliasWrapper::resolve` from the same rule snapshot; the
        // shared walk works over bare `(from, to)` pairs and has no source.
        first_hop_source: None,
    })
}

/// Eagerly validate an alias rule set: every chain must terminate within
/// [`MAX_ALIAS_HOPS`] rule applications and never revisit an address.
/// Root-independent by design — a real root can interrupt a
/// chain at dispatch (per-hop specificity), but roots come and go with
/// connections, so a rule set whose validity depended on a live root would be
/// a latent misconfiguration. Dangling chains (terminating in rule-free space
/// with no root) are legal and advertise as [`AliasState::Dangling`].
///
/// Used by [`AliasWrapperFactory`] at build time and by runtime connection
/// updates, so a dispatch-time `ChainTooLong` can
/// occur only under concurrent rule removal.
pub(crate) fn validate_alias_rules(rules: &[(Url, Url)]) -> Result<()> {
    // Dedup on the node, not the spelling. Two rules whose `from` differs only
    // by a trailing slash scope the same addresses, so an exact-string set let
    // both load; ranking then tied them and declaration order silently decided
    // which projection an address took. Rejecting at load makes the operator
    // say which one they meant.
    let mut seen = std::collections::HashSet::new();
    for (start, to) in rules {
        // A query is refused on BOTH sides, and the reason is the same one on
        // each: an address names a node, and a query is not part of what names
        // it.
        //
        // On `from` the failure is a silent NARROWING of a live rule.
        // Selection is `address::is_ancestor_or_self`, which does read the
        // query — its last comparison is exact equality against the prefix's
        // pin — so a query-bearing `from` matches that one spelling and no
        // extension of it. 0.2.0's `is_prefix_of` admitted an `&`-aligned
        // extension, so `from = https://h/pub?v=1` covered
        // `https://h/pub?v=1&download=1` and no longer would: the request
        // stops being rewritten and routes somewhere else entirely.
        //
        // On `to` the failure is that it applies only sometimes.
        // `address::replace_prefix` takes the query from the ADDRESS when the
        // address has one and from the replacement otherwise, so
        // `to = some-other://h/?hello` pins `some://h/path` but is silently
        // dropped from `some://h/path?v=2` — the one rewritten address whose
        // caller also cared about a query is the one the operator's pin does
        // not reach. Making it a merge instead was the alternative and was
        // withdrawn: it gains complexity in the merge for a feature nobody
        // asked for, and the same reasoning retired `plugin-http`'s
        // root-query merge in this release.
        //
        // A fragment is refused too, at the string boundary in [`parse_url`],
        // because `address::parse` strips one before a `Url` here could carry
        // it.
        //
        // The rule is located by its scheme, authority and path, rendered
        // through [`RedactedUrl`]: the query is the part being refused and is
        // exactly the part that carries a signature or an API key, and
        // `Error`'s redactor scrubs only the provider query names it knows, so
        // interpolating the URL would return `?api_key=…` verbatim to whatever
        // sink receives a startup failure.
        for (url, side) in [(start, "from"), (to, "to")] {
            // An authority-less rule is refused before anything renders it.
            // `RedactedUrl` writes `scheme://` followed by `path()`, and for
            // this class `path()` IS the whole post-scheme payload, userinfo
            // included — so rendering one would print the credential it exists
            // to hide, and manufacture a `://` that was never written. The
            // TOML loader cannot produce one (it parses through
            // `address::parse`, which refuses the class), but
            // `AliasWrapperFactory::with_rules` reaches here through bare
            // `canonicalize`, which does not.
            if url.cannot_be_a_base() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "alias rule `{side}` must have an authority; scheme '{}' was \
                         parsed as authority-less",
                        url.scheme()
                    ),
                ));
            }
            if url.query().is_some() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "alias rule `{side}` must not carry a query: {}. An address names a \
                         node, and a query is not part of what names it: on `from` it pins \
                         the rule to one exact spelling and no extension of it, and on `to` \
                         it survives only for callers whose own address carries no query. \
                         Write the rule without the query",
                        RedactedUrl(url)
                    ),
                ));
            }
        }
        // A `from` carrying credentials is refused, for the reason the authz
        // policy loader refuses a credential-bearing allow: matching compares
        // scheme, host, port and path, so `from = https://reader:token@h/reports/`
        // now covers the anonymous `https://h/reports/payroll` as well as
        // the address whose serialized form began with that authority, and
        // rewrites it onto `to`. On 0.2.0 the string comparison did not, so
        // this widens a live rule in the permissive direction with nothing
        // said. The rewrite is to delete the credentials from `from`: nothing
        // in matching ever consulted them.
        //
        // **`from` only**, and the reason is what the guard is about rather
        // than a judgement about credentials. A `from` SELECTS addresses, so
        // dropping userinfo from the comparison widens the set it selects. A
        // `to` is the address the rewrite produces; nothing compares it to a
        // caller's address, so there is no set to widen. What a backend then
        // does with userinfo on that address is the backend's own rule — the
        // HTTP one, for instance, authenticates from `root_url` and its
        // declared credential fields and puts neither a caller's nor an
        // alias's userinfo on the wire.
        if !start.username().is_empty() || start.password().is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "alias rule `from` must not carry credentials: {}. Alias matching \
                     compares scheme, host, port and path, so this rule covers its path \
                     for EVERY credential rather than the one written — on 0.2.0 the \
                     matcher compared the credential too, so this is a widening of a live \
                     rule. Write the prefix without the credentials to accept that scope; \
                     `to` may keep its own",
                    RedactedUrl(start)
                ),
            ));
        }
        if !seen.insert(ovstorage_layer::node_key(start)) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("duplicate alias `from` prefix: {}", RedactedUrl(start)),
            ));
        }
        walk_chain(rules, start, |_| None)?;
    }
    Ok(())
}

/// Reject two visibility rules that scope the same addresses.
///
/// Visibility rules are a separate list from the alias rules and never reach
/// [`validate_alias_rules`]. Two spellings of one scope both matched, the rank
/// tied them, and `max_by_key` returned whichever the iterator reached last —
/// so a `Hidden` rule was silently overridden by a `Visible` one written with
/// the other spelling. That direction fails **open**, which is why this is a
/// load-time rejection rather than a tie-break.
///
/// A `Visible` rule whose prefix carries credentials is refused for the same
/// reason, and the asymmetry is the one the authz policy loader already draws.
/// Matching ignores userinfo, so such a rule covers its path for every
/// credential rather than the one written — and for `Visible` that is the
/// direction that reveals, which is the direction that cannot be undone. A
/// widened `Hidden` or `Suppressed` rule hides more than it was written to,
/// so it loads — but it is the same authoring mistake and it does change what
/// the deployment does, turning a path that answered for anonymous callers
/// into one that does not. It warns, because an operator whose rule now covers
/// more than they wrote deserves to be told either way; only the direction
/// that publishes is worth refusing to start over.
///
/// # Errors
///
/// A prefix carrying a **query** is refused outright, in every direction.
/// Selection compares the query exactly, so such a rule matches only the
/// spelling it names — where 0.2.0 covered any `&`-extension of it. A live
/// `Hidden` or `Suppressed` rule written that way would quietly stop hiding,
/// and an address matched by no rule is `Visible`. That is a fail-open on the
/// one list whose job is to withhold, so it is a load error rather than a
/// warning.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — two rules name the same scope, a
///   `Visible` rule's prefix carries credentials, or any rule's prefix
///   carries a query.
fn validate_visibility_rules(rules: &[(Url, AddressVisibility)]) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for (prefix, visibility) in rules {
        if *visibility == AddressVisibility::Visible
            && (!prefix.username().is_empty() || prefix.password().is_some())
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "visibility rule `{}` is visible and its prefix carries credentials. \
                     Visibility matching compares scheme, host, port and path, so this \
                     rule reveals its path for EVERY credential rather than the one \
                     written — on 0.2.0 the matcher compared the credential too, so this \
                     is a widening of a live rule, in the direction that publishes. Write \
                     the prefix without the credentials to accept that scope",
                    RedactedUrl(prefix)
                ),
            ));
        }
        if !prefix.username().is_empty() || prefix.password().is_some() {
            tracing::warn!(
                prefix = %RedactedUrl(prefix),
                visibility = ?visibility,
                "visibility rule prefix carries credentials, which are not part of \
                 what it matches; this rule covers its path for every credential, \
                 not the one written"
            );
        }
        // A query on a visibility prefix is refused, the same way the alias
        // sides are and for a sharper reason than incoherence: it FAILS OPEN.
        //
        // Selection is `is_ancestor_or_self`, whose contract for a
        // query-bearing prefix is exact query equality. 0.2.0's `is_prefix_of`
        // admitted an `&`-aligned extension, so `https://h/private?v=1`
        // covered `https://h/private?v=1&download=1`; it no longer does, and
        // an address that falls out of every rule takes
        // `unwrap_or(AddressVisibility::Visible)` and is advertised. A live
        // `Hidden` or `Suppressed` rule would therefore stop hiding on
        // upgrade, silently, with no load error and nothing in the logs.
        //
        // Restoring the `&` boundary is the alternative and it is the wrong
        // one: boundary-matching a serialized string is the family this
        // release exists to remove, and it would make a visibility prefix the
        // one scope in the system where a query means something. Refusing at
        // load turns a silent exposure into a startup failure the operator
        // fixes once.
        //
        // Rendered through `RedactedUrl`, which drops the query: the query is
        // exactly the part being refused and exactly where a SAS signature or
        // an API key lives.
        if prefix.query().is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "visibility rule `{}` must not carry a query. Visibility is decided on \
                     scheme, authority and path, so a rule on a path already covers every \
                     version of it — and a query-bearing rule now matches only the exact \
                     query, so a `hidden` or `suppressed` rule written this way would stop \
                     hiding. Write the prefix without the query",
                    RedactedUrl(prefix)
                ),
            ));
        }
        if !seen.insert(ovstorage_layer::node_key(prefix)) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                // Redacted for the same reason as the alias messages above,
                // and it is reachable with a credential: the guard above
                // refuses only the `Visible` direction, so a `Hidden` or
                // `Suppressed` prefix arrives here exactly as the operator
                // wrote it.
                format!("duplicate visibility prefix: {}", RedactedUrl(prefix)),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Returned-address projection (physical → caller-facing)
//
// `chain` is the inverse of the alias hops the request's forward resolution
// applied, last hop first: for forward hops `h1 … hN`, the chain is
// `(to_N, from_N) … (to_1, from_1)`. Replaying exactly the applied hops in
// reverse maps a physical address on a returned result back to the caller's
// own spelling of the namespace — and nothing more. A request that was not
// rewritten carries an empty chain and projects as the identity, so a caller
// addressing a rule's target space directly gets results echoed in its own
// address space, and a caller entering a chain mid-way is
// mapped back only as far as its own entry point.
// ---------------------------------------------------------------------------

/// The inverse of `hops` (the forward rules applied by `resolve`, in
/// application order), ready to replay on returned addresses.
fn inverse_chain(hops: &[(Url, Url)]) -> Vec<(Url, Url)> {
    hops.iter()
        .rev()
        .map(|(from, to)| (to.clone(), from.clone()))
        .collect()
}

/// Replay `chain` on `addr`: each `(to, from)` hop whose `to` still prefixes
/// the address maps it one namespace outward. An empty chain is the identity.
fn project_back(chain: &[(Url, Url)], addr: &Url) -> Result<Url> {
    let mut current = addr.clone();
    for (to, from) in chain {
        if address::is_ancestor_or_self(to, &current) {
            current = address::replace_prefix(&current, to, from)?;
        }
    }
    Ok(current)
}

fn project_info(chain: &[(Url, Url)], mut info: ObjectInfo) -> Result<ObjectInfo> {
    info.address = project_back(chain, &info.address)?;
    Ok(info)
}

fn project_read_result(chain: &[(Url, Url)], result: ReadResult) -> Result<ReadResult> {
    match result {
        ReadResult::Bytes { bytes, info } => Ok(ReadResult::Bytes {
            bytes,
            info: project_info(chain, info)?,
        }),
        ReadResult::Stream { stream, info } => Ok(ReadResult::Stream {
            stream,
            info: project_info(chain, info)?,
        }),
        ReadResult::LocalDelegate(delegate) => Ok(ReadResult::LocalDelegate(project_delegate(
            chain, delegate,
        )?)),
        // A redirect carries an external URL and is left unprojected.
        ReadResult::Redirect(redirect) => Ok(ReadResult::Redirect(redirect)),
    }
}

fn project_delegate(chain: &[(Url, Url)], mut delegate: LocalDelegate) -> Result<LocalDelegate> {
    delegate.info.address = project_back(chain, &delegate.info.address)?;
    Ok(delegate)
}

fn project_write_result(chain: &[(Url, Url)], mut result: WriteResult) -> Result<WriteResult> {
    result.info.address = project_back(chain, &result.info.address)?;
    Ok(result)
}

fn project_write_step(chain: &[(Url, Url)], step: WriteStep) -> Result<WriteStep> {
    match step {
        WriteStep::Done(result) => Ok(WriteStep::Done(project_write_result(chain, result)?)),
        // A redirect batch carries external URLs — left unprojected.
        WriteStep::Redirects(batch) => Ok(WriteStep::Redirects(batch)),
    }
}

fn project_items(chain: &[(Url, Url)], items: &mut [ObjectInfo]) -> Result<()> {
    for item in items.iter_mut() {
        item.address = project_back(chain, &item.address)?;
    }
    Ok(())
}

/// Reverse-map the `address` on every `ChangeEvent::Object` flowing through a
/// watch stream.
fn project_change_stream(chain: Vec<(Url, Url)>, stream: ChangeStream) -> ChangeStream {
    Box::new(stream.map(move |event| {
        let mut event = event?;
        if let ChangeEvent::Object { address, .. } = &mut event {
            *address = project_back(&chain, address)?;
        }
        Ok(event)
    }))
}

/// Longest-prefix visibility lookup over a set of rules (default `Visible`).
fn visibility_of_in(visibility: &[(Url, AddressVisibility)], addr: &Url) -> AddressVisibility {
    visibility
        .iter()
        .filter(|(prefix, _)| address::is_ancestor_or_self(prefix, addr))
        .max_by_key(|(prefix, _)| Specificity::of(prefix))
        .map(|(_, vis)| *vis)
        .unwrap_or(AddressVisibility::Visible)
}

/// A bare alias-facing root for a chain with no terminating real root —
/// shared by the `list_address_roots` advertisement and `root_info_for` so
/// the two introspection paths report the same dangling-alias metadata (the
/// caller-facing fields — `source`/`alias_state`/visibility — are stamped by
/// the caller).
fn bare_alias_root(from: &Url) -> RootInfo {
    RootInfo {
        root: from.clone(),
        display_name: None,
        layer_kind: ALIAS_KIND.to_string(),
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

/// Resolve an alias rule's chain against the advertised real roots — the
/// same [`walk_chain`] dispatch uses, answering the per-hop specificity
/// check from the snapshot — and classify the terminal state. Returns the
/// terminating root for a `Live` chain; `Dangling` chains terminate nowhere,
/// and a cap breach / cycle — impossible for an eagerly validated rule set
/// short of a concurrent rule change — reports `ChainTooLong`.
fn chain_terminal<'r>(
    rules: &[(Url, Url)],
    roots: &'r [RootInfo],
    target: &Url,
) -> (Option<&'r RootInfo>, AliasState) {
    let covering = |addr: &Url| {
        roots
            .iter()
            .filter(|root| address::is_ancestor_or_self(&root.root, addr))
            .max_by_key(|root| Specificity::of(&root.root))
    };
    match walk_chain(rules, target, |addr| {
        covering(addr).map(|root| Specificity::of(&root.root))
    }) {
        Ok(resolved) => match covering(&resolved.address) {
            Some(root) => (Some(root), AliasState::Live),
            None => (None, AliasState::Dangling),
        },
        Err(error) => (
            None,
            AliasState::ChainTooLong {
                reason: error.message().to_string(),
            },
        ),
    }
}

/// The per-alias data [`project_advertised_roots`] needs to synthesize a
/// caller-facing alias root: the `(from, to)` rewrite, the rule's real
/// [`AliasSource`], and its presentation (`display_name`/`user_metadata`) so a
/// synthesized root carries the same presentation `list_connections` reports
/// for the alias connection (a bare `(from, to, source)` triple dropped the
/// presentation fields).
#[derive(Clone)]
struct AliasProjection {
    from: Url,
    to: Url,
    source: AliasSource,
    display_name: Option<String>,
    user_metadata: UserMetadata,
}

/// Synthesize the caller-facing root for one alias from its terminal state.
/// Shared by the snapshot projection and the `Removed`-delta path so both
/// stamp identical `Alias` source/state and presentation onto the root.
fn synthesize_alias_root(
    alias: &AliasProjection,
    terminal: Option<&RootInfo>,
    state: AliasState,
) -> RootInfo {
    let mut root = match terminal {
        Some(target) => target.clone(),
        None => bare_alias_root(&alias.from),
    };
    root.root = alias.from.clone();
    root.source = RouteSource::Alias {
        to: alias.to.clone(),
        alias_source: alias.source.clone(),
    };
    // An alias root is a caller-facing mount, not a connection owner: clear any
    // owning target inherited from the terminal so this synthesized root never
    // advertises the physical backend's routing target. Auth delegation walks
    // the chain to the physical terminal and reads ITS `owning_target`, so this
    // is informational only.
    root.owning_target = None;
    root.alias_state = Some(state);
    root.visibility = AddressVisibility::Visible;
    root.visible = true;
    // Thread the rule's presentation onto the projected root: an alias's own
    // `display_name` overrides the inherited target root's, and its
    // `user_metadata` is merged over any inherited from the terminal root.
    if alias.display_name.is_some() {
        root.display_name = alias.display_name.clone();
    }
    for (key, value) in &alias.user_metadata {
        root.user_metadata.insert(key.clone(), value.clone());
    }
    root
}

/// Apply the advertised-root projection to a set of roots: drop non-`Visible`
/// roots, force the survivors `Visible`, and synthesize a root for each
/// visible alias — `Live` when its chain terminates at a present root
/// (inheriting that root's advertisement), `Dangling`/`ChainTooLong`
/// otherwise (a bare alias-facing root, so a misconfigured alias is visible
/// in discovery instead of silently absent). Shared by the initial
/// `list_address_roots` snapshot and every live root-update event so the two
/// stay consistent.
fn project_advertised_roots(
    aliases: &[AliasProjection],
    visibility: &[(Url, AddressVisibility)],
    mut roots: Vec<RootInfo>,
) -> Vec<RootInfo> {
    // Alias-root synthesis runs against the UNFILTERED roots: a visible alias
    // whose target root is Hidden/Suppressed still advertises (the rewrite
    // shape — the caller-facing mount is the advertised surface while its
    // physical `rewrite_to` target is suppressed by construction).
    let pairs: Vec<(Url, Url)> = aliases
        .iter()
        .map(|alias| (alias.from.clone(), alias.to.clone()))
        .collect();
    let mut alias_roots = Vec::new();
    for alias in aliases {
        if visibility_of_in(visibility, &alias.from) != AddressVisibility::Visible {
            continue;
        }
        let (terminal, state) = chain_terminal(&pairs, &roots, &alias.to);
        alias_roots.push(synthesize_alias_root(alias, terminal, state));
    }
    roots.retain(|root| visibility_of_in(visibility, &root.root) == AddressVisibility::Visible);
    for root in roots.iter_mut() {
        root.visibility = AddressVisibility::Visible;
        root.visible = true;
    }
    roots.extend(alias_roots);
    roots
}

/// Project a `Removed` delta. Unlike the other variants this must NOT re-run
/// full alias-root synthesis: [`project_advertised_roots`] synthesizes a root
/// for EVERY visible alias, so feeding it a `Removed` delta would spuriously
/// report every alias root removed on any unrelated inner removal.
/// Instead, emit removal only for (a) the removed inner roots that were
/// themselves advertised (`Visible`), and (b) the alias roots whose backing
/// chain terminated at one of the removed inner roots — those go `Dangling`
/// and drop out of advertisement.
fn project_removed_roots(
    aliases: &[AliasProjection],
    visibility: &[(Url, AddressVisibility)],
    removed: Vec<RootInfo>,
) -> Vec<RootInfo> {
    let pairs: Vec<(Url, Url)> = aliases
        .iter()
        .map(|alias| (alias.from.clone(), alias.to.clone()))
        .collect();
    let mut out: Vec<RootInfo> = Vec::new();
    // Alias roots whose chain terminates at a removed inner root: resolve each
    // visible alias against ONLY the removed roots — a `Live` terminal means
    // the alias depended on a now-removed root and must be withdrawn too.
    for alias in aliases {
        if visibility_of_in(visibility, &alias.from) != AddressVisibility::Visible {
            continue;
        }
        let (terminal, state) = chain_terminal(&pairs, &removed, &alias.to);
        if let Some(terminal) = terminal {
            out.push(synthesize_alias_root(alias, Some(terminal), state));
        }
    }
    // The directly-removed inner roots that were advertised (`Visible`);
    // non-visible roots were never advertised, so removing them is a no-op.
    for mut root in removed {
        if visibility_of_in(visibility, &root.root) == AddressVisibility::Visible {
            root.visibility = AddressVisibility::Visible;
            root.visible = true;
            out.push(root);
        }
    }
    out
}

/// Project the roots carried by a live [`RootInfoChange`] the same way the
/// snapshot is projected, so later updates can't leak non-visible roots or skip
/// alias-root synthesis. `Snapshot`/`Added`/`Updated` re-run the full
/// filtering and synthesis; `Removed` uses [`project_removed_roots`] so it
/// withdraws only the roots that went away (and the alias roots they backed),
/// never the whole alias projection.
fn project_root_change(
    aliases: &[AliasProjection],
    visibility: &[(Url, AddressVisibility)],
    change: RootInfoChange,
) -> RootInfoChange {
    match change {
        RootInfoChange::Snapshot(roots) => {
            RootInfoChange::Snapshot(project_advertised_roots(aliases, visibility, roots))
        }
        RootInfoChange::Added(roots) => {
            RootInfoChange::Added(project_advertised_roots(aliases, visibility, roots))
        }
        RootInfoChange::Updated(roots) => {
            RootInfoChange::Updated(project_advertised_roots(aliases, visibility, roots))
        }
        // A `Removed` delta must only withdraw the roots that actually went
        // away — never re-synthesize the whole alias projection.
        RootInfoChange::Removed(roots) => {
            RootInfoChange::Removed(project_removed_roots(aliases, visibility, roots))
        }
    }
}

// ---------------------------------------------------------------------------
// Mutable rule set + connection identities
// ---------------------------------------------------------------------------

// The `user_metadata` keys stamped on alias / visibility-override connections
// are the public host-facing contract (a host rebuilds from/to/visibility from
// a `list_connections` row), so they live in `crate::layers` alongside
// `ALIAS_KIND`; alias the exports here to keep the local call sites terse.
use crate::layers::ALIAS_TO_METADATA_KEY as ALIAS_TO_KEY;
use crate::layers::ALIAS_VISIBILITY_METADATA_KEY as ALIAS_VISIBILITY_KEY;

/// One credentialless alias connection: a `(from → to)` URL-rewrite rule with a
/// `(target, id)` identity for CRUD. Carries no visibility of its own — an
/// alias's advertised visibility is the longest-prefix match over the
/// [`RuleSet::visibility`] overrides (the construction-time catalog resolves it
/// the same way).
#[derive(Clone)]
struct AliasRule {
    id: ConnectionId,
    from: Url,
    to: Url,
    source: AliasSource,
    display_name: Option<String>,
    user_metadata: UserMetadata,
    /// Intrinsic visibility of this alias, folded into the rule set's
    /// visibility overrides on `from` by [`RuleSet::visibility_pairs`]. `None` leaves the
    /// alias at the default `Visible` unless a separate override applies. Set
    /// via the `{from, to, visibility}` add-connection shape and patchable
    /// through `update_connection_attributes`.
    visibility: Option<AddressVisibility>,
}

/// One visibility-override connection: an `(address, visibility)` row with a
/// `(target, id)` identity. Visibility overrides are connections in their own
/// right (see the module docs) so an override on any address — an alias `from`
/// or a real backend root — is a uniformly removable row.
#[derive(Clone)]
struct VisibilityOverride {
    id: ConnectionId,
    address: Url,
    visibility: AddressVisibility,
    source: AliasSource,
    display_name: Option<String>,
    user_metadata: UserMetadata,
}

/// The wrapper's full rule state, swapped atomically as a unit so a reader that
/// cloned the `Arc` sees a consistent set across a whole operation even as a
/// writer installs a new one.
#[derive(Clone, Default)]
struct RuleSet {
    aliases: Vec<AliasRule>,
    visibility: Vec<VisibilityOverride>,
}

impl RuleSet {
    /// The alias `(from, to)` pairs, in registration order, for the shared
    /// chain-resolution helpers ([`walk_chain`], [`chain_terminal`]).
    fn alias_pairs(&self) -> Vec<(Url, Url)> {
        self.aliases
            .iter()
            .map(|rule| (rule.from.clone(), rule.to.clone()))
            .collect()
    }

    /// The alias projections, in registration order, for
    /// [`project_advertised_roots`]: each synthesized root's
    /// `RouteSource::Alias` carries the rule's real [`AliasSource`] so
    /// discovery agrees with what `list_connections` reports (a runtime/broker
    /// alias is not mislabelled `Static`), and its presentation
    /// (`display_name`/`user_metadata`) is threaded onto the projected root.
    fn alias_projection(&self) -> Vec<AliasProjection> {
        self.aliases
            .iter()
            .map(|rule| AliasProjection {
                from: rule.from.clone(),
                to: rule.to.clone(),
                source: rule.source.clone(),
                display_name: rule.display_name.clone(),
                user_metadata: rule.user_metadata.clone(),
            })
            .collect()
    }

    /// The `(address, visibility)` pairs for
    /// [`visibility_of_in`]/[`project_advertised_roots`], combining the
    /// standalone visibility overrides with each alias rule's intrinsic
    /// visibility (an override on the alias's `from`). Order is
    /// load-bearing: [`visibility_of_in`] breaks an exact-prefix tie toward the
    /// last entry, so a later entry wins. Alias-intrinsic entries are listed
    /// FIRST so a standalone explicit override on the same prefix wins the tie.
    fn visibility_pairs(&self) -> Vec<(Url, AddressVisibility)> {
        let mut pairs: Vec<(Url, AddressVisibility)> = self
            .aliases
            .iter()
            .filter_map(|rule| rule.visibility.map(|vis| (rule.from.clone(), vis)))
            .collect();
        pairs.extend(
            self.visibility
                .iter()
                .map(|rule| (rule.address.clone(), rule.visibility)),
        );
        pairs
    }

    fn contains_id(&self, id: &ConnectionId) -> bool {
        self.aliases.iter().any(|rule| &rule.id == id)
            || self.visibility.iter().any(|rule| &rule.id == id)
    }
}

/// Map a rule's `AliasSource` onto the equivalent `ConnectionSource` for
/// `list_connections` reporting.
fn connection_source(source: &AliasSource) -> ConnectionSource {
    match source {
        AliasSource::Static { layer } => ConnectionSource::Static { layer: *layer },
        AliasSource::Runtime { persisted } => ConnectionSource::Runtime {
            persisted: *persisted,
        },
        AliasSource::BrokerDelivered { broker_principal } => ConnectionSource::BrokerDelivered {
            broker_principal: broker_principal.clone(),
        },
    }
}

/// The `Connection` view of an alias rule: credentialless (`Anonymous`), with
/// the rewrite target and rule kind stamped into `user_metadata` for host
/// reconstruction.
fn alias_connection(rule: &AliasRule) -> Connection {
    let mut user_metadata = rule.user_metadata.clone();
    user_metadata.insert(ALIAS_TO_KEY.to_string(), rule.to.to_string());
    // An alias with an intrinsic visibility surfaces it so a host can round-trip
    // the full `{from, to, visibility}` shape from `list_connections`.
    if let Some(visibility) = rule.visibility {
        user_metadata.insert(
            ALIAS_VISIBILITY_KEY.to_string(),
            visibility_str(visibility).to_string(),
        );
    }
    Connection {
        id: rule.id.clone(),
        backend_kind: ALIAS_KIND.to_string(),
        display_name: rule
            .display_name
            .clone()
            .unwrap_or_else(|| rule.from.to_string()),
        source: connection_source(&rule.source),
        capabilities: Capabilities::empty(),
        current_addresses: vec![rule.from.clone()],
        auth_state: ConnectionAuthState::Anonymous,
        last_probed: None,
        user_metadata,
    }
}

/// The `Connection` view of a visibility-override rule.
fn visibility_connection(rule: &VisibilityOverride) -> Connection {
    let mut user_metadata = rule.user_metadata.clone();
    user_metadata.insert(
        ALIAS_VISIBILITY_KEY.to_string(),
        visibility_str(rule.visibility).to_string(),
    );
    Connection {
        id: rule.id.clone(),
        backend_kind: ALIAS_KIND.to_string(),
        display_name: rule
            .display_name
            .clone()
            .unwrap_or_else(|| rule.address.to_string()),
        source: connection_source(&rule.source),
        capabilities: Capabilities::empty(),
        current_addresses: vec![rule.address.clone()],
        auth_state: ConnectionAuthState::Anonymous,
        last_probed: None,
        user_metadata,
    }
}

fn visibility_str(visibility: AddressVisibility) -> &'static str {
    match visibility {
        AddressVisibility::Visible => "visible",
        AddressVisibility::Hidden => "hidden",
        AddressVisibility::Suppressed => "suppressed",
    }
}

fn parse_visibility_str(text: &str) -> Result<AddressVisibility> {
    match text {
        "visible" => Ok(AddressVisibility::Visible),
        "hidden" => Ok(AddressVisibility::Hidden),
        "suppressed" => Ok(AddressVisibility::Suppressed),
        other => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("invalid visibility `{other}` (want visible|hidden|suppressed)"),
        )),
    }
}

/// A required string config value parsed as a URL prefix, so runtime rule
/// prefixes normalize identically to construction-time ones — and are refused
/// on the same grounds.
fn config_url(connection: &ConnectionRequest, key: &str) -> Result<Url> {
    match connection.config.get(key) {
        Some(ConfigValue::String(text)) => parse_url(text, key),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("alias connection `{key}` must be a string"),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("alias connection config needs `{key}`"),
        )),
    }
}

fn config_visibility(connection: &ConnectionRequest, key: &str) -> Result<AddressVisibility> {
    match connection.config.get(key) {
        Some(ConfigValue::String(text)) => parse_visibility_str(text),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("alias connection `{key}` must be a string"),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("alias connection config needs `{key}`"),
        )),
    }
}

/// The caller-supplied connection id (`config.id`), else a freshly minted one.
/// A caller-supplied id makes `(target, id)` stable across a config replay
/// (the `[[connections]] target = "alias"` form); the fresh fallback lets simpler
/// callers (a programmatic `add_connection` that omits `id`) not care about ids.
/// A present-but-invalid `id`
/// (non-string, e.g. a TOML integer, or empty) is an `InvalidArgument` rather
/// than a silent fresh mint — minting would break `(target, id)`
/// stability across replay, giving a persisted entry a new id every restart.
fn connection_id(connection: &ConnectionRequest) -> Result<ConnectionId> {
    match connection.config.get("id") {
        None => Ok(ConnectionId(fresh_id("alias"))),
        Some(ConfigValue::String(text)) if !text.is_empty() => Ok(ConnectionId(text.clone())),
        Some(ConfigValue::String(_)) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "alias connection `id` must be a non-empty string",
        )),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "alias connection `id` must be a string",
        )),
    }
}

/// Which owned connection shape a request config describes.
enum RuleFragment {
    Alias {
        from: Url,
        to: Url,
        /// Optional intrinsic visibility (`{from, to, visibility}`); folds into
        /// a visibility override on `from`. `None` ⇒ default `Visible`.
        visibility: Option<AddressVisibility>,
    },
    Visibility {
        address: Url,
        visibility: AddressVisibility,
    },
}

/// Parse exactly one rule fragment from a request config: `{from, to}` (with an
/// optional `visibility`) for an alias rule, or `{address, visibility}` for a
/// visibility override.
fn parse_rule_fragment(connection: &ConnectionRequest) -> Result<RuleFragment> {
    let config = &connection.config;
    if config.contains_key("from") || config.contains_key("to") {
        Ok(RuleFragment::Alias {
            from: config_url(connection, "from")?,
            to: config_url(connection, "to")?,
            // A `visibility` alongside `from`/`to` is honored, not silently
            // dropped: it sets the alias's intrinsic visibility.
            visibility: if config.contains_key("visibility") {
                Some(config_visibility(connection, "visibility")?)
            } else {
                None
            },
        })
    } else if config.contains_key("address") || config.contains_key("visibility") {
        Ok(RuleFragment::Visibility {
            address: config_url(connection, "address")?,
            visibility: config_visibility(connection, "visibility")?,
        })
    } else {
        Err(Error::new(
            ErrorCode::InvalidArgument,
            "alias connection config needs `from`+`to` (alias rule) \
             or `address`+`visibility` (visibility override)",
        ))
    }
}

// ---------------------------------------------------------------------------
// AliasWrapper
// ---------------------------------------------------------------------------

/// Parsed alias and visibility rules injected by a host that already holds
/// canonical URLs, avoiding a serialize-and-parse round trip through layer
/// configuration.
#[derive(Default, Clone)]
pub struct AliasRules {
    pub aliases: Vec<(Url, Url)>,
    pub visibility: Vec<(Url, AddressVisibility)>,
}

/// [`WrapperFactory`] for the `alias` wrapper kind ([`ALIAS_KIND`]).
#[derive(Default)]
pub struct AliasWrapperFactory {
    /// When set, created wrappers seed their rule set from these in-process
    /// [`AliasRules`] directly, bypassing the `aliases`/`visibility` TOML config
    /// keys. Bespoke Stack builders already hold the catalogs as parsed `Url`s,
    /// so injecting them skips a
    /// pointless serialize→parse round-trip (and its `.expect("… serialize")`
    /// panic surface) on every epoch-gated rebuild. Mirrors
    /// the byte-cache plugin's cache-injected factory constructor.
    rules: Option<AliasRules>,
}

impl AliasWrapperFactory {
    /// Build a factory whose wrappers seed from `rules` directly, ignoring the
    /// `aliases`/`visibility` config keys — the in-process bespoke-Stack
    /// injection. The cacheless [`AliasWrapperFactory::default`] stays registered
    /// as the default for the external-TOML config path.
    pub fn with_rules(rules: AliasRules) -> Self {
        Self { rules: Some(rules) }
    }
}

#[async_trait]
impl WrapperFactory for AliasWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        // Alias is the connection owner (accepts_connections = true); it owns
        // the connection lifecycle.
        descriptor(ALIAS_KIND, LayerType::Wrapper, true)
    }

    async fn create_wrapper(
        &self,
        name: &str,
        config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        // Injected in-process rules win over the TOML config keys (the same
        // injected-beats-config precedence the cache wrappers use). The rules
        // are canonicalized exactly as the TOML path's `address::parse` would,
        // so direct injection is behavior-identical to the round-trip it
        // replaces — the endpoints are already canonical (host lowercasing,
        // path normalization applied when the alias rules are ingested),
        // so this is idempotent, but it keeps the two paths provably equal.
        //
        // The two paths differ on a fragment, and only a fragment. The TOML
        // path refuses one in `parse_url`, which sees the operator's string;
        // this path is handed a `Url`, and `canonicalize` strips the fragment
        // it may carry — there is no string left to refuse on, and no
        // post-parse view in which the fragment still exists. That is the whole
        // of the divergence: it is the string boundary that can enforce the
        // rule, and an in-process caller building `Url`s is past it. Every
        // other refusal is in `validate_alias_rules` and
        // `validate_visibility_rules` below, which both paths reach.
        let (aliases, visibility) = match &self.rules {
            Some(rules) => (
                rules
                    .aliases
                    .iter()
                    .map(|(from, to)| (canonicalize(from.clone()), canonicalize(to.clone())))
                    .collect::<Vec<_>>(),
                rules
                    .visibility
                    .iter()
                    .map(|(address, visibility)| (canonicalize(address.clone()), *visibility))
                    .collect::<Vec<_>>(),
            ),
            None => (
                parse_prefix_rules(config, "aliases")?,
                parse_visibility_rules(config, "visibility")?,
            ),
        };
        // Eager validation: a cycling or over-cap rule set is rejected at
        // build time, so dispatch-time `ChainTooLong` occurs only under
        // concurrent rule changes.
        validate_alias_rules(&aliases)?;
        // Construction. The runtime path validates separately, in
        // `add_connection`'s commit closure and in `preview` — the check has to
        // run wherever a rule ENTERS the set, because the fail-open it closes
        // does not care which path admitted the second spelling: two spellings
        // of one scope tie on rank and `max_by_key` hands the answer to
        // whichever the iterator reaches last, so a `Hidden` rule is silently
        // overridden by a `Visible` one.
        validate_visibility_rules(&visibility)?;
        // Construction-time rules seed the mutable set. Each gets a fresh id so
        // every row is a uniformly identified connection; the caller-facing
        // config shape (the `aliases`/`visibility` keys) is unchanged.
        let source = AliasSource::Static {
            layer: ConfigLayer::Programmatic,
        };
        let rules = RuleSet {
            aliases: aliases
                .into_iter()
                .map(|(from, to)| AliasRule {
                    id: ConnectionId(fresh_id("alias")),
                    from,
                    to,
                    source: source.clone(),
                    display_name: None,
                    user_metadata: UserMetadata::new(),
                    // Construction-time alias visibility arrives as separate
                    // `visibility` overrides, so the
                    // rule itself carries no intrinsic visibility.
                    visibility: None,
                })
                .collect(),
            visibility: visibility
                .into_iter()
                .map(|(address, visibility)| VisibilityOverride {
                    id: ConnectionId(fresh_id("alias")),
                    address,
                    visibility,
                    source: source.clone(),
                    display_name: None,
                    user_metadata: UserMetadata::new(),
                })
                .collect(),
        };
        Ok(Arc::new(AliasWrapper::new(
            name.to_string(),
            self.descriptor(),
            inner,
            rules,
        )))
    }
}

/// Multi-hop virtual→target alias rewriting + address visibility, plus
/// synthesis of live alias roots. Owns credentialless alias/visibility
/// connections whose rule state ([`RuleSet`]) is atomically swapped under the
/// write guard of a [`Sequenced`]; mutations broadcast synthesized root-change
/// and connection-change events on the `list_address_roots` /
/// `list_connections` update streams.
///
/// Executor-agnostic, like the rest of [`Layer`]: the connection mutators
/// detach their root-change notification onto a Tokio task when there is a
/// runtime and compute it inline when there is not (see
/// [`AliasWrapper::notify_root_change`]), so driving any slot under
/// `futures::executor::block_on` — as the plugin test layer does — works.
struct AliasWrapper {
    name: String,
    descriptor: LayerKindDescriptor,
    inner: LayerHandle,
    /// The live rule set, together with the two channels its mutations are
    /// reported on. Readers clone the `Arc` (a cheap snapshot) and drop the
    /// guard immediately — never holding the lock across an await or a stream
    /// yield. Writers swap in a fresh `Arc` under the write guard.
    ///
    /// Binding the state and its channels into one [`Sequenced`] is what makes
    /// the ordering a property of the type rather than of carefully placed
    /// statements. Both orderings here were originally just statements, and
    /// both were broken — the connection one twice, found by review rather than
    /// by the compiler.
    ///
    /// - **Primary (in-guard):** [`ConnectionChange`] for the
    ///   `list_connections` update stream. Cheap enough to compute under the
    ///   guard, so it is sent there and ordered by the lock alone.
    /// - **Deferred (ticketed):** [`RootInfoChange`] for the
    ///   `list_address_roots` update stream. Each delta needs a fresh
    ///   `inner.list_address_roots`, which cannot be awaited under a lock, so
    ///   the mutation stamps a ticket under the guard and the detached task
    ///   waits its turn before sampling (see
    ///   [`AliasWrapper::notify_root_change`]). Ticket order is rule-swap
    ///   order because the stamp happens under the guard.
    ///
    /// Ordering the root deltas is not a nicety: these are `Added`/`Removed`
    /// deltas, and a downstream notification drain applies
    /// them as a plain upsert/delete over a map rather than resnapshotting, so
    /// a trailing stale `Added` would leave that consumer holding a root the
    /// rule set no longer has. Ordering rather than discarding a superseded
    /// task's emission — the obvious cheaper fix — is required because these
    /// are deltas and not full state: with `add(A)` stalled and `add(B)`
    /// overtaking it, B's delta is `Added(B)` alone, so discarding A's leaves a
    /// delta consumer that never hears about A at all. Every ticket must
    /// therefore take its turn, in order; whether it emits anything is
    /// conditional — a ticket whose projection is unchanged emits nothing.
    ///
    /// A stalled notification consequently delays the ones behind it. That is
    /// bounded twice over: by [`INNER_ROOT_REQUERY_TIMEOUT`] on the re-query,
    /// and by the wrapper's `shutdown` token, which drop fires and which is
    /// also handed to `inner` as the re-query's cancel. A delayed delta is a
    /// far smaller problem than a misordered one, which corrupts a consumer's
    /// map permanently. The turn chain is strict — a ticket is released only
    /// by its predecessor retiring — and it still cannot wedge at shutdown,
    /// because dropping the `Sequenced` publishes a closed flag that wakes
    /// every parked ticket and grants it no turn.
    ///
    /// In the shipped broker chain that drain sits BELOW this wrapper and
    /// consumes the `Router`'s `Snapshot`-only stream, so it never sees these
    /// deltas; the exposure is a composition that places it above this wrapper.
    /// The ordering holds for any delta consumer either way — the `Router`'s
    /// own root watcher treats any item as a resync signal and is tolerant
    /// regardless.
    ///
    /// EXCEPTION, deliberate and enumerated: ordering across THIS wrapper's own
    /// emissions is what the type enforces; ordering between them and `inner`'s
    /// stream is not. `list_address_roots` / `list_connections` merge the two
    /// with `futures::stream::select`, and no discipline on this side can
    /// sequence another producer. Consumers key by root/id and tolerate
    /// interleaving ACROSS the two sources.
    rules: Sequenced<
        Arc<RuleSet>,
        broadcast::Sender<ConnectionChange>,
        broadcast::Sender<RootInfoChange>,
    >,
    /// Bounds the lifetime of the detached root-change notifications this
    /// wrapper spawns: cancelled on drop, so a task blocked on a stalled
    /// `inner.list_address_roots` cannot outlive the layer that owns it.
    shutdown: CancellationToken,
}

impl Drop for AliasWrapper {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// The outcome of [`AliasWrapper::resolve`]: the address to dispatch and the
/// alias hops applied to reach it (empty when no rewrite applied), which the
/// response side replays in reverse ([`inverse_chain`]/[`project_back`]) to
/// map returned addresses back to the caller's space.
struct ResolvedAddress {
    address: Url,
    hops: Vec<(Url, Url)>,
    /// The [`AliasSource`] of the FIRST applied hop's rule, captured by
    /// [`AliasWrapper::resolve`] from the same rule snapshot it walked, so
    /// `root_info_for` stamps the caller-facing root without a second lock +
    /// rescan (which could also observe a different rule under concurrent
    /// replacement). `None` when no rewrite applied, or if the rule vanished
    /// between the walk and the source lookup within the same snapshot.
    first_hop_source: Option<AliasSource>,
}

impl AliasWrapper {
    fn new(
        name: String,
        descriptor: LayerKindDescriptor,
        inner: LayerHandle,
        rules: RuleSet,
    ) -> Self {
        Self {
            name,
            descriptor,
            inner,
            // Connection changes are the in-guard channel, root changes the
            // deferred one; see the `rules` field.
            rules: Sequenced::broadcast(Arc::new(rules), 16, 16),
            shutdown: CancellationToken::new(),
        }
    }

    /// A consistent snapshot of the current rule set (a cheap `Arc` clone). The
    /// read guard is released before returning, so no reader holds the lock
    /// across an await.
    fn current_rules(&self) -> Arc<RuleSet> {
        self.rules.read().clone()
    }

    /// Reject suppressed caller addresses, then follow the alias-rule chain
    /// via the shared [`walk_chain`]: per-hop
    /// specificity — the walk asks the inner stack for the real root covering
    /// each intermediate address, and a rule applies only when strictly more
    /// specific — bounded by [`MAX_ALIAS_HOPS`] + cycle detection
    /// (`AliasChainTooLong`, unreachable short of a concurrent rule change
    /// thanks to eager validation).
    ///
    /// Suppression is checked on the **caller-supplied** address only:
    /// addresses reached through a rewrite are exempt, because a rule
    /// targeting a suppressed namespace is the encapsulation model itself
    /// (the mount's physical target is suppressed by construction and only
    /// reachable through the rule).
    ///
    /// Suppressed rejection is `NoRoute` — indistinguishable from an
    /// unconfigured namespace, per the settled suppression model: a suppressed
    /// namespace is omitted from projected introspection entirely, and a
    /// `NotConfigured` (or any distinct) error would leak that a suppressed
    /// configuration exists.
    async fn resolve(
        &self,
        addr: &Url,
        cancel: Option<CancellationToken>,
    ) -> Result<ResolvedAddress> {
        let rules = self.current_rules();
        // NOTE: `visibility_pairs`/`alias_pairs` each clone a fresh `Vec`
        // per dispatch. The rule set is atomically swapped under an `RwLock`, so
        // a cache would need its own invalidation keyed to the swap; deferred as
        // a straightforward-but-not-trivial follow-up (the clones are small).
        if visibility_of_in(&rules.visibility_pairs(), addr) == AddressVisibility::Suppressed {
            return Err(Error::new(ErrorCode::NoRoute, "no route matches address"));
        }
        self.walk_chain_async(&rules, addr, cancel).await
    }

    /// Async twin of the synchronous [`walk_chain`]: identical per-hop
    /// specificity / cap / cycle semantics, but the per-hop real-root probe
    /// awaits the now-async `inner.root_info_for` (forwarding `cancel`) rather
    /// than calling a synchronous closure. Separate from `walk_chain` because
    /// that one also backs synchronous callers (`chain_terminal`,
    /// `validate_alias_rules`) that must stay sync — those run inside sync
    /// stream-projection closures where awaiting is impossible.
    ///
    /// THE shared walk for every awaiting caller — data dispatch
    /// ([`Self::resolve`], which layers the caller-address suppression check on
    /// top), auth delegation ([`Self::resolve_auth_delegation`]), and connection
    /// ownership
    /// ([`Layer::owning_target_for`]) — so the load-bearing per-hop specificity
    /// rule cannot drift between them.
    async fn walk_chain_async(
        &self,
        rules: &RuleSet,
        addr: &Url,
        cancel: Option<CancellationToken>,
    ) -> Result<ResolvedAddress> {
        let pairs = rules.alias_pairs();
        let mut current = addr.clone();
        let mut hops: Vec<(Url, Url)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        while let Some((from, to)) = longest_matching_rule(&pairs, &current) {
            let (from, to) = (from.clone(), to.clone());
            // The covering real root's `Specificity`; a reported root that does
            // not actually cover the address (or no resolvable route at all)
            // lets the rule apply. A real root at least as specific as the rule
            // interrupts the alias chain at this hop.
            let covered = match self
                .inner
                .root_info_for(&current, &Extensions::new(), cancel.clone())
                .await
            {
                Ok(info) if address::is_ancestor_or_self(&info.root, &current) => {
                    Specificity::of(&info.root) >= Specificity::of(&from)
                }
                _ => false,
            };
            if covered {
                break;
            }
            if hops.len() == MAX_ALIAS_HOPS {
                return Err(Error::new(
                    ErrorCode::AliasChainTooLong,
                    format!(
                        "alias chain from `{}` exceeds the {MAX_ALIAS_HOPS}-hop cap",
                        RedactedUrl(addr)
                    ),
                ));
            }
            if !seen.insert(current.as_str().to_string()) {
                return Err(Error::new(
                    ErrorCode::AliasChainTooLong,
                    format!("alias chain from `{}` cycles", RedactedUrl(addr)),
                ));
            }
            current = address::replace_prefix(&current, &from, &to)?;
            hops.push((from, to));
        }
        let mut resolved = ResolvedAddress {
            address: current,
            hops,
            first_hop_source: None,
        };
        // Capture the first applied hop's source from the SAME snapshot
        // so `root_info_for` needn't re-lock and re-scan the rules.
        if let Some((from, to)) = resolved.hops.first() {
            resolved.first_hop_source = rules
                .aliases
                .iter()
                .find(|rule| &rule.from == from && &rule.to == to)
                .map(|rule| rule.source.clone());
        }
        Ok(resolved)
    }

    /// Start the post-commit advertised-root delta as owned background
    /// bookkeeping, so the mutation that committed the rule swap returns as
    /// soon as it has committed.
    ///
    /// The delta needs a fresh `inner.list_address_roots`, and `inner` may reach
    /// remote I/O — awaiting that on the mutating caller's future would let a
    /// stalled inner layer hold an already-committed `add_connection` /
    /// `remove_connection` pending. The task owns everything it touches (cloned
    /// `inner` handle, broadcast sender, both rule snapshots) and is bounded by
    /// the wrapper's `shutdown` token, which drop cancels.
    /// `deferred` is the ticket the mutation stamped under the rule write
    /// guard: detaching the WORK must not detach its ORDER. A stalled `add(A)`
    /// that finishes after the `remove(A)` which followed it would otherwise
    /// emit a trailing `Added(A)`, leaving a delta consumer holding a root no
    /// rule backs.
    ///
    /// Detaching requires a Tokio runtime, and [`Layer`] does not: the plugin
    /// test harness drives these slots under `futures::executor::block_on`. So
    /// when there is no runtime the delta is computed INLINE instead of
    /// panicking in a trait implementation. Inline is only a latency
    /// difference, never a correctness one — with no runtime there are no
    /// concurrent tasks to order against, and every ticket retires before its
    /// mutation returns.
    async fn notify_root_change(
        &self,
        deferred: Deferred<broadcast::Sender<RootInfoChange>>,
        old: Arc<RuleSet>,
        new: Arc<RuleSet>,
    ) {
        let inner = self.inner.clone();
        let shutdown = self.shutdown.clone();
        if tokio::runtime::Handle::try_current().is_err() {
            // No runtime: no `tokio::spawn`, and no `tokio::time::timeout`
            // either — hence the `None` budget. Nothing else is waiting on this
            // ticket, and the caller asked for a blocking executor.
            Self::broadcast_root_delta(inner, old, new, shutdown, deferred, None).await;
            return;
        }
        tokio::spawn(async move {
            // The ticket moves into the delta future below, so the shutdown
            // branch retires it by dropping that future — whether it is still
            // parked waiting its turn or already holding one.
            //
            // The token is also handed to `inner` as the re-query's cancel, so a
            // cooperative layer aborts promptly; the select is the backstop for
            // one that ignores it, guaranteeing the task ends at drop.
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {}
                () = Self::broadcast_root_delta(
                    inner,
                    old,
                    new,
                    shutdown.clone(),
                    deferred,
                    Some(INNER_ROOT_REQUERY_TIMEOUT),
                ) => {}
            }
        });
    }

    /// Compute what the rule change from `old` → `new` does to the advertised
    /// root set (both projected against `inner`'s current roots via the same
    /// [`project_advertised_roots`] the snapshot uses) and broadcast the delta.
    /// Projecting through that helper is what keeps the emission leak-proof:
    /// suppressed/hidden namespaces are already filtered out, so a `Removed`
    /// event can only ever carry advertised (non-suppressed) roots. Re-querying
    /// `inner` here (rather than tracking its roots) also folds in chain
    /// interactions — a distant alias flipping Live↔Dangling shows up as an
    /// `Updated`. Nothing is emitted when the projection is unchanged.
    ///
    /// Takes owned state rather than `&self` because it runs detached; see
    /// [`AliasWrapper::notify_root_change`].
    async fn broadcast_root_delta(
        inner: LayerHandle,
        old: Arc<RuleSet>,
        new: Arc<RuleSet>,
        cancel: CancellationToken,
        deferred: Deferred<broadcast::Sender<RootInfoChange>>,
        budget: Option<std::time::Duration>,
    ) {
        // Best-effort re-query of the committed state. A cancelled, failed, or
        // TIMED-OUT re-query degrades to the resync nudge below.
        //
        // The budget matters because the emissions are ordered: `cancel` is the
        // wrapper's lifetime token, so an inner layer that neither answers nor
        // errors — a broker-client child on a TCP connection that blackholes,
        // say — would park this ticket until the wrapper drops, and every ticket
        // behind it waits with it. Bounding the re-query turns "no alias
        // notification for the rest of the process" into one late nudge.
        //
        // `None` is the no-runtime path, which has no timer to arm and, being
        // inline, no other ticket waiting behind it.
        //
        // The query gets its OWN token, a child of the wrapper's, and the
        // timeout cancels it explicitly. Dropping the future is not enough:
        // that unwinds the Rust side only, and for a `ForeignVtableLayer` child
        // the plugin's task and its `user_data` allocation live until the FFI
        // operation finishes on its own. Against a blackholed plugin, relying
        // on drop would leak one foreign operation per alias mutation — exactly
        // the unbounded growth this budget exists to prevent. Cancelling the
        // token is the only signal that crosses the ABI. `route_catch_up` does
        // the same thing for the same reason.
        // The turn is taken BEFORE the re-query, not just before the sends.
        // Ordering the emissions alone is not enough: each notification samples
        // `inner` for itself, so a stalled ticket's sample can be NEWER than the
        // sample of a ticket behind it and still be published first. The two
        // deltas then do not telescope — one is computed against a view of
        // `inner` the other has already superseded — and the drain above this
        // wrapper applies them as upsert/delete without resnapshotting, so it
        // converges on the stale view. Nothing repairs that: an aliased root
        // exists only in this wrapper's projection, so `inner`'s own stream
        // carries no correction for its Live/Dangling state, and an
        // `updates: false` inner has no stream at all.
        //
        // The cost is that a slow re-query delays the notifications behind it
        // rather than overlapping with them. That is the right trade here:
        // every one of these is detached background work with no caller waiting
        // on it, the re-query is bounded by `budget`, and in the case where
        // serializing actually costs something — a wedged `inner` — every
        // ticket emits the same resync nudge, which the first one has already
        // told the consumer to act on.
        let Some(turn) = deferred.take().await else {
            // The wrapper is gone: no turn is granted, and nothing is left
            // listening on a stream it owned.
            return;
        };
        let query_cancel = cancel.child_token();
        let cx = Extensions::new();
        let query = inner.list_address_roots(&cx, Some(query_cancel.clone()));
        let queried = match budget {
            Some(budget) => match tokio::time::timeout(budget, query).await {
                Ok(result) => result,
                Err(_) => {
                    query_cancel.cancel();
                    Err(Error::new(
                        ErrorCode::DeadlineExceeded,
                        format!(
                            "the inner layer did not answer list_address_roots within {budget:?}"
                        ),
                    ))
                }
            },
            None => query.await,
        };
        let inner_roots = match queried {
            Ok((inner_snapshot, _)) => inner_snapshot.roots,
            Err(error) => {
                // A transient inner failure must not leave subscribers silently
                // stale. We can't compute the precise delta without inner's
                // roots, so we log and broadcast a resync nudge (an empty
                // `Updated`): consumers treat any stream item as a signal to
                // re-query `list_address_roots` — the `Router`'s root watcher
                // does exactly this, and `notification_drain` routes an empty
                // `Updated` to its resnapshot+resubscribe path
                // (`is_resync_nudge`) rather than through the delta-applying
                // `apply_root_change`, which would no-op on an empty payload. So
                // the projection re-converges rather than being pinned to a
                // stale view until the next mutation.
                tracing::warn!(
                    error = %error,
                    "alias wrapper: inner list_address_roots failed during \
                     root-change notification; emitting resync nudge",
                );
                turn.send(RootInfoChange::Updated(Vec::new()));
                return;
            }
        };
        let before = project_advertised_roots(
            &old.alias_projection(),
            &old.visibility_pairs(),
            inner_roots.clone(),
        );
        let after = project_advertised_roots(
            &new.alias_projection(),
            &new.visibility_pairs(),
            inner_roots,
        );
        let added: Vec<RootInfo> = after
            .iter()
            .filter(|root| !before.iter().any(|prev| prev.root == root.root))
            .cloned()
            .collect();
        let removed: Vec<RootInfo> = before
            .iter()
            .filter(|prev| !after.iter().any(|root| root.root == prev.root))
            .cloned()
            .collect();
        let updated: Vec<RootInfo> = after
            .iter()
            .filter(|root| {
                before
                    .iter()
                    .any(|prev| prev.root == root.root && prev != *root)
            })
            .cloned()
            .collect();
        // One `send_all` rather than three `send`s: these three events are one
        // delta. Sending them separately would re-admit per event, so the
        // wrapper could drop between two of them and a subscriber would see the
        // additions without the removals — a state the committed rule set never
        // had, which an upsert/delete consumer has nothing to correct with. The
        // turn is consumed by publishing, so that is the only shape available
        // here rather than the one this call site is asked to remember.
        // Nothing is emitted when the projection is unchanged.
        turn.send_all(
            [
                (!added.is_empty()).then_some(RootInfoChange::Added(added)),
                (!removed.is_empty()).then_some(RootInfoChange::Removed(removed)),
                (!updated.is_empty()).then_some(RootInfoChange::Updated(updated)),
            ]
            .into_iter()
            .flatten(),
        );
    }

    /// Preconditions shared by `probe` and `add_connection`, so a green probe
    /// implies a viable add (keeps the duplicate-id check in sync too):
    ///
    /// - the request must be alias-kinded: a mis-kinded request is rejected
    ///   rather than silently reinterpreted as an alias rule; and
    /// - it cannot ask for durable persistence the wrapper does not have:
    ///   alias rules live only in the in-memory [`RuleSet`], so `persist = true`
    ///   would return `Ok` while being silently memory-only — reject it instead.
    fn validate_connection_request(&self, connection: &ConnectionRequest) -> Result<()> {
        if connection.backend_kind != ALIAS_KIND {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "alias connection `backend_kind` must be `{ALIAS_KIND}`, got `{}`",
                    connection.backend_kind
                ),
            ));
        }
        if connection.persist {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "alias connections are in-memory only; `persist = true` is unsupported \
                 (the alias wrapper has no durable storage)",
            ));
        }
        Ok(())
    }

    /// Resolve an alias-keyed auth op to the downstream connection it delegates
    /// to: find the alias rule by id, walk its chain (the same
    /// bounded walk + per-hop specificity as data dispatch via the shared
    /// [`Self::walk_chain_async`] — but WITHOUT the caller-address suppression check:
    /// the caller owns the row, and auth on a hidden mount must keep working) to
    /// the terminal physical address, and identify the owning connection.
    /// Returns the rule, the backend [`ConnectionKey`] to forward, and the
    /// applied hops (for re-projecting responses back into alias space).
    ///
    /// The backend key's `target` is the **owning Layer instance name** for the
    /// terminal, recovered via [`Layer::owning_target_for`] — connection ops
    /// route by instance name, not descriptor kind, so a backend Layer named
    /// differently from its kind (`s3_prod` of kind `s3`) is reached correctly.
    ///
    /// Edge cases are typed, never silent, and never disclose the resolved
    /// physical terminal to the caller (only the alias's own `from`/`to`, which
    /// the caller already knows): an unknown id is `NotFound`; a
    /// visibility-override row is `Unsupported` (credentialless by
    /// construction); a dangling terminal is `NoRoute`; a terminal served by a
    /// route with no owning connection (a static route) is `PreconditionFailed`.
    async fn resolve_auth_delegation(
        &self,
        key: &ConnectionKey,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthDelegation> {
        let rules = self.current_rules();
        let Some(rule) = rules.aliases.iter().find(|rule| rule.id == key.id).cloned() else {
            if rules.visibility.iter().any(|row| row.id == key.id) {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "visibility-override connections are credentialless; \
                     there is nothing to authenticate",
                ));
            }
            return Err(Error::new(ErrorCode::NotFound, "connection does not exist"));
        };
        let resolved = self
            .walk_chain_async(&rules, &rule.from, cancel.clone())
            .await?;
        let terminal = resolved.address;
        // ONE `root_info_for` yields BOTH the owning connection id and the
        // owning-layer instance name (`RootInfo::owning_target`), so a live
        // route change cannot race two independent lookups into pairing one
        // backend's id with another backend's target. `owning_target` crosses
        // the plugin ABI, so a loaded composite backend resolves correctly;
        // `owning_target_for` is a fallback only for a plugin that reports a
        // connection but predates the `owning_target` field.
        //
        // Error text names only the alias's own `from`/`to` (the caller's own
        // configuration), never the chain-resolved physical terminal — the same
        // leak-proofing the success path applies to `current_addresses`.
        let info = self
            .inner
            .root_info_for(&terminal, cx, cancel.clone())
            .await
            .map_err(|err| {
                Error::new(
                    err.code(),
                    format!(
                        "alias `{}` (→ `{}`) cannot delegate auth: its target resolves to no \
                         serving route",
                        rule.from, rule.to
                    ),
                )
            })?;
        let Some(connection_id) = info.connection_id else {
            return Err(Error::new(
                ErrorCode::PreconditionFailed,
                format!(
                    "alias `{}` (→ `{}`) cannot delegate auth: its target is served by a route \
                     with no owning connection (a static route); authenticate the backend \
                     directly",
                    rule.from, rule.to
                ),
            ));
        };
        let target = match info.owning_target {
            Some(target) => target,
            None => self
                .inner
                .owning_target_for(&terminal, cx, cancel)
                .await
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::PreconditionFailed,
                        format!(
                            "alias `{}` (→ `{}`) cannot delegate auth: its target has no owning \
                             connection layer",
                            rule.from, rule.to
                        ),
                    )
                })?,
        };
        let backend_key = ConnectionKey {
            target,
            id: connection_id,
        };
        Ok(AuthDelegation {
            rule,
            backend_key,
            hops: resolved.hops,
        })
    }
}

/// The resolved target of an alias-keyed auth op: the alias
/// `rule` (for re-projecting the response to its identity), the backend
/// [`ConnectionKey`] to forward the op to, and the applied chain `hops` (for
/// re-projecting returned addresses back into alias space).
struct AuthDelegation {
    rule: AliasRule,
    backend_key: ConnectionKey,
    hops: Vec<(Url, Url)>,
}

/// Rewrite a delegated auth error so it discloses nothing of the backend's
/// physical namespace to the alias caller. The backend's free-text message,
/// `reason`, and recovery hint are dropped, not merely re-redacted: redaction
/// preserves a URL's scheme/host/path, so any of those fields could carry the
/// physical address (`s3://private-bucket/tenant/path`) the alias projection
/// exists to hide. The replacement names only the alias `from` (the caller's
/// own configuration), preserves the error code, and re-projects a
/// backend-referencing [`ErrorContext::Auth`] `connection_id` to the alias rule
/// id (so the caller can still correlate the failure with the row it
/// authenticated).
fn reproject_auth_error(rule: &AliasRule, err: Error) -> Error {
    let mut out = Error::new(
        err.code(),
        format!("delegated authentication for alias `{}` failed", rule.from),
    );
    if let Some(ErrorContext::Auth { expired_at, .. }) = err.context() {
        out = out.with_context(ErrorContext::Auth {
            connection_id: rule.id.clone(),
            reason: None,
            expired_at: *expired_at,
        });
    }
    out
}

/// Re-project a backend `Connection` returned by a delegated auth op back into
/// the alias's user-facing identity: the row keeps the ALIAS
/// identity — id, `alias` kind, display name, source, user metadata, exactly
/// the `list_connections` view ([`alias_connection`]) — while carrying the
/// backend's live auth facts (`auth_state`, `capabilities`, `last_probed`).
/// Backend addresses that fall under the applied chain re-project into the
/// caller's namespace; addresses outside the alias's window are dropped (they
/// are not reachable through this alias and would leak the physical
/// namespace). When nothing maps, the alias's own `from` (the
/// [`alias_connection`] default) stands.
fn project_delegated_connection(
    rule: &AliasRule,
    hops: &[(Url, Url)],
    backend: Connection,
) -> Result<Connection> {
    let mut projected = alias_connection(rule);
    // A failure-bearing auth state carries an `ErrorContext::Auth
    // { connection_id }` (and physical-URL free text) naming the physical
    // backend; re-project every such error to the alias id so the connection
    // view, like the event stream, never surfaces backend identity. `AuthFailed`
    // carries one directly; a parked `AwaitingAuth` records the last attempt's
    // error (`ConnectionSet::park` commits exactly this). `Authenticated` /
    // `Anonymous` carry none.
    projected.auth_state = match backend.auth_state {
        ConnectionAuthState::AuthFailed { error, attempts } => ConnectionAuthState::AuthFailed {
            error: reproject_auth_error(rule, error),
            attempts,
        },
        ConnectionAuthState::AwaitingAuth {
            reason,
            last_attempt,
        } => ConnectionAuthState::AwaitingAuth {
            reason,
            last_attempt: last_attempt.map(|attempt| AuthAttempt {
                at: attempt.at,
                error: attempt.error.map(|err| reproject_auth_error(rule, err)),
            }),
        },
        other => other,
    };
    projected.capabilities = backend.capabilities;
    projected.last_probed = backend.last_probed;
    let chain = inverse_chain(hops);
    let mut addresses = Vec::new();
    for address in &backend.current_addresses {
        let mapped = project_back(&chain, address)?;
        if &mapped != address {
            addresses.push(mapped);
        }
    }
    if !addresses.is_empty() {
        projected.current_addresses = addresses;
    }
    Ok(projected)
}

/// Re-project a delegated [`AuthEventStream`]. `Succeeded`'s `connection` is
/// re-projected to the alias identity (through [`project_delegated_connection`]),
/// and any backend-referencing `ErrorContext::Auth { connection_id }` on a
/// `Failed` event OR an `Err` stream item (through [`reproject_auth_error`]) —
/// the failure path reveals exactly the backend identity the success path hides,
/// and re-projecting the id also lets the caller correlate the failure with the
/// alias row it authenticated. The purely interactive events
/// (`OpenBrowser`/`DeviceCode`/`Progress`/`Cancelled`) carry IdP material, not
/// storage addresses, and pass through unchanged.
///
/// `Succeeded.credentials` are **scrubbed to `None`**. A delegated backend
/// commits its own credentials through its connection lifecycle (a
/// `ConnectionSet` backend does exactly this — it applies + scrubs the bundle
/// against the entry the flow ran against, so a delegated `Succeeded` normally
/// arrives here already `None`). The alias must never forward a raw bundle for
/// the host to re-apply by the *alias* key: that key is re-resolved on the
/// separate credential-update call and could drift if the alias row is removed
/// and recreated with the same id mid-flow, sending one backend's tokens to
/// another. Scrubbing binds credential application to the backend the flow
/// resolved, not to a re-resolvable alias key.
fn project_auth_events(
    rule: AliasRule,
    hops: Vec<(Url, Url)>,
    stream: AuthEventStream,
) -> AuthEventStream {
    Box::new(stream.map(move |event| match event {
        Ok(AuthEvent::Succeeded {
            connection,
            credentials: _,
        }) => Ok(AuthEvent::Succeeded {
            connection: Box::new(project_delegated_connection(&rule, &hops, *connection)?),
            credentials: None,
        }),
        Ok(AuthEvent::Failed { error }) => Ok(AuthEvent::Failed {
            error: reproject_auth_error(&rule, error),
        }),
        Ok(other) => Ok(other),
        Err(error) => Err(reproject_auth_error(&rule, error)),
    }))
}

#[async_trait]
impl Layer for AliasWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    /// `owned_targets`/`list_kinds` delegate through the trait defaults (which
    /// already compose this connection-owning wrapper's own name with `inner`);
    /// every other slot below is bespoke: address-bearing ops rewrite + project,
    /// `list_connections` unions this wrapper's rules with `inner`'s, and the
    /// connection-lifecycle ops gate on the wrapper as target.
    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    fn supports_buffered_write_capture(&self) -> bool {
        self.inner.supports_buffered_write_capture()
    }

    /// Resolve this alias's own rules before asking the child, so connection
    /// ownership composes across STACKED alias wrappers exactly as data
    /// dispatch does: a caller (e.g. an outer alias delegating through this one)
    /// probing an alias-space address gets the physical owner's instance name,
    /// not a dead-end on the raw alias URL. On an unrewritten address this is
    /// the trait default (delegate to the child unchanged). Suppression is NOT
    /// re-checked here — connection ownership is not an address-read.
    async fn owning_target_for(
        &self,
        url: &Url,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Option<String> {
        let rules = self.current_rules();
        let resolved = self
            .walk_chain_async(&rules, url, cancel.clone())
            .await
            .ok()?;
        self.inner
            .owning_target_for(&resolved.address, cx, cancel)
            .await
    }

    async fn root_info_for(
        &self,
        url: &Url,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        let resolved = self.resolve(url, cancel.clone()).await?;
        let inner_info = self
            .inner
            .root_info_for(&resolved.address, cx, cancel)
            .await;
        // Not rewritten — no matching alias, or one outweighed by a more
        // specific real route — the inner root is already
        // caller-facing, so it passes through (errors included).
        let Some((from, to)) = resolved.hops.first() else {
            return inner_info;
        };
        // Rewritten: present the caller-facing alias root of the FIRST hop +
        // `Alias` source/state, mirroring the alias synthesis in
        // `list_address_roots` — including for a dangling chain (`NoRoute`
        // from the inner stack), which reports the same synthesized bare
        // alias root the advertisement lists, so the two introspection paths
        // agree.
        let (mut info, state) = match inner_info {
            Ok(info) => (info, AliasState::Live),
            Err(error) if error.code() == ErrorCode::NoRoute => {
                (bare_alias_root(from), AliasState::Dangling)
            }
            Err(error) => return Err(error),
        };
        info.root = from.clone();
        info.source = RouteSource::Alias {
            to: to.clone(),
            // Threaded from `resolve`; falls back to `Static
            // { Programmatic }` only if the rule vanished within the snapshot.
            alias_source: resolved
                .first_hop_source
                .clone()
                .unwrap_or(AliasSource::Static {
                    layer: ConfigLayer::Programmatic,
                }),
        };
        info.alias_state = Some(state);
        Ok(info)
    }

    async fn list_address_roots(
        &self,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        // Subscribe to the local rule-change broadcast BEFORE snapshotting, so a
        // rule mutation racing between the two is delivered on the stream rather
        // than lost.
        let local = BroadcastStream::new(self.rules.subscribe_deferred())
            .map(|item| item.map_err(|error| Error::new(ErrorCode::Internal, error.to_string())));
        let rules = self.current_rules();
        let (mut snapshot, inner_stream) = self.inner.list_address_roots(cx, cancel).await?;
        // Advertise only `Visible` roots (drop `Hidden`/`Suppressed`) and
        // synthesize a root for each live, visible alias whose target
        // root exists — including Hidden/Suppressed targets, the rewrite shape:
        // the caller-facing mount advertises while its physical `rewrite_to`
        // target is suppressed by construction. Dangling/ChainTooLong aliases
        // are not advertised.
        snapshot.roots = project_advertised_roots(
            &rules.alias_projection(),
            &rules.visibility_pairs(),
            snapshot.roots,
        );
        // The wrapper always exposes an update stream now, because runtime rule
        // mutations synthesize root changes even when `inner` is static.
        snapshot.updates = true;
        // Merge `inner`'s projected updates with the local rule-change
        // broadcast. The projection closure re-reads the CURRENT rules per
        // change (a rule added after this subscribe still filters correctly);
        // the `.map` is synchronous, so the read guard never spans an await.
        let merged: RootInfoUpdateStream = match inner_stream {
            Some(inner_stream) => {
                // A `ReadHandle`, not a clone of the whole `Sequenced`: this
                // closure is RETURNED to the caller and outlives this call, and
                // anything that owns a sender would keep the local half of the
                // merged stream open forever, so a consumer draining to EOF
                // would hang.
                let rules_handle = self.rules.read_handle();
                let projected = inner_stream.map(move |change| {
                    let rules = rules_handle.read().clone();
                    change.map(|change| {
                        project_root_change(
                            &rules.alias_projection(),
                            &rules.visibility_pairs(),
                            change,
                        )
                    })
                });
                Box::pin(futures::stream::select(local, projected))
            }
            None => Box::pin(local),
        };
        Ok((snapshot, Some(merged)))
    }

    async fn stat(
        &self,
        mut request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let resolved = self.resolve(&request.input.address, cancel.clone()).await?;
        request.input.address = resolved.address;
        let chain = inverse_chain(&resolved.hops);
        let info = self.inner.stat(request, cancel).await?;
        project_info(&chain, info)
    }

    async fn read(
        &self,
        mut request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let resolved = self.resolve(&request.input.address, cancel.clone()).await?;
        request.input.address = resolved.address;
        let chain = inverse_chain(&resolved.hops);
        let result = self.inner.read(request, cancel).await?;
        project_read_result(&chain, result)
    }

    async fn write(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let resolved = self.resolve(&request.input.address, cancel.clone()).await?;
        request.input.address = resolved.address;
        let chain = inverse_chain(&resolved.hops);
        let result = self.inner.write(request, cancel).await?;
        project_write_result(&chain, result)
    }

    async fn write_stream(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let resolved = self.resolve(&request.input.address, cancel.clone()).await?;
        request.input.address = resolved.address;
        let chain = inverse_chain(&resolved.hops);
        let result = self.inner.write_stream(request, cancel).await?;
        project_write_result(&chain, result)
    }

    async fn write_redirect(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        // The redirect batch carries external (presigned) URLs, not backend
        // addresses, so it is forwarded unprojected.
        request.input.address = self
            .resolve(&request.input.address, cancel.clone())
            .await?
            .address;
        self.inner.write_redirect(request, cancel).await
    }

    async fn continue_write(
        &self,
        mut request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let resolved = self.resolve(&request.input.address, cancel.clone()).await?;
        request.input.address = resolved.address;
        let chain = inverse_chain(&resolved.hops);
        let step = self.inner.continue_write(request, cancel).await?;
        project_write_step(&chain, step)
    }

    async fn delete(
        &self,
        mut request: Request<DeleteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        request.input.address = self
            .resolve(&request.input.address, cancel.clone())
            .await?
            .address;
        self.inner.delete(request, cancel).await
    }

    async fn copy(
        &self,
        mut request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let source = self.resolve(&request.input.source, cancel.clone()).await?;
        let destination = self
            .resolve(&request.input.destination, cancel.clone())
            .await?;
        request.input.source = source.address;
        request.input.destination = destination.address;
        // The returned step carries the destination address, so it projects
        // back through the destination's applied chain.
        let chain = inverse_chain(&destination.hops);
        let step = self.inner.copy(request, cancel).await?;
        project_write_step(&chain, step)
    }

    async fn rename(
        &self,
        mut request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        request.input.source = self
            .resolve(&request.input.source, cancel.clone())
            .await?
            .address;
        request.input.destination = self
            .resolve(&request.input.destination, cancel.clone())
            .await?
            .address;
        self.inner.rename(request, cancel).await
    }

    async fn update_metadata(
        &self,
        mut request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        // `BackendItemInfo` carries no address — nothing to project back.
        request.input.address = self
            .resolve(&request.input.address, cancel.clone())
            .await?
            .address;
        self.inner.update_metadata(request, cancel).await
    }

    async fn check_access(
        &self,
        mut request: Request<CheckAccessRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        request.input.address = self
            .resolve(&request.input.address, cancel.clone())
            .await?
            .address;
        self.inner.check_access(request, cancel).await
    }

    async fn materialize(
        &self,
        mut request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        let resolved = self.resolve(&request.input.address, cancel.clone()).await?;
        request.input.address = resolved.address;
        let chain = inverse_chain(&resolved.hops);
        let delegate = self.inner.materialize(request, cancel).await?;
        project_delegate(&chain, delegate)
    }

    async fn list(
        &self,
        mut request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        let resolved = self.resolve(&request.input.prefix, cancel.clone()).await?;
        request.input.prefix = resolved.address;
        let chain = inverse_chain(&resolved.hops);
        let mut page = self.inner.list(request, cancel).await?;
        project_items(&chain, &mut page.items)?;
        Ok(page)
    }

    async fn list_versions(
        &self,
        mut request: Request<ListVersionsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        let resolved = self.resolve(&request.input.address, cancel.clone()).await?;
        request.input.address = resolved.address;
        let chain = inverse_chain(&resolved.hops);
        let mut page = self.inner.list_versions(request, cancel).await?;
        project_items(&chain, &mut page.items)?;
        Ok(page)
    }

    async fn get_latest_version(
        &self,
        mut request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let resolved = self.resolve(&request.input.address, cancel.clone()).await?;
        request.input.address = resolved.address;
        let chain = inverse_chain(&resolved.hops);
        let info = self.inner.get_latest_version(request, cancel).await?;
        project_info(&chain, info)
    }

    async fn watch_directory(
        &self,
        mut request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        let resolved = self.resolve(&request.input.prefix, cancel.clone()).await?;
        request.input.prefix = resolved.address;
        let chain = inverse_chain(&resolved.hops);
        let stream = self.inner.watch_directory(request, cancel).await?;
        Ok(project_change_stream(chain, stream))
    }

    async fn create_directory(
        &self,
        mut request: Request<CreateDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        request.input.address = self
            .resolve(&request.input.address, cancel.clone())
            .await?
            .address;
        self.inner.create_directory(request, cancel).await
    }

    async fn delete_directory(
        &self,
        mut request: Request<DeleteDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        request.input.address = self
            .resolve(&request.input.address, cancel.clone())
            .await?
            .address;
        self.inner.delete_directory(request, cancel).await
    }

    /// This connection-owning wrapper's rules unioned with `inner`'s
    /// connections (`self ∪ inner`, per the RFC identity table). Subscribes to
    /// the local connection-change broadcast BEFORE snapshotting so a mutation
    /// racing the snapshot is delivered on the stream, not lost.
    async fn list_connections(
        &self,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        let local = BroadcastStream::new(self.rules.subscribe_primary())
            .map(|item| item.map_err(|error| Error::new(ErrorCode::Internal, error.to_string())));
        let rules = self.current_rules();
        let (inner_snapshot, inner_stream) = self.inner.list_connections(cx, cancel).await?;
        let mut connections: Vec<Connection> = rules.aliases.iter().map(alias_connection).collect();
        connections.extend(rules.visibility.iter().map(visibility_connection));
        // Connection ids are unique only WITHIN an owner. This union places
        // alias-wrapper-owned ids and inner ids into one flat id-space, so a
        // collision between the two id-spaces is possible; a caller that needs
        // to disambiguate uses each row's owning `target` (the wrapper name vs.
        // the inner owner). Enforcing global uniqueness would require querying
        // `inner` on every add (racy against inner's own mutations), so this is
        // a documented constraint, not an enforced one.
        let has_local_rows = !connections.is_empty();
        let inner_has_updates = inner_stream.is_some();
        connections.extend(inner_snapshot.connections);
        // Merge `inner`'s connection updates (a backend below can add/remove
        // connections at runtime) with the local broadcast. `inner`'s
        // connections pass through unprojected — they are the backend's own,
        // not results of forward-rewritten requests.
        let merged: ConnectionUpdateStream = match inner_stream {
            Some(inner_stream) => Box::pin(futures::stream::select(local, inner_stream)),
            None => Box::pin(local),
        };
        // `updates` must reflect a real live stream for the listed rows. The
        // local rule-mutation broadcast covers alias/visibility rows; inner rows
        // are live only when `inner` itself supplies an update stream. Report
        // `true` only when a live source actually exists — not unconditionally,
        // which would promise live updates for inner rows that a static inner
        // will never send.
        let updates = has_local_rows || inner_has_updates;
        Ok((
            ConnectionSnapshot {
                connections,
                updates,
            },
            Some(merged),
        ))
    }

    // --- connection lifecycle ---------------------------------------
    //
    // When the request targets this wrapper, the alias/visibility rule set is
    // mutated directly; otherwise it delegates to the inner connection owner.

    async fn probe(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.target != self.name {
            return self.inner.probe(request, cancel).await;
        }
        // Validate the rule fragment without registering it — side-effect-free.
        // A green probe must imply a viable add, so it enforces the SAME
        // preconditions `add_connection` does: kind/persist, a valid id,
        // and the duplicate-id check `add_connection` runs.
        let connection = &request.input.connection;
        self.validate_connection_request(connection)?;
        let id = connection_id(connection)?;
        if self.current_rules().contains_id(&id) {
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                format!("connection id `{}` already exists", id.0),
            ));
        }
        let source = AliasSource::Runtime {
            persisted: connection.persist,
        };
        match parse_rule_fragment(connection)? {
            RuleFragment::Alias {
                from,
                to,
                visibility,
            } => {
                // Chain-validate the prospective rule set (current + candidate)
                // exactly as `add_connection` would, but discard it.
                let mut candidate = (*self.current_rules()).clone();
                candidate.aliases.push(AliasRule {
                    id,
                    from,
                    to,
                    source,
                    display_name: connection.display_name.clone(),
                    user_metadata: UserMetadata::new(),
                    visibility,
                });
                validate_alias_rules(&candidate.alias_pairs())?;
                Ok(alias_connection(
                    candidate.aliases.last().expect("just pushed"),
                ))
            }
            RuleFragment::Visibility {
                address,
                visibility,
            } => {
                // Preview what `add_connection` would do, including its
                // rejection, so a request that will be refused previews as
                // refused rather than as accepted.
                let rule = VisibilityOverride {
                    id,
                    address,
                    visibility,
                    source,
                    display_name: connection.display_name.clone(),
                    user_metadata: UserMetadata::new(),
                };
                let mut candidate = (*self.current_rules()).clone();
                candidate.visibility.push(rule.clone());
                validate_visibility_rules(&standalone_visibility_pairs(&candidate.visibility))?;
                Ok(visibility_connection(&rule))
            }
        }
    }

    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.target != self.name {
            return self.inner.add_connection(request, cancel).await;
        }
        let connection = &request.input.connection;
        // Reject mis-kinded and persist-requesting requests up front.
        self.validate_connection_request(connection)?;
        let id = connection_id(connection)?;
        let fragment = parse_rule_fragment(connection)?;
        let source = AliasSource::Runtime {
            persisted: connection.persist,
        };
        let display_name = connection.display_name.clone();
        // Read-modify-write under the write guard so a duplicate-id check and
        // the swap are atomic against concurrent adds. `validate_alias_rules`
        // (the eager check) runs on the candidate before it is committed, so
        // an over-cap/cycling add is rejected without ever being installed. The
        // rejections return `Err` from INSIDE the commit closure, so a rejected
        // add stamps no ticket at all; the guard drops on the way out, and
        // parking_lot never poisons.
        let (old, new, new_connection, deferred) = self.rules.commit(|rules, commit| {
            let old: Arc<RuleSet> = rules.clone();
            if old.contains_id(&id) {
                return Err(Error::new(
                    ErrorCode::AlreadyExists,
                    format!("connection id `{}` already exists", id.0),
                ));
            }
            let mut candidate = (*old).clone();
            let new_connection = match fragment {
                RuleFragment::Alias {
                    from,
                    to,
                    visibility,
                } => {
                    let rule = AliasRule {
                        id,
                        from,
                        to,
                        source,
                        display_name,
                        user_metadata: UserMetadata::new(),
                        visibility,
                    };
                    candidate.aliases.push(rule.clone());
                    validate_alias_rules(&candidate.alias_pairs())?;
                    alias_connection(&rule)
                }
                RuleFragment::Visibility {
                    address,
                    visibility,
                } => {
                    let rule = VisibilityOverride {
                        id,
                        address,
                        visibility,
                        source,
                        display_name,
                        user_metadata: UserMetadata::new(),
                    };
                    candidate.visibility.push(rule.clone());
                    // Mirrors the `validate_alias_rules` call in the `Alias`
                    // arm. Without it a runtime add could introduce a second
                    // spelling of a scope the TOML already scoped, and the two
                    // tie on rank — so the later `Visible` silently un-hides a
                    // subtree the operator hid, with no error surfaced.
                    validate_visibility_rules(&standalone_visibility_pairs(&candidate.visibility))?;
                    visibility_connection(&rule)
                }
            };
            let new = Arc::new(candidate);
            *rules = Arc::clone(&new);
            // Both notifications are sequenced by the guard that serializes the
            // swaps: the connection change is SENT here, and the root change is
            // TICKETED here (its delta needs an inner re-query, so it cannot be
            // computed under a lock). Sending from after the guard dropped would
            // let a concurrent remove commit and emit its `Removed` in between,
            // so a delta consumer ends up with a connection the rule set no
            // longer has. `broadcast::send` neither blocks nor awaits — it wakes
            // receivers, it does not run them — so it is safe under the guard.
            commit.send(ConnectionChange::Added(new_connection.clone()));
            Ok((old, new, new_connection, commit.defer()))
        })?;
        self.notify_root_change(deferred, old, new).await;
        Ok(new_connection)
    }

    async fn remove_connection(
        &self,
        key: Request<ConnectionKey>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        if key.input.target != self.name {
            return self.inner.remove_connection(key, cancel).await;
        }
        let id = &key.input.id;
        // Every rejection returns `Err` from inside the commit closure, so a
        // rejected removal stamps no ticket.
        let (old, new, deferred) = self.rules.commit(|rules, commit| {
            let old: Arc<RuleSet> = rules.clone();
            let mut candidate = (*old).clone();
            let removed = if let Some(pos) =
                candidate.aliases.iter().position(|rule| &rule.id == id)
            {
                let removed = candidate.aliases.remove(pos).id;
                // Removing a more-specific alias can expose a cycle it shielded:
                // e.g. removing `a:/// -> b:///guard/` unmasks a latent
                // `a:/// <-> b:///` loop. Re-validate the post-remove set before
                // committing the swap, rejecting a removal that would leave the
                // rule set invalid.
                validate_alias_rules(&candidate.alias_pairs())?;
                removed
            } else if let Some(pos) = candidate.visibility.iter().position(|rule| &rule.id == id) {
                // Visibility overrides don't participate in chains, so removing
                // one can't affect chain validity.
                candidate.visibility.remove(pos).id
            } else {
                return Err(Error::new(ErrorCode::NotFound, "connection does not exist"));
            };
            let new = Arc::new(candidate);
            *rules = Arc::clone(&new);
            // Sent and ticketed under the guard, as in `add_connection`: an
            // `add` racing this must not deliver its `Added` after this
            // `Removed` on either channel.
            commit.send(ConnectionChange::Removed { id: removed });
            Ok((old, new, commit.defer()))
        })?;
        // The synthesized root-change emission is projected through
        // `project_advertised_roots`, so a removed alias into a suppressed
        // namespace can only surface its (advertised) alias root, never the
        // suppressed target — and a later request to the now-unconfigured
        // namespace is `NoRoute`, indistinguishable from never-configured.
        self.notify_root_change(deferred, old, new).await;
        Ok(())
    }

    /// Alias-keyed credential updates delegate to the downstream backend
    /// connection: the alias resolves its chain terminal, the
    /// credentials are applied to the OWNING connection, and the returned row
    /// re-projects to the alias's user-facing identity.
    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.key.target != self.name {
            return self
                .inner
                .update_connection_credentials(request, cancel)
                .await;
        }
        let AuthDelegation {
            rule,
            backend_key,
            hops,
        } = self
            .resolve_auth_delegation(&request.input.key, &request.extensions, cancel.clone())
            .await?;
        let forwarded = Request {
            extensions: request.extensions,
            input: UpdateConnectionCredentialsRequest {
                key: backend_key,
                credentials: request.input.credentials,
            },
        };
        // A backend `Err` carries an `ErrorContext::Auth { connection_id }`
        // naming the physical backend; re-project it to the alias identity so
        // the failure path, like the success path, never surfaces backend
        // identity or its physical namespace.
        let backend = self
            .inner
            .update_connection_credentials(forwarded, cancel)
            .await
            .map_err(|err| reproject_auth_error(&rule, err))?;
        project_delegated_connection(&rule, &hops, backend)
    }

    async fn update_connection_attributes(
        &self,
        request: Request<UpdateConnectionAttributesRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.key.target != self.name {
            return self
                .inner
                .update_connection_attributes(request, cancel)
                .await;
        }
        let id = &request.input.key.id;
        let patch = &request.input.patch;
        // Every rejection returns `Err` from inside the commit closure, so a
        // rejected patch stamps no ticket.
        let (old, new, updated, deferred) = self.rules.commit(|rules, commit| {
            let old: Arc<RuleSet> = rules.clone();
            let mut candidate = (*old).clone();
            let updated = if let Some(rule) =
                candidate.aliases.iter_mut().find(|rule| &rule.id == id)
            {
                apply_presentation_patch(&mut rule.display_name, &mut rule.user_metadata, patch)?;
                // `patch.visible` drives the alias's intrinsic visibility,
                // honored rather than silently ignored. The two-state bool never
                // downgrades an already-`Suppressed` alias.
                if let Some(visible) = patch.visible {
                    rule.visibility = Some(patched_visibility(rule.visibility, visible));
                }
                alias_connection(rule)
            } else if let Some(rule) = candidate.visibility.iter_mut().find(|rule| &rule.id == id) {
                apply_presentation_patch(&mut rule.display_name, &mut rule.user_metadata, patch)?;
                // A visibility override's two-state `visible` maps onto its
                // value; reaching `Suppressed` at runtime is an add/remove, and
                // `visible: false` must never downgrade `Suppressed` (leak-proof)
                // to `Hidden`.
                if let Some(visible) = patch.visible {
                    rule.visibility = patched_visibility(Some(rule.visibility), visible);
                    // Re-validate this rule, because the patch can turn a rule
                    // the loader accepted into one it refuses. A prefix
                    // carrying credentials loads while it hides — hiding more
                    // than the rule spells is the safe direction — and this
                    // patch is the one operation that can make that same rule
                    // `Visible`, which is the direction that publishes a path
                    // under every credential. Validating only where a rule
                    // ENTERS the set would leave the refusal asserted at one
                    // door and unenforced at the other.
                    validate_visibility_rules(&[(rule.address.clone(), rule.visibility)])?;
                }
                visibility_connection(rule)
            } else {
                return Err(Error::new(ErrorCode::NotFound, "connection does not exist"));
            };
            let new = Arc::new(candidate);
            *rules = Arc::clone(&new);
            // Sent and ticketed under the guard, as in `add_connection`.
            commit.send(ConnectionChange::Updated(updated.clone()));
            Ok((old, new, updated, commit.defer()))
        })?;
        self.notify_root_change(deferred, old, new).await;
        Ok(updated)
    }

    /// Alias-keyed interactive auth delegates to the downstream backend
    /// connection: the flow runs against the OWNING
    /// connection, and the event stream re-projects `Succeeded` back to the
    /// alias's user-facing identity (interactive events pass through — they
    /// carry IdP material, not storage addresses).
    async fn authenticate_connection(
        &self,
        request: Request<AuthenticateRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        if request.input.key.target != self.name {
            return self.inner.authenticate_connection(request, cancel).await;
        }
        let AuthDelegation {
            rule,
            backend_key,
            hops,
        } = self
            .resolve_auth_delegation(&request.input.key, &request.extensions, cancel.clone())
            .await?;
        let forwarded = Request {
            extensions: request.extensions,
            input: AuthenticateRequest {
                key: backend_key,
                capability: request.input.capability,
                auto_open_browser: request.input.auto_open_browser,
            },
        };
        // An immediate (pre-stream) backend error carries backend-scoped text +
        // an `ErrorContext::Auth { connection_id }`; re-project it like the
        // stream errors and the update-credentials seam.
        let stream = self
            .inner
            .authenticate_connection(forwarded, cancel)
            .await
            .map_err(|err| reproject_auth_error(&rule, err))?;
        Ok(project_auth_events(rule, hops, stream))
    }
}

/// Map a two-state `visible` patch onto a three-category visibility, preserving
/// a leak-proof `Suppressed` on `visible: false`: the bool cannot express
/// `Suppressed`, so it must not silently downgrade it to the weaker `Hidden`
/// (which returns `NotFound` rather than `NoRoute` and is not leak-proof).
/// `current == None` (an alias with no intrinsic visibility) is the default
/// `Visible`.
fn patched_visibility(current: Option<AddressVisibility>, visible: bool) -> AddressVisibility {
    if visible {
        AddressVisibility::Visible
    } else if current == Some(AddressVisibility::Suppressed) {
        AddressVisibility::Suppressed
    } else {
        AddressVisibility::Hidden
    }
}

/// Apply an [`AttributePatch`]'s presentation fields (`display_name`,
/// `user_metadata`) to a rule. `access_mode` is ignored — alias connections are
/// credentialless and carry no access mode. Rejects a patch that writes the
/// wrapper-managed discriminator keys (`ALIAS_TO_KEY`/`ALIAS_VISIBILITY_KEY`)
/// into stored `user_metadata`: those are stamped on read from the rule's
/// own fields, so accepting them verbatim would corrupt the round-trip.
fn apply_presentation_patch(
    display_name: &mut Option<String>,
    user_metadata: &mut UserMetadata,
    patch: &AttributePatch,
) -> Result<()> {
    for key in patch.user_metadata.keys() {
        if key == ALIAS_TO_KEY || key == ALIAS_VISIBILITY_KEY {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("`{key}` is a reserved alias metadata key and cannot be patched"),
            ));
        }
    }
    if let Some(name) = &patch.display_name {
        *display_name = Some(name.clone());
    }
    for (key, value) in &patch.user_metadata {
        match value {
            Some(value) => {
                user_metadata.insert(key.clone(), value.clone());
            }
            None => {
                user_metadata.remove(key);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod config_shape_tests {
    //! Parser coverage for the config shape produced by the host.
    //!
    //! The local marshaler is a hand-maintained mirror of
    //! `ovstorage::config::config_value_from_toml`. Host-side integration tests
    //! in `ovstorage/tests/build_stack.rs` bind the real marshaler to this
    //! parser.
    use super::*;

    fn config_value_from_toml(key: &str, value: &toml::Value) -> Result<ConfigValue> {
        match value {
            toml::Value::String(value) => Ok(ConfigValue::String(value.clone())),
            toml::Value::Integer(value) => Ok(ConfigValue::Int(*value)),
            toml::Value::Boolean(value) => Ok(ConfigValue::Bool(*value)),
            toml::Value::Table(_) | toml::Value::Array(_) => {
                let mut wrapper = toml::value::Table::new();
                wrapper.insert(key.to_string(), value.clone());
                toml::to_string(&toml::Value::Table(wrapper))
                    .map(ConfigValue::Toml)
                    .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))
            }
            toml::Value::Float(_) | toml::Value::Datetime(_) => Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("config field '{key}' has an unsupported type"),
            )),
        }
    }

    /// Marshal `[[<key>]]`-shaped operator TOML through the mirrored host shape
    /// into a `LayerConfig`.
    fn marshaled_layer_config(key: &str, toml_body: &str) -> LayerConfig {
        let table: toml::Value = toml::from_str(toml_body).unwrap();
        let value = table.get(key).expect("array lives under the config key");
        let mut config = LayerConfig::new();
        config.insert(key.to_string(), config_value_from_toml(key, value).unwrap());
        config
    }

    #[test]
    fn operator_authored_aliases_parse_into_rules() {
        let config = marshaled_layer_config(
            "aliases",
            "[[aliases]]\nfrom = \"ov:///pub/\"\nto = \"file:///srv/\"\n",
        );
        let rules = parse_prefix_rules(&config, "aliases").unwrap();
        assert_eq!(rules.len(), 1, "operator alias rule was dropped: {rules:?}");
        assert_eq!(rules[0].0.as_str(), "ov:///pub/");
        assert_eq!(rules[0].1.as_str(), "file:///srv/");
    }

    #[test]
    fn operator_authored_visibility_parse_into_rules() {
        let config = marshaled_layer_config(
            "visibility",
            "[[visibility]]\naddress = \"file:///srv/secret/\"\nvisibility = \"suppressed\"\n",
        );
        let rules = parse_visibility_rules(&config, "visibility").unwrap();
        assert_eq!(rules.len(), 1, "operator visibility rule was dropped");
        assert_eq!(rules[0].0.as_str(), "file:///srv/secret/");
        assert_eq!(rules[0].1, AddressVisibility::Suppressed);
    }

    /// A query-bearing visibility prefix is refused, in every direction.
    ///
    /// The failure it prevents is a fail-open, which is why it is a load error
    /// rather than the warning a widened `Hidden` rule gets. Selection is
    /// `is_ancestor_or_self`, which for a query-bearing prefix requires exact
    /// query equality; 0.2.0's `is_prefix_of` admitted an `&`-aligned
    /// extension. Measured against this tree:
    ///
    /// ```text
    /// prefix https://h/private?v=1  addr https://h/private?v=1              covered
    /// prefix https://h/private?v=1  addr https://h/private?v=1&download=1   NOT covered
    /// ```
    ///
    /// So a `Suppressed` rule that covered the second address on 0.2.0 stops
    /// covering it, the address matches no rule, and `unwrap_or` makes it
    /// `Visible` — hidden content advertised, with no load error and nothing
    /// logged.
    ///
    /// The `Visible` row is deliberate: this refuses every direction, not just
    /// the ones that fail open, because a rule that matches one spelling of a
    /// pin and not its extensions is not what any operator meant to write.
    ///
    /// Load-bearing line: the `prefix.query().is_some()` refusal in
    /// `validate_visibility_rules`. Deleting it turns the first two assertions
    /// red and leaves the query-free row green.
    #[test]
    fn a_query_bearing_visibility_prefix_is_refused() {
        for visibility in [
            AddressVisibility::Suppressed,
            AddressVisibility::Hidden,
            AddressVisibility::Visible,
        ] {
            let error = validate_visibility_rules(&[(
                Url::parse("s3://b/secret/?v=1").unwrap(),
                visibility,
            )])
            .expect_err("a query-bearing visibility prefix must not load");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{visibility:?}");
            assert!(
                error.message().contains("query"),
                "the refusal must name what it refused: {}",
                error.message()
            );
        }

        // The query is not echoed: it is the part being refused and the part a
        // signature lives in.
        let error = validate_visibility_rules(&[(
            Url::parse("https://h/private?sig=SECRET").unwrap(),
            AddressVisibility::Suppressed,
        )])
        .expect_err("still refused");
        assert!(
            !error.message().contains("SECRET"),
            "the refusal leaked the signature: {}",
            error.message()
        );

        // The query-free rule still loads, or the refusal would have cost
        // every working visibility configuration.
        validate_visibility_rules(&[(
            Url::parse("s3://b/secret/").unwrap(),
            AddressVisibility::Suppressed,
        )])
        .expect("a query-free visibility prefix is the ordinary case");
    }

    /// A query and a fragment are both refused, in every rule field.
    ///
    /// An address names a node and neither component is part of what names it,
    /// so a config address carrying one is a component the operator believes is
    /// working that no code consults — and dropping it silently is what this
    /// refusal exists to stop.
    ///
    /// **The two are caught at different places, and that is structural.** A
    /// query survives `address::parse`, so `validate_alias_rules` and
    /// `validate_visibility_rules` can see it and do — which is what covers
    /// `AliasWrapperFactory::with_rules`, whose caller hands over `Url` values
    /// and never a string. A fragment does not survive: `canonicalize` strips
    /// it, so the only view that still contains one is the operator's raw
    /// string in `parse_url`.
    ///
    /// The good input is asserted beside each refusal, because a strip and a
    /// refusal are indistinguishable to a test that only checks the honest
    /// spelling loaded.
    #[test]
    fn a_query_or_a_fragment_is_refused_in_every_rule_field() {
        // Fragment: on `from`, on `to`, and on a visibility address.
        for (key, toml, what) in [
            (
                "aliases",
                "[[aliases]]\nfrom = \"ov:///pub#note\"\nto = \"file:///srv/\"\n",
                "a fragment on `from`",
            ),
            (
                "aliases",
                "[[aliases]]\nfrom = \"ov:///pub\"\nto = \"file:///srv/#note\"\n",
                "a fragment on `to`",
            ),
            (
                "visibility",
                "[[visibility]]\naddress = \"file:///srv/secret#note\"\nvisibility = \"suppressed\"\n",
                "a fragment on a visibility address",
            ),
            (
                "aliases",
                "[[aliases]]\nfrom = \"ov:///pub?v=1\"\nto = \"file:///srv/\"\n",
                "a query on `from`",
            ),
            (
                "aliases",
                "[[aliases]]\nfrom = \"ov:///pub\"\nto = \"file:///srv/?v=1\"\n",
                "a query on `to`",
            ),
            (
                "visibility",
                "[[visibility]]\naddress = \"file:///srv/secret?v=1\"\nvisibility = \"suppressed\"\n",
                "a query on a visibility address",
            ),
        ] {
            let config = marshaled_layer_config(key, toml);
            let error = match key {
                "aliases" => parse_prefix_rules(&config, key),
                _ => parse_visibility_rules(&config, key).map(|_| Vec::new()),
            }
            .err()
            .unwrap_or_else(|| panic!("{what} must be refused"));
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{what}");
            let component = if what.contains("fragment") {
                "fragment"
            } else {
                "query"
            };
            assert!(
                error.message().contains(component),
                "{what}: the refusal must name what it refused: {}",
                error.message()
            );
        }

        // The good input: the same rules without either component load, and
        // they load as the addresses that were written.
        let aliases = marshaled_layer_config(
            "aliases",
            "[[aliases]]\nfrom = \"ov:///pub\"\nto = \"file:///srv/\"\n",
        );
        let rules = parse_prefix_rules(&aliases, "aliases").expect("the ordinary rule loads");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].0.as_str(), "ov:///pub");
        assert_eq!(rules[0].1.as_str(), "file:///srv/");

        let visibility = marshaled_layer_config(
            "visibility",
            "[[visibility]]\naddress = \"file:///srv/secret\"\nvisibility = \"suppressed\"\n",
        );
        let vis = parse_visibility_rules(&visibility, "visibility")
            .expect("the ordinary visibility rule loads");
        assert_eq!(vis[0].0.as_str(), "file:///srv/secret");

        // `%23` and `%3F` are literal key bytes and survive as ones, which is
        // what stops the refusals above from being a blanket ban on `#` and
        // `?`.
        let escaped = marshaled_layer_config(
            "aliases",
            "[[aliases]]\nfrom = \"ov:///pub%23note%3Fx/\"\nto = \"file:///srv/\"\n",
        );
        assert_eq!(
            parse_prefix_rules(&escaped, "aliases").unwrap()[0]
                .0
                .as_str(),
            "ov:///pub%23note%3Fx/"
        );

        // The `Url`-typed path has no string to scan, so the query refusal
        // there is the validators'. Both sides, or `to` would be the exception
        // the rule says there is not.
        for (from, to) in [
            ("ov:///pub/?v=1", "file:///srv/"),
            ("ov:///pub/", "some-other:///?hello"),
        ] {
            let error =
                validate_alias_rules(&[(Url::parse(from).unwrap(), Url::parse(to).unwrap())])
                    .expect_err("a query on either side must be refused");
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
        }
        validate_alias_rules(&[(
            Url::parse("ov:///pub/").unwrap(),
            Url::parse("file:///srv/").unwrap(),
        )])
        .expect("the query-free pair is the ordinary case");
    }

    #[test]
    fn legacy_inline_rule_and_entry_spelling_still_parse() {
        // Hand-built `ConfigValue::Toml` fragments (older tests, direct callers)
        // use the inline `[[rule]]`/`[[entry]]` array names; `#[serde(alias)]`
        // keeps them working alongside the canonical config-key spelling.
        let mut config = LayerConfig::new();
        config.insert(
            "aliases".to_string(),
            ConfigValue::Toml(
                "[[rule]]\nfrom = \"ov:///pub/\"\nto = \"file:///srv/\"\n".to_string(),
            ),
        );
        config.insert(
            "visibility".to_string(),
            ConfigValue::Toml(
                "[[entry]]\naddress = \"file:///srv/secret/\"\nvisibility = \"hidden\"\n"
                    .to_string(),
            ),
        );
        assert_eq!(parse_prefix_rules(&config, "aliases").unwrap().len(), 1);
        assert_eq!(
            parse_visibility_rules(&config, "visibility").unwrap().len(),
            1
        );
    }
}

#[cfg(test)]
mod same_node_scope_tests {
    //! Two spellings of one scope must not both load.
    //!
    //! They tie on rank, so declaration order decides which one wins — and for
    //! visibility that inversion fails **open**, turning a `Hidden` rule into a
    //! `Visible` one.
    use super::*;

    fn url(value: &str) -> Url {
        address::parse(value).unwrap()
    }

    #[test]
    fn two_spellings_of_one_alias_from_fail_to_load() {
        for (first, second) in [
            ("alias:///team", "alias:///team/"),
            ("alias:///team/", "alias:///team"),
        ] {
            let rules = vec![
                (url(first), url("s3://b/one/")),
                (url(second), url("s3://b/two/")),
            ];
            let error = validate_alias_rules(&rules)
                .expect_err("two spellings of one `from` scope must be refused");
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
        }

        // The control: two genuinely different scopes still load.
        validate_alias_rules(&[
            (url("alias:///team/"), url("s3://b/one/")),
            (url("alias:///other/"), url("s3://b/two/")),
        ])
        .unwrap();
    }

    /// An alias `from` carrying credentials does not load, and `to` still may.
    ///
    /// Matching compares scheme, host, port and path, so a credential-bearing
    /// `from` covers its path for every credential rather than the one
    /// written — the widening the authz policy loader refuses for an allow.
    /// The two honest cases are asserted beside it, because a refusal that
    /// also refuses the ordinary configuration is worse than the widening.
    ///
    /// **The password carries a comma deliberately.** `Error`'s redactor
    /// strips userinfo on its own for an ordinary URL, so a `reader:token`
    /// fixture would stay clean with the `RedactedUrl` rendering deleted and
    /// would prove nothing about it. `scan_url_at` ends a token at `,`, the
    /// truncated token then fails to parse, and the whole thing is emitted
    /// verbatim — so only the rendering under test can catch this one.
    #[test]
    fn an_alias_from_carrying_credentials_is_refused() {
        let error = validate_alias_rules(&[(
            url("https://reader:tok,en@origin.invalid/reports/"),
            url("s3://b/reports/"),
        )])
        .expect_err("a credential-bearing `from` must be refused");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.message().contains("credentials"),
            "the refusal must name what is wrong with the rule: {}",
            error.message()
        );
        assert!(
            !error.message().contains("tok,en"),
            "the refusal leaked the credential: {}",
            error.message()
        );

        // A username with no password is the same widening.
        validate_alias_rules(&[(
            url("https://reader@origin.invalid/reports/"),
            url("s3://b/reports/"),
        )])
        .expect_err("a username-only `from` must be refused");

        // The duplicate `from` refusal below renders the same way, but nothing
        // can reach it carrying a secret: a `from` with a query or with
        // credentials is refused before the dedup runs. Its rendering is
        // defensive, and the reachable case of the same shape is the
        // visibility list, which has no such guard — see
        // `a_visible_rule_carrying_credentials_is_refused`.

        // The honest cases. A `to` names the backend the rewrite reaches, so
        // its credentials are the ones the operator meant to send.
        validate_alias_rules(&[(
            url("alias:///reports/"),
            url("https://writer:token@origin.invalid/reports/"),
        )])
        .expect("credentials on `to` are the backend's own and must still load");
        validate_alias_rules(&[(url("alias:///reports/"), url("s3://b/reports/"))])
            .expect("an alias with no credentials anywhere must still load");
    }

    /// A chain diagnostic names the address without its query.
    ///
    /// Unlike the load-time refusals, `walk_chain`'s two errors render a
    /// **caller's** dispatch address, so the query is caller-controlled and
    /// reaches whatever sink receives the error. `Error`'s redactor scrubs only
    /// the provider parameter names it knows, and `api_key` is not one.
    #[test]
    fn a_chain_diagnostic_does_not_echo_the_callers_query() {
        let rules = vec![
            (url("alias:///a/"), url("alias:///b/")),
            (url("alias:///b/"), url("alias:///a/")),
        ];
        let error = match walk_chain(&rules, &url("alias:///a/x?api_key=supersecret"), |_| None) {
            Ok(resolved) => panic!(
                "a two-rule cycle must not resolve, got {}",
                resolved.address
            ),
            Err(error) => error,
        };
        assert_eq!(error.code(), ErrorCode::AliasChainTooLong);
        assert!(
            !error.message().contains("supersecret"),
            "the chain diagnostic leaked the caller's query: {}",
            error.message()
        );
        assert!(
            error.message().contains("alias:///a/x"),
            "and it must still name the address that could not resolve: {}",
            error.message()
        );
    }

    /// An authority-less alias rule does not load, and is refused before
    /// anything renders it.
    ///
    /// The TOML loader cannot produce one — it parses through `address::parse`,
    /// which refuses the class — but `AliasWrapperFactory::with_rules` reaches
    /// validation through bare `canonicalize`, which does not. For such a URL
    /// the whole post-scheme payload is the `path()`, so rendering it through
    /// `RedactedUrl` would print the credential it exists to hide.
    #[test]
    fn an_authority_less_alias_rule_is_refused_without_rendering_it() {
        for (from, to) in [
            ("urn:reader:tok,en@x/p", "s3://b/p/"),
            ("alias:///p/", "urn:reader:tok,en@x/p"),
        ] {
            let error =
                validate_alias_rules(&[(Url::parse(from).unwrap(), Url::parse(to).unwrap())])
                    .expect_err("an authority-less rule must be refused");
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
            assert!(
                !error.message().contains("tok,en"),
                "the refusal leaked the payload: {}",
                error.message()
            );
            assert!(
                error.message().contains("authority"),
                "and it must say what is wrong: {}",
                error.message()
            );
        }
    }

    /// A `Visible` visibility rule carrying credentials does not load; a
    /// `Hidden` one does.
    ///
    /// The rank ignores userinfo, so a credential-bearing rule covers its path
    /// for every credential rather than the one written. For `Visible` that
    /// widening publishes addresses a live rule did not publish before, which
    /// is the direction that cannot be taken back — the same asymmetry the
    /// authz policy loader draws between an allow and a deny. A widened
    /// `Hidden` or `Suppressed` rule hides more than it was written to, so it
    /// loads unchanged and the test says so.
    #[test]
    fn a_visible_rule_carrying_credentials_is_refused() {
        let error = validate_visibility_rules(&[(
            url("https://reader:tok,en@origin.invalid/team/"),
            AddressVisibility::Visible,
        )])
        .expect_err("a credential-bearing visible rule must be refused");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            !error.message().contains("tok,en"),
            "the refusal leaked the credential: {}",
            error.message()
        );

        // The safe direction, and an ordinary rule, both still load.
        validate_visibility_rules(&[(
            url("https://reader:token@origin.invalid/team/"),
            AddressVisibility::Hidden,
        )])
        .expect("hiding more than the rule was written to is the safe direction");
        validate_visibility_rules(&[(
            url("https://origin.invalid/team/"),
            AddressVisibility::Visible,
        )])
        .expect("a visible rule with no credentials is unaffected");

        // The duplicate refusal is reachable with a credential, because the
        // guard above lets the hiding directions through.
        let duplicate = validate_visibility_rules(&[
            (
                url("https://reader:tok,en@origin.invalid/team/"),
                AddressVisibility::Hidden,
            ),
            (
                url("https://reader:tok,en@origin.invalid/team"),
                AddressVisibility::Suppressed,
            ),
        ])
        .expect_err("two spellings of one visibility scope must be refused");
        assert!(
            !duplicate.message().contains("tok,en"),
            "the duplicate refusal leaked the credential: {}",
            duplicate.message()
        );
    }

    /// No alias or visibility load diagnostic echoes the configured string.
    ///
    /// `address::parse` refuses an authority-less URL and deliberately
    /// withholds the opaque payload, because for a cannot-be-a-base URL
    /// everything after the scheme is one opaque string with the userinfo
    /// inside it, which `Error`'s redactor cannot normalize. `parse_url`
    /// wrapped that safe message in one that interpolated the raw text, which
    /// put the payload back.
    ///
    /// The rows are chosen to reach BOTH arms of `parse_url`'s error path —
    /// the authority-less refusal and a plain parse failure — because both
    /// wrapped the same way. A credential-bearing prefix with an authority
    /// never gets here: it parses, and `validate_alias_rules` refuses it by
    /// the credential rule with its own redacted rendering.
    ///
    /// The identical test on the authorization policy loader
    /// (`no_load_diagnostic_echoes_a_credential`) already carries the
    /// `s3:reader:hunter2@h/x` row. This loader is the adopter that did not
    /// get it.
    #[test]
    fn no_config_diagnostic_echoes_a_credential() {
        for text in [
            // Authority-less: the payload is opaque, userinfo included.
            "s3:reader:hunter2@h/x",
            "mailto:reader:hunter2@h/x",
            // Unparseable for a reason that has nothing to do with the
            // credential, so the raw string reaches the other arm.
            "s3://reader:hunter2@h:notaport/x",
        ] {
            for key in ["from", "to", "address"] {
                let error =
                    super::parse_url(text, key).expect_err("these prefixes must all be refused");
                assert_eq!(error.code(), ErrorCode::InvalidArgument);
                assert!(
                    !error.message().contains("hunter2"),
                    "`{key}` diagnostic leaked the credential in {text}: {}",
                    error.message()
                );
                assert!(
                    error.message().contains(key),
                    "the diagnostic must still name the config key: {}",
                    error.message()
                );
            }
        }
    }

    /// The query refusal names the rule without echoing the query.
    ///
    /// The rule fires exactly when a query is present, and a query is where a
    /// SAS signature or an API key lives. `Error`'s redactor scrubs only the
    /// provider parameter names it knows, so an unrecognized one would be
    /// returned verbatim to whatever sink receives a startup failure.
    ///
    /// Asserted on both sides, because the two messages are produced by one
    /// `format!` and a `side`-dependent rendering would be the way one of them
    /// started leaking.
    #[test]
    fn the_query_refusal_does_not_echo_the_query() {
        for (from, to) in [
            ("alias:///team/?api_key=supersecret", "s3://b/team/"),
            ("alias:///team/", "s3://b/team/?api_key=supersecret"),
        ] {
            let error = validate_alias_rules(&[(url(from), url(to))])
                .expect_err("a query on either side must be refused");
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
            assert!(
                !error.message().contains("supersecret"),
                "the refusal leaked the query value: {}",
                error.message()
            );
            // Still locatable: the message names the scope the rule is on.
            assert!(
                error.message().contains("/team/"),
                "the refusal must still name the rule: {}",
                error.message()
            );
        }
    }

    #[test]
    fn two_spellings_of_one_visibility_scope_fail_to_load() {
        for (first, second) in [
            ("alias:///team", "alias:///team/"),
            ("alias:///team/", "alias:///team"),
        ] {
            let rules = vec![
                (url(first), AddressVisibility::Hidden),
                (url(second), AddressVisibility::Visible),
            ];
            let error = validate_visibility_rules(&rules)
                .expect_err("two spellings of one visibility scope must be refused");
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
        }

        validate_visibility_rules(&[
            (url("alias:///team/"), AddressVisibility::Hidden),
            (url("alias:///other/"), AddressVisibility::Visible),
        ])
        .unwrap();
    }

    /// Rank on depth, not on how the scope was spelled — asserted as an
    /// **outcome**.
    ///
    /// The previous version called `node_segment_count` on two URLs and
    /// asserted `2 > 1`. That could not fail: canonicalization erases the
    /// premise (`alias:///%74eam/` becomes `alias:///team/`, 14 bytes against
    /// the 22 the test was reasoning about), and neither
    /// `longest_matching_rule` nor `visibility_of_in` was ever called, so
    /// reverting the ranking to `as_str().len()` left it green.
    ///
    /// Finding a real disagreement needs care, because nesting normally makes
    /// the two metrics agree — a covering ancestor is usually the shorter
    /// string. Two rules that both cover one address share a scheme and an
    /// authority and nest by path, so without userinfo the deeper rule is
    /// always the longer string. **Userinfo is the only lever**:
    /// `is_ancestor_or_self` ignores it, so a shallow rule can carry
    /// credentials and be far LONGER than a deep one that also covers the
    /// address. Here the shallow `omniverse://longuser:pw@h/team` is 30 bytes
    /// at depth 1 and the deep `omniverse://h/team/reports` is 26 at depth 2,
    /// so byte length and depth select opposite rules.
    ///
    /// That same property is why `validate_alias_rules` refuses a
    /// credential-bearing `from`, so this rule set is not installable and the
    /// ranking is asserted against `longest_matching_rule` directly. Both
    /// facts are asserted here, beside each other, so neither can be changed
    /// while leaving the other's rationale standing.
    ///
    /// A trailing-slash pair is deliberately not used instead: it ties on
    /// depth and falls through to declaration order, so the assertion would
    /// pin `max_by_key`'s last-maximum rather than the metric, and
    /// `node_rank`'s own doc says the tie-break is the caller's choice.
    #[test]
    fn a_deeper_scope_outranks_a_longer_spelling_of_a_shallower_one() {
        let shallow = url("omniverse://longuser:pw@h/team");
        let deep = url("omniverse://h/team/reports");
        let addr = url("omniverse://h/team/reports/q3.usd");
        assert!(
            shallow.as_str().len() > deep.as_str().len(),
            "the shallower rule must be the LONGER string, or byte length would not misrank it"
        );
        assert!(
            address::node_segment_count(&deep) > address::node_segment_count(&shallow),
            "and the deeper rule must genuinely be deeper"
        );

        let rules = vec![
            (shallow.clone(), url("backend:///shallow/")),
            (deep.clone(), url("backend:///deep/")),
        ];
        let refusal = validate_alias_rules(&rules)
            .expect_err("the credential the fixture needs is what the loader refuses");
        assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
        assert!(
            refusal.message().contains("credentials"),
            "and it must be refused for the credential, not for something else: {}",
            refusal.message()
        );
        let (from, _) = longest_matching_rule(&rules, &addr).expect("a rule covers the address");
        assert_eq!(
            from.as_str(),
            deep.as_str(),
            "depth must decide, not byte length"
        );

        // Reversing the declaration order must not change the answer — the
        // point is the metric, not the tie-break.
        let reversed = vec![
            (deep.clone(), url("backend:///deep/")),
            (shallow.clone(), url("backend:///shallow/")),
        ];
        let (from, _) = longest_matching_rule(&reversed, &addr).expect("a rule covers the address");
        assert_eq!(
            from.as_str(),
            deep.as_str(),
            "the metric is order-independent"
        );

        // Visibility ranks on the same metric, through a different call path.
        let visibility = vec![
            (shallow, AddressVisibility::Hidden),
            (deep, AddressVisibility::Visible),
        ];
        assert_eq!(
            visibility_of_in(&visibility, &addr),
            AddressVisibility::Visible,
            "the deeper rule decides visibility too"
        );
    }

    /// Selection and termination must rank on the SAME scale.
    ///
    /// A real root published as `omniverse://h/team` and an alias rule
    /// `from = omniverse://h/team/` name one node, so the real route owns the
    /// address and must interrupt the chain. Under the mixed scales that
    /// shipped — `node_rank` to select, `as_str().len()` to terminate —
    /// `17 >= 18` was false, the alias applied, and the request was rewritten
    /// away from the backend that owns it. Reversing the two slash spellings
    /// reversed the outcome, which is the tell.
    #[test]
    fn a_real_root_interrupts_an_alias_that_differs_only_by_a_slash() {
        let root = url("omniverse://h/team");
        let rules = vec![(url("omniverse://h/team/"), url("backend:///elsewhere/"))];
        assert!(
            root.as_str().len() < rules[0].0.as_str().len(),
            "the root must be the SHORTER spelling, or byte length would not misrank it"
        );

        let resolved = walk_chain(&rules, &url("omniverse://h/team/report.usd"), |_| {
            Some(Specificity::of(&root))
        })
        .expect("the walk terminates");
        assert!(
            resolved.hops.is_empty(),
            "the covering real root must interrupt the chain, but the alias applied and \
             rewrote the address to {}",
            resolved.address
        );
    }
}

/// The standalone visibility overrides as scope pairs.
///
/// Deliberately NOT `RuleSet::visibility_pairs`, which also folds in each alias
/// rule's intrinsic visibility. An alias `from` and a standalone override
/// naming the same scope is a documented, tolerated tie; two standalone
/// overrides naming that scope are the ambiguity `validate_visibility_rules`
/// rejects, and they are what a runtime add can introduce.
fn standalone_visibility_pairs(rules: &[VisibilityOverride]) -> Vec<(Url, AddressVisibility)> {
    rules
        .iter()
        .map(|rule| (rule.address.clone(), rule.visibility))
        .collect()
}
