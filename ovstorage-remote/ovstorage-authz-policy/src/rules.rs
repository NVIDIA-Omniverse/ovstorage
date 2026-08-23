// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The TOML rule set and matching engine. A [`Policy`] is an ordered list of
//! rules; [`Policy::evaluate`] picks the most specific matching rule (longest
//! address prefix, then latest declaration) and yields its effect.
//!
//! Matching is on **`principal id` glob + operation + address prefix only** —
//! attributes, epoch, and audit id are never read here (that is the built-in
//! policy's deliberate shape). The policy engine is infallible at decision time
//! (a miss denies); only parsing/validation can fail.

use std::time::Duration;

use ovstorage_plugin::{Error, ErrorCode, Result, Url, address};
use serde::Deserialize;

use crate::{Operation, operation_from_name, operation_name};

/// Parsed rule effect. Mirrors the TOML `effect` field.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Effect {
    Allow,
    Deny,
}

/// Outcome of evaluating a [`Policy`] for one (principal, operation, address).
/// `reason` is populated on deny (the message the caller maps to
/// `PermissionDenied`); `explanation` carries the winning rule id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub allow: bool,
    pub reason: Option<String>,
    pub explanation: Option<String>,
}

impl Decision {
    fn allow_with_explanation(explanation: impl Into<String>) -> Self {
        Self {
            allow: true,
            reason: None,
            explanation: Some(explanation.into()),
        }
    }

    fn deny(reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            reason: Some(reason.into()),
            explanation: None,
        }
    }

    fn deny_with_explanation(reason: impl Into<String>, explanation: impl Into<String>) -> Self {
        Self {
            allow: false,
            reason: Some(reason.into()),
            explanation: Some(explanation.into()),
        }
    }

    pub fn is_allow(&self) -> bool {
        self.allow
    }
}

/// TOML deserialization shape for a policy document. Matches the first-party
/// plugin's config (`plugin`, `decision_ttl_max_seconds`, `[[policy]]`). The
/// concrete `[ovstorage.layers.authz.*]` layer-config schema belongs to the
/// stack config; this is the value the auth Layer factory parses today.
#[derive(Clone, Debug, Deserialize)]
pub struct TomlPolicyConfig {
    #[serde(default = "default_plugin_name")]
    pub plugin: String,
    #[serde(default)]
    pub decision_ttl_max_seconds: Option<u64>,
    /// Acknowledges that a percent-escape in a policy prefix names the
    /// **decoded** key.
    ///
    /// Setting this asserts something specific: *I have re-read every rule
    /// whose prefix carries an escape, compared it against the scope it now
    /// resolves to, and accept that scope.* It is not a compatibility switch —
    /// it changes no behaviour, and the rules mean the decoded thing either
    /// way. It only records that a human looked. Document-level rather than
    /// per-rule because the mechanism is understood once, not per rule.
    ///
    /// Required before a policy whose prefixes have moved will load. A prefix
    /// moved when its SERIALIZED form carries a percent-escape, which includes
    /// prefixes written without one — `s3://b/pub x` serializes to
    /// `s3://b/pub%20x`, so it named `pub%20x` and now names `pub x`.
    #[serde(default)]
    pub prefix_escapes_are_decoded: bool,
    #[serde(default)]
    pub policy: Vec<TomlPolicyRule>,
}

impl Default for TomlPolicyConfig {
    fn default() -> Self {
        Self {
            plugin: default_plugin_name(),
            decision_ttl_max_seconds: None,
            prefix_escapes_are_decoded: false,
            policy: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TomlPolicyRule {
    #[serde(default)]
    pub id: Option<String>,
    pub effect: TomlPolicyEffect,
    pub principal: String,
    pub operations: Vec<String>,
    pub prefix: String,
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TomlPolicyEffect {
    Allow,
    Deny,
}

/// An ordered rule set. Built from a validated [`TomlPolicyConfig`]; evaluation
/// is pure and infallible (a non-match denies).
#[derive(Clone, Debug)]
pub struct Policy {
    rules: Vec<Rule>,
    decision_ttl: Option<Duration>,
}

#[derive(Clone, Debug)]
struct Rule {
    id: String,
    effect: Effect,
    principal: String,
    operations: Option<Vec<Operation>>,
    prefix: Option<Url>,
    /// The prefix **exactly as the operator wrote it**, before `parse_prefix`
    /// canonicalized it.
    ///
    /// Kept for one purpose: deciding whether two rules are the *same spelling*
    /// rather than the same scope. `reject_co_matching_equal_scopes` exempts a
    /// byte-identical duplicate because writing one prefix twice is how a later
    /// rule deliberately supersedes an earlier one — and "wrote it twice" is a
    /// fact about the config text, not about what the text resolves to.
    /// Canonicalization erases the difference between `s3://b/private/` and
    /// `s3://b/%70rivate/`, so keying that exemption on the parsed `Url` handed
    /// the exemption to pairs the operator never wrote as duplicates.
    prefix_written: Option<String>,
    order: usize,
}

impl Policy {
    /// Parses a TOML config string into a policy in one step.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — the TOML is malformed, or any of the
    ///   conditions listed on [`Policy::from_config`], which this delegates to.
    /// - [`ErrorCode::Unsupported`] — the policy names an unsupported plugin
    ///   kind.
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let config: TomlPolicyConfig = toml::from_str(toml_str).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid authz policy config: {err}"),
            )
        })?;
        Self::from_config(config)
    }

    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — a rule is individually invalid, or two
    ///   rules are ambiguous together. Individually: an empty or
    ///   whitespace-only id; an empty principal; an empty operation list; an
    ///   unknown operation name, or `"*"` alongside another; or a prefix that
    ///   is empty, unparseable, or refused by one of the scope guards
    ///   (whitespace the URL parser strips, a query, a
    ///   fragment, a `\` acting as a separator, a dot or interior-empty
    ///   segment, an escaped separator), or that is an **allow** carrying
    ///   credentials. Together: two rules whose prefixes are written
    ///   differently but resolve to one scope and can decide one request, or a
    ///   document with an escape-bearing prefix and no
    ///   `prefix_escapes_are_decoded` acknowledgement.
    /// - [`ErrorCode::Unsupported`] — the policy names an unsupported plugin
    ///   kind.
    pub fn from_config(config: TomlPolicyConfig) -> Result<Self> {
        if config.plugin != crate::AUTHZ_POLICY_KIND_TOML {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "unsupported authz policy '{}'; expected '{}'",
                    config.plugin,
                    crate::AUTHZ_POLICY_KIND_TOML
                ),
            ));
        }
        let escape_gate: Vec<(String, String)> = config
            .policy
            .iter()
            .enumerate()
            .map(|(index, policy)| {
                (
                    policy
                        .id
                        .clone()
                        .unwrap_or_else(|| format!("rule-{}", index + 1)),
                    policy.prefix.clone(),
                )
            })
            .collect();
        let acknowledged = config.prefix_escapes_are_decoded;
        let mut rules = Vec::with_capacity(config.policy.len());
        for (index, policy) in config.policy.into_iter().enumerate() {
            let id = policy.id.unwrap_or_else(|| format!("rule-{}", index + 1));
            if id.trim().is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "authz policy rule id must not be empty",
                ));
            }
            if policy.principal.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("authz policy rule '{id}' principal must not be empty"),
                ));
            }
            if policy.operations.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("authz policy rule '{id}' operations must not be empty"),
                ));
            }
            let operations = parse_operations(&id, policy.operations)?;
            let prefix = parse_prefix(&id, &policy.prefix)?;
            let prefix_written = prefix.is_some().then(|| policy.prefix.clone());
            let effect = match policy.effect {
                TomlPolicyEffect::Allow => Effect::Allow,
                TomlPolicyEffect::Deny => Effect::Deny,
            };
            // An ALLOW whose prefix carries credentials is refused, because
            // dropping userinfo from the comparison WIDENS it and the widening
            // is silent.
            //
            // Userinfo is not part of a scope — the matcher compares scheme,
            // host, port and path — so `allow https://readonly:token@h/reports/`
            // covers `https://admin:password@h/reports/payroll`. The previous
            // serialized matcher compared the whole string, so it did not:
            // measured, `is_prefix_of` returns false for that pair because the
            // address does not start with the prefix. A live allow therefore
            // gains reach across the upgrade with nothing said, which is the
            // same class the escape-retargeting gate refuses and the same
            // permissive direction.
            //
            // **Only allows.** Ignoring userinfo makes a DENY cover addresses
            // it did not cover before, which is the safe direction and needs no
            // acknowledgement — the same asymmetry the case fold already uses.
            //
            // The rewrite is to delete the credentials: they were never
            // consulted for authorization, and `root_url` keeps its own so the
            // wire is unchanged.
            if matches!(effect, Effect::Allow)
                && let Some(url) = &prefix
                && (!url.username().is_empty() || url.password().is_some())
            {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "authz policy rule '{id}' is an allow whose prefix carries credentials. \
                         Userinfo is not part of a scope, so this rule covers its path for \
                         EVERY credential rather than the one written — on 0.2.0 the matcher \
                         compared the credential too, so this is a widening of a live rule. \
                         Write the prefix without the credentials to accept that scope, or \
                         narrow the rule by path or principal instead"
                    ),
                ));
            }
            rules.push(Rule {
                id,
                effect,
                principal: policy.principal,
                operations,
                prefix,
                prefix_written,
                order: index,
            });
        }
        // AFTER the per-rule parse loop, and the ordering is LOAD-BEARING, not
        // just a matter of message quality.
        //
        // `parse_prefix` rejects a query, a fragment, a dot segment and an
        // escaped separator with diagnostics that name the actual problem, and
        // running this first would preempt them with a vaguer one. But it also
        // covers the one family this gate's predicate misses: an empty segment
        // moves the scope (`s3://b/a//b` scoped `a//b` and now scopes `a/b`)
        // while carrying no `%xx`, so the gate is silent on it. Every such
        // prefix is refused by the empty-segment check above.
        //
        // If that check is ever relaxed — its own comment already exempts a
        // TRAILING empty segment deliberately — `s3://b/a//` becomes a silent
        // retargeting with nothing left to catch it. Widen this predicate then.
        reject_unacknowledged_escaped_prefixes(&escape_gate, acknowledged)?;
        reject_co_matching_equal_scopes(&rules, HOST_FOLDS_FILE_PATHS)?;
        Ok(Self {
            rules,
            decision_ttl: config.decision_ttl_max_seconds.map(Duration::from_secs),
        })
    }

    /// The `decision_ttl_max_seconds` config value, if set. Retained for config
    /// fidelity — there is no decision cache, so it is not consumed by any
    /// decision.
    pub fn decision_ttl(&self) -> Option<Duration> {
        self.decision_ttl
    }

    /// Evaluate the policy for one `(principal_id, operation, address)`. Picks
    /// the most specific matching rule (longest prefix, then latest declared)
    /// and returns its effect; a non-match denies.
    pub fn evaluate(
        &self,
        principal_id: &str,
        operation: Operation,
        address: Option<&Url>,
    ) -> Decision {
        let op_name = operation_name(operation);
        let Some(rule) = self.matching_rule(principal_id, operation, address) else {
            tracing::debug!(
                target: "ovstorage.authz.policy",
                op = op_name,
                principal_id,
                outcome = "deny",
                "authz decision: no matching rule"
            );
            return Decision::deny("no matching authz policy rule");
        };
        match rule.effect {
            Effect::Allow => {
                tracing::debug!(
                    target: "ovstorage.authz.policy",
                    op = op_name,
                    principal_id,
                    rule_id = %rule.id,
                    outcome = "allow",
                    "authz decision"
                );
                Decision::allow_with_explanation(rule.id.clone())
            }
            Effect::Deny => {
                tracing::debug!(
                    target: "ovstorage.authz.policy",
                    op = op_name,
                    principal_id,
                    rule_id = %rule.id,
                    outcome = "deny",
                    "authz decision"
                );
                Decision::deny_with_explanation(
                    format!("authorization denied by policy '{}'", rule.id),
                    rule.id.clone(),
                )
            }
        }
    }

    /// Convenience predicate: `true` when [`Policy::evaluate`] allows.
    pub fn is_allowed(
        &self,
        principal_id: &str,
        operation: Operation,
        address: Option<&Url>,
    ) -> bool {
        self.evaluate(principal_id, operation, address).is_allow()
    }

    /// The most specific matching rule, evaluated against the **canonical**
    /// spelling of `address`.
    ///
    /// Canonicalization belongs here rather than at the callers because this is
    /// the one point every evaluation converges on. `evaluate` and `is_allowed`
    /// both route through it, and so therefore do the post-filters that call
    /// `is_allowed` directly — `filter_list_batch` over a listing page,
    /// `is_root_visible` for route visibility, `apply_authz_access_decision`
    /// for a `check_access` verdict, and the per-event `watch_directory`
    /// filter. Each of those is a separate call site that would otherwise have
    /// to remember, and one that forgot would let a spelling the matcher reads
    /// differently past a rule: the gate would deny `…/private%2F..%2Fpublic`
    /// while a listing filter judged the raw form and vice versa, so one
    /// principal could see a root through `list_address_roots` that
    /// `root_info_for` reports as absent.
    ///
    /// The matcher compares decoded path components, so it needs an address
    /// whose dot segments and empty segments are already resolved; the scope
    /// side is canonicalized once at load by `parse_prefix`.
    fn matching_rule(
        &self,
        principal_id: &str,
        operation: Operation,
        address: Option<&Url>,
    ) -> Option<&Rule> {
        let canonical = address.map(|url| address::canonicalize(url.clone()));
        let address = canonical.as_ref();
        self.rules
            .iter()
            .filter(|rule| rule.matches(principal_id, operation, address))
            .max_by_key(|rule| (rule.prefix.is_some(), rule.prefix_segments(), rule.order))
    }
}

impl Rule {
    fn matches(&self, principal_id: &str, operation: Operation, address: Option<&Url>) -> bool {
        if !glob_match(&self.principal, principal_id) {
            return false;
        }
        if let Some(operations) = &self.operations
            && !operations.contains(&operation)
        {
            return false;
        }
        match (&self.prefix, address) {
            (None, _) => true,
            (Some(prefix), Some(address)) => scope_covers(prefix, address, self.effect),
            (Some(_), None) => false,
        }
    }

    /// Rank by how many path segments the prefix pins, not by how many bytes it
    /// spells. Byte length is spelling-dependent: `file:/root/%70rivate/` is
    /// longer than `file:/root/private/` and names the same scope, so an
    /// encoded **allow** would outrank a plain **deny** regardless of
    /// declaration order. Canonicalization removes that particular spelling,
    /// but ranking on the derived value is correct whoever normalized what.
    fn prefix_segments(&self) -> usize {
        self.prefix.as_ref().map_or(0, |prefix| {
            scope_segments(prefix).map_or(0, |segments| segments.len())
        })
    }
}

/// True when the rule scope `prefix` covers `address`.
///
/// Authorization matches on **components**, not on the serialized string, and
/// on a different set of them than routing uses:
///
/// - **scheme** exact. `Url::parse` has already lowercased it.
/// - **host and port** exact. **Userinfo is ignored** — it is parsed and
///   carried but never consulted, here or anywhere else. A policy prefix scopes
///   *addresses*; ovstorage authorizes *principals*, and a credential written
///   into a prefix confers no protection.
/// - **path** segment-wise, so `…/foo` does not cover `…/foobar`. This is not a
///   change: the previous serialized matcher required the byte after the
///   prefix to be `/`, `?` or `#`, so it refused that pair too. What differs is
///   that the components are compared decoded rather than as serialized bytes,
///   and every prefix whose serialized form carries an escape is refused until
///   acknowledged.
/// - **query** not at all. A rule that matches a path matches every version pin
///   of it, which makes authorization strictly coarser than node identity —
///   it can cover more objects than a pin-aware rule would, never fewer.
fn scope_covers(prefix: &Url, address: &Url, effect: Effect) -> bool {
    if prefix.scheme() != address.scheme()
        || prefix.host() != address.host()
        || prefix.port() != address.port()
    {
        return false;
    }
    covers_with_host_semantics(prefix, address, HOST_FOLDS_FILE_PATHS, effect)
}

/// **Case folding widens a deny and never an allow, and that asymmetry is the
/// only defensible choice here.** Neither ASCII nor Rust's Unicode folding is
/// NTFS's `$UpCase` table, so either alone loses on one side:
///
/// - Folding with full Unicode over-grants an **allow**: `str::to_lowercase`
///   maps U+212A KELVIN SIGN to `k`, so a rule for `…/k/` would grant a
///   distinct file the operator never named.
/// - Folding only ASCII under-covers a **deny**: `é` and `É` are one directory
///   on a case-insensitive volume, so a deny written for one misses the other
///   while the file opens.
///
/// Both are real and they pull opposite ways, so the resolution is the one this
/// design already states for case folding generally: fold to make a deny match
/// *more*, never to make an allow match more. A deny therefore folds with full
/// Unicode — over-denying is safe, and `str::to_lowercase` equating U+212A with
/// `k` is a *feature* on the deny side, since NTFS's uppercase table equates
/// them too. **An allow does not fold at all**, not even ASCII: any fold on
/// that side grants a name the operator did not write, and the worst case of
/// not folding is refusing a spelling they can write out.
///
/// **The trailing-slash collapse below is deliberately NOT effect-aware, and
/// the contrast with `widen` is a decision rather than an oversight.** It is
/// also the most-argued line in this file, flagged independently by two
/// reviewers, so the reasoning is written out — including the part that does
/// not work.
///
/// The observation is correct and is a real widening: an allow scoped
/// `s3://bucket/team/` covers the slashless `team`, which the old
/// serialized-prefix matcher did not, and on a flat store those can be two
/// objects with different bytes. **Do not "fix" this by making the collapse
/// effect-aware without changing the address model first**, because the two
/// are the same decision:
///
/// - **It is the premise of the model, not a consequence of this matcher.** An
///   address names a node; `x` and `x/` are one node; whether that node is a
///   file or a directory is `ObjectKind`, never the spelling. Every comparison
///   site in the tree was made node-aware on that basis. An effect-aware
///   collapse would leave authorization as the single place where the spelling
///   still decides — and a rule set whose meaning depends on which of two
///   spellings of one node the operator happened to type is the class of defect
///   this work exists to remove.
/// - **The case asymmetry above answers a different question.** It resolves a
///   disagreement *between hosts* about what a case table is, where there is no
///   correct answer and the design takes the safe half of each. Every host
///   agrees the trailing slash is not part of identity, so there is nothing to
///   split.
/// - **The distinction is preserved everywhere it decides an object** — in
///   `relative_suffix`, so an alias projection stays transparent, and on
///   emission, which adds a separator and never removes one. It is refused only
///   where it would decide *who may reach* an object.
///
/// **The argument that does NOT hold**, recorded so it is not made again: that
/// an effect-aware collapse would reintroduce a spelling-dependent bypass. It
/// would not. A deny covering both spellings beside an allow covering one is
/// the conservative pairing, and its failure mode is refusing a caller who
/// spelled a permitted node the other way — over-denial, which is the safe
/// direction. The honest statement is that this is a *widening* justified by
/// the node model, not by a safety argument: "authorization may be coarser than
/// node identity" is true of a deny and is not, on its own, an argument for an
/// allow.
///
/// So the cost is real and bounded: an operator who writes `allow …/team/` on a
/// flat store also grants the distinct object `…/team`. The judgement is that
/// one address model applied everywhere is worth more than that, and it is a
/// design decision rather than a matcher detail — which is why changing it
/// belongs upstream of this function.
fn covers_with_host_semantics(prefix: &Url, address: &Url, fold: bool, effect: Effect) -> bool {
    let widen = matches!(effect, Effect::Deny);
    let (Some(scope), Some(target)) = (
        segments_with_host_semantics_widened(prefix, fold, widen),
        segments_with_host_semantics_widened(address, fold, widen),
    ) else {
        return false;
    };
    scope.len() <= target.len() && scope.iter().zip(&target).all(|(a, b)| a == b)
}

/// The path as decoded segments, with one trailing empty segment dropped so a
/// rule written `…/private/` covers the node `…/private` as well as its
/// children.
///
/// Decoding matters and stays: a canonical path still carries escapes for
/// controls, space and the rest of the canonical set, and the backend decodes
/// those to get its key. A matcher comparing `pub%20x` against a backend using
/// `pub x` would diverge. What canonicalization removed is the
/// *security-sensitive* part of this decode — nothing here can manufacture a
/// separator or a dot segment, because those are already resolved.
fn scope_segments(url: &Url) -> Option<Vec<Vec<u8>>> {
    segments_with_host_semantics(url, HOST_FOLDS_FILE_PATHS)
}

/// Whether the running host treats `\` as a path separator and file paths as
/// case-insensitive.
///
/// This is the only host-dependent value in the design, and it is a `cfg`
/// rather than a runtime probe because it describes the platform that will
/// resolve the path. `canonicalize` must never vary by host — an address has to
/// mean the same thing everywhere, or a value cached, persisted or sent over
/// the wire changes meaning when it moves between machines. Authorization is
/// the one consumer whose correctness depends on the local filesystem, and the
/// host that resolves a path is the host that matches it: every host composes
/// its own stack including its own authz layer, so a Windows machine serving
/// files evaluates the policy in a Windows process.
///
/// **Windows is named because it is the shipped platform that folds.** The
/// release targets are Linux x86_64, Linux aarch64 and Windows x86_64. A
/// case-insensitive volume elsewhere — an APFS default on macOS, a mounted
/// share — resolves two spellings to one file while the matcher keeps them
/// apart, so a deny written on one spelling is not applied to the other. That
/// is the *finer than the backend* direction, and it is unmodelled here rather
/// than accidentally handled: adding a platform to this constant would also
/// make `\` a separator there, which it is not.
const HOST_FOLDS_FILE_PATHS: bool = cfg!(windows);

/// The segment derivation, with the host behaviour passed in.
///
/// **The parameter exists so the Windows rule is testable off Windows**, and
/// that is not a stylistic preference. This repo's Windows CI leg runs only
/// `ovstorage-c-source-cc-test` and the Python bindings, so a `#[cfg(windows)]`
/// test in this crate would execute on no machine at all — indistinguishable
/// from having written no test. Passing the flag means the rule that closes a
/// deny bypass is exercised on every CI leg, and only the one-line binding of
/// [`HOST_FOLDS_FILE_PATHS`] goes uncovered.
///
/// **Folding runs before normalization, not after, and that ordering is the
/// whole correctness argument.** Turning `\` into a separator *creates* path
/// structure: `public\..\private` becomes three segments of which one is a dot
/// segment, and `private\\x` gains an empty one. Splitting on `\` and comparing
/// the pieces leaves both unresolved, so a deny written for `…/private/` misses
/// a request that Windows resolves straight into it. Rewriting the separator
/// and then running the *same* normalization the canonical form uses is what
/// makes the folded path comparable to the prefix.
fn segments_with_host_semantics(url: &Url, fold: bool) -> Option<Vec<Vec<u8>>> {
    segments_with_host_semantics_widened(url, fold, false)
}

fn segments_with_host_semantics_widened(
    url: &Url,
    fold: bool,
    widen: bool,
) -> Option<Vec<Vec<u8>>> {
    let fold_this = fold && url.scheme() == "file";

    // Rebuild the decoded path. A decoded segment cannot contain `/`: the
    // canonical form leaves `/` structural and never escapes it, so a `%2F` has
    // already become a real separator by the time an address reaches here.
    // Joining is therefore lossless.
    //
    // Bytes, not `String`. A key is an arbitrary byte sequence and the backends
    // resolve it byte for byte, so a matcher that decoded to text would be
    // coarser than the thing it guards: `x%FF` and `x%FE` are two files, and an
    // allow naming one would grant the other.
    let mut path: Vec<u8> = Vec::new();
    for (index, segment) in url.path_segments()?.enumerate() {
        if index > 0 {
            path.push(b'/');
        }
        path.extend_from_slice(&address::decode_segment(segment));
    }

    if fold_this {
        for byte in &mut path {
            if *byte == b'\\' {
                *byte = b'/';
            }
        }
        // Normalize where WINDOWS clamps, which is the drive — not the path
        // root, and not the relative start `path_segments()` leaves behind.
        //
        // `file:///C:/root/a%5C..%5C..%5C..%5Csecret.txt` survives
        // `canonicalize` intact (it escapes `\` and sees no `/../`) and folds to
        // `C:/root/a/../../../secret.txt`. Windows resolves that to
        // `C:\secret.txt` — the drive letter is a volume, and `..` at the volume
        // root stays there. RFC 3986 §5.2.4 does not know that: to it `C:` is an
        // ordinary segment, so the third `..` pops it and the matcher sees
        // `["secret.txt"]` while the OS opens `["c:","secret.txt"]`. A
        // `deny file:///C:/secret.txt` would miss.
        //
        // Prepending a separator is not enough on its own — the clamp then
        // lands at `/`, one component BELOW the drive, and `C:` is still popped.
        // So the drive segment is held out of normalization and re-attached.
        // Without a drive the leading separator alone is right, and matches
        // POSIX.
        // Locate the drive AFTER any stranded leading separator, which the `\`
        // rewrite can produce (`file:///%5Cc:/x`). The strip below would remove
        // it anyway, but it happens too late to be doing it here: a drive at
        // index 1 is invisible to `is_drive_segment`, and the two spellings —
        // which this matcher calls equal everywhere else — would clamp
        // differently.
        let path_from_root = path.strip_prefix(b"/").unwrap_or(&path);
        let (drive, rest) = match path_from_root.iter().position(|byte| *byte == b'/') {
            Some(separator) if is_drive_segment(&path_from_root[..separator]) => {
                path_from_root.split_at(separator)
            }
            None if is_drive_segment(path_from_root) => (path_from_root, &[][..]),
            _ => (&[][..], path_from_root),
        };
        let mut absolute = Vec::with_capacity(rest.len() + 1);
        if !rest.starts_with(b"/") {
            absolute.push(b'/');
        }
        absolute.extend_from_slice(rest);
        let mut folded = drive.to_vec();
        folded.extend_from_slice(&address::normalize_decoded_path(&absolute));
        path = folded;
    }

    // The rebuild is a RELATIVE path — `path_segments()` has already dropped the
    // leading `/` — so the list must not start with an empty segment. Two ways
    // one appears: the fold above reintroduces the separator deliberately, and
    // the `\` rewrite can strand a root marker (`file:///%5Croot/x`).
    // `normalize_decoded_path` collapses runs of `/` but a single leading one
    // survives, and only a *trailing* empty is popped below, so without this the
    // folded list has a shape the unfolded list never has — making a
    // `%5C`-leading prefix inert and a `%5C`-leading request escape a deny.
    let path = path.strip_prefix(b"/").unwrap_or(&path);

    let mut segments: Vec<Vec<u8>> = path
        .split(|byte| *byte == b'/')
        .map(|segment| {
            // Case folding is DENY-ONLY. `fold_this` still normalizes
            // separators for both effects above — that is structural — but
            // lowering case widens whichever side it touches, and widening an
            // allow is an over-grant.
            //
            // Windows has supported per-directory case sensitivity since 1803
            // (`fsutil file setCaseSensitiveInfo`, and it is on by default for
            // directories created through WSL interop), so `public` and
            // `PUBLIC` can be two directories the OS keeps apart. Folding an
            // allow made `allow …/root/public/` authorize `…/root/PUBLIC/x`,
            // which the file backend then opens — an over-grant the previous
            // case-sensitive matcher did not make. So an allow folds by no
            // table at all: ASCII would have been enough to cause exactly that
            // over-grant, which is why the fix was to drop the fold rather than
            // to narrow which table it uses.
            //
            // An unfolded allow can only be over-narrow, which an operator can
            // see and widen.
            if fold_this && widen {
                // The lossy decode belongs here and only here. It equates byte
                // sequences the filesystem may distinguish, which makes a deny
                // cover more — the safe direction. Both operands go through it,
                // so a deny never stops covering a name it already covered.
                String::from_utf8_lossy(segment).to_lowercase().into_bytes()
            } else {
                segment.to_vec()
            }
        })
        .collect();

    if segments.last().is_some_and(Vec::is_empty) {
        segments.pop();
    }
    Some(segments)
}

/// Whether a decoded path segment is a Windows drive designator (`c:`).
///
/// Only ever consulted on the folding path, where the host has already told us
/// it resolves `file:` paths with Windows semantics. Case is irrelevant — the
/// fold lowercases every segment anyway — and these are exactly the two forms
/// `Url::to_file_path` accepts as a drive (`X:` directly, `X%3A` once
/// `decode_segment` has run).
///
/// **A UNC share root is the same clamp one level up and is deliberately not
/// handled.** Windows clamps `..` at `\\server\share`, so the share is a first
/// path segment that behaves like a drive. It is out of reach rather than
/// solved: `FileBackend::file_path` refuses any authority that is not empty or
/// `localhost`, so a `file://server/share/…` address cannot become a path this
/// process resolves. If that ever loosens, this function is where the share
/// case belongs.
fn is_drive_segment(segment: &[u8]) -> bool {
    matches!(segment, [letter, b':'] if letter.is_ascii_alphabetic())
}

/// Whether `Url::parse` rewrites a raw `\` into `/` for this scheme.
///
/// These are exactly the WHATWG **special schemes**, for which the parser folds
/// `\` in both the authority state and the path state. The set is closed by the
/// URL Standard rather than open-ended, so listing it is not a guess about
/// future schemes: a scheme that is not on this list is parsed opaquely and a
/// backslash stays an ordinary byte.
///
/// **That distinction is what the raw-string guards in [`parse_prefix`] depend
/// on.** On `s3:`, `gs:` and `omniverse:` a backslash is a key byte —
/// `s3://b/data\..\` loads with scope `s3://b/data%5C..%5C`, which is the key
/// it spells — so refusing it there would reject a well-formed scope. On a
/// special scheme the same spelling silently resolves elsewhere, so it is
/// refused.
///
/// **Only a RAW backslash folds; `%5C` does not.** The parser leaves the escape
/// alone, and the `http`/`https` backend sends the serialized URL
/// (`plugin-http` passes `physical.as_str()` to `reqwest`), so the escape
/// reaches the origin as `%5C` rather than as a separator this stack invented.
/// That is why the escaped-separator check below names `%5C` for `file:` alone:
/// `file:` is the scheme whose resolver is known *from the scheme itself* to be
/// the local filesystem, so its treatment of the decoded byte is knowable here.
/// It is not the only scheme that can resolve in this process — the OpenDAL
/// plugin registers an `fs` driver, so an `opendal:` address may also land on
/// the local disk — but there the scheme does not say so, and a check keyed on
/// the scheme cannot tell.
///
/// **What an origin then does with `%5C` is not modelled, and that is a
/// residual rather than a claim.** An origin that percent-decodes and treats
/// `\` as a separator — an IIS or otherwise Windows-backed server — resolves
/// `https://h/private%5Csecret.txt` into the subtree that
/// `deny https://h/private/` names, while this matcher sees one segment
/// `private\secret.txt` and the deny does not cover it. That is the same
/// *finer than the backend* direction [`HOST_FOLDS_FILE_PATHS`] describes for a
/// case-insensitive volume, reached through a remote origin instead of a local
/// one, and it is unchanged by this design: the previous serialized-string
/// matcher did not cover that spelling either. Closing it needs either a
/// deny-side widening on every scheme or an origin contract, and both are
/// decisions above this function.
///
/// The set itself lives in the address layer, which draws the same distinction
/// for a plugin's returned address. One definition, because a closed set
/// copied twice is two things to keep in step.
fn scheme_folds_backslash(scheme: &str) -> bool {
    address::scheme_folds_backslash(scheme)
}

fn parse_operations(id: &str, operations: Vec<String>) -> Result<Option<Vec<Operation>>> {
    if operations.iter().any(|operation| operation == "*") {
        if operations.len() != 1 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("authz policy rule '{id}' must use '*' as its only operation"),
            ));
        }
        return Ok(None);
    }
    let mut parsed = Vec::with_capacity(operations.len());
    for operation in operations {
        let Some(parsed_operation) = operation_from_name(&operation) else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("authz policy rule '{id}' uses unknown operation '{operation}'"),
            ));
        };
        parsed.push(parsed_operation);
    }
    Ok(Some(parsed))
}

fn parse_prefix(id: &str, prefix: &str) -> Result<Option<Url>> {
    if prefix == "*" {
        return Ok(None);
    }
    if prefix.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("authz policy rule '{id}' prefix must not be empty"),
        ));
    }
    // Several checks below inspect the prefix AS WRITTEN, and `Url::parse` does
    // not read the string it was handed. It trims leading and trailing C0
    // controls and spaces, and removes every ASCII tab, LF and CR anywhere in
    // the input, before it decides either the scheme or the path. The raw
    // string and the parsed URL can therefore disagree about both, and
    // `resolving_prefix_segment`, `raw_prefix_path`, the backslash check and
    // the retargeting gate all key on the raw one — so they fail together.
    //
    // The removal is the sharper half, because it manufactures path structure
    // that no raw scan can see. Measured: `prefix = "s3://b/team/.<TAB>."`
    // loads with scope `s3://b/` — the WHOLE BUCKET — from a rule that reads as
    // scoped under `team`. The raw path holds the two segments `team` and
    // `.<TAB>.`, so the dot-segment check finds nothing; the parser drops the
    // tab, sees `team/..`, and resolves to the root. `s3:` is not special, so
    // the backslash check cannot fire either, and no escape is involved so the
    // retargeting gate stays quiet.
    //
    // The trim is the other half: a prefix the parser trims is one whose raw
    // and parsed forms disagree at all, and that agreement is the property
    // every other guard here rests on. It is refused for that reason rather
    // than because a specific bypass rides on it.
    //
    // An INTERIOR space stays legal and must: the parser preserves it as
    // `%20`, so `s3://b/pub x` names a real key and the two forms agree.
    if prefix
        .bytes()
        .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
        || prefix.starts_with(|c: char| c.is_ascii() && c as u8 <= b' ')
        || prefix.ends_with(|c: char| c.is_ascii() && c as u8 <= b' ')
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "authz policy rule '{id}' has leading or trailing whitespace in its prefix, \
                 or a tab, newline or carriage return inside it; the URL parser removes those \
                 before reading the scheme and the path, so the scope it covers is not the one \
                 it spells. Write the prefix without them"
            ),
        ));
    }
    let parsed = address::parse(prefix).map(Some).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "authz policy rule '{id}' has an invalid prefix: {}",
                error.message()
            ),
        )
    })?;

    // Authorization decides on scheme, authority and path. A prefix carrying a
    // query or a fragment asks for something the matcher cannot honour, and
    // loading it unchanged would SILENTLY WIDEN the rule rather than narrow it:
    //
    //   `allow s3://b/x?versionId=public`  narrows today; would become
    //                                      `allow s3://b/x` — every version.
    //   `allow s3://b/x#note`              matches nothing today, because
    //                                      `is_prefix_of` compares serialized
    //                                      strings; the fragment is stripped at
    //                                      parse, so it would match the WHOLE
    //                                      subtree. Inert to broad is the more
    //                                      dangerous of the two.
    //
    // Failing closed makes the operator rewrite it deliberately.
    //
    // The detection is [`address::refused_config_component`], shared with the
    // alias loader and `plugin-http`'s. One definition, because four hand-placed
    // copies of one rule are four things to keep in step — and it reads the raw
    // string, which is the only view in which the fragment still exists.
    if let Some(component) = address::refused_config_component(prefix) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            match component {
                address::ConfigComponent::Query => format!(
                    "authz policy rule '{id}' has a prefix carrying a query; authorization is \
                     decided on scheme, authority and path, so a rule on a path already covers \
                     every version of it"
                ),
                address::ConfigComponent::Fragment => format!(
                    "authz policy rule '{id}' has a prefix carrying a fragment; a fragment is \
                     never sent to a server, so the rule would silently widen to the whole \
                     subtree"
                ),
            },
        ));
    }
    // A raw `\` on a scheme whose parser folds it hides the path from every
    // raw-string guard here at once. `raw_prefix_path` scans the post-authority
    // remainder for `/`, `?` or `#`; `file://C:\data\public\..` contains none,
    // so it returns `None` and the dot-segment check short-circuits, the
    // escaped-separator check falls back to an empty path, and the retargeting
    // gate sees nothing. `Url::parse` meanwhile normalizes it happily —
    // measured, that prefix loads with scope `file:///C:/data/`, an allow
    // over the whole `data/` tree while reading as scoped to `data\public`.
    //
    // The same guards are fooled a second way when the fold happens in the
    // authority state: `https://h\evil/data` parses with host `h` and path
    // `/evil/data`, while `raw_prefix_path` reports `/data`, so every guard
    // inspects a path the rule does not have. And the plainest operator error
    // needs no dot segment at all — `https://h/team\sub`, written expecting the
    // literal key byte an s3 key would carry, loads scoped to the whole
    // `team/sub/` subtree.
    //
    // Refusing the spelling is cheaper and safer than re-deriving WHATWG's
    // host and path state machines in a security check, and costs the operator
    // one rewrite to the `/` form that every other guard already understands.
    //
    // It runs BEFORE the dot-segment check so that a folded separator is
    // reported as one. The diagnostic names the rewrite that fixes it, and the
    // two checks would otherwise cover for each other on the rows where a
    // backslash brackets a `..`.
    //
    // The scheme comes from the PARSED url, not from splitting the raw string:
    // the parser lowercases it and has already removed the characters that
    // would otherwise let a written scheme differ from the one it acts on.
    if let Some(url) = &parsed
        && scheme_folds_backslash(url.scheme())
        && prefix.contains('\\')
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "authz policy rule '{id}' has a prefix using `\\` as a path separator; \
                 write it with `/`, which is the only form the scope checks can read"
            ),
        ));
    }
    // A raw `\` in the AUTHORITY moves the boundary between authority and path,
    // and every raw-string guard here locates that boundary the same way — by
    // scanning for the first literal `/`, `?` or `#`. The parser's port state
    // ends the authority at `\` as well, on EVERY scheme, so the two disagree
    // about where the path starts and the guards inspect a different string
    // than the rule ends up with.
    //
    // The `is_none()` clause below catches this only when the `\` is the last
    // boundary in the prefix. One trailing `/` gives the scan something later
    // to find, and the disagreement survives with the guard silent. Measured,
    // all four on a NON-special scheme where the backslash check above
    // deliberately does not fire:
    //
    //   s3://corp:\secret%2F..%2F../   loaded scoped to s3://corp/ — the whole
    //                                  bucket, from a rule reading as `secret`
    //   s3://corp:\team%2Fsub/x        handed the escaped-separator check `/x`,
    //                                  so the `%2F` was never inspected
    //   s3://corp:\@evil/x             parsed with userinfo `corp:\` and host
    //                                  `evil` — a rule written to scope host
    //                                  `corp` scoped host `evil` instead, with
    //                                  no escape and no acknowledgement needed
    //   s3://corp:\secret/             every guard read `/`
    //
    // So the invariant is asserted on the authority itself rather than on one
    // symptom of it: a policy prefix is operator-authored config, and no scope
    // needs a backslash in its authority on any scheme.
    //
    // **This is the invariant, narrowed to where it can actually be violated.**
    // The invariant is "the raw scan and the parser agree where the authority
    // ends". `raw_authority` ends it at `/`, `?` or `#`; the parser's authority
    // states end it at (`url-2.5.8` `parser.rs`):
    //
    //   userinfo scan  :899   `/ ? #` always, `\` only when the scheme is special
    //   host state    :1008   `/ ? #` always, `\` only when the scheme is special
    //   file_host     :1091   `/ \ ? #`  — `file:` is special, so consistent
    //   port state    :1131   `/ \ ? #`  on EVERY scheme
    //
    // Subtract the three the scan already handles and `\` is the entire
    // remainder — but only in the PORT state, which is reached after a `:` in
    // the host/port region. Before the last `@` the byte sits in userinfo,
    // where a non-special scheme does not terminate on it, so the two still
    // agree; and a `\` in the host itself is `InvalidDomainCharacter`, so
    // `s3://corp\evil` never loads at all. Refusing `\` in the host/port
    // region is therefore exactly equivalent to asserting the agreement, for
    // the parser this crate pins — and refusing it in userinfo as well would
    // reject prefixes whose scan and parse agree, which the invariant does not
    // license. Special schemes never reach here: the check above refuses a raw
    // `\` anywhere in them.
    //
    // This subsumes the `is_none()` clause below for every spelling reachable
    // today — `\` is the only extra terminator the parser's port state accepts,
    // and it is refused here — so that clause is now a backstop rather than a
    // live check, kept because it states the invariant the two representations
    // must satisfy rather than the one byte that currently breaks it.
    if raw_authority(prefix).is_some_and(|authority| {
        // Only the HOST/PORT region, which is what the last raw `@` delimits —
        // the same boundary the parser uses (it keeps `last_at`). A `\` before
        // that `@` is inside userinfo, where the parser does NOT terminate on a
        // non-special scheme, so the scan and the parser still agree and there
        // is nothing to refuse: `s3://DOMAIN\alice@bucket/team/` parses to
        // userinfo `DOMAIN%5Calice`, host `bucket`, path `/team/`, which is
        // exactly the authority the scan reports.
        let host_port = authority
            .rsplit_once('@')
            .map_or(authority, |(_userinfo, after)| after);
        host_port.contains('\\')
    }) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "authz policy rule '{id}' has a `\\` between its scheme and the start of its \
                 path; the URL parser ends the authority there while the scope checks do not, \
                 so the host and path it resolves to are not the ones it spells. Write the \
                 authority and the path separated by `/`"
            ),
        ));
    }
    // `raw_prefix_path` returning `None` must not mean "there is no path to
    // check". It locates the path by scanning the post-`//` remainder for `/`,
    // `?` or `#`, and when it finds none it yields `None` — at which point
    // `resolving_prefix_segment` short-circuits, the escaped-separator check
    // falls back to an empty path, and the retargeting gate has nothing to
    // read. Every raw-string guard no-ops at once, and they fail OPEN.
    //
    // This is the second distinct spelling that reaches that state — a raw `\`
    // on a folding scheme is the other — so the fix is the invariant rather
    // than a third character in the scan: if the raw scan cannot find the path
    // and the parser found one, the two disagree and the prefix cannot be
    // validated, so it is refused.
    //
    // Whitespace belongs to a neighbouring failure mode rather than this one,
    // and the distinction is worth keeping: a stripped tab leaves the scan
    // returning a path that is *wrong*, not one that is *missing*. That is why
    // it needs its own check above and is not caught here.
    //
    // Measured, on a NON-special scheme where the backslash check above
    // deliberately does not fire:
    //
    //   allow s3://corp:\secret%2F..%2F..
    //     raw_prefix_path              None
    //     scope it loads with          s3://corp/     (the whole bucket)
    //     alice read …/finance/secret.csv    allowed
    //
    // The `\` ends the authority because the parser's port state lists it as a
    // TERMINATOR, beside `/`, `?` and `#` — not because it fails to be a port.
    // That distinction is the whole reason this is reachable: any other
    // non-digit there is a hard `InvalidPort` error and never loads at all
    // (`s3://corp:secret` and `s3://corp:9x/secret` both fail to parse). The
    // terminator list is in the port state, so it applies on EVERY scheme,
    // including the non-special ones the backslash check above leaves alone.
    // The parser then puts the `\` in the path, decodes `%2F` into separators
    // and resolves the `..` run to the bucket root, while the prefix reads as
    // scoped to `secret`.
    //
    // The parsed path here is read from `Url::parse` rather than from
    // `address::parse`: canonicalization has already resolved the dot segments,
    // so by then the path is `/` and there is nothing left to disagree with.
    if let Ok(unresolved) = Url::parse(prefix)
        && raw_prefix_path(prefix).is_none()
        && !unresolved.path().trim_start_matches('/').is_empty()
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                // The prefix is NOT interpolated here. `Error` re-serializes a
                // URL-like token while redacting userinfo, so the written
                // `s3://corp:\x` would be shown back as `s3://corp/\x` — a
                // spelling the operator did not write, and one that appears to
                // already satisfy what this message asks for.
                "authz policy rule '{id}' separates its authority from its path with a \
                 character other than '/', so the scope it covers cannot be read from the \
                 rule as written; a '\\' directly after the host or port does this. Write \
                 the authority and the path separated by '/'"
            ),
        ));
    }
    // A prefix whose scope differs from what it spells is the same silent
    // widening the two checks around it prevent, wearing a more innocent
    // spelling: `allow s3://corp/secret/../` reads as scoped to `corp/secret`
    // and is in fact the whole bucket.
    //
    // This one has to inspect the RAW string, and cannot use the predicate the
    // decode boundaries use, because `Url::parse` above has already resolved
    // the dot segments — by then there is nothing left to detect. String
    // inspection is the wrong tool for an address a *plugin* returned, where
    // `a/%2E%2E/b` may be a legitimate key. A policy prefix is operator-authored
    // config, not data: there is no scope a dot or empty segment expresses that
    // its resolved spelling does not express more clearly.
    if let Some(segment) = resolving_prefix_segment(prefix) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "authz policy rule '{id}' has a prefix containing a '{segment}' path \
                 segment, so the scope it covers is not the one it spells; write the \
                 resolved scope"
            ),
        ));
    }
    // An escaped separator is the last spelling that silently changes a live
    // rule's breadth across this upgrade, and it is the same "inert to broad"
    // direction as the two checks above. The matcher decodes each segment, so
    // `prefix = "s3://b/team%2Fsub"` — one literal key under the old serialized
    // matcher — now scopes the whole `team/sub/` subtree. `s3://b/team%2F` is
    // worse: it decodes to `/team/` with only a TRAILING empty segment, which
    // `resolving_prefix_segment` deliberately does not flag, so an allow over
    // one key becomes an allow over the subtree with no diagnostic at all. The
    // same shape narrows a deny, which fails open.
    //
    // `%5C` is included for `file:` only, and that is a narrower set than the
    // raw-`\` check above deliberately, not by oversight. A RAW backslash is
    // rewritten by the parser on every special scheme, so the guard there spans
    // all of them; an ESCAPED one survives parsing everywhere, so the question
    // becomes who decodes it later. On `file:` that is the Windows filesystem,
    // in this process, which reads the decoded byte as a component separator.
    // On `http:` it is a remote origin whose behaviour this process does not
    // know; `plugin-http` sends the serialized URL (`physical.as_str()`), so
    // the escape travels intact rather than becoming a separator this stack
    // invented. An origin that decodes and folds it is an unmodelled residual,
    // not something this check would fix — the bypass it would open is on the
    // request address, which no prefix rule reaches. See
    // [`scheme_folds_backslash`].
    if let Some(url) = &parsed {
        let escaped = if url.scheme().eq_ignore_ascii_case("file") {
            ["%2f", "%5c"].as_slice()
        } else {
            ["%2f"].as_slice()
        };
        // The RAW path, and only the path.
        //
        // Raw, because `address::parse` has already decoded `%2F` into a real
        // separator — by then there is nothing left to detect, the same reason
        // `resolving_prefix_segment` reads the string as written.
        //
        // Only the path, because the raw prefix also contains userinfo, where
        // an escaped separator is an ordinary character in a credential that
        // the matcher never consults. Refusing on it rejects a well-spelled
        // scope, and `Error` redacts userinfo, so the operator would read a
        // message naming an escape their prefix appears not to contain.
        let path = raw_prefix_path(prefix).unwrap_or("").to_ascii_lowercase();
        if let Some(found) = escaped.iter().find(|needle| path.contains(**needle)) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "authz policy rule '{id}' has a prefix containing an escaped separator \
                     ('{}'), so the scope it covers is not the one it spells — the matcher \
                     decodes it into a real path separator; write the resolved scope",
                    found.to_uppercase()
                ),
            ));
        }
    }

    Ok(parsed)
}

/// Whether a **serialized** path contains a percent-escape, as opposed to a
/// bare `%`.
///
/// Called on `Url::parse(prefix).path()`, never on the raw written string. A
/// `%` that does not begin a valid escape is left alone by the parser, so
/// `s3://b/100%` serialized to `/100%` before this change and still names
/// `100%` — nothing moved and no acknowledgement is owed. `%` plus two hex
/// digits is the case that moved.
fn contains_percent_escape(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        *byte == b'%'
            && bytes
                .get(index + 1..index + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
    })
}

/// Refuse a policy prefix whose key MOVED, until the operator acknowledges it.
///
/// **A migration gate, not a rule about what is well-formed.** The prefix is
/// still valid; what changed is which object it protects.
///
/// The baseline is the **authorization matcher**, not any backend's key
/// derivation. `address::is_prefix_of` compared `prefix.as_str()` against
/// `addr.as_str()` — the serialized string, uniformly, for every scheme — and
/// the matcher now compares decoded path components. So the scope of
/// `deny s3://b/100%25` was the literal text `100%25` and is now the decoded
/// `100%` — measured.
///
/// Saying "the backend key moved" would be wrong for most schemes: `address::key`
/// already percent-decoded before this PR, so azure, file, nucleus and opendal
/// derived a decoded key all along and only s3 and gcs sliced the serialized
/// form. What moved for every scheme alike is the comparison the matcher makes,
/// which is what a policy prefix feeds. The object it guarded is spelled `s3://b/100%2525`, which
/// a parent `allow s3://b/` covers, so previously denied data becomes reachable
/// with no diagnostic.
///
/// The checks in `parse_prefix` reject spellings that change a rule's
/// **breadth**. This is a different class: the breadth is intact and the rule
/// has been *retargeted*.
///
/// **The predicate is over the serialized path, not the written string.** That
/// distinction is the whole correctness of this function. The old key was a
/// slice of the serialization, so a prefix moved exactly when its serialized
/// form carried an escape — and the parser inserts escapes the operator never
/// typed. `s3://b/pub x` serializes to `/pub%20x`: it named `pub%20x` and now
/// names `pub x`, having moved just as far as `s3://b/100%25`. Reading the raw
/// string missed every such case while flagging `file:///C%3A/root/` but not
/// `file:///C:/root/`, whose serializations genuinely differ.
///
/// **Escapes are not banned, and under this predicate the reason is stronger
/// than a list of exceptions.** The old scope IS the serialized path, so a
/// prefix moved exactly when that path carries a `%xx` — which means no
/// escape-free spelling can ever reach a moved scope, and no rewrite preserves
/// the old meaning. Every spelling of one scope moved together.
///
/// The set with no escape-free serialization is also much larger than the
/// written-spelling intuition suggests: a space, `{`, `}`, `<`, `>`, `"`, a
/// backtick, `#`, `?`, `%`, every control byte and every non-ASCII character.
/// `s3://b/pub x` is a member, which is why it is this gate's headline example
/// rather than the safe rewrite an earlier version recommended.
///
/// So the operator accepts the new meaning once, per document, and the error
/// names each affected rule with the scope it now resolves to so the re-read is
/// a comparison rather than a leap.
fn reject_unacknowledged_escaped_prefixes(
    rules: &[(String, String)],
    acknowledged: bool,
) -> Result<()> {
    if acknowledged {
        return Ok(());
    }
    let mut affected: Vec<String> = Vec::new();
    for (id, prefix) in rules {
        let Ok(plain) = Url::parse(prefix) else {
            continue;
        };
        if !contains_percent_escape(plain.path()) {
            continue;
        }
        let resolved = address::parse(prefix).map_or_else(
            |_| "<unparseable>".to_string(),
            |url| {
                scope_segments(&url).map_or_else(
                    || "<unscoped>".to_string(),
                    |segments| {
                        segments
                            .iter()
                            .map(|segment| {
                                // Escaped, not lossy. The one key class whose
                                // whole justification is byte-exactness must not
                                // render `x%FF` and `x%FE` identically in the
                                // message the operator has to compare.
                                segment
                                    .iter()
                                    .flat_map(|byte| std::ascii::escape_default(*byte))
                                    .map(char::from)
                                    .collect::<String>()
                            })
                            .collect::<Vec<_>>()
                            .join("/")
                    },
                )
            },
        );
        affected.push(format!("'{id}' now scopes {resolved}"));
    }
    if affected.is_empty() {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        format!(
            "authz policy prefixes now scope a different object than they did before: {}. \
             Authorization used to compare the SERIALIZED address and now compares DECODED \
             path components — so any prefix whose serialized form carries a percent-escape \
             has moved, including ones written with no escape at all (`s3://b/pub x` \
             serializes to `s3://b/pub%20x`, so it scoped `pub%20x` and now scopes \
             `pub x`). **A deny written this way has stopped protecting the object it was \
             written for**, and a broader allow above it may now reach that object, so this \
             is refused rather than applied. Compare each rule above against the scope it \
             now resolves to, then set `prefix_escapes_are_decoded = true` at the top of the \
             policy document to accept the new meaning. Rewriting the prefix does NOT avoid \
             this — every spelling of one scope moved together",
            affected.join("; ")
        ),
    ))
}

/// The authority of a policy prefix **as written** — everything between `//`
/// and the first literal `/`, `?` or `#`.
///
/// `None` when the prefix has no `//` at all, which is the authority-less
/// `file:/root/` spelling much of this repo uses.
///
/// This is the region [`parse_prefix`] refuses a raw `\` in. The scan is the
/// same one [`raw_prefix_path`] uses to *skip* the authority, deliberately: the
/// two must agree about where the authority ends, or a byte that moves the
/// boundary is invisible to whichever of them is looking away.
fn raw_authority(prefix: &str) -> Option<&str> {
    let (_, rest) = prefix.split_once(':')?;
    let after_slashes = rest.strip_prefix("//")?;
    Some(match after_slashes.find(['/', '?', '#']) {
        Some(at) => &after_slashes[..at],
        None => after_slashes,
    })
}

/// The path portion of a policy prefix **as written**, with the authority and
/// any query or fragment removed.
///
/// Two checks need the raw string rather than the parsed URL, because
/// `address::parse` resolves dot segments and decodes `%2F` into a real
/// separator — by the time there is a `Url`, the spelling they exist to detect
/// is gone. Both must skip the authority: userinfo can carry the same escapes
/// as an ordinary part of a credential, and neither is consulted by the matcher.
///
/// **`None` does not mean "no path", it means "cannot tell", and
/// [`parse_prefix`] treats it as a refusal.** The authority scan below knows
/// three terminators; the parser knows more, and ends the authority on anything
/// that cannot continue a host or a port. When the two disagree this returns
/// `None`, and every caller then has nothing to inspect — so a `None` paired
/// with a parser that *did* find a path is a prefix no guard can validate, and
/// is rejected rather than admitted unchecked.
fn raw_prefix_path(prefix: &str) -> Option<&str> {
    let (_, rest) = prefix.split_once(':')?;
    let path = match rest.strip_prefix("//") {
        // An authority runs to the first `/`, `?` or `#`. A raw `/` cannot
        // appear inside one, so this locates the path unambiguously even with
        // userinfo, an IPv6 literal or an explicit port.
        Some(after_slashes) => match after_slashes.find(['/', '?', '#']) {
            Some(at) if after_slashes.as_bytes()[at] == b'/' => &after_slashes[at..],
            _ => return None,
        },
        None => rest,
    };
    Some(path.split(['?', '#']).next().unwrap_or(path))
}

/// The first `.`, `..` or interior-empty path segment a raw policy prefix
/// resolves to, if any.
///
/// Operates on the string as written, because `address::parse` resolves dot
/// segments before any predicate could see them. Three rules make it correct,
/// and the first version of this function got all three wrong:
///
/// 1. **The authority is optional.** `file:/root/` has no `://`, and that is
///    the spelling much of this repo uses. Keying on `://` skipped the check
///    entirely for it, so `prefix = "file:/root/%2E%2E/"` loaded with scope
///    `file:///` — allow everything, every principal, every operation.
/// 2. **Decode once over the whole path, then split.** Splitting first and
///    decoding each piece cannot see a separator hidden as `%2F`:
///    `secret/%2E%2E%2F` is one raw segment that decodes to two, of which one
///    is `..`. `canonicalize` decodes and *then* resolves, so a check that
///    splits first is not modelling the thing it guards.
/// 3. **`\` is a separator for `file:`, on every host.** The matcher folds it
///    only where the OS does, but this check folds it always: a prefix that
///    resolves elsewhere on Windows must be refused when the policy is
///    validated on Linux, or a file that loads in CI fails on the machine that
///    serves it.
///
///    `file:` and not the wider
///    [special-scheme set](scheme_folds_backslash), because what reaches here
///    is a *decoded* `%5C` — [`parse_prefix`] has already refused every raw `\`
///    on a scheme the parser folds. On `file:` the resolver is known from the
///    scheme to be the local filesystem, so the fold models something knowable.
///    Off `file:` it does not: folding here would refuse
///    `https://h/data%5C..%5Cx` while `https://h/data%5Cx` loaded, which draws
///    a line the matcher draws nowhere else. It would also not close the
///    residual it appears to address — that one is reached by a **request
///    address**, which is matched against a scope rather than validated here,
///    so no amount of prefix checking touches it.
fn resolving_prefix_segment(prefix: &str) -> Option<&'static str> {
    let (scheme, _) = prefix.split_once(':')?;
    let path = raw_prefix_path(prefix)?;

    let mut decoded = address::decode_segment(path);
    if scheme.eq_ignore_ascii_case("file") {
        for byte in &mut decoded {
            if *byte == b'\\' {
                *byte = b'/';
            }
        }
    }

    let segments: Vec<&[u8]> = decoded.split(|byte| *byte == b'/').collect();
    for (index, segment) in segments.iter().enumerate() {
        match *segment {
            b"." => return Some("."),
            b".." => return Some(".."),
            // A leading empty segment is the root marker and a trailing one is
            // the ordinary directory form. Only an interior one is a doubled
            // separator that resolves away.
            b"" if index > 0 && index + 1 < segments.len() => return Some("empty"),
            _ => {}
        }
    }
    None
}

/// **This function asks two different questions about a prefix, and each has
/// its own correct representation. Both defects found in it were the same
/// mistake: reaching for `rule.prefix` — the parsed, canonicalized `Url` —
/// because it was the value in hand.**
///
/// | question | correct representation | why |
/// |---|---|---|
/// | "did the operator write these two the same?" | [`Rule::prefix_written`], the raw config text | a deliberate ordered override is a fact about the document, and canonicalization erases the difference between `s3://b/private/` and `s3://b/%70rivate/` |
/// | "do these two name one scope?" | [`segments_with_host_semantics_widened`] under the widening the MATCHER will use | the matcher folds case for a deny and not for an allow, so an unwidened comparison calls one scope two |
///
/// The `Url` answers neither. It is too *coarse* for the first — it has already
/// thrown away the spelling — and too *fine* for the second, which must be
/// evaluated under host and effect semantics the `Url` does not carry. Adding a
/// third comparison here means naming which of the two questions it asks, and
/// if it is neither, the shape is wrong rather than the line.
///
/// Refuse two rules that name the **same scope in different spellings** and can
/// decide the same request.
///
/// Ranking is by segment count, so two spellings of one scope tie and the
/// winner falls through to declaration order. That silently flips live
/// policies, because byte length used to break the tie:
///
/// ```toml
/// [[policy]] id="deny-priv"  effect="deny"  prefix="file:///root/private/"
/// [[policy]] id="allow-priv" effect="allow" prefix="file:///root/private"
/// ```
///
/// The deny used to win on 21 bytes against 20. Under segment ranking the two
/// tie and the later **allow** wins — a live deny becoming an allow with no
/// diagnostic.
///
/// **The comparison must use the widening the matcher will use, or the check
/// misses the pair it exists for.** `covers_with_host_semantics` folds case for
/// a deny and never for an allow, so on a folding host
/// `deny file:///root/PRIVATE/` and `allow file:///root/private/` are two
/// scopes at load and one at match time. Measured: both cover
/// `file:///root/private/secret`, both pin two segments, so the rank ties and
/// declaration order decides — the deny survives only when the operator happens
/// to write it last. Worse, the verdict then depends on the *request's*
/// spelling: `file:///root/PRIVATE/secret` misses the unfolded allow, so the
/// deny wins there. One policy, one node, two answers. Comparing widened
/// segments whenever either rule is a deny refuses the pair at load, on exactly
/// the hosts where it is one scope at match time.
///
/// **The host behaviour is a parameter for the same reason it is one in
/// [`segments_with_host_semantics_widened`]** — this repo's Windows CI leg runs
/// neither this crate nor any Rust suite, so a `#[cfg(windows)]` test would
/// execute on no machine at all.
///
/// **Scoped to rules whose match sets intersect, not to rules that share
/// fields.** `matching_rule` filters principals with `glob_match` and treats
/// `operations: None` as *all*, so the sets overlap rather than partition:
/// `"*"` ⊃ `"alice"`, `None` ⊃ `["read"]`. A check keyed on field equality
/// would load the flip above whenever the two rules differ in principal, which
/// is exactly when an operator thinks they are unrelated.
///
/// Byte-identical duplicates keep today's ordered-override semantics — that is
/// how a later rule deliberately supersedes an earlier one.
fn reject_co_matching_equal_scopes(rules: &[Rule], fold: bool) -> Result<()> {
    for (index, rule) in rules.iter().enumerate() {
        let Some(prefix) = &rule.prefix else {
            continue;
        };
        for other in &rules[index + 1..] {
            let Some(other_prefix) = &other.prefix else {
                continue;
            };
            // The exemption is for a prefix the operator WROTE twice, so it is
            // keyed on the written text. Keying it on the parsed `Url` handed
            // the exemption to every pair canonicalization happens to collapse:
            // with the escape acknowledgement set, `deny s3://b/private/`
            // before `allow s3://b/%70rivate/` both hold `s3://b/private/`, so
            // the pair was skipped, both covered `s3://b/private/x`, both
            // pinned one segment, and the tie handed the verdict to the later
            // allow. `main` denied that request — its serialized matcher never
            // matched `%70rivate` against `private` — so it was a silent
            // deny-to-allow flip, reached through the one exemption meant to be
            // an operator's deliberate override.
            //
            // Matched explicitly rather than with `==` on the `Option`s: a
            // missing spelling must never earn the exemption. `None` here means
            // "no prefix", which the guards above have already excluded — but
            // comparing the `Option`s directly would silently exempt a pair
            // whose spellings were both absent, so the one representation that
            // grants an override is required to be present rather than assumed.
            let same_spelling = match (&rule.prefix_written, &other.prefix_written) {
                (Some(written), Some(other_written)) => written == other_written,
                _ => false,
            };
            if same_spelling {
                continue;
            }
            if !principals_intersect(&rule.principal, &other.principal)
                || !operations_intersect(rule.operations.as_deref(), other.operations.as_deref())
            {
                continue;
            }
            // Widen whenever EITHER rule is a deny, because that is when the
            // matcher will: the deny side folds case and the allow side does
            // not, so the two sides are compared under different rules at match
            // time and the collision is only visible under the wider one.
            let widen = matches!(rule.effect, Effect::Deny) || matches!(other.effect, Effect::Deny);
            let (Some(scope), Some(other_scope)) = (
                segments_with_host_semantics_widened(prefix, fold, widen),
                segments_with_host_semantics_widened(other_prefix, fold, widen),
            ) else {
                continue;
            };
            if scope != other_scope
                || prefix.scheme() != other_prefix.scheme()
                || prefix.host() != other_prefix.host()
                || prefix.port() != other_prefix.port()
            {
                continue;
            }
            // `Error` redacts userinfo, and userinfo is the one difference that
            // is invisible to a scope. Without this clause the message reads
            // "different spellings ('https://h/team/' and 'https://h/team/')"
            // — self-contradictory, and the operator cannot see what to change.
            // **The message must not print the two spellings side by side, and
            // printing the WRITTEN ones does not rescue it.** `Error`
            // re-serializes a URL-like token while redacting userinfo, so a
            // written `https://h:443/team/` is displayed as `https://h/team/`
            // — and the whole class this check catches is pairs whose
            // difference canonicalization removes. Measured over the eleven
            // realistic shapes, printing the written text still rendered six of
            // them as two identical strings: default port, host case, scheme
            // case, IDNA, and userinfo.
            //
            // So the diagnostic names the two RULE IDS, which the operator can
            // look up in their own document, and the one scope both resolve to.
            // Rule ids are the only handle here that no display-time rewrite
            // can collapse.
            // Named for what it tests: whether EITHER prefix carries credentials.
            // It does not test that the two DIFFER in them — two prefixes with
            // identical userinfo and different trailing slashes reach here too,
            // so the note below says "carries", not "differs by".
            let either_carries_credentials = [prefix, other_prefix]
                .iter()
                .any(|url| !url.username().is_empty() || url.password().is_some());
            // Say when the principals were ASSUMED to overlap rather than shown
            // to. `principals_intersect` decides disjointness only for patterns
            // it can prove, and answers "possibly" for the rest — so a pair can
            // reach here whose principals an operator can see never both match.
            // Naming the prefix spelling as the sole cause then sends them to
            // fix the one thing that is not the problem.
            let principals_assumed = rule.principal != other.principal
                && !glob_match(&rule.principal, &other.principal)
                && !glob_match(&other.principal, &rule.principal);
            let principal_note = if principals_assumed {
                format!(
                    " Their principal patterns '{}' and '{}' both carry a wildcard, so they are \
                     treated as possibly overlapping rather than shown to; if they cannot in \
                     fact both match one principal, that assumption is what brings these two \
                     rules together.",
                    rule.principal, other.principal
                )
            } else {
                String::new()
            };
            let note = if either_carries_credentials {
                " At least one carries credentials, which are never part of a scope, so a \
                 credential is not what separates them."
            } else {
                ""
            };
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "authz policy rules '{}' and '{}' are written differently but resolve to \
                     the same scope ('{}'), and can decide the same request; ranking cannot \
                     tell them apart, so which one wins would depend on declaration order. \
                     Compare their two `prefix` values: they differ only in spelling that \
                     nothing downstream preserves — a host's case, a default port, a \
                     percent-escape, an IPv6 or IDNA form, which the URL parser normalizes; \
                     or a trailing slash, userinfo, or letter case in a `file:` deny, which \
                     this matcher itself does not distinguish.{note} Delete one, give them \
                     genuinely different scopes, or — if a later rule is meant to supersede an \
                     earlier one — write both prefixes identically, which is how a deliberate \
                     override is expressed{principal_note}",
                    rule.id,
                    other.id,
                    // `RedactedUrl`, never the parsed `Url` itself. A DENY
                    // prefix is explicitly allowed to carry credentials — the
                    // gate above refuses only an ALLOW — so this branch is
                    // reachable with userinfo present, and `Error`'s message
                    // redactor is not a backstop for it: `scan_url_at` ends a
                    // token at `,`, `;`, `'`, `)` and friends, and emits the
                    // truncated token verbatim when it then fails to parse.
                    // Measured — `https://reader:hunt,er2@h/team/` reached the
                    // operator's terminal in full.
                    ovstorage_plugin::RedactedUrl(prefix)
                ),
            ));
        }
    }
    Ok(())
}

/// Whether two principal patterns can both match some principal.
///
/// **Defaults to `true`, and the default is the whole point.** Over-reporting
/// an intersection costs a rejected policy the operator can rewrite;
/// under-reporting ships the silent deny-to-allow flip this check exists to
/// prevent, so the predicate must never claim disjointness it has not proved.
///
/// An earlier version tested `glob_match` both ways and returned false
/// otherwise. That under-reports whenever two patterns overlap only through a
/// third value — `team-*` and `*-alice` both match `team-alice` while neither
/// matches the other — which reopened the flip with a one-character change to
/// a principal.
///
/// Disjointness is decided in exactly two shapes, both provable without a real
/// matcher, and assumed in every other:
///
/// 1. **A pattern with no wildcard matches only itself**, so if either side is
///    a literal and the other does not match it, they cannot overlap.
/// 2. **Two `literal*` patterns** — one wildcard, at the end — match exactly
///    the values starting with their literals, so they overlap only if one
///    literal is a prefix of the other.
///
/// Anything else is treated as possibly overlapping. The cost of that
/// assumption is no longer only a wider check: `reject_co_matching_equal_scopes`
/// turns a claimed intersection into a refusal to load, so an assumed overlap
/// can stop a broker starting on a policy that is not ambiguous. Where the
/// assumption is what brings two rules together, the diagnostic says so.
fn principals_intersect(a: &str, b: &str) -> bool {
    if a == b || glob_match(a, b) || glob_match(b, a) {
        return true;
    }
    // One shape is provably disjoint without a real matcher, and it is the one
    // the documented examples use. A pattern `literal*` — a single wildcard, at
    // the end — matches exactly the values starting with `literal`
    // (`glob_match` strips the prefix and has no trailing part to check), so two
    // of them overlap only if one literal is a prefix of the other. `team-*`
    // and `svc-*` therefore cannot both match anything.
    //
    // Deciding this rather than assuming it matters because the assumption is
    // no longer free: `reject_co_matching_equal_scopes` turns a claimed
    // intersection into a refusal to load, so assuming one where none exists
    // stops a broker starting on a policy that is not ambiguous at all.
    //
    // Every other shape keeps the conservative answer. `*-alice` and `team-*`
    // both match `team-alice` while neither matches the other, so a rule that
    // returned "disjoint" for two wildcards in general would reopen the silent
    // deny-to-allow flip this check exists to prevent.
    if let (Some(a_literal), Some(b_literal)) = (trailing_star_literal(a), trailing_star_literal(b))
    {
        return a_literal.starts_with(b_literal) || b_literal.starts_with(a_literal);
    }
    a.contains('*') && b.contains('*')
}

/// The literal of a `literal*` pattern — a single wildcard, at the end, with a
/// non-empty literal.
///
/// `None` for every other shape, including the bare `*`, whose literal would be
/// empty and which matches everything.
fn trailing_star_literal(pattern: &str) -> Option<&str> {
    let literal = pattern.strip_suffix('*')?;
    (!literal.is_empty() && !literal.contains('*')).then_some(literal)
}

/// `None` means every operation, so it intersects everything.
fn operations_intersect(a: Option<&[Operation]>, b: Option<&[Operation]>) -> bool {
    match (a, b) {
        (None, _) | (_, None) => true,
        (Some(a), Some(b)) => a.iter().any(|op| b.contains(op)),
    }
}

fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == value;
    }

    let mut remainder = value;
    if let Some(first) = parts.first()
        && !first.is_empty()
    {
        let Some(next) = remainder.strip_prefix(first) else {
            return false;
        };
        remainder = next;
    }

    for part in parts.iter().skip(1).take(parts.len().saturating_sub(2)) {
        if part.is_empty() {
            continue;
        }
        let Some(index) = remainder.find(part) else {
            return false;
        };
        remainder = &remainder[index + part.len()..];
    }

    if let Some(last) = parts.last()
        && !last.is_empty()
        && !remainder.ends_with(last)
    {
        return false;
    }
    true
}

pub fn default_plugin_name() -> String {
    crate::AUTHZ_POLICY_KIND_TOML.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn policy(contents: &str) -> Result<Policy> {
        Policy::from_toml(contents)
    }

    pub(super) fn url(value: &str) -> Url {
        address::parse(value).unwrap()
    }

    #[test]
    fn empty_policy_denies() {
        let policy = Policy::from_config(TomlPolicyConfig::default()).unwrap();
        let decision = policy.evaluate("alice", Operation::Read, Some(&url("file:/root/a.txt")));
        assert!(!decision.is_allow());
    }

    #[test]
    fn allow_and_deny_matching() {
        let policy = policy(
            r#"
            [[policy]]
            id = "allow-team"
            effect = "allow"
            principal = "team-*"
            operations = ["read"]
            prefix = "file:/root/"

            [[policy]]
            id = "deny-secret"
            effect = "deny"
            principal = "team-*"
            operations = ["read"]
            prefix = "file:/root/secret/"
            "#,
        )
        .unwrap();

        assert!(policy.is_allowed(
            "team-alice",
            Operation::Read,
            Some(&url("file:/root/a.txt"))
        ));
        let denied = policy.evaluate(
            "team-alice",
            Operation::Read,
            Some(&url("file:/root/secret/a.txt")),
        );
        assert!(!denied.is_allow());
        assert_eq!(denied.explanation.as_deref(), Some("deny-secret"));
    }

    #[test]
    fn wildcard_principal_and_operation_match() {
        let policy = policy(
            r#"
            [[policy]]
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "*"
            "#,
        )
        .unwrap();

        assert!(policy.is_allowed("anyone", Operation::Delete, Some(&url("s3://bucket/key"))));
    }

    #[test]
    fn longest_prefix_precedence_wins() {
        let policy = policy(
            r#"
            [[policy]]
            id = "allow-root"
            effect = "allow"
            principal = "alice"
            operations = ["read"]
            prefix = "file:/root/"

            [[policy]]
            id = "deny-narrow"
            effect = "deny"
            principal = "alice"
            operations = ["read"]
            prefix = "file:/root/narrow/"
            "#,
        )
        .unwrap();

        let decision = policy.evaluate(
            "alice",
            Operation::Read,
            Some(&url("file:/root/narrow/a.txt")),
        );
        assert!(!decision.is_allow());
        assert_eq!(decision.explanation.as_deref(), Some("deny-narrow"));
    }

    #[test]
    fn later_rule_wins_for_same_prefix() {
        let policy = policy(
            r#"
            [[policy]]
            id = "first"
            effect = "deny"
            principal = "alice"
            operations = ["read"]
            prefix = "file:/root/"

            [[policy]]
            id = "second"
            effect = "allow"
            principal = "alice"
            operations = ["read"]
            prefix = "file:/root/"
            "#,
        )
        .unwrap();

        let decision = policy.evaluate("alice", Operation::Read, Some(&url("file:/root/a.txt")));
        assert!(decision.is_allow());
        assert_eq!(decision.explanation.as_deref(), Some("second"));
    }

    #[test]
    fn invalid_operation_fails_validation() {
        let error = policy(
            r#"
            [[policy]]
            effect = "allow"
            principal = "*"
            operations = ["fly"]
            prefix = "*"
            "#,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn wildcard_operation_must_stand_alone() {
        let error = policy(
            r#"
            [[policy]]
            effect = "allow"
            principal = "*"
            operations = ["*", "read"]
            prefix = "*"
            "#,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn invalid_prefix_fails_validation() {
        let error = policy(
            r#"
            [[policy]]
            effect = "allow"
            principal = "*"
            operations = ["read"]
            prefix = "not-an-address"
            "#,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn invalid_effect_fails_deserialization() {
        let error = toml::from_str::<TomlPolicyConfig>(
            r#"
            [[policy]]
            effect = "maybe"
            principal = "*"
            operations = ["read"]
            prefix = "*"
            "#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown variant"));
    }

    #[test]
    fn unknown_plugin_is_rejected() {
        let error = Policy::from_toml(
            r#"
            plugin = "some-other-plugin"
            "#,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unsupported);
    }

    #[test]
    fn decision_ttl_round_trips_into_policy() {
        let policy = policy(
            r#"
            decision_ttl_max_seconds = 30

            [[policy]]
            id = "allow-alice"
            effect = "allow"
            principal = "alice"
            operations = ["read"]
            prefix = "file:/root/"
            "#,
        )
        .unwrap();
        assert_eq!(policy.decision_ttl(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn address_none_only_matches_wildcard_prefix() {
        let policy = policy(
            r#"
            [[policy]]
            id = "concrete"
            effect = "allow"
            principal = "alice"
            operations = ["list_address_roots"]
            prefix = "file:/root/"

            [[policy]]
            id = "wildcard"
            effect = "allow"
            principal = "ops-*"
            operations = ["list_address_roots"]
            prefix = "*"
            "#,
        )
        .unwrap();

        assert!(!policy.is_allowed("alice", Operation::ListAddressRoots, None));
        let ops = policy.evaluate("ops-bob", Operation::ListAddressRoots, None);
        assert!(ops.is_allow());
        assert_eq!(ops.explanation.as_deref(), Some("wildcard"));
    }

    #[test]
    fn glob_match_variants() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "team-alice"));
        assert!(glob_match("*foo", "barfoo"));
        assert!(!glob_match("*foo", "fooBAR"));
        assert!(glob_match("foo*", "foobar"));
        assert!(!glob_match("foo*", "barfoo"));
        assert!(glob_match("*foo*", "xyfoozz"));
        assert!(!glob_match("*foo*", "fxooz"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "abcd"));
        assert!(glob_match("a**b", "axb"));
        assert!(glob_match("alice", "alice"));
        assert!(!glob_match("alice", "alicebob"));
    }
}

#[cfg(test)]
mod component_matcher_tests {
    use super::tests::{policy, url};
    use super::*;

    /// `has_prefix` must rank above segment count, and this catch-all ships
    /// in-tree (`authz-layer/src/lib.rs`, `rest/src/main.rs`,
    /// `broker/src/lifecycle.rs`). A `prefix = "*"` rule has no prefix at all,
    /// so it counts zero segments — and under segment counting alone *every
    /// host-root prefix also counts zero*, which would let `allow *` tie with
    /// and then outrank `deny s3://corp/` on declaration order.
    #[test]
    fn a_catch_all_allow_does_not_outrank_a_host_root_deny() {
        let policy = policy(
            r#"
            [[policy]]
            id = "deny-corp"
            effect = "deny"
            principal = "*"
            operations = ["*"]
            prefix = "s3://corp/"

            [[policy]]
            id = "allow-all"
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "*"
            "#,
        )
        .unwrap();
        assert!(
            !policy
                .evaluate("alice", Operation::Read, Some(&url("s3://corp/secret")))
                .is_allow(),
            "the host-root deny must win over the catch-all allow"
        );
    }

    /// Byte length must not participate in the ranking — asserted as an
    /// **outcome**, through a policy that actually loads.
    ///
    /// The previous version ran two spellings of one scope through
    /// `parse_prefix` and compared `prefix_segments()`. `address::parse`
    /// decodes `%70` to `p`, so both rules held the byte-identical canonical
    /// string and the assertion was `2 == 2` — equally true under the byte
    /// length it was written to rule out, and `matching_rule` was never called.
    ///
    /// Nesting normally makes the two metrics agree, since a covering ancestor
    /// is usually the shorter string. **Userinfo is the exception**:
    /// `covers_with_host_semantics` ignores it, so a shallow rule can carry
    /// credentials and be far longer than a deep rule that also covers the
    /// address. `https://reader:secret@h/team/` is 30 bytes at depth 1;
    /// `https://h/team/reports/` is 23 at depth 2. Byte length prefers the
    /// shallow allow, depth prefers the deep deny.
    ///
    /// Deliberately not a trailing-slash pair: those tie on depth and fall
    /// through to declaration order, so the assertion would pin `max_by_key`'s
    /// last-maximum rather than the metric, and `reject_co_matching_equal_scopes`
    /// refuses to load them anyway. This fixture loads, ties on nothing, and
    /// gives the same answer in either declaration order.
    #[test]
    fn byte_length_does_not_decide_which_rule_applies() {
        // The userinfo sits on the DENY: a credential-bearing ALLOW is refused
        // at load, because dropping userinfo from the comparison widens it.
        // Userinfo is still what makes the shallow prefix the longer string,
        // which is the whole point of the fixture.
        for (first, second) in [
            ("deny-shallow", "allow-deep"),
            ("allow-deep", "deny-shallow"),
        ] {
            let rule = |id: &str| match id {
                "deny-shallow" => ("deny-shallow", "deny", "https://reader:secret@h/team/"),
                _ => ("allow-deep", "allow", "https://h/team/reports/"),
            };
            let (first_id, first_effect, first_prefix) = rule(first);
            let (second_id, second_effect, second_prefix) = rule(second);
            assert!(
                first_prefix.len() != second_prefix.len(),
                "the fixture must differ in byte length"
            );

            let policy = policy(&format!(
                r#"
                [[policy]]
                id = "{first_id}"
                effect = "{first_effect}"
                principal = "*"
                operations = ["*"]
                prefix = "{first_prefix}"

                [[policy]]
                id = "{second_id}"
                effect = "{second_effect}"
                principal = "*"
                operations = ["*"]
                prefix = "{second_prefix}"
                "#
            ))
            .expect("the fixture must be a policy that loads");

            let selected = policy
                .matching_rule(
                    "alice",
                    Operation::Read,
                    Some(&url("https://h/team/reports/q3.pdf")),
                )
                .expect("one of the two rules covers the address");
            assert_eq!(
                selected.id, "allow-deep",
                "the deeper scope must win; under byte length the userinfo-bearing \
                 shallow deny is the longer string and would win in either order \
                 (declared {first_id} first)"
            );
        }
    }

    /// `Policy` canonicalizes what it evaluates, so every call site inherits it.
    ///
    /// The matcher compares decoded path components, which leaves two shapes it
    /// cannot resolve on its own: a dot segment hidden behind an encoded
    /// separator, and a doubled separator. Both are handed straight to the
    /// policy by any caller below the `Stack` boundary.
    ///
    /// The assertion is deliberately made through **both** `evaluate` and
    /// `is_allowed`, because the second is what the post-filters call —
    /// `filter_list_batch` for a listing page, `is_root_visible` for route
    /// visibility, `apply_authz_access_decision` for `check_access`, and the
    /// per-event `watch_directory` filter. They reach the matcher without
    /// passing through the layer's gate, so if canonicalization lived at the
    /// gate instead of here, a listing filter would judge the raw spelling
    /// while the gate judged the canonical one.
    #[test]
    fn evaluation_canonicalizes_the_address_for_every_call_site() {
        let policy = policy(
            r#"
            [[policy]]
            id = "allow-root"
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "file:///root/"

            [[policy]]
            id = "deny-private"
            effect = "deny"
            principal = "*"
            operations = ["*"]
            prefix = "file:///root/private/"
            "#,
        )
        .unwrap();

        // The control: the plain spelling is denied, so the deny is live.
        assert!(
            !policy.is_allowed(
                "alice",
                Operation::Read,
                Some(&url("file:///root/private/secret.txt"))
            ),
            "the plain spelling must be denied, or the rows below prove nothing"
        );

        for raw in [
            "file:///root/public%2F%2E%2E%2Fprivate%2Fsecret.txt",
            "file:///root//private/secret.txt",
        ] {
            // `Url::parse`, not the canonicalizing `url` helper: this is the
            // spelling a caller below the boundary supplies.
            let raw = Url::parse(raw).unwrap();
            assert!(
                !policy
                    .evaluate("alice", Operation::Read, Some(&raw))
                    .is_allow(),
                "evaluate must resolve {raw} onto the denied node"
            );
            assert!(
                !policy.is_allowed("alice", Operation::Read, Some(&raw)),
                "is_allowed must resolve {raw} onto the denied node"
            );
        }
    }

    /// A rule scope matches segment-wise, so it cannot cover a sibling whose
    /// name merely starts with it.
    #[test]
    fn a_scope_does_not_cover_a_longer_sibling_name() {
        let scope = url("s3://b/docs");
        assert!(scope_covers(&scope, &url("s3://b/docs"), Effect::Deny));
        assert!(scope_covers(&scope, &url("s3://b/docs/x"), Effect::Deny));
        assert!(!scope_covers(&scope, &url("s3://b/docsx"), Effect::Deny));
        assert!(!scope_covers(&scope, &url("s3://b/docsx/y"), Effect::Deny));
    }

    /// A rule on a path covers every version pin of it. Authorization is
    /// strictly coarser than node identity, which is the safe direction.
    #[test]
    fn a_scope_covers_every_query_on_the_path() {
        let scope = url("s3://b/private/x");
        for spelling in [
            "s3://b/private/x?versionId=1",
            "s3://b/private/x?versionId=secret&versionId=public",
            "s3://b/private/x?other=1&versionId=secret",
        ] {
            assert!(
                scope_covers(&scope, &url(spelling), Effect::Deny),
                "{spelling}"
            );
        }
    }

    /// A `deny` on a path refuses a query-bearing request for that path —
    /// asserted through `evaluate`, not through `scope_covers`.
    ///
    /// [`scope_covers`]'s own doc states this as a property: authorization
    /// ignores the query, which makes it strictly **coarser** than node
    /// identity — it can cover more objects than a pin-aware rule would, never
    /// fewer. A doc comment is a claim, and on this project a self-justifying
    /// one about the matcher hid an authorization escape through three review
    /// panels, so the claim is pinned as a fact at the layer that decides.
    ///
    /// The direction is what matters. A version pin is caller-supplied, so if
    /// it could put an address outside a `deny`, appending `?versionId=…` to
    /// any denied address would be a bypass. The `allow` row asserts the other
    /// half: the same coarseness applies there, which is the cost of the rule
    /// and the reason it is stated rather than hidden.
    ///
    /// Load-bearing line: the `prefix.query()`-blind comparison in
    /// `scope_covers` — it compares scheme, host, port and path and nothing
    /// else. A matcher that started reading the query turns the deny rows red
    /// while leaving the query-free row green.
    #[test]
    fn a_deny_on_a_path_refuses_every_query_on_it() {
        let policy = policy(
            r#"
            [[policy]]
            id = "allow-all"
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "*"

            [[policy]]
            id = "deny-private"
            effect = "deny"
            principal = "*"
            operations = ["*"]
            prefix = "s3://b/private/x"
            "#,
        )
        .expect("the policy must load");

        // The plain spelling is denied, so the rows below are not passing
        // because nothing matched.
        assert!(
            !policy
                .evaluate("alice", Operation::Read, Some(&url("s3://b/private/x")))
                .is_allow(),
            "the unpinned address must be denied, or this test proves nothing"
        );

        for spelling in [
            "s3://b/private/x?versionId=1",
            "s3://b/private/x?versionId=secret&versionId=public",
            "s3://b/private/x?other=1&versionId=secret",
            "s3://b/private/x?",
        ] {
            assert!(
                !policy
                    .evaluate("alice", Operation::Read, Some(&url(spelling)))
                    .is_allow(),
                "a caller-chosen version pin must not escape the deny: {spelling}"
            );
        }

        // A sibling the deny does not name is still allowed, so the deny is
        // scoped rather than swallowing the bucket.
        assert!(
            policy
                .evaluate("alice", Operation::Read, Some(&url("s3://b/private/y")))
                .is_allow(),
            "the deny must not cover a sibling it does not name"
        );
    }

    /// Userinfo is carried and never consulted, so a policy prefix written with
    /// credentials scopes addresses rather than principals.
    #[test]
    fn userinfo_is_not_part_of_the_scope() {
        assert!(scope_covers(
            &url("https://reader:one@h/private/"),
            &url("https://writer:two@h/private/x"),
            Effect::Deny
        ));
    }

    /// Two case spellings of one `file:` scope are one scope on a folding host,
    /// so the collision check must see them under the same widening the matcher
    /// uses.
    ///
    /// The collision predicate compared unwidened segments while the matcher
    /// folds case for a deny. Measured on the pair below with the host flag
    /// forced on: `deny file:///root/PRIVATE/` and `allow file:///root/private/`
    /// both cover `file:///root/private/secret`, both pin two segments, so the
    /// rank tuple ties at `(true, 2, order)` and `max_by_key` hands the verdict
    /// to the later-declared rule — the allow. The deny is silently defeated
    /// unless the operator happens to declare it last. On
    /// `file:///root/PRIVATE/secret` the unfolded allow does not match at all
    /// and the deny wins, so one policy gave one node two verdicts selected by
    /// how the caller spelled the request.
    ///
    /// The host flag is forced rather than read from `HOST_FOLDS_FILE_PATHS`
    /// so this runs on the Linux CI leg, like
    /// `windows_semantics_close_the_backslash_and_case_bypass`. The
    /// `fold = false` half is the control: off a folding host the two names are
    /// genuinely two directories and the check must not fire.
    ///
    /// **The two rules are built directly rather than loaded from TOML, and
    /// that is what makes the test host-independent.** `Policy::from_config`
    /// calls this same check with `HOST_FOLDS_FILE_PATHS`, so on Windows the
    /// loader would refuse the fixture and the test would die at its fixture
    /// instead of at its assertion — green off Windows, red on Windows, for a
    /// reason unrelated to what it measures.
    #[test]
    fn two_case_spellings_of_one_file_scope_fail_to_load_on_a_folding_host() {
        let rules = vec![
            Rule {
                id: "deny-priv".into(),
                effect: Effect::Deny,
                principal: "*".into(),
                operations: None,
                prefix: Some(url("file:///root/PRIVATE/")),
                prefix_written: Some("file:///root/PRIVATE/".into()),
                order: 0,
            },
            Rule {
                id: "allow-priv".into(),
                effect: Effect::Allow,
                principal: "*".into(),
                operations: None,
                prefix: Some(url("file:///root/private/")),
                prefix_written: Some("file:///root/private/".into()),
                order: 1,
            },
        ];
        // The fixture must carry two DISTINCT spellings, or everything below is
        // vacuous: byte-identical prefixes take the ordered-override path and
        // are skipped by this check entirely.
        assert_ne!(
            rules[0].prefix.as_ref().map(Url::as_str),
            rules[1].prefix.as_ref().map(Url::as_str)
        );

        // The defect, stated as the assertion that fails without the widening:
        // on a folding host the pair must be refused.
        let error = reject_co_matching_equal_scopes(&rules, true)
            .expect_err("on a folding host these are one scope and must not load");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);

        // The control. `fold = false` is the only difference, so a green here
        // with a red above isolates the widening rather than the pair.
        reject_co_matching_equal_scopes(&rules, false)
            .expect("off a folding host the pair is two distinct scopes");

        // And the reason it matters: with the fold on, the deny covers the
        // lower-case request that the allow also covers exactly, so the two
        // tie on rank and declaration order decides the verdict.
        let deny = url("file:///root/PRIVATE/");
        let allow = url("file:///root/private/");
        let target = url("file:///root/private/secret");
        assert!(covers_with_host_semantics(
            &deny,
            &target,
            true,
            Effect::Deny
        ));
        assert!(covers_with_host_semantics(
            &allow,
            &target,
            true,
            Effect::Allow
        ));
        assert_eq!(
            rules[0].prefix_segments(),
            rules[1].prefix_segments(),
            "the rank ties, which is why declaration order would decide"
        );
    }

    /// The duplicate exemption is keyed on the WRITTEN prefix, not the parsed
    /// one, so canonicalization cannot smuggle a pair into it.
    ///
    /// The exemption exists for a prefix an operator wrote twice, which is how
    /// a later rule deliberately supersedes an earlier one. Keyed on the parsed
    /// `Url` it also caught every pair canonicalization collapses. Measured
    /// before the fix, with the escape acknowledgement the migration gate
    /// forces an operator to set: `deny s3://b/private/` declared before
    /// `allow s3://b/%70rivate/` both held `s3://b/private/`, the pair was
    /// skipped, both covered `s3://b/private/x` pinning one segment each, and
    /// the rank tie handed the verdict to the later allow — `allow=true`, by
    /// rule `allow-encoded`. `main` denied that request, because its serialized
    /// matcher never matched `%70rivate` against `private`. A silent
    /// deny-to-allow flip, through the one exemption meant to be deliberate.
    #[test]
    fn canonicalization_cannot_smuggle_a_pair_into_the_duplicate_exemption() {
        // Encoded versus plain, which canonicalization collapses.
        let error = policy(
            r#"
            prefix_escapes_are_decoded = true

            [[policy]]
            id = "deny-priv"
            effect = "deny"
            principal = "*"
            operations = ["*"]
            prefix = "s3://b/private/"

            [[policy]]
            id = "allow-encoded"
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "s3://b/%70rivate/"
            "#,
        )
        .expect_err("two spellings of one scope must not take the duplicate exemption");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.message().contains("'deny-priv'") && error.message().contains("'allow-encoded'"),
            "must be refused by the collision check, which is the only \
             diagnostic naming both rules, got: {}",
            error.message()
        );

        // A bare authority against its trailing-slash spelling, which
        // canonicalization also collapses.
        let error = policy(
            r#"
            [[policy]]
            id = "d"
            effect = "deny"
            principal = "*"
            operations = ["*"]
            prefix = "s3://b"

            [[policy]]
            id = "a"
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "s3://b/"
            "#,
        )
        .expect_err("`s3://b` and `s3://b/` are one scope in two spellings");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        // The message, not just the code: without this the row stays green if
        // some future `parse_prefix` rule starts rejecting a bare authority,
        // and it would then be testing that rule instead of the exemption.
        assert!(
            error.message().contains("'d'") && error.message().contains("'a'"),
            "must be refused by the collision check, which is the only \
             diagnostic naming both rules, got: {}",
            error.message()
        );
        // The message must NOT try to distinguish the pair by printing both
        // spellings: `Error` re-serializes a URL-like token, so for a
        // default-port or host-case pair both would render identically and the
        // message would contradict itself. It names the two rule ids instead.
        assert!(
            error.message().contains("'d'") && error.message().contains("'a'"),
            "the message must name both rule ids, got: {}",
            error.message()
        );

        // The control, and it is what keeps the exemption alive: a prefix
        // written IDENTICALLY twice is still the deliberate ordered override,
        // and the later rule still wins. Without this the fix would read as
        // "refuse every co-matching pair", which is a different change.
        let loaded = policy(
            r#"
            [[policy]]
            id = "first"
            effect = "deny"
            principal = "*"
            operations = ["*"]
            prefix = "s3://b/x/"

            [[policy]]
            id = "second"
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "s3://b/x/"
            "#,
        )
        .expect("a byte-identical duplicate is a deliberate override and must load");
        let decision = loaded.evaluate("alice", Operation::Read, Some(&url("s3://b/x/y")));
        assert!(decision.is_allow(), "the later rule must still win");
        assert_eq!(decision.explanation.as_deref(), Some("second"));
    }

    /// Disjoint wildcard principals must not turn a node-equivalent prefix pair
    /// into a refusal to start.
    ///
    /// `principals_intersect` answered "possibly overlapping" for any two
    /// patterns containing a wildcard. That was free while it only widened a
    /// warning, and stopped being free once the collision check turned a
    /// claimed intersection into a load error: `allow team-* s3://b/team`
    /// beside `allow svc-* s3://b/team/` — two spellings of one scope, two
    /// principal namespaces that cannot both match anything — refused to load,
    /// so a broker upgrading to this version would not start. `team-*` is the
    /// pattern this repo's own examples use.
    #[test]
    fn disjoint_wildcard_principals_do_not_collide() {
        let loaded = policy(
            r#"
            [[policy]]
            id = "team"
            effect = "allow"
            principal = "team-*"
            operations = ["read"]
            prefix = "s3://b/team"

            [[policy]]
            id = "svc"
            effect = "allow"
            principal = "svc-*"
            operations = ["read"]
            prefix = "s3://b/team/"
            "#,
        )
        .expect("`team-*` and `svc-*` cannot both match one principal");
        assert_eq!(loaded.rules.len(), 2);
        // And the rules still work: each principal reaches the scope, and the
        // other pattern does not decide for it.
        assert!(
            loaded
                .evaluate("team-a", Operation::Read, Some(&url("s3://b/team/x")))
                .is_allow()
        );
        assert!(
            !loaded
                .evaluate("other", Operation::Read, Some(&url("s3://b/team/x")))
                .is_allow()
        );

        // The proof is `literal*` against `literal*`, and only that shape.
        assert!(!principals_intersect("team-*", "svc-*"));
        assert!(principals_intersect("team-*", "team-a*"));
        // A bare `*` matches everything, so it overlaps every pattern.
        assert!(principals_intersect("*", "team-*"));
        // Two wildcards that overlap only through a third value keep the
        // conservative answer — `team-alice` matches both.
        assert!(principals_intersect("team-*", "*-alice"));

        // A pair that still collides must SAY the intersection was assumed,
        // or the operator is told to fix the prefix spelling when the real
        // cause is the wildcard assumption.
        let error = policy(
            r#"
            [[policy]]
            id = "one"
            effect = "deny"
            principal = "team-*"
            operations = ["read"]
            prefix = "s3://b/team"

            [[policy]]
            id = "two"
            effect = "allow"
            principal = "*-alice"
            operations = ["read"]
            prefix = "s3://b/team/"
            "#,
        )
        .expect_err("`team-*` and `*-alice` can both match `team-alice`");
        assert!(
            error.message().contains("treated as possibly overlapping"),
            "the message must disclose the assumption, got: {}",
            error.message()
        );
    }

    /// Two spellings of one scope that can decide the same request fail to
    /// load. Under segment ranking they tie, so the winner would fall through
    /// to declaration order — flipping a live deny into an allow silently,
    /// because byte length used to break that tie.
    #[test]
    fn two_spellings_of_one_scope_fail_to_load() {
        let error = policy(
            r#"
            [[policy]]
            id = "deny-priv"
            effect = "deny"
            principal = "*"
            operations = ["*"]
            prefix = "file:///root/private/"

            [[policy]]
            id = "allow-priv"
            effect = "allow"
            principal = "alice"
            operations = ["read"]
            prefix = "file:///root/private"
            "#,
        )
        .expect_err("two spellings of one scope must not load");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.message().contains("same scope"),
            "the error must name the problem, got {}",
            error.message()
        );
    }

    /// The check is scoped to rules that can decide the same request. Disjoint
    /// principals mean the two rules never race, so an ordinary policy that
    /// happens to spell one scope two ways still loads.
    #[test]
    fn disjoint_principals_may_spell_one_scope_two_ways() {
        policy(
            r#"
            [[policy]]
            id = "admin-rw"
            effect = "allow"
            principal = "admin"
            operations = ["*"]
            prefix = "s3://corp/team"

            [[policy]]
            id = "guest-ro"
            effect = "deny"
            principal = "guest"
            operations = ["write"]
            prefix = "s3://corp/team/"
            "#,
        )
        .expect("disjoint principals do not race");
    }

    /// Byte-identical duplicates keep ordered-override semantics: that is how a
    /// later rule deliberately supersedes an earlier one.
    #[test]
    fn byte_identical_duplicates_still_load() {
        let policy = policy(
            r#"
            [[policy]]
            id = "first"
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "file:///root/"

            [[policy]]
            id = "second"
            effect = "deny"
            principal = "*"
            operations = ["*"]
            prefix = "file:///root/"
            "#,
        )
        .expect("byte-identical duplicates are ordered override, not ambiguity");
        assert!(
            !policy
                .evaluate("alice", Operation::Read, Some(&url("file:///root/x")))
                .is_allow(),
            "the later rule must win"
        );
    }

    /// A prefix that resolves somewhere other than it spells fails to load.
    ///
    /// `allow s3://corp/secret/../` reads as scoped to `corp/secret` and is in
    /// fact the entire bucket — the same silent widening the query and fragment
    /// checks exist to prevent, wearing a more innocent spelling.
    #[test]
    fn a_prefix_that_resolves_elsewhere_fails_to_load() {
        for prefix in [
            "s3://corp/secret/../",
            "s3://corp/./",
            "s3://corp/%2E%2E/",
            "s3://corp//",
            "s3://corp/secret/..",
        ] {
            let error = policy(&format!(
                r#"
                [[policy]]
                id = "r"
                effect = "allow"
                principal = "*"
                operations = ["*"]
                prefix = "{prefix}"
                "#
            ))
            .err()
            .unwrap_or_else(|| panic!("{prefix} must not load"));
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{prefix}");
        }
    }

    /// Every spelling of a resolving prefix is refused, not just the one the
    /// first implementation happened to test.
    ///
    /// Each row loaded before, and the first is the worst thing in this file's
    /// history: `file:/root/%2E%2E/` has no `://`, so the check was skipped
    /// entirely and the rule loaded with scope `file:///` — allow everything,
    /// every principal, every operation, while reading as scoped under `/root`.
    #[test]
    fn resolving_prefixes_are_refused_in_every_spelling() {
        for prefix in [
            // No authority: the check keyed on `://` and skipped these.
            "file:/root/%2E%2E/",
            "file:/root/secret/../",
            "file:/root/./",
            // A separator hidden as %2F: one raw segment decoding to two.
            "s3://corp/secret/%2E%2E%2F",
            "s3://corp/a%2F%2E%2E%2Fb/",
            "s3://corp/%2E%2F",
            // A backslash traversal, refused on every host so a policy that
            // loads in Linux CI cannot fail on the Windows machine serving it.
            "file:///c:/root/public%5C..%5Cprivate/",
            "file:///c:/root/public%5C%2E%2E%5Cprivate/",
            // The spellings that already worked.
            "s3://corp/secret/../",
            "s3://corp//",
        ] {
            let error = policy(&format!(
                r#"
                [[policy]]
                id = "r"
                effect = "allow"
                principal = "*"
                operations = ["*"]
                prefix = "{prefix}"
                "#
            ))
            .err()
            .unwrap_or_else(|| panic!("{prefix} must not load"));
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{prefix}");
        }
    }

    /// Two globs can overlap through a third value even when neither matches
    /// the other, so disjointness must be proved rather than assumed.
    ///
    /// `team-*` and `*-alice` both match `team-alice`. Testing `glob_match`
    /// both ways says "disjoint", which loaded the exact deny-to-allow flip the
    /// co-matching check exists to prevent — reachable with a one-character
    /// change to a principal.
    #[test]
    fn principals_overlapping_through_a_third_value_are_not_called_disjoint() {
        for (a, b, witness) in [
            ("a*", "*b", "ab"),
            ("team-*", "*-alice", "team-alice"),
            ("a*c", "ab*", "abc"),
            ("svc-*-eu", "*-prod-*", "svc-prod-eu"),
        ] {
            assert!(
                glob_match(a, witness) && glob_match(b, witness),
                "{witness} must be matched by both patterns, or the case is wrong"
            );
            assert!(
                principals_intersect(a, b),
                "{a} and {b} both match {witness} and must be treated as intersecting"
            );
        }

        // Still provably disjoint: a literal that the other pattern misses.
        assert!(!principals_intersect("admin", "guest"));
        assert!(!principals_intersect("admin", "team-*"));
    }

    /// The flip must not load through non-obvious principal patterns.
    #[test]
    fn two_spellings_of_one_scope_fail_to_load_through_overlapping_globs() {
        let error = policy(
            r#"
            [[policy]]
            id = "deny-priv"
            effect = "deny"
            principal = "team-*"
            operations = ["*"]
            prefix = "file:///root/private/"

            [[policy]]
            id = "allow-priv"
            effect = "allow"
            principal = "*-alice"
            operations = ["*"]
            prefix = "file:///root/private"
            "#,
        )
        .expect_err("overlapping globs still race over one scope");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    /// A leading `\` must not strand an empty segment, which made a prefix
    /// carrying one inert and let a request carrying one escape a deny.
    /// **The PREFIX spelling here is refused at load** — `parse_prefix` rejects
    /// `%5C` in a `file:` prefix — so this pins matcher behaviour for a rule
    /// state no loaded policy can hold, and exists to keep that behaviour
    /// correct if the guard is ever relaxed. The **target** side is the
    /// reachable half: a request address may carry `%5C` freely, and that is
    /// what the assertions below actually exercise against a real policy.
    #[test]
    fn a_leading_backslash_does_not_strand_an_empty_segment() {
        let deny = url("file://server/%5Cshare/private/");
        assert!(
            covers_with_host_semantics(
                &deny,
                &url("file://server/share/private/secret"),
                true,
                Effect::Deny
            ),
            "the prefix must cover the spellings callers actually send"
        );

        let ordinary = url("file://server/share/private/");
        assert!(
            covers_with_host_semantics(
                &ordinary,
                &url("file://server/%5Cshare/private/secret"),
                true,
                Effect::Deny
            ),
            "a leading backslash in the request must not escape the deny"
        );
    }

    /// Cosmetic normalization is not resolution. These name the node they
    /// spell, so refusing them would reject prefixes that work today.
    #[test]
    fn cosmetically_normalized_prefixes_still_load() {
        for prefix in ["s3://CORP/secret/", "omniverse://H/team/"] {
            policy(&format!(
                r#"
                [[policy]]
                id = "r"
                effect = "allow"
                principal = "*"
                operations = ["*"]
                prefix = "{prefix}"
                "#
            ))
            .unwrap_or_else(|error| panic!("{prefix} must load: {error}"));
        }
    }

    /// An escaped separator changes a rule's breadth on upgrade, silently and
    /// in the dangerous direction, so it fails to load.
    ///
    /// `s3://b/team%2Fsub` scoped one literal key under the old serialized
    /// matcher; the component matcher decodes it and scopes the whole subtree.
    /// `s3://b/team%2F` is the worse one — it decodes to `/team/`, whose only
    /// empty segment is trailing, which the dot-segment check deliberately does
    /// not flag, so an allow over one key became an allow over the subtree with
    /// no diagnostic. `%5C` does the same on `file:`, where the Windows fold
    /// makes a backslash a separator, and must NOT be rejected elsewhere: on a
    /// storage scheme a backslash is an ordinary character in a key.
    #[test]
    fn an_escaped_separator_in_a_prefix_fails_to_load() {
        for prefix in [
            "s3://b/team%2Fsub",
            "s3://b/team%2F",
            "s3://b/team%2f",
            "file:///root/team%5Csub",
        ] {
            // Acknowledged, so the escaped-separator check is what refuses
            // these rather than the retargeting gate that runs before it.
            let error = policy(&format!(
                r#"
                prefix_escapes_are_decoded = true

                [[policy]]
                id = "r"
                effect = "allow"
                principal = "*"
                operations = ["*"]
                prefix = "{prefix}"
                "#
            ))
            .expect_err("{prefix} must fail to load");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{prefix}");
            assert!(
                error.message().contains("escaped separator"),
                "{prefix} must be refused for its separator, not merely for carrying \
                 an escape: {}",
                error.message()
            );
        }

        // Two controls, both load bearing.
        for prefix in [
            // A backslash is an ordinary character in an object key, so
            // rejecting `%5C` on a storage scheme would refuse a legitimate
            // scope.
            "s3://b/team%5Csub",
            // The check reads the PATH. An escaped separator in userinfo is an
            // ordinary character in a credential and is never consulted by the
            // matcher, so refusing it rejects a well-spelled scope — and since
            // `Error` redacts userinfo, the operator would read a message
            // naming an escape their prefix appears not to contain.
            "s3://user%2Fname@b/key",
        ] {
            policy(&format!(
                r#"
                prefix_escapes_are_decoded = true

                [[policy]]
                id = "r"
                effect = "deny"
                principal = "*"
                operations = ["*"]
                prefix = "{prefix}"
                "#
            ))
            .unwrap_or_else(|error| panic!("{prefix} must load: {}", error.message()));
        }
    }

    /// An escape-bearing prefix retargets a live rule, so it fails closed until
    /// the operator says they have re-read it.
    ///
    /// This is the exact upgrade shape: a parent allow, a deny naming one
    /// object with an escape, and a request for the object that deny used to
    /// protect. Under the old serialized matcher `deny s3://b/100%25` protected
    /// the literal key `100%25`; it now protects `100%`, and the old object is
    /// spelled `s3://b/100%2525`, which the parent allow covers. Measured — the
    /// deny does NOT cover it — which is why the load has to stop rather than
    /// let the rule quietly move.
    #[test]
    fn an_escape_bearing_prefix_retargets_a_rule_and_fails_closed() {
        const DOC: &str = r#"
            [[policy]]
            id = "allow-bucket"
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "s3://b/"

            [[policy]]
            id = "deny-one"
            effect = "deny"
            principal = "*"
            operations = ["*"]
            prefix = "s3://b/100%25"
        "#;

        let error = policy(DOC).expect_err("an unacknowledged retargeting must not load");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.message().contains("deny-one") && error.message().contains("now scopes 100%"),
            "the error must name the rule AND the scope it now resolves to; matching on \
             `b/100%` alone would be satisfied by the echoed prefix: {}",
            error.message()
        );
        assert!(
            !error.message().contains("allow-bucket"),
            "an escape-free rule must not be reported as affected: {}",
            error.message()
        );

        // Acknowledged, the policy loads — and the retargeting it warned about
        // is real: the object the deny used to protect is now reachable.
        let acknowledged = policy(&format!("prefix_escapes_are_decoded = true\n{DOC}"))
            .expect("acknowledgement lets the operator keep the rule as written");
        assert!(
            !acknowledged.is_allowed("alice", Operation::Read, Some(&url("s3://b/100%25"))),
            "the rule still denies the key it now names"
        );
        assert!(
            acknowledged.is_allowed("alice", Operation::Read, Some(&url("s3://b/100%2525"))),
            "and the formerly-protected object is reachable through the parent allow — \
             which is what the operator is acknowledging"
        );
    }

    /// Why the gate acknowledges rather than bans, demonstrated.
    ///
    /// **The structural reason is the strong one**: the old scope IS the
    /// serialized path, so a prefix moved exactly when that path carries a
    /// `%xx` — no escape-free spelling can reach a moved scope, and no rewrite
    /// preserves the old meaning. A ban would therefore not be a migration
    /// path, just a refusal.
    ///
    /// The second reason is that some scopes cannot be written without an
    /// escape at all, so a ban would make those objects impossible to deny.
    /// This measures two of them. It does NOT claim they are the only two —
    /// under the serialized-path predicate the set with no escape-free
    /// serialization also includes a space, `{`, `<`, every control byte and
    /// every non-ASCII character. An earlier version of this test named "two
    /// classes" and meant the much smaller written-spelling notion.
    #[test]
    fn some_scopes_cannot_be_written_without_an_escape() {
        // A byte that is not valid UTF-8. There is no character to type, and
        // the matcher is byte-exact precisely so `x%FF` and `x%FE` stay
        // distinct.
        let non_utf8 = url("file:///data/x%FF");
        assert_eq!(
            scope_segments(&non_utf8).unwrap().last().unwrap(),
            &vec![b'x', 0xFF],
            "the escape is the only way to name this byte"
        );

        // A literal `%` followed by two hex digits. Writing it raw is not a
        // spelling of it — the parser reads the escape and resolves it to
        // something else — so only the escaped escape names the scope.
        assert_eq!(
            scope_segments(&url("s3://b/100%25"))
                .unwrap()
                .last()
                .unwrap(),
            b"100%",
            "the raw-looking spelling names a DIFFERENT scope"
        );
        assert_eq!(
            scope_segments(&url("s3://b/100%2525"))
                .unwrap()
                .last()
                .unwrap(),
            b"100%25",
            "only the escaped escape names the literal scope"
        );

        // And a member of the larger set, to pin that the criterion is the
        // SERIALIZATION rather than what was typed: a space needs no escape to
        // write, and cannot be serialized without one.
        assert_eq!(
            Url::parse("s3://b/pub x").unwrap().path(),
            "/pub%20x",
            "the parser supplies the escape nobody typed"
        );
    }

    /// What the gate does and does not flag, measured against the OLD key.
    ///
    /// The predicate is "did the key move", and the key moved exactly when the
    /// **serialized** form of the prefix carried a percent-escape — because the
    /// old key was a raw slice of that serialization and the new key is the
    /// decoded path. Reading the RAW written string instead was wrong in both
    /// directions and is the mistake this table pins:
    ///
    /// | prefix | serialized | old key | new key | moved |
    /// |---|---|---|---|---|
    /// | `s3://b/plain` | `/plain` | `plain` | `plain` | no |
    /// | `s3://b/100%` | `/100%` | `100%` | `100%` | no |
    /// | `s3://b/pub x` | `/pub%20x` | `pub%20x` | `pub x` | **yes** |
    /// | `s3://b/a{b` | `/a%7Bb` | `a%7Bb` | `a{b` | **yes** |
    /// | `file:///C:/root/` | `/C:/root/` | `C:/root/` | `C:/root/` | no |
    /// | `file:///C%3A/root/` | `/C%3A/root/` | `C%3A/root/` | `C:/root/` | **yes** |
    ///
    /// A bare `%` really is exempt — `Url::parse` does not encode it, so the
    /// old and new keys are both `100%`. But a space or a brace is NOT, even
    /// though the operator wrote no escape, because the parser puts one in.
    #[test]
    fn the_gate_flags_exactly_the_prefixes_whose_key_moved() {
        let loads = |prefix: &str| {
            policy(&format!(
                r#"
                [[policy]]
                id = "r"
                effect = "deny"
                principal = "*"
                operations = ["*"]
                prefix = "{prefix}"
                "#
            ))
            .is_ok()
        };

        for exempt in [
            // No encoding anywhere: nothing moved.
            "s3://b/plain/",
            // A bare `%` is not an escape and is not encoded by the parser.
            "s3://b/100%",
            // An unencoded drive letter: `file:///C:/root/` keeps its colon in
            // the serialization, so its old key already read `C:`.
            "file:///C:/root/",
            // An escape in USERINFO is not part of the scope and never was.
            "s3://user%2Fname@b/key",
        ] {
            assert!(loads(exempt), "{exempt} did not move and must load");
        }

        for moved in [
            // Written with an escape.
            "s3://b/100%25",
            // Written WITHOUT one — the parser supplies it, and the old key
            // was the encoded form. These are the ones a raw-string predicate
            // missed, and `s3://b/pub x` was recommended as a safe rewrite.
            "s3://b/pub x",
            "s3://b/a{b",
            "file:///C%3A/root/",
        ] {
            assert!(!loads(moved), "{moved} moved and must be refused");
        }
    }

    /// A raw `\` on a WHATWG special scheme hid the path from every raw-string
    /// guard at once.
    ///
    /// `raw_prefix_path` scans the post-authority remainder for `/`, `?` or
    /// `#`. `file://C:\data\public\..` has none, so it returned `None` and the
    /// dot-segment check short-circuited, the escaped-separator check fell back
    /// to an empty path, and the retargeting gate saw nothing — while
    /// `Url::parse` normalized the spelling anyway. Measured, that prefix
    /// loaded with scope `file:///C:/data/`: an allow over the whole `data/`
    /// tree, reading as scoped to `data\public`.
    ///
    /// `file:` is not the only scheme that folds. Measured on the `https:` rows
    /// below before the guard covered them: `https://h/data\..\` loaded with
    /// scope `https://h/` — the entire host; `https://h\evil/data` loaded with
    /// path `/evil/data` while `raw_prefix_path` reported `/data`, so every
    /// guard read a path the rule did not have; and `https://h/team\sub`, which
    /// carries no dot segment at all, loaded scoped to the whole `team/sub/`
    /// subtree. `plugin-http` publishes `http`/`https` roots, so these are
    /// first-class policy prefixes.
    #[test]
    fn a_backslash_separator_cannot_hide_a_file_prefix_path() {
        for prefix in [
            // The dot segment that widens to the parent.
            r"file://C:\data\public\..",
            // The escaped separator the sibling check exists for.
            r"file://C:\data\team%2Fsub",
            // And a plain one, so the rejection is the spelling, not the payload.
            r"file://C:\data\public",
            // The fold in the PATH state, which widened to the whole host.
            r"https://h/data\..\",
            // The fold in the AUTHORITY state, which made every raw-string
            // guard inspect a different path than the rule ends up with.
            r"https://h\evil/data",
            // No dot segment, no escape: the plain operator error, which
            // silently scoped the whole subtree.
            r"https://h/team\sub",
            // The rest of the special set, so the list is not `file`+`https`.
            // Spelled WITHOUT a dot segment on purpose: with one, the
            // dot-segment check could refuse the row on its own and the scheme
            // list would go untested for these four.
            r"http://h/team\sub",
            r"ws://h/team\sub",
            r"wss://h/team\sub",
            r"ftp://h/team\sub",
        ] {
            let error = policy(&format!(
                r#"
                [[policy]]
                id = "r"
                effect = "allow"
                principal = "*"
                operations = ["*"]
                prefix = "{}"
                "#,
                prefix.replace('\\', "\\\\")
            ))
            .expect_err("a backslash-separated file prefix must not load");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{prefix}");
            // The MESSAGE, not just the code. Three checks in `parse_prefix`
            // refuse with `InvalidArgument`, so asserting the code alone lets
            // the dot-segment check cover for this one and the scheme list go
            // untested on every row that happens to carry a `..`.
            assert!(
                error.message().contains("using `\\` as a path separator"),
                "{prefix} must be refused BY THE BACKSLASH CHECK, got: {}",
                error.message()
            );
        }

        // The control: the `/` spelling of the same scope still loads, and a
        // backslash on a STORAGE scheme is an ordinary key byte, not a
        // separator, so it must not be caught by this.
        policy(
            r#"
            [[policy]]
            id = "r"
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "file:///c:/data/public/"
            "#,
        )
        .expect("the forward-slash spelling loads");

        // The negative control, and it is what keeps the guard from being
        // "reject every backslash". A non-special scheme is parsed opaquely:
        // `s3://b/data\..\` loads with scope `s3://b/data%5C..%5C`, which is
        // the literal key it spells, so refusing it would reject a well-formed
        // scope. If this half ever starts failing, the guard has stopped
        // discriminating and the rows above prove nothing about the fold.
        for prefix in [r"s3://b/data\..\", r"omniverse://h/data\..\"] {
            let loaded = policy(&format!(
                r#"
                [[policy]]
                id = "r"
                effect = "allow"
                principal = "*"
                operations = ["*"]
                prefix = "{}"
                "#,
                prefix.replace('\\', "\\\\")
            ))
            .expect("a backslash on a non-special scheme is an ordinary key byte");
            assert_eq!(
                loaded.rules[0].prefix.as_ref().map(Url::as_str),
                Some(prefix.replace('\\', "%5C").as_str()),
                "{prefix} must keep the backslash as a literal key byte"
            );
        }
    }

    /// The raw-string guards read the prefix as written; `Url::parse` does not.
    ///
    /// It trims leading and trailing C0 controls and spaces and removes every
    /// tab, LF and CR anywhere in the input, before deciding the scheme or the
    /// path. The whole raw-string guard family reads the wrong string
    /// together, which is why this is refused before any of them runs.
    ///
    /// **Not every row here is independently load-bearing, and the comment
    /// says so rather than implying otherwise.** With this check disabled,
    /// only the removal rows load — `s3://b/team/.<TAB>.` with scope
    /// `s3://b/`, the whole bucket, from a rule reading as scoped under
    /// `team`. The trim rows are then caught by the backslash check, which
    /// takes its scheme from the parsed URL. They stay because the message
    /// assertion pins which check refused them, and because a trimmed prefix
    /// is one whose raw and parsed forms disagree at all.
    #[test]
    fn whitespace_the_url_parser_removes_cannot_hide_a_prefix_path() {
        for prefix in [
            // THE load-bearing row: a tab that turns two raw segments into a
            // `..` only after the parser removes it. `s3:` is not special so
            // the backslash check cannot fire, and the raw segment is `.\t.`
            // so the dot-segment check cannot see it. Measured: this loads
            // with scope `s3://b/` — the WHOLE BUCKET — from a rule that reads
            // as scoped under `team`.
            "s3://b/team/.\t.",
            // The same with a carriage return, retargeting instead of widening.
            "s3://b/team/.\r./x",
            // And on a special scheme, where the sibling checks are also blind
            // to it: `/a/.\n./b` resolves to `/b`.
            "https://h/a/.\n./b",
            // Leading and trailing space. These are trimmed rather than
            // removed mid-string, so they cannot manufacture a dot segment;
            // they are refused because a trimmed prefix is one whose raw form
            // and parsed form disagree at all, which is the property every
            // other guard here depends on. See the mutation note below.
            " https://h/team/data\\..\\..\\",
            "https://h/team/data\\..\\..\\ ",
            // A tab inside the scheme, which no raw split can see.
            "htt\tps://h/team/data\\..\\..\\",
        ] {
            let error = policy(&format!(
                r#"
                [[policy]]
                id = "r"
                effect = "allow"
                principal = "alice"
                operations = ["read"]
                prefix = {}
                "#,
                // A TOML basic string, so the escapes above reach the parser
                // as the bytes they name rather than as backslash pairs.
                toml_basic_string(prefix)
            ))
            .expect_err("a prefix the parser rewrites must not load");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{prefix:?}");
            assert!(
                error.message().contains("whitespace")
                    || error.message().contains("tab, newline or carriage return"),
                "{prefix:?} must be refused by the whitespace check, got: {}",
                error.message()
            );
        }

        // The control, and it is the reason this check names three characters
        // rather than refusing every space. An INTERIOR space is preserved by
        // the parser as `%20`, so the raw and parsed forms agree about it and
        // the prefix names a real key.
        let loaded = policy(
            r#"
            prefix_escapes_are_decoded = true

            [[policy]]
            id = "r"
            effect = "allow"
            principal = "alice"
            operations = ["read"]
            prefix = "s3://b/pub x"
            "#,
        )
        .expect("an interior space is an ordinary key byte");
        assert_eq!(
            loaded.rules[0].prefix.as_ref().map(Url::as_str),
            Some("s3://b/pub%20x")
        );
    }

    /// A TOML basic string literal for `value`, escaping what TOML requires.
    fn toml_basic_string(value: &str) -> String {
        let mut out = String::with_capacity(value.len() + 2);
        out.push('"');
        for character in value.chars() {
            match character {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\t' => out.push_str("\\t"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                other => out.push(other),
            }
        }
        out.push('"');
        out
    }

    /// The collision diagnostic must never show one spelling twice.
    ///
    /// Every pair this check catches differs only in what canonicalization
    /// removes, so the two parsed URLs are identical by definition — and
    /// printing the WRITTEN text does not rescue it either, because `Error`
    /// re-serializes a URL-like token while redacting userinfo. Measured over
    /// the realistic shapes, printing the written text still rendered six of
    /// them identically: default port, host case, scheme case, IDNA and
    /// userinfo. A message reading "written differently ('https://h/team/' and
    /// 'https://h/team/')" tells an operator nothing, so the diagnostic names
    /// the two RULE IDS and the single scope instead.
    #[test]
    fn the_collision_message_never_shows_one_spelling_twice() {
        // A default-port pair: the two written prefixes differ, and both render
        // as `https://h/team/` once the error is built.
        let error = policy(
            r#"
            [[policy]]
            id = "with-port"
            effect = "deny"
            principal = "*"
            operations = ["*"]
            prefix = "https://h:443/team/"

            [[policy]]
            id = "without-port"
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "https://h/team/"
            "#,
        )
        .expect_err("a default port is not part of a scope");
        let message = error.message();
        assert_eq!(
            message.matches("'https://h/team/'").count(),
            1,
            "the scope must appear once, not as two 'different' spellings: {message}"
        );
        // And the operator still gets a handle on both rules.
        assert!(
            message.contains("'with-port'") && message.contains("'without-port'"),
            "the message must name both rule ids: {message}"
        );
    }

    /// The collision diagnostic keeps the credential redacted and still says
    /// why the two prefixes are one scope.
    ///
    /// Userinfo is never part of a scope, so a credential-bearing prefix
    /// collides with the same path written without one. The message must not
    /// leak the credential, and must name the reason — an operator comparing
    /// the two `prefix` values sees a difference the matcher ignores.
    #[test]
    fn the_collision_message_keeps_credentials_out_and_explains_the_collapse() {
        // The password carries a comma on purpose, and the row is worthless
        // without it. `Error::new` redacts by re-serializing a URL token it can
        // tokenize, and `scan_url_at` ends a token at `,` `;` `'` `)` — so a
        // plain password is scrubbed by the redactor even when the refusal
        // interpolates the raw `Url`, and this test passed for a year of
        // review against exactly that bug. Measured with `RedactedUrl` removed:
        // the full `https://reader:hunt,er2@h/team/` reaches the message.
        let error = policy(
            r#"
            [[policy]]
            id = "deny-team"
            effect = "deny"
            principal = "*"
            operations = ["*"]
            prefix = "https://reader:hunt,er2@h/team/"

            [[policy]]
            id = "allow-team"
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "https://h/team/"
            "#,
        )
        .expect_err("userinfo is not part of a scope, so these are one scope");
        assert!(
            !error.message().contains("reader") && !error.message().contains("hunt,er2"),
            "the credential must stay redacted: {}",
            error.message()
        );
        assert!(
            error.message().contains("carries credentials"),
            "the message must say why the two prefixes are one scope: {}",
            error.message()
        );
    }

    /// An allow whose prefix carries credentials is refused, because dropping
    /// userinfo from the comparison widens it and the widening is silent.
    ///
    /// Userinfo is not part of a scope — the matcher compares scheme, host,
    /// port and path — so `allow https://readonly:token@h/reports/` covers
    /// `https://admin:password@h/reports/payroll`. The previous serialized
    /// matcher did not: measured against 0.2.0's `is_prefix_of`, that address
    /// does not start with that prefix, so it returned false and the request
    /// fell to default-deny. A live allow therefore gains reach across the
    /// upgrade with nothing said, which is the class the escape-retargeting
    /// gate already refuses, in the same permissive direction.
    ///
    /// A DENY is left alone: ignoring userinfo makes it cover MORE, which is
    /// the safe direction and needs no acknowledgement.
    #[test]
    fn an_allow_carrying_credentials_is_refused() {
        let with_effect = |effect: &str, prefix: &str| {
            policy(&format!(
                r#"
                [[policy]]
                id = "r"
                effect = "{effect}"
                principal = "*"
                operations = ["*"]
                prefix = "{prefix}"
                "#
            ))
        };

        for prefix in [
            "https://readonly:token@origin/reports/",
            "https://reader@origin/reports/",
            "s3://user:pass@bucket/team/",
        ] {
            let error = with_effect("allow", prefix)
                .expect_err("an allow carrying credentials must not load");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{prefix}");
            assert!(
                error.message().contains("carries credentials"),
                "{prefix} must be refused by the credential gate, got: {}",
                error.message()
            );
            // The diagnostic must not echo what it is complaining about.
            assert!(
                !error.message().contains("token")
                    && !error.message().contains("pass")
                    && !error.message().contains("reader"),
                "the gate leaked a credential: {}",
                error.message()
            );

            // The same prefix as a DENY still loads: widening a deny is safe.
            with_effect("deny", prefix)
                .unwrap_or_else(|e| panic!("deny {prefix} must load: {}", e.message()));
        }

        // The control: an allow WITHOUT credentials is untouched, and it does
        // cover the address the credential-bearing spelling would have — which
        // is what makes the refusal a migration gate rather than a ban.
        let loaded = with_effect("allow", "https://origin/reports/")
            .expect("an allow with no credentials is unaffected");
        assert!(
            loaded
                .evaluate(
                    "alice",
                    Operation::Read,
                    Some(&url("https://admin:password@origin/reports/payroll"))
                )
                .is_allow(),
            "userinfo is not part of a scope, so the rewritten rule covers it"
        );
    }

    /// No load diagnostic may echo the operator's raw prefix text.
    ///
    /// `Error` redacts by re-serializing a recognizable URL token, so the RAW
    /// string is exactly the form it cannot normalize: a prefix whose userinfo
    /// carries punctuation that breaks tokenization, or which is not a
    /// parseable URL at all because the parser strips a tab out of it, is
    /// echoed verbatim into a startup error and the broker log. Both shapes
    /// reach a diagnostic added by this work — an escape-bearing path is what
    /// triggers the migration gate, and a stripped tab is what triggers the
    /// whitespace check.
    ///
    /// The rule id is the handle that is always safe, and it is the only one
    /// these messages use.
    #[test]
    fn no_load_diagnostic_echoes_a_credential() {
        let secrets = ["hunter2", "password", "s3cr3t-token"];
        // Each row carries a credential AND trips a different check.
        for prefix in [
            // migration gate: escape-bearing path, credential in userinfo
            "s3://reader:hunter2@bucket/pub%20x",
            // whitespace check: a tab the parser strips, so the whole string
            // is not a recognizable URL token
            "https\t://user:password@origin/x",
            // query, fragment, dot segment, escaped separator, backslash
            "https://reader:hunter2@h/x?v=1",
            "https://reader:hunter2@h/x#note",
            "https://reader:hunter2@h/a/../b",
            "s3://reader:hunter2@h/a%2Fb",
            "https://reader:hunter2@h/a\\b",
            // unparseable
            "s3://reader:s3cr3t-token@h:notaport/x",
            // Authority-less, which `address::parse` refuses — and whose
            // message `parse_prefix` forwards. This row is why the claim
            // "no diagnostic echoes the raw prefix" needed a test rather
            // than an audit: the leak was one level down, in a shared
            // function, and grepping this file could not see it.
            "s3:reader:hunter2@h/x",
            "mailto:reader:hunter2@h/x",
        ] {
            let toml = format!(
                "[[policy]]\nid = \"r\"\neffect = \"allow\"\nprincipal = \"*\"\n\
                 operations = [\"*\"]\nprefix = {}\n",
                toml_basic_string(prefix)
            );
            let Err(error) = policy(&toml) else {
                // If a row starts loading, it has stopped exercising a
                // diagnostic and the test is no longer covering that check.
                panic!("{prefix} must be refused, or this row proves nothing");
            };
            let message = error.message();
            for secret in secrets {
                assert!(
                    !message.contains(secret),
                    "diagnostic leaked a credential from {prefix}: {message}"
                );
            }
            assert!(
                message.contains("'r'"),
                "diagnostic must name the rule id: {message}"
            );
        }
    }

    /// A raw `\` in the authority is refused on every scheme, because it moves
    /// the authority/path boundary the raw-string guards depend on.
    ///
    /// `raw_prefix_path` scans the post-`//` remainder for `/`, `?` or `#`.
    /// The parser's port state accepts one more terminator than that — `\`,
    /// listed beside `/`, `?` and `#` — and it is listed there on **every**
    /// scheme, including the non-special ones where the backslash guard
    /// deliberately does not fire. Every other non-digit in that position is a
    /// hard `InvalidPort` error rather than a terminator, which is why `\` is
    /// the only spelling that reaches this. When the scan yields `None`,
    /// `resolving_prefix_segment` short-circuits, the escaped-separator check
    /// falls back to an empty path and the retargeting gate reads nothing:
    /// every raw-string guard no-ops together, and they fail open.
    ///
    /// Measured, with the escape acknowledgement set as the upgrade notes
    /// instruct: `allow s3://corp:\secret%2F..%2F..` loaded with scope
    /// `s3://corp/` — the whole bucket — and granted
    /// `s3://corp/finance/secret.csv`, from a rule that reads as scoped to
    /// `secret`.
    #[test]
    fn a_backslash_in_the_authority_is_refused_on_every_scheme() {
        for prefix in [
            r"s3://corp:\secret%2F..%2F../",
            r"s3://corp:\secret/",
            r"s3://corp:\team%2Fsub/x",
            // The authority ends at `\` because it is not a valid port, so the
            // parser puts the rest in the path and resolves it to the root.
            r"s3://corp:\secret%2F..%2F..",
            r"omniverse://h:\secret%2F..%2F..",
            // With a real port in front, so the terminator is the only thing
            // doing the work.
            r"s3://corp:8080\secret%2F..%2F..",
            // And one with no escape at all, to show the refusal is the
            // unreadable shape rather than the `%2F`.
            r"s3://corp:\secret",
        ] {
            let error = policy(&format!(
                r#"
                prefix_escapes_are_decoded = true

                [[policy]]
                id = "r"
                effect = "allow"
                principal = "alice"
                operations = ["read"]
                prefix = "{}"
                "#,
                prefix.replace('\\', "\\\\")
            ))
            .expect_err("a prefix whose path cannot be located must not load");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{prefix}");
            assert!(
                error
                    .message()
                    .contains("between its scheme and the start of its path"),
                "{prefix} must be refused by the authority-backslash check, got: {}",
                error.message()
            );
        }

        // The controls, and the second group is the point of the narrowing.
        // They load as DENIES because a credential-bearing ALLOW is refused at
        // load — dropping userinfo from the comparison widens an allow — and
        // three of these rows carry userinfo on purpose.
        //
        // A `\` BEFORE the last `@` sits in userinfo, where a non-special
        // scheme's parser does not terminate — so the scan and the parser still
        // agree about where the authority ends and the invariant is not
        // violated. Measured: `s3://DOMAIN\alice@bucket/team/` parses to
        // userinfo `DOMAIN%5Calice`, host `bucket`, path `/team/`, which is
        // exactly what `raw_authority` reports.
        //
        // `s3://corp:\@evil/x` is in this group deliberately. An earlier round
        // listed it as a host substitution; that was wrong. The `@` makes
        // `corp:\` userinfo and `evil` the host by ordinary URL syntax, every
        // guard reads the same `/x`, and the scope it loads with is the scope
        // it spells. The genuine defects in that round were the truncation
        // rows above, which still refuse.
        for prefix in [
            "s3://corp",
            "s3://corp/",
            "s3://corp/secret/",
            r"s3://DOMAIN\alice@bucket/team/",
            r"s3://us\er@h/x",
            r"s3://corp:\@evil/x",
        ] {
            let loaded = policy(&format!(
                r#"
                [[policy]]
                id = "r"
                effect = "deny"
                principal = "alice"
                operations = ["read"]
                prefix = "{}"
                "#,
                // TOML-escape, or a row carrying a backslash fails to parse as
                // TOML and the control passes for the wrong reason.
                prefix.replace('\\', "\\\\")
            ))
            .unwrap_or_else(|error| panic!("{prefix} must load: {}", error.message()));
            assert_eq!(loaded.rules.len(), 1, "{prefix} must produce a rule");
        }
    }

    /// A prefix the matcher cannot honour fails to load rather than widening.
    #[test]
    fn query_and_fragment_prefixes_fail_to_load() {
        for prefix in ["s3://b/x?versionId=public", "s3://b/x#note"] {
            let error = policy(&format!(
                r#"
                [[policy]]
                id = "r"
                effect = "allow"
                principal = "*"
                operations = ["*"]
                prefix = "{prefix}"
                "#
            ))
            .expect_err("{prefix} must fail to load");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{prefix}");
        }
    }

    /// The Windows deny bypass, exercised on every platform.
    ///
    /// `deny file:///c:/root/private/` must cover
    /// `file:///c:/root/private%5Csecret`: on Windows `to_file_path` hands the
    /// OS a native separator and opens the denied file, while a matcher
    /// comparing whole segments sees `private\secret` as one segment and
    /// misses. Case folds for the same reason.
    ///
    /// This runs on Linux CI because the host behaviour is a parameter. The
    /// Windows CI leg runs only the C-source and Python suites, so a
    /// `#[cfg(windows)]` version of this test would execute nowhere.
    #[test]
    fn windows_semantics_close_the_backslash_and_case_bypass() {
        let deny = url("file:///c:/root/private/");
        for spelling in [
            "file:///c:/root/private%5Csecret",
            "file:///c:/root/PRIVATE/secret",
            "file:///c:/ROOT/Private%5CSecret",
        ] {
            assert!(
                covers_with_host_semantics(&deny, &url(spelling), true, Effect::Deny),
                "{spelling} must be covered under Windows semantics"
            );
            assert!(
                !covers_with_host_semantics(&deny, &url(spelling), false, Effect::Deny),
                "{spelling} must NOT be covered off Windows, or this test \
                 proves nothing about the fold"
            );
        }
    }

    /// Rewriting `\` creates path structure, and the created structure must be
    /// resolved or it defeats the deny it was meant to close.
    ///
    /// Every row below opens `C:\root\private\secret.txt` on Windows. Before
    /// the fold normalized after rewriting, the first two produced a literal
    /// `..` segment and a stranded empty segment respectively, and the deny
    /// missed all of them.
    #[test]
    fn folding_resolves_the_structure_it_creates() {
        let deny = url("file:///c:/root/private/");
        for spelling in [
            "file:///c:/root/public%5C..%5Cprivate%5Csecret.txt",
            "file:///c:/root%5C%5Cprivate%5Csecret.txt",
            "file:///c:/root%5Cprivate%5C.%5Csecret.txt",
            "file:///c:/root/private%5Csecret.txt",
        ] {
            assert!(
                covers_with_host_semantics(&deny, &url(spelling), true, Effect::Deny),
                "{spelling} resolves into the denied directory on Windows"
            );
        }

        // An empty segment must not absorb a following `..`. Folding `\` to `/`
        // manufactures runs — `private\\..\public` becomes `private//../public`
        // — so this matcher meets doubled separators far more often than a
        // caller types them. If the pipeline resolved dot segments before
        // collapsing runs, the `..` would cancel the empty segment instead of
        // `private`, leaving the address inside the denied directory while
        // Windows opens `C:\root\public\secret.txt` outside it. Escaping an
        // allowed subtree must not be spellable by doubling a separator.
        let allow_private = url("file:///c:/root/private/");
        let escaping = url("file:///c:/root/private%5C%5C..%5Cpublic%5Csecret.txt");
        assert_eq!(
            segments_with_host_semantics_widened(&escaping, true, true),
            Some(vec![
                b"c:".to_vec(),
                b"root".to_vec(),
                b"public".to_vec(),
                b"secret.txt".to_vec(),
            ]),
            "the doubled separator must not shield the `..`"
        );
        assert!(
            !covers_with_host_semantics(&allow_private, &escaping, true, Effect::Allow),
            "a rule scoped to private/ must not cover an address that leaves it"
        );

        // A `..` run that climbs above the drive must clamp at the drive, as
        // Windows clamps: `C:\root\a\..\..\..\secret.txt` resolves to
        // `C:\secret.txt`, keeping the `c:` segment. Normalizing the RELATIVE
        // path put the clamp one component too high, popped `c:` like an
        // ordinary segment and produced `["secret.txt"]` — which a deny written
        // against the drive does not cover.
        let deny_at_drive = url("file:///c:/secret.txt");
        let climbing = url("file:///c:/root/a%5C..%5C..%5C..%5Csecret.txt");
        assert_eq!(
            segments_with_host_semantics_widened(&climbing, true, true),
            Some(vec![b"c:".to_vec(), b"secret.txt".to_vec()]),
            "the drive letter must survive a `..` run that climbs past it"
        );
        assert!(
            covers_with_host_semantics(&deny_at_drive, &climbing, true, Effect::Deny),
            "a deny at the drive root must cover a traversal that clamps there"
        );

        // The `\` rewrite can strand a root marker ahead of the drive. This
        // matcher already calls `file:///%5Cc:/x` and `file:///c:/x` the same
        // node, so the clamp must find the drive in both — otherwise one
        // spelling clamps at the volume and the other pops straight past it.
        let stranded = url("file:///%5Cc:/root/a%5C..%5C..%5C..%5Csecret.txt");
        assert_eq!(
            segments_with_host_semantics_widened(&stranded, true, true),
            Some(vec![b"c:".to_vec(), b"secret.txt".to_vec()]),
            "a stranded root marker must not hide the drive from the clamp"
        );
    }

    /// A deny prefix that itself carries `%5C` must cover the spellings callers
    /// actually send, not only the ones that carry `%5C` in the same slot.
    ///
    /// The `\` split produced one empty segment and the trailing `/` another,
    /// and only one was dropped — leaving a stranded empty segment mid-list, so
    /// the rule matched nothing real.
    /// **The PREFIX spelling here is refused at load** — `parse_prefix` rejects
    /// `%5C` in a `file:` prefix — so this pins matcher behaviour for a rule
    /// state no loaded policy can hold, and exists to keep that behaviour
    /// correct if the guard is ever relaxed. The **target** side is the
    /// reachable half: a request address may carry `%5C` freely, and that is
    /// what the assertions below actually exercise against a real policy.
    #[test]
    fn a_backslash_bearing_prefix_is_not_inert() {
        let deny = url("file:///root/private%5C/");
        for spelling in [
            "file:///root/private/secret",
            "file:///root/private%5Csecret",
        ] {
            assert!(
                covers_with_host_semantics(&deny, &url(spelling), true, Effect::Deny),
                "{spelling} is inside the denied directory"
            );
        }
    }

    /// Case folding is ASCII, not Unicode.
    ///
    /// `str::to_lowercase` maps U+212A KELVIN SIGN to `k`, so a rule written
    /// for `…/k/` would grant a distinct file named with the Kelvin sign — an
    /// equivalence no Windows volume makes. NTFS's table is neither ASCII nor
    /// full Unicode folding; ASCII is the subset it agrees with, so it is the
    /// one that cannot over-grant.
    #[test]
    fn the_deny_fold_is_unicode_and_an_allow_does_not_fold() {
        // A deny folds with `str::to_lowercase`, which is full Unicode, so it
        // covers U+212A KELVIN SIGN as well as ASCII `K`. Measured. That is the
        // over-deny direction, and it matches the platform being modelled:
        // NTFS's uppercase table maps U+212A onto `K`, so the two spellings do
        // open one file on the host whose behaviour this fold exists to track.
        let deny = url("file:///root/k/");
        for spelling in ["file:///root/K/x", "file:///root/%E2%84%AA/x"] {
            assert!(
                covers_with_host_semantics(&deny, &url(spelling), true, Effect::Deny),
                "{spelling} folds onto the denied name"
            );
        }
        // Not everything folds together: a deny on `k` must not reach an
        // unrelated character, or the fold would be covering by accident.
        assert!(!covers_with_host_semantics(
            &deny,
            &url("file:///root/%C3%85/x"),
            true,
            Effect::Deny
        ));

        // An ALLOW does not fold at all, through either table, so it cannot
        // over-grant by case. This is the assertion that carries the security
        // property; the deny rows above only document reach.
        let allow = url("file:///root/k/");
        for spelling in ["file:///root/K/x", "file:///root/%E2%84%AA/x"] {
            assert!(
                !covers_with_host_semantics(&allow, &url(spelling), true, Effect::Allow),
                "{spelling} is a name the allow never wrote"
            );
        }
    }

    /// Case folding widens a deny and never an allow.
    ///
    /// Neither ASCII nor Rust's Unicode folding is NTFS's table, so either
    /// alone loses on one side: Unicode over-grants an allow (U+212A KELVIN
    /// SIGN folds to `k`), ASCII under-covers a deny (`é` and `É` are one
    /// directory). Folding only in the deny direction takes the safe half of
    /// each.
    #[test]
    fn case_folding_widens_a_deny_but_not_an_allow() {
        // A deny reaches the non-ASCII case spelling the volume treats as one
        // name; `str::to_lowercase` is full Unicode and that is deliberate here.
        // directory.
        assert!(
            covers_with_host_semantics(
                &url("file:///c:/root/%C3%A9/"),
                &url("file:///c:/root/%C3%89/secret.txt"),
                true,
                Effect::Deny
            ),
            "a deny must cover every spelling the filesystem calls one node"
        );

        // An allow does not, so a rule for `k/` cannot grant a file named with
        // a character that merely folds to `k`.
        assert!(
            !covers_with_host_semantics(
                &url("file:///root/k/"),
                &url("file:///root/%E2%84%AA/x"),
                true,
                Effect::Allow
            ),
            "an allow must not grant a file it never named"
        );

        // A deny folds case (full Unicode); an ALLOW does not fold at all.
        //
        // Windows has supported per-directory case sensitivity since 1803, and
        // it is on by default for directories created through WSL interop, so
        // `private` and `PRIVATE` can be two directories the OS keeps apart.
        // Folding an allow grants the distinct one; folding a deny covers it,
        // which is the safe direction. This used to fold for both.
        assert!(
            covers_with_host_semantics(
                &url("file:///root/private/"),
                &url("file:///root/PRIVATE/secret"),
                true,
                Effect::Deny
            ),
            "a deny must reach the other case spelling"
        );
        assert!(
            !covers_with_host_semantics(
                &url("file:///root/private/"),
                &url("file:///root/PRIVATE/secret"),
                true,
                Effect::Allow
            ),
            "an allow must not grant a directory a case-sensitive volume keeps distinct"
        );
    }

    /// The fold is scoped to `file:`. A storage key is case-sensitive and `\`
    /// is an ordinary byte in it, so folding there would over-deny and, for an
    /// allow, over-grant.
    #[test]
    fn the_host_fold_does_not_reach_storage_schemes() {
        assert!(!covers_with_host_semantics(
            &url("s3://b/private/"),
            &url("s3://b/PRIVATE/secret"),
            true,
            Effect::Deny
        ));
        assert!(!covers_with_host_semantics(
            &url("s3://b/private/"),
            &url("s3://b/private%5Csecret"),
            true,
            Effect::Deny
        ));
    }

    /// The matcher must be no coarser than the backend, byte for byte.
    ///
    /// `file:` resolves an address through `Url::to_file_path`, which is
    /// byte-exact, so `x%FF` and `x%FE` are two different files. A decode that
    /// replaced both invalid sequences with U+FFFD made them one segment to the
    /// matcher, so an allow naming one file also granted the other.
    #[test]
    fn an_allow_on_a_non_utf8_name_does_not_cover_a_different_one() {
        // A byte that is not valid UTF-8 has no escape-free spelling, so this
        // is one of the two classes the acknowledgement exists for rather than
        // a case the gate could reasonably ban.
        let policy = policy(
            r#"
            prefix_escapes_are_decoded = true

            [[policy]]
            id = "allow-one-file"
            effect = "allow"
            principal = "*"
            operations = ["*"]
            prefix = "file:///data/x%FF"
            "#,
        )
        .unwrap();

        assert!(
            policy.is_allowed("mallory", Operation::Read, Some(&url("file:///data/x%FF"))),
            "control: the file the operator named must be allowed"
        );
        assert!(
            !policy.is_allowed("mallory", Operation::Read, Some(&url("file:///data/x%FE"))),
            "an allow on one file must not authorize a different one whose name \
             differs only in bytes a lossy decode collapses"
        );
    }

    /// The mirror of the allow case, on the safe side of the asymmetry.
    ///
    /// A deny written for one file covers that file. It does not have to cover
    /// the other, but it must not stop covering the one it names.
    #[test]
    fn a_deny_on_a_non_utf8_name_still_covers_that_name() {
        assert!(covers_with_host_semantics(
            &url("file:///data/x%FF"),
            &url("file:///data/x%FF"),
            false,
            Effect::Deny
        ));
    }
}
