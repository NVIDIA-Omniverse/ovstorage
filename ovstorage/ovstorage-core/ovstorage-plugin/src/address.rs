// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Address helpers operating on [`url::Url`].
//!
//! Addresses are RFC 3986 URLs. The path component (after
//! percent-decoding) is the backend's primary key; the query
//! component is reserved for backend-specific address modifiers.

use url::Url;

use crate::{Error, ErrorCode, Result};

/// The WHATWG special schemes, re-exported so the authorization matcher and
/// the address layer share one definition of the set.
pub use ovstorage_layer::scheme_folds_backslash;

/// Percent-encode decoded bytes as a canonical URL path component, re-exported
/// so a caller outside this crate escapes with the same set the emitters use.
///
/// [`join_relative_bytes`] is what an emitter wants: it applies this and then
/// checks that the address it built still names the key it was built from. Use
/// this directly only where there is no key and no address to check — config
/// validation asking what a written path resolves to, which is what the Nucleus
/// connection `prefix` does.
pub use ovstorage_layer::encode_canonical_path;

/// Parse and validate an ovstorage URL. Single error-mapping site
/// for `url::ParseError → InvalidArgument`. Output is RFC 3986 canonical:
/// scheme lowercased, default ports stripped, dot-segments resolved, and all
/// components percent-encoded by `Url::parse`; host lowercased and the
/// empty-authority path normalized by [`ovstorage_layer::canonicalize`].
///
/// `Url::parse` only lowercases the host for special schemes (http/https/…),
/// so the host-case and empty-authority-path (`omniverse://host` →
/// `omniverse://host/`) normalizations for ovstorage's non-special schemes come
/// from [`ovstorage_layer::canonicalize`] — the single source of truth for both
/// rules, the same canonicalization a [`Stack`](ovstorage_layer::Stack)
/// re-applies to every address-bearing request at its entry, so the contract
/// holds for callers that drive the `Stack` API directly.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the string is not a valid RFC 3986 URL,
///   or it has no authority (`s3:a/b`). The path state machine never runs for
///   an authority-less URL, so `canonicalize` cannot normalize one — it would
///   manufacture a separator and leave a traversal unresolved. Every ovstorage
///   scheme is written with an authority, so refusing here costs nothing and
///   keeps the invariant that a parsed address is a canonical address.
pub fn parse(value: &str) -> Result<Url> {
    let url = Url::parse(value)
        .map_err(|error| Error::new(ErrorCode::InvalidArgument, format!("invalid URL: {error}")))?;
    if url.cannot_be_a_base() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            // The opaque payload is NOT interpolated. For a cannot-be-a-base
            // URL everything after the scheme is one opaque string, userinfo
            // included, and `Error`'s redactor cannot normalize it — it only
            // recognizes URL-shaped tokens. A policy loader forwards this
            // message, so `s3:reader:hunter2@h/x` would print the credential
            // into a startup error and the log. The scheme is the part that
            // helps and the part that is safe.
            format!(
                "address must have an authority; scheme '{}' was parsed as \
                 authority-less",
                url.scheme()
            ),
        ));
    }
    Ok(ovstorage_layer::canonicalize(url))
}

/// A URL component that a **configuration** address may not carry.
///
/// See [`refused_config_component`] for what the distinction is and why it
/// stops at configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigComponent {
    Query,
    Fragment,
}

impl ConfigComponent {
    /// The component's name, for a diagnostic that has to say which one.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Fragment => "fragment",
        }
    }
}

/// The first component in a **configuration** address that the system would
/// otherwise drop — the one predicate every config loader refuses on.
///
/// **A configuration address names a SCOPE, and a scope is scheme, authority
/// and path.** Every containment decision in this system — routing,
/// authorization, alias selection, visibility — is made on those three, and a
/// fragment never leaves the client at all. So a query or a fragment written
/// into *configuration* either does nothing or narrows the scope to a single
/// spelling, and neither is what the operator wrote. Accepting it silently
/// costs a rule, route or prefix that covers something other than what it
/// spells, so it fails loudly instead.
///
/// This is a prohibition on config, not a claim that the query is inert. It is
/// not: [`same_node`] treats a query as part of node identity, because a
/// version pin selects which object is served, and [`is_ancestor_or_self`]
/// makes a query-bearing prefix match that query and no extension of it. That
/// second fact is precisely why a config prefix may not carry one.
///
/// **The distinction is configuration versus request, not component versus
/// component.** A *request* address may carry a query — that is where a caller
/// pins a version or presents a signed URL — so this predicate must never be
/// folded into [`parse`], which is the one normalizing entry point both paths
/// share. Every config surface calls it from its own config-only loader:
/// `parse_prefix` in the authz policy, `parse_url` in the alias wrapper,
/// `config_url` in `plugin-http`, `connection_prefix` in `plugin-opendal`,
/// `build_oauth_providers_from_config` in the broker, and
/// `root_url_from_config` in the `file` backend — which applies it to the
/// `file:` URL spelling only, because in its plain-filesystem-path spelling
/// `?` and `#` are ordinary bytes in a directory name and are escaped rather
/// than refused.
///
/// **It reads the RAW string, before any parse, and that is the whole design.**
/// `Url::parse` strips a fragment on the way through `canonicalize`, so by the
/// time a loader holds a `Url` there is nothing left to detect — a
/// post-parse fragment check is a guard that cannot execute. The parser also
/// removes every ASCII tab, LF and CR before deciding structure, so the raw
/// string is the only view that sees everything the operator wrote. Scanning it
/// therefore errs toward refusing, which is the safe direction for a loader.
///
/// A raw `?` or `#` is always a delimiter: the literal characters are spelled
/// `%3F` and `%23`, and those are left alone. Whichever comes first names the
/// component, so an address carrying both is reported one at a time.
#[must_use]
pub fn refused_config_component(text: &str) -> Option<ConfigComponent> {
    text.bytes().find_map(|byte| match byte {
        b'?' => Some(ConfigComponent::Query),
        b'#' => Some(ConfigComponent::Fragment),
        _ => None,
    })
}

/// True when a configuration prefix carries credentials it will not be matched
/// on.
///
/// **The rule this answers: a prefix that SELECTS addresses may not carry
/// userinfo.** Selection compares scheme, host, port and node path —
/// [`is_ancestor_or_self`] and the authorization matcher both — and never the
/// username or password. So a prefix written with a credential covers its path
/// for *every* credential rather than the one it spells, including for
/// anonymous callers. On 0.2.0 the matchers compared whole serialized strings,
/// so the credential had to be present to match; every adopter below is
/// therefore closing a widening rather than tightening a new rule.
///
/// **Adopters, and this list is the point of putting the predicate here.** The
/// rule was hand-placed at five sites in two different spellings before a sixth
/// and a seventh were found to be missing it, which is how a rule that lives
/// only in reviewers' heads behaves:
///
/// - an authorization policy `allow` prefix,
/// - an alias rule's `from`,
/// - a `visible` visibility prefix,
/// - a `broker_oauth_routes` route key,
/// - `plugin-http`'s connection `prefix`,
/// - the OpenDAL connection `prefix`,
/// - a Nucleus connection `server`, which does not look like an address in the
///   config file but is interpolated into one: the published root is
///   `omniverse://<server>/`, so an `@` in it is userinfo on a selecting
///   prefix.
///
/// **Documented exemptions, which are not oversights:**
///
/// - `plugin-http`'s `root_url`, where userinfo is a declared credential
///   channel rather than a scope — it authenticates the connection and is
///   never compared against a caller's address.
/// - an alias `to`, which is the address a rewrite *produces*. Nothing
///   compares it against a caller's address, so there is no selected set to
///   widen.
/// - a `deny` policy prefix and a `hidden` or `suppressed` visibility prefix,
///   which widen in the direction that withholds. They load, and the
///   visibility loader warns.
/// - the `file` backend's `root` and `prefix`: a `file:` URL cannot carry
///   userinfo at all — measured, `file://user@server/x` does not parse.
/// - a Nucleus connection `prefix`, which is a bare decoded path rather than a
///   URL, so no userinfo is expressible in it. Its sibling `server` is NOT
///   exempt — see the adopter list.
///
/// **The nearest thing outside the list** is a root a *server* supplies rather
/// than an operator: `ovstorage-plugin-services-client`'s `parse_server_address`
/// validates a returned root and does not refuse userinfo, and those roots
/// become `AddressRoot`s. That is the same widening shape with a different
/// provenance, and this predicate is about configuration, so it is named here
/// rather than silently excluded.
#[must_use]
pub fn config_prefix_carries_credentials(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

/// The address to put on the wire: the caller's, with any userinfo removed.
///
/// **The rule: a credential a CALLER spelled must not leave this process.**
/// Routing compares scheme, host, port and node path — [`is_ancestor_or_self`]
/// reads no userinfo — so `s3://alice:pw@h/team/x` reaches a connection whose
/// published root is `s3://h/team/`. The connection's own credential is the one
/// that authorizes the request; the caller's is an arbitrary string that would
/// otherwise be serialized into a request the backend sends *from this
/// process's network position*, to a peer that never asked for it.
///
/// Stripping rather than refusing is what the address model says: userinfo is
/// not part of what an address names, so a request for the object is honoured
/// and the credential simply does not travel.
///
/// **Adopters**, and the list is here because this rule was written at one
/// backend before two more were found without it:
///
/// - `plugin-http`'s `physical_url` identity arm, whose projection arm needs no
///   equivalent because `replace_prefix` builds its answer from the root,
/// - the services-client layer's `ResolvedTarget`, serialized into the gRPC
///   `resource_address`,
/// - the broker-client layer's `ResolvedTarget`, serialized into the upstream
///   broker's `address`.
///
/// A backend that builds its wire address from its own configured root rather
/// than from the caller's URL does not need this, because the caller's
/// authority never reaches the result.
#[must_use]
pub fn wire_address(url: &Url) -> Url {
    let mut bare = url.clone();
    // Both setters fail only for a cannot-be-a-base URL, which `parse` refuses
    // before an address reaches dispatch, and for `file:`, which spells no
    // userinfo. In both cases the clone is already what this returns.
    let _ = bare.set_username("");
    let _ = bare.set_password(None);
    bare
}

/// Backend's primary object key — the URL path with percent-encoding
/// removed. Empty for the root.
///
/// **The decode is byte-exact**, which is why this returns bytes rather than a
/// `String`. A key is an arbitrary byte sequence; `file:` resolves one through
/// `Url::to_file_path`, which is byte-exact, so `x%FF` and `x%FE` are two
/// different files. A decode that replaced both invalid sequences with U+FFFD
/// made them one key, and a matcher deriving that key was strictly coarser than
/// the backend it guards — an allow naming one file also granted the other.
///
/// The matcher must be neither coarser nor finer than the backend: coarser
/// widens an allow, finer lets a deny written on one spelling miss an object
/// the backend reaches by another. Comparing the same bytes everything else
/// compares is what makes that hold by construction rather than by convention.
///
/// **Which one to call:** this one when the backend can carry arbitrary bytes
/// to its storage — the `file:` backend is the in-tree example. [`key_utf8`]
/// when the key terminates at a `&str` boundary, which most wire APIs do; it
/// refuses a key it cannot spell rather than converting it lossily one frame
/// lower.
#[must_use]
pub fn key(url: &Url) -> Vec<u8> {
    let path = url.path();
    let path = path.strip_prefix('/').unwrap_or(path);
    percent_decode(path)
}

/// The [`key`] as UTF-8, for a backend whose wire API cannot carry other bytes.
///
/// Most backends terminate at a `&str` boundary — an HTTP URL path, an
/// HMAC-signed canonical string, a `path: &str` SDK. **Such a backend rejects a
/// key it cannot spell; it never converts one lossily.** A lossy conversion
/// here would put the collapse back one frame below the matcher, making the
/// matcher finer than the backend: it would distinguish `x%FF` from `x%FE`
/// while the backend fetched one object for both, so a deny written on one
/// spelling is defeated by the other.
///
/// The cost is that such an object is unreachable *on that backend* and says
/// so, instead of silently aliasing onto another object.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the decoded key is not valid UTF-8.
pub fn key_utf8(url: &Url) -> Result<String> {
    String::from_utf8(key(url)).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "object key is not valid UTF-8 and this backend cannot address it: {}",
                url.path()
            ),
        )
    })
}

/// Decode one already-split path segment, with the decode [`key`] uses.
///
/// The authorization matcher compares segments and the backend derives its key
/// from the whole path; both must decode identically or they disagree about
/// which object an address names, which is a bypass in one direction and an
/// over-deny in the other. Sharing this function is what makes that structural
/// rather than a convention, and it is why this returns bytes: this is the
/// segment-level counterpart of [`key`], carrying the same byte-exactness. A
/// segment decode that produced a `String` would reintroduce the collapse on
/// exactly the comparison that must not have it.
#[must_use]
pub fn decode_segment(segment: &str) -> Vec<u8> {
    percent_decode(segment)
}

/// True when [`parse`] would leave `url` naming the same node.
///
/// For validating a value that arrived already parsed — a policy prefix as the
/// operator wrote it, an address a plugin returned — where resolving it
/// silently would change which object it names instead of normalizing it.
///
/// It answers for [`parse`] and not for `Url::parse`, which has already
/// resolved dot segments, removed ASCII TAB/LF/CR, trimmed the edges and
/// folded `\` on a special scheme by the time a `Url` exists. A caller
/// validating a *string* needs [`ovstorage_layer::parsing_preserves_node`]
/// as well; the returned-address boundaries in this crate apply both.
#[must_use]
pub fn preserves_node(url: &Url) -> bool {
    ovstorage_layer::canonicalize_preserves_node(url)
}

/// [`same_node`]'s comparison value, owned, for a dedup set that outlives the
/// addresses it was built from.
#[must_use]
pub fn node_key_owned(url: &Url) -> (String, Option<String>, Option<u16>, String, Option<String>) {
    let (scheme, host, port, path, query) = ovstorage_layer::node_key(url);
    (
        scheme.to_string(),
        host.map(str::to_string),
        port,
        path.to_string(),
        query.map(str::to_string),
    )
}

/// How many path segments an address pins, for ranking one scope against
/// another.
///
/// **Rank on this, never on the serialized byte length.** Byte length is
/// spelling-dependent: `…/root/` is one byte longer than `…/root`, and the two
/// name one node, so the more verbose spelling of one scope outranks the
/// plainer spelling of the same scope regardless of declaration order. Segment
/// count is a property of the node, so two spellings tie and a stable sort
/// keeps the documented first-wins order.
///
/// A percent-escaped spelling is not a second example of this, for any `Url`
/// [`parse`] produced: it decodes the path and re-encodes it with one escape
/// set, so `…/%70rivate/` is `…/private/` by then.
#[must_use]
pub fn node_segment_count(url: &Url) -> usize {
    ovstorage_layer::node_segment_count(url)
}

/// The directory form of a backend key: one trailing separator, and empty for
/// the root.
///
/// **A directory verb must derive this itself.** `x` and `x/` name one node, so
/// the host does not rewrite the address to match the slot — on a flat store
/// the two spellings may be two distinct objects, and choosing for the backend
/// would be choosing which object a `delete_directory` destroys. A backend that
/// used the address's key verbatim as a listing prefix therefore matched every
/// sibling whose name merely starts with the directory's: `list …/docs` would
/// return the contents of `docsx` too.
#[must_use]
pub fn directory_key(key: &str) -> String {
    if key.is_empty() || key.ends_with('/') {
        key.to_string()
    } else {
        format!("{key}/")
    }
}

/// The specificity of a scope, for ordering one against another. More specific
/// sorts higher.
///
/// Depth first, then whether the scope pins a query. Ranking on depth alone
/// ties a pinned scope with its unpinned parent — same node path — so
/// declaration order decides and the pinned scope becomes unreachable for
/// precisely the address it publishes.
///
/// **How a tie resolves is the caller's choice**: a `Reverse` stable sort keeps
/// the first-declared scope, `max_by_key` the last-declared one.
#[must_use]
pub fn node_rank(url: &Url) -> (usize, bool) {
    ovstorage_layer::node_rank(url)
}

/// Normalize an **already-parsed** URL into the canonical spelling of the node
/// it names.
///
/// [`parse`] is `Url::parse` followed by this, and is what a consumer holding a
/// string wants. This is for a consumer that already holds a `Url` and must
/// compare it against something canonical — the authorization matcher, which
/// works over decoded path components and so needs dot segments and empty
/// segments resolved before it can compare anything.
///
/// Idempotent: the canonical encoding set includes `%`, so a second pass cannot
/// peel another escape layer, and every other step is a fixed point.
#[must_use]
pub fn canonicalize(url: Url) -> Url {
    ovstorage_layer::canonicalize(url)
}

/// Resolve dot segments and collapse runs of `/` in an already-decoded path.
///
/// The same pipeline `canonicalize` applies, exposed for a consumer that has
/// rewritten a path itself and must normalize the result the same way. The
/// authorization matcher does exactly that on Windows, where `\` is a
/// component separator: rewriting it creates dot segments and empty segments
/// that nothing else would resolve.
#[must_use]
pub fn normalize_decoded_path(decoded: &[u8]) -> Vec<u8> {
    ovstorage_layer::normalize_decoded_path(decoded)
}

/// True when the URL refers to a directory (path ends with `/`).
pub fn is_directory(url: &Url) -> bool {
    url.path().ends_with('/')
}

/// Append `/` if missing, preserving query and fragment.
///
/// # Errors
///
/// Never fails; always returns `Ok`.
pub fn to_directory(url: &Url) -> Result<Url> {
    if is_directory(url) {
        return Ok(url.clone());
    }
    let mut out = url.clone();
    let new_path = format!("{}/", out.path());
    out.set_path(&new_path);
    Ok(out)
}

/// Split into `(parent_directory, child_name)`. `child_name` is
/// percent-decoded with the byte-exact decode [`key`] uses, and is bytes for
/// the same reason: a name is part of an object's identity, and a name is not
/// required to be valid UTF-8. Returns `None` for directory-form URLs, root
/// paths, or URLs carrying a fragment.
pub fn parent_and_name(url: &Url) -> Option<(Url, Vec<u8>)> {
    if is_directory(url) || url.fragment().is_some() {
        return None;
    }
    let path = url.path();
    let slash = path.rfind('/')?;
    let name = &path[slash + 1..];
    if name.is_empty() {
        return None;
    }
    let mut parent = url.clone();
    parent.set_path(&path[..=slash]);
    parent.set_query(None);
    parent.set_fragment(None);
    Some((parent, percent_decode(name)))
}

/// Replace `prefix` with `replacement` at the head of `url`.
/// Returns `Err(NoRoute)` for a non-prefix.
///
/// # Errors
///
/// - [`ErrorCode::NoRoute`] — `url` does not start with `prefix`.
/// - [`ErrorCode::InvalidArgument`] — the combined result is not a valid URL.
pub fn replace_prefix(url: &Url, prefix: &Url, replacement: &Url) -> Result<Url> {
    let suffix = relative_suffix(url, prefix).ok_or_else(|| {
        Error::new(
            ErrorCode::NoRoute,
            "address is not under the selected route prefix",
        )
    })?;

    // Join on the replacement's PATH, not on its serialized string.
    //
    // Concatenating the two strings fused them whenever `prefix` ended in `/`,
    // because the suffix then has no leading separator: `alias:///a/hello.txt`
    // through `to = file:///tmp/xyz` became `file:///tmp/xyzhello.txt`. It also
    // spliced the suffix into the wrong component whenever `replacement`
    // carried a query, appending a path to the query string.
    //
    // Inserting a missing separator is not enough either: a `/`-terminated
    // replacement and a `/`-led suffix would then produce an empty segment,
    // which names a different node. Trimming one from each side and adding
    // exactly one collapses all four combinations.
    let (rest, _fragment) = suffix.split_once('#').unwrap_or((suffix, ""));
    let suffix_path = rest.split_once('?').map_or(rest, |(path, _)| path);
    // The query comes from the ADDRESS, not from the suffix string, and that is
    // the whole of the derivation rather than a correction to it.
    //
    // Deriving it from the suffix was wrong in one case and redundant in every
    // other. The suffix is a tail of `url.as_str()`, so whatever follows its
    // `?` is byte-identical to `url.query()` — except when `url` and `prefix`
    // are byte-identical, where `strip_prefix` returns `""` and the query left
    // with the head. There, `https://cdn/c/?v=2` under prefix
    // `https://cdn/c/?v=2` reached the replacement UNPINNED while its own child
    // `https://cdn/c/x?v=2` reached it pinned — and the root is the address the
    // route was written for.
    //
    // Reading it off the address once removes the case rather than patching it.
    // It cannot over-reach onto a prefix's own pin either: when `prefix` carries
    // a query, `is_ancestor_or_self` requires `url.query() == prefix.query()`,
    // so the value taken here is the pin the route already agreed on. A
    // replacement's own query still survives when neither side carries one.
    let suffix_query = url.query();

    // An empty suffix means `url` names the prefix's own node, and there the
    // trailing slash comes from the ADDRESS, never from how either prefix was
    // spelled. That is what makes the projection transparent to a flat store's
    // `p` versus `p/`.
    //
    // Reading it off the replacement instead collapsed the two whenever the
    // operator wrote `from` in directory form: `is_ancestor_or_self` covers
    // both spellings of the node it names, so `alias:///a/` and `alias:///a`
    // both reduce to an empty suffix, and both then came out as
    // `replacement.path()` verbatim. With `to = "s3://b/docs"` a `read` of the
    // directory address returned the file's bytes and a `delete` of it
    // destroyed the file. The unslashed-`from` spelling was correct, so the
    // defect was a function of the operator's spelling alone.
    //
    // The two trims below cannot serve this case: `/` trims to `""`, so a
    // single trim-and-join would map both spellings to one result — which is
    // the collapse, reached from the other direction.
    let path = if suffix_path.is_empty() {
        let base = ovstorage_layer::node_path(replacement);
        // The root has no unslashed spelling — `node_path` answers `/` for it,
        // and appending another would name an empty segment rather than the
        // root's directory form.
        if base == "/" || !url.path().ends_with('/') {
            base.to_string()
        } else {
            format!("{base}/")
        }
    } else {
        let base = replacement
            .path()
            .strip_suffix('/')
            .unwrap_or(replacement.path());
        let tail = suffix_path.strip_prefix('/').unwrap_or(suffix_path);
        format!("{base}/{tail}")
    };

    let mut out = replacement.clone();
    out.set_path(&path);
    // The suffix's own query wins; otherwise the replacement keeps its own. The
    // fragment is dropped, which `parse` would do anyway.
    if suffix_query.is_some() {
        out.set_query(suffix_query);
    }
    out.set_fragment(None);
    parse(out.as_str())
}

/// True when `a` and `b` name the same node.
///
/// A single trailing `/` is not part of node identity: `x` and `x/` are one
/// node, and which one a caller wrote is a rendering choice. The query **is**
/// part of it, because a version pin selects which object is served — so
/// `s3://b/x?versionId=1` and `s3://b/x` are two nodes. There is no fragment to
/// consider: [`parse`] strips it.
///
/// This is the identity question with no string surgery attached, which is why
/// it is separate from [`relative_suffix`]. Ask it wherever two addresses are
/// compared for sameness; `==` on `Url` answers a question about spelling.
#[must_use]
pub fn same_node(a: &Url, b: &Url) -> bool {
    ovstorage_layer::node_key(a) == ovstorage_layer::node_key(b)
}

/// The suffix of `addr` below `prefix`, or `None` when `prefix` is not an
/// ancestor-or-self of it.
///
/// **Concatenation-safe, and deliberately not symmetric.** This feeds
/// [`replace_prefix`], which is how the alias layer projects an address from
/// one prefix onto another, and a projection must carry the suffix through
/// verbatim or aliasing changes which object a spelling names. So a
/// slash-terminated `prefix` naming the same node as an unterminated `addr`
/// yields `Some("")`, while the reverse still yields `Some("/")`.
///
/// **What that buys: the projected address's trailing slash is always the
/// ADDRESS's own**, whatever spelling either prefix was written in. On a flat
/// store `p` and `p/` are two objects, and the alias has to be transparent to
/// that — so two caller spellings must never reduce to one projected address.
///
/// This function supplies half of it and [`replace_prefix`] the other half.
/// Here the mixed spellings are asymmetric on purpose: a slash-terminated
/// `prefix` naming the same node as an unterminated `addr` yields `Some("")`,
/// while the reverse yields `Some("/")`. But `is_ancestor_or_self` covers both
/// spellings of the node a prefix names, so a slash-terminated `prefix`
/// reduces BOTH `p` and `p/` to `Some("")` — the empty suffix says "this
/// address names the prefix's node" and does not say which spelling of it.
/// `replace_prefix` reads that from the address rather than from the
/// replacement, which is what keeps the two apart.
///
/// `an_alias_projection_carries_the_addresss_own_trailing_slash` pins all
/// sixteen combinations, so this paragraph cannot rot into a claim the code
/// stopped making.
///
/// Ask [`same_node`] instead when the question is identity rather than string
/// surgery. Keeping the asymmetry inside the one function whose job is string
/// surgery is what stops it from becoming a caveat on the identity predicate.
#[must_use]
pub fn relative_suffix<'a>(addr: &'a Url, prefix: &Url) -> Option<&'a str> {
    if !is_ancestor_or_self(prefix, addr) {
        return None;
    }
    let serialized = addr.as_str();
    if let Some(suffix) = serialized.strip_prefix(prefix.as_str()) {
        return Some(suffix);
    }
    // `prefix` names an ancestor-or-self whose own spelling is not a string
    // prefix of `addr` — the two differ in the trailing slash, in userinfo, or
    // in both. Re-spell the prefix's node using THIS address's own authority so
    // the head aligns, then strip that.
    //
    // **Never guess a suffix here.** Falling back to an empty one projects the
    // address onto the replacement's ROOT: an alias `logical://h/pub/` →
    // `s3://b/private` would answer `read logical://user@h/pub/allowed` with
    // the object `s3://b/private` itself, which authorization approved a child
    // of. `None` costs a `NoRoute`; a wrong suffix costs the wrong object.
    let mut head = addr.clone();
    head.set_query(None);
    head.set_fragment(None);
    head.set_path(prefix.path());
    if let Some(suffix) = serialized.strip_prefix(head.as_str()) {
        return Some(suffix);
    }
    // `addr` is the other spelling of the prefix's node. Strip the node form,
    // so a modifier tail survives the projection instead of being dropped with
    // the slash.
    head.set_path(ovstorage_layer::node_path(prefix));
    serialized.strip_prefix(head.as_str())
}

/// True when `prefix` names an ancestor of `addr`, or the same node.
///
/// Segment-aligned on **components**, not on the serialized string: `…/foo`
/// does not match `…/foobar`, and a single trailing `/` is not part of node
/// identity, so a root published as `…/root/` covers `…/root` and everything
/// beneath it.
///
/// Comparing serialized strings is what made containment depend on how the
/// prefix was spelled. `s3://b/root?versionId=1` matched the slashless root
/// through the `?` boundary and missed the slashed one, so the two spellings of
/// one root disagreed about pinned addresses — which is the routing failure
/// this predicate exists to remove, one class narrower.
///
/// **A prefix carrying a query matches only that exact query.** Admitting a
/// `&`-aligned narrowing gives `relative_suffix` a third grammar to return —
/// neither a path nor a `?query` but a bare `&`-led continuation — which
/// [`replace_prefix`] then joins as a path segment: `s3://b/root?versionId=1`
/// projecting `s3://b/root?versionId=1&b=2` produced the key `mirror/&b=2`
/// with the pin gone. Exact equality removes the case rather than specifying
/// around it, and it can only narrow containment.
#[must_use]
pub fn is_ancestor_or_self(prefix: &Url, addr: &Url) -> bool {
    if prefix.scheme() != addr.scheme()
        || prefix.host_str() != addr.host_str()
        || prefix.port() != addr.port()
    {
        return false;
    }
    if !path_contains(
        ovstorage_layer::node_path(prefix),
        ovstorage_layer::node_path(addr),
    ) {
        return false;
    }
    match prefix.query() {
        None => true,
        Some(pinned) => addr.query() == Some(pinned),
    }
}

/// Segment-aligned containment over two node paths.
///
/// Both operands have already had one trailing `/` removed, so an ancestor is
/// either equal or followed by a separator. The `ends_with('/')` arm is for the
/// root, whose node path is `/` and which therefore contains everything under
/// its authority.
fn path_contains(prefix: &str, path: &str) -> bool {
    if prefix == path {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some(rest) => prefix.ends_with('/') || rest.starts_with('/'),
        None => false,
    }
}

/// Append or replace one query parameter with URL-parser semantics.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — `key` is empty.
pub fn with_query_pair(url: &Url, key: &str, value: &str) -> Result<Url> {
    if key.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "query parameter key must not be empty",
        ));
    }
    let mut out = url.clone();
    let preserved: Vec<(String, String)> = out
        .query_pairs()
        .filter(|(k, _)| k != key)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    out.set_query(None);
    {
        let mut q = out.query_pairs_mut();
        for (k, v) in &preserved {
            q.append_pair(k, v);
        }
        q.append_pair(key, value);
    }
    Ok(out)
}

/// Append a relative backend key. The key must not start with `/`.
/// Empty keys are a no-op.
///
/// `relative_path` is **decoded data** — the bytes the backend gave us, not URL
/// syntax — so it is percent-encoded on the way in. Without that step
/// `Url::set_path` leaves a literal `%` bare and the emitted address re-derives
/// to a different key: an object named `dir/a%2Fb` would be handed out as
/// `s3://b/dir/a%2Fb`, which resolves to `dir/a/b`. A `/` in the key stays a
/// separator, because the canonical set omits it.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — `relative_path` starts with `/`.
pub fn join_relative(url: &Url, relative_path: &str) -> Result<Url> {
    join_relative_bytes(url, relative_path.as_bytes())
}

/// [`join_relative`] for an emitter that holds the key as raw bytes.
///
/// A backend key is an arbitrary byte sequence and the `file:` backend resolves
/// one byte for byte, so an emitter that had to spell its key as a `&str` first
/// would have to drop every key that is not valid UTF-8 — silently hiding files
/// the backend can open. The escape set works on bytes, so nothing is lost by
/// taking them directly.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — `relative_path` starts with `/`, or is
///   not addressable as a URI path.
pub fn join_relative_bytes(url: &Url, relative_path: &[u8]) -> Result<Url> {
    if relative_path.starts_with(b"/") {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "relative paths must not start with '/'",
        ));
    }
    if relative_path.is_empty() {
        return Ok(url.clone());
    }
    let mut base = url.clone();
    let encoded = ovstorage_layer::encode_canonical_path(&base, relative_path);
    let new_path = if base.path().ends_with('/') {
        format!("{}{}", base.path(), encoded)
    } else {
        format!("{}/{}", base.path(), encoded)
    };
    base.set_path(&new_path);

    // The emitted address must name the key it was built from. Two things can
    // break that, and neither is exotic:
    //
    //   key "a/../b"  -> `set_path` resolves the dot segment, so the address
    //                    names `b`. Under a configured prefix it is worse than
    //                    wrong — `a/../../etc` under `p/` climbs OUT of the
    //                    prefix to `bucket/etc`.
    //   key "a//b"    -> survives `set_path`, but canonicalization collapses
    //                    the empty segment, so the address names `a/b` the
    //                    moment anyone re-parses it.
    //
    // A caller handed such an address reads, or deletes, a different object
    // than the one it was listed. The key is not expressible as a URI path, so
    // it is refused here rather than approximated — the same treatment, and the
    // same reason, as a key that is not valid UTF-8.
    if base.path() != new_path || !ovstorage_layer::canonicalize_preserves_node(&base) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "backend key is not addressable as a URI path: {:?}",
                String::from_utf8_lossy(relative_path)
            ),
        ));
    }

    Ok(base)
}

fn percent_decode(input: &str) -> Vec<u8> {
    // Manual decode: `url`'s `percent_decode_str` is gated behind a
    // feature flag, and pulling in `percent-encoding` separately is
    // not worth it for this single use site.
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared config-address predicate, on the raw string.
    ///
    /// This is a unit test of the predicate alone. Whether each loader calls
    /// it is a separate question, asserted at each loader — `plugin-http`'s
    /// `a_config_address_may_not_carry_a_query_or_a_fragment`, alias's
    /// `a_query_or_a_fragment_is_refused_in_every_rule_field`, the authz
    /// `query_and_fragment_prefixes_fail_to_load`, OpenDAL's
    /// `a_prefix_carrying_a_query_or_a_fragment_is_refused`, the broker's
    /// `an_oauth_route_carrying_a_query_or_a_fragment_is_refused`, and the
    /// file backend's
    /// `a_file_url_root_refuses_a_query_or_fragment_and_a_path_root_escapes_them`.
    ///
    /// The fragment rows are the ones that need a raw scan: `parse` strips a
    /// fragment, so the last assertion here — that a fragment survives no round
    /// trip through `parse` — is why a post-parse check would be a guard that
    /// cannot execute, and why every config loader calls this instead.
    #[test]
    fn the_config_component_predicate_reads_the_raw_string() {
        for (text, want) in [
            ("s3://b/x", None),
            ("s3://b/x/", None),
            // The escaped spellings are literal key bytes, not delimiters.
            ("s3://b/x%3Fy%23z", None),
            ("s3://b/x?v=1", Some(ConfigComponent::Query)),
            // An empty query is still a query: `?` is the delimiter.
            ("s3://b/x?", Some(ConfigComponent::Query)),
            ("s3://b/x#note", Some(ConfigComponent::Fragment)),
            ("https://h#note", Some(ConfigComponent::Fragment)),
            // Whichever comes first names the component; both get reported,
            // one load at a time.
            ("s3://b/x?v=1#note", Some(ConfigComponent::Query)),
            ("s3://b/x#note?v=1", Some(ConfigComponent::Fragment)),
        ] {
            assert_eq!(refused_config_component(text), want, "{text}");
        }
        assert_eq!(ConfigComponent::Query.name(), "query");
        assert_eq!(ConfigComponent::Fragment.name(), "fragment");

        // The reason the scan is on the raw string: after `parse` the fragment
        // is gone and the query is not, so only one of the two could be caught
        // from a `Url`.
        let parsed = parse("s3://b/x?v=1#note").unwrap();
        assert_eq!(parsed.fragment(), None);
        assert_eq!(parsed.query(), Some("v=1"));
    }

    /// An alias projection carries the ADDRESS's own trailing slash, whatever
    /// spelling either prefix was written in.
    ///
    /// On a flat store `p` and `p/` are two objects, so two caller spellings
    /// reducing to one projected address hands one of the two callers the
    /// wrong object. That is what a slash-terminated `from` used to do: with
    /// `from = "alias:///a/"` and `to = "s3://b/docs"`, both `alias:///a` and
    /// `alias:///a/` projected onto `s3://b/docs`, so a `read` of the
    /// directory address returned the file's bytes and a `delete` of it
    /// destroyed the file.
    ///
    /// All sixteen combinations of (prefix slash, address slash, replacement
    /// slash) at the prefix's own node plus the below-prefix rows, because the
    /// defect was invisible to a table that exercised only the unslashed
    /// prefix.
    ///
    /// Load-bearing line: the `url.path().ends_with('/')` test in
    /// `replace_prefix`'s empty-suffix branch. Reading the slash off
    /// `replacement` instead turns the four `MERGED-BEFORE` rows red.
    #[test]
    fn an_alias_projection_carries_the_addresss_own_trailing_slash() {
        // (prefix, addr, to, projected)
        for (prefix, addr, to, want) in [
            // Unslashed prefix.
            ("s3://b/p", "s3://b/p", "s3://c/q", "s3://c/q"),
            ("s3://b/p", "s3://b/p/", "s3://c/q", "s3://c/q/"),
            ("s3://b/p", "s3://b/p", "s3://c/q/", "s3://c/q"),
            ("s3://b/p", "s3://b/p/", "s3://c/q/", "s3://c/q/"),
            // Slashed prefix. The first and third rows are MERGED-BEFORE: both
            // used to come out as the replacement's own spelling, so this pair
            // and the pair above it collided.
            ("s3://b/p/", "s3://b/p", "s3://c/q", "s3://c/q"),
            ("s3://b/p/", "s3://b/p/", "s3://c/q", "s3://c/q/"),
            ("s3://b/p/", "s3://b/p", "s3://c/q/", "s3://c/q"),
            ("s3://b/p/", "s3://b/p/", "s3://c/q/", "s3://c/q/"),
            // Strictly below the prefix, under every spelling of both sides.
            ("s3://b/p", "s3://b/p/c", "s3://c/q", "s3://c/q/c"),
            ("s3://b/p", "s3://b/p/c/", "s3://c/q", "s3://c/q/c/"),
            ("s3://b/p", "s3://b/p/c", "s3://c/q/", "s3://c/q/c"),
            ("s3://b/p", "s3://b/p/c/", "s3://c/q/", "s3://c/q/c/"),
            ("s3://b/p/", "s3://b/p/c", "s3://c/q", "s3://c/q/c"),
            ("s3://b/p/", "s3://b/p/c/", "s3://c/q", "s3://c/q/c/"),
            ("s3://b/p/", "s3://b/p/c", "s3://c/q/", "s3://c/q/c"),
            ("s3://b/p/", "s3://b/p/c/", "s3://c/q/", "s3://c/q/c/"),
        ] {
            let got = replace_prefix(
                &parse(addr).unwrap(),
                &parse(prefix).unwrap(),
                &parse(to).unwrap(),
            )
            .unwrap_or_else(|error| {
                panic!("{addr} under {prefix} must project: {}", error.message())
            });
            assert_eq!(got.as_str(), want, "prefix={prefix} addr={addr} to={to}");
        }

        // The root replacement has no unslashed spelling, so both address
        // spellings project onto it and neither manufactures an empty segment.
        for addr in ["s3://b/p", "s3://b/p/"] {
            let got = replace_prefix(
                &parse(addr).unwrap(),
                &parse("s3://b/p/").unwrap(),
                &parse("s3://c/").unwrap(),
            )
            .unwrap();
            assert_eq!(got.as_str(), "s3://c/", "{addr} onto a root replacement");
        }
    }

    #[test]
    fn percent_encoded_path_decodes_to_key() {
        let url = parse("s3://bucket/foo%20bar.txt").unwrap();
        assert_eq!(url.as_str(), "s3://bucket/foo%20bar.txt");
        assert_eq!(key(&url), b"foo bar.txt");
    }

    #[test]
    fn double_percent_encoding_round_trips_literal_percent() {
        let url = parse("s3://bucket/foo%2520bar.txt").unwrap();
        assert_eq!(key(&url), b"foo%20bar.txt");
    }

    #[test]
    fn question_mark_in_key_must_be_percent_encoded() {
        // Literal ? would split into a query.
        let url = parse("s3://bucket/foo%3Fbar.txt").unwrap();
        assert_eq!(key(&url), b"foo?bar.txt");
        assert!(url.query().is_none());
    }

    #[test]
    fn space_in_input_canonicalizes_to_percent_encoded() {
        let url = parse("s3://bucket/foo bar.txt").unwrap();
        assert_eq!(url.as_str(), "s3://bucket/foo%20bar.txt");
        assert_eq!(key(&url), b"foo bar.txt");
    }

    /// Two names the `file:` backend can tell apart must stay two keys.
    ///
    /// `Url::to_file_path` is byte-exact, so `x%FF` and `x%FE` open different
    /// files. Replacing each invalid sequence with U+FFFD made one key of them,
    /// and every consumer deriving that key — the authorization matcher above
    /// all — became coarser than the backend it guards.
    #[test]
    fn a_key_that_is_not_utf8_keeps_its_bytes() {
        assert_eq!(key(&parse("s3://bucket/x%FF").unwrap()), b"x\xFF");
        assert_ne!(
            key(&parse("s3://bucket/x%FF").unwrap()),
            key(&parse("s3://bucket/x%FE").unwrap()),
            "two distinct files must not derive one key"
        );
        assert_eq!(
            decode_segment("x%FF"),
            b"x\xFF",
            "the segment decode must agree with the key decode byte for byte"
        );
    }

    /// A backend that cannot spell such a key says so instead of guessing.
    #[test]
    fn key_utf8_refuses_what_it_cannot_spell() {
        assert_eq!(
            key_utf8(&parse("s3://bucket/pub%20x").unwrap()).unwrap(),
            "pub x"
        );
        let error = key_utf8(&parse("s3://bucket/x%FF").unwrap())
            .expect_err("a non-UTF-8 key has no `&str` spelling");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    /// A projection must carry the whole suffix, whatever the authority says.
    ///
    /// `is_ancestor_or_self` ignores userinfo — a credential in an address
    /// confers nothing, and ovstorage authorizes principals — so a prefix
    /// written without one is an ancestor of an address that has one. Their
    /// serializations then do not align, and a fallback that guessed an empty
    /// suffix would project every such address onto the replacement's ROOT: an
    /// alias `logical://h/pub/` -> `s3://b/private` would answer a read of
    /// `logical://user@h/pub/allowed` with the object `s3://b/private`.
    #[test]
    fn a_projection_keeps_its_suffix_across_differing_userinfo() {
        let prefix = parse("logical://h/pub/").unwrap();
        let replacement = parse("s3://b/private").unwrap();
        for spelling in [
            "logical://user@h/pub/allowed",
            "logical://user:pw@h/pub/allowed",
            "logical://h/pub/allowed",
        ] {
            let addr = parse(spelling).unwrap();
            assert_eq!(
                relative_suffix(&addr, &prefix),
                Some("allowed"),
                "{spelling} must keep its suffix"
            );
            assert_eq!(
                replace_prefix(&addr, &prefix, &replacement)
                    .unwrap()
                    .as_str(),
                "s3://b/private/allowed",
                "{spelling} must project onto the child, never onto the root"
            );
        }

        // The node itself still projects onto the replacement root, which is
        // the one case an empty suffix is correct for.
        let node = parse("logical://user@h/pub").unwrap();
        assert_eq!(relative_suffix(&node, &prefix), Some(""));
    }

    /// The six join shapes, because the obvious guard passes the first four.
    ///
    /// A raw concatenation fused the replacement with the suffix whenever the
    /// prefix ended in `/`. An insert-only guard fixes that and then produces
    /// an empty segment for the `/`-terminated replacement, which names a
    /// different node. Trimming one separator from each side and adding exactly
    /// one is what collapses every combination to a single separator while
    /// keeping the empty suffix distinct from `/`.
    #[test]
    fn replace_prefix_joins_on_exactly_one_separator() {
        for (prefix, address, replacement, expected) in [
            // The fused case: a slashed `from` and an unslashed `to`.
            (
                "alias:///a/",
                "alias:///a/hello.txt",
                "file:///tmp/xyz",
                "file:///tmp/xyz/hello.txt",
            ),
            // Already correct, and must stay so.
            (
                "alias:///a/",
                "alias:///a/hello.txt",
                "file:///tmp/xyz/",
                "file:///tmp/xyz/hello.txt",
            ),
            // The insert-only guard's failure: a `/`-led suffix onto a
            // `/`-terminated replacement must not make an empty segment.
            (
                "alias:///a",
                "alias:///a/hello.txt",
                "gs://b/p/",
                "gs://b/p/hello.txt",
            ),
            // A flat store's two objects stay two: the node itself projects
            // onto the replacement, its directory form onto the directory.
            ("alias:///a", "alias:///a", "gs://b/p", "gs://b/p"),
            ("alias:///a", "alias:///a/", "gs://b/p", "gs://b/p/"),
            // A modifier tail lands in the query, never in the path.
            (
                "alias:///a/",
                "alias:///a/hello.txt?versionId=1",
                "s3://b/p",
                "s3://b/p/hello.txt?versionId=1",
            ),
            // The EXACT root of a query-bearing prefix keeps its query, like
            // the descendant beneath it. These two rows belong together: the
            // suffix string is `""` for the first and `x?v=2` for the second,
            // so deriving the query from the strip alone projected the root
            // unpinned while every child stayed pinned — the root being the
            // address the route was written for.
            (
                "https://cdn/c/?v=2",
                "https://cdn/c/?v=2",
                "https://origin/c/",
                "https://origin/c/?v=2",
            ),
            (
                "https://cdn/c/?v=2",
                "https://cdn/c/x?v=2",
                "https://origin/c/",
                "https://origin/c/x?v=2",
            ),
            // And a query-free address under a query-free prefix gains none.
            (
                "https://cdn/c/",
                "https://cdn/c/",
                "https://origin/c/",
                "https://origin/c/",
            ),
            // The replacement's OWN query survives when neither side carries
            // one. Without this row a mutation that drops it — reading the
            // query off the address unconditionally into a cleared slot —
            // passes every other row here, because every other replacement is
            // query-free.
            (
                "https://cdn/c/",
                "https://cdn/c/",
                "https://origin/c/?token=abc",
                "https://origin/c/?token=abc",
            ),
            // And the address's pin still wins over the replacement's query
            // where both exist, exactly as it does for a descendant.
            (
                "https://cdn/c/?v=2",
                "https://cdn/c/?v=2",
                "https://origin/c/?token=abc",
                "https://origin/c/?v=2",
            ),
        ] {
            assert_eq!(
                replace_prefix(
                    &parse(address).unwrap(),
                    &parse(prefix).unwrap(),
                    &parse(replacement).unwrap()
                )
                .unwrap()
                .as_str(),
                expected,
                "{address} through {prefix} -> {replacement}"
            );
        }
    }

    /// A pinned prefix covers that pin and nothing else.
    ///
    /// Admitting a `&`-aligned narrowing gave `relative_suffix` a third
    /// grammar — a bare `&`-led continuation, neither path nor `?query` — and
    /// `replace_prefix` joined it as a path segment: an alias for one exact
    /// object reached `mirror/&b=2`, with the version pin gone.
    #[test]
    fn a_pinned_prefix_does_not_cover_a_narrowed_query() {
        let prefix = parse("s3://b/root?versionId=1").unwrap();
        assert!(is_ancestor_or_self(
            &prefix,
            &parse("s3://b/root?versionId=1").unwrap()
        ));
        for outside in [
            "s3://b/root?versionId=1&b=2",
            "s3://b/root?versionId=2",
            "s3://b/root",
        ] {
            let addr = parse(outside).unwrap();
            assert!(
                !is_ancestor_or_self(&prefix, &addr),
                "{outside} is a different scope from the pin"
            );
            assert!(relative_suffix(&addr, &prefix).is_none());
        }
    }

    /// The prefix's own trailing slash does not swallow a modifier tail.
    #[test]
    fn a_pinned_address_keeps_its_pin_through_a_slashed_prefix() {
        let prefix = parse("s3://b/root/").unwrap();
        let addr = parse("s3://b/root?versionId=1").unwrap();
        assert_eq!(relative_suffix(&addr, &prefix), Some("?versionId=1"));
    }

    #[test]
    fn is_ancestor_or_self_segment_aligned() {
        let prefix = parse("s3://bucket/foo").unwrap();
        let same = parse("s3://bucket/foo").unwrap();
        let child = parse("s3://bucket/foo/bar").unwrap();
        let unrelated = parse("s3://bucket/foobar").unwrap();
        assert!(is_ancestor_or_self(&prefix, &same));
        assert!(is_ancestor_or_self(&prefix, &child));
        assert!(!is_ancestor_or_self(&prefix, &unrelated));
    }

    #[test]
    fn is_ancestor_or_self_directory_form_matches_descendants() {
        let prefix = parse("s3://bucket/dir/").unwrap();
        let child = parse("s3://bucket/dir/sub/file.txt").unwrap();
        assert!(is_ancestor_or_self(&prefix, &child));
    }

    #[test]
    fn parent_and_name_splits_on_last_slash() {
        let url = parse("s3://bucket/dir/file.txt").unwrap();
        let (parent, name) = parent_and_name(&url).unwrap();
        assert_eq!(parent.as_str(), "s3://bucket/dir/");
        assert_eq!(name, b"file.txt");
    }

    #[test]
    fn parent_and_name_decodes_filename() {
        let url = parse("s3://bucket/dir/foo%20bar.txt").unwrap();
        let (parent, name) = parent_and_name(&url).unwrap();
        assert_eq!(parent.as_str(), "s3://bucket/dir/");
        assert_eq!(name, b"foo bar.txt");
    }

    #[test]
    fn parent_and_name_directory_returns_none() {
        let url = parse("s3://bucket/dir/").unwrap();
        assert!(parent_and_name(&url).is_none());
    }

    #[test]
    fn to_directory_appends_slash() {
        let url = parse("s3://bucket/dir").unwrap();
        let dir = to_directory(&url).unwrap();
        assert_eq!(dir.as_str(), "s3://bucket/dir/");
    }

    #[test]
    fn with_query_pair_appends_to_existing_query() {
        let url = parse("s3://bucket/foo.txt?other=ignored").unwrap();
        let out = with_query_pair(&url, "versionId", "abc").unwrap();
        assert!(out.as_str().contains("versionId=abc"));
        assert!(out.as_str().contains("other=ignored"));
    }

    #[test]
    fn replace_prefix_swaps_segment() {
        let addr = parse("server://new/bar/baz.txt").unwrap();
        let old = parse("server://new/").unwrap();
        let new = parse("server://old/").unwrap();
        let out = replace_prefix(&addr, &old, &new).unwrap();
        assert_eq!(out.as_str(), "server://old/bar/baz.txt");
    }
}

#[cfg(test)]
mod join_relative_round_trip {
    use super::*;

    /// A key must survive being turned into an address and read back.
    ///
    /// `set_path` does not escape `%`, so before the emit-side escape an object
    /// named `dir/a%2Fb` was handed out as `s3://b/dir/a%2Fb` — an address that
    /// re-derives to `dir/a/b`. `list` emitted it and `read`, `stat` and
    /// `delete` resolved a different object.
    #[test]
    fn keys_round_trip_through_the_emitted_address() {
        let root = parse("s3://bucket/").unwrap();
        for original in [
            "dir/a%2Fb",  // the literal-percent case that motivated this
            "dir/pl%75s", // would have decoded to "plus"
            "a b",        // a space: ordinary, and broken in the other direction
            "a%25b",
            "100%",
            "a+b",
            "dir/nested/x.txt",
        ] {
            let address = join_relative(&root, original).unwrap();
            assert_eq!(
                key(&address),
                original.as_bytes(),
                "{original} must survive the round trip, got {address}"
            );
        }
    }

    /// A key that cannot be named by a URI path is refused, not approximated.
    ///
    /// Both shapes hand the caller an address for a different object. The
    /// dot-segment one additionally climbs out of a configured prefix, so a
    /// listing under a tenant root could emit an address outside it.
    #[test]
    fn keys_that_would_name_another_object_are_refused() {
        let prefixed = parse("s3://bucket/p/").unwrap();
        for key in [
            "a/../../etc", // escaped the prefix entirely: bucket/etc
            "..",          // escaped to the bucket root
            "a/../b",      // named bucket/p/b
            "a/./b",       // named bucket/p/a/b
            ".",
            "a//b", // survived set_path, collapses on re-parse
            "a//",
        ] {
            let error = join_relative(&prefixed, key)
                .expect_err("{key} names a different object and must be refused");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{key}");
        }
    }

    /// The separator stays a separator: the canonical set omits `/`, so a key
    /// with real path structure keeps it rather than becoming one flat segment.
    #[test]
    fn separators_in_a_key_stay_separators() {
        let root = parse("s3://bucket/").unwrap();
        let address = join_relative(&root, "dir/sub/x.txt").unwrap();
        assert_eq!(address.as_str(), "s3://bucket/dir/sub/x.txt");
    }
}
