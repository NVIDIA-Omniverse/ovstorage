// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Address canonicalization for the layer chain.
//!
//! Addresses are RFC 3986 [`url::Url`]s. The `url` crate guarantees a lot on
//! parse — it always lowercases the scheme, percent-encodes components, and for
//! its *special* schemes (http/https/ws/wss/ftp/file) also lowercases the host,
//! strips default ports, and resolves `.`/`..` path segments. But ovstorage's
//! addressing schemes (`s3`, `omniverse`, `nucleus`, …) are **non-special**, and
//! for those the crate lowercases only the scheme: it leaves the **host case**
//! as the caller typed it (`omniverse://SERVER` stays `SERVER`). RFC 3986 §6.2.2.1
//! makes the host case-insensitive, so two spellings that differ only in host
//! case are the same address — but to a layer doing string-prefix routing or
//! cache-key identity they would look different.
//!
//! [`canonicalize`] closes that gap (it lowercases the host) plus the
//! ovstorage-specific empty-authority-path rule below. It is the single source
//! of truth for both, applied at two boundaries so that **every layer in a
//! [`Stack`](crate::Stack) sees a canonical URL spelling** — the precondition
//! the alias wrappers, the caches (cache-key identity), and the router all rely
//! on:
//!
//! - at the string → [`Url`] boundary, by the host's URL parser (the
//!   `ovstorage-plugin` `address::parse` entry point delegates here); and
//! - at the [`Stack`](crate::Stack) entry, where [`Stack`](crate::Stack)
//!   canonicalizes every address-bearing request before delegating to its root
//!   layer — so a caller driving the `Stack` API directly (e.g. through the C
//!   ABI) cannot bypass the contract.
//!
//! The path is normalized too, and that rule carries the weight: escapes are
//! decoded to bytes, dot segments are resolved, and the result is re-encoded so
//! that no byte can be decoded a second time. Two spellings of one key
//! therefore become one address at construction, and every site downstream —
//! router, authorization matcher, cache, backend key derivation — compares a
//! single spelling without knowing anything about percent-encoding.
//!
//! Raw characters keep the WHATWG normalization `Url::parse` already applied
//! (`\` → `/` on special schemes, TAB/LF/CR stripping, the `file:` drive-letter
//! rewrite). Escaped characters are decoded exactly once and re-escaped so they
//! can never be decoded again. `/` is deliberately absent from the encode set:
//! a decoded `%2F` *becomes* a separator, which is what lets a dot segment
//! hiding behind one resolve.

use percent_encoding::{AsciiSet, CONTROLS, percent_decode, percent_encode};
use url::Url;

/// `PATH` plus `%` and `\`.
///
/// The first nine members are the `url` crate's own `PATH` set, which
/// [`Url::set_path`] re-applies — listing them here keeps the string handed to
/// the setter a fixed point, so the setter has nothing left to rewrite.
///
/// The two additions are what the crate will not do for us:
///
/// - `%` — [`Url::set_path`] takes serialized URL syntax, so it treats a `%` as
///   the caller's escape introducer and leaves it bare. Without this the
///   canonical form would peel one escape layer per pass and an address would
///   degrade on every round trip.
/// - `\` — the crate rewrites a raw `\` to `/` for special schemes including
///   `file:`, with no platform gate, so a decoded `%5C` would silently name a
///   different file **on a platform where `\` is not a separator**. On Windows
///   it is one, so keeping it escaped preserves the address but leaves the
///   matcher blind to an equivalence the OS honours — §7.3's gap, closed in the
///   matcher rather than here, because `canonicalize` must not vary by host.
const CANONICAL_PATH: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?')
    .add(b'{')
    .add(b'}')
    .add(b'%')
    .add(b'\\');

/// [`CANONICAL_PATH`] plus `|`, for a `file:` path with no authority.
///
/// [`Url::set_path`] reads a leading `C|` segment of a `file:` path as a
/// Windows drive letter and rewrites it to `C:` — on every platform, and with
/// the `|` spelling surviving `Url::parse` intact, so the rewrite happens on the
/// canonicalizer's own setter call *(executed)*:
///
/// ```text
/// Url::parse("file:///C|/x")            -> file:///C|/x
/// then set_path("/C|/x")                -> file:///C:/x   a different Linux file
/// ```
///
/// Escaping keeps the byte as data, so the rewrite has no trigger to fire on.
///
/// **`:` is deliberately absent**, which is what makes `file:///C:/data/x` the
/// canonical spelling of a Windows path rather than `file:///C%3A/data/x`. The
/// rewrite `:` triggers is a different one — the parser *discards the host* of a
/// `file:` URL whose first path segment is a drive letter — and it needs an
/// authority to discard. When there is one, [`CANONICAL_FILE_SHARE_PATH`]
/// applies instead.
///
/// The set is scoped to `file:` deliberately: a sweep over `s3`, `gs`,
/// `omniverse`, `azure`, `http` and `https` found the rewrite fires on none of
/// them *(executed)*.
const CANONICAL_FILE_PATH: &AsciiSet = &CANONICAL_PATH.add(b'|');

/// [`CANONICAL_FILE_PATH`] plus `:`, for a `file:` path that has an authority.
///
/// A `file:` URL whose first path segment reads as a Windows drive letter parses
/// with **no host at all**, so the share it named is gone one layer before this
/// set is reached: `file://server/C:/x` and `file://localhost/C:/x` both parse
/// to `file:///C:/x` *(executed)*. What survives parsing is the **escaped**
/// spelling — `file://server/C%3A/data.txt` parses with `host = "server"` — and
/// decoding it here would hand the drive letter back to [`Url::set_path`]. The
/// value keeps its host, but its serialization does not:
///
/// ```text
/// file://server/C%3A/data.txt   decoded and re-encoded without `:`
///   -> value  file://server/C:/data.txt   host = Some("server")
///   -> string file://server/C:/data.txt   re-parses with host = None
/// ```
///
/// A remote share becomes a local disk on the next hop, and addresses cross a
/// string boundary on every hop. Escaping `:` where an authority exists removes
/// the trigger; where there is none there is nothing to lose, and
/// [`CANONICAL_FILE_PATH`] leaves the drive letter readable.
const CANONICAL_FILE_SHARE_PATH: &AsciiSet = &CANONICAL_FILE_PATH.add(b':');

/// The path escape set for an address, chosen by scheme and by whether the
/// address has a HOST — not merely an authority. `file:///tmp/a:b` has an
/// authority and no host, and there is nothing for the drive-letter rewrite to
/// discard, so it takes the local set.
///
/// Both callers — [`canonicalize`] on the parse side and
/// [`encode_canonical_path`] on the emit side — must choose identically, or an
/// emitted address fails its own round-trip check.
fn canonical_path_set(url: &Url) -> &'static AsciiSet {
    match (url.scheme(), url.host_str()) {
        ("file", Some(_)) => CANONICAL_FILE_SHARE_PATH,
        ("file", None) => CANONICAL_FILE_PATH,
        _ => CANONICAL_PATH,
    }
}

/// Resolve `.` and `..` segments, per RFC 3986 §5.2.4.
///
/// Operates on raw bytes: the input is a percent-decoded path, which need not
/// be valid UTF-8, and no step of the algorithm inspects anything but `/` and
/// `.`.
///
/// **Only this function is RFC 3986 §5.2.4.** The pipeline that calls it
/// ([`normalize_path_bytes`]) collapses separator runs *first*, so by the time
/// this runs there is no empty segment left for a `..` to cancel. That ordering
/// is what makes `a//../b` and `a/../b` both name `b`, which is what a
/// filesystem does — it reads `a//..` as `a/..`. **Do not swap the two**: with
/// this function first, `a//..` becomes a no-op and an address that reads as
/// leaving an allowed subtree is judged as staying inside it.
///
/// The crate's own resolution would do this, but relying on it is incompatible
/// with requiring [`Url::set_path`] to be a no-op — if the setter is the thing
/// resolving segments then it changes the path, and the postcondition rejects
/// every address containing one. Resolving first is what makes the two
/// consistent.
fn remove_dot_segments(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut rest = input;

    while !rest.is_empty() {
        // The `/./` and `/../` arms consume only the dot segment and leave the
        // leading `/` in `rest`, which is the RFC's "replace the prefix with
        // `/`" without needing to prepend to a slice.
        if rest.starts_with(b"../") {
            rest = &rest[3..];
        } else if rest.starts_with(b"./") || rest.starts_with(b"/./") {
            // RFC 3986 §5.2.4 states these as two rules — drop a leading `./`,
            // and replace `/./` with `/`. Both advance two bytes: the second
            // consumes only `/.` and leaves its `/` in place as the replacement.
            rest = &rest[2..];
        } else if rest == b"/." {
            rest = &rest[..1];
        } else if rest.starts_with(b"/../") {
            rest = &rest[3..];
            truncate_last_segment(&mut out);
        } else if rest == b"/.." {
            rest = &rest[..1];
            truncate_last_segment(&mut out);
        } else if rest == b"." || rest == b".." {
            rest = b"";
        } else {
            // Move the first segment — the leading `/`, if any, plus everything
            // up to but not including the next `/` — across to the output.
            let after_leading_slash = usize::from(rest.first() == Some(&b'/'));
            let end = rest[after_leading_slash..]
                .iter()
                .position(|byte| *byte == b'/')
                .map_or(rest.len(), |offset| after_leading_slash + offset);
            out.extend_from_slice(&rest[..end]);
            rest = &rest[end..];
        }
    }

    out
}

/// Drop the last segment of `out`, and the `/` that precedes it.
fn truncate_last_segment(out: &mut Vec<u8>) {
    match out.iter().rposition(|byte| *byte == b'/') {
        Some(slash) => out.truncate(slash),
        None => out.clear(),
    }
}

/// Percent-encode `bytes` as a canonical URL path component.
///
/// This is the emit-side half of [`canonicalize`]: the same escape set, applied
/// where a backend key becomes an address instead of where an address is
/// normalized. Sharing it is the point — `Url::set_path` does not escape `%`,
/// so a key containing a literal one is otherwise handed back as an address
/// whose `%` is re-read as an escape introducer, and the caller resolves a
/// different object:
///
/// ```text
/// key "dir/a%2Fb"  emitted as  s3://b/dir/a%2Fb    re-derives to "dir/a/b"    WRONG
///                              s3://b/dir/a%252Fb  re-derives to "dir/a%2Fb"  right
/// ```
///
/// `/` is deliberately absent from the set, so a separator in the key stays a
/// separator. A key with a `/` *inside* a segment is therefore not expressible
/// as an address — the same accepted limitation as `%2F` on the parse side.
///
/// The set is chosen from `base`, the address the key is being appended to,
/// rather than from its scheme alone: a `file:` address escapes `:` only where
/// it has an authority to lose — escaping the drive designator is what keeps a
/// `file://server/C%3A/…` share from re-parsing as a local disk — and an
/// emitter that chose the other set would build an address that
/// [`canonicalize`] immediately rewrites.
#[must_use]
pub fn encode_canonical_path(base: &Url, bytes: &[u8]) -> String {
    percent_encode(bytes, canonical_path_set(base)).collect()
}

/// True when [`canonicalize`] would leave `url` naming the same node.
///
/// This is the predicate for validating an address a plugin or a server
/// **returned**, where normalizing would retarget the claim rather than
/// normalize it. It is deliberately narrow: the path pipeline
/// (`normalize_path_bytes`) is the only part of `canonicalize` that can move
/// an address to a *different* object. Lowercasing the host (RFC 3986 §6.2.2.1
/// makes it case-insensitive), giving an empty authority path a `/`, dropping
/// the fragment, and re-encoding to the canonical escape set all leave the node
/// alone, so a returned address must not be refused for any of them.
///
/// What it cannot see is emitter fidelity — whether the address names the key
/// the plugin meant. A plugin whose literal key is `a%2Fb` must emit
/// `a%252Fb`; if it emits `a%2Fb` that address unambiguously means the key
/// `a/b`, and the host has no way to know the difference because the original
/// key never crosses the boundary. That obligation is the plugin's, asserted by
/// conformance.
#[must_use]
pub fn canonicalize_preserves_node(url: &Url) -> bool {
    if url.cannot_be_a_base() {
        return true;
    }
    let decoded = percent_decode(url.path().as_bytes()).collect::<Vec<u8>>();
    normalize_path_bytes(&decoded) == decoded
}

/// True when `Url::parse` leaves `raw`'s AUTHORITY where its spelling puts it.
///
/// The narrow half of [`parsing_preserves_node`], separated so a caller whose
/// only hazard is the authority can ask for exactly that. A **configuration**
/// address is such a caller: normalizing its path is the point — that is what
/// parsing it is for — while destroying its authority silently rehomes it.
///
/// Two rewrites move an authority, and neither is visible in the parsed form:
///
/// - **Discard.** For `file:`, a first path segment the parser reads as a
///   Windows drive letter makes it drop the host: measured, both
///   `file://server/C:/x` and `file://server/C|/x` parse to `file:///C:/x`, so
///   a remote share is renamed to a local disk. `file://server/x` keeps its
///   host, so this refuses the rewrite and not the scheme. [`canonicalize`]
///   blocks the same rewrite from the other side by escaping `:` in the path of
///   a `file:` URL that has an authority, which is the only case where a host is
///   left to discard by the time it runs.
/// - **Fill.** An empty raw authority is `://` followed straight by what reads
///   as the path, and on the schemes that skip the extra slash the first
///   segment becomes the authority: measured, `https:///evil.example.com/x`
///   parses to `https://evil.example.com/x`, while `s3:///evil.example.com/x`
///   and `file:///tmp/x` keep their empty authority. Which schemes do this is
///   asked of the parser rather than enumerated: `file:` is a WHATWG special
///   scheme that does NOT skip, so the special-scheme list would be the wrong
///   list.
///
/// **A spelling the parser reads as having no authority is preserved**, which
/// is what makes this usable where the whole predicate is not: `file:/data/`
/// has nothing for either rewrite to move, and it is a published spelling of a
/// file root (`docs/public/plugin-storage/plugin-file.md`).
///
/// "The parser reads as" is doing work there, and it is the one thing a caller
/// must not simplify to "does not spell `scheme://`". On a folding scheme a raw
/// `\` decides where the authority begins, so `file:\\server\C:\data\` — the
/// spelling a Windows operator writes for a UNC share — has an authority, loses
/// it, and contains no `//` for a raw scan to find. That case is answered
/// before the scan, not by it.
///
/// **Only the `\` that decides an authority is answered that way**, never every
/// `\` in the address. A backslash inside the PATH is folded to `/` and moves
/// nothing this predicate speaks for: `file:///C:\data\` and `file:///C:/data/`
/// parse to one URL with no host at all, and the first is what a Windows
/// operator writes for a local root. Refusing it would reject a working
/// configuration — and would report a lost authority for an address that never
/// spelled one.
///
/// **Neither rewrite is scoped to `file:`.** Asking the parser rather than the
/// scheme is what makes that safe: `s3://:@/x` spells an authority and parses
/// to `s3:///x`, losing it, which is the same destruction the drive letter
/// performs on a scheme that has no drive letters.
///
/// `localhost` is excluded because the parser drops THAT authority by design,
/// not as a side effect: `file://localhost/tmp/x` and `file:///tmp/x` are the
/// same local file, the URL Standard says so, and the file backend accepts the
/// spelling. Refusing it would reject a working configuration on a form that
/// backend itself supports.
#[must_use]
pub fn parsing_preserves_authority(raw: &str) -> bool {
    // A byte the parser DELETES is answered before anything scans for
    // structure, because deleting one moves every boundary the scan is looking
    // for. `Url::parse` removes every ASCII TAB, LF and CR and trims C0
    // controls and spaces from both ends, so a raw scan reads a different
    // string from the one the parser reads. Measured, and this is the whole
    // guard defeated rather than a cosmetic difference:
    //
    //     file:/<TAB>/server/C:/data/  -> file:///C:/data/       host DESTROYED
    //     file:/<TAB>\\server\C:\data\ -> file:///C:/data/       host DESTROYED
    //     <SP>file:\\server\C:\data\   -> file:///C:/data/       host DESTROYED
    //
    // The last also hides the SCHEME: `split_once(':')` reads `" file"`, which
    // is not on the folding list, so every clause below is skipped. There is no
    // spelling to lose — the parser was going to delete the byte either way, so
    // an address that means to carry one must escape it (`%09`), and the
    // `file` backend's plain-path form escapes it for the operator.
    if raw
        .bytes()
        .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
        || raw.starts_with(|c: char| c.is_ascii() && c as u8 <= b' ')
        || raw.ends_with(|c: char| c.is_ascii() && c as u8 <= b' ')
    {
        return false;
    }
    // A raw `\` on a folding scheme is answered FIRST, because the fold is what
    // decides where the authority is — so it can create one, move one, or hide
    // one from the raw scan entirely. Measured, all four with no literal `//`
    // for `raw_authority` to find:
    //
    //     file:\\server\C:\data\   -> file:///C:/data/            host DESTROYED
    //     file:/\server/C:/data/   -> file:///C:/data/            host DESTROYED
    //     file:\\server\share\x    -> file://server/share/x       host CREATED
    //     https:/\evil.example.com/x -> https://evil.example.com/x  host CREATED
    //
    // The first is what a Windows operator writes for a UNC share, and without
    // this clause it reaches the drive-letter discard with `raw_authority`
    // reporting `None` — read as "no authority to lose" when the authority is
    // exactly what was lost.
    if let Some((scheme, rest)) = raw.split_once(':')
        && scheme_folds_backslash(scheme)
        && backslash_decides_authority(rest)
    {
        return false;
    }
    let Some(authority) = raw_authority(raw) else {
        // No `//` for the raw scan to find. That is NOT "no authority to
        // move": on a scheme that skips the extra slash, one leading separator
        // is enough for the parser to read the first path segment as a host —
        // measured, `https:/evil.example.com/x` and `https:\evil.example.com/x`
        // both parse with host `evil.example.com`, out of a string that spells
        // a path. So the question is put to the parser rather than answered
        // from the spelling: a host here is one the parser created.
        //
        // `file:/data/` is why this cannot be decided by scheme. `file:` is a
        // WHATWG special scheme that does NOT fill, so it parses hostless and
        // is accepted — and it is the published minimal spelling of a file
        // root. A spelling that does not parse is accepted for the reason
        // below.
        return match Url::parse(raw) {
            Ok(parsed) => parsed.host_str().is_none(),
            Err(_) => true,
        };
    };
    // A spelling that does not parse has no parsed authority to compare
    // against, and answering `false` for it would put "this address moved" on a
    // string whose real problem is that it is not an address. Every caller
    // parses immediately afterwards and gets the parser's own diagnostic, which
    // is the better one — `s3://a b/x` should read as an invalid URL, not as a
    // retarget.
    let Ok(parsed) = Url::parse(raw) else {
        return true;
    };
    let parsed_host_exists = parsed.host_str().is_some();
    if authority.is_empty() {
        return !parsed_host_exists;
    }
    if parsed_host_exists {
        return true;
    }
    // Percent-decoded before comparing, because the parser decodes the host
    // before it decides: measured, `file://loc%61lhost/tmp/x` parses to
    // `file:///tmp/x` exactly as the plain spelling does, so a byte comparison
    // would refuse a spelling of localhost that names the same file.
    let decoded = percent_decode(authority.as_bytes()).collect::<Vec<u8>>();
    std::str::from_utf8(&decoded).is_ok_and(|decoded| decoded.eq_ignore_ascii_case("localhost"))
}

/// True when `Url::parse` leaves `raw` naming the node its spelling names.
///
/// [`canonicalize_preserves_node`] inspects an **already-parsed** `Url`, and by
/// then the parser has resolved dot segments, removed every ASCII TAB, LF and
/// CR, trimmed leading and trailing C0 controls and spaces, folded `\` to `/`
/// on a special scheme, and — for `file:` with a drive-letter first segment —
/// discarded the host. Each of those moves the address to a different node,
/// and none of them is visible in the parsed form. For an address a
/// caller **sent** that is exactly right — the request is a question and
/// normalizing it is the point. For one a plugin or a server **returned** it is
/// a retarget the host cannot see: `s3://bucket/public/../private/secret`
/// arrives as `s3://bucket/private/secret`, passes as a fixed point, and is
/// handed to a caller as the address of an object it was never shown.
///
/// **Nothing that went through a `Url` on the far side can be refused here.**
/// A `Url`'s serialization has its dot segments already resolved, carries no
/// raw TAB, LF or CR and no untrimmed edge, and carries no `\` in the region
/// where a special scheme would fold one — measured,
/// `Url::parse("s3://b/a/../c").as_str()` is `"s3://b/c"`. So every spelling
/// this refuses was built by string formatting and was about to be silently
/// moved. There is no third case to trade against, and
/// `a_serialized_url_is_never_refused` pins it by round-tripping every refused
/// row.
///
/// That region is the point of the qualification: the parser folds `\` in the
/// authority and path states only, so `https://h/a?x=a\b` and
/// `https://h/a#f\g` are their own serializations and must be accepted. A
/// backslash scan over the whole string refuses both.
///
/// A literal `..` segment is not the price: it is not expressible as an address
/// at all, because the URL Standard reads `%2e%2e` as a double-dot segment too.
/// The plugin obligation is unchanged — this refuses a spelling that cannot
/// mean what it says, rather than asking for a different one.
///
/// The empty-segment collapse is deliberately **not** here. The parser keeps a
/// doubled separator, so [`canonicalize_preserves_node`] already sees and
/// refuses it; duplicating it would be a second copy to keep in step.
#[must_use]
pub fn parsing_preserves_node(raw: &str) -> bool {
    if raw
        .bytes()
        .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
        || raw.starts_with(|c: char| c.is_ascii() && c as u8 <= b' ')
        || raw.ends_with(|c: char| c.is_ascii() && c as u8 <= b' ')
    {
        return false;
    }
    // Bounded to the region before the query, because that is where the fold
    // happens: the parser converts `\` in the authority and path states and
    // leaves it alone in the query and fragment. Measured — `Url::parse` keeps
    // `https://h/a?x=a\b` and `https://h/a#f\g` byte-identical, so scanning
    // the whole string would refuse a `Url`'s own serialization.
    let before_query = raw.split(['?', '#']).next().unwrap_or(raw);
    if let Some((scheme, _)) = raw.split_once(':')
        && scheme_folds_backslash(scheme)
        && before_query.contains('\\')
    {
        return false;
    }
    // The authority is parsed by a state machine that does not consult the
    // scheme list above: a raw `\` terminates the port state whatever the
    // scheme, so the bytes after it leave the authority for the path. Measured,
    // `s3://corp:\secret/` parses to `s3://corp/\secret/` — the raw scan below
    // stops at the trailing `/` and sees a path of `/`, and the parsed form is a
    // fixed point, so neither half of the returned-address contract can see the
    // move. The scan is bounded to the authority because that is the region the
    // state machine reads; a `\` in the path is either folded (handled above, by
    // scheme) or an ordinary byte.
    //
    // **The load-bearing case is a NON-SPECIAL scheme.** On a special scheme the
    // parser folds `\` to `/` before the authority is delimited at all, so the
    // host itself moves — measured, `https://co\rp/x` parses with host `co` and
    // `https://us\er@h/x` with host `us`, the userinfo destroyed rather than
    // escaped — and the clause above already refuses every one of those. This
    // clause exists for the schemes that clause does not cover.
    //
    // Scoped to the HOST/PORT region, which the last raw `@` delimits — the
    // same boundary the parser uses. Before that `@` the byte is inside
    // userinfo, where a non-special scheme's parser does NOT terminate, so the
    // scan and the parser agree and there is nothing to refuse:
    // `s3://DOMAIN\alice@bucket/team/` parses to userinfo `DOMAIN%5Calice`,
    // host `bucket`, path `/team/`. The policy loader reached the same
    // narrowing from the parser's state table
    // (`authz-policy/src/rules.rs`, the `raw_authority` guard), and refusing
    // userinfo here would contradict a spelling it is tested to accept.
    //
    // It cannot refuse a `Url`'s own serialization, by two different
    // mechanisms. On a non-special scheme a raw `\` in the HOST does not parse
    // at all (`s3://co\rp/x` is `InvalidDomainCharacter`), and in the PORT it
    // parses but leaves the authority for the path (`s3://corp:\secret/`
    // becomes `s3://corp/\secret/`), so neither serialization retains it there;
    // on a special scheme the fold means no serialization retains it either.
    // Both are asserted in `parsing_that_preserves_the_node_is_accepted`.
    if raw_authority(raw).is_some_and(|authority| {
        authority
            .rsplit_once('@')
            .map_or(authority, |(_userinfo, host_port)| host_port)
            .contains('\\')
    }) {
        return false;
    }
    // Both authority-moving rewrites, in one predicate that a caller whose only
    // hazard is the authority can also ask for on its own.
    if !parsing_preserves_authority(raw) {
        return false;
    }
    match raw_path(raw) {
        // Percent-decode each segment before comparing: the URL Standard reads
        // `%2e` as a dot for dot-segment purposes, so `public/%2E%2E/private`
        // is resolved by the parser exactly as the raw spelling is.
        RawPath::Path(path) => !path.split('/').any(|segment| {
            let decoded = percent_decode(segment.as_bytes()).collect::<Vec<u8>>();
            decoded == b"." || decoded == b".."
        }),
        RawPath::Empty => true,
        // The path region cannot be located, so the question is answered a
        // different way: if the parser's own serialization is byte-identical
        // to the input, the parser rewrote nothing and there is nothing to
        // refuse. `s3:/a/b` round-trips exactly and is accepted (a boundary
        // that requires an authority refuses it on that ground, with a
        // diagnostic that says so); `file:/a/../b` serializes as `file:///b`
        // and is refused. A blanket refusal here reported a rewrite that had
        // not happened.
        RawPath::Unlocatable => Url::parse(raw).is_ok_and(|url| url.as_str() == raw),
    }
}

/// True when a raw `\` in `rest` — everything after `scheme:` — falls where the
/// parser decides an authority **that the raw scan would otherwise misread**,
/// on a scheme that folds `\` to `/`.
///
/// Two positions, and neither is visible to [`raw_authority`], which knows only
/// `//` and `/?#`:
///
/// - **The two leading separators.** The parser accepts `\` for either, so
///   `file:\\server\share\x` and `https:/\evil.example.com/x` introduce an
///   authority that a raw scan for `//` reports as absent.
/// - **The authority's terminator.** The authority ends at the first `/`, `\`,
///   `?` or `#`; when that byte is a `\` the raw scan runs past it and reads
///   the following bytes as part of the authority. Measured,
///   `file://server\C:/x` parses to `file:///C:/x` — the host destroyed — and
///   `https://user\name@h/x` parses with host `user`, the `@h` demoted to the
///   path.
///
/// A **single** leading separator is deliberately not one of them, and that is
/// not because it is harmless: `https:\evil.example.com/x` parses with host
/// `evil.example.com`, created out of what reads as a path. It is left here
/// because its forward-slash twin `https:/evil.example.com/x` does exactly the
/// same thing, so the `\` is not what decides it — the caller answers both from
/// the parsed host, in the arm [`parsing_preserves_authority`] reaches when
/// [`raw_authority`] finds no `//`. A rule about `\` that covered one and not
/// the other would leave the hole open under its plainer spelling.
///
/// Every other `\` is inside the path, where the fold changes the path and
/// leaves the authority alone: `file:///C:\data\` is one URL with
/// `file:///C:/data/`, and both have no host. Normalizing a configuration
/// address's path is what parsing it is for, so this must not answer for it.
/// The query and fragment need no exclusion — they cannot be reached before the
/// authority's terminator — and `https://h/a?x=a\b` is its own serialization.
fn backslash_decides_authority(rest: &str) -> bool {
    let mut leading = rest.chars();
    let (Some(first), Some(second)) = (leading.next(), leading.next()) else {
        return false;
    };
    let is_separator = |c: char| c == '/' || c == '\\';
    if !is_separator(first) || !is_separator(second) {
        // Fewer than two leading separators: whether the parser found an
        // authority there anyway is answered from the parsed host by the
        // caller, for both separator spellings at once.
        return false;
    }
    if first == '\\' || second == '\\' {
        return true;
    }
    let after_separators = &rest[first.len_utf8() + second.len_utf8()..];
    after_separators
        .find(['/', '\\', '?', '#'])
        .is_some_and(|at| after_separators.as_bytes()[at] == b'\\')
}

/// The authority region of a raw URL string, `None` when it does not spell one.
///
/// Shares [`raw_path`]'s rule that an authority runs from `scheme://` to the
/// first `/`, `?` or `#`.
fn raw_authority(raw: &str) -> Option<&str> {
    let (_, rest) = raw.split_once(':')?;
    let after_slashes = rest.strip_prefix("//")?;
    Some(match after_slashes.find(['/', '?', '#']) {
        Some(at) => &after_slashes[..at],
        None => after_slashes,
    })
}

/// What [`raw_path`] could make of a raw URL string.
enum RawPath<'a> {
    /// The path region, starting at its leading `/`.
    Path(&'a str),
    /// An authority and no path — there is nothing for a dot segment to be in.
    Empty,
    /// The path region cannot be located from the raw string.
    Unlocatable,
}

/// The path region of a raw URL string.
///
/// An authority runs to the first `/`, `?` or `#`, and a raw `/` cannot appear
/// inside one, so this locates the path unambiguously even with userinfo, an
/// IPv6 literal or an explicit port. Bounding the scan matters: `..` is an
/// ordinary value in a query (`https://h/a?from=../b`) and the parser leaves it
/// alone there.
///
/// A string that does not spell its authority as `scheme://` is reported as
/// [`RawPath::Unlocatable`] rather than guessed at, because deciding where the
/// authority ends there means re-deriving WHATWG's state machine inside a
/// security check — `https:/h/x` gives host `h`, `file:/a/../b` gives no host
/// at all. [`parsing_preserves_node`] answers that arm by byte identity
/// instead of by refusal: it is the one shape where "did the parser rewrite
/// this?" can be asked directly.
fn raw_path(raw: &str) -> RawPath<'_> {
    let Some((_, rest)) = raw.split_once(':') else {
        return RawPath::Unlocatable;
    };
    let Some(after_slashes) = rest.strip_prefix("//") else {
        return RawPath::Unlocatable;
    };
    match after_slashes.find(['/', '?', '#']) {
        Some(at) if after_slashes.as_bytes()[at] == b'/' => {
            let path = &after_slashes[at..];
            let end = path.find(['?', '#']).unwrap_or(path.len());
            RawPath::Path(&path[..end])
        }
        _ => RawPath::Empty,
    }
}

/// The WHATWG **special schemes**, the closed set for which the parser folds a
/// raw `\` to `/` in both the authority state and the path state. A scheme off
/// this list is parsed opaquely and a backslash stays an ordinary key byte, so
/// refusing it there would reject a well-formed `s3://b/data\ok` address.
///
/// Public because the authorization matcher's prefix loader draws the same
/// distinction for the same reason, and a closed set copied twice is two
/// things to keep in step.
#[must_use]
pub fn scheme_folds_backslash(scheme: &str) -> bool {
    ["ftp", "file", "http", "https", "ws", "wss"]
        .iter()
        .any(|special| scheme.eq_ignore_ascii_case(special))
}

/// The comparison form of an address: equal for two spellings that name the
/// same node.
///
/// `x` and `x/` name one node. Which of the two a caller wrote is a rendering
/// choice; whether the node is a file or a directory comes from `ObjectKind`.
/// Every site that asks "are these the same object?" — cache invalidation,
/// route dedup, alias ranking — compares this rather than the serialized
/// string, so the answer cannot depend on who spelled it.
///
/// The query is part of the key, because a version pin selects a different
/// node. Userinfo is not, because nothing in ovstorage consults it: two
/// bindings differing only in credentials are the same node.
///
/// This is a comparison form, not a canonical form. It is derived on demand
/// and never stored, so no address is rewritten and the trailing slash a
/// caller wrote survives everywhere it is rendered.
#[must_use]
pub fn node_key(url: &Url) -> (&str, Option<&str>, Option<u16>, &str, Option<&str>) {
    (
        url.scheme(),
        url.host_str(),
        url.port(),
        node_path(url),
        url.query(),
    )
}

/// The path with one trailing `/` removed, except at the root.
///
/// The `len() > 1` guard keeps the root `/` from becoming `""`, which would
/// make every root of an authority collide with every other. No guard on the
/// preceding segment is needed: [`canonicalize`] collapses runs of `/`, so a
/// canonical path has no empty segment for the strip to expose.
#[must_use]
pub fn node_path(url: &Url) -> &str {
    let path = url.path();
    if path.len() > 1 {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        // An empty path and `/` are the same root. `canonicalize` gives an
        // empty-authority path its `/`, but this is also reachable from a
        // caller that built a URL with `set_path` rather than parsing one, and
        // a root that compares unequal to itself routes nothing.
        "/"
    }
}

/// How many path segments a node's address pins, for ranking one scope against
/// another.
///
/// **Rank on this, never on the serialized byte length.** Byte length is
/// spelling-dependent: `…/root/` is one byte longer than `…/root`, and the two
/// name one node, so the more verbose spelling of one scope outranks the
/// plainer spelling of the same scope regardless of declaration order. Segment
/// count is a property of the node, so two spellings tie and a stable sort then
/// keeps the documented first-wins order.
///
/// A percent-escaped spelling is not a second example of this, for any `Url`
/// [`canonicalize`] produced: it decodes the path and re-encodes it with one
/// escape set, so `…/%70rivate/` is `…/private/` by then.
#[must_use]
pub fn node_segment_count(url: &Url) -> usize {
    node_path(url)
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count()
}

/// The specificity of a scope, for ordering one against another. More specific
/// sorts higher.
///
/// Depth first, then whether the scope pins a query. A pinned scope covers a
/// strict subset of its unpinned parent — same node path, one exact query — so
/// ranking on depth alone ties them and registration order decides, leaving the
/// pinned scope unreachable for precisely the address it publishes.
///
/// **How a tie resolves is the caller's choice, not this function's**, and the
/// two shapes in the tree differ: a `Reverse` stable sort keeps the
/// first-declared scope, while `max_by_key` returns the *last* maximum and so
/// keeps the last-declared one. Both are defensible — two scopes that tie on
/// specificity and both match an address must be nested, which is a
/// configuration the load-time checks reject — but do not read one of them off
/// this doc comment.
#[must_use]
pub fn node_rank(url: &Url) -> (usize, bool) {
    (node_segment_count(url), url.query().is_some())
}

/// The serialization a consumer should key on: the address with userinfo
/// removed and an absent authority spelled one way.
///
/// Userinfo is carried through an address and never consulted for identity —
/// not by the matcher, not by [`node_key`], not by routing. A consumer that
/// keys on the raw serialization therefore splits one node into as many rows as
/// there are credentials, and an invalidation written without a credential
/// reaches none of them: stale metadata served for an object that was just
/// deleted.
///
/// **An authority that is absent and one that is empty are the same node**, and
/// on a scheme the parser does not normalize they are two serializations:
/// measured, `broker:/x` and `broker:///x` both round-trip byte-identically and
/// [`node_key`] gives both `(scheme, None, None, "/x", None)`. A special scheme
/// hides the split — `file:/data/` parses as `file:///data/` — which is exactly
/// what makes it easy to miss on the schemes that ovstorage itself routes. Two
/// keys for one node is the same defect the userinfo strip exists to close, so
/// the empty-authority spelling is written for both.
///
/// The trailing slash is preserved, because this is a spelling rather than a
/// comparison form — see [`node_spellings`] for the pair a consumer holding
/// strings compares against.
#[must_use]
pub fn node_address(url: &Url) -> String {
    let mut bare = url.clone();
    if !url.username().is_empty() || url.password().is_some() {
        // Both setters return `Err(())` for a URL with no host, one whose host
        // is the empty domain, or one on the `file:` scheme. None is reachable
        // behind this guard, and it is worth stating because a swallowed error
        // here fails OPEN — the address would be returned with its credential
        // still in it, straight into a cache key. Measured: `s3://user@/x` and
        // `s3://user:pw@/x` are `EmptyHost`, and `file://user@server/x` does
        // not parse either, so no parsed URL carries userinfo without a host.
        let _ = bare.set_password(None);
        let _ = bare.set_username("");
    }
    if bare.host_str().is_none() {
        // `Err` for a cannot-be-a-base URL, which spells no authority at all,
        // and for `file:`, whose parser has already written the empty
        // authority. Both are collapsed already, so the failure is the no-op.
        let _ = bare.set_host(Some(""));
    }
    bare.into()
}

/// The two serialized spellings of one node: without a trailing `/`, then with
/// one. Equal at the root, where there is only one spelling.
///
/// For a consumer that holds addresses as strings rather than as parsed URLs —
/// the metadata cache keys on the serialization — so it can recognize both
/// spellings without re-deriving [`node_key`]'s rule at a third site or parsing
/// every row it scans.
#[must_use]
pub fn node_spellings(url: &Url) -> (String, String) {
    let path = node_path(url).to_string();
    // Userinfo is not part of identity, so neither spelling carries it — the
    // consumer keys on [`node_address`] for the same reason.
    let mut bare = Url::parse(&node_address(url)).unwrap_or_else(|_| url.clone());
    bare.set_path(&path);
    if path == "/" {
        // The root has one spelling. Appending would give `s3://b//`, an empty
        // segment that `canonicalize` collapses, so it could never match a
        // stored key — a second spelling that matches nothing is a claim this
        // function does not get to make.
        let bare: String = bare.into();
        return (bare.clone(), bare);
    }
    let mut slashed = bare.clone();
    slashed.set_path(&format!("{path}/"));
    (bare.into(), slashed.into())
}

/// The path pipeline, on decoded bytes: collapse runs of `/`, **then** resolve
/// dot segments. The order is load-bearing and it is this way round so an empty
/// segment cannot absorb a following `..`: resolving first makes `a//..` cancel
/// the empty segment rather than `a`, which leaves an address that reads as
/// escaping an allowed subtree judged as staying inside it.
///
/// Exposed as [`normalize_decoded_path`] for consumers that must apply the same
/// rules to a path they have rewritten themselves — the authorization matcher
/// does, after treating `\` as a separator on Windows. That caller is the
/// reason the ordering matters here rather than only inside `canonicalize`:
/// folding `\` to `/` manufactures separator runs, so it meets the case this
/// order exists for far more often than a caller typing one.
///
/// Shared by [`canonicalize`] and [`canonicalize_preserves_node`] so the two
/// cannot disagree about what moves an address. Every step that rewrites the
/// path belongs here rather than in [`canonicalize`]'s body: a step the
/// validator does not know about is one that silently retargets a returned
/// address instead of refusing it.
#[must_use]
pub fn normalize_decoded_path(decoded: &[u8]) -> Vec<u8> {
    normalize_path_bytes(decoded)
}

/// Collapse separator runs, **then** resolve dot segments.
///
/// The order is load-bearing and it is this way round because an empty segment
/// must not absorb a following `..`. Resolving first makes `a//..` cancel the
/// empty segment rather than `a`, so `root/private//../public/x` stays inside
/// `root/private/` while every operating system opens `root/public/x` — an
/// address that reads as escaping an allowed subtree and is judged as not
/// escaping it. Collapsing first makes the two spellings one node, which is
/// what the OS already believes.
///
/// The composed result is therefore not RFC 3986 §5.2.4 on an input containing
/// both, and that is deliberate: §5.2.4 alone has no notion of an empty segment
/// to collapse, and this pipeline's job is to name the node the backend will
/// reach, not to reproduce the RFC's worked examples on inputs it does not
/// model. [`remove_dot_segments`] on its own remains exactly §5.2.4.
fn normalize_path_bytes(decoded: &[u8]) -> Vec<u8> {
    let mut out = decoded.to_vec();
    collapse_empty_segments(&mut out);
    remove_dot_segments(&out)
}

/// Canonicalize an address `Url` for the layer chain.
///
/// On top of the RFC-canonical form the `url` crate already guarantees on parse,
/// this applies the two normalizations the crate skips for ovstorage's
/// non-special schemes:
///
/// 1. **Host case.** The host is lowercased (RFC 3986 §6.2.2.1). The crate does
///    this for special schemes but not for ours, so `omniverse://SERVER` keeps
///    `SERVER` until here. The path is left untouched — it is case-sensitive.
/// 2. **Empty-authority path.** An authority-bearing URL with an empty path
///    (e.g. `omniverse://host`) gains a `/` path (`omniverse://host/`) so
///    route-prefix matching is consistent regardless of whether the caller typed
///    the trailing slash. (The crate does this for special schemes, not ours.)
/// 3. **Path.** Percent-escapes are decoded to bytes, dot segments are resolved
///    (RFC 3986 §5.2.4), and the result is re-encoded with the canonical set,
///    so `s3://b/a%2F..%2Fb` and `s3://b/b` become one address. The trailing
///    slash is **not** touched: `docs` and `docs/` are two objects on a flat
///    store, so collapsing them would destroy real information.
/// 4. **Fragment.** Discarded. RFC 3986 §3.5 defines it as client-side and never
///    sent to a server, so two addresses differing only in fragment name one
///    node. Stripping rather than ignoring means no site downstream needs a
///    fragment rule of its own.
///
/// The query and the authority are otherwise untouched — the query because it
/// carries version pins that select which object is served, the authority
/// because rule 1 already owns it.
///
/// Idempotent: canonicalizing an already-canonical `Url` returns it unchanged.
///
/// **Total.** Every transformation is performed here rather than left to
/// [`Url::set_path`], and the encode sets above remove the triggers for the
/// three rewrites the crate would otherwise apply — so the setter has nothing
/// left to do and the function has nothing to refuse. The one rewrite that is
/// *allowed* to happen is the `file:` leading-slash collapse
/// (`file:///%2Fetc/passwd` names `//etc/passwd`, which the crate trims to
/// `/etc/passwd`); POSIX makes those the same file, and the raw spelling
/// `file:////etc/passwd` already collapses at parse today, so accepting it
/// keeps the two spellings in agreement.
///
/// A `cannot_be_a_base` address (`s3:a/b`) is returned untouched: the path
/// state machine never runs for that class, so normalizing it would
/// *half*-normalize it — a separator manufactured and the traversal left
/// unresolved. `address::parse` refuses that class outright instead.
///
/// What this gives up, stated plainly: correctness now rests on the encode
/// sets being complete rather than on a checked postcondition, so a future
/// `url` release inventing a rewrite we have not enumerated would be applied
/// silently. `canonical_form_survives_a_string_round_trip` is the guard —
/// it asserts the property over a corpus, so the failure surfaces in CI at
/// dependency-bump time rather than in a caller's process. Pin the `url` minor
/// version and treat a bump as a deliberate act.
pub fn canonicalize(mut url: Url) -> Url {
    // No hierarchical path to normalize, and `set_path` would manufacture a
    // separator here rather than resolve one. `address::parse` rejects it.
    if url.cannot_be_a_base() {
        return url;
    }

    // Lowercase the host for non-special schemes (the crate already did it for
    // special ones, so this is a no-op there). Compute the lowered host first so
    // the immutable `host_str` borrow ends before the mutable `set_host`.
    let lowered_host = url.host_str().and_then(|host| {
        let lower = host.to_ascii_lowercase();
        (lower != host).then_some(lower)
    });
    if let Some(host) = lowered_host {
        // `set_host` only errors for schemes that forbid a host; we reach here
        // only when the URL already has one, so this just rewrites it lowercased.
        // Keep the original spelling on the impossible error rather than panic.
        let _ = url.set_host(Some(&host));
    }

    url.set_fragment(None);

    if url.has_authority() && url.path().is_empty() {
        url.set_path("/");
    }

    // `Url::path` returns the *encoded* path, so this decode is not redundant.
    // Working in bytes throughout is what keeps `x%FF` and `x%FE` distinct: no
    // `String` is ever built from the payload, so the question of whether the
    // bytes are valid UTF-8 never arises.
    let encode_set = canonical_path_set(&url);
    let decoded = percent_decode(url.path().as_bytes()).collect::<Vec<u8>>();
    let resolved = normalize_path_bytes(&decoded);
    let encoded = percent_encode(&resolved, encode_set).collect::<String>();

    url.set_path(&encoded);
    url
}

/// Collapse runs of `/` into one, in place. A single trailing `/` is untouched:
/// `docs` and `docs/` name one node, but on a flat store they may be two
/// objects, so the caller's spelling has to survive for the backend to choose
/// between them.
///
/// **Unlike the escape sets, this is not scheme-scoped, and the reason is that
/// scoping it cannot be made correct.** Whether a backend distinguishes `a//b`
/// from `a/b` is not a property of the scheme:
///
/// - a filesystem collapses the run, so `file:` must;
/// - S3, GCS and Nucleus keep it as literal key bytes, so `s3:` need not;
/// - **Azure does both**, selected by the `hierarchical_namespace` flag on the
///   *connection* (`plugin-azure/src/config.rs:47`). One scheme, two behaviours,
///   chosen by operator config.
///
/// A matcher that preserves the empty segment while the backend collapses it is
/// *finer* than the backend, which is the direction that defeats a deny rather
/// than over-denying it — the bypass this closes. Since the scheme cannot tell
/// us which case we are in, the rule has to be uniform, and it has to be the
/// coarse one: collapsing everywhere makes the matcher no finer than any
/// backend, so it can only ever over-deny.
///
/// The cost is that an object whose key genuinely contains `//` stops being
/// addressable through ovstorage. That is the same cost already accepted for
/// keys containing dot segments and literal `%2F`, and it gets the same
/// treatment — the emitter's round-trip check drops such a key from listings
/// with a `warn!` rather than handing out an address that names something else.
/// The three published plugin contracts state this rule rather than the
/// byte-for-byte preservation an author would otherwise implement to:
/// `docs/public/plugin-storage/README.md`,
/// `docs/public/plugin-storage/CONFORMANCE.md` and
/// `ovstorage-core/ovstorage-plugin/README.md`.
fn collapse_empty_segments(path: &mut Vec<u8>) {
    let mut previous_was_slash = false;
    path.retain(|byte| {
        let is_slash = *byte == b'/';
        let keep = !(is_slash && previous_was_slash);
        previous_was_slash = is_slash;
        keep
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(spelling: &str) -> Url {
        canonicalize(Url::parse(spelling).unwrap())
    }

    /// The authority half, asserted directly rather than through
    /// [`parsing_preserves_node`]'s corpus.
    ///
    /// It is public and has a caller — the `file` backend's config boundary —
    /// that asks it and nothing else, so a hole here is not covered by the node
    /// predicate's rows. The rows below are the ones a scan for `scheme://`
    /// cannot see: on a folding scheme a raw `\` decides where the authority
    /// begins, so it can destroy one, create one, or hide one from the scan,
    /// with no `//` in the string at all.
    #[test]
    fn the_authority_predicate_sees_an_authority_the_raw_scan_cannot() {
        for (raw, becomes) in [
            // Destroyed. The first is the UNC share a Windows operator writes.
            (r"file:\\server\C:\data\", "file:///C:/data/"),
            (r"file:/\server/C:/data/", "file:///C:/data/"),
            ("file://server/C:/data/", "file:///C:/data/"),
            ("s3://:@/x", "s3:///x"),
            // Created out of what reads as a path.
            (r"file:\\server\share\x", "file://server/share/x"),
            (r"https:/\evil.example.com/x", "https://evil.example.com/x"),
            ("https:///evil.example.com/x", "https://evil.example.com/x"),
            // The `\` that TERMINATES the authority rather than introducing
            // it. The raw scan knows only `/?#`, so it reads past the `\` and
            // reports an authority of `server\C:` or `user\name@h` — while the
            // parser stops at the `\` and takes what precedes it. These are
            // the rows that make the narrowing to the authority region a
            // narrowing rather than a hole.
            (r"file://server\C:/x", "file:///C:/x"),
            (r"https://user\name@h/x", "https://user/name@h/x"),
            // ONE leading separator, both spellings. A scheme that skips the
            // extra slash reads the first path segment as a host, so this is
            // the same Fill hazard as `https:///evil.example.com/x` — and the
            // `\` is not what does it, which is why the answer comes from the
            // parsed host rather than from a rule about backslashes.
            (r"https:\evil.example.com/x", "https://evil.example.com/x"),
            ("https:/evil.example.com/x", "https://evil.example.com/x"),
            ("ws:/evil/x", "ws://evil/x"),
            // No separator at all, which the same arm answers.
            ("https:evil.example.com/x", "https://evil.example.com/x"),
            // A byte the parser DELETES, which moves every boundary a raw scan
            // looks for. The first spells a host and loses it; the third hides
            // the scheme from the scan as well, since the raw string's first
            // `:` is preceded by `" file"`.
            ("file:/\t/server/C:/data/", "file:///C:/data/"),
            ("file:/\t\\server\\C:\\data\\", "file:///C:/data/"),
            (" file:\\\\server\\C:\\data\\", "file:///C:/data/"),
        ] {
            assert_eq!(
                Url::parse(raw).map(|url| url.to_string()).as_deref(),
                Ok(becomes),
                "{raw:?}"
            );
            assert!(
                !parsing_preserves_authority(raw),
                "{raw:?} moves its authority to {becomes:?} and must be refused"
            );
        }

        for raw in [
            // No authority for either rewrite to move — the published minimal
            // form of a file root, which is why this predicate exists apart
            // from the node one. `file:` is a special scheme that does NOT
            // fill, so one leading separator leaves it hostless and the arm
            // that refuses `https:/h/x` accepts these: the question is put to
            // the parser, not to the scheme list.
            "file:/data/",
            "file:/srv/public/",
            r"file:\data\x",
            "s3:/a/b",
            // An empty authority on the schemes that do not fill it.
            "file:///data/",
            "s3:///evil.example.com/x",
            // An authority that survives.
            "file://server/share/x",
            "file://localhost/data/",
            "s3://bucket/key",
            // Path rewrites are not this predicate's question — including the
            // `\` a Windows operator writes as a separator, which the parser
            // folds to `/` and which moves no authority. `file:///C:\data\`
            // parses to `file:///C:/data/`, byte for byte what the
            // forward-slash spelling parses to, and both have no host at all;
            // refusing it would reject a working local root and report a lost
            // authority for an address that never spelled one.
            r"file:///C:\data\",
            r"file:///tmp/a\b",
            "file:///srv/../data/",
            "s3://bucket/a/../b",
            // A `\` past the authority's end on a folding scheme. The query and
            // fragment need no exclusion of their own: the authority's
            // terminator is reached first.
            r"https://h/a?x=a\b",
            r"https://h/a#f\g",
            // A `\` on a scheme that does not fold: an ordinary key byte.
            r"s3://b/a\b",
            // Does not parse, so the question is unanswerable and the caller's
            // own parse gives the better diagnostic.
            "s3://a b/x",
        ] {
            assert!(
                parsing_preserves_authority(raw),
                "{raw:?} keeps its authority and must be accepted"
            );
        }
    }

    /// Every spelling the URL parser rewrites into a *different node* is
    /// refused, and the parsed form remembers none of them — which is why
    /// `canonicalize_preserves_node` cannot answer for any row here. Each is
    /// paired with its measured parse, so the assertion says what it is about.
    #[test]
    fn parsing_that_moves_the_node_is_refused() {
        for (raw, parses_to) in MOVED_BY_PARSING {
            assert!(
                !parsing_preserves_node(raw),
                "{raw:?} must be refused: the parser rewrites it to {:?}",
                Url::parse(raw).map(|url| url.to_string())
            );
            // The table names what each row BECOMES. That is a prompt for a
            // human, not a proof: a deliberate normalization is byte-different
            // while naming the same object, so `assert_ne!` cannot tell the
            // two apart and does not try. What it does catch is a row that is
            // its own parse — a refusal of something the parser leaves alone
            // entirely. The mechanical guard against over-refusal is the
            // `kept` corpus below, and the reason to write `parses_to` down is
            // that four refusals on this PR reached a spelling the parser
            // normalizes on purpose, and each would have had to be entered
            // here beside an object a reader can compare it to.
            assert_eq!(
                Url::parse(raw).map(|url| url.to_string()).as_deref(),
                Ok(*parses_to),
                "{raw:?}"
            );
            assert_ne!(raw, parses_to, "{raw:?} is its own parse, not a retarget");
        }
        // Every scheme whose parser folds `\`, not just the one with a row
        // above: dropping four of the six from `scheme_folds_backslash` left
        // the suite green, because only `https` was exercised.
        for scheme in ["ftp", "file", "http", "https", "ws", "wss"] {
            let raw = format!("{scheme}://host/a\\b");
            assert!(
                !parsing_preserves_node(&raw),
                "{raw:?} must be refused: the parser folds it to {:?}",
                Url::parse(&raw).map(|url| url.to_string())
            );
        }
    }

    /// Every spelling [`parsing_that_moves_the_node_is_refused`] refuses.
    ///
    /// Shared with [`a_serialized_url_is_never_refused`] so that the property
    /// test cannot be narrower than the refusal it claims to bound. It was:
    /// the property was asserted over a hand-picked six of these, and the row
    /// it left out was a counterexample to the property as first written.
    const MOVED_BY_PARSING: &[(&str, &str)] = &[
        // Dot segments, raw and in the two `%2e` spellings the URL Standard
        // also reads as dots.
        (
            "s3://bucket/public/../private/secret",
            "s3://bucket/private/secret",
        ),
        (
            "s3://bucket/public/%2e%2e/private/secret",
            "s3://bucket/private/secret",
        ),
        (
            "s3://bucket/public/%2E%2E/private/secret",
            "s3://bucket/private/secret",
        ),
        // A single-dot segment.
        ("s3://bucket/a/./b", "s3://bucket/a/b"),
        // ASCII TAB, LF and CR are removed from anywhere in the input, which
        // joins two segments' bytes into one — and can equally manufacture a
        // dot segment out of a key that has none, which is what the last row
        // shows: two ordinary segments become an escape to the bucket root.
        ("s3://bucket/a\tb", "s3://bucket/ab"),
        ("s3://bucket/a\nb", "s3://bucket/ab"),
        ("s3://bucket/a\rb", "s3://bucket/ab"),
        ("s3://bucket/team/.\t./private", "s3://bucket/private"),
        // A leading or trailing space is trimmed, so a key that really ends in
        // one names a different object.
        ("s3://bucket/file.txt ", "s3://bucket/file.txt"),
        (" s3://bucket/file.txt", "s3://bucket/file.txt"),
        // `\` folds to `/` on a special scheme: one segment becomes two.
        ("https://host/a\\b", "https://host/a/b"),
        // No `scheme://`, so where the path begins is a guess.
        ("file:/a/../b", "file:///b"),
        // `file:` with a drive-letter first segment discards the HOST, so a
        // remote share is renamed to a local disk. `file://server/x` keeps its
        // host and `file://localhost/x` is the Standard's own spelling of
        // `file:///x`; both are in the accept corpus. This refuses the rewrite,
        // not the scheme.
        ("file://server/C:/x", "file:///C:/x"),
        ("file://server/C|/x", "file:///C:/x"),
        // The same destruction with no drive letter and no `file:`. The raw
        // spelling names an authority and the parse has none, which is why the
        // authority predicate asks the parser rather than the scheme.
        ("s3://:@/x", "s3:///x"),
        // A raw `\` in the AUTHORITY, on a scheme whose paths do not fold one.
        // The port state terminates on it regardless of scheme, so `\secret`
        // leaves the authority for the path while the raw path scan sees only
        // the trailing `/`.
        ("s3://corp:\\secret/", "s3://corp/\\secret/"),
        // The empty authority, which the parser fills from the first path
        // segment on the schemes that promote — the drive-letter rewrite in the
        // opposite direction. `s3:///…` and `file:///…` do not promote and are
        // in the accept corpus.
        ("https:///evil.example.com/x", "https://evil.example.com/x"),
        // A tab INSIDE THE SCHEME, which the raw split cannot see: the parser
        // removes it, reads `https`, and folds the backslash. Only the
        // whitespace clause running first catches this, so the row pins the
        // clause ordering as much as the clauses.
        ("htt\tps://host/a\\b", "https://host/a/b"),
    ];

    /// The honest half, and it is the half that decides whether the refusal
    /// above is affordable. Nothing a plugin can build as a `Url` may be
    /// refused, so every row here is either a `Url` serialization or one of
    /// the spellings `canonicalize` normalizes harmlessly.
    #[test]
    fn parsing_that_preserves_the_node_is_accepted() {
        let kept = [
            // The plain case, and the trailing-slash directory form.
            "s3://bucket/team/file.txt",
            "s3://bucket/team/",
            // **Spellings the parser normalizes ON PURPOSE.** These are the
            // rows this test exists for: a refusal derived from an
            // enumeration of what the parser *does* keeps reaching one of
            // them, because a deliberate normalization and a destructive
            // rewrite look identical from the enumeration's side. Three
            // separate clauses on this PR over-reached onto this class, so a
            // new row belongs here whenever one is added to the refusal.
            //
            // `file://localhost/x` and `file:///x` are the same local file by
            // the URL Standard's own rule, and `FileBackend::file_path`
            // accepts the spelling. The host case and the empty authority
            // path are `canonicalize`'s own business.
            "file://localhost/tmp/data.csv",
            "file://LOCALHOST/tmp/data.csv",
            // `localhost` WITH a drive letter, which is the interesting row:
            // the parser drops the authority here too, and it still names the
            // same local file, so the exclusion must not be conditioned on the
            // absence of a drive letter. Measured — this parses to
            // `file:///C:/x`, while `file://server/C:/x` parsing to the same
            // string is a remote share renamed to a local disk and is refused.
            "file://localhost/C:/x",
            "omniverse://SERVER/p",
            "omniverse://host",
            // An escape set the parser re-spells, and an escaped separator —
            // the latter is caught by `canonicalize_preserves_node` instead,
            // which is where it belongs.
            "s3://bucket/a%7bb",
            "s3://bucket/public%2F..%2Fprivate/secret",
            // A dot segment in the QUERY is an ordinary value: the parser does
            // not resolve it, so refusing it would reject a working address.
            "https://host/a?from=../b",
            "https://host/a#../b",
            // A backslash is an ordinary key byte on a non-special scheme, and
            // `s3://bucket/data\ok` names the key it spells.
            "s3://bucket/data\\ok",
            // And on a SPECIAL scheme it is still ordinary in the query and
            // the fragment, where the parser does not fold it. Both are
            // byte-identical to their own `Url` serialization, so refusing
            // them would refuse an address a plugin cannot avoid emitting.
            "https://host/a?x=a\\b",
            "https://host/a#f\\g",
            // An interior space survives as `%20`, so the two forms agree.
            "s3://bucket/pub x",
            // A `..` that is part of a segment rather than the whole of it.
            "s3://bucket/..leading/trailing..",
            // No path to inspect at all — including one whose QUERY holds a
            // path-shaped dot segment. Narrowing the authority bound to `/`
            // alone would locate a "path" of `/a/../c` inside this query and
            // refuse it; the row exists so that bound cannot be dropped.
            "s3://bucket",
            "s3://bucket?versionId=7",
            "s3://bucket?next=/a/../c",
            // No `scheme://`, and the parser rewrites nothing: this is its own
            // serialization, so it names the node it spells. A boundary that
            // requires an authority refuses it on that ground instead.
            "s3:/a/b",
            "s3:reader@bucket/team/file.txt",
            // A `file:` host that survives, next to the two drive-letter
            // spellings that do not.
            "file://server/x",
            // An EMPTY authority on the two schemes that do not promote the
            // first path segment to the host. These are the rows that make the
            // promotion clause affordable: `file:///…` is the ordinary spelling
            // of every local root, and refusing it would refuse the file
            // backend's own addresses.
            "file:///tmp/data.csv",
            "s3:///evil.example.com/x",
            // A raw `\` in USERINFO on a non-special scheme, and its escaped
            // serialization. Both are accepted: the byte sits before the last
            // `@`, where the parser does not terminate the authority, so the
            // scan and the parse agree about where the path begins. The policy
            // loader's guard draws the same boundary and has a row requiring
            // this exact spelling to load.
            "s3://DOMAIN\\alice@bucket/team/",
            "s3://us%5Cer@h/x",
            // Does not parse at all. The authority question is unanswerable for
            // it, and every caller parses next and gets the parser's own
            // diagnostic, which says what is actually wrong — so this predicate
            // must not claim it moved.
            "s3://a b/x",
        ];
        for raw in kept {
            assert!(
                parsing_preserves_node(raw),
                "{raw:?} must be accepted: it is a spelling no plugin can avoid"
            );
        }
        // The authority scan refuses a raw `\` on every scheme, and what makes
        // that affordable is that no `Url` serializes one there. The mechanism
        // differs by scheme class and both halves are asserted, because the
        // scan's own comment is only correct if both hold.
        //
        // Non-special: in the host/port region the byte never survives parsing,
        // so the refusal costs nothing. In userinfo it does survive, escaped —
        // and is accepted in both spellings, which is the narrowing itself.
        assert!(
            Url::parse("s3://co\\rp/x").is_err(),
            "a raw backslash in a non-special host must not parse at all"
        );
        assert_eq!(
            Url::parse("s3://us\\er@h/x").unwrap().as_str(),
            "s3://us%5Cer@h/x",
            "a raw backslash in non-special userinfo must come back escaped"
        );
        assert!(
            parsing_preserves_node("s3://us\\er@h/x"),
            "and the raw userinfo spelling itself must be accepted"
        );
        // Special: the parser folds it to `/` before the authority is
        // delimited, so the HOST moves — which is why these are refused by the
        // fold clause rather than by the authority scan, and why the scan's
        // load-bearing case is the non-special one.
        for (raw, host) in [
            ("https://co\\rp/x", "co"),
            ("https://us\\er@h/x", "us"),
            ("https://corp:\\secret/", "corp"),
        ] {
            assert_eq!(
                Url::parse(raw).unwrap().host_str(),
                Some(host),
                "{raw:?} moves its host"
            );
            assert!(!parsing_preserves_node(raw), "{raw:?} must be refused");
        }
    }

    /// A `Url`'s own serialization is accepted, for **every** input the test
    /// above refuses that has an authority.
    ///
    /// This is the affordability argument stated as a property rather than as
    /// prose: a plugin that builds its answer as a `Url` cannot reach the
    /// refusal, because the parser has already removed what the refusal looks
    /// for. Only a string-formatted address can, and every one of those was
    /// about to be silently moved.
    ///
    /// It iterates the same corpus as the refusal test rather than a list of
    /// its own, which is the only version of this test worth having: an
    /// earlier one walked a hand-picked six, and the row it happened to leave
    /// out — `s3:reader@bucket/team/file.txt` — is a counterexample to the
    /// property as it was then written. The authority-less rows are the
    /// exception and are carved out **by measurement**, not by omission: they
    /// are refused for having no locatable path region, and every
    /// returned-address boundary refuses that class in its own right, with a
    /// better diagnostic, before this predicate is consulted.
    ///
    /// The extra rows below the corpus are the converse case — spellings the
    /// parser leaves alone, which an over-broad refusal would reject. Two are
    /// a raw `\` in a query and in a fragment, which is exactly the defect
    /// this test caught when they were added.
    #[test]
    fn a_serialized_url_is_never_refused() {
        let extra = [
            "https://host/a?x=a\\b",
            "https://host/a#f\\g",
            "https://host/a?from=../b",
        ];
        let refused = MOVED_BY_PARSING.iter().map(|(raw, _)| *raw);
        for raw in refused.chain(extra) {
            let url = Url::parse(raw).unwrap();
            if url.cannot_be_a_base() {
                // Carved out above. Assert the reason rather than skipping
                // silently, so a row that stops being authority-less is not
                // quietly dropped from the property.
                assert!(
                    !parsing_preserves_node(url.as_str()),
                    "{raw:?} is authority-less and must be refused as such"
                );
                continue;
            }
            let serialized = url.to_string();
            assert!(
                parsing_preserves_node(&serialized),
                "{raw:?} serializes to {serialized:?}, which must be accepted"
            );
        }
    }

    /// The key form collapses the two spellings of an absent authority, which
    /// [`node_key`] treats as one node.
    ///
    /// It does not collapse everything `node_key` equates, and must not: the
    /// trailing slash is identity-bearing in a spelling, so `broker://` and
    /// `broker:///` stay distinct here while `node_key` calls them one node.
    /// [`node_spellings`] is the function that hands a consumer both.
    ///
    /// On a special scheme the parser hides the split — `file:/data/` parses as
    /// `file:///data/` — so it shows up only on the schemes ovstorage itself
    /// routes, which is where it matters: a broker route is spelled both ways
    /// in this very tree. Two keys for one node is the defect the userinfo
    /// strip exists to close, reached by another spelling: a write through one
    /// leaves the other's row live.
    #[test]
    fn the_key_form_collapses_every_spelling_of_one_node() {
        for (spellings, key) in [
            (["broker:/x", "broker:///x"], "broker:///x"),
            (["logical:/a/b", "logical:///a/b"], "logical:///a/b"),
            (["broker:/", "broker:///"], "broker:///"),
            // The userinfo half, which is the other thing this function
            // removes. The two cannot combine: a URL carrying userinfo and no
            // host does not parse at all (`s3://u:p@/x` is `EmptyHost`), which
            // is what makes the swallowed setter errors in `node_address`
            // unreachable rather than merely unlikely.
            (["s3://u:p@b/x", "s3://b/x"], "s3://b/x"),
            (["file:/data/", "file:///data/"], "file:///data/"),
        ] {
            let keys: Vec<String> = spellings
                .iter()
                .map(|raw| node_address(&Url::parse(raw).unwrap()))
                .collect();
            assert_eq!(keys[0], key, "{:?}", spellings[0]);
            assert_eq!(keys[1], key, "{:?}", spellings[1]);
            for (raw, keyed) in spellings.iter().zip(&keys) {
                let parsed = Url::parse(raw).unwrap();
                let reparsed = Url::parse(keyed).unwrap();
                assert_eq!(
                    node_key(&reparsed),
                    node_key(&parsed),
                    "{raw:?} and its own key name different nodes"
                );
            }
        }
        // The converse, so the collapse is not a rewrite of things that
        // differ: an authority that is present is left exactly where it is,
        // including the empty-segment and trailing-slash spellings, which are
        // `canonicalize`'s business and not this function's.
        for raw in [
            "s3://b/x",
            "s3://b/x/",
            "file://server/share/x",
            "broker:///a/b",
        ] {
            assert_eq!(node_address(&Url::parse(raw).unwrap()), raw, "{raw:?}");
        }
    }

    #[test]
    fn empty_authority_path_gains_trailing_slash() {
        assert_eq!(canon("omniverse://host").as_str(), "omniverse://host/");
    }

    #[test]
    fn non_empty_path_is_unchanged() {
        for spelling in ["s3://bucket/key", "file:///dir/file", "logical:///x/obj"] {
            let url = Url::parse(spelling).unwrap();
            assert_eq!(canon(spelling), url, "{spelling} must be stable");
        }
    }

    #[test]
    fn non_special_scheme_host_is_lowercased() {
        // The `url` crate leaves the host case as-typed for non-special schemes;
        // `canonicalize` must fold it to lowercase (host is case-insensitive).
        let cases = [
            ("omniverse://SERVER", "omniverse://server/"),
            ("s3://BUCKET/Key", "s3://bucket/Key"), // path case preserved
            ("logical://Host/x/obj", "logical://host/x/obj"),
            ("scheme://[FE80::1]/p", "scheme://[fe80::1]/p"), // IPv6 hex lowercased
        ];
        for (input, expected) in cases {
            assert_eq!(
                canon(input).as_str(),
                expected,
                "{input} should canonicalize to {expected}"
            );
        }
    }

    #[test]
    fn special_scheme_host_already_canonical_is_noop() {
        for spelling in ["http://server/x", "https://server/x", "file:///d/f"] {
            let url = Url::parse(spelling).unwrap();
            assert_eq!(canon(spelling), url, "{spelling} must be stable");
        }
    }

    #[test]
    fn dot_segments_are_resolved() {
        assert_eq!(
            canon("omniverse://H/a/../b/./c").as_str(),
            "omniverse://h/b/c"
        );
    }

    /// The rule this whole construction exists for: an encoded separator becomes
    /// a real one, which exposes a dot segment that was hiding behind it.
    #[test]
    fn encoded_separators_decode_and_then_resolve() {
        let cases = [
            ("s3://b/a%2Fb", "s3://b/a/b"),
            ("s3://b/a%2F..%2Fb", "s3://b/b"),
            ("s3://b/a/..%2Fb", "s3://b/b"),
            // Unreserved characters decode too, so `%70rivate` cannot hide from
            // a rule written for `private`.
            ("s3://b/%70rivate/x", "s3://b/private/x"),
            // A whole-segment encoded dot was already resolved by `Url::parse`;
            // assert it still is.
            ("s3://b/a/%2E%2E/b", "s3://b/b"),
        ];
        for (input, expected) in cases {
            assert_eq!(canon(input).as_str(), expected, "{input}");
        }
    }

    #[test]
    fn fragment_is_stripped() {
        assert_eq!(
            canon("omniverse://s/p#checkpoint").as_str(),
            "omniverse://s/p"
        );
        assert_eq!(canon("s3://b/obj#?versionId=x").as_str(), "s3://b/obj");
    }

    #[test]
    fn query_is_preserved() {
        // The query selects *which* object is served, so it is part of node
        // identity and canonicalize must not touch it.
        assert_eq!(
            canon("s3://b/obj?versionId=1").as_str(),
            "s3://b/obj?versionId=1"
        );
    }

    #[test]
    fn trailing_slash_is_preserved_in_both_directions() {
        // `docs` and `docs/` are two objects on a flat store. Canonicalize must
        // not invent a spelling in either direction — that is the whole reason
        // node-awareness lives at the comparison sites instead of here.
        for spelling in ["s3://b/docs", "s3://b/docs/"] {
            assert_eq!(canon(spelling).as_str(), spelling);
        }
    }

    /// An empty path segment is not addressable, on any scheme.
    ///
    /// Whether a backend distinguishes `a//b` from `a/b` is not a property of
    /// the scheme — Azure decides it per connection — so the rule cannot be
    /// scoped, and the safe uniform choice is the coarse one. A key that really
    /// contains `//` joins the keys containing dot segments and literal `%2F`:
    /// unaddressable, and dropped from listings rather than mis-addressed.
    #[test]
    fn empty_segments_collapse_on_every_scheme() {
        for (spelling, expected) in [
            (
                "file:///root//private/secret",
                "file:///root/private/secret",
            ),
            (
                "file:///root///private/secret",
                "file:///root/private/secret",
            ),
            (
                "file:///root/%2Fprivate/secret",
                "file:///root/private/secret",
            ),
            ("s3://b/d//x", "s3://b/d/x"),
            ("s3://b/%2Fx", "s3://b/x"),
            ("omniverse://h/a//b", "omniverse://h/a/b"),
            (
                "azure://acct/container//blob",
                "azure://acct/container/blob",
            ),
        ] {
            assert_eq!(canon(spelling).as_str(), expected, "{spelling}");
        }
    }

    /// The trailing slash is the one separator that still carries identity —
    /// `docs` and `docs/` are two objects on a flat store, and that distinction
    /// is the distinction this whole address model exists to preserve.
    /// Collapsing runs must not touch it.
    #[test]
    fn a_single_trailing_slash_survives_the_collapse() {
        assert_eq!(canon("s3://b/docs/").as_str(), "s3://b/docs/");
        assert_eq!(canon("s3://b/docs//").as_str(), "s3://b/docs/");
        assert_ne!(canon("s3://b/docs"), canon("s3://b/docs/"));
    }

    /// Property 1 of three: **injectivity**. Idempotence is the weakest of the
    /// three and passed on every input that was losing data, so assert directly
    /// that distinct legal keys stay distinct addresses.
    #[test]
    fn distinct_keys_yield_distinct_addresses() {
        let pairs = [
            // TAB, which `set_path` strips rather than encodes.
            ("s3://b/a%09b", "s3://b/ab"),
            // A backslash, which the crate rewrites to `/` for special schemes
            // on every platform — a different file on Linux.
            (
                "file:///root/private%5Cnotes.txt",
                "file:///root/private/notes.txt",
            ),
            // Invalid UTF-8, which a `String`-based pipeline would collapse onto
            // one replacement character.
            ("s3://b/x%FF", "s3://b/x%FE"),
        ];
        for (left, right) in pairs {
            assert_ne!(canon(left), canon(right), "{left} vs {right}");
        }
    }

    /// Property 2: the **string** round trip, not value idempotence. Addresses
    /// cross the string boundary on every hop — gRPC, the plugin ABI, the Python
    /// bridge, SQLite byte-cache keys — and a construction can be stable as a
    /// value while losing a component on re-parse.
    #[test]
    fn canonical_form_survives_a_string_round_trip() {
        for spelling in [
            "s3://b/a%2F..%2Fb",
            "s3://b/dir/a%252Fb",
            "s3://b/a%25b",
            "s3://b/pub%20x",
            "s3://b/x%FF",
            "file:///root/private%5Cnotes.txt",
            "omniverse://H/a/../b#frag",
            "s3://b/obj?versionId=1",
            "s3://b/docs/",
            "file://server/share/x",
            "file://server/C%3A/data.txt",
            "file:///C%7C/notes.txt",
        ] {
            let once = canon(spelling);
            let round_tripped = canon(once.as_str());
            assert_eq!(round_tripped, once, "{spelling} degrades across a re-parse");
        }
    }

    /// Property 3: nothing is left for `set_path` to rewrite.
    ///
    /// The encode sets remove the triggers for the rewrites the crate would
    /// otherwise apply, so each of these keeps naming the object it names.
    /// `CANONICAL_FILE_PATH` and `CANONICAL_FILE_SHARE_PATH` exist for the first
    /// two; the third is the one rewrite deliberately allowed through; the
    /// fourth is what each set costs where it does not apply.
    #[test]
    fn the_crate_has_nothing_left_to_rewrite() {
        // `Url::parse` keeps `C|` intact, so `set_path` is where the
        // drive-letter rewrite would fire and turn this into `/C:/notes.txt`, a
        // different Linux file. Escaped on every `file:` address, with or
        // without an authority.
        assert_eq!(
            canon("file:///C%7C/notes.txt").as_str(),
            "file:///C%7C/notes.txt"
        );

        // With an authority, the decoded `C:` would make the serialization
        // re-parse with no host, turning a remote share into a local disk.
        let unc = canon("file://server/C%3A/data.txt");
        assert_eq!(unc.host_str(), Some("server"), "the share must survive");
        assert_eq!(
            Url::parse(unc.as_str()).unwrap().host_str(),
            Some("server"),
            "and must survive a re-parse, which is where it used to be lost"
        );

        // Without one there is no host to lose, so the drive letter is spelled
        // plainly. This is the canonical form of a Windows path — the spelling
        // `Url::from_file_path` and every other tool writes — and the reason
        // `:` is not in `CANONICAL_FILE_PATH`.
        assert_eq!(
            canon("file:///C:/data/x").as_str(),
            "file:///C:/data/x",
            "a local Windows path is canonically spelled C:, not C%3A"
        );
        assert_eq!(
            canon("file:///C%3A/data/x").as_str(),
            "file:///C:/data/x",
            "and the escaped spelling canonicalizes onto it"
        );
        assert_eq!(
            canon("file:///tmp/a:b").as_str(),
            "file:///tmp/a:b",
            "a colon anywhere else in a local path is ordinary data"
        );

        // Allowed through: `%2F` decodes to a leading separator and `file:`
        // trims it. POSIX makes `//etc/passwd` and `/etc/passwd` one file, and
        // the raw spelling `file:////etc/passwd` already collapses at parse, so
        // accepting it keeps the two spellings in agreement.
        assert_eq!(
            canon("file:///%2Fetc/passwd").as_str(),
            "file:///etc/passwd"
        );

        // Scoped to `file:`. An ordinary key keeps its colons rather than
        // being spelled `2026-08-02T10%3A00%3A00Z`.
        assert_eq!(
            canon("s3://b/2026-08-02T10:00:00Z/log").as_str(),
            "s3://b/2026-08-02T10:00:00Z/log"
        );
    }

    /// The same rejections must not swallow the raw spellings a person types.
    /// Every one of these is normalized by `Url::parse` before canonicalize sees
    /// it, and a regression here would break ordinary input while every
    /// rejection test above stayed green.
    #[test]
    fn raw_spellings_a_person_types_still_resolve() {
        // A Windows-style path, converted by `Url::parse`.
        assert_eq!(
            canon(r"file:\\server\share\x").as_str(),
            "file://server/share/x"
        );
        // Leading slashes are collapsed at parse for `file:`, so the ordinary
        // Unix spelling never reaches the postcondition.
        assert_eq!(
            canon("file:////tmp/data.csv").as_str(),
            "file:///tmp/data.csv"
        );
        // A URL wrapped across lines: the crate strips TAB/LF/CR on raw input.
        assert_eq!(canon("s3://b/a\nb").as_str(), "s3://b/ab");
    }

    /// Escaped bytes are decoded exactly once and re-escaped, so a second pass
    /// is a fixed point. Without the `%` re-escape the address would peel one
    /// layer per round trip.
    #[test]
    fn percent_signs_survive_as_data() {
        let cases = [
            ("s3://b/a%2525b", "s3://b/a%2525b"),
            ("s3://b/a%25b", "s3://b/a%25b"),
            ("s3://b/a%3Fb", "s3://b/a%3Fb"),
            ("s3://b/a%20b", "s3://b/a%20b"),
            // Control bytes come back as escapes rather than being stripped.
            ("s3://b/a%09b", "s3://b/a%09b"),
        ];
        for (input, expected) in cases {
            assert_eq!(canon(input).as_str(), expected, "{input}");
        }
    }

    #[test]
    fn is_idempotent() {
        for spelling in [
            "s3://bucket",
            "omniverse://SERVER/Obj",
            "s3://b/a%2F..%2Fb",
            "s3://b/a%2525b",
            "s3://b/x%FF",
            "s3://b/docs/",
        ] {
            let once = canon(spelling);
            let twice = canonicalize(once.clone());
            assert_eq!(once, twice, "{spelling}");
        }
    }

    /// `canonicalize` leaves this class alone rather than half-normalizing it:
    /// the path state machine never runs, so `set_path` would manufacture a
    /// separator from a decoded `%2F` and leave the traversal unresolved.
    /// `address::parse` refuses the class outright.
    #[test]
    fn authority_less_urls_are_left_untouched() {
        for spelling in ["s3:a/b", "s3:a%2F..%2Fb", "urn:example:resource"] {
            let url = Url::parse(spelling).unwrap();
            assert!(url.cannot_be_a_base(), "{spelling} must be opaque");
            assert_eq!(canonicalize(url.clone()), url, "{spelling}");
        }
    }

    #[test]
    fn dot_segments_cannot_escape_the_root() {
        // RFC 3986 §5.2.4 discards a `..` that would climb above the root, so an
        // address cannot reach outside its own authority.
        assert_eq!(canon("s3://b/..%2F..%2Fetc").as_str(), "s3://b/etc");
        assert_eq!(canon("s3://b/a%2F..%2F..%2Fb").as_str(), "s3://b/b");
    }

    /// An empty segment before `..` must not absorb the `..`.
    ///
    /// This is an authorization boundary, not a spelling question. Collapsing
    /// separator runs must happen *before* dot segments are resolved, or `a//..`
    /// becomes a no-op — the `..` cancels the empty segment instead of `a` — and
    /// `root/private//../public/secret.txt` normalizes to
    /// `root/private/public/secret.txt`, which a `root/private/` scope contains.
    /// Every operating system disagrees: `open(2)` and `realpath(3)` treat a run
    /// of separators as one, so it reaches `root/public/secret.txt`, outside
    /// that scope. Measured on Linux: both spellings `realpath` to
    /// `root/public/secret.txt`.
    ///
    /// **Every input here is escaped, and that is required, not incidental.**
    /// `Url::parse` resolves dot segments itself, and in doing so pops a
    /// preceding empty segment — so a *raw* `s3://b/a//../b` arrives as `/a/b`
    /// and this function never sees the run. Only an escaped separator survives
    /// parsing as data and reaches the normalizer, which is also the spelling an
    /// attacker uses to hide structure. Writing these rows raw would assert on
    /// the crate's behaviour and pass no matter what this pipeline does.
    ///
    /// The load-bearing line is the ordering in `normalize_path_bytes`; swapping
    /// the two calls reddens every row below.
    #[test]
    fn an_empty_segment_before_a_dot_dot_does_not_absorb_it() {
        // The escaped run and its collapsed equivalent must name one node.
        assert_eq!(canon("s3://b/a%2F%2F..%2Fb").as_str(), "s3://b/b");
        assert_eq!(
            canon("s3://b/a%2F%2F..%2Fb").as_str(),
            canon("s3://b/a%2F..%2Fb").as_str(),
        );

        // The escape this closes, in the shape a policy actually meets: the
        // doubled separator must not keep the address inside `private/`.
        assert_eq!(
            canon("s3://b/root/private%2F%2F..%2Fpublic%2Fsecret.txt").as_str(),
            "s3://b/root/public/secret.txt",
        );

        // Any number of separators, and repeated climbs.
        assert_eq!(canon("s3://b/a%2F%2F%2F..%2Fb").as_str(), "s3://b/b");
        assert_eq!(
            canon("s3://b/a%2F%2Fb%2F%2F..%2F..%2Fc").as_str(),
            "s3://b/c"
        );

        // The trailing slash is still untouched: collapsing runs is not
        // collapsing `docs` onto `docs/`.
        assert_eq!(canon("s3://b/docs%2F%2F").as_str(), "s3://b/docs/");
        assert_ne!(
            canon("s3://b/docs").as_str(),
            canon("s3://b/docs/").as_str(),
        );
    }

    #[test]
    fn remove_dot_segments_matches_the_rfc_examples() {
        // RFC 3986 §5.2.4's own worked examples.
        assert_eq!(remove_dot_segments(b"/a/b/c/./../../g"), b"/a/g");
        assert_eq!(remove_dot_segments(b"/mid/content=5/../6"), b"/mid/6");
        assert_eq!(remove_dot_segments(b"/a/b/c/."), b"/a/b/c/");
        assert_eq!(remove_dot_segments(b"/.."), b"/");
        assert_eq!(remove_dot_segments(b"/"), b"/");
        assert_eq!(remove_dot_segments(b""), b"");
    }
}
