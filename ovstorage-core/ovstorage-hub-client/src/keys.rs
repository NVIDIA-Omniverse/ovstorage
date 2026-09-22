// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cache key derivation for the hub's cache-aside interface.
//!
//! Hub keys are opaque to the hub, chosen by the client, and write-once, so
//! a key has to name the exact bytes it stands for: the object's identity
//! plus the validator the source reported for those bytes. Two schemes
//! derive one.
//!
//! [`KeyScheme::Ovstorage`] hashes ovstorage's own identity tuple. Nothing
//! else reads those keys, so the scheme is free of interop constraints and
//! can stay a fixed-width hash.
//!
//! [`KeyScheme::OmniClientCompat`] reproduces the key `HubAPI::generateKey`
//! writes in the omni.client library, so a workstation running both clients
//! keeps one cached copy of an object instead of two. omni.client picks
//! between three tiers: a content hash the source reported, `recompose(uri)
//! + '@' + version`, and `recompose(uri) + '@' + modified-time`. This
//! module emits the first two: the `md5;`-prefixed digest tier its HTTP and
//! Azure providers derive from a `Content-MD5` response header (used
//! whenever the caller supplies the raw digest), and the URL tier those
//! providers otherwise reach with `extractEtag(ETag)` as the version.
//!
//! `generateKey`'s first tier is broader than one spelling: it passes any
//! non-empty hash string a provider reports through verbatim, and each
//! shipped provider spells its own — `md5;` plus the `Content-MD5` value
//! from HTTP and Azure, `type;size;value` from Nucleus, `algorithm:hex`
//! from OmniStorage. Reproducing a spelling takes the same hash material
//! from the same source, and the `Content-MD5` form is the only one that
//! is both reachable (an ovstorage stat surfaces a raw md5 and nothing
//! Nucleus- or OmniStorage-shaped) and shareable (the URL schemes both
//! clients can address — http, https, s3 — are served by exactly the
//! providers that emit it, while a Nucleus or OmniStorage URL recomposes
//! differently in the two clients, so no tier could dedupe those entries
//! anyway). The digest tier therefore fires only as often as the source
//! surfaces a digest: a backend whose stat carries none falls to the URL
//! tier where omni.client may have keyed on the hash, and the compat key
//! then misses and duplicates — a tier 1 key is a bare hash and cannot be
//! mistaken for a tier 2 URL, so the cost is never a wrong hit.
//!
//! The modified-time tier is forbidden outright: RFC-0066 bans synthesized
//! weak validators, and a timestamp is exactly that. An object with no
//! strong validator gets no key and is never cached.
//!
//! The compat scheme also refuses any URL carrying userinfo. Reproducing
//! omni.client's spelling would put the username — and, for basic-auth
//! URLs, the password — into a key persisted by the shared local hub. The
//! digest tier could avoid spelling the URL, but credential-bearing URLs
//! are refused uniformly, so whether they enter the shared cache does not
//! depend on which validator metadata a backend happens to report.
//!
//! Nothing here performs I/O.

use sha2::{Digest, Sha256};
use url::Url;

/// How a hub cache key is derived from a request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyScheme {
    /// ovstorage's own scheme: a hash of partition, URL and etag.
    ///
    /// The key space is disjoint from anything else that talks to the hub,
    /// so a hit always came from ovstorage and always matches the exact
    /// validator that was cached.
    #[default]
    Ovstorage,
    /// omni.client's scheme, so both clients share cached objects.
    ///
    /// This is a single-partition, local-workstation interop mode: the
    /// partition deliberately does not participate, because omni.client has
    /// no notion of one and any partition byte in the key would miss every
    /// entry omni.client writes. Two ovstorage partitions pointing at the
    /// same URL therefore share an entry, which is exactly the sharing the
    /// mode is asking for.
    OmniClientCompat,
}

impl KeyScheme {
    /// Parses the `key_scheme` configuration value.
    ///
    /// Returns `None` for anything but the two exact spellings, so a
    /// misspelled scheme fails the stack build instead of silently keying
    /// objects a different way than the operator asked for.
    pub fn from_config_str(value: &str) -> Option<Self> {
        match value {
            "ovstorage" => Some(Self::Ovstorage),
            "omni-client-compat" => Some(Self::OmniClientCompat),
            _ => None,
        }
    }
}

/// The three strings a cache-aside open needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubKey {
    /// The cache key. Opaque to the hub and unique to the exact bytes.
    pub key: String,
    /// The extension the hub appends to the on-disk file name. It is not
    /// part of the key: opening a key with a different extension than it
    /// was written with succeeds and hands back a path that does not exist.
    pub extension: String,
    /// The originating scheme. The hub records it and otherwise discards
    /// it; it never affects lookup.
    pub provider: String,
    /// The raw content digest the key names, set exactly when the digest
    /// tier produced the key.
    ///
    /// A digest key claims a content identity, not a URL-and-validator one:
    /// a hit under it answers any URL whose current stat reports the same
    /// digest. A fill must therefore prove the staged bytes actually carry
    /// this digest before committing — an etag match is no proof, because
    /// an etag a source reuses across two bodies would let the wrong bytes
    /// be published under the digest of the right ones, and a write-once
    /// key never gets a second chance.
    pub digest: Option<Vec<u8>>,
}

/// Derives the hub key for `url` under `scheme`, from the validator `etag`
/// and, when the source reported one, the object's raw `md5` digest.
///
/// Returns `None` when the scheme cannot key this request, which for both
/// schemes means the source gave no usable validator: caching bytes under a
/// key that does not name their version is how a cache serves stale data
/// forever, and hub keys are write-once, so the mistake is unrecoverable.
/// [`KeyScheme::Ovstorage`] keys on the etag alone (hashed verbatim,
/// rejecting only an empty one); [`KeyScheme::OmniClientCompat`] follows
/// omni.client's tier order — a content digest first, then
/// `extractEtag(etag)` as the version, so a value that trims away to
/// nothing is rejected too. The compat scheme additionally rejects URLs
/// carrying userinfo, whose URL tier would otherwise persist those
/// credentials verbatim in the shared hub's key index.
pub fn hub_key(
    scheme: KeyScheme,
    partition: &str,
    url: &Url,
    etag: &str,
    md5: Option<&[u8]>,
) -> Option<HubKey> {
    match scheme {
        KeyScheme::Ovstorage => {
            // The digest never participates: this scheme's identity tuple
            // is partition, URL and etag by design, and nothing else reads
            // its keys, so there is no interop tier to follow.
            if etag.is_empty() {
                return None;
            }
            Some(HubKey {
                key: ovstorage_key(partition, url, etag),
                extension: OVSTORAGE_EXTENSION.to_string(),
                provider: url.scheme().to_string(),
                digest: None,
            })
        }
        KeyScheme::OmniClientCompat => {
            // The hub is a shared local daemon and persists client-provided
            // keys. omni.client's URL tier includes userinfo, which can hold
            // a basic-auth password, so reproducing it would turn a cache
            // key into durable credential storage. Refuse the URL before
            // choosing a tier, so whether a credential-bearing URL enters
            // the shared cache does not depend on which validator metadata a
            // backend happens to report.
            if !url.username().is_empty() || url.password().is_some() {
                return None;
            }
            let path = decoded_path(url);
            // Tier 1, checked before anything about the etag, as
            // generateKey checks it: omni.client's HTTP and Azure providers
            // key on `md5;` + the `Content-MD5` value when the source sends
            // one. The header carries the canonical base64 of the raw
            // digest, so encoding the raw bytes reproduces it exactly. A
            // content digest is the strongest byte-identity validator there
            // is; the partition deliberately stays out, as it does for
            // tier 2.
            if let Some(digest) = md5.filter(|digest| !digest.is_empty()) {
                use base64::Engine as _;
                return Some(HubKey {
                    key: format!(
                        "md5;{}",
                        base64::engine::general_purpose::STANDARD.encode(digest)
                    ),
                    extension: get_extension(&path),
                    provider: url.scheme().to_string(),
                    digest: Some(digest.to_vec()),
                });
            }
            let version = extract_etag(etag);
            if version.is_empty() {
                return None;
            }
            // A compat key is `url@version`, and `@` is legal inside a URL,
            // so the string decomposes uniquely only at its LAST `@` — which
            // holds exactly when the version carries none. A version with an
            // `@` lets two identities collide on one key (`url?q` with
            // version `r@s`, and `url?q@r` with version `s`), and
            // omni.client caches the ambiguous form anyway; refusing to key
            // it means this layer never serves bytes under an aliased key,
            // at the cost of not caching such objects.
            if version.contains('@') {
                return None;
            }
            Some(HubKey {
                key: format!("{}@{version}", recompose(url, &path)),
                extension: get_extension(&path),
                provider: url.scheme().to_string(),
                digest: None,
            })
        }
    }
}

/// Marks a key as ovstorage's and versions the derivation.
///
/// Disjointness from omni.client's key space is conventional rather than
/// provable: omni.client's first tier passes a provider-chosen hash string
/// through verbatim, and a provider may emit any text. Every hash its
/// shipped providers emit is `md5;`-prefixed or a Nucleus digest, and its
/// other tier is a `scheme://…@version` string — none begin with this
/// prefix. A deliberately colliding hash is outside this key's threat
/// model regardless: the hub accepts writes from any local process with no
/// authentication, so an actor able to publish a colliding hash could fill
/// this exact key directly. Changing the derivation without changing the
/// prefix would let old entries answer new lookups, so the two move
/// together.
const OVSTORAGE_KEY_PREFIX: &str = "ovs1-";

/// The extension every [`KeyScheme::Ovstorage`] entry is stored under.
///
/// This value is PERMANENT. The extension names the on-disk file but not
/// the key, so changing it does not invalidate anything: every existing
/// entry keeps answering `OpenForRead` with success and a path that no
/// longer exists, while the refill that would repair it is rejected with
/// `ALREADY_EXISTS` because the key is unchanged and hub keys are
/// write-once. The cache is then permanently poisoned for those keys.
const OVSTORAGE_EXTENSION: &str = "bin";

/// Hashes the identity tuple that decides whether two requests are the same
/// bytes.
///
/// Each field is length-prefixed before it is hashed, so the tuple's
/// framing cannot be forged: no delimiter convention survives a field that
/// may contain arbitrary bytes (an etag is backend-chosen, a partition is
/// operator-chosen), while a length prefix makes the encoding injective for
/// every input.
///
/// The etag goes in verbatim: unlike the compat scheme this key is never
/// read by anything else, so there is nothing to normalize toward, and
/// hashing the raw bytes keeps quoted, weak and opaque etags distinct
/// rather than collapsing them onto one key.
fn ovstorage_key(partition: &str, url: &Url, etag: &str) -> String {
    let mut hasher = Sha256::new();
    for field in [
        partition.as_bytes(),
        url.as_str().as_bytes(),
        etag.as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    let digest = hasher.finalize();
    let mut key = String::with_capacity(OVSTORAGE_KEY_PREFIX.len() + digest.len() * 2);
    key.push_str(OVSTORAGE_KEY_PREFIX);
    for byte in digest {
        // Lower-case hex, as everywhere else in the repository. The case is
        // part of the key format and cannot be changed for the same reason
        // the extension cannot.
        key.push_str(&format!("{byte:02x}"));
    }
    key
}

/// Reproduces `HttpBaseProvider::extractEtag`.
///
/// The `W/` prefix of a weak etag is stripped first and the quotes and
/// surrounding whitespace second, in that order: a value that arrives
/// already quoted keeps a `W/` that sits inside the quotes, because the
/// prefix test only looks at the first two bytes of the untrimmed value.
fn extract_etag(etag: &str) -> &str {
    let stripped = etag.strip_prefix("W/").unwrap_or(etag);
    stripped.trim_matches(['"', ' ', '\t', '\r', '\n'])
}

/// Reproduces `UriNormalizer::recompose` for `url`, given the parsed path
/// from [`decoded_path`].
///
/// The C++ pipeline is `parse` then `recompose`. `parse` percent-decodes
/// the path, query and fragment against the unreserved set only, decodes
/// the userinfo and host completely, lowercases the scheme and host, and
/// removes dot segments from an absolute path. `recompose` re-encodes each
/// component against its own table, drops a default port, and finishes with
/// one `percentDecode(…, kRFC3986_UNRESERVED)` pass over the whole string —
/// which is what turns `%7E` into `~` while leaving `%20` alone. This
/// function starts from `url::Url`'s already-parsed components and applies
/// the same recomposition.
///
/// The two pipelines agree on the schemes that matter here (http, https,
/// s3). They can drift elsewhere:
///
/// * `url` applies IDNA and IPv4 canonicalization to the hosts of special
///   schemes and percent-encodes opaque hosts; omni.client only decodes and
///   lowercases, so an internationalized or unusual host can recompose two
///   ways.
/// * `url` canonicalizes the port as a number; omni.client compares the
///   literal text, so it keeps a zero-padded `:080` that `url` folds to
///   `:80`.
/// * The default-port table below is omni.client's, which lists only http
///   and https. `url` additionally drops the ws, wss, ftp and file
///   defaults before this function sees them, where omni.client would keep
///   them.
/// * omni.client treats an input that starts with `/` as a raw path with no
///   scheme, and applies Windows path fixups to `file:` URLs. Every input
///   here has a scheme, so `file:` recomposes differently.
/// * omni.client expands its `omni:`/`omnis:` aliases before parsing.
///   ovstorage does not speak those schemes.
/// * `url` removes dot segments as it parses, one path segment at a time,
///   so `/a//../b.usd` spends its `..` on the empty segment that `//` left
///   and keeps `/a/b.usd`. omni.client collapses `//` into `/` first and
///   then spends the `..` on `a`, reaching `/b.usd`. The information the
///   two disagree about is gone by the time `url` hands over a parsed URL.
///   ovstorage's Stack canonicalizes an address before this module sees
///   it, so the interleaved form does not arrive here in practice.
/// * `url` drops the colon of an empty password, so `https://user:@server`
///   parses with no password at all and recomposes as `user@server`.
///   omni.client keeps the userinfo whole and encodes the colon, reaching
///   `user%3A@server`. `url` erases the colon before this module runs.
/// * A query that typed `%27` where a raw `'` was meant recomposes with the
///   apostrophe, not the escape. [`restore_query_apostrophes`] explains why
///   the two spellings cannot both be served.
///
/// Every one of those costs a duplicate cache entry and nothing more. The
/// validator is inside the key, so a key that drifts cannot collide with a
/// different object's key: it simply misses and refills.
fn recompose(url: &Url, path: &[u8]) -> String {
    let mut recomposed = String::new();

    // `recomposeSchemeAuthority`. A parsed `Url` always has a scheme, so the
    // `hasScheme` branch is always taken; both parsers lowercase it.
    recomposed.push_str(url.scheme());
    recomposed.push(':');
    if let Some(host) = url.host_str() {
        recomposed.push_str("//");
        // The userinfo is one field in omni.client, holding either `user`
        // or the deprecated `user:password`, decoded at parse time and
        // re-encoded against the unreserved set alone — which is why the
        // separating colon comes back out as `%3A`.
        let userinfo = percent_decode(userinfo(url).as_bytes(), None);
        if !userinfo.is_empty() {
            recomposed.push_str(&percent_encode(&userinfo, Allowed::Unreserved));
            recomposed.push('@');
        }
        recomposed.push_str(&host.to_ascii_lowercase());
        if let Some(port) = url.port()
            && default_port(url.scheme()) != Some(port)
        {
            recomposed.push(':');
            recomposed.push_str(&port.to_string());
        }
    }

    // `recomposePathQueryFragment`.
    let mut path = path.to_vec();
    if url.host_str().is_some() && !path.is_empty() && path[0] != b'/' {
        // A path under an authority must be absolute.
        path.insert(0, b'/');
    }
    recomposed.push_str(&percent_encode(&path, Allowed::Path));
    if let Some(query) = url.query() {
        // Presence, not content: a bare `?` recomposes as a bare `?`.
        recomposed.push('?');
        let decoded = percent_decode(query.as_bytes(), Some(Allowed::Unreserved));
        let decoded = if special_scheme(url.scheme()) {
            restore_query_apostrophes(&decoded)
        } else {
            decoded
        };
        recomposed.push_str(&percent_encode(&decoded, Allowed::Query));
    }
    if let Some(fragment) = url.fragment() {
        recomposed.push('#');
        let decoded = percent_decode(fragment.as_bytes(), Some(Allowed::Unreserved));
        recomposed.push_str(&percent_encode(&decoded, Allowed::Fragment));
    }

    // The final pass, and the reason an unreserved character never survives
    // as an escape. Every byte reaching it is ASCII — the encoders emit
    // ASCII and `url` percent-encodes everything else — so the lossy
    // conversion cannot replace anything.
    String::from_utf8_lossy(&percent_decode(
        recomposed.as_bytes(),
        Some(Allowed::Unreserved),
    ))
    .into_owned()
}

/// Rebuilds the single userinfo field omni.client parses out of an
/// authority.
fn userinfo(url: &Url) -> String {
    match url.password() {
        Some(password) => format!("{}:{password}", url.username()),
        None => url.username().to_string(),
    }
}

/// The WHATWG special schemes, the ones `url` percent-encodes a query
/// apostrophe for. `url` keeps the list private, so this repeats it.
fn special_scheme(scheme: &str) -> bool {
    matches!(scheme, "http" | "https" | "ws" | "wss" | "ftp" | "file")
}

/// Puts back the apostrophes `url` escaped on the way in.
///
/// `url` encodes a query against the WHATWG special-query set for a special
/// scheme, and that set holds one byte omni.client's
/// `kRFC3986_QUERY_ALLOWED` permits: `'`, a sub-delimiter. Every other byte
/// `url` escapes there — the C0 controls, DEL, space, `"`, `#`, `<`, `>`
/// and everything non-ASCII — is outside omni.client's table too, so
/// omni.client escapes it as well; every byte `url` leaves alone is
/// re-encoded here against omni.client's table regardless. The apostrophe
/// is therefore the whole of the gap, and decoding it closes it.
///
/// A query that typed `%27` instead diverges, because omni.client keeps
/// that escape where this hands back an apostrophe. `url` collapses the two
/// spellings into one before this module runs, so one of them has to lose,
/// and a raw apostrophe is what a user types. The cost is a duplicate
/// entry: the version is in the key, so a key that drifts misses and
/// refills.
///
/// Hex digits have no case here — `2` and `7` are digits — so the one
/// spelling `%27` is the only one `url` or an input can produce.
fn restore_query_apostrophes(query: &[u8]) -> Vec<u8> {
    decode_escapes(query, |byte| byte == b'\'')
}

/// Produces the path as omni.client's `ParsedUri::path` holds it: decoded
/// against the unreserved set, with dot segments removed when absolute.
///
/// Both the recomposed key and the extension are derived from this exact
/// string, as they are in omni.client, where the call site passes
/// `uri.path` to `getExtension`.
fn decoded_path(url: &Url) -> Vec<u8> {
    let decoded = percent_decode(url.path().as_bytes(), Some(Allowed::Unreserved));
    if decoded.first() == Some(&b'/') {
        remove_dots(&decoded)
    } else {
        decoded
    }
}

/// Reproduces `getExtension`: everything after the last `.`, with no
/// leading dot, and empty when the last dot names a directory rather than a
/// file (`/a.b/c`) or when there is no dot at all.
///
/// The dot and the slash are looked for in the path exactly as
/// [`decoded_path`] built it, which is the string omni.client searches too:
/// a `%2F` is an escape in both, so it does not trip the dot-then-slash
/// rule. The bytes that follow the dot are then decoded once more, by
/// [`escaped_from_raw`]'s rule, because omni.client's extension keeps raw
/// bytes raw where its key escapes them.
fn get_extension(path: &[u8]) -> String {
    let Some(dot) = path.iter().rposition(|byte| *byte == b'.') else {
        return String::new();
    };
    if path[dot..].contains(&b'/') {
        return String::new();
    }
    // A decode that does not land on UTF-8 was reading escapes no raw
    // input could have written: `url` parses a `&str`, so a raw byte is
    // always part of a well-formed character and only a typed escape can
    // be a loose one. omni.client keeps a typed escape as written, and a
    // `String` cannot hold the loose byte in any case, so the undecoded
    // spelling is both the closer match and the only representable one.
    String::from_utf8(decode_escapes(&path[dot + 1..], escaped_from_raw))
        .unwrap_or_else(|_| String::from_utf8_lossy(&path[dot + 1..]).into_owned())
}

/// Whether `url` percent-encodes `byte` when it appears raw in the path of
/// a URL it parses — which is the test for whether an escape in the
/// extension should be decoded.
///
/// omni.client reads one path two ways: `recompose` re-encodes it into the
/// key, and `getExtension` takes it as it stands. As it stands means
/// `percentDecode(input, kRFC3986_UNRESERVED)`, where a raw byte is raw and
/// an escape the input typed is still typed. `url` stores the mirror image
/// — it escapes the raw bytes and passes the typed escapes through — so by
/// the time this crate is handed a `Url`, raw and typed are one string. The
/// key does not care, because both pipelines escape the byte again on the
/// way out. The extension does, and an extension that differs under a key
/// that matches is the one failure this module cannot afford: both clients
/// hit the same key, the bytes sit under one client's file name, and the
/// other is handed a path that does not exist. Hub keys are write-once, so
/// no refill repairs it.
///
/// Decoding therefore follows the raw spelling, which is the one a user
/// types. An escape is decoded exactly when `url` could have produced it
/// from a raw byte: the WHATWG path percent-encode set — the C0 controls,
/// DEL, space, `"`, `#`, `<`, `>`, `?`, `` ` ``, `{`, `}` and every
/// non-ASCII byte — less the five of those that never reach a parsed path
/// raw, which the match below names. An escape for
/// anything outside that, `%2F` first among them, can only have been typed,
/// and omni.client keeps a typed escape exactly as written.
///
/// What is left over is an input that typed an escape for a byte in the
/// set, where omni.client keeps the escape and this decodes it: same key,
/// two extensions. omni.client already does that to itself — the raw and
/// typed spellings of one byte give it one key and two extensions — so the
/// trap is confined to the population that is already in it, and it is the
/// smaller of the two populations by far.
fn escaped_from_raw(byte: u8) -> bool {
    match byte {
        // In `url`'s table, but unreachable raw: `?` and `#` end the path
        // and start the query and the fragment, and tab, LF and CR are
        // stripped out of the input before the path is parsed at all. An
        // escape for one of these was typed.
        b'?' | b'#' | b'\t' | b'\n' | b'\r' => false,
        b' ' | b'"' | b'<' | b'>' | b'`' | b'{' | b'}' => true,
        // The rest of the C0 controls, DEL, and every non-ASCII byte.
        _ => !(0x20..0x7f).contains(&byte),
    }
}

/// `g_defaultPorts` from `UriNormalizer.cpp`, entire.
fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

/// RFC 3986 section 2.3.
const RFC3986_UNRESERVED: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

/// RFC 3986 section 2.2.
const RFC3986_SUB_DELIMS: &str = "!$&'()*+,;=";

/// The character tables `percentEncode` and `percentDecode` are called with.
#[derive(Clone, Copy)]
enum Allowed {
    /// `kRFC3986_UNRESERVED`.
    Unreserved,
    /// `kRFC3986_PATH_ALLOWED`.
    Path,
    /// `kRFC3986_QUERY_ALLOWED`.
    Query,
    /// `kRFC3986_FRAGMENT_ALLOWED`, defined identically to the query table.
    Fragment,
}

impl Allowed {
    fn contains(self, byte: u8) -> bool {
        let unreserved = RFC3986_UNRESERVED.as_bytes().contains(&byte);
        // `kRFC3986_PCHARS = kRFC3986_UNRESERVED + kRFC3986_SUB_DELIMS +
        // ":@"`; the path table adds `/`, the query and fragment tables add
        // `/?`.
        let pchar = unreserved
            || RFC3986_SUB_DELIMS.as_bytes().contains(&byte)
            || matches!(byte, b':' | b'@');
        match self {
            Self::Unreserved => unreserved,
            Self::Path => pchar || byte == b'/',
            Self::Query | Self::Fragment => pchar || matches!(byte, b'/' | b'?'),
        }
    }
}

/// Reproduces `UriNormalizer::percentEncode`.
///
/// An existing `%xx` passes through untouched, so re-encoding an already
/// encoded string never doubles the `%`. A `%` with no two hex digits
/// behind it is data and is encoded as `%25`; the lookahead needs both
/// digits inside the string, so a trailing `%` or `%4` is always data.
fn percent_encode(input: &[u8], allowed: Allowed) -> String {
    let mut encoded = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%'
            && i + 2 < input.len()
            && hex_decode(input[i + 1]).is_some()
            && hex_decode(input[i + 2]).is_some()
        {
            encoded.push('%');
            encoded.push(input[i + 1] as char);
            encoded.push(input[i + 2] as char);
            i += 3;
            continue;
        }
        if allowed.contains(input[i]) {
            encoded.push(input[i] as char);
        } else {
            encoded.push('%');
            encoded.push(hex_encode(input[i] >> 4));
            encoded.push(hex_encode(input[i] & 0xF));
        }
        i += 1;
    }
    encoded
}

/// Reproduces `UriNormalizer::percentDecode`.
///
/// `allowed` restricts which escapes are decoded: an escape whose byte is
/// outside the table stays as written. `None` decodes everything, which is
/// how the userinfo and host are parsed.
fn percent_decode(input: &[u8], allowed: Option<Allowed>) -> Vec<u8> {
    decode_escapes(input, |byte| {
        allowed.is_none_or(|table| table.contains(byte))
    })
}

/// The scan under [`percent_decode`], with the table swapped for a rule.
///
/// An escape is replaced by its byte when `decode` accepts that byte and
/// left as written otherwise. A `%` without two hex digits behind it is
/// data, which is what keeps a trailing `%` or `%4` intact.
fn decode_escapes(input: &[u8], decode: impl Fn(u8) -> bool) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%'
            && i + 2 < input.len()
            && let (Some(high), Some(low)) = (hex_decode(input[i + 1]), hex_decode(input[i + 2]))
        {
            let byte = high * 16 + low;
            if decode(byte) {
                decoded.push(byte);
                i += 3;
                continue;
            }
        }
        decoded.push(input[i]);
        i += 1;
    }
    decoded
}

/// Reproduces `removeDots`: RFC 3986 section 5.2.4 plus omni.client's
/// collapse of `//` into `/`, which the RFC does not ask for but every
/// filesystem does.
fn remove_dots(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut rest = input;
    while !rest.is_empty() {
        if let Some(tail) = rest.strip_prefix(b"./") {
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix(b"../") {
            rest = tail;
        } else if rest.starts_with(b"/./") {
            rest = &rest[2..];
        } else if rest.starts_with(b"//") {
            rest = &rest[1..];
        } else if rest == b"/." {
            rest = b"/";
        } else if rest.starts_with(b"/../") {
            rest = &rest[3..];
            truncate_last_segment(&mut out);
        } else if rest == b"/.." {
            rest = b"/";
            truncate_last_segment(&mut out);
        } else if rest == b"." || rest == b".." {
            rest = b"";
        } else {
            let next = rest[1..]
                .iter()
                .position(|byte| *byte == b'/')
                .map_or(rest.len(), |offset| offset + 1);
            out.extend_from_slice(&rest[..next]);
            rest = &rest[next..];
        }
    }
    out
}

/// Drops the last segment of `out` along with its leading `/`, as the
/// `/../` rule requires.
fn truncate_last_segment(out: &mut Vec<u8>) {
    match out.iter().rposition(|byte| *byte == b'/') {
        Some(slash) => out.truncate(slash),
        None => out.clear(),
    }
}

/// Uppercase, matching `hexEncode`. Percent-escapes this crate emits are
/// therefore uppercase, and escapes it passes through keep the case they
/// arrived with.
fn hex_encode(nibble: u8) -> char {
    char::from(if nibble < 10 {
        b'0' + nibble
    } else {
        b'A' + (nibble - 10)
    })
}

/// Case-insensitive, matching `hexDecode`.
fn hex_decode(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(10 + byte - b'a'),
        b'A'..=b'F' => Some(10 + byte - b'A'),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(url: &str) -> Url {
        Url::parse(url).expect("test URL parses")
    }

    fn compat(url: &str, etag: &str) -> HubKey {
        hub_key(
            KeyScheme::OmniClientCompat,
            "local",
            &parse(url),
            etag,
            None,
        )
        .expect("a usable validator produces a key")
    }

    fn ovstorage(partition: &str, url: &str, etag: &str) -> HubKey {
        hub_key(KeyScheme::Ovstorage, partition, &parse(url), etag, None)
            .expect("a usable validator produces a key")
    }

    /// `(url, etag, expected key, expected extension)`, each row derived by
    /// hand from `HubAPI::generateKey`, `UriNormalizer::recompose`,
    /// `HttpBaseProvider::extractEtag` and `getExtension`.
    const COMPAT_GOLDEN: &[(&str, &str, &str, &str)] = &[
        // The base shape: `recompose(uri) + '@' + extractEtag(etag)`, with
        // the quotes trimmed off the etag and the extension taken from the
        // path.
        (
            "https://server/path/file.usd",
            "\"abc123\"",
            "https://server/path/file.usd@abc123",
            "usd",
        ),
        // A weak etag loses its `W/` before the quotes are trimmed.
        (
            "https://server/path/file.usd",
            "W/\"xyz\"",
            "https://server/path/file.usd@xyz",
            "usd",
        ),
        // `W/` is only a prefix of the raw value: quoted first, it is data.
        (
            "https://server/path/file.usd",
            "\"W/xyz\"",
            "https://server/path/file.usd@W/xyz",
            "usd",
        ),
        // Whitespace and repeated quotes trim from both ends; an interior
        // quote is content.
        (
            "https://server/path/file.usd",
            "  \"\"a\"b\"\" \r\n",
            "https://server/path/file.usd@a\"b",
            "usd",
        ),
        // `g_defaultPorts` maps https to 443, so the port disappears.
        (
            "https://server:443/path/file.usd",
            "\"abc123\"",
            "https://server/path/file.usd@abc123",
            "usd",
        ),
        // Any other port is part of the authority.
        (
            "https://server:8443/path/file.usd",
            "\"abc123\"",
            "https://server:8443/path/file.usd@abc123",
            "usd",
        ),
        // http's default is 80.
        (
            "http://server:80/path/file.usd",
            "\"abc123\"",
            "http://server/path/file.usd@abc123",
            "usd",
        ),
        // s3 is in the overlap set and has no default port entry.
        (
            "s3://bucket/models/robot.usdz",
            "\"abc123\"",
            "s3://bucket/models/robot.usdz@abc123",
            "usdz",
        ),
        // A port on a scheme with no default is always kept, even when the
        // number is another scheme's default.
        (
            "s3://bucket:443/models/robot.usdz",
            "\"abc123\"",
            "s3://bucket:443/models/robot.usdz@abc123",
            "usdz",
        ),
        // `str_tolower` on the host only; the path keeps its case.
        (
            "s3://BUCKET/Models/Robot.usd",
            "\"abc123\"",
            "s3://bucket/Models/Robot.usd@abc123",
            "usd",
        ),
        // An authority with no path recomposes with no path: the empty-path
        // default only applies to schemes in `g_defaultPaths`, and the
        // leading `/` is only forced onto a non-empty path.
        ("s3://bucket", "\"abc123\"", "s3://bucket@abc123", ""),
        // The query is part of the key. `=` and `&` are sub-delimiters, so
        // they survive `kRFC3986_QUERY_ALLOWED` unencoded.
        (
            "https://server/a.usd?v=2&t=x",
            "\"abc123\"",
            "https://server/a.usd?v=2&t=x@abc123",
            "usd",
        ),
        // The fragment is part of the key too.
        (
            "https://server/a.usd#frag",
            "\"abc123\"",
            "https://server/a.usd#frag@abc123",
            "usd",
        ),
        // Both at once, in RFC order.
        (
            "https://server/a.usd?v=2#frag",
            "\"abc123\"",
            "https://server/a.usd?v=2#frag@abc123",
            "usd",
        ),
        // `hasQuery` records presence, not content, so an empty query keeps
        // its `?`.
        (
            "https://server/a.usd?",
            "\"abc123\"",
            "https://server/a.usd?@abc123",
            "usd",
        ),
        // A space is not unreserved, so neither the parse-time decode nor
        // the final decode pass touches it.
        (
            "https://server/my%20file.usd",
            "\"abc123\"",
            "https://server/my%20file.usd@abc123",
            "usd",
        ),
        // A tilde is unreserved: parse decodes it, the path table permits
        // it, and it stays decoded.
        (
            "https://server/my%7Efile.usd",
            "\"abc123\"",
            "https://server/my~file.usd@abc123",
            "usd",
        ),
        // The escape's hex digits are read case-insensitively.
        (
            "https://server/my%7efile.usd",
            "\"abc123\"",
            "https://server/my~file.usd@abc123",
            "usd",
        ),
        // A dot is unreserved, so `%2E` decodes and then feeds the
        // extension just like a literal dot.
        (
            "https://server/file%2Eusd",
            "\"abc123\"",
            "https://server/file.usd@abc123",
            "usd",
        ),
        // A slash is not unreserved, so `%2F` stays an escape — and being
        // an escape, it does not trigger `getExtension`'s dot-then-slash
        // rule.
        (
            "https://server/a%2Fb.usd",
            "\"abc123\"",
            "https://server/a%2Fb.usd@abc123",
            "usd",
        ),
        // A byte outside `kRFC3986_PATH_ALLOWED` is encoded, in upper-case
        // hex, and the final decode pass leaves it alone because `|` is not
        // unreserved.
        (
            "https://server/a|b.usd",
            "\"abc123\"",
            "https://server/a%7Cb.usd@abc123",
            "usd",
        ),
        // A `%` with nothing decodable behind it is data and encodes.
        (
            "https://server/p%",
            "\"abc123\"",
            "https://server/p%25@abc123",
            "",
        ),
        // No dot anywhere in the path: no extension.
        (
            "https://server/data/blob",
            "\"abc123\"",
            "https://server/data/blob@abc123",
            "",
        ),
        // The dot names a directory, so `getExtension` refuses to return
        // `b/c`.
        (
            "https://server/a.b/c",
            "\"abc123\"",
            "https://server/a.b/c@abc123",
            "",
        ),
        // A trailing slash puts a `/` after the last dot as well.
        (
            "https://server/a.b/",
            "\"abc123\"",
            "https://server/a.b/@abc123",
            "",
        ),
        // A leading-dot file name is all extension: the rule is "after the
        // last dot", with no special case for a dot in first position.
        (
            "https://server/dir/.hidden",
            "\"abc123\"",
            "https://server/dir/.hidden@abc123",
            "hidden",
        ),
        // `removeDots` collapses `//` inside a path, which RFC 3986 does
        // not do and `url` therefore leaves alone.
        (
            "https://server/a//b/c.usd",
            "\"abc123\"",
            "https://server/a/b/c.usd@abc123",
            "usd",
        ),
        // Ordinary dot-segment removal.
        (
            "https://server/a/./b/../c.usd",
            "\"abc123\"",
            "https://server/a/c.usd@abc123",
            "usd",
        ),
        // `%2E%2E` decodes to `..` before the dot segments are removed, so
        // an encoded traversal is removed as well.
        (
            "https://server/a/%2E%2E/c.usd",
            "\"abc123\"",
            "https://server/c.usd@abc123",
            "usd",
        ),
        // `'` is a sub-delimiter and so is inside
        // `kRFC3986_QUERY_ALLOWED`: omni.client keeps it literal. `url`
        // escapes it, because https is a special scheme and its
        // special-query set adds `'`, and `restore_query_apostrophes` puts
        // it back.
        (
            "https://server/a.usd?name='x'",
            "\"abc123\"",
            "https://server/a.usd?name='x'@abc123",
            "usd",
        ),
        // s3 is not a special scheme, so `url` never escaped the
        // apostrophe and nothing has to be undone.
        (
            "s3://bucket/a.usd?name='x'",
            "\"abc123\"",
            "s3://bucket/a.usd?name='x'@abc123",
            "usd",
        ),
        // A DOCUMENTED DIVERGENCE. omni.client would leave a typed `%27`
        // encoded, because `%` is not unreserved, and key this
        // `…?name=%27x%27@abc123`. `url` gives the typed and the raw
        // spelling one string, so the two cannot both be served, and the
        // raw one wins. The cost is a duplicate entry.
        (
            "https://server/a.usd?name=%27x%27",
            "\"abc123\"",
            "https://server/a.usd?name='x'@abc123",
            "usd",
        ),
        // The same input under a non-special scheme keeps the escape, and
        // so matches omni.client: with no escaping on the way in there is
        // no ambiguity to resolve, and `%27` can only have been typed.
        (
            "s3://bucket/a.usd?name=%27x%27",
            "\"abc123\"",
            "s3://bucket/a.usd?name=%27x%27@abc123",
            "usd",
        ),
        // `url`'s fragment set does not add `'`, so a fragment apostrophe
        // survives untouched and needs no repair.
        (
            "https://server/a.usd#fr'ag",
            "\"abc123\"",
            "https://server/a.usd#fr'ag@abc123",
            "usd",
        ),
        // A raw non-ASCII byte. Both pipelines key it escaped —
        // omni.client encodes the raw byte, `url` already did — but
        // omni.client's `getExtension` reads its path raw, so the
        // extension is the character, not the escape. Same key, so the
        // extension has to agree or the two clients name different files.
        (
            "https://server/a.usdé",
            "\"abc123\"",
            "https://server/a.usd%C3%A9@abc123",
            "usdé",
        ),
        // A raw space, the same case in ASCII.
        (
            "https://server/a.us d",
            "\"abc123\"",
            "https://server/a.us%20d@abc123",
            "us d",
        ),
        // A raw brace, which `url` escapes and omni.client's
        // `kRFC3986_PATH_ALLOWED` also rejects, so the keys agree and the
        // extension is again the raw character.
        (
            "https://server/a.us{d}",
            "\"abc123\"",
            "https://server/a.us%7Bd%7D@abc123",
            "us{d}",
        ),
        // A DOCUMENTED DIVERGENCE, and the residue of the two rows above:
        // an input that typed `%20` keys identically and omni.client
        // extends it `us%20d`. Its own two spellings already disagree this
        // way, so nothing can serve both, and the raw spelling is the one
        // a user types.
        (
            "https://server/a.us%20d",
            "\"abc123\"",
            "https://server/a.us%20d@abc123",
            "us d",
        ),
        // `%2F` can only have been typed: a raw `/` would have been a path
        // separator, so `url` never produces this escape. omni.client
        // keeps a typed escape as written, so the extension keeps it too —
        // and the dot-then-slash rule does not see a separator here, in
        // either pipeline.
        (
            "https://server/f.u%2Fsd",
            "\"abc123\"",
            "https://server/f.u%2Fsd@abc123",
            "u%2Fsd",
        ),
        // `%25` is in the same class: `url` leaves a raw `%` alone rather
        // than escaping it, so this escape was typed.
        (
            "https://server/a.us%25d",
            "\"abc123\"",
            "https://server/a.us%25d@abc123",
            "us%25d",
        ),
        // So is `%3F`: a raw `?` would have started the query.
        (
            "https://server/a.us%3Fd",
            "\"abc123\"",
            "https://server/a.us%3Fd@abc123",
            "us%3Fd",
        ),
        // And so is `%09`: `url` strips a raw tab out of the input
        // entirely, so it cannot be the source of this escape.
        (
            "https://server/a.us%09d",
            "\"abc123\"",
            "https://server/a.us%09d@abc123",
            "us%09d",
        ),
        // A control that is not stripped is in the decoded class, so the
        // extension carries the byte itself.
        (
            "https://server/a.us%01d",
            "\"abc123\"",
            "https://server/a.us%01d@abc123",
            "us\u{1}d",
        ),
        // A lone continuation byte is unreachable raw — `url` parses a
        // `&str` — so this escape was typed, and the extension keeps the
        // spelling omni.client keeps rather than a replacement character.
        (
            "https://server/a.us%C3d",
            "\"abc123\"",
            "https://server/a.us%C3d@abc123",
            "us%C3d",
        ),
    ];

    #[test]
    fn compat_keys_match_the_hand_derived_golden_vectors() {
        for (url, etag, expected_key, expected_extension) in COMPAT_GOLDEN {
            let derived = compat(url, etag);
            assert_eq!(&derived.key, expected_key, "key for {url} @ {etag}");
            assert_eq!(
                &derived.extension, expected_extension,
                "extension for {url} @ {etag}"
            );
            assert_eq!(
                derived.provider,
                parse(url).scheme(),
                "provider for {url} @ {etag}"
            );
        }
    }

    #[test]
    fn compat_ignores_the_partition_because_omni_client_has_none() {
        let url = parse("https://server/path/file.usd");
        let one = hub_key(KeyScheme::OmniClientCompat, "one", &url, "\"abc123\"", None);
        let other = hub_key(
            KeyScheme::OmniClientCompat,
            "other",
            &url,
            "\"abc123\"",
            None,
        );
        assert_eq!(one, other);
    }

    #[test]
    fn compat_keys_change_with_the_validator() {
        let first = compat("https://server/path/file.usd", "\"abc123\"");
        let second = compat("https://server/path/file.usd", "\"def456\"");
        assert_ne!(first.key, second.key);
    }

    /// A key that matches has to name a file that matches.
    ///
    /// `url` hands the raw and the typed spelling of one byte back as a
    /// single parsed URL, so the two key identically here and, in
    /// omni.client, key identically as well. The extension has to follow,
    /// or one client writes the bytes and the other opens the key,
    /// succeeds, and is handed a path that does not exist. omni.client is
    /// the one that does not follow: it extends the raw spelling `usdé`
    /// and the typed spelling `usd%C3%A9` under that one key.
    #[test]
    fn one_key_names_one_extension() {
        let raw = compat("https://server/a.usdé", "\"abc123\"");
        let typed = compat("https://server/a.usd%C3%A9", "\"abc123\"");
        assert_eq!(raw, typed);
        assert_eq!(raw.extension, "usdé");
    }

    /// The apostrophe repair belongs to the query of a special scheme and
    /// nowhere else, because that is the only place `url` escapes one.
    #[test]
    fn the_apostrophe_repair_is_scoped_to_a_special_scheme_query() {
        // `url`'s path set has no `'`, so a raw one arrives raw and
        // `kRFC3986_PATH_ALLOWED` keeps it.
        assert_eq!(
            compat("https://server/it's.usd", "\"abc123\"").key,
            "https://server/it's.usd@abc123"
        );
        // A typed one in the path stays an escape, as it does in
        // omni.client: nothing escaped it, so nothing decodes it.
        assert_eq!(
            compat("https://server/it%27s.usd", "\"abc123\"").key,
            "https://server/it%27s.usd@abc123"
        );
    }

    /// The parse-order divergence `recompose` documents as unfixable, pinned
    /// so the documentation cannot quietly stop being true. (The
    /// empty-password divergence it used to pin alongside is unreachable
    /// now: userinfo is refused before recomposition.)
    #[test]
    fn the_unfixable_parse_order_divergence_is_what_the_documentation_says() {
        // `url` spends the `..` on the empty segment `//` left behind.
        // omni.client collapses `//` first and spends it on `a`, keying
        // `https://server/b.usd@abc123`.
        assert_eq!(
            compat("https://server/a//../b.usd", "\"abc123\"").key,
            "https://server/a/b.usd@abc123"
        );
    }

    /// Userinfo is refused before either tier is chosen: a content digest
    /// must not make credential-bearing URLs conditionally cacheable, and
    /// the URL tier would persist the credentials verbatim.
    #[test]
    fn compat_refuses_userinfo_before_either_key_tier() {
        let digest = [0x5a; 16];
        for url in [
            "https://user@server/a.usd",
            "https://user:password@server/a.usd",
            "https://:password@server/a.usd",
            // `url` erases the empty-password colon but preserves the
            // username, so this spelling is refused as well.
            "https://user:@server/a.usd",
        ] {
            let url = parse(url);
            assert!(
                hub_key(
                    KeyScheme::OmniClientCompat,
                    "local",
                    &url,
                    "\"abc123\"",
                    None,
                )
                .is_none(),
                "{url} must not key"
            );
            assert!(
                hub_key(
                    KeyScheme::OmniClientCompat,
                    "local",
                    &url,
                    "\"abc123\"",
                    Some(&digest),
                )
                .is_none(),
                "a content digest must not bypass the userinfo refusal for {url}"
            );
        }
    }

    /// The opaque scheme never exposes URL text, so a credential-bearing
    /// URL keys there without persisting its credentials.
    #[test]
    fn ovstorage_hashes_userinfo_instead_of_persisting_it_as_text() {
        let url = parse("https://user:password@server/a.usd");
        let keyed = hub_key(KeyScheme::Ovstorage, "local", &url, "\"abc123\"", None)
            .expect("the opaque scheme does not expose URL text");
        assert!(keyed.key.starts_with(OVSTORAGE_KEY_PREFIX));
        assert!(!keyed.key.contains("user"));
        assert!(!keyed.key.contains("password"));
    }

    /// The exact key for one known input. It exists to fail when the
    /// derivation changes: hub keys are write-once, so a silent change
    /// strands every entry already written under the old one.
    #[test]
    fn the_ovstorage_key_for_a_known_input_is_stable() {
        let derived = ovstorage("local", "https://server/path/file.usd", "\"abc123\"");
        assert_eq!(
            derived.key,
            "ovs1-a7add35536c26749327f60c608e7eae290d8a893728aa33dbce43fd9effd8bc7"
        );
        assert_eq!(derived.extension, "bin");
        assert_eq!(derived.provider, "https");
    }

    /// The length-prefixed hash input is injective: shifting bytes across a
    /// field boundary — an etag that swallows the next URL, a partition that
    /// swallows the URL's head — derives a different key, so two stacks
    /// sharing one hub cannot alias objects across policy partitions.
    #[test]
    fn ovstorage_field_boundaries_cannot_be_forged() {
        let a = ovstorage("p", "https://x/a", "https://x/b\u{1f}e");
        let b = ovstorage("p\u{1f}https://x/a", "https://x/b", "e");
        assert_ne!(a.key, b.key);
    }

    /// An `@` inside the validator makes the compat concatenation ambiguous
    /// (two identities, one key), so such objects are never keyed; the
    /// unambiguous identity that shares the combined string still is.
    #[test]
    fn compat_refuses_a_validator_containing_an_at_sign() {
        let ambiguous = Url::parse("https://server/a.usd?q").unwrap();
        assert!(
            hub_key(
                KeyScheme::OmniClientCompat,
                "local",
                &ambiguous,
                "r@s",
                None
            )
            .is_none()
        );

        let unambiguous = Url::parse("https://server/a.usd?q@r").unwrap();
        let keyed = hub_key(
            KeyScheme::OmniClientCompat,
            "local",
            &unambiguous,
            "s",
            None,
        )
        .expect("an at-free validator keys");
        assert_eq!(keyed.key, "https://server/a.usd?q@r@s");
    }

    /// The digest tier, byte-for-byte against `generateKey`'s first arm:
    /// omni.client keys on `md5;` + the `Content-MD5` value, which is the
    /// canonical base64 of the raw digest. The vector is the well-known md5
    /// of the empty input, whose base64 is `1B2M2Y8AsgTpgAmY7PhCfg==`.
    #[test]
    fn a_content_digest_keys_the_compat_tier_one() {
        let url = Url::parse("https://server/path/file.usd").unwrap();
        let digest: [u8; 16] = [
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
            0x42, 0x7e,
        ];
        let keyed = hub_key(
            KeyScheme::OmniClientCompat,
            "local",
            &url,
            "\"abc123\"",
            Some(&digest),
        )
        .expect("a digest keys");
        // The digest wins over the etag, exactly as generateKey checks the
        // hash before the version.
        assert_eq!(keyed.key, "md5;1B2M2Y8AsgTpgAmY7PhCfg==");
        // The extension convention is the same for every tier.
        assert_eq!(keyed.extension, "usd");
        assert_eq!(keyed.provider, "https");
        // The key carries the digest it names, so a fill can prove the
        // staged bytes against it before committing.
        assert_eq!(keyed.digest.as_deref(), Some(&digest[..]));

        // An empty digest is no digest: the URL tier answers.
        let fallback = hub_key(
            KeyScheme::OmniClientCompat,
            "local",
            &url,
            "\"abc123\"",
            Some(&[]),
        )
        .expect("the etag still keys");
        assert_eq!(fallback.key, "https://server/path/file.usd@abc123");

        // A digest keys even when the etag alone could not — generateKey
        // never reaches the later tiers once a hash exists.
        let digest_only = hub_key(
            KeyScheme::OmniClientCompat,
            "local",
            &url,
            "",
            Some(&digest),
        )
        .expect("the digest needs no etag");
        assert_eq!(digest_only.key, "md5;1B2M2Y8AsgTpgAmY7PhCfg==");

        // The ovstorage scheme ignores the digest: its identity tuple is
        // partition, URL and etag by design.
        let with = hub_key(
            KeyScheme::Ovstorage,
            "local",
            &url,
            "\"abc123\"",
            Some(&digest),
        );
        let without = hub_key(KeyScheme::Ovstorage, "local", &url, "\"abc123\"", None);
        assert_eq!(with.unwrap().key, without.unwrap().key);
    }

    #[test]
    fn ovstorage_keys_are_prefixed_and_fixed_width() {
        let derived = ovstorage("local", "s3://bucket/models/robot.usdz", "\"abc123\"");
        assert!(derived.key.starts_with("ovs1-"));
        // The prefix plus a sha-256 in hex, and nothing that could be
        // mistaken for an omni.client key.
        assert_eq!(derived.key.len(), "ovs1-".len() + 64);
        assert!(
            derived.key["ovs1-".len()..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert_eq!(derived.extension, "bin");
        assert_eq!(derived.provider, "s3");
    }

    #[test]
    fn ovstorage_keys_separate_partitions_urls_and_validators() {
        let base = ovstorage("local", "https://server/path/file.usd", "\"abc123\"");
        let other_partition = ovstorage("other", "https://server/path/file.usd", "\"abc123\"");
        let other_url = ovstorage("local", "https://server/path/other.usd", "\"abc123\"");
        let other_etag = ovstorage("local", "https://server/path/file.usd", "\"def456\"");
        assert_ne!(base.key, other_partition.key);
        assert_ne!(base.key, other_url.key);
        assert_ne!(base.key, other_etag.key);
    }

    #[test]
    fn ovstorage_hashes_the_etag_verbatim() {
        // Quoted, unquoted and weak spellings of one etag are three keys.
        // Nothing else reads these keys, so normalizing toward another
        // client's spelling would buy nothing and could merge validators
        // that a source means to distinguish.
        let quoted = ovstorage("local", "https://server/a.usd", "\"abc123\"");
        let bare = ovstorage("local", "https://server/a.usd", "abc123");
        let weak = ovstorage("local", "https://server/a.usd", "W/\"abc123\"");
        assert_ne!(quoted.key, bare.key);
        assert_ne!(quoted.key, weak.key);
        assert_ne!(bare.key, weak.key);
    }

    #[test]
    fn ovstorage_keys_are_stable_across_calls() {
        let first = ovstorage("local", "https://server/path/file.usd", "\"abc123\"");
        let second = ovstorage("local", "https://server/path/file.usd", "\"abc123\"");
        assert_eq!(first, second);
    }

    #[test]
    fn an_empty_validator_has_no_key_under_either_scheme() {
        let url = parse("https://server/path/file.usd");
        assert!(hub_key(KeyScheme::Ovstorage, "local", &url, "", None).is_none());
        assert!(hub_key(KeyScheme::OmniClientCompat, "local", &url, "", None).is_none());
    }

    #[test]
    fn compat_rejects_a_validator_that_trims_away_to_nothing() {
        let url = parse("https://server/path/file.usd");
        for etag in ["  ", "\"\"", "W/\"\"", "\r\n", "W/"] {
            assert!(
                hub_key(KeyScheme::OmniClientCompat, "local", &url, etag, None).is_none(),
                "{etag:?} carries no version"
            );
            // The ovstorage scheme hashes the raw bytes, so only an empty
            // etag disqualifies a request there. Any non-empty validator is
            // a usable discriminator once it is hashed, and the layer's own
            // no-validator rule is what keeps unversioned objects out.
            assert!(hub_key(KeyScheme::Ovstorage, "local", &url, etag, None).is_some());
        }
    }

    #[test]
    fn the_scheme_name_parses_only_as_spelled() {
        assert_eq!(
            KeyScheme::from_config_str("ovstorage"),
            Some(KeyScheme::Ovstorage)
        );
        assert_eq!(
            KeyScheme::from_config_str("omni-client-compat"),
            Some(KeyScheme::OmniClientCompat)
        );
        for value in [
            "",
            "Ovstorage",
            "omni_client_compat",
            "omni-client",
            " ovstorage",
        ] {
            assert_eq!(KeyScheme::from_config_str(value), None, "{value:?}");
        }
        assert_eq!(KeyScheme::default(), KeyScheme::Ovstorage);
    }
}
