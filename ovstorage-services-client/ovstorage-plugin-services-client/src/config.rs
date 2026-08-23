// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use ovstorage_plugin::{
    ConfigField, ConfigFieldKind, ConfigValue, CredentialField, CredentialMethod, Error, ErrorCode,
    Result,
};

pub const KIND: &str = "omniverse-storage-service";

/// The one required config key: where the service is.
///
/// Named for what it holds — an address — rather than for one of the two things
/// an address can be. It carries either a discovery root or a storage gRPC
/// endpoint, and the broker client names the identical field the same way
/// (`ovstorage-remote/ovstorage-plugin-broker/src/layer.rs`).
pub const ADDRESS_KEY: &str = "address";

/// The pre-0.2.1 spelling of [`ADDRESS_KEY`]. Not accepted — kept only so a config
/// still carrying it is refused with a message naming the new key, instead of
/// being ignored while the connection reports a missing required field.
const RENAMED_FROM: &str = "discovery_url";

/// Opt-in to sending a bearer token over a cleartext `grpc://` channel that
/// leaves this machine.
pub const ALLOW_PLAINTEXT_CREDENTIALS_KEY: &str = "allow_plaintext_credentials";

pub fn config_schema() -> Vec<ConfigField> {
    vec![
        ConfigField {
            key: ADDRESS_KEY.into(),
            display_name: "Service address".into(),
            kind: ConfigFieldKind::Url,
            required: true,
            default: None,
            help: Some(
                "Where the Omniverse Storage Service is. Either a discovery URL \
                 serving /api/v1/services and /api/v1/auth-config, or a storage \
                 gRPC endpoint dialed directly: grpcs://host:port for TLS, \
                 grpc://host:port for plaintext. A direct endpoint means there \
                 is no discovery service, so there is no sign-in and no \
                 directory watching — a bearer token can still be supplied \
                 through the credential surface and rotated on a live \
                 connection."
                    .into(),
            ),
            example: Some("https://omniverse-storage-service.example.com".into()),
            group: Some("server".into()),
            advanced: false,
        },
        ConfigField {
            key: ALLOW_PLAINTEXT_CREDENTIALS_KEY.into(),
            display_name: "Allow credentials over plaintext gRPC".into(),
            kind: ConfigFieldKind::Bool,
            required: false,
            default: Some(ConfigValue::Bool(false)),
            help: Some(
                "Permit a bearer token to be sent over a grpc:// channel that leaves this \
                 machine. Off by default: the object bytes on such a link already travel in \
                 clear, but an access token is not bounded by them — whoever can read the link \
                 can replay the token anywhere else its audience is accepted. Set this only \
                 where the link is trusted end to end (a service mesh with mTLS, or an \
                 encrypted underlay). Loopback needs no opt-in, and grpcs:// is unaffected."
                    .into(),
            ),
            example: None,
            group: Some("auth".into()),
            advanced: false,
        },
        ConfigField {
            key: "oidc_client_name".into(),
            display_name: "OIDC client name".into(),
            kind: ConfigFieldKind::Text,
            required: false,
            default: Some(ConfigValue::String("default".into())),
            help: Some("Selects which client entry from /api/v1/auth-config to drive".into()),
            example: None,
            group: Some("auth".into()),
            advanced: true,
        },
        ConfigField {
            key: "persistence_id".into(),
            display_name: "Credential persistence ID".into(),
            kind: ConfigFieldKind::Text,
            required: false,
            default: None,
            help: Some(
                "Durable account discriminator. Give each connection to the same discovery \
                 URL and OIDC client its own value so each keeps a separate stored \
                 credential. Choose it once and keep it: changing it moves the connection to \
                 a fresh credential and requires signing in again."
                    .into(),
            ),
            example: Some("alice-work".into()),
            group: Some("auth".into()),
            advanced: true,
        },
    ]
}

pub fn credential_schema() -> Vec<CredentialField> {
    vec![
        CredentialField {
            key: "oauth".into(),
            display_name: "OIDC token bundle".into(),
            default: None,
            help: Some(
                "Access + refresh token returned by the upstream IDP after PKCE / device \
                 flow. A host that mints its own access token can also supply one here \
                 directly and replace it on a live connection; against a direct gRPC \
                 endpoint that is the only credential shape there is, since no OIDC \
                 endpoints are published to grant against."
                    .into(),
            ),
            advanced: false,
        },
        CredentialField {
            key: "client_id".into(),
            display_name: "Client ID".into(),
            default: None,
            help: Some("OIDC client identifier for client-credentials grants".into()),
            advanced: false,
        },
        CredentialField {
            key: "client_secret".into(),
            display_name: "Client secret".into(),
            default: None,
            help: Some("OIDC client secret paired with `client_id`".into()),
            advanced: false,
        },
    ]
}

pub fn credential_methods() -> Vec<CredentialMethod> {
    vec![
        CredentialMethod {
            key: "interactive".into(),
            display_name: "OIDC sign-in (browser / device flow)".into(),
            fields: vec!["oauth".into()],
            help: Some(
                "Recommended. Opens an OIDC sign-in flow in your browser or returns a device code."
                    .into(),
            ),
            advanced: false,
        },
        CredentialMethod {
            key: "client_credentials".into(),
            display_name: "OIDC client credentials (machine-to-machine)".into(),
            fields: vec!["client_id".into(), "client_secret".into()],
            help: Some(
                "For service identities: authenticates to the IDP with a client ID and secret \
                 instead of a user sign-in."
                    .into(),
            ),
            advanced: false,
        },
    ]
}

/// Where a connection's Omniverse Storage Service lives, as resolved from the
/// single [`ADDRESS_KEY`] config key.
///
/// The two arms are told apart by the URL scheme, which is the same
/// discrimination the broker client applies to its `address` key. `grpc://`
/// and `grpcs://` name a storage gRPC endpoint to dial; everything else names
/// an HTTP discovery root. A `grpc://` value cannot resolve as a discovery
/// root — services discovery is an HTTP GET and the client speaks only
/// `http`/`https` — so the spelling was free to take (pinned by
/// `discovery::tests::services_discovery_refuses_a_grpc_scheme_root`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceLocation {
    /// HTTP(S) root serving `/api/v1/services` and `/api/v1/auth-config`.
    Discovery(String),
    /// A storage-kind gRPC endpoint dialed directly. There is no discovery
    /// service, so no auth-config and no service kind other than `storage`.
    DirectGrpc {
        /// The tonic-dialable form, `http://…` or `https://…`.
        dial_uri: String,
        /// The operator's `grpc://` / `grpcs://` spelling, canonicalized. This
        /// is the connection's durable identity, kept distinct from `dial_uri`
        /// so a direct endpoint can never derive the same key as a discovery
        /// URL naming the same authority.
        locator: String,
    },
}

impl ServiceLocation {
    /// The one string that identifies this connection: its `BackendId`, its
    /// default display name, and its keyring key when it has one. For a
    /// discovery config it is the normalized address itself; for a direct
    /// endpoint it is the canonical `grpc://` / `grpcs://` spelling, which
    /// cannot collide with a discovery URL naming the same authority.
    pub fn locator(&self) -> &str {
        match self {
            Self::Discovery(url) => url,
            Self::DirectGrpc { locator, .. } => locator,
        }
    }

    /// The HTTP discovery root, when there is one. `None` says the connection
    /// has no auth-config to fetch and no service kind resolvable beyond the
    /// configured `storage` endpoint — so it can run no OIDC grant of any kind.
    /// It may still carry a bearer the host supplies directly.
    pub fn discovery_url(&self) -> Option<&str> {
        match self {
            Self::Discovery(url) => Some(url),
            Self::DirectGrpc { .. } => None,
        }
    }

    /// Whether this connection's channel is cleartext AND carries traffic off
    /// this machine — the condition under which a bearer token needs
    /// [`ALLOW_PLAINTEXT_CREDENTIALS_KEY`].
    ///
    /// Derived from `dial_uri` rather than stored, so it cannot disagree with
    /// the address it describes.
    ///
    /// **This is a much narrower question than `plaintext_is_safe`, and the
    /// two must not be conflated.** That one asks whether cleartext may be
    /// spoken to a host at all, and answers yes across private and in-cluster
    /// space — which is precisely where an eavesdropper who is not this machine
    /// lives. A discovery connection answers `false`: its channel scheme is not
    /// known until its endpoints are fetched, and the credential path this gates
    /// is the direct one.
    pub fn is_plaintext_beyond_loopback(&self) -> bool {
        let Self::DirectGrpc { dial_uri, .. } = self else {
            return false;
        };
        if !dial_uri.starts_with("http://") {
            return false;
        }
        // Taken from the PARSED host, never from the string. Every defect this
        // file has carried on the plaintext path was a string-matching accident,
        // and the string form of an IPv6 host is bracketed, so `[::1]` does not
        // parse as an address at all. `url::Host` hands over the three cases
        // already discriminated.
        //
        // A dial URI that will not parse has had its shape established by
        // nothing, so it needs the opt-in.
        let Ok(url) = url::Url::parse(dial_uri) else {
            return true;
        };
        match url.host() {
            Some(url::Host::Ipv4(v4)) => !v4.is_loopback(),
            // An IPv4-mapped address IS that IPv4 address, the same reading
            // `plaintext_is_safe` takes, so `[::ffff:127.0.0.1]` is loopback.
            Some(url::Host::Ipv6(v6)) => !match v6.to_ipv4_mapped() {
                Some(v4) => v4.is_loopback(),
                None => v6.is_loopback(),
            },
            Some(url::Host::Domain(name)) => !name_is_loopback(name),
            None => true,
        }
    }
}

/// Whether `name` addresses this machine, so that cleartext to it crosses no
/// network an eavesdropper can be on.
///
/// Deliberately the NARROW reading: `localhost` and nothing else. Not
/// `*.localhost`, which RFC 6761 reserves but resolvers honour unevenly, and
/// none of the private, shared, `.svc` or single-label space `plaintext_is_safe`
/// accepts — those are reachable from somewhere else on the network, which is
/// the entire question here. Widening this silently grants the permission the
/// config key exists to make explicit, so the failure direction is to answer
/// `false` and make the operator say so.
///
/// A trailing dot is a fully-qualified spelling of the same name, so
/// `localhost.` is `localhost`.
fn name_is_loopback(name: &str) -> bool {
    name.trim_end_matches('.').eq_ignore_ascii_case("localhost")
}

/// The direct gRPC schemes, in ONE place. Longest first, so `grpcs` is not
/// shadowed by `grpc`.
const DIRECT_SCHEMES: [(&str, &str); 2] = [("grpcs", "grpcs://"), ("grpc", "grpc://")];

/// Whether `value` carries a direct gRPC scheme, and its canonical spelling.
///
/// This is the ONLY hand-written parsing left on this path, and the reason is
/// worth stating once here rather than re-deriving at each site: the decision
/// is *which mode the operator meant*, and it has to be made on the value AS
/// TYPED. Two constraints force that. The discovery parse strips trailing
/// slashes, so a bare `grpc://` reaches it as `grpc:` and stops looking direct;
/// and `grpc:8080` — an ordinary authority whose HOST is named `grpc`, with
/// 8080 as the port — must stay a discovery root, which is why the literal
/// `://` is required rather than a scheme parse.
///
/// Everything AFTER this decision is `url::Url`'s job. Measured on `url` 2.5:
/// for the non-special `grpc` scheme it still yields host, port, path, query,
/// fragment and userinfo, so none of that needs hand-rolling — which is what
/// this file had been doing, in three places, with a byte-slice idiom that
/// aborted the process five times.
///
/// The byte-wise comparison itself is borrowed from the module that documents
/// why it must be byte-wise, rather than copied a third time.
fn split_direct_scheme(value: &str) -> Option<&'static str> {
    DIRECT_SCHEMES.iter().find_map(|(scheme, prefix)| {
        crate::discovery::strip_scheme_ci(value, prefix).map(|_| *scheme)
    })
}

/// Validate a direct gRPC endpoint, returning its canonical
/// `scheme://authority` and its bracket-free host.
///
/// A direct endpoint names a service to dial and nothing else. The string does
/// not stay private — it becomes the connection's `BackendId`, its default
/// display name, and an INFO-level log field — so anything beyond the authority
/// is refused rather than carried: `grpcs://storage:50051?token=SECRET` would
/// otherwise be persisted and printed, which is the exposure the userinfo
/// refusal exists to prevent, one delimiter over. Refusing also stops two
/// spellings of one endpoint deriving two different `BackendId`s.
fn canonical_direct_endpoint(scheme: &'static str, typed: &str) -> Result<(String, String)> {
    let parsed = url::Url::parse(typed).map_err(|err| {
        // `url` rejects an empty host itself, before the check below can reach
        // it, and "empty host" does not tell an operator which of the two
        // spellings to fix. `grpc://:50051` is a realistic paste from a
        // server's listen address, so it earns the same message as `grpc://`.
        if err == url::ParseError::EmptyHost {
            return Error::new(
                ErrorCode::InvalidArgument,
                "Service address names a direct gRPC endpoint but no host; expected \
                 grpc://host:port or grpcs://host:port",
            );
        }
        Error::new(
            ErrorCode::InvalidArgument,
            format!("Service address is not a valid URL: {err}"),
        )
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Service address must not carry userinfo: the address is recorded durably and \
             logged, and a credential belongs in the connection's credentials rather than in \
             its address",
        ));
    }
    let host = parsed.host_str().filter(|h| !h.is_empty()).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "Service address names a direct gRPC endpoint but no host; expected \
             grpc://host:port or grpcs://host:port",
        )
    })?;
    // AFTER the host check: `grpc://?x` has neither, and "no host" is the
    // more useful of the two things to say.
    if !(parsed.path().is_empty() || parsed.path() == "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Service address names a direct gRPC endpoint, which must be an address and nothing \
             else: remove the path, query or fragment",
        ));
    }
    // `url` treats a `grpc` host as OPAQUE: it neither lowercases nor decodes
    // it, and it percent-ENCODES anything non-ASCII rather than punycoding it.
    // So a `%` in the host is either a non-ASCII name the operator typed, or a
    // percent-escape they typed literally — and both must be refused here.
    //
    // Refused rather than decoded, because the classifier below counts labels
    // by splitting on `.`: `%2e` is not a separator, so `grpc://evil%2ecom`
    // reads as a single-label in-cluster name and
    // `grpc://%31%33%34%37%34%34%30%37%32` walks past the integer-address
    // guard. Both fail closed further down only by accident, because the
    // resolver does not decode either — and a gate that depends on a
    // downstream parser catching what it admitted is not a gate.
    if host.contains('%') {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            if typed.is_ascii() {
                "Service address host must not be percent-encoded; write the host literally"
            } else {
                "Service address host must be ASCII; supply an internationalized name in its \
                 punycode form (xn--...)"
            },
        ));
    }
    // A host made only of dots has no label. `url` accepts `grpcs://.` with
    // host `.` and an empty path, which then fails opaquely at connect — the
    // failure this whole guard exists to replace. `grpc://.` was worse: it
    // reached the plaintext arm and was told to "use grpcs://", and following
    // that advice landed on the silently-accepted spelling.
    if host.split('.').all(|label| label.is_empty()) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Service address names a direct gRPC endpoint but no host; expected \
             grpc://host:port or grpcs://host:port",
        ));
    }
    // Hostnames are case-insensitive, so one endpoint has one canonical
    // spelling. Without this `grpc://LOCALHOST` and `grpc://localhost` are the
    // same service with two `BackendId`s and two display names.
    let host = host.to_ascii_lowercase();
    let canonical = match parsed.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };
    // The host WITHOUT IPv6 brackets, for the classifier. Taken from the parser
    // rather than re-split off the canonical string: deriving it a second time
    // by hand is how the two-parsers-one-string defect kept recurring here.
    Ok((canonical, host.trim_matches(['[', ']']).to_string()))
}

/// Resolve the [`ADDRESS_KEY`] config key into a [`ServiceLocation`].
pub fn service_location(config: &HashMap<String, ConfigValue>) -> Result<ServiceLocation> {
    reject_renamed_key(config)?;
    let typed = match config.get(ADDRESS_KEY) {
        Some(ConfigValue::String(value)) => value.trim(),
        _ => "",
    };
    if let Some(scheme) = split_direct_scheme(typed) {
        // Rebuilt from the validated parts, so nothing unvalidated reaches the
        // dial URI, the durable locator or the log.
        let (canonical, host) = canonical_direct_endpoint(scheme, typed)?;
        // The SAME normalizer the discovery-published path uses, so one address
        // has one meaning however it arrives.
        let dial_uri = crate::discovery::normalize_grpc_uri(&canonical);
        if dial_uri.starts_with("http://") && !plaintext_is_safe(&host) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "Service address '{canonical}' asks for a plaintext gRPC connection to a host \
                     that is not local. Use grpcs:// for TLS. Plaintext is accepted only for \
                     localhost, .local / .internal / .svc names, single-label names, and \
                     loopback, private, link-local, shared-address-space, unspecified \
                     and broadcast addresses."
                ),
            ));
        }
        return Ok(ServiceLocation::DirectGrpc {
            dial_uri,
            locator: canonical,
        });
    }
    let raw = address_value(config)?;
    // A `grpc*` scheme that is not one of the two supported spellings is refused
    // by name. The broker client accepts `grpc+tls://` and `grpc+tcp://`, so an
    // operator moving between the two plugins will type them here; without this
    // they parse as a discovery root and fail much later as an
    // unsupported-scheme HTTP error naming neither problem.
    if let Ok(parsed) = url::Url::parse(&raw)
        && parsed
            .scheme()
            .as_bytes()
            .get(..4)
            .is_some_and(|head| head.eq_ignore_ascii_case(b"grpc"))
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "Service address scheme '{}' is not supported. Use grpcs:// for a direct gRPC \
                 endpoint over TLS, grpc:// for a plaintext one, or an http(s) URL for a \
                 discovery service.",
                parsed.scheme()
            ),
        ));
    }
    Ok(ServiceLocation::Discovery(raw))
}

/// Whether cleartext to `host` is acceptable without the operator saying so
/// twice.
///
/// The shared classifier covers `localhost`, `.local`, and loopback / private /
/// link-local addresses. Two more shapes belong here and are deliberately NOT
/// pushed into that shared function, because it also drives scheme inference
/// for bare authorities elsewhere in this plugin and in others, and widening it
/// would silently re-scheme existing deployments:
///
/// - **A single-label name**, `storage` or `ovstorage-svc`. This is how a
///   service is addressed inside a Docker network or from within a Kubernetes
///   namespace, and it is the likeliest spelling for the deployment this whole
///   mode exists to serve. Such a name resolves through the local search domain
///   or the container runtime's DNS, not through the public hierarchy.
///
///   Stated carefully, because the strong form is not quite true and cannot be
///   checked from here: a dotless name is not *impossible* to resolve publicly —
///   a few legacy top-level domains have carried address records — it is
///   prohibited for new gTLDs and refused by mainstream clients. So this is a
///   judgement that the in-cluster reading is overwhelmingly the intended one,
///   not a proof that the public reading cannot exist.
/// - **`.internal`**, ICANN-reserved for private use and so permanently safe,
///   and **`.svc`**, the Kubernetes in-cluster short form, which is merely
///   undelegated — the same weaker judgement as the dotless rule, not a proof.
///   Both matched as SUFFIXES only. The long form
///   `svc.namespace.svc.cluster.local` needs no special case: it ends in
///   `.local`.
/// - **Shared address space, `100.64.0.0/10`** — carrier-grade NAT and the
///   overlay networks built on it, including cluster CNIs and Tailscale.
/// - **IPv4-mapped IPv6**, judged as the IPv4 address it is — so
///   `[::ffff:127.0.0.1]` and `[::ffff:100.64.0.1]` classify exactly as
///   `127.0.0.1` and `100.64.0.1` do. Without this the shared classifier would
///   read every mapped address as public, since its `is_loopback` recognises
///   only `::1`.
/// - A **trailing dot** is a fully-qualified spelling of the same name, so
///   `localhost.` classifies like `localhost` — but it never qualifies a name
///   under the dotless rule, because a trailing dot is what turns off
///   search-domain expansion, making `ai.` public-root-only and so the exact
///   case that rule must not cover.
///
/// Getting this wrong in the other direction is what matters: refusing these
/// would block the in-cluster deployment outright, which is exactly the
/// customer this feature is for.
fn plaintext_is_safe(host: &str) -> bool {
    // Decided on the host's STRUCTURE, never by matching substrings of it.
    //
    // This predicate was got wrong four times while this change was in review,
    // and every one of those defects was a string-matching accident rather than
    // a disagreement about policy: a `.svc.` test that matched the public
    // `evil.svc.example.com`; a trailing dot stripped before the single-label
    // test, so the public apex `ai.` read as dotless. Both are unwritable
    // against a parsed host — there is no substring to match, only a last label
    // and a count — which is why this is a rewrite rather than a fifth patch.
    let is_fqdn = host.ends_with('.');
    let bare = host.trim_end_matches('.').to_ascii_lowercase();
    if bare.is_empty() {
        return false;
    }

    // Addresses first: an IP literal is not a name and has no labels.
    if let Ok(addr) = bare.parse::<std::net::IpAddr>() {
        // An IPv4-mapped address IS that IPv4 address, so judge it as one. The
        // shared classifier's `is_loopback` recognises only `::1`, so
        // `[::ffff:127.0.0.1]` would otherwise read as public.
        let v4 = match addr {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        };
        if let Some(v4) = v4 {
            // Shared address space (RFC 6598) — carrier-grade NAT and the
            // overlay networks built on it, notably cluster CNIs and Tailscale
            // — is not routable on the public internet.
            let [a, b, ..] = v4.octets();
            if a == 100 && (64..=127).contains(&b) {
                return true;
            }
            return ovstorage::net::is_local_cleartext_host(&v4.to_string());
        }
        return ovstorage::net::is_local_cleartext_host(&bare);
    }

    // Structure first, so nothing downstream can be handed a malformed name.
    // An empty label means a doubled or leading dot, which is not a hostname.
    // This has to precede the shared classifier, whose `.local` test is an
    // unstructured `ends_with` and so accepts `.local` and `a..local` — the
    // shortcut would otherwise skip a structural rule, and would carry any
    // future widening of that shared function past these checks too.
    let labels: Vec<&str> = bare.split('.').collect();
    if labels.iter().any(|label| label.is_empty()) {
        return false;
    }

    // Then the shared classifier, on the bare name: it owns `localhost` and
    // `.local`, and it must be consulted BEFORE the rules below so that a
    // fully-qualified spelling of a name it accepts — `localhost.` — qualifies
    // on its own terms rather than being caught by the trailing-dot exclusion,
    // which exists only to disqualify the single-label rule.
    if ovstorage::net::is_local_cleartext_host(&bare) {
        return true;
    }
    let last = *labels.last().expect("split always yields one element");

    // A private-use suffix is a property of the LAST label, so a public name
    // that merely contains one — `evil.svc.example.com` — cannot qualify.
    // `internal` is ICANN-reserved for private use and so permanently safe;
    // `local` is mDNS; `svc` is merely undelegated, which is the same weaker
    // judgement the single-label rule below carries.
    if matches!(last, "internal" | "local" | "svc") {
        return true;
    }

    // A single label resolves through a local search domain or the container
    // runtime's DNS rather than the public hierarchy — `storage`,
    // `ovstorage-svc`, the shape a Docker network or a Kubernetes namespace
    // uses. A trailing dot disqualifies it: that is exactly the syntax that
    // turns search expansion OFF, so `ai.` is public-root-only and is the case
    // this rule must not cover. (Dotless names are prohibited for new gTLDs and
    // refused by mainstream clients, so accepting them is a judgement that the
    // in-cluster reading is the intended one, not a proof that no such public
    // name exists.)
    if labels.len() == 1 {
        // ...unless the resolver would read it as an ADDRESS rather than a
        // name. `getaddrinfo` accepts an integer or hex form that Rust's
        // `IpAddr` parser refuses, so `134744072` never reaches the address
        // branch above and would arrive here looking like an ordinary
        // single-label service name. Measured on a stock glibc host:
        // `getent hosts 134744072` answers `8.8.8.8` — a public address, in
        // cleartext, through the branch meant for `storage`.
        //
        // A service name is never all digits and never `0x`-prefixed, so
        // refusing those costs nothing real.
        // Byte-wise, and `strip_prefix` rather than a slice. Writing
        // `last[..2]` here would abort on `пример`, whose second byte is inside
        // a character — the FIFTH occurrence of that shape in this file, in the
        // commit that claimed to make it unwritable. The lesson generalises
        // past the predicate's structure: never index a `&str` by a fixed
        // offset, use `strip_prefix`/`as_bytes().get()`.
        let hex = last
            .as_bytes()
            .get(..2)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"0x"))
            && last.len() > 2
            && last.bytes().skip(2).all(|b| b.is_ascii_hexdigit());
        let numeric = !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit());
        return !is_fqdn && !numeric && !hex;
    }

    // Everything else is a multi-label name that could be public.
    false
}

/// Refuse a config still written against the pre-0.2.1 key name.
///
/// Nothing in the host validates a supplied connection config against the
/// kind's `config_schema` — the schema drives the CLI wizard and the host UI,
/// while every consumer of a live config reads the keys it wants with `.get()`.
/// So a key nobody reads is silently ignored, and without this an upgrading
/// operator would be told the *address* is missing while the line supplying it
/// sat in the file being read by nobody.
///
/// It fires whenever the old key is present, not only when the new one is
/// absent: a config carrying both is a half-finished migration, and quietly
/// preferring one of them is the same silent-ignore defect in a smaller
/// costume.
///
/// The message names both keys and no value. The old key's value is an address
/// and may carry userinfo, so interpolating it would put a password in a
/// diagnostic.
fn reject_renamed_key(config: &HashMap<String, ConfigValue>) -> Result<()> {
    if config.contains_key(RENAMED_FROM) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "The '{RENAMED_FROM}' config key was renamed to '{ADDRESS_KEY}' and is no longer \
                 read. Its value is unchanged in meaning — a discovery URL or a direct \
                 grpc:// / grpcs:// endpoint — so rename the key and leave the value as it is."
            ),
        ));
    }
    Ok(())
}

fn address_value(config: &HashMap<String, ConfigValue>) -> Result<String> {
    let raw = match config.get(ADDRESS_KEY) {
        Some(ConfigValue::String(value)) => value.trim(),
        Some(_) => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "Service address must be text",
            ));
        }
        None => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "Service address is required",
            ));
        }
    };
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "Service address cannot be empty",
        ));
    }
    if trimmed.contains("://") {
        url::Url::parse(trimmed).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("Service address is not a valid URL: {err}"),
            )
        })?;
        return Ok(trimmed.to_string());
    }
    let scheme = if should_infer_http(trimmed) {
        "http"
    } else {
        "https"
    };
    Ok(format!("{scheme}://{trimmed}"))
}

/// Whether the operator has stated, in the config file, that this connection may
/// send a bearer token over a cleartext channel that leaves the machine.
///
/// **Absent means no, and an unset key is the common case**, so the default here
/// is the whole safety property rather than a convenience. Anything that is not
/// literally `true` reads as no: a value of the wrong TYPE is not a permission
/// granted in a spelling this function failed to recognise, and reading it as
/// one would turn a config typo into a silent credential disclosure. Nothing in
/// this host validates a supplied config against the kind's schema, so a
/// mistyped value arrives here rather than being refused above.
pub fn allow_plaintext_credentials(config: &HashMap<String, ConfigValue>) -> bool {
    matches!(
        config.get(ALLOW_PLAINTEXT_CREDENTIALS_KEY),
        Some(ConfigValue::Bool(true))
    )
}

pub fn oidc_client_name(config: &HashMap<String, ConfigValue>) -> String {
    config
        .get("oidc_client_name")
        .and_then(|v| match v {
            ConfigValue::String(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "default".to_string())
}

/// The connection's durable account discriminator, empty when unset.
///
/// Empty means the connection shares its durable key with any identically
/// configured sibling, and account separation falls to the stored identity
/// binding plus persistence-key exclusivity.
pub fn persistence_id(config: &HashMap<String, ConfigValue>) -> Result<String> {
    match config.get("persistence_id") {
        Some(ConfigValue::String(value)) => {
            Ok(ovstorage_plugin::oauth_secret_store::validate_persistence_id(value)?.to_string())
        }
        _ => Ok(String::new()),
    }
}

fn should_infer_http(host_part: &str) -> bool {
    let host = host_part
        .split('/')
        .next()
        .unwrap_or(host_part)
        .split(':')
        .next()
        .unwrap_or(host_part);
    if host == "localhost" {
        return true;
    }
    if host.ends_with(".local") {
        return true;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(value: &str) -> HashMap<String, ConfigValue> {
        let mut map = HashMap::new();
        map.insert(ADDRESS_KEY.into(), ConfigValue::String(value.into()));
        map
    }

    /// Which addresses put a bearer token on a wire a third party could read.
    ///
    /// The rows that matter are the ones where this DISAGREES with
    /// `plaintext_is_safe`: a single-label service name and RFC 1918 space are
    /// both fine to speak cleartext to and are both reachable from elsewhere on
    /// the network, so a credential needs the operator's opt-in there. Widening
    /// this to `plaintext_is_safe` would make the whole gate vacuous, and those
    /// rows are what would redden.
    #[test]
    fn only_a_non_loopback_cleartext_endpoint_needs_the_credential_opt_in() {
        for (address, needs_opt_in) in [
            // Cleartext, and it leaves the machine.
            ("grpc://storage:50051", true),
            ("grpc://storage.svc:50051", true),
            ("grpc://10.0.0.5:50051", true),
            ("grpc://100.64.0.1:50051", true),
            ("grpc://svc.internal:50051", true),
            // Cleartext, and it does not.
            ("grpc://localhost:50051", false),
            ("grpc://localhost.:50051", false),
            ("grpc://127.0.0.1:50051", false),
            ("grpc://127.9.9.9:50051", false),
            ("grpc://[::1]:50051", false),
            ("grpc://[::ffff:127.0.0.1]:50051", false),
            // Encrypted, so the question does not arise however remote it is.
            ("grpcs://storage.example.com:50051", false),
            ("grpcs://storage:50051", false),
            // A discovery connection's channel scheme is not known here.
            ("https://storage.example.com", false),
            ("http://localhost:8080", false),
        ] {
            let location = service_location(&cfg(address))
                .unwrap_or_else(|e| panic!("{address} is a valid address: {e}"));
            assert_eq!(
                location.is_plaintext_beyond_loopback(),
                needs_opt_in,
                "opt-in needed, for {address}",
            );
        }
    }

    /// Only a literal `true` grants the permission.
    ///
    /// Nothing in this host validates a supplied config against the kind's
    /// schema, so a value of the wrong type arrives here rather than being
    /// refused above. Reading `"true"` as permission would let a config typo
    /// disclose a credential silently, which is the one direction that cannot
    /// be undone.
    #[test]
    fn the_cleartext_credential_permission_is_granted_only_by_a_literal_true() {
        fn with(value: Option<ConfigValue>) -> HashMap<String, ConfigValue> {
            let mut map = cfg("grpc://storage:50051");
            if let Some(value) = value {
                map.insert(ALLOW_PLAINTEXT_CREDENTIALS_KEY.into(), value);
            }
            map
        }
        assert!(allow_plaintext_credentials(&with(Some(ConfigValue::Bool(
            true
        )))));
        for (what, value) in [
            ("absent", None),
            ("false", Some(ConfigValue::Bool(false))),
            (
                "the string 'true'",
                Some(ConfigValue::String("true".into())),
            ),
            ("the integer 1", Some(ConfigValue::Int(1))),
        ] {
            assert!(
                !allow_plaintext_credentials(&with(value)),
                "no permission, for {what}",
            );
        }
    }

    #[test]
    fn infers_https_for_remote_host() {
        let url = address_value(&cfg("storage.example.com")).unwrap();
        assert_eq!(url, "https://storage.example.com");
    }

    #[test]
    fn infers_http_for_localhost() {
        let url = address_value(&cfg("localhost:8080")).unwrap();
        assert_eq!(url, "http://localhost:8080");
    }

    #[test]
    fn preserves_explicit_scheme() {
        let url = address_value(&cfg("https://storage.example.com:443/")).unwrap();
        assert_eq!(url, "https://storage.example.com:443");
    }

    #[test]
    fn rejects_empty() {
        let err = address_value(&cfg("   ")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// The good-input coverage for a change that adds a new interpretation.
    /// Every spelling an operator can configure today must still resolve to a
    /// discovery root — that is the blast radius, and red-green on the new
    /// spelling would never have prompted for it.
    #[test]
    fn every_spelling_that_means_discovery_today_still_does() {
        for (raw, expected) in [
            ("storage.example.com", "https://storage.example.com"),
            ("localhost:8080", "http://localhost:8080"),
            (
                "https://storage.example.com:443/",
                "https://storage.example.com:443",
            ),
            ("http://10.0.0.1:8080", "http://10.0.0.1:8080"),
            ("8.8.8.8:8080", "http://8.8.8.8:8080"),
            // Hosts literally NAMED `grpc` / `grpcs`, which are ordinary
            // in-cluster service names, with `:8080` as the PORT. These resolve
            // to a discovery root today and must keep doing so.
            //
            // What protects them is that `split_direct_scheme` requires the
            // literal `://`. A scheme PARSE would read `grpc` here and route a
            // working deployment into direct mode; matching the separator does
            // not, because `grpc:8080` has none. That is the whole reason the
            // mode decision is a prefix match rather than a `Url::parse`,
            // stated on `split_direct_scheme` itself.
            ("grpc:8080", "https://grpc:8080"),
            ("grpcs:8080", "https://grpcs:8080"),
        ] {
            assert_eq!(
                service_location(&cfg(raw)),
                Ok(ServiceLocation::Discovery(expected.to_string())),
                "{raw} must still name a discovery root",
            );
        }
    }

    /// `grpc://` and `grpcs://` are the direct-endpoint spellings, matched
    /// case-insensitively. The dial URI is what tonic gets; the locator keeps
    /// the operator's scheme so a direct endpoint can never derive the same
    /// durable key as a discovery URL naming the same authority.
    #[test]
    fn grpc_schemes_name_a_direct_endpoint() {
        for (raw, dial, locator) in [
            (
                "grpc://localhost:1",
                "http://localhost:1",
                "grpc://localhost:1",
            ),
            ("grpcs://host:1", "https://host:1", "grpcs://host:1"),
            (
                "GRPC://127.0.0.1:1",
                "http://127.0.0.1:1",
                "grpc://127.0.0.1:1",
            ),
            ("grpcs://[::1]:1", "https://[::1]:1", "grpcs://[::1]:1"),
            (
                "grpc://localhost:50051/",
                "http://localhost:50051",
                "grpc://localhost:50051",
            ),
        ] {
            assert_eq!(
                service_location(&cfg(raw)),
                Ok(ServiceLocation::DirectGrpc {
                    dial_uri: dial.to_string(),
                    locator: locator.to_string(),
                }),
                "{raw} must name a direct gRPC endpoint",
            );
        }
    }

    /// A direct locator and a discovery URL for the same authority must not
    /// collapse onto one string. That string is the connection's durable
    /// identity, so equality here would mean two unrelated connections sharing
    /// a keyring key.
    #[test]
    fn direct_locator_never_equals_a_discovery_locator() {
        let direct = service_location(&cfg("grpc://localhost:1")).unwrap();
        let discovery = service_location(&cfg("http://localhost:1")).unwrap();
        assert_eq!(direct.discovery_url(), None);
        assert_eq!(discovery.discovery_url(), Some("http://localhost:1"));
        assert_ne!(
            direct.locator(),
            discovery.locator(),
            "a direct endpoint and a discovery URL on one authority must derive different keys",
        );
    }

    /// One normalizer, not two: a direct endpoint's dial URI is exactly what
    /// the discovery path would produce for the same string arriving in a
    /// `/api/v1/services` response. A future copy-pasted normalizer reddens.
    #[test]
    fn direct_dial_uri_matches_the_discovery_normalizer() {
        // Every row here is a normalization FIXED POINT, deliberately, and the
        // divergence rows below are why. Once the direct path started rebuilding
        // its value through `url`, the two paths stopped agreeing in general —
        // so the shared property this pins is narrower than "same output": it is
        // that the SCHEME-to-transport mapping is the same one, applied by the
        // same function.
        for raw in ["grpc://localhost:1", "grpcs://host:1", "GRPC://127.0.0.1:1"] {
            let endpoints = vec![crate::discovery::ServiceEndpoint {
                kind: "storage".into(),
                name: "storage".into(),
                id: "storage-01".into(),
                grpc: Some(raw.to_string()),
                rest: None,
            }];
            let (published, plaintext) =
                crate::discovery::find_grpc_endpoint_for_kind(&endpoints, "storage").unwrap();
            let ServiceLocation::DirectGrpc { dial_uri, .. } = service_location(&cfg(raw)).unwrap()
            else {
                panic!("{raw} must parse as a direct endpoint");
            };
            assert_eq!(dial_uri, published, "one normalizer for {raw}");
            assert_eq!(plaintext, dial_uri.starts_with("http://"));
        }

        // And the divergence, pinned so nobody "fixes" it by unifying the two
        // paths. Operator config is CANONICALIZED — `url` collapses an IPv6
        // spelling and strips a tab — while a discovery-published value is the
        // server describing itself and is passed through. Asserting equality
        // across these would be asserting that config is not canonicalized.
        for (raw, published, direct) in [
            (
                "grpc://[0:0:0:0:0:0:0:1]:1",
                "http://[0:0:0:0:0:0:0:1]:1",
                "http://[::1]:1",
            ),
            (
                "grpc://[::ffff:127.0.0.1]:1",
                "http://[::ffff:127.0.0.1]:1",
                "http://[::ffff:7f00:1]:1",
            ),
        ] {
            let endpoints = vec![crate::discovery::ServiceEndpoint {
                kind: "storage".into(),
                name: "storage".into(),
                id: "storage-01".into(),
                grpc: Some(raw.to_string()),
                rest: None,
            }];
            let (from_discovery, _) =
                crate::discovery::find_grpc_endpoint_for_kind(&endpoints, "storage").unwrap();
            assert_eq!(from_discovery, published, "discovery passes {raw} through");
            let ServiceLocation::DirectGrpc { dial_uri, .. } = service_location(&cfg(raw)).unwrap()
            else {
                panic!("{raw} must parse as a direct endpoint");
            };
            assert_eq!(dial_uri, direct, "config canonicalizes {raw}");
            assert_ne!(
                dial_uri, from_discovery,
                "{raw} is a deliberate divergence; if these now agree, this test is stale",
            );
        }
    }

    /// A direct spelling with no host is refused, rather than silently becoming
    /// a discovery root. The discovery parse strips trailing slashes, so a bare
    /// `grpc://` would otherwise arrive as `grpc:` and be read as an authority
    /// whose host is named `grpc` — landing an obvious typo in the wrong mode
    /// with no diagnostic at all.
    #[test]
    fn a_direct_spelling_with_no_host_is_refused() {
        for raw in [
            "grpc://",
            "grpcs://",
            "  grpc://  ",
            "GRPC://",
            "grpc:////",
            "grpc://?x",
            "grpc://#x",
            // A host of only dots has no label. `grpcs://.` was accepted with
            // host `.` and failed opaquely at connect; `grpc://.` was told to
            // "use grpcs://", which led straight to the accepted spelling.
            "grpc://.",
            "grpcs://.",
            "grpcs://..",
            // Non-empty authority, no host. Previously this reached
            // `Url::parse` and came back "empty host", which does not tell the
            // operator which of the two keys is wrong.
            "grpc://:50051",
            "grpcs://:50051",
            // A path is not a host: trimming slashes out of the remainder used
            // to let `path` stand in for one.
            "grpc:///",
            "grpcs:///",
            "grpc:///path",
            "grpcs:///path",
            "grpcs://///a/b",
        ] {
            let err = service_location(&cfg(raw))
                .expect_err("a direct endpoint with no host must be refused");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "for {raw:?}");
            assert!(
                err.message().contains("no host"),
                "the refusal must say what is missing, got: {}",
                err.message(),
            );
        }
    }

    /// A non-ASCII host is refused at CONFIG time, naming punycode.
    ///
    /// It used to be accepted and copied verbatim into the dial URI, then fail
    /// as an opaque `InvalidUri` when tonic built the channel, because an
    /// `http::Uri` authority must be ASCII. `url` does not help here: for a
    /// non-special scheme like `grpc` it percent-encodes the host rather than
    /// punycoding it.
    ///
    /// The `grpc://` rows are the load-bearing ones and the reason this test
    /// exists at all: matching the 8-byte `grpcs://` prefix against a 7-byte
    /// scheme is what put a byte index inside the first host character and
    /// aborted the process. A `grpcs://` row cannot reach that offset, so a
    /// test built only from those would go green against the broken code.
    #[test]
    fn a_non_ascii_host_is_refused_at_config_time_not_at_connect() {
        for raw in [
            "grpc://日本:50051",
            "grpc://пример",
            "grpcs://日本:50051",
            "grpcs://ölager.example:50051",
            "grpc://例え.example.com:50051",
        ] {
            let err = service_location(&cfg(raw))
                .expect_err("a non-ASCII host is refused before it can fail at connect");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "for {raw}");
            assert!(
                err.message().contains("punycode"),
                "the refusal must name the fix, got: {}",
                err.message(),
            );
        }
        // The punycode form, which is what an operator should type, works.
        assert!(service_location(&cfg("grpcs://xn--wgv71a.example:50051")).is_ok());
        // The discovery-published path still carries the raw form: that side is
        // the server's own output, not operator config, and is out of scope.
        assert_eq!(
            crate::discovery::normalize_grpc_uri("grpc://日本:1"),
            "http://日本:1",
        );
    }

    /// Userinfo is refused on a direct endpoint: it means nothing to an
    /// anonymous connection, and the value becomes the durable `BackendId`, the
    /// default display name and a log field.
    #[test]
    fn a_direct_endpoint_may_not_carry_userinfo() {
        for raw in ["grpc://user:pw@localhost:1", "grpcs://user@host:1"] {
            let err = service_location(&cfg(raw))
                .expect_err("userinfo on a direct endpoint must be refused");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "for {raw}");
            assert!(err.message().contains("userinfo"), "got: {}", err.message());
        }
        // A path is refused outright now, so an `@` inside one is moot: the
        // value is rejected for carrying a path, not for the `@`.
        let err = service_location(&cfg("grpc://localhost:1/a@b"))
            .expect_err("a direct endpoint carries no path");
        assert!(err.message().contains("path"), "got: {}", err.message());
        // Bracketed IPv6 authorities are unaffected.
        assert!(service_location(&cfg("grpc://[::1]:50051")).is_ok());

        // The refusal is confined to the direct arm. A discovery URL carrying
        // userinfo is accepted today, and refusing it here would be a
        // regression for deployments that rely on it.
        for raw in ["https://user:pw@host/a", "http://user@host:8080"] {
            assert!(
                service_location(&cfg(raw)).is_ok(),
                "{raw} is a discovery URL and must keep working",
            );
        }
    }

    /// Plaintext to a host that is not demonstrably local is REFUSED, not
    /// silently downgraded. `grpc://` means plaintext by convention, but our
    /// own broker client reads the same `grpc://remote-host` as TLS — one
    /// string, opposite encryption, in two plugins of this repo. Refusing a
    /// config the operator can edit is recoverable; shipping object bytes in
    /// the clear to a public host is not.
    #[test]
    fn plaintext_to_a_non_local_host_is_refused() {
        for raw in [
            "grpc://storage.example.com:50051",
            "grpc://8.8.8.8:50051",
            "GRPC://storage.example.com",
            // Just outside shared address space on either side.
            "grpc://100.63.255.255:50051",
            "grpc://100.128.0.1:50051",
            // Malformed names: an empty label is not a hostname, and must not
            // reach the shared classifier's unstructured `.local` test.
            "grpc://.local:50051",
            "grpc://..local:50051",
            "grpc://a..local:50051",
        ] {
            let err = service_location(&cfg(raw))
                .expect_err("plaintext to a public host must be refused");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "for {raw}");
            assert!(
                err.message().contains("grpcs://"),
                "the refusal must name the spelling that works, got: {}",
                err.message(),
            );
        }
        // Local hosts keep plaintext: the common CI shape, and the example the
        // documentation gives. The single-label and `.internal` rows are the
        // load-bearing ones — a container or in-cluster service name is the
        // likeliest spelling for the deployment this mode exists to serve, and
        // refusing it would block that deployment outright.
        for raw in [
            "grpc://localhost:50051",
            "grpc://127.0.0.1:50051",
            "grpc://[::1]:50051",
            "grpc://192.168.1.5:50051",
            "grpc://dev.local:50051",
            "grpc://storage:50051",
            "grpc://ovstorage-svc:50051",
            "grpc://storage.default.svc.cluster.local:50051",
            "grpc://storage.internal:50051",
            "grpc://[fd00::1]:50051",
            "grpc://storage.default.svc:50051",
            "grpc://100.64.0.1:50051",
            "grpc://[::ffff:127.0.0.1]:50051",
            "grpc://localhost.:50051",
            "grpc://broker.local.:50051",
            // Shared-address-space boundary: an off-by-one in the octet range
            // would otherwise redden nothing.
            "grpc://100.127.255.255:50051",
            // A mapped address is judged as the IPv4 address it is, so this
            // qualifies for the same reason bare `100.64.0.1` does. Pinned
            // because the comment describing it was wrong for a round.
            "grpc://[::ffff:100.64.0.1]:50051",
            "grpc://10.1.2.3:50051",
            "grpc://172.16.0.1:50051",
            "grpc://[fe80::1]:50051",
            // The unspecified and limited-broadcast addresses. These qualify
            // through `is_unspecified` / `is_broadcast` in the shared
            // classifier, and none of them can carry a TCP connection off this
            // host: `0.0.0.0` and `::` resolve to the local host when dialled,
            // and `255.255.255.255` is not a connectable unicast destination.
            // Pinned because they were reachable through the accept path with
            // nothing asserting them — a tightening that refused them, or a
            // widening that let a routable address in beside them, would
            // otherwise redden nothing.
            "grpc://0.0.0.0:50051",
            "grpc://[::]:50051",
            "grpc://255.255.255.255:50051",
        ] {
            let location = service_location(&cfg(raw))
                .unwrap_or_else(|e| panic!("{raw} is local and must keep plaintext: {e:?}"));
            // Assert the DIAL SCHEME, not merely that it parsed: a mutation
            // that quietly upgraded local hosts to TLS would satisfy `is_ok`
            // while changing what is actually dialled.
            let ServiceLocation::DirectGrpc { dial_uri, .. } = &location else {
                panic!("{raw} must be a direct endpoint");
            };
            assert!(
                dial_uri.starts_with("http://"),
                "{raw} must still dial plaintext, got {dial_uri}",
            );
        }
        // TLS to a public host is exactly what this asks for.
        assert!(service_location(&cfg("grpcs://storage.example.com:50051")).is_ok());
    }

    /// The private-suffix rules are SUFFIX tests, and this is why. Matching
    /// `.svc.` anywhere in the name accepts `evil.svc.example.com` — an
    /// ordinary registrable public hostname — and hands it cleartext, which is
    /// precisely what the refusal exists to prevent. An earlier revision of
    /// this function did exactly that.
    #[test]
    fn a_private_suffix_is_not_matched_as_an_infix() {
        for raw in [
            "grpc://evil.svc.example.com:50051",
            "grpc://attacker.svc.evil.net:50051",
            "grpc://host.internal.example.com:50051",
            // A private label as the FIRST label is equally not a suffix.
            "grpc://svc.example.com:50051",
            "grpc://internal.example.com:50051",
            // An empty label is not a name at all, and must not be read as a
            // single label by a split that yields `["", "example", "com"]`.
            "grpc://.example.com:50051",
            "grpc://evil..com:50051",
        ] {
            let err = service_location(&cfg(raw))
                .expect_err("a public host containing a private label is still public");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "for {raw}");
            // The message too, not only the code: otherwise this keeps passing
            // if a future change refuses these inputs for an unrelated reason.
            assert!(
                err.message().contains("grpcs://"),
                "must be refused BY THE PLAINTEXT GATE, got: {}",
                err.message(),
            );
        }
        // The forms the suffix rule is actually for still work, including the
        // Kubernetes long form, which qualifies via `.local` and not via `.svc`.
        for raw in [
            "grpc://storage.default.svc:50051",
            "grpc://db.internal:50051",
            "grpc://svc.ns.svc.cluster.local:50051",
        ] {
            assert!(service_location(&cfg(raw)).is_ok(), "{raw} is in-cluster");
        }
    }

    /// A percent-encoded host is refused, and one endpoint has one spelling.
    ///
    /// `url` percent-encodes rather than rejects, so `%38%2e%38%2e%38%2e%38`
    /// survived as a single opaque label, satisfied the single-label plaintext
    /// rule, and decodes to 8.8.8.8. It failed later inside tonic, but a gate
    /// that relies on a downstream parser to catch what it admitted is not a
    /// gate.
    #[test]
    fn a_percent_encoded_host_is_refused_and_case_is_canonical() {
        for raw in [
            "grpc://%38%2e%38%2e%38%2e%38:50051",
            "grpc://stor%61ge:50051",
        ] {
            let err =
                service_location(&cfg(raw)).expect_err("a percent-encoded host is not a host");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "for {raw}");
            assert!(
                err.message().contains("percent-encoded"),
                "got: {}",
                err.message(),
            );
        }
        // One endpoint, one canonical spelling: otherwise the same service
        // derives two `BackendId`s and two display names.
        for raw in ["grpc://LOCALHOST:1", "grpc://LocalHost:1"] {
            let location = service_location(&cfg(raw)).expect("a local host dials plaintext");
            assert_eq!(location.locator(), "grpc://localhost:1", "for {raw}");
        }
        assert_eq!(
            service_location(&cfg("grpcs://[FD00::1]:443"))
                .unwrap()
                .locator(),
            "grpcs://[fd00::1]:443",
        );
    }

    /// A refusal must name the thing that is actually wrong.
    ///
    /// The ASCII check used to run on the WHOLE typed value before parsing, so
    /// a non-ASCII character anywhere — in a path, a query, or userinfo —
    /// reported "host must be ASCII … punycode". Four misdiagnoses, each
    /// sending an operator to fix a host that was fine.
    #[test]
    fn a_refusal_names_the_part_that_is_wrong() {
        for (raw, expected) in [
            ("grpcs://storage:50051/päth", "path, query or fragment"),
            ("grpcs://storage:1?q=ü", "path, query or fragment"),
            ("grpcs://storage:1#ü", "path, query or fragment"),
            ("grpcs://ü@storage:50051", "userinfo"),
            // A non-ASCII HOST does get the punycode message, which is the one
            // case where that advice is right.
            ("grpcs://日本:50051", "punycode"),
            // ...and a literal percent-escape is told to write the host plainly
            // instead, since nothing about it is internationalized.
            ("grpcs://evil%2ecom:50051", "percent-encoded"),
        ] {
            let err = service_location(&cfg(raw)).expect_err("all of these are refused");
            assert!(
                err.message().contains(expected),
                "{raw} should be refused for {expected:?}, got: {}",
                err.message(),
            );
        }
    }

    /// A single label that the RESOLVER reads as an address is an address.
    ///
    /// `getaddrinfo` accepts integer and hex spellings that Rust's `IpAddr`
    /// parser refuses, so they bypass the address branch and arrive at the
    /// single-label rule looking like a service name. Measured on a stock
    /// glibc host: `getent hosts 134744072` answers `8.8.8.8`. Without this
    /// the gate hands a public address a cleartext connection through the
    /// branch that exists for `storage`.
    #[test]
    fn a_single_label_that_resolves_as_an_address_is_refused() {
        for raw in [
            "grpc://134744072:50051",  // 8.8.8.8
            "grpc://2130706433:50051", // 127.0.0.1, refused for being an integer, not for being public
            "grpc://0x8080808:50051",
            "grpc://0X8080808:50051",
        ] {
            let err = service_location(&cfg(raw))
                .expect_err("an integer address spelling is an address, not a service name");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "for {raw}");
        }
        // Ordinary names containing digits, and a `0x` prefix that is not a hex
        // number, are service names and are unaffected.
        for raw in [
            "grpc://storage2:50051",
            "grpc://node-01:50051",
            "grpc://0xstorage:50051",
        ] {
            assert!(
                service_location(&cfg(raw)).is_ok(),
                "{raw} is a service name"
            );
        }
    }

    /// A root-relative FQDN is not a local name, however few dots it has.
    ///
    /// `ai.`, `to.` and `dk.` are apex names of delegated country-code TLDs
    /// that have carried address records. Stripping the trailing dot before the
    /// single-label test made them dotless and therefore accepted — while a
    /// trailing dot is exactly the syntax that DISABLES the search-domain
    /// expansion that rule's reasoning depends on.
    ///
    /// Worth being honest about what this does and does not buy: a resolver
    /// that misses on the search list falls back to querying the bare name at
    /// the root, so `ai` and `ai.` can reach the same record. Refusing `ai.`
    /// therefore does not make `ai` safe — accepting bare single labels is a
    /// stated judgement, documented on `plaintext_is_safe`, and this test does
    /// not claim otherwise. What it pins is that the unambiguously
    /// root-relative spelling is not silently reclassified as a local name.
    #[test]
    fn a_root_relative_fqdn_never_qualifies_as_dotless() {
        for raw in ["grpc://ai.:50051", "grpc://to.:50051", "grpc://com.:50051"] {
            let err = service_location(&cfg(raw))
                .expect_err("a root-relative apex name is public, not local");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "for {raw}");
            assert!(
                err.message().contains("grpcs://"),
                "must be refused BY THE PLAINTEXT GATE, got: {}",
                err.message(),
            );
        }
        // A trailing dot still does not BREAK the names it should not: these
        // qualify through the shared classifier, not through the dotless rule.
        for raw in ["grpc://localhost.:50051", "grpc://broker.local.:50051"] {
            assert!(
                service_location(&cfg(raw)).is_ok(),
                "{raw} is local however it is spelled",
            );
        }
    }

    /// A path is not a host. Trimming slashes out of the whole remainder let
    /// `grpcs:///path` look named, so it was accepted and then failed as the
    /// opaque connect error this guard exists to replace.
    #[test]
    fn a_path_does_not_stand_in_for_a_host() {
        // Hostless spellings are covered by `a_direct_spelling_with_no_host_is_refused`,
        // which names the missing host. Here the host is present and the value
        // still carries something a direct endpoint must not: the message names
        // what to remove. Both matter — the old code told an operator who typed
        // `grpc://:50051` to "use grpcs://", and following that advice landed
        // them on a silently-accepted hostless value.
        for raw in [
            "grpc://localhost:1/path",
            "grpcs://storage:50051?token=SECRET",
            "grpcs://storage:1#frag",
        ] {
            let err = service_location(&cfg(raw))
                .expect_err("a direct endpoint must be an address and nothing else");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "for {raw}");
            assert!(
                err.message().contains("path, query or fragment"),
                "the refusal must name what to remove, got: {}",
                err.message(),
            );
        }
        // A bare authority, with or without a trailing slash, is fine.
        assert!(service_location(&cfg("grpc://localhost:1")).is_ok());
        assert!(service_location(&cfg("grpc://localhost:1/")).is_ok());
    }

    /// A `grpc*` scheme that is not one of the two supported spellings is
    /// refused by name. The broker client takes `grpc+tls://` and
    /// `grpc+tcp://`; typed here they would otherwise parse as a discovery root
    /// and fail much later as an unsupported-scheme HTTP error naming neither
    /// the scheme nor the fix.
    #[test]
    fn a_sibling_only_grpc_spelling_is_refused_by_name() {
        for raw in ["grpc+tls://host:1", "grpc+tcp://host:1", "grpcx://host:1"] {
            let err = service_location(&cfg(raw))
                .expect_err("an unsupported grpc scheme must be refused");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "for {raw}");
            assert!(err.message().contains("grpcs://"), "got: {}", err.message());
        }
    }

    /// The two normalizers are deliberately NOT unified, and this pins the one
    /// input where they disagree. `should_infer_http` treats any IP literal as
    /// local; `normalize_grpc_uri`'s classifier does not. Routing the discovery
    /// arm through the gRPC normalizer would re-scheme every public-IP-literal
    /// deployment from `http` to `https` AND move its durable key, orphaning
    /// the stored credential. Keep them separate.
    #[test]
    fn the_two_normalizers_disagree_on_a_public_ip_literal_by_design() {
        let discovery = service_location(&cfg("8.8.8.8:8080")).unwrap();
        assert_eq!(discovery.locator(), "http://8.8.8.8:8080");
        assert_eq!(
            crate::discovery::normalize_grpc_uri("8.8.8.8:8080"),
            "https://8.8.8.8:8080",
        );
    }

    /// The pre-0.2.1 key name is refused by name, rather than ignored.
    ///
    /// Nothing validates a supplied config against the schema, so without this
    /// the old key would be read by nobody while the connection reported the
    /// *address* missing — an error naming neither the key that is wrong nor
    /// the one that replaced it.
    ///
    /// Mutation control, run: deleting the `reject_renamed_key` call from
    /// `service_location` reddens this test and its `both keys` sibling, and
    /// nothing else.
    #[test]
    fn the_renamed_key_is_refused_by_name() {
        let mut map = HashMap::new();
        map.insert(
            "discovery_url".into(),
            ConfigValue::String("https://storage.example.com".into()),
        );
        let err = service_location(&map).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            err.message().contains("discovery_url") && err.message().contains("address"),
            "the refusal must name both the removed key and its replacement, got: {}",
            err.message(),
        );
        assert!(
            !err.message().contains("storage.example.com"),
            "a diagnostic must not repeat the address it was given, got: {}",
            err.message(),
        );
    }

    /// A config carrying BOTH keys is a half-finished migration. Preferring one
    /// silently is the same defect the refusal exists to prevent, so it is
    /// refused too.
    #[test]
    fn a_config_carrying_both_keys_is_refused() {
        let mut map = cfg("https://storage.example.com");
        map.insert(
            "discovery_url".into(),
            ConfigValue::String("https://elsewhere.example.com".into()),
        );
        let err = service_location(&map).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            err.message().contains("discovery_url"),
            "got: {}",
            err.message()
        );
    }

    /// The good input for the rename: a value that used to be written under the
    /// old key resolves identically under the new one. The rename changed the
    /// key's spelling and nothing about its meaning, and this is what says so.
    ///
    /// Both arms, because the key carries two kinds of value.
    #[test]
    fn the_new_key_resolves_every_value_the_old_one_did() {
        for (raw, expected) in [
            (
                "storage.example.com",
                ServiceLocation::Discovery("https://storage.example.com".into()),
            ),
            (
                "localhost:8080",
                ServiceLocation::Discovery("http://localhost:8080".into()),
            ),
            (
                "https://storage.example.com:443/",
                ServiceLocation::Discovery("https://storage.example.com:443".into()),
            ),
            (
                "http://10.0.0.1:8080",
                ServiceLocation::Discovery("http://10.0.0.1:8080".into()),
            ),
            (
                "grpc://localhost:50051",
                ServiceLocation::DirectGrpc {
                    dial_uri: "http://localhost:50051".into(),
                    locator: "grpc://localhost:50051".into(),
                },
            ),
            (
                "grpcs://storage.example.com:50051",
                ServiceLocation::DirectGrpc {
                    dial_uri: "https://storage.example.com:50051".into(),
                    locator: "grpcs://storage.example.com:50051".into(),
                },
            ),
        ] {
            let location = service_location(&cfg(raw))
                .unwrap_or_else(|err| panic!("{raw} must still resolve: {}", err.message()));
            // The WHOLE resolved location, not merely that something resolved:
            // a regression that inferred `https` for `localhost:8080` would pass
            // any weaker assertion, and it would silently move the connection's
            // durable identity.
            assert_eq!(location, expected, "for {raw}");
        }
    }

    /// The schema keeps exactly ONE required field. The CLI's `connect` flow
    /// derives `required_count` from this and decides between its interactive
    /// wizard and its non-interactive positional fill on the count alone, so a
    /// change here silently breaks both entry points — including the scriptable
    /// one-liner. The rename must not move it.
    #[test]
    fn the_schema_has_exactly_one_required_field_named_address() {
        let required: Vec<String> = config_schema()
            .into_iter()
            .filter(|field| field.required)
            .map(|field| field.key)
            .collect();
        assert_eq!(required, vec![ADDRESS_KEY.to_string()]);
    }
}
