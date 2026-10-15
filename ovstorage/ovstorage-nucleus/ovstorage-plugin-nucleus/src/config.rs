// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use ovstorage_plugin::{
    ConfigField, ConfigFieldKind, ConfigValue, ConnectionId, ConnectionRequest, CredentialField,
    CredentialMethod, Error, ErrorCode, Result, Url, address,
};

use crate::address::{NUCLEUS_KIND, NUCLEUS_SCHEME, canonical_server_from_root};

#[derive(Clone, Debug)]
pub(crate) struct NucleusConfig {
    pub server: String,
    /// Optional SOWS discovery override.
    #[allow(dead_code)]
    pub endpoint: Option<String>,
    pub prefix: String,
    pub root: Url,
    /// Stable keyring and cross-process-lock identity derived from the full
    /// non-secret connection request (including `display_name`).
    pub stable_id: ConnectionId,
    /// When false, LFT redirects are disabled even if the server advertises an LFT endpoint.
    pub use_lft: bool,
}

impl NucleusConfig {
    pub fn from_request(request: &ConnectionRequest) -> Result<Self> {
        if request.backend_kind != NUCLEUS_KIND {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "connection request backend kind is not nucleus",
            ));
        }
        let server = config_string(&request.config, "server")?;
        validate_server(&server)?;
        // `url::Url` preserves host casing for non-special schemes like `omniverse`, so lowercase explicitly.
        let server = server.to_ascii_lowercase();
        let endpoint = optional_config_string(&request.config, "endpoint")?;
        // The root is built before the prefix is validated, because validating
        // the prefix needs it: a `server` that is not addressable must fail
        // with the root's own diagnostic rather than as an unaddressable
        // `prefix`.
        let root = address::parse(&format!("{NUCLEUS_SCHEME}://{server}/"))?;
        let prefix = optional_config_string(&request.config, "prefix")?
            .map(|value| normalize_prefix(&root, &value))
            .transpose()?
            .unwrap_or_else(|| "/".into());
        let use_lft = optional_config_bool(&request.config, "use_lft")?.unwrap_or(true);
        // Validated but not read: the whole config map feeds the stable id, so
        // the discriminator reaches the key without an explicit field. It is
        // still checked here, because whitespace an operator did not mean is
        // the difference between two connections and one.
        // Read RAW, not through `optional_config_string`: that helper trims,
        // and trimming is precisely what must not happen here. A trimmed value
        // would validate, then reach the stable id in its untrimmed form, so
        // `"alice "` and `"alice"` would key differently while both looked
        // accepted — and correcting the config later would silently move the
        // connection to another credential.
        if let Some(ConfigValue::String(value)) = request.config.get("persistence_id") {
            ovstorage_plugin::oauth_secret_store::validate_persistence_id(value)?;
        }
        Ok(Self {
            server: canonical_server_from_root(&root)?,
            endpoint,
            prefix,
            root,
            stable_id: ovstorage_plugin::connection::identity::conn_id_from_request(request),
            use_lft,
        })
    }
}

fn optional_config_bool(config: &HashMap<String, ConfigValue>, key: &str) -> Result<Option<bool>> {
    match config.get(key) {
        Some(ConfigValue::Bool(value)) => Ok(Some(*value)),
        None => Ok(None),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} must be true or false"),
        )),
    }
}

pub(crate) fn nucleus_config_schema() -> Vec<ConfigField> {
    vec![
        ConfigField {
            key: "server".into(),
            display_name: "Server".into(),
            kind: ConfigFieldKind::Text,
            required: true,
            default: None,
            help: Some("Nucleus host[:port] used for omniverse:// address roots".into()),
            example: Some("localhost".into()),
            group: Some("provider".into()),
            advanced: false,
        },
        ConfigField {
            key: "endpoint".into(),
            display_name: "Discovery endpoint".into(),
            kind: ConfigFieldKind::Url,
            required: false,
            default: None,
            help: Some(
                "Optional SOWS discovery endpoint override (https://host[:port]); object addresses still use omniverse://server/"
                    .into(),
            ),
            example: Some("https://localhost:3019/".into()),
            group: Some("provider".into()),
            advanced: true,
        },
        ConfigField {
            key: "prefix".into(),
            display_name: "Provider path prefix".into(),
            kind: ConfigFieldKind::Text,
            required: false,
            default: Some(ConfigValue::String("/".into())),
            help: Some(
                "Optional Nucleus path prefix that scopes which omni1 paths this backend will \
                 serve. Write the path literally, as it resolves. A spelling that normalizes to \
                 a different path names a scope no request can reach and is refused, with the \
                 path it resolves to in the message."
                    .into(),
            ),
            example: Some("/Projects".into()),
            group: Some("provider".into()),
            advanced: true,
        },
        ConfigField {
            key: "use_lft".into(),
            display_name: "Use LFT".into(),
            kind: ConfigFieldKind::Bool,
            required: false,
            default: Some(ConfigValue::Bool(true)),
            help: Some(
                "Hint for native large-file-transfer uploads above the server-advertised threshold".into(),
            ),
            example: None,
            group: Some("provider".into()),
            advanced: true,
        },
        ConfigField {
            key: "persistence_id".into(),
            display_name: "Credential persistence ID".into(),
            kind: ConfigFieldKind::Text,
            required: false,
            default: None,
            help: Some(
                "Durable account discriminator. Give each connection to the same server its \
                 own value so each keeps a separate stored credential. Choose it once and \
                 keep it: changing it moves the connection to a fresh credential and \
                 requires signing in again."
                    .into(),
            ),
            example: Some("alice-work".into()),
            group: Some("auth".into()),
            advanced: true,
        },
    ]
}

pub(crate) fn nucleus_credential_methods() -> Vec<CredentialMethod> {
    vec![
        CredentialMethod {
            key: "sso".into(),
            display_name: "Single sign-on (browser)".into(),
            fields: Vec::new(),
            help: Some(
                "Recommended. Authenticate by opening a URL in your browser; \
                 no credentials are stored locally."
                    .into(),
            ),
            advanced: false,
        },
        CredentialMethod {
            key: "userpass".into(),
            display_name: "Username and password".into(),
            fields: vec!["username".into(), "password".into()],
            help: Some("OmniAuth username and password.".into()),
            advanced: false,
        },
        CredentialMethod {
            key: "api_token".into(),
            display_name: "API token".into(),
            fields: vec!["api_token".into()],
            help: Some("OmniAuth API token; takes precedence over username/password.".into()),
            advanced: false,
        },
    ]
}

pub(crate) fn nucleus_credential_schema() -> Vec<CredentialField> {
    vec![
        CredentialField {
            key: "username".into(),
            display_name: "Username".into(),
            default: None,
            help: Some("OmniAuth username paired with `password`".into()),
            advanced: false,
        },
        CredentialField {
            key: "password".into(),
            display_name: "Password".into(),
            default: None,
            help: Some("OmniAuth password paired with `username`".into()),
            advanced: false,
        },
        CredentialField {
            key: "api_token".into(),
            display_name: "API token".into(),
            default: None,
            help: Some("OmniAuth API token; takes precedence over username/password".into()),
            advanced: false,
        },
    ]
}

fn config_string(config: &HashMap<String, ConfigValue>, key: &str) -> Result<String> {
    match config.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => Ok(value.trim().into()),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} cannot be empty"),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} is required"),
        )),
    }
}

fn optional_config_string(
    config: &HashMap<String, ConfigValue>,
    key: &str,
) -> Result<Option<String>> {
    match config.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => {
            Ok(Some(value.trim().into()))
        }
        Some(ConfigValue::String(_)) | None => Ok(None),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("{key} must be text"),
        )),
    }
}

fn validate_server(server: &str) -> Result<()> {
    if server.contains("://")
        || server.contains('/')
        || server.contains('?')
        || server.contains('#')
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "server must be host[:port], not a URL",
        ));
    }
    // `server` is interpolated straight into the connection's published root,
    // which is the prefix routing selects on — so it is a scope-selecting
    // configuration address and carries the rule
    // `address::config_prefix_carries_credentials` documents. A `@` makes it
    // one: `server = "reader:token@prod"` publishes
    // `omniverse://reader:token@prod/`, and selection compares scheme, host,
    // port and node path and never the userinfo, so that root would be matched
    // for every credential including none. The credential would not even reach
    // the wire — `parse_nucleus_address` reads `host_str()` and discards it, so
    // the connection dials `prod` regardless.
    //
    // Not echoed: the value is operator-written and the part being refused is
    // the credential.
    if server.contains('@') {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "server must not carry credentials; it is published as this connection's \
             address root and routing reads its scheme, authority and path alone, so \
             the root would be selected under every credential rather than the one \
             written. Put credentials in the connection's credential fields",
        ));
    }
    if server.is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "server is required"));
    }
    Ok(())
}

/// The stored form of a connection `prefix`, refused when it names a scope no
/// request can reach.
///
/// The prefix is held as a bare path string and compared byte for byte against
/// [`parse_nucleus_address`](crate::address::parse_nucleus_address)'s
/// percent-decoded path, which comes from an address `address::parse` has
/// already canonicalized. So a prefix spelling that canonicalization moves
/// matches nothing at all: `prefix = "/team//docs"` is stored verbatim while
/// every request beneath it resolves to `/team/docs/…`, and the connection
/// accepts, routes, and then answers `NoRoute` for its entire scope with no
/// diagnostic.
///
/// Rather than enumerate the spellings that move, the check asks the same
/// pipeline the request path uses: build the address the prefix names, put it
/// through `address::parse`, and require the decoded path to come back
/// unchanged. That cannot fall behind `canonicalize` the way an enumeration
/// would.
///
/// **The prefix is DECODED data, so it is encoded on the way into the URL and
/// decoded again on the way out.** Splicing the operator's string in raw would
/// read it as URL syntax it is not: a folder literally named `a%41b` would
/// resolve to `/aAb`, so a reachable scope would be refused and the message
/// would recommend a different folder — one that is accepted, silently
/// rescoping the connection. The two halves of the round trip must be inverse,
/// and `encode_canonical_path` is the same escape set the emitters use.
///
/// What survives that round trip is every spelling a request can reach: a
/// space, a literal `%`, an escape sequence spelled literally, and — because
/// the escape set covers them — a literal `?` or `#`. This is the same place
/// the `file` backend's plain-path `root` bends the config-address rule, and
/// for the same reason: in a bare path those are ordinary bytes in a folder
/// name, not delimiters, so escaping them keeps a legal folder configurable
/// where refusing them would not. A folder named `my?docs` is reachable
/// (`omniverse://srv/my%3Fdocs/f.usd`), so its prefix loads.
///
/// What does not survive is exactly what `canonicalize` moves — a separator run
/// and a dot segment.
fn normalize_prefix(root: &Url, prefix: &str) -> Result<String> {
    let mut normalized = if prefix.starts_with('/') {
        prefix.to_string()
    } else {
        format!("/{prefix}")
    };
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    let mut spelled = root.clone();
    spelled.set_path(&format!(
        "/{}",
        address::encode_canonical_path(root, normalized.trim_start_matches('/').as_bytes())
    ));
    let spelled = address::parse(spelled.as_str()).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("prefix is not addressable: {}", error.message()),
        )
    })?;
    let resolved = format!("/{}", address::key_utf8(&spelled)?);
    if resolved != normalized {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "prefix '{normalized}' resolves to '{resolved}', so no request could reach it; \
                 configure it as '{resolved}'"
            ),
        ));
    }
    Ok(normalized)
}

#[cfg(test)]
mod prefix_tests {
    use super::*;
    use crate::address::{parse_nucleus_address, path_is_under_prefix};

    /// A `server` carrying credentials is refused at connection creation.
    ///
    /// `server` is interpolated straight into the published root
    /// `omniverse://<server>/`, which IS the prefix routing selects on — so it
    /// is the seventh member of the scope-selecting-prefix class that
    /// `address::config_prefix_carries_credentials` documents, and the one that
    /// does not look like a URL in the config file. `reader:token@prod` would
    /// publish `omniverse://reader:token@prod/`, matched for every credential
    /// including none, while `parse_nucleus_address` reads `host_str()` and
    /// dials plain `prod` — so the credential never even reaches the wire.
    ///
    /// The good input is asserted beside it, including a port, so the refusal
    /// is about the credential and not about the `server` shape.
    ///
    /// Load-bearing line: the `contains('@')` block in `validate_server`.
    #[test]
    fn a_server_carrying_credentials_is_refused() {
        let error = validate_server("reader:hunt,er2@prod")
            .expect_err("a credential-bearing server must be refused");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error.message().contains("must not carry credentials"),
            "the refusal must say what it refused: {}",
            error.message()
        );
        assert!(
            !error.message().contains("hunt,er2"),
            "the password must not survive into the startup error: {}",
            error.message()
        );

        for good in ["prod", "prod:8443", "nucleus.example.com"] {
            validate_server(good).unwrap_or_else(|error| {
                panic!("{good} must load: {}", error.message());
            });
            // And it must still publish a root that selects its own subtree.
            let root = address::parse(&format!("{NUCLEUS_SCHEME}://{good}/")).unwrap();
            assert!(
                ovstorage_plugin::address::is_ancestor_or_self(
                    &root,
                    &address::parse(&format!("{NUCLEUS_SCHEME}://{good}/Projects/f.usd")).unwrap()
                ),
                "{good} must still publish its own subtree"
            );
        }
    }

    /// An accepted `prefix` ROUTES, which is the property the refusal exists to
    /// guarantee and is not the same as loading.
    ///
    /// The two sides are written by different code and meet only here: the
    /// prefix is stored as a decoded path, and a request arrives as an address
    /// `canonicalize` has already normalized, from which
    /// [`parse_nucleus_address`] takes the percent-decoded path. A prefix that
    /// loads but that no decoded request path can be under is a connection that
    /// answers `NoRoute` for its whole scope, which is what this pins shut.
    #[test]
    fn every_accepted_prefix_is_one_a_request_can_be_under() {
        let root = address::parse("omniverse://srv/").unwrap();
        for spelling in [
            "/Projects",
            "/Projects/",
            "Projects",
            "/my docs",
            "/100%",
            "/100%25",
            "/a%41b",
            "/team%2Fsub",
            // A bare path is not a URL, so these are ordinary bytes in a folder
            // name rather than delimiters. `encode_canonical_path` escapes both,
            // so the folder stays configurable and the request that reaches it
            // is `omniverse://srv/my%3Fdocs/f.usd`.
            "/my?docs",
            "/my#docs",
            "/a-b_c.d",
            "/",
        ] {
            let stored = normalize_prefix(&root, spelling)
                .unwrap_or_else(|error| panic!("{spelling} must load: {}", error.message()));

            // The address a caller would write for `<prefix>/file.usd`, built
            // the way an emitter builds one — the prefix is decoded data, so it
            // is escaped rather than spliced.
            let base = stored.strip_prefix('/').unwrap_or(&stored);
            let key = if base.is_empty() {
                "file.usd".to_string()
            } else {
                format!("{base}/file.usd")
            };
            let request = address::join_relative(&root, &key).unwrap_or_else(|error| {
                panic!(
                    "{spelling}: key {key:?} must be addressable: {}",
                    error.message()
                )
            });
            let target = parse_nucleus_address(&request).unwrap();

            assert!(
                path_is_under_prefix(&target.path, &stored),
                "{spelling}: stored as {stored:?}, but a request for {} resolves to {:?}, \
                 which the backend would answer NoRoute",
                request.as_str(),
                target.path
            );
        }
    }

    /// The refusal, at the same seam: a moved prefix is refused, and the
    /// message names the scope it resolves to rather than the one written.
    #[test]
    fn a_prefix_the_pipeline_moves_is_refused_with_its_resolved_scope() {
        let root = address::parse("omniverse://srv/").unwrap();
        for (spelling, resolved) in [
            ("/team//docs", "/team/docs"),
            ("/team/../docs", "/docs"),
            ("/team/./docs", "/team/docs"),
        ] {
            let error = normalize_prefix(&root, spelling)
                .expect_err(&format!("{spelling} must be refused"));
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert!(
                error.message().contains(resolved),
                "{spelling}: message must name {resolved}, got {}",
                error.message()
            );
        }
    }
}
