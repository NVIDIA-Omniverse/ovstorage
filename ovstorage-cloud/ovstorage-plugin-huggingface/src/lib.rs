// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use futures::StreamExt;
use ovstorage_plugin::*;
use parking_lot::RwLock;
use tracing::Instrument;

mod api;
mod driver;
mod layer;
mod parse;

use api::RepoType;

pub use crate::layer::HfLayerFactory;

const DEFAULT_ENDPOINT: &str = "https://huggingface.co";
/// The origins a connection on the default endpoint accepts as spellings of
/// its root: exactly the URLs a user can realistically be holding for the
/// Hub. The canonical origin comes first, then the same host over cleartext
/// `http://`, the `www.` host over either scheme, and the Hub's short domain
/// `hf.co` (its share links and badges) over either scheme — each of the
/// five redirects to the canonical origin, so a pasted URL on any of them
/// names the same repository. Accepting a cleartext spelling never produces
/// a cleartext request: an alias `from` selects inbound addresses only, and
/// every request this plugin sends goes to `config.endpoint`.
const PUBLIC_HUB_ORIGINS: [&str; 6] = [
    DEFAULT_ENDPOINT,
    "http://huggingface.co",
    "https://www.huggingface.co",
    "http://www.huggingface.co",
    "https://hf.co",
    "http://hf.co",
];
/// Site-root path segments a model's web spelling must not begin with,
/// because this plugin already addresses something else under them:
/// `datasets/` and `spaces/` carry the dataset and space spellings, `api/`
/// carries every Hub API request, and `models/` is the listing those
/// requests mirror. The Hub reserves the names, so no model exists under
/// them — but a connection is built from syntactic configuration alone, and
/// a model configured as `datasets/<name>` would derive
/// `https://huggingface.co/datasets/<name>/`, a prefix that names a dataset
/// namespace and would capture URLs meant for other connections. Such a
/// model gets no web spelling; its `hf://` root is unaffected. This is the
/// collision set, not the Hub's route-root set: the Hub has many more
/// site-root routes (`docs`, `blog`, …), and a model there derives a prefix
/// nothing in ovstorage routes, which is harmless. Compared
/// case-insensitively, as the Hub matches namespaces.
const RESERVED_MODEL_NAMESPACES: [&str; 4] = ["api", "datasets", "models", "spaces"];
const HTTP_USER_AGENT: &str = concat!("ovstorage-plugin-huggingface/", env!("CARGO_PKG_VERSION"));
/// Query key that pins an address to one git revision (branch, tag, or
/// commit sha). The whole tree snapshot is named by one pin, so pinned-prefix
/// listings propagate it onto every child address.
const PINNED_VERSION_KEYS: &[&str] = &["revision"];
/// Per-request deadline on JSON API calls. Streamed `resolve` bodies carry no
/// total deadline — it would kill long downloads; cancellation and the host's
/// own deadlines bound those.
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on the redirect chain `read` follows before erroring; a longer chain is
/// a misbehaving origin, not a deeper cache.
const MAX_RESOLVE_HOPS: u32 = 5;
/// Fixed continuation history for detecting a misbehaving Hub pagination
/// cycle without retaining one token per page in an arbitrarily large list.
const LIST_STREAM_LINK_WINDOW: usize = 32;

/// The static backend descriptor; converted to the v2 `LayerKindDescriptor`
/// via `descriptor_to_layer_kind` at the factory/layer surface.
pub(crate) fn kind_descriptor() -> StorageBackendKindDescriptor {
    StorageBackendKindDescriptor {
        kind: "huggingface".into(),
        display_name: "Hugging Face Hub".into(),
        description: Some(
            "Read-only Hugging Face Hub repository access (models, datasets, spaces) with \
             revision-pinned addresses and CDN read redirects"
                .into(),
        ),
        config_schema: vec![
            text_field(
                "repo_id",
                "Repository",
                true,
                Some("google-bert/bert-base-uncased"),
                Some("Hub repository id as 'namespace/name'"),
                false,
            ),
            ConfigField {
                key: "repo_type".into(),
                display_name: "Repository type".into(),
                kind: ConfigFieldKind::Enum {
                    source: EnumSource::Static(vec![
                        "model".into(),
                        "dataset".into(),
                        "space".into(),
                    ]),
                },
                required: false,
                default: Some(ConfigValue::String("model".into())),
                help: Some("Kind of Hub repository served by this connection".into()),
                example: Some("model".into()),
                group: Some("provider".into()),
                advanced: false,
            },
            ConfigField {
                key: "revision".into(),
                display_name: "Revision".into(),
                kind: ConfigFieldKind::Text,
                required: false,
                default: Some(ConfigValue::String("main".into())),
                help: Some(
                    "Default git revision (branch, tag, or commit sha) served by this \
                     connection; callers pin another per address with ?revision="
                        .into(),
                ),
                example: Some("main".into()),
                group: Some("provider".into()),
                advanced: true,
            },
            url_field(
                "endpoint",
                "Endpoint",
                false,
                Some(DEFAULT_ENDPOINT),
                Some(
                    "Endpoint override; non-default values are restricted to loopback test fixtures",
                ),
                true,
            ),
        ],
        credential_schema: vec![CredentialField {
            key: "token".into(),
            display_name: "Access token".into(),
            // HF_TOKEN is the ecosystem-wide variable for exactly this token,
            // so the S3/Azure env-default precedent applies: an explicit
            // descriptor default resolved at TOML load, never a silent
            // ambient pickup inside the plugin.
            default: Some("${HF_TOKEN}".into()),
            help: Some(
                "Hugging Face access token (hf_…); leave empty for anonymous access to \
                 public repositories"
                    .into(),
            ),
            advanced: false,
        }],
        credential_methods: vec![CredentialMethod {
            key: "token".into(),
            display_name: "Access token".into(),
            fields: vec!["token".into()],
            help: Some("A read-scoped token is sufficient.".into()),
            advanced: false,
        }],
        icon: None,
        supports_runtime_add: true,
        // Read-only: there is no write for a metadata stamp to ride on.
        supports_user_metadata: false,
    }
}

/// The advertised capability set — identical for anonymous and tokened
/// connections (a token widens which repositories answer, not which
/// operations exist). Public so the conformance sweep can pin the advertised
/// set against the implemented one.
pub fn hf_capabilities() -> Capabilities {
    let mut caps = Capabilities::empty();
    caps.supports_list = true;
    caps.supports_list_stream = true;
    // The tree API takes `recursive=true` server-side.
    caps.supports_recursive_list = true;
    // The tree API returns real `type: "directory"` entries.
    caps.has_real_directories = true;
    // Directory entries carry no truthful size, and mtime only under
    // `expand=true` — so `populates_subdirectory_metadata` stays false, and
    // paths-info is the real stat (`wants_list_backed_stat` stays false).
    caps.supports_version_listing = true;
    caps.version_list_order = Some(VersionListOrder::Newest);
    caps
}

/// One connection's parsed, validated configuration.
#[derive(Clone, Debug)]
pub struct HfConnectionConfig {
    pub(crate) repo_id: String,
    pub(crate) repo_type: RepoType,
    pub(crate) revision: String,
    /// Endpoint origin with no trailing slash. Non-default values are
    /// restricted to loopback hosts (the hermetic-test seam).
    pub(crate) endpoint: String,
    /// Caller-facing root: `hf://{plural}/{repo_id}/`.
    pub(crate) address_root: Url,
    /// Decoded key of `address_root` (`"{repo_id}/"`), for relative-path
    /// extraction on the data path.
    root_key: String,
}

impl HfConnectionConfig {
    fn from_request(request: &ConnectionRequest) -> Result<Self> {
        let repo_id = required_text(&request.config, "repo_id")?;
        validate_repo_id(&repo_id)?;
        let repo_type = optional_text(&request.config, "repo_type")?
            .map(|text| RepoType::parse(&text))
            .transpose()?
            .unwrap_or(RepoType::Model);
        let revision = optional_text(&request.config, "revision")?
            .map(|text| {
                validate_revision(&text)?;
                Ok::<_, Error>(text)
            })
            .transpose()?
            .unwrap_or_else(|| "main".to_string());
        let endpoint = match optional_url(&request.config, "endpoint")? {
            None => DEFAULT_ENDPOINT.to_string(),
            Some(url) => {
                if url.query().is_some() {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "huggingface connection config 'endpoint' must not carry a query",
                    ));
                }
                // An endpoint is an origin, never a credential channel; the
                // token field is. Credentials written here would be sent on
                // every request URL, and on a loopback endpoint they would
                // also be copied into the accepted-URL spelling the connection
                // row publishes, where `list_connections` returns them to any
                // caller.
                if !url.username().is_empty() || url.password().is_some() {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "huggingface connection config 'endpoint' must not carry credentials; \
                         supply the access token through the 'token' credential",
                    ));
                }
                let text = url.as_str().trim_end_matches('/').to_string();
                // Unlike the GCS loopback escape hatch, credentialed loopback
                // fixtures are allowed: the conformance and lifecycle suites
                // drive tokened flows against a scripted local server, and
                // sending a credential to a loopback host is the same
                // carve-out the HTTP plugin's transport validation blesses.
                if text == DEFAULT_ENDPOINT
                    || (matches!(url.scheme(), "http" | "https") && url_host_is_loopback(&url))
                {
                    text
                } else {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "huggingface connection config 'endpoint' is only supported for \
                         loopback test endpoints",
                    ));
                }
            }
        };
        let address_root = address::parse(&format!("hf://{}/{repo_id}/", repo_type.plural()))?;
        let root_key = address::key_utf8(&address_root)?;
        Ok(Self {
            repo_id,
            repo_type,
            revision,
            endpoint,
            address_root,
            root_key,
        })
    }

    /// The alternate URL prefixes this connection accepts as spellings of its
    /// `hf://{plural}/{repo_id}/` root — the value the layer stamps under
    /// [`ACCEPTED_URL_SPELLINGS_METADATA_KEY`] so an alias wrapper above can
    /// auto-generate hidden alias rules. Built from the same two components
    /// `api::resolve_url` uses when constructing request URLs — the endpoint
    /// origin and [`RepoType::resolve_prefix`] (a model sits at the site
    /// root, a dataset under `datasets/`, a space under `spaces/`) — so a
    /// spelling cannot drift from the wire path.
    ///
    /// - **Default endpoint**: the repository path on each of
    ///   [`PUBLIC_HUB_ORIGINS`].
    /// - **Any other endpoint** (loopback by construction, path included):
    ///   exactly the one shape the configuration describes, with no public
    ///   twin — the endpoint IS the origin. A loopback path is not a
    ///   capability token, which is the same carve-out the Azure plugin
    ///   makes for path-style Azurite.
    ///
    /// Deliberately excluded, as different resources rather than other
    /// spellings: `/api/…`, the search and namespace pages, and the Hub's
    /// web-view and download forms (`…/{blob,resolve,tree}/<rev>/<path>`),
    /// which carry a revision as a path segment that a prefix rewrite cannot
    /// move into the `?revision=` pin. A model whose namespace is one of
    /// [`RESERVED_MODEL_NAMESPACES`] gets no spelling at all: its web URL
    /// would begin with a segment this plugin already addresses something
    /// else under.
    pub(crate) fn alternate_url_prefixes(&self) -> Vec<Url> {
        if self.repo_type == RepoType::Model
            && let Some(namespace) = self.repo_id.split('/').next()
            && RESERVED_MODEL_NAMESPACES
                .iter()
                .any(|reserved| reserved.eq_ignore_ascii_case(namespace))
        {
            return Vec::new();
        }
        let tail = format!("{}{}/", self.repo_type.resolve_prefix(), self.repo_id);
        let own = [self.endpoint.as_str()];
        let origins: &[&str] = if self.endpoint == DEFAULT_ENDPOINT {
            &PUBLIC_HUB_ORIGINS
        } else {
            &own
        };
        // `address::parse` so the prefixes normalize exactly as the alias
        // layer parses its rule config; these shapes cannot fail it, but one
        // that somehow does is dropped rather than poisoning its neighbours.
        origins
            .iter()
            .filter_map(|origin| address::parse(&format!("{origin}/{tail}")).ok())
            .collect()
    }

    /// Resolve a routed caller address into a repo-relative entry reference.
    fn parse_hf_address(&self, addr: &Url) -> Result<HfEntryRef> {
        if addr.scheme() != "hf" {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "huggingface backend requires hf:// addresses",
            ));
        }
        if addr.host_str() != Some(self.repo_type.plural()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "huggingface address host must be '{}' for this connection",
                    self.repo_type.plural()
                ),
            ));
        }
        if addr.port().is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "huggingface address must not carry a port",
            ));
        }
        // The only address modifier this backend honors is the revision pin;
        // an unknown query key would otherwise be silently dropped on the
        // wire, serving different bytes than the address names. An EMPTY pin
        // value is refused too — `extract_pinned_value` skips it, so it would
        // otherwise silently degrade to the connection default.
        for (key, value) in addr.query_pairs() {
            if !PINNED_VERSION_KEYS
                .iter()
                .any(|pin| pin.eq_ignore_ascii_case(&key))
            {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("huggingface address carries an unsupported modifier '?{key}='"),
                ));
            }
            if value.trim().is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("huggingface address modifier '?{key}=' carries no revision"),
                ));
            }
        }
        let revision_pin = extract_pinned_value(addr, PINNED_VERSION_KEYS);
        if let Some(pin) = revision_pin.as_deref() {
            validate_revision(pin)?;
        }
        let key = address::key_utf8(addr)?;
        let path = if key == self.root_key || format!("{key}/") == self.root_key {
            String::new()
        } else if let Some(rest) = key.strip_prefix(&self.root_key) {
            rest.to_string()
        } else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "huggingface address is outside this connection's repository",
            ));
        };
        for segment in path.split('/') {
            if matches!(segment, "." | "..") {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "huggingface address must not carry '.' or '..' segments",
                ));
            }
        }
        Ok(HfEntryRef { path, revision_pin })
    }
}

/// A routed address, split into the repo-relative path (decoded; may carry a
/// trailing slash as a directory hint; empty = repo root) and the optional
/// caller revision pin.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HfEntryRef {
    path: String,
    revision_pin: Option<String>,
}

impl HfEntryRef {
    fn effective_revision<'a>(&'a self, config: &'a HfConnectionConfig) -> &'a str {
        self.revision_pin.as_deref().unwrap_or(&config.revision)
    }
}

fn validate_repo_id(repo_id: &str) -> Result<()> {
    let invalid = |detail: &str| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("huggingface repo_id must be 'namespace/name' ({detail})"),
        )
    };
    let mut parts = repo_id.split('/');
    let (Some(namespace), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(invalid("exactly one '/' separator"));
    };
    for segment in [namespace, name] {
        if segment.is_empty() || segment.len() > 96 {
            return Err(invalid("each segment must be 1-96 characters"));
        }
        if !segment
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
        {
            return Err(invalid("each segment must start with a letter or digit"));
        }
        if !segment
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        {
            return Err(invalid(
                "segments may contain only letters, digits, '.', '_', and '-'",
            ));
        }
        if segment.contains("..") {
            return Err(invalid("segments must not contain '..'"));
        }
    }
    Ok(())
}

fn validate_revision(revision: &str) -> Result<()> {
    if revision.trim().is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "huggingface revision must not be empty",
        ));
    }
    // Reject anything a git ref cannot contain (git-check-ref-format's core
    // set) plus all whitespace, so an unusable revision fails at connect/add
    // time with `InvalidArgument` rather than surfacing later as a Hub 404.
    if revision.contains("..")
        || revision.chars().any(|ch| {
            ch.is_whitespace()
                || ch.is_control()
                || matches!(ch, '?' | '#' | '\\' | '~' | '^' | ':' | '*' | '[')
        })
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "huggingface revision must be a git ref: no whitespace, control characters, \
             '..', or any of '?#\\~^:*['",
        ));
    }
    Ok(())
}

/// Read-only Hub backend serving one repository. All I/O funnels through the
/// helpers here so status mapping and redaction cannot be bypassed.
#[derive(Clone)]
pub struct HfBackend {
    config: HfConnectionConfig,
    http: reqwest::Client,
    /// Live bearer shared with the connection's [`driver::HfDriver`]:
    /// `activate` writes it, every request re-reads it.
    live_token: Arc<RwLock<Option<SecretBytes>>>,
}

/// Immutable address and option state shared by every page of one tree walk.
struct HfListWalkSpec {
    first_url: String,
    recursive: bool,
    /// Ask the Hub for per-entry commit facts (`expand=true`); both
    /// `full_metadata` and `versioned_address` are served by them.
    expand: bool,
    containment_prefix: Url,
    revision_pin: Option<String>,
}

/// Pull-owned state for the Hub's `Link: rel="next"` tree walk.
///
/// The state retains only the current decoded provider page and a fixed-size
/// continuation history. The next HTTP request is made only when the caller
/// polls after the current page has been consumed.
struct HfListStreamState {
    backend: HfBackend,
    spec: HfListWalkSpec,
    current_items: std::vec::IntoIter<ObjectInfo>,
    next_url: Option<Url>,
    started: bool,
    recent_links: VecDeque<String>,
    pending_error: Option<Error>,
    cancel: Option<CancellationToken>,
}

impl HfListStreamState {
    fn repeated_link_error() -> Error {
        Error::new(
            ErrorCode::Transient,
            "huggingface list could not advance because the service repeated a pagination link",
        )
    }

    async fn next_item(mut self) -> Result<Option<(ObjectInfo, Self)>> {
        loop {
            bail_if_cancelled(&self.cancel)?;
            if let Some(item) = self.current_items.next() {
                return Ok(Some((item, self)));
            }
            if let Some(error) = self.pending_error.take() {
                return Err(error);
            }

            let (request, requested_url) = if self.started {
                let Some(url) = self.next_url.take() else {
                    return Ok(None);
                };
                (self.backend.http.get(url.clone()), url)
            } else {
                self.started = true;
                let mut url = Url::parse(&self.spec.first_url).map_err(|_| {
                    Error::new(
                        ErrorCode::Internal,
                        "huggingface tree endpoint is not an absolute URL",
                    )
                })?;
                if self.spec.recursive || self.spec.expand {
                    let mut query = url.query_pairs_mut();
                    if self.spec.recursive {
                        query.append_pair("recursive", "true");
                    }
                    if self.spec.expand {
                        query.append_pair("expand", "true");
                    }
                }
                (self.backend.http.get(url.clone()), url)
            };

            let cancel = self.cancel.clone();
            let (entries, link) = race_cancel(cancel.as_ref(), async {
                let response = self.backend.send_api(request).await?;
                let link = api::parse_link_next(response.headers(), &self.backend.config.endpoint)?;
                let entries: Vec<api::TreeEntry> = self.backend.decode_json(response).await?;
                Ok((entries, link))
            })
            .await?;

            if let Some(link) = link.as_ref() {
                if link == &requested_url {
                    // The current response is still valid, so yield it once;
                    // surface the no-progress failure after its entries rather
                    // than fetching and emitting the same page again.
                    self.pending_error = Some(Self::repeated_link_error());
                    self.next_url = None;
                    self.current_items = self
                        .backend
                        .convert_list_entries(&self.spec, entries)?
                        .into_iter();
                    continue;
                }
                let token = link.as_str();
                if self.recent_links.iter().any(|seen| seen == token) {
                    return Err(Self::repeated_link_error());
                }
                if self.recent_links.len() == LIST_STREAM_LINK_WINDOW {
                    self.recent_links.pop_front();
                }
                self.recent_links.push_back(token.to_string());
            }

            self.next_url = link;
            self.current_items = self
                .backend
                .convert_list_entries(&self.spec, entries)?
                .into_iter();
        }
    }
}

impl HfBackend {
    pub(crate) fn new(
        config: HfConnectionConfig,
        http: reqwest::Client,
        live_token: Arc<RwLock<Option<SecretBytes>>>,
    ) -> Self {
        Self {
            config,
            http,
            live_token,
        }
    }

    fn is_anonymous(&self) -> bool {
        self.live_token.read().is_none()
    }

    /// Attach the live bearer, marked sensitive so it never renders in logs.
    fn apply_bearer(&self, request: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder> {
        let guard = self.live_token.read();
        let Some(token) = guard.as_ref() else {
            return Ok(request);
        };
        let text = std::str::from_utf8(token.as_bytes()).map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "huggingface live token is not valid UTF-8",
            )
        })?;
        let mut value =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {text}")).map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "huggingface live token cannot be carried in a header",
                )
            })?;
        value.set_sensitive(true);
        Ok(request.header(reqwest::header::AUTHORIZATION, value))
    }

    /// Send one JSON-API request (bearer + per-request deadline attached).
    async fn send_api(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let request = self.apply_bearer(request)?.timeout(API_REQUEST_TIMEOUT);
        request.send().await.map_err(map_reqwest_error)
    }

    fn map_response(&self, status: u16, headers: Option<&reqwest::header::HeaderMap>) -> Error {
        map_status(status, headers, self.is_anonymous())
    }

    async fn ensure_success(&self, response: reqwest::Response) -> Result<reqwest::Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        Err(self.map_response(status.as_u16(), Some(response.headers())))
    }

    async fn decode_json<T: for<'de> serde::Deserialize<'de>>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        let response = self.ensure_success(response).await?;
        let body = response.text().await.map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "Hugging Face response body read failed: {}",
                    err.without_url()
                ),
            )
        })?;
        serde_json::from_str(&body).map_err(|err| {
            // Only the classification, position, and length are reported —
            // serde's `Display` renders offending values verbatim, which
            // would echo provider text into the message.
            Error::new(
                ErrorCode::Internal,
                format!(
                    "Hugging Face response was not the expected JSON shape \
                     ({:?} at line {} column {}; body length {})",
                    err.classify(),
                    err.line(),
                    err.column(),
                    body.len()
                ),
            )
        })
    }

    /// Resolve a ref to its commit sha via repo-info; `None` when the server
    /// omits it.
    async fn fetch_revision_sha(&self, revision: &str) -> Result<Option<String>> {
        let request = self.http.get(api::revision_url(&self.config, revision));
        let response = self.send_api(request).await?;
        let info: api::RepoInfo = self.decode_json(response).await?;
        Ok(info.sha)
    }

    /// One paths-info lookup. A missing path answers `200` with an empty
    /// array — the caller maps that to `NotFound`.
    async fn paths_info(
        &self,
        revision: &str,
        path: &str,
        expand: bool,
    ) -> Result<Vec<api::TreeEntry>> {
        let request = self
            .http
            .post(api::paths_info_url(&self.config, revision))
            .json(&serde_json::json!({ "paths": [path], "expand": expand }));
        let response = self.send_api(request).await?;
        self.decode_json(response).await
    }

    /// One paths-info lookup. `versioned_address`, like `full_metadata`, is
    /// served by the Hub's `expand=true` (per-entry commit facts), so either
    /// flag turns it on; a file is then pinned to the commit that last touched
    /// it. Without the flag only an immutable sha the caller already spelled is
    /// echoed.
    pub async fn stat(
        &self,
        target: ResolvedTarget,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = tracing::debug_span!(
            "huggingface.stat",
            op = "stat",
            plugin = "huggingface",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let entry_ref = self.config.parse_hf_address(&target.resolved_address)?;
                let revision = entry_ref.effective_revision(&self.config);
                if entry_ref.path.is_empty() {
                    // The repo root is a real directory; repo-info also
                    // resolves the ref to a commit sha.
                    let sha = self.fetch_revision_sha(revision).await?;
                    return Ok(parse::repo_root_info(&target.resolved_address, sha));
                }
                // The trailing slash is a hint, not an answer: paths-info
                // reports the entry's real kind either way.
                let lookup = entry_ref.path.trim_end_matches('/');
                let entries = self
                    .paths_info(
                        revision,
                        lookup,
                        opts.full_metadata || opts.versioned_address,
                    )
                    .await?;
                let Some(entry) = entries.first() else {
                    // paths-info reports a missing path as 200 + [].
                    return Err(not_found_error(self.is_anonymous(), None));
                };
                parse::entry_info(&target.resolved_address, entry)
            }
            .instrument(span),
        )
        .await
    }

    pub async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let span = tracing::debug_span!(
            "huggingface.read",
            op = "read",
            plugin = "huggingface",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let stream_cancel = cancel.clone();
        race_cancel(
            cancel.as_ref(),
            async move {
                let entry_ref = self.config.parse_hf_address(&target.resolved_address)?;
                if entry_ref.path.is_empty() || entry_ref.path.ends_with('/') {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "huggingface read requires a file address",
                    ));
                }
                let revision = entry_ref.effective_revision(&self.config);
                // Inverted ranges are refused here, before any wire call.
                let range_header = read_range_header(opts.range.as_ref())?;
                let endpoint_origin = Url::parse(&self.config.endpoint).map_err(|_| {
                    Error::new(
                        ErrorCode::Internal,
                        "huggingface endpoint is not an absolute URL",
                    )
                })?;
                let mut wire_url =
                    Url::parse(&api::resolve_url(&self.config, revision, &entry_ref.path))
                        .map_err(|_| {
                            Error::new(
                                ErrorCode::Internal,
                                "huggingface resolve URL failed to parse",
                            )
                        })?;
                // `resolve` answers with two redirect shapes and the plugin
                // FOLLOWS BOTH in-process rather than delegating either to the
                // host's redirect follower. A same-origin hop (often a
                // relative Location: the resolve-cache path for non-LFS files,
                // or a renamed repository) is followed with the bearer
                // re-attached; an off-origin hop is the signed CDN/LFS URL,
                // followed WITHOUT a bearer (its signature is the grant). Two
                // reasons not to mint a delegated `ReadRedirect`: (1) the LFS
                // canonical identity is the `x-linked-etag` sha256 on the 302,
                // which the CDN response does not carry, so a delegated read
                // could not report a `stat`-consistent etag; (2) it keeps an
                // attacker-influenced off-origin URL away from the host
                // follower's `file://` arm. Every hop's target scheme is
                // allowlisted before it is fetched.
                let mut hops = 0u32;
                // The LFS canonical identity, captured from whichever 302
                // carried the linked headers (the byte stream then comes from
                // the CDN, but the identity stays the sha256 the SPI wants).
                let mut linked: Option<LinkedIdentity> = None;
                let response = loop {
                    let same_origin = is_same_origin(&wire_url, &endpoint_origin);
                    let mut request = self.http.get(wire_url.clone());
                    if same_origin {
                        request = self.apply_bearer(request)?;
                    }
                    if let Some(range) = range_header.as_deref() {
                        request = request.header(reqwest::header::RANGE, range);
                    }
                    let response = request.send().await.map_err(map_reqwest_error)?;
                    let status = response.status().as_u16();
                    if !(300..400).contains(&status) {
                        break response;
                    }
                    if let Some(captured) = LinkedIdentity::from_headers(response.headers()) {
                        // The 302 carries the canonical LFS identity, so
                        // `if_match` and a whole-object `max_bytes` settle HERE,
                        // before the CDN is fetched — a precondition failure or
                        // an over-cap object never touches the wire again.
                        check_etag(opts.if_match.as_deref(), Some(&captured.etag))?;
                        if let (Some(max_bytes), Some(size)) = (opts.max_bytes, captured.size)
                            && opts.range.is_none()
                            && size > max_bytes
                        {
                            return Err(Error::new(
                                ErrorCode::ResourceExhausted,
                                format!(
                                    "Hugging Face object is {size} bytes, over the \
                                     caller-supplied max_bytes {max_bytes}"
                                ),
                            ));
                        }
                        linked = Some(captured);
                    }
                    let location = response
                        .headers()
                        .get(reqwest::header::LOCATION)
                        .and_then(|value| value.to_str().ok())
                        .ok_or_else(|| {
                            Error::new(
                                ErrorCode::Internal,
                                "Hugging Face resolve answered a redirect without a \
                                 Location header",
                            )
                        })?;
                    // Resolve relative forms against the URL that answered.
                    let redirect_target = wire_url.join(location).map_err(|_| {
                        Error::new(
                            ErrorCode::Internal,
                            "Hugging Face resolve answered a redirect with an \
                             unparsable Location",
                        )
                    })?;
                    if !is_same_origin(&redirect_target, &endpoint_origin)
                        && !offorigin_redirect_allowed(&redirect_target)
                    {
                        // A non-https off-origin Location — file://, or http to
                        // a non-loopback (link-local/private) host — is refused
                        // rather than followed, so a hostile endpoint cannot
                        // steer the read at a local file or an internal service.
                        return Err(Error::new(
                            ErrorCode::PermissionDenied,
                            format!(
                                "Hugging Face resolve redirected to an untrusted target \
                                 (scheme '{}'); only https CDN targets are followed",
                                redirect_target.scheme()
                            ),
                        ));
                    }
                    hops += 1;
                    if hops > MAX_RESOLVE_HOPS {
                        return Err(Error::new(
                            ErrorCode::Transient,
                            format!(
                                "Hugging Face resolve did not settle after \
                                 {MAX_RESOLVE_HOPS} redirects"
                            ),
                        ));
                    }
                    wire_url = redirect_target;
                };
                let status = response.status().as_u16();
                if !(200..300).contains(&status) {
                    return Err(self.map_response(status, Some(response.headers())));
                }
                if range_header.is_some() && status == 200 {
                    // Reject before buffering: an ignored open-ended
                    // `bytes=N-` has no cap, so draining first risks a
                    // multi-GB buffer.
                    drop(response);
                    return Err(Error::new(
                        ErrorCode::Unsupported,
                        "Hugging Face origin ignored Range during ranged read (returned 200 OK)",
                    ));
                }
                let hmap = lowercase_headers(response.headers());
                // A 206 must select exactly the requested interval; a server
                // answering `bytes 0-3/…` to a `bytes 100-103` request would
                // otherwise return bytes from the wrong offset.
                let content_range_total = if status == 206 {
                    Some(validate_content_range_206(
                        hmap.get("content-range"),
                        opts.range.as_ref(),
                    )?)
                } else {
                    None
                };
                // Identity: for an LFS object the canonical etag/size/version
                // are the linked headers from the 302, not the CDN response;
                // for a direct read they come from the resolve 200 itself
                // (ETag = git blob oid).
                let info = if let Some(linked) = linked.as_ref() {
                    // `if_match` / `max_bytes` for the linked identity were
                    // already settled at capture, before the CDN was fetched.
                    let mut checksums = ChecksumSet::new();
                    if let Some(sha256) = parse::decode_hex_sha256(&linked.etag) {
                        checksums.insert(ChecksumAlgorithm::sha256(), sha256);
                    }
                    let mut system_metadata = SystemMetadata::new();
                    if let Some(commit) = linked.repo_commit.as_deref() {
                        system_metadata.insert("x-repo-commit".into(), commit.to_string());
                    }
                    ObjectInfo {
                        etag_strength: EtagStrength::Strong,
                        address: target.resolved_address.clone(),
                        kind: ObjectKind::File,
                        etag: Some(linked.etag.clone()),
                        version: linked.repo_commit.clone(),
                        size: linked.size,
                        mtime: None,
                        checksums,
                        effective_permissions: None,
                        system_metadata: (!system_metadata.is_empty()).then_some(system_metadata),
                        user_metadata: None,
                        modified_by: None,
                        versioned_address: None,
                    }
                } else {
                    let advertised = hmap
                        .get("content-length")
                        .and_then(|value| value.parse::<u64>().ok());
                    let identity = identity_from_headers(&hmap, advertised, content_range_total);
                    check_etag(opts.if_match.as_deref(), identity.etag.as_deref())?;
                    ObjectInfo {
                        etag_strength: identity.etag_strength,
                        address: target.resolved_address.clone(),
                        kind: ObjectKind::File,
                        etag: identity.etag,
                        version: hmap.get("x-repo-commit").cloned(),
                        size: identity.size,
                        mtime: identity.mtime,
                        checksums: ChecksumSet::default(),
                        effective_permissions: None,
                        system_metadata: Some(headers_to_metadata(hmap)),
                        user_metadata: None,
                        modified_by: None,
                        versioned_address: None,
                    }
                };
                // A caller `max_bytes` bounds a whole-object read before any
                // byte is fetched when the size is known up front.
                if let (Some(max_bytes), Some(size)) = (opts.max_bytes, info.size)
                    && opts.range.is_none()
                    && size > max_bytes
                {
                    return Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        format!(
                            "Hugging Face object is {size} bytes, over the caller-supplied \
                             max_bytes {max_bytes}"
                        ),
                    ));
                }
                let open_ended = opts
                    .range
                    .as_ref()
                    .is_none_or(|range| range.end_inclusive.is_none());
                if open_ended {
                    // Whole-object and open-ended reads stream — never widen
                    // the buffer.
                    let upstream = response
                        .bytes_stream()
                        .map(|item| item.map_err(map_reqwest_error));
                    let stream: ReadStream =
                        Box::pin(CancelableStream::new(upstream, stream_cancel));
                    return Ok(ReadResult::Stream { stream, info });
                }
                // A closed range buffers under the SMALLER of the range length
                // and the caller's `max_bytes` (+1 to observe an overrun), so
                // a large range with a small cap cannot allocate the whole
                // range before the cap is enforced.
                let range_len = opts
                    .range
                    .as_ref()
                    .and_then(|range| range.end_inclusive)
                    .map(|end| {
                        end.saturating_sub(opts.range.as_ref().map(|r| r.start).unwrap_or(0))
                            .saturating_add(1)
                    })
                    .unwrap_or(u64::MAX);
                let cap = opts
                    .max_bytes
                    .map(|max_bytes| range_len.min(max_bytes.saturating_add(1)))
                    .unwrap_or(range_len);
                let mut body: Vec<u8> = Vec::new();
                let mut stream = response.bytes_stream();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(map_reqwest_error)?;
                    let remaining = cap.saturating_sub(body.len() as u64);
                    if remaining == 0 {
                        break;
                    }
                    let take = (chunk.len() as u64).min(remaining) as usize;
                    body.extend_from_slice(&chunk[..take]);
                    if (chunk.len() as u64) > remaining {
                        break;
                    }
                }
                if let Some(max_bytes) = opts.max_bytes
                    && body.len() as u64 > max_bytes
                {
                    return Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        format!(
                            "Hugging Face ranged read exceeded the caller-supplied \
                             max_bytes {max_bytes}"
                        ),
                    ));
                }
                Ok(ReadResult::Bytes { bytes: body, info })
            }
            .instrument(span),
        )
        .await
    }

    fn list_walk_spec(
        &self,
        prefix: &ResolvedTarget,
        opts: &ListOptions,
    ) -> Result<HfListWalkSpec> {
        let entry_ref = self.config.parse_hf_address(&prefix.resolved_address)?;
        let revision = entry_ref.effective_revision(&self.config).to_string();
        let dir_path = entry_ref.path.trim_end_matches('/');
        let first_url = api::tree_url(&self.config, &revision, dir_path);
        // Containment is checked against a prefix whose pin is re-spelled
        // through the SAME `with_query_pair` normalization the children get:
        // `is_ancestor_or_self` compares queries by exact raw equality, and
        // the caller's spelling of a pin (`?revision=refs/pr/1`) re-encodes
        // under form-urlencoding (`?revision=refs%2Fpr%2F1`). Comparing
        // against the raw caller spelling would drop every child of a
        // slashed-ref pin.
        let containment_prefix = match entry_ref.revision_pin.as_deref() {
            Some(pin) => {
                let mut base = prefix.resolved_address.clone();
                base.set_query(None);
                base.set_fragment(None);
                address::with_query_pair(&base, "revision", pin)?
            }
            None => prefix.resolved_address.clone(),
        };
        Ok(HfListWalkSpec {
            first_url,
            recursive: opts.recursive,
            expand: opts.full_metadata || opts.versioned_address,
            containment_prefix,
            revision_pin: entry_ref.revision_pin,
        })
    }

    /// Convert one provider page, preserving the buffered listing's omission
    /// rules and emission order.
    fn convert_list_entries(
        &self,
        spec: &HfListWalkSpec,
        entries: Vec<api::TreeEntry>,
    ) -> Result<Vec<ObjectInfo>> {
        let mut items = Vec::with_capacity(entries.len());
        for entry in entries {
            let Ok(child) = address::join_relative(&self.config.address_root, &entry.path) else {
                // The name cannot be spelled as a URI path, so any address
                // built for it would resolve to a different object. Invisible
                // beats mis-addressed, and failing the page would hide every
                // sibling too.
                tracing::warn!(
                    target: "ovstorage.huggingface.backend",
                    plugin = "huggingface",
                    "huggingface: entry path is not addressable as a URI path; omitted from listing",
                );
                continue;
            };
            let child = if entry.entry_type == "directory" {
                address::to_directory(&child)?
            } else {
                child
            };
            // A revision names a whole tree snapshot, so a pinned listing
            // emits pinned children — an unpinned child would silently resolve
            // to head.
            let child = match spec.revision_pin.as_deref() {
                Some(pin) => address::with_query_pair(&child, "revision", pin)?,
                None => child,
            };
            if !address::is_ancestor_or_self(&spec.containment_prefix, &child) {
                tracing::warn!(
                    target: "ovstorage.huggingface.backend",
                    plugin = "huggingface",
                    "huggingface: entry escapes the listed prefix; omitted",
                );
                continue;
            }
            match parse::entry_info(&child, &entry) {
                Ok(info) => items.push(info),
                Err(_) => {
                    tracing::warn!(
                        target: "ovstorage.huggingface.backend",
                        plugin = "huggingface",
                        "huggingface: entry has an unrecognized shape; omitted",
                    );
                }
            }
        }
        Ok(items)
    }

    /// Unpaginated listing (the layer folds and paginates). Entries the Hub
    /// reports outside the listed prefix, with unspellable names, or with an
    /// unknown type are omitted with a warning rather than failing the page.
    ///
    /// `versioned_address`, like `full_metadata`, is served by the Hub's
    /// `expand=true`, so either flag turns it on: file entries are then pinned
    /// to the commit that last touched them; directories carry `None`.
    pub async fn list(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let span = tracing::debug_span!(
            "huggingface.list",
            op = "list",
            plugin = "huggingface",
            object.address = %RedactedUrl(&prefix.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let spec = self.list_walk_spec(&prefix, &opts)?;
                let mut query: Vec<(&str, &str)> = Vec::new();
                if opts.recursive {
                    query.push(("recursive", "true"));
                }
                if spec.expand {
                    query.push(("expand", "true"));
                }
                let mut items: Vec<ObjectInfo> = Vec::new();
                let mut next: Option<Url> = None;
                loop {
                    let request = match next.take() {
                        // The cursor rides inside the server's own next URL.
                        Some(url) => self.http.get(url),
                        None => self.http.get(&spec.first_url).query(&query),
                    };
                    let response = self.send_api(request).await?;
                    let link = api::parse_link_next(response.headers(), &self.config.endpoint)?;
                    let entries: Vec<api::TreeEntry> = self.decode_json(response).await?;
                    items.extend(self.convert_list_entries(&spec, entries)?);
                    match link {
                        Some(url) => next = Some(url),
                        None => break,
                    }
                }
                Ok(items)
            }
            .instrument(span),
        )
        .await
    }

    /// Pull-driven listing over the Hub's native `Link: rel="next"` cursor.
    ///
    /// The returned stream retains one decoded Hub page and does not fetch the
    /// next page until the consumer polls past the current one.
    pub async fn list_stream(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ListStream> {
        if opts.max_results.is_some() || opts.page_token.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "list_stream does not accept max_results or page_token",
            ));
        }
        bail_if_cancelled(&cancel)?;
        let spec = self.list_walk_spec(&prefix, &opts)?;
        let state = HfListStreamState {
            backend: self.clone(),
            spec,
            current_items: Vec::new().into_iter(),
            next_url: None,
            started: false,
            recent_links: VecDeque::new(),
            pending_error: None,
            cancel,
        };
        Ok(Box::pin(futures::stream::try_unfold(
            state,
            HfListStreamState::next_item,
        )))
    }

    /// Repository commit history pinned onto the input address. Versions are
    /// repository commits (the git model): adjacent versions of a file may be
    /// byte-identical, and a pin predating the file answers `NotFound` on
    /// dereference — both contract-blessed shapes. Only per-commit facts are
    /// populated; file size/etag under a historical commit are unknown here
    /// and never fabricated.
    pub async fn list_versions(
        &self,
        target: ResolvedTarget,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let span = tracing::debug_span!(
            "huggingface.list_versions",
            op = "list",
            plugin = "huggingface",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let entry_ref = self.config.parse_hf_address(&target.resolved_address)?;
                // The walk starts from the connection's DEFAULT revision, not
                // the address pin: a pin selects one version, it never filters
                // the listing — walking a sha pin's git ancestry would omit
                // every commit newer than it (the same rule under which S3 and
                // GCS ignore versionId/generation pins here).
                let revision = self.config.revision.clone();
                let mut base = target.resolved_address.clone();
                base.set_query(None);
                base.set_fragment(None);
                let kind = if entry_ref.path.is_empty() || entry_ref.path.ends_with('/') {
                    ObjectKind::Directory
                } else {
                    ObjectKind::File
                };
                // Walk the FULL history here; `max_results`/`page_token`
                // paging is applied by the layer via `paginate_list_items` so
                // a truncated page still yields a resumable `next_page_token`
                // (`opts` is ignored on purpose — the layer owns it).
                let _ = &opts;
                let first_url = api::commits_url(&self.config, &revision);
                let mut versions: Vec<ObjectInfo> = Vec::new();
                let mut next: Option<Url> = None;
                loop {
                    let request = match next.take() {
                        Some(url) => self.http.get(url),
                        None => self.http.get(&first_url),
                    };
                    let response = self.send_api(request).await?;
                    let link = api::parse_link_next(response.headers(), &self.config.endpoint)?;
                    let commits: Vec<api::CommitInfo> = self.decode_json(response).await?;
                    for commit in commits {
                        let pinned = address::with_query_pair(&base, "revision", &commit.id)?;
                        let mut system_metadata = SystemMetadata::new();
                        if let Some(title) = commit.title.as_deref() {
                            system_metadata.insert("hf.commit.title".into(), title.to_string());
                        }
                        versions.push(ObjectInfo {
                            etag_strength: EtagStrength::Unspecified,
                            address: pinned.clone(),
                            kind,
                            etag: None,
                            version: Some(commit.id.clone()),
                            size: None,
                            mtime: commit.date.as_deref().and_then(parse::parse_rfc3339),
                            checksums: ChecksumSet::default(),
                            effective_permissions: None,
                            system_metadata: if system_metadata.is_empty() {
                                None
                            } else {
                                Some(system_metadata)
                            },
                            user_metadata: None,
                            modified_by: commit
                                .authors
                                .first()
                                .and_then(|author| author.user.clone()),
                            versioned_address: Some(pinned),
                        });
                    }
                    match link {
                        Some(url) => next = Some(url),
                        None => break,
                    }
                }
                Ok(versions)
            }
            .instrument(span),
        )
        .await
    }

    /// Resolve the effective revision to its immutable commit sha and return
    /// the addressed object pinned to THAT sha — the metadata is fetched at the
    /// resolved sha, and the returned address names it, so `version`, the
    /// entry facts, and the pin are one consistent snapshot even if the ref
    /// advances mid-call, and the returned address matches the immutable form
    /// `list_versions` emits. `versioned_address` is that same pinned address:
    /// the head sha, where `stat`/`list` pin the entry's last-touching commit.
    pub async fn get_latest_version(
        &self,
        target: ResolvedTarget,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = tracing::debug_span!(
            "huggingface.get_latest_version",
            op = "stat",
            plugin = "huggingface",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let entry_ref = self.config.parse_hf_address(&target.resolved_address)?;
                let revision = entry_ref.effective_revision(&self.config).to_string();
                let sha = self.fetch_revision_sha(&revision).await?.ok_or_else(|| {
                    Error::new(
                        ErrorCode::NotFound,
                        "Hugging Face revision did not resolve to a commit",
                    )
                })?;
                let mut base = target.resolved_address.clone();
                base.set_query(None);
                base.set_fragment(None);
                // Pin to the resolved sha (not the caller's possibly-mutable
                // ref), and read the entry AT that sha, so metadata and pin
                // cannot name two different commits.
                let pinned_address = address::with_query_pair(&base, "revision", &sha)?;
                if entry_ref.path.is_empty() {
                    return Ok(parse::repo_root_info(&pinned_address, Some(sha)));
                }
                let lookup = entry_ref.path.trim_end_matches('/');
                let entries = self.paths_info(&sha, lookup, false).await?;
                let Some(entry) = entries.first() else {
                    return Err(not_found_error(self.is_anonymous(), None));
                };
                let mut info = parse::entry_info(&pinned_address, entry)?;
                info.version = Some(sha);
                info.versioned_address = Some(pinned_address);
                Ok(info)
            }
            .instrument(span),
        )
        .await
    }
}

/// Map an HTTP status (plus the sanitized `x-error-code`, when present) to
/// the SPI error surface. 401 carries auth context (drives connection
/// parking); 403 deliberately carries none — it is final, not re-auth bait.
fn map_status(status: u16, headers: Option<&reqwest::header::HeaderMap>, anonymous: bool) -> Error {
    let code_token = headers.and_then(api::error_code_header);
    let detail = code_token
        .as_deref()
        .map(|code| format!(" (x-error-code: {code})"))
        .unwrap_or_default();
    if status == 401 {
        return Error::new(
            ErrorCode::AuthRequired,
            format!("Hugging Face request requires authentication (HTTP 401){detail}"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("hf_unauthorized".into()),
            expired_at: None,
        });
    }
    if status == 403 || code_token.as_deref() == Some("GatedRepo") {
        let hint = if code_token.as_deref() == Some("GatedRepo") {
            " — the repository is gated; accept its conditions on the Hub first"
        } else {
            ""
        };
        return Error::new(
            ErrorCode::PermissionDenied,
            format!("Hugging Face request forbidden (HTTP {status}){detail}{hint}"),
        );
    }
    match status {
        404 | 410 => not_found_error(anonymous, code_token.as_deref()),
        405 => Error::new(ErrorCode::Unsupported, "Hugging Face method not allowed"),
        412 => {
            let err = Error::new(
                ErrorCode::ObjectModified,
                format!("Hugging Face precondition failed{detail}"),
            );
            match headers
                .and_then(|h| h.get("etag"))
                .and_then(|v| v.to_str().ok())
            {
                Some(raw) => err.with_context(ErrorContext::Identity {
                    new_etag: Some(strip_etag_wire_form(raw)),
                }),
                None => err,
            }
        }
        416 => Error::new(
            ErrorCode::InvalidArgument,
            "Hugging Face range not satisfiable (HTTP 416)",
        ),
        408 | 504 => Error::new(
            ErrorCode::DeadlineExceeded,
            format!("Hugging Face request timed out (HTTP {status})"),
        ),
        429 | 503 => Error::new(
            ErrorCode::ResourceExhausted,
            format!("Hugging Face reported rate limiting (HTTP {status})"),
        ),
        500..=599 => Error::new(
            ErrorCode::Transient,
            format!("Hugging Face returned transient status {status}"),
        ),
        // A JSON-API endpoint answers 3xx when the repository has been
        // renamed or moved (`read` handles resolve's redirects itself and
        // never reaches this arm). The client's manual-redirect policy is a
        // bearer-safety decision, so the hop is reported rather than
        // followed.
        300..=399 => Error::new(
            ErrorCode::NotFound,
            format!(
                "Hugging Face answered a redirect (HTTP {status}){detail} — the repository \
                 may have been renamed or moved; update repo_id"
            ),
        ),
        other => Error::new(
            ErrorCode::Unsupported,
            format!("unsupported Hugging Face response status {other}"),
        ),
    }
}

/// `NotFound`, with the one HF nuance spelled out: the Hub hides private
/// repositories behind 404, so an anonymous miss may really be a
/// missing token. The hint stays in the message — the code must not become
/// `AuthRequired`, which the host would read as a drivable auth flow.
fn not_found_error(anonymous: bool, code_token: Option<&str>) -> Error {
    let detail = code_token
        .map(|code| format!(" (x-error-code: {code})"))
        .unwrap_or_default();
    let hint = if anonymous {
        " — if the repository is private or gated, supply a token"
    } else {
        ""
    };
    Error::new(
        ErrorCode::NotFound,
        format!("Hugging Face path not found{detail}{hint}"),
    )
}

fn map_reqwest_error(error: reqwest::Error) -> Error {
    let timed_out = error.is_timeout();
    let connect_failed = error.is_connect();
    let status = error.status();
    // Drop the URL before it reaches a caller-visible message: `Display`
    // appends `" for url ({url})"`, and a signed CDN URL's query is a
    // credential.
    let error = error.without_url();
    if timed_out {
        return Error::new(
            ErrorCode::Transient,
            format!("Hugging Face request timed out: {error}"),
        );
    }
    if connect_failed {
        return Error::new(
            ErrorCode::Transient,
            format!("Hugging Face connect error: {error}"),
        );
    }
    if let Some(status) = status {
        return map_status(status.as_u16(), None, false);
    }
    Error::new(
        ErrorCode::Transient,
        format!("Hugging Face HTTP error: {error}"),
    )
}

/// Open-ended ranges emit `bytes=start-`; inverted ranges are refused with
/// `InvalidArgument` before any wire call so a bad slice cannot panic the
/// host-side follower.
fn read_range_header(range: Option<&ByteRange>) -> Result<Option<String>> {
    let Some(range) = range else {
        return Ok(None);
    };
    if let Some(end) = range.end_inclusive
        && end < range.start
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "huggingface read: inverted byte range start={} end_inclusive={end}",
                range.start
            ),
        ));
    }
    let end = range
        .end_inclusive
        .map(|end| end.to_string())
        .unwrap_or_default();
    Ok(Some(format!("bytes={}-{end}", range.start)))
}

/// The LFS canonical identity carried on a `resolve` 302: the content sha256
/// (`x-linked-etag`), the real object size (`x-linked-size`), and the serving
/// commit (`x-repo-commit`). Captured before the redirect is followed so the
/// final `ObjectInfo` reports the same etag `stat` does, even though the byte
/// stream comes from a CDN response that carries a different tag.
struct LinkedIdentity {
    etag: String,
    size: Option<u64>,
    repo_commit: Option<String>,
}

impl LinkedIdentity {
    fn from_headers(headers: &reqwest::header::HeaderMap) -> Option<Self> {
        let etag = headers
            .get("x-linked-etag")
            .and_then(|value| value.to_str().ok())
            .map(strip_etag_wire_form)?;
        Some(Self {
            etag,
            size: headers
                .get("x-linked-size")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok()),
            repo_commit: headers
                .get("x-repo-commit")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
        })
    }
}

fn is_same_origin(url: &Url, origin: &Url) -> bool {
    url.scheme() == origin.scheme()
        && url.host_str() == origin.host_str()
        && url.port_or_known_default() == origin.port_or_known_default()
}

/// Whether an off-origin `resolve` redirect target may be followed. Only
/// `https` CDN URLs qualify, plus the loopback-`http` test seam; every other
/// scheme (notably `file://`) and any cleartext `http` to a non-loopback host
/// is refused, so a hostile endpoint cannot steer the read at a local file or
/// an internal/link-local service.
fn offorigin_redirect_allowed(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => url_host_is_loopback(url),
        _ => false,
    }
}

/// Validate a `206 Content-Range` against the requested interval and return
/// the object total. The start must equal the requested start (a server
/// answering `bytes 0-3/…` to a `bytes 100-103` request would otherwise hand
/// back bytes from the wrong offset), and the end must match the requested
/// end or the object's last byte.
fn validate_content_range_206(
    header: Option<&String>,
    requested: Option<&ByteRange>,
) -> Result<u64> {
    let mismatch = |detail: &str| {
        Error::new(
            ErrorCode::Internal,
            format!("Hugging Face 206 response {detail}"),
        )
    };
    let raw = header.ok_or_else(|| mismatch("carried no Content-Range"))?;
    // `bytes START-END/TOTAL` (TOTAL may be `*`).
    let spec = raw
        .trim()
        .strip_prefix("bytes ")
        .ok_or_else(|| mismatch("Content-Range was not a `bytes` range"))?;
    let (range_part, total_part) = spec
        .split_once('/')
        .ok_or_else(|| mismatch("Content-Range lacked a `/total`"))?;
    let (start_text, end_text) = range_part
        .split_once('-')
        .ok_or_else(|| mismatch("Content-Range lacked a `start-end`"))?;
    let start: u64 = start_text
        .trim()
        .parse()
        .map_err(|_| mismatch("Content-Range start was not a number"))?;
    let end: u64 = end_text
        .trim()
        .parse()
        .map_err(|_| mismatch("Content-Range end was not a number"))?;
    let total = total_part.trim().parse::<u64>().ok();
    if end < start {
        return Err(mismatch("Content-Range end preceded start"));
    }
    let requested = requested.ok_or_else(|| mismatch("arrived for an unranged request"))?;
    if start != requested.start {
        return Err(mismatch("started at the wrong offset"));
    }
    if let Some(requested_end) = requested.end_inclusive {
        // The server may clamp the end to the object's last byte.
        let clamped = total.map(|total| requested_end.min(total.saturating_sub(1)));
        if end != requested_end && Some(end) != clamped {
            return Err(mismatch("ended at the wrong offset"));
        }
    }
    total.ok_or_else(|| mismatch("did not report an object total"))
}

fn lowercase_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::with_capacity(headers.len());
    for (name, value) in headers.iter() {
        if let Ok(text) = value.to_str() {
            map.insert(name.as_str().to_ascii_lowercase(), text.to_string());
        }
    }
    map
}

/// Per-response identity fields; only `etag` is the SPI precondition token.
struct HttpIdentity {
    etag_strength: EtagStrength,
    etag: Option<String>,
    size: Option<u64>,
    mtime: Option<SystemTime>,
}

fn identity_from_headers(
    headers: &HashMap<String, String>,
    observed_len: Option<u64>,
    total_size: Option<u64>,
) -> HttpIdentity {
    let (etag, etag_strength) =
        normalize_optional_wire_etag(headers.get("etag").map(String::as_str));
    let mtime = headers
        .get("last-modified")
        .and_then(|raw| httpdate::parse_http_date(raw).ok());
    let size = total_size
        .or_else(|| {
            headers
                .get("content-length")
                .and_then(|value| value.parse().ok())
        })
        .or(observed_len);
    HttpIdentity {
        etag_strength,
        etag,
        size,
        mtime,
    }
}

/// Strip RFC 7232 quoting and the `W/` weak prefix so the SPI's `if_match`
/// string is the opaque token.
fn strip_etag_wire_form(raw: &str) -> String {
    let trimmed = raw.trim();
    let body = trimmed.strip_prefix("W/").unwrap_or(trimmed);
    body.trim_matches('"').to_string()
}

/// Response headers that must not be republished as object metadata: they
/// describe the connection's identity or session, not the bytes.
const NON_METADATA_RESPONSE_HEADERS: &[&str] = &[
    "authorization",
    "authentication-info",
    "proxy-authenticate",
    "proxy-authentication-info",
    "proxy-authorization",
    "set-cookie",
    "set-cookie2",
    "www-authenticate",
];

/// Republish the origin's response headers as object system metadata, minus
/// the credential/session set. A denylist, deliberately, so `x-repo-commit`
/// and future Hub headers arrive intact. (Only the direct-read 200 path runs
/// through here; a resolve 3xx is followed or minted before its headers could
/// be republished.)
fn headers_to_metadata(headers: HashMap<String, String>) -> SystemMetadata {
    headers
        .into_iter()
        .filter(|(name, _)| {
            !NON_METADATA_RESPONSE_HEADERS
                .iter()
                .any(|banned| name.eq_ignore_ascii_case(banned))
        })
        .collect()
}

fn check_etag(expected: Option<&str>, actual: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if expected.is_empty() {
        return Ok(());
    }
    // The Hugging Face SPI etag is an opaque token (the git blob oid or the
    // LFS content sha256), so `if_match` is an exact-byte comparison. A caller
    // value spelled like a weak HTTP tag (`W/…`) is compared literally too — it
    // is not special-cased into always passing.
    let etag_mismatch = actual != Some(expected);
    if etag_mismatch {
        Err(Error::new(
            ErrorCode::ObjectModified,
            "Hugging Face object etag changed",
        )
        .with_context(ErrorContext::Identity {
            new_etag: actual.map(str::to_string),
        }))
    } else {
        Ok(())
    }
}

/// Byte stream that surfaces host cancellation as `ErrorCode::Cancelled`
/// mid-body instead of hanging on a stalled origin.
struct CancelableStream<S> {
    inner: S,
    cancelled: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    done: bool,
}

impl<S> CancelableStream<S> {
    fn new(inner: S, cancel: Option<CancellationToken>) -> Self {
        let cancelled = cancel.map(|token| {
            Box::pin(token.cancelled_owned()) as Pin<Box<dyn Future<Output = ()> + Send>>
        });
        Self {
            inner,
            cancelled,
            done: false,
        }
    }
}

impl<S> futures::Stream for CancelableStream<S>
where
    S: futures::Stream<Item = Result<bytes::Bytes>> + Unpin,
{
    type Item = Result<bytes::Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        let cancelled_now = match self.cancelled.as_mut() {
            Some(fut) => fut.as_mut().poll(cx).is_ready(),
            None => false,
        };
        if cancelled_now {
            self.done = true;
            return Poll::Ready(Some(Err(Error::new(
                ErrorCode::Cancelled,
                "cancelled by host",
            ))));
        }
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

/// Shared client: manual redirects everywhere — on `resolve` the 302 IS the
/// product, and on API endpoints a hop would strip the bearer silently.
///
/// `bypass_proxy` disables the ambient proxy. It is set for a cleartext
/// loopback endpoint (the test seam), where `reqwest` would otherwise send the
/// request — bearer and all — to `HTTP_PROXY` in absolute form, leaking the
/// credential off-loopback. The production `https://huggingface.co` endpoint
/// keeps ambient proxy support (a corporate proxy CONNECT-tunnels it, so the
/// bearer stays inside TLS).
pub(crate) fn build_http_client(bypass_proxy: bool) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(HTTP_USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(30));
    if bypass_proxy {
        builder = builder.no_proxy();
    }
    builder.build().map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("failed to build Hugging Face HTTP client: {err}"),
        )
    })
}

/// Whether an endpoint is a cleartext (`http`) loopback host — the hermetic
/// test seam, where the ambient proxy must be bypassed so a bearer never
/// travels to a proxy in absolute cleartext form.
pub(crate) fn endpoint_is_cleartext_loopback(endpoint: &str) -> bool {
    Url::parse(endpoint)
        .ok()
        .filter(|url| url.scheme() == "http")
        .is_some_and(|url| url_host_is_loopback(&url))
}

fn required_text(config: &HashMap<String, ConfigValue>, key: &str) -> Result<String> {
    match config.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => {
            Ok(value.trim().to_string())
        }
        Some(ConfigValue::String(_)) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("huggingface connection config '{key}' must not be empty"),
        )),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("huggingface connection config '{key}' must be text"),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("missing required huggingface connection config '{key}'"),
        )),
    }
}

fn optional_text(config: &HashMap<String, ConfigValue>, key: &str) -> Result<Option<String>> {
    match config.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => {
            Ok(Some(value.trim().to_string()))
        }
        Some(ConfigValue::String(_)) | None => Ok(None),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("huggingface connection config '{key}' must be text"),
        )),
    }
}

fn optional_url(config: &HashMap<String, ConfigValue>, key: &str) -> Result<Option<Url>> {
    match config.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => {
            Ok(Some(address::parse(value.trim())?))
        }
        Some(ConfigValue::String(_)) | None => Ok(None),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("huggingface connection config '{key}' must be a URL string"),
        )),
    }
}

fn url_host_is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    // `host_str` keeps an IPv6 literal's brackets (`[::1]`); strip them so
    // the `IpAddr` parse sees the address itself.
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<std::net::IpAddr>()
        .map(|addr| addr.is_loopback())
        .unwrap_or(false)
}

fn text_field(
    key: &str,
    display_name: &str,
    required: bool,
    example: Option<&str>,
    help: Option<&str>,
    advanced: bool,
) -> ConfigField {
    ConfigField {
        key: key.into(),
        display_name: display_name.into(),
        kind: ConfigFieldKind::Text,
        required,
        default: None,
        help: help.map(str::to_string),
        example: example.map(str::to_string),
        group: Some("provider".into()),
        advanced,
    }
}

fn url_field(
    key: &str,
    display_name: &str,
    required: bool,
    example: Option<&str>,
    help: Option<&str>,
    advanced: bool,
) -> ConfigField {
    ConfigField {
        key: key.into(),
        display_name: display_name.into(),
        kind: ConfigFieldKind::Url,
        required,
        default: None,
        help: help.map(str::to_string),
        example: example.map(str::to_string),
        group: Some("provider".into()),
        advanced,
    }
}

/// Test-only parser hook; not part of the published surface.
#[doc(hidden)]
pub fn __test_only_parse_config(
    config: &HashMap<String, ConfigValue>,
) -> Result<HfConnectionConfig> {
    HfConnectionConfig::from_request(&ConnectionRequest {
        backend_kind: "huggingface".into(),
        config: config.clone(),
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    })
}

/// Test-only constructor hook; builds a backend from a parsed config, an
/// explicit token cell, and the shared client.
#[doc(hidden)]
pub fn __test_only_backend(
    config: HfConnectionConfig,
    token: Option<Vec<u8>>,
) -> Result<HfBackend> {
    let http = build_http_client(endpoint_is_cleartext_loopback(&config.endpoint))?;
    let live_token = Arc::new(RwLock::new(token.map(SecretBytes)));
    Ok(HfBackend::new(config, http, live_token))
}

ovstorage_plugin::ovstorage_layer_plugin!(backend, HfLayerFactory::default);

#[cfg(test)]
mod tests {
    use super::*;

    fn config_map(entries: &[(&str, &str)]) -> HashMap<String, ConfigValue> {
        entries
            .iter()
            .map(|(key, value)| (key.to_string(), ConfigValue::String(value.to_string())))
            .collect()
    }

    fn demo_config() -> HfConnectionConfig {
        __test_only_parse_config(&config_map(&[("repo_id", "acme/demo")])).unwrap()
    }

    #[test]
    fn config_defaults_fill_type_revision_and_endpoint() {
        let config = demo_config();
        assert_eq!(config.repo_type, RepoType::Model);
        assert_eq!(config.revision, "main");
        assert_eq!(config.endpoint, "https://huggingface.co");
        assert_eq!(config.address_root.as_str(), "hf://models/acme/demo/");
    }

    #[test]
    fn repo_id_validation_refuses_malformed_ids() {
        for bad in [
            "acme",
            "acme/demo/extra",
            "/demo",
            "acme/",
            ".hidden/demo",
            "acme/de mo",
            "acme/de?mo",
            "a..b/demo",
        ] {
            let err = __test_only_parse_config(&config_map(&[("repo_id", bad)])).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "repo_id {bad:?}");
        }
        for good in ["acme/demo", "Acme-Corp/Model_1.5", "a/b"] {
            __test_only_parse_config(&config_map(&[("repo_id", good)]))
                .unwrap_or_else(|err| panic!("repo_id {good:?} refused: {err:?}"));
        }
    }

    #[test]
    fn repo_type_enum_rejects_unknown_values() {
        let err = __test_only_parse_config(&config_map(&[
            ("repo_id", "acme/demo"),
            ("repo_type", "notebook"),
        ]))
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        let config = __test_only_parse_config(&config_map(&[
            ("repo_id", "acme/demo"),
            ("repo_type", "dataset"),
        ]))
        .unwrap();
        assert_eq!(config.address_root.as_str(), "hf://datasets/acme/demo/");
    }

    #[test]
    fn a_non_default_endpoint_must_be_loopback() {
        let err = __test_only_parse_config(&config_map(&[
            ("repo_id", "acme/demo"),
            ("endpoint", "https://hub.example.com"),
        ]))
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        let config = __test_only_parse_config(&config_map(&[
            ("repo_id", "acme/demo"),
            ("endpoint", "http://127.0.0.1:8080/"),
        ]))
        .unwrap();
        assert_eq!(config.endpoint, "http://127.0.0.1:8080");
        let config = __test_only_parse_config(&config_map(&[
            ("repo_id", "acme/demo"),
            ("endpoint", "https://huggingface.co/"),
        ]))
        .unwrap();
        assert_eq!(config.endpoint, "https://huggingface.co");
        // IPv6 loopback counts: `host_str` keeps the brackets, the gate
        // strips them before parsing.
        let config = __test_only_parse_config(&config_map(&[
            ("repo_id", "acme/demo"),
            ("endpoint", "http://[::1]:8080/"),
        ]))
        .unwrap();
        assert_eq!(config.endpoint, "http://[::1]:8080");
    }

    /// An endpoint is an origin, never a credential channel: with userinfo it
    /// would be sent on every request URL and, on a loopback endpoint, be
    /// copied into the spelling the connection row publishes. Refused at
    /// parse time, and the refusal never echoes the secret.
    #[test]
    fn an_endpoint_with_credentials_is_refused_without_echo() {
        for endpoint in [
            "http://alice:secret-value@127.0.0.1:8080",
            "http://alice@127.0.0.1:8080/",
            "http://:secret-value@[::1]:8080",
            "https://alice:secret-value@huggingface.co",
        ] {
            let err = __test_only_parse_config(&config_map(&[
                ("repo_id", "acme/demo"),
                ("endpoint", endpoint),
            ]))
            .unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{endpoint}");
            assert!(
                !err.message().contains("secret-value") && !err.message().contains("alice"),
                "the refusal must not echo the credential: {}",
                err.message()
            );
        }
    }

    fn prefixes(config: &HfConnectionConfig) -> Vec<String> {
        config
            .alternate_url_prefixes()
            .iter()
            .map(|url| url.as_str().to_string())
            .collect()
    }

    fn config_with(entries: &[(&str, &str)]) -> HfConnectionConfig {
        let mut all = vec![("repo_id", "acme/demo")];
        all.extend_from_slice(entries);
        __test_only_parse_config(&config_map(&all)).unwrap()
    }

    /// The default endpoint accepts the Hub's own repository URL on every
    /// public origin a user can hold, the signed origin first.
    #[test]
    fn the_default_endpoint_generates_the_six_public_hub_spellings() {
        assert_eq!(
            PUBLIC_HUB_ORIGINS[0], DEFAULT_ENDPOINT,
            "the signed origin leads the set"
        );
        let expected = [
            "https://huggingface.co/acme/demo/",
            "http://huggingface.co/acme/demo/",
            "https://www.huggingface.co/acme/demo/",
            "http://www.huggingface.co/acme/demo/",
            "https://hf.co/acme/demo/",
            "http://hf.co/acme/demo/",
        ];
        assert_eq!(prefixes(&demo_config()), expected);
        // An explicitly configured default endpoint normalizes to the default
        // and yields the same set.
        assert_eq!(
            prefixes(&config_with(&[("endpoint", "https://huggingface.co/")])),
            expected
        );
    }

    /// The web path follows the Hub's layout — models at the site root,
    /// datasets and spaces under their plural — never the `hf://` host.
    #[test]
    fn datasets_and_spaces_spellings_carry_their_web_path_prefix() {
        let dataset = prefixes(&config_with(&[("repo_type", "dataset")]));
        assert_eq!(dataset.len(), 6);
        assert_eq!(dataset[0], "https://huggingface.co/datasets/acme/demo/");
        assert!(
            dataset
                .iter()
                .all(|spelling| spelling.ends_with("/datasets/acme/demo/"))
        );
        let space = prefixes(&config_with(&[("repo_type", "space")]));
        assert_eq!(space[0], "https://huggingface.co/spaces/acme/demo/");
        assert!(
            space
                .iter()
                .all(|spelling| spelling.ends_with("/spaces/acme/demo/"))
        );
        assert!(
            prefixes(&demo_config())
                .iter()
                .all(|spelling| !spelling.contains("/models/"))
        );
    }

    /// A non-default endpoint is the origin itself: exactly its own shape,
    /// path included, and no public twin.
    #[test]
    fn a_loopback_endpoint_generates_exactly_its_own_shape() {
        assert_eq!(
            prefixes(&config_with(&[("endpoint", "http://127.0.0.1:8080/")])),
            ["http://127.0.0.1:8080/acme/demo/"]
        );
        assert_eq!(
            prefixes(&config_with(&[("endpoint", "http://[::1]:8080/hub")])),
            ["http://[::1]:8080/hub/acme/demo/"]
        );
        assert_eq!(
            prefixes(&config_with(&[
                ("repo_type", "dataset"),
                ("endpoint", "http://127.0.0.1:8080"),
            ])),
            ["http://127.0.0.1:8080/datasets/acme/demo/"]
        );
    }

    /// A model whose namespace is a Hub route root would spell itself on top
    /// of the dataset, space, or API URL space; it gets no web spelling, on
    /// any endpoint, while datasets and spaces under such a namespace keep
    /// theirs (their web path is already disambiguated by the plural) and
    /// the model's canonical root is untouched.
    #[test]
    fn a_model_in_a_reserved_hub_namespace_generates_no_web_spelling() {
        for namespace in ["datasets", "spaces", "api", "models", "Datasets"] {
            let repo_id = format!("{namespace}/acme");
            let model = __test_only_parse_config(&config_map(&[("repo_id", &repo_id)])).unwrap();
            assert!(
                prefixes(&model).is_empty(),
                "{repo_id} must generate no web spelling"
            );
            assert_eq!(
                model.address_root.as_str(),
                format!("hf://models/{repo_id}/"),
                "the canonical root is unaffected"
            );
            let loopback = __test_only_parse_config(&config_map(&[
                ("repo_id", &repo_id),
                ("endpoint", "http://127.0.0.1:8080"),
            ]))
            .unwrap();
            assert!(
                prefixes(&loopback).is_empty(),
                "{repo_id} on a loopback endpoint"
            );
        }
        assert_eq!(
            prefixes(&config_with(&[
                ("repo_id", "datasets/acme"),
                ("repo_type", "dataset"),
            ]))[0],
            "https://huggingface.co/datasets/datasets/acme/",
            "a dataset under such a namespace keeps its spelling"
        );
        assert_eq!(
            prefixes(&config_with(&[
                ("repo_id", "api/acme"),
                ("repo_type", "space")
            ]))[0],
            "https://huggingface.co/spaces/api/acme/"
        );
    }

    /// The origin and repository path the plugin resolves content against is
    /// always an accepted spelling, so the two derivations cannot drift.
    #[test]
    fn the_resolve_url_starts_with_the_accepted_spelling() {
        for config in [
            demo_config(),
            config_with(&[("repo_type", "dataset")]),
            config_with(&[("repo_type", "space")]),
            config_with(&[("endpoint", "http://127.0.0.1:8080")]),
        ] {
            let spelling = &prefixes(&config)[0];
            let resolve = api::resolve_url(&config, "main", "weights/model.bin");
            assert!(
                resolve.starts_with(spelling),
                "{resolve} does not start with {spelling}"
            );
        }
    }

    /// What the alias layer hands the plugin after rewriting a Hub URL onto
    /// the root: the pin rides through, the slash-less repository root is the
    /// root, a web-view infix is an in-repository path, and a carried selector
    /// this backend does not read is refused rather than dropped.
    #[test]
    fn a_projected_pinned_address_round_trips_through_the_parser() {
        let config = demo_config();
        let from = config.alternate_url_prefixes()[0].clone();
        let rewrite = |spelling: &str| {
            address::replace_prefix(
                &address::parse(spelling).unwrap(),
                &from,
                &config.address_root,
            )
            .unwrap()
        };
        let pinned = rewrite(
            "https://huggingface.co/acme/demo/config.json?revision=refs%2Fconvert%2Fparquet",
        );
        assert_eq!(
            pinned.as_str(),
            "hf://models/acme/demo/config.json?revision=refs%2Fconvert%2Fparquet"
        );
        assert_eq!(
            config.parse_hf_address(&pinned).unwrap(),
            HfEntryRef {
                path: "config.json".into(),
                revision_pin: Some("refs/convert/parquet".into()),
            }
        );
        assert_eq!(
            config
                .parse_hf_address(&rewrite("https://huggingface.co/acme/demo"))
                .unwrap()
                .path,
            ""
        );
        assert_eq!(
            config
                .parse_hf_address(&rewrite(
                    "https://huggingface.co/acme/demo/blob/main/config.json"
                ))
                .unwrap()
                .path,
            "blob/main/config.json"
        );
        let foreign = rewrite("https://huggingface.co/acme/demo/config.json?versionId=1");
        assert_eq!(
            config.parse_hf_address(&foreign).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn addresses_resolve_paths_and_pins() {
        let config = demo_config();
        let addr = address::parse("hf://models/acme/demo/weights/model.bin?revision=abc").unwrap();
        let entry_ref = config.parse_hf_address(&addr).unwrap();
        assert_eq!(entry_ref.path, "weights/model.bin");
        assert_eq!(entry_ref.revision_pin.as_deref(), Some("abc"));
        assert_eq!(entry_ref.effective_revision(&config), "abc");

        let root = address::parse("hf://models/acme/demo/").unwrap();
        let entry_ref = config.parse_hf_address(&root).unwrap();
        assert_eq!(entry_ref.path, "");
        assert_eq!(entry_ref.effective_revision(&config), "main");

        let dir = address::parse("hf://models/acme/demo/weights/").unwrap();
        assert_eq!(config.parse_hf_address(&dir).unwrap().path, "weights/");
    }

    #[test]
    fn addresses_with_unknown_modifiers_are_refused() {
        let config = demo_config();
        let addr = address::parse("hf://models/acme/demo/a.txt?versionId=3").unwrap();
        let err = config.parse_hf_address(&addr).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        // An EMPTY pin is refused too — silently degrading it to the
        // connection default would serve different bytes than the address
        // names.
        let addr = address::parse("hf://models/acme/demo/a.txt?revision=").unwrap();
        let err = config.parse_hf_address(&addr).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn addresses_outside_the_repo_are_refused() {
        let config = demo_config();
        for bad in [
            "hf://models/other/repo/a.txt",
            "hf://datasets/acme/demo/a.txt",
            "s3://models/acme/demo/a.txt",
        ] {
            let addr = address::parse(bad).unwrap();
            let err = config.parse_hf_address(&addr).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{bad}");
        }
    }

    #[test]
    fn capabilities_advertise_only_the_read_bits() {
        let mut expected = Capabilities::empty();
        expected.supports_list = true;
        expected.supports_list_stream = true;
        expected.supports_recursive_list = true;
        expected.has_real_directories = true;
        expected.supports_version_listing = true;
        expected.version_list_order = Some(VersionListOrder::Newest);
        assert_eq!(hf_capabilities(), expected);
    }

    #[test]
    fn descriptor_declares_the_huggingface_surface() {
        let descriptor = kind_descriptor();
        assert_eq!(descriptor.kind, "huggingface");
        assert!(!descriptor.supports_user_metadata);
        assert!(descriptor.supports_runtime_add);
        let token = descriptor
            .credential_schema
            .iter()
            .find(|field| field.key == "token")
            .expect("token credential field");
        assert_eq!(token.default.as_deref(), Some("${HF_TOKEN}"));
        assert_eq!(descriptor.credential_schema.len(), 1);
    }

    #[test]
    fn map_status_401_is_auth_required_with_context() {
        let err = map_status(401, None, false);
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ErrorContext::Auth { reason, .. }) => {
                assert_eq!(reason.as_deref(), Some("hf_unauthorized"));
            }
            other => panic!("expected auth context, got {other:?}"),
        }
    }

    #[test]
    fn map_status_403_is_permission_denied_no_context() {
        let err = map_status(403, None, false);
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.context().is_none());
    }

    #[test]
    fn x_error_code_header_refines_the_mapping() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-error-code", "RevisionNotFound".parse().unwrap());
        let err = map_status(404, Some(&headers), false);
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert!(err.message().contains("RevisionNotFound"));

        let mut gated = reqwest::header::HeaderMap::new();
        gated.insert("x-error-code", "GatedRepo".parse().unwrap());
        let err = map_status(403, Some(&gated), false);
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.message().contains("gated"));
    }

    #[test]
    fn a_private_repo_404_without_a_token_stays_not_found() {
        let err = map_status(404, None, true);
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert!(err.message().contains("supply a token"));
        let err = map_status(404, None, false);
        assert!(!err.message().contains("supply a token"));
    }

    #[test]
    fn status_table_matches_the_shared_convention() {
        assert_eq!(map_status(405, None, false).code(), ErrorCode::Unsupported);
        assert_eq!(
            map_status(408, None, false).code(),
            ErrorCode::DeadlineExceeded
        );
        assert_eq!(
            map_status(504, None, false).code(),
            ErrorCode::DeadlineExceeded
        );
        assert_eq!(
            map_status(416, None, false).code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            map_status(429, None, false).code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            map_status(503, None, false).code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(map_status(500, None, false).code(), ErrorCode::Transient);
        assert_eq!(map_status(599, None, false).code(), ErrorCode::Transient);
        // A JSON-API 3xx is a renamed/moved repository, reported as NotFound
        // with actionable guidance rather than a terminal Unsupported.
        let moved = map_status(307, None, false);
        assert_eq!(moved.code(), ErrorCode::NotFound);
        assert!(moved.message().contains("renamed or moved"));
        assert_eq!(map_status(100, None, false).code(), ErrorCode::Unsupported);
    }

    #[test]
    fn map_status_412_carries_the_new_etag() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("etag", "\"abc123\"".parse().unwrap());
        let err = map_status(412, Some(&headers), false);
        assert_eq!(err.code(), ErrorCode::ObjectModified);
        match err.context() {
            Some(ErrorContext::Identity { new_etag }) => {
                assert_eq!(new_etag.as_deref(), Some("abc123"));
            }
            other => panic!("expected identity context, got {other:?}"),
        }
    }

    #[test]
    fn inverted_range_is_refused_at_the_plugin_boundary() {
        let range = ByteRange {
            start: 10,
            end_inclusive: Some(3),
        };
        let err = read_range_header(Some(&range)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            read_range_header(Some(&ByteRange {
                start: 5,
                end_inclusive: None,
            }))
            .unwrap()
            .as_deref(),
            Some("bytes=5-")
        );
        assert_eq!(
            read_range_header(Some(&ByteRange {
                start: 0,
                end_inclusive: Some(9),
            }))
            .unwrap()
            .as_deref(),
            Some("bytes=0-9")
        );
    }

    #[test]
    fn if_match_compares_the_opaque_token_exactly() {
        assert!(check_etag(Some("abc"), Some("abc")).is_ok());
        assert!(check_etag(None, Some("anything")).is_ok());
        let err = check_etag(Some("abc"), Some("def")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ObjectModified);
        // A caller value spelled like a weak HTTP tag is NOT special-cased
        // into always passing — the SPI token is opaque and compared literally.
        assert!(check_etag(Some("W/abc"), Some("def")).is_err());
        assert!(check_etag(Some("W/abc"), Some("W/abc")).is_ok());
    }

    #[test]
    fn content_range_206_validates_the_selected_interval() {
        let range = ByteRange {
            start: 100,
            end_inclusive: Some(103),
        };
        // Correct 206 for a 100-103 request.
        assert_eq!(
            validate_content_range_206(Some(&"bytes 100-103/1000".to_string()), Some(&range))
                .unwrap(),
            1000
        );
        // The wrong-offset case the reviewer flagged: 0-3 for a 100-103 ask.
        let err = validate_content_range_206(Some(&"bytes 0-3/1000".to_string()), Some(&range))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        // Missing Content-Range on a 206 is a protocol violation.
        assert!(validate_content_range_206(None, Some(&range)).is_err());
        // The server may clamp the end to the object's last byte.
        let open = ByteRange {
            start: 0,
            end_inclusive: Some(4096),
        };
        assert_eq!(
            validate_content_range_206(Some(&"bytes 0-9/10".to_string()), Some(&open)).unwrap(),
            10
        );
    }

    #[test]
    fn credential_headers_are_not_republished_as_metadata() {
        let mut headers = HashMap::new();
        headers.insert("x-repo-commit".to_string(), "deadbeef".to_string());
        headers.insert("set-cookie".to_string(), "session=secret".to_string());
        headers.insert("www-authenticate".to_string(), "Bearer".to_string());
        let metadata = headers_to_metadata(headers);
        assert_eq!(
            metadata.get("x-repo-commit").map(String::as_str),
            Some("deadbeef")
        );
        assert!(!metadata.contains_key("set-cookie"));
        assert!(!metadata.contains_key("www-authenticate"));
    }

    #[test]
    fn offorigin_redirect_scheme_allowlist() {
        let allow = |url: &str| offorigin_redirect_allowed(&Url::parse(url).unwrap());
        assert!(allow("https://cdn-lfs.huggingface.co/blob"));
        // The loopback-http test seam only.
        assert!(allow("http://127.0.0.1:9099/blob"));
        assert!(allow("http://[::1]:9099/blob"));
        // Refused: file disclosure, and cleartext to non-loopback / internal.
        assert!(!allow("file:///etc/passwd"));
        assert!(!allow("http://169.254.169.254/latest/meta-data"));
        assert!(!allow("http://cdn.example/blob"));
        assert!(!allow("ftp://cdn.example/blob"));
    }

    #[test]
    fn cleartext_loopback_endpoints_bypass_the_proxy() {
        assert!(endpoint_is_cleartext_loopback("http://127.0.0.1:8080"));
        assert!(endpoint_is_cleartext_loopback("http://[::1]:8080"));
        // Not bypassed: the real https endpoint, or cleartext to a real host.
        assert!(!endpoint_is_cleartext_loopback("https://huggingface.co"));
        assert!(!endpoint_is_cleartext_loopback("http://huggingface.co"));
    }

    #[test]
    fn identity_without_content_length_leaves_size_unknown() {
        let identity = identity_from_headers(&HashMap::new(), None, None);
        assert!(identity.size.is_none());
        assert!(identity.etag.is_none());
        assert_eq!(identity.etag_strength, EtagStrength::Unspecified);
        assert!(identity.mtime.is_none());
    }

    #[test]
    fn direct_response_etag_strength_comes_from_http_syntax() {
        for (wire, expected_token, expected_strength) in [
            ("\"strong\"", "strong", EtagStrength::Strong),
            ("W/\"weak\"", "weak", EtagStrength::Weak),
            ("bare", "bare", EtagStrength::Unspecified),
        ] {
            let headers = HashMap::from([("etag".to_string(), wire.to_string())]);
            let identity = identity_from_headers(&headers, None, None);
            assert_eq!(identity.etag.as_deref(), Some(expected_token));
            assert_eq!(identity.etag_strength, expected_strength);
        }
    }
}

/// Wire-level behavior against a scripted loopback hub. These pin the
/// range/stream/pin plumbing the conformance sweep's registry scenarios do
/// not reach.
#[cfg(test)]
mod wire_tests {
    use super::*;
    use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

    fn backend_for(server: &ScriptedHttpServer, token: Option<&str>) -> HfBackend {
        backend_for_endpoint(server.endpoint(), token)
    }

    fn backend_for_endpoint(endpoint: &str, token: Option<&str>) -> HfBackend {
        let mut config = HashMap::new();
        config.insert("repo_id".into(), ConfigValue::String("acme/demo".into()));
        config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
        let config = __test_only_parse_config(&config).unwrap();
        __test_only_backend(config, token.map(|token| token.as_bytes().to_vec())).unwrap()
    }

    /// A loopback origin that answers one `resolve` GET with headers promising
    /// a large body but writes only `prefix` bytes and then holds the socket
    /// open, so `read`'s stream yields the prefix (proving it did not buffer
    /// the whole object) and then pends — the shape both the streaming and
    /// cancellation invariants need. Returns the endpoint; the listener thread
    /// keeps the connection alive until the process exits.
    fn spawn_one_chunk_then_stall(prefix: &'static [u8], promised_len: usize) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {promised_len}\r\nETag: \"e\"\r\n\r\n"
                );
                if stream.write_all(header.as_bytes()).is_err() {
                    continue;
                }
                let _ = stream.write_all(prefix);
                let _ = stream.flush();
                // Hold the body open so the stream pends after the prefix.
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        });
        endpoint
    }

    fn target(address: &str) -> ResolvedTarget {
        ResolvedTarget {
            backend_id: BackendId("huggingface:test".into()),
            resolved_address: address::parse(address).unwrap(),
        }
    }

    fn ranged(start: u64, end_inclusive: Option<u64>) -> ReadOptions {
        ReadOptions {
            range: Some(ByteRange {
                start,
                end_inclusive,
            }),
            ..ReadOptions::default()
        }
    }

    #[tokio::test]
    async fn ranged_read_uses_content_range_total_for_size() {
        let server = ScriptedHttpServer::spawn(
            CannedHttpResponse::new("206 Partial Content", "bcde")
                .with_header("Content-Range", "bytes 1-4/100")
                .with_header("ETag", "\"e1\""),
        );
        let backend = backend_for(&server, None);
        let result = backend
            .read(
                target("hf://models/acme/demo/data.bin"),
                ranged(1, Some(4)),
                None,
            )
            .await
            .unwrap();
        match result {
            ReadResult::Bytes { bytes, info } => {
                assert_eq!(bytes, b"bcde", "the 206 body is returned as-is");
                assert_eq!(info.size, Some(100), "size is the Content-Range total");
                assert_eq!(info.etag.as_deref(), Some("e1"));
                assert_eq!(info.etag_strength, EtagStrength::Strong);
            }
            other => panic!("a closed range buffers, got {other:?}"),
        }
        let raw = server.requests();
        assert!(
            ovstorage_plugin_test::request_has_header(&raw[0], "range", "bytes=1-4"),
            "the range must ride the wire: {}",
            raw[0]
        );
    }

    /// A `Range` request answered `200` is dropped with `Unsupported` before
    /// buffering — an ignored open-ended `bytes=N-` has no cap.
    #[tokio::test]
    async fn ranged_read_rejects_200_full_body() {
        for range in [ranged(0, Some(3)), ranged(5, None)] {
            let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "full body"));
            let backend = backend_for(&server, None);
            let err = backend
                .read(target("hf://models/acme/demo/data.bin"), range, None)
                .await
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::Unsupported);
        }
    }

    #[tokio::test]
    async fn open_ended_read_returns_stream_not_bytes() {
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "hello"));
        let backend = backend_for(&server, None);
        let result = backend
            .read(
                target("hf://models/acme/demo/data.bin"),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap();
        match result {
            ReadResult::Stream { mut stream, info } => {
                assert_eq!(info.size, Some(5));
                let mut drained = Vec::new();
                while let Some(chunk) = stream.next().await {
                    drained.extend_from_slice(&chunk.unwrap());
                }
                assert_eq!(drained, b"hello");
            }
            other => panic!("an open-ended read must stream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn if_match_mismatch_fails_with_object_modified_before_bytes() {
        let server = ScriptedHttpServer::spawn(
            CannedHttpResponse::new("200 OK", "hello").with_header("ETag", "\"current\""),
        );
        let backend = backend_for(&server, None);
        let err = backend
            .read(
                target("hf://models/acme/demo/data.bin"),
                ReadOptions {
                    if_match: Some("stale".into()),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ObjectModified);
        match err.context() {
            Some(ErrorContext::Identity { new_etag }) => {
                assert_eq!(new_etag.as_deref(), Some("current"));
            }
            other => panic!("expected identity context, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_over_max_bytes_is_resource_exhausted() {
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "0123456789"));
        let backend = backend_for(&server, None);
        let err = backend
            .read(
                target("hf://models/acme/demo/data.bin"),
                ReadOptions {
                    max_bytes: Some(4),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceExhausted);
    }

    /// A large closed range with a small `max_bytes` must not allocate the
    /// whole range before enforcing the cap: the buffer is bounded by
    /// `max_bytes`, and the overrun is reported.
    #[tokio::test]
    async fn a_large_closed_range_is_capped_by_max_bytes_while_buffering() {
        let body: String = "0123456789".repeat(1000); // 10_000 bytes
        let server = ScriptedHttpServer::spawn(
            CannedHttpResponse::new("206 Partial Content", body)
                .with_header("Content-Range", "bytes 0-9999/10000"),
        );
        let backend = backend_for(&server, None);
        let err = backend
            .read(
                target("hf://models/acme/demo/data.bin"),
                ReadOptions {
                    range: Some(ByteRange {
                        start: 0,
                        end_inclusive: Some(9_999),
                    }),
                    max_bytes: Some(16),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            ErrorCode::ResourceExhausted,
            "a range far larger than max_bytes is refused, not fully buffered"
        );
    }

    /// The pin selects the wire revision on every read-family endpoint.
    #[tokio::test]
    async fn pinned_revision_rides_wire_paths() {
        let server = ScriptedHttpServer::spawn_sequence(vec![
            Some(CannedHttpResponse::json(
                "200 OK",
                r#"[{"type":"file","oid":"f1","size":5,"path":"obj.txt"}]"#,
            )),
            Some(CannedHttpResponse::new("200 OK", "hello")),
            Some(CannedHttpResponse::json(
                "200 OK",
                r#"[{"type":"file","oid":"f1","size":5,"path":"obj.txt"}]"#,
            )),
        ]);
        let backend = backend_for(&server, None);
        let pinned = "hf://models/acme/demo/obj.txt?revision=abc123";
        backend
            .stat(target(pinned), StatOptions::default(), None)
            .await
            .unwrap();
        backend
            .read(target(pinned), ReadOptions::default(), None)
            .await
            .unwrap();
        backend
            .list(
                target("hf://models/acme/demo/?revision=abc123"),
                ListOptions::default(),
                None,
            )
            .await
            .unwrap();
        let raw = server.requests();
        assert!(raw[0].contains("/paths-info/abc123"), "stat: {}", raw[0]);
        assert!(
            raw[1].contains("/resolve/abc123/obj.txt"),
            "read: {}",
            raw[1]
        );
        assert!(raw[2].contains("/tree/abc123"), "list: {}", raw[2]);
    }

    /// A pinned-prefix listing emits pinned children — an unpinned child
    /// address would silently resolve to head.
    #[tokio::test]
    async fn a_pinned_list_emits_pinned_children() {
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            r#"[
                {"type":"directory","oid":"d1","size":0,"path":"team"},
                {"type":"file","oid":"a1","size":3,"path":"a.txt"}
            ]"#,
        ));
        let backend = backend_for(&server, None);
        let items = backend
            .list(
                target("hf://models/acme/demo/?revision=abc123"),
                ListOptions::default(),
                None,
            )
            .await
            .unwrap();
        let addresses: Vec<&str> = items.iter().map(|item| item.address.as_str()).collect();
        assert_eq!(
            addresses,
            vec![
                "hf://models/acme/demo/team/?revision=abc123",
                "hf://models/acme/demo/a.txt?revision=abc123",
            ]
        );
    }

    /// A slashed-ref pin re-encodes under the children's form-urlencoding
    /// (`refs/pr/1` → `refs%2Fpr%2F1`), so the containment guard must compare
    /// against the normalized spelling — not the caller's raw one — or every
    /// child of the pinned prefix is dropped.
    #[tokio::test]
    async fn a_pinned_list_with_a_slashed_ref_keeps_its_children() {
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            r#"[{"type":"file","oid":"a1","size":3,"path":"a.txt"}]"#,
        ));
        let backend = backend_for(&server, None);
        let items = backend
            .list(
                target("hf://models/acme/demo/?revision=refs/pr/1"),
                ListOptions::default(),
                None,
            )
            .await
            .unwrap();
        let addresses: Vec<&str> = items.iter().map(|item| item.address.as_str()).collect();
        assert_eq!(
            addresses,
            vec!["hf://models/acme/demo/a.txt?revision=refs%2Fpr%2F1"],
            "children survive the containment guard and carry the pin"
        );
        let raw = server.requests();
        assert!(raw[0].contains("/tree/refs%2Fpr%2F1"), "wire: {}", raw[0]);
    }

    /// A same-origin (often relative) resolve redirect — the non-LFS
    /// resolve-cache path on the real Hub — is followed in-plugin, rebuilding
    /// the request so the bearer rides every hop.
    #[tokio::test]
    async fn a_relative_same_origin_redirect_is_followed_with_the_bearer() {
        let server = ScriptedHttpServer::spawn_sequence(vec![
            Some(
                CannedHttpResponse::new("307 Temporary Redirect", "")
                    .with_header("Location", "/api/resolve-cache/acme/demo/blob"),
            ),
            Some(CannedHttpResponse::new("200 OK", "hello").with_header("ETag", "\"e1\"")),
        ]);
        let backend = backend_for(&server, Some("hf_tok"));
        let result = backend
            .read(
                target("hf://models/acme/demo/config.json"),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap();
        match result {
            ReadResult::Stream { mut stream, info } => {
                assert_eq!(info.size, Some(5));
                let mut drained = Vec::new();
                while let Some(chunk) = stream.next().await {
                    drained.extend_from_slice(&chunk.unwrap());
                }
                assert_eq!(drained, b"hello");
            }
            other => panic!("the followed read must stream, got {other:?}"),
        }
        let raw = server.requests();
        assert_eq!(raw.len(), 2, "resolve + followed hop: {raw:?}");
        assert!(
            raw[1].starts_with("GET /api/resolve-cache/acme/demo/blob"),
            "the relative Location resolves against the origin: {}",
            raw[1]
        );
        assert!(
            ovstorage_plugin_test::request_has_header(&raw[1], "authorization", "Bearer hf_tok"),
            "the bearer rides the same-origin hop: {}",
            raw[1]
        );
    }

    #[tokio::test]
    async fn a_same_origin_redirect_loop_fails_after_the_hop_cap() {
        // The single-response script repeats its tail, so every request
        // answers the same relative redirect.
        let server = ScriptedHttpServer::spawn(
            CannedHttpResponse::new("302 Found", "").with_header("Location", "/loop"),
        );
        let backend = backend_for(&server, None);
        let err = backend
            .read(
                target("hf://models/acme/demo/config.json"),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Transient);
        assert_eq!(
            server.hits() as u32,
            MAX_RESOLVE_HOPS + 1,
            "the chain is bounded"
        );
    }

    #[tokio::test]
    async fn commits_map_to_a_newest_first_version_page() {
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            r#"[
                {"id":"c2","title":"newer","date":"2026-02-02T00:00:00.000Z",
                 "authors":[{"user":"alice"}]},
                {"id":"c1","title":"older","date":"2026-01-01T00:00:00.000Z","authors":[]}
            ]"#,
        ));
        let backend = backend_for(&server, None);
        let versions = backend
            .list_versions(
                target("hf://models/acme/demo/obj.txt"),
                ListVersionsOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(
            versions[0].address.as_str(),
            "hf://models/acme/demo/obj.txt?revision=c2"
        );
        assert_eq!(versions[0].version.as_deref(), Some("c2"));
        assert_eq!(versions[0].modified_by.as_deref(), Some("alice"));
        assert!(versions[0].mtime.is_some());
        assert!(
            versions[0].etag.is_none() && versions[0].size.is_none(),
            "per-commit file facts are unknown and never fabricated"
        );
        assert_eq!(
            versions[1].address.as_str(),
            "hf://models/acme/demo/obj.txt?revision=c1"
        );
        for version in &versions {
            assert_eq!(
                version.versioned_address.as_ref(),
                Some(&version.address),
                "a version's own address is already the pin"
            );
        }
        // The caller's own pin never compresses OR filters the history: the
        // walk always starts from the connection's default revision (a sha
        // pin's ancestry would omit every commit newer than it).
        let pinned = backend
            .list_versions(
                target("hf://models/acme/demo/obj.txt?revision=c1"),
                ListVersionsOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(pinned.len(), 2);
        let raw = server.requests();
        assert!(
            raw[1].contains("/commits/main"),
            "the walk ignores the address pin: {}",
            raw[1]
        );
    }

    #[tokio::test]
    async fn get_latest_version_pins_the_head_sha() {
        let server = ScriptedHttpServer::spawn_sequence(vec![
            Some(CannedHttpResponse::json("200 OK", r#"{"sha":"deadbeef"}"#)),
            Some(CannedHttpResponse::json(
                "200 OK",
                r#"[{"type":"file","oid":"f1","size":5,"path":"obj.txt"}]"#,
            )),
        ]);
        let backend = backend_for(&server, None);
        let info = backend
            .get_latest_version(target("hf://models/acme/demo/obj.txt"), None)
            .await
            .unwrap();
        assert_eq!(
            info.address.as_str(),
            "hf://models/acme/demo/obj.txt?revision=deadbeef",
            "an unpinned input gains the resolved sha"
        );
        assert_eq!(info.version.as_deref(), Some("deadbeef"));
        assert_eq!(
            info.versioned_address.as_ref(),
            Some(&info.address),
            "the pinned address is also the versioned address"
        );
    }

    const LAST_COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    /// Under the flag, stat asks the Hub for commit facts and pins the entry
    /// to the commit that last touched it, replacing any ref the caller spelled.
    #[tokio::test]
    async fn stat_with_versioned_address_sends_expand_and_pins_the_last_commit() {
        let body = format!(
            r#"[{{"type":"file","oid":"f1","size":5,"path":"obj.txt","lastCommit":{{"id":"{LAST_COMMIT_SHA}","title":"t","date":"2026-01-01T00:00:00.000Z"}}}}]"#
        );
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", body));
        let backend = backend_for(&server, None);
        let flagged = StatOptions {
            versioned_address: true,
            ..StatOptions::default()
        };
        let pinned = format!("hf://models/acme/demo/obj.txt?revision={LAST_COMMIT_SHA}");

        let info = backend
            .stat(
                target("hf://models/acme/demo/obj.txt"),
                flagged.clone(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            info.versioned_address.as_ref().map(Url::as_str),
            Some(pinned.as_str())
        );
        assert_eq!(
            info.address.as_str(),
            "hf://models/acme/demo/obj.txt",
            "the address itself is untouched"
        );

        // A ref pin selects the wire revision but can move, so the answer
        // still pins the commit.
        let info = backend
            .stat(
                target("hf://models/acme/demo/obj.txt?revision=main"),
                flagged.clone(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            info.versioned_address.as_ref().map(Url::as_str),
            Some(pinned.as_str())
        );

        // An immutable sha the caller already spelled is the pin, whatever
        // commit the expanded entry reports.
        let caller_sha = "fedcba9876543210fedcba9876543210fedcba98";
        let info = backend
            .stat(
                target(&format!(
                    "hf://models/acme/demo/obj.txt?revision={caller_sha}"
                )),
                flagged,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            info.versioned_address.as_ref().map(Url::as_str),
            Some(format!("hf://models/acme/demo/obj.txt?revision={caller_sha}").as_str())
        );

        let raw = server.requests();
        assert_eq!(raw.len(), 3);
        for request in &raw {
            assert!(
                request.contains(r#""expand":true"#),
                "the flag sends expand: {request}"
            );
        }
    }

    /// Without the flag the Hub is not asked for commit facts, so the only pin
    /// that can be reported is one the caller already spelled, and only when
    /// it is immutable: a sha is echoed, a ref is not.
    #[tokio::test]
    async fn stat_without_the_flag_echoes_only_an_immutable_sha_pin() {
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            r#"[{"type":"file","oid":"f1","size":5,"path":"obj.txt"}]"#,
        ));
        let backend = backend_for(&server, None);
        let sha_pinned = format!("hf://models/acme/demo/obj.txt?revision={LAST_COMMIT_SHA}");
        let cases: [(&str, Option<&str>); 4] = [
            (sha_pinned.as_str(), Some(sha_pinned.as_str())),
            ("hf://models/acme/demo/obj.txt?revision=refs/pr/1", None),
            ("hf://models/acme/demo/obj.txt?revision=main", None),
            ("hf://models/acme/demo/obj.txt", None),
        ];
        for (address, expected) in cases {
            let info = backend
                .stat(target(address), StatOptions::default(), None)
                .await
                .unwrap();
            assert_eq!(
                info.versioned_address.as_ref().map(Url::as_str),
                expected,
                "{address}"
            );
        }
        for request in server.requests() {
            assert!(
                request.contains(r#""expand":false"#),
                "no flag, no expand: {request}"
            );
        }
    }

    /// A flagged listing pins each file to its last commit and asks the Hub
    /// for commit facts on the tree walk; directories carry no pin.
    #[tokio::test]
    async fn list_with_versioned_address_pins_files_and_leaves_directories_none() {
        let body = format!(
            r#"[
                {{"type":"directory","oid":"d1","size":0,"path":"team","lastCommit":{{"id":"{LAST_COMMIT_SHA}"}}}},
                {{"type":"file","oid":"a1","size":3,"path":"a.txt","lastCommit":{{"id":"{LAST_COMMIT_SHA}"}}}}
            ]"#
        );
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", body));
        let backend = backend_for(&server, None);
        let flagged = ListOptions {
            versioned_address: true,
            ..ListOptions::default()
        };
        let pinned = format!("hf://models/acme/demo/a.txt?revision={LAST_COMMIT_SHA}");

        let items = backend
            .list(target("hf://models/acme/demo/"), flagged.clone(), None)
            .await
            .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind, ObjectKind::Directory);
        assert_eq!(items[0].versioned_address, None);
        assert_eq!(
            items[1].versioned_address.as_ref().map(Url::as_str),
            Some(pinned.as_str())
        );

        // The streamed walk asks for the same facts.
        let mut stream = backend
            .list_stream(target("hf://models/acme/demo/"), flagged, None)
            .await
            .unwrap();
        let mut streamed = Vec::new();
        while let Some(item) = stream.next().await {
            streamed.push(item.unwrap());
        }
        assert_eq!(streamed.len(), 2);
        assert_eq!(streamed[0].versioned_address, None);
        assert_eq!(
            streamed[1].versioned_address.as_ref().map(Url::as_str),
            Some(pinned.as_str())
        );

        let raw = server.requests();
        assert_eq!(raw.len(), 2);
        for request in &raw {
            assert!(
                request.contains("expand=true"),
                "the flag sends expand: {request}"
            );
        }
    }

    #[tokio::test]
    async fn get_latest_version_resolves_a_mutable_pin_to_the_immutable_sha() {
        let server = ScriptedHttpServer::spawn_sequence(vec![
            Some(CannedHttpResponse::json("200 OK", r#"{"sha":"deadbeef"}"#)),
            Some(CannedHttpResponse::json(
                "200 OK",
                r#"[{"type":"file","oid":"f1","size":5,"path":"obj.txt"}]"#,
            )),
        ]);
        let backend = backend_for(&server, None);
        let info = backend
            .get_latest_version(target("hf://models/acme/demo/obj.txt?revision=v1.0"), None)
            .await
            .unwrap();
        assert_eq!(
            info.address.as_str(),
            "hf://models/acme/demo/obj.txt?revision=deadbeef",
            "a mutable ref pin is resolved to the immutable sha it names now"
        );
        assert_eq!(info.version.as_deref(), Some("deadbeef"));
        let raw = server.requests();
        assert!(
            raw[0].contains("/revision/v1.0"),
            "resolves the caller ref: {}",
            raw[0]
        );
        assert!(
            raw[1].contains("/paths-info/deadbeef"),
            "reads the entry AT the resolved sha, not the mutable ref: {}",
            raw[1]
        );
    }

    #[tokio::test]
    async fn pinned_nonexistent_revision_maps_to_not_found() {
        let server = ScriptedHttpServer::spawn(
            CannedHttpResponse::new("404 Not Found", "")
                .with_header("x-error-code", "RevisionNotFound"),
        );
        let backend = backend_for(&server, None);
        let err = backend
            .get_latest_version(target("hf://models/acme/demo/obj.txt?revision=gone"), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert!(err.message().contains("RevisionNotFound"));
    }

    #[tokio::test]
    async fn read_on_a_directory_address_is_invalid_argument() {
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
        let backend = backend_for(&server, None);
        for address in ["hf://models/acme/demo/", "hf://models/acme/demo/weights/"] {
            let err = backend
                .read(target(address), ReadOptions::default(), None)
                .await
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{address}");
        }
        assert_eq!(server.hits(), 0, "refused before the wire");
    }

    #[tokio::test]
    async fn stat_on_a_directory_reports_directory_kind() {
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::json(
            "200 OK",
            r#"[{"type":"directory","oid":"d1","size":0,"path":"weights"}]"#,
        ));
        let backend = backend_for(&server, None);
        // The trailing slash is a hint; paths-info answers the real kind for
        // either spelling.
        let info = backend
            .stat(
                target("hf://models/acme/demo/weights/"),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(info.kind, ObjectKind::Directory);
        assert_eq!(info.size, None);
        let raw = server.requests();
        assert!(
            raw[0].contains("\"weights\""),
            "the lookup path drops the trailing slash: {}",
            raw[0]
        );
    }

    #[tokio::test]
    async fn stat_on_the_repo_root_is_a_directory_with_the_head_sha() {
        let server =
            ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", r#"{"sha":"deadbeef"}"#));
        let backend = backend_for(&server, None);
        let info = backend
            .stat(
                target("hf://models/acme/demo/"),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(info.kind, ObjectKind::Directory);
        assert_eq!(info.version.as_deref(), Some("deadbeef"));
        let raw = server.requests();
        assert!(raw[0].contains("/revision/main"), "repo info: {}", raw[0]);
    }

    #[tokio::test]
    async fn reqwest_error_message_carries_no_request_url() {
        // Unroutable port: the connect error's Display would append the URL
        // (path and query included) unless `.without_url()` strips it.
        let client = build_http_client(true).unwrap();
        let err = client
            .get("http://127.0.0.1:9/secret-path?token=hush")
            .send()
            .await
            .expect_err("port 9 must refuse");
        let mapped = map_reqwest_error(err);
        assert_eq!(mapped.code(), ErrorCode::Transient);
        assert!(
            !mapped.message().contains("secret-path") && !mapped.message().contains("hush"),
            "the URL must not reach the message: {}",
            mapped.message()
        );
    }

    /// The read seam yields its first bytes before the whole object arrives —
    /// proving `read` streams rather than buffering. The origin promises a
    /// large body but sends only a prefix and stalls; if `read` buffered, this
    /// would hang instead of yielding the prefix.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_yields_before_the_body_is_complete() {
        let endpoint = spawn_one_chunk_then_stall(b"first-chunk", 1_000_000);
        let backend = backend_for_endpoint(&endpoint, None);
        let result = backend
            .read(
                target("hf://models/acme/demo/big.bin"),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap();
        let ReadResult::Stream { mut stream, info } = result else {
            panic!("a whole-object read must stream");
        };
        assert_eq!(info.size, Some(1_000_000), "size is the promised total");
        let first = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("read must yield the prefix without waiting for the whole body")
            .expect("a chunk arrives")
            .expect("the chunk is not an error");
        assert_eq!(&first[..], b"first-chunk");
    }

    /// Host cancellation drives all the way through `HfBackend::read`: the
    /// origin yields one prefix then stalls, and the cancel surfaces as
    /// `Cancelled` on the next poll rather than hanging.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_stream_surfaces_cancel_after_the_first_chunk() {
        let endpoint = spawn_one_chunk_then_stall(b"prefix", 1_000_000);
        let backend = backend_for_endpoint(&endpoint, None);
        let token = CancellationToken::new();
        let result = backend
            .read(
                target("hf://models/acme/demo/big.bin"),
                ReadOptions::default(),
                Some(token.clone()),
            )
            .await
            .unwrap();
        let ReadResult::Stream { mut stream, .. } = result else {
            panic!("a whole-object read must stream");
        };
        let first = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("the prefix arrives promptly")
            .expect("a chunk arrives")
            .expect("the chunk is not an error");
        assert_eq!(&first[..], b"prefix");
        token.cancel();
        let next = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("cancel must wake the stalled stream")
            .expect("cancel yields an item");
        assert_eq!(next.unwrap_err().code(), ErrorCode::Cancelled);
    }
}
