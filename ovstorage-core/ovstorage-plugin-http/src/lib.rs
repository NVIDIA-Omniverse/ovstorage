// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

mod credentials;
mod read_helpers;
mod redirect;
mod redirect_follower;
mod retry;

#[cfg(test)]
use credentials::credential_header;
use credentials::{
    CredentialShape, HttpCredentials, SignedQueryScope, apply_credential_headers,
    parse_signed_query_scope, resolve_credentials, sign_url, strip_held_query,
};

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use parking_lot::RwLock;

use ovstorage_plugin::address;
use ovstorage_plugin::*;
use ovstorage_plugin::{ReadResult, race_cancel};

pub struct HttpBackend {
    client: Arc<reqwest::Client>,
    /// Requests carrying a bearer always use a same-origin redirect policy,
    /// independent of the operator's anonymous redirect allow-list.
    credentialed_client: Arc<reqwest::Client>,
    allow_range_stat_fallback: bool,
    root_url: Option<Url>,
    prefix: Option<Url>,
    /// One atomic credential snapshot. An operation clones the `Arc` once and
    /// uses it for every request and redirect hop it issues.
    credentials: RwLock<Arc<HttpCredentials>>,
    /// Serialize async validate/probe/swap rotations without blocking reads.
    rotation_guard: tokio::sync::Mutex<()>,
    signed_query_scope: Option<SignedQueryScope>,
    credential_shape: ConnectionCredentialShape,
    /// The configured redirect follow set. `None` means never follow.
    redirects: Option<FollowScope>,
    /// Includes bundle credentials, root userinfo, and pinned default headers.
    /// Any of them must keep an HTTPS request from downgrading to cleartext.
    carries_secret_on_wire: bool,
}

/// Everything about a connection's credential channels that rotation may not
/// change. Root userinfo lives in configuration rather than the bundle, but is
/// included explicitly so the invariant has one named representation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ConnectionCredentialShape {
    bundle: CredentialShape,
    root_userinfo: bool,
}

impl HttpBackend {
    pub fn capabilities() -> Capabilities {
        Capabilities::empty()
    }

    pub fn new() -> Self {
        Self {
            client: Arc::new(default_client()),
            credentialed_client: Arc::new(default_credentialed_client()),
            allow_range_stat_fallback: false,
            root_url: None,
            prefix: None,
            credentials: RwLock::new(Arc::new(HttpCredentials::default())),
            rotation_guard: tokio::sync::Mutex::new(()),
            signed_query_scope: None,
            credential_shape: ConnectionCredentialShape {
                bundle: HttpCredentials::default().shape(),
                root_userinfo: false,
            },
            redirects: Some(FollowScope::SameOrigin),
            carries_secret_on_wire: false,
        }
    }

    fn physical_url(&self, dispatch_url: &Url) -> Result<Url> {
        match (self.prefix.as_ref(), self.root_url.as_ref()) {
            (Some(prefix), Some(root)) if prefix != root => {
                // Nothing of the route's own is spliced onto the result.
                // `root_url` and `prefix` are configuration addresses and both
                // are refused a query at load (`config_url`), so projection
                // carries only the caller's query. A held `signed_query` is a
                // credential and is appended later by `sign_url`, after this
                // address-space rewrite.
                address::replace_prefix(dispatch_url, prefix, root)
            }
            // The identity arm needs the userinfo strip, and that is not
            // symmetry with the projection arm — it is the same fact read the
            // other way. Routing compares scheme, host, port and path, so an
            // address carrying caller-chosen credentials reaches a connection
            // whose published prefix has none. This arm is reached when
            // `prefix == root`, and a prefix never carries userinfo (an
            // explicit one is refused at `default_prefix`, a defaulted one is
            // stripped there), so the root has none either: any credential on
            // the URL that leaves here is the CALLER's, and `request` hands
            // this string to reqwest, which lifts URL userinfo into
            // `Authorization: Basic` and sends it from the broker's network
            // position. The projection arm needs no equivalent because
            // `replace_prefix` builds its answer from the root.
            //
            // Stripping rather than refusing is what this branch's model
            // says: userinfo is not part of what an address names, so it is
            // not part of what goes on the wire either.
            _ => Ok(address::wire_address(dispatch_url)),
        }
    }
}

impl Default for HttpBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
pub struct HttpBackendFactory;

/// A freshly-instantiated HTTP connection: the concrete backend plus the
/// metadata [`HttpBackendLayer`] needs to build a `Connection` and its
/// `RootInfo`s.
struct InstantiatedBackend {
    backend_id: BackendId,
    backend: Arc<HttpBackend>,
    address_roots: Vec<AddressRoot>,
    display_name: Option<String>,
    auth_state: ConnectionAuthState,
    /// `None` when no probe reached an origin, so `Connection.last_probed`
    /// never claims one that did not happen.
    probed_at: Option<SystemTime>,
}

// Connection lifecycle methods driven by `HttpBackendLayer` below.
impl HttpBackendFactory {
    pub(crate) fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "http".into(),
            display_name: "HTTP".into(),
            description: Some("Read-only HTTP / HTTPS object access".into()),
            config_schema: vec![
                ConfigField {
                    key: "root_url".into(),
                    display_name: "Root URL".into(),
                    kind: ConfigFieldKind::Url,
                    required: true,
                    default: None,
                    help: Some("HTTP(S) URL prefix served by this connection".into()),
                    example: Some("https://cdn.example.com/assets/".into()),
                    group: None,
                    advanced: false,
                },
                ConfigField {
                    key: "prefix".into(),
                    display_name: "Address prefix".into(),
                    kind: ConfigFieldKind::Url,
                    required: false,
                    default: None,
                    help: Some(
                        "Optional caller-facing route prefix; defaults to root_url with its \
                         userinfo removed. It must not carry a query or a fragment, and \
                         neither may root_url"
                            .into(),
                    ),
                    example: None,
                    group: None,
                    advanced: true,
                },
                ConfigField {
                    key: "redirect_policy".into(),
                    display_name: "Redirect policy".into(),
                    kind: ConfigFieldKind::Text,
                    required: false,
                    default: Some(ConfigValue::String("same_origin".into())),
                    help: Some(
                        "How HTTP redirects are handled: 'none' surfaces them as errors, 'same_origin' follows only same-host redirects, 'allow_list' follows hosts in redirect_allow_hosts."
                            .into(),
                    ),
                    example: Some("same_origin".into()),
                    group: None,
                    advanced: true,
                },
                ConfigField {
                    key: "redirect_allow_hosts".into(),
                    display_name: "Redirect allow-list".into(),
                    kind: ConfigFieldKind::Text,
                    required: false,
                    default: None,
                    help: Some(
                        "Comma-separated host names. Only consulted when redirect_policy = 'allow_list'."
                            .into(),
                    ),
                    example: None,
                    group: None,
                    advanced: true,
                },
                ConfigField {
                    key: "default_headers".into(),
                    display_name: "Default headers".into(),
                    kind: ConfigFieldKind::Text,
                    required: false,
                    default: None,
                    help: Some(
                        "Comma-separated 'Name=Value' pairs sent with every request. Authorization, Cookie, and Proxy-Authorization are rejected at config time."
                            .into(),
                    ),
                    example: Some("X-User-Agent=ovstorage,X-Tenant=corp".into()),
                    group: None,
                    advanced: true,
                },
                ConfigField {
                    key: "signed_query_scope".into(),
                    display_name: "Signed query scope".into(),
                    kind: ConfigFieldKind::Enum {
                        source: EnumSource::Static(vec!["prefix".into(), "object".into()]),
                    },
                    required: false,
                    default: None,
                    help: Some(
                        "Scope family of the signed_query credential. 'prefix' means the token authorizes everything under root_url; 'object' names a per-object presign, which this connection-wide channel refuses."
                            .into(),
                    ),
                    example: Some("prefix".into()),
                    group: None,
                    advanced: false,
                },
                ConfigField {
                    key: "allow_range_stat_fallback".into(),
                    display_name: "Allow range-fallback stat".into(),
                    kind: ConfigFieldKind::Bool,
                    required: false,
                    default: Some(ConfigValue::Bool(false)),
                    help: Some(
                        "When the origin returns 405 to a HEAD, fall back to a single-byte ranged GET to compute identity headers."
                            .into(),
                    ),
                    example: Some("true".into()),
                    group: None,
                    advanced: true,
                },
            ],
            // Field names follow nucleus (`username` / `password`) so a host
            // UI prompts with one vocabulary across plugins. `bearer_token`
            // is spelled out rather than reusing nucleus's `api_token`
            // because the wire scheme is literally RFC 6750
            // `Authorization: Bearer`.
            //
            // No `default: Some("${ENV}")`. S3 and Azure carry env defaults
            // because a universally-agreed variable exists; there is none for
            // "the token for arbitrary HTTP origin X", and this plugin can be
            // routed at any host, so an ambient pickup would be an
            // exfiltration hazard.
            credential_schema: vec![
                CredentialField {
                    key: "bearer_token".into(),
                    display_name: "Bearer token".into(),
                    default: None,
                    help: Some(
                        "Token sent as 'Authorization: Bearer <token>' to the root_url origin."
                            .into(),
                    ),
                    advanced: false,
                },
                CredentialField {
                    key: "username".into(),
                    display_name: "Username".into(),
                    default: None,
                    help: Some("Username for HTTP Basic authentication.".into()),
                    advanced: false,
                },
                CredentialField {
                    key: "password".into(),
                    display_name: "Password".into(),
                    default: None,
                    help: Some("Password for HTTP Basic authentication.".into()),
                    advanced: false,
                },
                CredentialField {
                    key: "signed_query".into(),
                    display_name: "Signed query".into(),
                    default: None,
                    help: Some(
                        "Prefix-scoped query string appended byte-for-byte to every request; signed_query_scope is required."
                            .into(),
                    ),
                    advanced: false,
                },
                CredentialField {
                    key: "secret_headers".into(),
                    display_name: "Secret headers".into(),
                    default: None,
                    help: Some(
                        "Credential-bearing headers, one 'Name: Value' per line. Authority, framing, Range, and If-Match headers are refused."
                            .into(),
                    ),
                    advanced: false,
                },
            ],
            credential_methods: vec![
                CredentialMethod {
                    key: "bearer".into(),
                    display_name: "Bearer token".into(),
                    fields: vec!["bearer_token".into()],
                    help: Some("Send a pre-obtained token as an RFC 6750 bearer.".into()),
                    advanced: false,
                },
                CredentialMethod {
                    key: "basic".into(),
                    display_name: "Username and password".into(),
                    fields: vec!["username".into(), "password".into()],
                    help: Some("Send RFC 7617 HTTP Basic credentials.".into()),
                    advanced: false,
                },
                CredentialMethod {
                    key: "signed_query".into(),
                    display_name: "Signed query".into(),
                    fields: vec!["signed_query".into()],
                    help: Some("Present a pre-issued prefix-scoped signed query.".into()),
                    advanced: false,
                },
                CredentialMethod {
                    key: "secret_headers".into(),
                    display_name: "Secret headers".into(),
                    fields: vec!["secret_headers".into()],
                    help: Some("Present an explicit set of secret-bearing headers.".into()),
                    advanced: false,
                },
            ],
            icon: None,
            supports_runtime_add: true,
            // Read-only: every mutating verb is the `Layer` trait's
            // `Unsupported` default, and `stat` reports an always-empty
            // `user_metadata`. There is no write for a stamp to ride on.
            supports_user_metadata: false,
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "http", op = "instantiate"))]
    pub(crate) async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<InstantiatedBackend> {
        let root_url = config_url(&request.config, "root_url")?;
        validate_physical_scheme(&root_url)?;
        let signed_query_scope = config_string(&request.config, "signed_query_scope")?
            .as_deref()
            .map(parse_signed_query_scope)
            .transpose()?;
        let credentials = resolve_credentials(&request.credentials, signed_query_scope, &root_url)?;
        validate_credential_conflict(&root_url, &credentials)?;
        // Userinfo is an older credential channel the transport turns into a
        // Basic Authorization header. It participates in every wire-security
        // decision even though it is not part of the SecretBundle.
        let root_userinfo = url_carries_userinfo(&root_url);
        let carries_wire_auth = !credentials.is_anonymous() || root_userinfo;
        if carries_wire_auth {
            validate_credential_transport(&root_url)?;
        }
        let prefix = default_prefix(&request.config, &root_url)?;
        let redirect_policy = config_string_opt(&request.config, "redirect_policy")
            .unwrap_or_else(|| "same_origin".into());
        let redirect_allow_hosts = config_string_opt(&request.config, "redirect_allow_hosts");
        let default_headers = parse_default_headers(
            config_string_opt(&request.config, "default_headers").as_deref(),
        )?;
        let allow_range_stat_fallback = matches!(
            request.config.get("allow_range_stat_fallback"),
            Some(ConfigValue::Bool(true))
        );
        let redirects = redirect_scope(&redirect_policy, redirect_allow_hosts.as_deref())?;
        let carries_secret_on_wire =
            carries_secret_on_the_wire(carries_wire_auth, &default_headers);
        // The cleartext exemption is granted because a loopback destination
        // never leaves the machine — but reqwest honours `HTTP_PROXY` by
        // default (`auto_sys_proxy`), and a proxied cleartext request carries
        // `Authorization` in absolute form to a host that is not loopback at
        // all. Make the exemption mean what it claims.
        let bypass_proxy =
            carries_wire_auth && root_url.scheme() == "http" && is_loopback_host(&root_url);
        // Probe on a client of its own, built and dropped before the retained
        // one, so a cancelled or refused bring-up costs nothing further.
        //
        // It follows the configured policy intersected with same-origin: the
        // transport keeps `Authorization` across a same-origin hop, so such a
        // chain stays attributable and `301 /files` -> `/files/` still
        // resolves, while the intersection keeps the probe from establishing a
        // credential through a hop an ordinary read would refuse.
        let (auth_state, probed_at) = if carries_wire_auth {
            let probe_client = build_client(bypass_proxy, default_headers.clone())?;
            probe_credential(
                &probe_client,
                &root_url,
                &credentials,
                redirects.as_ref(),
                cancel,
            )
            .await?
        } else {
            (ConnectionAuthState::Anonymous, None)
        };
        // Bearer-carrying requests always bypass a process-wide HTTP proxy:
        // the loopback cleartext exemption a bearer may be granted means
        // nothing if the proxy receives the header first. Same manual
        // redirect policy and pinned headers as the retained client.
        let credentialed_client = build_client(true, default_headers.clone())?;
        let client = build_client(bypass_proxy, default_headers)?;
        let credential_shape = ConnectionCredentialShape {
            bundle: credentials.shape(),
            root_userinfo,
        };

        let backend = Arc::new(HttpBackend {
            client: Arc::new(client),
            credentialed_client: Arc::new(credentialed_client),
            allow_range_stat_fallback,
            root_url: Some(root_url),
            prefix: Some(prefix.clone()),
            credentials: RwLock::new(Arc::new(credentials)),
            rotation_guard: tokio::sync::Mutex::new(()),
            signed_query_scope,
            credential_shape,
            redirects,
            carries_secret_on_wire,
        });
        Ok(InstantiatedBackend {
            backend_id: BackendId(format!("http:{prefix}")),
            backend,
            address_roots: vec![AddressRoot {
                address: prefix,
                display_name: None,
                backend_kind: "http".into(),
                connection_id: None,
                capabilities: HttpBackend::capabilities(),
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }],
            display_name: request.display_name.clone().or_else(|| Some("http".into())),
            auth_state,
            probed_at,
        })
    }
}

// Object operations routed by `HttpBackendLayer`. The HTTP backend is
// read-only: it supports only `stat` and `read`, and every other Layer slot
// keeps its default.
impl HttpBackend {
    #[cfg(test)]
    async fn stat(
        &self,
        target: ResolvedTarget,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.stat_with_bearer(target, opts, None, cancel).await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "http", op = "stat"))]
    async fn stat_with_bearer(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        bearer: Option<SecretBytes>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let client = if bearer.is_some() {
            self.credentialed_client.clone()
        } else {
            self.client.clone()
        };
        let allow_fallback = self.allow_range_stat_fallback;
        let physical = self.physical_url(&target.resolved_address)?;
        validate_credentialed_origin(&physical, bearer.as_ref())?;
        let credentials = self.credentials.read().clone();
        let redirects = self.redirects.clone();
        let carries_secret_on_wire = self.carries_secret_on_wire;
        race_cancel(cancel.as_ref(), async move {
            let context = HttpRequestContext {
                client: &client,
                credentials: &credentials,
                redirects: redirects.as_ref(),
                carries_secret_on_wire,
            };
            let head = request(
                &context,
                "HEAD",
                &physical,
                RequestHeaders {
                    authorization: bearer.clone(),
                    ..RequestHeaders::default()
                },
                None,
            )
            .await;
            let response = match head {
                Ok(response) => response,
                Err(err) if allow_fallback && is_method_not_allowed(&err) => {
                    let resp = request(
                        &context,
                        "GET",
                        &physical,
                        RequestHeaders {
                            range: Some("bytes=0-0".to_string()),
                            authorization: bearer,
                            ..RequestHeaders::default()
                        },
                        Some(2),
                    )
                    .await?;
                    if resp.status == 200 {
                        return Err(Error::new(
                            ErrorCode::Unsupported,
                            "HTTP origin ignored Range during stat fallback (returned 200 OK)",
                        ));
                    }
                    resp
                }
                Err(err) => return Err(err),
            };
            let total = parse_content_range_total(response.headers.get("content-range"));
            let identity =
                identity_from_headers(&response.headers, Some(response.body.len() as u64), total);
            Ok(ObjectInfo {
                address: target.resolved_address,
                kind: ObjectKind::File,
                etag: identity.etag,
                version: None,
                size: identity.size,
                mtime: identity.mtime,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: Some(headers_to_metadata(response.headers)),
                user_metadata: Some(UserMetadata::new()),
                modified_by: None,
            })
        })
        .await
    }

    #[cfg(test)]
    async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.read_with_bearer(target, opts, None, cancel).await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "http", op = "read"))]
    async fn read_with_bearer(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        bearer: Option<SecretBytes>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let client = if bearer.is_some() {
            self.credentialed_client.clone()
        } else {
            self.client.clone()
        };
        let physical = self.physical_url(&target.resolved_address)?;
        validate_credentialed_origin(&physical, bearer.as_ref())?;
        let credentials = self.credentials.read().clone();
        let redirects = self.redirects.clone();
        let carries_secret_on_wire = self.carries_secret_on_wire;
        let stream_cancel = cancel.clone();
        race_cancel(cancel.as_ref(), async move {
            let context = HttpRequestContext {
                client: &client,
                credentials: &credentials,
                redirects: redirects.as_ref(),
                carries_secret_on_wire,
            };
            let range = opts.range.as_ref().map(|range| {
                let end = range
                    .end_inclusive
                    .map(|end| end.to_string())
                    .unwrap_or_default();
                format!("bytes={}-{}", range.start, end)
            });
            // The SPI etag is the opaque token (already stripped of
            // `W/` and quotes by `strip_etag_wire_form` on stat). Re-add
            // RFC 7232 quoting for the wire.
            let if_match = opts.if_match.as_deref().map(|etag| format!("\"{etag}\""));
            let open_ended = opts
                .range
                .as_ref()
                .is_none_or(|r| r.end_inclusive.is_none());
            if open_ended {
                let (info, stream) = request_streaming(
                    &context,
                    &physical,
                    target.resolved_address.clone(),
                    RequestHeaders {
                        range: range.clone(),
                        if_match,
                        authorization: bearer,
                    },
                    stream_cancel,
                )
                .await?;
                check_etag(opts.if_match.as_deref(), info.etag.as_deref())?;
                return Ok(ReadResult::Stream { stream, info });
            }
            let budget = opts.range.as_ref().map(|r| {
                r.end_inclusive
                    .map(|end| end.saturating_sub(r.start).saturating_add(1))
                    .unwrap_or(u64::MAX)
            });
            let response = request(
                &context,
                "GET",
                &physical,
                RequestHeaders {
                    range: range.clone(),
                    if_match,
                    authorization: bearer,
                },
                budget,
            )
            .await?;
            let total = parse_content_range_total(response.headers.get("content-range"));
            let identity =
                identity_from_headers(&response.headers, Some(response.body.len() as u64), total);
            check_etag(opts.if_match.as_deref(), identity.etag.as_deref())?;
            let body = response.body;
            let info = ObjectInfo {
                address: target.resolved_address,
                kind: ObjectKind::File,
                etag: identity.etag,
                version: None,
                size: identity.size,
                mtime: identity.mtime,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: Some(headers_to_metadata(response.headers)),
                user_metadata: Some(UserMetadata::new()),
                modified_by: None,
            };
            Ok(ReadResult::Bytes { bytes: body, info })
        })
        .await
    }

    // write / delete / list / create_directory / delete_directory:
    // HTTP supports none of these; the trait defaults to
    // `Unsupported` and the host's capability gating shortcuts the call
    // before it reaches us.
}

struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Clone, Default)]
struct RequestHeaders {
    range: Option<String>,
    if_match: Option<String>,
    authorization: Option<SecretBytes>,
}

/// The per-principal OAuth bearer as an `Authorization` header value, marked
/// sensitive so it is never HPACK-indexed and prints redacted.
fn bearer_header_value(token: &SecretBytes) -> Result<reqwest::header::HeaderValue> {
    let token = std::str::from_utf8(token.as_bytes()).map_err(|_| {
        Error::new(
            ErrorCode::CredentialUnavailable,
            "HTTP OAuth access token is not valid UTF-8",
        )
    })?;
    let mut value =
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
            Error::new(
                ErrorCode::CredentialUnavailable,
                "HTTP OAuth access token is not a valid Authorization header value",
            )
        })?;
    value.set_sensitive(true);
    Ok(value)
}

/// Immutable transport and credential snapshot shared by one operation and
/// all redirect hops it issues.
struct HttpRequestContext<'a> {
    client: &'a reqwest::Client,
    credentials: &'a HttpCredentials,
    redirects: Option<&'a FollowScope>,
    carries_secret_on_wire: bool,
}

fn build_client(
    bypass_proxy: bool,
    default_headers: reqwest::header::HeaderMap,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        // No `Referer` on a redirect hop. The transport's default sends the
        // previous URL, and it strips only userinfo and the fragment — so a
        // query would travel to the next host in a header no redirect policy
        // short of `none` inspects. The query on a projected request is the
        // CALLER's: a presigned URL pasted in as a dispatch address carries its
        // signature there, and disclosing it to a redirect target cannot be
        // undone. This is the protection for a secret carried in the URL; the
        // downgrade refusal in `redirect_is_allowed` is the one for a secret
        // carried in a header, and neither substitutes for the other.
        .referer(false)
        // The plugin follows explicitly so it can attach the held query and
        // secret headers to the request that is actually served.
        .redirect(reqwest::redirect::Policy::none());
    if bypass_proxy {
        builder = builder.no_proxy();
    }
    if !default_headers.is_empty() {
        builder = builder.default_headers(default_headers);
    }
    builder
        .build()
        .map_err(|err| Error::new(ErrorCode::Internal, format!("HTTP client init: {err}")))
}

fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .referer(false)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client init")
}

fn default_credentialed_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        // Bearers permitted for literal loopback HTTP must connect directly;
        // a process-wide HTTP proxy would otherwise receive them in cleartext.
        .no_proxy()
        .referer(false)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("credentialed reqwest client init")
}

/// OAuth bearer requests require TLS. Literal IPv4 loopback HTTP is retained
/// solely for local development and hermetic integration tests; hostnames and
/// every non-loopback cleartext origin fail before a header is constructed.
fn validate_credentialed_origin(address: &Url, bearer: Option<&SecretBytes>) -> Result<()> {
    if bearer.is_none() || address.scheme() == "https" {
        return Ok(());
    }
    let loopback_http = address.scheme() == "http" && address.host_str() == Some("127.0.0.1");
    if loopback_http {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::PermissionDenied,
        "HTTP OAuth bearer credentials require HTTPS or a literal IPv4 loopback origin",
    ))
}

/// Redirect chain cap, matching reqwest's default policy.
const MAX_REDIRECT_HOPS: usize = 10;

/// Total wall-clock budget for request headers across the whole redirect
/// chain. A per-client timeout alone restarts at every explicit `send()`.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Deadline for the connect-time credential probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Which targets a redirect may reach, once the transport checks have passed.
#[derive(Clone, Debug)]
enum FollowScope {
    SameOrigin,
    AllowList(Vec<String>),
}

/// Whether one redirect hop may be followed.
///
/// `previous` is the chain so far, oldest first; its **last** element is the
/// URL the 3xx came from, which is the only hop a scheme comparison can
/// meaningfully be made against. Comparing against `previous.first()` — the
/// original request — misses an upgrade-then-downgrade chain
/// (`http` → `https` → `http`), whose first and last schemes match.
///
/// Split out from the `Policy::custom` closures so it can be tested directly:
/// exercising the cleartext-downgrade case through a real client would need a
/// fixture serving TLS and cleartext on one port.
/// `carries_wire_auth` here means "this connection sends something across a
/// redirect that must not reach cleartext". That is broader than the credential
/// fields: it also covers `default_headers`, whose contents the transport does
/// not know to strip — its removal list is fixed at `Authorization`, cookies,
/// `Proxy-Authorization` and `WWW-Authenticate`.
fn redirect_is_allowed(
    previous: &[Url],
    next: &Url,
    scope: &FollowScope,
    carries_wire_auth: bool,
    restrict_to_origin: bool,
) -> bool {
    let Some(last) = previous.last() else {
        return false;
    };
    if previous.len() > MAX_REDIRECT_HOPS {
        return false;
    }
    // The probe sets this so its follow set is a subset of the data path's
    // (equal under the default `same_origin`): it must never establish a
    // credential through a hop an ordinary read would refuse, nor base its
    // verdict on a different origin than the configured root.
    if restrict_to_origin && !same_origin(last, next) {
        return false;
    }
    // This guard is about the HEADER channel, and it covers two cases the
    // transport treats differently.
    //
    // `Authorization` — which is where a declared credential and `root_url`'s
    // userinfo both end up — is dropped by reqwest only when the host or port
    // changes (`port_or_known_default`), so a same-host `https` → `http` hop
    // keeps it and puts it on the wire in clear. A pinned `default_headers`
    // entry is worse: reqwest's removal list is fixed at `Authorization`,
    // cookies, `Proxy-Authorization` and `WWW-Authenticate`, so an `X-Api-Key`
    // there is dropped on NO hop at all and this refusal is the only thing
    // between it and cleartext.
    //
    // It says nothing about a secret carried in the URL itself; `.referer(false)`
    // in `build_client` is what covers that channel.
    //
    // Refuse the downgrade specifically rather than any scheme change: an
    // `http` → `https` upgrade from a loopback root is safe and must keep
    // working.
    if carries_wire_auth && last.scheme() == "https" && next.scheme() == "http" {
        return false;
    }
    match scope {
        FollowScope::SameOrigin => same_origin(last, next),
        FollowScope::AllowList(hosts) => match next.host_str() {
            Some(host) => {
                let host = host.to_ascii_lowercase();
                hosts.iter().any(|allowed| allowed == &host)
            }
            None => false,
        },
    }
}

/// The configured follow set, or `None` for `redirect_policy = "none"`.
fn redirect_scope(policy: &str, allow_hosts: Option<&str>) -> Result<Option<FollowScope>> {
    match policy {
        "none" => Ok(None),
        "same_origin" => Ok(Some(FollowScope::SameOrigin)),
        "allow_list" => Ok(Some(FollowScope::AllowList(
            allow_hosts
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        ))),
        other => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "unknown HTTP redirect_policy '{other}' (expected 'none', 'same_origin', 'allow_list')"
            ),
        )),
    }
}

/// What the data path's redirect policy must protect: any request that puts
/// something confidential on the wire.
///
/// Named rather than inlined so the three inputs are testable. Getting this
/// wrong silently disarms the `https` → `http` downgrade refusal, which no
/// end-to-end test in this suite can catch — the fixtures are plain TCP, so
/// there is no `https` hop to downgrade from.
fn carries_secret_on_the_wire(
    carries_wire_auth: bool,
    default_headers: &reqwest::header::HeaderMap,
) -> bool {
    carries_wire_auth || !default_headers.is_empty()
}

#[cfg(test)]
fn build_redirect_policy(
    policy: &str,
    allow_hosts: Option<&str>,
    _carries_wire_auth: bool,
) -> Result<Option<FollowScope>> {
    redirect_scope(policy, allow_hosts)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn parse_default_headers(raw: Option<&str>) -> Result<reqwest::header::HeaderMap> {
    let mut map = reqwest::header::HeaderMap::new();
    let Some(raw) = raw else {
        return Ok(map);
    };
    // Numbered over the entries an operator would count, not over comma
    // positions: the index is the *only* identifier a rejected entry gets, so
    // "entry #3" has to mean the third header they wrote, not the third slot
    // in a string that may hold empty ones.
    let mut index = 0;
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        index += 1;
        // Identify a rejected entry by position and length, never by its
        // text. An operator who spells the separator as `:` writes
        // `Authorization: Basic <base64>`, which misses the credential
        // banlist below; the shared redaction pass matches `Bearer` only, so
        // echoing any part of the entry would publish a Basic or opaque
        // credential verbatim to the caller. That applies to the *name* as
        // much as the whole entry, because splitting on the first `=` puts
        // everything before the Base64 padding into `name` — for
        // `Authorization: Basic dXNlcjpwYXM=` the "name" is the credential.
        let malformed = |detail: &str| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "malformed default_headers entry #{index} ({} bytes): {detail}",
                    entry.len()
                ),
            )
        };
        let (name, value) = entry
            .split_once('=')
            .ok_or_else(|| malformed("expected Name=Value"))?;
        let name = name.trim();
        let value = value.trim();
        // Compared without lowercasing a copy: when the split lands on Base64
        // padding this `name` *is* the credential, and `to_ascii_lowercase`
        // would put a second, never-wiped plaintext copy on the heap on the
        // way to rejecting it.
        let banned = ["authorization", "cookie", "proxy-authorization"]
            .into_iter()
            .find(|banned| name.eq_ignore_ascii_case(banned));
        if let Some(banned) = banned {
            // `banned` is the matched literal, so this names a constant
            // rather than echoing operator text.
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "default_headers must not include credential header '{banned}' (use credential providers instead)"
                ),
            ));
        }
        let header_name: reqwest::header::HeaderName = name
            .parse()
            .map_err(|_| malformed("the part before '=' is not a valid header name"))?;
        let mut header_value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|_| malformed("the part after '=' is not a valid header value"))?;
        // The redirect policy already treats any pinned header as something
        // worth keeping off cleartext, because nothing stops an operator
        // putting an `X-Api-Key` here. Treat it the same way on the wire and
        // in `Debug`: sensitive values are never HPACK-indexed and print
        // redacted.
        header_value.set_sensitive(true);
        map.insert(header_name, header_value);
    }
    Ok(map)
}

/// A redirect target the plugin can follow. Statuses without defined method
/// preservation, and 3xx responses without a valid Location, stay final.
fn redirect_target(response: &reqwest::Response) -> Option<&str> {
    if !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    response
        .headers()
        .get(reqwest::header::LOCATION)?
        .to_str()
        .ok()
}

/// Strip userinfo injected by a `Location` and carry only the connection's
/// existing userinfo across a same-origin hop.
fn carry_userinfo(previous: &Url, next: &mut Url) {
    let previous_userinfo = url_carries_userinfo(previous);
    let same = same_origin(previous, next);
    let _ = next.set_username("");
    let _ = next.set_password(None);
    if previous_userinfo && same {
        let _ = next.set_username(previous.username());
        let _ = next.set_password(previous.password());
    }
}

/// Issue one request and follow every authorized hop with one total deadline.
async fn send_following_redirects(
    context: &HttpRequestContext<'_>,
    method: reqwest::Method,
    start: &Url,
    restrict_to_origin: bool,
    headers: &RequestHeaders,
) -> Result<reqwest::Response> {
    send_following_redirects_with_timeout(
        context,
        method,
        start,
        restrict_to_origin,
        headers,
        REQUEST_TIMEOUT,
    )
    .await
}

async fn send_following_redirects_with_timeout(
    context: &HttpRequestContext<'_>,
    method: reqwest::Method,
    start: &Url,
    restrict_to_origin: bool,
    headers: &RequestHeaders,
    timeout: Duration,
) -> Result<reqwest::Response> {
    // A per-principal bearer is a secret on the wire and must never cross an
    // origin boundary, whatever the operator's anonymous follow scope says.
    // Fold it into both transport facts for the whole chain.
    let carries_secret_on_wire = context.carries_secret_on_wire || headers.authorization.is_some();
    let restrict_to_origin = restrict_to_origin || headers.authorization.is_some();
    let chain = async {
        let mut current = start.clone();
        let mut previous = Vec::with_capacity(MAX_REDIRECT_HOPS + 1);
        loop {
            if !matches!(current.scheme(), "http" | "https") {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "HTTP backend supports http:// and https:// only",
                ));
            }
            let signed = sign_url(context.credentials, &current)?;
            let mut request = context.client.request(method.clone(), signed.as_str());
            request = apply_credential_headers(request, context.credentials);
            if let Some(bearer) = headers.authorization.as_ref() {
                validate_credentialed_origin(&current, Some(bearer))?;
                request =
                    request.header(reqwest::header::AUTHORIZATION, bearer_header_value(bearer)?);
            }
            if let Some(range) = headers.range.as_deref() {
                request = request.header(reqwest::header::RANGE, range);
            }
            if let Some(if_match) = headers.if_match.as_deref() {
                request = request.header(reqwest::header::IF_MATCH, if_match);
            }
            let response = request.send().await.map_err(map_reqwest_error)?;
            let Some(location) = redirect_target(&response) else {
                return Ok(response);
            };
            let Some(scope) = context.redirects else {
                return Ok(response);
            };
            let mut next = current.join(location).map_err(|_| {
                Error::new(
                    ErrorCode::Unsupported,
                    "HTTP redirect Location is not a URL this plugin can resolve",
                )
            })?;
            next = strip_held_query(context.credentials, &next)?;
            carry_userinfo(&current, &mut next);

            previous.push(current.clone());
            if !redirect_is_allowed(
                &previous,
                &next,
                scope,
                carries_secret_on_wire,
                restrict_to_origin,
            ) {
                return Ok(response);
            }
            if previous.len() > MAX_REDIRECT_HOPS {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    format!("HTTP request exceeded {MAX_REDIRECT_HOPS} redirects"),
                ));
            }
            current = next;
        }
    };

    tokio::time::timeout(timeout, chain).await.map_err(|_| {
        Error::new(
            ErrorCode::Transient,
            "HTTP request timed out while following redirects",
        )
    })?
}

async fn request_streaming(
    context: &HttpRequestContext<'_>,
    physical: &Url,
    dispatch_address: Url,
    headers: RequestHeaders,
    cancel: Option<CancellationToken>,
) -> Result<(ObjectInfo, ovstorage_plugin::ReadStream)> {
    use futures::StreamExt;
    let request_had_range = headers.range.is_some();
    let response =
        send_following_redirects(context, reqwest::Method::GET, physical, false, &headers).await?;
    let status = response.status().as_u16();
    let mut hmap = HashMap::with_capacity(response.headers().len());
    for (name, value) in response.headers().iter() {
        if let Ok(text) = value.to_str() {
            hmap.insert(name.as_str().to_ascii_lowercase(), text.to_string());
        }
    }
    if !(200..=299).contains(&status) {
        return Err(map_status(status, Some(&hmap)));
    }
    if request_had_range && status == 200 {
        drop(response);
        return Err(Error::new(
            ErrorCode::Unsupported,
            "HTTP origin ignored Range during ranged read (returned 200 OK)",
        ));
    }
    let advertised_size = hmap
        .get("content-length")
        .and_then(|value| value.parse::<u64>().ok());
    let total = parse_content_range_total(hmap.get("content-range"));
    let identity = identity_from_headers(&hmap, advertised_size, total);
    let info = ObjectInfo {
        address: dispatch_address,
        kind: ObjectKind::File,
        etag: identity.etag,
        version: None,
        size: identity.size,
        mtime: identity.mtime,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: Some(headers_to_metadata(hmap)),
        user_metadata: Some(UserMetadata::new()),
        modified_by: None,
    };
    let upstream = response.bytes_stream().map(|item| match item {
        Ok(bytes) => Ok(bytes),
        Err(err) => Err(map_reqwest_error(err)),
    });
    let stream: ovstorage_plugin::ReadStream = Box::pin(CancelableStream::new(upstream, cancel));
    Ok((info, stream))
}

async fn request(
    context: &HttpRequestContext<'_>,
    method: &str,
    address: &Url,
    headers: RequestHeaders,
    byte_budget: Option<u64>,
) -> Result<HttpResponse> {
    use futures::StreamExt;
    let method_obj = match method {
        "GET" => reqwest::Method::GET,
        "HEAD" => reqwest::Method::HEAD,
        other => {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!("HTTP method {other} not supported"),
            ));
        }
    };
    let request_had_range = headers.range.is_some();
    let response = send_following_redirects(context, method_obj, address, false, &headers).await?;
    let status = response.status().as_u16();
    let mut hmap = HashMap::with_capacity(response.headers().len());
    for (name, value) in response.headers().iter() {
        if let Ok(text) = value.to_str() {
            hmap.insert(name.as_str().to_ascii_lowercase(), text.to_string());
        }
    }
    if !(200..=299).contains(&status) {
        drop(response);
        return Err(map_status(status, Some(&hmap)));
    }
    if request_had_range && status == 200 {
        // Reject before buffering: open-ended `bytes=N-` has no cap, so draining first risks a multi-GB OOM.
        drop(response);
        return Err(Error::new(
            ErrorCode::Unsupported,
            "HTTP origin ignored Range during ranged read (returned 200 OK)",
        ));
    }
    let cap = byte_budget.unwrap_or(u64::MAX);
    let mut body = Vec::new();
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
    Ok(HttpResponse {
        status,
        headers: hmap,
        body,
    })
}

fn parse_content_range_total(header: Option<&String>) -> Option<u64> {
    let raw = header?;
    let after_slash = raw.rsplit_once('/')?.1.trim();
    if after_slash == "*" {
        return None;
    }
    after_slash.parse::<u64>().ok()
}

/// True when the host is one the local machine serves itself, so a cleartext
/// request never leaves the loopback interface.
fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        // `Ipv6Addr::is_loopback` is false for `::ffff:127.0.0.1`, which is
        // the same interface written another way.
        Some(url::Host::Ipv6(ip)) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        // RFC 6761 reserves `localhost` as loopback. Match it exactly: by
        // suffix would admit `localhost.evil.test`, and the trailing-root-dot
        // spelling `localhost.` is resolver-dependent — glibc forwards it to
        // DNS rather than answering `127.0.0.1` — so treating it as loopback
        // would waive the cleartext guard for a name that leaves the machine.
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// What one probe established about the credential.
///
/// Spelled out as an enum with an exhaustive match, and with `Accepted`
/// requiring *positive* evidence rather than being the fallthrough. Three
/// successive rounds on this branch shipped a version where "anything that is
/// not a 401" became a claim of success, and each time a response class nobody
/// had considered — a redirect the policy stopped, a `404`, a `503` — turned
/// into `Authenticated` for a credential nothing had accepted. The default
/// arm now claims nothing, so a class nobody considered is merely unproven.
enum ProbeOutcome {
    /// The origin refused the credential.
    Refused,
    /// The origin served the request: a `2xx`. This is the only class that
    /// shows the credential being honoured rather than merely not producing a
    /// challenge.
    Accepted,
    /// The origin answered, but with something that establishes nothing about
    /// the credential: a redirect the policy would not follow, a `404` or
    /// `405` that may equally have been produced before any authentication, a
    /// `429`, a `5xx` — or a `403`.
    ///
    /// `403` deserves its own note, because treating it as acceptance is
    /// tempting and wrong. S3's driver spells out why: "the raw status alone
    /// cannot distinguish 'bad credentials' from 'valid credentials,
    /// restricted policy' — the modeled code can". S3 therefore discriminates
    /// on modeled error codes in the response body, and deliberately chose a
    /// verb that returns one. This probe is a `HEAD`, which carries no body,
    /// so it has no such discriminator and must not borrow the conclusion.
    ///
    /// The status is carried so the note can name it. It is directly
    /// observed and is not a secret, and `403`, `404`, `405`, `429` and
    /// `503` call for entirely different operator actions.
    Unproven(u16),
    /// A `2xx`, but from an address other than the one the probe asked about.
    ///
    /// Bouncing a credential the origin does not accept to a login page is
    /// the ordinary form-auth pattern, and that page answers `200` exactly as
    /// an honoured credential does. The hop is same-origin, so the transport
    /// keeps `Authorization` across it and nothing downstream distinguishes
    /// the two. Only the landing address does.
    Diverted,
    /// No HTTP response arrived at all.
    Unreachable(Error),
}

/// True when the probe's final address is the one it asked about.
///
/// Compared component-wise, not as strings, because reqwest strips userinfo
/// out of the request URL before sending (`extract_authority`), so a
/// `root_url` that authenticates *through* userinfo never string-matches its
/// own response.
///
/// The query is compared and `root_url` cannot carry one — `config_url`
/// refuses it — so that clause reads as "the landing URL carries no query
/// either". A redirect that appended one landed on a different resource, and
/// the probe's answer is about the address it asked about.
///
/// Only the trailing-slash normalization an origin performs on a directory is
/// allowed to differ — the `301 /files -> /files/` case the probe follows
/// deliberately, which lands on the same resource. One slash, not any number:
/// `/protected/` and `/protected///` are different paths to HTTP, and an
/// origin is free to answer them differently.
fn probe_landed_on_root(final_url: &Url, root_url: &Url) -> bool {
    /// `/files` and `/files/` are the same resource; `/files//` is not.
    fn without_one_trailing_slash(path: &str) -> &str {
        path.strip_suffix('/')
            .filter(|rest| !rest.is_empty())
            .unwrap_or(path)
    }
    final_url.scheme() == root_url.scheme()
        && final_url.host_str() == root_url.host_str()
        && final_url.port_or_known_default() == root_url.port_or_known_default()
        && final_url.query() == root_url.query()
        && without_one_trailing_slash(final_url.path())
            == without_one_trailing_slash(root_url.path())
}

/// One `HEAD` on `root_url`, so a connection reporting `Authenticated` has
/// actually had its credential honoured by the origin.
///
/// It cannot be better than a black-box check: an origin that ignores
/// `Authorization` entirely answers `2xx` to anything. What it does rule out
/// is the case that matters in practice — a credential the origin actively
/// refuses — without borrowing a conclusion from a status that does not
/// support one.
///
/// The probe follows a strict subset of the data path's redirects — the
/// configured policy intersected with same-origin — so it can neither
/// establish a credential through a hop an ordinary read would refuse, nor
/// base its verdict on a different origin than the configured root.
///
/// The outcome is *recorded*; it never decides whether the connection is
/// accepted. A `[[ovstorage.connections]]` entry is materialized during stack
/// construction, so failing the add here would let one expired token stop a
/// whole host from starting and take every unrelated backend with it.
async fn probe_credential(
    client: &reqwest::Client,
    root_url: &Url,
    credentials: &HttpCredentials,
    redirects: Option<&FollowScope>,
    cancel: Option<CancellationToken>,
) -> Result<(ConnectionAuthState, Option<SystemTime>)> {
    // A deadline of its own, well under the data-path timeout: a connection is
    // materialized during stack construction and the loop over declared
    // connections is serial, so an origin that completes its handshake and
    // then stalls would otherwise hold up the whole host for the read timeout,
    // once per connection.
    let raced = tokio::time::timeout(
        PROBE_TIMEOUT,
        race_cancel(
            cancel.as_ref(),
            send_following_redirects(
                &HttpRequestContext {
                    client,
                    credentials,
                    redirects,
                    carries_secret_on_wire: true,
                },
                reqwest::Method::HEAD,
                root_url,
                true,
                &RequestHeaders::default(),
            ),
        ),
    )
    .await;

    let outcome = match raced {
        Err(_) => ProbeOutcome::Unreachable(Error::new(
            ErrorCode::Transient,
            "HTTP credential probe timed out",
        )),
        // The host cancelled: fail the whole `instantiate` rather than register
        // a connection nobody asked to keep.
        Ok(Err(cancelled)) if cancelled.code() == ErrorCode::Cancelled => return Err(cancelled),
        Ok(Err(error)) => ProbeOutcome::Unreachable(error),
        Ok(Ok(response)) => match response.status().as_u16() {
            401 => ProbeOutcome::Refused,
            status if (200..=299).contains(&status) => {
                let landed = strip_held_query(credentials, response.url())?;
                if probe_landed_on_root(&landed, root_url) {
                    ProbeOutcome::Accepted
                } else {
                    ProbeOutcome::Diverted
                }
            }
            status => ProbeOutcome::Unproven(status),
        },
    };

    let now = SystemTime::now();
    Ok(match outcome {
        ProbeOutcome::Refused => (
            ConnectionAuthState::AuthFailed {
                error: map_status(401, None),
                attempts: 1,
            },
            Some(now),
        ),
        ProbeOutcome::Accepted => (
            ConnectionAuthState::Authenticated {
                last_authenticated_at: now,
                expires_at: None,
            },
            Some(now),
        ),
        ProbeOutcome::Unproven(status) => (
            ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::Unknown {
                    // Says only what was observed, and says all of it. The
                    // status is the operator's whole handle on what to do
                    // next — `405` means the origin refuses `HEAD`, `404`
                    // means the root has no index, `403` and `429` mean
                    // something else again. What it does not say is where
                    // the response came from or why the origin sent it;
                    // neither is something this check can see.
                    details: format!(
                        "root_url answered the credential probe with HTTP {status}, \
                         which neither accepts nor refuses the credential"
                    ),
                },
                last_attempt: Some(AuthAttempt {
                    at: now,
                    error: None,
                }),
            },
            // The origin did answer, so a probe genuinely landed.
            Some(now),
        ),
        ProbeOutcome::Diverted => (
            ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::Unknown {
                    // Name the shape, not the address: the redirect target is
                    // origin-controlled text and the probe does not publish
                    // it. An operator who sees this checks whether their root
                    // bounces to a sign-in page.
                    details:
                        "the credential probe was redirected away from root_url to an address \
                         that answered 2xx, which a sign-in page does exactly as an accepted \
                         credential does"
                            .to_string(),
                },
                last_attempt: Some(AuthAttempt {
                    at: now,
                    error: None,
                }),
            },
            Some(now),
        ),
        ProbeOutcome::Unreachable(error) => unreachable_state(Some(error)),
    })
}

/// Nothing was proven and nothing was refuted, so claim neither. `last_probed`
/// stays `None` — no probe reached an origin — while `last_attempt` records
/// that one was made, and why it did not land.
fn unreachable_state(error: Option<Error>) -> (ConnectionAuthState, Option<SystemTime>) {
    (
        ConnectionAuthState::AwaitingAuth {
            reason: AuthReason::BackendUnreachable,
            last_attempt: Some(AuthAttempt {
                at: SystemTime::now(),
                error,
            }),
        },
        None,
    )
}

/// Name a route prefix in an operator-facing message by its origin alone.
///
/// Every other part of a route prefix can carry a secret: userinfo, a
/// signed-URL query under any name (`plugin-http.md` positively invites one),
/// and a capability token in the path. `Error::new`'s redaction pass strips
/// userinfo and a fixed list of known provider query keys, which covers none
/// of the rest — so render what is structurally safe rather than trying to
/// recognise what is not. The origin is enough to act on: it says which
/// connection the new one collides with, and the operator has their own
/// config.
fn route_prefix_origin_for_message(url: &Url) -> String {
    match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{}://{host}:{port}", url.scheme()),
        (Some(host), None) => format!("{}://{host}", url.scheme()),
        (None, _) => url.scheme().to_string(),
    }
}

/// True when the URL embeds userinfo, which reqwest turns into an
/// `Authorization: Basic` header on every request built from it.
///
/// The wholly-empty spelling needs no guard of its own: `Url` normalizes
/// `http://:@host/` to an empty username and a `None` password, so this
/// answers false, no `Authorization` is built, and the connection is
/// anonymous. Measured against `url` 2.5.8 — an empty password survives
/// parsing only when a username accompanies it, and `classify`'s
/// wholly-empty rejection covers the declared-field spelling.
fn url_carries_userinfo(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

/// Refuse two writers for the singleton `Authorization` header.
///
/// `reqwest::RequestBuilder::new` lifts userinfo out of the URL into its own
/// `Authorization` header, and `header()` *appends*, so the request would
/// carry two `Authorization` headers with no rule for which the origin
/// honours. Refuse rather than silently pick one.
fn validate_credential_conflict(root_url: &Url, credentials: &HttpCredentials) -> Result<()> {
    if url_carries_userinfo(root_url) && credentials.writes_authorization() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "root_url userinfo and the credential bundle both write Authorization; \
             use exactly one Basic, Bearer, or secret-header Authorization source",
        ));
    }
    Ok(())
}

/// Guard the transport a credential will travel over.
///
/// Applied to any connection that authenticates, whether through the declared
/// fields or through userinfo the HTTP client lifts out of `root_url` — a
/// guard that saw only the declared fields would leave the older channel
/// sending Basic credentials in clear.
fn validate_credential_transport(root_url: &Url) -> Result<()> {
    if root_url.scheme() == "http" && !is_loopback_host(root_url) {
        // Name the host, never the URL. The host is the part of this
        // diagnostic that helps, and interpolating a `root_url` that carries
        // userinfo — one of the channels this guard fires for —
        // would print the password into a startup error and the log.
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "HTTP credentials require https:// (host '{}' would receive the credential in cleartext); loopback hosts are exempt.",
                root_url.host_str().unwrap_or(""),
            ),
        ));
    }
    Ok(())
}

/// `root_url` is the physical origin every request is rewritten onto, so a
/// scheme the transport cannot serve makes the connection unusable. Rejecting
/// it at `instantiate` turns a per-read `Unsupported` into one config error.
/// `prefix` is deliberately not checked: it is caller-facing and documented as
/// free to use a different scheme.
fn validate_physical_scheme(root_url: &Url) -> Result<()> {
    if !matches!(root_url.scheme(), "http" | "https") {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "HTTP root_url scheme '{}' is not supported (expected http or https)",
                root_url.scheme()
            ),
        ));
    }
    Ok(())
}

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

/// Resolve the connection's published `prefix` — the address space callers
/// dispatch on — taking an explicit one as written and otherwise deriving it
/// from `root_url` **with the userinfo stripped**.
///
/// **The userinfo is stripped because the prefix is what gets published.**
/// `root_url` keeps its userinfo and `reqwest` keeps lifting it into an
/// `Authorization` header, so the wire is unchanged; what stops is printing the
/// password into `BackendId`, `RootInfo` and every `ObjectInfo.address`. The
/// strip also makes `prefix != root_url`, which sends
/// [`HttpBackend::physical_url`] down its projection arm — and that arm
/// rebuilds the userinfo-bearing physical URL from `root_url`, so nothing
/// downstream loses it.
///
/// **An explicit prefix is taken as written** — except that userinfo in one is
/// refused outright rather than stripped, because silently altering the address
/// space an operator wrote out would route their callers somewhere they did not
/// ask for.
///
/// Neither operand can carry a query or a fragment: `config_url` refuses both
/// on both keys, which is why there is no query handling here at all. The
/// consequence worth naming is that an ordinary root — no userinfo, no query —
/// makes `prefix == root_url`, so `physical_url` takes its identity arm and the
/// address a caller dispatched is the address that goes on the wire.
///
/// A malformed explicit prefix is an error rather than a silent fall back to
/// the root, which is what the previous `unwrap_or_else` did: a typo published
/// the root under a name the operator never wrote.
fn default_prefix(config: &HashMap<String, ConfigValue>, root_url: &Url) -> Result<Url> {
    // Branch on the key's presence, not on whether parsing happened to succeed:
    // a malformed or wrongly-typed `prefix` is the operator's error to see.
    if config.contains_key("prefix") {
        let prefix = config_url(config, "prefix")?;
        if url_carries_userinfo(&prefix) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "HTTP route prefix must not embed userinfo",
            ));
        }
        return Ok(prefix);
    }
    let mut prefix = root_url.clone();
    let _ = prefix.set_username("");
    let _ = prefix.set_password(None);
    Ok(prefix)
}

/// A required URL-valued connection config entry — `root_url` and `prefix`,
/// the plugin's two configuration addresses.
///
/// **Both are refused for carrying a query or a fragment**, on the one rule
/// [`address::refused_config_component`] states for every config address in
/// the workspace: an address names a node, and neither component is part of
/// what names it. The check is on the raw string because that is the only view
/// in which the fragment still exists — `address::parse` strips one, so a
/// post-parse check here would be a guard that cannot execute.
///
/// This is the loader for BOTH keys and it does not read which one it was
/// given, deliberately. The rule has no per-key exception, and a loader that
/// branched on the key would be the place one grew.
///
/// A **request** address is a different question and keeps its query: that is
/// where a caller pins a version. The two paths share `address::parse` and
/// nothing else, which is why the refusal lives here rather than there.
fn config_url(config: &HashMap<String, ConfigValue>, key: &str) -> Result<Url> {
    match config.get(key) {
        Some(ConfigValue::String(value)) => {
            if let Some(component) = address::refused_config_component(value) {
                // The value is not echoed. A query is where a signature or an
                // API key lives, and this message is a startup failure that
                // reaches a log.
                let credential_hint = if component.name() == "query" {
                    " Supply a connection-held signature through the 'signed_query' credential and declare signed_query_scope."
                } else {
                    ""
                };
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "HTTP connection config '{key}' must not carry a {}; an address names \
                         a node, and requests are routed on scheme, authority and path alone. \
                         Write it without the {}.{credential_hint}",
                        component.name(),
                        component.name()
                    ),
                ));
            }
            address::parse(value)
        }
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("HTTP connection config '{key}' must be a URL string"),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("missing required HTTP connection config '{key}'"),
        )),
    }
}

fn config_string_opt(config: &HashMap<String, ConfigValue>, key: &str) -> Option<String> {
    match config.get(key) {
        Some(ConfigValue::String(value)) => Some(value.clone()),
        _ => None,
    }
}

fn config_string(config: &HashMap<String, ConfigValue>, key: &str) -> Result<Option<String>> {
    match config.get(key) {
        Some(ConfigValue::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("HTTP connection config '{key}' must be a string"),
        )),
        None => Ok(None),
    }
}

/// Map HTTP status to `Error`. 401 → `AuthRequired` (retryable after re-auth); 403 → `PermissionDenied` (final). 412 carries response identity in `ErrorContext` when headers are supplied.
fn map_status(status: u16, headers: Option<&HashMap<String, String>>) -> Error {
    match status {
        401 => Error::new(
            ErrorCode::AuthRequired,
            "HTTP request requires authentication (HTTP 401)",
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("http_unauthorized".into()),
            expired_at: None,
        }),
        403 => Error::new(
            ErrorCode::PermissionDenied,
            "HTTP request forbidden (HTTP 403)",
        ),
        404 => Error::new(ErrorCode::NotFound, "HTTP object not found"),
        405 => Error::new(ErrorCode::Unsupported, "HTTP method not allowed"),
        408 => Error::new(ErrorCode::Transient, "HTTP request timed out"),
        412 => {
            let err = Error::new(ErrorCode::ObjectModified, "HTTP precondition failed");
            match headers {
                Some(h) => err.with_context(ErrorContext::Identity {
                    new_etag: h.get("etag").map(|raw| strip_etag_wire_form(raw)),
                }),
                None => err,
            }
        }
        416 => Error::new(
            ErrorCode::InvalidArgument,
            "HTTP range not satisfiable (HTTP 416)",
        ),
        429 => Error::new(
            ErrorCode::ResourceExhausted,
            "HTTP server reported rate limiting",
        ),
        500..=599 => Error::new(
            ErrorCode::Transient,
            format!("HTTP server returned transient status {status}"),
        ),
        status => Error::new(
            ErrorCode::Unsupported,
            format!("unsupported HTTP response status {status}"),
        ),
    }
}

/// `stat` may use its ranged-GET fallback only for a HEAD-specific 405. Other
/// `Unsupported` failures (for example a blocked redirect) describe the whole
/// request and must be returned unchanged.
fn is_method_not_allowed(err: &Error) -> bool {
    err.code() == ErrorCode::Unsupported && err.message() == "HTTP method not allowed"
}

/// Per-HTTP-response identity fields read from response headers.
/// Flattened onto `ObjectInfo` at construction; only `etag` is used as
/// the SPI precondition primitive.
struct HttpIdentity {
    etag: Option<String>,
    size: Option<u64>,
    mtime: Option<SystemTime>,
}

fn identity_from_headers(
    headers: &HashMap<String, String>,
    observed_len: Option<u64>,
    total_size: Option<u64>,
) -> HttpIdentity {
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
        etag: headers.get("etag").map(|raw| strip_etag_wire_form(raw)),
        size,
        mtime,
    }
}

/// Strip RFC 7232 quoting and `W/` weak prefix from a wire etag so the
/// SPI's `if_match` string is the opaque token — the HTTP-layer
/// quoting / weakness flags are re-applied when sending `If-Match`
/// upstream.
fn strip_etag_wire_form(raw: &str) -> String {
    let trimmed = raw.trim();
    let body = trimmed.strip_prefix("W/").unwrap_or(trimmed);
    body.trim_matches('"').to_string()
}

/// Response headers that must not be republished as object metadata.
///
/// `system_metadata` crosses the broker and REST boundaries to storage
/// callers, who are routinely less privileged than the connection's
/// credential. An origin answering a credentialed request emits session and
/// challenge material that belongs to the connection, not to the object: a
/// `Set-Cookie` handed to a caller is a usable session, and
/// `WWW-Authenticate` / `Authentication-Info` describe the credential rather
/// than the bytes.
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

/// Publish the origin's response headers as object metadata, minus the ones
/// that describe the *connection's* identity rather than the object.
///
/// A denylist rather than an allowlist, deliberately: the value of this map is
/// that an operator's own `x-`, vendor and content headers arrive intact, and
/// an allowlist would have to be extended for every origin.
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
    // RFC 7232: weak ETags (`W/`) allow byte-different responses to share a tag, so skip them for rotation checks.
    let etag_mismatch = !expected.starts_with("W/") && actual != Some(expected);
    if etag_mismatch {
        Err(
            Error::new(ErrorCode::ObjectModified, "HTTP object etag changed").with_context(
                ErrorContext::Identity {
                    new_etag: actual.map(|s| s.to_string()),
                },
            ),
        )
    } else {
        Ok(())
    }
}

fn map_reqwest_error(error: reqwest::Error) -> Error {
    let timed_out = error.is_timeout();
    let connect_failed = error.is_connect();
    let redirect_blocked = error.is_redirect();
    let status = error.status();
    // Drop the URL before it reaches a caller-visible message. `Display`
    // appends `" for url ({url})"`, and the shared `redact_url` pass scrubs
    // only the query keys on its fixed allowlist — a signed URL spelled
    // `?api_key=…` survives it. Same treatment as
    // `redirect::reqwest_transient_error`.
    let error = error.without_url();
    if timed_out {
        return Error::new(
            ErrorCode::Transient,
            format!("HTTP request timed out: {error}"),
        );
    }
    if connect_failed {
        return Error::new(ErrorCode::Transient, format!("HTTP connect error: {error}"));
    }
    if redirect_blocked {
        return Error::new(
            ErrorCode::Unsupported,
            format!("HTTP redirect blocked by configured policy: {error}"),
        );
    }
    if let Some(status) = status {
        return map_status(status.as_u16(), None);
    }
    Error::new(ErrorCode::Transient, format!("HTTP error: {error}"))
}

/// `BackendFactory` the `ovstorage_layer_plugin!` macro instantiates. Holds the
/// static kind descriptor (computed once); each built `HttpBackendLayer` owns
/// its own stateless connection factory, connections, and longest-prefix route
/// table.
pub struct HttpBackendLayerFactory {
    descriptor: StorageBackendKindDescriptor,
}

impl Default for HttpBackendLayerFactory {
    fn default() -> Self {
        Self {
            descriptor: HttpBackendFactory.descriptor(),
        }
    }
}

#[async_trait]
impl BackendFactory for HttpBackendLayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.descriptor)
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let layer = Arc::new(HttpBackendLayer {
            name: name.to_string(),
            factory: HttpBackendFactory,
            descriptor: self.descriptor.clone(),
            state: RwLock::new(HttpLayerState {
                instances: Vec::new(),
                routes: RouteTable::empty(),
            }),
        });
        // A non-empty layer config seeds one static connection (the
        // `[ovstorage.root]` / config-as-Stack path); runtime connections
        // arrive via `add_connection`.
        if !config.is_empty() {
            let request = ConnectionRequest {
                backend_kind: self.descriptor.kind.clone(),
                config: config.clone(),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            };
            let instance = layer
                .instantiate_connection(
                    request,
                    ConnectionSource::Static {
                        layer: ConfigLayer::Programmatic,
                    },
                    cancel,
                )
                .await?;
            layer.install(instance)?;
        }
        Ok(layer)
    }
}

/// Native ABI-v2 `Layer` for the HTTP backend. Owns its connections and routes
/// addresses to the right [`HttpBackend`] instance by longest prefix. The
/// backend is read-only, so only `stat` + `read` are implemented; every other
/// object/connection slot keeps the `Layer` trait default (`Unsupported` /
/// empty). There is no dynamic-root stream (each connection contributes a
/// single fixed prefix) and no interactive auth: connection credentials are
/// static, so `instantiate` installs and probes them and there is no flow to
/// drive. A broker host may additionally attach a per-principal OAuth keyring
/// reference, which this layer consumes before the request reaches
/// [`HttpBackend`].
struct HttpBackendLayer {
    name: String,
    factory: HttpBackendFactory,
    descriptor: StorageBackendKindDescriptor,
    /// Connections and the longest-prefix route table derived from them, under
    /// a single lock so a mutation and its route-table rebuild are published
    /// atomically — a separate `instances` / `route_table` pair let concurrent
    /// add/remove publish a stale table (a just-added connection resolving
    /// `NoRoute`, or a removed one staying routable).
    state: RwLock<HttpLayerState>,
}

/// The [`HttpBackendLayer`]'s connections plus the route table derived from
/// them; the two always mutate together under [`HttpBackendLayer::state`].
struct HttpLayerState {
    instances: Vec<Arc<HttpInstance>>,
    routes: RouteTable<Arc<HttpInstance>>,
}

struct HttpInstance {
    backend_id: BackendId,
    backend: Arc<HttpBackend>,
    roots: Vec<RootInfo>,
    connection: Connection,
}

/// Longest-prefix route table over the current instance set.
fn build_routes(instances: &[Arc<HttpInstance>]) -> RouteTable<Arc<HttpInstance>> {
    let items: Vec<(RootInfo, Arc<HttpInstance>)> = instances
        .iter()
        .flat_map(|instance| {
            instance
                .roots
                .iter()
                .cloned()
                .map(|root| (root, instance.clone()))
                .collect::<Vec<_>>()
        })
        .collect();
    RouteTable::build(items)
}

impl HttpBackendLayer {
    async fn instantiate_connection(
        &self,
        request: ConnectionRequest,
        source: ConnectionSource,
        cancel: Option<CancellationToken>,
    ) -> Result<Arc<HttpInstance>> {
        if request.backend_kind != self.descriptor.kind {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "connection backend_kind '{}' does not match layer kind '{}'",
                    request.backend_kind, self.descriptor.kind
                ),
            ));
        }
        let instance = self.factory.instantiate(&request, cancel).await?;
        let connection_id = ConnectionId(fresh_id(&self.descriptor.kind));
        // Resolve the connection's display label once and thread it into both
        // the roots and the Connection, so ABI-v2 root introspection keeps the
        // caller-supplied / default label (HTTP leaves `AddressRoot.display_name`
        // unset).
        let display_name = request
            .display_name
            .clone()
            .or_else(|| instance.display_name.clone())
            .unwrap_or_else(|| self.descriptor.display_name.clone());
        let roots: Vec<RootInfo> = instance
            .address_roots
            .iter()
            .cloned()
            .map(|root| {
                self.root_info_from_address_root(root, &connection_id, &source, &display_name)
            })
            .collect();
        let connection = Connection {
            id: connection_id,
            backend_kind: self.descriptor.kind.clone(),
            display_name,
            source,
            capabilities: roots
                .first()
                .map(|root| root.capabilities.clone())
                .unwrap_or_else(Capabilities::empty),
            current_addresses: roots.iter().map(|root| root.root.clone()).collect(),
            auth_state: instance.auth_state,
            last_probed: instance.probed_at,
            user_metadata: UserMetadata::new(),
        };
        Ok(Arc::new(HttpInstance {
            backend_id: instance.backend_id,
            backend: instance.backend,
            roots,
            connection,
        }))
    }

    fn root_info_from_address_root(
        &self,
        root: AddressRoot,
        connection_id: &ConnectionId,
        source: &ConnectionSource,
        display_name: &str,
    ) -> RootInfo {
        let route_source = match source {
            ConnectionSource::Static { layer } => RouteSource::Static { layer: *layer },
            _ => RouteSource::ConnectionContributed {
                connection_id: connection_id.clone(),
            },
        };
        RootInfo {
            root: root.address,
            // Fall back to the connection's resolved label, matching the
            // `Connection`'s own resolution (and the services-client Layer).
            display_name: root.display_name.or_else(|| Some(display_name.to_string())),
            layer_kind: self.descriptor.kind.clone(),
            connection_id: Some(connection_id.clone()),
            owning_target: None,
            capabilities: root.capabilities,
            range_read_strategy: RangeReadStrategy::Native,
            source: route_source,
            visible: root.visibility == AddressVisibility::Visible,
            visibility: root.visibility,
            alias_state: None,
            icon: self.descriptor.icon.clone(),
            user_metadata: root.user_metadata,
        }
    }

    /// Push an instance and republish the derived route table atomically.
    ///
    /// A caller-facing prefix another connection already serves is refused
    /// rather than installed. `RouteTable::build` shadows a duplicate root with
    /// only a `warn` and `lookup` returns the first match, so the second
    /// connection would otherwise register successfully, be permanently
    /// unroutable, and leave every read served by the first connection —
    /// including its credential.
    ///
    /// **The comparison is by node, not by spelling, because the router is.**
    /// `assets` and `assets/` are one node to `RouteTable`, which dedups them
    /// and ranks them equal, so a byte comparison here would report both
    /// installations as successful and then hand all their traffic to whichever
    /// arrived first. Refusing the second is only a guarantee if it is refused
    /// under every spelling the router will merge.
    fn install(&self, instance: Arc<HttpInstance>) -> Result<()> {
        let mut state = self.state.write();
        if let Some(clash) = state.instances.iter().find_map(|existing| {
            existing.roots.iter().find(|root| {
                instance
                    .roots
                    .iter()
                    .any(|new| address::same_node(&new.root, &root.root))
            })
        }) {
            // Name only the origin. The prefix's userinfo, query and path can
            // each carry a secret, and a connection's display name is
            // free-form caller text — under the broker, remote caller text —
            // which the shared redaction pass does not inspect.
            // `RouteConflict`, not `AlreadyExists`: this is specifically "the
            // caller-facing route is already served", which is what nucleus's
            // `reserve_root` already calls it for the identical reason. The
            // distinction is load-bearing — a host tolerating a duplicate
            // route at startup must not also swallow, say, the alias layer's
            // duplicate-*id* refusal, which is `AlreadyExists` and means
            // something else entirely.
            return Err(Error::new(
                ErrorCode::RouteConflict,
                format!(
                    "another connection already serves an address prefix on '{}'",
                    route_prefix_origin_for_message(&clash.root)
                ),
            ));
        }
        state.instances.push(instance);
        state.routes = build_routes(&state.instances);
        Ok(())
    }

    fn target(&self, url: &Url) -> Result<(Arc<HttpInstance>, ResolvedTarget)> {
        let instance = self
            .state
            .read()
            .routes
            .lookup(url)
            .map(|(_, instance)| instance.clone())
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))?;
        let target = ResolvedTarget {
            backend_id: instance.backend_id.clone(),
            resolved_address: url.clone(),
        };
        Ok((instance, target))
    }

    fn current_roots(&self) -> Vec<RootInfo> {
        let mut roots: Vec<RootInfo> = self.state.read().routes.roots().cloned().collect();
        roots.sort_by(|left, right| left.root.as_str().cmp(right.root.as_str()));
        roots
    }

    /// Consume the broker's non-secret credential reference and load the
    /// current principal's access token through the ABI host keyring callback.
    /// The reference cannot select another backend's keyring namespace, and a
    /// referenced credential without a stamped principal fails closed.
    fn request_bearer(&self, extensions: &mut Extensions) -> Result<Option<SecretBytes>> {
        let Some(credential) = ovstorage_plugin::ext::take_resolved_oauth_credential(extensions)?
        else {
            return Ok(None);
        };
        if credential.backend_kind != "http" {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "HTTP OAuth credential reference names a different backend kind",
            ));
        }
        let principal = extensions
            .get(ovstorage_plugin::ext::PRINCIPAL_ID)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::CredentialUnavailable,
                    "HTTP OAuth credential reference has no authenticated principal",
                )
            })?;
        let principal = std::str::from_utf8(principal).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "authenticated principal is not valid UTF-8",
            )
        })?;
        if principal.is_empty() {
            return Err(Error::new(
                ErrorCode::CredentialUnavailable,
                "HTTP OAuth credential reference has an empty authenticated principal",
            ));
        }
        let host = ovstorage_plugin::marshal::host().ok_or_else(|| {
            Error::new(
                ErrorCode::CredentialUnavailable,
                "HTTP OAuth credential requires host secret-store callbacks",
            )
        })?;
        if !host.is_broker() {
            return Err(Error::new(
                ErrorCode::PermissionDenied,
                "HTTP OAuth credential references are accepted only from a broker host",
            ));
        }
        let bearer = host
            .secret_get(
                "http",
                &ConnectionId(principal.to_string()),
                &credential.keyring_handle,
            )?
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::CredentialUnavailable,
                    "HTTP OAuth access token is unavailable from the host secret store",
                )
            })?;
        Ok(Some(bearer))
    }
}

#[async_trait]
impl Layer for HttpBackendLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.descriptor)
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        bail_if_cancelled(&cancel)?;
        self.state
            .read()
            .routes
            .lookup(url)
            .map(|(root, _)| root.clone())
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        bail_if_cancelled(&cancel)?;
        // HTTP roots are fixed at connection time — no dynamic-root stream.
        Ok((
            RootInfoSnapshot {
                roots: self.current_roots(),
                updates: false,
            },
            None,
        ))
    }

    async fn stat(
        &self,
        mut request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let bearer = self.request_bearer(&mut request.extensions)?;
        let (instance, target) = self.target(&request.input.address)?;
        instance
            .backend
            .stat_with_bearer(target, request.input.options, bearer, cancel)
            .await
    }

    async fn read(
        &self,
        mut request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let bearer = self.request_bearer(&mut request.extensions)?;
        let (instance, target) = self.target(&request.input.address)?;
        instance
            .backend
            .read_with_bearer(target, request.input.options, bearer, cancel)
            .await
    }

    async fn probe(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        let persist = request.input.connection.persist;
        let instance = self
            .instantiate_connection(
                request.input.connection,
                ConnectionSource::Runtime { persisted: persist },
                cancel,
            )
            .await?;
        // `probe` is the pre-flight verb and its contract is stricter than
        // `add_connection`'s: a rejected credential is `AuthRequired` and an
        // unreachable backend is `Transient`. `add_connection` deliberately
        // records both instead, because it must not be able to stop a host
        // from starting — so the translation lives here rather than in
        // `instantiate`.
        match &instance.connection.auth_state {
            ConnectionAuthState::AuthFailed { error, .. } => return Err(error.clone()),
            ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::BackendUnreachable,
                ..
            } => {
                return Err(Error::new(
                    ErrorCode::Transient,
                    "HTTP origin was unreachable during probe",
                ));
            }
            _ => {}
        }
        Ok(instance.connection.clone())
    }

    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        let persist = request.input.connection.persist;
        let instance = self
            .instantiate_connection(
                request.input.connection,
                ConnectionSource::Runtime { persisted: persist },
                cancel,
            )
            .await?;
        let connection = instance.connection.clone();
        self.install(instance)?;
        Ok(connection)
    }

    async fn list_connections(
        &self,
        _cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        bail_if_cancelled(&cancel)?;
        Ok((
            ConnectionSnapshot {
                connections: self
                    .state
                    .read()
                    .instances
                    .iter()
                    .map(|instance| instance.connection.clone())
                    .collect(),
                updates: false,
            },
            None,
        ))
    }

    async fn remove_connection(
        &self,
        key: Request<ConnectionKey>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        if key.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        let mut state = self.state.write();
        let index = state
            .instances
            .iter()
            .position(|instance| instance.connection.id == key.input.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))?;
        state.instances.remove(index);
        state.routes = build_routes(&state.instances);
        Ok(())
    }

    /// N10: apply a display-name / user-metadata patch to a stored connection.
    /// `HttpInstance`
    /// is shared behind an `Arc` with an immutable `Connection`, so build a
    /// fresh instance with the patched connection (and refreshed root labels)
    /// and swap it in under the same single write guard add/remove use.
    async fn update_connection_attributes(
        &self,
        request: Request<UpdateConnectionAttributesRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.key.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        // Fail closed on patch fields this layer cannot store/enforce yet:
        // silently dropping a requested restriction (`access_mode: read-only`,
        // `visible: false`) while returning Ok would let a caller mistake an
        // ignored restriction for an applied one.
        if request.input.patch.access_mode.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "the http backend does not support updating 'access_mode'",
            ));
        }
        if request.input.patch.visible.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "the http backend does not support updating 'visible'",
            ));
        }
        let mut state = self.state.write();
        let index = state
            .instances
            .iter()
            .position(|instance| instance.connection.id == request.input.key.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))?;

        let old = state.instances[index].clone();
        let mut connection = old.connection.clone();
        let mut roots = old.roots.clone();
        if let Some(display_name) = request.input.patch.display_name.clone() {
            connection.display_name = display_name.clone();
            // Refresh the presented root label so `list_address_roots` /
            // `root_info_for` reflect the rename.
            for root in &mut roots {
                root.display_name = Some(display_name.clone());
            }
        }
        for (key, value) in request.input.patch.user_metadata {
            match value {
                Some(value) => {
                    connection.user_metadata.insert(key, value);
                }
                None => {
                    connection.user_metadata.remove(&key);
                }
            }
        }
        let updated = Arc::new(HttpInstance {
            backend_id: old.backend_id.clone(),
            backend: old.backend.clone(),
            roots,
            connection: connection.clone(),
        });
        state.instances[index] = updated;
        state.routes = build_routes(&state.instances);
        Ok(connection)
    }

    /// Replace only the values inside a connection's existing credential
    /// channels. Configuration, channel set, header names, and roots stay
    /// fixed; changing any of those requires remove-and-add.
    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.key.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        bail_if_cancelled(&cancel)?;

        let initial = self
            .state
            .read()
            .instances
            .iter()
            .find(|instance| instance.connection.id == request.input.key.id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))?;
        let _rotation = initial.backend.rotation_guard.lock().await;
        bail_if_cancelled(&cancel)?;

        // Re-read after waiting for the per-connection rotation guard so two
        // callers cannot both validate against the same stale auth state.
        let old = self
            .state
            .read()
            .instances
            .iter()
            .find(|instance| instance.connection.id == request.input.key.id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))?;
        let root_url =
            old.backend.root_url.as_ref().ok_or_else(|| {
                Error::new(ErrorCode::Internal, "HTTP connection has no root_url")
            })?;
        let next = resolve_credentials(
            &request.input.credentials,
            old.backend.signed_query_scope,
            root_url,
        )?;
        validate_credential_conflict(root_url, &next)?;
        let next_shape = ConnectionCredentialShape {
            bundle: next.shape(),
            root_userinfo: url_carries_userinfo(root_url),
        };
        if next_shape != old.backend.credential_shape {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "HTTP credential rotation may replace values only; its authorization method, signed-query presence, and secret-header names must match the connection's original credential shape; remove and re-add the connection to change that shape",
            ));
        }

        // Preserve main's positive-evidence rule: a rotated credential is
        // reported Authenticated only after the origin answers a probe with
        // 2xx. The old credential remains live throughout this await.
        let (auth_state, probed_at) =
            if next.is_anonymous() && !old.backend.credential_shape.root_userinfo {
                (ConnectionAuthState::Anonymous, None)
            } else {
                probe_credential(
                    &old.backend.client,
                    root_url,
                    &next,
                    old.backend.redirects.as_ref(),
                    cancel,
                )
                .await?
            };

        let mut state = self.state.write();
        let index = state
            .instances
            .iter()
            .position(|instance| instance.connection.id == request.input.key.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))?;
        *old.backend.credentials.write() = Arc::new(next);
        let mut connection = state.instances[index].connection.clone();
        connection.auth_state = auth_state;
        connection.last_probed = probed_at;
        state.instances[index] = Arc::new(HttpInstance {
            backend_id: old.backend_id.clone(),
            backend: old.backend.clone(),
            roots: old.roots.clone(),
            connection: connection.clone(),
        });
        state.routes = build_routes(&state.instances);
        Ok(connection)
    }
}

pub use redirect_follower::{DISCLOSE_CREDENTIALS_KEY, RedirectFollowerWrapperFactory};

pub const REDIRECT_FOLLOWER_KIND: &str = "redirect_follower";

pub(crate) mod layers {
    use ovstorage_plugin::*;

    pub(crate) use crate::REDIRECT_FOLLOWER_KIND;

    pub(crate) fn descriptor(
        kind: impl Into<String>,
        layer_type: LayerType,
        accepts_connections: bool,
    ) -> LayerKindDescriptor {
        let kind = kind.into();
        LayerKindDescriptor {
            display_name: kind.clone(),
            kind,
            layer_type,
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections,
            auth_capable: false,
            // Declining is this helper's fixed answer, and only the
            // `redirect_follower` wrapper is built through it. The `http`
            // backend this crate also registers declares its own answer on its
            // own descriptor.
            supports_user_metadata: false,
        }
    }
}

pub(crate) fn config_u64(value: &ConfigValue, key: &str) -> Result<u64> {
    match value {
        ConfigValue::Int(value) if *value >= 0 => Ok(*value as u64),
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("layer config `{key}` must be a non-negative integer"),
        )),
    }
}

pub(crate) fn cache_config_field(
    key: &str,
    display_name: &str,
    kind: ConfigFieldKind,
    required: bool,
    help: &str,
) -> ConfigField {
    ConfigField {
        key: key.to_string(),
        display_name: display_name.to_string(),
        kind,
        required,
        default: None,
        help: Some(help.to_string()),
        example: None,
        group: None,
        advanced: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    fn spawn_http_fixture<F: FnOnce() + Send + 'static>(f: F) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("ovs-test-http".into())
            .spawn(f)
            .expect("failed to spawn thread")
    }

    /// Drain a `ReadResult` into its bytes + `ObjectInfo`. Whole-object reads
    /// return `Stream`; ranged reads return `Bytes`.
    async fn buffer_read(result: ReadResult) -> (Vec<u8>, ObjectInfo) {
        use futures::StreamExt;
        match result {
            ReadResult::Bytes { bytes, info } => (bytes, info),
            ReadResult::Stream { mut stream, info } => {
                let mut out = Vec::new();
                while let Some(chunk) = stream.next().await {
                    out.extend_from_slice(&chunk.unwrap());
                }
                (out, info)
            }
            other => panic!("unexpected read result: {other:?}"),
        }
    }

    /// A `ResolvedTarget` at the full fixture URL. `HttpBackend::new()` has no
    /// `root_url`, so `physical_url` passes the dispatch address through
    /// unchanged.
    fn target(addr: Url) -> ResolvedTarget {
        ResolvedTarget {
            backend_id: BackendId("http".into()),
            resolved_address: addr,
        }
    }

    #[tokio::test]
    async fn anonymous_http_read_and_stat() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut request = [0_u8; 1024];
                let len = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..len]);
                let body = if request.starts_with("HEAD ") {
                    Vec::new()
                } else {
                    b"hello-http".to_vec()
                };
                // `Connection: close` so reqwest does not pool the socket: the
                // fixture closes each connection after one reply, and a pooled
                // reuse of the dead HEAD connection makes the follow-up GET
                // fail with a Transient send error.
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"abc\"\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });

        let backend = HttpBackend::new();
        let addr = address::parse(&format!("http://127.0.0.1:{port}/object.txt")).unwrap();

        let stat = backend
            .stat(target(addr.clone()), StatOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(stat.etag.as_deref(), Some("abc"));

        let (bytes, info) = buffer_read(
            backend
                .read(target(addr.clone()), ReadOptions::default(), None)
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(bytes, b"hello-http");
        assert_eq!(info.address, addr);
        assert_eq!(info.etag.as_deref(), Some("abc"));
    }

    #[tokio::test]
    async fn http_read_forwards_strong_etag_precondition_and_maps_412() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            let mut stream = listener.incoming().next().unwrap().unwrap();
            let mut request = [0_u8; 1024];
            let len = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..len]);
            // RFC 7230: header names are case-insensitive; hyper lowercases on the wire.
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("if-match: \"abc\"\r\n")
            );
            let response = "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(response.as_bytes()).unwrap();
        });

        let backend = HttpBackend::new();
        let err = backend
            .read(
                target(address::parse(&format!("http://127.0.0.1:{port}/object.txt")).unwrap()),
                ReadOptions {
                    // SPI etag is the opaque token; the plugin re-quotes
                    // for the wire `If-Match` header.
                    if_match: Some("abc".into()),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ObjectModified);
    }

    #[tokio::test]
    async fn http_read_maps_503_to_transient() {
        // Retry orchestration is a host Stack wrapper concern now (covered by
        // ovstorage `tests/wrappers.rs`); the backend's contract is simply to
        // classify a 503 as `Transient` so the wrapper knows to retry.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            let mut stream = listener.incoming().next().unwrap().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nContent-Length: 0\r\n\r\n",
                )
                .unwrap();
        });

        let backend = HttpBackend::new();
        let err = backend
            .read(
                target(address::parse(&format!("http://127.0.0.1:{port}/eventual.txt")).unwrap()),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Transient);
    }

    #[test]
    fn weak_etag_in_check_identity_is_not_comparable() {
        // Weak etags ("W/...") match anything per RFC 7232; check_etag accepts.
        check_etag(Some("W/\"weak\""), Some("\"strong\"")).expect("weak etag accepted");
    }

    #[test]
    fn parse_default_headers_rejects_credential_headers() {
        let err = parse_default_headers(Some("Authorization=secret")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        let err = parse_default_headers(Some("cookie=session=abc")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn descriptor_declares_all_http_credential_channels() {
        let descriptor = HttpBackendFactory.descriptor();

        let schema: Vec<&str> = descriptor
            .credential_schema
            .iter()
            .map(|field| field.key.as_str())
            .collect();
        assert_eq!(
            schema,
            [
                "bearer_token",
                "username",
                "password",
                "signed_query",
                "secret_headers"
            ]
        );
        // No ambient pickup: there is no agreed environment variable for
        // "the token for arbitrary HTTP origin X", and this plugin can be
        // pointed at any host.
        assert!(
            descriptor
                .credential_schema
                .iter()
                .all(|field| field.default.is_none() && !field.advanced)
        );

        let methods: Vec<(&str, Vec<&str>)> = descriptor
            .credential_methods
            .iter()
            .map(|method| {
                (
                    method.key.as_str(),
                    method.fields.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            methods,
            [
                ("bearer", vec!["bearer_token"]),
                ("basic", vec!["username", "password"]),
                ("signed_query", vec!["signed_query"]),
                ("secret_headers", vec!["secret_headers"]),
            ]
        );

        // Every method field must name a schema entry, or the CLI's method
        // picker gathers a key the plugin will then reject as unknown.
        for method in &descriptor.credential_methods {
            for field in &method.fields {
                assert!(
                    schema.contains(&field.as_str()),
                    "method '{}' references undeclared field '{field}'",
                    method.key
                );
            }
        }

        assert_eq!(descriptor.display_name, "HTTP");
        assert_eq!(descriptor.kind, "http");
    }

    #[test]
    fn malformed_default_headers_entry_does_not_echo_a_credential() {
        // A colon instead of `=` is the natural HTTP spelling, so it is the
        // typo an operator actually makes — and it misses the banlist arm,
        // landing in the malformed-entry error instead. `Error::new` scrubs
        // `Bearer …` for us, so the schemes that matter here are Basic and
        // opaque ones.
        //
        // The padded rows are the ones that do reach `split_once('=')`: it
        // splits at the Base64 padding, so the credential arrives as the
        // "name" and any error naming the name publishes it.
        for (entry, secret) in [
            ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
            ("Authorization: Token abc123", "abc123"),
            ("Authorization: Basic dXNlcjpwYXM=", "dXNlcjpwYXM"),
            ("Authorization: Token abc123==", "abc123"),
            (
                "Authorization: Basic YWRtaW46aHVudGVyMg==",
                "YWRtaW46aHVudGVyMg",
            ),
        ] {
            let err = parse_default_headers(Some(entry)).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert!(
                !err.message().contains(secret),
                "malformed-entry error echoed a credential: {}",
                err.message()
            );
        }
    }

    #[test]
    fn every_channel_that_puts_a_secret_on_the_wire_arms_the_downgrade_guard() {
        let none = reqwest::header::HeaderMap::new();
        let pinned = parse_default_headers(Some("X-Api-Key=sekret")).unwrap();
        // A declared credential, and `root_url` userinfo, both arrive as
        // `carries_wire_auth`; a pinned header is the third channel, and the
        // transport's redirect-stripping list is fixed so it would survive a
        // hop the credential would not.
        assert!(carries_secret_on_the_wire(true, &none));
        assert!(carries_secret_on_the_wire(false, &pinned));
        assert!(carries_secret_on_the_wire(true, &pinned));
        // An anonymous connection with no pinned headers has nothing to lose
        // on a downgrade, and must keep following ordinary redirects.
        assert!(!carries_secret_on_the_wire(false, &none));
    }

    #[test]
    fn a_rejected_entry_is_numbered_as_an_operator_would_count_it() {
        // The number is the only identifier a rejected entry gets, so it has
        // to mean the third header they wrote, not the third comma slot.
        let err = parse_default_headers(Some("A=b,,C D=e")).unwrap_err();
        assert!(
            err.message().contains("entry #2"),
            "empty slots must not advance the count: {}",
            err.message()
        );
    }

    #[test]
    fn a_pinned_default_header_is_marked_sensitive() {
        // Nothing stops an operator pinning an `X-Api-Key`, and the redirect
        // policy already treats any pinned header as secret-bearing.
        let map = parse_default_headers(Some("X-Api-Key=sekret")).unwrap();
        let value = map.get("x-api-key").unwrap();
        assert!(value.is_sensitive());
        assert!(!format!("{value:?}").contains("sekret"));
    }

    #[test]
    fn the_probe_landing_check_compares_addresses_not_strings() {
        let parse = |s: &str| address::parse(s).unwrap();

        // reqwest strips userinfo from the request URL before sending, so the
        // response URL never carries it. Comparing as strings would report
        // every userinfo connection as diverted on a plain 200.
        assert!(probe_landed_on_root(
            &parse("http://h.example/files/"),
            &parse("http://user:pass@h.example/files/")
        ));
        // The normalization the probe follows on purpose.
        assert!(probe_landed_on_root(
            &parse("https://h.example/files/"),
            &parse("https://h.example/files")
        ));
        // A landing URL that gained a query is not the address the probe
        // asked about. `root_url` cannot carry one, so this is the only
        // direction the query clause can fire in.
        assert!(!probe_landed_on_root(
            &parse("https://h.example/files/?tenant=a"),
            &parse("https://h.example/files")
        ));
        // One slash, not any number: these are different paths to HTTP and an
        // origin may answer them differently.
        //
        // The landed URL is built with `Url::parse`, NOT `address::parse`,
        // and that is the whole point of the case. `final_url` is
        // `reqwest::Response::url()` — a wire value the transport built from a
        // `Location` header, which never passes through `address::parse` and so
        // never has its empty segments collapsed. Writing this row through
        // `address::parse` would fold it to `…/protected/` and assert that the
        // check tolerates a redirect it must actually reject.
        assert_eq!(
            parse("https://h.example/protected///").as_str(),
            "https://h.example/protected/",
            "address::parse collapses, which is why it cannot build this row"
        );
        assert!(!probe_landed_on_root(
            &Url::parse("https://h.example/protected///").unwrap(),
            &parse("https://h.example/protected/")
        ));
        // The cases that must stay diverted.
        assert!(!probe_landed_on_root(
            &parse("https://h.example/login/"),
            &parse("https://h.example/files/")
        ));
        assert!(!probe_landed_on_root(
            &parse("http://h.example/files/"),
            &parse("https://h.example/files/")
        ));
    }

    #[test]
    fn wholly_empty_userinfo_is_not_wire_authentication() {
        // `classify` refuses a Basic bundle with both halves empty, and the
        // question is whether userinfo can spell the same thing. It cannot:
        // `Url` drops the empty password, so the connection is simply
        // anonymous and no `Authorization` is ever built. Pinned because the
        // alternative — a guard for a state that cannot be constructed —
        // implies a hazard that does not exist.
        let parse = |s: &str| address::parse(s).unwrap();
        for spelling in ["http://:@h.example/", "http://@h.example/"] {
            let url = parse(spelling);
            assert_eq!(url.username(), "");
            assert_eq!(url.password(), None);
            assert!(
                !url_carries_userinfo(&url),
                "{spelling} must not count as wire authentication"
            );
        }
        // One half in either position is an ordinary credential.
        assert!(url_carries_userinfo(&parse("http://user@h.example/")));
        assert!(url_carries_userinfo(&parse("http://:pass@h.example/")));
    }

    #[test]
    fn a_rendered_credential_header_is_marked_sensitive() {
        // `set_sensitive` is what keeps the credential out of reqwest's
        // `Debug` output and out of HPACK's shared index. Nothing else in the
        // suite fails if that call is deleted.
        for credential in [
            credentials::HttpCredential::Bearer(credentials::SecretText::new("tok".into())),
            credentials::HttpCredential::Basic {
                username: credentials::SecretText::new("u".into()),
                password: credentials::SecretText::new("p".into()),
            },
        ] {
            let value = credential_header(&credential).unwrap();
            assert!(
                value.is_sensitive(),
                "the Authorization value must be marked sensitive"
            );
            assert!(
                !format!("{value:?}").contains("tok") && !format!("{value:?}").contains("dTpw"),
                "a sensitive HeaderValue must not Debug-print its bytes"
            );
        }
    }

    #[test]
    fn response_headers_that_describe_the_credential_are_not_republished() {
        // `system_metadata` crosses to callers who may be less privileged
        // than the connection's credential, so an origin's session and
        // challenge material must not ride out with the object's.
        let metadata = headers_to_metadata(HashMap::from([
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Set-Cookie".to_string(), "session=abc123".to_string()),
            ("set-cookie2".to_string(), "session=abc123".to_string()),
            ("WWW-Authenticate".to_string(), "Basic realm=x".to_string()),
            ("Authentication-Info".to_string(), "nextnonce=1".to_string()),
            ("Proxy-Authenticate".to_string(), "Basic".to_string()),
            ("authorization".to_string(), "Bearer tok".to_string()),
            ("x-vendor-id".to_string(), "keep-me".to_string()),
        ]));
        let mut kept: Vec<&str> = metadata.keys().map(String::as_str).collect();
        kept.sort_unstable();
        assert_eq!(kept, ["Content-Type", "x-vendor-id"]);
    }

    #[tokio::test]
    async fn reqwest_error_message_carries_no_request_url() {
        // Bind then drop, so the port is closed and `connect` fails at once.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let backend = HttpBackend::new();
        let address =
            address::parse(&format!("http://127.0.0.1:{port}/obj.bin?api_key=sekret")).unwrap();
        let err = backend
            .stat(target(address), StatOptions::default(), None)
            .await
            .expect_err("connect to a closed port must fail");

        // `api_key` is not in `REDACTED_QUERY_KEYS`, so `redact_url` leaves it
        // alone; the whole URL has to go instead.
        assert!(
            !err.message().contains("sekret") && !err.message().contains("127.0.0.1"),
            "reqwest error message carried the request URL: {}",
            err.message()
        );
    }

    #[test]
    fn parse_default_headers_accepts_safe_headers() {
        let map = parse_default_headers(Some("X-User=alice,X-Tenant=corp")).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("x-user").unwrap().to_str().unwrap(), "alice");
    }

    /// A fragment in `root_url` is an error at load, not a silent strip.
    ///
    /// `address::parse` would drop it — a fragment is client-side and never
    /// reaches a server — and dropping a component the operator wrote is
    /// exactly what has to fail loudly. The refusal is in `config_url`, which
    /// reads the raw string, because after the parse there is nothing left to
    /// see.
    ///
    /// The same `root_url` without the fragment loads, so the refusal is about
    /// the fragment and not about the address.
    #[test]
    fn a_fragment_in_root_url_is_refused_rather_than_stripped() {
        let instantiate = |root: &str| {
            let req = ConnectionRequest {
                backend_kind: "http".into(),
                config: HashMap::from([(
                    "root_url".to_string(),
                    ConfigValue::String(root.to_string()),
                )]),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            };
            futures::executor::block_on(HttpBackendFactory.instantiate(&req, None))
        };

        let Err(err) = instantiate("http://example.com/path#frag") else {
            panic!("a fragment-bearing root_url must be refused");
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("fragment"), "{}", err.message());

        let Ok(backend) = instantiate("http://example.com/path") else {
            panic!("the same root without a fragment must load");
        };
        let root = backend
            .address_roots
            .first()
            .expect("one published root")
            .address
            .clone();
        assert_eq!(root.as_str(), "http://example.com/path");
    }

    fn chain(urls: &[&str]) -> Vec<Url> {
        urls.iter().map(|u| address::parse(u).unwrap()).collect()
    }

    #[test]
    fn an_authenticated_redirect_may_not_downgrade_to_cleartext() {
        let allow = FollowScope::AllowList(vec!["h.example".into()]);

        // reqwest keeps `Authorization` here: its check compares host and
        // `port_or_known_default`, and both are unchanged. The allow-list
        // matches on host alone, so nothing else stops the downgrade.
        assert!(!redirect_is_allowed(
            &chain(&["https://h.example:8443/"]),
            &address::parse("http://h.example:8443/").unwrap(),
            &allow,
            true,
            false,
        ));

        // Upgrade-then-downgrade: the *first* hop and the last share a scheme,
        // so a guard comparing against `previous.first()` would follow this.
        assert!(!redirect_is_allowed(
            &chain(&["http://h.example:8443/", "https://h.example:8443/"]),
            &address::parse("http://h.example:8443/").unwrap(),
            &allow,
            true,
            false,
        ));

        // An `http` -> `https` upgrade is safe and must keep working, so the
        // guard is a downgrade check and not a scheme-equality check.
        assert!(redirect_is_allowed(
            &chain(&["http://h.example:8443/"]),
            &address::parse("https://h.example:8443/").unwrap(),
            &allow,
            true,
            false,
        ));

        // An anonymous connection has nothing to disclose.
        assert!(redirect_is_allowed(
            &chain(&["https://h.example:8443/"]),
            &address::parse("http://h.example:8443/").unwrap(),
            &allow,
            false,
            false,
        ));
    }

    #[test]
    fn a_redirect_chain_is_capped() {
        // `Policy::custom` does not inherit reqwest's own chain limit, so
        // without the cap a redirect cycle spins until the request timeout.
        let scope = FollowScope::SameOrigin;
        let next = address::parse("https://h.example/").unwrap();
        // Fixed lengths, not `MAX_REDIRECT_HOPS ± 1`: deriving the input from
        // the constant asserts only that the cap equals itself, and setting
        // the constant to 1 — which breaks ordinary multi-hop redirects —
        // would leave that green.
        assert_eq!(MAX_REDIRECT_HOPS, 10, "the documented hop budget");
        let chain_of = |n: usize| -> Vec<Url> { std::iter::repeat_n(next.clone(), n).collect() };
        assert!(redirect_is_allowed(
            &chain_of(1),
            &next,
            &scope,
            false,
            false
        ));
        assert!(redirect_is_allowed(
            &chain_of(10),
            &next,
            &scope,
            false,
            false
        ));
        assert!(!redirect_is_allowed(
            &chain_of(11),
            &next,
            &scope,
            false,
            false
        ));
        // An empty chain is not a redirect at all.
        assert!(!redirect_is_allowed(&[], &next, &scope, false, false));
    }

    #[test]
    fn same_origin_scope_compares_the_preceding_hop() {
        let scope = FollowScope::SameOrigin;
        assert!(redirect_is_allowed(
            &chain(&["https://h.example/a"]),
            &address::parse("https://h.example/b").unwrap(),
            &scope,
            true,
            false,
        ));
        assert!(!redirect_is_allowed(
            &chain(&["https://h.example/a"]),
            &address::parse("https://other.example/b").unwrap(),
            &scope,
            true,
            false,
        ));
        // Two hops, where the chain's first and last elements disagree: a
        // comparison against `previous.first()` would allow the return hop to
        // the original origin even though the preceding hop is elsewhere.
        assert!(!redirect_is_allowed(
            &chain(&["https://h.example/a", "https://other.example/b"]),
            &address::parse("https://h.example/c").unwrap(),
            &scope,
            true,
            false,
        ));
    }

    #[test]
    fn build_redirect_policy_rejects_unknown() {
        let err = build_redirect_policy("invalid-mode", None, false).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn build_redirect_policy_accepts_three_modes() {
        build_redirect_policy("none", None, false).expect("none");
        build_redirect_policy("same_origin", None, false).expect("same_origin");
        build_redirect_policy("allow_list", Some("a.example.com,b.example.com"), false)
            .expect("allow_list");
    }

    #[test]
    fn credentialed_origin_requires_https_or_literal_ipv4_loopback() {
        let bearer = SecretBytes(b"access-token".to_vec());
        assert!(
            validate_credentialed_origin(
                &Url::parse("https://objects.example/item").unwrap(),
                Some(&bearer),
            )
            .is_ok()
        );
        assert!(
            validate_credentialed_origin(
                &Url::parse("http://127.0.0.1:8080/item").unwrap(),
                Some(&bearer),
            )
            .is_ok()
        );
        for address in ["http://objects.example/item", "http://localhost:8080/item"] {
            assert_eq!(
                validate_credentialed_origin(&Url::parse(address).unwrap(), Some(&bearer))
                    .unwrap_err()
                    .code(),
                ErrorCode::PermissionDenied,
            );
        }
        assert!(
            validate_credentialed_origin(
                &Url::parse("http://objects.example/item").unwrap(),
                None,
            )
            .is_ok(),
            "anonymous HTTP retains its existing cleartext behavior"
        );
    }

    #[tokio::test]
    async fn resolved_credential_reference_is_backend_scoped_and_requires_principal() {
        ovstorage::init_auth_substrate(None).unwrap();
        let layer: LayerHandle = HttpBackendLayerFactory::default()
            .create_backend("http", &LayerConfig::new(), None)
            .await
            .unwrap();
        let address = Url::parse("https://objects.example/item").unwrap();

        let mut wrong_backend = Request::new(ReadRequest {
            address: address.clone(),
            options: ReadOptions::default(),
        });
        ovstorage_plugin::ext::insert_resolved_oauth_credential(
            &mut wrong_backend.extensions,
            &ovstorage_plugin::ext::ResolvedOAuthCredentialRef {
                backend_kind: "s3".into(),
                keyring_handle: "oauth/provider".into(),
            },
        )
        .unwrap();
        assert_eq!(
            layer.read(wrong_backend, None).await.unwrap_err().code(),
            ErrorCode::InvalidArgument,
        );

        let mut missing_principal = Request::new(ReadRequest {
            address,
            options: ReadOptions::default(),
        });
        ovstorage_plugin::ext::insert_resolved_oauth_credential(
            &mut missing_principal.extensions,
            &ovstorage_plugin::ext::ResolvedOAuthCredentialRef {
                backend_kind: "http".into(),
                keyring_handle: "oauth/provider".into(),
            },
        )
        .unwrap();
        assert_eq!(
            layer
                .read(missing_principal, None)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::CredentialUnavailable,
        );

        let mut direct_host_forgery = Request::new(ReadRequest {
            address: Url::parse("https://objects.example/item").unwrap(),
            options: ReadOptions::default(),
        });
        direct_host_forgery
            .extensions
            .insert(ovstorage_plugin::ext::PRINCIPAL_ID, b"victim".to_vec());
        ovstorage_plugin::ext::insert_resolved_oauth_credential(
            &mut direct_host_forgery.extensions,
            &ovstorage_plugin::ext::ResolvedOAuthCredentialRef {
                backend_kind: "http".into(),
                keyring_handle: "oauth/provider".into(),
            },
        )
        .unwrap();
        assert_eq!(
            layer
                .read(direct_host_forgery, None)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::PermissionDenied,
            "a direct host cannot forge broker-minted keyring context",
        );
    }

    #[test]
    fn map_status_412_with_headers_carries_identity_context() {
        let mut headers = HashMap::new();
        headers.insert("etag".to_string(), "\"new-etag\"".to_string());
        let err = map_status(412, Some(&headers));
        assert_eq!(err.code(), ErrorCode::ObjectModified);
        match err.context() {
            Some(ErrorContext::Identity { new_etag }) => {
                assert_eq!(new_etag.as_deref(), Some("new-etag"));
            }
            other => panic!("expected Identity context, got {other:?}"),
        }
    }

    #[test]
    fn strip_etag_wire_form_handles_quotes_and_weak_prefix() {
        assert_eq!(strip_etag_wire_form("\"abc\""), "abc");
        assert_eq!(strip_etag_wire_form("abc"), "abc");
        assert_eq!(strip_etag_wire_form("W/\"weak\""), "weak");
        assert_eq!(strip_etag_wire_form("W/weak"), "weak");
        assert_eq!(strip_etag_wire_form("  \"padded\"  "), "padded");
    }

    #[tokio::test]
    async fn stat_etag_round_trips_through_if_match() {
        // Server returns a quoted etag on stat; the SPI etag is the
        // opaque token (unquoted). Re-using that token as
        // `ReadOptions.if_match` must round-trip — the plugin re-adds
        // the wire quoting when sending `If-Match` upstream, so the
        // server matches and returns 200.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut request = [0_u8; 1024];
                let n = stream.read(&mut request).unwrap();
                let raw = std::str::from_utf8(&request[..n]).unwrap();
                let has_if_match = raw
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("if-match: \"abc\""));
                // `Connection: close`: one reply per accepted connection, so the
                // client must not pool the stat socket for the follow-up read.
                let response = if has_if_match || !raw.contains("If-Match") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"abc\"\r\nConnection: close\r\n\r\nhello"
                } else {
                    "HTTP/1.1 412 Precondition Failed\r\nETag: \"abc\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                stream.write_all(response.as_bytes()).unwrap();
            }
        });

        let backend = HttpBackend::new();
        let stat = backend
            .stat(
                target(address::parse(&format!("http://127.0.0.1:{port}/object.txt")).unwrap()),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap();
        let etag = stat.etag.clone().expect("etag");
        assert_eq!(etag, "abc", "SPI etag is the unquoted opaque token");
        let (bytes, _info) = buffer_read(
            backend
                .read(
                    target(address::parse(&format!("http://127.0.0.1:{port}/object.txt")).unwrap()),
                    ReadOptions {
                        if_match: Some(etag),
                        ..ReadOptions::default()
                    },
                    None,
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(&bytes[..], b"hello");
    }

    #[test]
    fn map_status_412_without_headers_omits_context() {
        let err = map_status(412, None);
        assert_eq!(err.code(), ErrorCode::ObjectModified);
        assert!(err.context().is_none());
    }

    #[test]
    fn map_status_401_is_auth_required_with_context() {
        let err = map_status(401, None);
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ErrorContext::Auth {
                reason, expired_at, ..
            }) => {
                assert_eq!(reason.as_deref(), Some("http_unauthorized"));
                assert!(expired_at.is_none());
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    #[test]
    fn map_status_403_is_permission_denied_no_context() {
        let err = map_status(403, None);
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.context().is_none());
    }

    #[test]
    fn check_identity_mismatch_carries_identity_context() {
        let err = check_etag(Some("\"old\""), Some("\"new\"")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ObjectModified);
        match err.context() {
            Some(ErrorContext::Identity { new_etag }) => {
                assert_eq!(new_etag.as_deref(), Some("\"new\""));
            }
            other => panic!("expected Identity context, got {other:?}"),
        }
    }

    fn instantiate_backend(config: HashMap<String, ConfigValue>) -> InstantiatedBackend {
        let factory = HttpBackendFactory;
        let req = ConnectionRequest {
            backend_kind: "http".into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        };
        futures::executor::block_on(factory.instantiate(&req, None)).unwrap()
    }

    fn config_of(pairs: &[(&str, &str)]) -> HashMap<String, ConfigValue> {
        pairs
            .iter()
            .map(|(key, value)| {
                (
                    (*key).to_string(),
                    ConfigValue::String((*value).to_string()),
                )
            })
            .collect()
    }

    fn credential_bundle(pairs: &[(&str, &str)]) -> SecretBundle {
        let mut bundle = SecretBundle::default();
        for (key, value) in pairs {
            bundle.fields.insert(
                (*key).to_string(),
                SecretValue::Bytes(SecretBytes(value.as_bytes().to_vec())),
            );
        }
        bundle
    }

    /// A credentialed `instantiate` probes the origin, so — unlike
    /// [`instantiate_backend`] — this must be awaited inside the test's tokio
    /// runtime rather than driven by `futures::executor::block_on`, which
    /// provides no reactor for the probe's HTTP client.
    async fn instantiate_with_credentials(
        config: HashMap<String, ConfigValue>,
        credentials: SecretBundle,
    ) -> Result<InstantiatedBackend> {
        HttpBackendFactory
            .instantiate(
                &ConnectionRequest {
                    backend_kind: "http".into(),
                    config,
                    credentials,
                    persist: false,
                    display_name: None,
                },
                None,
            )
            .await
    }

    /// `InstantiatedBackend` has no `Debug`, so `expect_err` is unavailable.
    async fn instantiate_rejected(
        config: HashMap<String, ConfigValue>,
        credentials: SecretBundle,
        why: &str,
    ) -> Error {
        match instantiate_with_credentials(config, credentials).await {
            Ok(_) => panic!("{why}"),
            Err(err) => err,
        }
    }

    #[tokio::test]
    async fn instantiate_rejects_a_malformed_credential_bundle() {
        for pairs in [
            // An unknown key: the caller named a field this build does not
            // know, and silently authenticating with less is worse than a
            // refusal.
            vec![("aws_access_key_id", "AKIA")],
            // Half a pair. An empty *value* is a different matter — RFC 7617
            // allows one empty half — but an absent key is not a credential.
            vec![("username", "u")],
            // Both halves empty authenticates as nobody.
            vec![("username", ""), ("password", "")],
            // Two shapes at once: there is no rule for which would win.
            vec![("bearer_token", "tok"), ("username", "u")],
        ] {
            let err = instantiate_with_credentials(
                config_of(&[("root_url", "https://origin.example/")]),
                credential_bundle(&pairs),
            )
            .await
            .err()
            .expect("a malformed credential bundle must fail the connection");
            assert_eq!(
                err.code(),
                ErrorCode::InvalidArgument,
                "bundle {pairs:?} was not rejected"
            );
        }
    }

    #[tokio::test]
    async fn a_credential_reaches_both_request_builders_and_the_probe() {
        use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer, request_has_header};

        for (pairs, expected) in [
            (vec![("bearer_token", "tok")], "Bearer tok"),
            (vec![("username", "u"), ("password", "p")], "Basic dTpw"),
            // An API key as the user-id with no password: `base64("key:")`.
            (
                vec![("username", "key"), ("password", "")],
                "Basic a2V5Og==",
            ),
        ] {
            let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "hello"));
            let instance = instantiate_with_credentials(
                config_of(&[("root_url", server.endpoint())]),
                credential_bundle(&pairs),
            )
            .await
            .expect("a credentialed loopback connection is accepted");

            let object = address::parse(&format!("{}/obj.bin", server.endpoint())).unwrap();
            let resolved = ResolvedTarget {
                backend_id: instance.backend_id.clone(),
                resolved_address: object,
            };
            // Whole-object read and `stat` go through two *different* request
            // builders; a single-path assertion would pass while the default
            // read path sent nothing.
            let read = instance
                .backend
                .read(resolved.clone(), ReadOptions::default(), None)
                .await
                .unwrap();
            let (bytes, _) = buffer_read(read).await;
            assert_eq!(bytes, b"hello");
            instance
                .backend
                .stat(resolved, StatOptions::default(), None)
                .await
                .unwrap();

            let requests = server.requests();
            assert_eq!(
                requests.len(),
                3,
                "expected probe + read + stat, got {requests:?}"
            );
            // Request 1 is the probe on the root, so the read and stat
            // assertions below cannot be satisfied by the probe's header.
            assert!(
                requests[0].starts_with("HEAD / "),
                "first request must be the root probe: {:?}",
                requests[0]
            );
            assert!(requests[1].starts_with("GET /obj.bin "));
            assert!(requests[2].starts_with("HEAD /obj.bin "));
            for (index, raw) in requests.iter().enumerate() {
                assert!(
                    request_has_header(raw, "authorization", expected),
                    "request {index} carried no '{expected}': {raw:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn the_probe_records_what_it_learned() {
        use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

        // An anonymous connection is not probed at all, and must not claim one.
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "hi"));
        let anonymous = instantiate_with_credentials(
            config_of(&[("root_url", server.endpoint())]),
            SecretBundle::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            anonymous.auth_state,
            ConnectionAuthState::Anonymous
        ));
        assert!(anonymous.probed_at.is_none());
        assert_eq!(server.hits(), 0, "an anonymous add must not reach the wire");

        // The origin answered and did not refuse the credential.
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "hi"));
        let ok = instantiate_with_credentials(
            config_of(&[("root_url", server.endpoint())]),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .unwrap();
        assert!(matches!(
            ok.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ));
        assert!(ok.probed_at.is_some());

        // 403 registers, but claims nothing. A bad token and a
        // correctly-scoped one that cannot read the root are indistinguishable
        // from the status alone, and a HEAD carries no body to discriminate
        // with.
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("403 Forbidden", ""));
        let scoped = instantiate_with_credentials(
            config_of(&[("root_url", server.endpoint())]),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .expect("403 must not fail the connection");
        // The note names the status: it is the operator's only handle on
        // which of `403`, `404`, `405`, `429` or `503` they are looking at,
        // and `print_success` shows this string verbatim.
        match &scoped.auth_state {
            ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::Unknown { details },
                ..
            } => assert!(
                details.contains("403"),
                "the unproven note dropped the observed status: {details}"
            ),
            other => panic!("403 is not evidence either way, got {other:?}"),
        }

        // 401 is a refusal. The connection still registers — the probe records
        // what it learned, it does not decide whether the host may boot — but
        // it says so.
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("401 Unauthorized", ""));
        let refused = instantiate_with_credentials(
            config_of(&[("root_url", server.endpoint())]),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .expect("a refused credential must not fail the add");
        match &refused.auth_state {
            ConnectionAuthState::AuthFailed { error, attempts } => {
                assert_eq!(error.code(), ErrorCode::AuthRequired);
                assert_eq!(*attempts, 1);
            }
            other => panic!("expected AuthFailed, got {other:?}"),
        }
        assert!(refused.probed_at.is_some(), "the probe did reach the wire");

        // No HTTP response at all: nothing was learned, so nothing is claimed.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let unreachable = instantiate_with_credentials(
            config_of(&[("root_url", &format!("http://127.0.0.1:{port}/"))]),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .expect("an unreachable origin must not fail the add");
        assert!(matches!(
            unreachable.auth_state,
            ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::BackendUnreachable,
                ..
            }
        ));
        assert!(
            unreachable.probed_at.is_none(),
            "last_probed must not claim a probe that never reached an origin"
        );
    }

    /// The assertions above are on the private carrier. This one is on the
    /// public `Connection.last_probed` that callers actually see, so
    /// re-wiring it back to an unconditional `Some(now)` cannot pass.
    #[tokio::test]
    async fn last_probed_is_published_only_when_a_probe_reached_an_origin() {
        use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

        let _ = ovstorage::init_auth_substrate(None);
        let layer: LayerHandle = HttpBackendLayerFactory::default()
            .create_backend("http", &LayerConfig::new(), None)
            .await
            .unwrap();

        let add = async |root_url: String, credentials: SecretBundle| {
            layer
                .add_connection(
                    Request::new(LayerConnectionRequest {
                        target: "http".into(),
                        connection: ConnectionRequest {
                            backend_kind: "http".into(),
                            config: HashMap::from([(
                                "root_url".into(),
                                ConfigValue::String(root_url),
                            )]),
                            credentials,
                            persist: false,
                            display_name: None,
                        },
                    }),
                    None,
                )
                .await
        };

        // Anonymous: no probe is made at all.
        let origin = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
        let anonymous = add(origin.endpoint().to_string(), SecretBundle::default())
            .await
            .unwrap();
        assert!(
            anonymous.last_probed.is_none(),
            "an unprobed connection must publish no probe time"
        );

        // Credentialed against a live origin: a probe landed.
        let origin = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
        let probed = add(
            origin.endpoint().to_string(),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .unwrap();
        assert!(
            probed.last_probed.is_some(),
            "a probe that reached an origin must publish its time"
        );

        // Credentialed against a closed port: nothing reached an origin.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let unreachable = add(
            format!("http://127.0.0.1:{port}/"),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .unwrap();
        assert!(
            unreachable.last_probed.is_none(),
            "a probe that never reached an origin must publish no time"
        );
    }

    #[tokio::test]
    async fn the_probe_claims_authentication_only_on_positive_evidence() {
        use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer, request_has_header};

        // A same-origin hop is followed, because the transport keeps
        // `Authorization` across it — so the chain stays attributable and a
        // 401 behind `301 /files -> /files/` is a real refusal.
        let origin = ScriptedHttpServer::spawn_sequence(vec![
            Some(
                CannedHttpResponse::new("301 Moved Permanently", "")
                    .with_header("Location", "/files/"),
            ),
            Some(CannedHttpResponse::new("401 Unauthorized", "")),
        ]);
        let followed = instantiate_with_credentials(
            config_of(&[("root_url", origin.endpoint())]),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .unwrap();
        assert!(
            matches!(followed.auth_state, ConnectionAuthState::AuthFailed { .. }),
            "a same-origin hop stays attributable, got {:?}",
            followed.auth_state
        );
        assert_eq!(origin.hits(), 2, "the same-origin hop is followed");

        // The mirror image, and the reason a 2xx alone is not evidence: an
        // origin that bounces an unaccepted credential to its sign-in page
        // answers 200 from a different address. The hop is same-origin, so
        // the transport carries `Authorization` across it and nothing but the
        // landing address separates this from an honoured credential.
        let login = ScriptedHttpServer::spawn_sequence(vec![
            Some(CannedHttpResponse::new("302 Found", "").with_header("Location", "/login/")),
            Some(CannedHttpResponse::new("200 OK", "sign in")),
        ]);
        let diverted = instantiate_with_credentials(
            config_of(&[("root_url", login.endpoint())]),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .unwrap();
        assert_eq!(login.hits(), 2, "the same-origin hop is followed");
        assert!(
            matches!(
                diverted.auth_state,
                ConnectionAuthState::AwaitingAuth { .. }
            ),
            "a 2xx from somewhere other than root_url is not evidence, got {:?}",
            diverted.auth_state
        );

        // And the trailing-slash normalization the probe follows on purpose
        // still lands on root_url, so it stays positive evidence.
        let normalized = ScriptedHttpServer::spawn_sequence(vec![
            Some(CannedHttpResponse::new("301 Moved Permanently", "").with_header("Location", "/")),
            Some(CannedHttpResponse::new("200 OK", "")),
        ]);
        let slash = instantiate_with_credentials(
            config_of(&[("root_url", normalized.endpoint().trim_end_matches('/'))]),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .unwrap();
        assert!(
            matches!(slash.auth_state, ConnectionAuthState::Authenticated { .. }),
            "a trailing-slash hop lands on the same resource, got {:?}",
            slash.auth_state
        );
        // The premise the whole design rests on: the credential survives that
        // hop. Without this the 401 above would be unattributable and the
        // `AuthFailed` verdict wrong.
        let seen = origin.requests();
        assert!(
            request_has_header(&seen[1], "authorization", "Bearer tok"),
            "the credential must survive a same-origin hop: {}",
            seen[1]
        );

        // Anything that is neither an acceptance nor a refusal claims nothing.
        // `Authenticated` requires positive evidence; it is not the fallthrough.
        for status in [
            "302 Found",
            "403 Forbidden",
            "404 Not Found",
            "503 Service Unavailable",
        ] {
            let server = ScriptedHttpServer::spawn(
                CannedHttpResponse::new(status, "")
                    .with_header("Location", "https://elsewhere.invalid/"),
            );
            let instance = instantiate_with_credentials(
                config_of(&[("root_url", server.endpoint())]),
                credential_bundle(&[("bearer_token", "tok")]),
            )
            .await
            .unwrap();
            assert!(
                matches!(
                    instance.auth_state,
                    ConnectionAuthState::AwaitingAuth {
                        reason: AuthReason::Unknown { .. },
                        ..
                    }
                ),
                "{status} establishes nothing, got {:?}",
                instance.auth_state
            );
        }

        // A `2xx` is the only class that shows the credential being honoured.
        let served = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "ok"));
        let instance = instantiate_with_credentials(
            config_of(&[("root_url", served.endpoint())]),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .unwrap();
        assert!(matches!(
            instance.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ));
    }

    #[tokio::test]
    async fn the_probe_never_follows_a_hop_the_data_path_would_refuse() {
        use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

        // With `redirect_policy = "none"` an ordinary read surfaces the 3xx as
        // `Unsupported`, so a probe that followed it would report a working,
        // authenticated connection whose every read fails. The probe's follow
        // set is the configured policy intersected with same-origin, so it
        // stops here too and claims nothing.
        let origin = ScriptedHttpServer::spawn(
            CannedHttpResponse::new("302 Found", "").with_header("Location", "/moved/"),
        );
        let instance = instantiate_with_credentials(
            config_of(&[("root_url", origin.endpoint()), ("redirect_policy", "none")]),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .unwrap();
        assert_eq!(origin.hits(), 1, "the probe must not follow the hop");
        assert!(
            matches!(
                instance.auth_state,
                ConnectionAuthState::AwaitingAuth { .. }
            ),
            "a hop the data path refuses proves nothing, got {:?}",
            instance.auth_state
        );

        // And the data path does refuse it, which is what makes the probe's
        // verdict consistent with what reads will do.
        let err = instance
            .backend
            .stat(
                ResolvedTarget {
                    backend_id: instance.backend_id.clone(),
                    resolved_address: address::parse(&format!("{}/obj.bin", origin.endpoint()))
                        .unwrap(),
                },
                StatOptions::default(),
                None,
            )
            .await
            .expect_err("redirect_policy = none surfaces the 3xx");
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn the_probe_does_not_cross_an_origin_the_data_path_is_allowed_to() {
        use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

        // `allow_list` lets the DATA path leave the origin, and the transport
        // strips `Authorization` when it does — so a verdict from the far end
        // would describe a request that never carried the credential. The
        // probe's follow set is intersected with same-origin for exactly this,
        // and nothing else in the suite reaches that intersection: the other
        // probe tests use `same_origin` (where the scope already stops the
        // hop) or `none` (which short-circuits before the callback runs).
        let destination = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "followed"));
        let origin = ScriptedHttpServer::spawn(
            CannedHttpResponse::new("302 Found", "")
                .with_header("Location", format!("{}/moved.bin", destination.endpoint())),
        );
        let instance = instantiate_with_credentials(
            config_of(&[
                ("root_url", origin.endpoint()),
                ("redirect_policy", "allow_list"),
                ("redirect_allow_hosts", "127.0.0.1"),
            ]),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .unwrap();

        assert_eq!(
            destination.hits(),
            0,
            "the probe must not carry the credential off the origin: {:?}",
            destination.requests()
        );
        assert!(
            matches!(
                instance.auth_state,
                ConnectionAuthState::AwaitingAuth { .. }
            ),
            "a cross-origin answer proves nothing about the configured root, got {:?}",
            instance.auth_state
        );

        // The data path is still allowed to follow it — the intersection
        // narrows the probe, not the connection.
        instance
            .backend
            .stat(
                ResolvedTarget {
                    backend_id: instance.backend_id.clone(),
                    resolved_address: address::parse(&format!("{}/obj.bin", origin.endpoint()))
                        .unwrap(),
                },
                StatOptions::default(),
                None,
            )
            .await
            .expect("allow_list follows the listed host on the data path");
        assert_eq!(destination.hits(), 1, "the data path did follow it");
    }

    #[test]
    fn loopback_covers_the_spellings_of_the_local_interface() {
        for host in [
            "127.0.0.1",
            "127.0.0.53",
            "localhost",
            "[::1]",
            "[::ffff:127.0.0.1]",
        ] {
            assert!(
                is_loopback_host(&address::parse(&format!("http://{host}/")).unwrap()),
                "{host} is the local interface"
            );
        }
        for host in [
            // The trailing-root-dot spelling. glibc forwards it to DNS rather
            // than answering `127.0.0.1`, so it is not the local interface
            // here and must not waive the cleartext guard.
            "localhost.",
            "localhost.evil.test",
            "example.test",
            "[::ffff:8.8.8.8]",
            "8.8.8.8",
        ] {
            assert!(
                !is_loopback_host(&address::parse(&format!("http://{host}/")).unwrap()),
                "{host} is not the local interface"
            );
        }
    }

    #[tokio::test]
    async fn userinfo_over_cleartext_is_refused_like_any_other_credential() {
        // Userinfo authenticates on the wire, so it is subject to the same
        // transport rule as a declared credential. A guard that saw only the
        // declared fields would let the older channel send Basic credentials
        // in clear to a public host.
        let err = instantiate_rejected(
            config_of(&[("root_url", "http://alice:hunter2@cdn.example.test/")]),
            SecretBundle::default(),
            "cleartext userinfo to a public host must be refused",
        )
        .await;
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("cleartext"));
        assert!(!err.message().contains("hunter2"));

        // Loopback keeps working, which is what the in-crate fixtures use.
        instantiate_with_credentials(
            config_of(&[("root_url", "http://alice:hunter2@127.0.0.1:9/")]),
            SecretBundle::default(),
        )
        .await
        .expect("loopback userinfo stays exempt");

        // HTTPS is unaffected. Checked through the guard directly rather than
        // a full instantiate, which would probe a name over the network.
        validate_credential_transport(
            &address::parse("https://alice:hunter2@cdn.example.test/").unwrap(),
        )
        .expect("userinfo over TLS is fine");
    }

    /// A **configuration** address may not carry a query or a fragment, and
    /// neither of this plugin's two config addresses is exempt.
    ///
    /// The refusal replaces a mechanism rather than tightening one.
    /// `root_url`'s query used to be spliced onto every projected request, so
    /// the connection held a signature the caller never had and could not see;
    /// a signed root now belongs in an explicit credential field routed
    /// through the credential system.
    ///
    /// **The honest config is asserted beside every refusal, and end to end.**
    /// A refusal and a silent drop are indistinguishable to a test that only
    /// checks the good config did not error, so the last block loads a plain
    /// root, dispatches through the published prefix, and reads the request
    /// line the origin actually saw.
    ///
    /// Load-bearing line: the `address::refused_config_component` block in
    /// `config_url`. Deleting it turns all four refusal rows red — each on its
    /// own `expect_err` — and leaves the routing block green.
    #[tokio::test]
    async fn a_config_address_may_not_carry_a_query_or_a_fragment() {
        for (config, component, what) in [
            (
                config_of(&[("root_url", "https://cdn.example.test/c/?sig=SECRET")]),
                "query",
                "a query on root_url",
            ),
            (
                config_of(&[("root_url", "https://cdn.example.test/c/#SECRET")]),
                "fragment",
                "a fragment on root_url",
            ),
            (
                config_of(&[
                    ("root_url", "https://cdn.example.test/c/"),
                    ("prefix", "https://public.example/?v=SECRET"),
                ]),
                "query",
                "a query on prefix",
            ),
            (
                config_of(&[
                    ("root_url", "https://cdn.example.test/c/"),
                    ("prefix", "https://public.example/#SECRET"),
                ]),
                "fragment",
                "a fragment on prefix",
            ),
        ] {
            let err = instantiate_rejected(config, SecretBundle::default(), what).await;
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{what}");
            assert!(
                err.message().contains(component),
                "{what}: the refusal must name what it refused, got: {}",
                err.message()
            );
            // The value is not echoed: a query is exactly where a signature
            // lives, and this message reaches a startup log.
            assert!(
                !err.message().contains("SECRET"),
                "{what}: the refusal echoed the value: {}",
                err.message()
            );
        }

        // The good input, end to end. A plain `root_url` and a plain explicit
        // `prefix` load, publish an address space, and route a read onto the
        // origin's own path.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(std::sync::Mutex::new(String::new()));
        let captured_clone = captured.clone();
        spawn_http_fixture(move || {
            let mut stream = listener.incoming().next().unwrap().unwrap();
            let mut buf = [0_u8; 1024];
            let len = stream.read(&mut buf).unwrap();
            *captured_clone.lock().unwrap() = String::from_utf8_lossy(&buf[..len]).to_string();
            let body = b"ok";
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"x\"\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.write_all(body).unwrap();
        });
        let instance = instantiate_backend(config_of(&[
            ("root_url", &format!("http://127.0.0.1:{port}/origin/")),
            ("prefix", "https://datasets.example/"),
        ]));
        let target = ResolvedTarget {
            backend_id: instance.backend_id.clone(),
            resolved_address: address::parse("https://datasets.example/file.bin").unwrap(),
        };
        instance
            .backend
            .read(target, ReadOptions::default(), None)
            .await
            .expect("a query-free config must still route");
        let line = captured.lock().unwrap().clone();
        assert!(
            line.starts_with("GET /origin/file.bin "),
            "the honest config must reach the origin's own path, got: {line:?}"
        );
    }

    #[tokio::test]
    async fn a_root_url_scheme_the_transport_cannot_serve_is_refused() {
        // `root_url` is the physical origin every request is rewritten onto,
        // so an unusable scheme is a config error, not a per-read failure.
        let err = instantiate_rejected(
            config_of(&[
                ("root_url", "ftp://files.example/"),
                ("prefix", "https://public.example/"),
            ]),
            SecretBundle::default(),
            "an unsupported root_url scheme must be refused",
        )
        .await;
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("ftp"));

        // `prefix` is caller-facing and documented as free to differ.
        instantiate_with_credentials(
            config_of(&[
                ("root_url", "https://origin.example/"),
                ("prefix", "ov://public.example/"),
            ]),
            SecretBundle::default(),
        )
        .await
        .expect("a caller-facing prefix may use another scheme");
    }

    #[tokio::test]
    async fn a_query_bearing_root_is_refused_before_the_duplicate_check() {
        let layer: LayerHandle = HttpBackendLayerFactory::default()
            .create_backend("http", &LayerConfig::new(), None)
            .await
            .unwrap();
        let add = |root: &str| {
            let layer = layer.clone();
            let config = config_of(&[("root_url", root)]);
            async move {
                layer
                    .add_connection(
                        Request::new(LayerConnectionRequest {
                            target: "http".into(),
                            connection: ConnectionRequest {
                                backend_kind: "http".into(),
                                config,
                                credentials: SecretBundle::default(),
                                persist: false,
                                display_name: None,
                            },
                        }),
                        None,
                    )
                    .await
            }
        };

        // The spelling that used to carry a secret here is refused before it
        // can reach the duplicate check at all: a config address may not carry
        // a query.
        let err = add("https://cdn.example/assets/?api_key=sekret")
            .await
            .expect_err("a query-bearing root_url is refused at load");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            !err.message().contains("sekret"),
            "the load refusal leaked the query: {}",
            err.message()
        );

        // And the duplicate check itself still fires on the query-free
        // spelling, or the row above would prove nothing about it.
        add("https://cdn.example/assets/").await.unwrap();
        let err = add("https://cdn.example/assets/")
            .await
            .expect_err("a duplicate prefix is refused");
        assert_eq!(err.code(), ErrorCode::RouteConflict);
    }

    #[tokio::test]
    async fn the_configured_redirect_policy_is_actually_installed() {
        use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

        // Drive a real client so the test fails if `redirect_is_allowed` stops
        // being wired into the policy, not merely if its logic regresses.
        let destination = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "followed"));
        let origin = ScriptedHttpServer::spawn(
            CannedHttpResponse::new("302 Found", "")
                .with_header("Location", format!("{}/moved.bin", destination.endpoint())),
        );
        let destination_host = "127.0.0.1";

        // `same_origin` must refuse the cross-port hop...
        let refused = instantiate_with_credentials(
            config_of(&[
                ("root_url", origin.endpoint()),
                ("redirect_policy", "same_origin"),
            ]),
            SecretBundle::default(),
        )
        .await
        .unwrap();
        let target_url = address::parse(&format!("{}/obj.bin", origin.endpoint())).unwrap();
        let err = refused
            .backend
            .stat(
                ResolvedTarget {
                    backend_id: refused.backend_id.clone(),
                    resolved_address: target_url.clone(),
                },
                StatOptions::default(),
                None,
            )
            .await
            .expect_err("same_origin must not follow a cross-port redirect");
        assert_eq!(err.code(), ErrorCode::Unsupported);

        // ...and `allow_list` must follow it.
        let allowed = instantiate_with_credentials(
            config_of(&[
                ("root_url", origin.endpoint()),
                ("redirect_policy", "allow_list"),
                ("redirect_allow_hosts", destination_host),
            ]),
            SecretBundle::default(),
        )
        .await
        .unwrap();
        let info = allowed
            .backend
            .stat(
                ResolvedTarget {
                    backend_id: allowed.backend_id.clone(),
                    resolved_address: target_url,
                },
                StatOptions::default(),
                None,
            )
            .await
            .expect("allow_list follows a listed host");
        assert_eq!(info.size, Some(8));
    }

    #[tokio::test]
    async fn userinfo_is_stripped_from_the_caller_facing_route() {
        use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer, request_has_header};

        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "body"));
        // The endpoint is loopback cleartext, which is what lets the userinfo
        // reach the wire in a test at all.
        let root = server
            .endpoint()
            .replacen("http://", "http://alice:s3cret@", 1);
        let instance = instantiate_with_credentials(
            config_of(&[("root_url", &root)]),
            SecretBundle::default(),
        )
        .await
        .unwrap();

        // Nothing the caller can see may carry the password.
        let published = format!(
            "{:?} {} {}",
            instance.backend_id,
            instance.address_roots[0].address,
            instance.address_roots[0].address.as_str()
        );
        assert!(
            !published.contains("s3cret") && !published.contains("alice"),
            "the route identity still publishes userinfo: {published}"
        );

        // ...and the caller-facing address is the clean one.
        let object = address::parse(&format!("{}/obj.bin", server.endpoint())).unwrap();
        let info = instance
            .backend
            .stat(
                ResolvedTarget {
                    backend_id: instance.backend_id.clone(),
                    resolved_address: object,
                },
                StatOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert!(!info.address.as_str().contains("s3cret"));

        // The wire behaviour is untouched: reqwest still turns the userinfo
        // on `root_url` into the same Basic header.
        let requests = server.requests();
        assert!(
            request_has_header(
                &requests[requests.len() - 1],
                "authorization",
                "Basic YWxpY2U6czNjcmV0"
            ),
            "userinfo must still authenticate: {requests:?}"
        );
    }

    #[tokio::test]
    async fn an_explicit_prefix_must_be_usable_and_credential_free() {
        // A prefix that fails to parse is the operator's error to see:
        // falling back to `root_url` routes their connection at an address
        // they never asked for.
        let err = instantiate_rejected(
            config_of(&[
                ("root_url", "https://origin.example/"),
                ("prefix", "not a url"),
            ]),
            SecretBundle::default(),
            "a malformed prefix must be reported",
        )
        .await;
        assert_eq!(err.code(), ErrorCode::InvalidArgument);

        // D2 has no explicit-prefix exception: the prefix *is* the published
        // identity, so userinfo in it is the same leak by another route.
        let err = instantiate_rejected(
            config_of(&[
                ("root_url", "https://origin.example/"),
                ("prefix", "https://bob:hunter2@public.example/"),
            ]),
            SecretBundle::default(),
            "userinfo in an explicit prefix must be rejected",
        )
        .await;
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(!err.message().contains("hunter2"));
    }

    #[tokio::test]
    async fn a_duplicate_caller_facing_prefix_is_refused() {
        let layer: LayerHandle = HttpBackendLayerFactory::default()
            .create_backend("http", &LayerConfig::new(), None)
            .await
            .unwrap();
        let add = |root: &str| {
            let layer = layer.clone();
            let config = config_of(&[("root_url", root)]);
            async move {
                layer
                    .add_connection(
                        Request::new(LayerConnectionRequest {
                            target: "http".into(),
                            connection: ConnectionRequest {
                                backend_kind: "http".into(),
                                config,
                                credentials: SecretBundle::default(),
                                persist: false,
                                display_name: None,
                            },
                        }),
                        None,
                    )
                    .await
            }
        };

        let first = add("https://cdn.example.invalid/assets/").await.unwrap();
        // Stripping userinfo makes these two collide where they did not
        // before. The route table shadows a duplicate root with only a `warn`,
        // so without an explicit refusal the second connection registers
        // successfully, is permanently unroutable, and every read silently
        // uses the first connection's credential.
        let err = add("https://bob:hunter2@cdn.example.invalid/assets/")
            .await
            .expect_err("a duplicate caller-facing prefix must be refused");
        assert_eq!(err.code(), ErrorCode::RouteConflict);
        assert!(!err.message().contains("hunter2"));

        // Remove-then-add is the documented way to replace a credential, so
        // removing a connection must free its prefix for the replacement.
        layer
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "http".into(),
                    id: first.id.clone(),
                }),
                None,
            )
            .await
            .unwrap();
        add("https://cdn.example.invalid/assets/")
            .await
            .expect("removing a connection frees its caller-facing prefix");
    }

    /// Two connections cannot publish one address space, and the trailing
    /// slash does not make a second one.
    ///
    /// The router merges `assets` and `assets/` onto one node and ranks them
    /// equal, so a refusal that keyed on bytes would report the second
    /// installation as successful and then serve its traffic over the first
    /// connection's origin, with nothing naming the substitution. A deployment
    /// that needs two origins under one path gives each an explicit `prefix`.
    ///
    /// The load-bearing line is the root comparison in `install`: it is what
    /// turns the second `add_connection` into an error instead of a silent
    /// second entry in the route table.
    #[tokio::test]
    async fn two_roots_on_one_path_cannot_both_publish_it() {
        let layer: LayerHandle = HttpBackendLayerFactory::default()
            .create_backend("http", &LayerConfig::new(), None)
            .await
            .unwrap();
        let add = |root: &str, prefix: Option<&str>| {
            let layer = layer.clone();
            let config = match prefix {
                Some(prefix) => config_of(&[("root_url", root), ("prefix", prefix)]),
                None => config_of(&[("root_url", root)]),
            };
            async move {
                layer
                    .add_connection(
                        Request::new(LayerConnectionRequest {
                            target: "http".into(),
                            connection: ConnectionRequest {
                                backend_kind: "http".into(),
                                config,
                                credentials: SecretBundle::default(),
                                persist: false,
                                display_name: None,
                            },
                        }),
                        None,
                    )
                    .await
            }
        };

        add("https://cdn.example.invalid/assets/", None)
            .await
            .expect("the first root publishes the prefix");
        let err = add(
            "https://other.invalid/assets/",
            Some("https://cdn.example.invalid/assets/"),
        )
        .await
        .expect_err("a second connection must not silently take the route");
        assert_eq!(err.code(), ErrorCode::RouteConflict);

        // The trailing slash is a spelling, not a second address space.
        let err = add(
            "https://other.invalid/assets/",
            Some("https://cdn.example.invalid/assets"),
        )
        .await
        .expect_err("a slash-differing spelling of a held prefix must be refused too");
        assert_eq!(err.code(), ErrorCode::RouteConflict);

        // The documented remedy has to actually work, or the refusal above is a
        // dead end rather than a redirection: a distinct explicit prefix
        // installs alongside.
        add(
            "https://other.invalid/assets/",
            Some("https://tenant-b.invalid/assets/"),
        )
        .await
        .expect("an explicit prefix gives the second connection its own space");
    }

    #[tokio::test]
    async fn a_cancelled_probe_fails_the_connection() {
        use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = match HttpBackendFactory
            .instantiate(
                &ConnectionRequest {
                    backend_kind: "http".into(),
                    config: config_of(&[("root_url", server.endpoint())]),
                    credentials: credential_bundle(&[("bearer_token", "tok")]),
                    persist: false,
                    display_name: None,
                },
                Some(cancel),
            )
            .await
        {
            // A cancelled probe registers nothing: the host asked for the work
            // to stop, so inventing a connection state would be worse than
            // failing.
            Ok(_) => panic!("a cancelled probe must fail the connection"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn probe_reports_credential_and_reachability_failures_as_errors() {
        use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

        async fn probe_root(root_url: &str) -> Result<Connection> {
            let layer: LayerHandle = HttpBackendLayerFactory::default()
                .create_backend("http", &LayerConfig::new(), None)
                .await
                .unwrap();
            layer
                .probe(
                    Request::new(LayerConnectionRequest {
                        target: "http".into(),
                        connection: ConnectionRequest {
                            backend_kind: "http".into(),
                            config: config_of(&[("root_url", root_url)]),
                            credentials: credential_bundle(&[("bearer_token", "tok")]),
                            persist: false,
                            display_name: None,
                        },
                    }),
                    None,
                )
                .await
        }

        // `probe` is the pre-flight verb, so unlike `add_connection` it must
        // surface a refusal rather than record it.
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("401 Unauthorized", ""));
        let err = probe_root(server.endpoint())
            .await
            .expect_err("probe must surface a refused credential");
        assert_eq!(err.code(), ErrorCode::AuthRequired);

        // The contract names Transient for an unreachable backend.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = probe_root(&format!("http://127.0.0.1:{port}/"))
            .await
            .expect_err("probe must surface an unreachable origin");
        assert_eq!(err.code(), ErrorCode::Transient);

        // A working origin still probes clean.
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
        let connection = probe_root(server.endpoint()).await.unwrap();
        assert!(matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ));
    }

    #[tokio::test]
    async fn credentials_are_refused_over_cleartext_except_on_loopback() {
        let err = instantiate_with_credentials(
            config_of(&[("root_url", "http://cdn.example.test/")]),
            credential_bundle(&[("bearer_token", "tok")]),
        )
        .await
        .err()
        .expect("a cleartext credential must be refused");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("cleartext"));

        // The message names the host, never the URL: `root_url` may carry
        // userinfo, which is one of the two channels this guard fires for.
        for host in ["127.0.0.1", "localhost", "[::1]"] {
            validate_credential_transport(
                &address::parse(&format!("http://{host}:8080/assets/")).unwrap(),
            )
            .unwrap_or_else(|err| panic!("loopback host {host} must be exempt: {}", err.message()));
        }
        // A public name that merely ends in `localhost` is not loopback.
        assert!(
            validate_credential_transport(&address::parse("http://localhost.evil.test/").unwrap(),)
                .is_err()
        );
        // HTTPS is always fine.
        validate_credential_transport(&address::parse("https://cdn.example.test/").unwrap())
            .unwrap();
    }

    #[tokio::test]
    async fn userinfo_in_root_url_conflicts_with_every_authorization_writer() {
        // reqwest lifts userinfo into its own `Authorization` header and
        // `header()` appends, so allowing both would put two on the wire.
        for credentials in [
            credential_bundle(&[("bearer_token", "tok")]),
            credential_bundle(&[("username", "other"), ("password", "secret")]),
            credential_bundle(&[("secret_headers", "Authorization: Token opaque")]),
        ] {
            let err = instantiate_with_credentials(
                config_of(&[("root_url", "https://u:p@cdn.example.test/")]),
                credentials,
            )
            .await
            .err()
            .expect("userinfo plus another Authorization writer must be refused");
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert!(err.message().contains("userinfo"));
        }

        // Userinfo on its own keeps working — D2 leaves the wire behaviour
        // alone. Point it at a closed loopback port rather than a name: this
        // path now probes, and a probe against a resolvable name would put a
        // real credential on a real network from a unit test.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        instantiate_with_credentials(
            config_of(&[("root_url", &format!("http://u:p@127.0.0.1:{port}/"))]),
            SecretBundle::default(),
        )
        .await
        .expect("userinfo without a bundle is still supported");
    }

    #[tokio::test]
    async fn userinfo_coexists_with_non_authorization_secrets_and_guards_rotation() {
        use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer, request_has_header};

        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", "ok"));
        let root = server
            .endpoint()
            .replacen("http://", "http://alice:s3cret@", 1);
        let layer: LayerHandle = HttpBackendLayerFactory::default()
            .create_backend("http", &LayerConfig::new(), None)
            .await
            .unwrap();
        let connection = layer
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "http".into(),
                    connection: ConnectionRequest {
                        backend_kind: "http".into(),
                        config: config_of(&[("root_url", &root)]),
                        credentials: credential_bundle(&[("secret_headers", "X-Api-Key: first")]),
                        persist: false,
                        display_name: None,
                    },
                }),
                None,
            )
            .await
            .expect("userinfo and a non-Authorization secret header are distinct channels");

        let first = server.requests();
        assert!(request_has_header(
            &first[0],
            "authorization",
            "Basic YWxpY2U6czNjcmV0"
        ));
        assert!(request_has_header(&first[0], "x-api-key", "first"));

        let err = layer
            .update_connection_credentials(
                Request::new(UpdateConnectionCredentialsRequest {
                    key: ConnectionKey {
                        target: "http".into(),
                        id: connection.id.clone(),
                    },
                    credentials: credential_bundle(&[(
                        "secret_headers",
                        "Authorization: Token second",
                    )]),
                }),
                None,
            )
            .await
            .expect_err("rotation must not introduce a second Authorization writer");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);

        let rotated = layer
            .update_connection_credentials(
                Request::new(UpdateConnectionCredentialsRequest {
                    key: ConnectionKey {
                        target: "http".into(),
                        id: connection.id,
                    },
                    credentials: credential_bundle(&[("secret_headers", "X-Api-Key: second")]),
                }),
                None,
            )
            .await
            .expect("rotation may replace a value without changing its channel shape");
        assert!(matches!(
            rotated.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ));
        let requests = server.requests();
        let last = requests.last().unwrap();
        assert!(request_has_header(
            last,
            "authorization",
            "Basic YWxpY2U6czNjcmV0"
        ));
        assert!(request_has_header(last, "x-api-key", "second"));
    }

    #[tokio::test]
    async fn instantiated_backend_uses_root_url_for_requests() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(std::sync::Mutex::new(String::new()));
        let captured_clone = captured.clone();
        spawn_http_fixture(move || {
            let mut stream = listener.incoming().next().unwrap().unwrap();
            let mut buf = [0_u8; 1024];
            let len = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..len]).to_string();
            *captured_clone.lock().unwrap() = req;
            let body = b"physical-bytes";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"x\"\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let mut config = HashMap::new();
        config.insert(
            "root_url".into(),
            ConfigValue::String(format!("http://127.0.0.1:{port}/origin/")),
        );
        config.insert(
            "prefix".into(),
            ConfigValue::String("https://datasets.example/".into()),
        );
        let instance = instantiate_backend(config);
        let target = ResolvedTarget {
            backend_id: instance.backend_id.clone(),
            resolved_address: address::parse("https://datasets.example/file.bin").unwrap(),
        };
        let result = instance
            .backend
            .read(target, ReadOptions::default(), None)
            .await
            .unwrap();
        match result {
            ReadResult::Stream { mut stream, .. } => {
                use futures::StreamExt;
                let mut got = Vec::new();
                while let Some(chunk) = stream.next().await {
                    got.extend_from_slice(&chunk.unwrap());
                }
                assert_eq!(got, b"physical-bytes");
            }
            other => panic!("expected Stream, got {other:?}"),
        }
        let line = captured.lock().unwrap().clone();
        assert!(
            line.starts_with("GET /origin/file.bin "),
            "expected request line under root_url path, got: {line:?}"
        );
    }

    #[tokio::test]
    async fn ranged_read_uses_content_range_total_for_size() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            for (idx, stream) in listener.incoming().take(2).enumerate() {
                let mut stream = stream.unwrap();
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf).unwrap();
                if idx == 0 {
                    // `Connection: close` so the ranged GET opens conn #1 instead
                    // of reusing this socket, which the fixture closes here.
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nETag: \"abc\"\r\nConnection: close\r\n\r\n";
                    stream.write_all(response.as_bytes()).unwrap();
                } else {
                    let body = b"0123456789";
                    let response = format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes 0-9/1000\r\nETag: \"abc\"\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).unwrap();
                    stream.write_all(body).unwrap();
                }
            }
        });

        let backend = HttpBackend::new();
        let addr = address::parse(&format!("http://127.0.0.1:{port}/object.bin")).unwrap();
        let stat = backend
            .stat(target(addr.clone()), StatOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(stat.size, Some(1000));
        let (bytes, info) = buffer_read(
            backend
                .read(
                    target(addr.clone()),
                    ReadOptions {
                        range: Some(ByteRange {
                            start: 0,
                            end_inclusive: Some(9),
                        }),
                        if_match: stat.etag.clone(),
                        ..ReadOptions::default()
                    },
                    None,
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(bytes, b"0123456789");
        assert_eq!(info.size, Some(1000));
    }

    #[tokio::test]
    async fn streaming_read_without_content_length_leaves_size_unknown() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            let mut stream = listener.incoming().next().unwrap().unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let response =
                "HTTP/1.1 200 OK\r\nETag: \"chunky\"\r\nTransfer-Encoding: chunked\r\n\r\n";
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(b"5\r\nhello\r\n0\r\n\r\n").unwrap();
        });

        let backend = HttpBackend::new();
        let (mut stream, info) = match backend
            .read(
                target(address::parse(&format!("http://127.0.0.1:{port}/chunked.txt")).unwrap()),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap()
        {
            ReadResult::Stream { stream, info } => (stream, info),
            other => panic!("expected Stream, got {other:?}"),
        };
        assert_eq!(info.size, None);
        use futures::StreamExt;
        let mut got = Vec::new();
        while let Some(chunk) = stream.next().await {
            got.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(got, b"hello");
    }

    #[tokio::test]
    async fn stat_fallback_rejects_200_when_range_is_ignored() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            for (idx, stream) in listener.incoming().take(2).enumerate() {
                let mut stream = stream.unwrap();
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf).unwrap();
                if idx == 0 {
                    // `Connection: close` so reqwest does not pool this socket: the
                    // fixture closes conn #0 right after this reply, and without the
                    // close hint reqwest may reuse the dead connection for the
                    // fallback ranged GET, surfacing a Transient connect error
                    // instead of the Unsupported we assert. Force a fresh conn #1.
                    stream
                        .write_all(
                            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                } else {
                    let body = vec![b'A'; 4096];
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"big\"\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).unwrap();
                    stream.write_all(&body).unwrap();
                }
            }
        });

        let mut config = HashMap::new();
        config.insert(
            "root_url".into(),
            ConfigValue::String(format!("http://127.0.0.1:{port}/")),
        );
        config.insert("allow_range_stat_fallback".into(), ConfigValue::Bool(true));
        let instance = instantiate_backend(config);
        let target = ResolvedTarget {
            backend_id: instance.backend_id.clone(),
            resolved_address: address::parse(&format!("http://127.0.0.1:{port}/object.bin"))
                .unwrap(),
        };
        let err = instance
            .backend
            .stat(target, StatOptions::default(), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn stat_does_not_fallback_after_a_blocked_redirect() {
        use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

        let server = ScriptedHttpServer::spawn(
            CannedHttpResponse::new("302 Found", "").with_header("Location", "/moved"),
        );
        let instance = instantiate_with_credentials(
            config_of(&[
                ("root_url", server.endpoint()),
                ("redirect_policy", "none"),
                ("allow_range_stat_fallback", "true"),
            ]),
            SecretBundle::default(),
        )
        .await
        .unwrap();
        let err = instance
            .backend
            .stat(
                ResolvedTarget {
                    backend_id: instance.backend_id.clone(),
                    resolved_address: address::parse(&format!("{}/object.bin", server.endpoint()))
                        .unwrap(),
                },
                StatOptions::default(),
                None,
            )
            .await
            .expect_err("a disabled redirect policy is not a HEAD limitation");
        assert_eq!(err.code(), ErrorCode::Unsupported);
        assert_eq!(
            server.hits(),
            1,
            "the redirect failure must not trigger a ranged GET fallback"
        );
    }

    #[tokio::test]
    async fn redirect_hops_share_one_total_timeout() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let fixture = spawn_http_fixture(move || {
            for index in 0..2 {
                let mut stream = listener.incoming().next().unwrap().unwrap();
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request).unwrap();
                thread::sleep(Duration::from_millis(200));
                let response = if index == 0 {
                    "HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                let _ = stream.write_all(response.as_bytes());
            }
        });

        let client = build_client(true, reqwest::header::HeaderMap::new()).unwrap();
        let credentials = HttpCredentials::default();
        let scope = FollowScope::SameOrigin;
        let context = HttpRequestContext {
            client: &client,
            credentials: &credentials,
            redirects: Some(&scope),
            carries_secret_on_wire: false,
        };
        let err = send_following_redirects_with_timeout(
            &context,
            reqwest::Method::GET,
            &address::parse(&format!("{endpoint}/first")).unwrap(),
            false,
            &RequestHeaders::default(),
            Duration::from_millis(300),
        )
        .await
        .expect_err("two individually-fast hops exceed their shared deadline");
        assert_eq!(err.code(), ErrorCode::Transient);
        fixture.join().unwrap();
    }

    #[tokio::test]
    async fn streaming_read_cancels_mid_body() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            let mut stream = listener.incoming().next().unwrap().unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let response =
                "HTTP/1.1 200 OK\r\nETag: \"slow\"\r\nTransfer-Encoding: chunked\r\n\r\n";
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(b"5\r\nfirst\r\n").unwrap();
            stream.flush().unwrap();
            std::thread::sleep(Duration::from_secs(2));
            let _ = stream.write_all(b"6\r\nsecond\r\n0\r\n\r\n");
        });

        let backend = HttpBackend::new();
        let target = ResolvedTarget {
            backend_id: BackendId("http".into()),
            resolved_address: address::parse(&format!("http://127.0.0.1:{port}/x.bin")).unwrap(),
        };
        let token = CancellationToken::new();
        let result = backend
            .read(target, ReadOptions::default(), Some(token.clone()))
            .await
            .unwrap();
        let mut stream = match result {
            ReadResult::Stream { stream, .. } => stream,
            other => panic!("expected Stream, got {other:?}"),
        };
        use futures::StreamExt;
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(&first[..], b"first");
        token.cancel();
        let next = stream.next().await.unwrap();
        let err = next.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn default_client_blocks_cross_origin_redirect() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            let mut stream = listener.incoming().next().unwrap().unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let response = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:9/redirected\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(response.as_bytes()).unwrap();
        });

        let backend = HttpBackend::new();
        let err = backend
            .read(
                target(address::parse(&format!("http://127.0.0.1:{port}/x.txt")).unwrap()),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err.code(),
            ErrorCode::Unsupported | ErrorCode::Transient | ErrorCode::NotFound
        ));
    }

    #[tokio::test]
    async fn credentialed_client_never_follows_cross_origin_redirect() {
        let target_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        target_listener.set_nonblocking(true).unwrap();
        let target_port = target_listener.local_addr().unwrap().port();
        let target_hit = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let target_hit_worker = Arc::clone(&target_hit);
        let target_worker = spawn_http_fixture(move || {
            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            while std::time::Instant::now() < deadline {
                match target_listener.accept() {
                    Ok((_stream, _)) => {
                        target_hit_worker.store(true, std::sync::atomic::Ordering::SeqCst);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("redirect target accept failed: {error}"),
                }
            }
        });

        let source_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let source_port = source_listener.local_addr().unwrap().port();
        let source_worker = spawn_http_fixture(move || {
            let mut stream = source_listener.incoming().next().unwrap().unwrap();
            let mut request = [0_u8; 2048];
            let len = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..len]);
            assert!(request.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("authorization")
                        && value.trim() == "Bearer access-token"
                })
            }));
            let response = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{target_port}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let backend = HttpBackend {
            // If the bearer'd request accidentally used the anonymous client,
            // reqwest itself would follow this permissive policy to the target.
            client: Arc::new(
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::limited(10))
                    .build()
                    .unwrap(),
            ),
            // And if it consulted only the connection's follow scope, this
            // host-wide allow-list would follow the cross-port hop (an
            // allow-list matches hosts, not ports); the bearer restricts
            // following to same-origin, so the hop must be refused and the
            // 307 surfaced unfollowed.
            redirects: Some(FollowScope::AllowList(vec!["127.0.0.1".into()])),
            ..HttpBackend::new()
        };
        let error = backend
            .read_with_bearer(
                target(address::parse(&format!("http://127.0.0.1:{source_port}/object")).unwrap()),
                ReadOptions::default(),
                Some(SecretBytes(b"access-token".to_vec())),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unsupported);
        source_worker.join().unwrap();
        target_worker.join().unwrap();
        assert!(
            !target_hit.load(std::sync::atomic::Ordering::SeqCst),
            "the bearer redirect target must never receive a connection"
        );
    }

    #[test]
    fn parse_content_range_total_handles_well_formed_header() {
        let header = "bytes 0-9/1000".to_string();
        assert_eq!(parse_content_range_total(Some(&header)), Some(1000));
        let header = "bytes 0-9/0".to_string();
        assert_eq!(parse_content_range_total(Some(&header)), Some(0));
    }

    #[test]
    fn parse_content_range_total_returns_none_for_unknown_total() {
        let header = "bytes 0-9/*".to_string();
        assert_eq!(parse_content_range_total(Some(&header)), None);
        let header = "garbage".to_string();
        assert_eq!(parse_content_range_total(Some(&header)), None);
        assert_eq!(parse_content_range_total(None), None);
    }

    #[tokio::test]
    async fn ranged_read_returns_206_body_as_is_for_nonzero_start() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            let mut stream = listener.incoming().next().unwrap().unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let body = b"56789";
            let response = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes 5-9/100\r\nETag: \"abc\"\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let backend = HttpBackend::new();
        let (bytes, info) = buffer_read(
            backend
                .read(
                    target(address::parse(&format!("http://127.0.0.1:{port}/obj.bin")).unwrap()),
                    ReadOptions {
                        range: Some(ByteRange {
                            start: 5,
                            end_inclusive: Some(9),
                        }),
                        ..ReadOptions::default()
                    },
                    None,
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(bytes, b"56789");
        assert_eq!(info.size, Some(100));
    }

    #[tokio::test]
    async fn ranged_read_rejects_200_full_body() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            let mut stream = listener.incoming().next().unwrap().unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let body = vec![b'x'; 4096];
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"big\"\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
        });

        let backend = HttpBackend::new();
        let err = backend
            .read(
                target(address::parse(&format!("http://127.0.0.1:{port}/obj.bin")).unwrap()),
                ReadOptions {
                    range: Some(ByteRange {
                        start: 5,
                        end_inclusive: Some(9),
                    }),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn open_ended_range_rejects_200_before_buffering_body() {
        // Open-ended `bytes=N-` budget is u64::MAX; rejecting 200-OK after draining would OOM.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let bytes_after_headers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bytes_after_headers_inner = bytes_after_headers.clone();
        spawn_http_fixture(move || {
            let mut stream = listener.incoming().next().unwrap().unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let body_len: usize = 16 * 1024 * 1024;
            let response =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nETag: \"open\"\r\n\r\n");
            stream.write_all(response.as_bytes()).unwrap();
            // Throttled body so the client can abort before the full payload arrives.
            let chunk = vec![b'x'; 64 * 1024];
            for _ in 0..(body_len / chunk.len()) {
                if stream.write_all(&chunk).is_err() {
                    break;
                }
                bytes_after_headers_inner
                    .fetch_add(chunk.len(), std::sync::atomic::Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(2));
            }
        });

        let backend = HttpBackend::new();
        let err = backend
            .read(
                target(address::parse(&format!("http://127.0.0.1:{port}/open.bin")).unwrap()),
                ReadOptions {
                    range: Some(ByteRange {
                        start: 5,
                        end_inclusive: None,
                    }),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
        // Post-buffer rejection would force ~16 MiB written; pre-buffer keeps it well under that.
        let observed = bytes_after_headers.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            observed < 4 * 1024 * 1024,
            "rejection should fire before the full body is drained; \
             server wrote {observed} bytes after headers",
        );
    }

    #[tokio::test]
    async fn streaming_read_wakes_on_cancel_after_first_chunk_pending() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            let mut stream = listener.incoming().next().unwrap().unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let response =
                "HTTP/1.1 200 OK\r\nETag: \"slow\"\r\nTransfer-Encoding: chunked\r\n\r\n";
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(b"5\r\nfirst\r\n").unwrap();
            stream.flush().unwrap();
            std::thread::sleep(Duration::from_secs(30));
            let _ = stream.write_all(b"6\r\nsecond\r\n0\r\n\r\n");
        });

        let backend = HttpBackend::new();
        let target = ResolvedTarget {
            backend_id: BackendId("http".into()),
            resolved_address: address::parse(&format!("http://127.0.0.1:{port}/x.bin")).unwrap(),
        };
        let token = CancellationToken::new();
        let result = backend
            .read(target, ReadOptions::default(), Some(token.clone()))
            .await
            .unwrap();
        let mut stream = match result {
            ReadResult::Stream { stream, .. } => stream,
            other => panic!("expected Stream, got {other:?}"),
        };
        use futures::StreamExt;
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(&first[..], b"first");
        let cancel_token = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel_token.cancel();
        });
        let started = std::time::Instant::now();
        let next = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("poll_next must wake on cancel signal");
        let elapsed = started.elapsed();
        let err = next.unwrap().unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
        assert!(
            elapsed < Duration::from_millis(500),
            "cancel wakeup took {elapsed:?}"
        );
    }

    // End-to-end proof that the ABI-v2 port composes + serves through a `Stack`:
    // the `HttpBackendLayerFactory` builds the layer, the connection's
    // `root_url` config wires the origin, and stat/read route through it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_layer_round_trips_through_stack() {
        let _ = ovstorage::init_auth_substrate(None);
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut request = [0_u8; 1024];
                let len = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..len]);
                let body = if request.starts_with("HEAD ") {
                    Vec::new()
                } else {
                    b"stacked".to_vec()
                };
                // `Connection: close`: one reply per accepted connection, so the
                // client must not pool the stat socket for the follow-up read.
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"s\"\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });

        let stack = ovstorage::Stack::builder("http")
            .backend_factory(Arc::new(HttpBackendLayerFactory::default()))
            .layer(ovstorage::LayerSpec::backend("http", "http"))
            .connection(ovstorage::LayerConnectionRequest {
                target: "http".into(),
                connection: ConnectionRequest {
                    backend_kind: "http".into(),
                    config: HashMap::from([(
                        "root_url".into(),
                        ConfigValue::String(format!("http://127.0.0.1:{port}/")),
                    )]),
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            })
            .build()
            .await
            .unwrap();

        let addr = address::parse(&format!("http://127.0.0.1:{port}/object.txt")).unwrap();
        let stat = stack
            .stat(
                ovstorage::Request::new(ovstorage::StatRequest {
                    address: addr.clone(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(stat.etag.as_deref(), Some("s"));

        let result = stack
            .read(
                ovstorage::Request::new(ovstorage::ReadRequest {
                    address: addr,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        let (bytes, info) = buffer_read(result).await;
        assert_eq!(bytes, b"stacked");
        assert_eq!(info.etag.as_deref(), Some("s"));
    }

    // Regression guard for the rebuild-routes TOCTOU: `instances` and the route
    // table live under one lock, so concurrent add/remove can't publish a stale
    // table. After the churn the route table must reflect exactly the surviving
    // connections — every survivor routable, every removed one not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn http_layer_concurrent_add_remove_is_consistent() {
        let _ = ovstorage::init_auth_substrate(None);
        let layer: LayerHandle = HttpBackendLayerFactory::default()
            .create_backend("http", &LayerConfig::new(), None)
            .await
            .unwrap();

        let mut handles = Vec::new();
        for i in 0..24u16 {
            let layer = layer.clone();
            handles.push(tokio::spawn(async move {
                let request = ConnectionRequest {
                    backend_kind: "http".into(),
                    config: HashMap::from([(
                        "root_url".into(),
                        ConfigValue::String(format!("http://127.0.0.1:{}/", 20000 + i)),
                    )]),
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                };
                let conn = layer
                    .add_connection(
                        Request::new(LayerConnectionRequest {
                            target: "http".into(),
                            connection: request,
                        }),
                        None,
                    )
                    .await
                    .unwrap();
                // Remove the even-indexed connections concurrently with the
                // other adds/removes to exercise interleaved mutation.
                if i % 2 == 0 {
                    layer
                        .remove_connection(
                            Request::new(ConnectionKey {
                                target: "http".into(),
                                id: conn.id.clone(),
                            }),
                            None,
                        )
                        .await
                        .unwrap();
                }
                (i, conn)
            }));
        }
        let results: Vec<(u16, Connection)> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        let (snapshot, _) = layer
            .list_connections(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        let survivors: std::collections::HashSet<_> =
            snapshot.connections.iter().map(|c| c.id.clone()).collect();
        assert_eq!(survivors.len(), 12, "the odd-indexed half survive");
        for (i, conn) in &results {
            let root = Url::parse(&format!("http://127.0.0.1:{}/", 20000 + i)).unwrap();
            let routable = layer
                .root_info_for(&root, &ovstorage_plugin::Extensions::new(), None)
                .await
                .is_ok();
            if i % 2 == 0 {
                assert!(!survivors.contains(&conn.id), "even connection {i} removed");
                assert!(!routable, "removed root {root} must not resolve");
            } else {
                assert!(survivors.contains(&conn.id), "odd connection {i} survives");
                assert!(routable, "surviving root {root} must resolve");
            }
        }
    }

    // N10 regression: `update_connection_attributes` applies a display-name +
    // user-metadata patch to the stored connection through the real ABI-v2
    // Layer slot, refreshing the presented root label.
    #[tokio::test]
    async fn http_layer_update_connection_attributes_applies_patch() {
        let _ = ovstorage::init_auth_substrate(None);
        let layer: LayerHandle = HttpBackendLayerFactory::default()
            .create_backend("http", &LayerConfig::new(), None)
            .await
            .unwrap();
        let root = Url::parse("http://127.0.0.1:29000/").unwrap();
        let conn = layer
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "http".into(),
                    connection: ConnectionRequest {
                        backend_kind: "http".into(),
                        config: HashMap::from([(
                            "root_url".into(),
                            ConfigValue::String(root.to_string()),
                        )]),
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: Some("before".into()),
                    },
                }),
                None,
            )
            .await
            .unwrap();

        let mut user_metadata = HashMap::new();
        user_metadata.insert("team".to_string(), Some("infra".to_string()));
        let updated = layer
            .update_connection_attributes(
                Request::new(UpdateConnectionAttributesRequest {
                    key: ConnectionKey {
                        target: "http".into(),
                        id: conn.id.clone(),
                    },
                    patch: AttributePatch {
                        display_name: Some("after".into()),
                        access_mode: None,
                        visible: None,
                        user_metadata,
                    },
                }),
                None,
            )
            .await
            .expect("http layer supports update_connection_attributes");
        assert_eq!(updated.display_name, "after");
        assert_eq!(
            updated.user_metadata.get("team").map(String::as_str),
            Some("infra")
        );

        // The change is durable in the layer's own catalogs.
        let (snapshot, _) = layer
            .list_connections(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        let stored = snapshot
            .connections
            .iter()
            .find(|c| c.id == conn.id)
            .expect("connection still listed");
        assert_eq!(stored.display_name, "after");
        // The presented root label is refreshed.
        let root_info = layer
            .root_info_for(&root, &ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        assert_eq!(root_info.display_name.as_deref(), Some("after"));
    }

    /// Patch fields the layer cannot store/enforce fail closed: a requested
    /// `access_mode` / `visible` restriction must be rejected (`Unsupported`),
    /// never silently ignored behind an `Ok(connection)` — and the rejection
    /// must not partially apply the rest of the patch.
    #[tokio::test]
    async fn http_layer_update_connection_attributes_rejects_unsupported_fields() {
        let _ = ovstorage::init_auth_substrate(None);
        let layer: LayerHandle = HttpBackendLayerFactory::default()
            .create_backend("http", &LayerConfig::new(), None)
            .await
            .unwrap();
        let root = Url::parse("http://127.0.0.1:29001/").unwrap();
        let conn = layer
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "http".into(),
                    connection: ConnectionRequest {
                        backend_kind: "http".into(),
                        config: HashMap::from([(
                            "root_url".into(),
                            ConfigValue::String(root.to_string()),
                        )]),
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: Some("before".into()),
                    },
                }),
                None,
            )
            .await
            .unwrap();

        for patch in [
            AttributePatch {
                display_name: Some("after".into()),
                access_mode: Some("read-only".into()),
                visible: None,
                user_metadata: HashMap::new(),
            },
            AttributePatch {
                display_name: Some("after".into()),
                access_mode: None,
                visible: Some(false),
                user_metadata: HashMap::new(),
            },
        ] {
            let err = layer
                .update_connection_attributes(
                    Request::new(UpdateConnectionAttributesRequest {
                        key: ConnectionKey {
                            target: "http".into(),
                            id: conn.id.clone(),
                        },
                        patch,
                    }),
                    None,
                )
                .await
                .expect_err("an unsupported restriction must be rejected, not dropped");
            assert_eq!(err.code(), ErrorCode::Unsupported);
        }
        // Nothing was partially applied.
        let (snapshot, _) = layer
            .list_connections(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        let stored = snapshot
            .connections
            .iter()
            .find(|c| c.id == conn.id)
            .expect("connection still listed");
        assert_eq!(stored.display_name, "before");
    }
}

#[cfg(test)]
mod projection_tests {
    use super::*;

    fn backend(prefix: &str, root: &str) -> HttpBackend {
        let mut backend = HttpBackend::new();
        backend.prefix = Some(address::parse(prefix).unwrap());
        backend.root_url = Some(address::parse(root).unwrap());
        backend
    }

    /// Projection carries only the caller's query; credentials attach later.
    ///
    /// This route used to splice `root_url`'s query onto every projected
    /// request, so a connection held a signature the caller never had.
    /// `config_url` refuses a query on both config addresses now. The held
    /// query is deliberately absent at this stage and `sign_url` attaches it
    /// only while building a request.
    #[test]
    fn the_projection_carries_only_the_callers_query() {
        let backend = backend("http://alias/c/", "https://origin/c/");

        let physical = backend
            .physical_url(&address::parse("http://alias/c/x?download=1").unwrap())
            .unwrap();
        assert_eq!(physical.as_str(), "https://origin/c/x?download=1");

        // A caller carrying no query gets none, rather than the route's.
        let physical = backend
            .physical_url(&address::parse("http://alias/c/x").unwrap())
            .unwrap();
        assert_eq!(physical.as_str(), "https://origin/c/x");
    }

    /// A caller's credentials do not travel to the origin.
    ///
    /// Routing compares scheme, host, port and path, so an address carrying
    /// userinfo reaches a connection whose published prefix has none. The
    /// identity arm used to return that address verbatim, and `request` hands
    /// the string to reqwest, which lifts URL userinfo into an
    /// `Authorization: Basic` header — so an operator's credential-less route
    /// became a way to send a caller's chosen credentials to an internal
    /// origin from the broker's network position.
    ///
    /// The honest cases are asserted beside it: an ordinary address is
    /// unchanged, and the projection arm still carries the ROOT's own
    /// credentials, which are the ones the operator configured.
    #[test]
    fn the_identity_arm_drops_a_callers_userinfo() {
        let identity = backend("https://origin/c/", "https://origin/c/");
        let physical = identity
            .physical_url(&address::parse("https://root:toor@origin/c/admin").unwrap())
            .unwrap();
        assert_eq!(physical.as_str(), "https://origin/c/admin");

        // The address the caller was supposed to send is untouched.
        let honest = identity
            .physical_url(&address::parse("https://origin/c/admin?download=1").unwrap())
            .unwrap();
        assert_eq!(honest.as_str(), "https://origin/c/admin?download=1");

        // The projection arm sends the operator's credential, not the
        // caller's: `replace_prefix` builds its answer from the root.
        let projecting = backend("http://alias/c/", "https://svc:secret@origin/c/");
        let physical = projecting
            .physical_url(&address::parse("http://root:toor@alias/c/x").unwrap())
            .unwrap();
        assert_eq!(physical.as_str(), "https://svc:secret@origin/c/x");
    }
}

#[cfg(test)]
mod default_prefix_tests {
    use super::*;

    fn config(pairs: &[(&str, &str)]) -> HashMap<String, ConfigValue> {
        pairs
            .iter()
            .map(|(key, value)| {
                (
                    (*key).to_string(),
                    ConfigValue::String((*value).to_string()),
                )
            })
            .collect()
    }

    /// The ordinary root defaults to itself, so the identity arm applies and
    /// the address a caller dispatched is the address that goes on the wire.
    #[test]
    fn an_ordinary_root_defaults_the_prefix_to_itself() {
        let root = address::parse("https://origin/c/").unwrap();
        let prefix = default_prefix(&config(&[("root_url", "https://origin/c/")]), &root).unwrap();
        assert_eq!(prefix, root);
    }

    /// A root's userinfo is stripped from the published prefix and kept on the
    /// wire.
    ///
    /// The prefix is what `BackendId`, `RootInfo` and every returned
    /// `ObjectInfo.address` print, so publishing the password there discloses
    /// it to every caller. The projection arm rebuilds the physical URL from
    /// `root_url`, which still has it — asserted, because a strip that also
    /// dropped the credential from the request would look identical here.
    #[test]
    fn a_roots_userinfo_is_stripped_from_the_prefix_and_kept_on_the_wire() {
        let root = address::parse("https://svc:secret@origin/c/").unwrap();
        let prefix = default_prefix(
            &config(&[("root_url", "https://svc:secret@origin/c/")]),
            &root,
        )
        .unwrap();
        assert_eq!(prefix.as_str(), "https://origin/c/");

        let mut backend = HttpBackend::new();
        backend.prefix = Some(prefix);
        backend.root_url = Some(root);
        let physical = backend
            .physical_url(&address::parse("https://origin/c/x").unwrap())
            .unwrap();
        assert_eq!(physical.as_str(), "https://svc:secret@origin/c/x");
    }

    /// An explicit prefix is the operator's address space and is taken as
    /// written — a different scheme and host from the root, which is the whole
    /// point of publishing one.
    #[test]
    fn an_explicit_prefix_is_honored() {
        let root = address::parse("https://origin/c/").unwrap();
        let prefix = default_prefix(
            &config(&[
                ("root_url", "https://origin/c/"),
                ("prefix", "http://alias/c/"),
            ]),
            &root,
        )
        .unwrap();
        assert_eq!(prefix.as_str(), "http://alias/c/");
    }

    /// Userinfo on an explicit prefix is refused rather than stripped.
    ///
    /// A defaulted prefix is derived, so silently narrowing it costs nothing;
    /// an explicit one is the address space the operator wrote out, and
    /// altering it would route their callers somewhere they did not ask for.
    #[test]
    fn userinfo_on_an_explicit_prefix_is_refused() {
        let root = address::parse("https://origin/c/").unwrap();
        let error = default_prefix(
            &config(&[
                ("root_url", "https://origin/c/"),
                ("prefix", "http://u:p@alias/c/"),
            ]),
            &root,
        )
        .expect_err("userinfo on a published prefix must be refused");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(error.message().contains("userinfo"), "{}", error.message());
    }

    /// A malformed explicit prefix is an error, not a silent fallback to the
    /// root. The previous `unwrap_or_else(|_| root_url.clone())` swallowed it,
    /// so an operator's typo published the root under a different name than the
    /// one they wrote.
    #[test]
    fn a_malformed_explicit_prefix_is_rejected_rather_than_defaulted() {
        let root = address::parse("https://origin/c/").unwrap();
        let error = default_prefix(
            &config(&[("root_url", "https://origin/c/"), ("prefix", "not a url")]),
            &root,
        )
        .expect_err("a malformed prefix must be rejected");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }
}

#[cfg(test)]
mod user_metadata_declaration_tests {
    use super::*;

    /// This kind's `supports_user_metadata` declaration is what a host reads to
    /// decide whether to compose its attribution layer over this backend's
    /// branch. Asserted here, in the crate that owns the answer, because a host
    /// crate cannot reach it: a plugin crate may not depend on a host-side
    /// crate, and two plugin rlibs in one test binary are a duplicate-symbol
    /// link error under `rust-lld`.
    ///
    /// Flipping it is a behaviour change for every host that loads this plugin —
    /// this backend is read-only: every mutating verb is the `Layer` trait's
    /// `Unsupported` default, and `stat` reports an always-empty
    /// `user_metadata`.
    #[test]
    fn http_declares_its_user_metadata_support() {
        let descriptor = HttpBackendFactory.descriptor();
        assert_eq!(descriptor.kind, "http");
        assert!(
            !descriptor.supports_user_metadata,
            "this backend's user-metadata declaration changed; a host composes \
             its attribution layer from it"
        );
    }
}
