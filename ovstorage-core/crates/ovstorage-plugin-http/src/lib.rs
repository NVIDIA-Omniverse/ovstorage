// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use ovstorage_plugin::address;
use ovstorage_plugin::shim;
use ovstorage_plugin::*;
use ovstorage_plugin::{ReadResult, race_cancel};

pub struct HttpBackend {
    client: Arc<reqwest::Client>,
    allow_range_stat_fallback: bool,
    root_url: Option<Url>,
    prefix: Option<Url>,
}

impl HttpBackend {
    pub fn capabilities() -> Capabilities {
        Capabilities::empty()
    }

    pub fn new() -> Self {
        Self {
            client: Arc::new(default_client()),
            allow_range_stat_fallback: false,
            root_url: None,
            prefix: None,
        }
    }

    fn physical_url(&self, dispatch_url: &Url) -> Result<Url> {
        match (self.prefix.as_ref(), self.root_url.as_ref()) {
            (Some(prefix), Some(root)) if prefix != root => {
                address::replace_prefix(dispatch_url, prefix, root)
            }
            _ => Ok(dispatch_url.clone()),
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

#[async_trait::async_trait]
impl shim::Factory for HttpBackendFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "http".into(),
            display_name: "Anonymous HTTP".into(),
            description: Some("Read-only anonymous HTTP / HTTPS object access".into()),
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
                    help: Some("Optional caller-facing route prefix; defaults to root_url".into()),
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
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "http", op = "instantiate"))]
    async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        let _ = &cancel; // synchronous body — nothing to interrupt.
        let root_url = config_url(&request.config, "root_url")?;
        validate_route_url(&root_url)?;
        let prefix = match config_url(&request.config, "prefix") {
            Ok(prefix) => {
                validate_route_url(&prefix)?;
                prefix
            }
            Err(_) => root_url.clone(),
        };
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

        let policy = build_redirect_policy(&redirect_policy, redirect_allow_hosts.as_deref())?;
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(policy);
        if !default_headers.is_empty() {
            builder = builder.default_headers(default_headers);
        }
        let client = builder
            .build()
            .map_err(|err| Error::new(ErrorCode::Internal, format!("HTTP client init: {err}")))?;
        let backend = Arc::new(HttpBackend {
            client: Arc::new(client),
            allow_range_stat_fallback,
            root_url: Some(root_url),
            prefix: Some(prefix.clone()),
        });
        Ok(shim::BackendInstance {
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
            auth_state: ConnectionAuthState::Anonymous,
        })
    }
}

#[async_trait::async_trait]
impl shim::Backend for HttpBackend {
    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "http", op = "stat"))]
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let client = self.client.clone();
        let allow_fallback = self.allow_range_stat_fallback;
        let physical = self.physical_url(&target.resolved_address)?;
        race_cancel(cancel.as_ref(), async move {
            let head = request(&client, "HEAD", &physical, RequestHeaders::default(), None).await;
            let response = match head {
                Ok(response) => response,
                Err(err) if err.code() == ErrorCode::Unsupported && allow_fallback => {
                    let resp = request(
                        &client,
                        "GET",
                        &physical,
                        RequestHeaders {
                            range: Some("bytes=0-0".to_string()),
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

    #[tracing::instrument(level = "debug", skip_all, fields(plugin = "http", op = "read"))]
    async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let client = self.client.clone();
        let physical = self.physical_url(&target.resolved_address)?;
        let stream_cancel = cancel.clone();
        race_cancel(cancel.as_ref(), async move {
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
                    &client,
                    &physical,
                    target.resolved_address.clone(),
                    RequestHeaders {
                        range: range.clone(),
                        if_match,
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
                &client,
                "GET",
                &physical,
                RequestHeaders {
                    range: range.clone(),
                    if_match,
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
    // anonymous HTTP supports none of these; the trait defaults to
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
}

fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(same_origin_redirect_policy())
        .build()
        .expect("reqwest client init")
}

fn same_origin_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let previous = match attempt.previous().first() {
            Some(url) => url,
            None => return attempt.stop(),
        };
        if same_origin(previous, attempt.url()) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

fn build_redirect_policy(
    policy: &str,
    allow_hosts: Option<&str>,
) -> Result<reqwest::redirect::Policy> {
    match policy {
        "none" => Ok(reqwest::redirect::Policy::none()),
        "same_origin" => Ok(same_origin_redirect_policy()),
        "allow_list" => {
            let hosts: Vec<String> = allow_hosts
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            Ok(reqwest::redirect::Policy::custom(move |attempt| {
                let host = match attempt.url().host_str() {
                    Some(h) => h.to_ascii_lowercase(),
                    None => return attempt.stop(),
                };
                if hosts.iter().any(|allowed| allowed == &host) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
        }
        other => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "unknown HTTP redirect_policy '{other}' (expected 'none', 'same_origin', 'allow_list')"
            ),
        )),
    }
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
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (name, value) = entry.split_once('=').ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("malformed default_headers entry '{entry}' (expected Name=Value)"),
            )
        })?;
        let name = name.trim();
        let value = value.trim();
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "authorization" | "cookie" | "proxy-authorization"
        ) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "default_headers must not include credential header '{name}' (use credential providers instead)"
                ),
            ));
        }
        let header_name: reqwest::header::HeaderName = name.parse().map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid header name '{name}'"),
            )
        })?;
        let header_value = reqwest::header::HeaderValue::from_str(value).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid header value for '{name}'"),
            )
        })?;
        map.insert(header_name, header_value);
    }
    Ok(map)
}

async fn request_streaming(
    client: &reqwest::Client,
    physical: &Url,
    dispatch_address: Url,
    headers: RequestHeaders,
    cancel: Option<CancellationToken>,
) -> Result<(ObjectInfo, ovstorage_plugin::ReadStream)> {
    use futures::StreamExt;
    if !matches!(physical.scheme(), "http" | "https") {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "anonymous HTTP backend supports http:// and https:// only",
        ));
    }
    let mut req = client.request(reqwest::Method::GET, physical.as_str());
    let request_had_range = headers.range.is_some();
    if let Some(range) = headers.range {
        req = req.header(reqwest::header::RANGE, range);
    }
    if let Some(if_match) = headers.if_match {
        req = req.header(reqwest::header::IF_MATCH, if_match);
    }
    let response = req.send().await.map_err(map_reqwest_error)?;
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
    client: &reqwest::Client,
    method: &str,
    address: &Url,
    headers: RequestHeaders,
    byte_budget: Option<u64>,
) -> Result<HttpResponse> {
    use futures::StreamExt;
    if !matches!(address.scheme(), "http" | "https") {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "anonymous HTTP backend supports http:// and https:// only",
        ));
    }
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
    let mut req = client.request(method_obj, address.as_str());
    let request_had_range = headers.range.is_some();
    if let Some(range) = headers.range {
        req = req.header(reqwest::header::RANGE, range);
    }
    if let Some(if_match) = headers.if_match {
        req = req.header(reqwest::header::IF_MATCH, if_match);
    }
    let response = req.send().await.map_err(map_reqwest_error)?;
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

fn validate_route_url(url: &Url) -> Result<()> {
    if url.fragment().is_some() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "HTTP route URLs must not contain a URL fragment",
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

fn config_url(config: &HashMap<String, ConfigValue>, key: &str) -> Result<Url> {
    match config.get(key) {
        Some(ConfigValue::String(value)) => address::parse(value),
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

fn headers_to_metadata(headers: HashMap<String, String>) -> SystemMetadata {
    headers
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
    if error.is_timeout() {
        return Error::new(
            ErrorCode::Transient,
            format!("HTTP request timed out: {error}"),
        );
    }
    if error.is_connect() {
        return Error::new(ErrorCode::Transient, format!("HTTP connect error: {error}"));
    }
    if error.is_redirect() {
        return Error::new(
            ErrorCode::Unsupported,
            format!("HTTP redirect blocked by configured policy: {error}"),
        );
    }
    if let Some(status) = error.status() {
        return map_status(status.as_u16(), None);
    }
    Error::new(ErrorCode::Transient, format!("HTTP error: {error}"))
}

ovstorage_plugin::ovstorage_plugin!(HttpBackendFactory::default);

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    use ovstorage::{Library, Storage};
    use ovstorage_plugin::shim::Backend as _;

    fn spawn_http_fixture<F: FnOnce() + Send + 'static>(f: F) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("ovs-test-http".into())
            .spawn(f)
            .expect("failed to spawn thread")
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
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"abc\"\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });

        let prefix = address::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "http",
                Arc::new(HttpBackend::new()),
                HttpBackend::capabilities(),
            )
            .open()
            .unwrap();
        let addr = address::join_relative(&prefix, "object.txt").unwrap();

        let stat = lib
            .stat(addr.clone(), StatOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(stat.etag.as_deref(), Some("abc"));

        let (bytes, info) = lib
            .read_bytes(addr.clone(), ReadOptions::default(), None)
            .await
            .unwrap();
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

        let prefix = address::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "http",
                Arc::new(HttpBackend::new()),
                HttpBackend::capabilities(),
            )
            .open()
            .unwrap();
        let err = lib
            .read_bytes(
                address::join_relative(&prefix, "object.txt").unwrap(),
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
    async fn http_read_retries_retryable_status_via_library() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        spawn_http_fixture(move || {
            for (idx, stream) in listener.incoming().take(2).enumerate() {
                let mut stream = stream.unwrap();
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request).unwrap();
                if idx == 0 {
                    stream
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nContent-Length: 0\r\n\r\n",
                        )
                        .unwrap();
                } else {
                    let body = b"retry-ok";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"retry\"\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).unwrap();
                    stream.write_all(body).unwrap();
                }
            }
        });

        let prefix = address::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let lib = Library::builder()
            .with_retry(ovstorage::retry::RetryConfig {
                initial_delay_ms: 1,
                max_delay_ms: 50,
                max_attempts: 5,
            })
            .unwrap()
            .add_route(
                prefix.clone(),
                "http",
                Arc::new(HttpBackend::new()),
                HttpBackend::capabilities(),
            )
            .open()
            .unwrap();

        let (bytes, info) = lib
            .read_bytes(
                address::join_relative(&prefix, "eventual.txt").unwrap(),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(bytes, b"retry-ok");
        assert_eq!(info.etag.as_deref(), Some("retry"));
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
    fn parse_default_headers_accepts_safe_headers() {
        let map = parse_default_headers(Some("X-User=alice,X-Tenant=corp")).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("x-user").unwrap().to_str().unwrap(), "alice");
    }

    #[test]
    fn fragment_in_prefix_is_invalid_argument() {
        let factory = HttpBackendFactory;
        let req = ConnectionRequest {
            backend_kind: "http".into(),
            config: HashMap::from([(
                "root_url".to_string(),
                ConfigValue::String("http://example.com/path#frag".into()),
            )]),
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        };
        let result = futures::executor::block_on(shim::Factory::instantiate(&factory, &req, None));
        let err = match result {
            Ok(_) => panic!("expected fragment rejection"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn build_redirect_policy_rejects_unknown() {
        let err = build_redirect_policy("invalid-mode", None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn build_redirect_policy_accepts_three_modes() {
        build_redirect_policy("none", None).expect("none");
        build_redirect_policy("same_origin", None).expect("same_origin");
        build_redirect_policy("allow_list", Some("a.example.com,b.example.com"))
            .expect("allow_list");
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
                let response = if has_if_match || !raw.contains("If-Match") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"abc\"\r\n\r\nhello"
                } else {
                    "HTTP/1.1 412 Precondition Failed\r\nETag: \"abc\"\r\nContent-Length: 0\r\n\r\n"
                };
                stream.write_all(response.as_bytes()).unwrap();
            }
        });

        let prefix = address::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "http",
                Arc::new(HttpBackend::new()),
                HttpBackend::capabilities(),
            )
            .open()
            .unwrap();
        let stat = lib
            .stat(
                address::join_relative(&prefix, "object.txt").unwrap(),
                StatOptions::default(),
                None,
            )
            .await
            .unwrap();
        let etag = stat.etag.clone().expect("etag");
        assert_eq!(etag, "abc", "SPI etag is the unquoted opaque token");
        let (bytes, _info) = lib
            .read_bytes(
                address::join_relative(&prefix, "object.txt").unwrap(),
                ReadOptions {
                    if_match: Some(etag),
                    ..ReadOptions::default()
                },
                None,
            )
            .await
            .unwrap();
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

    fn instantiate_backend(config: HashMap<String, ConfigValue>) -> shim::BackendInstance {
        let factory = HttpBackendFactory;
        let req = ConnectionRequest {
            backend_kind: "http".into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        };
        futures::executor::block_on(shim::Factory::instantiate(&factory, &req, None)).unwrap()
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
                    let response =
                        "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nETag: \"abc\"\r\n\r\n";
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

        let prefix = address::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "http",
                Arc::new(HttpBackend::new()),
                HttpBackend::capabilities(),
            )
            .open()
            .unwrap();
        let addr = address::join_relative(&prefix, "object.bin").unwrap();
        let stat = lib
            .stat(addr.clone(), StatOptions::default(), None)
            .await
            .unwrap();
        assert_eq!(stat.size, Some(1000));
        let (bytes, info) = lib
            .read_bytes(
                addr.clone(),
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
            .unwrap();
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

        let prefix = address::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "http",
                Arc::new(HttpBackend::new()),
                HttpBackend::capabilities(),
            )
            .open()
            .unwrap();
        let (mut stream, info) = lib
            .read_stream(
                address::join_relative(&prefix, "chunked.txt").unwrap(),
                ReadOptions::default(),
                None,
            )
            .await
            .unwrap();
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
                    stream
                        .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
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

        let prefix = address::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "http",
                Arc::new(HttpBackend::new()),
                HttpBackend::capabilities(),
            )
            .open()
            .unwrap();
        let err = lib
            .read_bytes(
                address::join_relative(&prefix, "x.txt").unwrap(),
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

    #[test]
    fn fragment_in_prefix_is_invalid_argument_at_instantiate() {
        let factory = HttpBackendFactory;
        let req = ConnectionRequest {
            backend_kind: "http".into(),
            config: HashMap::from([(
                "root_url".to_string(),
                ConfigValue::String("http://example.com/path#frag".into()),
            )]),
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        };
        let err =
            match futures::executor::block_on(shim::Factory::instantiate(&factory, &req, None)) {
                Ok(_) => panic!("expected fragment rejection at instantiate"),
                Err(err) => err,
            };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
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

        let prefix = address::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "http",
                Arc::new(HttpBackend::new()),
                HttpBackend::capabilities(),
            )
            .open()
            .unwrap();
        let (bytes, info) = lib
            .read_bytes(
                address::join_relative(&prefix, "obj.bin").unwrap(),
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
            .unwrap();
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

        let prefix = address::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "http",
                Arc::new(HttpBackend::new()),
                HttpBackend::capabilities(),
            )
            .open()
            .unwrap();
        let err = lib
            .read_bytes(
                address::join_relative(&prefix, "obj.bin").unwrap(),
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

        let prefix = address::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let lib = Library::builder()
            .add_route(
                prefix.clone(),
                "http",
                Arc::new(HttpBackend::new()),
                HttpBackend::capabilities(),
            )
            .open()
            .unwrap();
        let err = lib
            .read_bytes(
                address::join_relative(&prefix, "open.bin").unwrap(),
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
}
