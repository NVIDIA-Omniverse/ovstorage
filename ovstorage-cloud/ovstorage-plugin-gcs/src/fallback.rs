// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The anonymous `gs://` scheme fallback.
//!
//! A `gs://bucket/key` address that no configured connection serves reaches
//! the layer through the route table's second tier: the hidden, marked
//! `gs:///` root this module builds. The layer binds that root to a
//! [`GcsSchemeFallback`], which derives the bucket from the address itself
//! (a tier-2 hit has no prefix suffix to read), synthesizes the ordinary
//! per-bucket config, and builds a [`GcsBackend`] from a literal empty
//! [`SecretBundle`] — so the process's ambient Google identity is never spent
//! on a bucket the operator did not configure. The backends are cached in a
//! bounded, single-flight, budgeted [`FallbackCache`].
//!
//! GCS is the simplest of the three cloud tiers: one fixed public endpoint,
//! no region to learn, no project to name. Minting a backend costs no RPC.
//! The endpoint is also the one operator-supplied string every request URL is
//! built from, so it is reduced to its addressing parts when the policy is
//! read ([`optional_endpoint`]): a credential written into it would otherwise
//! ride every anonymous request.
//!
//! What the fallback refuses, and why, lives with the layer: every mutating
//! slot and `watch_directory` answer [`fallback_mutation_refused`] before any
//! wire activity, because a read-only promise is what the operator granted.

use std::sync::Arc;

use ovstorage_plugin::fallback::{
    ANONYMOUS_FALLBACK_KEY, fallback_mutation_refused, read_only_capabilities, scheme_fallback_root,
};
use ovstorage_plugin::fallback_cache::FallbackCache;
use ovstorage_plugin::instance_metadata::refuse_instance_metadata;
use ovstorage_plugin::*;

use crate::auth::Authenticator;
use crate::{
    DEFAULT_ENDPOINT, GcsBackend, GcsConnectionConfig, build_http_client, gcs_capabilities,
    optional_int, optional_text,
};

/// The one scheme the GCS kind serves through a fallback.
pub(crate) const SCHEME: &str = "gs";

/// Layer key: the JSON API endpoint the fallback's backends talk to. Absent
/// means the public `storage.googleapis.com`; set for an emulator or a
/// loopback fixture. Accepted with scheme, host, port and path only — see
/// [`optional_endpoint`] for what is refused and why.
const ENDPOINT_KEY: &str = "anonymous_fallback_endpoint";
/// Layer key: how many per-bucket backends stay resident.
const MAX_BACKENDS_KEY: &str = "anonymous_fallback_max_backends";
/// Layer key: how many backends may be minted per sliding minute.
const MINTS_PER_MINUTE_KEY: &str = "anonymous_fallback_mints_per_minute";

const DEFAULT_MAX_BACKENDS: i64 = 64;
const DEFAULT_MINTS_PER_MINUTE: i64 = 120;
/// Upper bound on both tunables. Generous enough for any real deployment and
/// small enough that a typo cannot ask for a cache the process cannot hold.
const TUNABLE_CEILING: i64 = 1_000_000;

/// Every layer key this module reads, for the refusal that names them.
const POLICY_KEYS: &[&str] = &[
    ANONYMOUS_FALLBACK_KEY,
    ENDPOINT_KEY,
    MAX_BACKENDS_KEY,
    MINTS_PER_MINUTE_KEY,
];

/// The operator's tunables for the fallback, read off the policy half of the
/// layer table.
#[derive(Clone, Debug)]
pub(crate) struct FallbackPolicy {
    endpoint: Option<Url>,
    max_backends: usize,
    mints_per_minute: u32,
}

impl FallbackPolicy {
    /// Read and validate the fallback tunables on layer `layer_name`.
    ///
    /// Runs whether or not the grant names `gs`, so a bad value fails the
    /// layer loudly instead of waiting for the day the grant is added. An
    /// unknown `anonymous_fallback_*` key is refused by name: a misspelled
    /// tunable that parsed as nothing would leave the operator believing it
    /// took effect. A fallback endpoint on a cloud instance-metadata host is
    /// refused here, before any backend could be pointed at it; so is one
    /// that embeds a credential or carries a query or fragment, before any
    /// client could be built from it ([`optional_endpoint`]).
    pub(crate) fn parse(policy: &LayerConfig, layer_name: &str) -> Result<Self> {
        for key in policy.keys() {
            if !POLICY_KEYS.contains(&key.as_str()) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "`{key}` on layer `{layer_name}` is not an anonymous fallback key; the \
                         accepted keys are {}",
                        POLICY_KEYS.join(", ")
                    ),
                ));
            }
        }
        let endpoint = optional_endpoint(policy, layer_name)?;
        if let Some(endpoint) = &endpoint {
            refuse_instance_metadata(endpoint)?;
        }
        let max_backends = optional_int(policy, MAX_BACKENDS_KEY, 1, TUNABLE_CEILING)?
            .unwrap_or(DEFAULT_MAX_BACKENDS);
        let mints_per_minute = optional_int(policy, MINTS_PER_MINUTE_KEY, 1, TUNABLE_CEILING)?
            .unwrap_or(DEFAULT_MINTS_PER_MINUTE);
        Ok(Self {
            endpoint,
            // Both fit: the ceiling is far below either target type's range.
            max_backends: usize::try_from(max_backends).unwrap_or(usize::MAX),
            mints_per_minute: u32::try_from(mints_per_minute).unwrap_or(u32::MAX),
        })
    }
}

/// Read and validate the fallback endpoint on layer `layer_name`: `None` when
/// the key is absent or blank, otherwise the endpoint rebuilt from its
/// addressing parts — scheme, host, port and path — and nothing else.
///
/// The string this yields is what every request URL is built from and, on an
/// anonymous `read`, what the redirect URL handed back to the caller is built
/// from. Userinfo is refused because reqwest turns `https://user:secret@host`
/// into a Basic `Authorization` header on every request it sends there, which
/// would put a credential on a tier whose whole promise is that none is ever
/// sent — and the redirect would hand that credential to the caller and across
/// the broker wire. A query or fragment is refused because request URLs are
/// made by appending an API path to this string, and a delimiter left in it
/// would push that path into the query. Both checks read the raw text as well
/// as the parsed URL: `Url` normalizes an empty userinfo (`https://@host`) and
/// a bare trailing `?` or `#` away before either is visible after parsing.
///
/// The refusal names the key and the layer, never the value: the value is
/// where the credential was.
fn optional_endpoint(policy: &LayerConfig, layer_name: &str) -> Result<Option<Url>> {
    let Some(raw) = optional_text(policy, ENDPOINT_KEY)? else {
        return Ok(None);
    };
    if let Some(component) = address::refused_config_component(&raw) {
        return Err(endpoint_refused(
            layer_name,
            &format!("must not carry a {}", component.name()),
        ));
    }
    if raw_authority(&raw).contains('@') {
        return Err(endpoint_refused(
            layer_name,
            "must not embed credentials in the URL",
        ));
    }
    let parsed = address::parse(&raw).map_err(|error| {
        endpoint_refused(
            layer_name,
            &format!("must be an absolute URL: {}", error.message()),
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(endpoint_refused(layer_name, "must use http or https"));
    }
    let Some(host) = parsed.host_str().filter(|host| !host.is_empty()) else {
        return Err(endpoint_refused(layer_name, "must name a host"));
    };
    // The raw scan above is the check that sees everything; this one is the
    // parser's own reading of the authority, kept so that no spelling the
    // parser recognizes as userinfo can reach the rebuild below.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(endpoint_refused(
            layer_name,
            "must not embed credentials in the URL",
        ));
    }
    // `port()` is already `None` for the scheme default, and an IPv6 host
    // comes back bracketed, so the parts concatenate straight into a URL.
    let port = parsed
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    let path = parsed.path().trim_end_matches('/');
    let rebuilt = format!("{}://{host}{port}{path}", parsed.scheme());
    Ok(Some(address::parse(&rebuilt)?))
}

/// The refusal for a fallback endpoint that fails validation.
fn endpoint_refused(layer_name: &str, why: &str) -> Error {
    Error::new(
        ErrorCode::InvalidArgument,
        format!("`{ENDPOINT_KEY}` on layer `{layer_name}` {why}"),
    )
}

/// The authority substring of a raw endpoint — `[userinfo@]host[:port]` — as
/// the operator wrote it. `Url` drops a syntactically empty userinfo
/// (`https://@host` parses with an empty username and no password), so the
/// raw text is the only place a stray `@` is still visible.
fn raw_authority(raw: &str) -> &str {
    let after_scheme = raw.split_once("://").map_or(raw, |(_, rest)| rest);
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    &after_scheme[..end]
}

/// The `gs://` fallback a granted layer binds to its scheme root.
///
/// One HTTP client and one anonymous [`Authenticator`] are shared by every
/// backend the fallback mints: the credential is the same literal nothing for
/// all of them, and a per-bucket client would only multiply connection pools.
pub(crate) struct GcsSchemeFallback {
    root: RootInfo,
    endpoint: Option<String>,
    http: reqwest::Client,
    auth: Arc<Authenticator>,
    cache: FallbackCache<String, GcsBackend>,
}

impl GcsSchemeFallback {
    /// Build the fallback for a layer of kind `layer_kind` under `policy`.
    ///
    /// The root's capabilities are the plugin's own capability set lowered
    /// through [`read_only_capabilities`]: `gcs_capabilities` is
    /// auth-agnostic and advertises every write bit for an anonymous
    /// connection too, so the clamp is what makes the root honest about the
    /// refusals the layer enforces. Its ranged-read strategy is the one the
    /// layer's connection roots advertise, because the fallback runs the same
    /// client with the same ranged-read support.
    pub(crate) fn new(
        policy: FallbackPolicy,
        layer_kind: &str,
        icon: Option<Vec<u8>>,
    ) -> Result<Self> {
        let endpoint = policy
            .endpoint
            .as_ref()
            .map(|address| address.as_str().trim_end_matches('/').to_string());
        // The capability set does not depend on the bucket, so any valid name
        // stands in for the buckets the fallback will meet.
        let placeholder =
            GcsConnectionConfig::anonymous_for_bucket("placeholder", endpoint.clone())?;
        let mut capabilities = read_only_capabilities(gcs_capabilities(&placeholder));
        capabilities.supports_list_stream = true;
        let mut root = scheme_fallback_root(SCHEME, layer_kind, capabilities, icon)?;
        // The shared constructor does not know the backend, so it leaves the
        // strategy at its default. The fallback mints the same `GcsBackend` a
        // configured connection runs, and `root_info_for` answers this root
        // verbatim for a fallback-served address; without this the same store
        // would look less capable through the fallback than through a
        // connection, and the direct and brokered answers could disagree.
        root.range_read_strategy = RangeReadStrategy::Native;
        let http = build_http_client()?;
        // A literal empty bundle is the whole of the anonymity guarantee: the
        // authenticator resolves it to `CredentialSource::Anonymous` and runs no
        // discovery chain, so no ADC file, no metadata server and no
        // environment variable can ever be consulted on this path.
        let auth = Arc::new(Authenticator::new(&SecretBundle::default(), http.clone())?);
        Ok(Self {
            root,
            endpoint,
            http,
            auth,
            cache: FallbackCache::new(policy.max_backends, policy.mints_per_minute),
        })
    }

    /// The hidden, marked `gs:///` root the layer publishes.
    pub(crate) fn root(&self) -> &RootInfo {
        &self.root
    }

    /// The endpoint the fallback's backends talk to.
    pub(crate) fn endpoint(&self) -> &str {
        self.endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT)
    }

    /// The routing identity for `url` under this fallback. Never fails, so the
    /// layer can resolve a route before deciding whether the slot may run at
    /// all; an address that names no bucket is refused by
    /// [`Self::backend_for`], not here.
    pub(crate) fn resolved_target(&self, url: &Url) -> ResolvedTarget {
        ResolvedTarget {
            backend_id: BackendId(format!(
                "gcs-fallback:{}",
                url.host_str().unwrap_or_default()
            )),
            resolved_address: url.clone(),
        }
    }

    /// The bucket root (`gs://{bucket}/`) an operator would configure a
    /// connection for to reach `url` with credentials; the scheme root itself
    /// when `url` names no bucket.
    pub(crate) fn node_root(&self, url: &Url) -> Url {
        match url.host_str() {
            Some(bucket) if !bucket.is_empty() => address::parse(&format!("{SCHEME}://{bucket}/"))
                .unwrap_or_else(|_| self.root.root.clone()),
            _ => self.root.root.clone(),
        }
    }

    /// The refusal every mutating slot and `watch_directory` answer for `url`.
    pub(crate) fn mutation_refused(&self, url: &Url) -> Error {
        fallback_mutation_refused(SCHEME, &self.node_root(url))
    }

    /// Resolve `url` to its anonymous per-bucket backend, minting one if none
    /// is resident.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — `url` names no bucket (`gs:///`,
    ///   `gs:///key`) or carries a port.
    /// - [`ErrorCode::ResourceExhausted`] — the mint budget is spent.
    /// - [`ErrorCode::PermissionDenied`] — the endpoint is an instance-metadata
    ///   host.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired first.
    pub(crate) async fn backend_for(
        &self,
        url: &Url,
        cancel: Option<CancellationToken>,
    ) -> Result<(Arc<GcsBackend>, ResolvedTarget)> {
        bail_if_cancelled(&cancel)?;
        let bucket = bucket_of(url)?;
        let target = self.resolved_target(url);
        let backend = self
            .cache
            .get_or_mint(bucket.clone(), cancel.as_ref(), || async move {
                self.mint(&bucket)
            })
            .await?;
        Ok((backend, target))
    }

    /// Drop the resident backend for the bucket `root` names. Called when an
    /// explicit connection installs for that bucket: the route table's first
    /// tier answers it from then on, and the anonymous client should not
    /// linger past its usefulness.
    pub(crate) fn evict_node(&self, root: &Url) {
        if let Some(bucket) = root.host_str().filter(|bucket| !bucket.is_empty()) {
            self.cache.evict(&bucket.to_string());
        }
    }

    /// Build the backend for `bucket`. Zero RPCs: the config is synthesized,
    /// the endpoint is judged, and the client is assembled from the shared
    /// parts. The first-touch log names the bucket origin only — never a key.
    fn mint(&self, bucket: &str) -> Result<GcsBackend> {
        let config = GcsConnectionConfig::anonymous_for_bucket(bucket, self.endpoint.clone())?;
        let endpoint = address::parse(self.endpoint())?;
        refuse_instance_metadata(&endpoint)?;
        let backend = GcsBackend::new(config.clone(), self.http.clone(), self.auth.clone());
        tracing::info!(
            target: "ovstorage.fallback",
            scheme = SCHEME,
            root = %origin_only(&config.address_root),
            "anonymous fallback backend built"
        );
        Ok(backend)
    }
}

/// The bucket a `gs://` address names. The host is the bucket, as
/// `parse_gcs_address` reads it; both spellings of a hostless address — the
/// bare scheme root and a hostless path — are first-tier hits under the scheme
/// root and must be refused here rather than minted for an empty name.
fn bucket_of(url: &Url) -> Result<String> {
    let bucket = url.host_str().unwrap_or_default();
    if bucket.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("a {SCHEME}:// address names no bucket"),
        ));
    }
    if url.port().is_some() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "GCS address must not carry a port",
        ));
    }
    Ok(bucket.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::fallback::is_scheme_fallback_root;

    fn policy(entries: &[(&str, ConfigValue)]) -> LayerConfig {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect()
    }

    fn built(policy_table: LayerConfig) -> GcsSchemeFallback {
        let policy = FallbackPolicy::parse(&policy_table, "gcs").expect("policy parses");
        GcsSchemeFallback::new(policy, "gcs", None).expect("fallback builds")
    }

    #[test]
    fn the_defaults_are_the_documented_bounds() {
        let parsed = FallbackPolicy::parse(&LayerConfig::new(), "gcs").unwrap();
        assert_eq!(parsed.max_backends, 64);
        assert_eq!(parsed.mints_per_minute, 120);
        assert!(parsed.endpoint.is_none());
        let fallback = built(LayerConfig::new());
        assert_eq!(fallback.endpoint(), DEFAULT_ENDPOINT);
        assert_eq!(fallback.cache.max_entries(), 64);
        assert_eq!(fallback.cache.mints_per_minute(), 120);
    }

    #[test]
    fn an_unknown_fallback_key_is_refused_by_name() {
        let table = policy(&[("anonymous_fallback_region", ConfigValue::String("x".into()))]);
        let error = FallbackPolicy::parse(&table, "gcs").unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error
                .message()
                .contains("`anonymous_fallback_region` on layer `gcs`"),
            "{}",
            error.message()
        );
        assert!(
            error.message().contains(MINTS_PER_MINUTE_KEY),
            "the refusal lists the accepted keys: {}",
            error.message()
        );
    }

    #[test]
    fn a_zero_or_negative_tunable_is_refused() {
        for key in [MAX_BACKENDS_KEY, MINTS_PER_MINUTE_KEY] {
            for value in [0, -1, TUNABLE_CEILING + 1] {
                let table = policy(&[(key, ConfigValue::Int(value))]);
                let error = FallbackPolicy::parse(&table, "gcs").unwrap_err();
                assert_eq!(error.code(), ErrorCode::InvalidArgument, "{key}={value}");
                assert!(error.message().contains(key), "{}", error.message());
            }
            let table = policy(&[(key, ConfigValue::String("7".into()))]);
            let error = FallbackPolicy::parse(&table, "gcs").unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{key} as text");
        }
    }

    #[test]
    fn an_instance_metadata_endpoint_is_refused_at_parse() {
        let table = policy(&[(
            ENDPOINT_KEY,
            ConfigValue::String("http://169.254.169.254".into()),
        )]);
        let error = FallbackPolicy::parse(&table, "gcs").unwrap_err();
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
        assert!(
            error.message().contains("instance-metadata"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn a_userinfo_bearing_fallback_endpoint_is_refused_before_any_client_is_built() {
        for spelling in [
            "https://reader:hunter2@storage.example.test",
            "https://reader@storage.example.test",
            "http://reader:hunter2@127.0.0.1:1/",
            // `Url` normalizes an empty userinfo away; only the raw authority
            // still shows the `@`.
            "https://@storage.example.test",
        ] {
            let table = policy(&[(ENDPOINT_KEY, ConfigValue::String(spelling.into()))]);
            let error = FallbackPolicy::parse(&table, "gcs").unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert!(
                error
                    .message()
                    .contains("`anonymous_fallback_endpoint` on layer `gcs`")
                    && error.message().contains("credentials"),
                "{spelling}: {}",
                error.message()
            );
            assert!(
                !error.message().contains("hunter2") && !error.message().contains("reader"),
                "the refusal never echoes the credential: {}",
                error.message()
            );
        }
    }

    #[test]
    fn a_fallback_endpoint_carrying_a_query_or_fragment_is_refused() {
        for (spelling, component) in [
            ("http://127.0.0.1:1/?alt=media", "query"),
            // A bare delimiter is refused too: the parser would drop it, and
            // the request URLs are built by appending a path to this string.
            ("http://127.0.0.1:1/?", "query"),
            ("http://127.0.0.1:1/#anchor", "fragment"),
            ("http://127.0.0.1:1/#", "fragment"),
        ] {
            let table = policy(&[(ENDPOINT_KEY, ConfigValue::String(spelling.into()))]);
            let error = FallbackPolicy::parse(&table, "gcs").unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert!(
                error
                    .message()
                    .contains("`anonymous_fallback_endpoint` on layer `gcs`")
                    && error.message().contains(component),
                "{spelling}: {}",
                error.message()
            );
        }
    }

    #[test]
    fn the_fallback_endpoint_keeps_only_its_addressing_parts() {
        for (spelling, expected) in [
            // Scheme and host fold to lower case and the default port drops.
            (
                "HTTPS://Storage.Example.Test:443/",
                "https://storage.example.test",
            ),
            ("http://127.0.0.1:4443", "http://127.0.0.1:4443"),
            // A path prefix survives, as it does on a connection's endpoint;
            // an IPv6 host keeps its brackets.
            ("http://[::1]:4443/emulator/", "http://[::1]:4443/emulator"),
        ] {
            let fallback = built(policy(&[(
                ENDPOINT_KEY,
                ConfigValue::String(spelling.into()),
            )]));
            assert_eq!(fallback.endpoint(), expected, "{spelling}");
        }
        for spelling in ["gs://bucket", "ftp://host/", "http://", "not a url"] {
            let table = policy(&[(ENDPOINT_KEY, ConfigValue::String(spelling.into()))]);
            let error = FallbackPolicy::parse(&table, "gcs").unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert!(
                error
                    .message()
                    .contains("`anonymous_fallback_endpoint` on layer `gcs`"),
                "{spelling}: {}",
                error.message()
            );
        }
    }

    #[test]
    fn the_root_is_the_marked_read_only_scheme_root() {
        let fallback = built(policy(&[(
            ENDPOINT_KEY,
            ConfigValue::String("http://127.0.0.1:1/".into()),
        )]));
        assert_eq!(fallback.endpoint(), "http://127.0.0.1:1");
        let root = fallback.root();
        assert_eq!(root.root.as_str(), "gs:///");
        assert!(is_scheme_fallback_root(root));
        assert_eq!(root.layer_kind, "gcs");
        assert!(root.connection_id.is_none());
        assert!(root.owning_target.is_none());
        assert!(!root.visible);
        assert_eq!(root.visibility, AddressVisibility::Hidden);
        assert_eq!(
            root.range_read_strategy,
            RangeReadStrategy::Native,
            "the fallback root advertises what a connection root does"
        );
        let caps = &root.capabilities;
        assert!(caps.supports_list && caps.supports_list_stream);
        assert!(caps.supports_version_listing && caps.supports_access_check);
        assert!(!caps.supports_write && !caps.supports_write_stream);
        assert!(!caps.supports_write_redirect && !caps.supports_delete);
        assert!(!caps.supports_copy && !caps.supports_rename);
        assert!(!caps.supports_create_directory && !caps.supports_delete_directory);
        assert!(!caps.supports_native_metadata_patch && !caps.supports_watch_directory);
    }

    #[test]
    fn a_hostless_address_names_no_bucket() {
        for spelling in ["gs:///", "gs:///k", "gs:///a/b"] {
            let url = address::parse(spelling).unwrap();
            let error = bucket_of(&url).unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert_eq!(error.message(), "a gs:// address names no bucket");
        }
        let url = address::parse("gs://bkt:8080/k").unwrap();
        assert_eq!(
            bucket_of(&url).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            bucket_of(&address::parse("gs://bkt/k").unwrap()).unwrap(),
            "bkt"
        );
    }

    #[test]
    fn the_node_root_is_the_bucket_root_or_the_scheme_root() {
        let fallback = built(LayerConfig::new());
        let bucket = address::parse("gs://bkt/deep/key.bin?generation=3").unwrap();
        assert_eq!(fallback.node_root(&bucket).as_str(), "gs://bkt/");
        let hostless = address::parse("gs:///k").unwrap();
        assert_eq!(fallback.node_root(&hostless).as_str(), "gs:///");
        let refusal = fallback.mutation_refused(&bucket);
        assert_eq!(refusal.code(), ErrorCode::Unsupported);
        assert!(refusal.message().contains("anonymous gs:// fallback"));
        assert!(
            refusal
                .next_action()
                .is_some_and(|action| action.contains("gs://bkt/") && !action.contains("deep")),
            "{:?}",
            refusal.next_action()
        );
    }

    #[tokio::test]
    async fn a_backend_is_minted_once_per_bucket_and_evicted_by_node() {
        let fallback = built(LayerConfig::new());
        let url = address::parse("gs://bkt/k").unwrap();
        let (first, target) = fallback.backend_for(&url, None).await.unwrap();
        assert_eq!(target.backend_id.0, "gcs-fallback:bkt");
        assert_eq!(target.resolved_address, url);
        let (second, _) = fallback.backend_for(&url, None).await.unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "a hit returns the resident backend"
        );
        assert_eq!(fallback.cache.len(), 1);
        fallback.evict_node(&address::parse("gs://bkt/").unwrap());
        assert!(fallback.cache.is_empty());
        // Evicting the scheme root itself names no bucket and is a no-op.
        fallback.evict_node(&address::parse("gs:///").unwrap());
        let (third, _) = fallback.backend_for(&url, None).await.unwrap();
        assert!(
            !Arc::ptr_eq(&first, &third),
            "an evicted bucket is minted again"
        );
    }

    #[tokio::test]
    async fn a_pre_cancelled_caller_does_not_reach_the_cache() {
        let fallback = built(LayerConfig::new());
        let token = CancellationToken::new();
        token.cancel();
        let url = address::parse("gs://bkt/k").unwrap();
        let error = match fallback.backend_for(&url, Some(token)).await {
            Err(error) => error,
            Ok(_) => panic!("a pre-cancelled caller must not be served"),
        };
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert!(fallback.cache.is_empty());
    }
}
