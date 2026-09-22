// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The anonymous `azure://` scheme fallback: the read-only, credential-free
//! route an `azure://{account}/{container}/…` address takes when no configured
//! connection serves it and the operator granted `anonymous_fallback = ["azure"]`
//! on this layer.
//!
//! The layer publishes one hidden, marked `azure:///` root (see
//! [`ovstorage_plugin::fallback`]); the shared route table answers an
//! otherwise-unrouted `azure://` address with it, and the layer binds that hit
//! to [`AzureSchemeFallback`]. From there the account and container come from
//! the address itself, an ordinary per-container config is synthesized for
//! them ([`AzureConnectionConfig::anonymous_for`]), and an [`AzureBackend`] is
//! built with an **empty** credential bundle — `AzureAuth::resolve` reads no
//! environment, so the process's ambient Azure identity can never be spent on
//! a node the operator did not configure.
//!
//! Backends are cached per `(account, container)` in a bounded, single-flight
//! LRU with a mint budget ([`FallbackCache`]), because those names are the
//! caller's to invent. Nothing here registers a `Connection`: the fallback has
//! no `ConnectionId`, appears in no connection listing, and cannot be probed,
//! removed or re-credentialed. Every mutating slot and `watch_directory` is
//! refused by the layer before any wire activity — the fallback's promise is
//! "reachable anonymously", and an anonymous mutation is not something to try
//! on an operator's behalf.

use std::sync::Arc;

use ovstorage_plugin::fallback::{
    ANONYMOUS_FALLBACK_KEY, fallback_mutation_refused, read_only_capabilities, scheme_fallback_root,
};
use ovstorage_plugin::fallback_cache::FallbackCache;
use ovstorage_plugin::instance_metadata::refuse_instance_metadata;
use ovstorage_plugin::{
    BackendId, CancellationToken, Error, ErrorCode, LayerConfig, RangeReadStrategy, ResolvedTarget,
    Result, RootInfo, SecretBundle, StorageBackendKindDescriptor, Url, bail_if_cancelled,
    origin_only,
};

use crate::auth::AzureAuth;
use crate::backend::{AzureBackend, azure_capabilities};
use crate::config::{
    self, AzureAddress, AzureConnectionConfig, AzureEndpoint, DEFAULT_ENDPOINT_SUFFIX,
    azure_address_root,
};

/// The one scheme this layer kind serves through a fallback.
pub(crate) const AZURE_SCHEME: &str = "azure";

/// Layer key: the DNS suffix the fallback derives `{account}.blob.{suffix}`
/// from, for sovereign clouds. Defaults to the public cloud.
pub(crate) const ENDPOINT_SUFFIX_KEY: &str = "anonymous_fallback_endpoint_suffix";
/// Layer key: how many anonymous backends stay resident.
pub(crate) const MAX_BACKENDS_KEY: &str = "anonymous_fallback_max_backends";
/// Layer key: how many backends may be built per sliding minute.
pub(crate) const MINTS_PER_MINUTE_KEY: &str = "anonymous_fallback_mints_per_minute";
/// Every layer key the fallback reads. Anything else under the
/// `anonymous_fallback` prefix is refused by name, so a key another kind
/// accepts (`anonymous_fallback_endpoint`, say) cannot sit inert here.
const POLICY_KEYS: &[&str] = &[
    ANONYMOUS_FALLBACK_KEY,
    ENDPOINT_SUFFIX_KEY,
    MAX_BACKENDS_KEY,
    MINTS_PER_MINUTE_KEY,
];
pub(crate) const DEFAULT_MAX_BACKENDS: u64 = 64;
pub(crate) const DEFAULT_MINTS_PER_MINUTE: u64 = 120;

/// The fallback's tunables, read off the policy half of the layer table.
///
/// Parsed even when the grant does not name `azure`, so a mistyped or
/// misplaced tunable is refused at startup rather than sitting inert until
/// the grant is added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AzureFallbackPolicy {
    pub(crate) endpoint_suffix: String,
    pub(crate) max_backends: usize,
    pub(crate) mints_per_minute: u32,
}

impl AzureFallbackPolicy {
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — a key under the fallback prefix this
    ///   kind does not read, a value of the wrong type, a suffix that is not
    ///   a DNS suffix, or a bound that is zero or does not fit its integer.
    pub(crate) fn parse(policy: &LayerConfig) -> Result<Self> {
        if let Some(key) = policy
            .keys()
            .filter(|key| !POLICY_KEYS.contains(&key.as_str()))
            .min()
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "unknown Azure layer key `{key}`; the anonymous fallback accepts {}",
                    POLICY_KEYS.join(", ")
                ),
            ));
        }
        let endpoint_suffix =
            config::optional_text(policy, ENDPOINT_SUFFIX_KEY, DEFAULT_ENDPOINT_SUFFIX)?;
        config::validate_endpoint_suffix(&endpoint_suffix)?;
        let max_backends = usize::try_from(positive_u64(
            policy,
            MAX_BACKENDS_KEY,
            DEFAULT_MAX_BACKENDS,
        )?)
        .map_err(|_| too_large(MAX_BACKENDS_KEY))?;
        let mints_per_minute = u32::try_from(positive_u64(
            policy,
            MINTS_PER_MINUTE_KEY,
            DEFAULT_MINTS_PER_MINUTE,
        )?)
        .map_err(|_| too_large(MINTS_PER_MINUTE_KEY))?;
        Ok(Self {
            endpoint_suffix,
            max_backends,
            mints_per_minute,
        })
    }
}

fn too_large(key: &str) -> Error {
    Error::new(
        ErrorCode::InvalidArgument,
        format!("Azure config field '{key}' is too large"),
    )
}

/// A cache bound off the layer table, refused at zero. A zero cache would keep
/// nothing, and a zero budget is what [`FallbackCache`] reads as no budget at
/// all — the amplification bound the knob exists to set, silently removed.
/// Neither is what an operator means by turning the fallback on.
fn positive_u64(policy: &LayerConfig, key: &str, default: u64) -> Result<u64> {
    let value = config::optional_u64(policy, key, default)?;
    if value == 0 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure config field '{key}' must be at least 1"),
        ));
    }
    Ok(value)
}

/// The `azure://{account}/{container}/` node an address resolves to under the
/// fallback — the unit a backend is built for, cached under, and evicted by.
struct FallbackNode {
    account: String,
    container: String,
    root: Url,
}

impl FallbackNode {
    fn key(&self) -> (String, String) {
        (self.account.clone(), self.container.clone())
    }

    fn backend_id(&self) -> BackendId {
        BackendId(format!(
            "azure-fallback:{}/{}",
            self.account, self.container
        ))
    }
}

/// The layer's `azure://` fallback: its published root, its tunables, and the
/// bounded cache of anonymous backends it has built.
pub(crate) struct AzureSchemeFallback {
    root: RootInfo,
    endpoint_suffix: String,
    /// The loopback-only test hook, shared with connections so a test can
    /// point the fallback at the same fake it points a connection at.
    test_endpoint: Option<AzureEndpoint>,
    cache: FallbackCache<(String, String), AzureBackend>,
}

impl AzureSchemeFallback {
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — the scheme root does not build,
    ///   which cannot happen for `azure` and is surfaced rather than unwrapped.
    pub(crate) fn new(
        descriptor: &StorageBackendKindDescriptor,
        policy: AzureFallbackPolicy,
        test_endpoint: Option<AzureEndpoint>,
    ) -> Result<Self> {
        // The root advertises what an anonymous flat-namespace connection
        // would, lowered to its read side: `azure_capabilities` already keeps
        // `supports_list_stream` on, and `read_only_capabilities` keeps every
        // listing, version-listing and access-check bit while clearing every
        // mutation, directory-mutation, metadata-patch and watch bit.
        let capabilities = read_only_capabilities(azure_capabilities(false, false, true));
        let mut root = scheme_fallback_root(
            AZURE_SCHEME,
            &descriptor.kind,
            capabilities,
            descriptor.icon.clone(),
        )?;
        // The fallback drives the same blob client a connection does, and a
        // ranged read works the same way through either, so the root
        // advertises the strategy the connection roots advertise. The shared
        // constructor leaves the field at its default because it does not
        // know the backend; without this line `root_info_for` would call the
        // same store less capable for being reached anonymously.
        root.range_read_strategy = RangeReadStrategy::Native;
        Ok(Self {
            root,
            endpoint_suffix: policy.endpoint_suffix,
            test_endpoint,
            cache: FallbackCache::new(policy.max_backends, policy.mints_per_minute),
        })
    }

    /// The hidden, marked `azure:///` root the layer publishes.
    pub(crate) fn root(&self) -> &RootInfo {
        &self.root
    }

    /// The node `url` names, or the refusal for an address that names none.
    ///
    /// A hostless address — the bare `azure:///` root and equally
    /// `azure:///container/key` — reaches the fallback entry through the
    /// prefix tier, not the scheme tier, so it arrives here like any other
    /// address and is refused here: there is no account to build a backend
    /// for. `AzureAddress::parse` then applies the connection-level account
    /// and container validation, so a node the fallback would build for is a
    /// node a connection could be configured for.
    fn node(&self, url: &Url) -> Result<FallbackNode> {
        if url.host_str().is_none_or(|host| host.is_empty()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "an azure:// address names no storage account",
            ));
        }
        let address = AzureAddress::parse(url)?;
        let root = azure_address_root(&address.account, &address.container)?;
        Ok(FallbackNode {
            account: address.account,
            container: address.container,
            root,
        })
    }

    /// The target a slot dispatches on for a fallback-served address: the
    /// per-node fallback `BackendId` and the address verbatim.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — `url` names no account, or fails
    ///   account/container validation.
    pub(crate) fn resolved_target(&self, url: &Url) -> Result<ResolvedTarget> {
        let node = self.node(url)?;
        Ok(ResolvedTarget {
            backend_id: node.backend_id(),
            resolved_address: url.clone(),
        })
    }

    /// The anonymous backend for the node `url` names, built on first touch
    /// and cached; and the target to hand it.
    ///
    /// The build is single-flight per node and charged against the mint
    /// budget; a build that fails is not cached, so the next caller tries
    /// again. Before any client exists, the outbound blob host is judged by
    /// the instance-metadata predicate — the host is derived from a
    /// caller-supplied account name, which is exactly the shape that check
    /// exists for.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before or during the build.
    /// - [`ErrorCode::InvalidArgument`] — see [`Self::resolved_target`].
    /// - [`ErrorCode::PermissionDenied`] — the derived blob host is an
    ///   instance-metadata endpoint.
    /// - [`ErrorCode::ResourceExhausted`] — the mint budget is spent;
    ///   retryable, and cached nodes keep answering.
    pub(crate) async fn backend_for(
        &self,
        url: &Url,
        cancel: Option<CancellationToken>,
    ) -> Result<(Arc<AzureBackend>, ResolvedTarget)> {
        bail_if_cancelled(&cancel)?;
        let node = self.node(url)?;
        let target = ResolvedTarget {
            backend_id: node.backend_id(),
            resolved_address: url.clone(),
        };
        let endpoint_suffix = self.endpoint_suffix.clone();
        let test_endpoint = self.test_endpoint.clone();
        let backend = self
            .cache
            .get_or_mint(node.key(), cancel.as_ref(), || async move {
                let config = AzureConnectionConfig::anonymous_for(
                    &node.account,
                    &node.container,
                    &endpoint_suffix,
                    test_endpoint,
                )?;
                refuse_instance_metadata(&blob_origin(&config)?)?;
                // A literal empty bundle, not one resolved from anywhere: the
                // resolver reads only the bundle, so this is anonymous by
                // construction rather than by the absence of an environment.
                let auth = AzureAuth::resolve(&SecretBundle::default())?;
                let backend = AzureBackend::new(config, auth)?;
                tracing::info!(
                    target: "ovstorage.fallback",
                    scheme = AZURE_SCHEME,
                    root = %origin_only(&node.root),
                    "anonymous fallback backend built"
                );
                Ok(backend)
            })
            .await?;
        Ok((backend, target))
    }

    /// The refusal for a mutating slot on `url`, naming the node root the
    /// operator would configure a connection for. An address that names no
    /// node gets that refusal instead.
    pub(crate) fn mutation_refused(&self, url: &Url) -> Error {
        match self.node(url) {
            Ok(node) => fallback_mutation_refused(AZURE_SCHEME, &node.root),
            Err(err) => err,
        }
    }

    /// Drop the cached backend for the node `root` names. Called when an
    /// explicit connection installs for that node: the prefix tier answers it
    /// from then on, so the entry is only an occupied slot. A root that names
    /// no node has nothing to evict.
    pub(crate) fn evict_node(&self, root: &Url) {
        if let Ok(node) = self.node(root) {
            self.cache.evict(&node.key());
        }
    }
}

/// The origin the fallback would open a socket toward for `config`, as a
/// URL the instance-metadata predicate can judge.
fn blob_origin(config: &AzureConnectionConfig) -> Result<Url> {
    let base = config.blob_url_base();
    Url::parse(&format!("{base}/")).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("the Azure blob endpoint does not parse as a URL: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::fallback::is_scheme_fallback_root;
    use ovstorage_plugin::{ConfigValue, address};

    fn policy_with(pairs: &[(&str, ConfigValue)]) -> LayerConfig {
        let mut policy = LayerConfig::new();
        policy.insert(
            ANONYMOUS_FALLBACK_KEY.into(),
            ConfigValue::Toml("anonymous_fallback = [\"azure\"]\n".into()),
        );
        for (key, value) in pairs {
            policy.insert((*key).into(), value.clone());
        }
        policy
    }

    fn fallback_with(pairs: &[(&str, ConfigValue)]) -> AzureSchemeFallback {
        AzureSchemeFallback::new(
            &crate::layer::kind_descriptor(),
            AzureFallbackPolicy::parse(&policy_with(pairs)).unwrap(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn the_policy_defaults_to_the_public_cloud_and_the_shared_bounds() {
        let policy = AzureFallbackPolicy::parse(&policy_with(&[])).unwrap();
        assert_eq!(
            policy,
            AzureFallbackPolicy {
                endpoint_suffix: DEFAULT_ENDPOINT_SUFFIX.into(),
                max_backends: 64,
                mints_per_minute: 120,
            }
        );
        // An empty table is the ungranted layer: every default, nothing
        // refused, so a layer with no fallback keys at all parses clean.
        assert_eq!(
            AzureFallbackPolicy::parse(&LayerConfig::new()).unwrap(),
            policy
        );

        let tuned = AzureFallbackPolicy::parse(&policy_with(&[
            (
                ENDPOINT_SUFFIX_KEY,
                ConfigValue::String("core.usgovcloudapi.net".into()),
            ),
            (MAX_BACKENDS_KEY, ConfigValue::Int(3)),
            (MINTS_PER_MINUTE_KEY, ConfigValue::Int(7)),
        ]))
        .unwrap();
        assert_eq!(tuned.endpoint_suffix, "core.usgovcloudapi.net");
        assert_eq!(tuned.max_backends, 3);
        assert_eq!(tuned.mints_per_minute, 7);
    }

    #[test]
    fn a_fallback_key_this_kind_does_not_read_is_refused_by_name() {
        for key in [
            "anonymous_fallback_endpoint",
            "anonymous_fallback_region",
            "anonymous_fallback_compatibility_profile",
        ] {
            let err =
                AzureFallbackPolicy::parse(&policy_with(&[(key, ConfigValue::String("x".into()))]))
                    .expect_err("a key another kind reads is not inert here");
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert!(err.message().contains(key), "{}", err.message());
            assert!(
                err.message().contains(ENDPOINT_SUFFIX_KEY),
                "the refusal lists what is accepted: {}",
                err.message()
            );
        }
    }

    #[test]
    fn malformed_tunables_are_refused() {
        for (key, value) in [
            (
                ENDPOINT_SUFFIX_KEY,
                ConfigValue::String("https://x/".into()),
            ),
            (ENDPOINT_SUFFIX_KEY, ConfigValue::Int(1)),
            (MAX_BACKENDS_KEY, ConfigValue::String("64".into())),
            (MAX_BACKENDS_KEY, ConfigValue::Int(-1)),
            // Zero is refused for both bounds: the cache reads a zero budget
            // as no budget at all, and a zero cache keeps nothing.
            (MAX_BACKENDS_KEY, ConfigValue::Int(0)),
            (MINTS_PER_MINUTE_KEY, ConfigValue::Int(0)),
            (MINTS_PER_MINUTE_KEY, ConfigValue::Bool(true)),
            (
                MINTS_PER_MINUTE_KEY,
                ConfigValue::Int(i64::from(u32::MAX) + 1),
            ),
        ] {
            let err = AzureFallbackPolicy::parse(&policy_with(&[(key, value.clone())]))
                .err()
                .unwrap_or_else(|| panic!("{key}={value:?} must be refused"));
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{key}={value:?}");
        }
    }

    /// The suffix is only ever the DNS tail spliced into
    /// `{account}.blob.{suffix}`, so userinfo, a query, a fragment or a port
    /// that reached it would reinterpret the host or ride into every request
    /// URL. The DNS-label validator refuses each shape at parse time, before
    /// any backend exists, and its message is a constant, so a secret an
    /// operator authored into the suffix is not echoed back either.
    #[test]
    fn an_endpoint_suffix_carrying_userinfo_a_query_or_a_fragment_is_refused() {
        for suffix in [
            "user:s3cret@core.windows.net",
            "s3cret@core.windows.net",
            "core.windows.net?sig=s3cret",
            "core.windows.net#s3cret",
            "core.windows.net:443",
        ] {
            let err = AzureFallbackPolicy::parse(&policy_with(&[(
                ENDPOINT_SUFFIX_KEY,
                ConfigValue::String(suffix.into()),
            )]))
            .expect_err(suffix);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{suffix}");
            assert!(
                !err.message().contains("s3cret"),
                "{suffix}: the refusal echoes the value: {}",
                err.message()
            );
        }
    }

    #[test]
    fn a_zero_bound_is_refused_by_name() {
        for key in [MAX_BACKENDS_KEY, MINTS_PER_MINUTE_KEY] {
            let err = AzureFallbackPolicy::parse(&policy_with(&[(key, ConfigValue::Int(0))]))
                .expect_err("a zero bound is not a bound");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{key}");
            assert_eq!(
                err.message(),
                format!("Azure config field '{key}' must be at least 1")
            );
        }
    }

    #[test]
    fn the_root_is_the_marked_read_only_scheme_root() {
        let fallback = fallback_with(&[]);
        let root = fallback.root();
        assert_eq!(root.root.as_str(), "azure:///");
        assert!(is_scheme_fallback_root(root));
        assert_eq!(root.layer_kind, "azure");
        assert_eq!(root.connection_id, None);
        assert_eq!(root.owning_target, None);
        // The same client, the same ranged reads: the fallback root says what
        // a connection root for the same store says, not the shared default.
        assert_eq!(root.range_read_strategy, RangeReadStrategy::Native);
        let caps = &root.capabilities;
        assert!(caps.supports_list);
        assert!(caps.supports_list_stream);
        assert!(caps.supports_version_listing);
        assert!(!caps.has_real_directories);
        assert!(!caps.supports_write);
        assert!(!caps.supports_write_redirect);
        assert!(!caps.supports_delete);
        assert!(!caps.supports_copy);
        assert!(!caps.supports_rename);
        assert!(!caps.supports_create_directory);
        assert!(!caps.supports_native_metadata_patch);
        assert!(!caps.supports_watch_directory);
    }

    #[test]
    fn a_hostless_address_names_no_account_in_either_spelling() {
        let fallback = fallback_with(&[]);
        for spelling in ["azure:///", "azure:///assets/key"] {
            let err = fallback
                .resolved_target(&address::parse(spelling).unwrap())
                .expect_err(spelling);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{spelling}");
            assert_eq!(
                err.message(),
                "an azure:// address names no storage account"
            );
            // The mutation refusal for the same address is the same
            // refusal, not a read-only complaint about a node that is not one.
            assert_eq!(
                fallback
                    .mutation_refused(&address::parse(spelling).unwrap())
                    .code(),
                ErrorCode::InvalidArgument
            );
        }
        // An account with no container is the connection parser's refusal.
        let err = fallback
            .resolved_target(&address::parse("azure://acct123/").unwrap())
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn the_target_and_the_refusal_name_the_node() {
        let fallback = fallback_with(&[]);
        let url = address::parse("azure://acct123/assets/dir/key.usd?versionid=7").unwrap();
        let target = fallback.resolved_target(&url).unwrap();
        assert_eq!(target.backend_id.0, "azure-fallback:acct123/assets");
        assert_eq!(target.resolved_address, url);

        let err = fallback.mutation_refused(&url);
        assert_eq!(err.code(), ErrorCode::Unsupported);
        assert!(err.message().contains("anonymous azure:// fallback"));
        let next = err.next_action().expect("the refusal says what to do");
        assert!(next.contains("azure://acct123/assets/"), "{next}");
        assert!(!next.contains("key.usd"), "never the caller's path: {next}");
    }

    #[tokio::test]
    async fn a_backend_is_built_once_per_node_and_evicted_by_its_root() {
        let fallback = fallback_with(&[]);
        let alpha = address::parse("azure://acct123/alpha/x").unwrap();
        let (first, target) = fallback.backend_for(&alpha, None).await.unwrap();
        assert_eq!(target.backend_id.0, "azure-fallback:acct123/alpha");
        let (again, _) = fallback
            .backend_for(&address::parse("azure://acct123/alpha/y").unwrap(), None)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&first, &again), "one node, one backend");
        assert_eq!(fallback.cache.len(), 1);

        let (beta, _) = fallback
            .backend_for(&address::parse("azure://acct123/beta/x").unwrap(), None)
            .await
            .unwrap();
        assert!(
            !Arc::ptr_eq(&first, &beta),
            "another container is another node"
        );
        assert_eq!(fallback.cache.len(), 2);

        fallback.evict_node(&address::parse("azure://acct123/alpha/").unwrap());
        assert_eq!(fallback.cache.len(), 1);
        // A root naming no node evicts nothing and panics on nothing.
        fallback.evict_node(&address::parse("azure:///").unwrap());
        assert_eq!(fallback.cache.len(), 1);
    }

    #[tokio::test]
    async fn a_cancelled_caller_is_refused_before_any_build() {
        let fallback = fallback_with(&[]);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let Err(err) = fallback
            .backend_for(
                &address::parse("azure://acct123/alpha/x").unwrap(),
                Some(cancel),
            )
            .await
        else {
            panic!("a cancelled caller must not receive a backend");
        };
        assert_eq!(err.code(), ErrorCode::Cancelled);
        assert!(fallback.cache.is_empty());
    }
}
