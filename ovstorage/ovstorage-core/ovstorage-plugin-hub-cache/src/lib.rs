// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `hub_cache` [`Layer`]: a cache-aside wrapper over the Omniverse Hub
//! (`usd-workstation-cache`).
//!
//! **Experimental.** The layer is new: its configuration keys and observable
//! behavior may change between releases, and the kind descriptor says so to
//! every listing surface.
//!
//! This crate owns the [`WrapperFactory`] that parses `hub_cache` config
//! into an [`ovstorage_hub_client::HubCacheClient`] and the wrapper whose
//! `read` serves repeat reads from the hub's local cache: a validator
//! probe against `inner`, a keyed hub lookup, and on a miss a streaming
//! tee that fills the hub while the body flows to the caller unchanged.
//! `materialize` answers the same lookup with the hub's own file under a
//! live lease, filling it from the inner `read` when the object is not
//! cached yet — which is how a backend that streams bytes but stages no
//! local file gains a `materialize` at all. Everything else passes
//! through — with write-once validator keys there is nothing to
//! invalidate, so mutations keep their pass-through defaults and a stale
//! entry is unreachable by construction.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ovstorage_hub_client::{HubCacheClient, HubClientConfig, KeyScheme};
use ovstorage_plugin::*;
use tokio::sync::Semaphore;

mod materialize;
mod metrics;
#[cfg(test)]
mod metrics_tests;
mod read;
#[cfg(test)]
mod testing;

/// The `hub_cache` wrapper kind registered by [`HubCacheWrapperFactory`].
pub const HUB_CACHE_KIND: &str = "hub_cache";

/// Marks a request whose caller wants a fully buffered result, so a hub hit
/// is returned as [`ReadResult::Bytes`] rather than a leased delegate. The
/// same crate-private constant every cache layer keys this behavior on.
pub(crate) const READ_TO_BYTES_EXTENSION: &str = "ovstorage.read_to_bytes";

/// The client name reported in every hub connect handshake this crate opens.
const HUB_CLIENT_NAME: &str = "ovstorage";

/// The `max_streaming_fills` default: how many fills may stream into the hub
/// concurrently before a read serves uncached.
const DEFAULT_MAX_STREAMING_FILLS: u64 = 64;

/// The `timeout_ms` default: the per-hub-call deadline in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 1000;

/// Builds a base [`LayerKindDescriptor`] for `kind`, matching the shape every
/// wrapper kind in this crate shares: no connections, no auth capability, and
/// no user-metadata carriage (this crate's layers own no storage of their
/// own).
fn descriptor(kind: impl Into<String>) -> LayerKindDescriptor {
    let kind = kind.into();
    LayerKindDescriptor {
        display_name: kind.clone(),
        kind,
        layer_type: LayerType::Wrapper,
        description: None,
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        auth_capable: false,
        supports_user_metadata: false,
    }
}

/// Builds one [`ConfigField`] entry, matching the shape every field in this
/// crate's config schemas shares.
fn config_field(
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

/// Reads `value` as a non-negative integer, failing the stack build on
/// anything else — a negative or non-integer value is an operator mistake,
/// not something to silently clamp or ignore.
fn config_u64(value: &ConfigValue, key: &str) -> Result<u64> {
    match value {
        ConfigValue::Int(value) if *value >= 0 => Ok(*value as u64),
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("layer config `{key}` must be a non-negative integer"),
        )),
    }
}

/// Reads `key` from `config` as text, falling back to `default` when the key
/// is absent. Any other value type fails the stack build: a wrong-typed
/// field is an operator mistake, not something to silently coerce.
fn config_text<'a>(config: &'a LayerConfig, key: &str, default: &'static str) -> Result<&'a str> {
    match config.get(key) {
        Some(ConfigValue::String(value)) => Ok(value.as_str()),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("layer config `{key}` must be a string"),
        )),
        None => Ok(default),
    }
}

/// A fill-slot semaphore sized from the `max_streaming_fills` config value,
/// or `None` when it configures `0` (filling disabled entirely).
fn fill_slots_for(max_streaming_fills: u64) -> Option<Arc<Semaphore>> {
    (max_streaming_fills > 0).then(|| Arc::new(Semaphore::new(max_streaming_fills as usize)))
}

/// [`WrapperFactory`] for the `hub_cache` wrapper kind ([`HUB_CACHE_KIND`]).
#[derive(Default)]
pub struct HubCacheWrapperFactory;

impl HubCacheWrapperFactory {
    /// Parses `config` and builds the wrapper's state.
    ///
    /// Kept separate from the boxed [`WrapperFactory::create_wrapper`] so
    /// tests can inspect the wrapper's fields directly instead of
    /// downcasting a `dyn Layer`. Performs no I/O: the returned wrapper's
    /// [`HubCacheClient`] dials the hub lazily on its first operation.
    fn build(
        &self,
        name: &str,
        config: &LayerConfig,
        inner: LayerHandle,
    ) -> Result<HubCacheWrapper> {
        let endpoint = config_text(
            config,
            "endpoint",
            ovstorage_hub_client::DEFAULT_HUB_ENDPOINT,
        )?;
        if endpoint.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "layer config `endpoint` must not be empty",
            ));
        }
        let partition = config_text(config, "partition", "local")?;
        if partition.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "layer config `partition` must not be empty",
            ));
        }
        let key_scheme_str = config_text(config, "key_scheme", "ovstorage")?;
        let key_scheme = KeyScheme::from_config_str(key_scheme_str).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "layer config `key_scheme` must be `ovstorage` or `omni-client-compat`, \
                     got `{key_scheme_str}`"
                ),
            )
        })?;
        let max_object_bytes = config
            .get("max_object_bytes")
            .map(|value| config_u64(value, "max_object_bytes"))
            .transpose()?;
        let max_streaming_fills = config
            .get("max_streaming_fills")
            .map(|value| config_u64(value, "max_streaming_fills"))
            .transpose()?
            .unwrap_or(DEFAULT_MAX_STREAMING_FILLS);
        // The semaphore's own permit ceiling: a value above it would panic
        // at construction, and a panic is not how configuration fails.
        if max_streaming_fills > Semaphore::MAX_PERMITS as u64 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "layer config `max_streaming_fills` must be at most {}",
                    Semaphore::MAX_PERMITS
                ),
            ));
        }
        let timeout_ms = config
            .get("timeout_ms")
            .map(|value| config_u64(value, "timeout_ms"))
            .transpose()?
            .unwrap_or(DEFAULT_TIMEOUT_MS);

        let client = HubCacheClient::new(HubClientConfig {
            endpoint: endpoint.to_string(),
            client_name: HUB_CLIENT_NAME.to_string(),
            timeout: Duration::from_millis(timeout_ms),
            ..HubClientConfig::default()
        });

        Ok(HubCacheWrapper {
            name: name.to_string(),
            descriptor: self.descriptor(),
            inner,
            client,
            key_scheme,
            partition: partition.to_string(),
            max_object_bytes,
            fill_slots: fill_slots_for(max_streaming_fills),
            fs: Arc::new(read::FsHealth::new()),
            proven: read::DigestProofs::default(),
        })
    }
}

#[async_trait]
impl WrapperFactory for HubCacheWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        let mut descriptor = descriptor(HUB_CACHE_KIND);
        descriptor.description = Some(
            "Experimental: caches object bytes in a local Omniverse Hub \
             (usd-workstation-cache); configuration keys and behavior may \
             change between releases"
                .to_string(),
        );
        descriptor.config_schema = vec![
            config_field(
                "endpoint",
                "Endpoint",
                ConfigFieldKind::Text,
                false,
                &format!(
                    "`host:port` of the hub's fixed shared-mode protobuf listener \
                     (default `{}`)",
                    ovstorage_hub_client::DEFAULT_HUB_ENDPOINT
                ),
            ),
            config_field(
                "partition",
                "Partition",
                ConfigFieldKind::Text,
                false,
                "Cache-sharing boundary for entries this layer keys under the \
                 `ovstorage` key scheme (default `local`)",
            ),
            config_field(
                "key_scheme",
                "Key scheme",
                ConfigFieldKind::Text,
                false,
                "`ovstorage` (default) keys entries under this layer's own scheme, or \
                 `omni-client-compat` to share cached objects with omni.client",
            ),
            config_field(
                "max_object_bytes",
                "Max object bytes",
                ConfigFieldKind::Integer,
                false,
                "Objects larger than this are served but never filled into the hub \
                 (unset = unbounded)",
            ),
            config_field(
                "max_streaming_fills",
                "Max streaming fills",
                ConfigFieldKind::Integer,
                false,
                "Maximum concurrent fills streamed into the hub (default 64); `0` \
                 disables filling entirely",
            ),
            config_field(
                "timeout_ms",
                "Timeout ms",
                ConfigFieldKind::Integer,
                false,
                "Deadline in milliseconds for each hub call (default 1000)",
            ),
        ];
        descriptor
    }

    async fn create_wrapper(
        &self,
        name: &str,
        config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(Arc::new(self.build(name, config, inner)?))
    }
}

/// The hub cache-aside [`Layer`] composed over `inner`.
///
/// Per RFC-0066, an entry's identity is the tuple `(partition, canonical
/// post-alias URL, etag)`. The read path keys the hub with exactly this
/// tuple through [`ovstorage_hub_client::hub_key`] under `key_scheme`, so
/// two requests for the same bytes at the same validator share one cached
/// copy and a changed etag always misses rather than serving stale
/// content. `max_object_bytes` bounds what gets filled (oversized objects
/// are still served, just never cached), and `fill_slots` bounds how many
/// fills stream into the hub at once, with `None` disabling filling
/// outright.
///
/// A hub that is unreachable at any point degrades this layer to a
/// transparent pass-through: every slot other than `read` and
/// `materialize` delegates to `inner` unchanged via the [`Layer`] trait's
/// defaults, and no hub failure inside either path ever fails a caller's
/// request that the inner layer could serve.
struct HubCacheWrapper {
    name: String,
    descriptor: LayerKindDescriptor,
    inner: LayerHandle,
    /// Lazily connects on first use; construction never blocks on hub
    /// connectivity or performs I/O.
    client: HubCacheClient,
    key_scheme: KeyScheme,
    partition: String,
    max_object_bytes: Option<u64>,
    /// `None` when `max_streaming_fills` configures `0`, disabling filling
    /// entirely; otherwise a semaphore with that many permits.
    fill_slots: Option<Arc<Semaphore>>,
    /// The stall latch every hub-cache filesystem operation runs through.
    fs: Arc<read::FsHealth>,
    /// Digest proofs already carried out, so a write-once entry is hashed
    /// once rather than on every hit.
    proven: read::DigestProofs,
}

#[async_trait]
impl Layer for HubCacheWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    /// Every slot this wrapper does not override delegates to `inner` via
    /// the [`Layer`] trait's defaults.
    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    fn supports_buffered_write_capture(&self) -> bool {
        self.inner.supports_buffered_write_capture()
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.read_impl(request, cancel).await
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        self.materialize_impl(request, cancel).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ovstorage_hub_client::DEFAULT_HUB_ENDPOINT;

    use super::*;

    fn backend_descriptor(kind: &str) -> LayerKindDescriptor {
        LayerKindDescriptor {
            display_name: kind.to_string(),
            kind: kind.to_string(),
            layer_type: LayerType::Backend,
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: false,
            auth_capable: false,
            supports_user_metadata: false,
        }
    }

    fn object_info(address: Url) -> ObjectInfo {
        ObjectInfo::from((
            address,
            BackendItemInfo {
                kind: ObjectKind::File,
                etag: Some("etag".to_string()),
                etag_strength: EtagStrength::Strong,
                version: None,
                size: Some(0),
                mtime: None,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
                versioned_address: None,
            },
        ))
    }

    /// A minimal inner [`Layer`] that counts `read`/`stat` calls and answers
    /// both trivially, standing in for a real backend so the wrapper's
    /// delegation can be observed.
    struct ProbeLayer {
        reads: AtomicUsize,
        stats: AtomicUsize,
    }

    impl ProbeLayer {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                reads: AtomicUsize::new(0),
                stats: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl Layer for ProbeLayer {
        fn name(&self) -> &str {
            "probe"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            backend_descriptor("probe")
        }

        async fn stat(
            &self,
            request: Request<StatRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ObjectInfo> {
            self.stats.fetch_add(1, Ordering::SeqCst);
            Ok(object_info(request.input.address))
        }

        async fn read(
            &self,
            request: Request<ReadRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ReadResult> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(ReadResult::Bytes {
                bytes: b"probe".to_vec(),
                info: object_info(request.input.address),
            })
        }
    }

    fn build(config: LayerConfig) -> Result<(Arc<ProbeLayer>, HubCacheWrapper)> {
        let probe = ProbeLayer::new();
        let wrapper = HubCacheWrapperFactory.build("hub-cache", &config, probe.clone())?;
        Ok((probe, wrapper))
    }

    /// Builds `config` expecting `create_wrapper`'s parsing to reject it,
    /// and returns the [`Error`]. Neither `HubCacheWrapper` nor `ProbeLayer`
    /// implements `Debug`, so this stands in for `Result::expect_err`.
    fn build_err(config: LayerConfig) -> Error {
        match build(config) {
            Ok(_) => panic!("expected the build to fail"),
            Err(err) => err,
        }
    }

    #[test]
    fn defaults_configure_the_client_with_the_default_endpoint_and_timeout() {
        let (_probe, wrapper) = build(LayerConfig::new()).expect("defaults build");
        assert_eq!(wrapper.name(), "hub-cache");
        assert_eq!(wrapper.descriptor().kind, HUB_CACHE_KIND);
        assert_eq!(wrapper.client.config().endpoint, DEFAULT_HUB_ENDPOINT);
        assert_eq!(wrapper.client.config().timeout, Duration::from_millis(1000));
        assert_eq!(wrapper.client.config().client_name, "ovstorage");
        assert_eq!(wrapper.partition, "local");
        assert_eq!(wrapper.key_scheme, KeyScheme::Ovstorage);
        assert!(wrapper.max_object_bytes.is_none());
    }

    #[test]
    fn a_configured_endpoint_and_timeout_reach_the_client() {
        let mut config = LayerConfig::new();
        config.insert(
            "endpoint".to_string(),
            ConfigValue::String("example:9999".to_string()),
        );
        config.insert("timeout_ms".to_string(), ConfigValue::Int(250));
        let (_probe, wrapper) = build(config).expect("builds with a custom endpoint");
        assert_eq!(wrapper.client.config().endpoint, "example:9999");
        assert_eq!(wrapper.client.config().timeout, Duration::from_millis(250));
    }

    #[test]
    fn a_wrong_typed_endpoint_fails_the_build() {
        let mut config = LayerConfig::new();
        config.insert("endpoint".to_string(), ConfigValue::Int(1));
        let err = build_err(config);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_wrong_typed_partition_fails_the_build() {
        let mut config = LayerConfig::new();
        config.insert("partition".to_string(), ConfigValue::Bool(true));
        let err = build_err(config);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_wrong_typed_key_scheme_fails_the_build() {
        let mut config = LayerConfig::new();
        config.insert("key_scheme".to_string(), ConfigValue::Int(1));
        let err = build_err(config);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_wrong_typed_max_object_bytes_fails_the_build() {
        let mut config = LayerConfig::new();
        config.insert(
            "max_object_bytes".to_string(),
            ConfigValue::String("big".to_string()),
        );
        let err = build_err(config);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_wrong_typed_max_streaming_fills_fails_the_build() {
        let mut config = LayerConfig::new();
        config.insert("max_streaming_fills".to_string(), ConfigValue::Bool(false));
        let err = build_err(config);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_wrong_typed_timeout_ms_fails_the_build() {
        let mut config = LayerConfig::new();
        config.insert(
            "timeout_ms".to_string(),
            ConfigValue::String("slow".to_string()),
        );
        let err = build_err(config);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_negative_integer_fails_like_a_wrong_type() {
        let mut config = LayerConfig::new();
        config.insert("timeout_ms".to_string(), ConfigValue::Int(-1));
        let err = build_err(config);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn an_unknown_key_scheme_names_both_valid_values() {
        let mut config = LayerConfig::new();
        config.insert(
            "key_scheme".to_string(),
            ConfigValue::String("nucleus-style".to_string()),
        );
        let err = build_err(config);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("ovstorage"), "{}", err.message());
        assert!(
            err.message().contains("omni-client-compat"),
            "{}",
            err.message()
        );
    }

    #[test]
    fn an_empty_endpoint_fails_the_build() {
        let mut config = LayerConfig::new();
        config.insert("endpoint".to_string(), ConfigValue::String(String::new()));
        let err = build_err(config);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn an_empty_partition_fails_the_build() {
        let mut config = LayerConfig::new();
        config.insert("partition".to_string(), ConfigValue::String(String::new()));
        let err = build_err(config);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn a_max_streaming_fills_above_the_permit_ceiling_fails_the_build() {
        let mut config = LayerConfig::new();
        config.insert(
            "max_streaming_fills".to_string(),
            ConfigValue::Int(i64::MAX),
        );
        let err = build_err(config);
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("at most"), "{}", err.message());
    }

    #[test]
    fn zero_max_streaming_fills_disables_the_fill_semaphore() {
        let mut config = LayerConfig::new();
        config.insert("max_streaming_fills".to_string(), ConfigValue::Int(0));
        let (_probe, wrapper) = build(config).expect("builds");
        assert!(wrapper.fill_slots.is_none());
    }

    #[test]
    fn a_positive_max_streaming_fills_produces_that_many_permits() {
        let mut config = LayerConfig::new();
        config.insert("max_streaming_fills".to_string(), ConfigValue::Int(3));
        let (_probe, wrapper) = build(config).expect("builds");
        let slots = wrapper.fill_slots.as_ref().expect("permits");
        assert_eq!(slots.available_permits(), 3);
    }

    #[tokio::test]
    async fn read_and_stat_delegate_to_the_inner_layer_and_count() {
        let (probe, wrapper) = build(LayerConfig::new()).expect("builds");
        let address = Url::parse("test:///object").unwrap();

        wrapper
            .stat(
                Request::new(StatRequest {
                    address: address.clone(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .expect("stat delegates");
        assert_eq!(probe.stats.load(Ordering::SeqCst), 1);

        wrapper
            .read(
                Request::new(ReadRequest {
                    address,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .expect("read delegates");
        assert_eq!(probe.reads.load(Ordering::SeqCst), 1);
    }
}
