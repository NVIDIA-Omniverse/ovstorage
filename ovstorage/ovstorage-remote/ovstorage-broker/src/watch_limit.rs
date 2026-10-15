// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker-native admission control for externally requested directory watches.
//!
//! This is a Layer by construction so its interception and delegation behavior
//! stay composable and unit-testable, but it is intentionally built into the
//! broker executable rather than exposed as a loadable plugin. It has no cdylib
//! or plugin manifest surface. Its admission scope is the broker's shared
//! inner-Stack chokepoint; the REST gateway's independently embedded Stack does
//! not include it.
//!
//! Internal cache-invalidation watches are opened and drained below this Layer,
//! so they are intentionally exempt from this externally facing admission
//! budget.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ovstorage::wrappers::ext;
use ovstorage::{
    CancellationToken, ChangeEvent, ChangeStream, ConfigValue, Error, ErrorCode, Layer,
    LayerConfig, LayerHandle, LayerKindDescriptor, LayerType, ListRequest, ListStream, Request,
    Result, WatchDirectoryRequest, WrapperFactory,
};

use crate::trace::RedactedUrl;

pub(crate) const WATCH_LIMIT_KIND: &str = "watch_limit";

pub(crate) const DEFAULT_MAX_WATCHES_PER_PRINCIPAL: usize = 256;
const DEFAULT_MAX_WATCHES_TOTAL: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WatchLimits {
    per_principal: usize,
    total: usize,
}

impl Default for WatchLimits {
    fn default() -> Self {
        Self {
            per_principal: DEFAULT_MAX_WATCHES_PER_PRINCIPAL,
            total: DEFAULT_MAX_WATCHES_TOTAL,
        }
    }
}

#[derive(Default)]
struct WatchBudget {
    total: usize,
    per_principal: HashMap<String, usize>,
}

/// Admission counters shared by every watch-limit wrapper built during this
/// broker process's lifetime.
///
/// Reload swaps the immutable Stack while existing streams remain live. The
/// wrapper configuration (and therefore its limits) belongs to each Stack,
/// but all generations must account against one set of live-watch counters.
#[derive(Clone, Default)]
pub(crate) struct SharedWatchBudget(Arc<Mutex<WatchBudget>>);

/// Broker-owned factory for the in-process [`WatchLimitWrapper`].
pub(crate) struct WatchLimitWrapperFactory {
    budget: SharedWatchBudget,
}

impl WatchLimitWrapperFactory {
    pub(crate) fn new(budget: SharedWatchBudget) -> Self {
        Self { budget }
    }
}

impl Default for WatchLimitWrapperFactory {
    fn default() -> Self {
        Self::new(SharedWatchBudget::default())
    }
}

#[async_trait]
impl WrapperFactory for WatchLimitWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: WATCH_LIMIT_KIND.to_string(),
            layer_type: LayerType::Wrapper,
            display_name: WATCH_LIMIT_KIND.to_string(),
            description: Some("Broker-wide directory-watch admission limits".to_string()),
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: false,
            auth_capable: false,
            supports_user_metadata: false,
        }
    }

    async fn create_wrapper(
        &self,
        name: &str,
        config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let limits = watch_limits_from(config)?;
        Ok(Arc::new(WatchLimitWrapper {
            name: name.to_string(),
            descriptor: self.descriptor(),
            inner,
            limits,
            budget: self.budget.clone(),
        }))
    }
}

fn watch_limits_from(config: &LayerConfig) -> Result<WatchLimits> {
    let defaults = WatchLimits::default();
    Ok(WatchLimits {
        per_principal: config_limit(config, "max_watches_per_principal", defaults.per_principal)?,
        total: config_limit(config, "max_watches_total", defaults.total)?,
    })
}

fn config_limit(config: &LayerConfig, key: &str, default: usize) -> Result<usize> {
    let Some(value) = config.get(key) else {
        return Ok(default);
    };
    let value = match value {
        ConfigValue::Int(value) if *value > 0 => *value,
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("layer config `{key}` must be a positive integer"),
            ));
        }
    };
    usize::try_from(value).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("layer config `{key}` exceeds the supported maximum"),
        )
    })
}

struct WatchLimitWrapper {
    name: String,
    descriptor: LayerKindDescriptor,
    inner: LayerHandle,
    limits: WatchLimits,
    budget: SharedWatchBudget,
}

impl WatchLimitWrapper {
    fn principal(request: &Request<WatchDirectoryRequest>) -> String {
        request.extensions.get(ext::PRINCIPAL_ID).map_or_else(
            || ovstorage_authz_context::ANONYMOUS_PRINCIPAL_ID.to_string(),
            |bytes| String::from_utf8_lossy(bytes).into_owned(),
        )
    }

    fn admit(&self, principal: String, request: &WatchDirectoryRequest) -> Result<WatchLease> {
        let mut budget = self
            .budget
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let principal_count = budget.per_principal.get(&principal).copied().unwrap_or(0);

        if principal_count >= self.limits.per_principal {
            tracing::warn!(
                target: "ovstorage.broker.watch_limit",
                event = "watch_admission_rejected",
                limit.dimension = "max_watches_per_principal",
                limit.value = self.limits.per_principal,
                object.address = %RedactedUrl(&request.prefix),
                "directory-watch admission limit exhausted"
            );
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                format!(
                    "watch admission exhausted `max_watches_per_principal` ({})",
                    self.limits.per_principal
                ),
            ));
        }

        if budget.total >= self.limits.total {
            tracing::warn!(
                target: "ovstorage.broker.watch_limit",
                event = "watch_admission_rejected",
                limit.dimension = "max_watches_total",
                limit.value = self.limits.total,
                object.address = %RedactedUrl(&request.prefix),
                "directory-watch admission limit exhausted"
            );
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                format!(
                    "watch admission exhausted `max_watches_total` ({})",
                    self.limits.total
                ),
            ));
        }

        budget.total += 1;
        *budget.per_principal.entry(principal.clone()).or_default() += 1;
        drop(budget);

        Ok(WatchLease {
            principal,
            budget: Some(self.budget.clone()),
        })
    }
}

#[async_trait]
impl Layer for WatchLimitWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    fn supports_buffered_write_capture(&self) -> bool {
        self.inner.supports_buffered_write_capture()
    }

    async fn list_stream(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListStream> {
        self.inner.list_stream(request, cancel).await
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        let lease = self.admit(Self::principal(&request), &request.input)?;
        let stream = self.inner.watch_directory(request, cancel).await?;
        Ok(Box::new(LimitedChangeStream {
            inner: stream,
            _lease: lease,
        }))
    }
}

struct WatchLease {
    principal: String,
    budget: Option<SharedWatchBudget>,
}

impl Drop for WatchLease {
    fn drop(&mut self) {
        let Some(budget) = self.budget.take() else {
            return;
        };
        let mut budget = budget
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        budget.total -= 1;
        if let Some(principal_count) = budget.per_principal.get_mut(&self.principal) {
            *principal_count -= 1;
            if *principal_count == 0 {
                budget.per_principal.remove(&self.principal);
            }
        }
    }
}

struct LimitedChangeStream {
    inner: ChangeStream,
    _lease: WatchLease,
}

impl Iterator for LimitedChangeStream {
    type Item = Result<ChangeEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use ovstorage::{BackendItemInfo, ObjectInfo, StatRequest, Url, WatchDirectoryOptions};

    use super::*;

    struct RecordingInner {
        fail_next_watch: AtomicBool,
        terminal_error: bool,
        watch_calls: AtomicUsize,
        stat_calls: AtomicUsize,
        stat_principal: Mutex<Option<Vec<u8>>>,
    }

    impl RecordingInner {
        fn new() -> Self {
            Self {
                fail_next_watch: AtomicBool::new(false),
                terminal_error: false,
                watch_calls: AtomicUsize::new(0),
                stat_calls: AtomicUsize::new(0),
                stat_principal: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl Layer for RecordingInner {
        fn name(&self) -> &str {
            "test-inner"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            LayerKindDescriptor {
                kind: "test-inner".to_string(),
                layer_type: LayerType::Backend,
                display_name: "test-inner".to_string(),
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

        async fn stat(
            &self,
            request: Request<StatRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ObjectInfo> {
            self.stat_calls.fetch_add(1, Ordering::SeqCst);
            *self
                .stat_principal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = request
                .extensions
                .get(ext::PRINCIPAL_ID)
                .map(<[u8]>::to_vec);
            Ok(ObjectInfo::from((
                request.input.address,
                BackendItemInfo::default(),
            )))
        }

        async fn watch_directory(
            &self,
            _request: Request<WatchDirectoryRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ChangeStream> {
            self.watch_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_next_watch.swap(false, Ordering::SeqCst) {
                return Err(Error::new(ErrorCode::Transient, "watch setup failed"));
            }
            if self.terminal_error {
                return Ok(Box::new(std::iter::once(Err(Error::new(
                    ErrorCode::Transient,
                    "watch stream failed",
                )))));
            }
            Ok(Box::new(std::iter::empty()))
        }
    }

    fn config(per_principal: i64, total: i64) -> LayerConfig {
        HashMap::from([
            (
                "max_watches_per_principal".to_string(),
                ConfigValue::Int(per_principal),
            ),
            ("max_watches_total".to_string(), ConfigValue::Int(total)),
        ])
    }

    async fn wrapper(inner: Arc<RecordingInner>, per_principal: i64, total: i64) -> LayerHandle {
        WatchLimitWrapperFactory::default()
            .create_wrapper("watch-limit", &config(per_principal, total), inner, None)
            .await
            .expect("create watch-limit wrapper")
    }

    fn principal_request<T>(principal: &[u8], input: T) -> Request<T> {
        let mut request = Request::new(input);
        request
            .extensions
            .insert(ext::PRINCIPAL_ID, principal.to_vec());
        request
    }

    fn watch_request(principal: Option<&[u8]>) -> Request<WatchDirectoryRequest> {
        let input = WatchDirectoryRequest {
            prefix: Url::parse("file:///watched/").unwrap(),
            options: WatchDirectoryOptions::default(),
        };
        match principal {
            Some(principal) => principal_request(principal, input),
            None => Request::new(input),
        }
    }

    async fn rejected(wrapper: &LayerHandle, principal: Option<&[u8]>) -> Error {
        match wrapper
            .watch_directory(watch_request(principal), None)
            .await
        {
            Ok(_) => panic!("watch admission unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn descriptor_is_non_connection_wrapper() {
        let descriptor = WatchLimitWrapperFactory::default().descriptor();
        assert_eq!(descriptor.kind, WATCH_LIMIT_KIND);
        assert_eq!(descriptor.layer_type, LayerType::Wrapper);
        assert!(!descriptor.accepts_connections);
    }

    #[test]
    fn config_uses_documented_defaults() {
        assert_eq!(
            watch_limits_from(&LayerConfig::new()).unwrap(),
            WatchLimits {
                per_principal: 256,
                total: 4096,
            }
        );
    }

    #[test]
    fn config_rejects_zero_or_non_integer_values() {
        for (key, value) in [
            ("max_watches_per_principal", ConfigValue::Int(0)),
            ("max_watches_total", ConfigValue::Int(0)),
            (
                "max_watches_per_principal",
                ConfigValue::String("1".to_string()),
            ),
            ("max_watches_total", ConfigValue::Bool(true)),
        ] {
            let error = watch_limits_from(&HashMap::from([(key.to_string(), value)]))
                .expect_err("invalid watch limit must fail the build");
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
            assert!(error.message().contains(key));
        }
    }

    #[tokio::test]
    async fn admits_watches_under_both_caps() {
        let inner = Arc::new(RecordingInner::new());
        let wrapper = wrapper(Arc::clone(&inner), 2, 3).await;

        let alice = wrapper
            .watch_directory(watch_request(Some(b"alice")), None)
            .await
            .expect("first watch is under both caps");
        let bob = wrapper
            .watch_directory(watch_request(Some(b"bob")), None)
            .await
            .expect("second watch is under both caps");

        assert_eq!(inner.watch_calls.load(Ordering::SeqCst), 2);
        drop((alice, bob));
    }

    #[tokio::test]
    async fn rejects_at_per_principal_cap_while_another_principal_is_admitted() {
        let inner = Arc::new(RecordingInner::new());
        let wrapper = wrapper(Arc::clone(&inner), 1, 4).await;
        let alice = wrapper
            .watch_directory(watch_request(Some(b"alice")), None)
            .await
            .expect("alice's first watch is admitted");
        let error = rejected(&wrapper, Some(b"alice")).await;
        assert_eq!(error.code(), ErrorCode::ResourceExhausted);
        assert!(error.message().contains("max_watches_per_principal"));

        let bob = wrapper
            .watch_directory(watch_request(Some(b"bob")), None)
            .await
            .expect("bob has an independent principal bucket");
        assert_eq!(
            inner.watch_calls.load(Ordering::SeqCst),
            2,
            "the rejected watch must not reach the inner layer"
        );
        drop((alice, bob));
    }

    #[tokio::test]
    async fn anonymous_requests_share_one_bounded_bucket() {
        let inner = Arc::new(RecordingInner::new());
        let wrapper = wrapper(Arc::clone(&inner), 1, 4).await;
        let anonymous = wrapper
            .watch_directory(watch_request(None), None)
            .await
            .expect("first anonymous watch is admitted");
        let error = rejected(&wrapper, None).await;
        assert_eq!(error.code(), ErrorCode::ResourceExhausted);
        assert!(error.message().contains("max_watches_per_principal"));

        let alice = wrapper
            .watch_directory(watch_request(Some(b"alice")), None)
            .await
            .expect("a named principal has a distinct bucket");
        assert_eq!(inner.watch_calls.load(Ordering::SeqCst), 2);
        drop((anonymous, alice));
    }

    #[tokio::test]
    async fn rejects_total_limit_across_principals() {
        let inner = Arc::new(RecordingInner::new());
        let wrapper = wrapper(Arc::clone(&inner), 3, 2).await;
        let alice = wrapper
            .watch_directory(watch_request(Some(b"alice")), None)
            .await
            .unwrap();
        let bob = wrapper
            .watch_directory(watch_request(Some(b"bob")), None)
            .await
            .unwrap();

        let error = rejected(&wrapper, Some(b"carol")).await;
        assert_eq!(error.code(), ErrorCode::ResourceExhausted);
        assert!(error.message().contains("max_watches_total"));
        assert_eq!(
            inner.watch_calls.load(Ordering::SeqCst),
            2,
            "the total-limit rejection must not reach the inner layer"
        );
        drop((alice, bob));
    }

    #[tokio::test]
    async fn stream_drop_releases_once_even_after_terminal_error() {
        let inner = Arc::new(RecordingInner {
            terminal_error: true,
            ..RecordingInner::new()
        });
        let wrapper = wrapper(inner, 1, 1).await;
        let mut first = wrapper
            .watch_directory(watch_request(Some(b"alice")), None)
            .await
            .unwrap();
        assert!(first.next().unwrap().is_err());

        assert_eq!(
            rejected(&wrapper, Some(b"alice")).await.code(),
            ErrorCode::ResourceExhausted
        );
        drop(first);

        let replacement = wrapper
            .watch_directory(watch_request(Some(b"alice")), None)
            .await
            .expect("dropping the stream releases its lease");
        drop(replacement);
    }

    #[tokio::test]
    async fn inner_setup_error_undoes_admission() {
        let inner = Arc::new(RecordingInner::new());
        inner.fail_next_watch.store(true, Ordering::SeqCst);
        let wrapper = wrapper(Arc::clone(&inner), 1, 1).await;

        let error = rejected(&wrapper, Some(b"alice")).await;
        assert_eq!(error.code(), ErrorCode::Transient);

        let stream = wrapper
            .watch_directory(watch_request(Some(b"alice")), None)
            .await
            .expect("failed setup must return its admission lease");
        assert_eq!(inner.watch_calls.load(Ordering::SeqCst), 2);
        drop(stream);
    }

    #[tokio::test]
    async fn non_watch_verbs_delegate_untouched() {
        let inner = Arc::new(RecordingInner::new());
        let wrapper = wrapper(Arc::clone(&inner), 1, 1).await;
        let address = Url::parse("file:///object.txt").unwrap();

        let info = wrapper
            .stat(
                principal_request(
                    b"alice",
                    StatRequest {
                        address: address.clone(),
                        options: Default::default(),
                    },
                ),
                None,
            )
            .await
            .expect("stat delegates to inner");

        assert_eq!(info.address, address);
        assert_eq!(inner.stat_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            inner
                .stat_principal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_deref(),
            Some(b"alice".as_slice()),
            "default delegation preserves request extensions"
        );
    }
}
