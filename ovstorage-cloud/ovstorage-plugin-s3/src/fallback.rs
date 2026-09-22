// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The anonymous `s3://` scheme fallback: how an `s3://bucket/key` address that
//! no configured connection serves is reached, and what reaching it may do.
//!
//! An operator grants the fallback with `anonymous_fallback = ["s3"]` on the
//! layer. The layer then publishes one hidden, read-only, marked scheme root
//! (`s3:///`) beside its connection roots; the shared route table's second
//! tier sends an unrouted `s3://` address to it, and this module turns that
//! address into a per-bucket anonymous [`S3Backend`]:
//!
//! - the bucket is the address's host, exactly as [`parse_s3_address`] reads
//!   it, so the synthesized config pins the bucket the same way a configured
//!   connection does;
//! - the backend is built with no credential source at all — the fallback
//!   never spends the process's ambient AWS identity on a bucket the operator
//!   did not configure — and is shared by every caller of that bucket through
//!   a bounded, single-flight, budgeted [`FallbackCache`];
//! - a cold bucket's region is learned once from an unsigned `HeadBucket`
//!   sent to the layer's default region (S3 stamps `x-amz-bucket-region` on
//!   the answer, including on the `301` it gives the wrong region), unless an
//!   explicit fallback endpoint pins the host, in which case no probe runs;
//!   a region learned wrongly heals from a built backend's own `301`, once,
//!   when that answer names a different region and no endpoint is pinned —
//!   any other `301` leaves the backend in place and reaches the caller as
//!   the `InvalidArgument` it maps to;
//! - the host every probe and every backend would contact is judged by the
//!   instance-metadata predicate before a socket opens;
//! - every mutating slot and `watch_directory` are refused before any wire
//!   activity, because an anonymous fallback grants routability, never
//!   authority.
//!
//! The fallback registers no `Connection`: it has no `ConnectionId`, so the
//! connection-management slots cannot name it, and `list_connections` never
//! lists it. An explicit connection for a bucket outranks the fallback through
//! the route table's first tier the moment it installs, and the layer evicts
//! the fallback's cached backend for that bucket at the same time.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ovstorage_plugin::fallback::{
    fallback_mutation_refused, read_only_capabilities, scheme_fallback_root,
};
use ovstorage_plugin::fallback_cache::FallbackCache;
use ovstorage_plugin::instance_metadata::refuse_instance_metadata;
use ovstorage_plugin::{
    BackendId, CancellationToken, Error, ErrorCode, RangeReadStrategy, ResolvedTarget, Result,
    RootInfo, Url, address, bail_if_cancelled, origin_only,
};
use parking_lot::Mutex;

use crate::backend::{S3Backend, anonymous_capabilities};
use crate::config::{
    FallbackPolicy, S3Config, fallback_config, parse_s3_address, resolve_endpoint,
};
use crate::errors::RegionMismatch;

/// The scheme this fallback serves; the only scheme the layer's kind owns.
pub(crate) const SCHEME: &str = "s3";

/// How long a bucket whose region probe the store did not judge — a transport
/// failure, or a `429` or `5xx` that shed the request — stays negative-cached.
/// Within the window a repeat miss answers from the cache instead of sending
/// another probe at an endpoint that did not answer; after it the next miss
/// probes again.
const REGION_FAILURE_TTL: Duration = Duration::from_secs(60);

/// Upper bound on entries in either region map. Each entry costs one charged
/// mint, so growth is already slow; this keeps a long-lived process from
/// accumulating one entry per bucket name a caller ever invented. When full,
/// an arbitrary entry makes room for a bucket not yet present: the region is
/// re-learned on demand, so dropping one costs at most a probe. An update to
/// a bucket already present grows nothing and so evicts nothing.
const REGION_CACHE_BOUND: usize = 4_096;

/// Per-bucket region knowledge, kept beside the backend cache rather than in
/// it: a bucket's region outlives any one backend (an evicted backend for the
/// same bucket is rebuilt without another probe), and a failed probe is a fact
/// worth remembering briefly even though no backend came of it.
struct RegionCache {
    known: HashMap<String, String>,
    failed: HashMap<String, Instant>,
    /// Entry bound on each map; [`REGION_CACHE_BOUND`] outside tests.
    bound: usize,
}

impl Default for RegionCache {
    fn default() -> Self {
        Self::with_bound(REGION_CACHE_BOUND)
    }
}

impl RegionCache {
    fn with_bound(bound: usize) -> Self {
        Self {
            known: HashMap::new(),
            failed: HashMap::new(),
            bound,
        }
    }

    fn remember(&mut self, bucket: String, region: String) {
        self.failed.remove(&bucket);
        bound(&mut self.known, &bucket, self.bound);
        self.known.insert(bucket, region);
    }

    fn remember_failure(&mut self, bucket: String, now: Instant) {
        bound(&mut self.failed, &bucket, self.bound);
        self.failed.insert(bucket, now);
    }

    /// Unlearn `bucket`'s region, returning what was known: the next miss
    /// probes again.
    fn forget(&mut self, bucket: &str) -> Option<String> {
        self.known.remove(bucket)
    }

    /// How much of [`REGION_FAILURE_TTL`] is left on `bucket`'s failed probe,
    /// or `None` when no failure is remembered or the window has passed.
    fn failure_remaining(&self, bucket: &str, now: Instant) -> Option<Duration> {
        let failed_at = self.failed.get(bucket)?;
        REGION_FAILURE_TTL
            .checked_sub(now.duration_since(*failed_at))
            .filter(|remaining| !remaining.is_zero())
    }
}

/// Make room in `map` for `key` if it is not already present: at capacity an
/// arbitrary entry goes. An existing key is about to be overwritten, which
/// grows nothing, so evicting for it would drop another bucket's region for
/// no gain.
fn bound<V>(map: &mut HashMap<String, V>, key: &str, bound: usize) {
    if map.len() >= bound
        && !map.contains_key(key)
        && let Some(victim) = map.keys().next().cloned()
    {
        map.remove(&victim);
    }
}

/// What the region step produced: the region to build for, and the probe
/// backend when one was built, so a bucket that lives where the probe was sent
/// does not pay for a second client.
struct ResolvedRegion {
    region: String,
    probe: Option<S3Backend>,
}

/// The per-layer state of the anonymous `s3://` fallback. See the module docs.
pub(crate) struct S3SchemeFallback {
    root: RootInfo,
    policy: FallbackPolicy,
    cache: FallbackCache<String, S3Backend>,
    regions: Mutex<RegionCache>,
    /// Test seam: send the region probe even though an endpoint is set, so a
    /// loopback fake can script `HeadBucket`. Production never sets it — an
    /// endpoint pins the host, so a learned region changes nothing on the
    /// wire there.
    #[cfg(test)]
    probe_despite_endpoint: bool,
}

impl S3SchemeFallback {
    /// Build the fallback for a layer of `layer_kind`.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::PermissionDenied`] — the configured fallback endpoint is
    ///   a cloud instance-metadata host.
    /// - [`ErrorCode::InvalidArgument`] — the scheme root cannot be built.
    pub(crate) fn new(
        policy: FallbackPolicy,
        layer_kind: &str,
        icon: Option<Vec<u8>>,
    ) -> Result<Self> {
        refuse_instance_metadata_endpoint(&policy)?;
        // The root advertises what a connection's anonymous shape advertises,
        // lowered to its read side; `supports_list_stream` is raised exactly
        // as `S3Layer::root_info` raises it for every connection root.
        let mut capabilities = read_only_capabilities(anonymous_capabilities());
        capabilities.supports_list_stream = true;
        let mut root = scheme_fallback_root(SCHEME, layer_kind, capabilities, icon)?;
        // The same client with the same ranged reads as a connection root,
        // which `S3Layer::root_info` advertises as `Native`; the shared
        // constructor cannot know the backend and leaves the default, so a
        // consumer reading the strategy off `root_info_for` would otherwise
        // see a less capable answer for a fallback-served address than for a
        // configured one on the same store.
        root.range_read_strategy = RangeReadStrategy::Native;
        Ok(Self {
            root,
            cache: FallbackCache::new(policy.max_backends, policy.mints_per_minute),
            regions: Mutex::new(RegionCache::default()),
            policy,
            #[cfg(test)]
            probe_despite_endpoint: false,
        })
    }

    /// The hidden, marked scheme root the layer publishes for this fallback.
    pub(crate) fn root(&self) -> &RootInfo {
        &self.root
    }

    /// The `s3://{bucket}/` node root of `url`: the address an operator would
    /// configure a connection for.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — `url` has no authority. Both the bare
    ///   scheme root `s3:///` and a hostless address such as `s3:///k` reach
    ///   the fallback as first-tier hits under its own root, and neither names
    ///   a bucket.
    pub(crate) fn node_root(url: &Url) -> Result<Url> {
        let bucket = bucket_of(url)?;
        address::parse(&format!("{SCHEME}://{bucket}/"))
    }

    /// The refusal every mutating slot and `watch_directory` return for an
    /// address reached through this fallback, built before any witness,
    /// buffering, decoding or wire activity.
    pub(crate) fn refuse_mutation(&self, url: &Url) -> Error {
        match Self::node_root(url) {
            Ok(root) => fallback_mutation_refused(SCHEME, &root),
            Err(no_bucket) => no_bucket,
        }
    }

    /// The trace-only backend id of the fallback backend for `bucket`; the
    /// region is appended once it is known.
    pub(crate) fn backend_id(bucket: &str, region: Option<&str>) -> BackendId {
        match region {
            Some(region) => BackendId(format!("{SCHEME}-fallback:{bucket}:{region}")),
            None => BackendId(format!("{SCHEME}-fallback:{bucket}")),
        }
    }

    /// The anonymous backend for the bucket `url` names, built on first touch
    /// and shared afterwards, with the target the backend's operation takes.
    ///
    /// A cached backend that has met a data-path `301` is rebuilt, once, only
    /// when the `301` named a valid region other than the one it was built
    /// for and the layer builds for a learned region (no explicit endpoint);
    /// every other `301` leaves the cached backend in place and the operation
    /// reports it. See [`Self::heal`] for why the rule is that narrow.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — `url` names no bucket, or is not an
    ///   `s3://` address the backend accepts.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before or during the build.
    /// - [`ErrorCode::ResourceExhausted`] — the layer's mint budget is spent,
    ///   or the bucket's region probe failed within [`REGION_FAILURE_TTL`]
    ///   and is not sent again yet; the `next_action` names the wait.
    /// - [`ErrorCode::PermissionDenied`] — the derived host is an
    ///   instance-metadata endpoint.
    /// - [`ErrorCode::NotFound`] — the region probe learned the bucket does
    ///   not exist.
    pub(crate) async fn backend_for(
        &self,
        url: &Url,
        cancel: Option<CancellationToken>,
    ) -> Result<(Arc<S3Backend>, ResolvedTarget)> {
        bail_if_cancelled(&cancel)?;
        let bucket = bucket_of(url)?;
        // Refused here, before the cache is entered, because `get_or_mint`
        // charges the mint budget before it runs the mint. A bucket whose
        // probe failed a moment ago would otherwise spend a charge on a
        // refusal that sends nothing, and a caller repeating that one bucket
        // could spend the whole window's budget on refusals and starve a
        // healthy bucket's first probe.
        if let Some(remaining) = self
            .regions
            .lock()
            .failure_remaining(&bucket, Instant::now())
        {
            return Err(recent_probe_failure(remaining));
        }
        let mut backend = self.get_or_mint(&bucket, cancel.as_ref()).await?;
        // A cached backend whose own request has since answered `301` was
        // built for a region the store says is wrong: the probe was answered
        // without a region and the default was taken, or the bucket moved.
        // The verdict is a fact about that backend and stays set, so this
        // runs on every call for the bucket until the backend is replaced;
        // `heal` evicts and relearns only when the rebuild would be built
        // differently, so the rebuild happens once. Otherwise the cached
        // backend stays and the caller's operation reports the `301` as the
        // non-retryable `InvalidArgument` it maps to.
        if let Some(verdict) = backend.region_mismatch()
            && self.heal(&bucket, &verdict, &backend.config().region)
        {
            backend = self.get_or_mint(&bucket, cancel.as_ref()).await?;
        }
        let target = ResolvedTarget {
            backend_id: Self::backend_id(&bucket, Some(&backend.config().region)),
            resolved_address: url.clone(),
        };
        Ok((backend, target))
    }

    /// Drop the cached backend for the bucket `root` names, if any. Called
    /// when an explicit connection installs for that node: the route table's
    /// first tier answers it from then on, and the fallback's client for it is
    /// only an occupied slot. The bucket's learned region is kept; it is a
    /// fact about the bucket, not about who serves it.
    pub(crate) fn evict_node(&self, root: &Url) {
        if let Ok(bucket) = bucket_of(root) {
            self.cache.evict(&bucket);
        }
    }

    /// The cached backend for `bucket`, minted once if absent.
    async fn get_or_mint(
        &self,
        bucket: &str,
        cancel: Option<&CancellationToken>,
    ) -> Result<Arc<S3Backend>> {
        self.cache
            .get_or_mint(bucket.to_string(), cancel, || {
                self.mint(bucket.to_string(), cancel)
            })
            .await
    }

    /// Act on the `301` the cached backend for `bucket`, built for
    /// `built_region`, has met, and say whether it was evicted so the caller
    /// rebuilds it.
    ///
    /// An eviction costs a mint charge — the layer-wide budget, charged on the
    /// miss before the mint runs — and the verdict on the backend is sticky,
    /// so an eviction whose rebuild came out identical would recur on every
    /// operation against the bucket for the life of the layer, each one a
    /// charge that sends nothing and starves other buckets' first probes. So
    /// the backend is evicted only when the rebuild is built differently:
    ///
    /// - with an explicit endpoint, nothing changes it. The endpoint pins the
    ///   host, and the region reaches the wire only through a SigV4 scope an
    ///   unsigned request has none of; `resolve_region` never reads the region
    ///   map on that path, so recording the named region would change nothing
    ///   either, and it is not recorded;
    /// - a `301` naming the region the backend was built for contradicts
    ///   itself, and nothing better is known;
    /// - a `301` naming a different valid region is the store saying where the
    ///   bucket lives: the region is relearned from it and the backend
    ///   evicted, so the next mint builds for that region without a probe;
    /// - a `301` naming no region says only "not here". The learned region is
    ///   dropped, so a later miss probes afresh rather than trust a verdict
    ///   the store has withdrawn, but the backend stays: a probe that already
    ///   answered without a region would most likely teach the same default,
    ///   and the rebuild earn the same `301`.
    ///
    /// The eviction is by key, so a caller racing this after another has
    /// already healed and rebuilt may evict the fresh backend too; that costs
    /// one extra mint and nothing else, and the cache stays single-flight.
    fn heal(&self, bucket: &str, verdict: &RegionMismatch, built_region: &str) -> bool {
        if !self.probes_region() {
            return false;
        }
        match verdict {
            RegionMismatch::Named(region) if region == built_region => false,
            RegionMismatch::Named(region) => {
                self.cache.evict(&bucket.to_string());
                let previous = {
                    let mut regions = self.regions.lock();
                    let previous = regions.forget(bucket);
                    regions.remember(bucket.to_string(), region.clone());
                    previous
                };
                tracing::info!(
                    target: "ovstorage.fallback",
                    scheme = SCHEME,
                    bucket,
                    previous_region = previous.as_deref().unwrap_or("<none>"),
                    relearned_region = %region,
                    "anonymous fallback backend answered 301; region relearned from the 301"
                );
                true
            }
            RegionMismatch::Unnamed => {
                // Nothing is logged when nothing was known: the region map is
                // bounded and may already have made room at this bucket's
                // expense, and then there is no change to report.
                if let Some(previous) = self.regions.lock().forget(bucket) {
                    tracing::info!(
                        target: "ovstorage.fallback",
                        scheme = SCHEME,
                        bucket,
                        previous_region = %previous,
                        "anonymous fallback backend answered 301; region unlearned; the next \
                         miss probes again"
                    );
                }
                false
            }
        }
    }

    /// Build the backend for `bucket`: learn its region, derive the host,
    /// judge the host, construct the unsigned client.
    async fn mint(&self, bucket: String, cancel: Option<&CancellationToken>) -> Result<S3Backend> {
        let resolved = self.resolve_region(&bucket, cancel).await?;
        let backend = match resolved.probe {
            // The probe was sent to the region the bucket lives in, so the
            // client that sent it is the client to keep.
            Some(probe) if probe.config().region == resolved.region => probe,
            _ => {
                let config = self.config_for(&bucket, &resolved.region)?;
                refuse_instance_metadata(&outbound_origin(&config)?)?;
                S3Backend::fallback(config)?
            }
        };
        tracing::info!(
            target: "ovstorage.fallback",
            scheme = SCHEME,
            root = %origin_only(&backend.config().address_root),
            region = %backend.config().region,
            "anonymous fallback backend built"
        );
        Ok(backend)
    }

    /// The region `bucket` lives in.
    ///
    /// With an explicit endpoint the layer's default region is the answer and
    /// no probe runs: the endpoint pins the host, so the region reaches the
    /// wire only through a SigV4 scope an unsigned request has none of.
    /// Otherwise one unsigned `HeadBucket` is sent to the default region and
    /// the region is read off the answer; a bucket the store judges without
    /// naming a region is taken to live in the default. The answer is cached
    /// per bucket; a `404` is not, because the bucket may be created later and
    /// each retry is bounded by the mint budget anyway; a probe the store did
    /// not judge — a transport failure, or a `429` or `5xx` that shed the
    /// request — is negative-cached for [`REGION_FAILURE_TTL`] and teaches no
    /// region, so a bucket in another region is not pinned to the default by
    /// a store that was merely busy.
    async fn resolve_region(
        &self,
        bucket: &str,
        cancel: Option<&CancellationToken>,
    ) -> Result<ResolvedRegion> {
        let default_region = self.policy.region.clone();
        if !self.probes_region() {
            return Ok(ResolvedRegion {
                region: default_region,
                probe: None,
            });
        }
        {
            let regions = self.regions.lock();
            if let Some(region) = regions.known.get(bucket) {
                return Ok(ResolvedRegion {
                    region: region.clone(),
                    probe: None,
                });
            }
            // `backend_for` refuses this before the mint is charged; this
            // is the same refusal for a caller that entered the mint while
            // another's probe was failing.
            if let Some(remaining) = regions.failure_remaining(bucket, Instant::now()) {
                return Err(recent_probe_failure(remaining));
            }
        }
        let probe_config = self.config_for(bucket, &default_region)?;
        refuse_instance_metadata(&outbound_origin(&probe_config)?)?;
        let probe = S3Backend::fallback(probe_config)?;
        match probe.head_bucket_region(cancel).await {
            Ok(answer) => {
                let region = answer.unwrap_or(default_region);
                self.regions
                    .lock()
                    .remember(bucket.to_string(), region.clone());
                Ok(ResolvedRegion {
                    region,
                    probe: Some(probe),
                })
            }
            // No such bucket: nothing to remember, and nothing to build.
            Err(err) if err.code() == ErrorCode::NotFound => Err(err),
            // The store did not judge the bucket — it did not answer, or shed
            // the request; do not ask it again for a while.
            Err(err) if err.code() != ErrorCode::Cancelled => {
                self.regions
                    .lock()
                    .remember_failure(bucket.to_string(), Instant::now());
                Err(err)
            }
            Err(err) => Err(err),
        }
    }

    fn probes_region(&self) -> bool {
        #[cfg(test)]
        if self.probe_despite_endpoint {
            return true;
        }
        self.policy.endpoint.is_none()
    }

    fn config_for(&self, bucket: &str, region: &str) -> Result<S3Config> {
        fallback_config(
            bucket,
            region,
            self.policy.endpoint_str(),
            self.policy.compatibility,
            self.policy.force_path_style,
        )
    }
}

/// Refuse a fallback endpoint that names a cloud instance-metadata host. Run
/// at `create_backend` whether or not the grant is on, so the mistake is
/// reported where the operator wrote it rather than when a grant later turns
/// the key live.
///
/// # Errors
///
/// - [`ErrorCode::PermissionDenied`] — the endpoint is an instance-metadata
///   host.
pub(crate) fn refuse_instance_metadata_endpoint(policy: &FallbackPolicy) -> Result<()> {
    match &policy.endpoint {
        Some(endpoint) => refuse_instance_metadata(endpoint),
        None => Ok(()),
    }
}

/// The bucket `url` names, canonicalised exactly as the backend reads it.
///
/// A hostless address is refused first and by name: `parse_s3_address` would
/// refuse it too, but its message ("S3 bucket is empty") reads as a bad
/// connection config, and here the caller wrote the address.
fn bucket_of(url: &Url) -> Result<String> {
    if url.host_str().is_none_or(str::is_empty) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("an {SCHEME}:// address names no bucket"),
        ));
    }
    Ok(parse_s3_address(url, "")?.bucket)
}

/// The `scheme://host[:port]/` origin a request for `config` would contact,
/// derived by the same rule that signs it.
fn outbound_origin(config: &S3Config) -> Result<Url> {
    let endpoint = resolve_endpoint(config, "")?;
    Url::parse(&format!("{}://{}/", endpoint.scheme, endpoint.host)).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("the derived S3 endpoint does not parse as a URL: {err}"),
        )
    })
}

/// The refusal for a bucket whose region probe failed within
/// [`REGION_FAILURE_TTL`]. `remaining` is how much of the window is left,
/// rounded up to whole seconds so the hint never says `0 s` while the refusal
/// is still in force.
///
/// `ResourceExhausted`, like the mint-budget refusal and like the `429` or
/// `5xx` the probe most likely met: the store shed the request and the
/// fallback is backing off on the caller's behalf. It stays retryable because
/// the condition does clear by itself and a retry costs nothing — `backend_for`
/// answers it from the negative cache before any mint is charged — so a
/// retry wrapper that replays it burns neither budget nor wire; the hint
/// names the wait so a caller that reads it need not replay at all.
fn recent_probe_failure(remaining: Duration) -> Error {
    let seconds = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
    Error::new(
        ErrorCode::ResourceExhausted,
        format!(
            "the region probe for this bucket failed recently; it is not sent again \
             for another {seconds} s"
        ),
    )
    .with_next_action(format!(
        "retry after ~{seconds} s, or add an explicit connection for the bucket"
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{ErrorKind, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use ovstorage_plugin::StatOptions;

    use super::*;
    use crate::config::CompatibilityProfile;

    /// How the loopback fake answers a `HeadBucket`. A `HeadObject` gets the
    /// next scripted [`HeadObjectAnswer`], or a `200` with fixed metadata once
    /// the script runs out.
    #[derive(Clone, Copy)]
    enum HeadBucketAnswer {
        /// The wrong region: `301` naming where the bucket lives.
        Redirect(&'static str),
        /// The wrong region, said without naming the right one: `301` with no
        /// `x-amz-bucket-region`, as an S3-compatible store may answer.
        RedirectUnnamed,
        /// The right region: `200` naming it.
        Here(&'static str),
        /// No such bucket.
        Missing,
        /// A refusal that names no region: `403` with no
        /// `x-amz-bucket-region`, as an S3-compatible store may answer.
        Forbidden,
        /// The store shed the probe: `503` naming no region.
        Unavailable,
    }

    /// How the loopback fake answers one `HeadObject`.
    #[derive(Clone, Copy)]
    enum HeadObjectAnswer {
        /// `301`, naming the bucket's region when `Some`.
        Redirect(Option<&'static str>),
    }

    struct FakeS3 {
        endpoint: String,
        head_buckets: Arc<AtomicUsize>,
        head_objects: Arc<AtomicUsize>,
    }

    fn read_request(stream: &mut TcpStream) -> Option<String> {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(len) => {
                    request.extend_from_slice(&buf[..len]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    break;
                }
                Err(_) => return None,
            }
        }
        (!request.is_empty()).then(|| String::from_utf8_lossy(&request).to_string())
    }

    /// A path-style fake: `HEAD /{bucket}` is `HeadBucket`, anything deeper is
    /// `HeadObject`. One thread per connection so eight concurrent probes
    /// cannot serialise on the fake itself.
    fn spawn_fake(answer: HeadBucketAnswer) -> FakeS3 {
        spawn_fake_scripted(answer, Vec::new())
    }

    /// [`spawn_fake`] whose `HeadObject` answers follow `objects` in order,
    /// then `200`. The tests that script it send object requests one at a
    /// time, so the order is the order of the requests.
    fn spawn_fake_scripted(answer: HeadBucketAnswer, objects: Vec<HeadObjectAnswer>) -> FakeS3 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
        let endpoint = format!("http://{}", listener.local_addr().expect("local addr"));
        let head_buckets = Arc::new(AtomicUsize::new(0));
        let head_objects = Arc::new(AtomicUsize::new(0));
        let script = Arc::new(Mutex::new(objects.into_iter().collect::<VecDeque<_>>()));
        let (buckets, objects) = (head_buckets.clone(), head_objects.clone());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (buckets, objects, script) = (buckets.clone(), objects.clone(), script.clone());
                thread::spawn(move || {
                    let Some(raw) = read_request(&mut stream) else {
                        return;
                    };
                    let line = raw.lines().next().unwrap_or("");
                    let path = line.split_whitespace().nth(1).unwrap_or("");
                    let is_head_bucket = line.starts_with("HEAD ")
                        && path.trim_end_matches('/').matches('/').count() == 1;
                    let response = if is_head_bucket {
                        buckets.fetch_add(1, Ordering::SeqCst);
                        match answer {
                            HeadBucketAnswer::Redirect(region) => format!(
                                "HTTP/1.1 301 Moved Permanently\r\nConnection: close\r\n\
                                 x-amz-request-id: TESTREQ\r\n\
                                 x-amz-bucket-region: {region}\r\nContent-Length: 0\r\n\r\n"
                            ),
                            HeadBucketAnswer::RedirectUnnamed => {
                                "HTTP/1.1 301 Moved Permanently\r\n\
                                 Connection: close\r\nx-amz-request-id: TESTREQ\r\n\
                                 Content-Length: 0\r\n\r\n"
                                    .to_string()
                            }
                            HeadBucketAnswer::Here(region) => format!(
                                "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                                 x-amz-request-id: TESTREQ\r\n\
                                 x-amz-bucket-region: {region}\r\nContent-Length: 0\r\n\r\n"
                            ),
                            HeadBucketAnswer::Missing => "HTTP/1.1 404 Not Found\r\n\
                                 Connection: close\r\nx-amz-request-id: TESTREQ\r\n\
                                 Content-Length: 0\r\n\r\n"
                                .to_string(),
                            HeadBucketAnswer::Forbidden => "HTTP/1.1 403 Forbidden\r\n\
                                 Connection: close\r\nx-amz-request-id: TESTREQ\r\n\
                                 Content-Length: 0\r\n\r\n"
                                .to_string(),
                            HeadBucketAnswer::Unavailable => "HTTP/1.1 503 Service Unavailable\r\n\
                                 Connection: close\r\nx-amz-request-id: TESTREQ\r\n\
                                 Content-Length: 0\r\n\r\n"
                                .to_string(),
                        }
                    } else {
                        objects.fetch_add(1, Ordering::SeqCst);
                        match script.lock().pop_front() {
                            Some(HeadObjectAnswer::Redirect(Some(region))) => format!(
                                "HTTP/1.1 301 Moved Permanently\r\nConnection: close\r\n\
                                 x-amz-request-id: TESTREQ\r\n\
                                 x-amz-bucket-region: {region}\r\nContent-Length: 0\r\n\r\n"
                            ),
                            Some(HeadObjectAnswer::Redirect(None)) => {
                                "HTTP/1.1 301 Moved Permanently\r\nConnection: close\r\n\
                                 x-amz-request-id: TESTREQ\r\nContent-Length: 0\r\n\r\n"
                                    .to_string()
                            }
                            None => "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                                 x-amz-request-id: TESTREQ\r\nETag: \"9a1f2b\"\r\n\
                                 Last-Modified: Fri, 02 Jan 2026 03:04:05 GMT\r\n\
                                 Content-Length: 2048\r\n\r\n"
                                .to_string(),
                        }
                    };
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                });
            }
        });
        thread::sleep(Duration::from_millis(50));
        FakeS3 {
            endpoint,
            head_buckets,
            head_objects,
        }
    }

    impl FakeS3 {
        fn head_buckets(&self) -> usize {
            self.head_buckets.load(Ordering::SeqCst)
        }

        fn head_objects(&self) -> usize {
            self.head_objects.load(Ordering::SeqCst)
        }
    }

    /// A fallback pointed at the fake, probing as it would with no endpoint.
    fn probing_fallback(endpoint: &str) -> S3SchemeFallback {
        probing_fallback_with_budget(endpoint, 120)
    }

    /// [`probing_fallback`] with `mints_per_minute` set, for the tests that
    /// count charges.
    fn probing_fallback_with_budget(endpoint: &str, mints_per_minute: u32) -> S3SchemeFallback {
        let mut fallback = pinned_fallback_with_budget(endpoint, mints_per_minute);
        fallback.probe_despite_endpoint = true;
        fallback
    }

    /// A fallback pinned at `endpoint` as production would be: the endpoint
    /// skips the probe, and the seam that forces one stays off.
    fn pinned_fallback_with_budget(endpoint: &str, mints_per_minute: u32) -> S3SchemeFallback {
        let policy = FallbackPolicy {
            region: "us-east-1".into(),
            endpoint: Some(Url::parse(endpoint).unwrap()),
            compatibility: CompatibilityProfile::Custom,
            force_path_style: true,
            max_backends: 64,
            mints_per_minute,
        };
        S3SchemeFallback::new(policy, "s3", None).expect("fallback builds")
    }

    fn object(bucket: &str) -> Url {
        address::parse(&format!("s3://{bucket}/assets/teapot.usd")).unwrap()
    }

    async fn stat_through(fallback: &S3SchemeFallback, url: &Url) -> Result<Arc<S3Backend>> {
        let (backend, target) = fallback.backend_for(url, None).await?;
        backend.stat(target, StatOptions::default(), None).await?;
        Ok(backend)
    }

    /// [`stat_through`] that hands the backend back beside the stat's
    /// outcome, so a test can tell a kept backend from a rebuilt one by
    /// pointer even when the stat fails.
    async fn touch(fallback: &S3SchemeFallback, url: &Url) -> (Arc<S3Backend>, Result<()>) {
        let (backend, target) = fallback
            .backend_for(url, None)
            .await
            .expect("the fallback hands out a backend");
        let outcome = backend
            .stat(target, StatOptions::default(), None)
            .await
            .map(|_| ());
        (backend, outcome)
    }

    /// The backend for `url` as the cache holds it, or the refusal a re-mint
    /// would meet; for the tests whose budget is set so that a re-mint is a
    /// refusal, and so distinguishable from a hit.
    async fn cached_or_refused(
        fallback: &S3SchemeFallback,
        url: &Url,
    ) -> (Arc<S3Backend>, ResolvedTarget) {
        fallback
            .backend_for(url, None)
            .await
            .unwrap_or_else(|err| panic!("refused instead of served from the cache: {err}"))
    }

    fn known_region(fallback: &S3SchemeFallback, bucket: &str) -> Option<String> {
        fallback.regions.lock().known.get(bucket).cloned()
    }

    /// One `HeadBucket` to the default region; S3 answers `301` and names the
    /// bucket's region; the backend is built for that region and the object
    /// request that follows reaches the store.
    #[tokio::test]
    async fn a_cold_bucket_learns_its_region_from_the_head_bucket_answer() {
        let fake = spawn_fake(HeadBucketAnswer::Redirect("eu-west-1"));
        let fallback = probing_fallback(&fake.endpoint);

        let backend = stat_through(&fallback, &object("cold"))
            .await
            .expect("the stat succeeds after the region is learned");

        assert_eq!(backend.config().region, "eu-west-1");
        assert_eq!(fake.head_buckets(), 1, "one probe");
        assert_eq!(fake.head_objects(), 1, "then the object request");
        assert_eq!(
            fallback
                .regions
                .lock()
                .known
                .get("cold")
                .map(String::as_str),
            Some("eu-west-1"),
            "the region is cached per bucket"
        );

        // A second touch is a cache hit: no probe, one more object request.
        stat_through(&fallback, &object("cold"))
            .await
            .expect("a warm bucket is served from the cache");
        assert_eq!(fake.head_buckets(), 1);
        assert_eq!(fake.head_objects(), 2);

        // Evicting the backend keeps the region: the rebuild sends no probe.
        fallback.evict_node(&address::parse("s3://cold/").unwrap());
        assert!(!fallback.cache.contains(&"cold".to_string()));
        let rebuilt = stat_through(&fallback, &object("cold"))
            .await
            .expect("the evicted bucket is rebuilt on demand");
        assert_eq!(rebuilt.config().region, "eu-west-1");
        assert_eq!(fake.head_buckets(), 1, "the region was remembered");
    }

    /// A bucket that lives where the probe was sent reuses the probe's client.
    #[tokio::test]
    async fn a_bucket_in_the_default_region_reuses_the_probe_backend() {
        let fake = spawn_fake(HeadBucketAnswer::Here("us-east-1"));
        let fallback = probing_fallback(&fake.endpoint);

        let backend = stat_through(&fallback, &object("home"))
            .await
            .expect("the stat succeeds");

        assert_eq!(backend.config().region, "us-east-1");
        assert_eq!(fake.head_buckets(), 1);
        assert_eq!(fake.head_objects(), 1);
    }

    /// A `404` to the probe is `NotFound`, is not cached in either direction,
    /// and charges nothing but the mint budget: the next touch probes again.
    #[tokio::test]
    async fn a_head_bucket_404_is_not_found_and_not_cached() {
        let fake = spawn_fake(HeadBucketAnswer::Missing);
        let fallback = probing_fallback(&fake.endpoint);

        for attempt in 1..=2 {
            let err = fallback
                .backend_for(&object("gone"), None)
                .await
                .err()
                .expect("a missing bucket is an error");
            assert_eq!(err.code(), ErrorCode::NotFound, "attempt {attempt}: {err}");
            assert!(
                err.message().contains("does not exist"),
                "attempt {attempt}: {}",
                err.message()
            );
            assert_eq!(fake.head_buckets(), attempt, "each attempt probes again");
        }
        let regions = fallback.regions.lock();
        assert!(regions.known.is_empty(), "no region was learned");
        assert!(regions.failed.is_empty(), "a 404 is not a failed probe");
        drop(regions);
        assert!(fallback.cache.is_empty(), "no backend was built");
        assert_eq!(fake.head_objects(), 0, "nothing reached the object");
    }

    /// A `403` that names no region is a verdict about the bucket: it lives
    /// where the probe was sent. The default region is cached for it and the
    /// object request that follows reports the bucket's real answer.
    #[tokio::test]
    async fn a_refused_probe_naming_no_region_means_the_default_region() {
        let fake = spawn_fake(HeadBucketAnswer::Forbidden);
        let fallback = probing_fallback(&fake.endpoint);

        let backend = stat_through(&fallback, &object("guarded"))
            .await
            .expect("the stat runs against the default region");

        assert_eq!(backend.config().region, "us-east-1");
        assert_eq!(fake.head_buckets(), 1, "one probe");
        assert_eq!(fake.head_objects(), 1, "then the object request");
        let regions = fallback.regions.lock();
        assert_eq!(
            regions.known.get("guarded").map(String::as_str),
            Some("us-east-1"),
            "the verdict is cached"
        );
        assert!(regions.failed.is_empty(), "a 403 is not a failed probe");
    }

    /// A probe the store sheds — a `503` naming no region — is a failed probe,
    /// not a verdict. No region is learned, so a bucket that lives elsewhere
    /// is not pinned to the default; the failure is negative-cached, so the
    /// next touch inside the window answers without probing again.
    #[tokio::test]
    async fn a_shed_probe_teaches_no_region_and_is_negative_cached() {
        let fake = spawn_fake(HeadBucketAnswer::Unavailable);
        let fallback = probing_fallback(&fake.endpoint);

        let err = fallback
            .backend_for(&object("busy"), None)
            .await
            .err()
            .expect("a shed probe is an error");
        assert_eq!(err.code(), ErrorCode::ResourceExhausted, "{err}");
        assert_eq!(fake.head_buckets(), 1, "one probe");
        {
            let regions = fallback.regions.lock();
            assert!(regions.known.is_empty(), "a shed probe teaches no region");
            assert!(
                regions.failed.contains_key("busy"),
                "the failure is remembered"
            );
        }
        assert!(fallback.cache.is_empty(), "no backend was built");

        let err = fallback
            .backend_for(&object("busy"), None)
            .await
            .err()
            .expect("the failure is still remembered");
        assert_eq!(err.code(), ErrorCode::ResourceExhausted, "{err}");
        assert!(
            err.message().contains("failed recently"),
            "{}",
            err.message()
        );
        // The hint names the wait: a fresh failure has (almost) the whole
        // window left, and the count is whole seconds rounded up.
        let next_action = err.next_action().expect("a remedy");
        assert!(
            next_action.starts_with("retry after ~60 s")
                || next_action.starts_with("retry after ~59 s"),
            "{next_action}"
        );
        assert!(
            next_action.contains("add an explicit connection"),
            "{next_action}"
        );
        assert_eq!(fake.head_buckets(), 1, "no second probe inside the window");
        assert!(fallback.cache.is_empty(), "still no backend");
        assert_eq!(fake.head_objects(), 0, "nothing reached the object");
    }

    /// A negatively-cached bucket is refused before the mint budget is
    /// charged. With a budget of two, one failed probe spends one charge;
    /// repeats of that bucket spend none, so a different bucket still gets
    /// the second. Before the check moved ahead of the cache, the second
    /// repeat would have taken the last charge and the third been refused as
    /// budget exhaustion, and the healthy bucket refused after it.
    #[tokio::test]
    async fn a_negatively_cached_bucket_spends_no_mint_charge() {
        let fake = spawn_fake(HeadBucketAnswer::Unavailable);
        let fallback = probing_fallback_with_budget(&fake.endpoint, 2);

        let err = fallback
            .backend_for(&object("busy"), None)
            .await
            .err()
            .expect("the shed probe fails the first touch");
        assert_eq!(err.code(), ErrorCode::ResourceExhausted, "{err}");
        assert_eq!(fake.head_buckets(), 1, "one probe, one charge");

        for attempt in 1..=3 {
            let err = fallback
                .backend_for(&object("busy"), None)
                .await
                .err()
                .expect("the failure is remembered");
            assert!(
                err.message()
                    .contains("region probe for this bucket failed"),
                "attempt {attempt} is the negative-cache refusal, not budget \
                 exhaustion: {}",
                err.message()
            );
        }
        assert_eq!(fake.head_buckets(), 1, "no repeat probed");

        // The second and last charge is still there for a bucket the store
        // has not been asked about. The fake answers every bucket `503`, so
        // "healthy" here means a bucket whose probe is *sent*; that it then
        // fails is the store's answer, and the point is that it was charged
        // and sent rather than refused unprobed.
        let err = fallback
            .backend_for(&object("other"), None)
            .await
            .err()
            .expect("the fake sheds this probe too");
        assert_eq!(err.code(), ErrorCode::ResourceExhausted, "{err}");
        assert!(
            !err.message().contains("mint budget"),
            "the healthy bucket was not refused for budget: {}",
            err.message()
        );
        assert_eq!(fake.head_buckets(), 2, "the second bucket's probe was sent");
    }

    /// A `301` probe answer that names no region is a failed probe, not a
    /// verdict that the bucket lives in the default region: a redirect says
    /// the opposite. No region is learned, so the bucket is not pinned to the
    /// wrong region until restart, and the failure is negative-cached.
    #[tokio::test]
    async fn a_redirect_probe_naming_no_region_teaches_no_region() {
        let fake = spawn_fake(HeadBucketAnswer::RedirectUnnamed);
        let fallback = probing_fallback(&fake.endpoint);

        let err = fallback
            .backend_for(&object("moved"), None)
            .await
            .err()
            .expect("an unnamed redirect is an error");
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
        assert!(
            err.message()
                .contains("not served from the configured region"),
            "{}",
            err.message()
        );
        assert!(err.next_action().is_none(), "no region to name");
        assert_eq!(fake.head_buckets(), 1, "one probe");
        let regions = fallback.regions.lock();
        assert!(
            regions.known.is_empty(),
            "the default region was not learned from a redirect"
        );
        assert!(
            regions.failed.contains_key("moved"),
            "the redirect is a failed probe"
        );
        drop(regions);
        assert!(fallback.cache.is_empty(), "no backend was built");
        assert_eq!(fake.head_objects(), 0);
    }

    /// A region learned wrongly heals, once. The probe is refused without a
    /// region, so the default is taken; the object request then answers
    /// `301` naming the real region. The error names the layer key rather
    /// than a connection; the next touch rebuilds for the named region
    /// without another probe and for exactly one more mint charge — the
    /// budget of two here is spent by then, so a third build would be refused
    /// as budget exhaustion — and the touch after that is a hit on the
    /// rebuilt backend, charged nothing.
    #[tokio::test]
    async fn a_data_path_301_naming_a_different_region_relearns_it_once() {
        let fake = spawn_fake_scripted(
            HeadBucketAnswer::Forbidden,
            vec![HeadObjectAnswer::Redirect(Some("eu-west-1"))],
        );
        let fallback = probing_fallback_with_budget(&fake.endpoint, 2);

        let (first, outcome) = touch(&fallback, &object("guarded")).await;
        let err = outcome.expect_err("the object request is redirected");
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
        let next_action = err.next_action().expect("the region to set");
        assert!(
            next_action.contains("anonymous_fallback_region = \"eu-west-1\""),
            "{next_action}"
        );
        assert!(
            next_action.contains("add a connection for s3://guarded/"),
            "{next_action}"
        );
        assert!(
            !next_action.contains("this connection"),
            "there is no connection: {next_action}"
        );
        assert_eq!(first.config().region, "us-east-1");
        assert_eq!(fake.head_buckets(), 1);
        assert_eq!(fake.head_objects(), 1);
        assert_eq!(
            known_region(&fallback, "guarded").as_deref(),
            Some("us-east-1"),
            "the default was learned from the refused probe"
        );

        let (second, outcome) = touch(&fallback, &object("guarded")).await;
        outcome.expect("the rebuilt backend reaches the object");
        assert!(!Arc::ptr_eq(&first, &second), "the backend was rebuilt");
        assert_eq!(second.config().region, "eu-west-1");
        assert_eq!(fake.head_buckets(), 1, "relearned from the 301, not probed");
        assert_eq!(fake.head_objects(), 2);
        assert_eq!(
            known_region(&fallback, "guarded").as_deref(),
            Some("eu-west-1")
        );
        assert!(second.region_mismatch().is_none(), "a fresh backend");

        // The budget is spent, so a third build would be refused; the third
        // touch is a hit on the healed backend instead.
        let (third, target) = cached_or_refused(&fallback, &object("guarded")).await;
        assert!(Arc::ptr_eq(&second, &third), "healed once, not again");
        third
            .stat(target, StatOptions::default(), None)
            .await
            .expect("the healed backend is served from the cache");
        assert_eq!(fake.head_objects(), 3);
        assert_eq!(fallback.cache.len(), 1);
    }

    /// A `301` naming no region says only "not here": the learned region is
    /// dropped, so a later miss probes afresh instead of trusting a verdict
    /// the store has withdrawn, but the backend stays — rebuilding from a
    /// probe that already answered without a region would teach the same
    /// default and earn the same `301` — so no mint is charged; the budget of
    /// two here covers the first build and the rebuild after the explicit
    /// eviction, and nothing else.
    #[tokio::test]
    async fn a_data_path_301_naming_no_region_drops_the_learned_region_and_keeps_the_backend() {
        let fake = spawn_fake_scripted(
            HeadBucketAnswer::Forbidden,
            vec![HeadObjectAnswer::Redirect(None)],
        );
        let fallback = probing_fallback_with_budget(&fake.endpoint, 2);

        let (first, outcome) = touch(&fallback, &object("guarded")).await;
        let err = outcome.expect_err("the object request is redirected");
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
        assert!(err.next_action().is_none(), "no region to name");
        assert_eq!(fake.head_buckets(), 1);
        assert_eq!(
            known_region(&fallback, "guarded").as_deref(),
            Some("us-east-1")
        );

        let (again, target) = cached_or_refused(&fallback, &object("guarded")).await;
        assert!(Arc::ptr_eq(&first, &again), "the backend was kept");
        assert!(
            known_region(&fallback, "guarded").is_none(),
            "the verdict the store withdrew was dropped"
        );
        assert_eq!(fake.head_buckets(), 1, "a kept backend is not probed for");
        // The fake's script is spent, so the kept backend's request now lands.
        again
            .stat(target, StatOptions::default(), None)
            .await
            .expect("the kept backend reaches the object");
        assert_eq!(fake.head_objects(), 2);

        // Once the backend is gone for any other reason, the next miss probes
        // again rather than building for the region the store contradicted.
        fallback.evict_node(&address::parse("s3://guarded/").unwrap());
        let (rebuilt, outcome) = touch(&fallback, &object("guarded")).await;
        outcome.expect("the rebuilt backend reaches the object");
        assert!(!Arc::ptr_eq(&first, &rebuilt), "the eviction was honoured");
        assert_eq!(
            fake.head_buckets(),
            2,
            "the region was unlearned, so it was probed"
        );
        assert_eq!(rebuilt.config().region, "us-east-1");
    }

    /// A `301` naming the region the backend was already built for
    /// contradicts itself and teaches nothing better: the backend stays, no
    /// mint is charged — the budget of one here would refuse a second build —
    /// and every operation reports the `301`.
    #[tokio::test]
    async fn a_data_path_301_naming_the_built_region_changes_nothing() {
        let fake = spawn_fake_scripted(
            HeadBucketAnswer::Here("us-east-1"),
            vec![HeadObjectAnswer::Redirect(Some("us-east-1")); 2],
        );
        let fallback = probing_fallback_with_budget(&fake.endpoint, 1);

        let (first, outcome) = touch(&fallback, &object("home")).await;
        let err = outcome.expect_err("the object request is redirected");
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
        assert_eq!(first.config().region, "us-east-1");

        let (again, target) = cached_or_refused(&fallback, &object("home")).await;
        assert!(Arc::ptr_eq(&first, &again), "the backend was not rebuilt");
        let err = again
            .stat(target, StatOptions::default(), None)
            .await
            .expect_err("the store keeps answering 301");
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
        assert_eq!(fake.head_buckets(), 1, "no second probe");
        assert_eq!(fake.head_objects(), 2);
        assert_eq!(
            known_region(&fallback, "home").as_deref(),
            Some("us-east-1"),
            "the region named is the region known; nothing to relearn"
        );
    }

    /// With an explicit endpoint the region does not reach the wire, so a
    /// data-path `301` can heal nothing: the cached backend stays, no mint is
    /// charged — the budget of one here would refuse a second build — and
    /// every operation reports the `301` as `InvalidArgument`. The seam that
    /// forces a probe stays off, so this is the production shape of a pinned
    /// endpoint, the one the probing fixture cannot reach.
    #[tokio::test]
    async fn a_data_path_301_with_a_pinned_endpoint_keeps_the_backend_and_charges_nothing() {
        let fake = spawn_fake_scripted(
            HeadBucketAnswer::Forbidden,
            vec![HeadObjectAnswer::Redirect(Some("eu-west-1")); 3],
        );
        let fallback = pinned_fallback_with_budget(&fake.endpoint, 1);

        let (first, outcome) = touch(&fallback, &object("pinned")).await;
        let err = outcome.expect_err("the object request is redirected");
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
        assert_eq!(first.config().region, "us-east-1");
        assert_eq!(
            fake.head_buckets(),
            0,
            "the endpoint pins the host; no probe"
        );

        for attempt in 2..=3 {
            let (again, target) = cached_or_refused(&fallback, &object("pinned")).await;
            assert!(
                Arc::ptr_eq(&first, &again),
                "attempt {attempt}: the backend was not rebuilt"
            );
            let err = again
                .stat(target, StatOptions::default(), None)
                .await
                .expect_err("the store keeps answering 301");
            assert_eq!(
                err.code(),
                ErrorCode::InvalidArgument,
                "attempt {attempt}: {err}"
            );
        }
        assert_eq!(fake.head_objects(), 3, "every operation reached the store");
        assert_eq!(fallback.cache.len(), 1);
        assert!(
            fallback.regions.lock().known.is_empty(),
            "a region no request would use is not recorded"
        );
    }

    /// A full region map evicts only to make room for a bucket it does not
    /// hold. Re-learning a region, or refreshing a failure timestamp, for a
    /// bucket already present grows nothing and must not cost another bucket
    /// its entry.
    #[test]
    fn a_full_region_cache_evicts_only_for_a_new_bucket() {
        let mut regions = RegionCache::with_bound(2);
        let now = Instant::now();
        regions.remember("a".into(), "us-east-1".into());
        regions.remember("b".into(), "eu-west-1".into());
        regions.remember_failure("c".into(), now);
        regions.remember_failure("d".into(), now);

        regions.remember("a".into(), "ap-south-1".into());
        assert_eq!(regions.known.len(), 2, "an update evicts nothing");
        assert_eq!(
            regions.known.get("a").map(String::as_str),
            Some("ap-south-1")
        );
        assert_eq!(
            regions.known.get("b").map(String::as_str),
            Some("eu-west-1")
        );

        regions.remember_failure("c".into(), now + Duration::from_secs(1));
        assert_eq!(regions.failed.len(), 2, "a refresh evicts nothing");
        assert!(regions.failed.contains_key("c") && regions.failed.contains_key("d"));

        regions.remember("e".into(), "us-west-2".into());
        assert_eq!(regions.known.len(), 2, "a new bucket makes room for itself");
        assert!(regions.known.contains_key("e"));
        regions.remember_failure("f".into(), now);
        assert_eq!(regions.failed.len(), 2);
        assert!(regions.failed.contains_key("f"));
    }

    /// The fallback root advertises the same ranged-read strategy as the
    /// connection roots for the same store: it is the same client.
    #[test]
    fn the_fallback_root_advertises_native_ranged_reads() {
        let fallback = probing_fallback("http://127.0.0.1:1");
        assert_eq!(
            fallback.root().range_read_strategy,
            RangeReadStrategy::Native
        );
    }

    /// Eight concurrent misses on one cold bucket send one probe and build one
    /// backend; every caller shares it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_misses_on_one_bucket_probe_once() {
        let fake = spawn_fake(HeadBucketAnswer::Redirect("eu-west-1"));
        let fallback = Arc::new(probing_fallback(&fake.endpoint));

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let fallback = fallback.clone();
            tasks.push(tokio::spawn(async move {
                stat_through(&fallback, &object("shared")).await
            }));
        }
        let mut backends = Vec::new();
        for task in tasks {
            backends.push(task.await.expect("task").expect("each stat succeeds"));
        }

        assert_eq!(fake.head_buckets(), 1, "one probe for eight callers");
        assert_eq!(fake.head_objects(), 8, "eight object requests");
        assert!(
            backends
                .iter()
                .all(|backend| Arc::ptr_eq(backend, &backends[0])),
            "every caller shares one backend"
        );
        assert_eq!(fallback.cache.len(), 1);
    }

    /// The bare scheme root and a hostless address both reach the fallback as
    /// first-tier hits under its own root, and neither names a bucket.
    #[tokio::test]
    async fn a_hostless_address_names_no_bucket() {
        let fallback = probing_fallback("http://127.0.0.1:1");
        for spelling in ["s3:///", "s3:///k", "s3://"] {
            let url = address::parse(spelling).unwrap();
            let err = fallback
                .backend_for(&url, None)
                .await
                .err()
                .expect("no bucket to build for");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{spelling}: {err}");
            assert_eq!(
                err.message(),
                "an s3:// address names no bucket",
                "{spelling}"
            );
            let refusal = fallback.refuse_mutation(&url);
            assert_eq!(refusal.code(), ErrorCode::InvalidArgument, "{spelling}");
        }
        assert!(fallback.cache.is_empty());
    }

    /// The mutation refusal names the node root the operator would configure,
    /// never the caller's path.
    #[test]
    fn a_mutation_refusal_names_the_bucket_root() {
        let fallback = probing_fallback("http://127.0.0.1:1");
        let err = fallback.refuse_mutation(&object("bkt"));
        assert_eq!(err.code(), ErrorCode::Unsupported);
        assert!(err.message().contains("anonymous s3:// fallback"), "{err}");
        let next_action = err.next_action().expect("a remedy");
        assert!(next_action.contains("s3://bkt/"), "{next_action}");
        assert!(!next_action.contains("teapot"), "{next_action}");
    }

    /// A dotted bucket is addressed path-style however the policy is set: its
    /// virtual-hosted host is outside AWS's wildcard certificate.
    #[test]
    fn a_dotted_bucket_is_addressed_path_style() {
        let policy = FallbackPolicy {
            region: "us-east-1".into(),
            endpoint: None,
            compatibility: CompatibilityProfile::Aws,
            force_path_style: false,
            max_backends: 64,
            mints_per_minute: 120,
        };
        let fallback = S3SchemeFallback::new(policy, "s3", None).unwrap();
        let plain = fallback.config_for("plain", "us-east-1").unwrap();
        assert!(!plain.use_path_style());
        assert_eq!(
            outbound_origin(&plain).unwrap().as_str(),
            "https://plain.s3.us-east-1.amazonaws.com/"
        );
        let dotted = fallback.config_for("my.bucket", "eu-west-1").unwrap();
        assert!(dotted.use_path_style());
        assert_eq!(
            outbound_origin(&dotted).unwrap().as_str(),
            "https://s3.eu-west-1.amazonaws.com/"
        );
    }

    /// The instance-metadata refusal fires on the configured endpoint whether
    /// the grant is on or not, and before any client is built.
    #[test]
    fn an_instance_metadata_endpoint_is_refused_before_any_client_is_built() {
        let policy = FallbackPolicy {
            region: "us-east-1".into(),
            endpoint: Some(Url::parse("http://169.254.169.254/").unwrap()),
            compatibility: CompatibilityProfile::Custom,
            force_path_style: true,
            max_backends: 64,
            mints_per_minute: 120,
        };
        let err = refuse_instance_metadata_endpoint(&policy).expect_err("refused");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.message().contains("instance-metadata"), "{err}");
        let err = S3SchemeFallback::new(policy, "s3", None)
            .err()
            .expect("the constructor refuses it too");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
    }
}
