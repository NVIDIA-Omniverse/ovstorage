// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, single-flight cache for the anonymous scheme-fallback backends.
//!
//! A granted scheme root turns every unrouted `s3://bucket/…`,
//! `gs://bucket/…` or `azure://account/container/…` address into a request for
//! a backend the layer has to build on demand: an unsigned client plus, for
//! S3, one region probe on the wire. The names in those addresses come from
//! callers, so without a bound a caller could make the layer build one client
//! and send one probe per distinct name it invents. This cache is what bounds
//! that work:
//!
//! - **one build per distinct key** — a hit hands back the cached `Arc<V>`; a
//!   miss builds once and every later caller shares the result;
//! - **bounded entries** — at most `max_entries` values stay resident, evicted
//!   least-recently-used, so the resident set cannot grow with the number of
//!   distinct names a caller tries;
//! - **bounded mints per minute** — at most `mints_per_minute` builds start in
//!   any sliding one-minute window; past that a miss answers
//!   [`ErrorCode::ResourceExhausted`] (retryable) instead of building.
//!
//! Misses are **single-flight per key**: two concurrent misses on one bucket
//! must not each build a client and each send the region probe. The first
//! caller claims the key and mints; the others wait for that mint to settle
//! and then re-read the cache. A mint that fails, panics or is cancelled
//! releases its claim on the way out, so waiters are never parked behind a key
//! nobody is minting: the next one through mints itself.
//!
//! The cache knows nothing about routes. When an explicit connection installs
//! for a node this cache serves, the route table's first tier answers that
//! node from then on and the cached fallback entry is only an occupied slot;
//! removing it is the caller's job via [`FallbackCache::evict`].

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::cancel::race_cancel;
use crate::{Error, ErrorCode, Result};

/// The sliding window the mint budget counts over.
/// cbindgen:ignore
const MINT_WINDOW: Duration = Duration::from_secs(60);

/// A bounded LRU of `Arc<V>` keyed by `K`, with single-flight minting and a
/// sliding-window mint budget. See the module docs for what it bounds and why.
///
/// Every method takes `&self`; the cache is meant to live in an `Arc` shared
/// by every task of a layer. No lock is held across an await, so the futures
/// it returns are `Send` whenever the caller's mint future is.
pub struct FallbackCache<K, V> {
    max_entries: usize,
    mints_per_minute: u32,
    state: Mutex<State<K, V>>,
}

struct Entry<V> {
    value: Arc<V>,
    /// Logical time of the last hit or insert; the smallest value marks the
    /// least recently used entry.
    last_used: u64,
}

struct State<K, V> {
    entries: HashMap<K, Entry<V>>,
    /// Monotonic counter behind `Entry::last_used`.
    clock: u64,
    /// One claim per key with a mint in flight. Waiters hold a receiver on the
    /// claim's channel; dropping the sender is what wakes them, and it happens
    /// on every exit from the mint, including unwinding.
    inflight: HashMap<K, watch::Sender<()>>,
    /// Start times of the mints charged inside the current window, oldest
    /// first. Unused when the budget is unlimited, so it cannot grow.
    mints: VecDeque<Instant>,
}

impl<K, V> State<K, V>
where
    K: Hash + Eq + Clone,
{
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            clock: 0,
            inflight: HashMap::new(),
            mints: VecDeque::new(),
        }
    }

    /// Return the cached value and mark it most recently used.
    fn touch(&mut self, key: &K) -> Option<Arc<V>> {
        let entry = self.entries.get_mut(key)?;
        self.clock += 1;
        entry.last_used = self.clock;
        Some(Arc::clone(&entry.value))
    }

    /// Insert as most recently used, then drop least-recently-used entries
    /// until the bound holds.
    fn insert(&mut self, key: K, value: Arc<V>, max_entries: usize) {
        self.clock += 1;
        let last_used = self.clock;
        self.entries.insert(key, Entry { value, last_used });
        while self.entries.len() > max_entries {
            let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&victim);
        }
    }

    /// Charge one mint to the sliding window, or refuse when the window is
    /// full. `mints_per_minute == 0` means unlimited and records nothing.
    fn charge_mint(&mut self, now: Instant, mints_per_minute: u32) -> bool {
        if mints_per_minute == 0 {
            return true;
        }
        while self
            .mints
            .front()
            .is_some_and(|started| now.duration_since(*started) >= MINT_WINDOW)
        {
            self.mints.pop_front();
        }
        if self.mints.len() >= mints_per_minute as usize {
            return false;
        }
        self.mints.push_back(now);
        true
    }
}

/// What a miss found under the lock.
enum Miss {
    /// Another caller holds the claim; wait for its channel to close.
    Wait(watch::Receiver<()>),
    /// This caller holds the claim and mints.
    Mint,
}

/// The in-flight claim on one key. Dropping it, on any path out of the mint,
/// removes the marker and closes the channel the waiters hold, so a failed,
/// cancelled or panicking mint never leaves them parked.
struct Claim<'a, K, V>
where
    K: Hash + Eq + Clone,
{
    cache: &'a FallbackCache<K, V>,
    key: Option<K>,
}

impl<K, V> Claim<'_, K, V>
where
    K: Hash + Eq + Clone,
{
    /// Publish the minted value and release the claim in one lock acquisition,
    /// so a waiter woken by the channel closing always finds the value.
    fn complete(mut self, value: Arc<V>) {
        let Some(key) = self.key.take() else {
            return;
        };
        let sender = {
            let mut state = self.cache.state.lock();
            let sender = state.inflight.remove(&key);
            state.insert(key, value, self.cache.max_entries);
            sender
        };
        // Wake waiters after the lock is released so they can take it.
        drop(sender);
    }
}

impl<K, V> Drop for Claim<'_, K, V>
where
    K: Hash + Eq + Clone,
{
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            let sender = self.cache.state.lock().inflight.remove(&key);
            drop(sender);
        }
    }
}

impl<K, V> FallbackCache<K, V>
where
    K: Hash + Eq + Clone + Send + 'static,
    V: Send + Sync + 'static,
{
    /// Build an empty cache holding at most `max_entries` values (a bound of
    /// `0` is clamped to `1`) and starting at most `mints_per_minute` mints per
    /// sliding minute (`0` means unlimited).
    pub fn new(max_entries: usize, mints_per_minute: u32) -> Self {
        Self {
            max_entries: max_entries.max(1),
            mints_per_minute,
            state: Mutex::new(State::new()),
        }
    }

    /// The resident bound the cache was built with.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// The mint budget the cache was built with; `0` means unlimited.
    pub fn mints_per_minute(&self) -> u32 {
        self.mints_per_minute
    }

    /// Return the cached value for `key`, marking it most recently used.
    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        self.state.lock().touch(key)
    }

    /// Return the cached value for `key`, minting it once if absent.
    ///
    /// A hit returns immediately. On a miss, if another caller is minting this
    /// key the call waits for that mint to settle and re-reads the cache,
    /// minting itself only if the other mint produced nothing. Otherwise the
    /// call charges the mint budget, runs `mint` under [`race_cancel`], stores
    /// the result as most recently used and evicts least-recently-used entries
    /// past the bound.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::ResourceExhausted`] — the sliding one-minute mint budget
    ///   is spent; retryable, and hits keep answering.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired while waiting or minting.
    ///   A cancelled minter releases its claim; the key is not poisoned.
    /// - Any error `mint` returns. The failure is not cached; the next caller
    ///   mints again (and is charged again).
    pub async fn get_or_mint<F, Fut>(
        &self,
        key: K,
        cancel: Option<&CancellationToken>,
        mint: F,
    ) -> Result<Arc<V>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V>>,
    {
        loop {
            let miss = {
                let mut state = self.state.lock();
                if let Some(value) = state.touch(&key) {
                    return Ok(value);
                }
                match state.inflight.get(&key) {
                    Some(sender) => Miss::Wait(sender.subscribe()),
                    None => {
                        if !state.charge_mint(Instant::now(), self.mints_per_minute) {
                            drop(state);
                            tracing::debug!(
                                mints_per_minute = self.mints_per_minute,
                                "anonymous fallback mint budget exhausted"
                            );
                            return Err(budget_exhausted());
                        }
                        let (sender, _initial) = watch::channel(());
                        state.inflight.insert(key.clone(), sender);
                        Miss::Mint
                    }
                }
            };
            match miss {
                Miss::Wait(mut settled) => {
                    // Nothing is ever sent on the channel: `changed` completes
                    // only when the claim drops its sender, and it completes
                    // even when that drop happened before this await began.
                    race_cancel(cancel, async {
                        let _ = settled.changed().await;
                        Ok(())
                    })
                    .await?;
                }
                Miss::Mint => {
                    let claim = Claim {
                        cache: self,
                        key: Some(key),
                    };
                    let value = Arc::new(race_cancel(cancel, mint()).await?);
                    claim.complete(Arc::clone(&value));
                    return Ok(value);
                }
            }
        }
    }

    /// Remove `key`, returning what it held. Callers do this when an explicit
    /// connection installs for the node the entry served. A mint in flight for
    /// the key at that moment still lands afterwards; the route table's first
    /// tier answers the node regardless, so that entry is only a slot that
    /// ages out.
    pub fn evict(&self, key: &K) -> Option<Arc<V>> {
        self.state
            .lock()
            .entries
            .remove(key)
            .map(|entry| entry.value)
    }

    /// Number of resident entries.
    pub fn len(&self) -> usize {
        self.state.lock().entries.len()
    }

    /// Whether no entry is resident.
    pub fn is_empty(&self) -> bool {
        self.state.lock().entries.is_empty()
    }

    /// Whether `key` is resident. Does not refresh its LRU position.
    pub fn contains(&self, key: &K) -> bool {
        self.state.lock().entries.contains_key(key)
    }

    #[cfg(test)]
    fn is_minting(&self, key: &K) -> bool {
        self.state.lock().inflight.contains_key(key)
    }
}

impl<K, V> fmt::Debug for FallbackCache<K, V>
where
    K: Hash + Eq + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock();
        f.debug_struct("FallbackCache")
            .field("max_entries", &self.max_entries)
            .field("mints_per_minute", &self.mints_per_minute)
            .field("len", &state.entries.len())
            .field("in_flight", &state.inflight.len())
            .finish()
    }
}

fn budget_exhausted() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "anonymous fallback mint budget exhausted; retry later",
    )
    .with_next_action(
        "retry after the one-minute window slides, or add an explicit connection for the address",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tokio::sync::Notify;

    use super::*;

    async fn until<F: Fn() -> bool>(condition: F) {
        for _ in 0..1_000 {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("condition did not hold within the wait budget");
    }

    #[tokio::test]
    async fn a_miss_mints_once_and_a_hit_returns_the_same_arc() {
        let cache = FallbackCache::<&str, u32>::new(4, 0);
        let mints = AtomicUsize::new(0);

        let first = cache
            .get_or_mint("bucket", None, || async {
                mints.fetch_add(1, Ordering::SeqCst);
                Ok(7)
            })
            .await
            .unwrap();
        let second = cache
            .get_or_mint("bucket", None, || async {
                mints.fetch_add(1, Ordering::SeqCst);
                Ok(8)
            })
            .await
            .unwrap();

        assert_eq!(*first, 7);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(mints.load(Ordering::SeqCst), 1);
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());
        assert!(cache.contains(&"bucket"));
        assert!(
            cache
                .get(&"bucket")
                .is_some_and(|v| Arc::ptr_eq(&v, &first))
        );
        assert!(cache.get(&"other").is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_misses_on_one_key_mint_once() {
        let cache = Arc::new(FallbackCache::<String, u32>::new(8, 0));
        let mints = Arc::new(AtomicUsize::new(0));

        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let mints = Arc::clone(&mints);
                tokio::spawn(async move {
                    cache
                        .get_or_mint("bucket".to_string(), None, || async move {
                            mints.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            Ok(7)
                        })
                        .await
                })
            })
            .collect();

        let mut shared: Option<Arc<u32>> = None;
        for task in tasks {
            let value = task.await.unwrap().unwrap();
            assert_eq!(*value, 7);
            match &shared {
                None => shared = Some(value),
                Some(first) => assert!(Arc::ptr_eq(first, &value)),
            }
        }

        assert_eq!(mints.load(Ordering::SeqCst), 1);
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_minting(&"bucket".to_string()));
    }

    #[tokio::test]
    async fn a_failed_mint_lets_the_next_caller_mint() {
        let cache = FallbackCache::<&str, u32>::new(4, 0);

        let err = cache
            .get_or_mint("bucket", None, || async {
                Err(Error::new(ErrorCode::Transient, "region probe timed out"))
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Transient);
        assert!(!cache.contains(&"bucket"));
        assert!(!cache.is_minting(&"bucket"));

        let value = cache
            .get_or_mint("bucket", None, || async { Ok(1) })
            .await
            .unwrap();
        assert_eq!(*value, 1);
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn a_waiter_behind_a_failed_mint_mints_itself() {
        let cache = Arc::new(FallbackCache::<String, u32>::new(4, 0));
        let gate = Arc::new(Notify::new());
        let key = "bucket".to_string();

        let failing = {
            let cache = Arc::clone(&cache);
            let gate = Arc::clone(&gate);
            let key = key.clone();
            tokio::spawn(async move {
                cache
                    .get_or_mint(key, None, || async move {
                        gate.notified().await;
                        Err(Error::new(ErrorCode::Transient, "probe failed"))
                    })
                    .await
            })
        };
        until(|| cache.is_minting(&key)).await;

        let waiter_minted = Arc::new(AtomicBool::new(false));
        let waiter = {
            let cache = Arc::clone(&cache);
            let key = key.clone();
            let waiter_minted = Arc::clone(&waiter_minted);
            tokio::spawn(async move {
                cache
                    .get_or_mint(key, None, || async move {
                        waiter_minted.store(true, Ordering::SeqCst);
                        Ok(2)
                    })
                    .await
            })
        };
        // The waiter must be parked, not minting, while the claim is held.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter_minted.load(Ordering::SeqCst));
        assert!(!waiter.is_finished());

        gate.notify_one();
        assert_eq!(
            failing.await.unwrap().unwrap_err().code(),
            ErrorCode::Transient
        );
        let value = waiter.await.unwrap().unwrap();
        assert_eq!(*value, 2);
        assert!(waiter_minted.load(Ordering::SeqCst));
        assert!(!cache.is_minting(&key));
    }

    #[tokio::test]
    async fn entries_beyond_the_bound_are_evicted_least_recently_used() {
        let cache = FallbackCache::<&str, u32>::new(2, 0);

        cache
            .get_or_mint("a", None, || async { Ok(1) })
            .await
            .unwrap();
        cache
            .get_or_mint("b", None, || async { Ok(2) })
            .await
            .unwrap();
        // Touching `a` makes `b` the least recently used entry.
        assert!(cache.get(&"a").is_some());
        cache
            .get_or_mint("c", None, || async { Ok(3) })
            .await
            .unwrap();

        assert_eq!(cache.len(), 2);
        assert!(cache.contains(&"a"));
        assert!(!cache.contains(&"b"));
        assert!(cache.contains(&"c"));

        // A hit through `get_or_mint` refreshes order too: `c` outlives `a`.
        cache
            .get_or_mint("c", None, || async { Ok(33) })
            .await
            .unwrap();
        cache
            .get_or_mint("d", None, || async { Ok(4) })
            .await
            .unwrap();

        assert_eq!(cache.len(), 2);
        assert!(!cache.contains(&"a"));
        assert!(cache.contains(&"c"));
        assert!(cache.contains(&"d"));
    }

    #[tokio::test]
    async fn a_zero_bound_is_clamped_to_one() {
        let cache = FallbackCache::<&str, u32>::new(0, 0);
        assert_eq!(cache.max_entries(), 1);

        cache
            .get_or_mint("a", None, || async { Ok(1) })
            .await
            .unwrap();
        cache
            .get_or_mint("b", None, || async { Ok(2) })
            .await
            .unwrap();

        assert_eq!(cache.len(), 1);
        assert!(!cache.contains(&"a"));
        assert!(cache.contains(&"b"));
    }

    #[tokio::test]
    async fn the_mint_budget_answers_resource_exhausted() {
        let cache = FallbackCache::<&str, u32>::new(4, 1);
        assert_eq!(cache.mints_per_minute(), 1);

        let first = cache
            .get_or_mint("a", None, || async { Ok(1) })
            .await
            .unwrap();

        let err = cache
            .get_or_mint("b", None, || async { Ok(2) })
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceExhausted);
        assert_eq!(
            err.message(),
            "anonymous fallback mint budget exhausted; retry later"
        );
        assert!(err.next_action().is_some());
        assert!(err.code().retryable());
        assert!(!cache.contains(&"b"));
        assert!(!cache.is_minting(&"b"));

        // A hit is not a mint: it answers while the budget is spent.
        let minted = AtomicBool::new(false);
        let hit = cache
            .get_or_mint("a", None, || async {
                minted.store(true, Ordering::SeqCst);
                Ok(99)
            })
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&first, &hit));
        assert!(!minted.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_zero_budget_is_unlimited() {
        let cache = FallbackCache::<u32, u32>::new(8, 0);
        for key in 0..500 {
            cache
                .get_or_mint(key, None, || async move { Ok(key) })
                .await
                .unwrap();
        }
        assert_eq!(cache.len(), 8);
        assert!(cache.state.lock().mints.is_empty());
    }

    #[test]
    fn the_mint_window_slides_after_one_minute() {
        let mut state = State::<&str, u32>::new();
        let start = Instant::now();

        assert!(state.charge_mint(start, 2));
        assert!(state.charge_mint(start + Duration::from_secs(30), 2));
        assert!(!state.charge_mint(start + Duration::from_secs(59), 2));
        // The first mint leaves the window exactly one minute after it started.
        assert!(state.charge_mint(start + Duration::from_secs(60), 2));
        assert!(!state.charge_mint(start + Duration::from_secs(61), 2));
        // The second mint leaves at ninety seconds.
        assert!(state.charge_mint(start + Duration::from_secs(90), 2));
        assert_eq!(state.mints.len(), 2);
    }

    #[tokio::test]
    async fn a_cancelled_caller_gets_cancelled_and_does_not_poison_the_key() {
        let cache = Arc::new(FallbackCache::<String, u32>::new(4, 0));
        let token = CancellationToken::new();
        let key = "bucket".to_string();

        let minter = {
            let cache = Arc::clone(&cache);
            let token = token.clone();
            let key = key.clone();
            tokio::spawn(async move {
                cache
                    .get_or_mint(key, Some(&token), std::future::pending::<Result<u32>>)
                    .await
            })
        };
        until(|| cache.is_minting(&key)).await;

        token.cancel();
        let err = minter.await.unwrap().unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
        assert!(!cache.is_minting(&key));
        assert!(!cache.contains(&key));

        let value = cache
            .get_or_mint(key.clone(), None, || async { Ok(5) })
            .await
            .unwrap();
        assert_eq!(*value, 5);
        assert!(cache.contains(&key));
    }

    #[tokio::test]
    async fn a_cancelled_waiter_leaves_the_minter_to_land() {
        let cache = Arc::new(FallbackCache::<String, u32>::new(4, 0));
        let gate = Arc::new(Notify::new());
        let key = "bucket".to_string();

        let minter = {
            let cache = Arc::clone(&cache);
            let gate = Arc::clone(&gate);
            let key = key.clone();
            tokio::spawn(async move {
                cache
                    .get_or_mint(key, None, || async move {
                        gate.notified().await;
                        Ok(1)
                    })
                    .await
            })
        };
        until(|| cache.is_minting(&key)).await;

        let token = CancellationToken::new();
        let waiter = {
            let cache = Arc::clone(&cache);
            let token = token.clone();
            let key = key.clone();
            tokio::spawn(async move {
                cache
                    .get_or_mint(key, Some(&token), || async { Ok(2) })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());

        token.cancel();
        assert_eq!(
            waiter.await.unwrap().unwrap_err().code(),
            ErrorCode::Cancelled
        );
        // The waiter's cancellation did not disturb the minter's claim.
        assert!(cache.is_minting(&key));

        gate.notify_one();
        let value = minter.await.unwrap().unwrap();
        assert_eq!(*value, 1);
        assert!(cache.contains(&key));
    }

    #[tokio::test]
    async fn evict_removes_the_entry() {
        let cache = FallbackCache::<&str, u32>::new(4, 0);
        cache
            .get_or_mint("a", None, || async { Ok(1) })
            .await
            .unwrap();
        cache
            .get_or_mint("b", None, || async { Ok(2) })
            .await
            .unwrap();

        let removed = cache.evict(&"a");
        assert!(removed.is_some_and(|v| *v == 1));
        assert!(!cache.contains(&"a"));
        assert!(cache.contains(&"b"));
        assert_eq!(cache.len(), 1);
        assert!(cache.evict(&"a").is_none());

        // The next caller for the evicted key mints afresh.
        let mints = AtomicUsize::new(0);
        let value = cache
            .get_or_mint("a", None, || async {
                mints.fetch_add(1, Ordering::SeqCst);
                Ok(10)
            })
            .await
            .unwrap();
        assert_eq!(*value, 10);
        assert_eq!(mints.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_cache_and_its_mint_future_are_send() {
        fn assert_send<T: Send>(_: &T) {}
        fn assert_sync<T: Sync>(_: &T) {}

        let cache = FallbackCache::<String, Vec<u8>>::new(1, 0);
        assert_send(&cache);
        assert_sync(&cache);

        let token = CancellationToken::new();
        let fut = cache.get_or_mint("k".to_string(), Some(&token), || async { Ok(Vec::new()) });
        assert_send(&fut);
        drop(fut);

        let rendered = format!("{cache:?}");
        assert!(rendered.contains("FallbackCache"));
        assert!(rendered.contains("max_entries: 1"));
    }
}
