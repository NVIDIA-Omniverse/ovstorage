// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use ovstorage::WatchDirectoryCursor;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::TrySendError;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;

/// Per-watcher queue depth; on overflow the broker injects a single
/// `ChangeEvent::Lapsed` so the caller re-lists and resumes from "now".
pub(crate) const DEFAULT_WATCH_DIRECTORY_QUEUE_DEPTH: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct WatchDirectoryKey {
    prefix: String,
    recursive: bool,
    include_metadata_changes: bool,
    since: Option<Vec<u8>>,
    poll_interval: Duration,
}

impl WatchDirectoryKey {
    pub(crate) fn new(prefix: &Url, opts: &WatchDirectoryOptions) -> Self {
        Self {
            prefix: prefix.to_string(),
            recursive: opts.recursive,
            include_metadata_changes: opts.include_metadata_changes,
            since: opts.since.as_ref().map(|cursor| cursor.0.clone()),
            poll_interval: opts.poll_interval,
        }
    }
}

/// Per-key coalescing cell: exactly one task drives the upstream
/// `library.watch_directory(...)`; the rest await the same result.
type FanoutCell = Arc<OnceCell<Arc<WatchDirectoryFanout>>>;

pub(crate) struct WatchDirectoryHub {
    streams: Mutex<HashMap<WatchDirectoryKey, FanoutCell>>,
    /// Hub-wide shutdown. Every fanout's `cancel` is a child of this,
    /// so `cancel_all()` cascades to every live AND future fanout —
    /// including a subscriber whose `get_or_try_init` closure is still
    /// racing the cancel. A child token of an already-cancelled parent
    /// is born cancelled, so the upstream returns `None` on its next
    /// poll and the fanout dies without ever blocking tonic drain.
    shutdown: CancellationToken,
}

impl Default for WatchDirectoryHub {
    fn default() -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
            shutdown: CancellationToken::new(),
        }
    }
}

impl WatchDirectoryHub {
    /// Cancel every live AND future fanout. Called from the gRPC
    /// server's shutdown path before tonic begins draining in-flight
    /// RPCs — otherwise streaming watch RPCs would keep the `Broker`
    /// alive (and `Drop for WatchDirectoryHub` would never run).
    pub(crate) fn cancel_all(&self) {
        self.shutdown.cancel();
    }
}

impl Drop for WatchDirectoryHub {
    fn drop(&mut self) {
        // Same shape as `cancel_all`, in case Drop fires without a prior
        // explicit shutdown path (direct-mode broker, panic teardown).
        self.cancel_all();
    }
}

pub(crate) const DEFAULT_WATCH_DIRECTORY_FANOUT_LIMIT: usize = 256;

/// How many times the hub retries `watch_directory` when it lands on a
/// fanout that was cancelled between `get_or_try_init` returning and
/// our register call. Three is generous: each iteration evicts the
/// dead cell, so consecutive failures imply concurrent shutdown +
/// resubscribe pressure that this loop isn't trying to solve.
const MAX_SUBSCRIBE_RETRIES: u8 = 3;

impl WatchDirectoryHub {
    pub(crate) async fn watch_directory(
        &self,
        library: Arc<Library>,
        prefix: Url,
        opts: WatchDirectoryOptions,
    ) -> ovstorage::Result<WatcherReceiver> {
        let span = tracing::info_span!(
            "broker.watch",
            op = "watch_directory",
            object.address = %crate::trace::RedactedUrl(&prefix),
        );
        let _guard = span.enter();
        let key = WatchDirectoryKey::new(&prefix, &opts);
        // Bounded retry. Three races can hand us a cancelled fanout:
        // (1) a sibling subscriber's last-consumer drop fires the
        //     fanout's cancel between our `get_or_try_init` returning
        //     and `fanout.watch_directory()` registering;
        // (2) hub shutdown cascades via `self.shutdown` to a fanout
        //     mid-init;
        // (3) the eviction check above misses a fanout that was alive
        //     when checked but cancelled before we got the cell.
        // In all cases `fanout.watch_directory()` returns `Cancelled`;
        // we evict and try once more.
        for _ in 0..MAX_SUBSCRIBE_RETRIES {
            let cell = {
                let mut streams = self.lock_streams()?;
                if let Some(existing) = streams.get(&key) {
                    if let Some(fanout) = existing.get() {
                        if !fanout.is_alive() || fanout.cancel.is_cancelled() {
                            streams.remove(&key);
                        }
                    }
                }
                streams
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(OnceCell::new()))
                    .clone()
            };
            let prefix_for_init = prefix.clone();
            let opts_for_init = opts.clone();
            let library_for_init = library.clone();
            let fanout = cell
                .get_or_try_init(|| async {
                    // Child of the hub-wide shutdown so this fanout
                    // dies when the hub does — including the case
                    // where shutdown fires DURING this init: a child
                    // of an already-cancelled parent is born
                    // cancelled, the upstream returns `None` on its
                    // next poll, and the fanout never blocks tonic
                    // drain.
                    let cancel = self.shutdown.child_token();
                    let stream = library_for_init
                        .watch_directory(prefix_for_init, opts_for_init, Some(cancel.clone()))
                        .await?;
                    Ok::<_, Error>(WatchDirectoryFanout::new_with_stream(stream, cancel))
                })
                .await
                .inspect_err(|_: &Error| {
                    if let Ok(mut streams) = self.streams.lock()
                        && let Some(entry) = streams.get(&key)
                        && entry.get().is_none()
                    {
                        streams.remove(&key);
                    }
                })?;
            match fanout.watch_directory() {
                Ok(receiver) => return Ok(receiver),
                Err(error) if error.code() == ErrorCode::Cancelled => {
                    if let Ok(mut streams) = self.streams.lock()
                        && let Some(entry) = streams.get(&key)
                        && let Some(stored) = entry.get()
                        && Arc::ptr_eq(stored, fanout)
                    {
                        streams.remove(&key);
                    }
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(Error::new(
            ErrorCode::Cancelled,
            "broker watch_directory: subscribe retries exhausted",
        ))
    }

    fn lock_streams(
        &self,
    ) -> ovstorage::Result<std::sync::MutexGuard<'_, HashMap<WatchDirectoryKey, FanoutCell>>> {
        self.streams.lock().map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "broker watch_directory hub lock is poisoned",
            )
        })
    }
}

/// Per-watcher entry: the bounded sender plus a sticky "lapsed pending"
/// flag. While the flag is set, the dispatcher skips fan-out events for
/// this watcher and instead retries a single `ChangeEvent::Lapsed`; once
/// that lands, normal forwarding resumes from "now."
struct WatcherEntry {
    sender: mpsc::SyncSender<ovstorage::Result<ChangeEvent>>,
    lapsed_pending: bool,
}

pub(crate) struct WatchDirectoryFanout {
    alive: AtomicBool,
    watchers: Mutex<Vec<WatcherEntry>>,
    /// Holds the upstream `ChangeStream` between `new_with_stream` and the
    /// first `watch_directory()` call. The first subscriber takes ownership,
    /// registers its own `WatcherEntry`, and spawns the fan-out thread —
    /// atomically with respect to the upstream pull. Late subscribers see
    /// only events that arrive after they register, which is normal pub/sub.
    /// Without this, the fan-out thread would race the registration window:
    /// a synchronous-emit upstream like the conformance test plugin can
    /// publish event 0 to an empty subscriber list before the hub's caller
    /// finishes registering. That event is then lost forever.
    pending_stream: Mutex<Option<ChangeStream>>,
    /// Signals the upstream backend's keep-alive iterator to stop emitting
    /// when the last downstream watcher disconnects. The dispatcher's
    /// `for event in stream` loop only detects watcher disconnects on the
    /// next event; with a keep-alive upstream that may never arrive,
    /// `WatcherReceiver::drop` fires this token directly the moment
    /// `active_consumers` transitions to zero.
    cancel: CancellationToken,
    /// Live downstream `WatcherReceiver` count, incremented at
    /// `watch_directory()` and decremented in the receiver's Drop. The
    /// `watchers` Vec only prunes disconnected entries on the next try_send
    /// — useless for keep-alive upstreams that never emit again — so the
    /// last-consumer detection happens via this atomic instead.
    active_consumers: AtomicUsize,
}

impl WatchDirectoryFanout {
    pub(crate) fn new_with_stream(stream: ChangeStream, cancel: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            alive: AtomicBool::new(true),
            watchers: Mutex::new(Vec::new()),
            pending_stream: Mutex::new(Some(stream)),
            cancel,
            active_consumers: AtomicUsize::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            alive: AtomicBool::new(true),
            watchers: Mutex::new(Vec::new()),
            pending_stream: Mutex::new(None),
            cancel: CancellationToken::new(),
            active_consumers: AtomicUsize::new(0),
        })
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    pub(crate) fn watch_directory(self: &Arc<Self>) -> ovstorage::Result<WatcherReceiver> {
        let (sender, receiver) = mpsc::sync_channel(DEFAULT_WATCH_DIRECTORY_QUEUE_DEPTH);
        // Take the pending upstream stream (if any) and the watcher slot
        // under one critical section so an upstream-pull thread can't fire
        // before the first WatcherEntry exists.
        let pending_stream = {
            let mut watchers = self.watchers.lock().map_err(|_| {
                Error::new(
                    ErrorCode::Internal,
                    "broker watch_directory fan-out lock is poisoned",
                )
            })?;
            // Refuse to attach to a cancelled fanout. The cancel
            // check under the watchers lock makes the hub's
            // race-prone path observable: if cancel fired between the
            // hub's `get_or_try_init` returning and our acquiring the
            // lock here, the hub catches the `Aborted` and retries
            // with a fresh fanout.
            if self.cancel.is_cancelled() {
                return Err(Error::new(
                    ErrorCode::Cancelled,
                    "broker watch_directory: fanout cancelled before subscriber registered",
                ));
            }
            if watchers.len() >= DEFAULT_WATCH_DIRECTORY_FANOUT_LIMIT {
                tracing::warn!(
                    target: "ovstorage.broker.watch",
                    fanout_limit = DEFAULT_WATCH_DIRECTORY_FANOUT_LIMIT,
                    "watch_directory fanout cap reached; rejecting new subscriber"
                );
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    format!(
                        "broker watch_directory fan-out limit of {DEFAULT_WATCH_DIRECTORY_FANOUT_LIMIT} downstream watchers reached"
                    ),
                ));
            }
            watchers.push(WatcherEntry {
                sender,
                lapsed_pending: false,
            });
            // Increment `active_consumers` UNDER the watchers lock so
            // a concurrent `WatcherReceiver::drop` (also taking this
            // lock) can't see the count before we've contributed and
            // mistakenly fire the cancel as the "last" consumer.
            self.active_consumers.fetch_add(1, Ordering::SeqCst);
            // Drop the watchers guard before reaching for `pending_stream`
            // to avoid a circular lock order with `run()`'s pulls.
            drop(watchers);
            self.pending_stream
                .lock()
                .map_err(|_| {
                    Error::new(
                        ErrorCode::Internal,
                        "broker watch_directory pending-stream lock is poisoned",
                    )
                })?
                .take()
        };
        if let Some(stream) = pending_stream {
            let fanout = self.clone();
            std::thread::Builder::new()
                .name("ovs-watch-fan".into())
                .spawn(move || fanout.run(stream))
                .expect("failed to spawn thread");
        }
        Ok(WatcherReceiver {
            inner: receiver,
            fanout: Arc::downgrade(self),
        })
    }

    pub(crate) fn run(self: Arc<Self>, stream: ChangeStream) {
        // Track the most recent observed upstream cursor so the synthetic
        // Lapsed-on-overflow carries a meaningful resume point.
        let mut latest_cursor = WatchDirectoryCursor::default();
        for event in stream {
            if let Ok(observed) = &event {
                latest_cursor = observed_cursor(observed);
            }
            let lapsed_payload = Ok(ChangeEvent::Lapsed {
                since: None,
                cursor: latest_cursor.clone(),
            });
            let alive_after = {
                let Ok(mut watchers) = self.watchers.lock() else {
                    break;
                };
                watchers.retain_mut(|watcher| {
                    if watcher.lapsed_pending {
                        // Slow watcher: keep retrying the Lapsed and
                        // skip the live event so the queue can drain.
                        match watcher.sender.try_send(lapsed_payload.clone()) {
                            Ok(()) => {
                                watcher.lapsed_pending = false;
                                true
                            }
                            Err(TrySendError::Full(_)) => true,
                            Err(TrySendError::Disconnected(_)) => false,
                        }
                    } else {
                        match watcher.sender.try_send(event.clone()) {
                            Ok(()) => true,
                            Err(TrySendError::Full(_)) => {
                                tracing::warn!(
                                    target: "ovstorage.broker.watch",
                                    queue_depth = DEFAULT_WATCH_DIRECTORY_QUEUE_DEPTH,
                                    "watch_directory queue overflow; injecting Lapsed and resuming",
                                );
                                watcher.lapsed_pending = true;
                                true
                            }
                            Err(TrySendError::Disconnected(_)) => false,
                        }
                    }
                });
                !watchers.is_empty()
            };

            if !alive_after {
                break;
            }
        }
        // Upstream ended: any watcher still flagged lapsed_pending hasn't
        // received its Lapsed marker. Retry within a short deadline so the
        // caller observes the gap signal before the receiver disconnects.
        self.flush_pending_lapsed(&latest_cursor, Duration::from_millis(100));
        self.alive.store(false, Ordering::SeqCst);
        // Drop every `SyncSender` so any late subscriber (one that
        // registered between cancel firing and `run()` exiting) sees
        // `recv()` return `Disconnected` instead of blocking forever on
        // a fanout whose dispatcher has already exited.
        if let Ok(mut watchers) = self.watchers.lock() {
            watchers.clear();
        }
    }

    fn flush_pending_lapsed(&self, cursor: &WatchDirectoryCursor, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let Ok(mut watchers) = self.watchers.lock() else {
                return;
            };
            let mut any_pending = false;
            watchers.retain_mut(|watcher| {
                if !watcher.lapsed_pending {
                    return true;
                }
                let payload = Ok(ChangeEvent::Lapsed {
                    since: None,
                    cursor: cursor.clone(),
                });
                match watcher.sender.try_send(payload) {
                    Ok(()) => {
                        watcher.lapsed_pending = false;
                        true
                    }
                    Err(TrySendError::Full(_)) => {
                        any_pending = true;
                        true
                    }
                    Err(TrySendError::Disconnected(_)) => false,
                }
            });
            drop(watchers);
            if !any_pending || std::time::Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn observed_cursor(event: &ChangeEvent) -> WatchDirectoryCursor {
    match event {
        ChangeEvent::Object { cursor, .. } | ChangeEvent::Lapsed { cursor, .. } => cursor.clone(),
    }
}

/// Wraps a fanout's `mpsc::Receiver`. The Drop hook decrements
/// `active_consumers` and fires the fanout's cancel token directly
/// when it was the last consumer — an event-driven last-watcher
/// detector, no polling thread required.
///
/// Holds a `Weak` rather than `Arc` so the receiver doesn't keep the
/// fanout (and its WatcherEntry's `SyncSender`) alive after the
/// fanout's other strong refs (hub + dispatcher) have dropped —
/// otherwise the receiver's `recv()` would never see end-of-stream.
pub(crate) struct WatcherReceiver {
    inner: mpsc::Receiver<ovstorage::Result<ChangeEvent>>,
    fanout: std::sync::Weak<WatchDirectoryFanout>,
}

impl Iterator for WatcherReceiver {
    type Item = ovstorage::Result<ChangeEvent>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.recv().ok()
    }
}

impl Drop for WatcherReceiver {
    fn drop(&mut self) {
        let Some(fanout) = self.fanout.upgrade() else {
            return;
        };
        // Serialize with `fanout.watch_directory`'s register-and-
        // increment: both `fetch_add` (subscribe) and our `fetch_sub`
        // happen under the watchers lock, so a concurrent subscriber
        // that hasn't yet incremented can't make us mistakenly fire
        // the cancel as the "last" consumer. The lock isn't load-
        // bearing for the atomic — fetch_sub is atomic on its own —
        // it's an ordering barrier with the subscribe path.
        let _guard = fanout.watchers.lock().ok();
        if fanout.active_consumers.fetch_sub(1, Ordering::SeqCst) == 1 {
            fanout.cancel.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage::ChangeKind;

    /// Slow-watcher overflow surfaces a `ChangeEvent::Lapsed` (not a
    /// terminal error) so the caller knows to re-list and resume from
    /// "now." The watcher stays alive and keeps receiving events.
    #[test]
    fn fanout_emits_lapsed_when_consumer_overflows_and_stays_alive() {
        let fanout = WatchDirectoryFanout::new();
        let receiver = fanout.watch_directory().unwrap();

        // Push past queue depth so try_send definitely hits Full. Use
        // `Object` events so any `Lapsed` we observe was injected by
        // the broker on overflow (not echoed from upstream).
        let event_count = DEFAULT_WATCH_DIRECTORY_QUEUE_DEPTH + 20;
        let stream: ChangeStream = Box::new((0..event_count).map(|i| {
            Ok(ChangeEvent::Object {
                address: Url::parse(&format!("test://demo/o-{i}")).unwrap(),
                kind: ChangeKind::Created,
                etag: None,
                version: None,
                size: None,
                mtime: None,
                at: SystemTime::UNIX_EPOCH,
                cursor: WatchDirectoryCursor(vec![(i & 0xff) as u8]),
            })
        }));

        // Test thread is the slow consumer.
        let dispatcher = std::thread::Builder::new()
            .name("ovs-test-watch".into())
            .spawn(move || fanout.run(stream))
            .expect("failed to spawn thread");

        let mut received = Vec::new();
        for msg in receiver {
            received.push(msg);
            // Slow drain so the queue stays near full and the dispatcher
            // marks this watcher as lapsed; not so slow that the post-
            // upstream Lapsed-flush window (100ms) is exhausted.
            std::thread::sleep(Duration::from_millis(1));
        }

        dispatcher.join().expect("dispatcher panicked");

        // No terminal errors: every message is `Ok(...)` and the
        // dispatcher only closes when the upstream stream ends.
        let errors: Vec<_> = received.iter().filter_map(|m| m.as_ref().err()).collect();
        assert!(
            errors.is_empty(),
            "expected zero terminal errors, got {}: {received:?}",
            errors.len(),
        );
        let lapsed_count = received
            .iter()
            .filter(|m| matches!(m, Ok(ChangeEvent::Lapsed { .. })))
            .count();
        assert!(
            lapsed_count >= 1,
            "expected at least one Lapsed marker after overflow, got {lapsed_count}",
        );
    }
}
