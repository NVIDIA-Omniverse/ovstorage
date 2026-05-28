// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::BackendChangeEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeliveryId(u64);

#[derive(Debug, Clone, Copy)]
pub enum AckToken {
    Provider(DeliveryId),
    Noop,
}

pub struct SubscriptionEvent {
    pub event: BackendChangeEvent,
    pub ack_token: AckToken,
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

struct PendingEntry<H> {
    handle: H,
    remaining: usize,
    deadline: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingDecrement<H> {
    Pending,
    Ready { handle: H, deadline: Instant },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingDeliveryId {
    pub id: DeliveryId,
}

pub struct Pending<H> {
    map: Mutex<HashMap<DeliveryId, PendingEntry<H>>>,
    next_id: AtomicU64,
}

impl<H> Pending<H> {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }

    pub fn insert(&self, handle: H, remaining: usize, deadline: Instant) -> DeliveryId {
        assert!(
            remaining > 0,
            "pending delivery must have at least one event"
        );
        let id = DeliveryId(self.next_id.fetch_add(1, Ordering::Relaxed));
        self.map.lock().unwrap().insert(
            id,
            PendingEntry {
                handle,
                remaining,
                deadline,
            },
        );
        id
    }

    pub fn decrement(&self, id: DeliveryId) -> Result<PendingDecrement<H>, MissingDeliveryId> {
        let mut m = self.map.lock().unwrap();
        let entry = m.get_mut(&id).ok_or(MissingDeliveryId { id })?;
        entry.remaining -= 1;
        if entry.remaining == 0 {
            let e = m.remove(&id).unwrap();
            Ok(PendingDecrement::Ready {
                handle: e.handle,
                deadline: e.deadline,
            })
        } else {
            Ok(PendingDecrement::Pending)
        }
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<H> Default for Pending<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    struct ManualClock {
        base: Instant,
        offset_nanos: AtomicU64,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                offset_nanos: AtomicU64::new(0),
            }
        }

        fn advance(&self, by: Duration) {
            self.offset_nanos
                .fetch_add(by.as_nanos() as u64, Ordering::Relaxed);
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            self.base + Duration::from_nanos(self.offset_nanos.load(Ordering::Relaxed))
        }
    }

    #[test]
    fn pending_decrement_returns_handle_only_when_remaining_hits_zero() {
        let p: Pending<&str> = Pending::new();
        let deadline = Instant::now();
        let id = p.insert("handle", 2, deadline);
        assert_eq!(p.decrement(id), Ok(PendingDecrement::Pending));
        assert_eq!(
            p.decrement(id),
            Ok(PendingDecrement::Ready {
                handle: "handle",
                deadline
            })
        );
        assert!(p.is_empty());
    }

    #[test]
    fn pending_decrement_reports_missing_delivery_id() {
        let p: Pending<&str> = Pending::new();
        let missing = DeliveryId(42);
        assert_eq!(p.decrement(missing), Err(MissingDeliveryId { id: missing }));
    }

    #[test]
    #[should_panic(expected = "pending delivery must have at least one event")]
    fn pending_insert_rejects_zero_remaining() {
        let p: Pending<&str> = Pending::new();
        p.insert("handle", 0, Instant::now());
    }

    #[test]
    fn pending_delivery_ids_are_unique() {
        let p: Pending<()> = Pending::new();
        let now = Instant::now();
        let a = p.insert((), 1, now);
        let b = p.insert((), 1, now);
        assert_ne!(a, b);
    }

    #[test]
    fn test_clock_advances() {
        let c = ManualClock::new();
        let t0 = c.now();
        c.advance(Duration::from_secs(10));
        let t1 = c.now();
        assert!(t1 >= t0 + Duration::from_secs(10));
    }
}
