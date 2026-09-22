// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The client and the fake hub, driven against each other.
//!
//! Every test here uses only the crate's public API: a `HubCacheClient`
//! talking to a `FakeHub` over a real loopback socket. That pairing is what
//! later layers test against, so these tests pin the behaviour both halves
//! have to agree on — write-once keys, pending-write visibility, the
//! extension trap, and lease accounting that settles at zero.

#![cfg(feature = "fake-hub")]

use std::sync::Arc;
use std::time::Duration;

use ovstorage_hub_client::fake::{EntryState, FakeHub, FakeHubConfig, HubCounters, HubInterface};
use ovstorage_hub_client::{HubCacheClient, HubClientConfig, HubError, ReadOpen, WriteOpen};
use tempfile::TempDir;

/// A client with deadlines long enough that only a real stall trips them and
/// no cooldown, so a test that restarts the hub re-dials on its next call.
fn client_for(hub: &FakeHub) -> HubCacheClient {
    HubCacheClient::new(HubClientConfig {
        endpoint: hub.endpoint(),
        client_name: "fake-hub-test".to_string(),
        timeout: Duration::from_secs(5),
        cooldown: Duration::ZERO,
    })
}

async fn hub() -> (TempDir, FakeHub) {
    let dir = TempDir::new().expect("a temporary directory");
    let hub = FakeHub::start(dir.path()).await;
    (dir, hub)
}

/// Fills `key` with `bytes` through the client, the way a cache layer does.
async fn fill(client: &HubCacheClient, key: &str, extension: &str, bytes: &[u8]) {
    let WriteOpen::Opened(handle) = client
        .open_for_write(key, "test", extension, bytes.len() as u64)
        .await
        .expect("the open succeeds")
    else {
        panic!("a fresh key opens for writing");
    };
    std::fs::write(handle.path(), bytes).expect("the reserved file is writable");
    handle.commit().await.expect("the commit succeeds");
}

#[tokio::test]
async fn a_fill_is_readable_by_another_client() {
    let (_dir, hub) = hub().await;
    let writer = client_for(&hub);
    let reader = client_for(&hub);

    fill(&writer, "key", "bin", b"cached bytes").await;

    assert_eq!(
        hub.entry("key"),
        Some(EntryState::Committed {
            size: 12,
            extension: "bin".to_string()
        })
    );
    // A second client, and therefore a second connection: the store is
    // shared, not per-connection.
    let ReadOpen::Opened(handle) = reader
        .open_for_read("key", "test", "bin")
        .await
        .expect("the open succeeds")
    else {
        panic!("a committed key opens for reading");
    };
    assert!(handle.path().exists());
    assert_eq!(
        std::fs::read(handle.path()).expect("the cached file is readable"),
        b"cached bytes"
    );
    handle.close().await.expect("the close succeeds");

    assert_eq!(
        hub.committed_bytes("key").as_deref(),
        Some(&b"cached bytes"[..])
    );
    hub.wait_for_open_handles(0).await;
}

#[tokio::test]
async fn a_committed_key_is_write_once() {
    let (_dir, hub) = hub().await;
    let client = client_for(&hub);
    fill(&client, "key", "bin", b"first").await;

    let second = client
        .open_for_write("key", "test", "bin", 6)
        .await
        .expect("the open succeeds");

    assert!(matches!(second, WriteOpen::AlreadyExists), "{second:?}");
    // The refused fill leaves the stored bytes alone.
    assert_eq!(hub.committed_bytes("key").as_deref(), Some(&b"first"[..]));
}

#[tokio::test]
async fn a_key_being_filled_is_pending_for_readers_and_writers_alike() {
    let (_dir, hub) = hub().await;
    let writer = client_for(&hub);
    let reader = client_for(&hub);
    let WriteOpen::Opened(handle) = writer
        .open_for_write("key", "test", "bin", 5)
        .await
        .expect("the open succeeds")
    else {
        panic!("a fresh key opens for writing");
    };

    let pending = reader
        .open_for_read("key", "test", "bin")
        .await
        .expect("the open succeeds");
    let taken = reader
        .open_for_write("key", "test", "bin", 5)
        .await
        .expect("the open succeeds");

    assert!(matches!(pending, ReadOpen::PendingWrite), "{pending:?}");
    assert!(matches!(taken, WriteOpen::PendingWrite), "{taken:?}");
    assert_eq!(hub.entry("key"), Some(EntryState::PendingWrite));

    // Once the fill commits, the same read is a hit.
    std::fs::write(handle.path(), b"bytes").expect("the reserved file is writable");
    handle.commit().await.expect("the commit succeeds");
    let hit = reader
        .open_for_read("key", "test", "bin")
        .await
        .expect("the open succeeds");
    assert!(matches!(hit, ReadOpen::Opened(_)), "{hit:?}");
}

#[tokio::test]
async fn an_aborted_fill_leaves_nothing_behind() {
    let (_dir, hub) = hub().await;
    let client = client_for(&hub);
    let WriteOpen::Opened(handle) = client
        .open_for_write("key", "test", "bin", 5)
        .await
        .expect("the open succeeds")
    else {
        panic!("a fresh key opens for writing");
    };
    let path = handle.path().to_path_buf();
    std::fs::write(&path, b"half ").expect("the reserved file is writable");

    handle.abort().await;

    assert_eq!(hub.entry("key"), None);
    assert!(!path.exists(), "the aborted file is deleted");
    let after = client
        .open_for_read("key", "test", "bin")
        .await
        .expect("the open succeeds");
    assert!(matches!(after, ReadOpen::NotCached), "{after:?}");
    hub.wait_for_open_handles(0).await;
}

#[tokio::test]
async fn reading_with_the_wrong_extension_succeeds_with_a_path_that_does_not_exist() {
    let (_dir, hub) = hub().await;
    let seeded = hub.seed_entry("key", "usd", b"stage bytes");
    let client = client_for(&hub);

    let ReadOpen::Opened(trapped) = client
        .open_for_read("key", "test", "bin")
        .await
        .expect("the open succeeds")
    else {
        panic!("the extension is not part of the key, so the open succeeds");
    };

    // The extension names the file, not the entry: this is a success whose
    // path was never written.
    assert!(!trapped.path().exists());
    assert_ne!(trapped.path(), seeded);
    trapped.close().await.expect("the close succeeds");

    // The extension it was written with resolves to the real file.
    let ReadOpen::Opened(hit) = client
        .open_for_read("key", "test", "usd")
        .await
        .expect("the open succeeds")
    else {
        panic!("a committed key opens for reading");
    };
    assert_eq!(hit.path(), seeded);
    assert_eq!(
        std::fs::read(hit.path()).expect("the cached file is readable"),
        b"stage bytes"
    );
    hit.close().await.expect("the close succeeds");
    hub.wait_for_open_handles(0).await;
}

#[tokio::test]
async fn an_entry_larger_than_the_hub_accepts_is_refused() {
    let dir = TempDir::new().expect("a temporary directory");
    let hub = FakeHub::start_with(
        dir.path(),
        FakeHubConfig {
            max_entry_size: Some(16),
            ..FakeHubConfig::default()
        },
    )
    .await;
    let client = client_for(&hub);

    let refused = client
        .open_for_write("big", "test", "bin", 17)
        .await
        .expect("the open succeeds");
    let accepted = client
        .open_for_write("small", "test", "bin", 16)
        .await
        .expect("the open succeeds");

    assert!(matches!(refused, WriteOpen::TooLarge), "{refused:?}");
    assert!(matches!(accepted, WriteOpen::Opened(_)), "{accepted:?}");
    // A refused reservation creates nothing.
    assert_eq!(hub.entry("big"), None);
}

#[tokio::test]
async fn a_hub_without_the_cache_aside_interface_fails_the_handshake() {
    let dir = TempDir::new().expect("a temporary directory");
    let hub = FakeHub::start_with(
        dir.path(),
        FakeHubConfig {
            interfaces: vec![HubInterface::BlockCache],
            ..FakeHubConfig::default()
        },
    )
    .await;
    let client = client_for(&hub);

    let err = client
        .open_for_read("key", "test", "bin")
        .await
        .expect_err("the handshake rejects the hub");

    assert!(matches!(err, HubError::Protocol(_)), "{err}");
    assert_eq!(hub.counters(), HubCounters::default());
}

#[tokio::test]
async fn a_dropped_client_releases_every_lease_it_held() {
    let (_dir, hub) = hub().await;
    hub.seed_entry("warm", "bin", b"warm bytes");
    let client = client_for(&hub);
    let ReadOpen::Opened(read) = client
        .open_for_read("warm", "test", "bin")
        .await
        .expect("the open succeeds")
    else {
        panic!("a committed key opens for reading");
    };
    let WriteOpen::Opened(write) = client
        .open_for_write("cold", "test", "bin", 5)
        .await
        .expect("the open succeeds")
    else {
        panic!("a fresh key opens for writing");
    };
    assert_eq!(hub.open_handles(), 2);

    drop(read);
    drop(write);
    drop(client);

    // The releases are enqueued rather than awaited, so the assertion waits
    // for the hub to settle instead of assuming it already has.
    hub.wait_for_open_handles(0).await;
    // The uncommitted fill is discarded; the entry that was only read
    // survives.
    assert_eq!(hub.entry("cold"), None);
    assert!(matches!(
        hub.entry("warm"),
        Some(EntryState::Committed { .. })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_clients_race_to_fill_one_key_and_exactly_one_wins() {
    let (_dir, hub) = hub().await;
    let hub = Arc::new(hub);

    let racers: Vec<_> = (0..8)
        .map(|_| {
            let hub = hub.clone();
            tokio::spawn(async move {
                let client = client_for(&hub);
                let outcome = client
                    .open_for_write("contested", "test", "bin", 5)
                    .await
                    .expect("the open succeeds");
                let won = match outcome {
                    WriteOpen::Opened(handle) => {
                        std::fs::write(handle.path(), b"bytes")
                            .expect("the reserved file is writable");
                        handle.commit().await.expect("the commit succeeds");
                        true
                    }
                    // A loser's answer names the winner's progress:
                    // pending-write while the fill is still open,
                    // already-exists once it has committed. Both mean
                    // "someone else owns this key".
                    WriteOpen::AlreadyExists | WriteOpen::PendingWrite => false,
                    WriteOpen::TooLarge => panic!("the hub has no size limit"),
                };
                client.quiesce().await;
                won
            })
        })
        .collect();

    let mut winners = 0;
    for racer in racers {
        if racer.await.expect("the task completes") {
            winners += 1;
        }
    }

    assert_eq!(winners, 1, "hub keys are write-once");
    assert_eq!(
        hub.entry("contested"),
        Some(EntryState::Committed {
            size: 5,
            extension: "bin".to_string()
        })
    );
    assert_eq!(
        hub.committed_bytes("contested").as_deref(),
        Some(&b"bytes"[..])
    );
    hub.wait_for_open_handles(0).await;
    assert_eq!(hub.counters().opens_for_write, 8);
}

#[tokio::test]
async fn a_sequence_of_operations_leaves_no_leases_behind() {
    let (_dir, hub) = hub().await;
    let client = client_for(&hub);

    fill(&client, "one", "bin", b"one").await;
    fill(&client, "two", "bin", b"two").await;
    let ReadOpen::Opened(handle) = client
        .open_for_read("one", "test", "bin")
        .await
        .expect("the open succeeds")
    else {
        panic!("a committed key opens for reading");
    };
    drop(handle);
    assert!(matches!(
        client
            .open_for_read("missing", "test", "bin")
            .await
            .expect("the open succeeds"),
        ReadOpen::NotCached
    ));
    let WriteOpen::Opened(aborted) = client
        .open_for_write("three", "test", "bin", 5)
        .await
        .expect("the open succeeds")
    else {
        panic!("a fresh key opens for writing");
    };
    aborted.abort().await;
    client.quiesce().await;

    assert_eq!(hub.open_handles(), 0);
    assert_eq!(
        hub.counters(),
        HubCounters {
            opens_for_read: 2,
            opens_for_write: 3,
            // Two commits and one read lease given back.
            closes: 3,
            removes: 1,
        }
    );
    assert_eq!(hub.entry("three"), None);
}

#[tokio::test]
async fn a_hub_that_goes_away_is_unavailable_and_a_restart_reconnects() {
    let (_dir, hub) = hub().await;
    let client = client_for(&hub);
    fill(&client, "warm", "bin", b"warm bytes").await;
    let WriteOpen::Opened(pending) = client
        .open_for_write("cold", "test", "bin", 5)
        .await
        .expect("the open succeeds")
    else {
        panic!("a fresh key opens for writing");
    };

    hub.shutdown();

    // Dropping the connections released their leases and discarded the
    // pending fill, exactly as a real hub does when a client's connection
    // ends.
    hub.wait_for_open_handles(0).await;
    assert_eq!(hub.entry("cold"), None);
    // A call while the hub is down is availability-shaped, never a miss.
    let err = client
        .open_for_read("warm", "test", "bin")
        .await
        .expect_err("the hub is down");
    assert!(err.is_unavailable(), "{err}");
    // The write lease died with the connection, so committing it must fail
    // rather than claim the entry is cached.
    let err = pending
        .commit()
        .await
        .expect_err("the reservation died with the connection");
    assert!(err.is_unavailable(), "{err}");

    hub.restart().await.expect("the hub restarts");

    // The client re-dials on its next call; the first one may still be
    // retiring the dead connection, so retry within a bounded window.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let hit = loop {
        match client.open_for_read("warm", "test", "bin").await {
            Ok(outcome) => break outcome,
            Err(err) => {
                assert!(err.is_unavailable(), "{err}");
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the client never reconnected to the restarted hub"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    };

    let ReadOpen::Opened(handle) = hit else {
        panic!("the restarted hub still holds the entry");
    };
    assert_eq!(
        std::fs::read(handle.path()).expect("the cached file is readable"),
        b"warm bytes"
    );
    handle.close().await.expect("the close succeeds");
    hub.wait_for_open_handles(0).await;
}
