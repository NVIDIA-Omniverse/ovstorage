// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ByteCacheWrapper` behavior: hit/miss, conditional/range bypass,
//! write-through, materialize leases, invalidation across mutating ops, and
//! factory config validation.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::StreamExt as _;
use ovstorage::layers::BYTE_CACHE_KIND;
use ovstorage::{
    Body, ByteRange, CancellationToken, ConfigValue, CopyOptions, CopyRequest,
    DeleteDirectoryOptions, DeleteDirectoryRequest, DeleteOptions, DeleteRequest, ErrorCode, Layer,
    LayerConfig, LayerHandle, LayerKindDescriptor, LocalDelegate, ObjectInfo, ReadRequest,
    ReadResult, ReadStream, RenameOptions, RenameRequest, Request, Result, Stack, StatRequest,
    UpdateMetadataOptions, UpdateMetadataRequest, Url, WriteOptions, WriteRequest, WriteResult,
    WriteStep,
};
use ovstorage_plugin_cache::ByteCacheWrapperFactory;

use crate::common::*;

/// Byte-cache wrapper config pointing at fresh dirs under `dir`.
fn byte_cache_config(dir: &std::path::Path) -> LayerConfig {
    std::fs::create_dir_all(dir.join("cache")).unwrap();
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let mut config = LayerConfig::new();
    config.insert(
        "cache_root".into(),
        ConfigValue::String(dir.join("cache").to_string_lossy().into_owned()),
    );
    config.insert(
        "state_root".into(),
        ConfigValue::String(dir.join("state").to_string_lossy().into_owned()),
    );
    config
}

/// As [`byte_cache_config`], with a whole-cache size budget.
fn byte_cache_config_budgeted(dir: &std::path::Path, max_bytes: i64) -> LayerConfig {
    let mut config = byte_cache_config(dir);
    config.insert("max_bytes".into(), ConfigValue::Int(max_bytes));
    config
}

/// As [`byte_cache_config`], with a per-object fill cap.
fn byte_cache_config_capped(dir: &std::path::Path, max_object_bytes: i64) -> LayerConfig {
    let mut config = byte_cache_config(dir);
    config.insert(
        "max_object_bytes".into(),
        ConfigValue::Int(max_object_bytes),
    );
    config
}

/// As [`byte_cache_config_capped`], opting the composition into warming a
/// cacheable `LocalDelegate` via the `warm_delegates` knob (no per-request hint).
fn byte_cache_config_warm_delegates(dir: &std::path::Path, max_object_bytes: i64) -> LayerConfig {
    let mut config = byte_cache_config_capped(dir, max_object_bytes);
    config.insert("warm_delegates".into(), ConfigValue::Bool(true));
    config
}

async fn byte_cache_stack_with_config(backend: LayerHandle, config: LayerConfig) -> Stack {
    build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .unwrap()
}

/// Drain a `ReadResult::Stream` fully into a byte vector.
async fn drain_stream(result: ReadResult) -> Vec<u8> {
    match result {
        ReadResult::Stream { mut stream, .. } => {
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk.expect("stream chunk"));
            }
            out
        }
        other => panic!("expected a stream, got {other:?}"),
    }
}

// --- stream-tee fill (streamed-result remainder) on the validator keying ----

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tee_fill_commits_and_serves_subsequent_hit() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = StreamProbe::new(b"streamed-object-body", 4, Some("etag-A"));
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;

    // First read streams through and tees into the cache on clean completion.
    let first = stack.read(read_request("file:///obj"), None).await.unwrap();
    assert_eq!(drain_stream(first).await, b"streamed-object-body");

    // Second read is served from the tee'd cache entry (no backend re-read).
    let second = stack.read(read_request("file:///obj"), None).await.unwrap();
    assert_eq!(collect(second).await, b"streamed-object-body");
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "the tee'd stream must serve the second read from cache"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tee_cap_aborts_midstream_stream_intact_no_commit() {
    let tmp = tempfile::tempdir().unwrap();
    // Object (256 KiB) far exceeds the fill cap (1 KiB); chunks are 4 KiB, so
    // the tee aborts after the first chunk overshoots the cap — the whole
    // object is never buffered (it spools chunk-by-chunk to the staging file,
    // discarded on abort).
    let body = vec![7u8; 256 * 1024];
    let backend = StreamProbe::new(&body, 4 * 1024, Some("etag-big"));
    let stack =
        byte_cache_stack_with_config(backend.clone(), byte_cache_config_capped(tmp.path(), 1024))
            .await;

    // The caller's stream is unaffected by the aborted fill: it receives the
    // full object.
    let first = stack.read(read_request("file:///big"), None).await.unwrap();
    assert_eq!(drain_stream(first).await, body);

    // No commit happened (over-cap): the second read re-enters the backend.
    let second = stack.read(read_request("file:///big"), None).await.unwrap();
    assert_eq!(drain_stream(second).await, body);
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "an over-cap object must not be cached"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tee_commits_only_on_clean_completion() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = StreamProbe::new(b"abcdefghijklmnop", 4, Some("etag-C"));
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;

    // Consume only the first chunk, then drop the stream (cancellation).
    {
        let result = stack.read(read_request("file:///obj"), None).await.unwrap();
        let ReadResult::Stream { mut stream, .. } = result else {
            panic!("expected a stream");
        };
        let _first = stream.next().await.expect("first chunk").expect("chunk ok");
        // `stream` (and its un-committed tee) drops here.
    }

    // The aborted fill left no cached row: the next read re-enters the backend.
    let second = stack.read(read_request("file:///obj"), None).await.unwrap();
    assert_eq!(collect(second).await, b"abcdefghijklmnop");
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "a cancelled stream must not leave a half-cached row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tee_no_etag_stream_stays_uncached() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = StreamProbe::new(b"no-identity-body", 4, None);
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;

    let first = stack.read(read_request("file:///obj"), None).await.unwrap();
    assert_eq!(drain_stream(first).await, b"no-identity-body");
    let second = stack.read(read_request("file:///obj"), None).await.unwrap();
    assert_eq!(drain_stream(second).await, b"no-identity-body");
    // No etag ⇒ no identity key ⇒ never cached: both reads hit the backend.
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

// --- `warm_delegates` knob — over-cap delegate passes through ---------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn warm_delegate_over_cap_passes_through_uncached() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("delegate-big.bin");
    // 64 KiB file, 1 KiB cap: the pre-read size check rejects caching without
    // ever reading the file into memory, even with `warm_delegates` set.
    std::fs::write(&source, vec![9u8; 64 * 1024]).unwrap();
    let backend = DelegateReadProbe::new(source.clone(), Some("etag-E"));
    let stack = byte_cache_stack_with_config(
        backend.clone(),
        byte_cache_config_warm_delegates(tmp.path(), 1024),
    )
    .await;

    let result = stack.read(read_request("file:///big"), None).await.unwrap();
    match result {
        ReadResult::LocalDelegate(local) => {
            // Over cap: the original backend delegate passes through unchanged.
            assert_eq!(local.path, source);
        }
        other => panic!("expected a local delegate, got {other:?}"),
    }

    // Not cached: a second read re-enters the backend.
    stack.read(read_request("file:///big"), None).await.unwrap();
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

// --- `warm_delegates` knob — warm without a per-request hint ----------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn warm_delegates_knob_warms_delegate_without_extension() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("delegate.bin");
    std::fs::write(&source, b"small-delegate-body").unwrap();
    let backend = DelegateReadProbe::new(source.clone(), Some("etag-W"));
    // `warm_delegates=true` composition, plain read (no per-request hint).
    let stack = byte_cache_stack_with_config(
        backend.clone(),
        byte_cache_config_warm_delegates(tmp.path(), 1024),
    )
    .await;

    let result = stack.read(read_request("file:///obj"), None).await.unwrap();
    match result {
        ReadResult::LocalDelegate(local) => {
            // Warmed into the CAS (a cache path, not the backend source) with a
            // lease — the knob drove warming without any per-request hint.
            assert_ne!(local.path, source, "delegate must be spooled into the CAS");
            assert!(local.guard.is_some(), "CAS delegate must carry a lease");
            assert_eq!(std::fs::read(&local.path).unwrap(), b"small-delegate-body");
        }
        other => panic!("expected a local delegate, got {other:?}"),
    }

    // Warmed under the object's validator: a second read is served from the CAS
    // without re-entering the backend read slot.
    stack.read(read_request("file:///obj"), None).await.unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "the knob-warmed delegate must serve the second read from cache"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_no_warm_delegate_passes_through_uncached() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("delegate.bin");
    std::fs::write(&source, b"small-delegate-body").unwrap();
    let backend = DelegateReadProbe::new(source.clone(), Some("etag-U"));
    // Default config: `warm_delegates` unset, and the plain read carries no
    // per-request hint — the delegate must pass through unwarmed.
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;

    let result = stack.read(read_request("file:///obj"), None).await.unwrap();
    match result {
        ReadResult::LocalDelegate(local) => {
            assert_eq!(local.path, source, "the backend delegate must pass through");
            assert!(
                local.guard.is_none(),
                "an un-warmed delegate carries no lease"
            );
        }
        other => panic!("expected a local delegate, got {other:?}"),
    }

    // Not cached: a second read re-enters the backend.
    stack.read(read_request("file:///obj"), None).await.unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "with no knob and no hint the delegate must not be cached"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_hit_avoids_second_backend_read() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::default()),
        backend.clone(),
        byte_cache_config(tmp.path()),
    )
    .await
    .unwrap();

    let first = stack.read(read_request("file:///obj"), None).await.unwrap();
    assert_eq!(collect(first).await, b"content");
    let second = stack.read(read_request("file:///obj"), None).await.unwrap();
    assert_eq!(collect(second).await, b"content");
    // Second read served from the byte cache — backend read only once.
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
}

/// Origin-shaped probe whose authenticated representation varies by principal
/// even though every response deliberately carries the same ETag.
struct PrincipalOriginProbe {
    reads: AtomicUsize,
    stats: AtomicUsize,
    materializes: AtomicUsize,
    alice_path: std::path::PathBuf,
    bob_path: std::path::PathBuf,
}

impl PrincipalOriginProbe {
    fn principal<'a>(&self, extensions: &'a ovstorage::Extensions) -> Result<&'a str> {
        let principal = extensions
            .get(ovstorage::wrappers::ext::PRINCIPAL_ID)
            .ok_or_else(|| ovstorage::Error::new(ErrorCode::Internal, "missing principal"))?;
        std::str::from_utf8(principal)
            .map_err(|_| ovstorage::Error::new(ErrorCode::Internal, "invalid principal"))
    }

    fn body(&self, extensions: &ovstorage::Extensions) -> Result<&'static [u8]> {
        match self.principal(extensions)? {
            "alice" => Ok(b"alice-private-body"),
            "bob" => Ok(b"bob-private-body"),
            _ => Err(ovstorage::Error::new(
                ErrorCode::PermissionDenied,
                "unknown principal",
            )),
        }
    }

    fn path(&self, extensions: &ovstorage::Extensions) -> Result<std::path::PathBuf> {
        match self.principal(extensions)? {
            "alice" => Ok(self.alice_path.clone()),
            "bob" => Ok(self.bob_path.clone()),
            _ => Err(ovstorage::Error::new(
                ErrorCode::PermissionDenied,
                "unknown principal",
            )),
        }
    }

    fn info(address: Url, size: usize) -> ObjectInfo {
        let mut info = object_info(address, size as u64);
        info.etag = Some("shared-etag".into());
        info
    }
}

#[async_trait::async_trait]
impl Layer for PrincipalOriginProbe {
    fn name(&self) -> &str {
        "principal-origin"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.stats.fetch_add(1, Ordering::SeqCst);
        let body = self.body(&request.extensions)?;
        Ok(Self::info(request.input.address, body.len()))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let body = self.body(&request.extensions)?;
        Ok(ReadResult::Bytes {
            bytes: body.to_vec(),
            info: Self::info(request.input.address, body.len()),
        })
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        self.materializes.fetch_add(1, Ordering::SeqCst);
        let body = self.body(&request.extensions)?;
        Ok(LocalDelegate {
            path: self.path(&request.extensions)?,
            info: Self::info(request.input.address, body.len()),
            guard: None,
        })
    }
}

fn credentialed_read_request(url: &str, principal: &str) -> Request<ReadRequest> {
    let mut request = read_request(url);
    request.extensions.insert(
        ovstorage::wrappers::ext::PRINCIPAL_ID,
        principal.as_bytes().to_vec(),
    );
    ovstorage::wrappers::ext::insert_resolved_oauth_credential(
        &mut request.extensions,
        &ovstorage::wrappers::ext::ResolvedOAuthCredentialRef {
            backend_kind: "http".into(),
            keyring_handle: "oauth/test".into(),
        },
    )
    .unwrap();
    request
}

#[tokio::test]
async fn credentialed_reads_and_materialize_bypass_principal_agnostic_byte_cache() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_path = tmp.path().join("alice.bin");
    let bob_path = tmp.path().join("bob.bin");
    std::fs::write(&alice_path, b"alice-private-body").unwrap();
    std::fs::write(&bob_path, b"bob-private-body").unwrap();
    let backend = Arc::new(PrincipalOriginProbe {
        reads: AtomicUsize::new(0),
        stats: AtomicUsize::new(0),
        materializes: AtomicUsize::new(0),
        alice_path: alice_path.clone(),
        bob_path: bob_path.clone(),
    });
    let stack = byte_cache_stack_with_config(
        backend.clone(),
        byte_cache_config_warm_delegates(tmp.path(), 1024),
    )
    .await;
    let address = "https://origin.example/private";

    let alice = stack
        .read(credentialed_read_request(address, "alice"), None)
        .await
        .unwrap();
    assert_eq!(collect(alice).await, b"alice-private-body");
    let bob = stack
        .read(credentialed_read_request(address, "bob"), None)
        .await
        .unwrap();
    assert_eq!(collect(bob).await, b"bob-private-body");
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "each credentialed principal must reach the origin despite the shared ETag"
    );
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        0,
        "the bypass must not consult cache validator or fallback state"
    );

    let alice = stack
        .materialize(credentialed_read_request(address, "alice"), None)
        .await
        .unwrap();
    let bob = stack
        .materialize(credentialed_read_request(address, "bob"), None)
        .await
        .unwrap();
    assert_eq!(alice.path, alice_path);
    assert_eq!(bob.path, bob_path);
    assert_eq!(
        backend.materializes.load(Ordering::SeqCst),
        2,
        "credentialed materialize must neither hit nor fill the shared CAS"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_skips_range_read() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::default()),
        backend.clone(),
        byte_cache_config(tmp.path()),
    )
    .await
    .unwrap();

    let mut request = read_request("file:///obj");
    request.input.options.range = Some(ByteRange {
        start: 0,
        end_inclusive: Some(2),
    });
    stack.read(request.clone(), None).await.unwrap();
    stack.read(request, None).await.unwrap();
    // Ranged reads are never cached — both hit the backend.
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_invalidates_on_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::default()),
        backend.clone(),
        byte_cache_config(tmp.path()),
    )
    .await
    .unwrap();

    stack.read(read_request("file:///obj"), None).await.unwrap(); // fill
    stack
        .delete(
            Request::new(DeleteRequest {
                address: Url::parse("file:///obj").unwrap(),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap(); // invalidate
    stack.read(read_request("file:///obj"), None).await.unwrap(); // re-fetch
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_write_through_serves_subsequent_read() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"old-content", Vec::new());
    let stack = build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::default()),
        backend.clone(),
        byte_cache_config(tmp.path()),
    )
    .await
    .unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("file:///obj").unwrap(),
                body: Body::Bytes(b"new-content".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let read = stack.read(read_request("file:///obj"), None).await.unwrap();
    // The buffered write is cached write-through; the read is served from it.
    assert_eq!(collect(read).await, b"new-content");
    assert_eq!(backend.reads.load(Ordering::SeqCst), 0);
}

/// Build a `byte_cache` stack over `backend` with fresh dirs under `tmp`.
async fn byte_cache_stack(tmp: &std::path::Path, backend: LayerHandle) -> Stack {
    build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::default()),
        backend,
        byte_cache_config(tmp),
    )
    .await
    .unwrap()
}

// --- terminal direct continue_write invalidates -----------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_invalidates_on_direct_continue_write() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    stack.read(read_request("file:///obj"), None).await.unwrap(); // fill
    // The direct write_redirect→continue_write completion path (broker upload)
    // bypasses write()/write_stream(); a terminal step must invalidate.
    let step = stack
        .continue_write(empty_continue_write("file:///obj"), None)
        .await
        .unwrap();
    assert!(matches!(step, WriteStep::Done(_)));
    stack.read(read_request("file:///obj"), None).await.unwrap(); // re-fetch
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_keeps_cache_on_mid_flight_continue_write() {
    // A non-terminal `WriteStep::Redirects` is mid-flight and must NOT
    // invalidate (only the terminal `Done` finalizes the object).
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::redirecting_continue(b"content", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    stack.read(read_request("file:///obj"), None).await.unwrap(); // fill
    let step = stack
        .continue_write(empty_continue_write("file:///obj"), None)
        .await
        .unwrap();
    assert!(matches!(step, WriteStep::Redirects(_)));
    stack.read(read_request("file:///obj"), None).await.unwrap(); // still cached
    // Mid-flight step left the cache intact — the second read was a hit.
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
}

// --- non-buffered overwrites invalidate the byte cache ----------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_invalidates_on_local_file_write() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    stack.read(read_request("file:///obj"), None).await.unwrap(); // fill
    let body_path = tmp.path().join("upload.bin");
    std::fs::write(&body_path, b"new").unwrap();
    stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("file:///obj").unwrap(),
                body: Body::LocalFile(body_path),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack.read(read_request("file:///obj"), None).await.unwrap(); // re-fetch
    // A LocalFile overwrite isn't write-through cached but must invalidate.
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_invalidates_on_stream_write() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    stack.read(read_request("file:///obj"), None).await.unwrap(); // fill
    stack
        .write(
            Request::new(WriteRequest {
                address: Url::parse("file:///obj").unwrap(),
                body: stream_body(b"new"),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack.read(read_request("file:///obj"), None).await.unwrap(); // re-fetch
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_invalidates_on_write_stream() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    stack.read(read_request("file:///obj"), None).await.unwrap(); // fill
    stack
        .write_stream(
            Request::new(WriteRequest {
                address: Url::parse("file:///obj").unwrap(),
                body: Body::Bytes(b"new".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack.read(read_request("file:///obj"), None).await.unwrap(); // re-fetch
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

// --- materialize fill / hit / conditional passthrough -----------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_materialize_fills_then_hits() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source.bin");
    std::fs::write(&source, b"staged-bytes").unwrap();
    let backend = CacheProbe::materializing(b"staged-bytes", source.clone());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    let first = stack
        .materialize(read_request("file:///obj"), None)
        .await
        .unwrap();
    // Filled into the CAS: a cache path (not the backend source) with a lease.
    assert_ne!(first.path, source);
    assert!(
        first.guard.is_some(),
        "cache fill must return a lease guard"
    );
    assert_eq!(std::fs::read(&first.path).unwrap(), b"staged-bytes");

    let second = stack
        .materialize(read_request("file:///obj"), None)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&second.path).unwrap(), b"staged-bytes");
    // Second materialize served from the cache — backend materialize once.
    assert_eq!(backend.materializes.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_materialize_skips_conditional() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source.bin");
    std::fs::write(&source, b"staged-bytes").unwrap();
    let backend = CacheProbe::materializing(b"staged-bytes", source.clone());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    let mut request = read_request("file:///obj");
    request.input.options.if_match = Some("etag-1".to_string());
    let delegate = stack.materialize(request, None).await.unwrap();
    // Conditional materialize isn't cached — the backend delegate passes through.
    assert_eq!(delegate.path, source);
    assert_eq!(backend.materializes.load(Ordering::SeqCst), 1);
}

// --- byte-cache invalidation across the other mutating ops ------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_invalidates_destination_on_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    stack
        .read(read_request("file:///dest"), None)
        .await
        .unwrap(); // fill dest
    stack
        .copy(
            Request::new(CopyRequest {
                source: Url::parse("file:///src").unwrap(),
                destination: Url::parse("file:///dest").unwrap(),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack
        .read(read_request("file:///dest"), None)
        .await
        .unwrap(); // re-fetch
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_invalidates_source_and_destination_on_rename() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    stack.read(read_request("file:///src"), None).await.unwrap(); // fill src
    stack
        .read(read_request("file:///dest"), None)
        .await
        .unwrap(); // fill dest
    stack
        .rename(
            Request::new(RenameRequest {
                source: Url::parse("file:///src").unwrap(),
                destination: Url::parse("file:///dest").unwrap(),
                options: RenameOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack.read(read_request("file:///src"), None).await.unwrap(); // re-fetch
    stack
        .read(read_request("file:///dest"), None)
        .await
        .unwrap(); // re-fetch
    // Both source and destination keys were invalidated.
    assert_eq!(backend.reads.load(Ordering::SeqCst), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_invalidates_on_update_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    stack.read(read_request("file:///obj"), None).await.unwrap(); // fill
    stack
        .update_metadata(
            Request::new(UpdateMetadataRequest {
                address: Url::parse("file:///obj").unwrap(),
                options: UpdateMetadataOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack.read(read_request("file:///obj"), None).await.unwrap(); // re-fetch
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_invalidates_on_delete_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    stack.read(read_request("file:///d/"), None).await.unwrap(); // fill
    stack
        .delete_directory(
            Request::new(DeleteDirectoryRequest {
                address: Url::parse("file:///d/").unwrap(),
                options: DeleteDirectoryOptions,
            }),
            None,
        )
        .await
        .unwrap();
    stack.read(read_request("file:///d/"), None).await.unwrap(); // re-fetch
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_skips_if_match_read() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    let mut request = read_request("file:///obj");
    request.input.options.if_match = Some("etag-1".to_string());
    stack.read(request.clone(), None).await.unwrap();
    stack.read(request, None).await.unwrap();
    // Conditional reads are never cached — both hit the backend.
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

// --- cache config validation ------------------------------------------------

#[tokio::test]
async fn byte_cache_factory_requires_cache_root() {
    let backend = CacheProbe::new(b"", Vec::new());
    let mut config = LayerConfig::new();
    config.insert(
        "state_root".into(),
        ConfigValue::String("/tmp/state".into()),
    );
    let error = build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .err()
    .expect("missing cache_root must fail the build");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn byte_cache_factory_rejects_non_string_path() {
    let backend = CacheProbe::new(b"", Vec::new());
    let mut config = LayerConfig::new();
    config.insert("cache_root".into(), ConfigValue::Int(7));
    config.insert(
        "state_root".into(),
        ConfigValue::String("/tmp/state".into()),
    );
    let error = build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .err()
    .expect("non-string cache_root must fail the build");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn byte_cache_factory_rejects_negative_max_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = byte_cache_config(tmp.path());
    config.insert("max_bytes".into(), ConfigValue::Int(-1));
    let backend = CacheProbe::new(b"", Vec::new());
    let error = build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .err()
    .expect("negative max_bytes must fail the build");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn byte_cache_factory_rejects_non_bool_lost_backing_fallback() {
    // A malformed knob must fail the build, not silently disable the
    // broker's survive-backing-loss behavior.
    let tmp = tempfile::tempdir().unwrap();
    let mut config = byte_cache_config(tmp.path());
    config.insert(
        "lost_backing_fallback".into(),
        ConfigValue::String("true".into()),
    );
    let backend = CacheProbe::new(b"", Vec::new());
    let error = build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .err()
    .expect("non-bool lost_backing_fallback must fail the build");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn byte_cache_never_serves_bytes_from_a_superseded_version() {
    // The cache key carries the object's validator. When the object
    // changes out-of-band (no mutation traverses this stack), the changed
    // etag makes the old entry unreachable — the read re-fetches instead of
    // serving stale bytes.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1, "same version hits");

    // The object changes behind the stack's back: new validator, old bytes
    // must not be served.
    backend.bump_version();
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "a changed etag must not reuse older cached bytes"
    );
}

#[tokio::test]
async fn byte_cache_never_caches_unversioned_content() {
    // A backend that reports no etag gets no byte caching at all — the
    // lookup bypasses (no current validator to prove freshness) and the fill
    // is skipped (unversioned content must not be inserted).
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    // Simulate an etag-less backend: CacheProbe's versioned_info is driven by
    // `version`; there is no switch, so build a bespoke stack over a probe
    // whose infos carry no etag.
    let stack = byte_cache_stack(tmp.path(), UnversionedProbe::new(backend.clone())).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "unversioned content must not be served from the cache"
    );
}

/// Strips the etag from every info a [`CacheProbe`] reports — an etag-less
/// backend for the unversioned-content rule.
struct UnversionedProbe {
    inner: Arc<CacheProbe>,
}

impl UnversionedProbe {
    fn new(inner: Arc<CacheProbe>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

#[async_trait::async_trait]
impl Layer for UnversionedProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        self.inner.descriptor()
    }

    async fn stat(
        &self,
        request: Request<ovstorage::StatRequest>,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ovstorage::ObjectInfo> {
        let mut info = self.inner.stat(request, cancel).await?;
        info.etag = None;
        Ok(info)
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ReadResult> {
        match self.inner.read(request, cancel).await? {
            ReadResult::Bytes { bytes, mut info } => {
                info.etag = None;
                Ok(ReadResult::Bytes { bytes, info })
            }
            other => Ok(other),
        }
    }
}

// --- stat-error discrimination + availability-fallback contract -------------

#[tokio::test]
async fn byte_cache_transient_stat_serves_the_availability_fallback() {
    // Availability-shaped stat errors (the backend cannot answer) serve the
    // last proven content from the index.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    backend.set_stat_error(Some(ErrorCode::Transient));
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "an unanswerable backend serves the last proven content"
    );
}

#[tokio::test]
async fn byte_cache_permission_denied_stat_never_serves_cached_bytes() {
    // Answer-shaped stat errors bypass the cache: a principal the backend
    // refuses must not be served partition-shared content another caller
    // filled.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    backend.set_stat_error(Some(ErrorCode::PermissionDenied));
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "a denied stat must bypass the cache, never the index"
    );
}

#[tokio::test]
async fn byte_cache_not_found_stat_is_definitive_by_default() {
    // An out-of-band-deleted object (NotFound with no through-stack mutation
    // to clear the index) must stop being served: NotFound is an answer, not
    // an outage — unless the composition opts into the lost-backing
    // fallback.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    backend.set_stat_error(Some(ErrorCode::NotFound));
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "NotFound must not engage the availability fallback by default"
    );
}

#[tokio::test]
async fn byte_cache_lost_backing_fallback_serves_on_not_found() {
    // The broker's composition opts in: NotFound is treated as lost backing
    // store and the last proven content is served.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let mut config = byte_cache_config(tmp.path());
    config.insert("lost_backing_fallback".into(), ConfigValue::Bool(true));
    let stack = build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::default()),
        backend.clone(),
        config,
    )
    .await
    .unwrap();
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    backend.set_stat_error(Some(ErrorCode::NotFound));
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "the opted-in composition survives lost backing store"
    );
}

#[tokio::test]
async fn byte_cache_unsupported_stat_bypasses_the_cache() {
    // A stat-less backend gets no validation at all, so index-serving would
    // remain stale until mutation for the whole backend class. Unsupported
    // therefore bypasses explicitly.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;
    let address = Url::parse("mem:///obj").unwrap();

    backend.set_stat_error(Some(ErrorCode::Unsupported));
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "a stat-less backend is never served unvalidated cached bytes"
    );
}

#[tokio::test]
async fn byte_cache_cancelled_stat_propagates_without_a_read() {
    // A cancelled validator stat must not produce a read (neither a cache
    // serve nor a backend re-entry).
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    backend.set_stat_error(Some(ErrorCode::Cancelled));
    let error = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Cancelled);
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "a cancelled stat must not produce a read"
    );
}

#[tokio::test]
async fn byte_cache_mutation_clears_the_availability_fallback() {
    // A mutation through the stack must clear the index: the fallback no
    // longer answers when the stat subsequently errs, even though the
    // pre-mutation content row would still parse.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    stack
        .delete(
            Request::new(DeleteRequest {
                address: address.clone(),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    backend.set_stat_error(Some(ErrorCode::Transient));
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "a deleted-through-the-stack object must not serve via the fallback"
    );
}

#[tokio::test]
async fn byte_cache_prunes_superseded_content_rows() {
    // A new fill best-effort removes the previous validator's content row
    // (the index names it), so the validator-keyed cache stays at ~one row
    // per address: an out-of-band revert to the OLD validator misses instead
    // of hitting a lingering stale row.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap(); // fills v1
    backend.bump_version(); // out-of-band change to v2
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap(); // fills v2, prunes v1
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);

    backend.set_version(1); // out-of-band revert: v1 is current again
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        3,
        "the superseded v1 content row was pruned, not merely shadowed"
    );
}

#[tokio::test]
async fn byte_cache_delete_directory_clears_child_fallback_entries() {
    // delete_directory must clear the availability index for the whole
    // subtree, not just the directory address (which never has a fill of its
    // own): a child filled before the delete must stop answering via the
    // fallback once its stat errs. A sibling outside the deleted prefix
    // keeps its entry — the sweep respects the `/` path boundary.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;
    let child = Url::parse("mem:///dir/child").unwrap();
    let sibling = Url::parse("mem:///dir2/child").unwrap();

    stack
        .read(read_request(child.as_str()), None)
        .await
        .unwrap(); // fill child
    stack
        .read(read_request(sibling.as_str()), None)
        .await
        .unwrap(); // fill sibling
    stack
        .delete_directory(
            Request::new(DeleteDirectoryRequest {
                address: Url::parse("mem:///dir").unwrap(),
                options: DeleteDirectoryOptions,
            }),
            None,
        )
        .await
        .unwrap();
    backend.set_stat_error(Some(ErrorCode::Transient));
    stack
        .read(read_request(child.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        3,
        "a child deleted via delete_directory must not serve via the fallback"
    );
    stack
        .read(read_request(sibling.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        3,
        "the sibling outside the deleted prefix keeps its fallback entry"
    );
}

#[tokio::test]
async fn byte_cache_watch_event_clears_the_availability_fallback() {
    // Content entries need no watch invalidation (the changed
    // validator makes them unreachable on the strict path), but the
    // last-known-validator index must be cleared: a watched change proves
    // the last-filled content superseded, so the stat-error availability
    // fallback must stop serving it.
    let tmp = tempfile::tempdir().unwrap();
    let address = Url::parse("mem:///obj").unwrap();
    let backend = CacheProbe::new(b"payload", vec![object_info(address.clone(), 7)]);
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);

    // Control: with the backend unable to answer the validator stat, the
    // availability index serves the last proven content.
    backend.set_stat_error(Some(ErrorCode::Transient));
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "the availability fallback serves while the index is intact"
    );
    backend.set_stat_error(None);

    // A watched change for the address flows through the wrapper (the probe
    // emits one Created event per list item).
    let events = stack
        .watch_directory(
            Request::new(ovstorage::WatchDirectoryRequest {
                prefix: Url::parse("mem:///").unwrap(),
                options: ovstorage::WatchDirectoryOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    for event in events {
        event.unwrap();
    }

    // The index is gone: with the backend unanswerable there is no fallback,
    // so the read bypasses the cache and re-enters the backend.
    backend.set_stat_error(Some(ErrorCode::Transient));
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "a watched change must clear the availability fallback"
    );
}

// --- over-cap fill clears the stale availability index ----------------------

/// A backend that reads back small content under `v1`, then a larger body
/// (over the fill cap) after [`ResizingProbe::grow`] bumps it to `v2`; `stat`
/// reports the current validator or a scripted outage. Drives the case where
/// an over-cap newer read must clear the index so the availability fallback
/// can't later serve the smaller, now-superseded `v1` bytes.
struct ResizingProbe {
    small: Vec<u8>,
    big: Vec<u8>,
    grown: std::sync::atomic::AtomicBool,
    reads: std::sync::atomic::AtomicUsize,
    stat_error: std::sync::Mutex<Option<ErrorCode>>,
}

impl ResizingProbe {
    fn new(small: &[u8], big: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            small: small.to_vec(),
            big: big.to_vec(),
            grown: std::sync::atomic::AtomicBool::new(false),
            reads: std::sync::atomic::AtomicUsize::new(0),
            stat_error: std::sync::Mutex::new(None),
        })
    }

    fn grow(&self) {
        self.grown.store(true, Ordering::SeqCst);
    }

    fn set_stat_error(&self, code: Option<ErrorCode>) {
        *self.stat_error.lock().unwrap() = code;
    }

    fn content(&self) -> Vec<u8> {
        if self.grown.load(Ordering::SeqCst) {
            self.big.clone()
        } else {
            self.small.clone()
        }
    }

    fn etag(&self) -> String {
        if self.grown.load(Ordering::SeqCst) {
            "v2".to_string()
        } else {
            "v1".to_string()
        }
    }

    fn info(&self, address: Url) -> ovstorage::ObjectInfo {
        let content = self.content();
        ovstorage::ObjectInfo {
            etag: Some(self.etag()),
            ..object_info(address, content.len() as u64)
        }
    }
}

#[async_trait::async_trait]
impl Layer for ResizingProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        backend_descriptor("probe")
    }

    async fn stat(
        &self,
        request: Request<ovstorage::StatRequest>,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ovstorage::ObjectInfo> {
        if let Some(code) = *self.stat_error.lock().unwrap() {
            return Err(ovstorage::Error::new(code, "scripted stat failure"));
        }
        Ok(self.info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(ReadResult::Bytes {
            bytes: self.content(),
            info: self.info(request.input.address),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_over_cap_read_clears_stale_availability_index() {
    // After a smaller version is cached, a larger (over-cap) newer
    // read is correctly refused caching — but it must also clear the
    // availability index, or a later stat outage serves the smaller, superseded
    // bytes this read already proved stale.
    let tmp = tempfile::tempdir().unwrap();
    let big = vec![9u8; 64];
    let backend = ResizingProbe::new(b"tiny", &big);
    // 16-byte cap: `tiny` fits, the 64-byte `v2` body does not.
    let stack =
        byte_cache_stack_with_config(backend.clone(), byte_cache_config_capped(tmp.path(), 16))
            .await;
    let address = Url::parse("mem:///obj").unwrap();

    // v1 (within cap) fills the cache + availability index.
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    let hit = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(collect(hit).await, b"tiny");
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "the second same-version read is served from cache"
    );

    // The object grows past the cap and gets a new validator. The newer read is
    // refused caching (over cap) and must clear the v1 availability index.
    backend.grow();
    let grown = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(collect(grown).await, big, "the over-cap read serves fresh");
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);

    // A stat outage now engages the availability fallback. With the index
    // cleared there is nothing to serve, so the read re-enters the backend
    // (fresh v2) instead of serving the superseded v1 bytes.
    backend.set_stat_error(Some(ErrorCode::Transient));
    let served = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        3,
        "the over-cap read must have cleared the stale availability index"
    );
    assert_eq!(
        collect(served).await,
        big,
        "the fallback must not serve the superseded smaller version"
    );
}

// --- watch_directory handles Lapsed + deleted-dir children ------------------

/// A backend that serves reads/stats from an inner [`CacheProbe`] but emits a
/// scripted set of `ChangeEvent`s from `watch_directory` — so a test can drive
/// the `Deleted`/`Lapsed` invalidation paths the `CacheProbe`'s Created-only
/// watch stream can't.
struct WatchProbe {
    inner: Arc<CacheProbe>,
    events: Vec<ovstorage::ChangeEvent>,
}

impl WatchProbe {
    fn new(inner: Arc<CacheProbe>, events: Vec<ovstorage::ChangeEvent>) -> Arc<Self> {
        Arc::new(Self { inner, events })
    }
}

#[async_trait::async_trait]
impl Layer for WatchProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        self.inner.descriptor()
    }

    async fn stat(
        &self,
        request: Request<ovstorage::StatRequest>,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ovstorage::ObjectInfo> {
        self.inner.stat(request, cancel).await
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ReadResult> {
        self.inner.read(request, cancel).await
    }

    async fn watch_directory(
        &self,
        _request: Request<ovstorage::WatchDirectoryRequest>,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ovstorage::ChangeStream> {
        let events = self.events.clone();
        Ok(Box::new(events.into_iter().map(Ok)))
    }
}

fn deleted_object_event(address: &str) -> ovstorage::ChangeEvent {
    ovstorage::ChangeEvent::Object {
        address: Url::parse(address).unwrap(),
        kind: ovstorage::ChangeKind::Deleted,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        at: std::time::SystemTime::now(),
        cursor: ovstorage::WatchDirectoryCursor::default(),
    }
}

fn lapsed_event() -> ovstorage::ChangeEvent {
    ovstorage::ChangeEvent::Lapsed {
        since: None,
        cursor: ovstorage::WatchDirectoryCursor::default(),
    }
}

fn modified_object_event(address: &str) -> ovstorage::ChangeEvent {
    ovstorage::ChangeEvent::Object {
        address: Url::parse(address).unwrap(),
        kind: ovstorage::ChangeKind::Modified,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        at: std::time::SystemTime::now(),
        cursor: ovstorage::WatchDirectoryCursor::default(),
    }
}

/// Injectable, blocking change queue shared between an [`InjectableWatchProbe`]
/// and the iterators it hands out.
#[derive(Default)]
struct InjectableShared {
    queue: std::sync::Mutex<std::collections::VecDeque<ovstorage::ChangeEvent>>,
    ready: std::sync::Condvar,
    /// Count of `watch_directory` opens. Note this increments INSIDE
    /// `watch_directory`, i.e. BEFORE the drain loop runs its post-open
    /// activation `sweep(&prefix)`, so it is NOT a safe fill barrier on its own.
    opens: std::sync::atomic::AtomicUsize,
    /// Count of stream polls by the drain. The drain sweeps the subtree and only
    /// THEN polls the opened stream, so the first poll fires strictly after the
    /// activation sweep has completed — a fill gated on it provably lands after
    /// the sweep, closing the sweep-vs-fill false-positive window.
    polls: std::sync::atomic::AtomicUsize,
}

/// A backend whose `watch_directory` blocks until events are injected (honoring
/// the host cancel token), so a direct-`Stack` test can drive the notification
/// drain deterministically — inject *after* the cache is filled. Reads/stats
/// delegate to an inner [`CacheProbe`].
struct InjectableWatchProbe {
    inner: Arc<CacheProbe>,
    shared: Arc<InjectableShared>,
}

impl InjectableWatchProbe {
    fn new(inner: Arc<CacheProbe>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            shared: Arc::new(InjectableShared::default()),
        })
    }

    fn inject(&self, event: ovstorage::ChangeEvent) {
        self.shared.queue.lock().unwrap().push_back(event);
        self.shared.ready.notify_all();
    }
}

struct InjectableWatchIter {
    shared: Arc<InjectableShared>,
    cancel: Option<ovstorage::CancellationToken>,
}

impl Iterator for InjectableWatchIter {
    type Item = Result<ovstorage::ChangeEvent>;
    fn next(&mut self) -> Option<Self::Item> {
        // The drain sweeps the subtree BEFORE it polls the stream, so this poll
        // is a post-activation-sweep barrier for the test.
        self.shared.polls.fetch_add(1, Ordering::SeqCst);
        let mut queue = self.shared.queue.lock().unwrap();
        loop {
            if let Some(event) = queue.pop_front() {
                return Some(Ok(event));
            }
            if self.cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
                return None;
            }
            let (guard, _) = self
                .shared
                .ready
                .wait_timeout(queue, std::time::Duration::from_millis(20))
                .unwrap();
            queue = guard;
        }
    }
}

#[async_trait::async_trait]
impl Layer for InjectableWatchProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        self.inner.descriptor()
    }

    async fn list_address_roots(
        &self,
        _cx: &ovstorage::Extensions,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<(
        ovstorage::RootInfoSnapshot,
        Option<ovstorage::RootInfoUpdateStream>,
    )> {
        let mut root = test_root("mem:///");
        root.capabilities.supports_watch_directory = true;
        Ok((
            ovstorage::RootInfoSnapshot {
                roots: vec![root],
                updates: false,
            },
            None,
        ))
    }

    async fn stat(
        &self,
        request: Request<ovstorage::StatRequest>,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ovstorage::ObjectInfo> {
        self.inner.stat(request, cancel).await
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ReadResult> {
        self.inner.read(request, cancel).await
    }

    async fn watch_directory(
        &self,
        _request: Request<ovstorage::WatchDirectoryRequest>,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ovstorage::ChangeStream> {
        self.shared.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(InjectableWatchIter {
            shared: self.shared.clone(),
            cancel,
        }))
    }
}

/// `watch_invalidation = true` discovers watch-capable roots and spawns bounded
/// shared drains that invalidate on out-of-band changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_stack_watch_invalidation_drives_invalidation() {
    let tmp = tempfile::tempdir().unwrap();
    let inner = CacheProbe::new(b"payload", Vec::new());
    let probe = InjectableWatchProbe::new(inner.clone());
    let mut config = byte_cache_config(tmp.path());
    config.insert("watch_invalidation".into(), ConfigValue::Bool(true));
    let stack = byte_cache_stack_with_config(probe.clone(), config).await;
    let address = Url::parse("mem:///obj").unwrap();

    // Synchronize on the drain's FIRST stream poll, not merely on `opens`. The
    // `opens` counter increments inside `watch_directory`, BEFORE the drain loop
    // runs its post-open activation `sweep(&prefix)`; filling on `opens` alone
    // leaves a window where that sweep clears the just-filled entry and the
    // later cached-read assertion passes for the wrong reason. The drain sweeps
    // and only THEN polls the stream, so the first poll fires strictly after the
    // activation sweep completes — the fill below provably lands after it.
    let mut swept = false;
    for _ in 0..500 {
        if probe.shared.polls.load(Ordering::SeqCst) >= 1 {
            swept = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        swept,
        "the drain must poll its stream (after the activation sweep) before the fill"
    );

    // Fill the availability index after the shared drain is established.
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    let reads_after_fill = inner.reads.load(Ordering::SeqCst);
    // Make the fallback unavailable so a post-clear read must hit the backend.
    inner.set_stat_error(Some(ErrorCode::Transient));

    // Out-of-band change: the drain pulls it and clears the address's index.
    probe.inject(modified_object_event("mem:///obj"));

    // Poll a read until the drain has cleared the entry (backend re-hit).
    let mut cleared = false;
    for _ in 0..500 {
        stack
            .read(read_request(address.as_str()), None)
            .await
            .unwrap();
        if inner.reads.load(Ordering::SeqCst) > reads_after_fill {
            cleared = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        cleared,
        "the config-driven notification drain must invalidate on an out-of-band change"
    );

    // Dropping the Stack drops the wrapper, whose Drop stops the drain.
    drop(stack);
}

/// Drain a `watch_directory` change stream over `prefix`, propagating errors.
async fn drain_watch(stack: &Stack, prefix: &str) {
    let events = stack
        .watch_directory(
            Request::new(ovstorage::WatchDirectoryRequest {
                prefix: Url::parse(prefix).unwrap(),
                options: ovstorage::WatchDirectoryOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    for event in events {
        event.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_watch_deleted_directory_clears_children() {
    // A `Deleted` directory event must drop its children's
    // availability index (mirroring MetadataCacheWrapper), not just the exact
    // directory address; a sibling outside the watched prefix is preserved.
    //
    // The watch is scoped to `mem:///dir` so the sibling under `mem:///other`
    // is outside the watched prefix: the per-event `Deleted` clear drops the
    // child, and the stream-end gap sweep (which drops the whole watched
    // subtree once the scripted stream ends) also stays within `mem:///dir`,
    // leaving the sibling untouched.
    let tmp = tempfile::tempdir().unwrap();
    let inner = CacheProbe::new(b"payload", Vec::new());
    let backend = WatchProbe::new(inner.clone(), vec![deleted_object_event("mem:///dir")]);
    let stack = byte_cache_stack(tmp.path(), backend).await;
    let child = Url::parse("mem:///dir/child").unwrap();
    let sibling = Url::parse("mem:///other/child").unwrap();

    stack
        .read(read_request(child.as_str()), None)
        .await
        .unwrap(); // fill child
    stack
        .read(read_request(sibling.as_str()), None)
        .await
        .unwrap(); // fill sibling
    assert_eq!(inner.reads.load(Ordering::SeqCst), 2);

    drain_watch(&stack, "mem:///dir").await;

    // The deleted directory's child does not answer via the fallback.
    inner.set_stat_error(Some(ErrorCode::Transient));
    stack
        .read(read_request(child.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        inner.reads.load(Ordering::SeqCst),
        3,
        "a Deleted directory watch event must clear its children's index"
    );
    // The sibling outside the deleted prefix keeps its fallback entry.
    stack
        .read(read_request(sibling.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        inner.reads.load(Ordering::SeqCst),
        3,
        "a sibling outside the deleted directory keeps its fallback entry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_empty_watch_end_sweeps_only_watched_subtree() {
    let tmp = tempfile::tempdir().unwrap();
    let inner = CacheProbe::new(b"payload", Vec::new());
    let backend = WatchProbe::new(inner.clone(), Vec::new());
    let stack = byte_cache_stack(tmp.path(), backend).await;
    let inside = "mem:///dir/inside";
    let outside = "mem:///other/outside";

    stack.read(read_request(inside), None).await.unwrap();
    stack.read(read_request(outside), None).await.unwrap();
    assert_eq!(inner.reads.load(Ordering::SeqCst), 2);

    drain_watch(&stack, "mem:///dir/").await;
    inner.set_stat_error(Some(ErrorCode::Transient));

    stack.read(read_request(inside), None).await.unwrap();
    assert_eq!(
        inner.reads.load(Ordering::SeqCst),
        3,
        "an empty-ended watch must sweep the watched byte-cache subtree"
    );
    stack.read(read_request(outside), None).await.unwrap();
    assert_eq!(
        inner.reads.load(Ordering::SeqCst),
        3,
        "the terminal sweep must not clear an unrelated byte-cache subtree"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_watch_lapsed_prefix_clears_the_watched_subtree() {
    // A `Lapsed` event (lost notifications) must drop the whole
    // watched prefix's availability index — ignoring Lapsed would leave
    // proven-stale bytes servable under a later stat outage.
    let tmp = tempfile::tempdir().unwrap();
    let inner = CacheProbe::new(b"payload", Vec::new());
    let backend = WatchProbe::new(inner.clone(), vec![lapsed_event()]);
    let stack = byte_cache_stack(tmp.path(), backend).await;
    let child = Url::parse("mem:///dir/child").unwrap();

    stack
        .read(read_request(child.as_str()), None)
        .await
        .unwrap(); // fill
    assert_eq!(inner.reads.load(Ordering::SeqCst), 1);

    // Control: while the index is intact, a stat outage serves the fallback.
    inner.set_stat_error(Some(ErrorCode::Transient));
    stack
        .read(read_request(child.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        inner.reads.load(Ordering::SeqCst),
        1,
        "the availability fallback serves while the index is intact"
    );
    inner.set_stat_error(None);

    drain_watch(&stack, "mem:///").await;

    // The Lapsed event cleared the watched subtree: with the backend
    // unanswerable there is no fallback, so the read re-enters the backend.
    inner.set_stat_error(Some(ErrorCode::Transient));
    stack
        .read(read_request(child.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        inner.reads.load(Ordering::SeqCst),
        2,
        "a Lapsed event must prefix-clear the watched subtree's index"
    );
}

// --- shared tee-generations registry across a SIGHUP rebuild ----------------

/// Two `ByteCacheWrapper`s built over one process-cached `Cache` with a shared
/// [`ByteCacheGenerations`] registry (the broker's SIGHUP reuse) share one
/// resurrection guard: an old-Stack tee in flight across the reload observes a
/// new-Stack mutation's generation bump and refuses to resurrect a stale row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_generations_block_cross_stack_tee_resurrection() {
    use ovstorage_cache::{Cache, CacheConfig};
    use ovstorage_plugin_cache::ByteCacheGenerations;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("cache")).unwrap();
    std::fs::create_dir_all(tmp.path().join("state")).unwrap();
    // One process-cached Cache + one shared tee-generations registry, exactly as
    // the broker threads both (keyed by `cache_root`) across a SIGHUP reload.
    let cache = Arc::new(
        Cache::open(CacheConfig {
            state_root: tmp.path().join("state"),
            cache_root: tmp.path().join("cache"),
        })
        .unwrap(),
    );
    let generations = ByteCacheGenerations::new();

    // "Old" Stack: a streaming backend, so a read registers a tee on the shared
    // registry.
    let old_backend = StreamProbe::new(b"pre-reload-body", 4, Some("etag-A"));
    let old_stack = build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::with_cache_and_generations(
            cache.clone(),
            generations.clone(),
        )),
        old_backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // "New" Stack (post-reload): a delete-capable backend over the SAME cache and
    // the SAME generations registry.
    let new_backend = CacheProbe::new(b"pre-reload-body", Vec::new());
    let new_stack = build_stack(
        BYTE_CACHE_KIND,
        Arc::new(ByteCacheWrapperFactory::with_cache_and_generations(
            cache.clone(),
            generations.clone(),
        )),
        new_backend,
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // Start (but do not finish) an old-Stack streaming read: the tee registers on
    // the shared registry at the address's current generation.
    let old_read = old_stack
        .read(read_request("file:///obj"), None)
        .await
        .unwrap();
    let ReadResult::Stream { mut stream, .. } = old_read else {
        panic!("expected a stream");
    };

    // A mutation through the NEW Stack bumps the shared generation for the
    // address — its tee registration lives in the shared map.
    new_stack
        .delete(
            Request::new(DeleteRequest {
                address: Url::parse("file:///obj").unwrap(),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    // Drain the old read to clean completion: the tee reaches EOF but sees a
    // bumped generation and refuses to commit — no resurrection.
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk.expect("chunk"));
    }
    assert_eq!(body, b"pre-reload-body");
    drop(stream);

    // The old tee left no cached row, so a subsequent old-Stack read re-enters
    // the backend (a resurrected row would have served it from cache, keeping
    // reads at 1). With a fresh per-wrapper registry the new-Stack delete would
    // bump only its own map, the old tee would commit, and this would be 1.
    let again = old_stack
        .read(read_request("file:///obj"), None)
        .await
        .unwrap();
    assert_eq!(drain_stream(again).await, b"pre-reload-body");
    assert_eq!(
        old_backend.reads.load(Ordering::SeqCst),
        2,
        "a new-Stack mutation must invalidate the old-Stack tee via the shared \
         generations registry — the stale row must not resurrect",
    );
}

// --- streamed write-through (the write counterpart of the read tee) ---------

/// A write-capable backend that DRAINS the write body through to EOF (as a real
/// backend must to finalize a streamed upload), stores it, and serves it back
/// on `read`/`stat` under a monotonic validator. Optionally pauses after
/// draining — before returning — so a test can interleave a concurrent mutation
/// while the byte-cache write tee is registered and staged but not yet
/// committed (the generations guard).
struct StreamWriteProbe {
    content: std::sync::Mutex<Vec<u8>>,
    version: std::sync::atomic::AtomicUsize,
    reads: std::sync::atomic::AtomicUsize,
    writes: std::sync::atomic::AtomicUsize,
    /// `(paused, resume)`: `write` fires `paused` after draining, then awaits
    /// `resume` before returning. `None` = never pauses.
    pause: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}

impl StreamWriteProbe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            content: std::sync::Mutex::new(Vec::new()),
            version: std::sync::atomic::AtomicUsize::new(1),
            reads: std::sync::atomic::AtomicUsize::new(0),
            writes: std::sync::atomic::AtomicUsize::new(0),
            pause: None,
        })
    }

    fn paused(paused: Arc<tokio::sync::Notify>, resume: Arc<tokio::sync::Notify>) -> Arc<Self> {
        Arc::new(Self {
            content: std::sync::Mutex::new(Vec::new()),
            version: std::sync::atomic::AtomicUsize::new(1),
            reads: std::sync::atomic::AtomicUsize::new(0),
            writes: std::sync::atomic::AtomicUsize::new(0),
            pause: Some((paused, resume)),
        })
    }

    fn etag(&self) -> String {
        format!("v{}", self.version.load(Ordering::SeqCst))
    }

    fn info(&self, address: Url, size: u64) -> ovstorage::ObjectInfo {
        ovstorage::ObjectInfo {
            etag: Some(self.etag()),
            ..object_info(address, size)
        }
    }
}

#[async_trait::async_trait]
impl Layer for StreamWriteProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        backend_descriptor("probe")
    }

    async fn stat(
        &self,
        request: Request<ovstorage::StatRequest>,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ovstorage::ObjectInfo> {
        let size = self.content.lock().unwrap().len() as u64;
        Ok(self.info(request.input.address, size))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let bytes = self.content.lock().unwrap().clone();
        let info = self.info(request.input.address, bytes.len() as u64);
        Ok(ReadResult::Bytes { bytes, info })
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<WriteResult> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        let address = request.input.address.clone();
        let ovstorage::Body::Stream(mut stream) = request.input.body else {
            panic!("StreamWriteProbe expects a Body::Stream");
        };
        // Drain the (byte-cache-teed) body to EOF, exactly as a real streaming
        // backend does to finalize the object.
        let mut content = Vec::new();
        while let Some(chunk) = stream.next_chunk() {
            content.extend_from_slice(&chunk?);
        }
        *self.content.lock().unwrap() = content.clone();
        if let Some((paused, resume)) = &self.pause {
            paused.notify_one();
            resume.notified().await;
        }
        // The finalized object gets a new validator (the write tee commits under
        // it).
        self.version.fetch_add(1, Ordering::SeqCst);
        Ok(WriteResult {
            info: self.info(address, content.len() as u64),
        })
    }

    async fn delete(
        &self,
        _request: Request<DeleteRequest>,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<()> {
        // A no-op at the backend: the byte cache's own `clear_latest` bumps the
        // generation (the mutation the write tee must observe). Content is left
        // in place so the post-sequence read is a deterministic backend
        // re-entry vs. a resurrected cache hit.
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamed_write_through_caches_under_the_new_validator() {
    // A streamed write tees through the cache and commits under the write
    // result's new validator; a subsequent read is served from the cache
    // without re-entering the backend.
    let tmp = tempfile::tempdir().unwrap();
    let backend = StreamWriteProbe::new();
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;
    let address = Url::parse("file:///streamed").unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: address.clone(),
                body: chunked_stream_body(b"streamed-write-through-body", 8),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    let read = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(collect(read).await, b"streamed-write-through-body");
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        0,
        "the streamed write-through must serve the read from cache",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamed_write_over_cap_writes_but_does_not_cache() {
    // A streamed write past `max_object_bytes` aborts the tee mid-stream: the
    // object is still written (the body streams on to the backend intact) but
    // is not cached, and the availability index is not left naming it.
    let tmp = tempfile::tempdir().unwrap();
    let backend = StreamWriteProbe::new();
    // 8-byte cap; a 27-byte body in 8-byte chunks overshoots on the second
    // chunk, so the tee aborts without ever buffering the whole object.
    let stack =
        byte_cache_stack_with_config(backend.clone(), byte_cache_config_capped(tmp.path(), 8))
            .await;
    let address = Url::parse("file:///over-cap-streamed").unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: address.clone(),
                body: chunked_stream_body(b"streamed-write-through-body", 8),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    // The object was written through to the backend.
    let read = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(collect(read).await, b"streamed-write-through-body");
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "an over-cap streamed write must not be cached — the read re-enters the backend",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamed_write_tee_does_not_resurrect_over_concurrent_mutation() {
    // For the write tee: a mutation that lands while a streamed write is
    // in flight bumps the address's generation, so the write tee refuses to
    // commit its staged bytes — no resurrection. Mirrors the read-tee guard.
    let tmp = tempfile::tempdir().unwrap();
    let paused = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let backend = StreamWriteProbe::paused(paused.clone(), resume.clone());
    let stack = byte_cache_stack(tmp.path(), backend.clone()).await;
    let address = Url::parse("file:///raced-streamed").unwrap();

    let write_fut = stack.write(
        Request::new(WriteRequest {
            address: address.clone(),
            body: chunked_stream_body(b"pre-mutation-streamed-body", 8),
            options: WriteOptions::default(),
        }),
        None,
    );
    // While the write is paused (body drained + tee staged, not yet committed),
    // a concurrent delete through the same stack bumps the write tee's
    // generation slot.
    let mutate_fut = async {
        paused.notified().await;
        stack
            .delete(
                Request::new(DeleteRequest {
                    address: address.clone(),
                    options: DeleteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        resume.notify_one();
    };
    let (write_result, ()) = tokio::join!(write_fut, mutate_fut);
    write_result.unwrap();

    // The write tee saw the bumped generation and declined to publish: a read
    // re-enters the backend rather than being served the resurrected bytes.
    let read = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(collect(read).await, b"pre-mutation-streamed-body");
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "a concurrent mutation must invalidate the write tee's commit — no resurrection",
    );
}

// --- over-cap / admission best-effort index clears -------------------

/// A backend that starts serving a buffered `Bytes` version (which the wrapper
/// caches, recording the availability index) and can then switch to serving a
/// newer `Stream` version — so a test can seed the index, then drive the tee
/// admission / cap-breach paths that must clear that stale row. Supports a
/// scripted `stat` error to exercise the availability fallback afterward.
struct SwitchableProbe {
    state: std::sync::Mutex<SwitchableState>,
    reads: AtomicUsize,
    stat_error: std::sync::Mutex<Option<ErrorCode>>,
}

struct SwitchableState {
    content: Vec<u8>,
    etag: String,
    stream: bool,
    chunk_size: usize,
}

impl SwitchableProbe {
    fn bytes(content: &[u8], etag: &str) -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(SwitchableState {
                content: content.to_vec(),
                etag: etag.to_string(),
                stream: false,
                chunk_size: 4096,
            }),
            reads: AtomicUsize::new(0),
            stat_error: std::sync::Mutex::new(None),
        })
    }

    /// Switch to serving `content` as a chunked `Stream` under a new `etag`.
    fn switch_to_stream(&self, content: &[u8], etag: &str, chunk_size: usize) {
        let mut state = self.state.lock().unwrap();
        state.content = content.to_vec();
        state.etag = etag.to_string();
        state.stream = true;
        state.chunk_size = chunk_size.max(1);
    }

    fn set_stat_error(&self, code: Option<ErrorCode>) {
        *self.stat_error.lock().unwrap() = code;
    }

    fn info(&self, address: Url) -> ObjectInfo {
        let state = self.state.lock().unwrap();
        ObjectInfo {
            etag: Some(state.etag.clone()),
            ..object_info(address, state.content.len() as u64)
        }
    }
}

#[async_trait::async_trait]
impl Layer for SwitchableProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        if let Some(code) = *self.stat_error.lock().unwrap() {
            return Err(ovstorage::Error::new(code, "scripted stat failure"));
        }
        Ok(self.info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let (content, chunk_size, stream) = {
            let state = self.state.lock().unwrap();
            (state.content.clone(), state.chunk_size, state.stream)
        };
        let info = self.info(request.input.address);
        if stream {
            let chunks: Vec<Result<bytes::Bytes>> = content
                .chunks(chunk_size)
                .map(|c| Ok(bytes::Bytes::copy_from_slice(c)))
                .collect();
            let read_stream: ReadStream = Box::pin(futures::stream::iter(chunks));
            Ok(ReadResult::Stream {
                stream: read_stream,
                info,
            })
        } else {
            Ok(ReadResult::Bytes {
                bytes: content,
                info,
            })
        }
    }
}

/// As [`byte_cache_config`], with `max_streaming_fills`.
fn byte_cache_config_fills(dir: &std::path::Path, max_streaming_fills: i64) -> LayerConfig {
    let mut config = byte_cache_config(dir);
    config.insert(
        "max_streaming_fills".into(),
        ConfigValue::Int(max_streaming_fills),
    );
    config
}

/// When `begin_streaming_put` is refused (fill slots exhausted — here
/// forced with `max_streaming_fills = 0`) the tee serves the newer version
/// uncached, but must first best-effort clear the availability index so a later
/// stat outage under `lost_backing_fallback` can't serve the superseded bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fill_admission_failure_clears_the_stale_availability_index() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = SwitchableProbe::bytes(b"v1-small-body", "v1");
    let mut config = byte_cache_config_fills(tmp.path(), 0);
    config.insert("lost_backing_fallback".into(), ConfigValue::Bool(true));
    let stack = byte_cache_stack_with_config(backend.clone(), config).await;
    let address = "file:///obj";

    // Seed the availability index with v1 (buffered Bytes fill; no tee).
    stack.read(read_request(address), None).await.unwrap();
    let reads_after_seed = backend.reads.load(Ordering::SeqCst);

    // Newer v2 served as a Stream: the tee admission is refused (0 fill slots),
    // so it serves uncached and must clear the v1 index.
    backend.switch_to_stream(b"v2-newer-streamed-body", "v2", 4);
    let served = stack.read(read_request(address), None).await.unwrap();
    assert_eq!(
        drain_stream(served).await,
        b"v2-newer-streamed-body",
        "the caller still receives the current (uncached) stream"
    );

    // Stat outage: the fallback must NOT serve the superseded v1 bytes — the
    // index was cleared, so the read re-enters the backend.
    backend.set_stat_error(Some(ErrorCode::NotFound));
    let after = stack.read(read_request(address), None).await.unwrap();
    assert_eq!(drain_stream(after).await, b"v2-newer-streamed-body");
    assert!(
        backend.reads.load(Ordering::SeqCst) > reads_after_seed + 1,
        "the fill-admission failure must clear the stale index so the fallback does not serve v1"
    );
}

/// A tee that breaches `max_object_bytes` mid-stream abandons the fill
/// AND best-effort clears the availability index; a prior (smaller) validator's
/// row must not survive the abandonment to be served on a later stat outage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tee_cap_breach_clears_the_stale_availability_index() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = SwitchableProbe::bytes(b"v1-small", "v1");
    // Cap at 1 KiB; v2 (over-cap) will breach it mid-tee.
    let mut config = byte_cache_config_capped(tmp.path(), 1024);
    config.insert("lost_backing_fallback".into(), ConfigValue::Bool(true));
    let stack = byte_cache_stack_with_config(backend.clone(), config).await;
    let address = "file:///obj";

    // Seed the index with the small v1.
    stack.read(read_request(address), None).await.unwrap();
    let reads_after_seed = backend.reads.load(Ordering::SeqCst);

    // v2 is over-cap and streamed: the tee admits, then aborts mid-stream when
    // the body passes the cap, clearing the v1 index on the way out.
    let big = vec![7u8; 8 * 1024];
    backend.switch_to_stream(&big, "v2", 4 * 1024);
    let served = stack.read(read_request(address), None).await.unwrap();
    assert_eq!(
        drain_stream(served).await,
        big,
        "caller gets the full object"
    );

    backend.set_stat_error(Some(ErrorCode::NotFound));
    stack.read(read_request(address), None).await.unwrap();
    assert!(
        backend.reads.load(Ordering::SeqCst) > reads_after_seed + 1,
        "the tee cap-breach must clear the stale index so the fallback does not serve v1"
    );
}

// --- atomic, generation-guarded availability-index publication --------

/// A backend whose `read` parks on a barrier so a test can interleave a
/// mutation between the byte-cache wrapper capturing the read's start epoch and
/// the wrapper publishing the fetched validator. `stat` can be forced to err to
/// exercise the availability fallback afterward.
struct BarrierProbe {
    body: Vec<u8>,
    etag: String,
    /// Fires when the (first) read enters `read` — the wrapper has captured its
    /// start epoch and is now parked.
    entered: Arc<tokio::sync::Notify>,
    /// Awaited by the parked read; the test fires it to release the read.
    release: Arc<tokio::sync::Notify>,
    armed: std::sync::atomic::AtomicBool,
    reads: AtomicUsize,
    stat_error: std::sync::Mutex<Option<ErrorCode>>,
    /// On-disk file `materialize` hands back as a `LocalDelegate` (its bytes are
    /// `body`); `None` for probes whose tests never call `materialize`.
    materialize_source: Option<std::path::PathBuf>,
}

impl BarrierProbe {
    fn new(body: &[u8], etag: &str) -> Arc<Self> {
        Self::build(body, etag, None)
    }
    /// A probe whose parked `materialize` returns `source` as the delegate.
    fn materializing(body: &[u8], etag: &str, source: std::path::PathBuf) -> Arc<Self> {
        Self::build(body, etag, Some(source))
    }
    fn build(body: &[u8], etag: &str, materialize_source: Option<std::path::PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            body: body.to_vec(),
            etag: etag.to_string(),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
            armed: std::sync::atomic::AtomicBool::new(true),
            reads: AtomicUsize::new(0),
            stat_error: std::sync::Mutex::new(None),
            materialize_source,
        })
    }
    /// Park on the barrier the first time (like `read`), then continue.
    async fn barrier(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
    }
    fn set_stat_error(&self, code: Option<ErrorCode>) {
        *self.stat_error.lock().unwrap() = code;
    }
    fn info(&self, address: Url) -> ObjectInfo {
        ObjectInfo {
            etag: Some(self.etag.clone()),
            ..object_info(address, self.body.len() as u64)
        }
    }
}

#[async_trait::async_trait]
impl Layer for BarrierProbe {
    fn name(&self) -> &str {
        "backend"
    }
    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }
    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        if let Some(code) = *self.stat_error.lock().unwrap() {
            return Err(ovstorage::Error::new(code, "scripted stat failure"));
        }
        Ok(self.info(request.input.address))
    }
    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        // Only the first read/materialize parks; the fallback-probe read returns at once.
        self.barrier().await;
        Ok(ReadResult::Bytes {
            bytes: self.body.clone(),
            info: self.info(request.input.address),
        })
    }
    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ovstorage::LocalDelegate> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.barrier().await;
        let path = self
            .materialize_source
            .clone()
            .expect("materializing probe needs a source");
        Ok(ovstorage::LocalDelegate {
            path,
            info: self.info(request.input.address),
            guard: None,
        })
    }
    async fn delete(
        &self,
        _request: Request<DeleteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        Ok(())
    }
}

/// A slow pre-mutation read that finishes AFTER a concurrent mutation's
/// `clear_latest` must NOT re-publish its now-superseded validator, so the
/// availability fallback cannot serve the stale bytes on a later stat outage.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn slow_read_does_not_republish_over_a_concurrent_mutation() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = BarrierProbe::new(b"v1-body", "v1");
    let mut config = byte_cache_config(tmp.path());
    config.insert("lost_backing_fallback".into(), ConfigValue::Bool(true));
    let stack = Arc::new(byte_cache_stack_with_config(backend.clone(), config).await);

    // Start a slow read; it captures the start epoch, then parks in the backend.
    let entered = backend.entered.clone();
    let read_stack = stack.clone();
    let reader = tokio::spawn(async move {
        read_stack
            .read(read_request("mem:///obj"), None)
            .await
            .map(|_| ())
    });
    entered.notified().await;

    // Mutate through the stack while the read is parked: `clear_latest` bumps
    // the address's epoch and tombstones the availability index.
    stack
        .delete(
            Request::new(DeleteRequest {
                address: Url::parse("mem:///obj").unwrap(),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    // Release the parked read: its fill's publish is keyed on the pre-mutation
    // epoch, so `record_latest`'s compare_and_put refuses to republish v1.
    backend.release.notify_one();
    reader.await.unwrap().unwrap();

    // Stat outage: the availability fallback must NOT answer with v1 — the row
    // is a tombstone, so the read re-enters the backend instead.
    let reads_before = backend.reads.load(Ordering::SeqCst);
    backend.set_stat_error(Some(ErrorCode::NotFound));
    let _ = stack.read(read_request("mem:///obj"), None).await;
    assert!(
        backend.reads.load(Ordering::SeqCst) > reads_before,
        "the fallback must not serve the superseded v1 after the mutation"
    );
}

/// The epoch fence also covers `materialize` (a read-family op with no
/// preceding mutation and no S2 guard) — a mutation during the materialize fetch
/// must abort the republish, so the fallback doesn't serve the stale validator.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn slow_materialize_does_not_republish_over_a_concurrent_mutation() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("delegate-src");
    std::fs::write(&source, b"v1-body").unwrap();
    let backend = BarrierProbe::materializing(b"v1-body", "v1", source);
    let mut config = byte_cache_config(tmp.path());
    config.insert("lost_backing_fallback".into(), ConfigValue::Bool(true));
    let stack = Arc::new(byte_cache_stack_with_config(backend.clone(), config).await);

    let entered = backend.entered.clone();
    let mat_stack = stack.clone();
    let mat = tokio::spawn(async move {
        mat_stack
            .materialize(read_request("mem:///obj"), None)
            .await
            .map(|_| ())
    });
    entered.notified().await;

    stack
        .delete(
            Request::new(DeleteRequest {
                address: Url::parse("mem:///obj").unwrap(),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    backend.release.notify_one();
    mat.await.unwrap().unwrap();

    let reads_before = backend.reads.load(Ordering::SeqCst);
    backend.set_stat_error(Some(ErrorCode::NotFound));
    let _ = stack.read(read_request("mem:///obj"), None).await;
    assert!(
        backend.reads.load(Ordering::SeqCst) > reads_before,
        "the fence must cover materialize: the fallback must not serve the superseded v1"
    );
}

// --- a cache that cannot be written must degrade, not fail or go stale ------

/// A byte-cache config whose `cache_root` is a symlink, so a test can repoint
/// it mid-run at a tree where CAS publication is impossible (`sha256` is a
/// regular file, so `create_dir_all` fails for every shard). The SQLite index
/// lives under `state_root` and is unaffected, so rows written while the cache
/// was healthy survive the switch.
#[cfg(unix)]
fn byte_cache_config_repointable(dir: &std::path::Path) -> (LayerConfig, std::path::PathBuf) {
    let healthy = dir.join("cache-healthy");
    let blocked = dir.join("cache-blocked");
    std::fs::create_dir_all(&healthy).unwrap();
    std::fs::create_dir_all(&blocked).unwrap();
    std::fs::write(blocked.join("sha256"), b"").unwrap();
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let link = dir.join("cache");
    std::os::unix::fs::symlink(&healthy, &link).unwrap();

    let mut config = LayerConfig::new();
    config.insert(
        "cache_root".into(),
        ConfigValue::String(link.to_string_lossy().into_owned()),
    );
    config.insert(
        "state_root".into(),
        ConfigValue::String(dir.join("state").to_string_lossy().into_owned()),
    );
    (config, link)
}

/// Repoint the symlink from `byte_cache_config_repointable` at `target`.
#[cfg(unix)]
fn repoint_cache_root(dir: &std::path::Path, link: &std::path::Path, target: &str) {
    let staging = dir.join("cache-repoint-staging");
    std::os::unix::fs::symlink(dir.join(target), &staging).unwrap();
    std::fs::rename(&staging, link).unwrap();
}

// Unix-only: drives the failure by repointing a symlinked cache root
// (`std::os::unix::fs::symlink`).
#[cfg(unix)]
#[tokio::test]
async fn byte_cache_fill_failure_degrades_to_uncached_and_clears_the_stale_index() {
    // A cache write failure is "this validator can't be retained" -- exactly
    // what the over-cap arm handles by clearing the index. Taking `?` instead
    // does two wrong things at once: it leaves the availability index naming
    // the validator this read just proved superseded (so a later stat outage
    // serves bytes the read disproved), and it converts a successful backend
    // read into a hard error.
    let tmp = tempfile::tempdir().unwrap();
    let (config, link) = byte_cache_config_repointable(tmp.path());
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack_with_config(backend.clone(), config).await;
    let address = Url::parse("mem:///obj").unwrap();

    // Warm: the index now names v1 and v1's body is cached.
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);

    // The cache disk stops accepting writes, and the object changes
    // out-of-band. The next read proves v2 current but cannot cache it.
    repoint_cache_root(tmp.path(), &link, "cache-blocked");
    backend.bump_version();

    let served = stack
        .read(read_request(address.as_str()), None)
        .await
        .expect("a cache that cannot be written must serve uncached, not fail the read");
    assert_eq!(collect(served).await, b"payload");

    // Restore the cache disk, so the index and v1's cached body are readable
    // again. Without this the fallback would be unavailable for an unrelated
    // reason and the assertion below would pass without proving anything.
    repoint_cache_root(tmp.path(), &link, "cache-healthy");

    // The index must no longer name v1: this read proved it superseded, and a
    // stat outage would otherwise serve v1's cached body as current.
    backend.set_stat_error(Some(ErrorCode::Transient));
    let reads_before = backend.reads.load(Ordering::SeqCst);
    let _ = stack.read(read_request(address.as_str()), None).await;
    assert!(
        backend.reads.load(Ordering::SeqCst) > reads_before,
        "the stale validator must not still answer the availability fallback"
    );
}

#[tokio::test]
async fn byte_cache_failed_backend_mutation_still_invalidates() {
    // A failed backend mutation is ambiguous: a timeout can arrive after the
    // server has already committed, and that is indistinguishable from a clean
    // refusal without per-backend knowledge this layer does not have. So a
    // mutation that errors must still invalidate, or a delete that actually
    // landed leaves the fallback serving the deleted body during the next stat
    // outage.
    //
    // What enforces this is `MutationGuard::arm`'s write-ahead clear, not the
    // guard's `Drop`: the row is gone before the backend is called at all. The
    // assertion holds with `Drop` neutered, so this pins the invariant
    // end-to-end and does NOT isolate the unwind path -- the unprovable-publish
    // test is what covers a guard firing on an exit that reached no clear.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    // Warm the index and the body.
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);

    // The delete errors. Whether it landed is unknowable from here.
    backend.set_delete_error(Some(ErrorCode::Transient));
    let deleted = stack
        .delete(
            Request {
                extensions: Default::default(),
                input: DeleteRequest {
                    address: address.clone(),
                    options: DeleteOptions::default(),
                },
            },
            None,
        )
        .await;
    assert!(deleted.is_err(), "the backend refused the delete");
    backend.set_delete_error(None);

    // A stat outage must not serve the pre-delete body as current.
    backend.set_stat_error(Some(ErrorCode::Transient));
    let reads_before = backend.reads.load(Ordering::SeqCst);
    let served = stack.read(read_request(address.as_str()), None).await;
    // Both halves matter: the read must reach the backend (so the fallback did
    // not answer from cache) AND succeed (so "reached the backend" is not just
    // "failed on the way there").
    assert!(served.is_ok(), "the read itself must still succeed");
    assert!(
        backend.reads.load(Ordering::SeqCst) > reads_before,
        "a mutation whose outcome is unknown must not leave the fallback answering"
    );
}

// --- instance 9: the degraded streamed-write branch -------------------------

/// A backend that reads and stats normally but refuses every write. Bespoke to
/// this file, like the other probes here: it injects nothing into shared test
/// infrastructure, it is simply a backend whose writes fail.
#[cfg(unix)]
struct WriteRefusingBackend {
    body: Vec<u8>,
    reads: AtomicUsize,
    version: AtomicUsize,
    stat_error: std::sync::Mutex<Option<ErrorCode>>,
}

#[cfg(unix)]
impl WriteRefusingBackend {
    fn new(body: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            body: body.to_vec(),
            reads: AtomicUsize::new(0),
            version: AtomicUsize::new(1),
            stat_error: std::sync::Mutex::new(None),
        })
    }

    fn etag(&self) -> String {
        format!("v{}", self.version.load(Ordering::SeqCst))
    }

    fn set_stat_error(&self, code: Option<ErrorCode>) {
        *self.stat_error.lock().unwrap() = code;
    }

    fn info(&self, address: Url) -> ObjectInfo {
        ObjectInfo {
            etag: Some(self.etag()),
            ..object_info(address, self.body.len() as u64)
        }
    }
}

#[async_trait::async_trait]
#[cfg(unix)]
impl Layer for WriteRefusingBackend {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        if let Some(code) = *self.stat_error.lock().unwrap() {
            return Err(ovstorage::Error::new(code, "scripted stat failure"));
        }
        Ok(self.info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(ReadResult::Bytes {
            bytes: self.body.clone(),
            info: self.info(request.input.address),
        })
    }

    async fn write(
        &self,
        _request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        Err(ovstorage::Error::new(
            ErrorCode::Transient,
            "backend refused the write",
        ))
    }

    async fn write_stream(
        &self,
        _request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        Err(ovstorage::Error::new(
            ErrorCode::Transient,
            "backend refused the write",
        ))
    }
}

/// Make `begin_streaming_put` fail by pointing the cache root at a tree whose
/// `staging` is a regular file, so the staging directory cannot be created.
/// Models the ordinary case the degraded branch exists for -- the streaming
/// fill-slot budget being exhausted on a perfectly healthy cache -- which is
/// load-dependent and so cannot be triggered deterministically.
#[cfg(unix)]
fn block_streaming_fills(dir: &std::path::Path) {
    let blocked = dir.join("cache-nostage");
    std::fs::create_dir_all(&blocked).unwrap();
    std::fs::write(blocked.join("staging"), b"").unwrap();
}

// Unix-only: drives the failure by repointing a symlinked cache root
// (`std::os::unix::fs::symlink`).
#[cfg(unix)]
#[tokio::test]
async fn byte_cache_degraded_streamed_write_invalidates_when_the_backend_fails() {
    // The streamed write-through degrades to an uncached write whenever the
    // cache cannot open a streaming fill -- notably when the fill-slot budget
    // is exhausted, which happens on a healthy cache under load. That degraded
    // branch still calls the backend, so a failure there is ambiguous in
    // exactly the way `MutationGuard` exists for: the object may have
    // committed. It must not leave the index naming the pre-write validator.
    //
    // SCOPE, honestly: this began as the regression test for the guard being
    // armed below the `begin_streaming_put` match, which left the degraded
    // branch uncovered. Write-ahead invalidation has since subsumed that --
    // `arm` clears before either branch runs -- so the assertion now holds for
    // three independent reasons and does not isolate the degraded branch. It
    // is kept as an end-to-end guard on the invariant, not as a witness for
    // that ordering, which is now structural.
    let tmp = tempfile::tempdir().unwrap();
    let (config, link) = byte_cache_config_repointable(tmp.path());
    block_streaming_fills(tmp.path());
    let backend = WriteRefusingBackend::new(b"payload");
    let stack = byte_cache_stack_with_config(backend.clone(), config).await;
    let address = Url::parse("mem:///obj").unwrap();

    // Warm the index and the body.
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);

    // No streaming fill can be opened, so the write takes the degraded branch.
    repoint_cache_root(tmp.path(), &link, "cache-nostage");
    let wrote = stack
        .write(
            Request {
                extensions: Default::default(),
                input: WriteRequest {
                    address: address.clone(),
                    body: stream_body(b"new-body"),
                    options: WriteOptions::default(),
                },
            },
            None,
        )
        .await;
    assert!(wrote.is_err(), "the backend refused the write");

    // Restore the cache disk so the index and the cached body are readable
    // again -- otherwise the assertion below would be measuring unreadability.
    repoint_cache_root(tmp.path(), &link, "cache-healthy");

    backend.set_stat_error(Some(ErrorCode::Transient));
    let reads_before = backend.reads.load(Ordering::SeqCst);
    let served = stack.read(read_request(address.as_str()), None).await;
    assert!(served.is_ok(), "the read itself must still succeed");
    assert!(
        backend.reads.load(Ordering::SeqCst) > reads_before,
        "a degraded streamed write whose backend call failed must not leave the fallback answering"
    );
}

// --- the read guard must not disarm on an unproven publish -----------------

/// The availability row's blob path, via the index. Returns `None` when no
/// availability row exists.
#[cfg(unix)]
fn availability_blob_path(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let conn = rusqlite::Connection::open(dir.join("state").join("index.sqlite")).unwrap();
    let cas_key: Option<String> = conn
        .query_row(
            "SELECT cas_key FROM entries WHERE resolved_target LIKE '%' || char(2) || '%'",
            [],
            |row| row.get(0),
        )
        .ok();
    cas_key.map(|key| {
        dir.join("cache")
            .join("sha256")
            .join(&key[..2])
            .join(&key[2..])
    })
}

// Unix-only: drives the failure by repointing a symlinked cache root
// (`std::os::unix::fs::symlink`).
#[cfg(unix)]
#[tokio::test]
async fn byte_cache_unprovable_publish_does_not_disarm_the_read_guard() {
    // A read guard may only disarm once the publish has left the row in a
    // state that needs no further clearing. When the row cannot be snapshotted
    // -- its blob is unreadable, so the fence has nothing to compare against --
    // the publish is skipped entirely and the row still names the validator
    // this read has just superseded. Disarming there hands back exactly the
    // defect the guard exists to prevent.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    // Warm: the row names v1 and v1's body is cached.
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);

    // Make the row unreadable without removing it: a self-referential symlink
    // fails `read` with a loop error rather than NotFound, so the row survives
    // instead of self-healing to a clean miss. Keep the bytes to restore later.
    let blob = availability_blob_path(tmp.path()).expect("an availability row exists");
    let saved = std::fs::read(&blob).unwrap();
    std::fs::remove_file(&blob).unwrap();
    std::os::unix::fs::symlink(&blob, &blob).unwrap();

    // The object changes out of band, and a read proves the new validator.
    backend.bump_version();
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();

    // Repair the row's blob. The row itself was never touched, so whatever it
    // names is readable again -- which is what makes the assertion meaningful
    // rather than a measurement of unreadability.
    // Best-effort: when the guard behaves, it has already removed the row and
    // reclaimed this blob, so there is nothing to repair.
    let _ = std::fs::remove_file(&blob);
    if let Some(parent) = blob.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&blob, &saved);

    backend.set_stat_error(Some(ErrorCode::Transient));
    let reads_before = backend.reads.load(Ordering::SeqCst);
    let served = stack.read(read_request(address.as_str()), None).await;
    assert!(served.is_ok(), "the read itself must still succeed");
    assert!(
        backend.reads.load(Ordering::SeqCst) > reads_before,
        "a publish that could not be attempted must leave the guard armed, not disarm it"
    );
}

#[tokio::test]
async fn byte_cache_create_directory_invalidates_the_address() {
    // `create_directory` is a mutating endpoint the wrapper did not override,
    // so it inherited plain delegation and invalidated nothing. An address that
    // held a file can become a directory: the file's row survives the
    // out-of-band deletion, the directory is created at that address, and a
    // later stat outage serves the cached FILE bytes for something that is now
    // a directory.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);

    stack
        .create_directory(
            Request {
                extensions: Default::default(),
                input: ovstorage::CreateDirectoryRequest {
                    address: address.clone(),
                    options: Default::default(),
                },
            },
            None,
        )
        .await
        .unwrap();

    backend.set_stat_error(Some(ErrorCode::Transient));
    let reads_before = backend.reads.load(Ordering::SeqCst);
    let served = stack.read(read_request(address.as_str()), None).await;
    assert!(served.is_ok(), "the read itself must still succeed");
    assert!(
        backend.reads.load(Ordering::SeqCst) > reads_before,
        "creating a directory at the address must not leave the file's bytes answering"
    );
}

// --- write-ahead invalidation: no window where the backend has moved --------

/// Read the availability row's validator straight from the index, exactly as
/// `last_known_validator` would. `None` means no row, or a tombstone.
fn availability_validator(dir: &std::path::Path) -> Option<String> {
    let conn = rusqlite::Connection::open(dir.join("state").join("index.sqlite")).ok()?;
    let cas_key: String = conn
        .query_row(
            "SELECT cas_key FROM entries WHERE resolved_target LIKE '%' || char(2) || '%'",
            [],
            |row| row.get(0),
        )
        .ok()?;
    let blob = dir
        .join("cache")
        .join("sha256")
        .join(&cas_key[..2])
        .join(&cas_key[2..]);
    let bytes = std::fs::read(blob).ok()?;
    // `version || nonce(16) || etag`; an empty etag is a tombstone.
    if bytes.len() <= 17 {
        return None;
    }
    String::from_utf8(bytes[17..].to_vec()).ok()
}

/// A backend that runs a caller-supplied probe from inside its `write`, so a
/// test can observe cache state at the instant the backend is mutating.
struct ObservingBackend {
    body: Vec<u8>,
    reads: AtomicUsize,
    version: AtomicUsize,
    observed: std::sync::Mutex<Option<Option<String>>>,
    observe: Box<dyn Fn() -> Option<String> + Send + Sync>,
    stat_error: std::sync::Mutex<Option<ErrorCode>>,
}

impl ObservingBackend {
    fn new(body: &[u8], observe: Box<dyn Fn() -> Option<String> + Send + Sync>) -> Arc<Self> {
        Arc::new(Self {
            body: body.to_vec(),
            reads: AtomicUsize::new(0),
            version: AtomicUsize::new(1),
            observed: std::sync::Mutex::new(None),
            observe,
            stat_error: std::sync::Mutex::new(None),
        })
    }

    fn etag(&self) -> String {
        format!("v{}", self.version.load(Ordering::SeqCst))
    }

    fn info(&self, address: Url) -> ObjectInfo {
        ObjectInfo {
            etag: Some(self.etag()),
            ..object_info(address, self.body.len() as u64)
        }
    }
}

#[async_trait::async_trait]
impl Layer for ObservingBackend {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        if let Some(code) = *self.stat_error.lock().unwrap() {
            return Err(ovstorage::Error::new(code, "scripted stat failure"));
        }
        Ok(self.info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(ReadResult::Bytes {
            bytes: self.body.clone(),
            info: self.info(request.input.address),
        })
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        // The backend is mutating right now. Whatever the index says at this
        // instant is what a crash here would leave behind.
        *self.observed.lock().unwrap() = Some((self.observe)());
        self.version.fetch_add(1, Ordering::SeqCst);
        Ok(WriteResult {
            info: self.info(request.input.address),
        })
    }
}

#[tokio::test]
async fn byte_cache_invalidates_before_the_backend_mutation_not_after() {
    // Invalidating after the backend commits leaves a window in which the
    // object has changed and the index has not. A crash there -- SIGKILL, OOM,
    // container eviction -- leaves the row naming a superseded validator with
    // its body still cached, and nothing repairs it until that address is next
    // written, watched, or evicted. On a cache with no size budget, "never" is
    // a realistic answer.
    //
    // Clearing first removes the window rather than narrowing it: at every
    // instant from here on, the row either names nothing or names something the
    // backend actually has.
    let tmp = tempfile::tempdir().unwrap();
    let probe_dir = tmp.path().to_path_buf();
    let backend = ObservingBackend::new(
        b"payload",
        Box::new(move || availability_validator(&probe_dir)),
    );
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    // Warm: the index names v1 and v1's body is cached.
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        availability_validator(tmp.path()),
        Some("v1".to_string()),
        "the warm read published v1"
    );

    stack
        .write(
            Request {
                extensions: Default::default(),
                input: WriteRequest {
                    address: address.clone(),
                    body: Body::Bytes(b"new-body".to_vec()),
                    options: WriteOptions::default(),
                },
            },
            None,
        )
        .await
        .unwrap();

    let during = backend
        .observed
        .lock()
        .unwrap()
        .clone()
        .expect("the backend observed the index");
    assert_eq!(
        during, None,
        "while the backend is mutating, the index must name no validator -- a crash \
         at that instant would otherwise strand the superseded one indefinitely"
    );
}

#[tokio::test]
async fn byte_cache_refuses_an_object_that_cannot_coexist_with_its_bookkeeping() {
    // An object sized at the whole budget cannot be cached alongside its own
    // availability row: the fill evicts the row, and the publish then compares
    // against a row that is gone and refuses. The object is cached and its
    // fallback is silently absent -- the read paths report success and the
    // degradation is invisible.
    //
    // Refuse the fill instead. An object that cannot coexist with its own
    // bookkeeping is one the cache cannot serve coherently, and declining is
    // both predictable and leaves the budget for objects it can.
    let tmp = tempfile::tempdir().unwrap();
    let budget = 600;
    let backend = CacheProbe::new(&vec![b'x'; budget as usize], Vec::new());
    let stack = byte_cache_stack_with_config(
        backend.clone(),
        byte_cache_config_budgeted(tmp.path(), budget),
    )
    .await;
    let address = Url::parse("mem:///big").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();

    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "an object that cannot coexist with its bookkeeping must not be cached at all, \
         rather than cached with its fallback silently evicted"
    );
}

/// A backend with a body and a validator a test picks exactly, so a budget can
/// be set to the byte.
struct SizedProbe {
    body: Vec<u8>,
    etag: String,
    reads: AtomicUsize,
}

impl SizedProbe {
    fn new(body_len: usize, etag: &str) -> Arc<Self> {
        Arc::new(Self {
            body: vec![7u8; body_len],
            etag: etag.to_string(),
            reads: AtomicUsize::new(0),
        })
    }

    fn info(&self, address: Url) -> ObjectInfo {
        ObjectInfo {
            etag: Some(self.etag.clone()),
            ..object_info(address, self.body.len() as u64)
        }
    }
}

#[async_trait::async_trait]
impl Layer for SizedProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        backend_descriptor("probe")
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        Ok(self.info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(ReadResult::Bytes {
            bytes: self.body.clone(),
            info: self.info(request.input.address),
        })
    }
}

/// Read `address` twice and report whether the second read was served without
/// re-entering the backend.
async fn second_read_was_cached(stack: &Stack, backend: &Arc<SizedProbe>, address: &str) -> bool {
    stack.read(read_request(address), None).await.unwrap();
    stack.read(read_request(address), None).await.unwrap();
    backend.reads.load(Ordering::SeqCst) == 1
}

#[tokio::test]
async fn byte_cache_budget_admits_an_object_that_fits_beside_its_row() {
    // End to end, with a long etag: a fill whose body and availability row fit
    // the budget exactly must be admitted, which any reserve larger than the
    // real row width would refuse.
    //
    // This direction is all an end-to-end test can pin down. One byte short,
    // the object is equally unserved whether the admission check refused it or
    // admitted it and eviction took it -- so the exactness of the width itself
    // is asserted on the arithmetic directly, in
    // `budget_admission_scales_the_row_with_the_etag`.
    let tmp = tempfile::tempdir().unwrap();
    let body_len = 64_usize;
    let etag = "v-".to_string() + &"e".repeat(60);
    let exact = (body_len + 1 + 16 + etag.len()) as i64;
    let backend = SizedProbe::new(body_len, &etag);
    let stack = byte_cache_stack_with_config(
        backend.clone(),
        byte_cache_config_budgeted(tmp.path(), exact),
    )
    .await;

    assert!(
        second_read_was_cached(&stack, &backend, "mem:///exact").await,
        "an object that fits alongside its row to the byte must be cached"
    );
}

// --- mutation-path reclamation ---------------------------------------------

/// Number of *content* rows in the cache index — every row that is not an
/// availability row. A tombstoned availability row is the correct resting state
/// after an invalidation, so counting all rows would conflate it with the
/// orphaned body this asserts against.
fn content_row_count(dir: &std::path::Path) -> i64 {
    let conn = rusqlite::Connection::open(dir.join("state").join("index.sqlite")).unwrap();
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
        .unwrap();
    let availability: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM entries WHERE resolved_target LIKE '%' || char(2) || '%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    total - availability
}

#[tokio::test]
async fn byte_cache_delete_reclaims_the_superseded_body() {
    // The availability row is the only record of which validator a cached body
    // was filled under. A mutation reclaims that body by reading the validator
    // out of the row -- so anything that clears the row before the reclaim
    // destroys the only pointer to it.
    //
    // Nothing else ever revisits that content row: it is keyed by an etag no
    // future read will look up, invisible to the strict path, and with no
    // `max_bytes` there is no eviction to catch it either. `delete` is the
    // sharpest case because it publishes no replacement validator at all.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        content_row_count(tmp.path()),
        1,
        "the warm read leaves the object's body cached"
    );

    stack
        .delete(
            Request {
                extensions: Default::default(),
                input: DeleteRequest {
                    address: address.clone(),
                    options: DeleteOptions::default(),
                },
            },
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        content_row_count(tmp.path()),
        0,
        "the deleted object's body must be reclaimed, not left resident with no \
         reader that will ever key on it"
    );
}

#[tokio::test]
async fn byte_cache_write_reclaims_the_body_it_supersedes() {
    // Same reclamation, on the path that does publish a replacement. Repeated
    // writes to one address must reach a steady state of about one content row,
    // not accumulate one per version for the life of the process.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();

    for generation in 0..5 {
        stack
            .write(
                Request {
                    extensions: Default::default(),
                    input: WriteRequest {
                        address: address.clone(),
                        body: Body::Bytes(format!("body-{generation}").into_bytes()),
                        options: WriteOptions::default(),
                    },
                },
                None,
            )
            .await
            .unwrap();
    }

    assert!(
        content_row_count(tmp.path()) <= 1,
        "repeated writes to one address must reach a steady state of about one \
         content row, not one per version: found {}",
        content_row_count(tmp.path())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byte_cache_materialize_never_returns_an_evicted_path() {
    // `materialize` exists so callers can mmap or `fseek` the file directly --
    // load-bearing for USD and ML workloads. An object larger than the cache
    // budget is published and then immediately evicted by its own fill, so
    // `put_path_and_lease` mints no lease and the CAS path it reports is
    // already gone. Handing that back reports success with a path the consumer
    // cannot open.
    //
    // No lease means no promise the file stays readable, so the only safe
    // answer is the delegate the backend staged.
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source.bin");
    let body = vec![b'x'; 4096];
    std::fs::write(&source, &body).unwrap();
    let backend = CacheProbe::materializing(&body, source.clone());
    // A budget far below the object: the fill publishes, then evicts itself.
    let stack =
        byte_cache_stack_with_config(backend.clone(), byte_cache_config_budgeted(tmp.path(), 512))
            .await;

    let delegate = stack
        .materialize(read_request("file:///big"), None)
        .await
        .unwrap();

    assert!(
        delegate.path.exists(),
        "materialize returned a path that does not exist: {}",
        delegate.path.display()
    );
    assert_eq!(
        std::fs::read(&delegate.path).unwrap(),
        body,
        "and it must hold the object's bytes"
    );
}

#[tokio::test]
async fn byte_cache_over_cap_read_reclaims_the_superseded_body() {
    // A read that proves a new validator but fills nothing -- over-cap here,
    // and equally a failed fill or a pass-through delegate -- drops its guard.
    // The guard clears the availability row, which is the ONLY pointer to the
    // superseded validator's content row: nothing keys on that etag again, the
    // strict path can't see it, and the default cache has no budget to evict
    // it. Clearing the row without reclaiming the body it named leaks one
    // content row per such transition, forever.
    let tmp = tempfile::tempdir().unwrap();
    let big = vec![9u8; 64];
    let backend = ResizingProbe::new(b"tiny", &big);
    let stack =
        byte_cache_stack_with_config(backend.clone(), byte_cache_config_capped(tmp.path(), 16))
            .await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        content_row_count(tmp.path()),
        1,
        "the warm read leaves v1's body cached"
    );

    // v2 is over the cap: nothing is filled, and the guard clears the row that
    // named v1.
    backend.grow();
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();

    assert_eq!(
        content_row_count(tmp.path()),
        0,
        "an unpublished read must reclaim the body its clear made unreachable"
    );
}

#[tokio::test]
async fn byte_cache_failed_mutation_reclaims_the_superseded_body() {
    // The mutation guard reclaims the superseded body on `disarm`, but an error
    // exit never reaches it: the guard drops instead, and its clear removes the
    // availability row -- the only record of which validator the cached body
    // was filled under. The body is then unreachable and unreclaimable.
    //
    // Reclaiming it is safe in both directions a failed mutation can resolve:
    // if the backend committed, the body is stale; if it did not, the body is
    // still valid but the write-ahead clear has already cost its fallback, so
    // dropping it costs one re-fetch.
    let tmp = tempfile::tempdir().unwrap();
    let backend = CacheProbe::new(b"payload", Vec::new());
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        content_row_count(tmp.path()),
        1,
        "the warm read leaves the object's body cached"
    );

    backend.set_delete_error(Some(ErrorCode::Transient));
    let refused = stack
        .delete(
            Request {
                extensions: Default::default(),
                input: DeleteRequest {
                    address: address.clone(),
                    options: DeleteOptions::default(),
                },
            },
            None,
        )
        .await;
    assert!(refused.is_err(), "the scripted delete must fail");

    assert_eq!(
        content_row_count(tmp.path()),
        0,
        "a mutation that exits by error must reclaim the body whose only pointer \
         its write-ahead clear destroyed"
    );
}

/// A backend whose `continue_write` reports one mid-flight
/// `WriteStep::Redirects` and then a terminal `Done` -- the multi-round upload
/// the single-shot [`CacheProbe::redirecting_continue`] cannot express.
struct RedirectThenDoneProbe {
    inner: Arc<CacheProbe>,
    continues: AtomicUsize,
}

impl RedirectThenDoneProbe {
    fn new(inner: Arc<CacheProbe>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            continues: AtomicUsize::new(0),
        })
    }
}

#[async_trait::async_trait]
impl Layer for RedirectThenDoneProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        self.inner.descriptor()
    }

    async fn stat(
        &self,
        request: Request<ovstorage::StatRequest>,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ovstorage::ObjectInfo> {
        self.inner.stat(request, cancel).await
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<ReadResult> {
        self.inner.read(request, cancel).await
    }

    async fn continue_write(
        &self,
        request: Request<ovstorage::ContinueWriteRequest>,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> Result<WriteStep> {
        if self.continues.fetch_add(1, Ordering::SeqCst) == 0 {
            return Ok(WriteStep::Redirects(ovstorage::WriteRedirectBatch {
                continuation: Vec::new(),
                redirects: Vec::new(),
            }));
        }
        self.inner.continue_write(request, cancel).await
    }
}

#[tokio::test]
async fn byte_cache_mid_flight_redirect_restores_the_availability_fallback() {
    // `MutationGuard::arm` clears the availability row write-ahead. A
    // `WriteStep::Redirects` step then reports that NOTHING landed at the
    // backend, so the pre-write validator is still the current one -- and
    // `disarm_unchanged` only stops the drop clear, it does not put the row
    // back. A caller that abandons the upload there leaves the object
    // unchanged but permanently without its last-known-validator fallback.
    let tmp = tempfile::tempdir().unwrap();
    let inner = CacheProbe::new(b"payload", Vec::new());
    let backend = RedirectThenDoneProbe::new(inner.clone());
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(inner.reads.load(Ordering::SeqCst), 1);

    let step = stack
        .continue_write(empty_continue_write(address.as_str()), None)
        .await
        .unwrap();
    assert!(matches!(step, WriteStep::Redirects(_)));

    // The upload is abandoned here. A stat outage engages the availability
    // fallback: the object is unchanged, so its cached body is still current
    // and must still be servable.
    inner.set_stat_error(Some(ErrorCode::Transient));
    let served = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(collect(served).await, b"payload");
    assert_eq!(
        inner.reads.load(Ordering::SeqCst),
        1,
        "a mid-flight redirect must leave the last-known-validator fallback intact"
    );
}

#[tokio::test]
async fn byte_cache_redirect_then_done_reclaims_the_superseded_body() {
    // The other half of the same defect: with the row never restored, the
    // guard the terminal `Done` step arms reads an absent row, captures no
    // superseded validator, and reclaims nothing. The pre-upload body is then
    // orphaned for the life of an unbudgeted cache.
    let tmp = tempfile::tempdir().unwrap();
    let inner = CacheProbe::new(b"payload", Vec::new());
    let backend = RedirectThenDoneProbe::new(inner.clone());
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        content_row_count(tmp.path()),
        1,
        "the warm read leaves the object's body cached"
    );

    let step = stack
        .continue_write(empty_continue_write(address.as_str()), None)
        .await
        .unwrap();
    assert!(matches!(step, WriteStep::Redirects(_)));
    let step = stack
        .continue_write(empty_continue_write(address.as_str()), None)
        .await
        .unwrap();
    assert!(matches!(step, WriteStep::Done(_)));

    assert_eq!(
        content_row_count(tmp.path()),
        0,
        "the terminal step must reclaim the body the upload superseded"
    );
}

/// A backend that reports an empty `etag` -- the shape a validator-less origin
/// or a misconfigured S3-compatible endpoint produces. Its content changes out
/// of band while the validator stays empty.
struct EmptyEtagProbe {
    /// On-disk copy the probe's `materialize` hands back, kept in step with
    /// `content`; `None` for tests that never materialize.
    source: std::sync::Mutex<Option<std::path::PathBuf>>,
    content: std::sync::Mutex<Vec<u8>>,
    etag: std::sync::Mutex<String>,
    stat_error: std::sync::Mutex<Option<ErrorCode>>,
    reads: AtomicUsize,
}

impl EmptyEtagProbe {
    fn new(content: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            source: std::sync::Mutex::new(None),
            content: std::sync::Mutex::new(content.to_vec()),
            etag: std::sync::Mutex::new(String::new()),
            stat_error: std::sync::Mutex::new(None),
            reads: AtomicUsize::new(0),
        })
    }

    /// A probe that starts out naming versions properly, so a test can
    /// establish a real validator before the backend stops naming them.
    fn versioned(content: &[u8], etag: &str) -> Arc<Self> {
        let probe = Self::new(content);
        *probe.etag.lock().unwrap() = etag.to_string();
        probe
    }

    fn set_etag(&self, etag: &str) {
        *self.etag.lock().unwrap() = etag.to_string();
    }

    fn set_stat_error(&self, code: Option<ErrorCode>) {
        *self.stat_error.lock().unwrap() = code;
    }

    fn set_content(&self, content: &[u8]) {
        *self.content.lock().unwrap() = content.to_vec();
        if let Some(source) = self.source.lock().unwrap().as_ref() {
            std::fs::write(source, content).unwrap();
        }
    }

    /// Back this probe with a file on disk so it can serve `materialize`.
    fn with_source(self: Arc<Self>, source: std::path::PathBuf) -> Arc<Self> {
        std::fs::write(&source, self.content.lock().unwrap().clone()).unwrap();
        *self.source.lock().unwrap() = Some(source);
        self
    }

    fn info(&self, address: Url) -> ObjectInfo {
        let size = self.content.lock().unwrap().len() as u64;
        ObjectInfo {
            etag: Some(self.etag.lock().unwrap().clone()),
            // Reported as unknown so a streamed write's commit is gated by the
            // validator rule under test and not by a size mismatch against a
            // body this probe never sees.
            size: None,
            ..object_info(address, size)
        }
    }
}

#[async_trait::async_trait]
impl Layer for EmptyEtagProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        backend_descriptor("probe")
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        if let Some(code) = *self.stat_error.lock().unwrap() {
            return Err(ovstorage::Error::new(code, "scripted stat failure"));
        }
        Ok(self.info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        // Bind the bytes first: the lock guard behind a struct-literal field
        // lives to the end of the whole expression, so calling `info` (which
        // locks too) inline would deadlock against it.
        let bytes = self.content.lock().unwrap().clone();
        Ok(ReadResult::Bytes {
            bytes,
            info: self.info(request.input.address),
        })
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ovstorage::LocalDelegate> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let path = self
            .source
            .lock()
            .unwrap()
            .clone()
            .expect("this probe was built without a source file");
        Ok(ovstorage::LocalDelegate {
            path,
            info: self.info(request.input.address),
            guard: None,
        })
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let address = request.input.address.clone();
        match request.input.body {
            Body::Bytes(bytes) => self.set_content(&bytes),
            // Drained to EOF as a real streaming backend does, so the cache's
            // write tee reaches its commit rather than abandoning the fill.
            Body::Stream(mut stream) => {
                let mut content = Vec::new();
                while let Some(chunk) = stream.next_chunk() {
                    content.extend_from_slice(&chunk?);
                }
                self.set_content(&content);
            }
            _ => {}
        }
        Ok(WriteResult {
            info: self.info(address),
        })
    }
}

#[tokio::test]
async fn byte_cache_write_through_refuses_an_empty_validator() {
    // `ProvenValidator` rejects an empty etag because it cannot distinguish two
    // versions -- but the write-through path keys its fill on any `Some(etag)`,
    // the empty string included, and `lookup_etag` hands that same empty string
    // back on every later read. The first write's body is then served forever,
    // through every out-of-band change the backend reports the same way.
    let tmp = tempfile::tempdir().unwrap();
    let backend = EmptyEtagProbe::new(b"first");
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: address.clone(),
                body: Body::Bytes(b"written".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    // The object changes out of band, still reporting an empty validator.
    backend.set_content(b"changed");
    let served = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        collect(served).await,
        b"changed",
        "an empty validator proves nothing, so it must never serve a cached body"
    );
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "the read must reach the backend rather than an empty-keyed content row"
    );
}

/// A backend whose `stat` reports no validator but whose `read` does -- the
/// shape a redirecting backend presents (the follower below the cache resolves
/// the redirect, so the validator arrives with the bytes, not with the stat).
struct ReadOnlyValidatorProbe {
    inner: Arc<CacheProbe>,
}

impl ReadOnlyValidatorProbe {
    fn new(inner: Arc<CacheProbe>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

#[async_trait::async_trait]
impl Layer for ReadOnlyValidatorProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        self.inner.descriptor()
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let mut info = self.inner.stat(request, cancel).await?;
        info.etag = None;
        Ok(info)
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.inner.read(request, cancel).await
    }
}

#[tokio::test]
async fn byte_cache_fill_publishes_a_fallback_when_only_the_read_proves_a_validator() {
    // The availability fallback is what makes a brokered read survive backing
    // loss, and the fill that populates it is fenced on a snapshot taken before
    // the backend read. Gating that snapshot on the STAT's validator is gating
    // it on the wrong one: a backend that names versions only on its read (a
    // redirecting one, whose follower resolves the redirect below this layer)
    // then never snapshots, so its fill can never publish and the address has
    // no fallback at all.
    let tmp = tempfile::tempdir().unwrap();
    let inner = CacheProbe::new(b"payload", Vec::new());
    let backend = ReadOnlyValidatorProbe::new(inner.clone());
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(inner.reads.load(Ordering::SeqCst), 1);

    // The backend can no longer answer freshly: the fallback must serve the
    // body the first read proved.
    inner.set_stat_error(Some(ErrorCode::Transient));
    let served = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(collect(served).await, b"payload");
    assert_eq!(
        inner.reads.load(Ordering::SeqCst),
        1,
        "a fill whose validator came from the read must still publish a fallback"
    );
}

/// Every row in the cache index, availability rows included -- the residue a
/// read leaves behind.
fn total_row_count(dir: &std::path::Path) -> i64 {
    let conn = rusqlite::Connection::open(dir.join("state").join("index.sqlite")).unwrap();
    conn.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
        .unwrap()
}

/// A backend that has nothing at any address.
struct MissingProbe {
    reads: AtomicUsize,
}

impl MissingProbe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            reads: AtomicUsize::new(0),
        })
    }
}

#[async_trait::async_trait]
impl Layer for MissingProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        backend_descriptor("probe")
    }

    async fn stat(
        &self,
        _request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        Err(ovstorage::Error::new(ErrorCode::NotFound, "no such object"))
    }

    async fn read(
        &self,
        _request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Err(ovstorage::Error::new(ErrorCode::NotFound, "no such object"))
    }
}

#[tokio::test]
async fn byte_cache_probing_a_missing_address_leaves_no_rows() {
    // Snapshotting seeds an absent row, so a read that will never publish
    // against that seed has to take it back. An asset resolver walking
    // candidate paths would otherwise leave a row and a CAS blob per miss, and
    // the default cache has no size budget to reclaim them.
    let tmp = tempfile::tempdir().unwrap();
    let backend = MissingProbe::new();
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;

    for candidate in ["mem:///a", "mem:///b", "mem:///c"] {
        let missed = stack.read(read_request(candidate), None).await;
        assert_eq!(missed.unwrap_err().code(), ErrorCode::NotFound);
    }

    assert_eq!(
        total_row_count(tmp.path()),
        0,
        "a probed path that does not exist must leave no residue"
    );
}

/// A backend whose `read` hands back a `LocalDelegate` and whose `stat` can be
/// scripted to fail -- the shape the broker warms and then has to survive the
/// backing store going away under.
struct WarmDelegateProbe {
    path: std::path::PathBuf,
    size: u64,
    etag: String,
    reads: AtomicUsize,
    stat_error: std::sync::Mutex<Option<ErrorCode>>,
}

impl WarmDelegateProbe {
    fn new(path: std::path::PathBuf, etag: &str) -> Arc<Self> {
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Arc::new(Self {
            path,
            size,
            etag: etag.to_string(),
            reads: AtomicUsize::new(0),
            stat_error: std::sync::Mutex::new(None),
        })
    }

    fn set_stat_error(&self, code: Option<ErrorCode>) {
        *self.stat_error.lock().unwrap() = code;
    }

    fn info(&self, address: Url) -> ObjectInfo {
        ObjectInfo {
            etag: Some(self.etag.clone()),
            ..object_info(address, self.size)
        }
    }
}

#[async_trait::async_trait]
impl Layer for WarmDelegateProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        backend_descriptor("probe")
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        if let Some(code) = *self.stat_error.lock().unwrap() {
            return Err(ovstorage::Error::new(code, "scripted stat failure"));
        }
        Ok(self.info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(ovstorage::ReadResult::LocalDelegate(
            ovstorage::LocalDelegate {
                path: self.path.clone(),
                info: self.info(request.input.address),
                guard: None,
            },
        ))
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        Ok(WriteResult {
            info: self.info(request.input.address),
        })
    }
}

#[tokio::test]
async fn byte_cache_delegate_read_keeps_an_established_fallback() {
    // The pass-through delegate arm drops an armed guard, which clears the
    // availability row. That is only reachable on a strict-path MISS: a read
    // whose validator already has a content row is answered from the cache
    // before the backend read happens at all. So an established fallback --
    // row plus body -- is not exposed to it.
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("delegate.bin");
    std::fs::write(&source, b"delegate-body").unwrap();
    let backend = WarmDelegateProbe::new(source.clone(), "etag-W");
    // The DEFAULT composition: no delegate warming.
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("file:///obj").unwrap();

    // Establish the fallback: a write-through publishes the row AND fills the
    // body under the same validator.
    stack
        .write(
            Request::new(WriteRequest {
                address: address.clone(),
                body: Body::Bytes(b"delegate-body".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    // A plain (non-buffering) delegate read -- the arm in question.
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();

    backend.set_stat_error(Some(ErrorCode::Transient));
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        0,
        "an established fallback must survive a plain delegate read"
    );
}

#[tokio::test]
async fn byte_cache_warmed_delegate_keeps_the_fallback_it_published() {
    // Delegate warming exists so a brokered read survives backing-store loss:
    // it spools the delegate into the CAS and publishes the availability row
    // that makes the body discoverable when the backend cannot answer. The
    // warm path runs under its own guard, so the caller's guard must be handed
    // over rather than left armed -- an outer guard still armed when the warm
    // returns clears the very row the warm just published, leaving the CAS body
    // cached but unreachable through the fallback.
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("delegate.bin");
    std::fs::write(&source, b"delegate-body").unwrap();
    let backend = WarmDelegateProbe::new(source.clone(), "etag-W");
    let stack = byte_cache_stack_with_config(
        backend.clone(),
        byte_cache_config_warm_delegates(tmp.path(), 1024),
    )
    .await;

    let warmed = stack.read(read_request("file:///obj"), None).await.unwrap();
    match warmed {
        ReadResult::LocalDelegate(local) => {
            assert_ne!(
                local.path, source,
                "the delegate must be spooled into the CAS"
            );
        }
        other => panic!("expected a local delegate, got {other:?}"),
    }
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);

    // The backing store goes away. The warmed body is the whole point of the
    // composition, and the availability row is what finds it.
    backend.set_stat_error(Some(ErrorCode::Transient));
    stack.read(read_request("file:///obj"), None).await.unwrap();
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "a warmed delegate must stay reachable through the fallback it published"
    );
}

#[tokio::test]
async fn byte_cache_streamed_write_through_refuses_an_empty_validator() {
    // The streamed write tee commits on `(Some(put), Some(etag))`, which
    // accepts the empty string exactly as the buffered path did. Nothing can
    // ever read that row back -- the lookup refuses an empty validator -- so it
    // is a content row per address that no eviction reaches on an unbudgeted
    // cache.
    let tmp = tempfile::tempdir().unwrap();
    let backend = EmptyEtagProbe::new(b"first");
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    stack
        .write(
            Request::new(WriteRequest {
                address: address.clone(),
                body: stream_body(b"streamed"),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        content_row_count(tmp.path()),
        0,
        "a validator that cannot distinguish two versions must key nothing"
    );
}

#[tokio::test]
async fn byte_cache_empty_etag_read_clears_a_real_validator() {
    // An empty etag proves nothing about WHICH version was read, but the read
    // still happened -- and it observed a version the row's older, real
    // validator no longer describes. Leaving that row is the one outcome that
    // serves superseded bytes: a later stat outage engages the fallback and
    // hands back the body of a version this read disproved.
    let tmp = tempfile::tempdir().unwrap();
    let backend = EmptyEtagProbe::versioned(b"first", "v1");
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    // A real validator, published and filled.
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);

    // The object changes, and the backend stops naming versions.
    backend.set_content(b"changed");
    backend.set_etag("");
    let served = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(collect(served).await, b"changed");

    // The backend can no longer answer freshly. The fallback must have nothing
    // to say rather than answering with the version just disproved.
    backend.set_stat_error(Some(ErrorCode::Transient));
    let after = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        collect(after).await,
        b"changed",
        "an empty-etag read must clear a real validator it superseded"
    );
}

#[tokio::test]
async fn byte_cache_empty_etag_materialize_clears_a_real_validator() {
    // `materialize` is a read-family op with the same obligation as `read`: a
    // result that reports an EMPTY etag has observed a version, so a row naming
    // an older real validator no longer describes the object. Discarding only
    // an unused seed is not enough -- the seed discard deliberately keeps a row
    // that names a real validator, which is precisely the row that is now
    // wrong.
    let tmp = tempfile::tempdir().unwrap();
    let backend =
        EmptyEtagProbe::versioned(b"first", "v1").with_source(tmp.path().join("source.bin"));
    let stack = byte_cache_stack_with_config(backend.clone(), byte_cache_config(tmp.path())).await;
    let address = Url::parse("mem:///obj").unwrap();

    // A real validator, published and filled.
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();

    // The object changes, and the backend stops naming versions.
    backend.set_content(b"changed");
    backend.set_etag("");
    stack
        .materialize(read_request(address.as_str()), None)
        .await
        .unwrap();

    // The backend can no longer answer freshly.
    backend.set_stat_error(Some(ErrorCode::Transient));
    let after = stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        collect(after).await,
        b"changed",
        "an empty-etag materialize must clear a real validator it superseded"
    );
}
