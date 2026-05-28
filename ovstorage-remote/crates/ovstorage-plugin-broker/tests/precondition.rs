// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Boundary-sanity coverage for the broker-client Backend plugin.
//!
//! Mirrors the nucleus plugin's `tests/precondition.rs` shape but is
//! intentionally smaller. The systemic-enforcement checklist born from
//! the PR 42 / PR 43 / PR 4 reviews collapses dramatically for the
//! broker plugin because the broker wire (defined in
//! `ovstorage-broker-protocol/proto/ovstorage/v1/broker.proto`) is a
//! *faithful forwarder* of the Backend SPI: the wire carries the
//! SPI's `if_match` / `if_source` / `if_dest` etag strings on every
//! conditional op; `ListOptions` carries `recursive`, `max_results`,
//! and `page_token` verbatim; `CopyOptions` / `RenameOptions` mirror
//! the SPI's single `if_match` shape. So no `require_*_only_if_match`
//! plugin-side refusals apply.
//!
//! What this file covers:
//!
//! 1. **Range validation** — the only Pattern D / boundary-sanity
//!    refusal that does apply: inverted `ReadOptions::range`
//!    (`end_inclusive < start`) must be rejected with
//!    `InvalidArgument` BEFORE the plugin touches the transport.
//!
//! 2. **`write_redirect` size_hint forwarding** — pinning the design
//!    decision: the broker daemon's `should_redirect_write` accepts
//!    `Option<u64>` and treats unknown size as "do redirect" when an
//!    endpoint is configured (see `ovstorage-broker/src/policy.rs:27`
//!    and `broker.rs:568`). The plugin must therefore *forward*
//!    `size_hint = None`, not refuse it — which is what this test
//!    pins.
//!
//! 3. **Positive forwarding** — confirms the full precondition shape
//!    (`if_match` / `if_source` / `if_dest` etag strings) crosses the
//!    plugin boundary intact for read/write/copy/rename, and that
//!    `recursive`/`page_token` on `list` / `list_versions` are not
//!    silently dropped or refused. These tests guard against a future
//!    refactor accidentally introducing a narrowing helper.
//!
//! The plugin's only `tokio::spawn` (write-stream chunk pump) and
//! every `std::thread::spawn` (watch-directory bridge, OAuth flow
//! bridge, upstream-auth bridge) are RPC-scoped, not background
//! credential-refresh loops; credential refresh is on-demand through
//! the broker daemon's `Auth` streaming RPC (see
//! `auth::DiscoveryState::token_needs_refresh`). Pattern H is
//! satisfied by construction; no test required.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::stream;
use ovstorage_broker_protocol::{
    AddressRootsChangeStream, BrokerClientTransport, BrokerClientWatchDirectoryStream,
    RegisterCredentialPayload, UpstreamAuthStream,
};
use ovstorage_plugin::shim::Backend;
use ovstorage_plugin::{
    AccessDecision, AccessOps, AddressRoot, BackendId, Body, ByteRange, ChecksumSet, CopyOptions,
    CreateDirectoryOptions, DeleteDirectoryOptions, DeleteOptions, ErrorCode, IfDestExists,
    ListOptions, ListPage, ListVersionsOptions, ObjectInfo, ObjectKind, ReadOptions, ReadResult,
    RedirectResultBatch, RenameOptions, ResolvedTarget, Result, StatOptions, UpdateMetadataOptions,
    Url, WatchDirectoryOptions, WriteOptions, WriteRedirectBatch, WriteResult, WriteStep, address,
};
use ovstorage_plugin_broker::BrokerClientBackend;

// === Helpers ===

fn full_etag() -> String {
    "etag-abc".into()
}

fn target(addr: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId(format!("broker:test:{addr}")),
        resolved_address: address::parse(addr).expect("address parses"),
    }
}

fn placeholder_info(addr: &str) -> ObjectInfo {
    ObjectInfo {
        address: address::parse(addr).expect("placeholder address parses"),
        kind: ObjectKind::File,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

fn placeholder_write_result(addr: &str) -> WriteResult {
    WriteResult {
        info: placeholder_info(addr),
    }
}

/// Records every transport call the SPI dispatches. The `Backend`
/// methods we exercise are read-only against the recorder, so a
/// `std::sync::Mutex` is sufficient — no async-aware lock needed.
#[derive(Default)]
struct RecordingTransport {
    read: Mutex<Option<(Url, ReadOptions)>>,
    write: Mutex<Option<(Url, WriteOptions)>>,
    write_redirect: Mutex<Option<(Url, WriteOptions)>>,
    list: Mutex<Option<(Url, ListOptions)>>,
    list_versions: Mutex<Option<(Url, ListVersionsOptions)>>,
    copy: Mutex<Option<(Url, Url, CopyOptions)>>,
    rename: Mutex<Option<(Url, Url, RenameOptions)>>,
}

impl RecordingTransport {
    fn last_read(&self) -> Option<(Url, ReadOptions)> {
        self.read.lock().unwrap().clone()
    }
    fn last_write(&self) -> Option<(Url, WriteOptions)> {
        self.write.lock().unwrap().clone()
    }
    fn last_write_redirect(&self) -> Option<(Url, WriteOptions)> {
        self.write_redirect.lock().unwrap().clone()
    }
    fn last_list(&self) -> Option<(Url, ListOptions)> {
        self.list.lock().unwrap().clone()
    }
    fn last_list_versions(&self) -> Option<(Url, ListVersionsOptions)> {
        self.list_versions.lock().unwrap().clone()
    }
    fn last_copy(&self) -> Option<(Url, Url, CopyOptions)> {
        self.copy.lock().unwrap().clone()
    }
    fn last_rename(&self) -> Option<(Url, Url, RenameOptions)> {
        self.rename.lock().unwrap().clone()
    }
}

#[async_trait]
impl BrokerClientTransport for RecordingTransport {
    async fn list_address_roots(&self) -> Result<Vec<AddressRoot>> {
        Ok(Vec::new())
    }

    async fn watch_address_roots(&self) -> Result<AddressRootsChangeStream> {
        Ok(Box::pin(stream::empty()))
    }

    async fn stat(&self, address: Url, _options: StatOptions) -> Result<ObjectInfo> {
        Ok(placeholder_info(address.as_str()))
    }

    async fn read(&self, address: Url, options: ReadOptions) -> Result<ReadResult> {
        *self.read.lock().unwrap() = Some((address.clone(), options));
        Ok(ReadResult::Bytes {
            bytes: Vec::new(),
            info: placeholder_info(address.as_str()),
        })
    }

    async fn write(&self, address: Url, _body: Body, options: WriteOptions) -> Result<WriteStep> {
        *self.write.lock().unwrap() = Some((address.clone(), options));
        Ok(WriteStep::Done(placeholder_write_result(address.as_str())))
    }

    async fn write_redirect(
        &self,
        address: Url,
        options: WriteOptions,
    ) -> Result<WriteRedirectBatch> {
        *self.write_redirect.lock().unwrap() = Some((address, options));
        Ok(WriteRedirectBatch {
            continuation: Vec::new(),
            redirects: Vec::new(),
        })
    }

    async fn continue_write(
        &self,
        address: Url,
        _redirects: WriteRedirectBatch,
        _results: RedirectResultBatch,
    ) -> Result<WriteStep> {
        Ok(WriteStep::Done(placeholder_write_result(address.as_str())))
    }

    async fn delete(&self, _address: Url, _options: DeleteOptions) -> Result<()> {
        Ok(())
    }

    async fn list(&self, prefix: Url, options: ListOptions) -> Result<ListPage> {
        *self.list.lock().unwrap() = Some((prefix, options));
        Ok(ListPage {
            items: Vec::new(),
            next_page_token: None,
        })
    }

    async fn list_versions(
        &self,
        address: Url,
        options: ListVersionsOptions,
    ) -> Result<Vec<ObjectInfo>> {
        *self.list_versions.lock().unwrap() = Some((address, options));
        Ok(Vec::new())
    }

    async fn get_latest_version(&self, address: Url) -> Result<ObjectInfo> {
        Ok(placeholder_info(address.as_str()))
    }

    async fn watch_directory(
        &self,
        _prefix: Url,
        _opts: WatchDirectoryOptions,
    ) -> Result<BrokerClientWatchDirectoryStream> {
        Ok(Box::new(std::iter::empty()))
    }

    async fn create_directory(
        &self,
        address: Url,
        _options: CreateDirectoryOptions,
    ) -> Result<ObjectInfo> {
        Ok(placeholder_info(address.as_str()))
    }

    async fn delete_directory(
        &self,
        _address: Url,
        _options: DeleteDirectoryOptions,
    ) -> Result<()> {
        Ok(())
    }

    async fn copy(
        &self,
        source: Url,
        destination: Url,
        options: CopyOptions,
    ) -> Result<WriteResult> {
        let dest_str = destination.as_str().to_owned();
        *self.copy.lock().unwrap() = Some((source, destination, options));
        Ok(placeholder_write_result(&dest_str))
    }

    async fn rename(&self, source: Url, destination: Url, options: RenameOptions) -> Result<()> {
        *self.rename.lock().unwrap() = Some((source, destination, options));
        Ok(())
    }

    async fn update_metadata(
        &self,
        address: Url,
        _options: UpdateMetadataOptions,
    ) -> Result<ObjectInfo> {
        Ok(placeholder_info(address.as_str()))
    }

    async fn check_access(&self, _address: Url, _operations: AccessOps) -> Result<AccessDecision> {
        Ok(AccessDecision {
            allowed: true,
            denied_ops: AccessOps::default(),
            reason: None,
        })
    }

    async fn auth_stream(&self, _address: Url) -> Result<UpstreamAuthStream> {
        Ok(Box::pin(stream::empty()))
    }

    async fn register_credential(
        &self,
        _address: Url,
        _payload: RegisterCredentialPayload,
    ) -> Result<()> {
        Ok(())
    }
}

fn backend_with(transport: Arc<RecordingTransport>) -> BrokerClientBackend {
    BrokerClientBackend::new_for_tests(
        "https://broker.example.com",
        transport as Arc<dyn BrokerClientTransport>,
    )
}

// === Boundary sanity ===

#[tokio::test]
async fn read_inverted_range_returns_invalid_argument() {
    let recorder = Arc::new(RecordingTransport::default());
    let backend = backend_with(recorder.clone());

    let opts = ReadOptions {
        range: Some(ByteRange {
            start: 10,
            end_inclusive: Some(5),
        }),
        ..Default::default()
    };

    let err = backend
        .read(target("https://broker.example.com/obj"), opts, None)
        .await
        .expect_err("inverted range must be rejected");

    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("inverted byte range"),
        "expected boundary-sanity message; got: {}",
        err.message(),
    );
    // Pre-wire refusal: transport must not see the call.
    assert!(
        recorder.last_read().is_none(),
        "inverted range must fail before reaching the transport"
    );
}

#[tokio::test]
async fn read_valid_range_forwards_faithfully() {
    let recorder = Arc::new(RecordingTransport::default());
    let backend = backend_with(recorder.clone());

    let range = ByteRange {
        start: 5,
        end_inclusive: Some(10),
    };
    let opts = ReadOptions {
        range: Some(range.clone()),
        ..Default::default()
    };
    backend
        .read(target("https://broker.example.com/obj"), opts, None)
        .await
        .expect("valid range must pass");

    let (_addr, observed) = recorder.last_read().expect("transport saw the call");
    assert_eq!(observed.range, Some(range));
}

#[tokio::test]
async fn write_redirect_forwards_none_size_hint_faithfully() {
    // Pins the design decision (see `BrokerClientBackend::write_redirect`
    // doc-comment): broker daemon's `should_redirect_write` accepts
    // `Option<u64>` and routes unknown-size writes to the configured
    // `write_redirect_endpoint`; refusing here would deny a path the
    // wire fully supports.
    let recorder = Arc::new(RecordingTransport::default());
    let backend = backend_with(recorder.clone());

    let opts = WriteOptions {
        size_hint: None,
        ..Default::default()
    };
    backend
        .write_redirect(target("https://broker.example.com/obj"), opts, None)
        .await
        .expect("None size_hint must forward, not refuse");

    let (_addr, observed) = recorder
        .last_write_redirect()
        .expect("transport saw the call");
    assert!(
        observed.size_hint.is_none(),
        "size_hint must reach the wire unchanged"
    );
}

// === Positive forwarding ===

#[tokio::test]
async fn read_with_full_object_identity_passes_through() {
    let recorder = Arc::new(RecordingTransport::default());
    let backend = backend_with(recorder.clone());

    let opts = ReadOptions {
        if_match: Some(full_etag()),
        ..Default::default()
    };
    backend
        .read(target("https://broker.example.com/obj"), opts, None)
        .await
        .expect("read forwards");

    let (_addr, observed) = recorder.last_read().expect("transport saw the call");
    assert_eq!(
        observed.if_match.as_deref(),
        Some(full_etag().as_str()),
        "etag must cross the boundary intact"
    );
}

#[tokio::test]
async fn write_with_full_object_identity_passes_through() {
    let recorder = Arc::new(RecordingTransport::default());
    let backend = backend_with(recorder.clone());

    let opts = WriteOptions {
        if_dest: IfDestExists::MatchEtag(full_etag()),
        size_hint: Some(99),
        ..Default::default()
    };
    backend
        .write(
            target("https://broker.example.com/obj"),
            Vec::new(),
            opts,
            None,
        )
        .await
        .expect("write forwards");

    let (_addr, observed) = recorder.last_write().expect("transport saw the call");
    assert!(matches!(
        &observed.if_dest,
        IfDestExists::MatchEtag(s) if s == &full_etag()
    ));
    assert_eq!(observed.size_hint, Some(99));
}

#[tokio::test]
async fn copy_with_if_match_passes_through() {
    let recorder = Arc::new(RecordingTransport::default());
    let backend = backend_with(recorder.clone());

    let opts = CopyOptions {
        if_source: Some(full_etag()),
        if_dest: IfDestExists::Overwrite,
        message: Some("annotated copy".into()),
    };
    backend
        .copy(
            target("https://broker.example.com/src"),
            target("https://broker.example.com/dst"),
            opts,
            None,
        )
        .await
        .expect("copy forwards");

    let (_src, _dst, observed) = recorder.last_copy().expect("transport saw the call");
    assert_eq!(observed.if_source.as_deref(), Some(full_etag().as_str()));
    assert_eq!(observed.message.as_deref(), Some("annotated copy"));
}

#[tokio::test]
async fn rename_with_if_match_passes_through() {
    let recorder = Arc::new(RecordingTransport::default());
    let backend = backend_with(recorder.clone());

    let opts = RenameOptions {
        if_source: Some(full_etag()),
        if_dest: IfDestExists::Overwrite,
        message: Some("annotated rename".into()),
    };
    backend
        .rename(
            target("https://broker.example.com/src"),
            target("https://broker.example.com/dst"),
            opts,
            None,
        )
        .await
        .expect("rename forwards");

    let (_src, _dst, observed) = recorder.last_rename().expect("transport saw the call");
    assert_eq!(observed.if_source.as_deref(), Some(full_etag().as_str()));
    assert_eq!(observed.message.as_deref(), Some("annotated rename"));
}

#[tokio::test]
async fn list_with_recursive_passes_through() {
    let recorder = Arc::new(RecordingTransport::default());
    let backend = backend_with(recorder.clone());

    let opts = ListOptions {
        recursive: true,
        max_results: Some(50),
        page_token: Some("cursor-1".into()),
        full_metadata: true,
    };
    backend
        .list(target("https://broker.example.com/dir/"), opts, None)
        .await
        .expect("list forwards");

    let (_prefix, observed) = recorder.last_list().expect("transport saw the call");
    assert!(observed.recursive, "recursive must forward");
    assert_eq!(observed.max_results, Some(50));
    assert_eq!(observed.page_token.as_deref(), Some("cursor-1"));
    assert!(observed.full_metadata);
}

#[tokio::test]
async fn list_versions_with_page_token_passes_through() {
    let recorder = Arc::new(RecordingTransport::default());
    let backend = backend_with(recorder.clone());

    let opts = ListVersionsOptions {
        max_results: Some(25),
        page_token: Some("versions-cursor".into()),
    };
    backend
        .list_versions(target("https://broker.example.com/obj"), opts, None)
        .await
        .expect("list_versions forwards");

    let (_addr, observed) = recorder
        .last_list_versions()
        .expect("transport saw the call");
    assert_eq!(observed.max_results, Some(25));
    assert_eq!(observed.page_token.as_deref(), Some("versions-cursor"));
}
