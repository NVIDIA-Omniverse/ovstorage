// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registry-as-spec conformance pass for the broker-client plugin
//! (RFC-0066): iterate every named scenario in
//! `ovstorage_plugin_test::ScenarioRegistry::with_defaults()` and either
//! DRIVE it against the plugin or SKIP it with a concrete reason.
//! Recorder-based `expected_calls` verification is test-backend-only, so
//! driven scenarios assert the observable outcome (success shape or the
//! exact `failure_contract` error code) and push
//! `ScenarioReport::passed`.
//!
//! Hermetic setup: the plugin is stood up through
//! `BrokerClientBackend::new_for_tests` against an in-process
//! [`ScriptedTransport`] (the same seam `tests/precondition.rs` and the
//! `layer.rs` unit tests use) — no network, no external processes.
//!
//! The broker-client plugin is a *faithful forwarder* of the Backend SPI
//! over the broker wire: capability enforcement, type-mismatch
//! classification, and data-preservation semantics live in the broker
//! daemon / whichever upstream backend it dispatches to. What IS
//! plugin-observable — and what the driven scenarios pin — is that each
//! op is exactly one transport RPC, that options (`if_dest`,
//! `recursive`, pagination) cross the plugin boundary intact, and that
//! the daemon's typed error codes surface verbatim. Scenarios whose
//! essence is a plugin-side self-gate the forwarder deliberately lacks
//! (or an upstream-enforced invariant a scripted transport could only
//! echo) skip visibly.
//!
//! Capability gating follows the plugin's real capability channel: the
//! broker publishes a `Capabilities` profile on its address roots, the
//! scripted transport publishes one such profile, and every scenario's
//! `required_capabilities` / `required_profile` are checked against it
//! before a driver is considered (`has_real_directories` is not
//! advertised, so the `DirectoriesReal` scenarios gate off).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::StreamExt as _;
use ovstorage_broker_protocol::{BrokerClientTransport, BrokerClientWatchDirectoryStream};
use ovstorage_plugin::{
    AccessDecision, AccessOps, AddressRoot, AddressVisibility, BackendId, Body, Capabilities,
    ChecksumSet, ConfigLayer, CopyOptions, CreateDirectoryOptions, DeleteDirectoryOptions,
    DeleteOptions, Error, ErrorCode, IfDestExists, ListOptions, ListPage, ListVersionsOptions,
    ObjectInfo, ObjectKind, ReadOptions, ReadResult, RedirectResultBatch, RenameOptions,
    ResolvedTarget, Result, RouteSource, StatOptions, UpdateMetadataOptions, Url, UserMetadata,
    WatchDirectoryOptions, WriteOptions, WriteRedirectBatch, WriteResult, WriteStep, address,
};
use ovstorage_plugin_broker::BrokerClientBackend;
use ovstorage_plugin_test::{
    ConformanceReport, Scenario, ScenarioRegistry, ScenarioReport, ScenarioRunner,
};

// === Scripted in-process broker transport ===

/// The `Capabilities` profile the scripted broker publishes on its root.
/// The broker wire carries every conditional-op knob verbatim
/// (`if_match` / `if_source` / `if_dest`, `recursive`, pagination), so
/// the published profile advertises the conditional/copy/rename/redirect
/// families. `has_real_directories` stays false: directory semantics are
/// whatever the upstream behind the daemon provides — the wire itself
/// carries no real-directory guarantee.
fn broker_published_capabilities() -> Capabilities {
    let mut caps = Capabilities::empty();
    caps.supports_write = true;
    caps.supports_write_stream = true;
    caps.supports_write_redirect = true;
    caps.supports_delete = true;
    caps.supports_list = true;
    caps.supports_recursive_list = true;
    caps.supports_create_directory = true;
    caps.supports_delete_directory = true;
    caps.supports_no_overwrite_write = true;
    caps.supports_if_match_write = true;
    caps.supports_server_side_copy = true;
    caps.supports_server_side_rename = true;
    caps.supports_copy = true;
    caps.supports_rename = true;
    caps.supports_atomic_rename = true;
    caps.supports_version_listing = true;
    caps
}

fn canned_info(address: &Url, kind: ObjectKind, size: Option<u64>) -> ObjectInfo {
    ObjectInfo {
        address: address.clone(),
        kind,
        etag: Some("etag-1".into()),
        version: None,
        size,
        mtime: None,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

/// Models the broker daemon: records every RPC in dispatch order,
/// captures the options that crossed the wire for fidelity assertions,
/// and refuses a method with a scripted typed error when told to (the
/// stand-in for a daemon-side refusal such as the no-overwrite
/// `AlreadyExists`).
#[derive(Default)]
struct ScriptedTransport {
    calls: Mutex<Vec<&'static str>>,
    refusals: Mutex<HashMap<&'static str, ErrorCode>>,
    write_options: Mutex<Option<WriteOptions>>,
    rename_options: Mutex<Option<RenameOptions>>,
    list_options: Mutex<Vec<ListOptions>>,
}

impl ScriptedTransport {
    /// Script `method` to refuse with `code` (after recording the call —
    /// the RPC did reach the wire).
    fn refuse(&self, method: &'static str, code: ErrorCode) {
        self.refusals.lock().unwrap().insert(method, code);
    }

    fn record(&self, method: &'static str) -> Result<()> {
        self.calls.lock().unwrap().push(method);
        if let Some(code) = self.refusals.lock().unwrap().get(method) {
            return Err(Error::new(
                *code,
                format!("scripted broker refusal on {method}"),
            ));
        }
        Ok(())
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    fn last_write_options(&self) -> Option<WriteOptions> {
        self.write_options.lock().unwrap().clone()
    }

    fn last_rename_options(&self) -> Option<RenameOptions> {
        self.rename_options.lock().unwrap().clone()
    }

    fn observed_list_options(&self) -> Vec<ListOptions> {
        self.list_options.lock().unwrap().clone()
    }
}

#[async_trait]
impl BrokerClientTransport for ScriptedTransport {
    async fn list_address_roots(&self) -> Result<Vec<AddressRoot>> {
        self.record("list_address_roots")?;
        Ok(vec![AddressRoot {
            address: address::parse("broker://host/").expect("root parses"),
            display_name: None,
            backend_kind: "broker".into(),
            connection_id: None,
            capabilities: broker_published_capabilities(),
            source: RouteSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            visibility: AddressVisibility::Visible,
            user_metadata: UserMetadata::new(),
        }])
    }

    async fn stat(&self, address: Url, _options: StatOptions) -> Result<ObjectInfo> {
        self.record("stat")?;
        Ok(canned_info(&address, ObjectKind::File, Some(0)))
    }

    async fn read(&self, address: Url, _options: ReadOptions) -> Result<ReadResult> {
        self.record("read")?;
        Ok(ReadResult::Stream {
            stream: Box::pin(futures::stream::empty()),
            info: canned_info(&address, ObjectKind::File, Some(0)),
        })
    }

    async fn write(&self, address: Url, body: Body, options: WriteOptions) -> Result<WriteStep> {
        // Capture the options BEFORE the scripted refusal: they reached the
        // wire either way, and the refused drivers assert on them.
        *self.write_options.lock().unwrap() = Some(options);
        self.record("write")?;
        let size = match &body {
            Body::Bytes(bytes) => Some(bytes.len() as u64),
            _ => None,
        };
        Ok(WriteStep::Done(WriteResult {
            info: canned_info(&address, ObjectKind::File, size),
        }))
    }

    async fn write_redirect(
        &self,
        _address: Url,
        _options: WriteOptions,
    ) -> Result<WriteRedirectBatch> {
        self.record("write_redirect")?;
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
        self.record("continue_write")?;
        Ok(WriteStep::Done(WriteResult {
            info: canned_info(&address, ObjectKind::File, None),
        }))
    }

    async fn delete(&self, _address: Url, _options: DeleteOptions) -> Result<()> {
        self.record("delete")?;
        Ok(())
    }

    /// Server-shaped pages, exactly as the daemon would return them: the
    /// flat page folds one marker + one file and carries a live
    /// continuation token; the recursive page surfaces the nested file.
    async fn list(&self, prefix: Url, options: ListOptions) -> Result<ListPage> {
        self.record("list")?;
        self.list_options.lock().unwrap().push(options.clone());
        let item = |suffix: &str, kind: ObjectKind| {
            canned_info(
                &prefix.join(suffix).expect("scripted key joins"),
                kind,
                Some(0),
            )
        };
        Ok(if options.recursive {
            ListPage {
                items: vec![
                    item("a.txt", ObjectKind::File),
                    item("team/file.txt", ObjectKind::File),
                ],
                next_page_token: None,
            }
        } else {
            ListPage {
                items: vec![
                    item("team/", ObjectKind::DirectoryMarker),
                    item("a.txt", ObjectKind::File),
                ],
                next_page_token: Some("cursor-2".into()),
            }
        })
    }

    async fn list_versions(
        &self,
        _address: Url,
        _options: ListVersionsOptions,
    ) -> Result<Vec<ObjectInfo>> {
        self.record("list_versions")?;
        Ok(Vec::new())
    }

    async fn get_latest_version(&self, address: Url) -> Result<ObjectInfo> {
        self.record("get_latest_version")?;
        Ok(canned_info(&address, ObjectKind::File, Some(0)))
    }

    async fn watch_directory(
        &self,
        _prefix: Url,
        _opts: WatchDirectoryOptions,
    ) -> Result<BrokerClientWatchDirectoryStream> {
        self.record("watch_directory")?;
        Ok(Box::new(std::iter::empty()))
    }

    async fn create_directory(
        &self,
        address: Url,
        _options: CreateDirectoryOptions,
    ) -> Result<ObjectInfo> {
        self.record("create_directory")?;
        Ok(canned_info(&address, ObjectKind::Directory, None))
    }

    async fn delete_directory(
        &self,
        _address: Url,
        _options: DeleteDirectoryOptions,
    ) -> Result<()> {
        self.record("delete_directory")?;
        Ok(())
    }

    async fn copy(
        &self,
        _source: Url,
        destination: Url,
        _options: CopyOptions,
    ) -> Result<WriteResult> {
        self.record("copy")?;
        Ok(WriteResult {
            info: canned_info(&destination, ObjectKind::File, Some(0)),
        })
    }

    async fn rename(&self, _source: Url, _destination: Url, options: RenameOptions) -> Result<()> {
        // Same as `write`: capture before the scripted refusal.
        *self.rename_options.lock().unwrap() = Some(options);
        self.record("rename")?;
        Ok(())
    }

    async fn update_metadata(
        &self,
        address: Url,
        _options: UpdateMetadataOptions,
    ) -> Result<ObjectInfo> {
        self.record("update_metadata")?;
        Ok(canned_info(&address, ObjectKind::File, Some(0)))
    }

    async fn check_access(&self, _address: Url, _operations: AccessOps) -> Result<AccessDecision> {
        self.record("check_access")?;
        Ok(AccessDecision {
            allowed: true,
            denied_ops: AccessOps::default(),
            reason: None,
        })
    }
}

// === Helpers ===

fn scripted_backend() -> (BrokerClientBackend, Arc<ScriptedTransport>) {
    let transport = Arc::new(ScriptedTransport::default());
    let backend = BrokerClientBackend::new_for_tests(
        "https://broker.example.com",
        transport.clone() as Arc<dyn BrokerClientTransport>,
    );
    (backend, transport)
}

fn target(addr: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId(format!("broker:test:{addr}")),
        resolved_address: address::parse(addr).expect("address parses"),
    }
}

fn pass(scenario: &Scenario) -> ScenarioReport {
    ScenarioReport::passed(scenario, Vec::new())
}

fn fail(scenario: &Scenario, reason: String) -> ScenarioReport {
    ScenarioReport::failed(scenario, reason, Vec::new())
}

/// `true` iff the broker-published profile advertises `name`. Unknown
/// capability names (a future registry addition) read as unsupported, so
/// the scenario skips visibly instead of driving vacuously.
fn capability_supported(caps: &Capabilities, name: &str) -> bool {
    match name {
        "supports_no_overwrite_write" => caps.supports_no_overwrite_write,
        "supports_if_match_write" => caps.supports_if_match_write,
        "supports_server_side_copy" => caps.supports_server_side_copy,
        "supports_server_side_rename" => caps.supports_server_side_rename,
        "supports_atomic_rename" => caps.supports_atomic_rename,
        "supports_write_redirect" => caps.supports_write_redirect,
        "supports_watch_directory" => caps.supports_watch_directory,
        "has_real_directories" => caps.has_real_directories,
        _ => false,
    }
}

/// The skip reason when `scenario`'s `required_capabilities` are not in
/// the broker-published profile, or `None` when the gate passes.
fn capability_gap(scenario: &Scenario, caps: &Capabilities) -> Option<String> {
    let missing: Vec<&str> = scenario
        .required_capabilities
        .iter()
        .copied()
        .filter(|name| !capability_supported(caps, name))
        .collect();
    (!missing.is_empty()).then(|| {
        format!(
            "requires {:?}-profile capabilities {missing:?} that the broker's published \
             roots do not advertise (the broker-client forwards the upstream profile \
             verbatim and adds none of its own)",
            scenario.required_profile
        )
    })
}

// === Driven scenarios ===

/// stat → exactly one forwarded RPC, materializing an ObjectInfo.
async fn drive_stat_basic_objectinfo(scenario: &Scenario) -> ScenarioReport {
    let (backend, transport) = scripted_backend();
    let info = match backend
        .stat(
            target("broker://host/obj.txt"),
            StatOptions::default(),
            None,
        )
        .await
    {
        Ok(info) => info,
        Err(err) => return fail(scenario, format!("stat failed: {err}")),
    };
    if info.kind != ObjectKind::File {
        return fail(scenario, format!("expected File kind, got {:?}", info.kind));
    }
    if transport.calls() != ["stat"] {
        return fail(
            scenario,
            format!("stat must be exactly one RPC, saw {:?}", transport.calls()),
        );
    }
    pass(scenario)
}

/// The daemon's typed `NotFound` surfaces verbatim — no local retry, no
/// code remapping — from exactly one RPC.
async fn drive_stat_not_found(scenario: &Scenario) -> ScenarioReport {
    let (backend, transport) = scripted_backend();
    transport.refuse("stat", ErrorCode::NotFound);
    match backend
        .stat(
            target("broker://host/missing.txt"),
            StatOptions::default(),
            None,
        )
        .await
    {
        Err(err) if err.code() == ErrorCode::NotFound => {
            if transport.calls() != ["stat"] {
                return fail(
                    scenario,
                    format!(
                        "the refused stat must be exactly one RPC (no local retry), saw {:?}",
                        transport.calls()
                    ),
                );
            }
            pass(scenario)
        }
        Err(err) => fail(
            scenario,
            format!("expected NotFound on stat, got {:?}: {err}", err.code()),
        ),
        Ok(info) => fail(scenario, format!("stat unexpectedly succeeded: {info:?}")),
    }
}

/// Read of an empty object surfaces the daemon's streamed shape intact:
/// a `ReadResult::Stream` that yields zero bytes, from one RPC.
async fn drive_read_streamed_empty(scenario: &Scenario) -> ScenarioReport {
    let (backend, transport) = scripted_backend();
    let result = match backend
        .read(
            target("broker://host/empty.txt"),
            ReadOptions::default(),
            None,
        )
        .await
    {
        Ok(result) => result,
        Err(err) => return fail(scenario, format!("read failed: {err}")),
    };
    let mut stream = match result {
        ReadResult::Stream { stream, info } => {
            if info.kind != ObjectKind::File {
                return fail(scenario, format!("expected File kind, got {:?}", info.kind));
            }
            stream
        }
        other => return fail(scenario, format!("expected a streamed read, got {other:?}")),
    };
    let mut total = 0usize;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => total += bytes.len(),
            Err(err) => return fail(scenario, format!("stream chunk failed: {err}")),
        }
    }
    if total != 0 {
        return fail(
            scenario,
            format!("empty read must stream zero bytes, got {total}"),
        );
    }
    if transport.calls() != ["read"] {
        return fail(
            scenario,
            format!("read must be exactly one RPC, saw {:?}", transport.calls()),
        );
    }
    pass(scenario)
}

/// Zero-byte write completes inline: one forwarded RPC whose
/// `WriteStep::Done` unwraps to the final `WriteResult`.
async fn drive_write_done_inline(scenario: &Scenario) -> ScenarioReport {
    let (backend, transport) = scripted_backend();
    let result = match backend
        .write(
            target("broker://host/inline.txt"),
            Vec::new(),
            WriteOptions::default(),
            None,
        )
        .await
    {
        Ok(result) => result,
        Err(err) => return fail(scenario, format!("write failed: {err}")),
    };
    if result.info.size != Some(0) {
        return fail(
            scenario,
            format!(
                "inline write must report size 0, got {:?}",
                result.info.size
            ),
        );
    }
    if transport.calls() != ["write"] {
        return fail(
            scenario,
            format!(
                "inline write must be exactly one RPC, saw {:?}",
                transport.calls()
            ),
        );
    }
    pass(scenario)
}

/// write then delete both succeed, one forwarded RPC each, in order.
async fn drive_delete_existing_object(scenario: &Scenario) -> ScenarioReport {
    let (backend, transport) = scripted_backend();
    if let Err(err) = backend
        .write(
            target("broker://host/victim.txt"),
            Vec::new(),
            WriteOptions::default(),
            None,
        )
        .await
    {
        return fail(scenario, format!("seed write failed: {err}"));
    }
    if let Err(err) = backend
        .delete(
            target("broker://host/victim.txt"),
            DeleteOptions::default(),
            None,
        )
        .await
    {
        return fail(scenario, format!("delete failed: {err}"));
    }
    if transport.calls() != ["write", "delete"] {
        return fail(
            scenario,
            format!(
                "write + delete must be exactly two RPCs in order, saw {:?}",
                transport.calls()
            ),
        );
    }
    pass(scenario)
}

/// `IfDestExists::Fail` rides the wire verbatim and the daemon's
/// `AlreadyExists` refusal surfaces exactly, from one RPC.
async fn drive_write_no_overwrite_existing(scenario: &Scenario) -> ScenarioReport {
    let (backend, transport) = scripted_backend();
    transport.refuse("write", ErrorCode::AlreadyExists);
    let outcome = backend
        .write(
            target("broker://host/existing.txt"),
            Vec::new(),
            WriteOptions {
                if_dest: IfDestExists::Fail,
                ..WriteOptions::default()
            },
            None,
        )
        .await;
    match outcome {
        Err(err) if err.code() == ErrorCode::AlreadyExists => {
            if transport.calls() != ["write"] {
                return fail(
                    scenario,
                    format!(
                        "the refused no-overwrite write must be exactly one RPC, saw {:?}",
                        transport.calls()
                    ),
                );
            }
            let observed = transport.last_write_options();
            if !matches!(
                observed.as_ref().map(|opts| &opts.if_dest),
                Some(IfDestExists::Fail)
            ) {
                return fail(
                    scenario,
                    format!("IfDestExists::Fail must cross the wire intact, saw {observed:?}"),
                );
            }
            pass(scenario)
        }
        Err(err) => fail(
            scenario,
            format!(
                "expected AlreadyExists on the no-overwrite refusal, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(result) => fail(
            scenario,
            format!(
                "no-overwrite write unexpectedly succeeded: {:?}",
                result.info
            ),
        ),
    }
}

/// `RenameOptions.if_dest = Fail` rides the single rename RPC verbatim;
/// the daemon's `AlreadyExists` surfaces exactly and the plugin never
/// decomposes the refused rename into client-side copy + delete.
async fn drive_rename_no_overwrite_existing(scenario: &Scenario) -> ScenarioReport {
    let (backend, transport) = scripted_backend();
    transport.refuse("rename", ErrorCode::AlreadyExists);
    let outcome = backend
        .rename(
            target("broker://host/move-src.txt"),
            target("broker://host/move-dst.txt"),
            RenameOptions {
                if_dest: IfDestExists::Fail,
                ..RenameOptions::default()
            },
            None,
        )
        .await;
    match outcome {
        Err(err) if err.code() == ErrorCode::AlreadyExists => {
            if transport.calls() != ["rename"] {
                return fail(
                    scenario,
                    format!(
                        "the refused rename must be exactly one RPC (no copy/delete \
                         decomposition), saw {:?}",
                        transport.calls()
                    ),
                );
            }
            let observed = transport.last_rename_options();
            if !matches!(
                observed.as_ref().map(|opts| &opts.if_dest),
                Some(IfDestExists::Fail)
            ) {
                return fail(
                    scenario,
                    format!("IfDestExists::Fail must cross the wire intact, saw {observed:?}"),
                );
            }
            pass(scenario)
        }
        Err(err) => fail(
            scenario,
            format!(
                "expected AlreadyExists on the no-overwrite rename, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(()) => fail(
            scenario,
            "no-overwrite rename unexpectedly succeeded".into(),
        ),
    }
}

/// One-level vs recursive listing: the `recursive` flag crosses the
/// wire verbatim on both calls, and the daemon's server-shaped pages —
/// marker folding on the flat page, nested files on the recursive page,
/// and the flat page's live continuation token — surface unmodified
/// (the broker is the only server-paginating v2 backend; re-paginating
/// locally would strand pages 2+).
async fn drive_list_one_level_vs_recursive(scenario: &Scenario) -> ScenarioReport {
    let (backend, transport) = scripted_backend();
    let flat = match backend
        .list(target("broker://host/dir/"), ListOptions::default(), None)
        .await
    {
        Ok(page) => page,
        Err(err) => return fail(scenario, format!("flat list failed: {err}")),
    };
    let kinds: Vec<ObjectKind> = flat.items.iter().map(|item| item.kind).collect();
    if kinds != vec![ObjectKind::DirectoryMarker, ObjectKind::File] {
        return fail(scenario, format!("unexpected flat page shape: {kinds:?}"));
    }
    if flat.next_page_token.as_deref() != Some("cursor-2") {
        return fail(
            scenario,
            format!(
                "the daemon's continuation token must pass through verbatim, got {:?}",
                flat.next_page_token
            ),
        );
    }
    let recursive = match backend
        .list(
            target("broker://host/dir/"),
            ListOptions {
                recursive: true,
                ..ListOptions::default()
            },
            None,
        )
        .await
    {
        Ok(page) => page,
        Err(err) => return fail(scenario, format!("recursive list failed: {err}")),
    };
    if !recursive
        .items
        .iter()
        .any(|item| item.address.as_str().ends_with("team/file.txt"))
    {
        return fail(scenario, "recursive list must surface nested files".into());
    }
    let observed: Vec<bool> = transport
        .observed_list_options()
        .iter()
        .map(|opts| opts.recursive)
        .collect();
    if observed != [false, true] {
        return fail(
            scenario,
            format!("the recursive flag must cross the wire verbatim, saw {observed:?}"),
        );
    }
    if transport.calls() != ["list", "list"] {
        return fail(
            scenario,
            format!(
                "the two listings must be exactly two RPCs, saw {:?}",
                transport.calls()
            ),
        );
    }
    pass(scenario)
}

// === Registry sweep ===

#[tokio::test]
async fn conformance_scenarios_cover_the_registry() {
    // Fetch the capability profile the way the real plugin learns it: from
    // the broker's published address roots.
    let (backend, _transport) = scripted_backend();
    let published = backend
        .list_address_roots()
        .await
        .expect("the scripted broker publishes roots");
    let caps = published
        .first()
        .map(|root| root.capabilities.clone())
        .expect("the scripted broker publishes at least one root");

    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();
    let mut driven: Vec<&'static str> = Vec::new();

    for scenario in registry.iter() {
        if let Some(gap) = capability_gap(scenario, &caps) {
            report.push(runner.skip(scenario.name, gap));
            continue;
        }
        let entry = match scenario.name {
            "stat-basic-objectinfo" => {
                driven.push(scenario.name);
                drive_stat_basic_objectinfo(scenario).await
            }
            "stat-not-found" => {
                driven.push(scenario.name);
                drive_stat_not_found(scenario).await
            }
            "read-streamed-empty" => {
                driven.push(scenario.name);
                drive_read_streamed_empty(scenario).await
            }
            "write-done-inline" => {
                driven.push(scenario.name);
                drive_write_done_inline(scenario).await
            }
            "delete-existing-object" => {
                driven.push(scenario.name);
                drive_delete_existing_object(scenario).await
            }
            "write-no-overwrite-existing" => {
                driven.push(scenario.name);
                drive_write_no_overwrite_existing(scenario).await
            }
            "rename-no-overwrite-existing" => {
                driven.push(scenario.name);
                drive_rename_no_overwrite_existing(scenario).await
            }
            "list-one-level-vs-recursive" => {
                driven.push(scenario.name);
                drive_list_one_level_vs_recursive(scenario).await
            }
            "copy-to-self-preserves-content" => runner.skip(
                scenario.name,
                "same-key copy data preservation is enforced by whichever upstream backend \
                 the broker daemon dispatches to; the plugin forwards one copy RPC verbatim, \
                 and a scripted transport could only echo the test's own script, proving \
                 nothing about the provider",
            ),
            "metadata-unsupported-not-called" => runner.skip(
                scenario.name,
                "recorder-based negative assertion; expected_calls verification is \
                 test-backend-only",
            ),
            "capability-gate-delete-unsupported"
            | "capability-gate-write-redirect-unsupported"
            | "capability-gate-update-metadata-unsupported"
            | "capability-gate-check-access-unsupported"
            | "capability-gate-create-directory-unsupported"
            | "capability-gate-delete-directory-unsupported"
            | "capability-gate-list-versions-unsupported"
            | "capability-gate-watch-directory-unsupported" => runner.skip(
                scenario.name,
                "the broker-client plugin has no capability self-gates by design: every op \
                 forwards to the broker daemon, which owns capability enforcement and returns \
                 the typed Unsupported the plugin surfaces verbatim; there is no plugin-side \
                 refusal to observe",
            ),
            "readonly-connection-rejects-mutations" => runner.skip(
                scenario.name,
                "read-only is a broker-daemon policy advertised through published root \
                 capabilities; the plugin performs no local mutation refusal — the daemon's \
                 typed refusal forwards verbatim",
            ),
            "compat-gates-v1-capability" => runner.skip(
                scenario.name,
                "stable capability-gate scenario; driven in ovstorage's \
                 conformance_protocol_slots.rs",
            ),
            "write-redirect-commits-on-done"
            | "retry-never-replays-continue-write"
            | "protocol-slots-pass-through" => runner.skip(
                scenario.name,
                "host/wrapper-side protocol-slot contract; driven in ovstorage's \
                 conformance_protocol_slots.rs",
            ),
            _ => runner.skip(
                scenario.name,
                "no provider driver wired; extend tests/conformance_scenarios.rs",
            ),
        };
        report.push(entry);
    }

    eprintln!("{}", report.render_human());
    assert_eq!(
        report.entries.len(),
        registry.len(),
        "every registry scenario must be reported"
    );
    assert!(
        report.ok(),
        "conformance failures:\n{}",
        report.render_human()
    );
    assert_eq!(report.failed(), 0);

    // Pin the driven set so silently-lost coverage fails loudly.
    driven.sort_unstable();
    assert_eq!(
        driven,
        vec![
            "delete-existing-object",
            "list-one-level-vs-recursive",
            "read-streamed-empty",
            "rename-no-overwrite-existing",
            "stat-basic-objectinfo",
            "stat-not-found",
            "write-done-inline",
            "write-no-overwrite-existing",
        ],
        "the driven scenario set changed; update the pin deliberately"
    );
}
