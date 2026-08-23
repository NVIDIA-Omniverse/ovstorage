// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Registry-as-spec conformance pass for the omniverse-storage-service
//! plugin (RFC-0066): iterate every named scenario in
//! `ovstorage_plugin_test::ScenarioRegistry::with_defaults()` and either
//! DRIVE it against `OmniverseStorageBackend` or SKIP it with a concrete
//! reason. Recorder-based `expected_calls` verification is
//! test-backend-only, so driven scenarios assert the observable outcome
//! (success shape or the exact `failure_contract` error code) and push
//! `ScenarioReport::passed`.
//!
//! Hermetic fixture: an in-process tonic Storage API fake served over a
//! tokio duplex channel — the same transport fixture shape as
//! `tests/end_to_end.rs` / `tests/streaming_invariant.rs` (no network, no
//! auth; the fake mirrors the fileobject/filefolder v1alpha wire contract
//! that `skills/ovstorage-contributor-services-client-conformance/SKILL.md`
//! documents as covered by the service's own conformance suite).
//!
//! Applicability is gated on the scenario's `required_profile` /
//! `required_capabilities` against the plugin's real advertised bits
//! (`factory::descriptor_capabilities`): the Storage API write/copy/move
//! wire has no fail-if-exists primitive, so
//! `supports_no_overwrite_write = false` capability-gates the two
//! `*-no-overwrite-existing` scenarios (the upfront typed `Unsupported`
//! refusal is pinned by `end_to_end.rs::write_refuses_no_overwrite`).
//!
//! Deviation from the s3/nucleus suites: `write-redirect-commits-on-done`
//! is DRIVEN here rather than deferred to the host-side
//! `conformance_protocol_slots.rs` — on this plugin the commit is an
//! explicit `CompleteRedirectUpload` RPC, so "mutations commit at
//! `continue_write` → Done, not at `write_redirect`" is directly
//! observable at the plugin seam.

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures::{Stream, StreamExt};
use ovstorage_plugin::{
    BackendId, Capabilities, DeleteOptions, ErrorCode, ListOptions, ObjectKind, ReadOptions,
    ReadResult, RedirectResult, RedirectResultBatch, ResolvedTarget, StatOptions, Url,
    WriteOptions, WriteStep,
};
use ovstorage_plugin_services_client::auth::DiscoveryState;
use ovstorage_plugin_services_client::backend::OmniverseStorageBackend;
use ovstorage_plugin_services_client::factory::descriptor_capabilities;
use ovstorage_plugin_services_client::transport::OmniverseStorageTransport;
use ovstorage_plugin_test::{
    ConformanceReport, FailureContract, Profile, Scenario, ScenarioOutcome, ScenarioRegistry,
    ScenarioReport, ScenarioRunner,
};
use ovstorage_services_protos::nvidia::omniverse::storage::filefolder::v1alpha as ff;
use ovstorage_services_protos::nvidia::omniverse::storage::fileobject::v1alpha as fo;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

// === Scripted Storage API fake (duplex tonic transport, as in
// tests/end_to_end.rs) ===

/// How the fake answers the bidirectional `Write` RPC.
#[derive(Clone, Copy)]
enum WriteBehavior {
    /// Drain the chunk frames and reply `ResourceInfo` (inline commit).
    Inline,
    /// Reply a single `WriteRedirect` on the first frame.
    SingleRedirect,
}

#[derive(Default)]
struct Recorded {
    stat_calls: u32,
    read_calls: u32,
    read_from_address_calls: u32,
    list_stat_folders: Vec<String>,
    write_params: Vec<fo::WriteParameters>,
    write_bodies: Vec<Vec<u8>>,
    delete_requests: Vec<fo::DeleteRequest>,
    completed_redirects: Vec<fo::CompleteRedirectUploadRequest>,
}

fn resource_info(identity: &str, size: u64) -> fo::ResourceInfo {
    fo::ResourceInfo {
        resource_identity: Some(fo::ResourceIdentity {
            encoded_identity: identity.into(),
        }),
        metadata: Some(fo::Metadata {
            data_object_size: Some(size),
            last_modified_timestamp: None,
        }),
    }
}

#[derive(Clone)]
struct FakeFileObjectService {
    write_behavior: WriteBehavior,
    recorded: Arc<Mutex<Recorded>>,
}

#[tonic::async_trait]
impl fo::file_object_service_server::FileObjectService for FakeFileObjectService {
    type EnumerateStream =
        Pin<Box<dyn Stream<Item = std::result::Result<fo::EnumerateResponse, Status>> + Send>>;
    type ReadStream =
        Pin<Box<dyn Stream<Item = std::result::Result<fo::ReadResponse, Status>> + Send>>;
    type ReadFromAddressStream = Pin<
        Box<dyn Stream<Item = std::result::Result<fo::ReadFromAddressResponse, Status>> + Send>,
    >;
    type WriteStream =
        Pin<Box<dyn Stream<Item = std::result::Result<fo::WriteResponse, Status>> + Send>>;

    async fn enumerate(
        &self,
        _req: Request<fo::EnumerateRequest>,
    ) -> std::result::Result<Response<Self::EnumerateStream>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn stat(
        &self,
        req: Request<fo::StatRequest>,
    ) -> std::result::Result<Response<fo::StatResponse>, Status> {
        self.recorded.lock().unwrap().stat_calls += 1;
        let address = req.into_inner().resource_address;
        if address.contains("missing") {
            return Err(Status::not_found("scripted missing object"));
        }
        Ok(Response::new(fo::StatResponse {
            resource_info: Some(resource_info(&format!("identity:{address}"), 42)),
        }))
    }

    async fn read(
        &self,
        _req: Request<fo::ReadRequest>,
    ) -> std::result::Result<Response<Self::ReadStream>, Status> {
        // Identity reads (if_match) are not part of the driven scenarios;
        // record so a driver can prove the address path was taken.
        self.recorded.lock().unwrap().read_calls += 1;
        Err(Status::unimplemented("identity read unused"))
    }

    async fn read_from_address(
        &self,
        req: Request<fo::ReadFromAddressRequest>,
    ) -> std::result::Result<Response<Self::ReadFromAddressStream>, Status> {
        self.recorded.lock().unwrap().read_from_address_calls += 1;
        let address = req.into_inner().resource_address;
        let (tx, rx) = mpsc::channel(4);
        // ResourceInfo only: a zero-byte object with no body frames.
        tx.send(Ok(fo::ReadFromAddressResponse {
            reply_type: Some(fo::read_from_address_response::ReplyType::ResourceInfo(
                resource_info(&format!("identity:{address}"), 0),
            )),
        }))
        .await
        .ok();
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn fetch_write_type_info(
        &self,
        _req: Request<fo::FetchWriteTypeInfoRequest>,
    ) -> std::result::Result<Response<fo::FetchWriteTypeInfoResponse>, Status> {
        Ok(Response::new(fo::FetchWriteTypeInfoResponse {
            write_type_intervals: vec![fo::WriteTypeForSizeInterval {
                minimum_data_object_size: 0,
                maximum_data_object_size: u64::MAX,
                preferred_upload_method: fo::UploadPreference::Redirect as i32,
            }],
        }))
    }

    async fn write(
        &self,
        req: Request<Streaming<fo::WriteRequest>>,
    ) -> std::result::Result<Response<Self::WriteStream>, Status> {
        let mut inbound = req.into_inner();
        let first = inbound
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("missing params"))?;
        let Some(fo::write_request::WriteRequestType::Params(params)) = first.write_request_type
        else {
            return Err(Status::invalid_argument("first write frame must be params"));
        };
        let mut body = Vec::new();
        if matches!(self.write_behavior, WriteBehavior::Inline) {
            while let Some(frame) = inbound.message().await? {
                if let Some(fo::write_request::WriteRequestType::Chunk(chunk)) =
                    frame.write_request_type
                {
                    body.extend_from_slice(&chunk.chunk);
                }
            }
        }
        {
            let mut recorded = self.recorded.lock().unwrap();
            recorded.write_params.push(params);
            if matches!(self.write_behavior, WriteBehavior::Inline) {
                recorded.write_bodies.push(body.clone());
            }
        }
        let (tx, rx) = mpsc::channel(4);
        match self.write_behavior {
            WriteBehavior::Inline => {
                tx.send(Ok(fo::WriteResponse {
                    write_response_type: Some(fo::write_response::WriteResponseType::ResourceInfo(
                        resource_info("etag-inline", body.len() as u64),
                    )),
                }))
                .await
                .ok();
            }
            WriteBehavior::SingleRedirect => {
                tx.send(Ok(fo::WriteResponse {
                    write_response_type: Some(
                        fo::write_response::WriteResponseType::WriteRedirect(
                            fo::WriteRedirectProperties {
                                redirect_target_url: "https://upload.example/put".into(),
                                method: fo::UploadMethod::Put as i32,
                                additional_headers: Vec::new(),
                                completion_header_names: vec!["etag".into()],
                            },
                        ),
                    ),
                }))
                .await
                .ok();
            }
        }
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn complete_redirect_upload(
        &self,
        req: Request<fo::CompleteRedirectUploadRequest>,
    ) -> std::result::Result<Response<fo::CompleteRedirectUploadResponse>, Status> {
        self.recorded
            .lock()
            .unwrap()
            .completed_redirects
            .push(req.into_inner());
        Ok(Response::new(fo::CompleteRedirectUploadResponse {
            resource_info: Some(resource_info("etag-after-redirect", 100)),
        }))
    }

    async fn upload_part(
        &self,
        _req: Request<fo::UploadPartRequest>,
    ) -> std::result::Result<Response<fo::UploadPartResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn complete_multipart_upload(
        &self,
        _req: Request<fo::CompleteMultipartUploadRequest>,
    ) -> std::result::Result<Response<fo::CompleteMultipartUploadResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn abort_multipart_upload(
        &self,
        _req: Request<fo::AbortMultipartUploadRequest>,
    ) -> std::result::Result<Response<fo::AbortMultipartUploadResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete(
        &self,
        req: Request<fo::DeleteRequest>,
    ) -> std::result::Result<Response<fo::DeleteResponse>, Status> {
        self.recorded
            .lock()
            .unwrap()
            .delete_requests
            .push(req.into_inner());
        Ok(Response::new(fo::DeleteResponse {}))
    }

    async fn copy(
        &self,
        _req: Request<fo::CopyRequest>,
    ) -> std::result::Result<Response<fo::CopyResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn r#move(
        &self,
        _req: Request<fo::MoveRequest>,
    ) -> std::result::Result<Response<fo::MoveResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_optimistic_locking_support(
        &self,
        _req: Request<fo::GetOptimisticLockingSupportRequest>,
    ) -> std::result::Result<Response<fo::GetOptimisticLockingSupportResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

#[derive(Clone)]
struct FakeFileFolderService {
    recorded: Arc<Mutex<Recorded>>,
}

#[tonic::async_trait]
impl ff::file_folder_service_server::FileFolderService for FakeFileFolderService {
    type ListStream =
        Pin<Box<dyn Stream<Item = std::result::Result<ff::ListResponse, Status>> + Send>>;
    type ListStatStream =
        Pin<Box<dyn Stream<Item = std::result::Result<ff::ListStatResponse, Status>> + Send>>;

    async fn list(
        &self,
        _req: Request<ff::ListRequest>,
    ) -> std::result::Result<Response<Self::ListStream>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn list_stat(
        &self,
        req: Request<ff::ListStatRequest>,
    ) -> std::result::Result<Response<Self::ListStatStream>, Status> {
        let folder = req
            .into_inner()
            .folder
            .map(|folder| folder.uri)
            .unwrap_or_default();
        self.recorded.lock().unwrap().list_stat_folders.push(folder);
        // One page: a subfolder plus a stat-carrying file entry, and one
        // unaddressable sibling of each.
        //
        // The doubled separator is a spelling `parse_server_address` refuses:
        // it names a different node from the one it spells, so no caller could
        // act on it. Both are placed FIRST so that a page which aborted on one
        // would hide every valid entry behind it — which is exactly what the
        // scenario's fold assertion then detects.
        let stream = tokio_stream::iter(vec![Ok(ff::ListStatResponse {
            subfolder_addresses: vec![
                ff::FolderAddress {
                    uri: "omni://server/dir//unaddressable/".into(),
                },
                ff::FolderAddress {
                    uri: "omni://server/dir/sub/".into(),
                },
            ],
            entries: vec![
                ff::ListItem {
                    resource_address: "omni://server/dir//unaddressable.usd".into(),
                    resource_info: Some(resource_info("e0", 3)),
                },
                ff::ListItem {
                    resource_address: "omni://server/dir/file.usd".into(),
                    resource_info: Some(resource_info("e1", 17)),
                },
            ],
        })]);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn create_folder(
        &self,
        _req: Request<ff::CreateFolderRequest>,
    ) -> std::result::Result<Response<ff::CreateFolderResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn delete_folder(
        &self,
        _req: Request<ff::DeleteFolderRequest>,
    ) -> std::result::Result<Response<ff::DeleteFolderResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_folder_mode(
        &self,
        _req: Request<ff::GetFolderModeRequest>,
    ) -> std::result::Result<Response<ff::GetFolderModeResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

/// Backend wired to a fresh scripted fake over a duplex channel.
async fn spawn_backend(
    write_behavior: WriteBehavior,
) -> (OmniverseStorageBackend, Arc<Mutex<Recorded>>) {
    let recorded = Arc::new(Mutex::new(Recorded::default()));
    let fileobject = FakeFileObjectService {
        write_behavior,
        recorded: recorded.clone(),
    };
    let filefolder = FakeFileFolderService {
        recorded: recorded.clone(),
    };
    let (client, server) = tokio::io::duplex(64 * 1024);
    let mut server_io = Some(server);
    let server_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(fo::file_object_service_server::FileObjectServiceServer::new(fileobject))
            .add_service(ff::file_folder_service_server::FileFolderServiceServer::new(filefolder))
            .serve_with_incoming(tokio_stream::once(Ok::<_, std::io::Error>(
                server_io.take().unwrap(),
            )))
            .await
            .ok();
    });
    let mut client_io = Some(client);
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_| {
            let io = client_io.take().expect("connector called twice");
            async move { Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(io)) }
        }))
        .await
        .expect("duplex connect");
    let transport =
        OmniverseStorageTransport::with_channel(channel, DiscoveryState::new("default"));
    let backend =
        OmniverseStorageBackend::new("http://duplex".into(), descriptor_capabilities(), transport);
    // Detach the server task; it shuts down when its duplex peer closes.
    drop(server_task);
    (backend, recorded)
}

fn target(path: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId("omniverse-storage-service:test".into()),
        resolved_address: Url::parse(&format!("omni://server/{path}")).expect("address parses"),
    }
}

fn pass(scenario: &Scenario) -> ScenarioReport {
    ScenarioReport::passed(scenario, Vec::new())
}

fn fail(scenario: &Scenario, reason: String) -> ScenarioReport {
    ScenarioReport::failed(scenario, reason, Vec::new())
}

// === Capability gate (required_profile / required_capabilities vs the
// plugin's advertised bits) ===

/// Whether the plugin advertises `bit`. Unknown bit names gate
/// conservatively (a visible skip beats driving an uncheckable
/// requirement).
fn advertises(caps: &Capabilities, bit: &str) -> bool {
    match bit {
        "supports_list" => caps.supports_list,
        "supports_delete" => caps.supports_delete,
        "supports_write" => caps.supports_write,
        "supports_write_stream" => caps.supports_write_stream,
        "supports_create_directory" => caps.supports_create_directory,
        "supports_delete_directory" => caps.supports_delete_directory,
        "supports_no_overwrite_write" => caps.supports_no_overwrite_write,
        "supports_if_match_write" => caps.supports_if_match_write,
        "supports_native_metadata_patch" => caps.supports_native_metadata_patch,
        "supports_version_listing" => caps.supports_version_listing,
        "has_real_directories" => caps.has_real_directories,
        "supports_recursive_list" => caps.supports_recursive_list,
        "supports_server_side_copy" => caps.supports_server_side_copy,
        "supports_server_side_rename" => caps.supports_server_side_rename,
        "supports_atomic_rename" => caps.supports_atomic_rename,
        "supports_watch_directory" => caps.supports_watch_directory,
        "supports_write_redirect" => caps.supports_write_redirect,
        _ => false,
    }
}

/// Capability bits a profile requires of a real provider. `Minimal` is the
/// registry floor; the other arms list only their additions (the floor is
/// exercised by the Minimal-profile scenarios that dominate the registry).
/// `DirectoriesReal` deliberately requires only `has_real_directories` —
/// its documented essence ("real directory entities, no marker-folding") —
/// not the test plugin's bundled `supports_recursive_list`, so the
/// type-mismatch scenarios skip with their accurate service-enforcement
/// reason instead of a misleading recursive-list one.
fn profile_required_bits(profile: Profile) -> &'static [&'static str] {
    match profile {
        Profile::Minimal => &[
            "supports_list",
            "supports_delete",
            "supports_write",
            "supports_write_stream",
            "supports_create_directory",
            "supports_delete_directory",
        ],
        Profile::ConditionalWrites => &["supports_no_overwrite_write", "supports_if_match_write"],
        Profile::MetadataNative => &["supports_native_metadata_patch"],
        Profile::VersionsNewest => &["supports_version_listing"],
        Profile::DirectoriesReal => &["has_real_directories"],
        Profile::AtomicRename => &["supports_server_side_rename", "supports_atomic_rename"],
        Profile::WatchDirectoryResumable => &["supports_watch_directory"],
        Profile::Redirects | Profile::LocalDelegate => &[],
        // `Profile` is #[non_exhaustive]: an unknown future profile gates
        // out visibly rather than driving unchecked.
        _ => &["<unrecognized-profile>"],
    }
}

/// `Some(skip reason)` when the scenario's profile/capability requirements
/// are not met by the plugin's advertised capability set.
fn capability_gate(scenario: &Scenario, caps: &Capabilities) -> Option<String> {
    let mut missing: Vec<&str> = Vec::new();
    for bit in profile_required_bits(scenario.required_profile)
        .iter()
        .chain(scenario.required_capabilities.iter())
    {
        if !advertises(caps, bit) && !missing.contains(bit) {
            missing.push(bit);
        }
    }
    if missing.is_empty() {
        return None;
    }
    Some(format!(
        "capability-gated: requires {} (profile {:?}) which omniverse-storage-service does not \
         advertise (factory::descriptor_capabilities)",
        missing.join(" + "),
        scenario.required_profile,
    ))
}

// === Driven scenarios ===

/// stat → exactly one Stat RPC, materializing a File ObjectInfo with the
/// identity-derived etag and the wire-reported size.
async fn drive_stat_basic_objectinfo(scenario: &Scenario) -> ScenarioReport {
    let (backend, recorded) = spawn_backend(WriteBehavior::Inline).await;
    let info = match backend
        .stat(target("asset.usd"), StatOptions::default(), None)
        .await
    {
        Ok(info) => info,
        Err(err) => return fail(scenario, format!("stat failed: {err}")),
    };
    if info.kind != ObjectKind::File {
        return fail(scenario, format!("expected File kind, got {:?}", info.kind));
    }
    if info.size != Some(42) || info.etag.as_deref() != Some("identity:omni://server/asset.usd") {
        return fail(
            scenario,
            format!("stat mismatch: size {:?} etag {:?}", info.size, info.etag),
        );
    }
    if recorded.lock().unwrap().stat_calls != 1 {
        return fail(scenario, "stat must be exactly one Stat RPC".into());
    }
    pass(scenario)
}

/// stat on a missing address surfaces exactly the contract's `NotFound`
/// (the fake rejects with gRPC NOT_FOUND; `map_status` must preserve it).
async fn drive_stat_not_found(scenario: &Scenario) -> ScenarioReport {
    let (method, code) = match &scenario.failure_contract {
        FailureContract::Errors { method, code } => (*method, *code),
        other => {
            return fail(
                scenario,
                format!("stat-not-found must carry an Errors contract, got {other:?}"),
            );
        }
    };
    let (backend, recorded) = spawn_backend(WriteBehavior::Inline).await;
    match backend
        .stat(target("missing.usd"), StatOptions::default(), None)
        .await
    {
        Err(err) if err.code() == code => {
            if recorded.lock().unwrap().stat_calls != 1 {
                return fail(scenario, "stat must be exactly one Stat RPC".into());
            }
            pass(scenario)
        }
        Err(err) => fail(
            scenario,
            format!(
                "expected {code:?} on `{method}`, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(info) => fail(scenario, format!("stat unexpectedly succeeded: {info:?}")),
    }
}

/// A zero-byte object reads as an EMPTY stream (ResourceInfo frame, no
/// chunks), taken via the latest-version `ReadFromAddress` path — never
/// the identity `Read` RPC when no if_match is supplied.
async fn drive_read_streamed_empty(scenario: &Scenario) -> ScenarioReport {
    let (backend, recorded) = spawn_backend(WriteBehavior::Inline).await;
    let result = match backend
        .read(target("empty.usd"), ReadOptions::default(), None)
        .await
    {
        Ok(result) => result,
        Err(err) => return fail(scenario, format!("read failed: {err}")),
    };
    match result {
        ReadResult::Stream { mut stream, info } => {
            if info.size != Some(0) {
                return fail(scenario, format!("expected size 0, got {:?}", info.size));
            }
            if let Some(chunk) = stream.next().await {
                return fail(
                    scenario,
                    format!("zero-byte read yielded an unexpected chunk: {chunk:?}"),
                );
            }
            let recorded = recorded.lock().unwrap();
            if recorded.read_from_address_calls != 1 || recorded.read_calls != 0 {
                return fail(
                    scenario,
                    format!(
                        "read without if_match must be exactly one ReadFromAddress (saw {} + {} \
                         identity reads)",
                        recorded.read_from_address_calls, recorded.read_calls
                    ),
                );
            }
            pass(scenario)
        }
        other => fail(scenario, format!("expected an empty Stream, got {other:?}")),
    }
}

/// Inline write commits in one bidirectional Write RPC: params frame with
/// the destination address and Body preference, chunk frames carrying the
/// payload, ResourceInfo reply shaping the WriteResult.
async fn drive_write_done_inline(scenario: &Scenario) -> ScenarioReport {
    let (backend, recorded) = spawn_backend(WriteBehavior::Inline).await;
    let result = match backend
        .write(
            target("new.usd"),
            b"payload".to_vec(),
            WriteOptions::default(),
            None,
        )
        .await
    {
        Ok(result) => result,
        Err(err) => return fail(scenario, format!("write failed: {err}")),
    };
    if result.info.etag.as_deref() != Some("etag-inline") || result.info.size != Some(7) {
        return fail(
            scenario,
            format!(
                "write result mismatch: etag {:?} size {:?}",
                result.info.etag, result.info.size
            ),
        );
    }
    let recorded = recorded.lock().unwrap();
    if recorded.write_params.len() != 1 {
        return fail(
            scenario,
            "inline write must be exactly one Write RPC".into(),
        );
    }
    let params = &recorded.write_params[0];
    if params.destination_resource_address != "omni://server/new.usd"
        || params.upload_preference != Some(fo::UploadPreference::Body as i32)
        || params.data_object_size != 7
    {
        return fail(
            scenario,
            format!("inline write params mismatch: {params:?}"),
        );
    }
    if recorded.write_bodies[0] != b"payload" {
        return fail(
            scenario,
            format!(
                "payload must arrive as chunk frames, got {:?}",
                recorded.write_bodies[0]
            ),
        );
    }
    pass(scenario)
}

/// write then delete both succeed; the Delete RPC carries the object's
/// resource address.
async fn drive_delete_existing_object(scenario: &Scenario) -> ScenarioReport {
    let (backend, recorded) = spawn_backend(WriteBehavior::Inline).await;
    if let Err(err) = backend
        .write(
            target("doomed.usd"),
            b"bye".to_vec(),
            WriteOptions::default(),
            None,
        )
        .await
    {
        return fail(scenario, format!("seed write failed: {err}"));
    }
    if let Err(err) = backend
        .delete(target("doomed.usd"), DeleteOptions::default(), None)
        .await
    {
        return fail(scenario, format!("delete failed: {err}"));
    }
    let recorded = recorded.lock().unwrap();
    if recorded.write_params.len() != 1 || recorded.delete_requests.len() != 1 {
        return fail(
            scenario,
            format!(
                "write + delete must be exactly one RPC each (saw {} writes, {} deletes)",
                recorded.write_params.len(),
                recorded.delete_requests.len()
            ),
        );
    }
    if recorded.delete_requests[0].resource_address != "omni://server/doomed.usd" {
        return fail(
            scenario,
            format!(
                "delete must carry the object address: {:?}",
                recorded.delete_requests[0]
            ),
        );
    }
    pass(scenario)
}

/// One-level listing folds the ListStat page (`subfolder_addresses` →
/// Directory, `entries` → File with wire etag/size); the recursive half of
/// the contract is this plugin's typed LOCAL refusal — the OvCS ListStat
/// RPC enumerates one level per call and silently amplifying one call into
/// N is forbidden, so `recursive=true` surfaces `Unsupported` with no
/// additional RPC (`supports_recursive_list = false` is advertised).
async fn drive_list_one_level_vs_recursive(scenario: &Scenario) -> ScenarioReport {
    let (backend, recorded) = spawn_backend(WriteBehavior::Inline).await;
    let items = match backend
        .list(target("dir/"), ListOptions::default(), None)
        .await
    {
        Ok(items) => items,
        Err(err) => return fail(scenario, format!("flat list failed: {err}")),
    };
    let kinds: Vec<ObjectKind> = items.iter().map(|item| item.kind).collect();
    if kinds != vec![ObjectKind::Directory, ObjectKind::File] {
        return fail(scenario, format!("unexpected flat list fold: {kinds:?}"));
    }
    // The page carries one unaddressable subfolder and one unaddressable
    // entry, ahead of the valid ones. Each is dropped with a `warn!` and the
    // rest of the page survives: failing the page would hide every valid
    // sibling over a property of one entry. Reverting either call site to `?`
    // turns this scenario red, because both bad rows come first.
    if items
        .iter()
        .any(|item| item.address.as_str().contains("unaddressable"))
    {
        return fail(
            scenario,
            format!(
                "an entry no caller can act on must be omitted, not returned: {:?}",
                items.iter().map(|i| i.address.as_str()).collect::<Vec<_>>()
            ),
        );
    }
    if items[1].address.as_str() != "omni://server/dir/file.usd"
        || items[1].etag.as_deref() != Some("e1")
        || items[1].size != Some(17)
    {
        return fail(
            scenario,
            format!("flat list entry mismatch: {:?}", items[1]),
        );
    }
    {
        let recorded = recorded.lock().unwrap();
        if recorded.list_stat_folders != vec!["omni://server/dir/".to_string()] {
            return fail(
                scenario,
                format!(
                    "flat list must be one ListStat for the prefix: {:?}",
                    recorded.list_stat_folders
                ),
            );
        }
    }
    // The registry pins this scenario `FailureContract::Success`, so the
    // recursive half must not REQUIRE a failure. `supports_recursive_list` is
    // in neither `required_capabilities` nor the Minimal profile, so a refusal
    // is conforming while the plugin does not advertise it — but so is a real
    // recursive page, and demanding `Unsupported` would turn a future
    // implementation of recursive listing into a suite failure, inverting what
    // a conformance suite is for. What is never conforming, either way, is a
    // silent one-level fold presented as a recursive result.
    let advertises_recursive = descriptor_capabilities().supports_recursive_list;
    match backend
        .list(
            target("dir/"),
            ListOptions {
                recursive: true,
                ..ListOptions::default()
            },
            None,
        )
        .await
    {
        // A real recursive page is conforming — assert it reaches the
        // descendant rather than silently folding to one level.
        Ok(items) => {
            if items
                .iter()
                .any(|item| item.address.as_str().contains("nested"))
            {
                pass(scenario)
            } else {
                fail(
                    scenario,
                    "a recursive list must reach the descendant, not silently fold to one level"
                        .into(),
                )
            }
        }
        // So is a refusal, while the plugin does not advertise the bit.
        Err(err) if err.code() == ErrorCode::Unsupported && !advertises_recursive => {
            if recorded.lock().unwrap().list_stat_folders.len() != 1 {
                return fail(
                    scenario,
                    "the recursive refusal must not reach the wire".into(),
                );
            }
            pass(scenario)
        }
        Err(err) if advertises_recursive => fail(
            scenario,
            format!(
                "recursive list is advertised but failed with {:?}: {err}",
                err.code()
            ),
        ),
        Err(err) => fail(
            scenario,
            format!(
                "an unadvertised recursive list may refuse with Unsupported, got {:?}: {err}",
                err.code()
            ),
        ),
    }
}

/// Protocol-slot contract at the plugin seam: `write_redirect` only plans
/// (no `CompleteRedirectUpload` fires), and the mutation commits at
/// `continue_write` → `WriteStep::Done` — with the captured completion
/// header round-tripping onto the commit RPC.
async fn drive_write_redirect_commits_on_done(scenario: &Scenario) -> ScenarioReport {
    let (backend, recorded) = spawn_backend(WriteBehavior::SingleRedirect).await;
    let batch = match backend
        .write_redirect(
            target("big.bin"),
            WriteOptions {
                size_hint: Some(1024),
                ..WriteOptions::default()
            },
            None,
        )
        .await
    {
        Ok(batch) => batch,
        Err(err) => return fail(scenario, format!("write_redirect failed: {err}")),
    };
    if batch.redirects.len() != 1 {
        return fail(
            scenario,
            format!("expected one redirect, got {}", batch.redirects.len()),
        );
    }
    if !recorded.lock().unwrap().completed_redirects.is_empty() {
        return fail(
            scenario,
            "write_redirect must not commit (CompleteRedirectUpload fired before continue_write)"
                .into(),
        );
    }
    let results = RedirectResultBatch {
        results: vec![RedirectResult {
            status_code: 200,
            captured_headers: vec![("etag".into(), "remote-etag".into())],
            captured_body: Vec::new(),
        }],
    };
    let step = match backend
        .continue_write(target("big.bin"), batch, results, None, None)
        .await
    {
        Ok(step) => step,
        Err(err) => return fail(scenario, format!("continue_write failed: {err}")),
    };
    match step {
        WriteStep::Done(result) => {
            if result.info.etag.as_deref() != Some("etag-after-redirect") {
                return fail(
                    scenario,
                    format!("Done must carry the committed etag: {:?}", result.info.etag),
                );
            }
        }
        other => return fail(scenario, format!("expected WriteStep::Done, got {other:?}")),
    }
    let recorded = recorded.lock().unwrap();
    if recorded.completed_redirects.len() != 1 {
        return fail(
            scenario,
            format!(
                "commit must be exactly one CompleteRedirectUpload, saw {}",
                recorded.completed_redirects.len()
            ),
        );
    }
    let commit = &recorded.completed_redirects[0];
    if commit.destination_resource_address != "omni://server/big.bin" {
        return fail(
            scenario,
            format!("commit must name the destination: {commit:?}"),
        );
    }
    if !commit
        .additional_headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("etag") && h.value == "remote-etag")
    {
        return fail(
            scenario,
            format!("captured completion header must round-trip: {commit:?}"),
        );
    }
    pass(scenario)
}

// === Registry sweep ===

#[tokio::test]
async fn conformance_scenarios_cover_the_registry() {
    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let caps = descriptor_capabilities();
    let mut report = ConformanceReport::new();
    let mut driven: Vec<&'static str> = Vec::new();
    let mut gated: Vec<&'static str> = Vec::new();

    for scenario in registry.iter() {
        let entry = if let Some(reason) = capability_gate(scenario, &caps) {
            gated.push(scenario.name);
            runner.skip(scenario.name, reason)
        } else {
            match scenario.name {
                "stat-basic-objectinfo" => drive_stat_basic_objectinfo(scenario).await,
                "stat-not-found" => drive_stat_not_found(scenario).await,
                "read-streamed-empty" => drive_read_streamed_empty(scenario).await,
                "write-done-inline" => drive_write_done_inline(scenario).await,
                "delete-existing-object" => drive_delete_existing_object(scenario).await,
                "list-one-level-vs-recursive" => drive_list_one_level_vs_recursive(scenario).await,
                "write-redirect-commits-on-done" => {
                    drive_write_redirect_commits_on_done(scenario).await
                }
                name if name.starts_with("capability-gate-") => runner.skip(
                    name,
                    "every gate-table op is advertised by omniverse-storage-service \
                     (descriptor_capabilities); per-root downgrades (GetFolderMode / \
                     GetOptimisticLockingSupport) only lower the advertised bits for the HOST \
                     to enforce — there is no plugin-side self-gated refusal to observe",
                ),
                "compat-gates-v1-capability"
                | "retry-never-replays-continue-write"
                | "protocol-slots-pass-through" => runner.skip(
                    scenario.name,
                    "host/wrapper-side protocol-slot contract; driven in ovstorage's \
                     conformance_protocol_slots.rs",
                ),
                "copy-to-self-preserves-content" => runner.skip(
                    scenario.name,
                    "data preservation on a same-address Copy is service-enforced; the canned \
                     duplex fake would only echo the CopyResponse the test scripted, proving \
                     nothing about the provider",
                ),
                "delete-on-directory-type-mismatch"
                | "delete-directory-on-file-type-mismatch"
                | "list-on-file-type-mismatch"
                | "read-on-directory-type-mismatch" => runner.skip(
                    scenario.name,
                    "the file-vs-folder kind verdict behind the InvalidArgument contract is \
                     enforced server-side (Delete/DeleteFolder/ListStat semantics); a canned \
                     duplex fake would only echo the test's own script — driving this honestly \
                     needs a live Storage API service (see the services-client conformance \
                     skill's run-conformance-tests suite)",
                ),
                "metadata-unsupported-not-called" => runner.skip(
                    scenario.name,
                    "recorder-based negative assertion (expected_calls) is test-backend-only",
                ),
                "readonly-connection-rejects-mutations" => runner.skip(
                    scenario.name,
                    "no read-only connection mode: descriptor capabilities are static and \
                     anonymous (no auth-config) connections keep write support; there is no \
                     plugin-side mutation refusal to observe",
                ),
                _ => runner.skip(
                    scenario.name,
                    "no provider driver wired; extend tests/conformance_scenarios.rs",
                ),
            }
        };
        if !matches!(entry.outcome, ScenarioOutcome::Skipped { .. }) {
            driven.push(scenario.name);
        }
        report.push(entry);
    }

    eprintln!("{}", report.render_human());
    assert_eq!(
        report.entries.len(),
        registry.len(),
        "every registry scenario must be reported"
    );
    // Pin the capability-gated set: a capability flip must be answered by a
    // deliberate drive/skip decision here, not a silent fallback skip.
    assert_eq!(
        gated,
        vec![
            "rename-no-overwrite-existing",
            "write-no-overwrite-existing"
        ],
        "the capability-gated scenario set drifted:\n{}",
        report.render_human()
    );
    // Pin the driven set (registry iteration is name-ordered) so a scenario
    // silently downgraded to a skip fails loudly.
    assert_eq!(
        driven,
        vec![
            "delete-existing-object",
            "list-one-level-vs-recursive",
            "read-streamed-empty",
            "stat-basic-objectinfo",
            "stat-not-found",
            "write-done-inline",
            "write-redirect-commits-on-done",
        ],
        "the driven scenario set drifted:\n{}",
        report.render_human()
    );
    assert_eq!(report.failed(), 0, "{}", report.render_human());
    assert!(report.ok(), "{}", report.render_human());
}
