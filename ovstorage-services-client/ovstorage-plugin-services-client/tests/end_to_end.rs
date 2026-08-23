// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end test: stand up an in-memory tonic FileObjectService, point
//! `OmniverseStorageBackend` at it via a duplex transport, exercise stat +
//! write_redirect (single + multipart) + continue_write.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use bytes::Bytes;
use futures::Stream;
use futures::StreamExt;
use ovstorage_plugin::{
    AccessDecision, AccessOps, BackendId, ByteRange, Capabilities, ChecksumSet, CopyOptions,
    DeleteOptions, IfDestExists, ListOptions, ListVersionsOptions, ObjectInfo, ObjectKind,
    ReadOptions, ReadResult, RedirectResult, RedirectResultBatch, RenameOptions, ResolvedTarget,
    StatOptions, UpdateMetadataOptions, Url, WriteOptions, WriteStep,
};
use ovstorage_plugin_services_client::auth::DiscoveryState;
use ovstorage_plugin_services_client::backend::OmniverseStorageBackend;
use ovstorage_plugin_services_client::factory::build_auth_state;
use ovstorage_plugin_services_client::transport::OmniverseStorageTransport;
use ovstorage_services_protos::google::protobuf::{ListValue, Value, value::Kind};
use ovstorage_services_protos::nvidia::omniverse::storage::filefolder::v1alpha as ff;
use ovstorage_services_protos::nvidia::omniverse::storage::fileobject::v1alpha as fo;
use ovstorage_services_protos::nvidia::omniverse::storage::metadata::v1alpha as md;
use ovstorage_services_protos::nvidia::omniverse::storage::versioning::v1alpha as ver;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

#[derive(Default, Clone)]
struct Recorded {
    completed_redirects: Vec<fo::CompleteRedirectUploadRequest>,
    completed_multiparts: Vec<fo::CompleteMultipartUploadRequest>,
    aborted_multiparts: Vec<fo::AbortMultipartUploadRequest>,
    stat_calls: u32,
    copy_requests: Vec<fo::CopyRequest>,
    move_requests: Vec<fo::MoveRequest>,
    read_calls: Vec<fo::ReadRequest>,
    read_from_address_calls: Vec<fo::ReadFromAddressRequest>,
    enumerate_versions_calls: Vec<ver::EnumerateVersionsRequest>,
    update_metadata_requests: Vec<md::UpdateMetadataRequest>,
    delete_metadata_requests: Vec<md::DeleteMetadataRequest>,
    /// How the fake metadata service answers `UpdateMetadata`. Lives here
    /// rather than in a constructor argument so a test can flip it without
    /// threading a parameter through six `spawn_fake_server_*` wrappers.
    update_metadata_behavior: UpdateMetadataBehavior,
}

/// How `FakeMetadataService::update_metadata` answers. `AlwaysFail` is the
/// post-commit failure the `PartialCompletion` propagation exists to report;
/// `FailKeys` covers a partially-applied map, which is the case the payload
/// deliberately reports per stash rather than per key.
#[derive(Default, Clone, PartialEq, Eq)]
enum UpdateMetadataBehavior {
    #[default]
    Ok,
    /// Fail every key with this gRPC code.
    AlwaysFail(tonic::Code),
    /// Fail only the named keys; the rest are stored.
    FailKeys(Vec<String>, tonic::Code),
}

#[derive(Default, Clone)]
enum WriteServerBehavior {
    /// First Write response is `WriteRedirect`.
    SingleRedirect,
    /// First Write response is `MultipartUpload` with N parts.
    Multipart { parts: u32 },
    #[default]
    Inline,
}

#[derive(Clone, Default)]
enum ReadServerBehavior {
    /// ResourceInfo, then chunks containing the supplied payload.
    Chunks { payload: Vec<u8> },
    /// ResourceInfo, then a Redirect to a presigned URL.
    Redirect {
        url: String,
        headers: Vec<(String, String)>,
    },
    /// ResourceInfo only (zero-byte body).
    #[default]
    Empty,
    /// Server rejects with NOT_FOUND — simulates an identity supplied
    /// via if_match that the service cannot honor.
    RejectNotFound,
}

#[derive(Clone)]
struct VersionServerBehavior {
    responses: Vec<ver::EnumerateVersionsResponse>,
    reject_invalid_argument: bool,
}

impl Default for VersionServerBehavior {
    fn default() -> Self {
        Self {
            responses: vec![ver::EnumerateVersionsResponse {
                versions_order: ver::VersionsOrder::NewestFirst as i32,
                items: vec![version_info(
                    "omni://server/path?version=v1",
                    "v1",
                    "2026-01",
                )],
            }],
            reject_invalid_argument: false,
        }
    }
}

#[derive(Clone, Default)]
struct CapabilityServerBehavior {
    folder_mode: Option<ff::FolderMode>,
    optimistic_supports_write: Option<bool>,
}

#[derive(Clone)]
struct FakeFileObjectService {
    behavior: Arc<Mutex<WriteServerBehavior>>,
    read_behavior: Arc<Mutex<ReadServerBehavior>>,
    capability_behavior: Arc<Mutex<CapabilityServerBehavior>>,
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
            return Err(Status::not_found("simulated missing object"));
        }
        Ok(Response::new(fo::StatResponse {
            resource_info: Some(fo::ResourceInfo {
                resource_identity: Some(fo::ResourceIdentity {
                    encoded_identity: format!("identity:{address}"),
                }),
                metadata: Some(fo::Metadata {
                    data_object_size: Some(42),
                    last_modified_timestamp: None,
                }),
            }),
        }))
    }

    async fn read(
        &self,
        req: Request<fo::ReadRequest>,
    ) -> std::result::Result<Response<Self::ReadStream>, Status> {
        let inner = req.into_inner();
        self.recorded.lock().unwrap().read_calls.push(inner.clone());
        let behavior = self.read_behavior.lock().unwrap().clone();
        if matches!(behavior, ReadServerBehavior::RejectNotFound) {
            return Err(Status::not_found("simulated rejected identity"));
        }
        let (tx, rx) = mpsc::channel(8);
        let total_size: u64 = match &behavior {
            ReadServerBehavior::Chunks { payload } => payload.len() as u64,
            _ => 0,
        };
        // First frame: Metadata (note: Read RPC's reply omits ResourceInfo;
        // the identity is implicit from the request).
        tx.send(Ok(fo::ReadResponse {
            reply_type: Some(fo::read_response::ReplyType::Metadata(fo::Metadata {
                data_object_size: Some(total_size),
                last_modified_timestamp: None,
            })),
        }))
        .await
        .ok();
        match behavior {
            ReadServerBehavior::Chunks { payload } => {
                let mid = payload.len() / 2;
                let (lo, hi) = payload.split_at(mid);
                tx.send(Ok(fo::ReadResponse {
                    reply_type: Some(fo::read_response::ReplyType::Chunk(fo::Chunk {
                        chunk: Bytes::copy_from_slice(lo),
                    })),
                }))
                .await
                .ok();
                tx.send(Ok(fo::ReadResponse {
                    reply_type: Some(fo::read_response::ReplyType::Chunk(fo::Chunk {
                        chunk: Bytes::copy_from_slice(hi),
                    })),
                }))
                .await
                .ok();
            }
            ReadServerBehavior::Redirect { url, headers } => {
                #[allow(deprecated)]
                let redirect = fo::Redirect {
                    redirect_target_url: url,
                    method: String::new(),
                    additional_headers: headers
                        .into_iter()
                        .map(|(name, value)| fo::Header { name, value })
                        .collect(),
                };
                tx.send(Ok(fo::ReadResponse {
                    reply_type: Some(fo::read_response::ReplyType::Redirect(redirect)),
                }))
                .await
                .ok();
            }
            ReadServerBehavior::Empty | ReadServerBehavior::RejectNotFound => {}
        }
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn read_from_address(
        &self,
        req: Request<fo::ReadFromAddressRequest>,
    ) -> std::result::Result<Response<Self::ReadFromAddressStream>, Status> {
        let inner = req.into_inner();
        self.recorded
            .lock()
            .unwrap()
            .read_from_address_calls
            .push(inner.clone());
        let address = inner.resource_address;
        let behavior = self.read_behavior.lock().unwrap().clone();
        if matches!(behavior, ReadServerBehavior::RejectNotFound) {
            return Err(Status::not_found("simulated missing object"));
        }
        let (tx, rx) = mpsc::channel(8);
        // First: ResourceInfo.
        let total_size: u64 = match &behavior {
            ReadServerBehavior::Chunks { payload } => payload.len() as u64,
            _ => 0,
        };
        tx.send(Ok(fo::ReadFromAddressResponse {
            reply_type: Some(fo::read_from_address_response::ReplyType::ResourceInfo(
                fo::ResourceInfo {
                    resource_identity: Some(fo::ResourceIdentity {
                        encoded_identity: format!("identity:{address}"),
                    }),
                    metadata: Some(fo::Metadata {
                        data_object_size: Some(total_size),
                        last_modified_timestamp: None,
                    }),
                },
            )),
        }))
        .await
        .ok();
        match behavior {
            ReadServerBehavior::Chunks { payload } => {
                // Send the body as two chunks to exercise the prepend-and-chain path.
                let mid = payload.len() / 2;
                let (lo, hi) = payload.split_at(mid);
                tx.send(Ok(fo::ReadFromAddressResponse {
                    reply_type: Some(fo::read_from_address_response::ReplyType::Chunk(
                        fo::Chunk {
                            chunk: Bytes::copy_from_slice(lo),
                        },
                    )),
                }))
                .await
                .ok();
                tx.send(Ok(fo::ReadFromAddressResponse {
                    reply_type: Some(fo::read_from_address_response::ReplyType::Chunk(
                        fo::Chunk {
                            chunk: Bytes::copy_from_slice(hi),
                        },
                    )),
                }))
                .await
                .ok();
            }
            ReadServerBehavior::Redirect { url, headers } => {
                #[allow(deprecated)]
                let redirect = fo::Redirect {
                    redirect_target_url: url,
                    method: String::new(),
                    additional_headers: headers
                        .into_iter()
                        .map(|(name, value)| fo::Header { name, value })
                        .collect(),
                };
                tx.send(Ok(fo::ReadFromAddressResponse {
                    reply_type: Some(fo::read_from_address_response::ReplyType::Redirect(
                        redirect,
                    )),
                }))
                .await
                .ok();
            }
            ReadServerBehavior::Empty | ReadServerBehavior::RejectNotFound => {}
        }
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
        // Drain the params message; chunks (if any) follow but we don't read
        // them since we're testing the redirect path.
        let _params = inbound
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("missing params"))?;
        let behavior = self.behavior.lock().unwrap().clone();
        let (tx, rx) = mpsc::channel(4);
        match behavior {
            WriteServerBehavior::SingleRedirect => {
                let redirect = fo::WriteRedirectProperties {
                    redirect_target_url: "https://upload.example/put".into(),
                    method: fo::UploadMethod::Put as i32,
                    additional_headers: Vec::new(),
                    completion_header_names: vec!["etag".into()],
                };
                tx.send(Ok(fo::WriteResponse {
                    write_response_type: Some(
                        fo::write_response::WriteResponseType::WriteRedirect(redirect),
                    ),
                }))
                .await
                .ok();
            }
            WriteServerBehavior::Multipart { parts } => {
                let first_part = fo::WriteRedirectProperties {
                    redirect_target_url: "https://upload.example/part0".into(),
                    method: fo::UploadMethod::Put as i32,
                    additional_headers: Vec::new(),
                    completion_header_names: vec!["etag".into()],
                };
                tx.send(Ok(fo::WriteResponse {
                    write_response_type: Some(
                        fo::write_response::WriteResponseType::MultipartUpload(
                            fo::CreateMultipartUploadResponse {
                                upload_id: "test-upload-id".into(),
                                first_part_write_redirect: Some(first_part),
                                maximum_parts_number: Some(parts),
                                minimum_size_per_part: Some(1),
                                maximum_size_per_part: Some(1024 * 1024),
                            },
                        ),
                    ),
                }))
                .await
                .ok();
            }
            WriteServerBehavior::Inline => {
                tx.send(Ok(fo::WriteResponse {
                    write_response_type: Some(fo::write_response::WriteResponseType::ResourceInfo(
                        fo::ResourceInfo {
                            resource_identity: Some(fo::ResourceIdentity {
                                encoded_identity: "etag-inline".into(),
                            }),
                            metadata: Some(fo::Metadata {
                                data_object_size: Some(0),
                                last_modified_timestamp: None,
                            }),
                        },
                    )),
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
            .push(req.get_ref().clone());
        Ok(Response::new(fo::CompleteRedirectUploadResponse {
            resource_info: Some(fo::ResourceInfo {
                resource_identity: Some(fo::ResourceIdentity {
                    encoded_identity: "etag-after-redirect".into(),
                }),
                metadata: Some(fo::Metadata {
                    data_object_size: Some(100),
                    last_modified_timestamp: None,
                }),
            }),
        }))
    }

    async fn upload_part(
        &self,
        _req: Request<fo::UploadPartRequest>,
    ) -> std::result::Result<Response<fo::UploadPartResponse>, Status> {
        Ok(Response::new(fo::UploadPartResponse {
            part_write_redirects: vec![fo::WriteRedirectProperties {
                redirect_target_url: "https://upload.example/part1".into(),
                method: fo::UploadMethod::Put as i32,
                additional_headers: Vec::new(),
                completion_header_names: vec!["etag".into()],
            }],
        }))
    }

    async fn complete_multipart_upload(
        &self,
        req: Request<fo::CompleteMultipartUploadRequest>,
    ) -> std::result::Result<Response<fo::CompleteMultipartUploadResponse>, Status> {
        self.recorded
            .lock()
            .unwrap()
            .completed_multiparts
            .push(req.get_ref().clone());
        Ok(Response::new(fo::CompleteMultipartUploadResponse {
            resource_info: Some(fo::ResourceInfo {
                resource_identity: Some(fo::ResourceIdentity {
                    encoded_identity: "etag-after-multipart".into(),
                }),
                metadata: Some(fo::Metadata {
                    data_object_size: Some(2048),
                    last_modified_timestamp: None,
                }),
            }),
        }))
    }

    async fn abort_multipart_upload(
        &self,
        req: Request<fo::AbortMultipartUploadRequest>,
    ) -> std::result::Result<Response<fo::AbortMultipartUploadResponse>, Status> {
        self.recorded
            .lock()
            .unwrap()
            .aborted_multiparts
            .push(req.into_inner());
        Ok(Response::new(fo::AbortMultipartUploadResponse {}))
    }

    async fn delete(
        &self,
        _req: Request<fo::DeleteRequest>,
    ) -> std::result::Result<Response<fo::DeleteResponse>, Status> {
        Ok(Response::new(fo::DeleteResponse {}))
    }

    async fn copy(
        &self,
        req: Request<fo::CopyRequest>,
    ) -> std::result::Result<Response<fo::CopyResponse>, Status> {
        let inner = req.into_inner();
        let rejected_source = inner
            .source_resource_identity
            .as_ref()
            .map(|identity| identity.encoded_identity.as_str() == "rejected-v1")
            .unwrap_or(false);
        self.recorded.lock().unwrap().copy_requests.push(inner);
        if rejected_source {
            return Err(Status::not_found("simulated rejected source identity"));
        }
        Ok(Response::new(fo::CopyResponse {
            resource_identity: Some(fo::ResourceIdentity {
                encoded_identity: "copy-result-etag".into(),
            }),
        }))
    }

    async fn r#move(
        &self,
        req: Request<fo::MoveRequest>,
    ) -> std::result::Result<Response<fo::MoveResponse>, Status> {
        let inner = req.into_inner();
        self.recorded.lock().unwrap().move_requests.push(inner);
        Ok(Response::new(fo::MoveResponse {
            resource_identity: Some(fo::ResourceIdentity {
                encoded_identity: "move-result-etag".into(),
            }),
        }))
    }

    async fn get_optimistic_locking_support(
        &self,
        _req: Request<fo::GetOptimisticLockingSupportRequest>,
    ) -> std::result::Result<Response<fo::GetOptimisticLockingSupportResponse>, Status> {
        let behavior = self.capability_behavior.lock().unwrap().clone();
        let Some(supports_write) = behavior.optimistic_supports_write else {
            return Err(Status::unimplemented("unused"));
        };
        Ok(Response::new(fo::GetOptimisticLockingSupportResponse {
            supports_write,
            supports_delete: false,
            supports_copy: false,
            supports_move: false,
        }))
    }
}

#[derive(Clone)]
struct FakeFileFolderService {
    capability_behavior: Arc<Mutex<CapabilityServerBehavior>>,
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
        _req: Request<ff::ListStatRequest>,
    ) -> std::result::Result<Response<Self::ListStatStream>, Status> {
        Err(Status::unimplemented("unused"))
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
        let behavior = self.capability_behavior.lock().unwrap().clone();
        let Some(folder_mode) = behavior.folder_mode else {
            return Err(Status::unimplemented("unused"));
        };
        Ok(Response::new(ff::GetFolderModeResponse {
            folder_mode: folder_mode as i32,
        }))
    }
}

#[derive(Clone)]
struct FakeVersioningService {
    behavior: Arc<Mutex<VersionServerBehavior>>,
    recorded: Arc<Mutex<Recorded>>,
}

#[tonic::async_trait]
impl ver::versioning_service_server::VersioningService for FakeVersioningService {
    type EnumerateVersionsStream = Pin<
        Box<dyn Stream<Item = std::result::Result<ver::EnumerateVersionsResponse, Status>> + Send>,
    >;

    async fn enumerate_versions(
        &self,
        req: Request<ver::EnumerateVersionsRequest>,
    ) -> std::result::Result<Response<Self::EnumerateVersionsStream>, Status> {
        let request = req.into_inner();
        self.recorded
            .lock()
            .unwrap()
            .enumerate_versions_calls
            .push(request);
        let behavior = self.behavior.lock().unwrap().clone();
        if behavior.reject_invalid_argument {
            return Err(Status::invalid_argument(
                "version resource addresses cannot be enumerated",
            ));
        }
        let responses = behavior.responses;
        let stream = tokio_stream::iter(responses.into_iter().map(Ok));
        Ok(Response::new(Box::pin(stream)))
    }
}

async fn spawn_fake_server(
    behavior: WriteServerBehavior,
) -> (OmniverseStorageBackend, Arc<Mutex<Recorded>>) {
    spawn_fake_server_full(behavior, ReadServerBehavior::default(), AclResponse::None).await
}

async fn spawn_fake_server_with_read(
    behavior: WriteServerBehavior,
    read_behavior: ReadServerBehavior,
) -> (OmniverseStorageBackend, Arc<Mutex<Recorded>>) {
    spawn_fake_server_full(behavior, read_behavior, AclResponse::None).await
}

async fn spawn_fake_server_with_versions(
    version_behavior: VersionServerBehavior,
) -> (OmniverseStorageBackend, Arc<Mutex<Recorded>>) {
    spawn_fake_server_full_with_versions(
        WriteServerBehavior::Inline,
        ReadServerBehavior::default(),
        AclResponse::None,
        version_behavior,
    )
    .await
}

#[derive(Clone)]
enum AclResponse {
    /// Server has no record of this object's metadata at all.
    None,
    /// Server returns an `acl` user-metadata key with the supplied list of
    /// permission tokens.
    Acl(Vec<&'static str>),
    /// Server returns metadata but no `acl` key.
    OtherKey,
}

#[derive(Clone)]
struct FakeMetadataService {
    response: Arc<Mutex<AclResponse>>,
    entries: Arc<Mutex<std::collections::HashMap<String, md::UserMetadataValue>>>,
    recorded: Arc<Mutex<Recorded>>,
}

#[tonic::async_trait]
impl md::metadata_service_server::MetadataService for FakeMetadataService {
    async fn get_metadata(
        &self,
        req: Request<md::GetMetadataRequest>,
    ) -> std::result::Result<Response<md::GetMetadataResponse>, Status> {
        let request = req.into_inner();
        let response = self.response.lock().unwrap().clone();
        let mut user_metadata = self.entries.lock().unwrap().clone();
        user_metadata
            .entry("modified_by".to_string())
            .or_insert_with(|| md::UserMetadataValue {
                value: Some(Value {
                    kind: Some(Kind::StringValue("alice@example".into())),
                }),
                etag: String::new(),
            });
        user_metadata
            .entry("created_by".to_string())
            .or_insert_with(|| md::UserMetadataValue {
                value: Some(Value {
                    kind: Some(Kind::StringValue("bob@example".into())),
                }),
                etag: String::new(),
            });
        match response {
            AclResponse::None => {}
            AclResponse::Acl(tokens) => {
                let values: Vec<Value> = tokens
                    .into_iter()
                    .map(|t| Value {
                        kind: Some(Kind::StringValue(t.into())),
                    })
                    .collect();
                user_metadata.insert(
                    "acl".to_string(),
                    md::UserMetadataValue {
                        value: Some(Value {
                            kind: Some(Kind::ListValue(ListValue { values })),
                        }),
                        etag: String::new(),
                    },
                );
            }
            AclResponse::OtherKey => {
                user_metadata.insert(
                    "label".to_string(),
                    md::UserMetadataValue {
                        value: Some(Value {
                            kind: Some(Kind::StringValue("widget".into())),
                        }),
                        etag: String::new(),
                    },
                );
            }
        }
        if !request.user_metadata_keys.is_empty() {
            user_metadata.retain(|key, _| {
                request
                    .user_metadata_keys
                    .iter()
                    .any(|wanted| wanted == key)
            });
        }
        Ok(Response::new(md::GetMetadataResponse { user_metadata }))
    }

    async fn update_metadata(
        &self,
        req: Request<md::UpdateMetadataRequest>,
    ) -> std::result::Result<Response<md::UpdateMetadataResponse>, Status> {
        let request = req.into_inner();
        let behavior = {
            let mut recorded = self.recorded.lock().unwrap();
            recorded.update_metadata_requests.push(request.clone());
            recorded.update_metadata_behavior.clone()
        };
        match &behavior {
            UpdateMetadataBehavior::Ok => {}
            UpdateMetadataBehavior::AlwaysFail(code) => {
                return Err(Status::new(*code, "fake metadata service refused"));
            }
            UpdateMetadataBehavior::FailKeys(keys, code) => {
                if keys.contains(&request.user_metadata_key) {
                    // Name the key: a test asserting WHICH failure reached the
                    // caller cannot do it if every refusal reads the same.
                    return Err(Status::new(
                        *code,
                        format!("fake refused key {}", request.user_metadata_key),
                    ));
                }
            }
        }
        self.entries.lock().unwrap().insert(
            request.user_metadata_key,
            md::UserMetadataValue {
                value: request.user_metadata,
                etag: "metadata-etag".into(),
            },
        );
        Ok(Response::new(md::UpdateMetadataResponse {
            etag: "metadata-etag".into(),
        }))
    }

    async fn delete_metadata(
        &self,
        req: Request<md::DeleteMetadataRequest>,
    ) -> std::result::Result<Response<md::DeleteMetadataResponse>, Status> {
        let request = req.into_inner();
        self.recorded
            .lock()
            .unwrap()
            .delete_metadata_requests
            .push(request.clone());
        self.entries
            .lock()
            .unwrap()
            .remove(&request.user_metadata_key);
        Ok(Response::new(md::DeleteMetadataResponse {}))
    }
}

async fn spawn_fake_server_full(
    behavior: WriteServerBehavior,
    read_behavior: ReadServerBehavior,
    acl_response: AclResponse,
) -> (OmniverseStorageBackend, Arc<Mutex<Recorded>>) {
    spawn_fake_server_full_with_versions(
        behavior,
        read_behavior,
        acl_response,
        VersionServerBehavior::default(),
    )
    .await
}

async fn spawn_fake_server_full_with_versions(
    behavior: WriteServerBehavior,
    read_behavior: ReadServerBehavior,
    acl_response: AclResponse,
    version_behavior: VersionServerBehavior,
) -> (OmniverseStorageBackend, Arc<Mutex<Recorded>>) {
    spawn_fake_server_full_with_versions_and_capabilities(
        behavior,
        read_behavior,
        acl_response,
        version_behavior,
        CapabilityServerBehavior::default(),
        capabilities(),
    )
    .await
}

async fn spawn_fake_server_full_with_versions_and_capabilities(
    behavior: WriteServerBehavior,
    read_behavior: ReadServerBehavior,
    acl_response: AclResponse,
    version_behavior: VersionServerBehavior,
    capability_behavior: CapabilityServerBehavior,
    base_capabilities: Capabilities,
) -> (OmniverseStorageBackend, Arc<Mutex<Recorded>>) {
    let recorded = Arc::new(Mutex::new(Recorded::default()));
    let capability_behavior = Arc::new(Mutex::new(capability_behavior));
    let service = FakeFileObjectService {
        behavior: Arc::new(Mutex::new(behavior)),
        read_behavior: Arc::new(Mutex::new(read_behavior)),
        capability_behavior: capability_behavior.clone(),
        recorded: recorded.clone(),
    };
    let filefolder_service = FakeFileFolderService {
        capability_behavior: capability_behavior.clone(),
    };
    let metadata_service = FakeMetadataService {
        response: Arc::new(Mutex::new(acl_response)),
        entries: Arc::new(Mutex::new(std::collections::HashMap::new())),
        recorded: recorded.clone(),
    };
    let versioning_service = FakeVersioningService {
        behavior: Arc::new(Mutex::new(version_behavior)),
        recorded: recorded.clone(),
    };
    let (client, server) = tokio::io::duplex(64 * 1024);
    let mut server_io = Some(server);
    let server_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(fo::file_object_service_server::FileObjectServiceServer::new(service))
            .add_service(
                ff::file_folder_service_server::FileFolderServiceServer::new(filefolder_service),
            )
            .add_service(md::metadata_service_server::MetadataServiceServer::new(
                metadata_service,
            ))
            .add_service(
                ver::versioning_service_server::VersioningServiceServer::new(versioning_service),
            )
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
    let auth = DiscoveryState::new("default");
    let transport = OmniverseStorageTransport::with_channel(channel, auth);
    let backend =
        OmniverseStorageBackend::new("http://duplex".into(), base_capabilities, transport);
    // Detach the server task; it shuts down when its duplex peer closes.
    drop(server_task);
    (backend, recorded)
}

fn capabilities() -> Capabilities {
    Capabilities::empty()
}

fn target() -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId("test".into()),
        resolved_address: Url::parse("omni://server/path").unwrap(),
    }
}

fn missing_target() -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId("test".into()),
        resolved_address: Url::parse("omni://server/missing").unwrap(),
    }
}

fn version_info(resource_address: &str, identity: &str, sorting_key: &str) -> ver::VersionInfo {
    ver::VersionInfo {
        resource_info: Some(fo::ResourceInfo {
            resource_identity: Some(fo::ResourceIdentity {
                encoded_identity: identity.into(),
            }),
            metadata: Some(fo::Metadata {
                data_object_size: Some(42),
                last_modified_timestamp: None,
            }),
        }),
        sorting_key: Some(sorting_key.into()),
        resource_address: Some(resource_address.into()),
    }
}

#[tokio::test]
async fn stat_round_trips_through_duplex_channel() {
    let (backend, _) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let info = backend
        .stat(target(), StatOptions::default(), None)
        .await
        .expect("stat ok");
    assert_eq!(info.size, Some(42));
    assert_eq!(info.etag.as_deref(), Some("identity:omni://server/path"));
}

#[tokio::test]
async fn capabilities_for_root_applies_native_folder_mode_and_optimistic_locking() {
    let (backend, _) = spawn_fake_server_full_with_versions_and_capabilities(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Empty,
        AclResponse::None,
        VersionServerBehavior::default(),
        CapabilityServerBehavior {
            folder_mode: Some(ff::FolderMode::Native),
            optimistic_supports_write: Some(true),
        },
        Capabilities::empty(),
    )
    .await;
    let address = target().resolved_address;
    let caps = backend.capabilities_for_root(&address).await;
    assert!(caps.has_real_directories);
    assert!(caps.supports_create_directory);
    assert!(caps.supports_delete_directory);
    assert!(caps.supports_if_match_write);
}

#[tokio::test]
async fn capabilities_for_root_can_turn_off_directory_and_write_locking_bits() {
    let base_capabilities = Capabilities {
        supports_if_match_write: true,
        has_real_directories: true,
        supports_create_directory: true,
        supports_delete_directory: true,
        ..Capabilities::empty()
    };
    let (backend, _) = spawn_fake_server_full_with_versions_and_capabilities(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Empty,
        AclResponse::None,
        VersionServerBehavior::default(),
        CapabilityServerBehavior {
            folder_mode: Some(ff::FolderMode::NoEmpty),
            optimistic_supports_write: Some(false),
        },
        base_capabilities,
    )
    .await;
    let address = target().resolved_address;
    let caps = backend.capabilities_for_root(&address).await;
    assert!(!caps.has_real_directories);
    assert!(!caps.supports_create_directory);
    assert!(!caps.supports_delete_directory);
    assert!(!caps.supports_if_match_write);
}

#[tokio::test]
async fn write_redirect_single_completes_via_complete_redirect_upload() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::SingleRedirect).await;
    let batch = backend
        .write_redirect(
            target(),
            WriteOptions {
                size_hint: Some(1024),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("write_redirect ok");
    assert_eq!(batch.redirects.len(), 1);
    let results = RedirectResultBatch {
        results: vec![RedirectResult {
            status_code: 200,
            captured_headers: vec![("etag".into(), "remote-etag".into())],
            captured_body: Vec::new(),
        }],
    };
    let step = backend
        .continue_write(target(), batch, results, None, None)
        .await
        .expect("continue_write ok");
    match step {
        WriteStep::Done(result) => {
            assert_eq!(result.info.etag.as_deref(), Some("etag-after-redirect"));
        }
        other => panic!("unexpected step: {other:?}"),
    }
    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.completed_redirects.len(), 1);
    let req = &recorded.completed_redirects[0];
    assert_eq!(req.destination_resource_address, "omni://server/path");
    let etag = req
        .additional_headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("etag"));
    assert!(etag.is_some(), "completion header `etag` should round-trip");
}

#[tokio::test]
async fn write_redirect_multipart_aborts_on_part_failure() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Multipart { parts: 2 }).await;
    let batch = backend
        .write_redirect(
            target(),
            WriteOptions {
                size_hint: Some(2 * 1024 * 1024),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("write_redirect ok");
    assert_eq!(batch.redirects.len(), 2);
    // Simulate part 1 failing.
    let results = RedirectResultBatch {
        results: vec![
            RedirectResult {
                status_code: 200,
                captured_headers: vec![("etag".into(), "p0".into())],
                captured_body: Vec::new(),
            },
            RedirectResult {
                status_code: 503,
                captured_headers: Vec::new(),
                captured_body: Vec::new(),
            },
        ],
    };
    let err = backend
        .continue_write(target(), batch, results, None, None)
        .await
        .expect_err("continue_write should fail");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::Transient);
    // Give the abort RPC a moment to flush.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let recorded = recorded.lock().unwrap();
    assert_eq!(
        recorded.aborted_multiparts.len(),
        1,
        "aborter should have fired"
    );
    assert_eq!(recorded.aborted_multiparts[0].upload_id, "test-upload-id");
    assert_eq!(recorded.completed_multiparts.len(), 0);
}

#[tokio::test]
async fn read_streams_chunks_when_server_sends_body() {
    let payload = b"hello-omniverse-storage".to_vec();
    let (backend, _) = spawn_fake_server_with_read(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Chunks {
            payload: payload.clone(),
        },
    )
    .await;
    let result = backend
        .read(target(), ReadOptions::default(), None)
        .await
        .expect("read ok");
    match result {
        ReadResult::Stream { mut stream, info } => {
            assert_eq!(info.size, Some(payload.len() as u64));
            let mut received = Vec::new();
            while let Some(chunk) = stream.next().await {
                received.extend_from_slice(&chunk.expect("chunk ok"));
            }
            assert_eq!(received, payload);
        }
        other => panic!("expected Stream, got {other:?}"),
    }
}

#[tokio::test]
async fn read_returns_redirect_when_server_emits_one() {
    let url = "https://signed.example/blob?sig=abc".to_string();
    let headers = vec![
        (
            "x-amz-server-side-encryption".to_string(),
            "AES256".to_string(),
        ),
        (
            "Authorization".to_string(),
            "AWS4-HMAC-SHA256 …".to_string(),
        ),
    ];
    let (backend, _) = spawn_fake_server_with_read(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Redirect {
            url: url.clone(),
            headers: headers.clone(),
        },
    )
    .await;
    let result = backend
        .read(target(), ReadOptions::default(), None)
        .await
        .expect("read ok");
    match result {
        ReadResult::Redirect(redirect) => {
            assert_eq!(redirect.request.method, "GET");
            assert_eq!(redirect.request.url, url);
            assert_eq!(redirect.request.headers, headers);
            assert_eq!(redirect.scope.physical_url_prefix, url);
            assert!(redirect.scope.operations.read);
            assert!(!redirect.scope.operations.write);
        }
        other => panic!("expected Redirect, got {other:?}"),
    }
}

#[tokio::test]
async fn read_returns_empty_stream_for_zero_byte_object() {
    let (backend, _) =
        spawn_fake_server_with_read(WriteServerBehavior::Inline, ReadServerBehavior::Empty).await;
    let result = backend
        .read(target(), ReadOptions::default(), None)
        .await
        .expect("read ok");
    match result {
        ReadResult::Stream { mut stream, info } => {
            assert_eq!(info.size, Some(0));
            assert!(stream.next().await.is_none(), "stream must be empty");
        }
        other => panic!("expected Stream, got {other:?}"),
    }
}

/// `ReadOptions.if_match` is already the Storage API ResourceIdentity token.
/// The plugin passes it directly to `Read` instead of first resolving
/// the address through `ReadFromAddress`.
#[tokio::test]
async fn read_with_if_match_uses_read_identity_directly() {
    let (backend, recorded) = spawn_fake_server_with_read(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Chunks {
            payload: b"abcdef".to_vec(),
        },
    )
    .await;
    let opts = ReadOptions {
        if_match: Some("etag-v1".into()),
        ..Default::default()
    };
    let result = backend
        .read(target(), opts, None)
        .await
        .expect("if_match identity must return body");
    match result {
        ReadResult::Stream { info, .. } => {
            assert_eq!(info.etag.as_deref(), Some("etag-v1"));
        }
        other => panic!("expected Stream, got {other:?}"),
    }
    let recorded = recorded.lock().unwrap();
    assert_eq!(
        recorded.read_calls.len(),
        1,
        "with if_match, plugin must call Read by identity exactly once",
    );
    let identity = recorded.read_calls[0]
        .resource_identity
        .as_ref()
        .expect("resource_identity populated");
    assert_eq!(identity.encoded_identity, "etag-v1");
    assert!(
        recorded.read_from_address_calls.is_empty(),
        "ReadFromAddress must not be used when if_match already supplies the identity",
    );
}

/// A missing or server-rejected identity is a failed precondition, not
/// a plain missing-address read.
#[tokio::test]
async fn read_with_rejected_if_match_identity_surfaces_object_modified() {
    let (backend, _) = spawn_fake_server_with_read(
        WriteServerBehavior::Inline,
        ReadServerBehavior::RejectNotFound,
    )
    .await;
    let opts = ReadOptions {
        if_match: Some("rejected-v1".into()),
        ..Default::default()
    };
    let err = backend
        .read(target(), opts, None)
        .await
        .expect_err("rejected if_match identity must surface ObjectModified");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::ObjectModified);
}

/// Regression guard: without if_match, the plugin uses
/// `ReadFromAddress` (the latest-version path).
#[tokio::test]
async fn read_without_if_match_uses_read_from_address() {
    let (backend, recorded) = spawn_fake_server_with_read(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Chunks {
            payload: b"abcdef".to_vec(),
        },
    )
    .await;
    let _ = backend
        .read(target(), ReadOptions::default(), None)
        .await
        .expect("read ok");
    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.read_from_address_calls.len(), 1);
    assert!(recorded.read_calls.is_empty());
}

/// `ReadOptions.range` on a chunk-reply path must slice the bytes
/// the plugin is producing. The server only chooses inline streaming
/// for small objects, so a client-side slice is acceptable.
#[tokio::test]
async fn read_with_range_slices_chunked_body() {
    let (backend, _) = spawn_fake_server_with_read(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Chunks {
            payload: b"0123456789".to_vec(),
        },
    )
    .await;
    let opts = ReadOptions {
        range: Some(ByteRange {
            start: 2,
            end_inclusive: Some(5),
        }),
        ..Default::default()
    };
    let result = backend.read(target(), opts, None).await.expect("read ok");
    match result {
        ReadResult::Bytes { bytes, info } => {
            assert_eq!(&bytes[..], b"2345");
            // Info should describe the underlying object, not the slice.
            assert_eq!(info.size, Some(10));
        }
        other => panic!("expected Bytes for ranged read, got {other:?}"),
    }
}

/// `ReadOptions.range` on a redirect-reply path: the plugin returns
/// `ReadResult::Redirect` unchanged — the host is responsible for
/// injecting the `Range:` header into the redirect request before
/// following. This test guards against the plugin double-injecting.
#[tokio::test]
async fn read_with_range_redirect_passes_through_unchanged() {
    let url = "https://signed.example/blob?sig=abc".to_string();
    let (backend, _) = spawn_fake_server_with_read(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Redirect {
            url: url.clone(),
            headers: vec![],
        },
    )
    .await;
    let opts = ReadOptions {
        range: Some(ByteRange {
            start: 100,
            end_inclusive: Some(199),
        }),
        ..Default::default()
    };
    let result = backend.read(target(), opts, None).await.expect("read ok");
    match result {
        ReadResult::Redirect(redirect) => {
            assert_eq!(redirect.request.url, url);
            assert!(
                redirect
                    .request
                    .headers
                    .iter()
                    .all(|(name, _)| !name.eq_ignore_ascii_case("range")),
                "plugin must NOT pre-inject Range; host owns this. got headers={:?}",
                redirect.request.headers,
            );
        }
        other => panic!("expected Redirect, got {other:?}"),
    }
}

/// Server-side NOT_FOUND on an identity read means the caller's
/// `if_match` etag/resource identity does not name readable bytes, so the
/// precondition failed.
#[tokio::test]
async fn read_with_missing_identity_surfaces_object_modified() {
    let (backend, _) = spawn_fake_server_with_read(
        WriteServerBehavior::Inline,
        ReadServerBehavior::RejectNotFound,
    )
    .await;
    let opts = ReadOptions {
        if_match: Some("gone".into()),
        ..Default::default()
    };
    let err = backend
        .read(target(), opts, None)
        .await
        .expect_err("missing if_match identity must surface ObjectModified");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::ObjectModified);
}

/// `range.end_inclusive < range.start` is an invalid range. The plugin
/// must reject it with InvalidArgument before slicing — without
/// validation, `buf[start..end_exclusive]` would panic and (under the
/// workspace's panic policy) abort the process.
#[tokio::test]
async fn read_with_inverted_range_returns_invalid_argument() {
    let (backend, _) = spawn_fake_server_with_read(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Chunks {
            payload: b"0123456789".to_vec(),
        },
    )
    .await;
    let opts = ReadOptions {
        range: Some(ByteRange {
            start: 5,
            end_inclusive: Some(2),
        }),
        ..Default::default()
    };
    let err = backend
        .read(target(), opts, None)
        .await
        .expect_err("inverted range must fail validation, not panic the slice");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::InvalidArgument);
}

/// `WriteOptions.no_overwrite = true` must be refused. The plugin
/// advertises `supports_no_overwrite_write = false` and the OvCS proto
/// has no wire field to enforce it, so silently overwriting would
/// break the caller's atomic-create guarantee.
#[tokio::test]
async fn write_refuses_no_overwrite() {
    let (backend, _) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = WriteOptions {
        if_dest: IfDestExists::Fail,
        ..Default::default()
    };
    let err = backend
        .write(target(), b"hello".to_vec(), opts, None)
        .await
        .expect_err("write must refuse no_overwrite, not silently overwrite");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::Unsupported);
}

#[tokio::test]
async fn write_stream_refuses_no_overwrite() {
    use ovstorage_plugin::BodyStream;
    let (backend, _) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = WriteOptions {
        if_dest: IfDestExists::Fail,
        ..Default::default()
    };
    let body = BodyStream::from_iter(vec![Ok(b"hello".to_vec())].into_iter());
    let err = backend
        .write_stream(target(), body, opts, None)
        .await
        .expect_err("write_stream must refuse no_overwrite");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::Unsupported);
}

#[tokio::test]
async fn write_redirect_refuses_no_overwrite() {
    let (backend, _) = spawn_fake_server(WriteServerBehavior::SingleRedirect).await;
    let opts = WriteOptions {
        if_dest: IfDestExists::Fail,
        size_hint: Some(1024),
        ..Default::default()
    };
    let err = backend
        .write_redirect(target(), opts, None)
        .await
        .expect_err("write_redirect must refuse no_overwrite");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::Unsupported);
}

/// The plugin advertises `supports_recursive_list = false`, and the
/// OvCS ListStat RPC is single-level only. The host doesn't
/// post-filter recursive=true away, so the plugin must refuse with
/// Unsupported — otherwise the caller silently gets a one-level
/// enumeration in place of the full subtree.
#[tokio::test]
async fn list_refuses_recursive() {
    let (backend, _) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = ListOptions {
        recursive: true,
        ..Default::default()
    };
    let err = backend
        .list(target(), opts, None)
        .await
        .expect_err("recursive list must be refused");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::Unsupported);
}

/// EnumerateVersions has no pagination knobs on the wire, and the
/// host doesn't paginate list_versions for the plugin. Honor the
/// caller's bounded request or refuse — silently returning every
/// version when they asked for a page is wrong.
#[tokio::test]
async fn list_versions_refuses_max_results() {
    let (backend, _) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = ListVersionsOptions {
        max_results: Some(10),
        ..Default::default()
    };
    let err = backend
        .list_versions(target(), opts, None)
        .await
        .expect_err("list_versions must refuse max_results");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::Unsupported);
}

#[tokio::test]
async fn list_versions_refuses_page_token() {
    let (backend, _) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = ListVersionsOptions {
        page_token: Some("cursor".into()),
        ..Default::default()
    };
    let err = backend
        .list_versions(target(), opts, None)
        .await
        .expect_err("list_versions must refuse page_token");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::Unsupported);
}

#[tokio::test]
async fn list_versions_uses_resource_address_for_version_address() {
    let (backend, _) = spawn_fake_server_with_versions(VersionServerBehavior {
        responses: vec![ver::EnumerateVersionsResponse {
            versions_order: ver::VersionsOrder::NewestFirst as i32,
            items: vec![
                version_info("omni://server/path?version=v2", "identity-v2", "k2"),
                version_info("omni://server/path?version=v1", "identity-v1", "k1"),
            ],
        }],
        ..Default::default()
    })
    .await;
    let versions = backend
        .list_versions(target(), ListVersionsOptions::default(), None)
        .await
        .expect("list_versions ok");
    assert_eq!(versions.len(), 2);
    assert_eq!(
        versions[0].address.as_str(),
        "omni://server/path?version=v2"
    );
    assert_eq!(versions[0].etag.as_deref(), Some("identity-v2"));
    assert_eq!(
        versions[1].address.as_str(),
        "omni://server/path?version=v1"
    );
}

#[tokio::test]
async fn list_versions_refuses_items_without_resource_address() {
    let mut item = version_info("omni://server/path?version=v1", "identity-v1", "k1");
    item.resource_address = None;
    let (backend, _) = spawn_fake_server_with_versions(VersionServerBehavior {
        responses: vec![ver::EnumerateVersionsResponse {
            versions_order: ver::VersionsOrder::NewestFirst as i32,
            items: vec![item],
        }],
        ..Default::default()
    })
    .await;
    let err = backend
        .list_versions(target(), ListVersionsOptions::default(), None)
        .await
        .expect_err("missing resource_address is unsupported");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::Unsupported);
}

#[tokio::test]
async fn list_versions_refuses_service_rejected_version_address() {
    let (backend, _) = spawn_fake_server_with_versions(VersionServerBehavior {
        reject_invalid_argument: true,
        ..Default::default()
    })
    .await;
    let err = backend
        .list_versions(target(), ListVersionsOptions::default(), None)
        .await
        .expect_err("opaque version address cannot be expanded to full history");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::Unsupported);
}

#[tokio::test]
async fn get_latest_version_selects_first_item_when_newest_first() {
    let (backend, recorded) = spawn_fake_server_with_versions(VersionServerBehavior {
        responses: vec![ver::EnumerateVersionsResponse {
            versions_order: ver::VersionsOrder::NewestFirst as i32,
            items: vec![
                version_info("omni://server/path?version=v3", "identity-v3", "k3"),
                version_info("omni://server/path?version=v2", "identity-v2", "k2"),
            ],
        }],
        ..Default::default()
    })
    .await;
    let latest = backend
        .get_latest_version(target(), None)
        .await
        .expect("latest ok");
    assert_eq!(latest.address.as_str(), "omni://server/path?version=v3");
    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.enumerate_versions_calls.len(), 1);
    assert_eq!(
        recorded.enumerate_versions_calls[0].resource_address,
        "omni://server/path"
    );
}

#[tokio::test]
async fn get_latest_version_stats_service_rejected_version_address() {
    let address = "omni://server/path;2";
    let (backend, recorded) = spawn_fake_server_with_versions(VersionServerBehavior {
        reject_invalid_argument: true,
        ..Default::default()
    })
    .await;
    let pinned = ResolvedTarget {
        backend_id: BackendId("test".into()),
        resolved_address: Url::parse(address).unwrap(),
    };
    let latest = backend
        .get_latest_version(pinned, None)
        .await
        .expect("pinned latest ok");
    assert_eq!(latest.address.as_str(), address);
    let expected_etag = format!("identity:{address}");
    assert_eq!(latest.etag.as_deref(), Some(expected_etag.as_str()));
    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.enumerate_versions_calls.len(), 1);
    assert_eq!(recorded.stat_calls, 1);
}

#[tokio::test]
async fn get_latest_version_selects_last_item_when_oldest_first() {
    let (backend, _) = spawn_fake_server_with_versions(VersionServerBehavior {
        responses: vec![ver::EnumerateVersionsResponse {
            versions_order: ver::VersionsOrder::OldestFirst as i32,
            items: vec![
                version_info("omni://server/path?version=v1", "identity-v1", "k1"),
                version_info("omni://server/path?version=v2", "identity-v2", "k2"),
            ],
        }],
        ..Default::default()
    })
    .await;
    let latest = backend
        .get_latest_version(target(), None)
        .await
        .expect("latest ok");
    assert_eq!(latest.address.as_str(), "omni://server/path?version=v2");
}

#[tokio::test]
async fn get_latest_version_selects_max_sorting_key_when_by_key() {
    let (backend, _) = spawn_fake_server_with_versions(VersionServerBehavior {
        responses: vec![ver::EnumerateVersionsResponse {
            versions_order: ver::VersionsOrder::ByKey as i32,
            items: vec![
                version_info("omni://server/path?version=v2", "identity-v2", "b"),
                version_info("omni://server/path?version=v3", "identity-v3", "z"),
                version_info("omni://server/path?version=v1", "identity-v1", "a"),
            ],
        }],
        ..Default::default()
    })
    .await;
    let latest = backend
        .get_latest_version(target(), None)
        .await
        .expect("latest ok");
    assert_eq!(latest.address.as_str(), "omni://server/path?version=v3");
}

#[tokio::test]
async fn get_latest_version_refuses_unspecified_order() {
    let (backend, _) = spawn_fake_server_with_versions(VersionServerBehavior {
        responses: vec![ver::EnumerateVersionsResponse {
            versions_order: ver::VersionsOrder::Unspecified as i32,
            items: vec![version_info(
                "omni://server/path?version=v1",
                "identity-v1",
                "k1",
            )],
        }],
        ..Default::default()
    })
    .await;
    let err = backend
        .get_latest_version(target(), None)
        .await
        .expect_err("unspecified order is unsupported");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::Unsupported);
}

/// `write_redirect` without a `size_hint` cannot produce a valid
/// `RedirectBodySource::UserBytes { len }` (the host's redirect
/// follower needs an exact byte count). Refuse rather than emit a
/// redirect with `len = u64::MAX`, which the follower would fail at
/// EOF.
#[tokio::test]
async fn write_redirect_without_size_hint_returns_unsupported() {
    let (backend, _) = spawn_fake_server(WriteServerBehavior::SingleRedirect).await;
    let err = backend
        .write_redirect(target(), WriteOptions::default(), None)
        .await
        .expect_err("redirect with unknown size must be refused");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::Unsupported);
}

// === Etag-only if_match (the supported precondition shape) ===
//
// The SPI's `if_match` is a single opaque etag string. These tests pin
// that the etag-only precondition path is accepted (not rejected) at
// the SPI entry points.

/// Sanity guard: etag-only `if_match` is the supported precondition
/// shape and must NOT be rejected. Exercised via `delete` because that
/// path's behavior is simple (Ok on success).
#[tokio::test]
async fn delete_accepts_etag_only_if_match() {
    let (backend, _) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = DeleteOptions {
        if_match: Some("v1".into()),
    };
    backend
        .delete(target(), opts, None)
        .await
        .expect("etag-only if_match must be accepted");
}

#[tokio::test]
async fn stat_full_metadata_populates_modified_by_and_system_metadata() {
    let (backend, _) = spawn_fake_server_full(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Empty,
        AclResponse::None,
    )
    .await;
    let info = backend
        .stat(
            target(),
            StatOptions {
                full_metadata: true,
            },
            None,
        )
        .await
        .expect("stat ok");
    assert_eq!(info.modified_by.as_deref(), Some("alice@example"));
    let sys = info.system_metadata.expect("system_metadata populated");
    assert_eq!(
        sys.get("modified_by").map(String::as_str),
        Some("alice@example")
    );
    assert_eq!(
        sys.get("created_by").map(String::as_str),
        Some("bob@example")
    );
    let user = info.user_metadata.expect("user_metadata populated");
    assert_eq!(
        user.get("modified_by").map(String::as_str),
        Some("alice@example")
    );
    assert_eq!(
        user.get("created_by").map(String::as_str),
        Some("bob@example")
    );
}

#[tokio::test]
async fn stat_default_skips_metadata_round_trip() {
    let (backend, _) = spawn_fake_server_full(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Empty,
        AclResponse::None,
    )
    .await;
    let info = backend
        .stat(target(), StatOptions::default(), None)
        .await
        .expect("stat ok");
    // No full_metadata → no GetMetadata call → no modified_by populated.
    assert!(info.modified_by.is_none());
    assert!(info.system_metadata.is_none());
    assert!(info.user_metadata.is_none());
}

#[tokio::test]
async fn check_access_grants_when_acl_lists_read_and_write() {
    let (backend, _) = spawn_fake_server_full(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Empty,
        AclResponse::Acl(vec!["read", "write"]),
    )
    .await;
    let decision: AccessDecision = backend
        .check_access(
            target(),
            AccessOps {
                read: true,
                write: true,
                update_metadata: true,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("check_access ok");
    assert!(decision.allowed);
    assert_eq!(decision.denied_ops, AccessOps::default());
    assert!(decision.reason.is_none());
}

#[tokio::test]
async fn check_access_denies_delete_without_admin() {
    let (backend, _) = spawn_fake_server_full(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Empty,
        AclResponse::Acl(vec!["read", "write"]),
    )
    .await;
    let decision = backend
        .check_access(
            target(),
            AccessOps {
                read: true,
                delete: true,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("check_access ok");
    assert!(!decision.allowed);
    assert_eq!(
        decision.denied_ops,
        AccessOps {
            delete: true,
            ..Default::default()
        }
    );
    assert!(decision.reason.is_some());
}

#[tokio::test]
async fn check_access_grants_all_when_acl_absent() {
    let (backend, _) = spawn_fake_server_full(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Empty,
        AclResponse::OtherKey,
    )
    .await;
    let decision = backend
        .check_access(
            target(),
            AccessOps {
                read: true,
                write: true,
                delete: true,
                update_metadata: true,
            },
            None,
        )
        .await
        .expect("check_access ok");
    assert!(decision.allowed);
    assert_eq!(decision.denied_ops, AccessOps::default());
}

#[tokio::test]
async fn check_access_stats_target_before_acl_lookup() {
    let (backend, recorded) = spawn_fake_server_full(
        WriteServerBehavior::Inline,
        ReadServerBehavior::Empty,
        AclResponse::OtherKey,
    )
    .await;
    let err = backend
        .check_access(
            missing_target(),
            AccessOps {
                read: true,
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("missing target must not be granted by empty metadata");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::NotFound);
    assert_eq!(recorded.lock().unwrap().stat_calls, 1);
}

#[tokio::test]
async fn update_metadata_returns_refreshed_info_with_user_metadata() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let mut opts = UpdateMetadataOptions::default();
    opts.user_metadata_set.insert("label".into(), "hero".into());
    opts.user_metadata_remove.push("obsolete".into());
    let info = backend
        .update_metadata(target(), opts, None)
        .await
        .expect("update_metadata ok");
    assert_eq!(info.size, Some(42));
    assert_eq!(info.etag.as_deref(), Some("identity:omni://server/path"));
    let user = info.user_metadata.expect("user metadata returned");
    assert_eq!(user.get("label").map(String::as_str), Some("hero"));
    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.update_metadata_requests.len(), 1);
    assert_eq!(
        recorded.update_metadata_requests[0]
            .expected_etag
            .as_deref(),
        None
    );
    assert_eq!(recorded.delete_metadata_requests.len(), 1);
    assert_eq!(
        recorded.delete_metadata_requests[0]
            .expected_etag
            .as_deref(),
        None
    );
}

/// End-to-end smoke for the `client_credentials` OAuth grant: stand up a
/// mock OIDC IDP that serves `/api/v1/auth-config`, the OIDC discovery
/// document, and a `/token` endpoint; call `build_auth_state` with
/// `client_id`/`client_secret` credentials; verify the grant drove
/// through to the IDP and installed an access token. Then wire the
/// resulting `DiscoveryState` into a duplex tonic channel + stat an
/// object to prove the bearer-equipped state really works for real RPCs.
#[tokio::test]
async fn client_credentials_e2e() {
    use ovstorage_plugin::{ConnectionRequest, SecretBundle, SecretBytes, SecretValue};
    use ovstorage_plugin_services_client::config as plugin_config;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // ---- Mock OIDC / discovery HTTP server. -------------------------------
    let idp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp_addr = idp.local_addr().unwrap();
    let idp_base = format!("http://{idp_addr}");
    let token_endpoint = format!("{idp_base}/token");
    let auth_config_body = serde_json::json!({
        "openid_configuration": format!("{idp_base}/.well-known/openid-configuration"),
        "clients": {
            "default": {
                "client_id": "ignored-default-config-client",
                "scope": "storage.read"
            }
        }
    })
    .to_string();
    let oidc_body = serde_json::json!({
        "issuer": idp_base,
        "token_endpoint": token_endpoint,
    })
    .to_string();
    let token_body = r#"{"access_token":"e2e-access","token_type":"Bearer","expires_in":300}"#;
    let captured_form: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_for_task = Arc::clone(&captured_form);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = idp.accept().await else {
                return;
            };
            let captured = Arc::clone(&captured_for_task);
            let auth_config_body = auth_config_body.clone();
            let oidc_body = oidc_body.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut total = 0usize;
                let mut content_length: Option<usize> = None;
                let mut header_end: Option<usize> = None;
                loop {
                    if total >= buf.len() {
                        break;
                    }
                    let n = match sock.read(&mut buf[total..]).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    total += n;
                    if header_end.is_none()
                        && let Some(idx) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n")
                    {
                        header_end = Some(idx + 4);
                        let header_str = String::from_utf8_lossy(&buf[..idx]).to_string();
                        for line in header_str.lines() {
                            if let Some(value) = line
                                .strip_prefix("Content-Length:")
                                .or_else(|| line.strip_prefix("content-length:"))
                            {
                                content_length = value.trim().parse().ok();
                            }
                        }
                    }
                    if let Some(hend) = header_end {
                        if matches!(content_length, Some(cl) if total >= hend + cl) {
                            break;
                        }
                        if content_length.is_none() {
                            // GET with no body; we're done.
                            break;
                        }
                    }
                }
                let request_str = String::from_utf8_lossy(&buf[..total]).into_owned();
                let first_line = request_str.lines().next().unwrap_or("");
                let mut parts = first_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");
                let (status, body) = if path.starts_with("/api/v1/auth-config") {
                    (200, auth_config_body)
                } else if path.starts_with("/.well-known/openid-configuration") {
                    (200, oidc_body)
                } else if path.starts_with("/token") && method == "POST" {
                    let header_end = header_end.unwrap_or(total);
                    let body = String::from_utf8_lossy(&buf[header_end..total]).into_owned();
                    captured.lock().unwrap().push(body);
                    (200, token_body.to_string())
                } else {
                    (404, "{}".into())
                };
                let response = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: \
                     {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    // ---- Drive build_auth_state through the client_credentials path. ------
    let mut credentials = SecretBundle::default();
    credentials.fields.insert(
        "client_id".into(),
        SecretValue::Bytes(SecretBytes(b"e2e-client".to_vec())),
    );
    credentials.fields.insert(
        "client_secret".into(),
        SecretValue::Bytes(SecretBytes(b"e2e-secret".to_vec())),
    );
    let request = ConnectionRequest {
        backend_kind: plugin_config::KIND.into(),
        display_name: Some("e2e-client-credentials".into()),
        config: std::collections::HashMap::new(),
        credentials,
        persist: false,
    };
    let (state, auth_state) = build_auth_state(Some(idp_base.as_str()), &request)
        .await
        .expect("build_auth_state should succeed against mock IDP");
    match auth_state {
        ovstorage_plugin::ConnectionAuthState::Authenticated { .. } => {}
        other => panic!("expected Authenticated, got {other:?}"),
    }
    assert_eq!(
        state.access_token().await.as_deref(),
        Some("e2e-access"),
        "access token must be installed from the token endpoint",
    );
    assert_eq!(
        state.client_credentials().await,
        Some(("e2e-client".into(), "e2e-secret".into())),
        "client_credentials must be cached on the state for future refresh",
    );
    let forms = captured_form.lock().unwrap().clone();
    assert_eq!(forms.len(), 1, "exactly one /token POST");
    let pairs: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(forms[0].as_bytes())
            .into_owned()
            .collect();
    assert_eq!(
        pairs.get("grant_type").map(String::as_str),
        Some("client_credentials"),
    );
    assert_eq!(
        pairs.get("client_id").map(String::as_str),
        Some("e2e-client")
    );
    assert_eq!(
        pairs.get("client_secret").map(String::as_str),
        Some("e2e-secret"),
    );

    // ---- Wire the authenticated state into a duplex transport + stat. -----
    let recorded = Arc::new(Mutex::new(Recorded::default()));
    let service = FakeFileObjectService {
        behavior: Arc::new(Mutex::new(WriteServerBehavior::Inline)),
        read_behavior: Arc::new(Mutex::new(ReadServerBehavior::Empty)),
        capability_behavior: Arc::new(Mutex::new(CapabilityServerBehavior::default())),
        recorded: recorded.clone(),
    };
    let (client, server) = tokio::io::duplex(64 * 1024);
    let mut server_io = Some(server);
    let server_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(fo::file_object_service_server::FileObjectServiceServer::new(service))
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
    let transport = OmniverseStorageTransport::with_channel(channel, state);
    let backend = OmniverseStorageBackend::new(idp_base.clone(), capabilities(), transport);
    let info = backend
        .stat(target(), StatOptions::default(), None)
        .await
        .expect("stat must succeed using the access token from client_credentials grant");
    assert_eq!(info.size, Some(42));
    drop(server_task);
    let _ = recorded;
}

fn dest_target() -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId("test".into()),
        resolved_address: Url::parse("omni://server/dest").unwrap(),
    }
}

/// CopyRequest.source_resource_identity is REQUIRED by the proto and
/// must be a server-issued opaque identity (the server tries to
/// recover the URL via url_from_identity, so a raw URL would fail).
/// When the caller doesn't supply if_match, the plugin must Stat the
/// source first to get a valid identity.
#[tokio::test]
async fn copy_without_if_match_stats_source_for_identity() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    backend
        .copy(target(), dest_target(), CopyOptions::default(), None)
        .await
        .expect("copy ok");
    let recorded = recorded.lock().unwrap();
    assert!(
        recorded.stat_calls >= 1,
        "without if_match, plugin must Stat source for identity (stat_calls={})",
        recorded.stat_calls,
    );
    assert_eq!(recorded.copy_requests.len(), 1);
    let identity = recorded.copy_requests[0]
        .source_resource_identity
        .as_ref()
        .expect("source_resource_identity must be populated")
        .encoded_identity
        .as_str();
    assert!(
        identity.starts_with("identity:"),
        "source_resource_identity must come from Stat (got {identity:?})",
    );
    assert_ne!(
        identity, "omni://server/path",
        "source_resource_identity must NOT be the raw URL",
    );
}

/// When `if_source` is supplied, it is already the Storage API source
/// ResourceIdentity. The plugin must pass it straight through and skip
/// the source Stat.
#[tokio::test]
async fn copy_with_if_source_uses_identity_directly() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = CopyOptions {
        if_source: Some("source-etag-v1".into()),
        ..Default::default()
    };
    backend
        .copy(target(), dest_target(), opts, None)
        .await
        .expect("copy with if_source must succeed");
    let recorded = recorded.lock().unwrap();
    assert_eq!(
        recorded.stat_calls, 0,
        "if_source already supplies the source ResourceIdentity; source Stat must be skipped",
    );
    assert_eq!(recorded.copy_requests.len(), 1);
    let identity = recorded.copy_requests[0]
        .source_resource_identity
        .as_ref()
        .expect("source_resource_identity must be populated")
        .encoded_identity
        .as_str();
    assert_eq!(
        identity, "source-etag-v1",
        "copy must use the caller-supplied source identity",
    );
    assert!(
        recorded.copy_requests[0].previous_version.is_none(),
        "SPI's if_source is a source precondition; previous_version (destination) must stay unset",
    );
}

/// CopyRequest.previous_version is the destination-side optimistic
/// lock. The source side is always source_resource_identity.
#[tokio::test]
async fn copy_with_if_dest_match_etag_puts_etag_on_previous_version() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = CopyOptions {
        if_source: Some("source-etag-v1".into()),
        if_dest: IfDestExists::MatchEtag("dest-etag-v1".into()),
        ..Default::default()
    };
    backend
        .copy(target(), dest_target(), opts, None)
        .await
        .expect("copy with destination precondition must succeed");
    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.copy_requests.len(), 1);
    let req = &recorded.copy_requests[0];
    assert_eq!(
        req.source_resource_identity
            .as_ref()
            .expect("source_resource_identity must be populated")
            .encoded_identity,
        "source-etag-v1",
    );
    assert_eq!(
        req.previous_version
            .as_ref()
            .expect("previous_version must carry destination precondition")
            .encoded_identity,
        "dest-etag-v1",
    );
}

/// If the server rejects the supplied source identity as missing or
/// otherwise invalid, surface the source precondition failure as
/// `ObjectModified`.
#[tokio::test]
async fn copy_with_rejected_if_source_identity_surfaces_object_modified() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = CopyOptions {
        if_source: Some("rejected-v1".into()),
        ..Default::default()
    };
    let err = backend
        .copy(target(), dest_target(), opts, None)
        .await
        .expect_err("rejected if_source must surface ObjectModified");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::ObjectModified);
    let recorded = recorded.lock().unwrap();
    assert_eq!(
        recorded.stat_calls, 0,
        "with if_source, plugin must not Stat before trying the supplied identity",
    );
    assert_eq!(recorded.copy_requests.len(), 1);
}

/// MoveRequest's `source_previous_version` is the source-side
/// precondition; `destination_previous_version` is the destination-side
/// one. SPI semantics for RenameOptions.if_match protect the source,
/// so it must land on source_previous_version.
#[tokio::test]
async fn rename_with_if_match_puts_etag_on_source_previous_version() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = RenameOptions {
        if_source: Some("src-etag".into()),
        ..Default::default()
    };
    backend
        .rename(target(), dest_target(), opts, None)
        .await
        .expect("rename ok");
    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.move_requests.len(), 1);
    let req = &recorded.move_requests[0];
    let src_pv = req
        .source_previous_version
        .as_ref()
        .expect("source_previous_version must carry the if_match etag");
    assert_eq!(src_pv.encoded_identity, "src-etag");
    assert!(
        req.destination_previous_version.is_none(),
        "destination_previous_version must stay unset; SPI if_match is source-side",
    );
}

// Silence dead-code warnings for fields that exist only so the SPI
// surface compiles cleanly in tests.
#[allow(dead_code)]
fn _unused_drop() {
    let _: ChecksumSet = ChecksumSet::default();
    let _: ObjectKind = ObjectKind::File;
    let _: Bytes = Bytes::new();
    let _: ObjectInfo = ObjectInfo {
        address: Url::parse("a:b").unwrap(),
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
    };
    let _: AccessOps = AccessOps::default();
    let _: DeleteOptions = DeleteOptions::default();
}

/// Substitution, not modification: a caller holding a genuine multipart
/// continuation minted for `omni://server/path` presents it against the
/// authorized request address `omni://server/victim`. Under the broker's
/// client-driven `ContinueWrite` RPC the batch is echoed back by the remote
/// caller, so the completion — and the abort behind it — must name the address
/// authorization was decided on.
#[tokio::test]
async fn continue_write_completes_against_the_authorized_destination() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Multipart { parts: 2 }).await;
    let minted_for = target();
    let authorized = ResolvedTarget {
        backend_id: BackendId("test".into()),
        resolved_address: Url::parse("omni://server/victim").unwrap(),
    };
    let batch = backend
        .write_redirect(
            minted_for,
            WriteOptions {
                size_hint: Some(2 * 1024 * 1024),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("write_redirect ok");
    assert_eq!(batch.redirects.len(), 2);
    let results = RedirectResultBatch {
        results: (0..2)
            .map(|idx| RedirectResult {
                status_code: 200,
                captured_headers: vec![("etag".into(), format!("p{idx}"))],
                captured_body: Vec::new(),
            })
            .collect(),
    };
    backend
        .continue_write(authorized, batch, results, None, None)
        .await
        .expect("continue_write ok");

    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.completed_multiparts.len(), 1);
    assert_eq!(
        recorded.completed_multiparts[0].destination_resource_address, "omni://server/victim",
        "CompleteMultipartUpload must name the authorized destination, not the continuation's"
    );
    // The server-issued upload id still rides along from the continuation —
    // it is not derivable — but it no longer chooses the object.
    assert_eq!(recorded.completed_multiparts[0].upload_id, "test-upload-id");
}

/// The aborter takes the derived destination too, not just the completions.
/// Mint for `omni://server/path`, continue against `omni://server/victim`, and
/// force a part failure — the recorded abort must name the authorized address.
#[tokio::test]
async fn continue_write_aborts_against_the_authorized_destination() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Multipart { parts: 2 }).await;
    let authorized = ResolvedTarget {
        backend_id: BackendId("test".into()),
        resolved_address: Url::parse("omni://server/victim").unwrap(),
    };
    let batch = backend
        .write_redirect(
            target(),
            WriteOptions {
                size_hint: Some(2 * 1024 * 1024),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("write_redirect ok");
    let results = RedirectResultBatch {
        results: vec![
            RedirectResult {
                status_code: 200,
                captured_headers: vec![("etag".into(), "p0".into())],
                captured_body: Vec::new(),
            },
            RedirectResult {
                status_code: 503,
                captured_headers: Vec::new(),
                captured_body: Vec::new(),
            },
        ],
    };
    backend
        .continue_write(authorized, batch, results, None, None)
        .await
        .expect_err("a failed part must surface as an error");
    // No sleep: `abort_now().await` is awaited inline before `continue_write`
    // returns, so the recording is already complete here.
    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.aborted_multiparts.len(), 1);
    assert_eq!(
        recorded.aborted_multiparts[0].destination_resource_address, "omni://server/victim",
        "the abort must name the authorized destination, not the continuation's"
    );
    assert_eq!(recorded.completed_multiparts.len(), 0);
}

/// The single-redirect branch substitutes the destination too, and only the
/// multipart branch was covered.
#[tokio::test]
async fn continue_write_single_redirect_completes_against_the_authorized_destination() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::SingleRedirect).await;
    let authorized = ResolvedTarget {
        backend_id: BackendId("test".into()),
        resolved_address: Url::parse("omni://server/victim").unwrap(),
    };
    let batch = backend
        .write_redirect(
            target(),
            WriteOptions {
                size_hint: Some(1024),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("write_redirect ok");
    let results = RedirectResultBatch {
        results: vec![RedirectResult {
            status_code: 200,
            captured_headers: vec![("etag".into(), "remote-etag".into())],
            captured_body: Vec::new(),
        }],
    };
    backend
        .continue_write(authorized, batch, results, None, None)
        .await
        .expect("continue_write ok");

    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.completed_redirects.len(), 1);
    assert_eq!(
        recorded.completed_redirects[0].destination_resource_address, "omni://server/victim",
        "CompleteRedirectUpload must name the authorized destination"
    );
}

/// Substitution, not modification: a genuine multipart continuation for the
/// authorized object, whose reserved attribution key names someone else. The
/// commit stashes the continuation's metadata through the metadata service, so
/// a host assertion on the request has to win over what travelled.
///
/// Shaped so only that assertion can catch it — same object, same upload id,
/// same part count, so the address derivation and the count check are both
/// satisfied by the input.
#[tokio::test]
async fn continue_write_stashes_the_asserted_writer_over_the_continuations() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Multipart { parts: 2 }).await;
    let mut planted = std::collections::HashMap::new();
    planted.insert(
        "ovstorage-modified-by".to_string(),
        "impersonated-principal".to_string(),
    );
    planted.insert("author".to_string(), "unreserved".to_string());
    let batch = backend
        .write_redirect(
            target(),
            WriteOptions {
                size_hint: Some(2 * 1024 * 1024),
                user_metadata: Some(planted),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("write_redirect ok");
    assert_eq!(batch.redirects.len(), 2);
    let results = RedirectResultBatch {
        results: (0..2)
            .map(|idx| RedirectResult {
                status_code: 200,
                captured_headers: vec![("etag".into(), format!("p{idx}"))],
                captured_body: Vec::new(),
            })
            .collect(),
    };
    backend
        .continue_write(target(), batch, results, Some("alice@example.com"), None)
        .await
        .expect("continue_write ok");

    let recorded = recorded.lock().unwrap();
    let stashed: std::collections::HashMap<&str, Option<&str>> = recorded
        .update_metadata_requests
        .iter()
        .map(|request| {
            (
                request.user_metadata_key.as_str(),
                request
                    .user_metadata
                    .as_ref()
                    .and_then(|value| match value.kind.as_ref() {
                        Some(
                            ovstorage_services_protos::google::protobuf::value::Kind::StringValue(
                                s,
                            ),
                        ) => Some(s.as_str()),
                        _ => None,
                    }),
            )
        })
        .collect();
    assert!(
        !stashed.is_empty(),
        "the commit must have stashed something to assert about"
    );
    assert_eq!(
        stashed.get("ovstorage-modified-by").copied().flatten(),
        Some("alice@example.com"),
        "the asserted writer must be what the commit stashes"
    );
    assert_eq!(
        stashed.get("author").copied().flatten(),
        Some("unreserved"),
        "unreserved caller metadata must still be stashed"
    );
}

/// With no host assertion — a direct Stack, or a branch composed not to
/// attribute — the continuation's metadata is stashed exactly as it arrived.
/// Pins the decision that the plugin does not derive attribution for itself.
#[tokio::test]
async fn continue_write_without_an_assertion_stashes_the_continuations_metadata() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Multipart { parts: 2 }).await;
    let mut planted = std::collections::HashMap::new();
    planted.insert(
        "ovstorage-modified-by".to_string(),
        "impersonated-principal".to_string(),
    );
    let batch = backend
        .write_redirect(
            target(),
            WriteOptions {
                size_hint: Some(2 * 1024 * 1024),
                user_metadata: Some(planted),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("write_redirect ok");
    let results = RedirectResultBatch {
        results: (0..2)
            .map(|idx| RedirectResult {
                status_code: 200,
                captured_headers: vec![("etag".into(), format!("p{idx}"))],
                captured_body: Vec::new(),
            })
            .collect(),
    };
    backend
        .continue_write(target(), batch, results, None, None)
        .await
        .expect("continue_write ok");

    let recorded = recorded.lock().unwrap();
    assert_eq!(
        recorded.update_metadata_requests.len(),
        1,
        "exactly the continuation's one key"
    );
    let request = &recorded.update_metadata_requests[0];
    assert_eq!(request.user_metadata_key, "ovstorage-modified-by");
    let value = match request
        .user_metadata
        .as_ref()
        .and_then(|value| value.kind.as_ref())
    {
        Some(ovstorage_services_protos::google::protobuf::value::Kind::StringValue(s)) => {
            s.as_str()
        }
        other => panic!("expected a string metadata value, got {other:?}"),
    };
    assert_eq!(
        value, "impersonated-principal",
        "with no assertion the continuation's value stands, unchanged and not blanked"
    );
}

// ---------------------------------------------------------------------------
// Post-commit user-metadata stash: PartialCompletion propagation.
//
// `stash_user_metadata` runs after the object bytes have committed, at three
// call sites (inline write, single-redirect completion, multipart completion).
// It used to return `()` and discard every failure, so a write whose metadata
// was lost reported `Ok`. Each site is driven separately below: mutating one
// proves nothing about the other two.
// ---------------------------------------------------------------------------

fn metadata_map(pairs: &[(&str, &str)]) -> ovstorage_plugin::UserMetadata {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn set_update_behavior(recorded: &Arc<Mutex<Recorded>>, behavior: UpdateMetadataBehavior) {
    recorded.lock().unwrap().update_metadata_behavior = behavior;
}

/// Assert the error is the partial-completion an after-commit metadata failure
/// must produce, including the payload a caller acts on.
fn assert_metadata_partial_completion(
    err: &ovstorage_plugin::Error,
    expected_outcome: ovstorage_plugin::StageOutcome,
) {
    use ovstorage_plugin::{ErrorCode, ErrorContext, PartialStage, RollbackEffect};
    assert_eq!(
        err.code(),
        ErrorCode::PartialCompletion,
        "expected PartialCompletion, got {err:?}",
    );
    // Non-retryable is the property the whole design turns on: a retry here
    // re-uploads an object that is already committed.
    assert!(!err.code().retryable());
    match err.context() {
        Some(ErrorContext::Partial {
            completed,
            failed,
            failed_outcome,
            rollback,
        }) => {
            assert_eq!(*completed, PartialStage::ObjectData);
            assert_eq!(*failed, PartialStage::UserMetadata);
            assert_eq!(*failed_outcome, expected_outcome);
            // Undoing the committed stage would delete the object the caller
            // asked for — the opposite of the emulated-rename case.
            assert_eq!(*rollback, RollbackEffect::DestroysRequestedWork);
        }
        other => panic!("expected a Partial context, got {other:?}"),
    }
    let next = err.next_action().expect("a next_action hint is attached");
    // Deliberately NOT "the hint names update_metadata": the hint for keys the
    // service refused as unimplemented must not promise that call will work,
    // because it issues the very RPC that just refused them. The universal
    // property is the one below; the per-cause remedy is asserted on typed
    // values in the backend's own unit tests.
    assert!(
        next.contains("Do not re-issue the write"),
        "every hint must steer away from re-issuing the committed write, got {next:?}",
    );
    assert!(
        next.contains("committed and readable"),
        "every hint must say the object is durable, got {next:?}",
    );
}

// --- Site 1: inline write --------------------------------------------------

#[tokio::test]
async fn inline_write_reports_partial_completion_when_metadata_stash_fails() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::AlwaysFail(tonic::Code::Internal),
    );
    let opts = WriteOptions {
        user_metadata: Some(metadata_map(&[("label", "hero")])),
        ..Default::default()
    };
    let err = backend
        .write(target(), b"hello".to_vec(), opts, None)
        .await
        .expect_err("a lost metadata patch must not report success");
    // A refusal that is not `Unimplemented` may still have applied — a lost
    // response is indistinguishable from a refusal from the client side.
    assert_metadata_partial_completion(&err, ovstorage_plugin::StageOutcome::Unknown);
    // The bytes really did commit: the stash runs only after the server has
    // returned `ResourceInfo`, so a stash attempt at all proves the write
    // finished. (The fake records no inline write — `Recorded` has no field
    // for one — so this is established by control flow, not by a recording.)
    assert!(
        !recorded.lock().unwrap().update_metadata_requests.is_empty(),
        "the stash must have been attempted after the commit",
    );
}

/// The honest input. Red-green gives the hostile case by construction and
/// never prompts for this one, which is where the blast radius is: every
/// ordinary write carrying metadata goes through the propagation added above.
#[tokio::test]
async fn inline_write_with_user_metadata_still_succeeds_and_stores_it() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = WriteOptions {
        user_metadata: Some(metadata_map(&[("label", "hero"), ("shot", "0420")])),
        ..Default::default()
    };
    backend
        .write(target(), b"hello".to_vec(), opts, None)
        .await
        .expect("a normal write carrying user metadata must still succeed");

    let stored = recorded.lock().unwrap();
    let keys: Vec<&str> = stored
        .update_metadata_requests
        .iter()
        .map(|r| r.user_metadata_key.as_str())
        .collect();
    assert!(keys.contains(&"label"), "keys actually stashed: {keys:?}");
    assert!(keys.contains(&"shot"), "keys actually stashed: {keys:?}");
}

/// The metadata must be *readable afterwards*, not merely dispatched — the
/// assertion above is about the RPCs, this one about the resulting state.
#[tokio::test]
async fn user_metadata_written_inline_reads_back_from_stat() {
    let (backend, _recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = WriteOptions {
        user_metadata: Some(metadata_map(&[("label", "hero")])),
        ..Default::default()
    };
    backend
        .write(target(), b"hello".to_vec(), opts, None)
        .await
        .expect("write ok");
    let info = backend
        .stat(
            target(),
            StatOptions {
                full_metadata: true,
            },
            None,
        )
        .await
        .expect("stat ok");
    let user = info.user_metadata.expect("user_metadata populated");
    assert_eq!(
        user.get("label").map(String::as_str),
        Some("hero"),
        "the metadata a successful write reported must be readable afterwards",
    );
}

// --- Site 2: single-redirect completion ------------------------------------

async fn drive_single_redirect(
    backend: &OmniverseStorageBackend,
    user_metadata: Option<ovstorage_plugin::UserMetadata>,
) -> ovstorage_plugin::Result<WriteStep> {
    let batch = backend
        .write_redirect(
            target(),
            WriteOptions {
                size_hint: Some(1024),
                user_metadata,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("write_redirect ok");
    let results = RedirectResultBatch {
        results: vec![RedirectResult {
            status_code: 200,
            captured_headers: vec![("etag".into(), "remote-etag".into())],
            captured_body: Vec::new(),
        }],
    };
    backend
        .continue_write(target(), batch, results, None, None)
        .await
}

#[tokio::test]
async fn single_redirect_completion_reports_partial_completion_when_metadata_stash_fails() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::SingleRedirect).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::AlwaysFail(tonic::Code::Internal),
    );
    let err = drive_single_redirect(&backend, Some(metadata_map(&[("label", "hero")])))
        .await
        .expect_err("a lost metadata patch must not report success");
    assert_metadata_partial_completion(&err, ovstorage_plugin::StageOutcome::Unknown);
    // The upload really was completed before the stash failed.
    assert_eq!(recorded.lock().unwrap().completed_redirects.len(), 1);
}

#[tokio::test]
async fn single_redirect_completion_with_user_metadata_still_succeeds() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::SingleRedirect).await;
    let step = drive_single_redirect(&backend, Some(metadata_map(&[("label", "hero")])))
        .await
        .expect("a normal redirect completion carrying metadata must succeed");
    assert!(matches!(step, WriteStep::Done(_)), "got {step:?}");
    let stored = recorded.lock().unwrap();
    assert!(
        stored
            .update_metadata_requests
            .iter()
            .any(|r| r.user_metadata_key == "label"),
        "the metadata riding the continuation must be stashed",
    );
}

// --- Site 3: multipart completion ------------------------------------------

async fn drive_multipart(
    backend: &OmniverseStorageBackend,
    user_metadata: Option<ovstorage_plugin::UserMetadata>,
) -> ovstorage_plugin::Result<WriteStep> {
    let batch = backend
        .write_redirect(
            target(),
            WriteOptions {
                size_hint: Some(1024),
                user_metadata,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("write_redirect ok");
    let results = RedirectResultBatch {
        results: batch
            .redirects
            .iter()
            .map(|_| RedirectResult {
                status_code: 200,
                captured_headers: vec![("etag".into(), "part-etag".into())],
                captured_body: Vec::new(),
            })
            .collect(),
    };
    backend
        .continue_write(target(), batch, results, None, None)
        .await
}

#[tokio::test]
async fn multipart_completion_reports_partial_completion_when_metadata_stash_fails() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Multipart { parts: 2 }).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::AlwaysFail(tonic::Code::Internal),
    );
    let err = drive_multipart(&backend, Some(metadata_map(&[("label", "hero")])))
        .await
        .expect_err("a lost metadata patch must not report success");
    assert_metadata_partial_completion(&err, ovstorage_plugin::StageOutcome::Unknown);
    // The multipart upload was committed, not aborted: the stash runs after
    // the aborter is disarmed, so this really is a post-commit failure.
    let stored = recorded.lock().unwrap();
    assert_eq!(stored.completed_multiparts.len(), 1);
    assert!(
        stored.aborted_multiparts.is_empty(),
        "a post-commit metadata failure must not abort the committed upload",
    );
}

#[tokio::test]
async fn multipart_completion_with_user_metadata_still_succeeds() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Multipart { parts: 2 }).await;
    let step = drive_multipart(&backend, Some(metadata_map(&[("label", "hero")])))
        .await
        .expect("a normal multipart completion carrying metadata must succeed");
    assert!(matches!(step, WriteStep::Done(_)), "got {step:?}");
    assert!(
        recorded
            .lock()
            .unwrap()
            .update_metadata_requests
            .iter()
            .any(|r| r.user_metadata_key == "label"),
    );
}

// --- Payload discrimination ------------------------------------------------

/// `Unimplemented` is the server refusing to implement the call for the keys it
/// names, so those keys definitively did not apply and re-issuing them repeats
/// the refusal. Any other failure may be a lost response over a request that
/// did apply. The two must not report the same outcome — `NotApplied` is what
/// tells a caller the failed keys really did not land, and the remedy attached
/// to it says re-issuing cannot help rather than that it will.
#[tokio::test]
async fn an_unimplemented_metadata_service_reports_not_applied() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::AlwaysFail(tonic::Code::Unimplemented),
    );
    let opts = WriteOptions {
        user_metadata: Some(metadata_map(&[("label", "hero")])),
        ..Default::default()
    };
    let err = backend
        .write(target(), b"hello".to_vec(), opts, None)
        .await
        .expect_err("metadata that can never be stored must not report success");
    assert_metadata_partial_completion(&err, ovstorage_plugin::StageOutcome::NotApplied);
}

/// A map can be partially applied — one RPC per key, and some succeed. The
/// payload reports this per stash, not per key: `failed: UserMetadata` means
/// *at least one* key did not apply. Pinned so the contract in the doc comment
/// cannot drift from the behaviour.
#[tokio::test]
async fn a_partially_applied_map_still_reports_one_partial_completion() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::FailKeys(vec!["shot".into()], tonic::Code::Internal),
    );
    let opts = WriteOptions {
        user_metadata: Some(metadata_map(&[("label", "hero"), ("shot", "0420")])),
        ..Default::default()
    };
    let err = backend
        .write(target(), b"hello".to_vec(), opts, None)
        .await
        .expect_err("one failed key must still fail the stash");
    assert_metadata_partial_completion(&err, ovstorage_plugin::StageOutcome::Unknown);

    // And the key that *did* apply was really stored — the error does not mean
    // "none of them landed", which is what the doc comment warns about.
    // Asserted against the service's resulting STATE, not against the recorder:
    // the fake records every request before deciding whether to fail it, so a
    // recorder assertion would pass even if nothing were stored.
    let info = backend
        .stat(
            target(),
            StatOptions {
                full_metadata: true,
            },
            None,
        )
        .await
        .expect("stat ok");
    let user = info.user_metadata.expect("user_metadata populated");
    assert_eq!(
        user.get("label").map(String::as_str),
        Some("hero"),
        "the key that succeeded must really be stored: {user:?}",
    );
    assert!(
        !user.contains_key("shot"),
        "the refused key must NOT be stored: {user:?}",
    );
}

/// A mixed run: one key stored, the rest refused `Unimplemented`. The refused
/// keys can never be stored on this deployment, so the outcome is `NotApplied`
/// and the hint must not promise that `update_metadata` will fix them. This is
/// the case an earlier `failed == total` guard routed to the generic
/// "some may have applied" remedy, which would have sent an operator round a
/// loop that cannot terminate.
#[tokio::test]
async fn a_mixed_unimplemented_run_reports_not_applied_and_promises_no_retry() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::FailKeys(vec!["shot".into()], tonic::Code::Unimplemented),
    );
    let opts = WriteOptions {
        user_metadata: Some(metadata_map(&[("label", "hero"), ("shot", "0420")])),
        ..Default::default()
    };
    let err = backend
        .write(target(), b"hello".to_vec(), opts, None)
        .await
        .expect_err("a key the service cannot store must not report success");

    // `Unimplemented` is definitive even when a sibling key succeeded.
    assert_metadata_partial_completion(&err, ovstorage_plugin::StageOutcome::NotApplied);

    let next = err.next_action().expect("hint");
    assert!(
        next.contains("fails the same way"),
        "the hint must say retrying cannot store these keys, got {next:?}",
    );

    // The key that could be stored really was: the error does not mean the
    // whole map was lost.
    let info = backend
        .stat(
            target(),
            StatOptions {
                full_metadata: true,
            },
            None,
        )
        .await
        .expect("stat ok");
    let user = info.user_metadata.expect("user_metadata populated");
    assert_eq!(user.get("label").map(String::as_str), Some("hero"));
    assert!(!user.contains_key("shot"));
}

/// `opts.message` stays best-effort by contract — it is a per-operation
/// annotation a backend may drop. A write carrying only a message must still
/// succeed against a metadata service that refuses everything, or every
/// `--message` write to such a deployment becomes a hard failure.
#[tokio::test]
async fn a_message_only_write_still_succeeds_when_the_metadata_service_refuses() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::AlwaysFail(tonic::Code::Internal),
    );
    let opts = WriteOptions {
        message: Some("checkpoint before lighting".into()),
        user_metadata: None,
        ..Default::default()
    };
    backend
        .write(target(), b"hello".to_vec(), opts, None)
        .await
        .expect("a dropped message must not fail a committed write");
    // The attempt was made and discarded, so this is the best-effort path and
    // not a case where nothing was tried.
    assert!(
        recorded
            .lock()
            .unwrap()
            .update_metadata_requests
            .iter()
            .any(|r| r.user_metadata_key == "x-ov-message"),
        "the message stash must have been attempted",
    );
}

/// A write carrying no metadata at all is untouched by any of this.
#[tokio::test]
async fn a_write_without_user_metadata_is_unaffected_by_a_refusing_metadata_service() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::AlwaysFail(tonic::Code::Internal),
    );
    backend
        .write(target(), b"hello".to_vec(), WriteOptions::default(), None)
        .await
        .expect("a write with no metadata must not consult the metadata service");
    assert!(
        recorded.lock().unwrap().update_metadata_requests.is_empty(),
        "no metadata means no metadata RPC",
    );
}

// ---------------------------------------------------------------------------
// The host's own reserved-namespace keys are exempt from propagation.
//
// A broker or REST branch stamps `ovstorage-modified-by` on every mutating
// write, whether or not the caller asked for metadata. Failing the caller's
// committed write because the HOST's audit stamp did not land would charge the
// caller for a decision the host made — so a failure confined to the reserved
// namespace warns and returns Ok. The operator, who owns the audit trail, is
// who the warning is for, so these tests assert the warning EXISTS: a silent
// drop and a deliberate exemption are indistinguishable to a test that only
// checks the call succeeded.
// ---------------------------------------------------------------------------

/// Capture the tracing events emitted while an async `body` runs.
///
/// Deliberately a PROCESS-GLOBAL subscriber behind a lock rather than
/// `tracing::subscriber::set_default`. The thread-local form captured nothing
/// under the full suite while passing in isolation — the warning is emitted
/// from a future the runtime is free to poll off the thread the guard was
/// installed on, so the capture is a coin flip that lands heads when the
/// machine is idle. A test that silently stops observing is worse than no test:
/// it would have reported the exemption "warns" long after the warning was
/// gone. The lock serialises the capturing tests against each other; every
/// other test in this file is unaffected.
static EVENT_CAPTURE: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// Async-aware: this guard is held across the body's await points, and a
/// `std::sync::Mutex` held across an await can park a runtime worker holding
/// the lock. `clippy::await_holding_lock` catches exactly that.
static CAPTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static CAPTURE_INSTALLED: std::sync::Once = std::sync::Once::new();

async fn captured_events<F, T>(body: F) -> (T, Vec<String>)
where
    F: std::future::Future<Output = T>,
{
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};

    struct Capture;

    struct Visitor(String);

    impl tracing::field::Visit for Visitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" | {}={:?}", field.name(), value));
        }
    }

    impl<S: tracing::Subscriber> Layer<S> for Capture {
        fn on_event(&self, event: &tracing::Event<'_>, _cx: Context<'_, S>) {
            let mut visitor = Visitor(String::new());
            event.record(&mut visitor);
            if let Ok(mut buffer) = EVENT_CAPTURE.lock() {
                buffer.push(visitor.0);
            }
        }
    }

    let guard = CAPTURE_LOCK.lock().await;
    CAPTURE_INSTALLED.call_once(|| {
        let subscriber = tracing_subscriber::registry().with(Capture);
        // Ignore an existing global: another test may have installed one, in
        // which case this capture cannot run and the assertions below will say
        // so rather than passing vacuously.
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
    EVENT_CAPTURE.lock().unwrap().clear();
    let out = body.await;
    let events = EVENT_CAPTURE.lock().unwrap().clone();
    drop(guard);
    (out, events)
}

fn attribution_only_metadata() -> ovstorage_plugin::UserMetadata {
    metadata_map(&[(
        ovstorage_plugin::ATTRIBUTION_KEY_MODIFIED_BY,
        "alice@example",
    )])
}

/// A write carrying ONLY the host's attribution stamp still succeeds when the
/// stash fails — and the operator gets the warning, with the attribution flag
/// set so the one key they care about is not masked.
#[tokio::test]
async fn an_attribution_only_stash_failure_warns_but_does_not_fail_the_write() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::AlwaysFail(tonic::Code::Internal),
    );
    // The fixture must actually be reserved-only, or this test asserts nothing.
    let planted = attribution_only_metadata();
    assert!(
        planted
            .keys()
            .all(|k| k.starts_with(ovstorage_plugin::RESERVED_METADATA_PREFIX)),
        "fixture must contain only reserved keys: {planted:?}",
    );

    let opts = WriteOptions {
        user_metadata: Some(planted),
        ..Default::default()
    };
    let (result, events) =
        captured_events(backend.write(target(), b"hello".to_vec(), opts, None)).await;
    result.expect("the host's own stamp must not fail the caller's committed write");

    // The attempt really was made — otherwise this would pass for a build that
    // never stashes at all.
    assert!(
        recorded
            .lock()
            .unwrap()
            .update_metadata_requests
            .iter()
            .any(|r| r.user_metadata_key == ovstorage_plugin::ATTRIBUTION_KEY_MODIFIED_BY),
        "the attribution stash must have been attempted",
    );

    // The operator's copy of the failure. Without this assertion a silent drop
    // and a deliberate exemption look identical.
    // Control the instrument before trusting a reading from it: a subscriber
    // that captured nothing at all is indistinguishable from a warning that was
    // never emitted, and only one of those is a product defect.
    assert!(
        !events.is_empty(),
        "the capture saw no events at all, so it proves nothing about the warning",
    );
    // The buffer is process-global, so a test running in parallel can drop its
    // own stash warning into it, hence a conjunction rather than the first
    // stash warning found. (Taking the first made this test fail under a
    // mutation of a call site it does not exercise — a false reading from
    // contamination, not a defect.)
    //
    // The fields whose value could be a PREFIX of another value are matched
    // with their surrounding delimiters: `keys_failed=1` would otherwise match
    // `keys_failed=10`, and the sample key would match any key that begins with
    // the attribution key. The two booleans are matched bare, which is
    // unambiguous because `=true` cannot prefix another value.
    events
        .iter()
        .find(|e| {
            e.contains("metadata stash after commit failed")
                && e.contains("attribution_failed=true")
                && e.contains("exempted=true")
                && e.contains(" | metadata.keys_failed=1 |")
                && e.contains(" | metadata.keys_total=1 |")
                && e.contains(&format!(
                    " | metadata.sample_failed_key={} |",
                    ovstorage_plugin::ATTRIBUTION_KEY_MODIFIED_BY
                ))
        })
        .unwrap_or_else(|| {
            panic!(
                "no stash warning naming a single failed attribution key was \
                 emitted; captured: {events:?}"
            )
        });
}

/// The control for the test above: with a CALLER key in the same map, the same
/// failure does propagate. Without this, "returns Ok" could equally mean the
/// propagation was broken outright.
#[tokio::test]
async fn a_caller_key_alongside_the_stamp_still_propagates() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::AlwaysFail(tonic::Code::Internal),
    );
    let mut planted = attribution_only_metadata();
    planted.insert("label".into(), "hero".into());

    let opts = WriteOptions {
        user_metadata: Some(planted),
        ..Default::default()
    };
    let err = backend
        .write(target(), b"hello".to_vec(), opts, None)
        .await
        .expect_err("a caller key that did not land must surface");
    assert_metadata_partial_completion(&err, ovstorage_plugin::StageOutcome::Unknown);

    // The counts describe the CALLER's map, not the host-augmented one: a
    // "1 of 2" here would name a map the caller never sent.
    let message = err.message();
    assert!(
        message.contains("1 of 1"),
        "counts must cover caller keys only, got {message:?}",
    );
}

/// The good path for the exemption: a write carrying only the stamp, against a
/// working metadata service, succeeds AND stores the stamp. The exemption must
/// not become a silent skip of the attribution write.
#[tokio::test]
async fn an_attribution_only_write_still_stores_the_stamp_when_the_service_works() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    let opts = WriteOptions {
        user_metadata: Some(attribution_only_metadata()),
        ..Default::default()
    };
    backend
        .write(target(), b"hello".to_vec(), opts, None)
        .await
        .expect("write ok");

    let stored = recorded.lock().unwrap();
    assert!(
        stored
            .update_metadata_requests
            .iter()
            .any(|r| r.user_metadata_key == ovstorage_plugin::ATTRIBUTION_KEY_MODIFIED_BY),
        "the stamp must still be written on the happy path",
    );
}

/// The stated consequence of testing the namespace rather than the one key the
/// host plants: a caller that sets its own `ovstorage-`-prefixed key on a path
/// with no attribution layer to strip it gets best-effort semantics.
///
/// Pinned deliberately. It is a real hole and an accepted one — the namespace is
/// documented as reserved for host-attested keys — but an accepted consequence
/// that no test names is indistinguishable from one nobody noticed, and the next
/// reader deserves to find it asserted rather than argued.
#[tokio::test]
async fn a_caller_key_inside_the_reserved_namespace_is_treated_as_the_hosts() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::AlwaysFail(tonic::Code::Internal),
    );
    // Not the attribution key: a key a caller invented inside the namespace.
    let smuggled = metadata_map(&[("ovstorage-my-own-key", "value")]);
    assert!(
        !smuggled.contains_key(ovstorage_plugin::ATTRIBUTION_KEY_MODIFIED_BY),
        "the fixture must not be the host's own stamp, or it proves nothing",
    );

    let opts = WriteOptions {
        user_metadata: Some(smuggled),
        ..Default::default()
    };
    backend
        .write(target(), b"hello".to_vec(), opts, None)
        .await
        .expect("a reserved-namespace key is treated as the host's, so Ok");

    // "Treated as the host's" means ATTEMPTED and then exempted. Without this
    // the test would pass for a build that skipped reserved keys entirely,
    // which is a different behaviour with the same return value.
    assert!(
        recorded
            .lock()
            .unwrap()
            .update_metadata_requests
            .iter()
            .any(|r| r.user_metadata_key == "ovstorage-my-own-key"),
        "the reserved key must have been attempted, not skipped",
    );

    // Control: the identical write with a NON-reserved key does surface, so
    // this test is about the namespace and not about propagation being broken.
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::AlwaysFail(tonic::Code::Internal),
    );
    let opts = WriteOptions {
        user_metadata: Some(metadata_map(&[("my-own-key", "value")])),
        ..Default::default()
    };
    backend
        .write(target(), b"hello".to_vec(), opts, None)
        .await
        .expect_err("the same key outside the namespace must surface");
}

/// The caller's error must quote a CALLER key's failure, never the host
/// stamp's.
///
/// `map` is a `HashMap`, so iteration order is unspecified. A single failure
/// sample shared between the operator warning and the caller's error lets the
/// stamp's message become the caller's `reason` whenever the stamp is visited
/// first — nondeterministically, on identical input, and pairing a situation
/// computed from caller keys with a message from a key the caller never sent.
///
/// Both keys fail here with distinguishable messages, so the assertion is about
/// which one was selected rather than about whether anything failed. Looped
/// because the defect is order-dependent: one pass could pick the right sample
/// by luck.
#[tokio::test]
async fn the_callers_error_never_quotes_the_host_stamps_failure() {
    for attempt in 0..16 {
        let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
        set_update_behavior(
            &recorded,
            UpdateMetadataBehavior::FailKeys(
                vec![
                    "label".into(),
                    ovstorage_plugin::ATTRIBUTION_KEY_MODIFIED_BY.into(),
                ],
                tonic::Code::Internal,
            ),
        );
        let mut planted = attribution_only_metadata();
        planted.insert("label".into(), "hero".into());

        let opts = WriteOptions {
            user_metadata: Some(planted),
            ..Default::default()
        };
        let err = backend
            .write(target(), b"hello".to_vec(), opts, None)
            .await
            .expect_err("a failed caller key must surface");

        let message = err.message();
        assert!(
            message.contains("fake refused key label"),
            "attempt {attempt}: the caller's error must quote the caller's key, \
             got {message:?}",
        );
        assert!(
            !message.contains(ovstorage_plugin::ATTRIBUTION_KEY_MODIFIED_BY),
            "attempt {attempt}: the caller's error quoted the host stamp's \
             failure, got {message:?}",
        );
    }
}

/// `service_unreachable` distinguishes "no RPC was ever dispatched" from "keys
/// were individually refused". It replaced an empty `sample_failed_key` as the
/// signal, because nothing rejects an empty metadata key from a caller, so
/// emptiness was a sentinel a caller could forge.
///
/// Only the per-key path is reachable from a test — the client-unavailable
/// producer needs `metadata_client()` to fail, and the transport memoises one
/// channel per kind and never evicts it, so after a successful write that call
/// cannot fail. That asymmetry is the point of the assertion: the field must
/// read `false` on the path that IS reachable, or the flag would be worse than
/// the sentinel it replaced.
#[tokio::test]
async fn a_per_key_refusal_is_not_reported_as_an_unreachable_service() {
    let (backend, recorded) = spawn_fake_server(WriteServerBehavior::Inline).await;
    set_update_behavior(
        &recorded,
        UpdateMetadataBehavior::AlwaysFail(tonic::Code::Internal),
    );
    let opts = WriteOptions {
        user_metadata: Some(attribution_only_metadata()),
        ..Default::default()
    };
    let (result, events) =
        captured_events(backend.write(target(), b"hello".to_vec(), opts, None)).await;
    result.expect("a reserved-only failure returns Ok");

    assert!(
        !events.is_empty(),
        "the capture saw no events at all, so it proves nothing",
    );
    let warning = events
        .iter()
        .find(|e| {
            e.contains("metadata stash after commit failed")
                && e.contains(&format!(
                    " | metadata.sample_failed_key={} |",
                    ovstorage_plugin::ATTRIBUTION_KEY_MODIFIED_BY
                ))
        })
        .unwrap_or_else(|| panic!("no stash warning emitted; captured: {events:?}"));

    assert!(
        warning.contains("service_unreachable=false"),
        "a key that was individually refused must not read as an unreachable \
         service: {warning}",
    );
    // Control on the instrument: the field is present at all, so the assertion
    // above is about its value and not about a field name that never renders.
    assert!(
        warning.contains("service_unreachable="),
        "the field must be emitted: {warning}",
    );
}
