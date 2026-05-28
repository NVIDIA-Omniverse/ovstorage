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
use ovstorage_plugin::shim::Backend;
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
    /// via if_match that the service can no longer honor.
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
        self.recorded
            .lock()
            .unwrap()
            .update_metadata_requests
            .push(request.clone());
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
        .continue_write(target(), batch, results, None)
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
        .continue_write(target(), batch, results, None)
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
/// `if_match` etag/resource identity is no longer readable, so the
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
    let (state, auth_state) = build_auth_state(&idp_base, &request)
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
