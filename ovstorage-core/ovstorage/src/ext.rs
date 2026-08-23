// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The [`LayerExt`] ergonomic extension trait.
//!
//! Every [`Layer`] (and therefore every [`Stack`](crate::Stack)) is dispatched
//! through typed `Request<..>` envelopes. Callers that want the friendlier
//! `Url` + options verbs use a blanket
//! `impl<L: Layer + ?Sized> LayerExt for L`. The semantics — the `max_bytes` cap, the
//! `read_bytes` buffering signal, the object→directory `stat` fallback, the
//! `create_directory`/`update_metadata` address re-stamp, and the `copy`
//! `WriteStep::Done` unwrap — are consistent across every Layer.
//!
//! Method names that collide with [`Layer`]'s typed primitives (`stat`,
//! `write`, `delete`, `copy`, `rename`, `materialize`, `update_metadata`,
//! `create_directory`, `delete_directory`, `list_connections`,
//! `list_address_roots`) call the underlying primitive via fully-qualified
//! `Layer::method(self, ..)` syntax so the ergonomic verb never recurses into
//! itself.

use crate::read_helpers::{ensure_read_bytes_within_max_bytes, maybe_cap_read_stream};
use crate::wrappers::{READ_TO_BYTES_EXTENSION, buffer_read_stream};
use crate::{
    Body, Capabilities, Connection, CopyOptions, CopyRequest, CreateDirectoryOptions,
    CreateDirectoryRequest, DeleteDirectoryOptions, DeleteDirectoryRequest, DeleteOptions,
    DeleteRequest, EMPTY_LAYER_KIND, Error, ErrorCode, Extensions, Layer, LayerType, ListOptions,
    ListPage, ListRequest, LocalDelegate, ObjectInfo, ReadOptions, ReadRequest, ReadResult,
    ReadStream, RenameOptions, RenameRequest, Request, Result, RootInfo, StatOptions, StatRequest,
    StorageBackendKindDescriptor, UpdateMetadataOptions, UpdateMetadataRequest, Url, WriteOptions,
    WriteRequest, WriteResult, WriteStep, address, layer_kind_to_backend_descriptor,
    validate_update_metadata_options,
};
use ovstorage_layer::{canonicalize, io_error};
use tokio_util::sync::CancellationToken;

/// Ergonomic `Url` + options verbs over any [`Layer`]/[`Stack`](crate::Stack).
///
/// See the module docs for the collision rule.
///
/// # Deliberate verb-name collision with [`Layer`]
///
/// Several verbs here (`stat`, `write`, `delete`, `copy`, `rename`,
/// `materialize`, `update_metadata`, `create_directory`, `delete_directory`,
/// `list_connections`, `list_address_roots`) intentionally share a name with
/// [`Layer`]'s typed `Request<..>` primitives. This is not an oversight: the
/// names provide the ergonomic spelling expected by Stack callers, such as
/// `stack.stat(url, opts, cancel)`.
///
/// The cost of that parity is that both traits are in scope at once, so the
/// bare method name is ambiguous. Wherever both a `Layer` and a `LayerExt`
/// verb of the same name could apply, disambiguate with fully-qualified
/// (UFCS) syntax:
///
/// - **Inside this trait's impl**, every collided body calls the underlying
///   primitive via `Layer::method(self, request, cancel)` so the ergonomic
///   verb never recurses into itself.
/// - **At mixed call sites** (e.g. the CLI's connection-lifecycle and
///   introspection helpers) pick the intended trait explicitly:
///   `LayerExt::stat(&*stack, url, opts, cancel)` for the ergonomic verb,
///   `Layer::stat(&*stack, request, cancel)` for the typed primitive.
///
/// The module deliberately is not re-exported at the crate root (see `lib.rs`)
/// to keep the collision opt-in per importer rather than crate-wide.
#[async_trait::async_trait]
pub trait LayerExt: Layer {
    /// # Errors
    ///
    /// The [`Layer::stat`] contract: [`ErrorCode::NoRoute`],
    /// [`ErrorCode::PermissionDenied`], [`ErrorCode::InvalidArgument`],
    /// [`ErrorCode::Unsupported`], [`ErrorCode::Cancelled`], and
    /// [`ErrorCode::Transient`]. Because of the object→directory
    /// fallback, [`ErrorCode::NotFound`] means neither the object nor the
    /// directory spelling exists.
    async fn stat(
        &self,
        addr: Url,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo>;

    /// # Errors
    ///
    /// The [`Layer::read`] contract ([`ErrorCode::NotFound`],
    /// [`ErrorCode::NoRoute`], [`ErrorCode::PermissionDenied`],
    /// [`ErrorCode::ObjectModified`], [`ErrorCode::Unsupported`],
    /// [`ErrorCode::Cancelled`], [`ErrorCode::Transient`]), plus:
    ///
    /// - [`ErrorCode::ResourceExhausted`] — the object is larger than
    ///   `opts.max_bytes`.
    /// - [`ErrorCode::NotFound`] / [`ErrorCode::PermissionDenied`] /
    ///   [`ErrorCode::Transient`] — reading a returned local delegate off
    ///   disk failed.
    /// - [`ErrorCode::Internal`] — the chain returned an unfollowed read
    ///   redirect (a mis-composed Stack).
    async fn read_bytes(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<(Vec<u8>, ObjectInfo)>;

    /// # Errors
    ///
    /// The [`Layer::read`] contract ([`ErrorCode::NotFound`],
    /// [`ErrorCode::NoRoute`], [`ErrorCode::PermissionDenied`],
    /// [`ErrorCode::ObjectModified`], [`ErrorCode::Unsupported`],
    /// [`ErrorCode::Cancelled`], [`ErrorCode::Transient`]), plus:
    ///
    /// - [`ErrorCode::ResourceExhausted`] — a buffered response already
    ///   exceeds `opts.max_bytes`; a capped stream reports overflow as an
    ///   `Err` item mid-stream instead.
    /// - [`ErrorCode::NotFound`] / [`ErrorCode::PermissionDenied`] /
    ///   [`ErrorCode::Transient`] — opening a returned local delegate off
    ///   disk failed.
    /// - [`ErrorCode::Internal`] — the chain returned an unfollowed read
    ///   redirect (a mis-composed Stack).
    async fn read_stream(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ReadStream, ObjectInfo)>;

    /// # Errors
    ///
    /// The [`Layer::materialize`] contract: [`ErrorCode::NotFound`],
    /// [`ErrorCode::NoRoute`], [`ErrorCode::PermissionDenied`],
    /// [`ErrorCode::InvalidArgument`] (the address names a directory
    /// rather than an object), [`ErrorCode::Unsupported`] (the chain
    /// cannot produce a local file), [`ErrorCode::Cancelled`], and
    /// [`ErrorCode::Transient`].
    async fn materialize(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate>;

    /// # Errors
    ///
    /// The [`Layer::write`] contract: [`ErrorCode::NoRoute`],
    /// [`ErrorCode::PermissionDenied`], [`ErrorCode::AlreadyExists`],
    /// [`ErrorCode::PreconditionFailed`], [`ErrorCode::InvalidArgument`],
    /// [`ErrorCode::Unsupported`], [`ErrorCode::Cancelled`], and
    /// [`ErrorCode::Transient`]. Deriving a size hint from a
    /// [`Body::LocalFile`] never fails — an unreadable file simply yields
    /// no hint.
    async fn write(
        &self,
        dest: Url,
        body: Body,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult>;

    /// # Errors
    ///
    /// The [`Layer::delete`] contract: [`ErrorCode::PreconditionFailed`]
    /// on an `if_match` mismatch, [`ErrorCode::InvalidArgument`] when the
    /// target is a directory, plus [`ErrorCode::NotFound`],
    /// [`ErrorCode::NoRoute`], [`ErrorCode::PermissionDenied`],
    /// [`ErrorCode::Unsupported`], [`ErrorCode::Cancelled`], and
    /// [`ErrorCode::Transient`].
    async fn delete(
        &self,
        addr: Url,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()>;

    /// # Errors
    ///
    /// The [`Layer::list`] contract: [`ErrorCode::NotFound`],
    /// [`ErrorCode::InvalidArgument`] (malformed page token),
    /// [`ErrorCode::NoRoute`], [`ErrorCode::PermissionDenied`],
    /// [`ErrorCode::Unsupported`], [`ErrorCode::Cancelled`], and
    /// [`ErrorCode::Transient`]. The prefix is converted to directory
    /// form before dispatch, so both spellings list the same page.
    async fn list_page(
        &self,
        prefix: Url,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage>;

    /// # Errors
    ///
    /// The [`Layer::create_directory`] contract:
    /// [`ErrorCode::AlreadyExists`], [`ErrorCode::InvalidArgument`],
    /// [`ErrorCode::NoRoute`], [`ErrorCode::PermissionDenied`],
    /// [`ErrorCode::Unsupported`], [`ErrorCode::Cancelled`], and
    /// [`ErrorCode::Transient`].
    async fn create_directory(
        &self,
        addr: Url,
        opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo>;

    /// # Errors
    ///
    /// The [`Layer::delete_directory`] contract:
    /// [`ErrorCode::DirectoryNotEmpty`], [`ErrorCode::InvalidArgument`]
    /// (the target is an object), [`ErrorCode::NotFound`],
    /// [`ErrorCode::NoRoute`], [`ErrorCode::PermissionDenied`],
    /// [`ErrorCode::Unsupported`], [`ErrorCode::Cancelled`], and
    /// [`ErrorCode::Transient`].
    async fn delete_directory(
        &self,
        addr: Url,
        opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()>;

    /// # Errors
    ///
    /// The [`Layer::rename`] contract: [`ErrorCode::NotFound`],
    /// [`ErrorCode::AlreadyExists`], [`ErrorCode::PreconditionFailed`]
    /// (checked before anything is committed),
    /// [`ErrorCode::ObjectModified`] (an emulated rename runs as a copy, so
    /// the source changing after staging surfaces here too),
    /// [`ErrorCode::Unsupported`] (the stack performs no rename for this
    /// pair and no `copy_rename_fallback` layer is composed),
    /// [`ErrorCode::CommitAmbiguous`] (an emulated rename wrote the
    /// destination but could not delete the source, so the object exists at
    /// both addresses), [`ErrorCode::DirectoryNotEmpty`] (a directory renamed
    /// onto a destination directory that has children, which a native rename
    /// cannot replace), [`ErrorCode::NoRoute`], [`ErrorCode::PermissionDenied`],
    /// [`ErrorCode::Cancelled`], and [`ErrorCode::Transient`].
    async fn rename(
        &self,
        src: Url,
        dest: Url,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()>;

    /// # Errors
    ///
    /// The [`Layer::copy`] contract: [`ErrorCode::NotFound`],
    /// [`ErrorCode::AlreadyExists`], [`ErrorCode::PreconditionFailed`]
    /// (checked before anything is committed),
    /// [`ErrorCode::ObjectModified`] (the source changed after the bytes
    /// were staged),
    /// [`ErrorCode::Unsupported`] (the stack performs no copy for this pair
    /// and no `copy_rename_fallback` layer is composed),
    /// [`ErrorCode::NoRoute`],
    /// [`ErrorCode::PermissionDenied`], [`ErrorCode::ResourceExhausted`],
    /// [`ErrorCode::Cancelled`], and [`ErrorCode::Transient`] — plus
    /// [`ErrorCode::Unsupported`] when the server-side copy returns a
    /// redirect continuation this ergonomic verb does not drive.
    async fn copy(
        &self,
        src: Url,
        dest: Url,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult>;

    /// # Errors
    ///
    /// The [`Layer::update_metadata`] contract:
    /// [`ErrorCode::NotFound`], [`ErrorCode::PreconditionFailed`],
    /// [`ErrorCode::NoRoute`], [`ErrorCode::PermissionDenied`],
    /// [`ErrorCode::Unsupported`], [`ErrorCode::Cancelled`], and
    /// [`ErrorCode::Transient`] — plus [`ErrorCode::InvalidArgument`]
    /// when the options set and remove the same user-metadata key.
    async fn update_metadata(
        &self,
        addr: Url,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo>;

    /// # Errors
    ///
    /// The [`Layer::root_info_for`] contract: [`ErrorCode::NoRoute`] when
    /// no configured root matches `prefix`, [`ErrorCode::Unsupported`] on
    /// a chain without root introspection, [`ErrorCode::Cancelled`], and
    /// [`ErrorCode::Transient`].
    async fn capabilities_for(
        &self,
        prefix: &Url,
        cancel: Option<CancellationToken>,
    ) -> Result<Capabilities>;

    /// The backend Layers this Stack was built with, as backend-kind
    /// descriptors.
    ///
    /// This enumerates the graph in front of you; it is not a catalogue of
    /// the kinds the process is able to construct. A Stack assembled from a
    /// single backend layer reports exactly that one kind, and a Stack with no
    /// configured layers reports zero — regardless of which backend factories
    /// are linked into the binary or loaded from plugins. The built-in `file`
    /// backend needs no plugin artifact, and it appears here once the config
    /// declares a `file` layer, not before.
    ///
    /// For the connectable-kind catalogue — every backend factory built in or
    /// loaded, whether or not the graph declares a Layer for it — use
    /// [`host::discover_backend_kinds`](crate::host::discover_backend_kinds).
    /// That is what the REST gateway's `GET /v1/backend-kinds` and the
    /// broker's discovery RPC serve, so those two answers differ by design.
    ///
    /// # Errors
    ///
    /// The [`Layer::list_kinds`] contract: the built-in default only
    /// fails when a delegated layer fails — a plugin-bridged layer may
    /// surface [`ErrorCode::Internal`], and a gating layer may answer
    /// [`ErrorCode::PermissionDenied`].
    fn list_backend_kinds(&self) -> Result<Vec<StorageBackendKindDescriptor>>;

    /// Flat connection list — drops the [`Layer::list_connections`] update-stream half.
    ///
    /// # Errors
    ///
    /// The [`Layer::list_connections`] contract:
    /// [`ErrorCode::Transient`] from a child enumeration and
    /// [`ErrorCode::Cancelled`] when `cancel` fires during the fan-out.
    async fn list_connections(&self, cancel: Option<CancellationToken>) -> Result<Vec<Connection>>;

    /// Flat address-root list — drops the [`Layer::list_address_roots`] update-stream half.
    ///
    /// # Errors
    ///
    /// The [`Layer::list_address_roots`] contract:
    /// [`ErrorCode::Transient`] from a child enumeration and
    /// [`ErrorCode::Cancelled`] when `cancel` fires during the fan-out.
    async fn list_address_roots(&self, cancel: Option<CancellationToken>) -> Result<Vec<RootInfo>>;
}

#[async_trait::async_trait]
impl<L: Layer + ?Sized> LayerExt for L {
    async fn stat(
        &self,
        addr: Url,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        // Canonicalize at entry so the exact-object-vs-directory decision agrees
        // with what the Layer routes (an authority-form `mock://team`
        // canonicalizes to `mock://team/`). Dispatch under the anonymous,
        // single-identity scope (empty request `Extensions`).
        let addr = canonicalize(addr);
        if !address::is_directory(&addr) {
            match Layer::stat(
                self,
                Request {
                    extensions: Extensions::new(),
                    input: StatRequest {
                        address: addr.clone(),
                        options: opts.clone(),
                    },
                },
                cancel.clone(),
            )
            .await
            {
                Ok(info) => return Ok(info),
                Err(error) if error.code() == ErrorCode::NotFound => {}
                Err(error) => return Err(error),
            }
            let dir_addr = address::to_directory(&addr)?;
            return Layer::stat(
                self,
                Request {
                    extensions: Extensions::new(),
                    input: StatRequest {
                        address: dir_addr,
                        options: opts,
                    },
                },
                cancel,
            )
            .await;
        }
        Layer::stat(
            self,
            Request {
                extensions: Extensions::new(),
                input: StatRequest {
                    address: addr,
                    options: opts,
                },
            },
            cancel,
        )
        .await
    }

    async fn read_bytes(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<(Vec<u8>, ObjectInfo)> {
        let max_bytes = opts.max_bytes;
        let mut request = Request::new(ReadRequest {
            address: addr,
            options: opts,
        });
        // Signal the byte-cache wrapper that this is a buffering read, so a
        // streamed / delegated / redirected object is materialized and cached
        // once rather than re-fetched on every call. Streaming callers
        // (`read_stream`) don't set this, so their reads still stream unbuffered.
        request
            .extensions
            .insert(READ_TO_BYTES_EXTENSION.to_string(), vec![1]);
        let read_result = self.read(request, cancel).await?;
        match read_result {
            ReadResult::Bytes { bytes, info } => {
                ensure_read_bytes_within_max_bytes(bytes.len(), max_bytes)?;
                Ok((bytes, info))
            }
            ReadResult::Stream { stream, info } => {
                let bytes = buffer_read_stream(stream, max_bytes).await?;
                Ok((bytes, info))
            }
            ReadResult::LocalDelegate(local) => {
                let bytes = tokio::fs::read(&local.path).await.map_err(io_error)?;
                ensure_read_bytes_within_max_bytes(bytes.len(), max_bytes)?;
                Ok((bytes, local.info))
            }
            ReadResult::Redirect(_) => Err(Error::new(
                ErrorCode::Internal,
                "internal Stack returned an unfollowed read redirect",
            )),
        }
    }

    async fn read_stream(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ReadStream, ObjectInfo)> {
        let max_bytes = opts.max_bytes;
        let read_result = self
            .read(
                Request::new(ReadRequest {
                    address: addr,
                    options: opts,
                }),
                cancel,
            )
            .await?;
        match read_result {
            ReadResult::Stream { stream, info } => {
                Ok((maybe_cap_read_stream(stream, max_bytes), info))
            }
            ReadResult::Bytes { bytes, info } => {
                ensure_read_bytes_within_max_bytes(bytes.len(), max_bytes)?;
                let stream: ReadStream = Box::pin(futures::stream::once(async move {
                    Ok(bytes::Bytes::from(bytes))
                }));
                Ok((stream, info))
            }
            ReadResult::LocalDelegate(local) => {
                let file = tokio::fs::File::open(&local.path).await.map_err(io_error)?;
                let reader = tokio_util::io::ReaderStream::new(file);
                use futures::StreamExt;
                let stream: ReadStream = Box::pin(reader.map(|chunk| chunk.map_err(io_error)));
                Ok((maybe_cap_read_stream(stream, max_bytes), local.info))
            }
            ReadResult::Redirect(_) => Err(Error::new(
                ErrorCode::Internal,
                "internal Stack returned an unfollowed read redirect",
            )),
        }
    }

    async fn materialize(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        Layer::materialize(
            self,
            Request::new(ReadRequest {
                address: addr,
                options: opts,
            }),
            cancel,
        )
        .await
    }

    async fn write(
        &self,
        dest: Url,
        body: Body,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        // Size-hint derivation stays at this ergonomic edge (the write-redirect
        // wrapper reads it for its threshold decision). Body-type dispatch, the
        // write-redirect loop, write-through byte caching, and metadata-cache
        // invalidation are owned by the wrapper chain + backend.
        let size_hint = match opts.size_hint {
            Some(hint) => Some(hint),
            None => match &body {
                Body::Bytes(bytes) => Some(bytes.len() as u64),
                Body::LocalFile(path) => {
                    let path = path.clone();
                    tokio::fs::metadata(path).await.ok().map(|m| m.len())
                }
                Body::Stream(_) => None,
            },
        };
        let opts = WriteOptions { size_hint, ..opts };
        Layer::write(
            self,
            Request::new(WriteRequest {
                address: dest,
                body,
                options: opts,
            }),
            cancel,
        )
        .await
    }

    async fn delete(
        &self,
        addr: Url,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        Layer::delete(
            self,
            Request::new(DeleteRequest {
                address: addr,
                options: opts,
            }),
            cancel,
        )
        .await
    }

    async fn list_page(
        &self,
        prefix: Url,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        let prefix = address::to_directory(&prefix)?;
        self.list(
            Request {
                extensions: Extensions::new(),
                input: ListRequest {
                    prefix,
                    options: opts,
                },
            },
            cancel,
        )
        .await
    }

    async fn create_directory(
        &self,
        addr: Url,
        opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let addr = address::to_directory(&addr)?;
        // The Layer returns a `BackendItemInfo`; stamp the caller-facing address
        // back on via `ObjectInfo::from`.
        let info = Layer::create_directory(
            self,
            Request::new(CreateDirectoryRequest {
                address: addr.clone(),
                options: opts,
            }),
            cancel,
        )
        .await?;
        Ok(ObjectInfo::from((addr, info)))
    }

    async fn delete_directory(
        &self,
        addr: Url,
        opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let addr = address::to_directory(&addr)?;
        Layer::delete_directory(
            self,
            Request::new(DeleteDirectoryRequest {
                address: addr,
                options: opts,
            }),
            cancel,
        )
        .await
    }

    async fn rename(
        &self,
        src: Url,
        dest: Url,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        Layer::rename(
            self,
            Request::new(RenameRequest {
                source: src,
                destination: dest,
                options: opts,
            }),
            cancel,
        )
        .await
    }

    async fn copy(
        &self,
        src: Url,
        dest: Url,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        // Server-side vs. emulated transfer is decided by the
        // CopyRenameFallbackWrapper; unwrap the completed step.
        match Layer::copy(
            self,
            Request::new(CopyRequest {
                source: src,
                destination: dest,
                options: opts,
            }),
            cancel,
        )
        .await?
        {
            WriteStep::Done(result) => Ok(result),
            WriteStep::Redirects(_) => Err(Error::new(
                ErrorCode::Unsupported,
                "server-side copy returned redirect continuation",
            )),
        }
    }

    async fn update_metadata(
        &self,
        addr: Url,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        validate_update_metadata_options(&opts)?;
        // The Layer returns a `BackendItemInfo`; stamp the caller-facing address
        // back on via `ObjectInfo::from`.
        let info = Layer::update_metadata(
            self,
            Request::new(UpdateMetadataRequest {
                address: addr.clone(),
                options: opts,
            }),
            cancel,
        )
        .await?;
        Ok(ObjectInfo::from((addr, info)))
    }

    async fn capabilities_for(
        &self,
        prefix: &Url,
        cancel: Option<CancellationToken>,
    ) -> Result<Capabilities> {
        // Anonymous in-process entry (CLI/MCP): no principal to gate on, so pass
        // an empty context bag to the N6-widened introspection slots.
        Ok(
            Layer::root_info_for(self, prefix, &Extensions::new(), cancel)
                .await?
                .capabilities,
        )
    }

    fn list_backend_kinds(&self) -> Result<Vec<StorageBackendKindDescriptor>> {
        Ok(self
            .list_kinds(&Extensions::new())?
            .into_iter()
            // `EmptyLayer` (the root of an unconfigured Stack) reports the
            // reserved kind `"empty"` as a `Backend`. It is not a connectable
            // backend, so exclude it: an unconfigured host reports zero backend
            // kinds and `connect`'s "no backend kinds registered" guard fires.
            .filter(|d| d.layer_type == LayerType::Backend && d.kind != EMPTY_LAYER_KIND)
            .map(|d| layer_kind_to_backend_descriptor(&d))
            .collect())
    }

    async fn list_connections(&self, cancel: Option<CancellationToken>) -> Result<Vec<Connection>> {
        Ok(Layer::list_connections(self, &Extensions::new(), cancel)
            .await?
            .0
            .connections)
    }

    async fn list_address_roots(&self, cancel: Option<CancellationToken>) -> Result<Vec<RootInfo>> {
        Ok(Layer::list_address_roots(self, &Extensions::new(), cancel)
            .await?
            .0
            .roots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StackConfig;

    /// An unconfigured host is a one-layer Stack rooted at `EmptyLayer`, whose
    /// reserved `"empty"` backend kind must not surface as connectable.
    #[tokio::test]
    async fn list_backend_kinds_excludes_reserved_empty_kind() {
        let stack = crate::host::build_stack(&StackConfig::default(), Vec::new())
            .await
            .unwrap();
        let kinds = LayerExt::list_backend_kinds(stack.as_ref()).unwrap();
        assert!(
            kinds.is_empty(),
            "EmptyLayer-rooted stack must report zero backend kinds, got: {:?}",
            kinds.iter().map(|d| &d.kind).collect::<Vec<_>>()
        );
    }
}
