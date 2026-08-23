// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI-shaped DTOs for the REST contract.
//!
//! Doc comments on each item flow through to the generated OpenAPI
//! document as `description` fields — this is the primary
//! documentation mechanism for the public REST contract.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Metadata describing a single object.
#[derive(Serialize, ToSchema)]
pub(crate) struct ObjectInfoResponse {
    /// Caller-facing address of the object.
    pub address: String,
    /// One of `file`, `directory`, `directory_marker`, `directory_inferred`.
    pub kind: String,
    /// Opaque entity tag used for optimistic-concurrency preconditions
    /// (`If-Match: "<etag>"` on read/delete/update_metadata and the
    /// destination side of write/copy/rename; `X-OV-If-Source-Match:
    /// <etag>` on the source side of copy/rename).
    pub etag: Option<String>,
    /// Backend-assigned version identifier (descriptive; not a precondition).
    pub version: Option<String>,
    /// Object size in bytes. `None` for directories of any kind.
    pub size: Option<u64>,
    /// Last-modified time as Unix nanoseconds since epoch. `None` for
    /// inferred directories (no backing object).
    pub mtime_unix_nanos: Option<i128>,
    /// Backend-controlled metadata; keys are opaque to clients.
    #[schema(value_type = Option<Object>)]
    pub system_metadata: Option<HashMap<String, String>>,
    /// User-set metadata; round-trips unchanged through ovstorage.
    #[schema(value_type = Option<Object>)]
    pub user_metadata: Option<HashMap<String, String>>,
}

/// Bit-set of operations a check-access call can ask about.
#[derive(Serialize, ToSchema)]
pub(crate) struct AccessOpsResponse {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub update_metadata: bool,
}

/// Outcome of `POST /v1/objects:check-access`; `denied_ops` lists
/// the operations that failed when `allowed = false`.
#[derive(Serialize, ToSchema)]
pub(crate) struct AccessDecisionResponse {
    pub allowed: bool,
    pub denied_ops: AccessOpsResponse,
    pub reason: Option<String>,
}

/// Capabilities advertised by a backend route; drives client-side
/// feature detection.
#[derive(Serialize, ToSchema)]
pub(crate) struct CapabilitiesResponse {
    /// Backend honors `If-Match` on writes.
    pub supports_if_match_write: bool,
    /// Backend honors `If-None-Match: *` (no-overwrite create).
    pub supports_no_overwrite_write: bool,
    /// Backend can patch user metadata in place without rewriting the body.
    pub supports_native_metadata_patch: bool,
    /// Backend can emulate metadata patches by rewriting the object.
    pub supports_metadata_rewrite_emulation: bool,
    /// Writes commit atomically (readers never see partial state).
    pub writes_are_atomic: bool,
    /// A copy naming this root can be attempted (natively or emulated).
    pub supports_copy: bool,
    /// A rename naming this root can be attempted (natively or emulated).
    pub supports_rename: bool,
    /// Server-side copy is supported (no bytes through the gateway).
    pub supports_server_side_copy: bool,
    /// Server-side rename is supported.
    pub supports_server_side_rename: bool,
    /// Rename is atomic (no non-resolving window).
    pub supports_atomic_rename: bool,
    /// First-class directories (vs. prefix-simulated).
    pub has_real_directories: bool,
    /// Single-level (non-recursive) listing is supported.
    pub supports_list: bool,
    /// `stat` resolves via listing; clients should batch stats.
    pub wants_list_backed_stat: bool,
    /// Recursive listing is supported.
    pub supports_recursive_list: bool,
    /// List entries for subdirectories include populated metadata.
    pub populates_subdirectory_metadata: bool,
    /// Object versions are tracked; `/v1/objects:versions` is non-empty.
    pub supports_version_listing: bool,
    /// Stat results include the caller's effective permissions.
    pub populates_effective_permissions_on_stat: bool,
    /// `POST /v1/objects:check-access` is supported.
    pub supports_access_check: bool,
    /// `GET /v1/objects:watch-directory` produces non-empty streams.
    pub supports_watch_directory: bool,
    /// Watch streams support resume-from-cursor.
    pub watch_directory_resumable: bool,
    /// Backend implements the buffered single-shot write path.
    pub supports_write: bool,
    /// Backend implements the streaming-write path.
    pub supports_write_stream: bool,
    /// Backend can mint presigned-URL redirects for writes.
    pub supports_write_redirect: bool,
    /// Backend implements object delete.
    pub supports_delete: bool,
    /// Backend implements explicit directory creation.
    pub supports_create_directory: bool,
    /// Backend implements explicit directory delete.
    pub supports_delete_directory: bool,
}

/// One address root currently routed by the gateway.
#[derive(Serialize, ToSchema)]
pub(crate) struct AddressRootResponse {
    /// Root address (URL-prefix form).
    pub address: String,
    /// Operator-supplied human-readable label.
    pub display_name: Option<String>,
    /// Plugin kind backing this root (`file`, `s3`, `gcs`, etc.).
    pub backend_kind: String,
    /// Connection this root belongs to; `None` for static routes.
    pub connection_id: Option<String>,
    /// Capabilities of the backing backend.
    pub capabilities: CapabilitiesResponse,
}

/// One backend kind installed in this gateway.
#[derive(Serialize, ToSchema)]
pub(crate) struct BackendKindResponse {
    /// Stable `backend_kind` identifier (`file`, `s3`, etc.).
    pub kind: String,
    pub display_name: String,
    pub description: Option<String>,
    /// Whether this kind can be added at runtime (vs. config-file only).
    pub supports_runtime_add: bool,
}

/// Request body for `POST /v1/objects:copy` and `POST /v1/objects:rename`.
#[derive(Deserialize, ToSchema)]
pub(crate) struct CopyRenameBody {
    pub src: String,
    pub dest: String,
}

/// Request body for `PATCH /v1/objects:metadata`; partial update
/// applying `set` and `remove`, other keys untouched.
#[derive(Deserialize, ToSchema, Default)]
pub(crate) struct MetadataPatchBody {
    /// Keys to set or overwrite.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub set: HashMap<String, String>,
    /// Keys to remove.
    #[serde(default)]
    pub remove: Vec<String>,
    /// Opt into the non-atomic rewrite-emulation fallback when the
    /// backend lacks native metadata patches.
    #[serde(default)]
    pub allow_rewrite_emulation: bool,
    /// Optional annotation attached to this operation; backends that
    /// support per-operation annotations stash it under the
    /// `x-ov-message` user-metadata key.
    #[serde(default)]
    pub message: Option<String>,
}

/// Request body for `POST /v1/objects:check-access`; each `true`
/// flag probes one operation.
#[derive(Deserialize, ToSchema)]
pub(crate) struct CheckAccessBody {
    pub address: String,
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub delete: bool,
    #[serde(default)]
    pub update_metadata: bool,
}

/// Returned by `GET /v1/objects:list`.
#[derive(Serialize, ToSchema)]
pub(crate) struct ObjectInfoList {
    pub items: Vec<ObjectInfoResponse>,
}

/// Returned by `GET /v1/address-roots`.
#[derive(Serialize, ToSchema)]
pub(crate) struct AddressRootList {
    pub items: Vec<AddressRootResponse>,
}

/// Returned by `GET /v1/backend-kinds`.
#[derive(Serialize, ToSchema)]
pub(crate) struct BackendKindList {
    pub items: Vec<BackendKindResponse>,
}

/// Returned by `GET /v1/objects:versions`; newest-first by default.
#[derive(Serialize, ToSchema)]
pub(crate) struct VersionList {
    pub items: Vec<ObjectInfoResponse>,
}

/// Returned by `GET /v1/objects:latest-version`.
#[derive(Serialize, ToSchema)]
pub(crate) struct LatestVersionResponse {
    pub version: ObjectInfoResponse,
}

/// Error response shape returned by every error path; HTTP status
/// gives the coarse category, `error.code` the machine-readable code.
#[derive(Serialize, ToSchema)]
pub(crate) struct ErrorEnvelope {
    pub error: ErrorBody,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ErrorBody {
    /// Stable machine-readable error code.
    pub code: String,
    pub message: String,
    /// Recovery hint, when the producer attached one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_action: Option<String>,
    /// Present only on `PartialCompletion`. Without it an HTTP caller sees a
    /// 409 naming a code that means "your request half-happened" and has no
    /// way to learn whether undoing the committed part is safe — the natural
    /// guess (delete and re-issue) destroys data on the shipped case. 409 also
    /// carries `AlreadyExists`, where nothing was written at all, so the
    /// status alone cannot be acted on: read `error.code` first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial: Option<PartialBody>,
}

/// Wire form of `ErrorContext::Partial`. Field values are the stable
/// snake_case names from the corresponding `as_str()` helpers.
#[derive(Serialize, ToSchema)]
pub(crate) struct PartialBody {
    /// The stage that committed durably and will not be undone.
    /// One of: `object_data`, `user_metadata`, `source_removal`.
    pub completed: String,
    /// The stage that did not complete.
    /// One of: `object_data`, `user_metadata`, `source_removal`.
    pub failed: String,
    /// Whether the failed stage took effect: `not_applied` means the stage
    /// left no durable mark; `unknown` means we cannot tell from the client
    /// side (a lost response is indistinguishable from a refusal).
    /// One of: `not_applied`, `unknown`.
    pub failed_outcome: String,
    /// What undoing the committed stage would cost.
    /// `destroys_requested_work` means undoing it throws away work the caller
    /// asked for and must not be done blindly.
    /// `restores_prior_state` means undoing it returns the system to where it
    /// was before the operation.
    /// Read together with `failed_outcome`, never alone: rolling back is
    /// unconditionally safe only when `rollback` is `restores_prior_state`
    /// AND `failed_outcome` is `not_applied`. When `failed_outcome` is
    /// `unknown` the failed stage may already have taken effect, so undoing
    /// the committed stage can destroy the last surviving copy — verify the
    /// failed stage's actual state before acting.
    /// One of: `restores_prior_state`, `destroys_requested_work`.
    pub rollback: String,
}

/// One event from `GET /v1/objects:watch-directory`.
#[derive(Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ChangeEventResponse {
    /// An object changed under the watched prefix.
    Object {
        address: String,
        /// One of `created`, `modified`, `deleted`, `metadata_changed`.
        kind: String,
        /// Etag at event time; `None` for deletes.
        etag: Option<String>,
        /// Backend-specific version identifier when the backend
        /// surfaces it on the notification (e.g. S3 versionId, GCS
        /// generation, Azure blob version-id). `None` on deletes and
        /// on backends that don't version.
        version: Option<String>,
        /// Object size in bytes after the change, when the backend
        /// surfaces it on the notification.
        size: Option<u64>,
        /// Last-modified time of the object after the change as Unix
        /// nanoseconds, when the backend surfaces it on the
        /// notification.
        mtime_unix_nanos: Option<i128>,
        /// Resume cursor (pass as `since` on reconnect).
        cursor: String,
    },
    /// Events were missed from the previous cursor; client should
    /// re-list and resume from the new cursor.
    Lapsed { cursor: String },
}
