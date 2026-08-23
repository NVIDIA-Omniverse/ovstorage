// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `Backend` impl: maps ovstorage SPI calls to Omniverse Storage Service gRPC RPCs.

use std::pin::Pin;

use bytes::Bytes;
use futures::{Stream, StreamExt};
use ovstorage_plugin::{
    AccessDecision, AccessOps, AddressRoot, AddressRootsChange, AddressVisibility,
    BackendAddressRootsStream, BackendChangeEvent, BackendChangeStream, BackendItemInfo, Body,
    BodyStream, Capabilities, ChangeKind, ChecksumSet, ConnectionId, CopyOptions,
    CreateDirectoryOptions, DeleteDirectoryOptions, DeleteOptions, Error, ErrorCode, ErrorContext,
    HttpRequest, IfDestExists, ListOptions, ListVersionsOptions, ObjectInfo, ObjectKind,
    PartialStage, ReadOptions, ReadRedirect, ReadResult, RedirectBodySource, RedirectCredential,
    RedirectResultBatch, RedirectScope, RenameOptions, ResolvedTarget, ResponseParsing, Result,
    ResultCapture, RollbackEffect, RouteSource, StageOutcome, StatOptions, SystemMetadata,
    UpdateMetadataOptions, UserMetadata, WatchDirectoryCursor, WatchDirectoryOptions, WriteOptions,
    WriteRedirect, WriteRedirectBatch, WriteResult, WriteStep, race_cancel,
    validate_redirect_results,
};
use ovstorage_services_protos::nvidia::omniverse::notifications::consumer::v1beta as notif;
use ovstorage_services_protos::nvidia::omniverse::storage::{
    filefolder::v1alpha as ff, fileobject::v1alpha as fo, metadata::v1alpha as md,
    versioning::v1alpha as ver,
};

use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::convert::{
    fields_from_metadata, map_status, object_info_from, require_etag_only_if_match, require_field,
    resource_identity_from,
};
use crate::multipart::{Continuation, ContinuationKind};
use crate::trace::RedactedUrl;
use crate::transport::OmniverseStorageTransport;

/// Default chunk size for streaming writes. Each chunk maps 1:1 to a gRPC
/// `WriteRequest`. Storage-core itself doesn't impose a hard cap, but the
/// 4 MiB default keeps tonic's per-message buffer modest.
const WRITE_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// User-metadata key the Omniverse Storage Service uses to publish a
/// per-object access-control list. Matches the C++ provider's
/// `kMetadataKeyAcl` at `StorageProvider.cpp:168`.
const ACL_METADATA_KEY: &str = "acl";

// SPI: opts.message stashed via the metadata service when the backend has
// no per-operation annotation slot.
const OV_MESSAGE_KEY: &str = "x-ov-message";

/// The counts and flags one stash warning carries.
///
/// A struct rather than nine positional parameters: four of them are `usize`
/// and three are `bool`, so a transposed pair would compile silently and
/// mislabel an operator's only record of the failure. Named fields do not make
/// that impossible — nothing stops `failed: caller_total` — but they move the
/// mistake from invisible ordering to a name the reader can check, which is the
/// same reason the remedy and the failed stage are types rather than strings.
struct MetadataStashWarning<'a> {
    /// Keys that failed, over the whole map including the host's own.
    failed: usize,
    /// Keys attempted, over the whole map.
    total: usize,
    /// Keys OUTSIDE the reserved namespace that failed — the ones a
    /// `PartialCompletion` reports on.
    ///
    /// "Caller" is shorthand: the test is the namespace, not provenance, so a
    /// caller that sets its own `ovstorage-` key is counted with the host's.
    /// A different denominator from `failed`, which counts the whole map —
    /// equal to it whenever no reserved key was involved, smaller when one was.
    caller_failed: usize,
    /// Keys outside the reserved namespace.
    caller_total: usize,
    /// Whichever key failed first, reserved or not. Meaningless when
    /// `service_unreachable` is set, since no key was individually refused.
    sample_key: &'a str,
    /// Whether `ovstorage-modified-by` was among the failures. Called out
    /// separately because the sample is whichever key iterated first, which
    /// for a `HashMap` is not a stable choice, so without the flag the one key
    /// an operator cares about could be masked by a neighbour.
    attribution_failed: bool,
    /// True exactly when every failure was in the reserved namespace, so the
    /// write was downgraded from an error to `Ok` and the caller was
    /// deliberately not told.
    exempted: bool,
    /// The metadata service could not be reached at all, which took every key
    /// with it — the one case where `keys_failed == keys_total` without any key
    /// having been individually refused.
    ///
    /// An explicit flag rather than an empty `sample_key`: nothing rejects an
    /// empty metadata key from a caller, so emptiness was a sentinel a caller
    /// could forge.
    service_unreachable: bool,
    /// The sampled key's failure message.
    reason: &'a str,
}

/// Report post-commit metadata stashes that did not land. The object is already
/// written when these run, so the keys keep whatever the object carried before,
/// which for `ovstorage-modified-by` on an overwrite is the previous writer.
///
/// This warning is the operator's copy of the failure. When a CALLER key
/// failed, the caller also gets `ErrorCode::PartialCompletion` carrying the
/// same fact as a typed payload; when only reserved-namespace keys failed the
/// caller gets `Ok` and this warning is the only record, which `exempted`
/// marks. The two exist because they reach different audiences: the warning
/// has the counts and the flags and reaches a log, the error reaches the code
/// that issued the write. A `message` stash reaches neither: `stash_message`
/// discards every failure without warning, because that field is droppable by
/// contract.
///
/// One record per stash, not per key: the key set comes from a continuation the
/// caller supplied, so a per-key line lets a caller choose how many records a
/// failing metadata service emits. The address is deliberately absent — the
/// caller's span already carries the redacted one.
fn warn_metadata_stash_failed(warning: MetadataStashWarning<'_>) {
    let MetadataStashWarning {
        failed,
        total,
        caller_failed,
        caller_total,
        sample_key,
        attribution_failed,
        exempted,
        service_unreachable,
        reason,
    } = warning;
    let mut key: String = sample_key.chars().take(64).collect();
    if sample_key.chars().nth(64).is_some() {
        key.push('\u{2026}');
    }
    tracing::warn!(
        target: "ovstorage::services_client",
        plugin = "omniverse-storage-service",
        metadata.keys_failed = failed,
        metadata.keys_total = total,
        // The caller's own denominator. The error reports on caller keys and
        // this warning reports on the whole map, so without both an operator
        // reading "2 of 2" here and a caller reading "1 of 1" cannot tell they
        // describe one event.
        metadata.caller_keys_failed = caller_failed,
        metadata.caller_keys_total = caller_total,
        // True when every failure was in the reserved namespace, so the write
        // was downgraded from an error to `Ok`. Without it nothing in the log
        // marks that a caller was deliberately not told.
        metadata.exempted = exempted,
        // Explicit, so an operator never has to infer "unreachable" from an
        // empty sample key — a caller can supply an empty key.
        metadata.service_unreachable = service_unreachable,
        metadata.sample_failed_key = %key,
        metadata.attribution_failed = attribution_failed,
        reason = %ovstorage_plugin::redact::redact_message(reason),
        "metadata stash after commit failed; those keys keep their prior values",
    );
}

/// What a caller can actually do about a failed metadata stash.
///
/// Modelled as data rather than sentences. The recurring defect on this PR was
/// an operator hint that recommended an action which could not succeed for the
/// cause it was attached to — three times, in two directions, with every test
/// green. Prose cannot be constrained by asserting that phrases appear in it;
/// a typed remedy can be constrained by asserting values.
///
/// The instruction sentence is a pure function of the remedy
/// ([`Remedy::instruction`]), so the only thing that can be misclassified is
/// the cause-to-remedy mapping, and that is what the tests assert.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Remedy {
    /// Issue `update_metadata` once the service is reachable.
    ApplyWithUpdateMetadata,
    /// Read the object back first, because some keys may have landed, then
    /// apply the ones that did not.
    StatThenApplyMissing,
    /// There is nothing to retry here: the service refused these keys as
    /// unimplemented, and `update_metadata` issues the very same call.
    NoneAvailableHere,
}

impl Remedy {
    /// The instruction an operator follows. Every arm must steer away from
    /// re-issuing the write, which would change the etag.
    fn instruction(self) -> &'static str {
        match self {
            Remedy::ApplyWithUpdateMetadata => {
                "Apply the metadata with update_metadata once the service is \
                 reachable. Do not re-issue the write, which would change the \
                 etag."
            }
            Remedy::StatThenApplyMissing => {
                "Read the keys back with a full-metadata stat, then apply the \
                 missing ones with update_metadata. This repair is only safe \
                 under external serialization against concurrent replacement: \
                 update_metadata carries no identity condition, so a concurrent \
                 writer replacing the object between the stat and the patch \
                 would attach these keys to the replacement. If the service \
                 refused them for a permanent reason — permission, an invalid \
                 key — that refusal will repeat and the metadata cannot be \
                 stored as asked. Do not re-issue the write, which would change \
                 the etag."
            }
            Remedy::NoneAvailableHere => {
                "Retrying update_metadata issues the same call and fails the \
                 same way, so nothing will store these keys on this \
                 deployment. Either accept the object without them or route it \
                 to a deployment that stores user metadata. Do not re-issue \
                 the write, which would change the etag without storing \
                 anything."
            }
        }
    }

    /// Whether this remedy names `update_metadata` as the action to take.
    ///
    /// Deliberately NOT "expects it to succeed": `KeysRefused` covers every
    /// status but `Unimplemented`, including permanent ones like
    /// `PermissionDenied`, so no remedy can promise the call works. What the
    /// classification does guarantee is narrower and still worth enforcing —
    /// a cause whose keys were refused `Unimplemented` must never name
    /// `update_metadata` as the remedy, because that call provably repeats the
    /// refusal. That is the non-terminating loop.
    ///
    /// Exists to be asserted, not called: it turns the classification into a
    /// predicate a test can check, which is what the prose could not be.
    #[cfg(test)]
    fn names_update_metadata_as_the_remedy(self) -> bool {
        match self {
            Remedy::ApplyWithUpdateMetadata | Remedy::StatThenApplyMissing => true,
            Remedy::NoneAvailableHere => false,
        }
    }
}

/// Why an after-commit metadata stash failed.
///
/// Hints are keyed on **this**, not on [`StageOutcome`]: two causes share
/// `NotApplied` and need opposite remedies, so a sentence per outcome is wrong
/// for at least one producer by construction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MetadataStashFailure {
    /// The metadata client could not be built — a connect or discovery
    /// failure, so no RPC was dispatched.
    ///
    /// **Defensive.** In practice the transport memoises one channel per kind
    /// and never evicts it (`transport.rs`), and every caller of this path runs
    /// after a gRPC write that necessarily established that channel, so this
    /// arm is not reachable today. A later connection drop surfaces inside the
    /// per-key loop as [`MetadataStashFailure::KeysRefused`] instead. Kept
    /// because the fallible call is real and its handling should not be a
    /// guess if the memoisation ever changes.
    ClientUnavailable,
    /// Every **caller** key that failed was refused `Unimplemented`: the
    /// service does not implement metadata for them, so retrying cannot help.
    /// Scoped to caller keys because they are the only ones the remedy speaks
    /// to — a reserved key failing for some other reason alongside them does
    /// not change what the caller should do. Covers both "no caller key
    /// succeeded" and a mixed run; in either case the *failed caller* keys are
    /// the ones that can never be stored, which is what the instruction has to
    /// be true of.
    UnimplementedKeys,
    /// At least one key failed for some other reason. Any of those may have
    /// applied and reported failure on a lost response.
    KeysRefused,
}

impl MetadataStashFailure {
    /// The stage outcome this cause implies. Several causes share one, which
    /// is exactly why the remedy is not derived from it.
    fn outcome(self) -> StageOutcome {
        match self {
            // Nothing was dispatched, or the service refused outright. Neither
            // can be a lost response over a request that applied.
            MetadataStashFailure::ClientUnavailable | MetadataStashFailure::UnimplementedKeys => {
                StageOutcome::NotApplied
            }
            MetadataStashFailure::KeysRefused => StageOutcome::Unknown,
        }
    }

    /// The remedy for this cause. This mapping is the whole classification;
    /// `no_cause_names_a_remedy_that_provably_repeats_its_refusal` asserts it.
    fn remedy(self) -> Remedy {
        match self {
            MetadataStashFailure::ClientUnavailable => Remedy::ApplyWithUpdateMetadata,
            MetadataStashFailure::UnimplementedKeys => Remedy::NoneAvailableHere,
            MetadataStashFailure::KeysRefused => Remedy::StatThenApplyMissing,
        }
    }

    /// What happened, in one clause. Paired with the remedy's instruction to
    /// build the hint, so no cause carries a hand-written instruction that can
    /// drift from its remedy.
    fn situation(self) -> &'static str {
        match self {
            MetadataStashFailure::ClientUnavailable => {
                "The object is committed and readable. The metadata service \
                 could not be reached, so no key was attempted and none was \
                 stored."
            }
            MetadataStashFailure::UnimplementedKeys => {
                "The object is committed and readable. The metadata service \
                 refused the failed keys as unimplemented, so they were not \
                 stored."
            }
            MetadataStashFailure::KeysRefused => {
                "The object is committed and readable. Some keys may have been \
                 stored and some not."
            }
        }
    }
}

/// Build the `PartialCompletion` an after-commit metadata stash failure
/// surfaces. The object bytes are durable and correct; only the user-metadata
/// stage did not apply.
///
/// `rollback` is always `DestroysRequestedWork` here: the committed stage is
/// the object the caller asked for, so undoing it destroys the write itself.
fn partial_metadata_error(
    failed: usize,
    total: usize,
    cause: MetadataStashFailure,
    reason: &str,
) -> Error {
    Error::new(
        ErrorCode::PartialCompletion,
        format!(
            "omniverse-storage-service: object committed, but {failed} of {total} \
             user-metadata key(s) could not be stashed: {reason}"
        ),
    )
    .with_context(ErrorContext::Partial {
        completed: PartialStage::ObjectData,
        failed: PartialStage::UserMetadata,
        failed_outcome: cause.outcome(),
        rollback: RollbackEffect::DestroysRequestedWork,
    })
    .with_next_action(format!(
        "{} {}",
        cause.situation(),
        cause.remedy().instruction(),
    ))
}

/// Well-known metadata keys the Omniverse Storage Service stamps on every object. Mirrors
/// `kMetadataKey*` constants at `provider_omnistorage/StorageProvider.cpp:168-173`
/// and the explicit list at `_getMetadata` (`StorageProvider.cpp:5919-5920`).
const STD_KEY_CREATED_BY: &str = "created_by";
const STD_KEY_MODIFIED_BY: &str = "modified_by";
const STD_KEY_CREATED_TIMESTAMP: &str = "created_timestamp";
const STD_KEY_MODIFIED_TIMESTAMP: &str = "modified_timestamp";

const STANDARD_METADATA_KEYS: &[&str] = &[
    STD_KEY_CREATED_BY,
    STD_KEY_MODIFIED_BY,
    STD_KEY_CREATED_TIMESTAMP,
    STD_KEY_MODIFIED_TIMESTAMP,
];

/// Output of a `full_metadata` fetch. The plugin merges these into
/// `ObjectInfo` / `BackendItemInfo` so the host's stat / list paths see
/// who-touched-what and when, paying the extra round-trip only when the
/// caller asked for it.
#[derive(Debug, Default)]
struct StandardMetadata {
    modified_by: Option<String>,
    system_metadata: SystemMetadata,
    user_metadata: UserMetadata,
}

fn config_kind() -> &'static str {
    crate::config::KIND
}

fn grant_all() -> AccessOps {
    AccessOps {
        read: true,
        write: true,
        delete: true,
        update_metadata: true,
    }
}

fn parse_standard_metadata(response: md::GetMetadataResponse) -> StandardMetadata {
    use ovstorage_services_protos::google::protobuf::value::Kind;
    let mut out = StandardMetadata::default();
    for (key, entry) in response.user_metadata {
        let value = match entry.value.as_ref().and_then(|v| v.kind.as_ref()) {
            Some(Kind::StringValue(s)) => Some(s.clone()),
            Some(Kind::NumberValue(n))
                if matches!(
                    key.as_str(),
                    STD_KEY_CREATED_TIMESTAMP | STD_KEY_MODIFIED_TIMESTAMP
                ) =>
            {
                Some(format_timestamp_seconds(*n))
            }
            Some(Kind::NumberValue(n)) => Some(n.to_string()),
            Some(Kind::BoolValue(b)) => Some(b.to_string()),
            _ => None,
        };
        let Some(value) = value else { continue };
        out.user_metadata.insert(key.clone(), value.clone());
        if key.as_str() == STD_KEY_MODIFIED_BY {
            out.modified_by = Some(value.clone());
        }
        // Stamp every recognized key into system_metadata too so callers
        // that want the raw values (or future keys we don't yet promote
        // to a typed field) still see them.
        if STANDARD_METADATA_KEYS.contains(&key.as_str()) {
            out.system_metadata.insert(key, value);
        }
    }
    out
}

/// Storage-core publishes timestamps as `NumberValue` (Unix seconds, possibly
/// fractional). The C++ client formats them via `system_clock::time_point`;
/// we hand back an ISO-8601 string so the SPI's `system_metadata` map (which
/// is `String → String`) carries something humans can reason about.
fn format_timestamp_seconds(seconds: f64) -> String {
    if seconds.is_finite() {
        let whole = seconds.trunc() as i64;
        let nanos = ((seconds.fract().abs() * 1_000_000_000.0).round()) as u32;
        if let Some(t) =
            std::time::UNIX_EPOCH.checked_add(std::time::Duration::new(whole.max(0) as u64, nanos))
        {
            // RFC 3339-ish with seconds resolution. No external crate
            // dep; the host doesn't parse this — it's display-only.
            let secs_since_epoch = t
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            return format!("{secs_since_epoch}");
        }
    }
    seconds.to_string()
}

fn merge_standard_metadata_into_object(info: &mut ObjectInfo, extra: StandardMetadata) {
    if extra.modified_by.is_some() {
        info.modified_by = extra.modified_by;
    }
    if !extra.system_metadata.is_empty() {
        match info.system_metadata.as_mut() {
            Some(existing) => existing.extend(extra.system_metadata),
            None => info.system_metadata = Some(extra.system_metadata),
        }
    }
    if !extra.user_metadata.is_empty() {
        match info.user_metadata.as_mut() {
            Some(existing) => existing.extend(extra.user_metadata),
            None => info.user_metadata = Some(extra.user_metadata),
        }
    }
}

/// Translate a `google.protobuf.Value` ACL list into a granted-op set.
/// Unknown permission tokens are ignored (logged at trace level by the
/// C++ provider too). Bad shapes (not a list, or a list of non-strings)
/// fall through to `AccessOps::default()` — granting nothing — which the
/// caller composes with the requested ops to produce a fail-closed
/// decision.
fn parse_acl_grants(value: &md::UserMetadataValue) -> AccessOps {
    use ovstorage_services_protos::google::protobuf::value::Kind;
    let mut grants = AccessOps::default();
    let list = match value.value.as_ref().and_then(|v| v.kind.as_ref()) {
        Some(Kind::ListValue(list)) => list,
        _ => return grants,
    };
    for item in &list.values {
        let permission = match item.kind.as_ref() {
            Some(Kind::StringValue(s)) => s.as_str(),
            _ => continue,
        };
        match permission {
            "read" => grants.read = true,
            "write" => {
                grants.write = true;
                grants.update_metadata = true;
            }
            "admin" => grants.delete = true,
            _ => {
                tracing::trace!(
                    target: "ovstorage.omniverse_storage_service.access",
                    permission,
                    "omniverse-storage-service: unknown ACL permission token",
                );
            }
        }
    }
    grants
}

pub struct OmniverseStorageBackend {
    /// The connection's configured service URL, as typed: a discovery root, or
    /// a `grpc://` / `grpcs://` direct endpoint. Identity and diagnostics only.
    service_locator: String,
    capabilities: Capabilities,
    transport: OmniverseStorageTransport,
}

impl OmniverseStorageBackend {
    pub fn new(
        service_locator: String,
        capabilities: Capabilities,
        transport: OmniverseStorageTransport,
    ) -> Self {
        Self {
            service_locator,
            capabilities,
            transport,
        }
    }

    pub async fn capabilities_for_root(&self, address: &Url) -> Capabilities {
        let mut capabilities = self.capabilities.clone();
        self.apply_folder_mode_capabilities(address, &mut capabilities)
            .await;
        self.apply_optimistic_locking_capabilities(address, &mut capabilities)
            .await;
        capabilities
    }

    async fn apply_folder_mode_capabilities(&self, address: &Url, capabilities: &mut Capabilities) {
        let Ok(mut client) = self.transport.filefolder_client().await else {
            return;
        };
        let response = match client
            .get_folder_mode(ff::GetFolderModeRequest {
                folder: Some(ff::FolderAddress {
                    uri: address.to_string(),
                }),
            })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == tonic::Code::Unimplemented => return,
            Err(status) => {
                tracing::warn!(
                    target: "ovstorage.omniverse_storage_service.backend",
                    plugin = "omniverse-storage-service",
                    address = %RedactedUrl(address),
                    error = %status,
                    "omniverse-storage-service: GetFolderMode failed; using default directory capabilities",
                );
                return;
            }
        };
        match ff::FolderMode::try_from(response.folder_mode).unwrap_or(ff::FolderMode::Unspecified)
        {
            ff::FolderMode::Native => {
                capabilities.has_real_directories = true;
                capabilities.supports_create_directory = true;
                capabilities.supports_delete_directory = true;
            }
            ff::FolderMode::Hybrid => {
                capabilities.has_real_directories = false;
                capabilities.supports_create_directory = true;
                capabilities.supports_delete_directory = true;
            }
            ff::FolderMode::NoEmpty => {
                capabilities.has_real_directories = false;
                capabilities.supports_create_directory = false;
                capabilities.supports_delete_directory = false;
            }
            ff::FolderMode::Unspecified => {}
        }
    }

    async fn apply_optimistic_locking_capabilities(
        &self,
        address: &Url,
        capabilities: &mut Capabilities,
    ) {
        let Ok(mut client) = self.transport.fileobject_client().await else {
            return;
        };
        let response = match client
            .get_optimistic_locking_support(fo::GetOptimisticLockingSupportRequest {
                resource_address: address.to_string(),
            })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == tonic::Code::Unimplemented => return,
            Err(status) => {
                tracing::warn!(
                    target: "ovstorage.omniverse_storage_service.backend",
                    plugin = "omniverse-storage-service",
                    address = %RedactedUrl(address),
                    error = %status,
                    "omniverse-storage-service: GetOptimisticLockingSupport failed; using default precondition capabilities",
                );
                return;
            }
        };
        capabilities.supports_if_match_write = response.supports_write;
    }

    pub fn transport(&self) -> &OmniverseStorageTransport {
        &self.transport
    }
}

// Backend operations called directly by the crate's Layer in `layer.rs`.
impl OmniverseStorageBackend {
    pub async fn stat(
        &self,
        target: ResolvedTarget,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.stat",
            op = "stat",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.fileobject_client().await?;
            let response = client
                .stat(fo::StatRequest {
                    resource_address: target.resolved_address.to_string(),
                })
                .await
                .map_err(map_status)?;
            let info = require_field(response.into_inner().resource_info, "stat.resource_info")?;
            let mut object_info = object_info_from(target.resolved_address.clone(), &info);
            if opts.full_metadata
                && let Some(extra) = self.fetch_standard_metadata(&target).await?
            {
                merge_standard_metadata_into_object(&mut object_info, extra);
            }
            Ok(object_info)
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        require_etag_only_if_match(opts.if_match.as_deref())?;
        let span = tracing::debug_span!(
            "omniverse_storage_service.read",
            op = "read",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.fileobject_client().await?;
            let (object_info, body) = if let Some(expected) = opts.if_match.as_ref() {
                // ResourceIdentity.encoded_identity is the SPI etag
                // token. A caller-supplied if_match is therefore already the
                // server-side precondition identity; resolving the address
                // first would only add latency and can race the read.
                fetch_read_by_identity(&mut client, &target, expected).await?
            } else {
                fetch_read_from_address(&mut client, &target).await?
            };
            // Apply opts.range on the body. For Chunks we slice the
            // bytes the plugin is producing (servers only inline-stream
            // small objects). For Redirect we return the redirect
            // unchanged — the host injects the Range header in
            // `redirect.rs` so every plugin returning ReadResult::Redirect
            // benefits without re-implementing.
            match body {
                ReadBody::Empty => {
                    if let Some(range) = opts.range.as_ref() {
                        // start>0 against a zero-byte object is out of bounds.
                        if range.start > 0 {
                            return Err(Error::new(
                                ErrorCode::InvalidArgument,
                                format!(
                                    "omniverse-storage-service: range start {} beyond object size 0",
                                    range.start,
                                ),
                            ));
                        }
                    }
                    let empty: Pin<
                        Box<dyn Stream<Item = ovstorage_plugin::Result<Bytes>> + Send>,
                    > = Box::pin(futures::stream::empty());
                    Ok(ReadResult::Stream {
                        stream: empty,
                        info: object_info,
                    })
                }
                ReadBody::Chunks(mut stream) => {
                    if let Some(range) = opts.range.as_ref() {
                        // Buffer-then-slice. Bounded waste: the server only
                        // chooses inline streaming for small objects.
                        let mut buf: Vec<u8> = Vec::new();
                        while let Some(chunk) = stream.next().await {
                            buf.extend_from_slice(&chunk?);
                        }
                        // Validate range BEFORE slicing — otherwise an
                        // inverted (end < start) or out-of-bounds range
                        // would panic the slice and abort under the
                        // workspace's panic policy.
                        if let Some(end) = range.end_inclusive
                            && end < range.start
                        {
                            return Err(Error::new(
                                ErrorCode::InvalidArgument,
                                format!(
                                    "omniverse-storage-service: range end_inclusive {} is less than start {}",
                                    end, range.start,
                                ),
                            ));
                        }
                        let start = range.start as usize;
                        if start > buf.len() {
                            return Err(Error::new(
                                ErrorCode::InvalidArgument,
                                format!(
                                    "omniverse-storage-service: range start {} beyond object size {}",
                                    range.start,
                                    buf.len(),
                                ),
                            ));
                        }
                        let end_exclusive = range
                            .end_inclusive
                            .map(|e| (e as usize).saturating_add(1).min(buf.len()))
                            .unwrap_or(buf.len());
                        debug_assert!(
                            end_exclusive >= start,
                            "end_exclusive >= start should be guaranteed by the inverted-range check above",
                        );
                        let slice = buf[start..end_exclusive].to_vec();
                        Ok(ReadResult::Bytes {
                            bytes: slice,
                            info: object_info,
                        })
                    } else {
                        Ok(ReadResult::Stream {
                            stream,
                            info: object_info,
                        })
                    }
                }
                ReadBody::Redirect(redirect) => {
                    Ok(ReadResult::Redirect(build_read_redirect(redirect)))
                }
            }
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn write(
        &self,
        target: ResolvedTarget,
        bytes: Vec<u8>,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.write",
            op = "write",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let body = Body::Bytes(bytes);
            self.send_inline_write(target, body, opts).await
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn write_stream(
        &self,
        target: ResolvedTarget,
        body: BodyStream,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.write",
            op = "write",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            self.send_inline_write(target, Body::Stream(body), opts)
                .await
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn write_redirect(
        &self,
        target: ResolvedTarget,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.write",
            op = "write",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            self.start_write_redirect(target, opts).await
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn continue_write(
        &self,
        target: ResolvedTarget,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        attested_modified_by: Option<&str>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.write",
            op = "write",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            self.finalize_write_redirect(target, redirects, results, attested_modified_by)
                .await
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn delete(
        &self,
        target: ResolvedTarget,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        require_etag_only_if_match(opts.if_match.as_deref())?;
        let span = tracing::debug_span!(
            "omniverse_storage_service.delete",
            op = "delete",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.fileobject_client().await?;
            let previous_version = resource_identity_from(&opts.if_match);
            // delete is idempotent: a missing target is success (NotFound from server is mapped to Ok).
            match client
                .delete(fo::DeleteRequest {
                    resource_address: target.resolved_address.to_string(),
                    previous_version,
                })
                .await
            {
                Ok(_) => Ok(()),
                Err(status) => {
                    let err = map_status(status);
                    if err.code() == ErrorCode::NotFound {
                        Ok(())
                    } else {
                        Err(err)
                    }
                }
            }
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn list(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.list",
            op = "list",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&prefix.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        // Capability `supports_recursive_list = false` (factory.rs).
        // The OvCS ListStat RPC only enumerates the immediate level,
        // so silently dropping `opts.recursive = true` would hand
        // callers a partial subtree as if it were the full result.
        // Refuse instead.
        if opts.recursive {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: recursive list is not supported by this backend \
                 (Capabilities.supports_recursive_list = false)",
            ));
        }
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.filefolder_client().await?;
            let mut stream = client
                .list_stat(ff::ListStatRequest {
                    folder: Some(ff::FolderAddress {
                        uri: prefix.resolved_address.to_string(),
                    }),
                })
                .await
                .map_err(map_status)?
                .into_inner();
            let mut items = Vec::new();
            let mut metadata_targets: Vec<(usize, String)> = Vec::new();
            while let Some(frame) = stream.message().await.map_err(map_status)? {
                // An entry whose address does not survive canonicalization is
                // dropped with a `warn!`, not propagated. That is a property of
                // the one entry, and failing the page would hide every valid
                // sibling with it — the policy the object backends state for
                // the same case. `get_latest_version` is the opposite and
                // deliberately so: it has one answer, so an unusable winner
                // there is an error rather than an older version.
                for sub in frame.subfolder_addresses {
                    match parse_server_address(&sub.uri, "list subfolder address") {
                        Ok(address) => {
                            items.push(default_object_info(address, ObjectKind::Directory))
                        }
                        Err(error) => tracing::warn!(
                            target: "ovstorage::services_client",
                            address = %redacted_address(&sub.uri),
                            reason = %error.message(),
                            "omniverse-storage-service: subfolder address is not addressable; \
                             omitted from the listing",
                        ),
                    }
                }
                for entry in frame.entries {
                    let address = match parse_server_address(
                        &entry.resource_address,
                        "list resource address",
                    ) {
                        Ok(address) => address,
                        Err(error) => {
                            tracing::warn!(
                                target: "ovstorage::services_client",
                                address = %redacted_address(&entry.resource_address),
                                reason = %error.message(),
                                "omniverse-storage-service: list resource_address is not \
                                 addressable; omitted from the listing",
                            );
                            continue;
                        }
                    };
                    let info = entry
                        .resource_info
                        .as_ref()
                        .map(|info| object_info_from(address.clone(), info))
                        .unwrap_or_else(|| default_object_info(address.clone(), ObjectKind::File));
                    // Indexed against the item this pushes, so a dropped entry
                    // cannot shift a later entry's metadata onto its neighbour.
                    if opts.full_metadata {
                        metadata_targets.push((items.len(), entry.resource_address.clone()));
                    }
                    items.push(info);
                }
            }
            // Per-entry metadata fetch on `full_metadata`. Mirrors the C++
            // provider, which calls `_getMetadata` for each list entry
            // (`StorageProvider.cpp:_listStat` callback). N round-trips by
            // design — the host pays a clear cost when it asks for it, and
            // a cheap stat / list never pays.
            if opts.full_metadata {
                for (idx, address) in metadata_targets {
                    if let Some(extra) = self.fetch_standard_metadata_by_address(&address).await? {
                        merge_standard_metadata_into_object(&mut items[idx], extra);
                    }
                }
            }
            Ok(items)
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn list_versions(
        &self,
        target: ResolvedTarget,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.list_versions",
            op = "list_versions",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        // EnumerateVersions has no max_results / page_token on the
        // wire, and the host does NOT paginate list_versions for the
        // plugin (unlike list). Silently dropping these knobs would
        // hand the caller every version from the start when they
        // asked for a bounded page. Refuse instead — the test plugin
        // does the same.
        if opts.max_results.is_some() || opts.page_token.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: list_versions does not support max_results / page_token \
                 (EnumerateVersions returns every version in one stream)",
            ));
        }
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.versioning_client().await?;
            let mut stream = client
                .enumerate_versions(ver::EnumerateVersionsRequest {
                    resource_address: target.resolved_address.to_string(),
                })
                .await
                .map_err(|status| {
                    if status.code() == tonic::Code::InvalidArgument {
                        Error::new(
                            ErrorCode::Unsupported,
                            "omniverse-storage-service: cannot list all versions from this address; \
                             the service rejected it as invalid for EnumerateVersions. \
                             Pass the unversioned resource address instead of a version resource address.",
                        )
                    } else {
                        map_status(status)
                    }
                })?
                .into_inner();
            let mut items = Vec::new();
            while let Some(frame) = stream.message().await.map_err(map_status)? {
                for v in frame.items {
                    if let Some(item) = object_info_from_version_proto(v)? {
                        items.push(item);
                    }
                }
            }
            Ok(items)
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn get_latest_version(
        &self,
        target: ResolvedTarget,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.get_latest_version",
            op = "get_latest_version",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.versioning_client().await?;
            let enumerate = client
                .enumerate_versions(ver::EnumerateVersionsRequest {
                    resource_address: target.resolved_address.to_string(),
                })
                .await
                .map_err(map_status);
            let mut stream = match enumerate {
                Ok(response) => response.into_inner(),
                Err(err) if err.code() == ErrorCode::InvalidArgument => {
                    // Omniverse Storage Service resource addresses are opaque. A version address
                    // returned by EnumerateVersions is valid for Stat/Read,
                    // but the service rejects it as an input to
                    // EnumerateVersions. Preserve that exact address instead
                    // of trying to recognize a backend-specific URL shape.
                    let mut client = self.transport.fileobject_client().await?;
                    let response = client
                        .stat(fo::StatRequest {
                            resource_address: target.resolved_address.to_string(),
                        })
                        .await
                        .map_err(map_status)?;
                    let info =
                        require_field(response.into_inner().resource_info, "stat.resource_info")?;
                    return Ok(object_info_from(target.resolved_address.clone(), &info));
                }
                Err(err) => return Err(err),
            };
            let mut picker = LatestVersionPicker::new();
            while let Some(frame) = stream.message().await.map_err(map_status)? {
                if picker.observe_frame(frame)? {
                    break;
                }
            }
            picker.finish()
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn create_directory(
        &self,
        target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.create_directory",
            op = "create_directory",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.filefolder_client().await?;
            client
                .create_folder(ff::CreateFolderRequest {
                    folder: Some(ff::FolderAddress {
                        uri: target.resolved_address.to_string(),
                    }),
                })
                .await
                .map_err(map_status)?;
            Ok(BackendItemInfo {
                kind: ObjectKind::Directory,
                ..Default::default()
            })
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn delete_directory(
        &self,
        target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.delete_directory",
            op = "delete_directory",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.filefolder_client().await?;
            // delete_directory is idempotent: a missing target is success.
            match client
                .delete_folder(ff::DeleteFolderRequest {
                    folder: Some(ff::FolderAddress {
                        uri: target.resolved_address.to_string(),
                    }),
                })
                .await
            {
                Ok(_) => Ok(()),
                Err(status) => {
                    let err = map_status(status);
                    if err.code() == ErrorCode::NotFound {
                        Ok(())
                    } else {
                        Err(err)
                    }
                }
            }
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn copy(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        require_etag_only_if_match(opts.if_source.as_deref())?;
        // The Storage API wire has no "fail if destination exists" primitive —
        // CopyRequest.previous_version is a compare-and-swap on the
        // destination's current identity, not an absence assertion.
        // Silently ignoring `IfDestExists::Fail` would clobber an
        // existing object; refuse loudly instead (matches the
        // `supports_no_overwrite_write = false` capability).
        if matches!(opts.if_dest, IfDestExists::Fail) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: copy with if_dest=Fail is not supported by this backend \
                 (Storage API wire has no fail-if-exists primitive; \
                 Capabilities.supports_no_overwrite_write = false)",
            ));
        }
        let span = tracing::debug_span!(
            "omniverse_storage_service.copy",
            op = "copy",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&src.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.fileobject_client().await?;
            // CopyRequest.source_resource_identity is required by the Storage API
            // wire. With an explicit source etag, use it directly as the
            // opaque ResourceIdentity/precondition token. Without one, Stat
            // the current source head to obtain the identity the RPC requires.
            let source_resource_identity = if let Some(etag) = opts.if_source.as_ref() {
                fo::ResourceIdentity {
                    encoded_identity: etag.clone(),
                }
            } else {
                let stat = client
                    .stat(fo::StatRequest {
                        resource_address: src.resolved_address.to_string(),
                    })
                    .await
                    .map_err(map_status)?;
                let stat_info =
                    require_field(stat.into_inner().resource_info, "stat.resource_info")?;
                require_field(
                    stat_info.resource_identity,
                    "stat.resource_info.resource_identity",
                )?
            };
            // Destination-side precondition: `MatchEtag` becomes a
            // compare-and-swap on `previous_version`. `Overwrite`
            // leaves the field unset. (`Fail` was rejected above.)
            let previous_version = match &opts.if_dest {
                IfDestExists::MatchEtag(etag) => resource_identity_from(&Some(etag.clone())),
                IfDestExists::Overwrite | IfDestExists::Fail => None,
            };
            let response = client
                .copy(fo::CopyRequest {
                    source_resource_identity: Some(source_resource_identity),
                    destination_resource_address: dest.resolved_address.to_string(),
                    previous_version,
                })
                .await
                .map_err(|status| {
                    if opts.if_source.is_some() {
                        map_identity_precondition_status(status, &src.resolved_address, "copy")
                    } else {
                        map_status(status)
                    }
                })?;
            let resource_identity = response.into_inner().resource_identity;
            let etag = resource_identity
                .map(|id| id.encoded_identity)
                .filter(|s| !s.is_empty());
            let dest_address = dest.resolved_address.clone();
            self.stash_message(dest_address.as_str(), opts.message.as_deref())
                .await;
            Ok(WriteStep::Done(WriteResult {
                info: ObjectInfo {
                    address: dest_address,
                    kind: ObjectKind::File,
                    etag,
                    version: None,
                    size: None,
                    mtime: None,
                    checksums: ChecksumSet::default(),
                    effective_permissions: None,
                    system_metadata: None,
                    user_metadata: None,
                    modified_by: None,
                },
            }))
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn rename(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        require_etag_only_if_match(opts.if_source.as_deref())?;
        // The Storage API wire has no "fail if destination exists" primitive
        // for Move: MoveRequest.destination_previous_version is a
        // compare-and-swap on an existing identity, not an absence
        // assertion. Silently ignoring `IfDestExists::Fail` would
        // clobber an existing object; refuse loudly.
        if matches!(opts.if_dest, IfDestExists::Fail) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: rename with if_dest=Fail is not supported by this backend \
                 (Storage API wire has no fail-if-exists primitive; \
                 Capabilities.supports_no_overwrite_write = false)",
            ));
        }
        let span = tracing::debug_span!(
            "omniverse_storage_service.rename",
            op = "rename",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&src.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.fileobject_client().await?;
            // The Storage API proto's MoveRequest carries separate
            // source/destination previous-version slots, so the new
            // split SPI maps cleanly: `if_source` -> source side,
            // `if_dest::MatchEtag` -> destination side.
            let source_previous_version = resource_identity_from(&opts.if_source);
            let destination_previous_version = match &opts.if_dest {
                IfDestExists::MatchEtag(etag) => resource_identity_from(&Some(etag.clone())),
                IfDestExists::Overwrite | IfDestExists::Fail => None,
            };
            client
                .r#move(fo::MoveRequest {
                    source_resource_address: src.resolved_address.to_string(),
                    source_previous_version,
                    destination_resource_address: dest.resolved_address.to_string(),
                    destination_previous_version,
                })
                .await
                .map_err(map_status)?;
            self.stash_message(dest.resolved_address.as_str(), opts.message.as_deref())
                .await;
            Ok(())
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn update_metadata(
        &self,
        target: ResolvedTarget,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.update_metadata",
            op = "update_metadata",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            if opts.if_match.is_some() {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "omniverse-storage-service update_metadata cannot honor object-level if_match: \
                     the metadata service uses per-key etags, not an object identity",
                ));
            }
            let mut client = self.transport.metadata_client().await?;
            for (key, value) in opts.user_metadata_set {
                client
                    .update_metadata(md::UpdateMetadataRequest {
                        uri: target.resolved_address.to_string(),
                        user_metadata_key: key,
                        user_metadata: Some(md_value_string(value)),
                        expected_etag: None,
                    })
                    .await
                    .map_err(map_status)?;
            }
            for key in opts.user_metadata_remove {
                client
                    .delete_metadata(md::DeleteMetadataRequest {
                        uri: target.resolved_address.to_string(),
                        user_metadata_key: key,
                        expected_etag: None,
                    })
                    .await
                    .map_err(map_status)?;
            }
            self.stash_message(target.resolved_address.as_str(), opts.message.as_deref())
                .await;
            let mut object_client = self.transport.fileobject_client().await?;
            let stat = object_client
                .stat(fo::StatRequest {
                    resource_address: target.resolved_address.to_string(),
                })
                .await
                .map_err(map_status)?;
            let info = require_field(stat.into_inner().resource_info, "stat.resource_info")?;
            let mut object_info = object_info_from(target.resolved_address.clone(), &info);
            if let Some(extra) = self.fetch_standard_metadata(&target).await? {
                merge_standard_metadata_into_object(&mut object_info, extra);
            }
            Ok(backend_item_info_from_object(object_info))
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn watch_directory(
        &self,
        prefix: ResolvedTarget,
        opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendChangeStream> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.watch_directory",
            op = "watch_directory",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&prefix.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.event_consumer_client().await?;
            let prefix_address = prefix.resolved_address.to_string();
            let request_msg = notif::ConsumeNonDurableEventsRequest {
                filter_groups: build_watch_filter_groups(&prefix_address, opts.recursive),
                reconnect_token: opts
                    .since
                    .as_ref()
                    .and_then(|c| std::str::from_utf8(&c.0).ok())
                    .map(|s| s.to_string()),
                // Single-shot filter request: we never refilter mid-stream, so
                // there are no previous filter groups to invalidate.
                previous_filter_groups: Vec::new(),
            };
            // Bidi streaming: single-shot filter request, then read events.
            // Storage-core supports refilter mid-stream by sending more
            // ConsumeNonDurableEventsRequest frames; we don't refilter here.
            let request_stream = futures::stream::once(async move { request_msg });
            let response = client
                .consume_non_durable_events(request_stream)
                .await
                .map_err(map_status)?;
            let server_stream = response.into_inner();
            Ok(spawn_watch_bridge(prefix.resolved_address, server_stream))
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    pub async fn watch_address_roots(
        &self,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendAddressRootsStream> {
        race_cancel(cancel.as_ref(), async move {
            // Block until interactive sign-in installs a bearer; without it
            // services discovery (and hence ListTopLevelAddresses) 401s
            // against auth-required deployments.
            //
            // Skipped for a connection configured with a direct gRPC endpoint:
            // it publishes no auth-config, so no grant can run and no token will
            // ever arrive. Waiting there is not slow, it is unbounded — and
            // nothing downstream needs a bearer, since the interceptor simply
            // sends no `authorization` header when the cell is empty.
            if self.transport.requires_bearer() {
                self.transport.auth_state().wait_for_token().await;
            }
            // Storage-core today exposes ListTopLevelAddresses but no delta
            // feed. Emit a single Snapshot so the host's per-connection
            // watcher gets the current view, then end the stream. When the
            // upstream service publishes Added/Removed events, replace this
            // with a real bridge.
            let urls = self.list_top_level_addresses().await?;
            tracing::debug!(
                target: "ovstorage.omniverse_storage_service.backend",
                plugin = "omniverse-storage-service",
                // The locator is operator-configured and may carry userinfo,
                // so it is rendered like every server-supplied address here.
                service_url = %redacted_address(&self.service_locator),
                count = urls.len(),
                "omniverse-storage-service: list_top_level_addresses returned",
            );
            let backend_kind = config_kind();
            let connection_id = ConnectionId(format!(
                "omniverse-storage-service:{}",
                self.service_locator
            ));
            let mut roots = Vec::with_capacity(urls.len());
            for address in urls {
                let capabilities = self.capabilities_for_root(&address).await;
                roots.push(AddressRoot {
                    address,
                    display_name: None,
                    backend_kind: backend_kind.to_string(),
                    connection_id: Some(connection_id.clone()),
                    capabilities,
                    source: RouteSource::ConnectionContributed {
                        connection_id: connection_id.clone(),
                    },
                    visibility: AddressVisibility::Visible,
                    user_metadata: UserMetadata::new(),
                });
            }
            let snapshot = Ok(AddressRootsChange::Snapshot(roots));
            let stream: BackendAddressRootsStream =
                Box::pin(futures::stream::once(async move { snapshot }));
            Ok(stream)
        })
        .await
    }

    pub async fn check_access(
        &self,
        target: ResolvedTarget,
        ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        race_cancel(cancel.as_ref(), async move {
            let mut file_client = self.transport.fileobject_client().await?;
            file_client
                .stat(fo::StatRequest {
                    resource_address: target.resolved_address.to_string(),
                })
                .await
                .map_err(map_status)?;
            let granted = self.fetch_acl_grants(&target).await?;
            let denied_ops = AccessOps {
                read: ops.read && !granted.read,
                write: ops.write && !granted.write,
                delete: ops.delete && !granted.delete,
                update_metadata: ops.update_metadata && !granted.update_metadata,
            };
            let allowed = !denied_ops.read
                && !denied_ops.write
                && !denied_ops.delete
                && !denied_ops.update_metadata;
            Ok(AccessDecision {
                allowed,
                denied_ops,
                reason: if allowed {
                    None
                } else {
                    Some("omniverse-storage-service: object ACL does not grant the requested operations".into())
                },
            })
        })
        .await
    }
}

fn extract_chunk(frame: fo::ReadFromAddressResponse) -> Result<Bytes> {
    use fo::read_from_address_response::ReplyType;
    match frame.reply_type {
        Some(ReplyType::Chunk(chunk)) => Ok(chunk.chunk),
        Some(ReplyType::ResourceInfo(_)) => Err(Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service: server sent ResourceInfo mid-stream",
        )),
        Some(ReplyType::Redirect(_)) => Err(Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service: server sent Redirect after Chunk frames; \
             redirect path is mutually exclusive with chunk delivery",
        )),
        None => Err(Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service: empty Read frame",
        )),
    }
}

fn extract_read_chunk(frame: fo::ReadResponse) -> Result<Bytes> {
    use fo::read_response::ReplyType;
    match frame.reply_type {
        Some(ReplyType::Chunk(chunk)) => Ok(chunk.chunk),
        Some(ReplyType::Metadata(_)) => Err(Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service: server sent Metadata mid-stream",
        )),
        Some(ReplyType::Redirect(_)) => Err(Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service: server sent Redirect after Chunk frames; \
             redirect path is mutually exclusive with chunk delivery",
        )),
        None => Err(Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service: empty Read frame",
        )),
    }
}

/// Unified body-delivery shape returned by the read path.
enum ReadBody {
    Empty,
    Chunks(Pin<Box<dyn Stream<Item = ovstorage_plugin::Result<Bytes>> + Send>>),
    Redirect(fo::Redirect),
}

/// Read a caller-supplied etag as a Storage API ResourceIdentity.
///
/// This is not address-level version selection. The SPI version selector is
/// the URL returned by version listing; `if_match` is the opaque etag token
/// from a prior operation on the same address. The Storage API names that token
/// `ResourceIdentity`, so a successful identity read is the server-side
/// precondition check. If the server has discarded or rejects the identity,
/// map that miss to `ObjectModified`.
async fn fetch_read_by_identity(
    client: &mut crate::transport::FileObject,
    target: &ResolvedTarget,
    etag: &str,
) -> Result<(ObjectInfo, ReadBody)> {
    let response = client
        .read(fo::ReadRequest {
            resource_identity: Some(fo::ResourceIdentity {
                encoded_identity: etag.to_string(),
            }),
            download_preference: None,
        })
        .await
        .map_err(|status| {
            map_identity_precondition_status(status, &target.resolved_address, "read")
        })?;
    let mut server_stream = response.into_inner();
    use fo::read_response::ReplyType;
    let first = server_stream
        .message()
        .await
        .map_err(|status| {
            map_identity_precondition_status(status, &target.resolved_address, "read")
        })?
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: read stream closed before first reply",
            )
        })?;
    let object_info = match first.reply_type {
        Some(ReplyType::Metadata(metadata)) => {
            object_info_from_read_metadata(target.resolved_address.clone(), Some(&metadata), etag)
        }
        Some(ReplyType::Chunk(_)) => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: server sent Chunk before Metadata",
            ));
        }
        Some(ReplyType::Redirect(_)) => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: server sent Redirect before Metadata",
            ));
        }
        None => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: Read reply_type missing on first frame",
            ));
        }
    };
    let second = server_stream.message().await.map_err(|status| {
        map_identity_precondition_status(status, &target.resolved_address, "read")
    })?;
    let body = match second.and_then(|frame| frame.reply_type) {
        Some(ReplyType::Chunk(chunk)) => {
            let first_chunk = futures::stream::once(async move { Ok(chunk.chunk) });
            let rest =
                server_stream.map(|frame| frame.map_err(map_status).and_then(extract_read_chunk));
            let stream: Pin<Box<dyn Stream<Item = ovstorage_plugin::Result<Bytes>> + Send>> =
                Box::pin(first_chunk.chain(rest));
            ReadBody::Chunks(stream)
        }
        Some(ReplyType::Redirect(redirect)) => ReadBody::Redirect(redirect),
        Some(ReplyType::Metadata(_)) => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: server sent Metadata mid-stream",
            ));
        }
        None => ReadBody::Empty,
    };
    Ok((object_info, body))
}

fn object_info_from_read_metadata(
    address: Url,
    metadata: Option<&fo::Metadata>,
    etag: &str,
) -> ObjectInfo {
    let fields = fields_from_metadata(metadata, Some(etag.to_string()).filter(|s| !s.is_empty()));
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: fields.etag,
        version: None,
        size: fields.size,
        mtime: fields.mtime,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

fn default_object_info(address: Url, kind: ObjectKind) -> ObjectInfo {
    ObjectInfo {
        address,
        kind,
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

fn backend_item_info_from_object(info: ObjectInfo) -> BackendItemInfo {
    BackendItemInfo {
        kind: info.kind,
        etag: info.etag,
        version: info.version,
        size: info.size,
        mtime: info.mtime,
        checksums: info.checksums,
        effective_permissions: info.effective_permissions,
        system_metadata: info.system_metadata,
        user_metadata: info.user_metadata,
        modified_by: info.modified_by,
    }
}

/// A loggable form of a server-supplied address.
///
/// **The redactor for every diagnostic that names a rejected address**, in the
/// `warn!` and in `parse_server_address`'s own errors, which four call sites
/// propagate to the host. A server-supplied address can carry userinfo or a
/// signed query, so echoing it verbatim writes a password or a signature to
/// whatever sink receives the error — past the [`RedactedUrl`] policy the rest
/// of this crate applies.
///
/// Three cases, and each is rendered for what it can still tell an operator
/// rather than by one rule:
///
/// - A base-able URL prints as scheme, host and path. Userinfo lands in
///   `username()`/`password()` and the query is dropped, neither of which
///   `RedactedUrl` emits.
/// - A **cannot-be-a-base** URL has no host, and its `path()` is the entire
///   opaque payload — userinfo, query and all — so [`RedactedUrl`], which
///   writes `scheme://` and then the path, would print the whole string.
///   (`ovstorage_plugin`'s separate copy of that type withholds the class;
///   this crate's does not, and it is this crate's that is in scope here.)
///   That is not a corner case: being that class is one of the two conditions
///   `parse_server_address` rejects on, so it is a common input to this
///   function precisely when redaction matters.
/// - Anything `Url::parse` refuses has no structure to redact at all.
///
/// The byte count is a deliberate concession: it narrows a fixed-format
/// credential slightly, and it is often the only thing that makes a rejection
/// diagnosable.
pub(crate) fn redacted_address(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(url) if !url.cannot_be_a_base() => RedactedUrl(&url).to_string(),
        Ok(url) => format!("<opaque {} address, {} bytes>", url.scheme(), raw.len()),
        Err(_) => format!("<unparseable address, {} bytes>", raw.len()),
    }
}

/// Normalize an address the server returned, refusing one that names a
/// different node than it spells.
///
/// Same class as an address arriving over the plugin ABI, and the same
/// asymmetry: normalizing a *request* is the point, but a server's answer is a
/// claim about which object it named, so rewriting it retargets that claim. A
/// server answering `omniverse://h/public%2F..%2Fprivate/secret` for that
/// literal object would otherwise have it silently remapped.
///
/// Only dot-segment resolution can move an address to a different object, so
/// that is all this refuses; host case, the empty authority path, the fragment
/// and escape spelling are normalized through.
///
/// The parse alone was also not enough for a second reason: `Stack`
/// canonicalizes requests, so an un-normalized server address later compared
/// against a canonicalized prefix (`strip_prefix`, below) fails a containment
/// check it should pass, and a legitimate event is dropped as out-of-prefix.
pub(crate) fn parse_server_address(raw: &str, label: &'static str) -> Result<Url> {
    let url = Url::parse(raw).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "omniverse-storage-service: invalid {label} {}: {err}",
                redacted_address(raw)
            ),
        )
    })?;
    // Two steps can move a returned address and both are checked.
    // `parsing_preserves_node` answers for `Url::parse` itself, which resolves
    // dot segments, removes ASCII TAB/LF/CR and folds `\` on a special scheme
    // before `canonicalize_preserves_node` can see any of them — so a server
    // answering `omni://server/public/../private/secret` would otherwise arrive
    // already flattened and pass as a fixed point.
    if url.cannot_be_a_base()
        || !ovstorage::parsing_preserves_node(raw)
        || !ovstorage::canonicalize_preserves_node(&url)
    {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "omniverse-storage-service: {label} {} resolves elsewhere, so a caller \
                 acting on it would reach a different object",
                redacted_address(raw)
            ),
        ));
    }
    Ok(ovstorage::canonicalize(url))
}

fn map_identity_precondition_status(
    status: tonic::Status,
    address: &Url,
    op: &'static str,
) -> Error {
    match status.code() {
        tonic::Code::NotFound | tonic::Code::FailedPrecondition => Error::new(
            ErrorCode::ObjectModified,
            format!(
                "omniverse-storage-service {op}: supplied identity does not name readable bytes for {}",
                RedactedUrl(address),
            ),
        )
        .with_context(ErrorContext::Identity { new_etag: None }),
        _ => map_status(status),
    }
}

/// One version listing entry, or `None` when the server named it with an
/// address no caller could act on.
///
/// A version listing is a listing: omit the entry rather than failing the page
/// and hiding every other version with it — including the ones the caller can
/// act on. This mirrors `blob_to_version_item` in the Azure plugin, which omits
/// for exactly this reason.
fn object_info_from_version_proto(v: ver::VersionInfo) -> Result<Option<ObjectInfo>> {
    let Some(address) = version_resource_address(&v)? else {
        return Ok(None);
    };
    Ok(Some(
        v.resource_info
            .as_ref()
            .map(|info| object_info_from(address.clone(), info))
            .unwrap_or_else(|| default_object_info(address, ObjectKind::File)),
    ))
}

/// `None` when the server's `resource_address` is not one a caller could act on.
///
/// An address that does not survive canonicalization names a different object
/// than it spells, so acting on it would reach the wrong version. That is a
/// property of the one entry, not of the page, so it is dropped with a `warn!`
/// rather than propagated — the absent `resource_address` below stays an error
/// because it is a malformed response rather than an unaddressable object.
fn version_resource_address(v: &ver::VersionInfo) -> Result<Option<Url>> {
    let raw = v
        .resource_address
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: EnumerateVersions item has no resource_address",
            )
        })?;
    match parse_server_address(raw, "version resource_address") {
        Ok(url) => Ok(Some(url)),
        Err(error) => {
            tracing::warn!(
                target: "ovstorage::services_client",
                address = %redacted_address(raw),
                reason = %error.message(),
                "omniverse-storage-service: version resource_address is not addressable; \
                 omitted from the version listing",
            );
            Ok(None)
        }
    }
}

struct LatestVersionPicker {
    order: Option<ver::VersionsOrder>,
    selected: Option<SelectedVersion>,
}

struct SelectedVersion {
    /// The winning entry as the server sent it, converted only in `finish`.
    ///
    /// Selection is on `versions_order` ALONE. Converting here and skipping an
    /// entry whose address does not survive canonicalization would answer
    /// "latest" with an older version — the caller asked which version is
    /// newest and would be handed stale bytes with nothing saying so. The
    /// skip-and-warn policy the listing paths use is right there because the
    /// caller still sees the rest of the page; a single-answer call has no
    /// such remainder, so an unusable winner is an error.
    item: ver::VersionInfo,
    sorting_key: Option<String>,
}

impl LatestVersionPicker {
    fn new() -> Self {
        Self {
            order: None,
            selected: None,
        }
    }

    fn observe_frame(&mut self, frame: ver::EnumerateVersionsResponse) -> Result<bool> {
        let order = ver::VersionsOrder::try_from(frame.versions_order)
            .unwrap_or(ver::VersionsOrder::Unspecified);
        if order == ver::VersionsOrder::Unspecified {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: EnumerateVersions returned VERSIONS_ORDER_UNSPECIFIED",
            ));
        }
        if let Some(previous) = self.order {
            if previous != order {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "omniverse-storage-service: EnumerateVersions changed versions_order mid-stream",
                ));
            }
        } else {
            self.order = Some(order);
        }

        match order {
            ver::VersionsOrder::NewestFirst => {
                // The first entry the server sent, addressable or not.
                if self.selected.is_none()
                    && let Some(item) = frame.items.into_iter().next()
                {
                    self.selected = Some(SelectedVersion {
                        item,
                        sorting_key: None,
                    });
                    return Ok(true);
                }
            }
            ver::VersionsOrder::OldestFirst => {
                if let Some(item) = frame.items.into_iter().next_back() {
                    self.selected = Some(SelectedVersion {
                        item,
                        sorting_key: None,
                    });
                }
            }
            ver::VersionsOrder::ByKey => {
                for item in frame.items {
                    let sorting_key = item.sorting_key.clone().ok_or_else(|| {
                        Error::new(
                            ErrorCode::Unsupported,
                            "omniverse-storage-service: versions_order=BY_KEY item has no sorting_key",
                        )
                    })?;
                    // Per the vendored storage API proto,
                    // VERSIONS_ORDER_BY_KEY sorts ascending by sorting_key
                    // lexicographically, so the latest item is the greatest
                    // sorting_key under string comparison.
                    let replace = self
                        .selected
                        .as_ref()
                        .and_then(|selected| selected.sorting_key.as_ref())
                        .map(|current| sorting_key.as_str() > current.as_str())
                        .unwrap_or(true);
                    if replace {
                        self.selected = Some(SelectedVersion {
                            item,
                            sorting_key: Some(sorting_key),
                        });
                    }
                }
            }
            ver::VersionsOrder::Unspecified => unreachable!("handled above"),
        }
        Ok(false)
    }

    fn finish(self) -> Result<ObjectInfo> {
        let selected = self.selected.ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "omniverse-storage-service: EnumerateVersions returned no versions",
            )
        })?;
        // The winner is converted here, and a failure is propagated rather
        // than skipped: there is no next-best answer to `get_latest_version`.
        let raw = selected
            .item
            .resource_address
            .as_deref()
            .filter(|address| !address.is_empty())
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Unsupported,
                    "omniverse-storage-service: EnumerateVersions item has no resource_address",
                )
            })?;
        let address = parse_server_address(raw, "latest version resource_address")?;
        Ok(selected
            .item
            .resource_info
            .as_ref()
            .map(|info| object_info_from(address.clone(), info))
            .unwrap_or_else(|| default_object_info(address, ObjectKind::File)))
    }
}

/// Read the latest version at the address via `ReadFromAddress`.
async fn fetch_read_from_address(
    client: &mut crate::transport::FileObject,
    target: &ResolvedTarget,
) -> Result<(ObjectInfo, ReadBody)> {
    let response = client
        .read_from_address(fo::ReadFromAddressRequest {
            resource_address: target.resolved_address.to_string(),
            download_preference: None,
        })
        .await
        .map_err(map_status)?;
    let mut server_stream = response.into_inner();
    use fo::read_from_address_response::ReplyType;
    let first = server_stream
        .message()
        .await
        .map_err(map_status)?
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: read stream closed before first reply",
            )
        })?;
    let object_info = match first.reply_type {
        Some(ReplyType::ResourceInfo(info)) => {
            object_info_from(target.resolved_address.clone(), &info)
        }
        Some(ReplyType::Chunk(_)) => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: server sent Chunk before ResourceInfo",
            ));
        }
        Some(ReplyType::Redirect(_)) => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: server sent Redirect before ResourceInfo",
            ));
        }
        None => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: ReadFromAddress reply_type missing on first frame",
            ));
        }
    };
    let second = server_stream.message().await.map_err(map_status)?;
    let body = match second.and_then(|frame| frame.reply_type) {
        Some(ReplyType::Chunk(chunk)) => {
            let first_chunk = futures::stream::once(async move { Ok(chunk.chunk) });
            let rest = server_stream.map(|frame| frame.map_err(map_status).and_then(extract_chunk));
            let stream: Pin<Box<dyn Stream<Item = ovstorage_plugin::Result<Bytes>> + Send>> =
                Box::pin(first_chunk.chain(rest));
            ReadBody::Chunks(stream)
        }
        Some(ReplyType::Redirect(redirect)) => ReadBody::Redirect(redirect),
        Some(ReplyType::ResourceInfo(_)) => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: server sent ResourceInfo mid-stream",
            ));
        }
        None => ReadBody::Empty,
    };
    Ok((object_info, body))
}

/// Build the SPI's `ReadRedirect` from the proto `Redirect` frame.
///
/// Storage-core's `Redirect.method` is deprecated; we default to GET
/// unless the server explicitly sets it. Headers round-trip verbatim so
/// the host's redirect follower replays signed-URL parameters
/// (`x-amz-*`, `Authorization`, etc.) the server stamped on.
fn build_read_redirect(redirect: fo::Redirect) -> ReadRedirect {
    #[allow(deprecated)]
    let method = if redirect.method.trim().is_empty() {
        "GET".to_string()
    } else {
        redirect.method.clone()
    };
    let headers: Vec<(String, String)> = redirect
        .additional_headers
        .iter()
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect();
    let url = redirect.redirect_target_url;
    // Server doesn't publish a redirect TTL today; one hour matches the
    // signed-URL window storage backends typically grant.
    let expires_at = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
    // The non-redirect read path returns the Storage API wire's
    // `ResourceIdentity.encoded_identity` as the etag. The redirect path
    // lands on whichever underlying cloud the server federates to
    // (S3, Azure, GCS, …), whose HTTP-level `ETag` header has its own
    // shape — sending that value back through a future `if_match` would
    // be rejected at the Storage API wire. Clear `etag_header` so the redirect
    // path advertises "no usable etag" instead of returning an
    // incompatible token. (`Stat` remains the supported way to obtain
    // an `if_match` token before a redirect-fetched read.)
    let response_parsing = ResponseParsing {
        etag_header: None,
        ..ResponseParsing::default()
    };
    ReadRedirect {
        request: HttpRequest {
            method,
            url: url.clone(),
            headers,
        },
        response_parsing,
        expires_at,
        scope: RedirectScope {
            physical_url_prefix: url,
            operations: AccessOps {
                read: true,
                ..Default::default()
            },
            expires_at,
            // The headers are copied straight out of the service's response;
            // this plugin did not mint them and cannot state what they cover.
            credential: RedirectCredential::Unspecified,
        },
        audit_id: String::new(),
        policy_epoch: 0,
    }
}

fn md_value_string(value: String) -> ovstorage_services_protos::google::protobuf::Value {
    use ovstorage_services_protos::google::protobuf::{Value, value::Kind};
    Value {
        kind: Some(Kind::StringValue(value)),
    }
}

impl OmniverseStorageBackend {
    async fn list_top_level_addresses(&self) -> Result<Vec<url::Url>> {
        use ovstorage_services_protos::nvidia::omniverse::storage::capabilities::v1alpha as cap;
        let mut client = self.transport.capabilities_client().await?;
        let response = client
            .list_top_level_addresses(cap::ListTopLevelAddressesRequest {})
            .await
            .map_err(map_status)?;
        let raw: Vec<String> = response
            .into_inner()
            .items
            .into_iter()
            .map(|entry| entry.top_level_address)
            .collect();
        // One pass: the rejection is classified where it happens rather than
        // re-derived inside the `warn!`, which used to parse every entry a
        // second time purely to build the log field.
        let mut parsed: Vec<url::Url> = Vec::with_capacity(raw.len());
        let mut rejected: Vec<String> = Vec::new();
        for entry in &raw {
            match parse_server_address(entry, "top-level address") {
                Ok(url) => parsed.push(url),
                Err(_) => rejected.push(redacted_address(entry)),
            }
        }
        if !rejected.is_empty() {
            tracing::warn!(
                target: "ovstorage.omniverse_storage_service.backend",
                plugin = "omniverse-storage-service",
                raw_count = raw.len(),
                parsed_count = parsed.len(),
                rejected_count = rejected.len(),
                rejected = ?rejected,
                "omniverse-storage-service: ListTopLevelAddresses returned entries that failed address validation",
            );
        }
        Ok(parsed)
    }

    async fn send_inline_write(
        &self,
        target: ResolvedTarget,
        body: Body,
        opts: WriteOptions,
    ) -> Result<WriteResult> {
        // Map IfDestExists to Storage API WriteParameters.previous_version:
        // - Overwrite -> no precondition
        // - MatchEtag(s) -> compare-and-swap on the destination's
        //   current identity
        // - Fail -> the Storage API wire has no fail-if-exists primitive;
        //   refuse loudly (matches `supports_no_overwrite_write = false`).
        let previous_version = match &opts.if_dest {
            IfDestExists::Overwrite => None,
            IfDestExists::MatchEtag(etag) => resource_identity_from(&Some(etag.clone())),
            IfDestExists::Fail => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "omniverse-storage-service: write with if_dest=Fail is not supported by this backend \
                     (Storage API wire has no fail-if-exists primitive; \
                     Capabilities.supports_no_overwrite_write = false)",
                ));
            }
        };
        let mut client = self.transport.fileobject_client().await?;
        let (data_object_size, body_stream) = body_to_chunk_stream(body, opts.size_hint).await?;
        let params = fo::WriteRequest {
            write_request_type: Some(fo::write_request::WriteRequestType::Params(
                fo::WriteParameters {
                    destination_resource_address: target.resolved_address.to_string(),
                    previous_version,
                    data_object_size,
                    upload_preference: Some(fo::UploadPreference::Body as i32),
                },
            )),
        };
        let (request_stream, source_err) = build_write_request_stream(params, body_stream);
        // `.fuse()` keeps the receiver safe to re-poll after it has
        // resolved — without it, the second select! below would panic
        // with "called after complete" on the clean-EOS path.
        use futures::future::FutureExt;
        let mut source_err = source_err.fuse();

        // We can't truly cancel a tonic 0.14 client-streaming RPC
        // mid-flight — `Grpc::streaming` wraps the request stream as
        // `s.map(Ok)`, so source errors can't reach h2's error path,
        // and dropping the response future / response stream lets h2
        // send END_STREAM gracefully rather than RST_STREAM. A
        // truncated upload can therefore finalize on the server. The
        // OmniverseStorageService doesn't validate received bytes
        // against `WriteParameters.data_object_size` either, so we
        // can't rely on server-side rejection. Best we can do from
        // the client is surface the source error to the caller so it
        // never silently reports success on a partial upload.
        let response = tokio::select! {
            biased;
            Ok(err) = &mut source_err => return Err(err),
            resp = client.write(request_stream) => resp.map_err(map_status)?,
        };
        let mut server_stream = response.into_inner();
        let mut last_resource_info: Option<fo::ResourceInfo> = None;
        loop {
            tokio::select! {
                biased;
                Ok(err) = &mut source_err => return Err(err),
                msg = server_stream.message() => {
                    let Some(msg) = msg.map_err(map_status)? else { break };
                    use fo::write_response::WriteResponseType;
                    match msg.write_response_type {
                        Some(WriteResponseType::WriteChunksAccepted(_)) => continue,
                        Some(WriteResponseType::ResourceInfo(info)) => {
                            last_resource_info = Some(info);
                        }
                        Some(WriteResponseType::WriteRedirect(_))
                        | Some(WriteResponseType::MultipartUpload(_)) => {
                            return Err(Error::new(
                                ErrorCode::Unsupported,
                                "omniverse-storage-service: server demanded redirect mid-inline-write; \
                                 host should call write_redirect for this size class",
                            ));
                        }
                        None => {}
                    }
                }
            }
        }
        // Server-stream end and source-error can land in the same
        // poll cycle. Prefer the source error over the (potentially
        // truncated) server response.
        if let Some(Ok(err)) = source_err.now_or_never() {
            return Err(err);
        }
        let info = last_resource_info.ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: write stream closed without ResourceInfo",
            )
        })?;
        let address = target.resolved_address.clone();
        let address_str = address.as_str().to_string();
        self.stash_message(&address_str, opts.message.as_deref())
            .await;
        self.stash_user_metadata(&address_str, opts.user_metadata.as_ref())
            .await?;
        Ok(WriteResult {
            info: object_info_from(address, &info),
        })
    }

    async fn start_write_redirect(
        &self,
        target: ResolvedTarget,
        opts: WriteOptions,
    ) -> Result<WriteRedirectBatch> {
        // Map IfDestExists to Storage API WriteParameters.previous_version
        // (see send_inline_write for the full rationale on each arm).
        let previous_version = match &opts.if_dest {
            IfDestExists::Overwrite => None,
            IfDestExists::MatchEtag(etag) => resource_identity_from(&Some(etag.clone())),
            IfDestExists::Fail => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "omniverse-storage-service: write with if_dest=Fail is not supported by this backend \
                     (Storage API wire has no fail-if-exists primitive; \
                     Capabilities.supports_no_overwrite_write = false)",
                ));
            }
        };
        // Redirect uploads emit `RedirectBodySource::UserBytes { len }`,
        // which the host's redirect follower drains exactly. Without
        // an upfront size we can't supply a finite `len` — emitting
        // `u64::MAX` would make any normal finite body fail at EOF.
        // The host falls back to write/write_stream when redirect is
        // not viable.
        let size = opts.size_hint.ok_or_else(|| {
            Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: write_redirect requires size_hint; \
                 host should fall through to write/write_stream",
            )
        })?;
        let mut client = self.transport.fileobject_client().await?;
        let preferred = preferred_upload_method(&mut client, &target, size).await?;
        if matches!(
            preferred,
            fo::UploadPreference::Body | fo::UploadPreference::Unspecified
        ) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: server reports inline upload for this size; \
                 host should fall through to write/write_stream",
            ));
        }
        let params = fo::WriteRequest {
            write_request_type: Some(fo::write_request::WriteRequestType::Params(
                fo::WriteParameters {
                    destination_resource_address: target.resolved_address.to_string(),
                    previous_version,
                    data_object_size: size,
                    upload_preference: Some(preferred as i32),
                },
            )),
        };
        // No chunks — server must respond on the first frame with a redirect
        // or a multipart_upload control message.
        let empty: Pin<Box<dyn Stream<Item = Result<fo::WriteRequest>> + Send>> =
            futures::stream::empty().boxed();
        // No chunks → source can never error → the receiver here will
        // resolve with `RecvError` when the sender is dropped (stream
        // ends). We just discard it.
        let (request_stream, _source_err) = build_write_request_stream(params, empty);
        let response = client.write(request_stream).await.map_err(map_status)?;
        let mut server_stream = response.into_inner();
        let first = server_stream
            .message()
            .await
            .map_err(map_status)?
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Internal,
                    "omniverse-storage-service: write stream closed before first reply",
                )
            })?;
        use fo::write_response::WriteResponseType;
        match first.write_response_type {
            Some(WriteResponseType::WriteRedirect(props)) => Ok(single_redirect_batch(
                &target,
                size,
                opts.message.clone(),
                opts.user_metadata.clone(),
                props,
            )),
            Some(WriteResponseType::MultipartUpload(mp)) => {
                multipart_redirect_batch(
                    self,
                    &target,
                    size,
                    opts.message.clone(),
                    opts.user_metadata.clone(),
                    mp,
                )
                .await
            }
            Some(WriteResponseType::ResourceInfo(_))
            | Some(WriteResponseType::WriteChunksAccepted(_)) => Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: server accepted inline write but write_redirect was requested",
            )),
            None => Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: write_response_type missing on first redirect frame",
            )),
        }
    }

    // Stash opts.message under user_metadata key `x-ov-message` after a
    // successful mutating write.
    //
    // Best-effort, and unlike `stash_user_metadata` it stays that way: EVERY
    // failure is discarded — a metadata client that cannot be built and any
    // RPC error alike, not only `Unimplemented`. That is the contract's own
    // distinction rather than an oversight: `message` is a per-operation
    // annotation a backend may drop, while `user_metadata` must be surfaced
    // when it cannot be stored, so failing a committed write over a dropped
    // annotation would be wrong.
    async fn stash_message(&self, address: &str, message: Option<&str>) {
        let Some(value) = message.filter(|m| !m.is_empty()) else {
            return;
        };
        let Ok(mut client) = self.transport.metadata_client().await else {
            return;
        };
        let _ = client
            .update_metadata(md::UpdateMetadataRequest {
                uri: address.to_string(),
                user_metadata_key: OV_MESSAGE_KEY.to_string(),
                user_metadata: Some(md_value_string(value.to_string())),
                expected_etag: None,
            })
            .await;
    }

    /// Stash `user_metadata` with one `UpdateMetadata` RPC per key, after the
    /// object bytes have committed.
    ///
    /// Returns `ErrorCode::PartialCompletion` when a key **outside the reserved
    /// `ovstorage-` namespace** fails. The object is durable at that point and must not be re-written,
    /// so the error names the object data as committed and the user metadata as
    /// the stage that did not apply. The remedy depends on why the stash failed
    /// and is carried in `next_action` — see [`MetadataStashFailure`]; it is
    /// not always `update_metadata`.
    ///
    /// # Why the host's own reserved keys are exempt
    ///
    /// A failure confined to the `ovstorage-` reserved namespace warns and
    /// returns `Ok`. That looks like it contradicts the multi-stage durability
    /// rule, which says a metadata failure after a commit must surface — so
    /// the reasoning belongs here rather than in a merge commit nobody reads.
    ///
    /// **The `ovstorage-` namespace is the host's**, and on the deployments
    /// this matters for the keys in it are the host's too. A broker or REST
    /// branch running the default `UserMetadata` attribution strategy stamps
    /// `ovstorage-modified-by` into `user_metadata` on every mutating write —
    /// whether or not the caller asked for any metadata, since the stamp
    /// creates the map when there is none. If that stamp failing were to fail
    /// the write, then against a deployment whose metadata service is absent,
    /// *every* brokered write would return an error after its bytes had already
    /// committed — for callers who supplied no metadata and would not
    /// understand the failure. Losing an audit record is bad; converting every
    /// write into a post-commit error is worse, and it is the caller who pays
    /// for a decision the host made.
    ///
    /// Under `AttributionStrategy::Passthrough` the host stamps nothing, so
    /// that deployment never reaches this case at all.
    ///
    /// The rule the contract is actually protecting is *the caller must learn
    /// when what they asked for did not happen*. A caller who supplied metadata
    /// still learns. The operator, who owns the audit trail, learns from
    /// `warn_metadata_stash_failed`: it carries both denominators (whole map
    /// and caller keys), an `attribution_failed` flag for the one key they
    /// usually care about, and an `exempted` flag that is true exactly when
    /// this function downgraded a failure to `Ok` — so a downgrade is visible
    /// even for a reserved key that is not the attribution stamp.
    ///
    /// This also keeps the decision independent of which branches a host
    /// composes its attribution layer over. That is decided from each backend
    /// kind's own `supports_user_metadata` declaration, which is a static,
    /// per-kind answer: this plugin declares that it can carry user metadata,
    /// and whether a given root's deployment runs the metadata service is a
    /// fact the declaration does not resolve. Keying on the reserved namespace
    /// instead means this path does not depend on that declaration at all.
    ///
    /// # The consequence a caller can hit, stated
    ///
    /// The test is the `ovstorage-` **namespace**, not the one key the host
    /// actually plants, and the host strips that namespace out of
    /// client-supplied metadata only where an attribution layer is composed and
    /// stamping (`ovstorage-authz`'s `stamp_write` / `stamp_update_metadata`).
    /// A direct, unbrokered caller — or one on a `Passthrough` branch — can
    /// therefore reach this backend with an `ovstorage-`-prefixed key of their
    /// own, and it will be treated as the host's: warned about and not
    /// surfaced.
    ///
    /// That is accepted rather than overlooked. The namespace is documented as
    /// reserved for host-attested keys, so a caller writing into it is already
    /// outside the contract, and the failure direction is the safe one — they
    /// lose a key they were not entitled to set, with a warning, instead of
    /// every brokered write turning into a post-commit error.
    ///
    /// Narrowing the test to `ATTRIBUTION_KEY_MODIFIED_BY` would shrink that
    /// surface to one key, and is deliberately **not** done: the host planting
    /// a second reserved key later would then start failing writes over it and
    /// reintroduce exactly the defect this exemption exists to prevent. The
    /// namespace is the stable unit, and it is the host's.
    ///
    /// # Reporting granularity
    ///
    /// **The failure is reported per stash, not per key.** A map can be
    /// partially applied — the loop issues one RPC per key and some may
    /// succeed — so `failed: UserMetadata` means *at least one caller key* did
    /// not apply, not that none did. A key-count field in the payload would
    /// make the context metadata-specific rather than serving any compound
    /// operation.
    async fn stash_user_metadata(
        &self,
        address: &str,
        user_metadata: Option<&ovstorage_plugin::UserMetadata>,
    ) -> Result<()> {
        let Some(map) = user_metadata.filter(|m| !m.is_empty()) else {
            return Ok(());
        };
        // Counted over CALLER keys only: they are what a `PartialCompletion`
        // reports on, so a "3 of 4 keys" message that included the host's
        // stamp would describe a map the caller never sent.
        let caller_total = map
            .keys()
            .filter(|key| !ovstorage_plugin::is_reserved_metadata_key(key))
            .count();
        let total = map.len();
        let mut client = match self.transport.metadata_client().await {
            Ok(client) => client,
            Err(err) => {
                let attribution_failed = map.keys().any(|key| {
                    key.eq_ignore_ascii_case(ovstorage_plugin::ATTRIBUTION_KEY_MODIFIED_BY)
                });
                let reason = err.to_string();
                warn_metadata_stash_failed(MetadataStashWarning {
                    // No RPC was dispatched, so every key failed.
                    failed: total,
                    total,
                    caller_failed: caller_total,
                    caller_total,
                    sample_key: "",
                    attribution_failed,
                    exempted: caller_total == 0,
                    service_unreachable: true,
                    reason: &reason,
                });
                if caller_total == 0 {
                    return Ok(());
                }
                // No RPC was dispatched, so nothing can have been applied.
                return Err(partial_metadata_error(
                    caller_total,
                    caller_total,
                    MetadataStashFailure::ClientUnavailable,
                    &err.to_string(),
                ));
            }
        };
        let mut failed = 0usize;
        let mut caller_failed = 0usize;
        let mut attribution_failed = false;
        // TWO samples, deliberately. `map` is a `HashMap`, so iteration order is
        // unspecified: a single sample shared between the warning and the error
        // lets the host stamp's failure message become the CALLER's `reason`
        // whenever the stamp happens to be visited first. That pairs a
        // per-cause situation computed from caller keys with a message from a
        // key the caller never sent, and it changes run to run on identical
        // input.
        let mut caller_first_failure: Option<(String, String)> = None;
        let mut any_first_failure: Option<(String, String)> = None;
        // `Unimplemented` is the server refusing to implement the call for
        // that key, so it definitively did not apply and re-issuing it repeats
        // the refusal. (Usually that means no metadata service at all, but the
        // proof only covers the keys that were refused.) Any other error may be
        // a lost response over a request that did apply, so one non-
        // `Unimplemented` CALLER failure downgrades the stash to `Unknown`.
        // Reserved-key failures do not vote: they never reach the caller.
        let mut every_caller_failure_was_unimplemented = true;
        for (key, value) in map {
            if let Err(status) = client
                .update_metadata(md::UpdateMetadataRequest {
                    uri: address.to_string(),
                    user_metadata_key: key.clone(),
                    user_metadata: Some(md_value_string(value.clone())),
                    expected_etag: None,
                })
                .await
            {
                failed += 1;
                attribution_failed |=
                    key.eq_ignore_ascii_case(ovstorage_plugin::ATTRIBUTION_KEY_MODIFIED_BY);
                // The operator's sample is whichever key failed first,
                // reserved or not, so the warning names a key that really was
                // refused rather than the first CALLER key, which may not be
                // the one an operator is chasing.
                any_first_failure
                    .get_or_insert_with(|| (key.clone(), status.message().to_string()));
                if !ovstorage_plugin::is_reserved_metadata_key(key) {
                    caller_failed += 1;
                    every_caller_failure_was_unimplemented &=
                        status.code() == tonic::Code::Unimplemented;
                    caller_first_failure
                        .get_or_insert_with(|| (key.clone(), status.message().to_string()));
                }
            }
        }
        if let Some((key, reason)) = &any_first_failure {
            warn_metadata_stash_failed(MetadataStashWarning {
                failed,
                total,
                caller_failed,
                caller_total,
                sample_key: key,
                attribution_failed,
                exempted: caller_failed == 0,
                service_unreachable: false,
                reason,
            });
        }
        // Only reserved-namespace keys failed: the caller got everything they
        // asked for, so the write succeeded from where they stand.
        if caller_failed == 0 {
            return Ok(());
        }
        // A caller key failed, so a caller sample exists.
        // Not `unwrap_or_else`: `caller_failed` is incremented in the same
        // branch that sets this sample, and the `caller_failed == 0` early
        // return above is the only other path here. A default would be a silent
        // answer for a state the code has already proved impossible.
        let (_, reason) =
            caller_first_failure.expect("caller_failed > 0 implies a caller sample was recorded");
        // Keyed on the FAILED caller keys only, with no `caller_failed ==
        // caller_total` guard. A mixed run (some keys stored, the rest refused
        // `Unimplemented`) still has failed keys that no retry can store, so
        // routing it to `KeysRefused` would promise an `update_metadata` that
        // fails identically — the same non-terminating loop, one case further
        // out.
        let cause = if every_caller_failure_was_unimplemented {
            MetadataStashFailure::UnimplementedKeys
        } else {
            MetadataStashFailure::KeysRefused
        };
        Err(partial_metadata_error(
            caller_failed,
            caller_total,
            cause,
            &reason,
        ))
    }

    async fn fetch_standard_metadata(
        &self,
        target: &ResolvedTarget,
    ) -> Result<Option<StandardMetadata>> {
        self.fetch_standard_metadata_by_address(target.resolved_address.as_str())
            .await
    }

    async fn fetch_standard_metadata_by_address(
        &self,
        address: &str,
    ) -> Result<Option<StandardMetadata>> {
        let mut client = self.transport.metadata_client().await?;
        let response = match client
            .get_metadata(md::GetMetadataRequest {
                uri: address.to_string(),
                // Empty key list asks the service for all user metadata.
                // `parse_standard_metadata` also promotes the known
                // service-stamped keys into system_metadata/modified_by.
                user_metadata_keys: Vec::new(),
            })
            .await
        {
            Ok(resp) => resp,
            Err(status) if status.code() == tonic::Code::Unimplemented => {
                // Server has no metadata service: silent no-op so stat/list
                // don't fail just because the deployment skips notifications.
                return Ok(None);
            }
            Err(status) => return Err(map_status(status)),
        };
        Ok(Some(parse_standard_metadata(response.into_inner())))
    }

    /// Fetch the per-object `acl` user metadata key and translate it to the
    /// granted-op set. Mirrors the C++ provider_omnistorage parse at
    /// `StorageProvider.cpp:5966-6011`. Mapping:
    ///
    /// - `"read"`  → `AccessOps::read`
    /// - `"write"` → `AccessOps::write` + `AccessOps::update_metadata`
    ///   (writing object content implies writing user metadata)
    /// - `"admin"` → `AccessOps::delete` (the elevated permission the C++
    ///   client uses to gate destructive ops)
    ///
    /// Absent `acl` key or missing `metadata` user-metadata altogether →
    /// grant all ops. An `acl` value that is not a list grants nothing;
    /// unknown or non-string entries inside a list are ignored. The server
    /// is still the authoritative gate; `check_access` is a hint, and the
    /// actual RPC may return `PermissionDenied` even after an allowed
    /// decision.
    async fn fetch_acl_grants(&self, target: &ResolvedTarget) -> Result<AccessOps> {
        let mut client = self.transport.metadata_client().await?;
        let response = match client
            .get_metadata(md::GetMetadataRequest {
                uri: target.resolved_address.to_string(),
                user_metadata_keys: vec![ACL_METADATA_KEY.to_string()],
            })
            .await
        {
            Ok(resp) => resp,
            Err(status) if status.code() == tonic::Code::Unimplemented => {
                // Server has no metadata service; fall back to "grant all".
                return Ok(grant_all());
            }
            Err(status) => return Err(map_status(status)),
        };
        let map = response.into_inner().user_metadata;
        match map.get(ACL_METADATA_KEY) {
            Some(value) => Ok(parse_acl_grants(value)),
            None => Ok(grant_all()),
        }
    }

    async fn finalize_write_redirect(
        &self,
        target: ResolvedTarget,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        attested_modified_by: Option<&str>,
    ) -> Result<WriteStep> {
        validate_redirect_results(&redirects, &results)?;
        let mut continuation = Continuation::decode(&redirects.continuation)?;
        // The metadata service is addressed by the resource the commit creates,
        // so this metadata cannot be applied until then — it rides in the
        // continuation and comes back through the caller. Where a host
        // attribution layer asserted a writer identity for this request, it
        // replaces the reserved namespace in the copy that travelled. Applied
        // once here so both commit shapes stash the same map.
        ovstorage_plugin::reassert_attribution(
            attested_modified_by,
            &mut continuation.user_metadata,
        );
        // Derive the destination from the authorized request address rather
        // than reading it back out of a blob the remote caller echoes. The
        // metadata stash below already keys off this value, so the commit, the
        // abort and the stash now all name one object.
        let destination = target.resolved_address.to_string();
        let pending_message = continuation.message.clone();
        let pending_user_metadata = continuation.user_metadata.clone();
        let mut client = self.transport.fileobject_client().await?;
        match continuation.kind {
            ContinuationKind::SingleRedirect {
                completion_header_names,
            } => {
                let result = results.results.into_iter().next().ok_or_else(|| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "omniverse-storage-service: single-redirect continuation expected one result",
                    )
                })?;
                if !(200..300).contains(&result.status_code) {
                    return Err(map_redirect_status(result.status_code, 0));
                }
                let additional_headers =
                    extract_completion_headers(&completion_header_names, &result.captured_headers);
                let response = client
                    .complete_redirect_upload(fo::CompleteRedirectUploadRequest {
                        destination_resource_address: destination,
                        additional_headers,
                    })
                    .await
                    .map_err(map_status)?;
                let info = require_field(
                    response.into_inner().resource_info,
                    "complete_redirect_upload.resource_info",
                )?;
                let address_str = target.resolved_address.as_str().to_string();
                self.stash_message(&address_str, pending_message.as_deref())
                    .await;
                self.stash_user_metadata(&address_str, pending_user_metadata.as_ref())
                    .await?;
                Ok(WriteStep::Done(WriteResult {
                    info: object_info_from(target.resolved_address, &info),
                }))
            }
            ContinuationKind::Multipart {
                upload_id,
                total_parts,
            } => {
                let aborter = MultipartAborter {
                    transport: self.transport.clone(),
                    destination: destination.clone(),
                    upload_id: upload_id.clone(),
                    armed: true,
                };
                if results.results.len() as u32 != total_parts {
                    aborter.abort_now().await;
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "omniverse-storage-service: multipart continuation result count != redirect count",
                    ));
                }
                let mut parts = Vec::with_capacity(results.results.len());
                for (idx, result) in results.results.iter().enumerate() {
                    if !(200..300).contains(&result.status_code) {
                        aborter.abort_now().await;
                        return Err(map_redirect_status(result.status_code, idx));
                    }
                    parts.push(fo::CompletedUploadPart {
                        part_number: idx as u32,
                        headers: result
                            .captured_headers
                            .iter()
                            .map(|(name, value)| fo::Header {
                                name: name.clone(),
                                value: value.clone(),
                            })
                            .collect(),
                    });
                }
                let response = client
                    .complete_multipart_upload(fo::CompleteMultipartUploadRequest {
                        upload_id: upload_id.clone(),
                        destination_resource_address: destination,
                        parts,
                    })
                    .await;
                let response = match response {
                    Ok(response) => response,
                    Err(status) => {
                        aborter.abort_now().await;
                        return Err(map_status(status));
                    }
                };
                aborter.disarm();
                let info = require_field(
                    response.into_inner().resource_info,
                    "complete_multipart_upload.resource_info",
                )?;
                let address_str = target.resolved_address.as_str().to_string();
                self.stash_message(&address_str, pending_message.as_deref())
                    .await;
                self.stash_user_metadata(&address_str, pending_user_metadata.as_ref())
                    .await?;
                Ok(WriteStep::Done(WriteResult {
                    info: object_info_from(target.resolved_address, &info),
                }))
            }
        }
    }
}

// 4xx codes from the redirect upload are caller faults (auth, precondition,
// not-found); only 5xx / 408 / 429 are retryable. Mirrors
// `ovstorage-plugin-opendal::map_redirect_status`.
fn map_redirect_status(status: u16, index: usize) -> Error {
    if status == 401 {
        return Error::new(
            ErrorCode::AuthRequired,
            format!("omniverse-storage-service redirect upload #{index} returned HTTP 401"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("omniverse_storage_service_redirect_unauthorized".into()),
            expired_at: None,
        });
    }
    let code = match status {
        403 => ErrorCode::PermissionDenied,
        404 | 410 => ErrorCode::NotFound,
        408 => ErrorCode::Transient,
        409 => ErrorCode::Conflict,
        412 => ErrorCode::PreconditionFailed,
        416 => ErrorCode::InvalidArgument,
        429 => ErrorCode::ResourceExhausted,
        500..=599 => ErrorCode::Transient,
        _ => ErrorCode::Internal,
    };
    Error::new(
        code,
        format!("omniverse-storage-service redirect upload #{index} returned HTTP {status}"),
    )
}

fn single_redirect_batch(
    target: &ResolvedTarget,
    size: u64,
    message: Option<String>,
    user_metadata: Option<ovstorage_plugin::UserMetadata>,
    props: fo::WriteRedirectProperties,
) -> WriteRedirectBatch {
    let mut continuation = Continuation::single_redirect(
        target.resolved_address.to_string(),
        props.completion_header_names.clone(),
    );
    continuation.message = message;
    continuation.user_metadata = user_metadata.filter(|m| !m.is_empty());
    let redirect = redirect_from_props(target, size, &props);
    WriteRedirectBatch {
        continuation: continuation.encode(),
        redirects: vec![redirect],
    }
}

async fn multipart_redirect_batch(
    backend: &OmniverseStorageBackend,
    target: &ResolvedTarget,
    size: u64,
    message: Option<String>,
    user_metadata: Option<ovstorage_plugin::UserMetadata>,
    mp: fo::CreateMultipartUploadResponse,
) -> Result<WriteRedirectBatch> {
    let upload_id = mp.upload_id.clone();
    let aborter = MultipartAborter {
        transport: backend.transport.clone(),
        destination: target.resolved_address.to_string(),
        upload_id: upload_id.clone(),
        armed: true,
    };
    let result = async {
        let first_part = require_field(mp.first_part_write_redirect, "multipart.first_part")?;
        let total_parts = compute_total_parts(
            size,
            mp.minimum_size_per_part,
            mp.maximum_size_per_part,
            mp.maximum_parts_number,
        )?;
        let mut redirects = Vec::with_capacity(total_parts as usize);
        redirects.push(part_redirect(target, size, &first_part, 0, total_parts));
        if total_parts > 1 {
            let mut client = backend.transport.fileobject_client().await?;
            let response = client
                .upload_part(fo::UploadPartRequest {
                    upload_id: upload_id.clone(),
                    destination_resource_address: target.resolved_address.to_string(),
                    part_number: 1,
                    part_count: Some(total_parts - 1),
                })
                .await
                .map_err(map_status)?;
            for (offset, props) in response
                .into_inner()
                .part_write_redirects
                .into_iter()
                .enumerate()
            {
                let part_index = (offset + 1) as u32;
                redirects.push(part_redirect(target, size, &props, part_index, total_parts));
            }
        }
        if redirects.len() as u32 != total_parts {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: multipart UploadPart returned fewer redirects than requested",
            ));
        }
        let mut continuation =
            Continuation::multipart(target.resolved_address.to_string(), upload_id, total_parts);
        continuation.message = message;
        continuation.user_metadata = user_metadata.filter(|m| !m.is_empty());
        Ok(WriteRedirectBatch {
            continuation: continuation.encode(),
            redirects,
        })
    }
    .await;
    match result {
        Ok(batch) => {
            aborter.disarm();
            Ok(batch)
        }
        Err(err) => {
            aborter.abort_now().await;
            Err(err)
        }
    }
}

fn redirect_from_props(
    _target: &ResolvedTarget,
    size: u64,
    props: &fo::WriteRedirectProperties,
) -> WriteRedirect {
    let method =
        match fo::UploadMethod::try_from(props.method).unwrap_or(fo::UploadMethod::Unspecified) {
            fo::UploadMethod::Post => "POST",
            _ => "PUT",
        };
    WriteRedirect {
        request: HttpRequest {
            method: method.into(),
            url: props.redirect_target_url.clone(),
            headers: props
                .additional_headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
        },
        body_source: RedirectBodySource::UserBytes {
            offset: 0,
            len: size,
        },
        result_capture: ResultCapture {
            headers: props.completion_header_names.clone(),
            body_max_bytes: 0,
        },
        expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        scope: RedirectScope {
            physical_url_prefix: props.redirect_target_url.clone(),
            operations: AccessOps {
                write: true,
                ..Default::default()
            },
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
            // As on the read side: the upload headers came back from the
            // service, so their scope is not this plugin's to declare.
            credential: RedirectCredential::Unspecified,
        },
        audit_id: String::new(),
        policy_epoch: 0,
    }
}

/// Target per-part size when the server's constraints leave us
/// freedom to choose. Sits between common SDK defaults (AWS CLI
/// 8 MiB, aws-sdk-go 5 MiB) and AWS's "100 MB+ for large objects"
/// recommendation — balances per-RPC overhead against retry
/// granularity and parallelism on multi-GiB uploads.
const TARGET_PART_SIZE: u64 = 32 * 1024 * 1024;

/// Pick `total_parts` for a multipart upload of `size` bytes given
/// the server's optional constraints. Each resulting part (computed
/// later by [`part_redirect`]) must satisfy:
///
/// - sum of parts = `size` (covers the upload),
/// - per-part size `>= min` and `<= max` (where set),
/// - `total_parts <= max_parts` (where set).
///
/// Strategy: aim for parts of [`TARGET_PART_SIZE`] (clamped into the
/// server's [min, max] window), then clamp the part count into
/// [`min_parts_for_max_size`, `max_parts_allowed`] so we never
/// violate the server's caps. This avoids two anti-patterns:
/// "1 huge part" (when max is huge — bad for parallelism / retry)
/// and "many tiny parts at min" (when min is tiny — too much RPC
/// overhead on big uploads). For tight ranges like
/// `min=5, max=6`, the clamps dominate and total falls out of the
/// hard constraints (the `size=16, min=5, max=6` case, parts 6/5/5).
///
/// Inconsistent server constraints (e.g. `min > max`, or
/// `max_size * max_parts < size`) surface as `Internal` — the
/// server-issued multipart contract was unsatisfiable.
///
/// All four constraint inputs honor the proto's `optional` semantics:
/// `None` or `Some(0)` means "unconstrained".
fn compute_total_parts(
    size: u64,
    min_size_per_part: Option<u64>,
    max_size_per_part: Option<u64>,
    max_parts_number: Option<u32>,
) -> Result<u32> {
    let min = min_size_per_part.filter(|v| *v > 0);
    let max = max_size_per_part.filter(|v| *v > 0);
    let max_parts = max_parts_number.filter(|v| *v > 0);

    // Hard lower bound: enough parts so no single part exceeds max.
    let min_parts_for_max_size = match max {
        Some(max) => size.div_ceil(max).max(1),
        None => 1,
    };
    // Hard upper bound: enough headroom so every part is >= min (floor).
    let max_parts_for_min_size = match min {
        Some(min) => size / min,
        None => u64::MAX,
    };
    let max_parts_for_count = max_parts.map(u64::from).unwrap_or(u64::MAX);
    let max_parts_allowed = max_parts_for_min_size.min(max_parts_for_count);

    if min_parts_for_max_size == 0 || min_parts_for_max_size > max_parts_allowed {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "omniverse-storage-service: server's multipart constraints unsatisfiable for \
                 size={size} (min_size={min:?}, max_size={max:?}, max_parts={max_parts:?})",
            ),
        ));
    }

    // Pick a target per-part size inside the server's window, then
    // a target part count from it. The clamps below pull the count
    // back into the hard feasibility range when the target lands
    // outside (e.g. for tight `[min, max]` windows, the clamps
    // dominate and we converge on the same total a naive
    // smallest-count algorithm would have picked).
    let target_part_size = TARGET_PART_SIZE
        .max(min.unwrap_or(1))
        .min(max.unwrap_or(u64::MAX));
    let target_total = size.div_ceil(target_part_size).max(1);
    let total = target_total
        .max(min_parts_for_max_size)
        .min(max_parts_allowed);

    // The returned value fits in u32 iff `max_parts_for_count` is
    // u32-bounded (always — it's derived from a u32 proto field).
    // The only path that can produce an oversized value is when
    // `max_size` is set, `max_parts` is unset, and the upload is
    // huge (e.g. size=u64::MAX with max=1). Guard explicitly
    // rather than truncating silently on the `as u32`.
    if total > u32::MAX as u64 {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "omniverse-storage-service: server's multipart constraints would require more \
                 than u32::MAX parts for size={size} max_size={max:?}; cannot represent on the wire",
            ),
        ));
    }
    Ok(total as u32)
}

fn part_redirect(
    target: &ResolvedTarget,
    size: u64,
    props: &fo::WriteRedirectProperties,
    part_index: u32,
    total_parts: u32,
) -> WriteRedirect {
    let total = total_parts as u64;
    let base = size / total;
    let remainder = size % total;
    // Balanced split: distribute the remainder as +1 across the
    // first `remainder` parts, so every part is `base` or
    // `base + 1`. The naive "ceil(size / total) for all but last,
    // last = whatever remains" approach leaves the last part
    // potentially below `minimum_size_per_part` even when
    // compute_total_parts picked a viable `total`. Example:
    // size=16, min=5, max=6 → total=3; ceil(16/3)=6 gives 6/6/4,
    // but the balanced split 6/5/5 keeps every part in [5,6].
    let idx = part_index as u64;
    let (offset, len) = if idx < remainder {
        ((base + 1) * idx, base + 1)
    } else {
        ((base + 1) * remainder + base * (idx - remainder), base)
    };
    let mut redirect = redirect_from_props(target, size, props);
    redirect.body_source = RedirectBodySource::UserBytes { offset, len };
    redirect
}

fn extract_completion_headers(names: &[String], captured: &[(String, String)]) -> Vec<fo::Header> {
    if names.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for name in names {
        let lc = name.to_ascii_lowercase();
        if let Some((_, value)) = captured
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&lc) || k.eq_ignore_ascii_case(name))
        {
            out.push(fo::Header {
                name: name.clone(),
                value: value.clone(),
            });
        }
    }
    out
}

async fn preferred_upload_method(
    client: &mut crate::transport::FileObject,
    target: &ResolvedTarget,
    size: u64,
) -> Result<fo::UploadPreference> {
    let response = client
        .fetch_write_type_info(fo::FetchWriteTypeInfoRequest {
            destination_resource_address: target.resolved_address.to_string(),
        })
        .await
        .map_err(map_status)?;
    let intervals = response.into_inner().write_type_intervals;
    for iv in &intervals {
        if size >= iv.minimum_data_object_size && size < iv.maximum_data_object_size {
            return Ok(fo::UploadPreference::try_from(iv.preferred_upload_method)
                .unwrap_or(fo::UploadPreference::Unspecified));
        }
    }
    Ok(fo::UploadPreference::Redirect)
}

async fn body_to_chunk_stream(
    body: Body,
    size_hint: Option<u64>,
) -> Result<(
    u64,
    Pin<Box<dyn Stream<Item = Result<fo::WriteRequest>> + Send>>,
)> {
    match body {
        Body::Bytes(bytes) => {
            let size = bytes.len() as u64;
            let chunks = chunk_bytes_into_requests(bytes);
            Ok((size, futures::stream::iter(chunks).boxed()))
        }
        Body::LocalFile(path) => {
            // Probe size up front so the WriteParameters carries an
            // accurate `data_object_size` (the server uses it to pick
            // inline vs. multipart). Falls back to size_hint, then 0.
            let size = match tokio::fs::metadata(&path).await {
                Ok(meta) => meta.len(),
                Err(_) => size_hint.unwrap_or(0),
            };
            let file = tokio::fs::File::open(&path).await.map_err(|err| {
                Error::new(
                    ErrorCode::NotFound,
                    format!(
                        "omniverse-storage-service: open {} failed: {err}",
                        path.display()
                    ),
                )
            })?;
            let reader = tokio_util::io::ReaderStream::with_capacity(file, WRITE_CHUNK_SIZE);
            let request_stream = reader.map(|item| match item {
                Ok(chunk) => Ok(fo::WriteRequest {
                    write_request_type: Some(fo::write_request::WriteRequestType::Chunk(
                        fo::Chunk { chunk },
                    )),
                }),
                Err(err) => Err(Error::new(
                    ErrorCode::Transient,
                    format!("omniverse-storage-service: LocalFile read error: {err}"),
                )),
            });
            Ok((size, request_stream.boxed()))
        }
        Body::Stream(stream) => {
            let known_size = size_hint.unwrap_or(0);
            let stream = body_stream_to_request_stream(stream);
            Ok((known_size, stream))
        }
    }
}

fn chunk_bytes_into_requests(bytes: Vec<u8>) -> Vec<Result<fo::WriteRequest>> {
    if bytes.is_empty() {
        return vec![Ok(fo::WriteRequest {
            write_request_type: Some(fo::write_request::WriteRequestType::Chunk(fo::Chunk {
                chunk: Bytes::new(),
            })),
        })];
    }
    bytes
        .chunks(WRITE_CHUNK_SIZE)
        .map(|slice| {
            Ok(fo::WriteRequest {
                write_request_type: Some(fo::write_request::WriteRequestType::Chunk(fo::Chunk {
                    chunk: Bytes::copy_from_slice(slice),
                })),
            })
        })
        .collect()
}

/// Bridge a sync `BodyStream` into an async `Stream` of `WriteRequest`. The
/// iterator runs on a blocking-friendly task; chunks are forwarded one at a
/// time so peak in-flight memory stays bounded by the channel capacity.
fn body_stream_to_request_stream(
    body: BodyStream,
) -> Pin<Box<dyn Stream<Item = Result<fo::WriteRequest>> + Send>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<fo::WriteRequest>>(2);
    // BodyStream::next_chunk re-enters tokio via the host's FFI callback
    // (LoadedBackend::run_ffi). spawn_blocking workers inherit the calling
    // runtime context and would deadlock when the callback drives async I/O.
    // A vanilla OS thread severs that context.
    std::thread::Builder::new()
        .name("ovs-oms-body".into())
        .spawn(move || {
            let mut iter = body;
            while let Some(item) = iter.next_chunk() {
                let msg = match item {
                    Ok(bytes) => Ok(fo::WriteRequest {
                        write_request_type: Some(fo::write_request::WriteRequestType::Chunk(
                            fo::Chunk {
                                chunk: Bytes::from(bytes),
                            },
                        )),
                    }),
                    Err(err) => Err(err),
                };
                if tx.blocking_send(msg).is_err() {
                    break;
                }
            }
        })
        .expect("ovs-oms-body thread spawn");
    ReceiverStream::new(rx).boxed()
}

/// Build the bidirectional WriteRequest stream that gets handed to
/// `FileObjectService::write`. The chunk source can fail mid-stream
/// (a `LocalFile` read error, a `BodyStream::next_chunk` error).
/// gRPC client streams have no Err variant, so we forward the first
/// source error through a oneshot channel and end the stream. The
/// caller races that receiver against the server response so it
/// never silently reports success on a partial upload.
fn build_write_request_stream(
    params: fo::WriteRequest,
    chunk_stream: Pin<Box<dyn Stream<Item = Result<fo::WriteRequest>> + Send>>,
) -> (
    impl Stream<Item = fo::WriteRequest> + Send,
    tokio::sync::oneshot::Receiver<Error>,
) {
    let (err_tx, err_rx) = tokio::sync::oneshot::channel::<Error>();
    // Box-pin the combined stream so `StreamExt::next` (which requires
    // `Self: Unpin`) can be called inside the unfold closure — the
    // `Once<async block>` half isn't Unpin on its own.
    let combined: Pin<Box<dyn Stream<Item = Result<fo::WriteRequest>> + Send>> =
        futures::stream::once(async move { Ok::<fo::WriteRequest, Error>(params) })
            .chain(chunk_stream)
            .boxed();
    let stream = futures::stream::unfold(
        (combined, Some(err_tx)),
        |(mut inner, mut err_tx)| async move {
            match inner.next().await {
                None => None,
                Some(Ok(req)) => Some((req, (inner, err_tx))),
                Some(Err(err)) => {
                    if let Some(tx) = err_tx.take() {
                        let _ = tx.send(err);
                    }
                    None
                }
            }
        },
    );
    (stream, err_rx)
}

#[cfg(test)]
mod latest_version_tests {
    //! `get_latest_version` has ONE answer, so it must not substitute another.
    //!
    //! The listing paths drop an entry whose address does not survive
    //! canonicalization and warn, because the caller still sees the rest of the
    //! page. Applying that policy here selected the newest *addressable*
    //! version instead of the newest one — the caller asked which version is
    //! latest and would be handed older bytes with nothing saying so.
    use super::*;

    /// An address that `parse_server_address` refuses: the empty segment does
    /// not survive canonicalization, so it names a different object.
    const UNADDRESSABLE: &str = "omniverse://server/team//report.usd";
    const GOOD: &str = "omniverse://server/team/report.usd";
    /// A second addressable version, so a multi-frame row can tell WHICH
    /// entry won rather than only that one did.
    const OTHER: &str = "omniverse://server/team/report.usd?versionId=2";

    fn version(address: &str, key: Option<&str>) -> ver::VersionInfo {
        ver::VersionInfo {
            resource_address: Some(address.to_string()),
            sorting_key: key.map(str::to_string),
            resource_info: None,
        }
    }

    fn frame(
        order: ver::VersionsOrder,
        items: Vec<ver::VersionInfo>,
    ) -> ver::EnumerateVersionsResponse {
        ver::EnumerateVersionsResponse {
            versions_order: order as i32,
            items,
        }
    }

    /// The premise: the fixture address really is one the parser refuses.
    #[test]
    fn the_unaddressable_fixture_is_refused() {
        parse_server_address(UNADDRESSABLE, "fixture")
            .expect_err("the fixture must be unaddressable, or every row below proves nothing");
        parse_server_address(GOOD, "fixture").expect("and the good one must be addressable");
    }

    #[test]
    fn newest_first_does_not_fall_through_to_the_second_entry() {
        let mut picker = LatestVersionPicker::new();
        picker
            .observe_frame(frame(
                ver::VersionsOrder::NewestFirst,
                vec![version(UNADDRESSABLE, None), version(GOOD, None)],
            ))
            .unwrap();
        picker
            .finish()
            .expect_err("the newest version is unusable; the second is not an answer");
    }

    #[test]
    fn oldest_first_takes_the_last_entry_not_the_last_usable_one() {
        let mut picker = LatestVersionPicker::new();
        picker
            .observe_frame(frame(
                ver::VersionsOrder::OldestFirst,
                vec![version(GOOD, None), version(UNADDRESSABLE, None)],
            ))
            .unwrap();
        picker
            .finish()
            .expect_err("the last entry is the latest, and it is unusable");
    }

    #[test]
    fn by_key_does_not_leave_a_lower_keyed_selection_in_place() {
        let mut picker = LatestVersionPicker::new();
        picker
            .observe_frame(frame(
                ver::VersionsOrder::ByKey,
                vec![
                    version(GOOD, Some("2026-01-01")),
                    version(UNADDRESSABLE, Some("2026-06-01")),
                ],
            ))
            .unwrap();
        picker
            .finish()
            .expect_err("the greatest sorting_key wins, and it is unusable");
    }

    /// Across FRAMES, not just within one — the property every test above
    /// takes on trust, because each of them calls `observe_frame` once.
    ///
    /// Each row names the mutation it exists to catch, and each was confirmed
    /// to redden this test and leave the single-frame rows green:
    ///
    /// - `NewestFirst` — deleting `self.selected.is_none() &&` makes the last
    ///   frame's first item win, i.e. an OLDER version, silently.
    /// - `OldestFirst` with an empty trailing frame — assigning
    ///   unconditionally (dropping the `if let Some`) clears the selection and
    ///   answers `NotFound` for a stream that has an answer.
    /// - `ByKey` split across frames — clearing `self.selected` per frame
    ///   answers with the greatest key of the LAST frame rather than of the
    ///   stream.
    #[test]
    fn selection_carries_across_frames() {
        for (order, frames, expected) in [
            (
                ver::VersionsOrder::NewestFirst,
                vec![vec![version(GOOD, None)], vec![version(OTHER, None)]],
                GOOD,
            ),
            (
                ver::VersionsOrder::OldestFirst,
                vec![vec![version(GOOD, None)], vec![]],
                GOOD,
            ),
            (
                ver::VersionsOrder::ByKey,
                vec![
                    vec![version(GOOD, Some("2026-06-01"))],
                    vec![version(OTHER, Some("2026-01-01"))],
                ],
                GOOD,
            ),
        ] {
            let mut picker = LatestVersionPicker::new();
            let mut short_circuited = false;
            for items in frames {
                short_circuited |= picker.observe_frame(frame(order, items)).unwrap();
            }
            // `observe_frame` returns "stop reading" so the caller can end the
            // stream early, and only `NewestFirst` can know after one frame.
            // Without this the return value is unasserted and could be
            // hard-wired to `false` with every row still green.
            assert_eq!(
                short_circuited,
                order == ver::VersionsOrder::NewestFirst,
                "{order:?} short-circuit"
            );
            let info = picker
                .finish()
                .unwrap_or_else(|e| panic!("{order:?} must answer: {}", e.message()));
            assert_eq!(info.address.as_str(), expected, "{order:?}");
        }
    }

    /// A server address the URL parser rewrites is refused here too, and by
    /// the parse-step check rather than by `canonicalize_preserves_node`:
    /// `omni://server/public/../private/secret` arrives already flattened and
    /// is a fixed point of everything the parsed form can be asked.
    ///
    /// The load-bearing line is the `parsing_preserves_node(raw)` call in
    /// `parse_server_address`; deleting it turns this test red.
    #[test]
    fn a_server_address_the_parser_rewrites_is_refused() {
        parse_server_address("omni://server/public/../private/secret", "fixture")
            .expect_err("a spelling the parser resolves elsewhere is refused");
        // And the honest spelling of the same object still parses, or the
        // refusal would have cost a working listing.
        parse_server_address("omni://server/private/secret", "fixture")
            .expect("the node it resolves to is an ordinary address");
    }

    /// An authority-less address is refused here, and this is the rule the
    /// discovered-roots filter depends on.
    ///
    /// Neither `parsing_preserves_node` nor `canonicalize_preserves_node`
    /// rejects this class on its own — the first answers the unlocatable-path
    /// arm by byte identity and `omni:team-share` is its own serialization, the
    /// second returns `true` unconditionally for it. Only the
    /// `cannot_be_a_base()` clause in this function does, which is why
    /// `factory::list_top_level_addresses` calls THIS function rather than the
    /// two predicates: a root it admitted and the watcher's copy refused would
    /// be installed at bring-up and vanish on the first `Snapshot`.
    ///
    /// Load-bearing line: the `url.cannot_be_a_base()` in the refusal. Deleting
    /// it turns this test red and leaves the sibling rows green.
    #[test]
    fn an_authority_less_server_address_is_refused() {
        for raw in ["omni:team-share", "omni:reader@server/team"] {
            let error = parse_server_address(raw, "fixture")
                .expect_err("an address no request can ever match is refused");
            assert_eq!(error.code(), ErrorCode::Internal, "{raw}");
        }
        parse_server_address("omni://server/team", "fixture")
            .expect("the authority-bearing spelling is an ordinary address");
    }

    /// The honest cases, because a refusal that also refuses ordinary answers
    /// is worse than the substitution it replaces.
    #[test]
    fn an_addressable_winner_is_returned_under_every_order() {
        for (order, items, expected) in [
            (
                ver::VersionsOrder::NewestFirst,
                vec![version(GOOD, None), version(UNADDRESSABLE, None)],
                GOOD,
            ),
            (
                ver::VersionsOrder::OldestFirst,
                vec![version(UNADDRESSABLE, None), version(GOOD, None)],
                GOOD,
            ),
            (
                ver::VersionsOrder::ByKey,
                vec![
                    version(UNADDRESSABLE, Some("2026-01-01")),
                    version(GOOD, Some("2026-06-01")),
                ],
                GOOD,
            ),
        ] {
            let mut picker = LatestVersionPicker::new();
            picker.observe_frame(frame(order, items)).unwrap();
            let info = picker
                .finish()
                .unwrap_or_else(|e| panic!("{order:?} must answer: {}", e.message()));
            assert_eq!(info.address.as_str(), expected, "{order:?}");
        }
    }
}

#[cfg(test)]
mod acl_tests {
    use super::*;
    use ovstorage_services_protos::google::protobuf::{ListValue, Value, value::Kind};

    fn list_value(strings: &[&str]) -> md::UserMetadataValue {
        let values: Vec<Value> = strings
            .iter()
            .map(|s| Value {
                kind: Some(Kind::StringValue((*s).into())),
            })
            .collect();
        md::UserMetadataValue {
            value: Some(Value {
                kind: Some(Kind::ListValue(ListValue { values })),
            }),
            etag: String::new(),
        }
    }

    #[test]
    fn read_only_grants_read() {
        let g = parse_acl_grants(&list_value(&["read"]));
        assert_eq!(
            g,
            AccessOps {
                read: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn write_grants_write_and_update_metadata() {
        let g = parse_acl_grants(&list_value(&["write"]));
        assert_eq!(
            g,
            AccessOps {
                write: true,
                update_metadata: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn admin_grants_delete() {
        let g = parse_acl_grants(&list_value(&["admin"]));
        assert_eq!(
            g,
            AccessOps {
                delete: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn full_acl_grants_everything() {
        let g = parse_acl_grants(&list_value(&["read", "write", "admin"]));
        assert_eq!(g, grant_all());
    }

    #[test]
    fn unknown_tokens_are_ignored() {
        let g = parse_acl_grants(&list_value(&["banana", "read", "moderator"]));
        assert_eq!(
            g,
            AccessOps {
                read: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn malformed_value_grants_nothing() {
        let bad = md::UserMetadataValue {
            value: Some(Value {
                kind: Some(Kind::StringValue("not-a-list".into())),
            }),
            etag: String::new(),
        };
        assert_eq!(parse_acl_grants(&bad), AccessOps::default());
    }
}

/// Storage-core publishes folder mutations under these event-type names.
/// Mirrors `provider_omnistorage` `StorageProvider.cpp:3175-3180`.
const WATCH_EVENT_TYPES: &[&str] = &[
    "omni.storage.created",
    "omni.storage.deleted",
    "omni.storage.dir_created",
    "omni.storage.dir_deleted",
];

fn build_watch_filter_groups(prefix: &str, recursive: bool) -> Vec<notif::FilterGroup> {
    let filter_type = if recursive {
        notif::resource_filter::FilterType::StartsWithGreedy
    } else {
        notif::resource_filter::FilterType::StartsWithLazy
    } as i32;
    WATCH_EVENT_TYPES
        .iter()
        .map(|event_type| notif::FilterGroup {
            event_type: (*event_type).to_string(),
            filters: vec![notif::ResourceFilter {
                filter_type,
                resource_id: prefix.to_string(),
            }],
        })
        .collect()
}

/// Bridge the async ConsumeNonDurableEvents stream into the SPI's sync
/// iterator-shaped `BackendChangeStream`. Mirrors the broker plugin's
/// `auth.rs::drive_upstream_auth` pattern: dedicated thread + per-bridge
/// tokio runtime + std::sync::mpsc, no buffering.
fn spawn_watch_bridge(
    prefix: Url,
    mut server_stream: tonic::Streaming<notif::ConsumeNonDurableEventsResponse>,
) -> BackendChangeStream {
    let (sender, receiver) = std::sync::mpsc::channel::<Result<BackendChangeEvent>>();
    std::thread::Builder::new()
        .name("ovs-oms-watch".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = sender.send(Err(Error::new(
                        ErrorCode::Internal,
                        format!("omniverse-storage-service: watch_directory runtime: {err}"),
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                loop {
                    let frame = match server_stream.message().await {
                        Ok(Some(frame)) => frame,
                        Ok(None) => return, // Stream closed cleanly.
                        Err(status) => {
                            let _ = sender.send(Err(map_status(status)));
                            return;
                        }
                    };
                    let cursor = WatchDirectoryCursor(frame.reconnect_token.into_bytes());
                    for event in frame.events {
                        match convert_notification_event(&prefix, event, &cursor) {
                            Ok(Some(change)) => {
                                if sender.send(Ok(change)).is_err() {
                                    return;
                                }
                            }
                            Ok(None) => {}
                            Err(err) => {
                                let _ = sender.send(Err(err));
                                return;
                            }
                        }
                    }
                }
            });
        })
        .expect("failed to spawn thread");
    Box::new(receiver.into_iter())
}

fn convert_notification_event(
    prefix: &Url,
    event: notif::Event,
    cursor: &WatchDirectoryCursor,
) -> Result<Option<BackendChangeEvent>> {
    let kind = match event.event_type.as_str() {
        "omni.storage.created" | "omni.storage.dir_created" => ChangeKind::Created,
        "omni.storage.deleted" | "omni.storage.dir_deleted" => ChangeKind::Deleted,
        _ => return Ok(None),
    };
    let resource_address = event_resource_address(&event).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service watch event missing resource_address",
        )
    })?;
    // Normalize before the containment check below: the prefix is canonical, so
    // comparing a raw server address against it drops legitimate events as
    // out-of-prefix.
    //
    // One unaddressable path must not end the stream: the caller of this
    // function sends the error and returns, so propagating here would lose every
    // later event for every other path with it. Skip the event instead, which is
    // what the nucleus, azure, s3 and gcs watchers do for the same input.
    let address = match parse_server_address(&resource_address, "watch event resource_address") {
        Ok(address) => address,
        Err(error) => {
            tracing::warn!(
                target: "ovstorage::services_client",
                address = %redacted_address(&resource_address),
                reason = %error.message(),
                "omniverse-storage-service: watch event resource_address is not addressable; \
                 event skipped",
            );
            return Ok(None);
        }
    };
    ovstorage_plugin::address::relative_suffix(&address, prefix).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            // Both sides are rendered redacted: the address is server-supplied
            // and the prefix is the caller's watched root, so either may carry
            // userinfo or a signed query, and the two paths are what this
            // message is contrasting.
            format!(
                "omniverse-storage-service watch event address {} is outside watched prefix {}",
                RedactedUrl(&address),
                RedactedUrl(prefix)
            ),
        )
    })?;
    let at = event
        .occurred_at
        .as_ref()
        .and_then(crate::convert::timestamp_to_system_time)
        .unwrap_or_else(std::time::SystemTime::now);
    // the Notifications API `EventConsumerService` notification carries `event_type`,
    // `principal_identity`, `occurred_at`/`published_at`, and a generic
    // `message: google.protobuf.Struct` whose only consumed field today is
    // `resource_address`. The notification surface does not publish an
    // object etag, resource_identity, size, or object mtime alongside the
    // event, so those descriptive fields stay `None` until the Storage API wire
    // adds them.
    Ok(Some(BackendChangeEvent::Object {
        address,
        kind,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        at,
        cursor: cursor.clone(),
    }))
}

fn event_resource_address(event: &notif::Event) -> Option<String> {
    use ovstorage_services_protos::google::protobuf::value::Kind;
    let message = event.message.as_ref()?;
    let value = message.fields.get("resource_address")?;
    match value.kind.as_ref()? {
        Kind::StringValue(s) => Some(s.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;
    use ovstorage_services_protos::google::protobuf::{Struct, Value, value::Kind};

    fn make_event(event_type: &str, resource_address: &str) -> notif::Event {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "resource_address".to_string(),
            Value {
                kind: Some(Kind::StringValue(resource_address.into())),
            },
        );
        notif::Event {
            event_type: event_type.into(),
            principal_identity: String::new(),
            occurred_at: None,
            published_at: None,
            message: Some(Struct {
                fields: fields.into_iter().collect(),
            }),
        }
    }

    #[test]
    fn maps_created_event_and_strips_prefix() {
        let cursor = WatchDirectoryCursor(b"tok".to_vec());
        let evt = convert_notification_event(
            &Url::parse("omni://server/folder/").unwrap(),
            make_event("omni.storage.created", "omni://server/folder/file.usd"),
            &cursor,
        )
        .unwrap()
        .expect("event present");
        match evt {
            BackendChangeEvent::Object {
                address,
                kind,
                cursor: c,
                ..
            } => {
                assert_eq!(address.as_str(), "omni://server/folder/file.usd");
                assert!(matches!(kind, ChangeKind::Created));
                assert_eq!(c.0, b"tok");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn maps_dir_deleted_event() {
        let cursor = WatchDirectoryCursor(Vec::new());
        let evt = convert_notification_event(
            &Url::parse("omni://server/folder/").unwrap(),
            make_event("omni.storage.dir_deleted", "omni://server/folder/sub"),
            &cursor,
        )
        .unwrap()
        .expect("event present");
        match evt {
            BackendChangeEvent::Object { kind, .. } => {
                assert!(matches!(kind, ChangeKind::Deleted));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn ignores_unknown_event_type() {
        let cursor = WatchDirectoryCursor(Vec::new());
        let evt = convert_notification_event(
            &Url::parse("omni://server/folder/").unwrap(),
            make_event("omni.other.event", "omni://server/folder/x"),
            &cursor,
        )
        .unwrap();
        assert!(evt.is_none());
    }

    #[test]
    fn errors_on_event_without_resource_address() {
        let cursor = WatchDirectoryCursor(Vec::new());
        let event = notif::Event {
            event_type: "omni.storage.created".into(),
            principal_identity: String::new(),
            occurred_at: None,
            published_at: None,
            message: None,
        };
        let err =
            convert_notification_event(&Url::parse("omni://server/").unwrap(), event, &cursor)
                .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[test]
    fn errors_on_event_outside_watched_prefix() {
        let cursor = WatchDirectoryCursor(Vec::new());
        let err = convert_notification_event(
            &Url::parse("omni://server/folder/").unwrap(),
            make_event("omni.storage.created", "omni://server/other/file.usd"),
            &cursor,
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
    }
}

/// RAII abort guard for in-flight multipart uploads.
struct MultipartAborter {
    transport: OmniverseStorageTransport,
    destination: String,
    upload_id: String,
    armed: bool,
}

impl MultipartAborter {
    fn disarm(mut self) {
        self.armed = false;
    }

    async fn abort_now(self) {
        let mut this = self;
        if !this.armed {
            return;
        }
        this.armed = false;
        // Disarming happens before the RPC, so `Drop` will not warn for us and
        // a discarded failure here would be the last chance to see the orphan.
        // The upload id comes from the continuation while the destination is
        // derived from the authorized address, so a service that binds the two
        // rejects an abort whose continuation was minted for another object.
        let upload_id = std::mem::take(&mut this.upload_id);
        match this.transport.fileobject_client().await {
            Ok(mut client) => {
                if let Err(status) = client
                    .abort_multipart_upload(fo::AbortMultipartUploadRequest {
                        upload_id: upload_id.clone(),
                        destination_resource_address: std::mem::take(&mut this.destination),
                    })
                    .await
                {
                    tracing::warn!(
                        target: "ovstorage.omniverse_storage_service.write_redirect",
                        upload_id = %UploadIdPrefix(&upload_id),
                        code = ?status.code(),
                        "omniverse-storage-service: AbortMultipartUpload failed; \
                         server-side garbage collection should reclaim parts"
                    );
                }
            }
            Err(err) => tracing::warn!(
                target: "ovstorage.omniverse_storage_service.write_redirect",
                upload_id = %UploadIdPrefix(&upload_id),
                error = %err,
                "omniverse-storage-service: could not reach the service to abort a \
                 multipart upload; server-side garbage collection should reclaim parts"
            ),
        }
    }
}

/// Bounds a caller-supplied upload id before it reaches a log field. On the
/// broker's client-driven route the id comes out of the echoed continuation,
/// whose only integrity check is a plugin-kind tag, so an unbounded copy would
/// let a caller choose how *large* a WARN record it can trigger. A prefix is
/// enough to correlate with the service's own records. Note what this does not
/// do: the retained prefix is still caller-chosen, so treat it as untrusted
/// text in any log consumer that interprets escape sequences.
struct UploadIdPrefix<'a>(&'a str);

impl std::fmt::Display for UploadIdPrefix<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const KEEP: usize = 24;
        match self.0.char_indices().nth(KEEP) {
            Some((cut, _)) => write!(f, "{}…", &self.0[..cut]),
            None => f.write_str(self.0),
        }
    }
}

impl Drop for MultipartAborter {
    fn drop(&mut self) {
        // Sync drop can't issue an async abort. The on-success path calls
        // `disarm()`; on-error paths above call `abort_now().await` before
        // dropping. If we hit Drop while still armed (panic, early return
        // we missed), log so the orphan upload is visible.
        if self.armed {
            tracing::warn!(
                target: "ovstorage.omniverse_storage_service.write_redirect",
                upload_id = %UploadIdPrefix(&self.upload_id),
                "omniverse-storage-service: multipart aborter dropped while armed; \
                 server-side garbage collection should reclaim parts"
            );
        }
    }
}

#[cfg(test)]
mod multipart_sizing_tests {
    use super::*;

    /// Mirror `part_redirect`'s balanced split rule so the
    /// assertions match what the host would actually send on the
    /// wire. Distribute the remainder as +1 across the first parts
    /// — `[base+1, base+1, ..., base, base]`.
    fn part_sizes(size: u64, total_parts: u32) -> Vec<u64> {
        let total = total_parts as u64;
        let base = size / total;
        let remainder = size % total;
        (0..total_parts)
            .map(|i| {
                if (i as u64) < remainder {
                    base + 1
                } else {
                    base
                }
            })
            .collect()
    }

    /// Reviewer's concrete case: 11-byte upload with `min=5`, no
    /// other constraints. A naive `total_parts = ceil(11/5) = 3` would
    /// make `part_redirect` produce 4/4/3 — the last part
    /// violates `min`. The right answer is a single 11-byte part
    /// (or 6/5); pick the smallest viable count to minimize
    /// per-part overhead.
    #[test]
    fn min_only_size_11_min_5_picks_single_part() {
        let total = compute_total_parts(11, Some(5), None, None).expect("constraints satisfiable");
        assert_eq!(total, 1);
        let parts = part_sizes(11, total);
        assert_eq!(parts, vec![11]);
        assert!(
            parts.iter().all(|&p| p >= 5),
            "every part must be >= min=5; got {parts:?}",
        );
    }

    /// `max_parts_number` on its own must not force a split. With
    /// no other constraints, a single part is fine.
    #[test]
    fn max_parts_only_picks_single_part_when_no_size_constraint() {
        let total = compute_total_parts(11, None, None, Some(4)).expect("constraints satisfiable");
        assert_eq!(total, 1);
    }

    /// `max_parts_number` actively constrains: 11 bytes, max=3,
    /// max_parts=2 → we'd want 4 parts to fit under max=3, but
    /// max_parts=2 says we can only have 2 parts. Constraints are
    /// jointly unsatisfiable (no way to have 2 parts of size <=3
    /// covering 11 bytes); fail loudly.
    #[test]
    fn unsatisfiable_constraints_error() {
        let err = compute_total_parts(11, None, Some(3), Some(2))
            .expect_err("max=3, max_parts=2 can't cover 11 bytes");
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    /// `min=max` doesn't divide evenly: 11 bytes, min=max=5 →
    /// ceil(11/5)=3 parts of <=5, but floor(11/5)=2 parts of >=5;
    /// unsatisfiable.
    #[test]
    fn min_equal_max_non_multiple_errors() {
        let err = compute_total_parts(11, Some(5), Some(5), None)
            .expect_err("size=11, min=max=5 is unsatisfiable");
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    /// All three constraints in harmony: 11 bytes, min=5, max=10,
    /// max_parts=2. Both bounds agree on 2 parts (6, 5).
    #[test]
    fn all_three_constraints_pick_two_parts() {
        let total =
            compute_total_parts(11, Some(5), Some(10), Some(2)).expect("constraints satisfiable");
        assert_eq!(total, 2);
        let parts = part_sizes(11, total);
        assert_eq!(parts, vec![6, 5]);
        assert!(parts.iter().all(|&p| (5..=10).contains(&p)));
    }

    /// Existing-shape regression: 2 MiB upload, min=1, max=1 MiB,
    /// max_parts=2 (the test mock's hardcoded values). Expect 2
    /// equal 1 MiB parts.
    #[test]
    fn existing_two_mib_two_parts_matches_prior_behavior() {
        let size = 2 * 1024 * 1024;
        let total = compute_total_parts(size, Some(1), Some(1024 * 1024), Some(2))
            .expect("constraints satisfiable");
        assert_eq!(total, 2);
        let parts = part_sizes(size, total);
        assert_eq!(parts, vec![1024 * 1024, 1024 * 1024]);
    }

    /// `Some(0)` is treated as "unconstrained" — matches the proto's
    /// optional-but-uint convention.
    #[test]
    fn zero_constraint_is_unconstrained() {
        let total =
            compute_total_parts(11, Some(0), Some(0), Some(0)).expect("zero means unconstrained");
        assert_eq!(total, 1);
    }

    /// No constraints at all → single-part upload.
    #[test]
    fn no_constraints_picks_single_part() {
        let total = compute_total_parts(11, None, None, None).expect("unconstrained");
        assert_eq!(total, 1);
    }

    /// Small object with max_size present: 100 bytes, min=10, max=40,
    /// max_parts=3. min_parts_by_size = ceil(100/40)=3, max_parts=3.
    /// total=3 → 100/3 = 33 with remainder 1, so parts of 34, 33, 33,
    /// all in [10,40].
    #[test]
    fn medium_object_three_parts_all_in_range() {
        let total =
            compute_total_parts(100, Some(10), Some(40), Some(3)).expect("constraints satisfiable");
        assert_eq!(total, 3);
        let parts = part_sizes(100, total);
        assert_eq!(parts, vec![34, 33, 33]);
        assert!(parts.iter().all(|&p| (10..=40).contains(&p)));
    }

    /// size=16, min=5, max=6 forces total=3, but ceil(16/3)=6 leaves
    /// the last part at 4 (below min). The balanced split 6/5/5 stays
    /// within [5,6].
    #[test]
    fn size_16_min_5_max_6_balanced_split_avoids_under_min_last_part() {
        let total =
            compute_total_parts(16, Some(5), Some(6), None).expect("constraints satisfiable");
        assert_eq!(total, 3);
        let parts = part_sizes(16, total);
        assert_eq!(
            parts,
            vec![6, 5, 5],
            "balanced split must keep every part in [min, max]; \
             ceil(size/total) would have produced 6/6/4 with the last below min=5",
        );
        assert_eq!(parts.iter().sum::<u64>(), 16);
        assert!(
            parts.iter().all(|&p| (5..=6).contains(&p)),
            "every part must satisfy 5 <= p <= 6; got {parts:?}",
        );
    }

    /// `compute_total_parts` must guard the `as u32` cast: a huge
    /// upload with a small max and no other constraints would
    /// otherwise truncate silently.
    #[test]
    fn parts_count_overflowing_u32_errors() {
        // 5 * 2^32 bytes with max=1 → 5 * 2^32 parts > u32::MAX.
        let huge = 5u64 << 32;
        let err = compute_total_parts(huge, None, Some(1), None)
            .expect_err("more than u32::MAX parts must be refused");
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    /// Realistic S3-shaped backend (min=5 MiB, max=5 GiB): a 10 GiB
    /// upload with the OLD smallest-count algorithm produced 2 parts
    /// of 5 GiB (terrible for retry granularity and parallelism).
    /// The target-based algorithm aims for ~32 MiB parts and picks
    /// 320, giving real parallelism without exceeding the max.
    #[test]
    fn s3_shaped_10gib_upload_uses_target_part_size() {
        let mib = 1024 * 1024u64;
        let gib = 1024 * mib;
        let total = compute_total_parts(10 * gib, Some(5 * mib), Some(5 * gib), None)
            .expect("constraints satisfiable");
        // 10 GiB / 32 MiB = 320.
        assert_eq!(total, 320);
        let parts = part_sizes(10 * gib, total);
        // Every part should be ~32 MiB (within [5 MiB, 5 GiB]).
        assert!(
            parts.iter().all(|&p| (5 * mib..=5 * gib).contains(&p)),
            "every part must be in [5 MiB, 5 GiB]; got len={} first={} last={}",
            parts.len(),
            parts[0],
            parts[parts.len() - 1],
        );
        assert_eq!(parts.iter().sum::<u64>(), 10 * gib);
    }

    /// max_parts cap dominates the target: a 500 GiB upload with
    /// S3-like (min=5 MiB, max=5 GiB) and max_parts=10000 (S3's
    /// real cap) — the target wants 16000 parts but we clamp to
    /// 10000 parts of ~50 MiB.
    #[test]
    fn s3_shaped_500gib_upload_clamps_to_max_parts() {
        let mib = 1024 * 1024u64;
        let gib = 1024 * mib;
        let total = compute_total_parts(500 * gib, Some(5 * mib), Some(5 * gib), Some(10_000))
            .expect("constraints satisfiable");
        assert_eq!(total, 10_000);
        let parts = part_sizes(500 * gib, total);
        // Every part ~50 MiB, all within [5 MiB, 5 GiB].
        assert!(parts.iter().all(|&p| (5 * mib..=5 * gib).contains(&p)));
        assert_eq!(parts.iter().sum::<u64>(), 500 * gib);
    }

    /// Tight `[min, max]` ranges should still respect the hard
    /// `min_parts_for_max_size` lower bound even when the target
    /// part size lands above max. Reviewer's case: target wants
    /// 1 part of 16 bytes (target=32 MiB > 16), but max=6 forces
    /// 3 parts.
    #[test]
    fn target_clamped_up_to_min_parts_when_max_is_tight() {
        let total = compute_total_parts(16, Some(5), Some(6), None).expect("satisfiable");
        // 32 MiB target / 16 byte upload would naively be 1, but
        // ceil(16/6) = 3 dominates.
        assert_eq!(total, 3);
    }
}

#[cfg(test)]
mod metadata_stash_failure_tests {
    use super::*;

    /// Every cause, so a new one cannot be added without being classified.
    const ALL: &[MetadataStashFailure] = &[
        MetadataStashFailure::ClientUnavailable,
        MetadataStashFailure::UnimplementedKeys,
        MetadataStashFailure::KeysRefused,
    ];

    /// **The property this whole structure exists for.** A cause whose keys
    /// were refused `Unimplemented` must not name `update_metadata` as the
    /// remedy: that call issues the very RPC that just refused them, so the
    /// instruction never terminates.
    ///
    /// The property is deliberately narrow. No remedy can promise the call
    /// SUCCEEDS — `KeysRefused` covers permanent statuses like
    /// `PermissionDenied` too. What is provable, and enforced here, is that a
    /// cause is never given an action known to repeat its own refusal.
    ///
    /// Asserted on the typed remedy, not on the hint's wording. An earlier
    /// version of this test checked that phrases appeared in the English, and
    /// a reviewer showed several plausible-but-wrong hints that satisfied it —
    /// including one that recommended retrying in a loop. A substring check
    /// constrains spelling; this constrains the decision.
    #[test]
    fn no_cause_names_a_remedy_that_provably_repeats_its_refusal() {
        assert_eq!(ALL.len(), 3, "a cause was added without being classified");
        for &cause in ALL {
            let remedy = cause.remedy();
            if cause == MetadataStashFailure::UnimplementedKeys {
                assert!(
                    !remedy.names_update_metadata_as_the_remedy(),
                    "{cause:?} carries {remedy:?}, which tells the caller to \
                     retry a call that just refused these keys",
                );
                assert_eq!(remedy, Remedy::NoneAvailableHere);
            } else {
                assert!(
                    remedy.names_update_metadata_as_the_remedy(),
                    "{cause:?} has no proof that update_metadata repeats, so \
                     it must name it as the action to take",
                );
            }
        }
    }

    /// The instruction is a pure function of the remedy, so a cause cannot
    /// carry text that disagrees with its own classification. Pin that: the
    /// hint must END with the remedy's instruction verbatim.
    ///
    /// This is what stops the substring theatre from coming back — there is no
    /// per-cause instruction to get wrong, only the mapping above.
    #[test]
    fn every_hint_ends_with_its_remedys_instruction_verbatim() {
        for &cause in ALL {
            // Read the hint off the ERROR the production constructor builds.
            // Composing it here instead would assert a property of `format!`:
            // `format!("{a} {b}").ends_with(b)` holds for any two strings, so
            // the check would pass however `partial_metadata_error` behaved.
            let err = partial_metadata_error(1, 1, cause, "boom");
            let hint = err.next_action().expect("a hint is attached").to_string();
            assert!(
                hint.ends_with(cause.remedy().instruction()),
                "{cause:?} hint does not end with its remedy's instruction: {hint}",
            );
            assert!(
                hint.starts_with(cause.situation()),
                "{cause:?} hint does not open with its situation: {hint}",
            );
            // The situation states the durable fact; the remedy states the
            // action. Only the remedy may mention re-issuing, and only to
            // forbid it. A plain exclusion: the earlier `||` form had a left
            // side that was always true, so it never evaluated anything.
            assert!(
                !cause.situation().to_ascii_lowercase().contains("re-issue"),
                "{cause:?} situation must leave the remedy to the remedy: {}",
                cause.situation(),
            );
        }
    }

    /// Every remedy must steer away from the destructive action, whichever
    /// cause it is attached to.
    #[test]
    fn every_remedy_forbids_re_issuing_the_write() {
        for remedy in [
            Remedy::ApplyWithUpdateMetadata,
            Remedy::StatThenApplyMissing,
            Remedy::NoneAvailableHere,
        ] {
            let text = remedy.instruction();
            assert!(
                text.contains("Do not re-issue the write"),
                "{remedy:?} does not steer away from re-issuing the write: {text}",
            );
        }
    }

    /// Outcomes are shared, remedies are not — which is why the remedy is not
    /// derived from the outcome. Pin both so a future edit cannot go back to
    /// deriving one from the other.
    #[test]
    fn two_causes_share_an_outcome_and_need_different_remedies() {
        assert_eq!(
            MetadataStashFailure::ClientUnavailable.outcome(),
            MetadataStashFailure::UnimplementedKeys.outcome(),
            "the premise of keying remedies on the cause is that these collide",
        );
        assert_ne!(
            MetadataStashFailure::ClientUnavailable.remedy(),
            MetadataStashFailure::UnimplementedKeys.remedy(),
            "two causes with one outcome must not share one remedy",
        );
        assert_eq!(
            MetadataStashFailure::KeysRefused.outcome(),
            StageOutcome::Unknown,
        );
    }

    /// The payload a caller acts on, per cause.
    #[test]
    fn every_cause_produces_a_partial_completion_with_its_outcome() {
        for &cause in ALL {
            let err = partial_metadata_error(1, 2, cause, "boom");
            assert_eq!(err.code(), ErrorCode::PartialCompletion);
            assert!(!err.code().retryable(), "{cause:?} must not be retryable");
            match err.context() {
                Some(ErrorContext::Partial {
                    completed,
                    failed,
                    failed_outcome,
                    rollback,
                }) => {
                    assert_eq!(*completed, PartialStage::ObjectData);
                    assert_eq!(*failed, PartialStage::UserMetadata);
                    assert_eq!(*failed_outcome, cause.outcome(), "{cause:?}");
                    assert_eq!(*rollback, RollbackEffect::DestroysRequestedWork);
                }
                other => panic!("{cause:?} produced {other:?}"),
            }
            let hint = err.next_action().expect("a hint is attached");
            assert!(
                hint.ends_with(cause.remedy().instruction()),
                "{cause:?} hint lost its remedy instruction",
            );
        }
    }
}
