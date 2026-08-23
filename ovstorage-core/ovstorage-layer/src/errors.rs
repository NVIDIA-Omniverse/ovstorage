// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt;
use std::time::SystemTime;

use crate::ConnectionId;
use crate::redact::redact_message;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    code: ErrorCode,
    message: String,
    context: Option<Box<ErrorContext>>,
    next_action: Option<String>,
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let raw = message.into();
        let message = redact_error_text(raw);
        Self {
            code,
            message,
            context: None,
            next_action: None,
        }
    }

    /// Attach a typed [`ErrorContext`] to an existing error.
    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = Some(Box::new(context));
        self
    }

    /// Attach a human/agent-readable recovery hint.
    pub fn with_next_action(mut self, next_action: impl Into<String>) -> Self {
        self.next_action = Some(redact_error_text(next_action.into()));
        self
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// Return the structured payload, if any.
    pub fn context(&self) -> Option<&ErrorContext> {
        self.context.as_deref()
    }

    pub fn next_action(&self) -> Option<&str> {
        self.next_action.as_deref()
    }
}

/// Typed payload attached to an [`Error`] for variants with stable
/// structured fields. Codes without a canonical payload leave
/// `context` as `None`; future unknown variants are treated as `None`
/// for forward-compatibility.
///
/// - `ObjectModified` and `PreconditionFailed` →
///   [`ErrorContext::Identity`]. Both carry the etag the backend observed,
///   which is what a caller retries a conditional operation with.
/// - `AuthRequired` / `AuthCancelled` / `AuthExpired` →
///   [`ErrorContext::Auth`].
/// - `PartialCompletion` → [`ErrorContext::Partial`].
///
/// Deliberately **not** `#[non_exhaustive]`: an exhaustive `match` is what
/// forces every wrapper that projects an error onto its own taxonomy to
/// classify a new variant, rather than absorbing it into a `_` arm that
/// compiles and reports something wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorContext {
    /// Companion to `ErrorCode::ObjectModified` and
    /// `ErrorCode::PreconditionFailed`. `new_etag` is the etag the backend
    /// reported, distinct from the caller's `if_match` / `if_dest`
    /// precondition — every in-tree producer of the `PreconditionFailed`
    /// pairing is a destination precondition.
    Identity { new_etag: Option<String> },
    /// Companion to `ErrorCode::AuthRequired` / `AuthCancelled` /
    /// `AuthExpired`. `expired_at` is set only on `AuthExpired`.
    Auth {
        connection_id: ConnectionId,
        reason: Option<String>,
        expired_at: Option<SystemTime>,
    },
    /// Companion to `ErrorCode::PartialCompletion`. Says which stage of a
    /// compound operation committed durably and which one did not, so a
    /// caller can act without a distinct error code per compound operation.
    ///
    /// The two axes are independent, and both are needed. Consider the two
    /// motivating cases:
    ///
    /// - **User metadata after a committed write.** The bytes are durable and
    ///   are what the caller asked for; the sidecar patch is not applied. The
    ///   usual remedy is to re-issue the metadata patch, because undoing the
    ///   write would destroy the very work the call was meant to produce —
    ///   `rollback: DestroysRequestedWork`.
    /// - **A rename emulated as copy-then-delete whose delete failed.** The
    ///   caller did not ask to keep a copy at the destination, so undoing the
    ///   destination write returns the system to where it started —
    ///   `rollback: RestoresPriorState`. Whether the source also survives is
    ///   `failed_outcome`'s business: on `Unknown` the delete may have
    ///   committed and lost its response, so the object may exist at one
    ///   address or both.
    ///
    /// Same code, opposite advice; `rollback` is what carries the difference.
    ///
    /// `failed_outcome` is the second axis because "may I roll back" is not one
    /// bit. A delete can commit and still report failure when its response is
    /// lost, so in the rename case the destination is safe to remove *only*
    /// once the source has been inspected. A caller composes the two fields:
    /// rolling back is unconditionally safe only when `rollback` is
    /// `RestoresPriorState` **and** `failed_outcome` is `NotApplied`.
    Partial {
        /// The stage that committed durably. No layer will undo it.
        completed: PartialStage,
        /// The stage that did not complete.
        failed: PartialStage,
        /// Whether `failed` is known not to have taken effect, or whether its
        /// outcome is unknown.
        failed_outcome: StageOutcome,
        /// What undoing `completed` would cost. This states a consequence,
        /// not a prohibition — a caller weighing an unstored access-control
        /// key against a committed object may still choose to roll back.
        rollback: RollbackEffect,
    },
}

/// A stage of a compound operation, named by what it acts on rather than by
/// the operation it belongs to, so one vocabulary serves every compound
/// operation instead of growing a variant per caller.
///
/// Deliberately **not** `#[non_exhaustive]`, for the same reason as
/// [`ErrorContext`]: a consumer acts on this value, and a `_` arm absorbing a
/// stage it has never heard of would hand the caller confident, wrong advice.
/// An exhaustive `match` makes a new variant a compile error at every site
/// that has to classify it. Cross-version safety comes from the exact
/// `abi_version` match, not from a wildcard.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PartialStage {
    /// The object's bytes at the operation's destination.
    ObjectData,
    /// The user-metadata map for the object — a sidecar, a metadata RPC, or
    /// any store the backend keeps apart from the bytes.
    UserMetadata,
    /// Removal of the source object of a move.
    ///
    /// No in-tree error producer constructs this — outside tests, the only
    /// references are the marshalling translations that carry it across the
    /// C ABI and the broker wire. The emulated copy/rename wrapper still
    /// reports its half-completed move as `ErrorCode::CommitAmbiguous`
    /// (`ovstorage-plugin-core/src/copy_rename_fallback.rs`). The variant
    /// exists because it is the case this vocabulary was designed against —
    /// a rename implemented as copy-then-delete whose delete fails wants the
    /// opposite remedy from a failed metadata patch, and carrying that
    /// difference in the payload is why the code is general rather than
    /// named for metadata. `a_half_completed_move_crosses_the_abi_intact`
    /// (in `ovstorage-plugin/tests/error_code_abi_round_trip.rs`) walks this
    /// shape through the C ABI, so the fit is executed rather than asserted.
    SourceRemoval,
}

/// Whether a stage that reported failure is known not to have taken effect.
///
/// Deliberately **not** `#[non_exhaustive]`, for the same reason as
/// [`ErrorContext`]: a consumer acts on this value, and a `_` arm absorbing a
/// value it has never heard of would hand the caller confident, wrong advice.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum StageOutcome {
    /// The part of the stage that failed definitively did not take effect — it
    /// was never dispatched, or it was refused before it could apply anything.
    ///
    /// Scoped to the failed part on purpose. A stage can be a SET — the
    /// user-metadata stage is a map of keys — and some of it may have applied
    /// while the rest was refused. This says nothing about the part that
    /// succeeded.
    NotApplied,
    /// The part of the stage that failed may or may not have taken effect. A
    /// request can commit and still report failure when its response is lost.
    Unknown,
}

/// What undoing the completed stage would cost.
///
/// This is a statement about consequence, not an instruction. A caller still
/// decides: `DestroysRequestedWork` does not forbid a rollback, it says what a
/// rollback would take with it.
///
/// Deliberately **not** `#[non_exhaustive]`, for the same reason as
/// [`ErrorContext`]: a consumer acts on this value, and a `_` arm absorbing a
/// value it has never heard of would hand the caller confident, wrong advice.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RollbackEffect {
    /// Undoing the completed stage returns the system to its state before the
    /// call, *as far as that stage goes* — the completed stage is only part of
    /// the outcome the caller asked for and is not useful on its own. Compose
    /// with `failed_outcome`: on `Unknown` the failed stage may also have taken
    /// effect, so undoing is unconditionally safe only alongside `NotApplied`.
    RestoresPriorState,
    /// Undoing the completed stage destroys work the caller asked for. The
    /// completed stage is the requested outcome; only a later, subordinate
    /// stage failed.
    DestroysRequestedWork,
}

impl PartialStage {
    /// Stable snake_case name for agent-facing JSON and cross-wrapper
    /// taxonomies.
    pub fn as_str(self) -> &'static str {
        match self {
            PartialStage::ObjectData => "object_data",
            PartialStage::UserMetadata => "user_metadata",
            PartialStage::SourceRemoval => "source_removal",
        }
    }
}

impl StageOutcome {
    /// Stable snake_case name for agent-facing JSON and cross-wrapper
    /// taxonomies.
    pub fn as_str(self) -> &'static str {
        match self {
            StageOutcome::NotApplied => "not_applied",
            StageOutcome::Unknown => "unknown",
        }
    }
}

impl RollbackEffect {
    /// Stable snake_case name for agent-facing JSON and cross-wrapper
    /// taxonomies.
    pub fn as_str(self) -> &'static str {
        match self {
            RollbackEffect::RestoresPriorState => "restores_prior_state",
            RollbackEffect::DestroysRequestedWork => "destroys_requested_work",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

fn redact_error_text(raw: String) -> String {
    match redact_message(&raw) {
        Cow::Borrowed(_) => raw,
        Cow::Owned(scrubbed) => scrubbed,
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    NotFound,
    AlreadyExists,
    PermissionDenied,
    PreconditionFailed,
    Conflict,
    DirectoryNotEmpty,
    Unsupported,
    InvalidArgument,
    IncompatibleType,
    Locked,
    Cancelled,
    DeadlineExceeded,
    Transient,
    ResourceExhausted,
    IntegrityFailure,
    Internal,
    BrokerUnavailable,
    BrokerRequired,
    RedirectExpired,
    PolicyEpochStale,
    AuthorizationLeaseExpired,
    CacheCorrupt,
    StagingExpired,
    CommitAmbiguous,
    CacheLockContention,
    StateRootUnavailable,
    NetworkFilesystemRefused,
    ObjectModified,
    NoRoute,
    RouteConflict,
    NotConfigured,
    AliasChainTooLong,
    CredentialExpired,
    CredentialUnavailable,
    AuthRequired,
    AuthCancelled,
    AuthExpired,
    ContentMismatch,
    ContentChecksumMismatch,
    /// Host rejected the plugin load for policy reasons (e.g. a
    /// `test_only` cdylib in a production host). Distinct from
    /// `InvalidArgument` so operators can tell a policy refusal apart
    /// from a malformed binary.
    PluginRejected,
    /// A compound operation committed one stage durably and then failed a
    /// later one. The caller's state is neither "it happened" nor "it did not
    /// happen", and the difference matters: re-issuing the whole operation can
    /// be wasteful or destructive, and rolling it back can destroy committed
    /// data.
    ///
    /// General by design rather than one code per compound operation. What
    /// completed, what failed, and what a rollback would do are carried by
    /// [`ErrorContext::Partial`], which is where a caller reads its remedy.
    PartialCompletion,
}

/// Coarse, stable classification over the full [`ErrorCode`] set.
///
/// Every [`ErrorCode`] maps to exactly one bucket via
/// [`ErrorCode::bucket`]. Retryability is derived from the bucket and
/// nowhere else: see [`ErrorBucket::retryable`].
///
/// The wrappers (C ABI status, HTTP/gRPC codes, Python exceptions, CLI
/// exit codes) do **not** derive their taxonomies from the bucket —
/// each matches on [`ErrorCode`] directly, so that a code can be given
/// a finer-grained status than its bucket implies, and each falls back
/// to its own literal rather than to the bucket — CLI to `1`, HTTP to
/// `500`, gRPC and the C host to their `Internal` equivalents.
///
/// Python's exception hierarchy mirrors the bucket, but by hand: each
/// `create_exception!` names its base literally, and a test walks this
/// mapping to check the two agree. So no wrapper *derives* its taxonomy
/// from the bucket at runtime; the bucket is the specification that the
/// hand-written mirrors are checked against.
///
/// The set is intentionally small (nine buckets) and marked
/// `#[non_exhaustive]` so new buckets can be added without breaking
/// downstream `match`es. Callers should treat an unrecognised bucket as
/// non-retryable and internal-flavoured.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorBucket {
    /// The addressed object, route, or configuration does not exist.
    NotFound,
    /// The caller is not authenticated or not authorized. Folds both
    /// authorization denials and authentication/credential failures.
    Permission,
    /// A required precondition on server or object state was not met
    /// (etag mismatch, conflict, locked, stale epoch, expired lease
    /// window, missing broker/state root).
    Precondition,
    /// The request itself is malformed or semantically invalid.
    Invalid,
    /// A transient failure a blind retry might clear (upstream
    /// unavailable, deadline exceeded, lock contention, refreshable
    /// lease). Retryable.
    Transient,
    /// A quota or capacity limit was hit. Retryable.
    ResourceExhausted,
    /// The operation is not implemented or not supported here.
    Unsupported,
    /// The operation was cancelled before it completed.
    Cancelled,
    /// A server-side failure that is not the caller's fault and is not
    /// safe to blindly retry (corruption, ambiguous commit, backend
    /// refusal, otherwise-unclassified internal error).
    Internal,
}

impl ErrorBucket {
    /// Stable snake_case name of the bucket for agent-facing JSON and
    /// cross-wrapper taxonomies.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorBucket::NotFound => "not_found",
            ErrorBucket::Permission => "permission",
            ErrorBucket::Precondition => "precondition",
            ErrorBucket::Invalid => "invalid",
            ErrorBucket::Transient => "transient",
            ErrorBucket::ResourceExhausted => "resource_exhausted",
            ErrorBucket::Unsupported => "unsupported",
            ErrorBucket::Cancelled => "cancelled",
            ErrorBucket::Internal => "internal",
        }
    }

    /// Whether errors in this bucket may succeed on a blind retry.
    ///
    /// This is the single source of truth for [`ErrorCode::retryable`]:
    /// exactly the [`ErrorBucket::Transient`] and
    /// [`ErrorBucket::ResourceExhausted`] buckets are retryable.
    pub fn retryable(self) -> bool {
        matches!(
            self,
            ErrorBucket::Transient | ErrorBucket::ResourceExhausted
        )
    }
}

impl ErrorCode {
    // Rust-only exhaustive `&[Self]` slice of every `ErrorCode`, used by the
    // internal completeness test; cbindgen can't render a `&'static [Self]`
    // slice constant, and the C header maps `ErrorCode` as a plain enum.
    /// cbindgen:ignore
    pub const KNOWN: &'static [Self] = &[
        Self::NotFound,
        Self::AlreadyExists,
        Self::PermissionDenied,
        Self::PreconditionFailed,
        Self::Conflict,
        Self::DirectoryNotEmpty,
        Self::Unsupported,
        Self::InvalidArgument,
        Self::IncompatibleType,
        Self::Locked,
        Self::Cancelled,
        Self::DeadlineExceeded,
        Self::Transient,
        Self::ResourceExhausted,
        Self::IntegrityFailure,
        Self::Internal,
        Self::BrokerUnavailable,
        Self::BrokerRequired,
        Self::RedirectExpired,
        Self::PolicyEpochStale,
        Self::AuthorizationLeaseExpired,
        Self::CacheCorrupt,
        Self::StagingExpired,
        Self::CommitAmbiguous,
        Self::CacheLockContention,
        Self::StateRootUnavailable,
        Self::NetworkFilesystemRefused,
        Self::ObjectModified,
        Self::NoRoute,
        Self::RouteConflict,
        Self::NotConfigured,
        Self::AliasChainTooLong,
        Self::CredentialExpired,
        Self::CredentialUnavailable,
        Self::AuthRequired,
        Self::AuthCancelled,
        Self::AuthExpired,
        Self::ContentMismatch,
        Self::ContentChecksumMismatch,
        Self::PluginRejected,
        Self::PartialCompletion,
    ];

    /// Stable string name of the variant for agent-facing JSON errors.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotFound => "NotFound",
            ErrorCode::AlreadyExists => "AlreadyExists",
            ErrorCode::PermissionDenied => "PermissionDenied",
            ErrorCode::PreconditionFailed => "PreconditionFailed",
            ErrorCode::Conflict => "Conflict",
            ErrorCode::DirectoryNotEmpty => "DirectoryNotEmpty",
            ErrorCode::Unsupported => "Unsupported",
            ErrorCode::InvalidArgument => "InvalidArgument",
            ErrorCode::IncompatibleType => "IncompatibleType",
            ErrorCode::Locked => "Locked",
            ErrorCode::Cancelled => "Cancelled",
            ErrorCode::DeadlineExceeded => "DeadlineExceeded",
            ErrorCode::Transient => "Transient",
            ErrorCode::ResourceExhausted => "ResourceExhausted",
            ErrorCode::IntegrityFailure => "IntegrityFailure",
            ErrorCode::Internal => "Internal",
            ErrorCode::BrokerUnavailable => "BrokerUnavailable",
            ErrorCode::BrokerRequired => "BrokerRequired",
            ErrorCode::RedirectExpired => "RedirectExpired",
            ErrorCode::PolicyEpochStale => "PolicyEpochStale",
            ErrorCode::AuthorizationLeaseExpired => "AuthorizationLeaseExpired",
            ErrorCode::CacheCorrupt => "CacheCorrupt",
            ErrorCode::StagingExpired => "StagingExpired",
            ErrorCode::CommitAmbiguous => "CommitAmbiguous",
            ErrorCode::CacheLockContention => "CacheLockContention",
            ErrorCode::StateRootUnavailable => "StateRootUnavailable",
            ErrorCode::NetworkFilesystemRefused => "NetworkFilesystemRefused",
            ErrorCode::ObjectModified => "ObjectModified",
            ErrorCode::NoRoute => "NoRoute",
            ErrorCode::RouteConflict => "RouteConflict",
            ErrorCode::NotConfigured => "NotConfigured",
            ErrorCode::AliasChainTooLong => "AliasChainTooLong",
            ErrorCode::CredentialExpired => "CredentialExpired",
            ErrorCode::CredentialUnavailable => "CredentialUnavailable",
            ErrorCode::AuthRequired => "AuthRequired",
            ErrorCode::AuthCancelled => "AuthCancelled",
            ErrorCode::AuthExpired => "AuthExpired",
            ErrorCode::ContentMismatch => "ContentMismatch",
            ErrorCode::ContentChecksumMismatch => "ContentChecksumMismatch",
            ErrorCode::PluginRejected => "PluginRejected",
            ErrorCode::PartialCompletion => "PartialCompletion",
        }
    }

    /// Coarse [`ErrorBucket`] classification of this code.
    ///
    /// Total over every variant. It is the source of truth for retryability,
    /// and the specification each wrapper's hand-written taxonomy is checked
    /// against rather than derived from (see [`ErrorBucket`]). The mapping tracks the
    /// HTTP/gRPC groupings the wrappers already use, except where
    /// retryability forces a different bucket: refreshable failures such
    /// as `AuthorizationLeaseExpired` and `CacheLockContention` land in
    /// [`ErrorBucket::Transient`] so that retryability is exactly bucket
    /// membership.
    pub fn bucket(self) -> ErrorBucket {
        match self {
            // Absent object / route / configuration.
            ErrorCode::NotFound | ErrorCode::NoRoute | ErrorCode::NotConfigured => {
                ErrorBucket::NotFound
            }
            // Authentication and authorization failures (folded).
            ErrorCode::PermissionDenied
            | ErrorCode::PluginRejected
            | ErrorCode::CredentialExpired
            | ErrorCode::CredentialUnavailable
            | ErrorCode::AuthRequired
            | ErrorCode::AuthCancelled
            | ErrorCode::AuthExpired => ErrorBucket::Permission,
            // Server/object state preconditions not met.
            ErrorCode::PreconditionFailed
            | ErrorCode::ObjectModified
            | ErrorCode::AlreadyExists
            | ErrorCode::Conflict
            | ErrorCode::DirectoryNotEmpty
            | ErrorCode::IncompatibleType
            | ErrorCode::Locked
            | ErrorCode::RouteConflict
            | ErrorCode::PolicyEpochStale
            | ErrorCode::RedirectExpired
            | ErrorCode::StagingExpired
            | ErrorCode::BrokerRequired
            | ErrorCode::StateRootUnavailable
            | ErrorCode::ContentMismatch
            | ErrorCode::ContentChecksumMismatch => ErrorBucket::Precondition,
            // Malformed / semantically invalid request.
            ErrorCode::InvalidArgument | ErrorCode::AliasChainTooLong => ErrorBucket::Invalid,
            // Not implemented / not supported here.
            ErrorCode::Unsupported => ErrorBucket::Unsupported,
            // Retryable transient failures (see method doc).
            ErrorCode::Transient
            | ErrorCode::BrokerUnavailable
            | ErrorCode::DeadlineExceeded
            | ErrorCode::CacheLockContention
            | ErrorCode::AuthorizationLeaseExpired => ErrorBucket::Transient,
            // Retryable quota / capacity limit.
            ErrorCode::ResourceExhausted => ErrorBucket::ResourceExhausted,
            // Cancellation.
            ErrorCode::Cancelled => ErrorBucket::Cancelled,
            // Server-side, not caller's fault, not blindly retryable.
            //
            // `PartialCompletion` is classified from the two properties this
            // bucket asserts, both of which it has: durable effects the caller
            // must not assume away, and a blind retry that is unsafe. A
            // retryable bucket would make a well-behaved caller re-issue the
            // whole operation — for a write whose metadata patch failed, that
            // re-uploads the object and changes its etag.
            //
            // Bucket membership does not by itself encode whether the
            // operation happened — `Cancelled` is non-retryable and says
            // nothing about effects — so the fact that a stage committed is
            // carried by the code and by `ErrorContext::Partial`, not inferred
            // from the bucket. `CommitAmbiguous`, the nearest neighbour, sits
            // here for the same two reasons.
            ErrorCode::Internal
            | ErrorCode::IntegrityFailure
            | ErrorCode::CacheCorrupt
            | ErrorCode::CommitAmbiguous
            | ErrorCode::PartialCompletion
            | ErrorCode::NetworkFilesystemRefused => ErrorBucket::Internal,
        }
    }

    /// Whether a blind retry of the same operation might succeed.
    ///
    /// Derived from [`ErrorCode::bucket`]: retryable iff the bucket is
    /// retryable. This is exactly Transient, BrokerUnavailable,
    /// ResourceExhausted, DeadlineExceeded, CacheLockContention, and
    /// AuthorizationLeaseExpired.
    pub fn retryable(self) -> bool {
        self.bucket().retryable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_new_redacts_signed_url_in_message() {
        let err = Error::new(
            ErrorCode::Transient,
            "broker fetch failed from \
             https://bucket.s3.amazonaws.com/key?X-Amz-Signature=secret&versionId=7",
        );
        let msg = err.message();
        assert!(msg.contains("X-Amz-Signature=REDACTED"), "{msg}");
        assert!(msg.contains("versionId=7"), "{msg}");
        assert!(!msg.contains("secret"), "{msg}");
    }

    #[test]
    fn error_new_redacts_bearer_in_message() {
        let err = Error::new(
            ErrorCode::PermissionDenied,
            "request rejected: Bearer eyJhbGciOiJIUzI1NiJ9.bogus.token",
        );
        let msg = err.message();
        assert!(msg.contains("Bearer REDACTED"), "{msg}");
        assert!(!msg.contains("eyJhbGciOiJIUzI1NiJ9"), "{msg}");
    }

    #[test]
    fn error_new_passes_through_plain_messages_unchanged() {
        let err = Error::new(ErrorCode::NotFound, "object does not exist");
        assert_eq!(err.message(), "object does not exist");
    }

    #[test]
    fn error_display_shows_redacted_message() {
        let err = Error::new(
            ErrorCode::Transient,
            "fetch failed from https://example.com/x?X-Amz-Signature=abc",
        );
        let display = format!("{err}");
        assert!(display.contains("Transient:"), "{display}");
        assert!(display.contains("X-Amz-Signature=REDACTED"), "{display}");
        assert!(!display.contains("X-Amz-Signature=abc"), "{display}");
    }

    #[test]
    fn error_with_next_action_sets_field() {
        let err = Error::new(ErrorCode::NotFound, "object missing")
            .with_next_action("call LayerExt::stat first to confirm the address");
        assert_eq!(
            err.next_action(),
            Some("call LayerExt::stat first to confirm the address")
        );
    }

    #[test]
    fn error_without_next_action_returns_none() {
        let err = Error::new(ErrorCode::NotFound, "object missing");
        assert!(err.next_action().is_none());
    }

    #[test]
    fn error_next_action_is_redacted() {
        let err = Error::new(ErrorCode::Transient, "transient").with_next_action(
            "retry using \
             https://example.com/p?X-Amz-Signature=secret",
        );
        let na = err.next_action().expect("next_action present");
        assert!(na.contains("X-Amz-Signature=REDACTED"), "{na}");
        assert!(!na.contains("secret"), "{na}");
    }

    #[test]
    fn error_code_retryable_classification() {
        use ErrorCode::*;
        assert!(Transient.retryable());
        assert!(BrokerUnavailable.retryable());
        assert!(ResourceExhausted.retryable());
        assert!(DeadlineExceeded.retryable());
        assert!(CacheLockContention.retryable());
        assert!(AuthorizationLeaseExpired.retryable());

        assert!(!NotFound.retryable());
        assert!(!PermissionDenied.retryable());
        assert!(!InvalidArgument.retryable());
        assert!(!Cancelled.retryable());
        assert!(!ObjectModified.retryable());
        assert!(!CredentialUnavailable.retryable());
        assert!(!AuthRequired.retryable());
    }

    #[test]
    fn error_code_bucket_is_total_and_retryable_consistent() {
        // Every KNOWN code maps to a bucket (the match in `bucket()` is
        // exhaustive, so this also fails to compile if a variant is
        // added without classification), and retryability is exactly
        // bucket membership.
        for &code in ErrorCode::KNOWN {
            let bucket = code.bucket();
            assert!(!bucket.as_str().is_empty(), "{code:?} bucket has no name");
            assert_eq!(
                code.retryable(),
                bucket.retryable(),
                "{code:?} retryable/bucket mismatch (bucket {bucket:?})",
            );
            if code.retryable() {
                assert!(
                    matches!(
                        bucket,
                        ErrorBucket::Transient | ErrorBucket::ResourceExhausted
                    ),
                    "retryable {code:?} landed in non-retryable bucket {bucket:?}",
                );
            }
        }
    }

    #[test]
    fn error_code_bucket_matches_documented_retryable_set() {
        use ErrorCode::*;
        // The six historically-retryable codes and their buckets.
        assert_eq!(Transient.bucket(), ErrorBucket::Transient);
        assert_eq!(BrokerUnavailable.bucket(), ErrorBucket::Transient);
        assert_eq!(DeadlineExceeded.bucket(), ErrorBucket::Transient);
        assert_eq!(CacheLockContention.bucket(), ErrorBucket::Transient);
        assert_eq!(AuthorizationLeaseExpired.bucket(), ErrorBucket::Transient);
        assert_eq!(ResourceExhausted.bucket(), ErrorBucket::ResourceExhausted);

        // Spot-check non-retryable classifications.
        assert_eq!(NotFound.bucket(), ErrorBucket::NotFound);
        assert_eq!(NoRoute.bucket(), ErrorBucket::NotFound);
        assert_eq!(PermissionDenied.bucket(), ErrorBucket::Permission);
        assert_eq!(AuthRequired.bucket(), ErrorBucket::Permission);
        assert_eq!(ObjectModified.bucket(), ErrorBucket::Precondition);
        assert_eq!(InvalidArgument.bucket(), ErrorBucket::Invalid);
        assert_eq!(Unsupported.bucket(), ErrorBucket::Unsupported);
        assert_eq!(Cancelled.bucket(), ErrorBucket::Cancelled);
        assert_eq!(CacheCorrupt.bucket(), ErrorBucket::Internal);
    }

    #[test]
    fn error_bucket_as_str_is_stable_and_unique() {
        let buckets = [
            ErrorBucket::NotFound,
            ErrorBucket::Permission,
            ErrorBucket::Precondition,
            ErrorBucket::Invalid,
            ErrorBucket::Transient,
            ErrorBucket::ResourceExhausted,
            ErrorBucket::Unsupported,
            ErrorBucket::Cancelled,
            ErrorBucket::Internal,
        ];
        let mut names = std::collections::HashSet::new();
        for bucket in buckets {
            assert!(
                names.insert(bucket.as_str()),
                "duplicate bucket name: {bucket:?}"
            );
        }
        assert_eq!(names.len(), 9);
        assert!(ErrorBucket::Transient.retryable());
        assert!(ErrorBucket::ResourceExhausted.retryable());
        assert!(!ErrorBucket::NotFound.retryable());
        assert!(!ErrorBucket::Cancelled.retryable());
    }

    #[test]
    fn partial_completion_is_internal_and_never_retryable() {
        // The two properties the design turns on. A retryable bucket would
        // have a well-behaved caller re-upload the object to fix a metadata
        // failure; `Internal` is the only bucket asserting durable effects
        // plus an unsafe blind retry.
        assert_eq!(ErrorCode::PartialCompletion.bucket(), ErrorBucket::Internal);
        assert!(!ErrorCode::PartialCompletion.retryable());
        assert!(!ErrorCode::PartialCompletion.bucket().retryable());
        assert_eq!(ErrorCode::PartialCompletion.as_str(), "PartialCompletion");
    }

    #[test]
    fn partial_context_names_the_committed_and_failed_stages() {
        // The metadata-after-write case: bytes durable, sidecar not applied.
        // Rolling back would delete the object the caller asked for.
        let err = Error::new(ErrorCode::PartialCompletion, "object committed").with_context(
            ErrorContext::Partial {
                completed: PartialStage::ObjectData,
                failed: PartialStage::UserMetadata,
                failed_outcome: StageOutcome::NotApplied,
                rollback: RollbackEffect::DestroysRequestedWork,
            },
        );
        let Some(ErrorContext::Partial {
            completed,
            failed,
            failed_outcome,
            rollback,
        }) = err.context()
        else {
            panic!("expected a Partial context, got {:?}", err.context());
        };
        assert_eq!(*completed, PartialStage::ObjectData);
        assert_eq!(*failed, PartialStage::UserMetadata);
        assert_eq!(*failed_outcome, StageOutcome::NotApplied);
        assert_eq!(*rollback, RollbackEffect::DestroysRequestedWork);
    }

    /// The generality the code's name is paying for: the payload must express
    /// a rename emulated as copy-then-delete whose delete failed, **without a
    /// second error code**, and must give the opposite rollback advice from
    /// the metadata case above.
    ///
    /// This pins a property of the **vocabulary**, not of a code path — it
    /// constructs both shapes and checks they are distinguishable and carry
    /// opposing advice, so it would survive any change that did not alter the
    /// enums. The marshalling side is covered separately by
    /// `a_half_completed_move_crosses_the_abi_intact` in
    /// `ovstorage-plugin/tests/error_code_abi_round_trip.rs`, which walks the
    /// value through the C ABI. No in-tree producer emits this shape yet — the
    /// emulated rename still reports `CommitAmbiguous`.
    #[test]
    fn partial_context_expresses_a_half_completed_move() {
        let move_case = ErrorContext::Partial {
            completed: PartialStage::ObjectData,
            failed: PartialStage::SourceRemoval,
            // A delete can commit and still report failure if its response is
            // lost, so the source's state is genuinely unknown.
            failed_outcome: StageOutcome::Unknown,
            rollback: RollbackEffect::RestoresPriorState,
        };
        let metadata_case = ErrorContext::Partial {
            completed: PartialStage::ObjectData,
            failed: PartialStage::UserMetadata,
            failed_outcome: StageOutcome::NotApplied,
            rollback: RollbackEffect::DestroysRequestedWork,
        };

        // Same code, opposite advice — the whole point of the general name.
        assert_ne!(move_case, metadata_case);
        let (
            ErrorContext::Partial { rollback: mv, .. },
            ErrorContext::Partial { rollback: md, .. },
        ) = (&move_case, &metadata_case)
        else {
            panic!("both must be Partial contexts");
        };
        assert_eq!(*mv, RollbackEffect::RestoresPriorState);
        assert_eq!(*md, RollbackEffect::DestroysRequestedWork);
        assert_ne!(mv, md);

        // And rollback safety is NOT one bit: the move's rollback restores the
        // prior state, yet is unsafe until the source is inspected, because
        // the delete's outcome is unknown. A single "safe to roll back" flag
        // would have shipped that over-claim.
        let ErrorContext::Partial {
            rollback,
            failed_outcome,
            ..
        } = &move_case
        else {
            panic!("expected Partial");
        };
        let unconditionally_safe = *rollback == RollbackEffect::RestoresPriorState
            && *failed_outcome == StageOutcome::NotApplied;
        assert!(
            !unconditionally_safe,
            "a half-completed move with an unknown delete outcome must not read \
             as unconditionally safe to roll back",
        );
    }

    #[test]
    fn partial_enum_names_are_stable_and_unique() {
        let stages = [
            PartialStage::ObjectData,
            PartialStage::UserMetadata,
            PartialStage::SourceRemoval,
        ];
        let mut names = std::collections::HashSet::new();
        for stage in stages {
            assert!(names.insert(stage.as_str()), "duplicate stage: {stage:?}");
        }
        assert_eq!(names.len(), 3);

        assert_eq!(StageOutcome::NotApplied.as_str(), "not_applied");
        assert_eq!(StageOutcome::Unknown.as_str(), "unknown");
        assert_ne!(
            StageOutcome::NotApplied.as_str(),
            StageOutcome::Unknown.as_str()
        );
        assert_eq!(
            RollbackEffect::RestoresPriorState.as_str(),
            "restores_prior_state"
        );
        assert_eq!(
            RollbackEffect::DestroysRequestedWork.as_str(),
            "destroys_requested_work"
        );
        assert_ne!(
            RollbackEffect::RestoresPriorState.as_str(),
            RollbackEffect::DestroysRequestedWork.as_str()
        );
    }

    #[test]
    fn error_code_as_str_returns_variant_name() {
        use ErrorCode::*;
        assert_eq!(NotFound.as_str(), "NotFound");
        assert_eq!(PermissionDenied.as_str(), "PermissionDenied");
        assert_eq!(CredentialUnavailable.as_str(), "CredentialUnavailable");
        assert_eq!(BrokerUnavailable.as_str(), "BrokerUnavailable");
    }

    #[test]
    fn error_code_known_covers_current_variants() {
        let mut seen = std::collections::HashSet::new();
        for code in ErrorCode::KNOWN {
            let index = known_error_code_index(*code);
            assert!(
                seen.insert(index),
                "duplicate ErrorCode::KNOWN entry: {code:?}"
            );
        }
        assert_eq!(seen.len(), 41);
    }

    fn known_error_code_index(code: ErrorCode) -> usize {
        match code {
            ErrorCode::NotFound => 0,
            ErrorCode::AlreadyExists => 1,
            ErrorCode::PermissionDenied => 2,
            ErrorCode::PreconditionFailed => 3,
            ErrorCode::Conflict => 4,
            ErrorCode::DirectoryNotEmpty => 5,
            ErrorCode::Unsupported => 6,
            ErrorCode::InvalidArgument => 7,
            ErrorCode::IncompatibleType => 8,
            ErrorCode::Locked => 9,
            ErrorCode::Cancelled => 10,
            ErrorCode::DeadlineExceeded => 11,
            ErrorCode::Transient => 12,
            ErrorCode::ResourceExhausted => 13,
            ErrorCode::IntegrityFailure => 14,
            ErrorCode::Internal => 15,
            ErrorCode::BrokerUnavailable => 16,
            ErrorCode::BrokerRequired => 17,
            ErrorCode::RedirectExpired => 18,
            ErrorCode::PolicyEpochStale => 19,
            ErrorCode::AuthorizationLeaseExpired => 20,
            ErrorCode::CacheCorrupt => 21,
            ErrorCode::StagingExpired => 22,
            ErrorCode::CommitAmbiguous => 23,
            ErrorCode::CacheLockContention => 24,
            ErrorCode::StateRootUnavailable => 25,
            ErrorCode::NetworkFilesystemRefused => 26,
            ErrorCode::ObjectModified => 27,
            ErrorCode::NoRoute => 28,
            ErrorCode::RouteConflict => 29,
            ErrorCode::NotConfigured => 30,
            ErrorCode::AliasChainTooLong => 31,
            ErrorCode::CredentialExpired => 32,
            ErrorCode::CredentialUnavailable => 33,
            ErrorCode::AuthRequired => 34,
            ErrorCode::AuthCancelled => 35,
            ErrorCode::AuthExpired => 36,
            ErrorCode::ContentMismatch => 37,
            ErrorCode::ContentChecksumMismatch => 38,
            ErrorCode::PluginRejected => 39,
            ErrorCode::PartialCompletion => 40,
        }
    }
}
