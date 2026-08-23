/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * ovstorage library C ABI.
 *
 * Hand-maintained. This is the header for the C implementation in
 * ../src, and the two are edited together: adding, changing or removing
 * a declaration here means changing that implementation, and the
 * link-completeness gate fails if a function declared here is never
 * defined there.
 *
 * No tool regenerates this file; edit it directly. Keep the existing
 * shape -- one declaration per function, with the return type and name
 * on the first line at column zero -- because the completeness gate
 * parses this file to build its expected symbol set.
 *
 * ovstorage_plugin.h is NOT hand-maintained. It is generated from the
 * ovstorage-plugin crate and byte-copied here, because plugins are
 * prebuilt cdylibs loaded at runtime and both sides must agree on
 * layout. Do not edit that file; edit the crate and regenerate.
 */


#ifndef OVSTORAGE_H
#define OVSTORAGE_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "ovstorage_plugin.h"

/**
 * Coarse status every C entry point reports.
 *
 * The values are additive, stable ABI: an existing discriminant is never
 * renumbered or reused, and new statuses only ever append after the
 * highest non-`Internal` value. A newer library may therefore return a
 * status an older caller does not know; callers MUST treat an
 * unrecognized value as `OvStorage_Status_Internal`-equivalent (a server-side,
 * non-retryable failure). Route retry decisions through
 * `ovstorage_status_is_retryable` rather than a hand-rolled list so
 * newly appended retryable statuses classify correctly.
 */
typedef enum {
  OvStorage_Status_Ok = 0,
  OvStorage_Status_NotFound = 1,
  OvStorage_Status_AlreadyExists = 2,
  OvStorage_Status_PermissionDenied = 3,
  OvStorage_Status_PreconditionFailed = 4,
  OvStorage_Status_Conflict = 5,
  OvStorage_Status_DirectoryNotEmpty = 6,
  OvStorage_Status_Unsupported = 7,
  OvStorage_Status_InvalidArgument = 8,
  OvStorage_Status_ObjectModified = 9,
  OvStorage_Status_NoRoute = 10,
  OvStorage_Status_Transient = 11,
  OvStorage_Status_Cancelled = 12,
  /**
   * The underlying plugin error was `IncompatibleType`. Any entry point
   * whose operation fails with that error surfaces this status;
   * `ovstorage_import_handle` is the primary producer — a foreign handle
   * whose vtable header is undersized, or whose `abi_version` this build
   * does not support, fails the ABI handshake with it.
   */
  OvStorage_Status_IncompatibleType = 13,
  /**
   * A quota or capacity limit was hit. Retryable, typically after
   * backoff — see `ovstorage_status_is_retryable`.
   */
  OvStorage_Status_ResourceExhausted = 14,
  /**
   * A compound operation committed one stage durably and then failed a
   * later one. The caller's state is neither "it happened" nor "it did
   * not happen": re-issuing the whole operation can be wasteful or
   * destructive, and rolling it back can destroy committed data.
   *
   * Distinct from `OvStorage_Status_Internal` because the remedies
   * differ. Not retryable — see `ovstorage_status_is_retryable`. Which
   * stage committed and what a rollback would do are carried in the
   * plugin-level `OvStoragePlugin_ErrorContextV1` partial slot; this
   * host surface reports the status and the code name only.
   */
  OvStorage_Status_PartialCompletion = 15,
  /**
   * The host refused to load or use a plugin: it declared itself
   * `test_only` where test plugins are not allowed, or it was otherwise
   * rejected by policy before any of its code ran.
   *
   * Distinct from `OvStorage_Status_Internal` because nothing failed —
   * the refusal is the host's own decision and the remedy is a
   * configuration change, not a retry. Distinct from
   * `OvStorage_Status_PermissionDenied`, which is a backend's answer
   * about an object. Not retryable — see `ovstorage_status_is_retryable`.
   */
  OvStorage_Status_PluginRejected = 16,
  OvStorage_Status_Internal = 255,
} OvStorage_Status;

typedef enum {
  OvStorage_ObjectKind_File = 0,
  OvStorage_ObjectKind_Directory = 1,
  OvStorage_ObjectKind_DirectoryMarker = 2,
  OvStorage_ObjectKind_DirectoryInferred = 3,
} OvStorage_ObjectKind;

typedef enum {
  OvStorage_ConfigValueKind_String = 0,
  OvStorage_ConfigValueKind_Int = 1,
  OvStorage_ConfigValueKind_Bool = 2,
  /**
   * Reserialized TOML payload (a nested table or array of tables).
   * The plugin reading the value parses the string with its own
   * TOML deserializer.
   */
  OvStorage_ConfigValueKind_Toml = 3,
} OvStorage_ConfigValueKind;

typedef enum {
  OvStorage_VersionListOrder_Newest = 0,
  OvStorage_VersionListOrder_Oldest = 1,
  OvStorage_VersionListOrder_Unordered = 2,
} OvStorage_VersionListOrder;

typedef enum {
  OvStorage_ConnectionSourceKind_Static = 0,
  OvStorage_ConnectionSourceKind_Runtime = 1,
  OvStorage_ConnectionSourceKind_BrokerDelivered = 2,
} OvStorage_ConnectionSourceKind;

typedef enum {
  OvStorage_ConfigLayer_Programmatic = 0,
  OvStorage_ConfigLayer_Env = 1,
  OvStorage_ConfigLayer_Project = 2,
  OvStorage_ConfigLayer_User = 3,
  OvStorage_ConfigLayer_Machine = 4,
} OvStorage_ConfigLayer;

typedef enum {
  OvStorage_ConnectionAuthStateKind_Authenticated = 0,
  OvStorage_ConnectionAuthStateKind_AwaitingAuth = 1,
  OvStorage_ConnectionAuthStateKind_AuthFailed = 2,
  OvStorage_ConnectionAuthStateKind_Anonymous = 3,
} OvStorage_ConnectionAuthStateKind;

/**
 * Why a connection is awaiting authentication. The remedies differ per
 * variant — `NeverAuthenticated` wants a first sign-in, `RefreshTokenRevoked`
 * wants the operator to re-grant, `BackendUnreachable` wants a retry — so a
 * caller that collapses them to "needs auth" prompts a user who cannot fix
 * anything. `Unknown` carries a free-form string in
 * `awaiting_auth_unknown_details`.
 */
typedef enum {
  OvStorage_AuthReason_NeverAuthenticated = 0,
  OvStorage_AuthReason_RefreshTokenExpired = 1,
  OvStorage_AuthReason_RefreshTokenRevoked = 2,
  OvStorage_AuthReason_CredentialsRotated = 3,
  OvStorage_AuthReason_ManuallyRequested = 4,
  OvStorage_AuthReason_BackendUnreachable = 5,
  OvStorage_AuthReason_Unknown = 6,
} OvStorage_AuthReason;

/**
 * Whether a root can serve efficient random-access range reads. Mirrors
 * the plugin ABI's `OvStoragePlugin_RangeReadStrategy` discriminants.
 */
typedef enum {
  /** The backend serves ranges directly. */
  OvStorage_RangeReadStrategy_Native = 0,
  /** Ranges are served through a local cache that fills on demand. */
  OvStorage_RangeReadStrategy_CachedReadThrough = 1,
  /** A range requires materializing the whole object first. */
  OvStorage_RangeReadStrategy_MaterializeOnly = 2,
  /** Random access is not available at any cost. */
  OvStorage_RangeReadStrategy_Unsupported = 3,
} OvStorage_RangeReadStrategy;

typedef enum {
  OvStorage_AuthEventKind_OpenBrowser = 0,
  OvStorage_AuthEventKind_DeviceCode = 1,
  OvStorage_AuthEventKind_Progress = 2,
  OvStorage_AuthEventKind_Succeeded = 3,
  OvStorage_AuthEventKind_Failed = 4,
  OvStorage_AuthEventKind_Cancelled = 5,
} OvStorage_AuthEventKind;

typedef enum {
  OvStorage_ChangeKind_Created = 0,
  OvStorage_ChangeKind_Modified = 1,
  OvStorage_ChangeKind_Deleted = 2,
  OvStorage_ChangeKind_MetadataChanged = 3,
} OvStorage_ChangeKind;

typedef enum {
  OvStorage_BackendChangeEventKind_Object = 0,
  OvStorage_BackendChangeEventKind_Lapsed = 1,
} OvStorage_BackendChangeEventKind;

/**
 * How much interactive-auth machinery the caller can drive, mapped onto
 * the core `InteractiveAuthCapability`.
 */
typedef enum {
  /**
   * No interactive auth (CI / sandboxed): the flow must succeed
   * non-interactively or fail.
   */
  OvStorage_InteractiveAuthCapability_None = 0,
  /**
   * Cross-device flows only (device code), no local redirect listener.
   */
  OvStorage_InteractiveAuthCapability_Headless = 1,
  /**
   * Full browser flow with a local redirect listener.
   */
  OvStorage_InteractiveAuthCapability_Browser = 2,
} OvStorage_InteractiveAuthCapability;

typedef enum {
  OvStorage_AddressVisibility_Visible = 0,
  OvStorage_AddressVisibility_Hidden = 1,
  OvStorage_AddressVisibility_Suppressed = 2,
} OvStorage_AddressVisibility;

typedef enum {
  OvStorage_RouteSourceKind_Static = 0,
  OvStorage_RouteSourceKind_ConnectionContributed = 1,
  OvStorage_RouteSourceKind_BrokerDelivered = 2,
  OvStorage_RouteSourceKind_Alias = 3,
} OvStorage_RouteSourceKind;

typedef enum {
  OvStorage_AliasSourceKind_Static = 0,
  OvStorage_AliasSourceKind_Runtime = 1,
  OvStorage_AliasSourceKind_BrokerDelivered = 2,
} OvStorage_AliasSourceKind;

typedef enum {
  OvStorage_AliasStateKind_Live = 0,
  OvStorage_AliasStateKind_Dangling = 1,
  OvStorage_AliasStateKind_ChainTooLong = 2,
} OvStorage_AliasStateKind;

/** Owned authentication-event snapshot; its active payload is selected by `kind`. */
typedef struct OvStorage_AuthEvent OvStorage_AuthEvent;

typedef struct OvStorage_CancelToken OvStorage_CancelToken;

/**
 * Opaque config-value handle. Built via `ovstorage_config_value_create_*`;
 * freed via `ovstorage_config_value_destroy` (or consumed by
 * `ovstorage_connection_request_add_config`).
 */
typedef struct OvStorage_ConfigValue OvStorage_ConfigValue;

/** Owned immutable connection snapshot. */
typedef struct OvStorage_Connection OvStorage_Connection;

/** Owned list of contiguous borrowed `Connection` items. */
typedef struct OvStorage_ConnectionList OvStorage_ConnectionList;

/**
 * Opaque connection-request builder. Built with
 * `ovstorage_connection_request_create` + per-field setters; consumed
 * by `ovstorage_stack_add_connection` (build-time) or
 * `ovstorage_add_connection` (runtime). Both take the builder through a
 * `OvStorage_ConnectionRequest **` slot and NULL that slot exactly when
 * they take ownership, so the caller always finishes with one
 * unconditional `ovstorage_connection_request_destroy` on whatever the
 * slot still holds.
 */
typedef struct OvStorage_ConnectionRequest OvStorage_ConnectionRequest;

/** Owned immutable object-information snapshot. */
typedef struct OvStorage_Info OvStorage_Info;

/**
 * The kinds a plugin advertises, returned by `ovstorage_inspect_plugin`.
 */
typedef struct OvStorage_KindDescriptorList OvStorage_KindDescriptorList;

/**
 * A built, immutable Stack root plus the runtime its ops dispatch on.
 */
typedef struct OvStorage_LayerHandle OvStorage_LayerHandle;

/** Owned list of contiguous borrowed `Info` items. */
typedef struct OvStorage_List OvStorage_List;

typedef struct OvStorage_LocalDelegate OvStorage_LocalDelegate;

/**
 * A loaded plugin cdylib's factories. Holding this keeps the cdylib
 * mapped; drop it only after the registry and built Stack are done with it.
 */
typedef struct OvStorage_Plugin OvStorage_Plugin;

/**
 * `kind` → factory registry seeded with the built-in factories and
 * extended by `ovstorage_registry_add_plugin`.
 */
typedef struct OvStorage_Registry OvStorage_Registry;

/** Owned immutable address-root snapshot. */
typedef struct OvStorage_RootInfo OvStorage_RootInfo;

/** Owned list of contiguous borrowed `RootInfo` items. */
typedef struct OvStorage_RootInfoList OvStorage_RootInfoList;

/**
 * Opaque secret-bundle handle used by
 * `ovstorage_update_connection_credentials` to refresh an
 * existing connection's credentials.
 *
 * That call takes the bundle through an `OvStorage_SecretBundle **` slot
 * and NULLs the slot exactly when it takes ownership, so the caller
 * always finishes with one unconditional
 * `ovstorage_secret_bundle_destroy` on whatever the slot still holds.
 */
typedef struct OvStorage_SecretBundle OvStorage_SecretBundle;

/**
 * Opaque secret-value handle. Write-only — secrets never flow back
 * out across the C ABI.
 *
 * All `_create_*` constructors copy the input bytes into a host-owned
 * zero-on-drop buffer; the caller may free input pointers as soon as
 * the constructor returns.
 */
typedef struct OvStorage_SecretValue OvStorage_SecretValue;

/**
 * Mutable Stack-builder accumulator. Consumed by `ovstorage_stack_build`.
 */
typedef struct OvStorage_Stack OvStorage_Stack;

typedef struct OvStorage_UpdateMetadataOptions OvStorage_UpdateMetadataOptions;

/** Owned list of contiguous borrowed version `Info` items. */
typedef struct OvStorage_VersionList OvStorage_VersionList;

typedef struct OvStorage_Error {
  OvStorage_Status code;
  char *message;
  /**
   * Stable machine-readable name of the fine-grained error code behind
   * `OvStorage_Error.code` (e.g. `"BrokerUnavailable"`), or NULL when the error
   * carries no code name. Points at a static string owned by the
   * library: it stays valid for the process lifetime, must not be
   * freed, and is read through `ovstorage_error_code_name`.
   */
  const char *code_name;
} OvStorage_Error;

typedef struct OvStorage_InitAuthSubstrateOptions {
  /**
   * Borrowed C-string naming the auth directory to pin. Must not be
   * NULL: pass `options = NULL` to `ovstorage_init_auth_substrate` to
   * request the default (`$OVSTORAGE_AUTH_DIR` or a per-process temp
   * dir) instead. Calling `ovstorage_init_auth_substrate` twice with
   * the same resolved path is a no-op; calling it with a different path
   * returns `OvStorage_Status_Unsupported`.
   */
  const char *auth_dir;
} OvStorage_InitAuthSubstrateOptions;

typedef struct OvStorage_AccessOps {
  bool read;
  bool write;
  bool delete_;
  bool update_metadata;
} OvStorage_AccessOps;

typedef struct OvStorage_AccessDecision {
  bool allowed;
  OvStorage_AccessOps denied_ops;
  char *reason;
} OvStorage_AccessDecision;

typedef struct OvStorage_Bytes {
  const uint8_t *data;
  size_t len;
  void *free_ctx;
} OvStorage_Bytes;

typedef struct OvStorage_StatOptions {
  bool full_metadata;
} OvStorage_StatOptions;

typedef void (*OvStorage_InfoCallback)(OvStorage_Status status,
                                       OvStorage_Info *info,
                                       const OvStorage_Error *error,
                                       void *user_data);

typedef struct OvStorage_ReadOptions {
  bool has_range;
  uint64_t range_start;
  bool has_range_end;
  uint64_t range_end_inclusive;
} OvStorage_ReadOptions;

typedef void (*OvStorage_ReadBytesCallback)(OvStorage_Status status,
                                            OvStorage_Bytes bytes,
                                            OvStorage_Info *info,
                                            const OvStorage_Error *error,
                                            void *user_data);

typedef void (*OvStorage_ReadStreamCallback)(OvStorage_Bytes chunk,
                                             const OvStorage_Error *error,
                                             bool done,
                                             void *user_data);

typedef void (*OvStorage_ReadLocalFileCallback)(OvStorage_Status status,
                                                OvStorage_LocalDelegate *delegate,
                                                const OvStorage_Error *error,
                                                void *user_data);

/**
 * Options common to `ovstorage_write`, `ovstorage_write_stream` and
 * `ovstorage_write_redirect`.
 *
 * `no_overwrite` and `if_match_etag` are the two spellings of a
 * destination precondition and are mutually exclusive: `no_overwrite`
 * means "fail if anything is there", `if_match_etag` means "fail unless
 * what is there is exactly this". Setting both is rejected with
 * `OvStorage_Status_InvalidArgument` rather than given a precedence,
 * because either precedence silently ignores half of what the caller
 * asked for.
 */
typedef struct OvStorage_WriteOptions {
  bool no_overwrite;
  bool has_size_hint;
  uint64_t size_hint;
  /**
   * NUL-terminated etag the destination must currently carry for the
   * write to proceed; NULL for no precondition. The etag is a
   * precondition, never a key: it is compared against whatever is at
   * `address`, and it does not name the object.
   *
   * Must be non-empty and valid UTF-8. An empty string is rejected
   * rather than treated as "no precondition", so a caller that
   * propagates an absent etag from `OvStorage_Info::etag` as `""` gets
   * an error instead of an unconditional overwrite.
   *
   * `supports_if_match_write` in `OvStorage_Capabilities` reports whether
   * a backend evaluates it. The host does not pre-screen on that bit: the
   * precondition is forwarded either way and the backend answers, because
   * capabilities are reported per root and a write may cross a Layer that
   * supplies semantics the backend beneath it lacks.
   */
  const char *if_match_etag;
} OvStorage_WriteOptions;

typedef enum {
  OvStorage_WriteStreamStep_Chunk = 0,
  OvStorage_WriteStreamStep_End = 1,
  OvStorage_WriteStreamStep_Error = 2,
} OvStorage_WriteStreamStep;

typedef enum {
  OvStorage_RedirectBodySourceKind_Empty = 0,
  OvStorage_RedirectBodySourceKind_UserBytes = 1,
  OvStorage_RedirectBodySourceKind_Inline = 2,
} OvStorage_RedirectBodySourceKind;

/**
 * What a redirect's credential authorizes, declared by the backend that
 * minted it.
 *
 * The declaration is the only source of this answer: a signature scoped to
 * one object for five minutes and an account-wide one an operator pasted
 * into config are the same shape on the wire, so no inspection of the URL or
 * the headers recovers the difference. A caller uses the declaration to
 * decide whether the redirect may leave its own process.
 */
typedef enum {
  /**
   * The minting backend does not know — it forwards an opaque credential it
   * did not construct. Callers treat this exactly as
   * `OvStorage_RedirectCredential_Connection`: an undeclared scope is not a
   * narrow one.
   */
  OvStorage_RedirectCredential_Unspecified = 0,
  /**
   * The redirect carries no credential. Its target is fetchable by anyone
   * holding the URL, and handing it on discloses nothing.
   */
  OvStorage_RedirectCredential_None = 1,
  /**
   * The credential authorizes this request and expires with the redirect: it
   * names the object and the method, and outlives neither.
   */
  OvStorage_RedirectCredential_Request = 2,
  /**
   * The credential authorizes the connection at large — objects this
   * redirect does not name, and time beyond its expiry.
   */
  OvStorage_RedirectCredential_Connection = 3,
} OvStorage_RedirectCredential;

typedef struct OvStorage_Header {
  const char *name;
  const char *value;
} OvStorage_Header;

/**
 * One borrowed redirect inside an owned `OvStorage_WriteRedirectBatch`.
 * Every pointer remains valid until the batch is destroyed. Before executing
 * a request, the caller MUST verify that `expires_at_unix_nanos` and
 * `scope_expires_at_unix_nanos` are still fresh, that `url` is under
 * `scope_physical_url_prefix`, that `scope_operations` permits the required
 * operation, and that `body_offset` plus `body_len` is in bounds for the
 * caller's source buffer. Header values are credentials: callers MUST NOT log
 * them or forward them to any destination outside the validated scope.
 *
 * `scope_credential` states how much the credential in those headers
 * authorizes. `OvStorage_RedirectCredential_Connection` and
 * `OvStorage_RedirectCredential_Unspecified` both mean it authorizes more
 * than this one request — other objects, and time beyond
 * `scope_expires_at_unix_nanos` — so a caller that would hand the redirect to
 * a party outside its own process performs the transfer itself instead. Only
 * `OvStorage_RedirectCredential_Request` and
 * `OvStorage_RedirectCredential_None` are safe to delegate, and only while
 * every header on the redirect is one the caller can account for as
 * addressing or conditioning the transfer rather than authorizing it.
 */
typedef struct OvStorage_WriteRedirect {
  const char *method;
  const char *url;
  const OvStorage_Header *headers;
  size_t headers_len;
  OvStorage_RedirectBodySourceKind body_source_kind;
  uint64_t body_offset;
  uint64_t body_len;
  const uint8_t *inline_body;
  size_t inline_body_len;
  const char *const *capture_headers;
  size_t capture_headers_len;
  uint32_t capture_body_max_bytes;
  uint64_t expires_at_unix_nanos;
  const char *scope_physical_url_prefix;
  OvStorage_AccessOps scope_operations;
  uint64_t scope_expires_at_unix_nanos;
  OvStorage_RedirectCredential scope_credential;
  const char *audit_id;
  uint64_t policy_epoch;
} OvStorage_WriteRedirect;

/**
 * Owned write plan returned by `ovstorage_write_redirect` or a redirecting
 * `ovstorage_continue_write` step. Its fields are read-only borrowed views;
 * release the complete object with `ovstorage_write_redirect_batch_destroy`.
 */
typedef struct OvStorage_WriteRedirectBatch {
  const uint8_t *continuation;
  size_t continuation_len;
  OvStorage_WriteRedirect *redirects;
  size_t redirects_len;
} OvStorage_WriteRedirectBatch;

/**
 * Caller-produced HTTP response for one redirect. All pointers are borrowed
 * and copied by `ovstorage_continue_write` before that function returns.
 */
typedef struct OvStorage_RedirectResult {
  uint16_t status_code;
  const OvStorage_Header *captured_headers;
  size_t captured_headers_len;
  const uint8_t *captured_body;
  size_t captured_body_len;
} OvStorage_RedirectResult;

typedef struct OvStorage_RedirectResultBatch {
  const OvStorage_RedirectResult *results;
  size_t results_len;
} OvStorage_RedirectResultBatch;

typedef void (*OvStorage_WriteRedirectCallback)(
    OvStorage_Status status,
    OvStorage_WriteRedirectBatch *redirects,
    const OvStorage_Error *error,
    void *user_data);

/**
 * Completion for `ovstorage_continue_write`. On success exactly one of `info`
 * or `redirects` is non-NULL and owned by the caller.
 */
typedef void (*OvStorage_WriteStepCallback)(
    OvStorage_Status status,
    OvStorage_Info *info,
    OvStorage_WriteRedirectBatch *redirects,
    const OvStorage_Error *error,
    void *user_data);

/**
 * Pull one input chunk for `ovstorage_write_stream`.
 *
 * On `Chunk`, initialize `out_chunk`; the library consumes it with
 * `ovstorage_bytes_destroy` after copying. On `Error`, optionally overwrite
 * `out_status` and set `*out_error_message` to a borrowed C-string valid for
 * this callback. `End` initializes neither output.
 */
typedef OvStorage_WriteStreamStep (*OvStorage_WriteStreamNext)(
    void *state,
    OvStorage_Bytes *out_chunk,
    OvStorage_Status *out_status,
    const char **out_error_message);

typedef void (*OvStorage_WriteStreamDrop)(void *state);

/**
 * Caller-owned pull stream transferred through a writable slot to
 * `ovstorage_write_stream`. Both callbacks must be non-NULL.
 */
typedef struct OvStorage_WriteStream {
  void *state;
  OvStorage_WriteStreamNext next;
  OvStorage_WriteStreamDrop drop;
} OvStorage_WriteStream;

/**
 * Independently optional presentation fields for
 * `ovstorage_update_connection_attributes`. A false `has_*` flag leaves that
 * field unchanged. `user_metadata` is an optional borrowed set/remove patch
 * built with `ovstorage_update_metadata_options_create`; NULL leaves user
 * metadata unchanged.
 */
typedef struct OvStorage_AttributePatch {
  bool has_display_name;
  const char *display_name;
  bool has_access_mode;
  const char *access_mode;
  bool has_visible;
  bool visible;
  const OvStorage_UpdateMetadataOptions *user_metadata;
} OvStorage_AttributePatch;

typedef void (*OvStorage_StatusCallback)(OvStorage_Status status,
                                         const OvStorage_Error *error,
                                         void *user_data);

typedef struct OvStorage_ListOptions {
  bool recursive;
  bool has_max_results;
  uint32_t max_results;
  const char *page_token;
  bool full_metadata;
} OvStorage_ListOptions;

typedef void (*OvStorage_ListCallback)(OvStorage_Status status,
                                       OvStorage_List *list,
                                       const OvStorage_Error *error,
                                       void *user_data);

typedef struct OvStorage_ListVersionsOptions {
  bool has_max_results;
  uint32_t max_results;
  const char *page_token;
} OvStorage_ListVersionsOptions;

typedef struct OvStorage_WatchDirectoryOptions {
  bool recursive;
  bool include_metadata_changes;
  /** A resume cursor. NULL with `has_since == false` is a fresh subscription. */
  const uint8_t *since;
  size_t since_len;
  /**
   * Resume from `since` even when `since_len` is zero.
   *
   * A backend may mint a zero-length cursor, and length alone cannot
   * tell that apart from having no cursor at all — so without this flag
   * a caller handed one replays the entire change history instead of
   * resuming. A cursor with `since_len != 0` resumes whether or not this
   * flag is set, so a caller that predates the flag keeps its behaviour.
   */
  bool has_since;
  /** Poll cadence in milliseconds; zero selects the 1000 ms default. */
  uint64_t poll_interval_ms;
} OvStorage_WatchDirectoryOptions;

/**
 * Borrowed view delivered by `OvStorage_WatchDirectoryCallback`. Strings and
 * cursor bytes remain valid only for the duration of that callback.
 */
typedef struct OvStorage_BackendChangeEvent {
  OvStorage_BackendChangeEventKind kind;
  const char *address;
  OvStorage_ChangeKind change_kind;
  const char *etag;
  const char *version;
  bool has_size;
  uint64_t size;
  bool has_mtime_unix_nanos;
  uint64_t mtime_unix_nanos;
  uint64_t at_unix_nanos;
  bool has_since_unix_nanos;
  uint64_t since_unix_nanos;
  const uint8_t *cursor;
  size_t cursor_len;
} OvStorage_BackendChangeEvent;

/**
 * Multi-fire callback for `ovstorage_watch_directory`.
 *
 * Event fire: `event != NULL`, `error == NULL`, `done == false`. The event is
 * borrowed and valid only during the callback. Terminal success:
 * `event == NULL`, `error == NULL`, `done == true`. Terminal failure:
 * `event == NULL`, `error != NULL`, `done == true`.
 */
typedef void (*OvStorage_WatchDirectoryCallback)(
    const OvStorage_BackendChangeEvent *event,
    const OvStorage_Error *error,
    bool done,
    void *user_data);

typedef void (*OvStorage_ListVersionsCallback)(OvStorage_Status status,
                                               OvStorage_VersionList *list,
                                               const OvStorage_Error *error,
                                               void *user_data);

typedef void (*OvStorage_CheckAccessCallback)(OvStorage_Status status,
                                              OvStorage_AccessDecision decision,
                                              const OvStorage_Error *error,
                                              void *user_data);

/**
 * Options for `ovstorage_stack_build`. `runtime_threads == 0` selects the
 * default: `OVSTORAGE_C_RUNTIME_THREADS` if set, else available parallelism
 * clamped to [2,32]. It sizes the process-global runtime built on the first
 * `stack_build` and is ignored on later calls (a later build that requests a
 * different non-zero count logs a warning to stderr).
 */
typedef struct OvStorage_StackBuildOptions {
  uint32_t runtime_threads;
} OvStorage_StackBuildOptions;

/**
 * Delivers a built root `LayerHandle` on success from
 * `ovstorage_stack_build_async`. The caller owns the handle on `Ok` and
 * frees it with `ovstorage_layer_handle_destroy`. On error or cancellation
 * `handle == NULL` and the Stack builder is left intact and reusable.
 */
typedef void (*OvStorage_StackBuildCallback)(OvStorage_Status status,
                                             OvStorage_LayerHandle *handle,
                                             const OvStorage_Error *error,
                                             void *user_data);

typedef struct OvStorage_ChangeKindSet {
  bool created;
  bool modified;
  bool deleted;
  bool metadata_changed;
} OvStorage_ChangeKindSet;

/**
 * Flat capabilities struct. Caller stack-allocates one and passes a
 * `*mut` to a getter, which overwrites every field.
 */
typedef struct OvStorage_Capabilities {
  bool supports_if_match_write;
  bool supports_no_overwrite_write;
  bool supports_native_metadata_patch;
  bool supports_metadata_rewrite_emulation;
  bool writes_are_atomic;
  bool supports_copy;
  bool supports_rename;
  bool supports_server_side_copy;
  bool supports_server_side_rename;
  bool supports_atomic_rename;
  bool has_real_directories;
  /** Availability: `ovstorage_write` can be attempted. */
  bool supports_write;
  /** Availability: `ovstorage_write_stream` can be attempted. */
  bool supports_write_stream;
  /** Availability: `ovstorage_write_redirect` can be attempted. */
  bool supports_write_redirect;
  /** Availability: `ovstorage_delete` can be attempted. */
  bool supports_delete;
  bool supports_list;
  bool wants_list_backed_stat;
  bool supports_recursive_list;
  bool populates_subdirectory_metadata;
  /** Availability: `ovstorage_create_directory` can be attempted. */
  bool supports_create_directory;
  /** Availability: `ovstorage_delete_directory` can be attempted. */
  bool supports_delete_directory;
  bool supports_version_listing;
  bool has_version_list_order;
  OvStorage_VersionListOrder version_list_order;
  bool populates_effective_permissions_on_stat;
  bool supports_access_check;
  bool supports_watch_directory;
  OvStorage_ChangeKindSet watch_directory_kinds;
  bool watch_directory_resumable;
  bool has_watch_directory_max_lag;
  uint64_t watch_directory_max_lag_nanos;
  bool has_redirect_size_threshold;
  uint64_t redirect_size_threshold;
} OvStorage_Capabilities;

/**
 * One NUL-terminated metadata key/value pair.
 *
 * Both pointers are borrowed from the snapshot that carries this entry and
 * remain valid only until that snapshot is destroyed.
 */
typedef struct OvStorage_MetadataEntry {
  const char *key;
  const char *value;
} OvStorage_MetadataEntry;

/**
 * One `(algorithm, bytes)` checksum a backend reported for an object.
 *
 * `algorithm` is a normalized NUL-terminated token such as `"sha256"` or
 * `"crc32c"`. `bytes` is the raw digest, not a hex or base64 rendering,
 * and is not NUL-terminated. Both are borrowed from the snapshot that
 * carries this entry and remain valid only until that snapshot is
 * destroyed.
 */
typedef struct OvStorage_ChecksumEntry {
  const char *algorithm;
  const uint8_t *bytes;
  size_t bytes_len;
} OvStorage_ChecksumEntry;

/**
 * Immutable object-information snapshot.
 *
 * The library allocates and populates this struct. Every pointer field is
 * borrowed from it: callers read fields directly, do not modify or free them,
 * and destroy only independently owned snapshots with
 * `ovstorage_info_destroy`.
 */
struct OvStorage_Info {
  const char *address;
  OvStorage_ObjectKind kind;
  bool has_size;
  uint64_t size;
  bool has_mtime_unix_nanos;
  uint64_t mtime_unix_nanos;
  const char *etag;    /* NULL when absent. */
  const char *version; /* NULL when absent. */
  const OvStorage_MetadataEntry *user_metadata;
  size_t user_metadata_len;
  const OvStorage_MetadataEntry *system_metadata;
  size_t system_metadata_len;
  /**
   * Principal that last modified the object, as the backend names it;
   * NULL when the backend does not report one.
   */
  const char *modified_by;
  /**
   * Checksums the backend reported. `checksums_len == 0` means the
   * backend reported none, which is not a claim that the object has no
   * checksum — only that this answer does not carry one.
   */
  const OvStorage_ChecksumEntry *checksums;
  size_t checksums_len;
  /**
   * The caller's permissions on this object, populated only by backends
   * whose `populates_effective_permissions_on_stat` capability is true.
   * `has_effective_permissions == false` means "not reported", which is
   * distinct from "reported as none permitted".
   */
  bool has_effective_permissions;
  OvStorage_AccessOps effective_permissions;
};

/**
 * Immutable list snapshot. `items` points to `len` contiguous borrowed
 * entries. Neither an item nor any field reached through one may be destroyed
 * independently of the list.
 */
struct OvStorage_List {
  const OvStorage_Info *items;
  size_t len;
  const char *next_page_token; /* NULL when absent. */
};

/** Version-list counterpart of `OvStorage_List`. */
struct OvStorage_VersionList {
  const OvStorage_Info *items;
  size_t len;
  const char *next_page_token; /* NULL when absent. */
};

/**
 * Immutable connection snapshot.
 *
 * All four `auth_state_kind` variants are reachable: the kind is carried
 * through from the plugin unchanged. The `source_*` payload fields are
 * meaningful only when `source_kind` selects their matching variant, and may
 * be populated while inactive. The same holds for the auth-state payloads:
 * `authenticated_*` for `Authenticated`, `awaiting_auth_*` for `AwaitingAuth`,
 * `auth_failed_*` for `AuthFailed`. `Anonymous` carries no payload.
 */
struct OvStorage_Connection {
  const char *id;
  const char *backend_kind;
  const char *display_name; /* NULL when absent. */
  OvStorage_Capabilities capabilities;
  const char *const *addresses;
  size_t addresses_len;
  const OvStorage_MetadataEntry *user_metadata;
  size_t user_metadata_len;
  bool has_last_probed;
  uint64_t last_probed_unix_nanos;
  OvStorage_ConnectionSourceKind source_kind;
  OvStorage_ConfigLayer source_static_layer;
  bool source_runtime_persisted;
  const char *source_broker_principal; /* NULL when absent. */
  OvStorage_ConnectionAuthStateKind auth_state_kind;
  uint32_t auth_failed_attempts;
  const char *auth_failed_message; /* NULL when absent. */
  /**
   * `AuthFailed` payload: the backend's own classification of the failure,
   * mapped onto the coarse status. A permanent rejection reports
   * `OvStorage_Status_PermissionDenied` and a broker outage reports
   * `OvStorage_Status_Transient`, so the two are distinguishable without
   * parsing `auth_failed_message`. `auth_failed_code_name` is the
   * fine-grained plugin error-code name behind that status (for one,
   * `"CredentialExpired"` and `"AuthRequired"` both map to
   * `PermissionDenied`); it is a static string that is never freed.
   */
  OvStorage_Status auth_failed_code;
  const char *auth_failed_code_name; /* NULL when absent. */
  /** `Authenticated` payload: when the connection last authenticated. */
  bool has_authenticated_at;
  uint64_t authenticated_at_unix_nanos;
  /**
   * `Authenticated` payload: when the current credential expires, when
   * the backend reports one. This is what a caller needs to refresh
   * before an operation fails rather than after.
   */
  bool has_authenticated_expires_at;
  uint64_t authenticated_expires_at_unix_nanos;
  /** `AwaitingAuth` payload: why authentication is pending. */
  OvStorage_AuthReason awaiting_auth_reason;
  /**
   * `AwaitingAuth` payload: free-form detail, non-NULL only when
   * `awaiting_auth_reason` is `OvStorage_AuthReason_Unknown`.
   */
  const char *awaiting_auth_unknown_details; /* NULL when absent. */
};

/** Connection-list counterpart of `OvStorage_List`, without pagination. */
struct OvStorage_ConnectionList {
  const OvStorage_Connection *items;
  size_t len;
};

/**
 * Immutable tagged authentication-event snapshot.
 *
 * Read only the member selected by `kind`. Reading an inactive union member is
 * undefined behaviour. The nested `Succeeded` connection is borrowed from the
 * event and must not be destroyed independently.
 */
struct OvStorage_AuthEvent {
  OvStorage_AuthEventKind kind;
  union {
    struct {
      const char *url;
      uint64_t expires_at_unix_nanos;
    } open_browser;
    struct {
      const char *user_code;
      const char *verification_url;
      uint64_t expires_at_unix_nanos;
      uint64_t interval_nanos;
    } device_code;
    struct {
      const char *message;
    } progress;
    struct {
      const OvStorage_Connection *connection;
    } succeeded;
    struct {
      OvStorage_Status code;
      const char *message;
      /**
       * Fine-grained plugin error-code name behind `code`, matching
       * `ovstorage_error_code_name`'s vocabulary. The coarse status folds
       * an expired credential, a revoked one and a broker outage that
       * never reached the identity provider onto neighbouring buckets;
       * this names which it was. A static string that is never freed;
       * NULL when the plugin reported no code.
       */
      const char *code_name;
    } failed;
  } as;
};

/**
 * Immutable address-root snapshot.
 *
 * The `source_*` payload fields are meaningful only when `source_kind`
 * selects their matching variant, and may be populated while inactive.
 * Alias-source payloads are meaningful only for `Alias`, then only when
 * `source_alias_source_kind` selects their matching variant. Alias-state
 * fields are gated by `has_alias_state`; the reason is meaningful only for
 * `ChainTooLong`.
 */
struct OvStorage_RootInfo {
  const char *root;
  const char *layer_kind;
  const char *display_name; /* NULL when absent. */
  bool has_connection_id;
  const char *connection_id; /* NULL when absent. */
  bool visible;
  OvStorage_AddressVisibility visibility;
  OvStorage_Capabilities capabilities;
  OvStorage_RouteSourceKind source_kind;
  OvStorage_ConfigLayer source_static_layer;
  const char *source_connection_id; /* NULL when absent. */
  const char *source_broker_principal; /* NULL when absent. */
  const char *source_alias_to; /* NULL when absent. */
  OvStorage_AliasSourceKind source_alias_source_kind;
  OvStorage_ConfigLayer source_alias_source_static_layer;
  bool source_alias_source_runtime_persisted;
  const char *source_alias_source_broker_principal; /* NULL when absent. */
  bool has_alias_state;
  OvStorage_AliasStateKind alias_state_kind;
  const char *alias_state_chain_too_long_reason; /* NULL when absent. */
  const OvStorage_MetadataEntry *user_metadata;
  size_t user_metadata_len;
  bool has_icon;
  const uint8_t *icon;
  size_t icon_len;
  /**
   * Instance name of the Layer that owns connections for this root — the
   * `target` argument `ovstorage_authenticate`,
   * `ovstorage_update_connection_credentials` and
   * `ovstorage_remove_connection` route by.
   *
   * It is reported here because it is not derivable from `root`: a
   * composite plugin's internal owning backend has a different name from
   * the outer root, and the resolution that knows the difference is
   * host-side. NULL when the Layer reports none, in which case there is
   * no connection op to address.
   */
  const char *owning_target; /* NULL when absent. */
  /**
   * What a range read against this root actually costs. A caller
   * deciding between `ovstorage_read_bytes` with a window and
   * `ovstorage_read_local_file` needs this: `MaterializeOnly` means a
   * one-kilobyte window pulls the whole object.
   */
  OvStorage_RangeReadStrategy range_read_strategy;
};

/** Address-root-list counterpart of `OvStorage_List`, without pagination. */
struct OvStorage_RootInfoList {
  const OvStorage_RootInfo *items;
  size_t len;
};

/**
 * Delivers a single owned `Connection` on success. The caller owns the
 * handle on `Ok` and frees it with `ovstorage_connection_destroy`.
 */
typedef void (*OvStorage_ConnectionCallback)(OvStorage_Status status,
                                             OvStorage_Connection *connection,
                                             const OvStorage_Error *error,
                                             void *user_data);

/**
 * Delivers an owned `ConnectionList` snapshot on success. The caller
 * owns the handle on `Ok` and frees it with
 * `ovstorage_connection_list_destroy`.
 */
typedef void (*OvStorage_ConnectionListCallback)(OvStorage_Status status,
                                                 OvStorage_ConnectionList *list,
                                                 const OvStorage_Error *error,
                                                 void *user_data);

/**
 * Multi-fire callback for `ovstorage_authenticate_connection`.
 *
 * Per-event fire: `event != NULL`, `error == NULL`, `done == false`;
 * the caller owns `event` and must free it with
 * `ovstorage_auth_event_destroy`.
 * Final fire on success: `event == NULL`, `error == NULL`, `done == true`.
 * Final fire on terminal error: `event == NULL`, `error != NULL`,
 * `done == true`; the host frees the error message after the callback
 * returns.
 */
typedef void (*OvStorage_AuthEventCallback)(OvStorage_AuthEvent *event,
                                            const OvStorage_Error *error,
                                            bool done,
                                            void *user_data);

/**
 * Delivers an owned `RootInfoList` snapshot on success. The caller owns
 * the handle on `Ok` and frees it with `ovstorage_root_info_list_destroy`.
 */
typedef void (*OvStorage_RootInfoListCallback)(OvStorage_Status status,
                                               OvStorage_RootInfoList *list,
                                               const OvStorage_Error *error,
                                               void *user_data);

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Free the heap `message` carried by `error` (if any) and reset the
 * struct to the `Ok`/empty state, ready to receive a later call's error.
 *
 * # Safety
 *
 * `error` must be NULL (a no-op) or point to a valid `OvStorage_Error`
 * that is either zero-initialized or was last written by this library;
 * its `message` is freed here, so a stale or caller-fabricated pointer
 * is undefined behavior. Pointers previously returned by
 * `ovstorage_error_message` dangle afterwards. No other thread may
 * access `*error` during the call.
 */
void ovstorage_error_clear(OvStorage_Error *error);

/**
 * Borrowed failure message carried by `error`, or NULL when `error` is
 * NULL or carries none. Owned by `error`: valid until
 * `ovstorage_error_clear` runs on it or a later call overwrites it;
 * do not free.
 *
 * # Safety
 *
 * `error` must be NULL or a valid `OvStorage_Error*`.
 */
const char *ovstorage_error_message(const OvStorage_Error *error);

/**
 * Stable machine-readable name of the fine-grained error code carried by
 * `error` (e.g. `"BrokerUnavailable"` for a broker outage surfaced as
 * `OvStorage_Status_Transient`). Returns NULL when `error` is NULL or carries no
 * code name. The returned pointer is a static string owned by the
 * library: it stays valid for the process lifetime, must not be freed,
 * and outlives `ovstorage_error_clear` on `error`.
 *
 * # Safety
 *
 * `error` must be NULL or a valid `OvStorage_Error*`.
 */
const char *ovstorage_error_code_name(const OvStorage_Error *error);

/**
 * Whether a blind retry of the operation that produced `status` might
 * succeed. Exactly `OvStorage_Status_Transient` and `OvStorage_Status_ResourceExhausted`
 * are retryable; every other value — including status values appended by
 * a newer library — reports `false`, matching the unknown-status
 * Internal-equivalent rule documented on `OvStorage_Status`.
 *
 * # Safety
 *
 * `status` must be an `OvStorage_Status` value produced by this library
 * (any declared discriminant; arbitrary integers are not valid input).
 */
bool ovstorage_status_is_retryable(OvStorage_Status status);

/**
 * Explicitly initialize the process-global auth substrate.
 *
 * The plugin SPI's host callbacks are set-once-per-process (see the
 * loader comment in `ovstorage::loader::register_host_substrate`), so
 * the `(SecretStore, AuthRefreshLock)` pair is shared across every Stack
 * and plugin load in one process. This function lets callers pin a
 * non-default `auth_dir` before any plugin is loaded.
 *
 * `options = NULL` uses the default `auth_dir` (resolved from
 * `$OVSTORAGE_AUTH_DIR` or a per-process temp dir). Calling this
 * twice with the same resolved path is a no-op; calling it with a
 * different path returns `OvStorage_Status_Unsupported`. `ovstorage_load_plugin`
 * auto-initializes the substrate with the default `auth_dir` if this was
 * not called first.
 *
 * Pinning is one-shot and process-global, so a non-NULL `options` must
 * name a directory: `options->auth_dir == NULL` returns
 * `OvStorage_Status_InvalidArgument` rather than quietly pinning the default and
 * making a later explicit call fail with `OvStorage_Status_Unsupported`. Pass
 * `options = NULL` to ask for the default.
 *
 * # Safety
 *
 * `options` must be NULL or point to a valid
 * `OvStorage_InitAuthSubstrateOptions` whose `auth_dir` is a
 * NUL-terminated UTF-8 string that stays valid for the duration of the
 * call (it is copied, not retained). `out_error` must be NULL or a valid
 * `OvStorage_Error*`.
 */
OvStorage_Status ovstorage_init_auth_substrate(const OvStorage_InitAuthSubstrateOptions *options,
                                               OvStorage_Error *out_error);

/**
 * Create a cancel token to hand to the async ops that accept one.
 *
 * # Safety
 *
 * No preconditions. The returned token is owned by the caller and must
 * be freed exactly once with `ovstorage_cancel_token_destroy`.
 */
OvStorage_CancelToken *ovstorage_cancel_token_create(void);

/**
 * # Safety
 *
 * `token` must be NULL (a no-op) or a pointer from
 * `ovstorage_cancel_token_create` not yet destroyed; it is freed here
 * and must not be used afterwards. Each async op clones the underlying
 * token during the call that receives it, so in-flight operations do
 * not need `token` to stay alive — but no thread may still be inside a
 * call that was passed `token` when it is destroyed.
 */
void ovstorage_cancel_token_destroy(OvStorage_CancelToken *token);

/**
 * Request cancellation: every pending and future operation handed this
 * token completes with `OvStorage_Status_Cancelled`.
 *
 * # Safety
 *
 * `token` must be NULL (a no-op) or a live pointer from
 * `ovstorage_cancel_token_create`. Callable from any thread,
 * concurrently with the operations observing the token.
 */
void ovstorage_cancel_token_cancel(const OvStorage_CancelToken *token);

/**
 * Whether `ovstorage_cancel_token_cancel` has run on `token`;
 * `false` when `token` is NULL.
 *
 * # Safety
 *
 * `token` must be NULL or a live pointer from
 * `ovstorage_cancel_token_create`. Callable from any thread.
 */
bool ovstorage_cancel_token_is_canceled(const OvStorage_CancelToken *token);

/**
 * Create an empty set/remove metadata edit list for
 * `ovstorage_update_metadata`.
 *
 * # Safety
 *
 * No preconditions. The returned handle is owned by the caller and must
 * be freed exactly once with
 * `ovstorage_update_metadata_options_destroy`.
 * `ovstorage_update_metadata` borrows it (the edits are copied during
 * the call), so the caller still frees it afterwards.
 */
OvStorage_UpdateMetadataOptions *ovstorage_update_metadata_options_create(void);

/**
 * # Safety
 *
 * `options` must be NULL (a no-op) or a pointer from
 * `ovstorage_update_metadata_options_create` not yet destroyed; it is
 * freed here and must not be used afterwards.
 */
void ovstorage_update_metadata_options_destroy(OvStorage_UpdateMetadataOptions *options);

/**
 * Record a `key = value` metadata upsert in `options`.
 *
 * # Safety
 *
 * `options` must be a live pointer from
 * `ovstorage_update_metadata_options_create` with no concurrent
 * access. `key` and `value` must be NUL-terminated UTF-8 strings valid
 * for the duration of the call (they are copied). `out_error` must be
 * NULL or a valid `OvStorage_Error*`.
 */
OvStorage_Status ovstorage_update_metadata_options_set(OvStorage_UpdateMetadataOptions *options,
                                                       const char *key,
                                                       const char *value,
                                                       OvStorage_Error *out_error);

/**
 * Record the removal of metadata key `key` in `options`.
 *
 * # Safety
 *
 * `options` must be a live pointer from
 * `ovstorage_update_metadata_options_create` with no concurrent
 * access. `key` must be a NUL-terminated UTF-8 string valid for the
 * duration of the call (it is copied). `out_error` must be NULL or a
 * valid `OvStorage_Error*`.
 */
OvStorage_Status ovstorage_update_metadata_options_remove(OvStorage_UpdateMetadataOptions *options,
                                                          const char *key,
                                                          OvStorage_Error *out_error);

/**
 * Free the heap `reason` carried by `decision` (if any) and reset the
 * field to NULL.
 *
 * # Safety
 *
 * `decision` must be NULL (a no-op) or point to a valid
 * `OvStorage_AccessDecision` whose `reason` is NULL or the exact
 * pointer a check-access callback delivered, not yet freed. No other
 * thread may access `*decision` during the call.
 */
void ovstorage_access_decision_clear(OvStorage_AccessDecision *decision);

/**
 * Release the buffer behind a `Bytes` value delivered by a read
 * callback and reset it to empty; a second call on the reset value is
 * a no-op.
 *
 * # Safety
 *
 * `bytes` must be NULL (a no-op) or point to a `Bytes` value produced
 * by this library with its `data`/`len`/`free_ctx` fields unmodified.
 * `data` dangles after the call. No other thread may access `*bytes`
 * during the call.
 */
void ovstorage_bytes_destroy(OvStorage_Bytes *bytes);

/**
 * Destroy an owned redirect batch returned by a write callback.
 *
 * # Safety
 *
 * `batch` must be NULL (a no-op) or an unmodified batch returned by this
 * library and not yet destroyed. Every borrowed pointer within it dangles
 * afterwards.
 */
void ovstorage_write_redirect_batch_destroy(OvStorage_WriteRedirectBatch *batch);

/**
 * # Safety
 *
 * `info` must be NULL (a no-op) or an independently owned
 * `OvStorage_Info*` delivered through a callback or returned by
 * `ovstorage_info_clone`, not yet destroyed. Do not pass a list item or
 * the borrowed pointer returned by `ovstorage_local_delegate_info`.
 */
void ovstorage_info_destroy(OvStorage_Info *info);

/**
 * Deep-copy one object-information snapshot.
 *
 * # Safety
 *
 * `info` must be NULL or point to a valid snapshot. Returns NULL for a
 * NULL input or allocation failure; otherwise the caller owns the result
 * and destroys it with `ovstorage_info_destroy`.
 */
OvStorage_Info *ovstorage_info_clone(const OvStorage_Info *info);

/**
 * # Safety
 *
 * `delegate` must be NULL (a no-op) or an owned
 * `OvStorage_LocalDelegate*` delivered by a read-local-file callback,
 * not yet destroyed; it is freed here. The borrowed pointers returned
 * by `ovstorage_local_delegate_path` and
 * `ovstorage_local_delegate_info` dangle afterwards.
 */
void ovstorage_local_delegate_destroy(OvStorage_LocalDelegate *delegate);

/**
 * Borrowed local filesystem path of the delegated object; NULL if
 * `delegate` is NULL. Owned by `delegate`: valid until it is
 * destroyed; do not free.
 *
 * # Safety
 *
 * `delegate` must be NULL or a valid `OvStorage_LocalDelegate*`.
 */
const char *ovstorage_local_delegate_path(const OvStorage_LocalDelegate *delegate);

/**
 * Borrowed `OvStorage_Info*` describing the delegated object; NULL if
 * `delegate` is NULL. Owned by `delegate`: valid until it is destroyed
 * and must NOT be passed to `ovstorage_info_destroy`.
 *
 * # Safety
 *
 * `delegate` must be NULL or a valid `OvStorage_LocalDelegate*`.
 */
const OvStorage_Info *ovstorage_local_delegate_info(const OvStorage_LocalDelegate *delegate);

/**
 * # Safety
 *
 * `list` must be NULL (a no-op) or an owned `OvStorage_List*`
 * delivered by a list callback, not yet destroyed; it is freed here.
 * Every borrowed field and item pointer within the list dangles afterwards.
 */
void ovstorage_list_destroy(OvStorage_List *list);

/**
 * # Safety
 *
 * `list` must be NULL (a no-op) or an owned `OvStorage_VersionList*`
 * delivered by a list-versions callback, not yet destroyed. Every borrowed
 * field and item pointer within the list dangles afterwards.
 */
void ovstorage_version_list_destroy(OvStorage_VersionList *list);

/**
 * # Safety
 *
 * `value` must be a NUL-terminated UTF-8 C-string valid for the duration
 * of the call (it is copied), or NULL. Returns an owned `*mut ConfigValue`
 * the caller frees exactly once with `ovstorage_config_value_destroy`,
 * or NULL if `value` is NULL or contains non-UTF-8 bytes.
 */
OvStorage_ConfigValue *ovstorage_config_value_create_string(const char *value);

/**
 * # Safety
 *
 * No preconditions. Returns an owned `*mut ConfigValue` the caller frees
 * exactly once with `ovstorage_config_value_destroy`.
 */
OvStorage_ConfigValue *ovstorage_config_value_create_int(int64_t value);

/**
 * # Safety
 *
 * No preconditions. Returns an owned `*mut ConfigValue` the caller frees
 * exactly once with `ovstorage_config_value_destroy`.
 */
OvStorage_ConfigValue *ovstorage_config_value_create_bool(bool value);

/**
 * Build a Toml-variant `ConfigValue` from a TOML-formatted string.
 * Carries nested tables / arrays of tables across the ABI.
 *
 * # Safety
 *
 * `toml` must be a NUL-terminated UTF-8 C-string valid for the duration
 * of the call (it is copied), or NULL. Returns an owned `*mut ConfigValue`
 * the caller frees exactly once with `ovstorage_config_value_destroy`,
 * or NULL if `toml` is NULL or contains non-UTF-8 bytes.
 */
OvStorage_ConfigValue *ovstorage_config_value_create_toml(const char *toml);

/**
 * # Safety
 *
 * `value` must be NULL (a no-op) or a pointer from a create function
 * not yet destroyed. It is freed here and must not be used afterwards.
 */
void ovstorage_config_value_destroy(OvStorage_ConfigValue *value);

/**
 * # Safety
 *
 * `value` must be NULL or a valid `*const ConfigValue`. Returns
 * `ConfigValueKind::String` if `value` is NULL or the handle was already
 * consumed; otherwise returns the stored variant.
 */
OvStorage_ConfigValueKind ovstorage_config_value_kind(const OvStorage_ConfigValue *value);

/**
 * Returns a borrowed `*const c_char` that is valid until the handle
 * is destroyed. Returns null if the variant is not String or the
 * handle is null.
 *
 * # Safety
 *
 * `value` must be NULL or a valid `*const ConfigValue`.
 */
const char *ovstorage_config_value_as_string(const OvStorage_ConfigValue *value);

/**
 * Returns the inner i64. Returns 0 if the variant is not Int or the
 * handle is null.
 *
 * # Safety
 *
 * `value` must be NULL or a valid `*const ConfigValue`.
 */
int64_t ovstorage_config_value_as_int(const OvStorage_ConfigValue *value);

/**
 * Returns the inner bool. Returns false if the variant is not Bool
 * or the handle is null.
 *
 * # Safety
 *
 * `value` must be NULL or a valid `*const ConfigValue`.
 */
bool ovstorage_config_value_as_bool(const OvStorage_ConfigValue *value);

/**
 * Returns a borrowed `*const c_char` pointing at the reserialized TOML
 * payload, valid until the handle is destroyed. Returns null if the
 * variant is not Toml or the handle is null.
 *
 * # Safety
 *
 * `value` must be NULL or a valid `*const ConfigValue`.
 */
const char *ovstorage_config_value_as_toml(const OvStorage_ConfigValue *value);

/**
 * # Safety
 *
 * `data` must either be NULL (equivalent to zero-length input) or point
 * to readable bytes for the range [0, len). If `data` is non-NULL, the
 * caller may free it immediately upon return (the bytes are copied).
 * Returns an owned `*mut SecretValue` the caller frees exactly once with
 * `ovstorage_secret_value_destroy`.
 */
OvStorage_SecretValue *ovstorage_secret_value_create_bytes(const uint8_t *data, size_t len);

/**
 * # Safety
 *
 * `data` must either be NULL (equivalent to zero-length input) or point
 * to readable bytes for the range [0, len). If `data` is non-NULL, the
 * caller may free it immediately upon return (the bytes are copied).
 * Returns an owned `*mut SecretValue` the caller frees exactly once with
 * `ovstorage_secret_value_destroy`.
 */
OvStorage_SecretValue *ovstorage_secret_value_create_file(const uint8_t *data, size_t len);

/**
 * # Safety
 *
 * `token` must either be NULL or point to readable bytes for the range
 * [0, token_len); `refresh` must either be NULL or point to readable
 * bytes for [0, refresh_len). Both are copied; the caller may free them
 * immediately upon return. `has_refresh` and `has_expires_at` control
 * which of the optional fields are populated; the corresponding values
 * are interpreted only when these flags are true. Returns an owned
 * `*mut SecretValue` the caller frees exactly once with
 * `ovstorage_secret_value_destroy`.
 */
OvStorage_SecretValue *ovstorage_secret_value_create_oauth_token(const uint8_t *token,
                                                                 size_t token_len,
                                                                 const uint8_t *refresh,
                                                                 size_t refresh_len,
                                                                 bool has_refresh,
                                                                 uint64_t expires_at_unix_nanos,
                                                                 bool has_expires_at);

/**
 * # Safety
 *
 * `cert_pem` must either be NULL or point to readable bytes for the range
 * [0, cert_len); `key_pem` must either be NULL or point to readable bytes
 * for [0, key_len). Both are copied; the caller may free them immediately
 * upon return. Returns an owned `*mut SecretValue` the caller frees
 * exactly once with `ovstorage_secret_value_destroy`.
 */
OvStorage_SecretValue *ovstorage_secret_value_create_mtls_cert_pair(const uint8_t *cert_pem,
                                                                    size_t cert_len,
                                                                    const uint8_t *key_pem,
                                                                    size_t key_len);

/**
 * # Safety
 *
 * No preconditions. Returns an owned `*mut SecretValue` the caller frees
 * exactly once with `ovstorage_secret_value_destroy`.
 */
OvStorage_SecretValue *ovstorage_secret_value_create_system_identity(void);

/**
 * # Safety
 *
 * `value` must be NULL (a no-op) or a pointer from a create function
 * not yet destroyed. It is freed here and must not be used afterwards.
 */
void ovstorage_secret_value_destroy(OvStorage_SecretValue *value);

/**
 * # Safety
 *
 * `backend_kind` must be a NUL-terminated UTF-8 C-string valid for the
 * duration of the call (it is copied), or NULL. Returns an owned
 * `*mut ConnectionRequest` the caller frees exactly once with
 * `ovstorage_connection_request_destroy`, or NULL if `backend_kind` is
 * NULL or contains non-UTF-8 bytes.
 */
OvStorage_ConnectionRequest *ovstorage_connection_request_create(const char *backend_kind);

/**
 * # Safety
 *
 * `request` must be NULL (a no-op) or a pointer from
 * `ovstorage_connection_request_create` not yet destroyed, or not yet
 * consumed by `ovstorage_stack_add_connection` or
 * `ovstorage_add_connection`. Passing the value those two leave in their
 * slot is always correct: NULL when they took the builder, the builder
 * itself when they did not. It is freed here and must not be used
 * afterwards.
 */
void ovstorage_connection_request_destroy(OvStorage_ConnectionRequest *request);

/**
 * Set the request's display name. Pass `NULL` to clear.
 *
 * # Safety
 *
 * `request` must be NULL (a no-op) or a valid `*mut ConnectionRequest`
 * not yet consumed. `display_name` must be NULL or a NUL-terminated
 * UTF-8 C-string valid for the duration of the call (it is copied).
 * Non-UTF-8 strings are silently ignored.
 */
void ovstorage_connection_request_set_display_name(OvStorage_ConnectionRequest *request,
                                                   const char *display_name);

/**
 * # Safety
 *
 * `request` must be NULL (a no-op) or a valid `*mut ConnectionRequest`
 * not yet consumed.
 */
void ovstorage_connection_request_set_persist(OvStorage_ConnectionRequest *request, bool persist);

/**
 * Add a config entry to the request. On success, the request takes
 * ownership of `value` and the caller's `*value` is invalidated. On
 * failure (null arg, non-UTF-8 key, request already consumed), the
 * caller still owns `value` and must `_destroy` it.
 *
 * Returns `true` on success, `false` on error.
 *
 * # Safety
 *
 * `request` must be NULL or a valid `*mut ConnectionRequest` not yet
 * consumed. `key` must be a NUL-terminated UTF-8 C-string valid for the
 * duration of the call (it is copied). `value` must be NULL or a valid
 * `*mut ConfigValue` from a create function; on any return the pointer
 * must not be reused. Ownership is transferred to the request on success
 * only.
 */
bool ovstorage_connection_request_add_config(OvStorage_ConnectionRequest *request,
                                             const char *key,
                                             OvStorage_ConfigValue *value);

/**
 * Add a credential entry to the request. On success, the request
 * takes ownership of `value` and the caller's `*value` is invalidated.
 * On failure (null arg, non-UTF-8 key, request already consumed), the
 * caller still owns `value` and must `_destroy` it.
 *
 * Returns `true` on success, `false` on error.
 *
 * # Safety
 *
 * `request` must be NULL or a valid `*mut ConnectionRequest` not yet
 * consumed. `key` must be a NUL-terminated UTF-8 C-string valid for the
 * duration of the call (it is copied). `value` must be NULL or a valid
 * `*mut SecretValue` from a create function; on any return the pointer
 * must not be reused. Ownership is transferred to the request on success
 * only.
 */
bool ovstorage_connection_request_add_credential(OvStorage_ConnectionRequest *request,
                                                 const char *key,
                                                 OvStorage_SecretValue *value);

/**
 * # Safety
 *
 * No preconditions. Returns an owned `*mut SecretBundle` the caller frees
 * exactly once with `ovstorage_secret_bundle_destroy`.
 */
OvStorage_SecretBundle *ovstorage_secret_bundle_create(void);

/**
 * # Safety
 *
 * `bundle` must be NULL (a no-op) or a pointer from
 * `ovstorage_secret_bundle_create` not yet destroyed, or not yet
 * consumed by `ovstorage_update_connection_credentials`. Passing the
 * value that call leaves in its slot is always correct: NULL when it
 * took the bundle, the bundle itself when it did not. It is freed here
 * and must not be used afterwards.
 */
void ovstorage_secret_bundle_destroy(OvStorage_SecretBundle *bundle);

/**
 * Add a credential entry to the bundle. On success, the bundle takes
 * ownership of `value` and the caller's `*value` is invalidated. On
 * failure (null arg, non-UTF-8 key, bundle already consumed), the
 * caller still owns `value` and must `_destroy` it.
 *
 * Returns `true` on success, `false` on error.
 *
 * # Safety
 *
 * `bundle` must be NULL or a valid `*mut SecretBundle` not yet consumed.
 * `key` must be a NUL-terminated UTF-8 C-string valid for the duration of
 * the call (it is copied). `value` must be NULL or a valid `*mut SecretValue`
 * from a create function; on any return the pointer must not be reused.
 * Ownership is transferred to the bundle on success only.
 */
bool ovstorage_secret_bundle_add(OvStorage_SecretBundle *bundle,
                                 const char *key,
                                 OvStorage_SecretValue *value);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `address` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning).
 * `options` must be NULL or point to valid `StatOptions`. `cancel` must
 * be NULL or a valid `*const CancelToken`; it may be destroyed after this
 * call returns (the token is cloned internally). `on_complete` must be a
 * valid callback function or NULL (NULL is a no-op — the request is
 * discarded); it fires once on completion (success or error). `user_data`
 * is an opaque context pointer passed to the callback unchanged; only the
 * pointer is copied, so it must remain valid until `on_complete` fires
 * exactly once.
 */
void ovstorage_stat(const OvStorage_LayerHandle *handle,
                    const char *address,
                    const OvStorage_StatOptions *options,
                    const OvStorage_CancelToken *cancel,
                    OvStorage_InfoCallback on_complete,
                    void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `address` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning).
 * `options` must be NULL or point to valid `ReadOptions`. `cancel` must
 * be NULL or a valid `*const CancelToken`; it may be destroyed after this
 * call returns (the token is cloned internally). `on_complete` must be a
 * valid callback function or NULL (NULL is a no-op — the request is
 * discarded); it fires once on completion (success or error). `user_data`
 * is an opaque context pointer passed to the callback unchanged; only the
 * pointer is copied, so it must remain valid until `on_complete` fires
 * exactly once.
 */
void ovstorage_read_bytes(const OvStorage_LayerHandle *handle,
                          const char *address,
                          const OvStorage_ReadOptions *options,
                          const OvStorage_CancelToken *cancel,
                          OvStorage_ReadBytesCallback on_complete,
                          void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `address` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning).
 * `options` must be NULL or point to valid `ReadOptions`. `cancel` must
 * be NULL or a valid `*const CancelToken`; it may be destroyed after this
 * call returns (the token is cloned internally). `on_complete` must be a
 * valid callback function or NULL (NULL is a no-op — the request is
 * discarded); it fires once per stream chunk (including final empty chunk
 * on success), or once on terminal error. `user_data` is an opaque context
 * pointer passed to the callback unchanged; only the pointer is copied, so
 * it must remain valid until the TERMINAL fire, not merely until this call
 * returns.
 */
void ovstorage_read_stream(const OvStorage_LayerHandle *handle,
                           const char *address,
                           const OvStorage_ReadOptions *options,
                           const OvStorage_CancelToken *cancel,
                           OvStorage_ReadStreamCallback on_complete,
                           void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `address` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning).
 * `options` must be NULL or point to valid `ReadOptions`. `cancel` must
 * be NULL or a valid `*const CancelToken`; it may be destroyed after this
 * call returns (the token is cloned internally). `on_complete` must be a
 * valid callback function or NULL (NULL is a no-op — the request is
 * discarded); it fires once on completion (success or error). `user_data`
 * is an opaque context pointer passed to the callback unchanged; only the
 * pointer is copied, so it must remain valid until `on_complete` fires
 * exactly once.
 */
void ovstorage_read_local_file(const OvStorage_LayerHandle *handle,
                               const char *address,
                               const OvStorage_ReadOptions *options,
                               const OvStorage_CancelToken *cancel,
                               OvStorage_ReadLocalFileCallback on_complete,
                               void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `address` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning). `data`
 * must either be NULL (when len is 0) or point to readable bytes for [0,
 * len); the bytes are copied before spawning, so the caller may free the
 * buffer immediately. `options` must be NULL or point to valid
 * `WriteOptions`. `cancel` must be NULL or a valid `*const CancelToken`;
 * it may be destroyed after this call returns (the token is cloned
 * internally). `on_complete` must be a valid callback function or NULL
 * (NULL is a no-op — the request is discarded); it fires once on
 * completion (success or error). `user_data` is an opaque context pointer
 * passed to the callback unchanged; only the pointer is copied, so it must
 * remain valid until `on_complete` fires exactly once.
 */
void ovstorage_write(const OvStorage_LayerHandle *handle,
                     const char *address,
                     const uint8_t *data,
                     size_t len,
                     const OvStorage_WriteOptions *options,
                     const OvStorage_CancelToken *cancel,
                     OvStorage_InfoCallback on_complete,
                     void *user_data);

/**
 * Store a caller-produced chunk stream without buffering the whole object.
 *
 * Ownership of `*stream` moves to the operation exactly when this function
 * zeroes the slot. A prologue rejection leaves it untouched; after transfer,
 * the library calls its `drop` callback exactly once.
 *
 * # Safety
 *
 * `handle`, `address`, `options`, `cancel`, `on_complete`, and `user_data`
 * follow `ovstorage_write`. `stream` must be NULL or point to a writable,
 * initialized `OvStorage_WriteStream` slot whose `next` and `drop` callbacks
 * remain callable until `drop` fires. A NULL callback makes this a no-op and
 * leaves the stream untouched.
 */
void ovstorage_write_stream(const OvStorage_LayerHandle *handle,
                            const char *address,
                            OvStorage_WriteStream *stream,
                            const OvStorage_WriteOptions *options,
                            const OvStorage_CancelToken *cancel,
                            OvStorage_InfoCallback on_complete,
                            void *user_data);

/**
 * Request a body-less direct-upload plan.
 *
 * # Safety
 *
 * `handle`, `address`, `options`, `cancel`, and `user_data` follow
 * `ovstorage_write`. `on_complete` may be NULL (a no-op); otherwise it fires
 * exactly once. On success the callback owns `redirects` and must destroy it
 * with `ovstorage_write_redirect_batch_destroy`. Before executing each
 * redirect, the caller MUST apply the freshness, URL-scope, operation,
 * credential-handling, and body-range checks documented on
 * `OvStorage_WriteRedirect`.
 */
void ovstorage_write_redirect(const OvStorage_LayerHandle *handle,
                              const char *address,
                              const OvStorage_WriteOptions *options,
                              const OvStorage_CancelToken *cancel,
                              OvStorage_WriteRedirectCallback on_complete,
                              void *user_data);

/**
 * Resume a redirect write after executing every request in `redirects`.
 *
 * # Safety
 *
 * `handle`, `address`, `cancel`, and `user_data` follow `ovstorage_write`.
 * `redirects` must be a live batch returned by this library. `results` must
 * contain exactly one entry per redirect; all nested pointer/length pairs
 * must be readable during this call and are copied before it returns.
 * `captured_body_len` must not exceed the corresponding redirect's
 * `capture_body_max_bytes`. The caller MUST execute redirects only after
 * applying the safety checks documented on `OvStorage_WriteRedirect`.
 * `on_complete` may be NULL (a no-op); otherwise it fires exactly once.
 */
void ovstorage_continue_write(const OvStorage_LayerHandle *handle,
                              const char *address,
                              const OvStorage_WriteRedirectBatch *redirects,
                              const OvStorage_RedirectResultBatch *results,
                              const OvStorage_CancelToken *cancel,
                              OvStorage_WriteStepCallback on_complete,
                              void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `address` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning).
 * `cancel` must be NULL or a valid `*const CancelToken`; it may be
 * destroyed after this call returns (the token is cloned internally).
 * `on_complete` must be a valid callback function or NULL (NULL is a no-op
 * — the request is discarded); it fires once on completion (success or
 * error). `user_data` is an opaque context pointer passed to the callback
 * unchanged; only the pointer is copied, so it must remain valid until
 * `on_complete` fires exactly once.
 */
void ovstorage_delete(const OvStorage_LayerHandle *handle,
                      const char *address,
                      const OvStorage_CancelToken *cancel,
                      OvStorage_StatusCallback on_complete,
                      void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `prefix` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning).
 * `options` must be NULL or point to valid `ListOptions`. `cancel` must
 * be NULL or a valid `*const CancelToken`; it may be destroyed after this
 * call returns (the token is cloned internally). `on_complete` must be a
 * valid callback function or NULL (NULL is a no-op — the request is
 * discarded); it fires once on completion (success or error). `user_data`
 * is an opaque context pointer passed to the callback unchanged; only the
 * pointer is copied, so it must remain valid until `on_complete` fires
 * exactly once.
 */
void ovstorage_list(const OvStorage_LayerHandle *handle,
                    const char *prefix,
                    const OvStorage_ListOptions *options,
                    const OvStorage_CancelToken *cancel,
                    OvStorage_ListCallback on_complete,
                    void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `address` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning).
 * `options` must be NULL or point to valid `ListVersionsOptions`.
 * `cancel` must be NULL or a valid `*const CancelToken`; it may be
 * destroyed after this call returns (the token is cloned internally).
 * `on_complete` must be a valid callback function or NULL (NULL is a no-op
 * — the request is discarded); it fires once on completion (success or
 * error). `user_data` is an opaque context pointer passed to the callback
 * unchanged; only the pointer is copied, so it must remain valid until
 * `on_complete` fires exactly once.
 */
void ovstorage_list_versions(const OvStorage_LayerHandle *handle,
                             const char *address,
                             const OvStorage_ListVersionsOptions *options,
                             const OvStorage_CancelToken *cancel,
                             OvStorage_ListVersionsCallback on_complete,
                             void *user_data);

/**
 * Return metadata for the latest version of an object.
 *
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `address` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning).
 * `options` must be NULL or point to valid `ReadOptions`. `cancel` must be
 * NULL or a valid `*const CancelToken`; it may be destroyed after this
 * call returns (the token is cloned internally). `on_complete` must be a
 * valid callback function or NULL (NULL is a no-op — the request is
 * discarded); it fires once on completion (success or error). `user_data`
 * is an opaque context pointer passed to the callback unchanged; only the
 * pointer is copied, so it must remain valid until `on_complete` fires
 * exactly once. The callback owns the returned `Info*` on success and must
 * free it with `ovstorage_info_destroy`.
 */
void ovstorage_get_latest_version(const OvStorage_LayerHandle *handle,
                                  const char *address,
                                  const OvStorage_ReadOptions *options,
                                  const OvStorage_CancelToken *cancel,
                                  OvStorage_InfoCallback on_complete,
                                  void *user_data);

/**
 * Subscribe to changes below `prefix`.
 *
 * # Safety
 *
 * `handle`, `prefix`, `cancel`, and `user_data` follow the other asynchronous
 * object operations. `options` may be NULL for defaults; a non-empty `since`
 * cursor is copied before this call returns. `on_complete` may be NULL (a
 * no-op); otherwise it remains callable until its terminal `done` fire.
 */
void ovstorage_watch_directory(const OvStorage_LayerHandle *handle,
                               const char *prefix,
                               const OvStorage_WatchDirectoryOptions *options,
                               const OvStorage_CancelToken *cancel,
                               OvStorage_WatchDirectoryCallback on_complete,
                               void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `src` and `dest`
 * must be NULL or NUL-terminated UTF-8 C-strings (copied before spawning).
 * `cancel` must be NULL or a valid `*const CancelToken`; it may be
 * destroyed after this call returns (the token is cloned internally).
 * `on_complete` must be a valid callback function or NULL (NULL is a no-op
 * — the request is discarded); it fires once on completion (success or
 * error). `user_data` is an opaque context pointer passed to the callback
 * unchanged; only the pointer is copied, so it must remain valid until
 * `on_complete` fires exactly once.
 */
void ovstorage_copy(const OvStorage_LayerHandle *handle,
                    const char *src,
                    const char *dest,
                    const OvStorage_CancelToken *cancel,
                    OvStorage_InfoCallback on_complete,
                    void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `src` and `dest`
 * must be NULL or NUL-terminated UTF-8 C-strings (copied before spawning).
 * `cancel` must be NULL or a valid `*const CancelToken`; it may be
 * destroyed after this call returns (the token is cloned internally).
 * `on_complete` must be a valid callback function or NULL (NULL is a no-op
 * — the request is discarded); it fires once on completion (success or
 * error). `user_data` is an opaque context pointer passed to the callback
 * unchanged; only the pointer is copied, so it must remain valid until
 * `on_complete` fires exactly once.
 */
void ovstorage_rename(const OvStorage_LayerHandle *handle,
                      const char *src,
                      const char *dest,
                      const OvStorage_CancelToken *cancel,
                      OvStorage_StatusCallback on_complete,
                      void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `address` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning).
 * `cancel` must be NULL or a valid `*const CancelToken`; it may be
 * destroyed after this call returns (the token is cloned internally).
 * `on_complete` must be a valid callback function or NULL (NULL is a no-op
 * — the request is discarded); it fires once on completion (success or
 * error). `user_data` is an opaque context pointer passed to the callback
 * unchanged; only the pointer is copied, so it must remain valid until
 * `on_complete` fires exactly once.
 */
void ovstorage_create_directory(const OvStorage_LayerHandle *handle,
                                const char *address,
                                const OvStorage_CancelToken *cancel,
                                OvStorage_InfoCallback on_complete,
                                void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `address` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning).
 * `cancel` must be NULL or a valid `*const CancelToken`; it may be
 * destroyed after this call returns (the token is cloned internally).
 * `on_complete` must be a valid callback function or NULL (NULL is a no-op
 * — the request is discarded); it fires once on completion (success or
 * error). `user_data` is an opaque context pointer passed to the callback
 * unchanged; only the pointer is copied, so it must remain valid until
 * `on_complete` fires exactly once.
 */
void ovstorage_delete_directory(const OvStorage_LayerHandle *handle,
                                const char *address,
                                const OvStorage_CancelToken *cancel,
                                OvStorage_StatusCallback on_complete,
                                void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `address` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning).
 * `options` must be NULL or point to valid `UpdateMetadataOptions`.
 * `cancel` must be NULL or a valid `*const CancelToken`; it may be
 * destroyed after this call returns (the token is cloned internally).
 * `on_complete` must be a valid callback function or NULL (NULL is a no-op
 * — the request is discarded); it fires once on completion (success or
 * error). `user_data` is an opaque context pointer passed to the callback
 * unchanged; only the pointer is copied, so it must remain valid until
 * `on_complete` fires exactly once.
 */
void ovstorage_update_metadata(const OvStorage_LayerHandle *handle,
                               const char *address,
                               const OvStorage_UpdateMetadataOptions *options,
                               const OvStorage_CancelToken *cancel,
                               OvStorage_InfoCallback on_complete,
                               void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `address` must be
 * NULL or a NUL-terminated UTF-8 C-string (copied before spawning).
 * `cancel` must be NULL or a valid `*const CancelToken`; it may be
 * destroyed after this call returns (the token is cloned internally).
 * `on_complete` must be a valid callback function or NULL (NULL is a no-op
 * — the request is discarded); it fires once on completion (success or
 * error). `user_data` is an opaque context pointer passed to the callback
 * unchanged; only the pointer is copied, so it must remain valid until
 * `on_complete` fires exactly once.
 */
void ovstorage_check_access(const OvStorage_LayerHandle *handle,
                            const char *address,
                            OvStorage_AccessOps ops,
                            const OvStorage_CancelToken *cancel,
                            OvStorage_CheckAccessCallback on_complete,
                            void *user_data);

/**
 * Load a plugin cdylib, returning a handle the caller frees with
 * `ovstorage_plugin_destroy`. Set `allow_test_plugins` only for tests.
 *
 * # Safety
 *
 * `path` must be a NUL-terminated UTF-8 string valid for the duration
 * of the call (it is copied). `out_plugin` must point at writable
 * storage for one `OvStorage_Plugin*`; on `Ok` it receives an owned
 * handle the caller frees exactly once with
 * `ovstorage_plugin_destroy`. `out_error` must be NULL or a valid
 * `OvStorage_Error*`. The named cdylib must be a well-formed ovstorage
 * plugin — its init entry point runs during this call.
 */
OvStorage_Status ovstorage_load_plugin(const char *path,
                                       bool allow_test_plugins,
                                       OvStorage_Plugin **out_plugin,
                                       OvStorage_Error *out_error);

/**
 * # Safety
 *
 * `plugin` must be NULL (a no-op) or a pointer from
 * `ovstorage_load_plugin` not yet destroyed; it is freed here and
 * must not be used afterwards. Registries and Stacks hold their own
 * clones of the plugin's factories (which keep the cdylib mapped), so
 * they stay valid after the plugin handle is destroyed.
 */
void ovstorage_plugin_destroy(OvStorage_Plugin *plugin);

/**
 * Create a registry seeded with the built-in factories. Free with
 * `ovstorage_registry_destroy`.
 *
 * # Safety
 *
 * No preconditions. The returned registry is owned by the caller and
 * must be freed exactly once with `ovstorage_registry_destroy`.
 */
OvStorage_Registry *ovstorage_registry_create(void);

/**
 * # Safety
 *
 * `registry` must be NULL (a no-op) or a pointer from
 * `ovstorage_registry_create` not yet destroyed; it is freed here
 * and must not be used afterwards. Stacks keep clones of the factories
 * they resolved through it, so destroying the registry does not
 * invalidate declared layers or built handles.
 */
void ovstorage_registry_destroy(OvStorage_Registry *registry);

/**
 * Register every kind a loaded plugin advertises into the registry. The
 * plugin handle is borrowed (its factory `Arc`s are cloned), so the
 * caller still owns and must free it.
 *
 * # Safety
 *
 * `registry` must be a live pointer from `ovstorage_registry_create`
 * with no concurrent access during the call. `plugin` must be a live
 * pointer from `ovstorage_load_plugin`; it is borrowed, so the
 * caller still owns it and frees it later. `out_error` must be NULL or
 * a valid `OvStorage_Error*`.
 */
OvStorage_Status ovstorage_registry_add_plugin(OvStorage_Registry *registry,
                                               const OvStorage_Plugin *plugin,
                                               OvStorage_Error *out_error);

/**
 * Inspect the Layer kinds a plugin provides for discovery / config UIs,
 * without composing them into a Stack. Free the list with
 * `ovstorage_kind_descriptor_list_destroy`.
 *
 * In the current ABI the kind descriptors live in the plugin's init
 * result, so this opens the cdylib and runs its init, but never
 * instantiates a Layer. The descriptors are identity-only today
 * (`kind`/`layer_type`/`display_name`); schemas are empty until the
 * manifest carries them.
 *
 * WARNING: each call permanently pins the cdylib for the rest of the
 * process lifetime (the mapping is never unloaded). Inspect a given
 * plugin once; do not poll this or re-scan a plugin directory on a
 * refresh loop, or each call leaks a mapped cdylib.
 *
 * # Safety
 *
 * `path` must be a NUL-terminated UTF-8 string valid for the duration
 * of the call (it is copied). `out_list` must point at writable
 * storage for one `OvStorage_KindDescriptorList*`; on `Ok` it receives
 * an owned list the caller frees exactly once with
 * `ovstorage_kind_descriptor_list_destroy`. `out_error` must be NULL
 * or a valid `OvStorage_Error*`. The named cdylib must be a
 * well-formed ovstorage plugin — its init entry point runs during this
 * call.
 */
OvStorage_Status ovstorage_inspect_plugin(const char *path,
                                          bool allow_test_plugins,
                                          OvStorage_KindDescriptorList **out_list,
                                          OvStorage_Error *out_error);

/**
 * # Safety
 *
 * `list` must be NULL (a no-op) or a pointer from
 * `ovstorage_inspect_plugin` not yet destroyed; it is freed here.
 * Every `kind` / `display_name` slice previously returned by the item
 * accessors borrows from `list` and dangles afterwards.
 */
void ovstorage_kind_descriptor_list_destroy(OvStorage_KindDescriptorList *list);

/**
 * Number of kind descriptors in `list`; 0 if `list` is NULL.
 *
 * # Safety
 *
 * `list` must be NULL or a valid `OvStorage_KindDescriptorList*`.
 */
size_t ovstorage_kind_descriptor_list_len(const OvStorage_KindDescriptorList *list);

/**
 * `layer_type` of item `index`: `0`=Backend, `1`=Wrapper, `2`=Router,
 * `-1` if out of range.
 *
 * # Safety
 *
 * `list` must be NULL or a valid `OvStorage_KindDescriptorList*`.
 */
int32_t ovstorage_kind_descriptor_list_item_layer_type(const OvStorage_KindDescriptorList *list,
                                                       size_t index);

/**
 * Borrowed `kind` of item `index` as a `(ptr, *out_len)` byte slice —
 * **not** NUL-terminated. Read exactly `*out_len` bytes; do not call
 * `strlen` / `strcpy` / `printf("%s")` on it (the bytes run on into
 * unrelated descriptor storage). Valid until the list is destroyed;
 * returns `NULL` with `*out_len = 0` if `index` is out of range or the
 * value contains an interior NUL. Copy if you need to retain it.
 *
 * # Safety
 *
 * `list` must be NULL or a valid `OvStorage_KindDescriptorList*`.
 * `out_len` must be NULL or point at writable storage for one `size_t`
 * — pass it: without the length the non-NUL-terminated result cannot
 * be read safely. The returned pointer borrows from `list`; do not
 * free it or read it after the list is destroyed.
 */
const char *ovstorage_kind_descriptor_list_item_kind(const OvStorage_KindDescriptorList *list,
                                                     size_t index,
                                                     size_t *out_len);

/**
 * Borrowed `display_name` of item `index` as a `(ptr, *out_len)` byte
 * slice; see `ovstorage_kind_descriptor_list_item_kind` for the
 * (non-NUL-terminated) slice contract and lifetime rules.
 *
 * # Safety
 *
 * Same contract as `ovstorage_kind_descriptor_list_item_kind`:
 * `list` must be NULL or a valid `OvStorage_KindDescriptorList*`;
 * `out_len` must be NULL or point at writable storage for one
 * `size_t`; the returned pointer borrows from `list` and must not be
 * freed or read after the list is destroyed.
 */
const char *ovstorage_kind_descriptor_list_item_display_name(const OvStorage_KindDescriptorList *list,
                                                             size_t index,
                                                             size_t *out_len);

/**
 * Create an empty Stack builder. Free with `ovstorage_stack_destroy`
 * (or hand to `ovstorage_stack_build`, which consumes it).
 *
 * # Safety
 *
 * No preconditions. The returned builder is owned by the caller and is
 * released exactly once: by `ovstorage_stack_destroy`, or by the
 * consume-on-success path of `ovstorage_stack_build` /
 * `ovstorage_stack_build_async` (on error or cancellation those
 * leave it owned by the caller).
 */
OvStorage_Stack *ovstorage_stack_create(void);

/**
 * # Safety
 *
 * `stack` must be NULL (a no-op) or a pointer from
 * `ovstorage_stack_create` that has not already been released —
 * neither destroyed before, nor consumed by a *successful*
 * `ovstorage_stack_build` / `ovstorage_stack_build_async` build
 * (after a failed or cancelled build the caller still owns it and
 * frees it here). It must not have an async build in flight: wait for
 * `on_complete` before destroying.
 */
void ovstorage_stack_destroy(OvStorage_Stack *stack);

/**
 * Declare a named Layer instance of `kind`, resolved through `registry`.
 * The instance's `layer_type` comes from the registered factory's
 * descriptor. Add instance configuration with
 * `ovstorage_stack_add_layer_config`.
 *
 * # Safety
 *
 * `stack` must be a live builder from `ovstorage_stack_create` with
 * no concurrent access and no async build in flight. `registry` must
 * be a live pointer from `ovstorage_registry_create`; it is borrowed
 * (the resolved factory is cloned into the builder), so it may be
 * destroyed afterwards. `instance_id` and `kind` must be
 * NUL-terminated UTF-8 strings valid for the duration of the call
 * (they are copied). `out_error` must be NULL or a valid
 * `OvStorage_Error*`.
 */
OvStorage_Status ovstorage_stack_add_layer(OvStorage_Stack *stack,
                                           const OvStorage_Registry *registry,
                                           const char *instance_id,
                                           const char *kind,
                                           OvStorage_Error *out_error);

/**
 * Add or replace one configuration value on a declared Layer instance.
 *
 * The Stack takes ownership of `value` only on success. A replacement
 * destroys the previous value for the same key. Layer configuration is
 * distinct from backend connection configuration: factories receive these
 * values while creating the Layer.
 *
 * # Safety
 *
 * `stack` must be a live builder with no concurrent access and no async build
 * in flight. `instance_id` and `key` must be NUL-terminated UTF-8 strings
 * valid for the duration of the call. `value` must be a live handle from an
 * `ovstorage_config_value_create_*` function; the caller retains it when this
 * function fails. `out_error` must be NULL or a valid `OvStorage_Error*`.
 */
OvStorage_Status ovstorage_stack_add_layer_config(
    OvStorage_Stack *stack,
    const char *instance_id,
    const char *key,
    OvStorage_ConfigValue *value,
    OvStorage_Error *out_error);

/**
 * Name the application-facing root Layer instance.
 *
 * # Safety
 *
 * `stack` must be a live builder from `ovstorage_stack_create` with
 * no concurrent access and no async build in flight. `instance_id`
 * must be a NUL-terminated UTF-8 string valid for the duration of the
 * call (it is copied). `out_error` must be NULL or a valid
 * `OvStorage_Error*`.
 */
OvStorage_Status ovstorage_stack_set_root(OvStorage_Stack *stack,
                                          const char *instance_id,
                                          OvStorage_Error *out_error);

/**
 * Record the `inner` edge of a wrapper Layer. Validates that
 * `wrapper_id` was declared with `layer_type = wrapper`.
 *
 * # Safety
 *
 * `stack` must be a live builder from `ovstorage_stack_create` with
 * no concurrent access and no async build in flight. `wrapper_id` and
 * `inner_id` must be NUL-terminated UTF-8 strings valid for the
 * duration of the call (they are copied). `out_error` must be NULL or
 * a valid `OvStorage_Error*`.
 */
OvStorage_Status ovstorage_stack_set_inner(OvStorage_Stack *stack,
                                           const char *wrapper_id,
                                           const char *inner_id,
                                           OvStorage_Error *out_error);

/**
 * Record the `children` edges of a router Layer. Validates that
 * `router_id` was declared with `layer_type = router`.
 *
 * # Safety
 *
 * `stack` must be a live builder from `ovstorage_stack_create` with
 * no concurrent access and no async build in flight. `router_id` must
 * be a NUL-terminated UTF-8 string valid for the duration of the call.
 * `child_ids` may be NULL only when `child_count` is 0; otherwise it
 * must point to `child_count` pointers, each a NUL-terminated UTF-8
 * string, all valid for the duration of the call (they are copied).
 * `out_error` must be NULL or a valid `OvStorage_Error*`.
 */
OvStorage_Status ovstorage_stack_set_children(OvStorage_Stack *stack,
                                              const char *router_id,
                                              const char *const *child_ids,
                                              size_t child_count,
                                              OvStorage_Error *out_error);

/**
 * Record a connection owned by the Layer named `target`, taking ownership
 * of the `request` builder (the backend kind, config, credentials, persist
 * flag, and display name).
 *
 * Ownership moves through the slot, not through the status: `*request` is
 * set to NULL if and only if this call took the builder. So the caller's
 * cleanup is unconditional —
 *
 * ```c
 * OvStorage_ConnectionRequest *request = ovstorage_connection_request_create("file");
 * ovstorage_stack_add_connection(stack, "files", &request, &error);
 * ovstorage_connection_request_destroy(request);
 * ```
 *
 * — which frees a builder this call declined and is a no-op on the NULL
 * left behind by one it took. Nothing has to be inferred from the status,
 * and a caller that reuses `request` after a failure is reusing exactly
 * the builder it still owns.
 *
 * # Safety
 *
 * `stack` must be a live builder from `ovstorage_stack_create` with
 * no concurrent access and no async build in flight. `target` must be
 * a NUL-terminated UTF-8 string valid for the duration of the call.
 * `request` must be NULL (rejected with `InvalidArgument`) or point to a
 * writable slot holding NULL (also rejected) or a live, unconsumed handle
 * from `ovstorage_connection_request_create`. `out_error` must be NULL or
 * a valid `OvStorage_Error*`.
 */
OvStorage_Status ovstorage_stack_add_connection(OvStorage_Stack *stack,
                                                const char *target,
                                                OvStorage_ConnectionRequest **request,
                                                OvStorage_Error *out_error);

/**
 * Finalize the Stack and return the root `OvStorage_LayerHandle*` (free
 * with `ovstorage_layer_handle_destroy`). Consumes `stack` on success;
 * on error the caller still owns it. A build-phase failure zeroes recorded
 * credentials (secret hygiene) and then rejects a retry with
 * `InvalidArgument` for every connection that carried secrets — recover by
 * destroying the Stack and rebuilding it with fresh credentials.
 * Connections without credentials retry unchanged, and a prologue
 * rejection leaves the builder untouched.
 *
 * This is the explicitly blocking compatibility adapter over the async
 * build path: it drives `ovstorage_stack_build_async`'s work to
 * completion on the process-global runtime before returning, so it must
 * not be called from a thread already inside that runtime. Callers that
 * own an event loop should prefer the async entry point.
 *
 * # Safety
 *
 * `stack` must be a live builder from `ovstorage_stack_create` with
 * no concurrent access and no async build in flight; on success it is
 * consumed (freed) and must not be used or destroyed afterwards, on
 * *any* error the caller still owns it. `options` must be NULL or
 * point to a valid `OvStorage_StackBuildOptions`, valid for the
 * duration of the call.
 * `out_handle` must point at writable storage for one
 * `OvStorage_LayerHandle*`; on `Ok` it receives an owned handle the
 * caller frees exactly once with `ovstorage_layer_handle_destroy`.
 * `out_error` must be NULL or a valid `OvStorage_Error*`. Must not be
 * called from a runtime worker thread (it blocks on the process-global
 * runtime); use `ovstorage_stack_build_async` there.
 *
 * NOTE: this verb does NOT use the slot idiom. `ovstorage_add_connection`,
 * `ovstorage_update_connection_credentials` and
 * `ovstorage_stack_add_connection` take their handle through a `**` slot and
 * NULL it exactly when they take ownership, so a caller can always finish with
 * one unconditional destroy. This one consumes the Stack on `Ok` ONLY, and
 * leaves the caller's pointer dangling. Do not generalise the unconditional
 * destroy to it: `ovstorage_stack_destroy` after a successful build is a
 * double free.
 */
OvStorage_Status ovstorage_stack_build(OvStorage_Stack *stack,
                                       const OvStorage_StackBuildOptions *options,
                                       OvStorage_LayerHandle **out_handle,
                                       OvStorage_Error *out_error);

/**
 * Finalize the Stack asynchronously, delivering the built root
 * `OvStorage_LayerHandle*` through `on_complete` without blocking the
 * caller thread. This is the non-blocking sibling of
 * `ovstorage_stack_build`: it marshals the builder on the calling thread,
 * spawns the build onto the process-global runtime, and never calls
 * `block_on`, so it is safe to invoke from inside that runtime (e.g. an
 * async host wiring up nested Stacks).
 *
 * Ownership of `stack`:
 * - On a prologue error (null `stack`, a runtime-build failure, or an
 *   unset root), the callback
 *   fires inline with the error and `stack` is NOT consumed — the caller
 *   still owns it and must free it with `ovstorage_stack_destroy` (or fix
 *   and retry).
 * - On a successful build the builder is consumed (freed) before the
 *   callback fires with `OvStorage_Status_Ok` and the owned `*mut LayerHandle`; the
 *   caller must NOT call `ovstorage_stack_destroy` on it afterwards.
 * - On a build-phase error or cancellation the callback fires with the
 *   error / `OvStorage_Status_Cancelled` and `handle == NULL`, and the builder is
 *   not consumed. Whether it is still REUSABLE follows the same rule as the
 *   blocking `ovstorage_stack_build`: recorded credentials are zeroed on any
 *   path that reaches the build epilogue (secret hygiene), and a retry is
 *   then rejected with `InvalidArgument` for every connection that carried
 *   secrets — recover by destroying the Stack and rebuilding with fresh
 *   credentials.
 *
 * Cancelling `cancel` before the build starts completes with
 * `OvStorage_Status_Cancelled` and leaves the builder untouched. Cancelling
 * once the build is under way is subject to the same credential handling as a
 * build-phase error. A layer that ignores the cancel token it is handed and
 * stays parked does not hold up the callback: the runtime stops waiting on
 * the parked step and reports `OvStorage_Status_Cancelled`. The abandoned
 * layer is released later, once it finally completes the call it was left
 * running, and its cancel token fires on the way out so a cooperative plugin
 * learns the call was abandoned. A layer that never completes that
 * call is never released: it, the factory behind it, and the plugin mapping
 * that factory keeps loaded are pinned for the life of the process, because
 * the ABI has no verb that retracts an in-flight call and dropping the layer
 * under one would free state the plugin is still using. Two further pure-C
 * caveats: a factory that parks inside layer construction itself
 * (`create_backend` / `create_wrapper` / `create_router`, which are
 * synchronous and receive no token) still blocks the build, and
 * `ovstorage_cancel_token_cancel` runs every subscriber on the calling
 * thread, so a plugin cancellation callback that blocks delays the build's
 * own wakeup.
 *
 * `stack` and every request/config/secret handle recorded into it (via the
 * `ovstorage_stack_*` builder calls) must remain alive and untouched by the
 * caller until `on_complete` fires; the build reads the builder from the
 * spawned task.
 *
 * # Safety
 *
 * `stack` must be a live `*mut Stack` from `ovstorage_stack_create` and
 * must not be mutated, freed, or built again until `on_complete` fires.
 * `options` (if non-null) and `cancel` (if non-null) must point to valid
 * instances for the duration of this call; `cancel` may be destroyed after
 * this call returns (the token is cloned internally). `on_complete` must be
 * a valid callback function or NULL (NULL is a no-op — the request is
 * discarded). `user_data` is an opaque context pointer passed to
 * `on_complete`, which may run on a runtime worker thread; only the pointer
 * is copied, so it must remain valid until `on_complete` fires exactly once.
 *
 * NOTE: this verb does NOT use the slot idiom. `ovstorage_add_connection`,
 * `ovstorage_update_connection_credentials` and
 * `ovstorage_stack_add_connection` take their handle through a `**` slot and
 * NULL it exactly when they take ownership, so a caller can always finish with
 * one unconditional destroy. This one consumes the Stack on `Ok` ONLY, and
 * leaves the caller's pointer dangling. Do not generalise the unconditional
 * destroy to it: `ovstorage_stack_destroy` after a successful build is a
 * double free.
 */
void ovstorage_stack_build_async(OvStorage_Stack *stack,
                                 const OvStorage_StackBuildOptions *options,
                                 const OvStorage_CancelToken *cancel,
                                 OvStorage_StackBuildCallback on_complete,
                                 void *user_data);

/**
 * # Safety
 *
 * `handle` must be NULL (a no-op) or an owned `OvStorage_LayerHandle*`
 * — from `ovstorage_stack_build`, an `ovstorage_stack_build_async`
 * callback, or `ovstorage_import_handle` — not yet destroyed; it is
 * freed here and must not be used afterwards. Each async op clones the
 * root and runtime during the call that receives the handle, so
 * operations already dispatched run to completion — but no thread may
 * still be inside an `ovstorage_*` call that was passed `handle` when
 * it is destroyed.
 */
void ovstorage_layer_handle_destroy(OvStorage_LayerHandle *handle);

/**
 * Destroy an independently owned `Connection` snapshot. Null pointers are
 * safe and do nothing.
 *
 * # Safety
 *
 * `connection` must be NULL or an independently owned connection delivered
 * through a connection callback. Do not pass an item borrowed from a list.
 */
void ovstorage_connection_destroy(OvStorage_Connection *connection);

/**
 * Destroy an owned `ConnectionList` snapshot. Null pointers are safe and do
 * nothing.
 *
 * # Safety
 *
 * `list` must be NULL or a valid `*mut ConnectionList` from
 * `ovstorage_list_connections`. Its inline items are borrowed and must not
 * be individually destroyed.
 */
void ovstorage_connection_list_destroy(OvStorage_ConnectionList *list);

/**
 * Validate a connection request against the Layer named by `target` without
 * registering it. The request builder is borrowed and remains owned by the
 * caller after the call returns and after completion.
 *
 * # Safety
 *
 * `handle` must be a live `OvStorage_LayerHandle*` from
 * `ovstorage_stack_build`. `target` must be NULL or a valid C-string
 * pointer. `request` must be NULL or a valid, not-yet-consumed
 * `OvStorage_ConnectionRequest*`; it must remain valid only for the duration
 * of this call because its contents are copied before dispatch. `cancel`
 * must be NULL or a valid `*const OvStorage_CancelToken`; it may be destroyed
 * after this call returns. `on_complete` must be a valid callback function or
 * NULL (NULL is a no-op). `user_data` must remain valid until `on_complete`
 * fires exactly once. The callback owns the returned `Connection*` on success
 * and must free it with `ovstorage_connection_destroy`.
 */
void ovstorage_probe(const OvStorage_LayerHandle *handle,
                     const char *target,
                     const OvStorage_ConnectionRequest *request,
                     const OvStorage_CancelToken *cancel,
                     OvStorage_ConnectionCallback on_complete,
                     void *user_data);

/**
 * Register a new connection owned by the Layer named `target`. The
 * result is delivered through `on_complete` as a `*mut Connection` the
 * caller owns and must free with `ovstorage_connection_destroy`.
 *
 * Ownership of `request` moves through the slot, not through the status:
 * `*request` is set to NULL if and only if this call took the builder,
 * and the decision is final by the time the call returns — earlier than
 * the callback: the slot is settled before `on_complete` can fire on ANY
 * path, including an inline prologue rejection, so a callback may safely
 * free the object that holds the slot. With a NULL `on_complete` the call
 * is a no-op and leaves the builder in the slot. So the caller's cleanup
 * is unconditional —
 *
 * ```c
 * OvStorage_ConnectionRequest *request = ovstorage_connection_request_create("s3");
 * ovstorage_add_connection(handle, "backend", &request, NULL, on_complete, ctx);
 * ovstorage_connection_request_destroy(request);
 * ```
 *
 * — which frees a builder this call declined and is a no-op on the NULL
 * left behind by one it took. This is what the status cannot express: a
 * prologue rejection that keeps its hands off the builder and a
 * layer-side error that already consumed it both reach `on_complete` as
 * the same failed result, so a caller reading only the status cannot tell
 * a leak from a double free. The slot tells it.
 *
 * A rejection attributable to the HANDLE or the TARGET (null `handle`,
 * null or non-UTF-8 `target`) leaves a live builder untouched in the slot,
 * so correcting that argument and retrying with the same builder is well
 * defined.
 *
 * A null or already-consumed `*request` is NOT that case. It is a caller
 * bug, not a correctable argument, and such a handle must not be reused.
 * Whether an alias to a consumed builder still points at live memory
 * depends on who consumed it: this call and `ovstorage_stack_build` destroy
 * the builder, so an alias is dangling and touching it is a use-after-free,
 * while `ovstorage_stack_add_connection` keeps the builder alive until the
 * Stack is built or destroyed. A caller must not rely on the difference.
 * The slot is left as the caller supplied it purely so this call frees
 * nothing it did not take.
 *
 * # Safety
 *
 * `handle` must be a live `OvStorage_LayerHandle*` from
 * `ovstorage_stack_build`. `target` must be NULL or a valid C-string
 * pointer. `request` must be NULL or point to a writable slot holding
 * NULL or a valid, not-yet-consumed `*mut OvStorage_ConnectionRequest`;
 * the slot must stay valid for the duration of the call. `cancel` must be NULL or a valid
 * `*const OvStorage_CancelToken`; it may be destroyed after this call
 * returns (the token is cloned internally). `on_complete` must be a valid
 * callback function or NULL (NULL is a no-op). `user_data` is an opaque
 * context pointer passed to the callback; it must remain valid until
 * `on_complete` fires exactly once. The callback receives ownership of the
 * returned `Connection*` on success and must free it with
 * `ovstorage_connection_destroy`, or receives NULL on error.
 */
void ovstorage_add_connection(const OvStorage_LayerHandle *handle,
                              const char *target,
                              OvStorage_ConnectionRequest **request,
                              const OvStorage_CancelToken *cancel,
                              OvStorage_ConnectionCallback on_complete,
                              void *user_data);

/**
 * List the connections currently registered on the built Stack root.
 *
 * Snapshot-only: the optional `Layer` update stream is dropped end-to-end
 * in the v2 freeze slice, so this delivers the point-in-time snapshot and
 * no live updates. Cancelling `cancel` aborts the in-flight discovery and
 * completes with `OvStorage_Status_Cancelled`.
 *
 * # Safety
 *
 * `handle` must be a live `OvStorage_LayerHandle*` from
 * `ovstorage_stack_build`. `cancel` must be NULL or a valid
 * `*const OvStorage_CancelToken`; it may be destroyed after this call
 * returns (the token is cloned internally). `on_complete` must be a valid
 * callback function or NULL (NULL is a no-op). `user_data` is an opaque
 * context pointer passed to the callback; it must remain valid until
 * `on_complete` fires exactly once. The callback receives ownership of the
 * returned `ConnectionList*` on success and must free it with
 * `ovstorage_connection_list_destroy`, or receives NULL on error.
 */
void ovstorage_list_connections(const OvStorage_LayerHandle *handle,
                                const OvStorage_CancelToken *cancel,
                                OvStorage_ConnectionListCallback on_complete,
                                void *user_data);

/**
 * Remove a registered connection owned by `target` by its id.
 *
 * # Safety
 *
 * `handle` must be a live `OvStorage_LayerHandle*` from
 * `ovstorage_stack_build`. `target` and `connection_id` must both be NULL
 * or valid C-string pointers. `cancel` must be NULL or a valid
 * `*const OvStorage_CancelToken`; it may be destroyed after this call
 * returns (the token is cloned internally). `on_complete` must be a valid
 * callback function or NULL (NULL is a no-op). `user_data` is an opaque
 * context pointer passed to the callback; it must remain valid until
 * `on_complete` fires exactly once.
 */
void ovstorage_remove_connection(const OvStorage_LayerHandle *handle,
                                 const char *target,
                                 const char *connection_id,
                                 const OvStorage_CancelToken *cancel,
                                 OvStorage_StatusCallback on_complete,
                                 void *user_data);

/**
 * Refresh the credentials on an existing connection owned by `target`,
 * taking ownership of the `credentials` bundle.
 *
 * Ownership moves through the slot, not through the status: `*credentials`
 * is set to NULL if and only if this call took the bundle, and the
 * decision is final by the time the call returns — earlier than the
 * callback: the slot is settled before `on_complete` can fire on ANY path,
 * including an inline prologue rejection, so a callback may safely free the
 * object that holds the slot. With a NULL `on_complete` the call is a no-op
 * and leaves the bundle in the slot. So the caller's cleanup is
 *
 * ```c
 * OvStorage_SecretBundle *credentials = ovstorage_secret_bundle_create();
 * ovstorage_update_connection_credentials(
 *     handle, "backend", "id", &credentials, NULL, on_complete, ctx);
 * ovstorage_secret_bundle_destroy(credentials);
 * ```
 *
 * — which zeroes and frees a bundle this call declined and is a no-op on
 * the NULL left behind by one it took. What is at stake here is credential
 * material: a caller that guesses "consumed" and abandons an unconsumed
 * bundle leaves secrets in the heap unwiped, and one that guesses the
 * other way frees a bundle twice. The status cannot tell them apart,
 * because a prologue rejection and a layer-side error both reach
 * `on_complete` as the same failed result. The slot can.
 *
 * A rejection attributable to the HANDLE, the TARGET or the CONNECTION ID
 * (null `handle`, null or non-UTF-8 `target` or `connection_id`) leaves a
 * live bundle untouched in the slot, so correcting that argument and
 * retrying with the same bundle is well defined.
 *
 * A null or already-consumed `*credentials` is NOT that case. It is a
 * caller bug, and such a handle must not be reused: this call destroys the
 * bundle it takes, so an alias to a consumed bundle is dangling and
 * touching it is a use-after-free. The slot is left as supplied purely so
 * this call frees nothing it did not take.
 *
 * # Safety
 *
 * `handle` must be a live `OvStorage_LayerHandle*` from
 * `ovstorage_stack_build`. `target` and `connection_id` must both be NULL
 * or valid C-string pointers. `credentials` must be NULL or point to a
 * writable slot holding NULL or a valid, not-yet-consumed
 * `*mut OvStorage_SecretBundle`; the slot must stay valid for the
 * duration of the call. `cancel` must be NULL or a valid
 * `*const OvStorage_CancelToken`; it may be destroyed after this call
 * returns (the token is cloned internally). `on_complete` must be a valid
 * callback function or NULL (NULL is a no-op). `user_data` is an opaque
 * context pointer passed to the callback; it must remain valid until
 * `on_complete` fires exactly once. The callback receives ownership of the
 * returned `Connection*` on success and must free it with
 * `ovstorage_connection_destroy`, or receives NULL on error.
 */
void ovstorage_update_connection_credentials(const OvStorage_LayerHandle *handle,
                                             const char *target,
                                             const char *connection_id,
                                             OvStorage_SecretBundle **credentials,
                                             const OvStorage_CancelToken *cancel,
                                             OvStorage_ConnectionCallback on_complete,
                                             void *user_data);

/**
 * Patch presentation attributes for one connection. Credentials are not part
 * of this patch; use `ovstorage_update_connection_credentials` for them.
 *
 * # Safety
 *
 * `handle` must be a live `OvStorage_LayerHandle*`. `target` and
 * `connection_id` must be NULL or valid C-string pointers. `patch` may be
 * NULL (an empty patch) or point to a valid `OvStorage_AttributePatch`;
 * present strings and the optional metadata patch are copied before this call
 * returns. `cancel` may be NULL or a valid token and may be destroyed after
 * this call returns. `on_complete` may be NULL (a no-op) or a valid callback;
 * `user_data` must remain valid until it fires exactly once. The callback owns
 * the returned `Connection*` on success.
 */
void ovstorage_update_connection_attributes(const OvStorage_LayerHandle *handle,
                                            const char *target,
                                            const char *connection_id,
                                            const OvStorage_AttributePatch *patch,
                                            const OvStorage_CancelToken *cancel,
                                            OvStorage_ConnectionCallback on_complete,
                                            void *user_data);

/**
 * # Safety
 *
 * `event` must be NULL (a no-op) or a pointer from
 * `ovstorage_authenticate_connection` callback not yet destroyed. It is
 * freed here and must not be used afterwards.
 */
void ovstorage_auth_event_destroy(OvStorage_AuthEvent *event);
/**
 * Drive the authentication flow for the connection `connection_id` owned
 * by the Layer named `target`. The layer returns a stream of `AuthEvent`s;
 * this thunk drains it on the process-global runtime and fires the
 * multi-fire `on_complete` once per event, with a final `done=true` fire
 * on end-of-stream (null event, null error) or terminal error (null event,
 * non-null error). Cancellation is polled between events.
 *
 * # Safety
 *
 * `handle` must be NULL or a valid `*const LayerHandle`. `target` and
 * `connection_id` must be NUL-terminated UTF-8 C-strings (copied before
 * spawning). `cancel` must be NULL or a valid `*const CancelToken`; it may
 * be destroyed after this call returns (the token is cloned internally).
 * `on_complete` must be a valid callback function or NULL (NULL is a no-op
 * — the request is discarded); it fires once per event and a final time on
 * completion. `user_data` is an opaque context pointer passed to the
 * callback unchanged for every fire; only the pointer is copied, so it
 * must remain valid until the FINAL completion fire, not merely until this
 * call returns. Each fired `*mut AuthEvent` is owned by the callback
 * (freed with `ovstorage_auth_event_destroy`).
 */
void ovstorage_authenticate_connection(const OvStorage_LayerHandle *handle,
                                       const char *target,
                                       const char *connection_id,
                                       OvStorage_InteractiveAuthCapability capability,
                                       bool auto_open_browser,
                                       const OvStorage_CancelToken *cancel,
                                       OvStorage_AuthEventCallback on_complete,
                                       void *user_data);

/**
 * Destroy an independently owned `RootInfo` snapshot. Null pointers are safe
 * and do nothing.
 *
 * # Safety
 *
 * `info` must be NULL or an independently owned `RootInfo`; do not pass an
 * item borrowed from a list.
 */
void ovstorage_root_info_destroy(OvStorage_RootInfo *info);

/**
 * Destroy an owned `RootInfoList` snapshot. Null pointers are safe and do
 * nothing.
 *
 * # Safety
 *
 * `list` must be NULL or a valid `*mut RootInfoList` from
 * `ovstorage_list_address_roots`. Its inline items are borrowed and must not
 * be individually destroyed.
 */
void ovstorage_root_info_list_destroy(OvStorage_RootInfoList *list);

/**
 * List the address roots the built Stack root currently exposes.
 *
 * Snapshot-only: the optional `Layer` update stream is dropped end-to-end
 * in the v2 freeze slice, so this delivers the point-in-time snapshot and
 * no live updates. Cancelling `cancel` aborts the in-flight discovery and
 * completes with `OvStorage_Status_Cancelled`.
 *
 * # Safety
 *
 * `handle` must be a live `OvStorage_LayerHandle*` from
 * `ovstorage_stack_build`. `cancel` must be NULL or a valid
 * `*const OvStorage_CancelToken`; it may be destroyed after this call
 * returns (the token is cloned internally). `on_complete` must be a valid
 * callback function or NULL (NULL is a no-op). `user_data` is an opaque
 * context pointer passed to the callback; it must remain valid until
 * `on_complete` fires exactly once. The callback receives ownership of the
 * returned `RootInfoList*` on success and must free it with
 * `ovstorage_root_info_list_destroy`, or receives NULL on error.
 */
void ovstorage_list_address_roots(const OvStorage_LayerHandle *handle,
                                  const OvStorage_CancelToken *cancel,
                                  OvStorage_RootInfoListCallback on_complete,
                                  void *user_data);

/**
 * Mint one owned `OvStoragePlugin_LayerHandle` over the root Layer of a
 * built `handle`, writing it into `*out_handle`. This is the produce side
 * of the cross-language live handoff: the minted handle has the exact
 * shape every plugin factory returns (`state` is the canonical boxed
 * `Arc<dyn Layer>`, `vtable` this cdylib's Layer vtable), and it can be
 * driven directly through its vtable slots or handed to
 * `ovstorage_import_handle` (in this process or any other).
 *
 * Ownership and lifetime:
 * - Each call clones the root `Arc` and mints exactly **one** owned
 *   handle. The Layer vtable has no clone slot, so handles are move-only;
 *   for multiple consumers, call this once per consumer.
 * - The minted handle must be disposed exactly once — either by
 *   `ovstorage_import_handle` (which consumes it) or by invoking its
 *   `vtable->drop(state)` slot exactly once. Dropping it twice, or reading
 *   `state` after drop, is undefined behavior.
 * - The producer — this process, plus the runtime driving the exported
 *   Layer — must outlive every handle it exports. A bare handle carries no
 *   keep-alive pin; this is a documented ABI contract (debug builds
 *   tripwire stray live exports at producer teardown).
 *
 * Returns `OvStorage_Status_Ok` on success. `handle` or `out_handle` NULL
 * yields `InvalidArgument` and writes nothing; the built stack is
 * unaffected. `error` receives the message on failure (may be NULL).
 *
 * # Safety
 *
 * `handle` must be a live `OvStorage_LayerHandle*` from
 * `ovstorage_stack_build`; `out_handle` must point at writable storage for
 * one `OvStoragePlugin_LayerHandle`; `error` must be NULL or a valid
 * `OvStorage_Error*`.
 */
OvStorage_Status ovstorage_export_handle(const OvStorage_LayerHandle *handle,
                                         OvStoragePlugin_LayerHandle *out_handle,
                                         OvStorage_Error *out_error);

/**
 * Take ownership of an `OvStoragePlugin_LayerHandle` and re-seat it as a
 * driveable `OvStorage_LayerHandle*`, written into `*out_handle`. This is
 * the consume side of the cross-language live handoff.
 *
 * A handle minted by *this* cdylib (its `vtable` is this image's Layer
 * vtable) unwraps back to the original `Arc` with zero FFI, preserving
 * `Arc` identity across an export/import round-trip. Anything else — a
 * handle from another linked image (host, a second copy of the cdylib, or
 * a pure-C / Python producer) — is validated against the ABI handshake and
 * wrapped in an adapter that drives the producer's vtable slot-by-slot. The
 * imported root dispatches on the same process-global runtime a built Stack
 * uses.
 *
 * Ownership transfer and failure disposal (normative):
 * - On success the handle is consumed; the resulting
 *   `OvStorage_LayerHandle*` is freed with `ovstorage_layer_handle_destroy`
 *   like any built root, and dropping it releases the producer-side `Arc`.
 * - `vtable->abi_version` not supported by this build →
 *   `OvStorage_Status_IncompatibleType`, and the handle **is consumed**
 *   (dropped via its `drop` slot, which immediately follows the stable
 *   `{struct_size, abi_version}` vtable header).
 * - NULL `state`/`vtable` → `InvalidArgument`; undersized `vtable`
 *   `struct_size` → `IncompatibleType`. In both cases the handle carries no
 *   trustworthy `drop` slot, so it is **not** disposed and the caller
 *   retains whatever it passed.
 * - `out_handle` NULL → `InvalidArgument` before the handle is touched; the
 *   caller retains it.
 *
 * # Raw-vtable consumption (driving the handle without importing it)
 *
 * A caller may skip `ovstorage_import_handle` and drive an
 * `OvStoragePlugin_LayerHandle` directly through the vtable declared in
 * `ovstorage_plugin.h` (`OvStoragePlugin_LayerVTableV1`). The contract:
 * - **Callback shape.** Object/connection ops are asynchronous and take an
 *   `on_complete(status, result, error, user_data)` callback that fires
 *   exactly once, possibly on a producer runtime thread. `status == 0`
 *   (`FFI_STATUS_OK`) is success; otherwise `error` is non-NULL. Identity
 *   slots (`name`, `descriptor`, `owned_targets`) are synchronous and write
 *   their owned output into an out-param.
 * - **Result/error reclaim.** On the completion callback, ownership of the
 *   non-NULL `result` and `error` transfers to the receiver, which must
 *   free each through the matching plugin free fn (or `ovc_abi_free` under
 *   the shared allocator contract). Every `const *` input to a slot
 *   transfers to the producer at the call and must be consumed
 *   synchronously — do not hold an input pointer across the async boundary.
 * - **Drop obligations.** The handle owns `state`; invoke `vtable->drop(
 *   state)` exactly once when done, after every in-flight op has completed.
 *   Never drive a slot after drop.
 * - **Thread contract.** Slots may be invoked concurrently from multiple
 *   threads (the host itself dispatches I/O from a worker pool); `drop` is
 *   exclusive-after-drain. The producer runtime must stay alive for the
 *   life of the handle.
 * - **Derived handles.** A handle a completed op hands back -- a body, a
 *   change stream, an auth-event stream, a root or connection update stream
 *   -- is owned by the HOST and may outlive the Layer that produced it. The
 *   host routinely drops its Layer reference and keeps pulling such a
 *   stream. `drop(state)` therefore relinquishes the handle's owned
 *   reference and may free layer state, but it must not invalidate any live
 *   derived handle: each one must be self-contained, or own all producer
 *   state it needs -- normally through a counted reference. The producer
 *   runtime must outlive every live derived handle too, not just the handle
 *   that produced them.
 *
 * # Safety
 *
 * Trusted like a plugin load (cf. `ovstorage_load_plugin`): `handle` must
 * be a live Layer-ABI `{state, vtable}` pair whose producer outlives every
 * use of the imported layer, and ownership must genuinely transfer to this
 * call (it must not be driven or dropped elsewhere afterwards).
 * `out_handle` must point at writable storage for one
 * `OvStorage_LayerHandle*`; `error` must be NULL or a valid
 * `OvStorage_Error*`.
 */
OvStorage_Status ovstorage_import_handle(OvStoragePlugin_LayerHandle handle,
                                         OvStorage_LayerHandle **out_handle,
                                         OvStorage_Error *out_error);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* OVSTORAGE_H */
