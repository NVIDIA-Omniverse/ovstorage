/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Private portability interface for the pure-C ovstorage implementation.
 */

/*
 * This header must be the first include in every ovstorage-c-source
 * translation unit.  In particular, these feature-test macros have to be
 * visible before any libc header is included.
 */
#if !defined(_WIN32)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#if _POSIX_C_SOURCE < 200809L
#error "ovstorage-c-source requires _POSIX_C_SOURCE >= 200809L"
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#if _XOPEN_SOURCE < 700
#error "ovstorage-c-source requires _XOPEN_SOURCE >= 700"
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#endif

#ifndef OVSTORAGE_C_SOURCE_INTERNAL_H
#define OVSTORAGE_C_SOURCE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "ovstorage.h"
#include "ovstorage_plugin.h"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
/* SRW locks and condition variables are available starting with Vista. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>

typedef struct ovc_thread {
    HANDLE handle;
    int joinable;
} ovc_thread;

typedef struct ovc_mutex {
    SRWLOCK native;
} ovc_mutex;

typedef struct ovc_cond {
    CONDITION_VARIABLE native;
} ovc_cond;

typedef HMODULE ovc_dlhandle;
typedef HANDLE ovc_file;
typedef intptr_t ovc_ssize_t;

#define OVC_MUTEX_INITIALIZER { SRWLOCK_INIT }
#define OVC_COND_INITIALIZER { CONDITION_VARIABLE_INIT }
#define OVC_INVALID_FILE INVALID_HANDLE_VALUE
#define OVC_PATH_SEPARATOR '\\'

#else

#include <pthread.h>
#include <sys/types.h>

typedef struct ovc_thread {
    pthread_t handle;
    int joinable;
} ovc_thread;

typedef struct ovc_mutex {
    pthread_mutex_t native;
} ovc_mutex;

typedef struct ovc_cond {
    pthread_cond_t native;
    /* Nonzero when the condition waits against CLOCK_MONOTONIC (set by
     * ovc_cond_init where the platform supports it). */
    int monotonic;
} ovc_cond;

typedef void *ovc_dlhandle;
typedef int ovc_file;
typedef ssize_t ovc_ssize_t;

#define OVC_MUTEX_INITIALIZER { PTHREAD_MUTEX_INITIALIZER }
#define OVC_COND_INITIALIZER { PTHREAD_COND_INITIALIZER, 0 }
#define OVC_INVALID_FILE (-1)
#define OVC_PATH_SEPARATOR '/'

#endif

/*
 * Private value representations.
 *
 * OvStorage_Error and OvStorage_Bytes are complete public structs in
 * ovstorage.h, so they cannot be defined again here.  These aliases record
 * that their public layouts are also the pure-C implementation layouts.
 * Error messages and non-NULL Bytes::free_ctx values always point at
 * allocations that may be released with free().  Bytes::data borrows from
 * the free_ctx allocation and is never released separately.
 */
typedef OvStorage_Error ovc_error;
typedef OvStorage_Bytes ovc_bytes;

/* GCC/Clang __sync builtins and Win32 Interlocked operations use this field. */
typedef struct ovc_ref_count {
    volatile long value;
} ovc_ref_count;

#define OVC_REF_COUNT_INITIALIZER { 1L }

typedef OvStorage_MetadataEntry ovc_metadata_entry;

/* An owned byte slice.  ptr is not required to be NUL-terminated. */
typedef struct ovc_string_slice {
    char *ptr;
    size_t len;
} ovc_string_slice;

typedef union ovc_config_value_payload {
    char *string;
    int64_t integer;
    bool boolean;
} ovc_config_value_payload;

struct OvStorage_ConfigValue {
    OvStorage_ConfigValueKind kind;
    ovc_config_value_payload payload;
};

struct OvStorage_UpdateMetadataOptions {
    ovc_metadata_entry *set_entries;
    size_t set_len;
    size_t set_capacity;
    char **remove_keys;
    size_t remove_len;
    size_t remove_capacity;
};

typedef void (*ovc_local_delegate_release_fn)(void *context);

struct OvStorage_LocalDelegate {
    char *path;
    OvStorage_Info *info;
    ovc_local_delegate_release_fn release;
    void *release_context;
};

typedef struct ovc_kind_descriptor {
    int32_t layer_type;
    ovc_string_slice kind;
    ovc_string_slice display_name;
} ovc_kind_descriptor;

/*
 * Descriptor slices point into string_storage.  The storage contains exact
 * bytes with no terminators inserted; an empty valid slice therefore still
 * uses a non-NULL pointer.  Accessors reject an interior NUL at read time as
 * required by the frozen header contract.
 */
struct OvStorage_KindDescriptorList {
    ovc_kind_descriptor *items;
    size_t len;
    char *string_storage;
};

/*
 * Registry factory ownership.
 *
 * A loaded plugin has one ref-counted registration shared by all of its
 * advertised factories.  Each factory is itself ref-counted: the public
 * Plugin handle, a Registry entry, and a Stack declaration may therefore
 * retain it independently.  Releasing the final factory releases the plugin
 * registration; releasing the final registration calls plugin_vtable->drop.
 * The dynamic-library mapping is deliberately not closed (see ovc_dlopen).
 */
typedef struct ovc_plugin_registration ovc_plugin_registration;

typedef struct ovc_layer_factory {
    ovc_ref_count references;
    ovc_plugin_registration *registration;
    void *plugin_state;
    const OvStoragePlugin_PluginVTableV1 *plugin_vtable;
    const OvStoragePlugin_LayerKindDescriptor *descriptor;
    OvStoragePlugin_LayerType layer_type;
    bool accepts_connections;
    ovc_string_slice kind;
    ovc_string_slice display_name;
} ovc_layer_factory;

struct OvStorage_Plugin {
    ovc_plugin_registration *registration;
    ovc_layer_factory **factories;
    size_t factory_count;
};

struct OvStorage_Registry {
    ovc_layer_factory **factories;
    size_t factory_count;
    size_t factory_capacity;
};

typedef struct ovc_config_entry {
    char *key;
    OvStorage_ConfigValue *value;
} ovc_config_entry;

/*
 * Mutable Stack-builder recording.
 *
 * The first declaration of each kind pins its registry-resolved factory, and
 * later declarations of that kind retain the same factory (matching the frozen
 * first-factory-wins builder).  Each declaration still snapshots layer_type
 * from the descriptor resolved by its own add_layer call.  Callers may destroy
 * the Registry (and original Plugin handle) before building or destroying the
 * Stack.  Edges are recorded by instance name rather than by declaration
 * position.  This recording phase validates that named endpoints already
 * exist and that set_inner/set_children target the right layer type.
 *
 * Whole-graph shape rules remain build-time concerns: build chooses the graph
 * reachable from root (leaving orphan declarations uninstantiated), rejects
 * cycles/repeated references, and rejects required edges left unset (for
 * example, a wrapper without inner).  Recording an edge therefore never walks
 * the graph and deliberately permits a self-edge until build.
 */
typedef struct ovc_stack_layer {
    char *instance_id;
    ovc_layer_factory *factory;
    OvStoragePlugin_LayerType layer_type;
    ovc_config_entry *config;
    size_t config_len;
    size_t config_capacity;
    char *inner_id;
    char **child_ids;
    size_t child_count;
} ovc_stack_layer;

typedef struct ovc_stack_connection {
    char *target;
    OvStorage_ConnectionRequest *request;
} ovc_stack_connection;

struct OvStorage_Stack {
    char *root_id;
    ovc_stack_layer *layers;
    size_t layer_count;
    size_t layer_capacity;
    ovc_stack_connection *connections;
    size_t connection_count;
    size_t connection_capacity;
};

/* Connection/auth values are copied out of plugin-ABI values before use. */
typedef struct ovc_secret_bytes {
    uint8_t *data;
    size_t len;
} ovc_secret_bytes;

typedef enum ovc_secret_value_kind {
    OVC_SECRET_VALUE_BYTES = 0,
    OVC_SECRET_VALUE_OAUTH_TOKEN = 1,
    OVC_SECRET_VALUE_FILE = 2,
    OVC_SECRET_VALUE_MTLS_CERT_PAIR = 3,
    OVC_SECRET_VALUE_SYSTEM_IDENTITY = 4
} ovc_secret_value_kind;

typedef struct ovc_secret_oauth_token {
    ovc_secret_bytes token;
    bool has_refresh;
    ovc_secret_bytes refresh;
    bool has_expires_at;
    uint64_t expires_at_unix_nanos;
} ovc_secret_oauth_token;

typedef struct ovc_secret_mtls_cert_pair {
    ovc_secret_bytes cert_pem;
    ovc_secret_bytes key_pem;
} ovc_secret_mtls_cert_pair;

typedef union ovc_secret_value_payload {
    ovc_secret_bytes bytes;
    ovc_secret_oauth_token oauth_token;
    ovc_secret_mtls_cert_pair mtls_cert_pair;
} ovc_secret_value_payload;

struct OvStorage_SecretValue {
    ovc_secret_value_kind kind;
    ovc_secret_value_payload payload;
};

typedef struct ovc_secret_entry {
    char *key;
    OvStorage_SecretValue *value;
} ovc_secret_entry;

struct OvStorage_SecretBundle {
    ovc_secret_entry *entries;
    size_t len;
    size_t capacity;
    bool consumed;
};

struct OvStorage_ConnectionRequest {
    char *backend_kind;
    ovc_config_entry *config;
    size_t config_len;
    size_t config_capacity;
    OvStorage_SecretBundle credentials;
    bool persist;
    char *display_name;
    bool consumed;
};

#ifdef __cplusplus
extern "C" {
#endif

/** Worker entry point used by ovc_thread_create. */
typedef void (*ovc_thread_fn)(void *argument);

/* Thread functions return zero on success and a nonzero platform error. */
int ovc_thread_create(ovc_thread *thread, ovc_thread_fn function, void *argument);
int ovc_thread_join(ovc_thread *thread);

int ovc_mutex_init(ovc_mutex *mutex);
int ovc_mutex_destroy(ovc_mutex *mutex);
int ovc_mutex_lock(ovc_mutex *mutex);
int ovc_mutex_unlock(ovc_mutex *mutex);

int ovc_cond_init(ovc_cond *condition);
int ovc_cond_destroy(ovc_cond *condition);
int ovc_cond_wait(ovc_cond *condition, ovc_mutex *mutex);
int ovc_cond_signal(ovc_cond *condition);
int ovc_cond_broadcast(ovc_cond *condition);

/**
 * Wait on `condition` for at most `wait_ns` nanoseconds.  Returns zero when
 * signalled, ETIMEDOUT when the wait elapsed, and another nonzero platform
 * error on failure.  The wait is measured against a monotonic clock where
 * the platform provides one, so a wall-clock step cannot stall it.  Callers
 * re-check their predicate on return, exactly as with ovc_cond_wait.
 */
int ovc_cond_timedwait_ns(ovc_cond *condition,
                          ovc_mutex *mutex,
                          uint64_t wait_ns);

/** A process-global runtime work item. */
typedef void (*ovc_runtime_task_fn)(void *argument);

/**
 * One-shot completion latch that turns an async callback into a blocking
 * internal helper.  Completion is sticky, so completing before wait is safe.
 * A runtime worker must not wait for work submitted to the same fixed-size
 * pool: exhausting every worker that way would deadlock.
 */
typedef struct ovc_completion_latch {
    ovc_mutex mutex;
    ovc_cond condition;
    int completed;
} ovc_completion_latch;

/**
 * Resolve the pure-C runtime worker count without reading process state.
 *
 * A nonzero requested value wins.  Otherwise a strict, positive base-ten
 * environment value wins.  If neither is present, hardware_parallelism is
 * clamped to the inclusive range [2, 32].
 */
uint32_t ovc_runtime_resolve_threads(uint32_t requested,
                                     const char *env_value_string,
                                     uint32_t hw_parallelism);

/**
 * Ensure that the process-lifetime worker pool exists.
 *
 * The first successful call fixes its size.  A later conflicting explicit
 * request is ignored with a warning.  There is deliberately no teardown API:
 * Stack destruction must not stop a runtime shared by another Stack.
 */
int ovc_runtime_ensure(uint32_t requested);

/** Return the fixed worker count, or zero before successful initialization. */
uint32_t ovc_runtime_worker_count(void);

/**
 * Queue one task on the initialized process-global runtime.
 *
 * A nonzero return guarantees that the function was not queued.  After a
 * successful return, argument must remain valid until function returns.
 */
int ovc_runtime_submit(ovc_runtime_task_fn function, void *argument);

#if defined(OVC_RUNTIME_TEST_MAIN) || \
    defined(OVC_RUNTIME_TEST_QUIESCENCE)
/**
 * Wait until the test-instrumented runtime has no queued or executing tasks.
 *
 * The caller must first stop every external producer. Runtime tasks may still
 * submit follow-up work: the outstanding count covers that transitive work.
 * Returns ETIMEDOUT when the runtime does not quiesce within timeout_ns.
 *
 * This is deliberately absent from production builds. It exists for the
 * embedded runtime suite and the Windows CRT leak gate, whose final heap
 * snapshot must not race detached cleanup tasks.
 */
int ovc_runtime_wait_for_idle(uint64_t timeout_ns);
#endif

int ovc_completion_latch_init(ovc_completion_latch *latch);
int ovc_completion_latch_complete(ovc_completion_latch *latch);
int ovc_completion_latch_wait(ovc_completion_latch *latch);
int ovc_completion_latch_destroy(ovc_completion_latch *latch);

/*
 * Successfully initialized dynamic-library mappings are deliberately
 * process-lifetime: plugins may retain host callbacks, and inspect_plugin's
 * frozen contract requires load + init + permanent pinning.  ovc_dlclose
 * exists only for load-validation failures that occur *before* the plugin's
 * init function has run — once init ran, a mapping must never be closed.
 */
ovc_dlhandle ovc_dlopen(const char *utf8_path); /* utf8_path must be non-NULL. */
void ovc_dlclose(ovc_dlhandle handle);          /* NULL-tolerant. */
void *ovc_dlsym(ovc_dlhandle handle,
                const char *symbol_name); /* Arguments must be non-NULL. */
const char *ovc_dlerror(void);

/*
 * Release every buffer a snapshot owns and zero the struct in place, leaving
 * the struct's own storage to the caller.  A second call is a no-op.  The
 * storage may be an interior element of a list's contiguous item array, so
 * these functions never free the struct itself; each public `_destroy`
 * function is clear-then-free over an independently allocated snapshot.
 */
void ovc_info_clear(OvStorage_Info *info);

void ovc_checksums_destroy(const OvStorage_ChecksumEntry *entries,
                          size_t length);
void ovc_connection_clear(OvStorage_Connection *connection);
void ovc_root_info_clear(OvStorage_RootInfo *info);

/*
 * Zeroize a secret's buffer in place, leaving it allocated and owned.  The
 * secret-clearing path calls this before releasing; it is separate so the
 * wipe can be exercised without also freeing the buffer it just cleared,
 * mirroring the Rust codec's SecretBytes::wipe.
 */
void ovc_pval_secret_bytes_wipe(OvStoragePlugin_SecretBytes *value);

/*
 * Release every buffer a plugin-minted `Error` owns — message, context, and
 * next-action hint — leaving the struct's own storage to the caller, which
 * may be heap (ovc_abi_free) or stack.  The cleared fields are left NULL and
 * zero-length, so a second call is a no-op.
 *
 * The single definition of what an `Error` owns.  Every reclamation path
 * routes through here rather than open-coding the field frees: a field added
 * to the struct is then released everywhere at once, which an open-coded
 * destructor per surface is not (the next_action hint leaked from the Stack
 * and Dispatch surfaces precisely because they each had their own).
 */
void ovc_pval_error_clear(OvStoragePlugin_Error *error);

/*
 * Allocator for values that cross the plugin ABI in either direction.  The
 * Rust marshalling code mints and reclaims these buffers with Rust's System
 * allocator, which resolves to the same pair: malloc/free on POSIX and the
 * process heap on Win32.  That pair names one heap the whole process agrees
 * on, which is the point — the Rust global allocator is a per-binary choice
 * (`#[global_allocator]`), so a value minted on it in one image is not
 * releasable from another.  Every allocation a plugin adopts, and every
 * plugin-produced allocation the host releases, must go through this pair;
 * host-internal allocations remain ordinary C
 * allocations.  ovc_abi_alloc returns a one-byte block for a zero size and
 * NULL on failure; ovc_abi_free is NULL-tolerant.  ovc_abi_copy_bytes
 * returns an ABI copy of `bytes` (a one-byte zeroed block for a zero size)
 * or NULL on failure.
 */
void *ovc_abi_alloc(size_t byte_count);
void ovc_abi_free(void *allocation);
void *ovc_abi_copy_bytes(const void *bytes, size_t byte_count);

/* Validate exactly `length` bytes as Unicode UTF-8. NULL is accepted only
 * for an empty slice. This checks encoding only; callers that forbid an
 * interior NUL enforce that separately. */
bool ovc_utf8_is_valid(const void *value, size_t length);

/*
 * Status/error taxonomy shared by dispatch.c, stack.c, and the public
 * error accessors.  The tables live in values.c, in the declaration
 * order of `OvStorage_Status` and `OvStoragePlugin_ErrorCode`; keep them
 * that way so a code added to either enum is an obvious gap in review.
 */

/**
 * Public status for a plugin ABI error code.  A code minted by a newer
 * plugin ABI reports OvStorage_Status_Internal, per the unknown-code
 * forward-compat rule.
 */
OvStorage_Status ovc_status_from_plugin_code(OvStoragePlugin_ErrorCode code);

/**
 * Stable ErrorCode variant name for a plugin ABI error code (matches the
 * Rust `ErrorCode::as_str`).  Unknown codes report "Internal".  The
 * result is a static string; it is never freed.
 */
const char *ovc_plugin_error_code_name(OvStoragePlugin_ErrorCode code);

/**
 * Canonical same-named ErrorCode name for a status this implementation
 * mints directly (every non-Ok status has one), or NULL for Ok and
 * unknown values.  The result is a static string; it is never freed.
 */
const char *ovc_status_code_name(OvStorage_Status status);

/** ABI-v2 entry point exported as `ovstorage_plugin_init_v1`. */
typedef OvStoragePlugin_PluginInitResultV1 (*ovc_plugin_init_v1_fn)(
    const OvStoragePlugin_HostCallbacks *host);

/**
 * Retain/release one registry factory.  `retain` returns NULL only on a NULL
 * input or reference-count overflow.  A retained factory keeps its plugin
 * state alive but never assumes ownership of the loader mapping.
 */
ovc_layer_factory *ovc_layer_factory_retain(
    const ovc_layer_factory *factory);
void ovc_layer_factory_release(ovc_layer_factory *factory);

/**
 * Borrow the last-registered factory whose kind is exactly the supplied C
 * string.  The result remains valid only while the Registry is alive unless
 * the caller retains it with `ovc_layer_factory_retain`.
 */
const ovc_layer_factory *ovc_registry_find_factory(
    const OvStorage_Registry *registry,
    const char *kind);

/**
 * Add one process-lifetime built-in factory to a Registry.
 *
 * `descriptor`, `plugin_state`, and `plugin_vtable` are borrowed static
 * objects supplied by the pure-C built-in implementation.  Unlike a loaded
 * plugin, their state is not dropped when the factory is released.  The
 * matching create_* slot is validated from descriptor->layer_type.
 */
OvStorage_Status ovc_registry_register_builtin_kind(
    OvStorage_Registry *registry,
    const OvStoragePlugin_LayerKindDescriptor *descriptor,
    void *plugin_state,
    const OvStoragePlugin_PluginVTableV1 *plugin_vtable,
    OvStorage_Error *out_error);

/**
 * Distribution-owned built-in enumeration hook.
 *
 * file_backend.c is the source of truth for the pure-C built-in set and calls
 * `ovc_registry_register_builtin_kind` for each kind it ships.  Returning an
 * error makes `ovstorage_registry_create` fail rather than expose an
 * accidentally unseeded Registry.
 */
OvStorage_Status ovstorage_c_register_builtin_kinds(
    OvStorage_Registry *registry,
    OvStorage_Error *out_error);

/*
 * Positioned I/O returns a byte count, or -1 with errno set.  On Win32,
 * ovc_file must have been opened with FILE_FLAG_OVERLAPPED so these calls do
 * not mutate a shared file pointer.
 */
ovc_ssize_t ovc_pread(ovc_file file,
                      void *buffer,
                      size_t byte_count,
                      uint64_t offset);
ovc_ssize_t ovc_pwrite(ovc_file file,
                       const void *buffer,
                       size_t byte_count,
                       uint64_t offset);

/** Irrecoverably overwrite byte_count bytes at data. */
void ovc_secure_zero(void *data, size_t byte_count);

/* Read an environment variable as an OWNED string on every platform, or NULL
 * when unset or on failure (errno set).
 *
 * The ownership is uniform on purpose. Win32 has no thread-safe borrowing
 * form -- `getenv` there returns a pointer into a snapshot that
 * `_putenv`/`_wputenv` can invalidate -- so without this helper each caller needs
 * `_dupenv_s` under `#if defined(_WIN32)` and plain `getenv` otherwise,
 * carrying its own conditional declarations, free and error path. Every
 * environment-backed option repeats that bookkeeping. Always-owned costs one
 * `strdup` on POSIX and removes the conditional from the callers. */
char *ovc_env_dup(const char *name);

#if defined(_WIN32)
/* UTF-8 <-> UTF-16 for the Win32 path APIs. Owned result, NULL with errno
 * on failure.
 *
 * One pair, in the portability layer, so a Unicode or error-mapping change
 * is made once rather than in every module that converts a path. Callers must reach for the WIDE Win32 entry points: the ANSI
 * ones transcode through the active code page and mangle or reject a path
 * that UTF-8 represents fine. */
wchar_t *ovc_utf8_to_wide(const char *utf8);
char *ovc_wide_to_utf8(const wchar_t *wide);

/* Set `errno` from a Win32 error code, for the same reason as the pair above.
 *
 * The single mapping for the whole source set: plat.c, file_backend.c and
 * temp_dir.c all translate through it, so a given Win32 code yields the same
 * errno whichever module reports it. Coverage spans the process-level codes
 * (EBADF, ENOMEM, ECANCELED, EOVERFLOW) and the filesystem ones (EEXIST,
 * EXDEV, ENOTEMPTY, ENAMETOOLONG); an unrecognised code is EIO.
 *
 * Add a case here rather than translating locally at a call site: a local
 * table covers only the codes its author happened to need, and the same
 * failure then reports a specific errno on one path and EIO on another. */
void ovc_win32_set_errno(DWORD error);
#endif

/** Return monotonic nanoseconds, or zero with errno set if the clock fails. */
uint64_t ovc_monotonic_ns(void);

/** Return the number of online logical processors, falling back to one. */
unsigned int ovc_cpu_count(void);

/**
 * Ensure that the process-global plugin auth substrate exists.
 *
 * This is the load/inspect-plugin entry point.  Unlike the public
 * explicit-init function, it accepts any substrate that an earlier explicit
 * call pinned; the environment/temp-directory default is resolved only when
 * this call wins first initialization.
 */
OvStorage_Status ovc_auth_substrate_auto_init(OvStorage_Error *out_error);

/**
 * Return the process-lifetime callback table passed to plugin init functions.
 *
 * This accessor auto-initializes the default substrate and returns NULL only
 * when that initialization fails.  Callers that need the failure detail call
 * `ovc_auth_substrate_auto_init` first with an error output.
 */
const OvStoragePlugin_HostCallbacks *ovc_host_callbacks_get(void);

/**
 * Build the plugin-ABI view of a host cancellation token.
 *
 * The returned value owns one state reference.  It is borrowed by a plugin
 * vtable only for that call's synchronous prologue; after the vtable returns,
 * the caller must invoke `value.drop(value.state)`.  A plugin that retains the
 * state beyond the prologue uses the ABI's clone/drop pair.
 *
 * A NULL host token mints an independent never-canceled state, so plugins see
 * the complete CancelTokenFFI contract even for an uncancellable operation.
 */
OvStoragePlugin_CancelTokenFFI
ovc_cancel_token_mint(const OvStorage_CancelToken *token);

/*
 * Cancellation scope shared by a stream-producing operation and its pump.
 *
 * The scope owns a private host token.  It must be created before invoking the
 * producer, and a value returned by `ovc_stream_cancel_scope_mint_producer`
 * must be passed to that producer.  Cancellation of `parent`, when non-NULL,
 * is forwarded into the private token without retaining the parent's public
 * wrapper pointer.  Closing the eventual pump cancels that same private token,
 * which is the producer's signal to wake a blocking stream `next_fn`.
 */
typedef struct ovc_stream_cancel_scope ovc_stream_cancel_scope;

ovc_stream_cancel_scope *
ovc_stream_cancel_scope_create(const OvStorage_CancelToken *parent);

/**
 * Mint the producer-facing ABI token.  The returned value owns one reference;
 * drop it after the producer vtable's synchronous prologue returns.
 */
OvStoragePlugin_CancelTokenFFI
ovc_stream_cancel_scope_mint_producer(
    const ovc_stream_cancel_scope *scope);

/** Request cancellation of the producer-facing token. */
void ovc_stream_cancel_scope_cancel(ovc_stream_cancel_scope *scope);

/** Return whether the producer-facing token has been canceled. */
bool ovc_stream_cancel_scope_is_canceled(
    const ovc_stream_cancel_scope *scope);

/**
 * Cancel the producer, unregister parent forwarding, and release the scope.
 * A scope transferred to a pump is destroyed by `ovc_stream_pump_destroy`.
 */
void ovc_stream_cancel_scope_destroy(ovc_stream_cancel_scope *scope);

/*
 * Dedicated-thread adapters for the frozen blocking-pull stream ABI.
 *
 * A successful start transfers `stream`, `stream_owner`, and `cancel_scope`
 * to the returned pump, but leaves the worker behind a one-shot start barrier.
 * The caller first publishes the pump in its owning LayerHandle and then calls
 * `ovc_stream_pump_arm`; no `next_fn` or callback can run before that call.
 * `stream_owner` is a non-NULL outer allocation or producer-specific wrapper
 * context.  `reclaim_stream(stream_owner)` must invoke the producing module's
 * correct stream destructor; that destructor drives the stream's `drop_fn`
 * exactly once and releases its outer allocation.  The callback is invoked
 * by the pump only after the last `next_fn` has returned.  On start failure,
 * ownership remains with the caller.
 *
 * Item callbacks consume the initialized plugin-ABI item before returning.
 * `deliver == true` means convert it and fire the public host callback;
 * `deliver == false` means release it without a host fire because cancellation
 * won the race with `next_fn`.
 *
 * The terminal callback fires exactly once.  `error` is initialized and must
 * be consumed when non-NULL.  It can accompany CANCELED when the producer
 * returned Failed while cancellation was being observed; in that case the
 * callback releases the plugin error but reports cancellation to the host.
 * The dispatch adapter maps ENDED to the frozen success final-fire
 * (`event/chunk empty, error NULL, done true`) and every other reason to its
 * terminal-error final-fire (`event/chunk empty, error non-NULL, done true`).
 */
typedef struct ovc_stream_pump ovc_stream_pump;

typedef enum ovc_stream_terminal_reason {
    OVC_STREAM_TERMINAL_ENDED = 0,
    OVC_STREAM_TERMINAL_FAILED = 1,
    OVC_STREAM_TERMINAL_CANCELED = 2,
    OVC_STREAM_TERMINAL_PROTOCOL_ERROR = 3
} ovc_stream_terminal_reason;

typedef void (*ovc_stream_reclaim_fn)(void *stream_owner);

typedef void (*ovc_auth_stream_item_fn)(
    OvStoragePlugin_AuthEvent *event,
    bool deliver,
    void *user_data);

typedef void (*ovc_byte_stream_item_fn)(
    OvStoragePlugin_Bytes *chunk,
    bool deliver,
    void *user_data);

typedef void (*ovc_backend_change_stream_item_fn)(
    OvStoragePlugin_BackendChangeEvent *event,
    bool deliver,
    void *user_data);

typedef void (*ovc_stream_terminal_fn)(
    ovc_stream_terminal_reason reason,
    OvStoragePlugin_Error *error,
    void *user_data);

int ovc_auth_stream_pump_start(
    ovc_stream_pump **out_pump,
    OvStoragePlugin_AuthEventStream *stream,
    void *stream_owner,
    ovc_stream_reclaim_fn reclaim_stream,
    ovc_stream_cancel_scope *cancel_scope,
    ovc_auth_stream_item_fn on_event,
    ovc_stream_terminal_fn on_terminal,
    void *user_data);

int ovc_byte_stream_pump_start(
    ovc_stream_pump **out_pump,
    OvStoragePlugin_BodyStream *stream,
    void *stream_owner,
    ovc_stream_reclaim_fn reclaim_stream,
    ovc_stream_cancel_scope *cancel_scope,
    ovc_byte_stream_item_fn on_chunk,
    ovc_stream_terminal_fn on_terminal,
    void *user_data);

int ovc_backend_change_stream_pump_start(
    ovc_stream_pump **out_pump,
    OvStoragePlugin_BackendChangeStream *stream,
    void *stream_owner,
    ovc_stream_reclaim_fn reclaim_stream,
    ovc_stream_cancel_scope *cancel_scope,
    ovc_backend_change_stream_item_fn on_event,
    ovc_stream_terminal_fn on_terminal,
    void *user_data);

/** Release the start barrier after the owner has recorded the pump handle. */
void ovc_stream_pump_arm(ovc_stream_pump *pump);

/**
 * Signal a cooperative stop; the terminal callback reports cancellation.
 * This is not a quiescence barrier: use destroy when callbacks must be done.
 */
void ovc_stream_pump_cancel(ovc_stream_pump *pump);

/**
 * Cancel, join the dedicated thread, and release the pump handle.
 *
 * Item and terminal callbacks run on that dedicated thread.  They must not
 * synchronously destroy this pump or its owning LayerHandle; schedule that
 * destruction on another thread so this function can perform the required
 * join before the Layer vtable is dropped.
 */
void ovc_stream_pump_destroy(ovc_stream_pump *pump);

/*
 * Snapshot-only public calls never drain these update channels.  These
 * helpers synchronously invoke the producer-correct stream destructor.
 */
int ovc_root_updates_discard(
    OvStoragePlugin_RootInfoChangeStream *stream,
    void *stream_owner,
    ovc_stream_reclaim_fn reclaim_stream);

int ovc_connection_updates_discard(
    OvStoragePlugin_ConnectionChangeStream *stream,
    void *stream_owner,
    ovc_stream_reclaim_fn reclaim_stream);

/** Mark a builder handed off, rejecting a repeated handoff. */
bool ovc_connection_request_mark_consumed(OvStorage_ConnectionRequest *request);
bool ovc_secret_bundle_mark_consumed(OvStorage_SecretBundle *bundle);

/** Return nonzero when character is a native path separator. */
int ovc_path_is_separator(char character);

/** Return nonzero when a UTF-8 path is absolute on the current platform. */
int ovc_path_is_absolute(const char *utf8_path);

/**
 * Allocate base + one native separator + child as a UTF-8 path.
 *
 * A duplicate separator at the join is collapsed.  The caller owns the
 * returned allocation.  NULL is returned with errno set on failure.
 */
char *ovc_path_join(const char *base, const char *child);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OVSTORAGE_C_SOURCE_INTERNAL_H */
