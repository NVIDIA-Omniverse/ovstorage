/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Parked async cancellable operation over the pure-C runtime, driven against
 * the Rust `ovstorage-plugin-test-abi` parking fixture.
 *
 * WHY ROOT DISCOVERY, NOT ovstorage_stack_build_async:
 * ----------------------------------------------------
 * This driver needs a parked build. The parking fixture exposes its
 * `ParkBackend` ONLY through the dlsym'able `ovstorage_test_export_parked_stack`
 * symbol; it is deliberately NOT registered on the plugin's factory set. The
 * pure-C Stack builder (registry.c / stack.c) composes layers ONLY by factory
 * `kind` resolved through a `Registry` (`ovstorage_stack_add_layer` +
 * `ovstorage_stack_add_connection`); there is no public verb that mounts a
 * pre-built / imported handle into a Stack. So a genuinely parked
 * `ovstorage_stack_build_async` against this fixture is not reachable through
 * the real public API, and inventing an FFI is out of scope.
 *
 * The strongest GENUINE parked async operation the fixture supports through the
 * public pure-C surface is its root-discovery slot: import the parked root
 * (`ovstorage_import_handle` — which the pure-C runtime drives across the
 * foreign Rust vtable) and call `ovstorage_list_address_roots`, whose v8 slot
 * parks until released or cancelled. That IS root discovery, exactly the
 * build-time work wu12 targets. The real `ovstorage_stack_build_async`
 * non-blocking / inline-rejection / cancel / builder-reuse contract (over the
 * built-in file backend, which does not park) is pinned by the sibling
 * `stack_async_c.c` driver in this same crate.
 *
 * A genuinely parked `ovstorage_stack_build_async` IS covered, by the sibling
 * `stack_build_abandon_repro.c`: it reaches past the public composition verbs
 * to the internal `ovc_registry_register_builtin_kind`, which lets it register
 * a backend of its own that parks in `add_connection` / `list_address_roots`,
 * and it pins that cancelling such a build reports `Cancelled` instead of
 * hanging. That driver runs as a separate timed process under a sanitizer, so
 * it is not linked into this crate's test binary.
 *
 * This driver pins, over the pure-C runtime:
 *   (a) a parked discovery does not complete while parked and does not block
 *       the caller (a sibling `stat` on this thread progresses meanwhile);
 *   (b) firing the op's cancel token completes it with `Cancelled` (code name
 *       "Cancelled");
 *   (c) the imported root is destructible after the cancelled op, and a fresh
 *       import drives the same slot to a normal completion once released
 *       (reusable).
 *
 * Every wait is a condition-variable latch; the fixture signals arrival the
 * instant its slot parks (`ovstorage_test_park_wait_arrived`), so cancel /
 * release always land on a genuinely in-flight parked op — no sleeps.
 */

#include "ovstorage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include "windows_posix_compat.h"
#else
#include <dlfcn.h>
#include <pthread.h>
#endif

typedef int (*ExportParkedFn)(OvStoragePlugin_LayerHandle *);
typedef void (*ParkVoidFn)(void);

/* Prove config-driven composition resolves a non-built-in kind through the
 * caller's Registry. The same fixture also exports the parked root used below,
 * but its ordinary plugin manifest advertises the `test` backend factory. */
static int config_builds_registered_plugin_kind(const char *fixture_path)
{
    static const char source[] =
        "[ovstorage]\n"
        "root = \"custom\"\n"
        "[ovstorage.layers.custom]\n"
        "kind = \"test\"\n";
    OvStorage_Plugin *plugin = NULL;
    OvStorage_Registry *registry = NULL;
    OvStorage_Registry *unregistered = NULL;
    OvStorage_StackConfig *config = NULL;
    OvStorage_LayerHandle *handle = NULL;
    OvStorage_Error error = {0};
    OvStorage_Status status;
    int result = 0;

    status = ovstorage_load_plugin(fixture_path, true, &plugin, &error);
    if (status != OvStorage_Status_Ok) {
        fprintf(stderr,
                "could not load the config-build plugin: %s\n",
                error.message == NULL ? "(null)" : error.message);
        goto cleanup;
    }
    registry = ovstorage_registry_create();
    if (registry == NULL) {
        fprintf(stderr, "could not create the config-build registry\n");
        goto cleanup;
    }
    status = ovstorage_registry_add_plugin(registry, plugin, &error);
    if (status != OvStorage_Status_Ok) {
        fprintf(stderr,
                "could not register the config-build plugin: %s\n",
                error.message == NULL ? "(null)" : error.message);
        goto cleanup;
    }
    status = ovstorage_stack_config_from_toml_str(source, &config, &error);
    if (status != OvStorage_Status_Ok) {
        fprintf(stderr,
                "could not parse the plugin-backed Stack config: %s\n",
                error.message == NULL ? "(null)" : error.message);
        goto cleanup;
    }
    unregistered = ovstorage_registry_create();
    if (unregistered == NULL) {
        fprintf(stderr, "could not create the unregistered-kind registry\n");
        goto cleanup;
    }
    handle = (OvStorage_LayerHandle *)(uintptr_t)1;
    status = ovstorage_stack_build_from_config(config,
                                               unregistered,
                                               NULL,
                                               &handle,
                                               &error);
    if (status != OvStorage_Status_InvalidArgument || handle != NULL) {
        fprintf(stderr,
                "unregistered `test` kind returned status=%d handle=%p\n",
                (int)status,
                (void *)handle);
        goto cleanup;
    }
    ovstorage_registry_destroy(unregistered);
    unregistered = NULL;
    ovstorage_error_clear(&error);
    status = ovstorage_stack_build_from_config(config,
                                               registry,
                                               NULL,
                                               &handle,
                                               &error);
    if (status != OvStorage_Status_Ok || handle == NULL) {
        fprintf(stderr,
                "could not build the registered `test` kind: status=%d %s\n",
                (int)status,
                error.message == NULL ? "(null)" : error.message);
        goto cleanup;
    }
    result = 1;

cleanup:
    ovstorage_layer_handle_destroy(handle);
    ovstorage_stack_config_destroy(config);
    ovstorage_registry_destroy(unregistered);
    ovstorage_registry_destroy(registry);
    ovstorage_plugin_destroy(plugin);
    ovstorage_error_clear(&error);
    return result;
}

/* --- root-discovery completion latch ------------------------------------- */

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int done;
    OvStorage_Status status;
    OvStorage_RootInfoList *list;
    int had_error;
    const char *code_name; /* static, process-lifetime */
} RootsCompletion;

static int roots_completion_init(RootsCompletion *c)
{
    memset(c, 0, sizeof(*c));
    if (pthread_mutex_init(&c->mutex, NULL) != 0) {
        return 0;
    }
    if (pthread_cond_init(&c->changed, NULL) != 0) {
        (void)pthread_mutex_destroy(&c->mutex);
        return 0;
    }
    c->status = OvStorage_Status_Internal;
    return 1;
}

static void roots_completion_destroy(RootsCompletion *c)
{
    (void)pthread_cond_destroy(&c->changed);
    (void)pthread_mutex_destroy(&c->mutex);
}

static void on_roots(OvStorage_Status status,
                     OvStorage_RootInfoList *list,
                     const OvStorage_Error *error,
                     void *user_data)
{
    RootsCompletion *c = (RootsCompletion *)user_data;

    (void)pthread_mutex_lock(&c->mutex);
    c->status = status;
    c->list = list;
    c->had_error = error != NULL;
    c->code_name = ovstorage_error_code_name(error);
    c->done = 1;
    (void)pthread_cond_signal(&c->changed);
    (void)pthread_mutex_unlock(&c->mutex);
}

static void roots_completion_wait(RootsCompletion *c)
{
    (void)pthread_mutex_lock(&c->mutex);
    while (!c->done) {
        (void)pthread_cond_wait(&c->changed, &c->mutex);
    }
    (void)pthread_mutex_unlock(&c->mutex);
}

static int roots_completion_is_done(RootsCompletion *c)
{
    int done;

    (void)pthread_mutex_lock(&c->mutex);
    done = c->done;
    (void)pthread_mutex_unlock(&c->mutex);
    return done;
}

/* --- sibling stat completion latch --------------------------------------- */

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int done;
    OvStorage_Status status;
    OvStorage_Info *info;
} InfoCompletion;

static void on_stat(OvStorage_Status status,
                    OvStorage_Info *info,
                    const OvStorage_Error *error,
                    void *user_data)
{
    InfoCompletion *c = (InfoCompletion *)user_data;

    (void)error;
    (void)pthread_mutex_lock(&c->mutex);
    c->status = status;
    c->info = info;
    c->done = 1;
    (void)pthread_cond_signal(&c->changed);
    (void)pthread_mutex_unlock(&c->mutex);
}

/* The version pin the Rust fixture answers for its one object when asked. */
static const char PARKED_OBJECT_PIN[] = "park://data/a.bin?version=1";

/* Dispatch `stat` and block on its callback latch. The Rust fixture declares
 * its synthetic validator strong, pinning that the imported ABI field reaches
 * the public C snapshot intact, and answers its version pin only when the
 * options ask for one: with `ask_pin` the pin must arrive, so a request path
 * that drops the flag fails here; without it none may arrive, so a path that
 * invents the flag fails here too. */
static int stat_sync(OvStorage_LayerHandle *handle,
                     const char *address,
                     bool ask_pin)
{
    InfoCompletion c;
    OvStorage_StatOptions options;
    const char *pin;
    int pin_ok;
    int ok;

    memset(&c, 0, sizeof(c));
    if (pthread_mutex_init(&c.mutex, NULL) != 0) {
        return 0;
    }
    if (pthread_cond_init(&c.changed, NULL) != 0) {
        (void)pthread_mutex_destroy(&c.mutex);
        return 0;
    }
    c.status = OvStorage_Status_Internal;
    memset(&options, 0, sizeof(options));
    options.versioned_address = ask_pin;
    ovstorage_stat(handle, address, &options, NULL, on_stat, &c);
    (void)pthread_mutex_lock(&c.mutex);
    while (!c.done) {
        (void)pthread_cond_wait(&c.changed, &c.mutex);
    }
    (void)pthread_mutex_unlock(&c.mutex);
    pin = c.info == NULL ? NULL : c.info->versioned_address;
    pin_ok = ask_pin ? (pin != NULL && strcmp(pin, PARKED_OBJECT_PIN) == 0)
                     : pin == NULL;
    ok = c.status == OvStorage_Status_Ok && c.info != NULL &&
         c.info->etag_strength == OVSTORAGE_ETAG_STRENGTH_STRONG && pin_ok;
    if (c.status == OvStorage_Status_Ok &&
        (c.info == NULL ||
         c.info->etag_strength != OVSTORAGE_ETAG_STRENGTH_STRONG)) {
        fprintf(stderr,
                "imported Rust stat did not preserve its strong etag "
                "declaration\n");
    }
    if (c.status == OvStorage_Status_Ok && c.info != NULL && !pin_ok) {
        if (ask_pin) {
            fprintf(stderr,
                    "imported Rust stat lost the versioned address it asked "
                    "for: %s\n",
                    pin == NULL ? "(NULL)" : pin);
        } else {
            fprintf(stderr,
                    "imported Rust stat carried a versioned address it never "
                    "asked for: %s\n",
                    pin);
        }
    }
    if (c.info != NULL) {
        ovstorage_info_destroy(c.info);
    }
    (void)pthread_cond_destroy(&c.changed);
    (void)pthread_mutex_destroy(&c.mutex);
    return ok;
}

/* --- discovery worker thread --------------------------------------------- */

typedef struct {
    OvStorage_LayerHandle *handle;
    OvStorage_CancelToken *cancel; /* NULL for the release leg */
    RootsCompletion *completion;
} DiscoverArgs;

static void *discover_thread(void *arg)
{
    DiscoverArgs *a = (DiscoverArgs *)arg;
    ovstorage_list_address_roots(a->handle, a->cancel, on_roots, a->completion);
    return NULL;
}

/* --- fixture import ------------------------------------------------------- */

static OvStorage_LayerHandle *import_parked_root(ExportParkedFn export_parked)
{
    OvStoragePlugin_LayerHandle raw;
    OvStorage_LayerHandle *handle = NULL;
    OvStorage_Error error = {0};
    OvStorage_Status status;

    memset(&raw, 0, sizeof(raw));
    if (export_parked(&raw) != 0) {
        fprintf(stderr, "ovstorage_test_export_parked_stack failed\n");
        return NULL;
    }
    status = ovstorage_import_handle(raw, &handle, &error);
    if (status != OvStorage_Status_Ok) {
        fprintf(stderr,
                "ovstorage_import_handle rejected the Rust parked handle: "
                "status=%d message=%s\n",
                (int)status,
                error.message == NULL ? "(null)" : error.message);
        ovstorage_error_clear(&error);
        return NULL;
    }
    return handle;
}

/* Scenario A: cancel a parked discovery, with a sibling stat progressing. */
static int run_cancel_while_parked(ExportParkedFn export_parked,
                                   ParkVoidFn park_wait_arrived)
{
    OvStorage_LayerHandle *handle;
    OvStorage_CancelToken *cancel = NULL;
    RootsCompletion completion;
    DiscoverArgs args;
    pthread_t worker = {0};
    int worker_started = 0;
    int completion_ready = 0;
    int result = 0;

    handle = import_parked_root(export_parked);
    if (handle == NULL) {
        return 0;
    }
    if (!roots_completion_init(&completion)) {
        goto cleanup;
    }
    completion_ready = 1;
    cancel = ovstorage_cancel_token_create();
    if (cancel == NULL) {
        fprintf(stderr, "ovstorage_cancel_token_create failed\n");
        goto cleanup;
    }
    args.handle = handle;
    args.cancel = cancel;
    args.completion = &completion;
    if (pthread_create(&worker, NULL, discover_thread, &args) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        goto cleanup;
    }
    worker_started = 1;

    park_wait_arrived(); /* rendezvous: the discovery slot has parked */

    if (roots_completion_is_done(&completion)) {
        fprintf(stderr, "parked discovery completed before cancel\n");
        goto cleanup;
    }
    /* Unrelated work progresses on this thread while the discovery is parked;
     * one stat asks for the version pin and one does not, so the pure-C
     * request path is proven to carry the flag in both directions. */
    if (!stat_sync(handle, "park://data/a.bin", true) ||
        !stat_sync(handle, "park://data/a.bin", false)) {
        fprintf(stderr, "sibling stat failed while the discovery was parked\n");
        goto cleanup;
    }

    ovstorage_cancel_token_cancel(cancel);
    /* `ovstorage_list_address_roots` dispatches and returns; the callback fires
     * on a runtime thread. Wait on the latch, then reap the worker. */
    roots_completion_wait(&completion);
    (void)pthread_join(worker, NULL);
    worker_started = 0;

    if (completion.status != OvStorage_Status_Cancelled) {
        fprintf(stderr,
                "cancelled discovery reported status %d instead of Cancelled\n",
                (int)completion.status);
        goto cleanup;
    }
    if (!completion.had_error || completion.code_name == NULL ||
        strcmp(completion.code_name, "Cancelled") != 0) {
        fprintf(stderr,
                "cancelled discovery code name was %s instead of Cancelled\n",
                completion.code_name == NULL ? "(null)" : completion.code_name);
        goto cleanup;
    }
    if (completion.list != NULL) {
        fprintf(stderr, "a cancelled discovery must not deliver a list\n");
        goto cleanup;
    }
    result = 1;

cleanup:
    if (worker_started) {
        /* Only reached if a check tripped after the discovery was launched but
         * before it was cancelled. Unpark it (cancel) and drain its callback so
         * it releases its layer ref before the handle/token are destroyed. */
        ovstorage_cancel_token_cancel(cancel);
        roots_completion_wait(&completion);
        (void)pthread_join(worker, NULL);
    }
    if (completion_ready && completion.list != NULL) {
        ovstorage_root_info_list_destroy(completion.list);
    }
    if (cancel != NULL) {
        ovstorage_cancel_token_destroy(cancel);
    }
    if (completion_ready) {
        roots_completion_destroy(&completion);
    }
    if (handle != NULL) {
        ovstorage_layer_handle_destroy(handle); /* destructible after cancel */
    }
    return result;
}

/* Scenario B: release a parked discovery -> normal completion (proves the
 * imported root is reusable via a fresh import + drive). */
static int run_release_while_parked(ExportParkedFn export_parked,
                                    ParkVoidFn park_wait_arrived,
                                    ParkVoidFn release_park_gate)
{
    OvStorage_LayerHandle *handle;
    RootsCompletion completion;
    DiscoverArgs args;
    pthread_t worker = {0};
    int completion_ready = 0;
    int result = 0;

    handle = import_parked_root(export_parked);
    if (handle == NULL) {
        return 0;
    }
    if (!roots_completion_init(&completion)) {
        goto cleanup;
    }
    completion_ready = 1;
    args.handle = handle;
    args.cancel = NULL;
    args.completion = &completion;
    if (pthread_create(&worker, NULL, discover_thread, &args) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        goto cleanup;
    }

    park_wait_arrived();

    if (roots_completion_is_done(&completion)) {
        fprintf(stderr, "parked discovery completed before release\n");
        release_park_gate();
        (void)pthread_join(worker, NULL);
        goto cleanup;
    }
    release_park_gate();
    roots_completion_wait(&completion);
    (void)pthread_join(worker, NULL);

    if (completion.status != OvStorage_Status_Ok) {
        fprintf(stderr,
                "released discovery reported status %d instead of Ok\n",
                (int)completion.status);
        goto cleanup;
    }
    if (completion.list == NULL ||
        completion.list->len != 1) {
        fprintf(stderr, "released discovery did not deliver exactly one root\n");
        goto cleanup;
    }
    result = 1;

cleanup:
    if (completion_ready && completion.list != NULL) {
        ovstorage_root_info_list_destroy(completion.list);
    }
    if (completion_ready) {
        roots_completion_destroy(&completion);
    }
    if (handle != NULL) {
        ovstorage_layer_handle_destroy(handle);
    }
    return result;
}

/* Entry point: `fixture_path` is the workspace `ovstorage-plugin-test-abi`
 * cdylib, located and skip-gated by roundtrip.rs. Returns 0 on success. */
int ovstorage_c_source_stack_build_parked_contract(const char *fixture_path)
{
    void *fixture;
    ExportParkedFn export_parked;
    ParkVoidFn park_wait_arrived;
    ParkVoidFn release_park_gate;
    int i;
    const int iterations = 25;

    if (fixture_path == NULL) {
        fprintf(stderr, "fixture path is null\n");
        return 1;
    }
    if (!config_builds_registered_plugin_kind(fixture_path)) {
        return 1;
    }
    /* RTLD_LOCAL so the fixture's own bundled plugin-SDK symbols never
     * interpose the statically-linked pure-C runtime. */
    fixture = dlopen(fixture_path, RTLD_NOW | RTLD_LOCAL);
    if (fixture == NULL) {
        fprintf(stderr, "dlopen(%s): %s\n", fixture_path, dlerror());
        return 1;
    }
    export_parked =
        (ExportParkedFn)dlsym(fixture, "ovstorage_test_export_parked_stack");
    park_wait_arrived =
        (ParkVoidFn)dlsym(fixture, "ovstorage_test_park_wait_arrived");
    release_park_gate =
        (ParkVoidFn)dlsym(fixture, "ovstorage_test_release_park_gate");
    if (export_parked == NULL || park_wait_arrived == NULL ||
        release_park_gate == NULL) {
        fprintf(stderr, "dlsym of a fixture export failed\n");
        return 1;
    }

    /* The fixture (and the imported roots it produces) may be referenced by the
     * process-global runtime, so it is never dlclose'd — it stays mapped for
     * process lifetime, matching the inspect fixture's pin-for-lifetime
     * contract. */
    for (i = 0; i < iterations; ++i) {
        if (!run_cancel_while_parked(export_parked, park_wait_arrived)) {
            fprintf(stderr, "cancel-while-parked failed on iteration %d\n", i);
            return 1;
        }
        if (!run_release_while_parked(export_parked, park_wait_arrived,
                                      release_park_gate)) {
            fprintf(stderr, "release-while-parked failed on iteration %d\n", i);
            return 1;
        }
    }

    return 0;
}
