// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * Reference C plugin used by `c_example_compiles` in
 * `crates/ovstorage-plugin/tests/header_verification.rs` to verify the
 * generated `ovstorage_plugin.h` end-to-end.
 *
 * The plugin populates a full `BackendFactoryVTableV1` with stub
 * thunks. The thunks don't need to do anything sensible at runtime —
 * the test only invokes `cc -c` (compile, no link, no dlopen). What
 * matters is that every struct, every field name, and every
 * function-pointer signature in the SPI is *named* by this file. Any
 * cbindgen regression (elided struct, renamed field, signature drift)
 * surfaces as a compile error here.
 *
 * Per `cc -Werror=implicit-function-declaration -Wall`, every
 * identifier we reference must be declared by the header.
 */

#include <stddef.h>

#include "ovstorage_plugin.h"

/* ------------------------------------------------------------------- */
/* Static manifest, exported as a `dlsym`-discoverable symbol.         */
/* ------------------------------------------------------------------- */

const OvStoragePlugin_PluginManifestV1 ovstorage_plugin_manifest_v1 = {
    sizeof(OvStoragePlugin_PluginManifestV1),
    OVSTORAGE_PLUGIN_ABI_VERSION,
    "example-c",
    "0.1.0",
};

/* ------------------------------------------------------------------- */
/* Stub thunks for `BackendFactoryVTableV1`.                           */
/*                                                                     */
/* Each thunk has the correct signature for its slot but a trivial     */
/* body: callback-shape thunks fire `on_complete` with status=1 and    */
/* null pointers; the synchronous descriptor returns null (the host    */
/* would interpret this as success with an unpopulated out-pointer).   */
/* The compile test exercises signatures, not behaviour.               */
/* ------------------------------------------------------------------- */

static void factory_drop(void *factory_state)
{
    (void)factory_state;
}

static OvStoragePlugin_Error *factory_descriptor(
    void *factory_state,
    OvStoragePlugin_StorageBackendKindDescriptor *out)
{
    (void)factory_state;
    (void)out;
    return NULL;
}

static void factory_instantiate(
    void *factory_state,
    const OvStoragePlugin_ConnectionRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_FactoryInstantiateCallback on_complete,
    void *user_data)
{
    (void)factory_state;
    (void)request;
    (void)cancel;
    on_complete(1, NULL, NULL, user_data);
}

static void factory_update_credentials(
    void *factory_state,
    const OvStoragePlugin_Connection *connection,
    const OvStoragePlugin_SecretBundle *credentials,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_BackendUnitCallback on_complete,
    void *user_data)
{
    (void)factory_state;
    (void)connection;
    (void)credentials;
    (void)cancel;
    on_complete(1, NULL, user_data);
}

static void factory_authenticate(
    void *factory_state,
    const OvStoragePlugin_Connection *connection,
    OvStoragePlugin_InteractiveAuthCapabilityV1 capability,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_FactoryAuthenticateCallback on_complete,
    void *user_data)
{
    (void)factory_state;
    (void)connection;
    (void)capability;
    (void)cancel;
    on_complete(1, NULL, NULL, user_data);
}

static const OvStoragePlugin_BackendFactoryVTableV1 FACTORY_VTABLE = {
    sizeof(OvStoragePlugin_BackendFactoryVTableV1),
    factory_drop,
    factory_descriptor,
    factory_instantiate,
    factory_update_credentials,
    factory_authenticate,
    /* _reserved = */ {0},
};

/* ------------------------------------------------------------------- */
/* Init entry point. The host invokes this once after `dlopen` + the   */
/* manifest read, then casts `kind_vtable` based on the manifest's     */
/* `plugin_kind` (here: BACKEND ⇒ `*const BackendFactoryVTableV1`).    */
/* ------------------------------------------------------------------- */

OvStoragePlugin_BackendPluginInitResultV1 ovstorage_plugin_init_v1(
    const OvStoragePlugin_HostCallbacks *host)
{
    (void)host;
    OvStoragePlugin_BackendPluginInitResultV1 result = {
        sizeof(OvStoragePlugin_BackendPluginInitResultV1),
        OVSTORAGE_PLUGIN_ABI_VERSION,
        /* min_supported_abi_version = */ OVSTORAGE_PLUGIN_ABI_VERSION,
        /* max_supported_abi_version = */ OVSTORAGE_PLUGIN_ABI_VERSION,
        /* plugin_state   = */ NULL,
        /* factory_vtable = */ &FACTORY_VTABLE,
    };
    return result;
}
