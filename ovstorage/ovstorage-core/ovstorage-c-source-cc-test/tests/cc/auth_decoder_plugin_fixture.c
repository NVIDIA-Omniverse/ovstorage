/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Genuine C listener-auth plugin fixture for the plugin-owned decoder
 * contract. Its shared-library link includes auth_credential.c, utf8.c, and
 * plat.c, so the decode/free calls below resolve inside this image. The host
 * deliberately loads the fixture with local symbol visibility and supplies no
 * decoder exports.
 */

#include "ovstorage_plugin.h"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define OVC_TEST_EXPORT __declspec(dllexport)
#else
#define OVC_TEST_EXPORT __attribute__((visibility("default")))
#endif

static char g_auth_decoder_kind[] = "cc-auth-decoder";
static char g_auth_decoder_display_name[] = "C auth decoder fixture";
static int g_auth_decoder_plugin_state;

static void auth_decoder_fixture_drop(void *plugin_state)
{
    (void)plugin_state;
}

static OvStoragePlugin_FfiStatus auth_decoder_fixture_create_wrapper(
    void *plugin_state,
    const OvStoragePlugin_CreateWrapperRequest *request,
    OvStoragePlugin_LayerHandle *out,
    OvStoragePlugin_Error **error)
{
    (void)plugin_state;
    (void)request;
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    if (error != NULL) {
        *error = NULL;
    }
    return OvStoragePlugin_FFI_STATUS_ERR;
}

static const OvStoragePlugin_PluginVTableV1 g_auth_decoder_plugin_vtable = {
    .struct_size = sizeof(OvStoragePlugin_PluginVTableV1),
    .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
    .drop = auth_decoder_fixture_drop,
    .create_wrapper = auth_decoder_fixture_create_wrapper,
};

static const OvStoragePlugin_LayerKindDescriptor g_auth_decoder_descriptor = {
    .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
    .layer_type = OvStoragePlugin_LayerType_Wrapper,
    .kind = {g_auth_decoder_kind, sizeof(g_auth_decoder_kind) - 1},
    .display_name = {g_auth_decoder_display_name,
                     sizeof(g_auth_decoder_display_name) - 1},
    .auth_capable = true,
};

OVC_TEST_EXPORT const OvStoragePlugin_PluginManifestV1
    ovstorage_plugin_manifest_v1 = {
        .struct_size = sizeof(OvStoragePlugin_PluginManifestV1),
        .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
        .name = "ovstorage-c-auth-decoder-fixture",
        .version = "0.0.0",
        .test_only = true,
};

OVC_TEST_EXPORT OvStoragePlugin_PluginInitResultV1
ovstorage_plugin_init_v1(const OvStoragePlugin_HostCallbacks *host)
{
    OvStoragePlugin_PluginInitResultV1 result;

    (void)host;
    memset(&result, 0, sizeof(result));
    result.struct_size = sizeof(result);
    result.abi_version = OVSTORAGE_PLUGIN_ABI_VERSION;
    result.plugin_state = &g_auth_decoder_plugin_state;
    result.plugin_vtable = &g_auth_decoder_plugin_vtable;
    result.kinds = &g_auth_decoder_descriptor;
    result.kind_count = 1;
    return result;
}

/* Invoked through dlsym/GetProcAddress by a host that does not export either
 * decoder function. A successful call therefore demonstrates that the helper
 * implementation is retained and bound inside this plugin image. */
OVC_TEST_EXPORT int ovstorage_test_c_auth_decoder_probe(void)
{
    static const uint8_t wire[] = {
        OVSTORAGE_AUTH_CREDENTIAL_WIRE_VERSION,
        3u, 0u, 0u, 0u, 'a', 'b', 'c',
        OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_UDS,
        7u, 0u, 0u, 0u,
        8u, 0u, 0u, 0u,
        9u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u,
    };
    OvStoragePlugin_AuthCredential *credential;
    OvStoragePlugin_Error *error;
    OvStoragePlugin_FfiStatus status;
    int matches;

    credential = NULL;
    error = NULL;
    status = ovstorage_plugin_auth_credential_decode(
        wire, sizeof(wire), &credential, &error);
    matches = status == OvStoragePlugin_FFI_STATUS_OK &&
              credential != NULL && error == NULL &&
              credential->bearer.present &&
              credential->bearer.value.len == 3u &&
              memcmp(credential->bearer.value.ptr, "abc", 3u) == 0 &&
              credential->transport.tag ==
                  OvStoragePlugin_AuthCredentialTransportTag_Uds &&
              credential->transport.uds.uid == 7u &&
              credential->transport.uds.gid == 8u &&
              credential->transport.uds.pid == 9 &&
              credential->forwarded_headers.len == 0u;
    ovstorage_plugin_auth_credential_free(credential);
    ovstorage_plugin_error_free(error);
    return matches ? EXIT_SUCCESS : EXIT_FAILURE;
}
