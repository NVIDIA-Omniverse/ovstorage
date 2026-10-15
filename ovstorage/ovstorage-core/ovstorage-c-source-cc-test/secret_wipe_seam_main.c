/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The pure-C secret wipe, observed at its SEVEN wiring sites.
 *
 * `tests/cc/secret_wipe_c.c` proves the PRIMITIVE
 * (`ovc_pval_secret_bytes_wipe`) erases a buffer.  It says nothing about
 * whether the ownership cleanup still CALLS it for every `SecretValue`
 * payload: Bytes, the OAuth token, the OAuth refresh, File, and both halves
 * of the mTLS pair, or whether `AuthCredential` cleanup wipes its decoded
 * bearer. Deleting any one of those seven calls leaves that test green while
 * plaintext reaches the heap's free list.
 *
 * Seeing the difference requires observing the buffer at RELEASE, and the
 * clearing chain is `static` from `ovc_pval_secret_bundle_clear` down.  The
 * seam is therefore the allocator call in `plugin_values.c` and
 * `auth_credential.c`: this driver compiles both translation units with
 * OVC_ABI_FREE naming the observer below.
 *
 * The driver builds one `ConnectionRequest` whose `SecretBundle` carries all
 * six payloads and decodes one bearer-carrying `AuthCredential`, releases both
 * through their public free functions, and asserts that each watched buffer
 * was (a) actually released and (b) already zeroed when it was. A
 * pre-check that every buffer holds its plaintext immediately before the
 * release keeps the "all zero" assertion from passing vacuously, and the
 * observed count is asserted too, so a site that stops being reached at all
 * fails rather than disappearing.
 *
 * Built and run by `tools/ovtasks/_c_source_examples.py`; it is deliberately
 * at the crate root, next to `leak_contracts_main.c`, so `build.rs` never
 * compiles it into the Rust test binary.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ovstorage_plugin.h"

/* Declared here rather than included: `internal.h` is not on this program's
 * include path, and a mismatch would fail to link. */
void *ovc_abi_alloc(size_t byte_count);
void ovc_abi_free(void *allocation);

#define OVC_WATCH_CAPACITY 16u
#define OVC_SECRET_LEN 96u
#define OVC_SECRET_BYTE 0x5Au
/* Bytes, OAuth token, OAuth refresh, File, mTLS cert, mTLS key, auth bearer. */
#define OVC_SECRET_SITES 7u
/* Bundle entries carrying those six payloads: the OAuth and mTLS entries hold
 * two each, which is how six sites fit in four entries. */
#define OVC_SECRET_ENTRIES 4u

typedef struct ovc_watch_entry {
    const void *pointer;
    size_t length;
    const char *site;
    int released;
    int zero_at_release;
} ovc_watch_entry;

static ovc_watch_entry g_watched[OVC_WATCH_CAPACITY];
static size_t g_watched_count;

static void ovc_watch(const void *pointer, size_t length, const char *site)
{
    if (g_watched_count >= OVC_WATCH_CAPACITY) {
        fprintf(stderr, "the secret-wipe watch table is too small\n");
        exit(1);
    }
    g_watched[g_watched_count].pointer = pointer;
    g_watched[g_watched_count].length = length;
    g_watched[g_watched_count].site = site;
    g_watched[g_watched_count].released = 0;
    g_watched[g_watched_count].zero_at_release = 0;
    ++g_watched_count;
}

/* Every cross-TU `ovc_abi_free` in the distribution sources lands here. Most
 * releases are unwatched (strings, list backing stores) and pass straight
 * through; a watched one is inspected BEFORE the real free, which is the only
 * moment the contents are legitimately readable. */
void ovc_test_abi_free(void *allocation);
void ovc_test_abi_free(void *allocation)
{
    size_t index;

    for (index = 0; index < g_watched_count; ++index) {
        if (g_watched[index].pointer != allocation) {
            continue;
        }
        {
            const unsigned char *bytes = (const unsigned char *)allocation;
            size_t offset;

            g_watched[index].released = 1;
            g_watched[index].zero_at_release = 1;
            for (offset = 0; offset < g_watched[index].length; ++offset) {
                if (bytes[offset] != 0u) {
                    g_watched[index].zero_at_release = 0;
                    break;
                }
            }
        }
        break;
    }
    ovc_abi_free(allocation);
}

/* An ABI-allocated buffer full of plaintext, registered for observation. */
static OvStoragePlugin_SecretBytes ovc_secret_payload(const char *site)
{
    OvStoragePlugin_SecretBytes secret;
    unsigned char *buffer;

    buffer = (unsigned char *)ovc_abi_alloc(OVC_SECRET_LEN);
    if (buffer == NULL) {
        fprintf(stderr, "failed to allocate the %s secret payload\n", site);
        exit(1);
    }
    memset(buffer, (int)OVC_SECRET_BYTE, OVC_SECRET_LEN);
    ovc_watch(buffer, OVC_SECRET_LEN, site);
    secret.bytes.ptr = buffer;
    secret.bytes.len = OVC_SECRET_LEN;
    return secret;
}

static OvStoragePlugin_Str ovc_field_name(const char *text)
{
    OvStoragePlugin_Str value;
    size_t length;
    char *buffer;

    length = strlen(text);
    buffer = (char *)ovc_abi_alloc(length == 0 ? 1 : length);
    if (buffer == NULL) {
        fprintf(stderr, "failed to allocate a bundle field name\n");
        exit(1);
    }
    memcpy(buffer, text, length);
    value.ptr = buffer;
    value.len = length;
    return value;
}

static void ovc_wire_u32(uint8_t *wire, size_t *position, uint32_t value)
{
    wire[(*position)++] = (uint8_t)(value & 0xffu);
    wire[(*position)++] = (uint8_t)((value >> 8) & 0xffu);
    wire[(*position)++] = (uint8_t)((value >> 16) & 0xffu);
    wire[(*position)++] = (uint8_t)((value >> 24) & 0xffu);
}

static OvStoragePlugin_AuthCredential *ovc_bearer_credential(void)
{
    uint8_t wire[1u + 4u + OVC_SECRET_LEN + 1u + 12u + 4u];
    size_t position;
    OvStoragePlugin_AuthCredential *credential;
    OvStoragePlugin_Error *error;
    OvStoragePlugin_FfiStatus status;

    position = 0;
    wire[position++] = OVSTORAGE_AUTH_CREDENTIAL_WIRE_VERSION;
    ovc_wire_u32(wire, &position, OVC_SECRET_LEN);
    memset(wire + position, (int)OVC_SECRET_BYTE, OVC_SECRET_LEN);
    position += OVC_SECRET_LEN;
    wire[position++] = OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_UDS;
    ovc_wire_u32(wire, &position, 7u);
    ovc_wire_u32(wire, &position, 8u);
    ovc_wire_u32(wire, &position, 9u);
    ovc_wire_u32(wire, &position, 0u);
    if (position != sizeof(wire)) {
        fprintf(stderr, "auth credential wire length mismatch\n");
        exit(1);
    }

    credential = NULL;
    error = NULL;
    status = ovstorage_plugin_auth_credential_decode(
        wire, sizeof(wire), &credential, &error);
    if (status != OvStoragePlugin_FFI_STATUS_OK || credential == NULL ||
        error != NULL || !credential->bearer.present ||
        credential->bearer.value.ptr == NULL ||
        credential->bearer.value.len != OVC_SECRET_LEN) {
        fprintf(stderr, "failed to decode the auth bearer wipe witness\n");
        ovstorage_plugin_auth_credential_free(credential);
        ovstorage_plugin_error_free(error);
        exit(1);
    }
    ovc_watch(credential->bearer.value.ptr,
              credential->bearer.value.len,
              "AuthCredential bearer");
    return credential;
}

/* Every payload still holds its plaintext at this point.
 *
 * Both halves matter. The pattern check says the buffer is the one this
 * program built; the NON-ZERO check is what stops the post-release "all zero"
 * assertion from being vacuous, and it deliberately does not compare against
 * OVC_SECRET_BYTE -- a plaintext of 0x00 would satisfy any such comparison
 * while making every wipe assertion below trivially true. */
static int ovc_plaintext_is_present(void)
{
    size_t index;

    if (g_watched_count != OVC_SECRET_SITES) {
        fprintf(stderr,
                "expected %u watched secret payloads, built %zu\n",
                OVC_SECRET_SITES,
                g_watched_count);
        return 0;
    }
    for (index = 0; index < g_watched_count; ++index) {
        const unsigned char *bytes = (const unsigned char *)g_watched[index].pointer;
        size_t offset;

        if (g_watched[index].length == 0u) {
            fprintf(stderr,
                    "the %s payload is empty, so its wipe is unobservable\n",
                    g_watched[index].site);
            return 0;
        }
        for (offset = 0; offset < g_watched[index].length; ++offset) {
            if (bytes[offset] == 0u) {
                fprintf(stderr,
                        "the %s payload is already zero at %zu, so the "
                        "post-release check would prove nothing\n",
                        g_watched[index].site,
                        offset);
                return 0;
            }
            if (bytes[offset] != (unsigned char)OVC_SECRET_BYTE) {
                fprintf(stderr,
                        "the %s payload was not populated at %zu\n",
                        g_watched[index].site,
                        offset);
                return 0;
            }
        }
    }
    return 1;
}

int main(void)
{
    OvStoragePlugin_AuthCredential *credential;
    OvStoragePlugin_ConnectionRequest request;
    OvStoragePlugin_SecretBundleEntry *entries;
    size_t index;
    int failures = 0;

    memset(&request, 0, sizeof(request));
    request.backend_kind = ovc_field_name("wrap-seam");

    entries = (OvStoragePlugin_SecretBundleEntry *)ovc_abi_alloc(
        OVC_SECRET_ENTRIES * sizeof(*entries));
    if (entries == NULL) {
        fprintf(stderr, "failed to allocate the secret bundle\n");
        return 1;
    }
    memset(entries, 0, OVC_SECRET_ENTRIES * sizeof(*entries));

    /* One entry per SecretValue tag that owns a payload. SystemIdentity owns
     * nothing and is deliberately absent. Adding a payload here means bumping
     * OVC_SECRET_SITES, and adding a tag means bumping OVC_SECRET_ENTRIES;
     * `ovc_plaintext_is_present` cross-checks the first against what was
     * actually built. */
    entries[0].field = ovc_field_name("bytes");
    entries[0].value.tag = OvStoragePlugin_SecretValueTag_Bytes;
    entries[0].value.bytes = ovc_secret_payload("Bytes");

    entries[1].field = ovc_field_name("oauth");
    entries[1].value.tag = OvStoragePlugin_SecretValueTag_OAuthToken;
    entries[1].value.oauth_token.token = ovc_secret_payload("OAuth token");
    entries[1].value.oauth_token.refresh.present = true;
    entries[1].value.oauth_token.refresh.value =
        ovc_secret_payload("OAuth refresh");

    entries[2].field = ovc_field_name("file");
    entries[2].value.tag = OvStoragePlugin_SecretValueTag_File;
    entries[2].value.file = ovc_secret_payload("File");

    entries[3].field = ovc_field_name("mtls");
    entries[3].value.tag = OvStoragePlugin_SecretValueTag_MtlsCertPair;
    entries[3].value.mtls_cert_pair.cert_pem =
        ovc_secret_payload("mTLS cert");
    entries[3].value.mtls_cert_pair.key_pem = ovc_secret_payload("mTLS key");

    request.credentials.entries.ptr = entries;
    request.credentials.entries.len = OVC_SECRET_ENTRIES;
    credential = ovc_bearer_credential();

    if (!ovc_plaintext_is_present()) {
        return 1;
    }

    ovstorage_plugin_connection_request_free(&request);
    ovstorage_plugin_auth_credential_free(credential);

    for (index = 0; index < g_watched_count; ++index) {
        if (!g_watched[index].released) {
            fprintf(stderr,
                    "the %s payload was never released, so its wipe was not "
                    "observed\n",
                    g_watched[index].site);
            failures = 1;
            continue;
        }
        if (!g_watched[index].zero_at_release) {
            fprintf(stderr,
                    "the %s payload reached the allocator still holding "
                    "plaintext\n",
                    g_watched[index].site);
            failures = 1;
        }
    }
    if (failures != 0) {
        return 1;
    }
    printf("secret wipe observed at all %u wiring sites\n", OVC_SECRET_SITES);
    return 0;
}
