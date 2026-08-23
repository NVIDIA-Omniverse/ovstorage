/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * A declining slot releases the request it was handed.
 *
 * `OVSTORAGE_UNSUPPORTED_VTABLE` is what a partial backend copies, so every
 * slot it does not patch answers "unsupported" -- while still owning the
 * request, because the host relinquished it before the call. A slot that
 * answers without releasing leaks every buffer the request names.
 *
 * The oracle is LeakSanitizer, and it lives in ONE of the two places this file
 * is compiled into. `make c-source-examples` links it into the sanitized
 * leak-contracts driver with `-fsanitize=address,leak`, and that is the run
 * that can see a leak. The copy linked into the ordinary `cargo test` binary
 * carries no sanitizer, so there it asserts only the completion counts and the
 * stream-drop ordering below -- useful, but not the leak check.
 *
 * Each case builds a request whose buffers come from the plugin-ABI allocator,
 * hands it to the slot, and returns. If the slot does not release, the buffers
 * are unreachable when the process exits and LSan reports them.
 *
 * That makes the leak-check the assertion under the sanitized gate, so two
 * things matter.
 *
 * Every request is built with MANY SMALL allocations rather than one large
 * one. A single large block can stay reachable through a stale pointer left
 * in a register or on the stack, and LSan would then report nothing while the
 * leak is real. A few dozen small blocks cannot all hide that way.
 *
 * And every case asserts its completion fired. Without that a slot that
 * returned early -- before releasing AND before completing -- would look
 * identical to a slot that did both.
 *
 * All 27 slots are driven. Six of them are what `file_backend.c` leaves at
 * the default, so those are the leak as it ships -- `probe` most of all,
 * since its request carries the connection's whole `SecretBundle`. The rest
 * are covered because a slot a future backend declines leaks identically,
 * and because the macro's release argument is only type-checked: passing
 * some OTHER type's release compiles wherever the two requests happen to
 * agree, and only exercising the slot shows it.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ovstorage_defaults.h"
#include "ovstorage_plugin.h"

/* The plugin-ABI allocator. Declared rather than included: internal.h is not
 * on this test's include path, and a signature drift would fail to link. */
void *ovc_abi_alloc(size_t byte_count);
void ovc_abi_free(void *allocation);

/* SecretValue arms that own a payload. SystemIdentity owns nothing. */
#define OVC_DECLINED_SECRET_ARMS 4u

static unsigned g_completions;

/* Set while driving the one case whose request carries a `Stream` body. The
 * completion callback then asserts the host's `drop_fn` has ALREADY run.
 *
 * That is what pins release-before-completion, and nothing else here does:
 * checking the drop count after the slot returns passes either way, so
 * swapping `release_fn(request)` and `ovc_complete_unsupported` in the macro
 * -- the exact regression the ordering comment exists to prevent -- stayed
 * green. The hazard is real precisely because the callback runs first: a C
 * app's completion can tear down the state the stream's `drop_fn` refers to. */
static int g_expect_drop_before_completion;

/* A stream body's release runs the host's `drop_fn`. */
static unsigned g_stream_drops;

static void ovc_declined_complete(OvStoragePlugin_FfiStatus status,
                                  void *result,
                                  OvStoragePlugin_Error *error,
                                  void *user_data)
{
    (void)result;
    (void)user_data;
    if (g_expect_drop_before_completion && g_stream_drops == 0u) {
        fprintf(stderr,
                "the slot completed before releasing its request: the stream\n"
                "body's drop_fn had not run when the completion fired, so a\n"
                "host callback could have torn down the state it refers to\n");
        exit(1);
    }
    if (status != OvStoragePlugin_FFI_STATUS_ERR) {
        fprintf(stderr, "a declining slot did not report failure\n");
        exit(1);
    }
    if (error != NULL) {
        ovstorage_plugin_error_free(error);
    }
    ++g_completions;
}

/* Every string is its own small allocation, for the reason in the header
 * comment: a stranded block has to be small enough that LSan cannot lose it. */
static OvStoragePlugin_Str ovc_declined_str(const char *text)
{
    OvStoragePlugin_Str value;
    size_t length;
    char *buffer;

    length = strlen(text);
    buffer = (char *)ovc_abi_alloc(length == 0 ? 1u : length);
    if (buffer == NULL) {
        fprintf(stderr, "failed to allocate a request string\n");
        exit(1);
    }
    memcpy(buffer, text, length);
    value.ptr = buffer;
    value.len = length;
    return value;
}

static OvStoragePlugin_Bytes ovc_declined_bytes(size_t length)
{
    OvStoragePlugin_Bytes value;
    unsigned char *buffer;

    buffer = (unsigned char *)ovc_abi_alloc(length);
    if (buffer == NULL) {
        fprintf(stderr, "failed to allocate a request payload\n");
        exit(1);
    }
    memset(buffer, 0x5A, length);
    value.ptr = buffer;
    value.len = length;
    return value;
}


/* Owned collections several requests carry. Populated for the same reason the
 * optional scalars are: an unpopulated field cannot strand anything, so a
 * release that forgets it stays invisible. */
static OvStoragePlugin_KeyValueList ovc_declined_key_values(void)
{
    OvStoragePlugin_KeyValueList list;
    OvStoragePlugin_KeyValuePair *pairs;

    pairs = (OvStoragePlugin_KeyValuePair *)ovc_abi_alloc(2u * sizeof(*pairs));
    if (pairs == NULL) {
        fprintf(stderr, "failed to allocate a key/value list\n");
        exit(1);
    }
    memset(pairs, 0, 2u * sizeof(*pairs));
    pairs[0].key = ovc_declined_str("k0");
    pairs[0].value = ovc_declined_str("v0");
    pairs[1].key = ovc_declined_str("k1");
    pairs[1].value = ovc_declined_str("v1");
    list.ptr = pairs;
    list.len = 2u;
    return list;
}

static OvStoragePlugin_List_Str ovc_declined_str_list(void)
{
    OvStoragePlugin_List_Str list;
    OvStoragePlugin_Str *items;

    items = (OvStoragePlugin_Str *)ovc_abi_alloc(2u * sizeof(*items));
    if (items == NULL) {
        fprintf(stderr, "failed to allocate a string list\n");
        exit(1);
    }
    items[0] = ovc_declined_str("remove-0");
    items[1] = ovc_declined_str("remove-1");
    list.ptr = items;
    list.len = 2u;
    return list;
}

/* `extensions` is borrowed by every request release. Populate both levels so
 * an accidental deep release is observable when the host frees it afterwards:
 * ASan reports a double free whether the release reclaimed the entries or the
 * outer allocation. */
static OvStoragePlugin_Extensions *ovc_declined_extensions(void)
{
    OvStoragePlugin_Extensions *extensions;
    OvStoragePlugin_ExtensionEntry *entry;

    extensions =
        (OvStoragePlugin_Extensions *)ovc_abi_alloc(sizeof(*extensions));
    entry = (OvStoragePlugin_ExtensionEntry *)ovc_abi_alloc(sizeof(*entry));
    if (extensions == NULL || entry == NULL) {
        fprintf(stderr, "failed to allocate borrowed extensions\n");
        exit(1);
    }
    memset(extensions, 0, sizeof(*extensions));
    memset(entry, 0, sizeof(*entry));
    entry->key = ovc_declined_str("trace-id");
    entry->value = ovc_declined_bytes(24u);
    extensions->entries.ptr = entry;
    extensions->entries.len = 1u;
    return extensions;
}

/* The host owns the stream state and this callback is where it reclaims it,
 * which is exactly the arrangement that makes the ordering rule matter: the
 * release runs host code. Freeing here is not incidental -- LeakSanitizer
 * reports the state otherwise, and that report would be about the TEST rather
 * than the library. */
void ovc_abi_free(void *allocation);

static void ovc_declined_stream_drop(void *state)
{
    ovc_abi_free(state);
    ++g_stream_drops;
}

static OvStoragePlugin_BodyStream ovc_declined_stream(void)
{
    OvStoragePlugin_BodyStream stream;

    memset(&stream, 0, sizeof(stream));
    stream.state = ovc_abi_alloc(32u);
    if (stream.state == NULL) {
        fprintf(stderr, "failed to allocate stream state\n");
        exit(1);
    }
    stream.drop_fn = ovc_declined_stream_drop;
    return stream;
}

static void ovc_declined_write(const OvStoragePlugin_LayerVTableV1 *vtable,
                               const char *label)
{
    OvStoragePlugin_WriteRequest request;
    unsigned before;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_declined_str("mem:///declined/write");
    request.body = (OvStoragePlugin_Body){0};
    request.body.tag = OvStoragePlugin_BodyTag_Bytes;
    request.body.bytes = ovc_declined_bytes(64u);
    request.options.struct_size = sizeof(request.options);
    request.options.message.present = true;
    request.options.message.value = ovc_declined_str("a declined write");
    request.options.if_dest.tag = OvStoragePlugin_IfDestExistsTag_MatchEtag;
    request.options.if_dest.match_etag.etag = ovc_declined_str("dest-etag");
    request.options.user_metadata.present = true;
    request.options.user_metadata.value = ovc_declined_key_values();

    before = g_completions;
    vtable->write(NULL, &request, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "%s did not complete exactly once\n", label);
        exit(1);
    }
}

static void ovc_declined_probe(const OvStoragePlugin_LayerVTableV1 *vtable)
{
    OvStoragePlugin_LayerConnectionRequest request;
    OvStoragePlugin_SecretBundleEntry *entries;
    unsigned before;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.target = ovc_declined_str("files");
    request.connection.backend_kind = ovc_declined_str("file");
    request.connection.display_name.present = true;
    request.connection.display_name.value = ovc_declined_str("declined probe");

    /* The credential material, which is the reason this slot leaking is worse
     * than the others. */
    entries = (OvStoragePlugin_SecretBundleEntry *)ovc_abi_alloc(
        OVC_DECLINED_SECRET_ARMS * sizeof(*entries));
    if (entries == NULL) {
        fprintf(stderr, "failed to allocate the secret bundle\n");
        exit(1);
    }
    memset(entries, 0, OVC_DECLINED_SECRET_ARMS * sizeof(*entries));
    /* One entry per SecretValue arm that owns a payload, for the same reason
     * the Body arms are covered: with only `Bytes` present, deleting any other
     * branch of `ovc_pval_secret_value_clear` left the contract green.
     * SystemIdentity owns nothing and is deliberately absent. */
    entries[0].field = ovc_declined_str("bytes");
    entries[0].value.tag = OvStoragePlugin_SecretValueTag_Bytes;
    entries[0].value.bytes.bytes = ovc_declined_bytes(48u);
    entries[1].field = ovc_declined_str("oauth");
    entries[1].value.tag = OvStoragePlugin_SecretValueTag_OAuthToken;
    entries[1].value.oauth_token.token.bytes = ovc_declined_bytes(40u);
    entries[1].value.oauth_token.refresh.present = true;
    entries[1].value.oauth_token.refresh.value.bytes = ovc_declined_bytes(36u);
    entries[2].field = ovc_declined_str("file");
    entries[2].value.tag = OvStoragePlugin_SecretValueTag_File;
    entries[2].value.file.bytes = ovc_declined_bytes(28u);
    entries[3].field = ovc_declined_str("mtls");
    entries[3].value.tag = OvStoragePlugin_SecretValueTag_MtlsCertPair;
    entries[3].value.mtls_cert_pair.cert_pem.bytes = ovc_declined_bytes(24u);
    entries[3].value.mtls_cert_pair.key_pem.bytes = ovc_declined_bytes(20u);
    request.connection.credentials.entries.ptr = entries;
    request.connection.credentials.entries.len = OVC_DECLINED_SECRET_ARMS;

    before = g_completions;
    vtable->probe(NULL, &request, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "probe did not complete exactly once\n");
        exit(1);
    }
}

static void ovc_declined_continue_write(
    const OvStoragePlugin_LayerVTableV1 *vtable)
{
    OvStoragePlugin_ContinueWriteRequest request;
    unsigned before;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_declined_str("mem:///declined/continue");
    {
        OvStoragePlugin_WriteRedirect *redirects;
        OvStoragePlugin_RedirectResult *results;

        redirects = (OvStoragePlugin_WriteRedirect *)ovc_abi_alloc(
            sizeof(*redirects));
        results = (OvStoragePlugin_RedirectResult *)ovc_abi_alloc(
            sizeof(*results));
        if (redirects == NULL || results == NULL) {
            fprintf(stderr, "failed to allocate the redirect batches\n");
            exit(1);
        }
        memset(redirects, 0, sizeof(*redirects));
        memset(results, 0, sizeof(*results));
        /* Every owning member of the redirect, not just one. With only
         * `audit_id` set, most of `ovc_pval_write_redirect_batch_clear` could
         * be deleted and nothing would strand -- the same vacuity the file's
         * own rule warns about. */
        redirects[0].request.method = ovc_declined_str("PUT");
        redirects[0].request.url = ovc_declined_str("https://declined/upload");
        redirects[0].request.headers = ovc_declined_key_values();
        redirects[0].body_source.tag =
            OvStoragePlugin_RedirectBodySourceTag_Inline;
        redirects[0].body_source.inline_ = ovc_declined_bytes(18u);
        redirects[0].result_capture.headers = ovc_declined_str_list();
        redirects[0].scope.physical_url_prefix =
            ovc_declined_str("https://declined/");
        redirects[0].audit_id = ovc_declined_str("declined-audit");
        request.redirects.continuation = ovc_declined_bytes(32u);
        request.redirects.redirects.ptr = redirects;
        request.redirects.redirects.len = 1u;
        results[0].captured_headers = ovc_declined_key_values();
        results[0].captured_body = ovc_declined_bytes(20u);
        request.results.results.ptr = results;
        request.results.results.len = 1u;
    }

    before = g_completions;
    vtable->continue_write(NULL, &request, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "continue_write did not complete exactly once\n");
        exit(1);
    }
}

static void ovc_declined_update_attributes(
    const OvStoragePlugin_LayerVTableV1 *vtable)
{
    OvStoragePlugin_UpdateConnectionAttributesRequest request;
    unsigned before;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.key.target = ovc_declined_str("files");
    request.key.id = ovc_declined_str("declined-attributes");
    request.patch.display_name.present = true;
    request.patch.display_name.value = ovc_declined_str("a declined rename");
    request.patch.access_mode.present = true;
    request.patch.access_mode.value = ovc_declined_str("read-only");
    request.patch.set_user_metadata = ovc_declined_key_values();
    request.patch.remove_user_metadata = ovc_declined_str_list();

    before = g_completions;
    vtable->update_connection_attributes(
        NULL, &request, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr,
                "update_connection_attributes did not complete exactly once\n");
        exit(1);
    }
}

static void ovc_declined_authenticate(
    const OvStoragePlugin_LayerVTableV1 *vtable)
{
    OvStoragePlugin_AuthenticateRequest request;
    unsigned before;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.key.target = ovc_declined_str("files");
    request.key.id = ovc_declined_str("declined-auth");

    before = g_completions;
    vtable->authenticate_connection(
        NULL, &request, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr,
                "authenticate_connection did not complete exactly once\n");
        exit(1);
    }
}


/* ---------------------------------------------------------------------- */
/* The remaining slots. Every one of the 27 is driven, because the six above
 * are only the ones the file backend happens to inherit today: a slot a
 * future backend leaves at the default leaks exactly the same way, and the
 * macro's release argument is only checked by the compiler for slots that
 * exist. Coverage here is what makes a WRONG release argument -- one that
 * compiles because it is some other type's release -- visible. */

/* `optionals` populates every OPTIONAL owning field the request carries.
 *
 * That is not padding. A release that forgets an optional still frees the
 * address, and the address sits at the same offset in most request types --
 * so a release wired to the WRONG type's function frees the field they share
 * and leaks only the one they do not. With optionals left empty there is
 * nothing to leak and the mistake is invisible; populating them is what makes
 * the coverage mean anything. */
#define OVC_ADDRESSED_CASE(name, type, field, slot, optionals)               \
    static void ovc_declined_##name(                                         \
        const OvStoragePlugin_LayerVTableV1 *vtable)                         \
    {                                                                        \
        type request;                                                        \
        unsigned before;                                                     \
                                                                             \
        memset(&request, 0, sizeof(request));                                \
        request.struct_size = sizeof(request);                               \
        request.field = ovc_declined_str("mem:///declined/" #name);          \
        request.options.struct_size = sizeof(request.options);               \
        optionals                                                            \
        before = g_completions;                                              \
        vtable->slot(NULL, &request, NULL, ovc_declined_complete, NULL);     \
        if (g_completions != before + 1u) {                                  \
            fprintf(stderr, #name " did not complete exactly once\n");       \
            exit(1);                                                         \
        }                                                                    \
    }

#define OVC_IF_MATCH                                                         \
    request.options.if_match.present = true;                                 \
    request.options.if_match.value = ovc_declined_str("an-etag");

#define OVC_PAGE_TOKEN                                                       \
    request.options.page_token.present = true;                               \
    request.options.page_token.value = ovc_declined_str("a-page-token");

OVC_ADDRESSED_CASE(stat, OvStoragePlugin_StatRequest, address, stat, )
OVC_ADDRESSED_CASE(read, OvStoragePlugin_ReadRequest, address, read, OVC_IF_MATCH)
OVC_ADDRESSED_CASE(materialize,
                   OvStoragePlugin_ReadRequest,
                   address,
                   materialize,
                   OVC_IF_MATCH)
OVC_ADDRESSED_CASE(latest_version,
                   OvStoragePlugin_ReadRequest,
                   address,
                   get_latest_version,
                   OVC_IF_MATCH)
OVC_ADDRESSED_CASE(delete_object,
                   OvStoragePlugin_DeleteRequest,
                   address,
                   delete_,
                   OVC_IF_MATCH)
OVC_ADDRESSED_CASE(update_metadata,
                   OvStoragePlugin_UpdateMetadataRequest,
                   address,
                   update_metadata,
                   OVC_IF_MATCH
                   request.options.message.present = true;
                   request.options.message.value =
                       ovc_declined_str("a declined metadata update");
                   request.options.user_metadata_set =
                       ovc_declined_key_values();
                   request.options.user_metadata_remove =
                       ovc_declined_str_list();)
OVC_ADDRESSED_CASE(list_versions,
                   OvStoragePlugin_ListVersionsRequest,
                   address,
                   list_versions,
                   OVC_PAGE_TOKEN)
OVC_ADDRESSED_CASE(list_objects,
                   OvStoragePlugin_ListRequest,
                   prefix,
                   list,
                   OVC_PAGE_TOKEN)
OVC_ADDRESSED_CASE(watch_directory,
                   OvStoragePlugin_WatchDirectoryRequest,
                   prefix,
                   watch_directory,
                   request.options.since.present = true;
                   request.options.since.value.bytes =
                       ovc_declined_bytes(16u);)
OVC_ADDRESSED_CASE(create_directory,
                   OvStoragePlugin_CreateDirectoryRequest,
                   address,
                   create_directory, )
OVC_ADDRESSED_CASE(delete_directory,
                   OvStoragePlugin_DeleteDirectoryRequest,
                   address,
                   delete_directory, )

/* `check_access` and `root_info_for` have no options member, and the two
 * list-the-world requests own nothing at all -- driven anyway, so that a
 * field added to either has a case already watching it. */
static void ovc_declined_check_access(
    const OvStoragePlugin_LayerVTableV1 *vtable)
{
    OvStoragePlugin_CheckAccessRequest request;
    unsigned before;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_declined_str("mem:///declined/check_access");
    before = g_completions;
    vtable->check_access(NULL, &request, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "check_access did not complete exactly once\n");
        exit(1);
    }
}

static void ovc_declined_root_info_for(
    const OvStoragePlugin_LayerVTableV1 *vtable)
{
    OvStoragePlugin_RootInfoForRequest request;
    unsigned before;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.url = ovc_declined_str("mem:///declined/root");
    before = g_completions;
    vtable->root_info_for(NULL, &request, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "root_info_for did not complete exactly once\n");
        exit(1);
    }
}

static void ovc_declined_copy_like(const OvStoragePlugin_LayerVTableV1 *vtable)
{
    OvStoragePlugin_CopyRequest copy;
    OvStoragePlugin_RenameRequest rename;
    unsigned before;

    memset(&copy, 0, sizeof(copy));
    copy.struct_size = sizeof(copy);
    copy.source = ovc_declined_str("mem:///declined/copy/src");
    copy.destination = ovc_declined_str("mem:///declined/copy/dst");
    copy.options.struct_size = sizeof(copy.options);
    copy.options.message.present = true;
    copy.options.message.value = ovc_declined_str("a declined copy");
    copy.options.if_source.present = true;
    copy.options.if_source.value = ovc_declined_str("source-etag");
    copy.options.if_dest.tag = OvStoragePlugin_IfDestExistsTag_MatchEtag;
    copy.options.if_dest.match_etag.etag = ovc_declined_str("copy-dest-etag");
    before = g_completions;
    vtable->copy(NULL, &copy, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "copy did not complete exactly once\n");
        exit(1);
    }

    /* Both prefixes reach the preconditions but stop before `message`. The
     * outer request is allocated at EXACTLY that length: requiring it to hold
     * the newest complete options struct leaks both strings just as surely as
     * gating the nested prefix on its last field does. */
    {
        size_t options_prefix_size =
            offsetof(OvStoragePlugin_CopyOptions, if_dest)
            + sizeof(copy.options.if_dest);
        size_t request_prefix_size =
            offsetof(OvStoragePlugin_CopyRequest, options)
            + options_prefix_size;
        OvStoragePlugin_CopyRequest *shortened =
            (OvStoragePlugin_CopyRequest *)ovc_abi_alloc(request_prefix_size);

        if (shortened == NULL) {
            fprintf(stderr, "failed to allocate the shortened copy request\n");
            exit(1);
        }
        memset(&copy, 0, sizeof(copy));
        copy.struct_size = request_prefix_size;
        copy.source = ovc_declined_str("mem:///declined/short-copy/src");
        copy.destination = ovc_declined_str("mem:///declined/short-copy/dst");
        copy.options.struct_size = options_prefix_size;
        copy.options.if_source.present = true;
        copy.options.if_source.value =
            ovc_declined_str("short-copy-source-etag");
        copy.options.if_dest.tag = OvStoragePlugin_IfDestExistsTag_MatchEtag;
        copy.options.if_dest.match_etag.etag =
            ovc_declined_str("short-copy-dest-etag");
        memcpy(shortened, &copy, request_prefix_size);

        before = g_completions;
        vtable->copy(NULL, shortened, NULL, ovc_declined_complete, NULL);
        if (g_completions != before + 1u) {
            fprintf(stderr, "short-options copy did not complete exactly once\n");
            exit(1);
        }
        ovc_abi_free(shortened);
    }

    memset(&rename, 0, sizeof(rename));
    rename.struct_size = sizeof(rename);
    rename.source = ovc_declined_str("mem:///declined/rename/src");
    rename.destination = ovc_declined_str("mem:///declined/rename/dst");
    rename.options.struct_size = sizeof(rename.options);
    rename.options.message.present = true;
    rename.options.message.value = ovc_declined_str("a declined rename");
    rename.options.if_source.present = true;
    rename.options.if_dest.tag = OvStoragePlugin_IfDestExistsTag_MatchEtag;
    rename.options.if_source.value = ovc_declined_str("rename-source-etag");
    rename.options.if_dest.match_etag.etag =
        ovc_declined_str("rename-dest-etag");
    before = g_completions;
    vtable->rename(NULL, &rename, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "rename did not complete exactly once\n");
        exit(1);
    }

    {
        size_t options_prefix_size =
            offsetof(OvStoragePlugin_RenameOptions, if_dest)
            + sizeof(rename.options.if_dest);
        size_t request_prefix_size =
            offsetof(OvStoragePlugin_RenameRequest, options)
            + options_prefix_size;
        OvStoragePlugin_RenameRequest *shortened =
            (OvStoragePlugin_RenameRequest *)ovc_abi_alloc(request_prefix_size);

        if (shortened == NULL) {
            fprintf(stderr, "failed to allocate the shortened rename request\n");
            exit(1);
        }
        memset(&rename, 0, sizeof(rename));
        rename.struct_size = request_prefix_size;
        rename.source = ovc_declined_str("mem:///declined/short-rename/src");
        rename.destination =
            ovc_declined_str("mem:///declined/short-rename/dst");
        rename.options.struct_size = options_prefix_size;
        rename.options.if_source.present = true;
        rename.options.if_source.value =
            ovc_declined_str("short-rename-source-etag");
        rename.options.if_dest.tag = OvStoragePlugin_IfDestExistsTag_MatchEtag;
        rename.options.if_dest.match_etag.etag =
            ovc_declined_str("short-rename-dest-etag");
        memcpy(shortened, &rename, request_prefix_size);

        before = g_completions;
        vtable->rename(NULL, shortened, NULL, ovc_declined_complete, NULL);
        if (g_completions != before + 1u) {
            fprintf(stderr,
                    "short-options rename did not complete exactly once\n");
            exit(1);
        }
        ovc_abi_free(shortened);
    }
}

static void ovc_declined_connection_rest(
    const OvStoragePlugin_LayerVTableV1 *vtable)
{
    OvStoragePlugin_RemoveConnectionRequest remove_request;
    OvStoragePlugin_UpdateConnectionCredentialsRequest credentials;
    OvStoragePlugin_SecretBundleEntry *entries;
    OvStoragePlugin_ListAddressRootsRequest roots;
    OvStoragePlugin_ListConnectionsRequest connections;
    unsigned before;

    memset(&remove_request, 0, sizeof(remove_request));
    remove_request.struct_size = sizeof(remove_request);
    remove_request.key.target = ovc_declined_str("files");
    remove_request.key.id = ovc_declined_str("declined-remove");
    before = g_completions;
    vtable->remove_connection(
        NULL, &remove_request, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "remove_connection did not complete exactly once\n");
        exit(1);
    }

    /* The second credential-bearing slot, after probe. */
    memset(&credentials, 0, sizeof(credentials));
    credentials.struct_size = sizeof(credentials);
    credentials.key.target = ovc_declined_str("files");
    credentials.key.id = ovc_declined_str("declined-credentials");
    entries = (OvStoragePlugin_SecretBundleEntry *)ovc_abi_alloc(
        sizeof(*entries));
    if (entries == NULL) {
        fprintf(stderr, "failed to allocate the credential bundle\n");
        exit(1);
    }
    memset(entries, 0, sizeof(*entries));
    entries[0].field = ovc_declined_str("token");
    entries[0].value.tag = OvStoragePlugin_SecretValueTag_Bytes;
    entries[0].value.bytes.bytes = ovc_declined_bytes(40u);
    credentials.credentials.entries.ptr = entries;
    credentials.credentials.entries.len = 1u;
    before = g_completions;
    vtable->update_connection_credentials(
        NULL, &credentials, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr,
                "update_connection_credentials did not complete exactly once\n");
        exit(1);
    }

    memset(&roots, 0, sizeof(roots));
    roots.struct_size = sizeof(roots);
    before = g_completions;
    vtable->list_address_roots(
        NULL, &roots, NULL, ovc_declined_complete, NULL);
    memset(&connections, 0, sizeof(connections));
    connections.struct_size = sizeof(connections);
    vtable->list_connections(
        NULL, &connections, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 2u) {
        fprintf(stderr,
                "the list-the-world slots did not complete exactly once each\n");
        exit(1);
    }
}

static void ovc_declined_add_connection(
    const OvStoragePlugin_LayerVTableV1 *vtable)
{
    OvStoragePlugin_LayerConnectionRequest request;
    unsigned before;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.target = ovc_declined_str("files");
    request.connection.backend_kind = ovc_declined_str("file");
    {
        OvStoragePlugin_ConnectionConfigEntry *config;

        config = (OvStoragePlugin_ConnectionConfigEntry *)ovc_abi_alloc(
            2u * sizeof(*config));
        if (config == NULL) {
            fprintf(stderr, "failed to allocate the connection config\n");
            exit(1);
        }
        memset(config, 0, 2u * sizeof(*config));
        config[0].key = ovc_declined_str("root");
        config[0].value.tag = OvStoragePlugin_ConfigValueTag_String;
        config[0].value.string_value = ovc_declined_str("mem:///root");
        /* `Toml` is the other owning `ConfigValue` arm. Covering only
         * `String` would let a miswired release leak every declined
         * connection request carrying TOML config while this contract stayed
         * green. */
        config[1].key = ovc_declined_str("tuning");
        config[1].value.tag = OvStoragePlugin_ConfigValueTag_Toml;
        config[1].value.toml_value = ovc_declined_str("[a]\nb = 1\n");
        request.connection.config.ptr = config;
        request.connection.config.len = 2u;
    }
    before = g_completions;
    vtable->add_connection(NULL, &request, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "add_connection did not complete exactly once\n");
        exit(1);
    }
}

static void ovc_declined_write_redirect(
    const OvStoragePlugin_LayerVTableV1 *vtable)
{
    OvStoragePlugin_WriteRequest request;
    unsigned before;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_declined_str("mem:///declined/redirect");
    /* The third `Body` arm. With every case on `Bytes`, deleting either of the
     * other two branches from `ovstorage_plugin_body_free` left the contract
     * green. */
    request.body.tag = OvStoragePlugin_BodyTag_LocalFile;
    request.body.local_file = ovc_declined_str("/tmp/declined-redirect");
    request.options.struct_size = sizeof(request.options);
    before = g_completions;
    vtable->write_redirect(NULL, &request, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "write_redirect did not complete exactly once\n");
        exit(1);
    }
}


/* The `struct_size` prefix rule, which nothing else here exercises.
 *
 * Every case above passes a full struct, so the guards are never consulted and
 * an all-or-nothing gate would look identical. This drives the case a
 * versioned prefix exists for: a caller whose struct is SHORTER than this
 * build's, which is what a host older than the plugin sends.
 *
 * The fields inside that prefix are present and owned, so they must be
 * released; a gate that refuses the whole struct leaks them, and LeakSanitizer
 * reports it. Nothing past the prefix is read at all -- reading it would be
 * the opposite defect, so the tail here is left uninitialised on purpose.
 */
static void ovc_declined_short_struct(const OvStoragePlugin_LayerVTableV1 *vtable)
{
    OvStoragePlugin_StatRequest stat;
    OvStoragePlugin_LayerConnectionRequest connection;
    OvStoragePlugin_Extensions *extensions;
    OvStoragePlugin_SecretBundleEntry *entries;
    unsigned before;

    /* A prefix that reaches `address` and stops before `options`.
     *
     * Allocated at EXACTLY the prefix length rather than declared full-size
     * with a short `struct_size`. That distinction is the whole point: a
     * full-size object with a small size field still has the memory behind
     * it, so a release that copies the whole struct reads valid bytes and
     * nothing complains. An older host allocates only what its own header
     * describes, and a whole-struct copy then reads past the end of the
     * caller's object -- which ASan reports and a short-struct-in-full-storage
     * fixture cannot. */
    {
        size_t prefix_size = offsetof(OvStoragePlugin_StatRequest, address)
                             + sizeof(stat.address);
        OvStoragePlugin_StatRequest *shortened =
            (OvStoragePlugin_StatRequest *)ovc_abi_alloc(prefix_size);

        if (shortened == NULL) {
            fprintf(stderr, "failed to allocate the shortened request\n");
            exit(1);
        }
        memset(&stat, 0, sizeof(stat));
        stat.struct_size = prefix_size;
        stat.address = ovc_declined_str("mem:///declined/short-prefix");
        memcpy(shortened, &stat, prefix_size);

        before = g_completions;
        vtable->stat(NULL, shortened, NULL, ovc_declined_complete, NULL);
        if (g_completions != before + 1u) {
            fprintf(stderr,
                    "the short-allocation stat did not complete exactly once\n");
            exit(1);
        }
        ovc_abi_free(shortened);
    }

    memset(&stat, 0, sizeof(stat));
    stat.struct_size = offsetof(OvStoragePlugin_StatRequest, address)
                       + sizeof(stat.address);
    extensions = ovc_declined_extensions();
    stat.extensions = extensions;
    stat.address = ovc_declined_str("mem:///declined/short-prefix-2");
    before = g_completions;
    vtable->stat(NULL, &stat, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "the short-prefix stat did not complete exactly once\n");
        exit(1);
    }
    /* The request lends `extensions`; the host still owns and releases it. */
    ovstorage_plugin_extensions_free(extensions);

    /* The credential-bearing one, where an all-or-nothing gate is a silent
     * total leak of the bundle rather than of one string. */
    memset(&connection, 0, sizeof(connection));
    connection.struct_size =
        offsetof(OvStoragePlugin_LayerConnectionRequest, connection)
        + sizeof(connection.connection);
    connection.target = ovc_declined_str("files");
    connection.connection.backend_kind = ovc_declined_str("file");
    entries = (OvStoragePlugin_SecretBundleEntry *)ovc_abi_alloc(
        sizeof(*entries));
    if (entries == NULL) {
        fprintf(stderr, "failed to allocate the short-prefix bundle\n");
        exit(1);
    }
    memset(entries, 0, sizeof(*entries));
    entries[0].field = ovc_declined_str("token");
    entries[0].value.tag = OvStoragePlugin_SecretValueTag_Bytes;
    entries[0].value.bytes.bytes = ovc_declined_bytes(44u);
    connection.connection.credentials.entries.ptr = entries;
    connection.connection.credentials.entries.len = 1u;
    before = g_completions;
    vtable->probe(NULL, &connection, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "the short-prefix probe did not complete exactly once\n");
        exit(1);
    }

    /* A NULL request is ignored rather than dereferenced. */
    before = g_completions;
    vtable->stat(NULL, NULL, NULL, ovc_declined_complete, NULL);
    if (g_completions != before + 1u) {
        fprintf(stderr, "the NULL-request stat did not complete exactly once\n");
        exit(1);
    }
}

int ovstorage_c_source_declined_release_contract(void);

int ovstorage_c_source_declined_release_contract(void)
{
    const OvStoragePlugin_LayerVTableV1 *vtable;
    size_t iteration;

    vtable = &OVSTORAGE_UNSUPPORTED_VTABLE;
    /* Both counters, since both are checked against absolute constants below
     * and this entry point is called once per process from two drivers. */
    g_completions = 0;
    g_stream_drops = 0;
    g_expect_drop_before_completion = 0;

    /* Repeated so a stranded buffer is many blocks rather than one, which is
     * what keeps LeakSanitizer from losing it behind a stale pointer. */
    for (iteration = 0; iteration < 16u; ++iteration) {
        ovc_declined_write(vtable, "write");
        ovc_declined_probe(vtable);
        ovc_declined_continue_write(vtable);
        ovc_declined_update_attributes(vtable);
        ovc_declined_authenticate(vtable);
        ovc_declined_stat(vtable);
        ovc_declined_read(vtable);
        ovc_declined_materialize(vtable);
        ovc_declined_latest_version(vtable);
        ovc_declined_delete_object(vtable);
        ovc_declined_update_metadata(vtable);
        ovc_declined_list_versions(vtable);
        ovc_declined_list_objects(vtable);
        ovc_declined_watch_directory(vtable);
        ovc_declined_create_directory(vtable);
        ovc_declined_delete_directory(vtable);
        ovc_declined_check_access(vtable);
        ovc_declined_root_info_for(vtable);
        ovc_declined_copy_like(vtable);
        ovc_declined_connection_rest(vtable);
        ovc_declined_add_connection(vtable);
        ovc_declined_write_redirect(vtable);
        ovc_declined_short_struct(vtable);
        /* `write_stream` and `write_redirect` take the same request type as
         * `write` and are inherited too, so both are driven. */
        {
            OvStoragePlugin_WriteRequest streamed;
            unsigned before;

            memset(&streamed, 0, sizeof(streamed));
            streamed.struct_size = sizeof(streamed);
            streamed.address = ovc_declined_str("mem:///declined/stream");
            /* The Stream arm, whose release calls the host's `drop_fn`. */
            streamed.body.tag = OvStoragePlugin_BodyTag_Stream;
            streamed.body.stream = ovc_declined_stream();
            streamed.options.struct_size = sizeof(streamed.options);

            before = g_completions;
            g_expect_drop_before_completion = 1;
            vtable->write_stream(
                NULL, &streamed, NULL, ovc_declined_complete, NULL);
            g_expect_drop_before_completion = 0;
            if (g_completions != before + 1u) {
                fprintf(stderr, "write_stream did not complete exactly once\n");
                return EXIT_FAILURE;
            }
        }
    }

    if (g_stream_drops != 16u) {
        fprintf(stderr,
                "expected %u stream drops, saw %u -- the Stream body arm was "
                "not released, so the ordering rule is untested\n",
                16u,
                g_stream_drops);
        return EXIT_FAILURE;
    }
    if (g_completions != 16u * 33u) {
        fprintf(stderr,
                "expected %u completions, saw %u\n",
                16u * 33u,
                g_completions);
        return EXIT_FAILURE;
    }
    printf("every declining slot released its request (%u calls)\n",
           g_completions);
    return EXIT_SUCCESS;
}
