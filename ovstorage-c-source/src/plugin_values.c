/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Plugin-ABI reclamation surface declared by ovstorage_plugin.h.
 *
 * This translation unit implements every ovstorage_plugin_* free function
 * (plus the next-action accessor) so C hosts and wrapper plugins can honor
 * the header's ownership contracts without hand-rolling deep frees.  Each
 * function mirrors the Rust codec's Drop chain exactly: the same nested
 * buffers, optionals, lists, and tagged-union payloads are released at the
 * same depth, and heap-versus-in-place semantics follow the codec body.  The
 * whole surface is kept in this one file so the link-completeness gate can
 * pin it.
 *
 * Every buffer crossing the plugin ABI uses the codec's System-allocator
 * convention, so all releases go through ovc_abi_free (never CRT free).
 */

#include "internal.h"

/* The request releases below are declared here; including it makes a signature
 * drift a compile error rather than an ABI mismatch found at link time. */
#include "ovstorage_defaults.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(OVC_ABI_FREE)
void OVC_ABI_FREE(void *allocation);
#define ovc_abi_free OVC_ABI_FREE
#endif

/* ------------------------------------------------------------------------- */
/* Primitive owning containers.
 *
 * Rust-minted empty Str/Bytes/List values still carry a non-NULL one-byte
 * sentinel allocation; releasing unconditionally through the NULL-tolerant
 * ovc_abi_free covers both that sentinel and C-minted NULL buffers. */

static void ovc_pval_str_clear(OvStoragePlugin_Str *value)
{
    if (value == NULL) {
        return;
    }
    ovc_abi_free(value->ptr);
    value->ptr = NULL;
    value->len = 0;
}

static void ovc_pval_opt_str_clear(OvStoragePlugin_Optional_Str *value)
{
    if (value == NULL) {
        return;
    }
    if (value->present) {
        ovc_pval_str_clear(&value->value);
        value->present = false;
    }
}

static void ovc_pval_bytes_clear(OvStoragePlugin_Bytes *value)
{
    if (value == NULL) {
        return;
    }
    ovc_abi_free(value->ptr);
    value->ptr = NULL;
    value->len = 0;
}

static void ovc_pval_opt_bytes_clear(OvStoragePlugin_Optional_Bytes *value)
{
    if (value == NULL) {
        return;
    }
    if (value->present) {
        ovc_pval_bytes_clear(&value->value);
        value->present = false;
    }
}

static void ovc_pval_key_values_clear(OvStoragePlugin_KeyValueList *values)
{
    size_t index;

    if (values == NULL) {
        return;
    }
    if (values->ptr != NULL) {
        for (index = 0; index < values->len; ++index) {
            ovc_pval_str_clear(&values->ptr[index].key);
            ovc_pval_str_clear(&values->ptr[index].value);
        }
    }
    ovc_abi_free(values->ptr);
    values->ptr = NULL;
    values->len = 0;
}

static void ovc_pval_extension_entries_clear(
    OvStoragePlugin_List_ExtensionEntry *entries)
{
    size_t index;

    if (entries == NULL) {
        return;
    }
    if (entries->ptr != NULL) {
        for (index = 0; index < entries->len; ++index) {
            ovc_pval_str_clear(&entries->ptr[index].key);
            ovc_pval_bytes_clear(&entries->ptr[index].value);
        }
    }
    ovc_abi_free(entries->ptr);
    entries->ptr = NULL;
    entries->len = 0;
}

static void ovc_pval_str_list_clear(OvStoragePlugin_List_Str *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    if (list->ptr != NULL) {
        for (index = 0; index < list->len; ++index) {
            ovc_pval_str_clear(&list->ptr[index]);
        }
    }
    ovc_abi_free(list->ptr);
    list->ptr = NULL;
    list->len = 0;
}

static void ovc_pval_checksum_list_clear(
    OvStoragePlugin_List_ChecksumEntry *checksums)
{
    size_t index;

    if (checksums == NULL) {
        return;
    }
    if (checksums->ptr != NULL) {
        for (index = 0; index < checksums->len; ++index) {
            ovc_pval_str_clear(&checksums->ptr[index].algorithm.token);
            ovc_pval_bytes_clear(&checksums->ptr[index].bytes);
        }
    }
    ovc_abi_free(checksums->ptr);
    checksums->ptr = NULL;
    checksums->len = 0;
}

/* ------------------------------------------------------------------------- */
/* Streams.  Every stream shape is (state, next_fn, drop_fn); reclamation
 * drives drop_fn exactly once with the opaque state. */

static void ovc_pval_stream_drop(void *state, OvStoragePlugin_StreamDropFn drop_fn)
{
    if (drop_fn != NULL) {
        drop_fn(state);
    }
}

/* ------------------------------------------------------------------------- */
/* Object metadata. */

static void ovc_pval_object_info_clear(OvStoragePlugin_ObjectInfo *info)
{
    if (info == NULL) {
        return;
    }
    ovc_pval_str_clear(&info->address);
    ovc_pval_opt_str_clear(&info->etag);
    ovc_pval_opt_str_clear(&info->version);
    ovc_pval_checksum_list_clear(&info->checksums);
    if (info->system_metadata.present) {
        ovc_pval_key_values_clear(&info->system_metadata.value);
        info->system_metadata.present = false;
    }
    if (info->user_metadata.present) {
        ovc_pval_key_values_clear(&info->user_metadata.value);
        info->user_metadata.present = false;
    }
    ovc_pval_opt_str_clear(&info->modified_by);
}

static void ovc_pval_object_info_list_clear(
    OvStoragePlugin_List_ObjectInfo *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    if (list->ptr != NULL) {
        for (index = 0; index < list->len; ++index) {
            ovc_pval_object_info_clear(&list->ptr[index]);
        }
    }
    ovc_abi_free(list->ptr);
    list->ptr = NULL;
    list->len = 0;
}

/* ------------------------------------------------------------------------- */
/* Connection identity, auth state, and connection values. */

static void ovc_pval_connection_id_clear(OvStoragePlugin_ConnectionId *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_str_clear(&value->id);
}

static void ovc_pval_opt_connection_id_clear(
    OvStoragePlugin_Optional_ConnectionId *value)
{
    if (value == NULL) {
        return;
    }
    if (value->present) {
        ovc_pval_connection_id_clear(&value->value);
        value->present = false;
    }
}

static void ovc_pval_auth_reason_clear(OvStoragePlugin_AuthReason *reason)
{
    if (reason == NULL) {
        return;
    }
    /* Only the Unknown variant owns a payload; the other variants leave
     * unknown_details uninitialized and it must not be read. */
    if (reason->tag == OvStoragePlugin_AuthReasonTag_Unknown) {
        ovc_pval_str_clear(&reason->unknown_details);
    }
}

static void ovc_pval_auth_state_clear(OvStoragePlugin_ConnectionAuthState *state)
{
    if (state == NULL) {
        return;
    }
    switch (state->tag) {
    case OvStoragePlugin_ConnectionAuthStateTag_AwaitingAuth:
        ovc_pval_auth_reason_clear(&state->awaiting_auth.reason);
        if (state->awaiting_auth.last_attempt.present) {
            if (state->awaiting_auth.last_attempt.value.error.present) {
                ovc_pval_str_clear(
                    &state->awaiting_auth.last_attempt.value.error.value
                         .message);
                state->awaiting_auth.last_attempt.value.error.present = false;
            }
            state->awaiting_auth.last_attempt.present = false;
        }
        break;
    case OvStoragePlugin_ConnectionAuthStateTag_AuthFailed:
        ovc_pval_str_clear(&state->auth_failed.error_message);
        break;
    case OvStoragePlugin_ConnectionAuthStateTag_Authenticated:
    case OvStoragePlugin_ConnectionAuthStateTag_Anonymous:
    default:
        /* No owned payload. */
        break;
    }
}

static void ovc_pval_connection_source_clear(
    OvStoragePlugin_ConnectionSource *source)
{
    if (source == NULL) {
        return;
    }
    /* Only the BrokerDelivered variant owns memory; Static/Runtime payloads
     * are plain values and the non-active slots carry unspecified bytes. */
    if (source->tag == OvStoragePlugin_ConnectionSourceTag_BrokerDelivered) {
        ovc_pval_str_clear(&source->broker_delivered.broker_principal);
    }
}

static void ovc_pval_connection_clear(OvStoragePlugin_Connection *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_connection_id_clear(&value->id);
    ovc_pval_str_clear(&value->backend_kind);
    ovc_pval_str_clear(&value->display_name);
    ovc_pval_connection_source_clear(&value->source);
    ovc_pval_str_list_clear(&value->current_addresses);
    ovc_pval_auth_state_clear(&value->auth_state);
    ovc_pval_key_values_clear(&value->user_metadata);
}

static void ovc_pval_connection_list_clear(
    OvStoragePlugin_List_Connection *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    if (list->ptr != NULL) {
        for (index = 0; index < list->len; ++index) {
            ovc_pval_connection_clear(&list->ptr[index]);
        }
    }
    ovc_abi_free(list->ptr);
    list->ptr = NULL;
    list->len = 0;
}

/* ------------------------------------------------------------------------- */
/* Secrets and connection requests.
 *
 * Matching the Rust codec, releasing a SecretBytes zeroizes its buffer
 * before the ABI allocator reclaims it, so no plaintext reaches the process
 * heap's free list.  The wipe lives in the ownership cleanup rather than in
 * the conversions that consume a secret: a decode that fails partway drops
 * whatever secrets remain without ever reaching a conversion. */

void ovc_pval_secret_bytes_wipe(OvStoragePlugin_SecretBytes *value)
{
    if (value == NULL || value->bytes.ptr == NULL) {
        return;
    }
    ovc_secure_zero(value->bytes.ptr, value->bytes.len);
}

static void ovc_pval_secret_bytes_clear(OvStoragePlugin_SecretBytes *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_secret_bytes_wipe(value);
    ovc_pval_bytes_clear(&value->bytes);
}

static void ovc_pval_secret_value_clear(OvStoragePlugin_SecretValue *value)
{
    if (value == NULL) {
        return;
    }
    switch (value->tag) {
    case OvStoragePlugin_SecretValueTag_Bytes:
        ovc_pval_secret_bytes_clear(&value->bytes);
        break;
    case OvStoragePlugin_SecretValueTag_OAuthToken:
        ovc_pval_secret_bytes_clear(&value->oauth_token.token);
        if (value->oauth_token.refresh.present) {
            ovc_pval_secret_bytes_clear(&value->oauth_token.refresh.value);
            value->oauth_token.refresh.present = false;
        }
        break;
    case OvStoragePlugin_SecretValueTag_File:
        ovc_pval_secret_bytes_clear(&value->file);
        break;
    case OvStoragePlugin_SecretValueTag_MtlsCertPair:
        ovc_pval_secret_bytes_clear(&value->mtls_cert_pair.cert_pem);
        ovc_pval_secret_bytes_clear(&value->mtls_cert_pair.key_pem);
        break;
    case OvStoragePlugin_SecretValueTag_SystemIdentity:
    default:
        /* No owned payload. */
        break;
    }
}

static void ovc_pval_secret_bundle_clear(OvStoragePlugin_SecretBundle *bundle)
{
    size_t index;

    if (bundle == NULL) {
        return;
    }
    if (bundle->entries.ptr != NULL) {
        for (index = 0; index < bundle->entries.len; ++index) {
            ovc_pval_str_clear(&bundle->entries.ptr[index].field);
            ovc_pval_secret_value_clear(&bundle->entries.ptr[index].value);
        }
    }
    ovc_abi_free(bundle->entries.ptr);
    bundle->entries.ptr = NULL;
    bundle->entries.len = 0;
}

static void ovc_pval_config_value_clear(OvStoragePlugin_ConfigValue *value)
{
    if (value == NULL) {
        return;
    }
    switch (value->tag) {
    case OvStoragePlugin_ConfigValueTag_String:
        ovc_pval_str_clear(&value->string_value);
        break;
    case OvStoragePlugin_ConfigValueTag_Toml:
        ovc_pval_str_clear(&value->toml_value);
        break;
    case OvStoragePlugin_ConfigValueTag_Int:
    case OvStoragePlugin_ConfigValueTag_Bool:
    default:
        /* No owned payload. */
        break;
    }
}

static void ovc_pval_config_entries_clear(
    OvStoragePlugin_List_ConnectionConfigEntry *entries)
{
    size_t index;

    if (entries == NULL) {
        return;
    }
    if (entries->ptr != NULL) {
        for (index = 0; index < entries->len; ++index) {
            ovc_pval_str_clear(&entries->ptr[index].key);
            ovc_pval_config_value_clear(&entries->ptr[index].value);
        }
    }
    ovc_abi_free(entries->ptr);
    entries->ptr = NULL;
    entries->len = 0;
}

/* ------------------------------------------------------------------------- */
/* Backend-kind / layer-kind descriptor schemas. */

static void ovc_pval_enum_source_clear(OvStoragePlugin_EnumSource *source)
{
    if (source == NULL) {
        return;
    }
    if (source->tag == OvStoragePlugin_EnumSourceTag_Static) {
        ovc_pval_str_list_clear(&source->static_choices);
    }
}

static void ovc_pval_config_field_kind_clear(
    OvStoragePlugin_ConfigFieldKind *kind)
{
    if (kind == NULL) {
        return;
    }
    if (kind->tag == OvStoragePlugin_ConfigFieldKindTag_Enum) {
        ovc_pval_enum_source_clear(&kind->enum_source);
    }
}

static void ovc_pval_config_field_list_clear(
    OvStoragePlugin_List_ConfigField *fields)
{
    size_t index;

    if (fields == NULL) {
        return;
    }
    if (fields->ptr != NULL) {
        for (index = 0; index < fields->len; ++index) {
            OvStoragePlugin_ConfigField *field;

            field = &fields->ptr[index];
            ovc_pval_str_clear(&field->key);
            ovc_pval_str_clear(&field->display_name);
            ovc_pval_config_field_kind_clear(&field->kind);
            if (field->default_.present) {
                ovc_pval_config_value_clear(&field->default_.value);
                field->default_.present = false;
            }
            ovc_pval_opt_str_clear(&field->help);
            ovc_pval_opt_str_clear(&field->example);
            ovc_pval_opt_str_clear(&field->group);
        }
    }
    ovc_abi_free(fields->ptr);
    fields->ptr = NULL;
    fields->len = 0;
}

static void ovc_pval_credential_field_list_clear(
    OvStoragePlugin_List_CredentialField *fields)
{
    size_t index;

    if (fields == NULL) {
        return;
    }
    if (fields->ptr != NULL) {
        for (index = 0; index < fields->len; ++index) {
            ovc_pval_str_clear(&fields->ptr[index].key);
            ovc_pval_str_clear(&fields->ptr[index].display_name);
            ovc_pval_opt_str_clear(&fields->ptr[index].default_);
            ovc_pval_opt_str_clear(&fields->ptr[index].help);
        }
    }
    ovc_abi_free(fields->ptr);
    fields->ptr = NULL;
    fields->len = 0;
}

static void ovc_pval_credential_method_list_clear(
    OvStoragePlugin_List_CredentialMethod *methods)
{
    size_t index;

    if (methods == NULL) {
        return;
    }
    if (methods->ptr != NULL) {
        for (index = 0; index < methods->len; ++index) {
            ovc_pval_str_clear(&methods->ptr[index].key);
            ovc_pval_str_clear(&methods->ptr[index].display_name);
            ovc_pval_str_list_clear(&methods->ptr[index].fields);
            ovc_pval_opt_str_clear(&methods->ptr[index].help);
        }
    }
    ovc_abi_free(methods->ptr);
    methods->ptr = NULL;
    methods->len = 0;
}

/* ------------------------------------------------------------------------- */
/* Redirect / HTTP machinery reached through ReadResult and WriteStep. */

static void ovc_pval_http_request_clear(OvStoragePlugin_HttpRequest *request)
{
    if (request == NULL) {
        return;
    }
    ovc_pval_str_clear(&request->method);
    ovc_pval_str_clear(&request->url);
    ovc_pval_key_values_clear(&request->headers);
}

static void ovc_pval_response_parsing_clear(
    OvStoragePlugin_ResponseParsing *parsing)
{
    size_t index;

    if (parsing == NULL) {
        return;
    }
    ovc_pval_opt_str_clear(&parsing->etag_header);
    ovc_pval_opt_str_clear(&parsing->version_header);
    ovc_pval_opt_str_clear(&parsing->size_header);
    ovc_pval_opt_str_clear(&parsing->mtime_header);
    ovc_pval_str_list_clear(&parsing->system_metadata_headers);
    ovc_pval_opt_str_clear(&parsing->content_checksum_header);
    if (parsing->content_checksum_algorithm.present) {
        ovc_pval_str_clear(&parsing->content_checksum_algorithm.value.token);
        parsing->content_checksum_algorithm.present = false;
    }
    if (parsing->checksum_headers.ptr != NULL) {
        for (index = 0; index < parsing->checksum_headers.len; ++index) {
            ovc_pval_str_clear(
                &parsing->checksum_headers.ptr[index].algorithm.token);
            ovc_pval_str_clear(&parsing->checksum_headers.ptr[index].header);
        }
    }
    ovc_abi_free(parsing->checksum_headers.ptr);
    parsing->checksum_headers.ptr = NULL;
    parsing->checksum_headers.len = 0;
}

static void ovc_pval_read_redirect_clear(OvStoragePlugin_ReadRedirect *redirect)
{
    if (redirect == NULL) {
        return;
    }
    ovc_pval_http_request_clear(&redirect->request);
    ovc_pval_response_parsing_clear(&redirect->response_parsing);
    ovc_pval_str_clear(&redirect->scope.physical_url_prefix);
    ovc_pval_str_clear(&redirect->audit_id);
}

static void ovc_pval_write_redirect_clear(
    OvStoragePlugin_WriteRedirect *redirect)
{
    if (redirect == NULL) {
        return;
    }
    ovc_pval_http_request_clear(&redirect->request);
    /* Non-active body_source payloads carry safe defaults (NULL Bytes), so
     * an unconditional release frees at most one allocation, exactly as the
     * Rust field-by-field drop does. */
    ovc_pval_bytes_clear(&redirect->body_source.inline_);
    ovc_pval_str_list_clear(&redirect->result_capture.headers);
    ovc_pval_str_clear(&redirect->scope.physical_url_prefix);
    ovc_pval_str_clear(&redirect->audit_id);
}

static void ovc_pval_write_redirect_batch_clear(
    OvStoragePlugin_WriteRedirectBatch *batch)
{
    size_t index;

    if (batch == NULL) {
        return;
    }
    ovc_pval_bytes_clear(&batch->continuation);
    if (batch->redirects.ptr != NULL) {
        for (index = 0; index < batch->redirects.len; ++index) {
            ovc_pval_write_redirect_clear(&batch->redirects.ptr[index]);
        }
    }
    ovc_abi_free(batch->redirects.ptr);
    batch->redirects.ptr = NULL;
    batch->redirects.len = 0;
}

/* ------------------------------------------------------------------------- */
/* Root introspection values. */

static void ovc_pval_route_source_clear(OvStoragePlugin_RouteSource *source)
{
    if (source == NULL) {
        return;
    }
    /* RouteSource and AliasSource are single discriminated structs (no
     * uninitialized union slots): non-active optionals are absent, so every
     * optional is released unconditionally, as in the Rust auto-drop. */
    ovc_pval_opt_connection_id_clear(&source->connection_id);
    ovc_pval_opt_str_clear(&source->broker_principal);
    ovc_pval_opt_str_clear(&source->alias_to);
    if (source->alias_source.present) {
        ovc_pval_opt_str_clear(&source->alias_source.value.broker_principal);
        source->alias_source.present = false;
    }
}

static void ovc_pval_root_info_clear(OvStoragePlugin_RootInfo *info)
{
    if (info == NULL) {
        return;
    }
    ovc_pval_str_clear(&info->root);
    ovc_pval_opt_str_clear(&info->display_name);
    ovc_pval_str_clear(&info->layer_kind);
    ovc_pval_opt_connection_id_clear(&info->connection_id);
    ovc_pval_route_source_clear(&info->source);
    if (info->alias_state.present) {
        ovc_pval_opt_str_clear(&info->alias_state.value.reason);
        info->alias_state.present = false;
    }
    ovc_pval_opt_bytes_clear(&info->icon);
    ovc_pval_key_values_clear(&info->user_metadata);
    ovc_pval_opt_str_clear(&info->owning_target);
}

static void ovc_pval_root_info_list_clear(OvStoragePlugin_List_RootInfo *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    if (list->ptr != NULL) {
        for (index = 0; index < list->len; ++index) {
            ovc_pval_root_info_clear(&list->ptr[index]);
        }
    }
    ovc_abi_free(list->ptr);
    list->ptr = NULL;
    list->len = 0;
}

static void ovc_pval_address_roots_clear(
    OvStoragePlugin_List_AddressRootEntry *roots)
{
    size_t index;

    if (roots == NULL) {
        return;
    }
    if (roots->ptr != NULL) {
        for (index = 0; index < roots->len; ++index) {
            ovc_pval_str_clear(&roots->ptr[index].address);
        }
    }
    ovc_abi_free(roots->ptr);
    roots->ptr = NULL;
    roots->len = 0;
}

/* ------------------------------------------------------------------------- */
/* Errors.
 *
 * A non-NULL but misaligned context pointer came from an older-ABI producer
 * that never initialized the field; the Rust codec leaks it rather than
 * reclaiming a garbage allocation, and so does this implementation. */

struct ovc_pval_context_align_probe {
    char prefix;
    OvStoragePlugin_ErrorContextV1 context;
};

static bool ovc_pval_error_context_is_aligned(
    const OvStoragePlugin_ErrorContextV1 *context)
{
    size_t alignment;

    alignment = offsetof(struct ovc_pval_context_align_probe, context);
    return ((uintptr_t)(const void *)context % alignment) == 0;
}

static void ovc_pval_error_context_clear(
    OvStoragePlugin_ErrorContextV1 *context)
{
    if (context == NULL) {
        return;
    }
    if (context->kind == OvStoragePlugin_ErrorContextKindV1_Identity) {
        ovc_pval_opt_str_clear(&context->identity.new_etag);
    } else if (context->kind == OvStoragePlugin_ErrorContextKindV1_Auth) {
        ovc_pval_connection_id_clear(&context->auth.connection_id);
        ovc_pval_opt_str_clear(&context->auth.reason);
    } else if (context->kind == OvStoragePlugin_ErrorContextKindV1_Partial) {
        /* Four plain enums: the slot owns no allocation. Spelled out rather
         * than left to the unknown-discriminant fallthrough below, so a
         * future slot that does own memory cannot inherit a silent no-op. */
    }
    /* An unrecognized discriminant means "context absent" per the SPI's
     * ignore-unknown forward-compat rule: nothing further is released. */
}

void ovc_pval_error_clear(OvStoragePlugin_Error *error)
{
    if (error == NULL) {
        return;
    }
    ovc_abi_free(error->message_ptr);
    error->message_ptr = NULL;
    error->message_len = 0;
    if (error->context != NULL &&
        ovc_pval_error_context_is_aligned(error->context)) {
        ovc_pval_error_context_clear(error->context);
        ovc_abi_free(error->context);
    }
    error->context = NULL;
    ovc_pval_opt_str_clear(&error->next_action);
}

/* ------------------------------------------------------------------------- */
/* Public reclamation surface, in ovstorage_plugin.h declaration order. */

void ovstorage_plugin_backend_change_event_free(
    OvStoragePlugin_BackendChangeEvent *value)
{
    if (value == NULL) {
        return;
    }
    switch (value->tag) {
    case OvStoragePlugin_BackendChangeEventTag_Object:
        ovc_pval_str_clear(&value->object.address);
        ovc_pval_opt_str_clear(&value->object.etag);
        ovc_pval_opt_str_clear(&value->object.version);
        ovc_pval_bytes_clear(&value->object.cursor.bytes);
        break;
    case OvStoragePlugin_BackendChangeEventTag_Lapsed:
        ovc_pval_bytes_clear(&value->lapsed.cursor.bytes);
        break;
    default:
        break;
    }
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_auth_event_stream_free(
    OvStoragePlugin_AuthEventStream *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_stream_drop(value->state, value->drop_fn);
    ovc_abi_free(value);
}

void ovstorage_plugin_backend_change_stream_free(
    OvStoragePlugin_BackendChangeStream *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_stream_drop(value->state, value->drop_fn);
    ovc_abi_free(value);
}

void ovstorage_plugin_backend_address_roots_change_free(
    OvStoragePlugin_BackendAddressRootsChange *value)
{
    if (value == NULL) {
        return;
    }
    /* Every variant carries the same list-shaped payload. */
    ovc_pval_address_roots_clear(&value->roots);
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_backend_address_roots_stream_free(
    OvStoragePlugin_BackendAddressRootsStream *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_stream_drop(value->state, value->drop_fn);
    ovc_abi_free(value);
}

void ovstorage_plugin_error_context_free(OvStoragePlugin_ErrorContextV1 *context)
{
    if (context == NULL) {
        return;
    }
    if (!ovc_pval_error_context_is_aligned(context)) {
        return;
    }
    ovc_pval_error_context_clear(context);
    ovc_abi_free(context);
}

void ovstorage_plugin_error_free(OvStoragePlugin_Error *error)
{
    if (error == NULL) {
        return;
    }
    ovc_pval_error_clear(error);
    ovc_abi_free(error);
}

bool ovstorage_plugin_error_get_next_action(const OvStoragePlugin_Error *error,
                                            const char **out_ptr,
                                            size_t *out_len)
{
    if (error == NULL || out_ptr == NULL || out_len == NULL) {
        return false;
    }
    /*
     * The hint travels in the Error struct, so this reads it directly and
     * agrees with the Rust accessor on any error either side minted.  A
     * zero-length buffer counts as absent, matching the encoder.
     */
    if (!error->next_action.present || error->next_action.value.ptr == NULL ||
        error->next_action.value.len == 0) {
        return false;
    }
    *out_ptr = error->next_action.value.ptr;
    *out_len = error->next_action.value.len;
    return true;
}

void ovstorage_plugin_backend_id_free(OvStoragePlugin_BackendId *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_str_clear(&value->id);
}

void ovstorage_plugin_resolved_target_free(OvStoragePlugin_ResolvedTarget *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_str_clear(&value->backend_id.id);
    ovc_pval_str_clear(&value->resolved_address);
}

void ovstorage_plugin_object_info_free(OvStoragePlugin_ObjectInfo *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_object_info_clear(value);
    ovc_abi_free(value);
}

void ovstorage_plugin_body_stream_free(OvStoragePlugin_BodyStream *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_stream_drop(value->state, value->drop_fn);
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_body_free(OvStoragePlugin_Body *value)
{
    if (value == NULL) {
        return;
    }
    switch (value->tag) {
    case OvStoragePlugin_BodyTag_Bytes:
        ovc_pval_bytes_clear(&value->bytes);
        break;
    case OvStoragePlugin_BodyTag_LocalFile:
        ovc_pval_str_clear(&value->local_file);
        break;
    case OvStoragePlugin_BodyTag_Stream:
        ovc_pval_stream_drop(value->stream.state, value->stream.drop_fn);
        break;
    default:
        break;
    }
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_write_result_free(OvStoragePlugin_WriteResult *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_object_info_clear(&value->info);
    ovc_abi_free(value);
}

void ovstorage_plugin_read_result_free(OvStoragePlugin_ReadResult *value)
{
    if (value == NULL) {
        return;
    }
    switch (value->tag) {
    case OvStoragePlugin_ReadResultTag_Bytes:
        ovc_pval_bytes_clear(&value->bytes.bytes);
        ovc_pval_object_info_clear(&value->bytes.info);
        break;
    case OvStoragePlugin_ReadResultTag_LocalDelegate:
        ovc_pval_str_clear(&value->local_delegate.path);
        ovc_pval_object_info_clear(&value->local_delegate.info);
        ovc_pval_stream_drop(value->local_delegate.lease.state,
                             value->local_delegate.lease.drop_fn);
        break;
    case OvStoragePlugin_ReadResultTag_Redirect:
        ovc_pval_read_redirect_clear(&value->redirect);
        break;
    case OvStoragePlugin_ReadResultTag_Stream:
        ovc_pval_stream_drop(value->stream.stream.state,
                             value->stream.stream.drop_fn);
        ovc_pval_object_info_clear(&value->stream.info);
        break;
    default:
        break;
    }
    ovc_abi_free(value);
}

void ovstorage_plugin_write_step_free(OvStoragePlugin_WriteStep *value)
{
    if (value == NULL) {
        return;
    }
    switch (value->tag) {
    case OvStoragePlugin_WriteStepTag_Done:
        ovc_pval_object_info_clear(&value->done.info);
        break;
    case OvStoragePlugin_WriteStepTag_Redirects:
        ovc_pval_write_redirect_batch_clear(&value->redirects);
        break;
    default:
        break;
    }
    ovc_abi_free(value);
}

void ovstorage_plugin_access_decision_free(OvStoragePlugin_AccessDecision *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_opt_str_clear(&value->reason);
    ovc_abi_free(value);
}

void ovstorage_plugin_str_free(OvStoragePlugin_Str *value)
{
    ovc_pval_str_clear(value);
}

void ovstorage_plugin_bytes_free(OvStoragePlugin_Bytes *value)
{
    ovc_pval_bytes_clear(value);
}

void ovstorage_plugin_storage_backend_kind_descriptor_free(
    OvStoragePlugin_StorageBackendKindDescriptor *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_str_clear(&value->kind);
    ovc_pval_str_clear(&value->display_name);
    ovc_pval_opt_str_clear(&value->description);
    ovc_pval_config_field_list_clear(&value->config_schema);
    ovc_pval_credential_field_list_clear(&value->credential_schema);
    ovc_pval_credential_method_list_clear(&value->credential_methods);
    ovc_pval_opt_bytes_clear(&value->icon);
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_connection_request_free(
    OvStoragePlugin_ConnectionRequest *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_str_clear(&value->backend_kind);
    ovc_pval_config_entries_clear(&value->config);
    ovc_pval_secret_bundle_clear(&value->credentials);
    ovc_pval_opt_str_clear(&value->display_name);
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_connection_free(OvStoragePlugin_Connection *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_connection_clear(value);
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_auth_event_free(OvStoragePlugin_AuthEvent *value)
{
    if (value == NULL) {
        return;
    }
    switch (value->tag) {
    case OvStoragePlugin_AuthEventTag_OpenBrowser:
        ovc_pval_str_clear(&value->open_browser.url);
        break;
    case OvStoragePlugin_AuthEventTag_DeviceCode:
        ovc_pval_str_clear(&value->device_code.user_code);
        ovc_pval_str_clear(&value->device_code.verification_url);
        break;
    case OvStoragePlugin_AuthEventTag_Progress:
        ovc_pval_str_clear(&value->progress.message);
        break;
    case OvStoragePlugin_AuthEventTag_Succeeded:
        ovc_pval_connection_clear(&value->succeeded.connection);
        if (value->succeeded.credentials.present) {
            ovc_pval_secret_bundle_clear(&value->succeeded.credentials.value);
            value->succeeded.credentials.present = false;
        }
        break;
    case OvStoragePlugin_AuthEventTag_Failed:
        ovc_pval_str_clear(&value->failed.error_message);
        break;
    case OvStoragePlugin_AuthEventTag_Cancelled:
    default:
        /* No owned payload. */
        break;
    }
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_extension_entry_free(OvStoragePlugin_ExtensionEntry *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_str_clear(&value->key);
    ovc_pval_bytes_clear(&value->value);
}

void ovstorage_plugin_extensions_free(OvStoragePlugin_Extensions *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_extension_entries_clear(&value->entries);
    ovc_abi_free(value);
}

void ovstorage_plugin_root_info_free(OvStoragePlugin_RootInfo *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_root_info_clear(value);
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_root_info_snapshot_free(
    OvStoragePlugin_RootInfoSnapshot *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_root_info_list_clear(&value->roots);
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_root_info_change_free(OvStoragePlugin_RootInfoChange *value)
{
    if (value == NULL) {
        return;
    }
    /* Every variant carries the same list-shaped payload. */
    ovc_pval_root_info_list_clear(&value->roots);
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_root_info_change_stream_free(
    OvStoragePlugin_RootInfoChangeStream *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_stream_drop(value->state, value->drop_fn);
    ovc_abi_free(value);
}

void ovstorage_plugin_connection_snapshot_free(
    OvStoragePlugin_ConnectionSnapshot *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_connection_list_clear(&value->connections);
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_connection_change_free(
    OvStoragePlugin_ConnectionChange *value)
{
    if (value == NULL) {
        return;
    }
    /* ConnectionChange is a single discriminated struct: non-active fields
     * are absent/empty rather than uninitialized, so every field is
     * released unconditionally, as in the Rust auto-drop. */
    if (value->connection.present) {
        ovc_pval_connection_clear(&value->connection.value);
        value->connection.present = false;
    }
    ovc_pval_connection_list_clear(&value->connections);
    ovc_pval_opt_connection_id_clear(&value->removed_id);
    memset(value, 0, sizeof(*value));
}

void ovstorage_plugin_connection_change_stream_free(
    OvStoragePlugin_ConnectionChangeStream *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_stream_drop(value->state, value->drop_fn);
    ovc_abi_free(value);
}

void ovstorage_plugin_list_page_free(OvStoragePlugin_ListPage *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_object_info_list_clear(&value->items);
    ovc_pval_opt_str_clear(&value->next_page_token);
    ovc_abi_free(value);
}

void ovstorage_plugin_version_page_free(OvStoragePlugin_VersionPage *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_object_info_list_clear(&value->items);
    ovc_pval_opt_str_clear(&value->next_page_token);
    ovc_abi_free(value);
}

/*
 * Reclaim the ABI-v8 `list_address_roots` success envelope: an
 * ovc_abi_alloc'd struct that owns its RootInfoSnapshot by value and,
 * when non-NULL, a heap RootInfoChangeStream pointer.  Inverts the
 * producer allocation (ovc_file_list_address_roots_result) exactly and
 * mirrors the Rust `ListAddressRootsResult` Drop: the optional updates
 * stream is dropped first (drive drop_fn, then free the stream struct),
 * the snapshot's buffers are released in place, then the envelope itself
 * is freed.  This is the producer-side error-path / external-consumer
 * reclaimer; the in-tree dispatch consumer clears the envelope through
 * its own static helpers, so the two paths never touch the same
 * envelope.  Safe with NULL and on an all-zero (updates == NULL,
 * empty-snapshot) envelope.
 */
void ovstorage_plugin_list_address_roots_result_free(
    OvStoragePlugin_ListAddressRootsResult *value)
{
    if (value == NULL) {
        return;
    }
    /* NULL-safe: no-op when the Layer has no update channel. */
    ovstorage_plugin_root_info_change_stream_free(value->updates);
    ovstorage_plugin_root_info_snapshot_free(&value->snapshot);
    ovc_abi_free(value);
}

/*
 * Reclaim the ABI-v8 `list_connections` success envelope.  Same
 * ownership contract as ovstorage_plugin_list_address_roots_result_free,
 * over a ConnectionSnapshot and an optional ConnectionChangeStream.
 */
void ovstorage_plugin_list_connections_result_free(
    OvStoragePlugin_ListConnectionsResult *value)
{
    if (value == NULL) {
        return;
    }
    /* NULL-safe: no-op when the Layer has no update channel. */
    ovstorage_plugin_connection_change_stream_free(value->updates);
    ovstorage_plugin_connection_snapshot_free(&value->snapshot);
    ovc_abi_free(value);
}

/*
 * Mirrors the Rust codec body exactly: nested allocations are released in
 * place and the outer storage is NOT reclaimed here.  Descriptor storage
 * belongs to its producer (init-result kinds are plugin-owned and released
 * through plugin_vtable->drop; list elements ride their list's release).
 */
void ovstorage_plugin_layer_kind_descriptor_free(
    OvStoragePlugin_LayerKindDescriptor *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_str_clear(&value->kind);
    ovc_pval_str_clear(&value->display_name);
    ovc_pval_opt_str_clear(&value->description);
    ovc_pval_config_field_list_clear(&value->config_schema);
    ovc_pval_credential_field_list_clear(&value->credential_schema);
    ovc_pval_credential_method_list_clear(&value->credential_methods);
    ovc_pval_opt_bytes_clear(&value->icon);
    memset(value, 0, sizeof(*value));
}

/* ------------------------------------------------------------------------- */
/* Request releases, declared by ovstorage_defaults.h.
 *
 * A slot owns the request it is handed, so a slot that declines still has to
 * release it.  These give a slot author one call per request type instead of
 * a hand-rolled deep free per decline path.
 *
 * Three rules hold for every one of them.
 *
 * The parameter is const because that is what a slot receives.  Each release
 * copies the struct and clears the COPY: every owned thing in a request is
 * reached by pointer, so the copy names the same buffers while the caller's
 * storage -- which may legitimately be read-only -- is never written.
 *
 * `extensions` is never touched.  It is the one borrowed field: the host
 * retains it and frees it itself, so releasing it here double-frees.
 *
 * A NULL request is ignored.  For a non-NULL request, `struct_size` describes
 * a versioned prefix: every owned field fully inside that prefix is released,
 * and fields beyond it are untouched.  Where an options struct carries its own
 * `struct_size`, both the outer and nested prefixes have to reach a field
 * before it is released.
 */

/* Copy only the bytes the caller actually has.
 *
 * `moved = *request` would read `sizeof(this build's type)` from an object the
 * caller may have allocated SHORTER -- which is the whole premise the prefix
 * gates below rest on. That overread is a stack-buffer-overflow abort under an
 * ASan-instrumented host, and it happens before any gate can prevent it.
 *
 * The tail beyond the caller's prefix is zeroed, so the gates see absent
 * fields as absent rather than as whatever was next in memory. */
static void ovc_pval_copy_prefix(void *destination,
                                 const void *source,
                                 size_t destination_size,
                                 size_t source_size)
{
    size_t copied;

    memset(destination, 0, destination_size);
    copied = source_size < destination_size ? source_size : destination_size;
    memcpy(destination, source, copied);
}

/* Whether a caller's `struct_size` reaches a given field.
 *
 * `struct_size` describes a PREFIX, not a version number: a field that fits
 * entirely inside it is present and owned, and anything past it does not
 * exist. Gating all-or-nothing on `struct_size < sizeof(*request)` and
 * releasing nothing therefore leaks the WHOLE prefix in the ordinary skew
 * direction -- a plugin built against a newer header than the host that loaded
 * it, which is the case a versioned prefix exists to support. On a
 * credential-bearing request that is a silent total leak of the bundle.
 *
 * So each owned field is released on its own terms. A field the caller's
 * prefix does not reach is not skipped defensively; it is not there. */
#define OVC_PVAL_HAS(request, type, field)                                     \
    ((request)->struct_size >=                                                 \
     offsetof(type, field) + sizeof(((type *)0)->field))

/* The same question for a nested options struct, which carries its own prefix
 * length. Both prefixes have to reach the SPECIFIC field. Requiring the outer
 * prefix to contain the newest complete `options` struct would still leak an
 * earlier field from an older request whose allocation ends before a later
 * option. Reaching any option field also reaches the nested `struct_size`,
 * which is its first member, so reading that prefix length is safe. */
#define OVC_PVAL_OPT_HAS(request, type, opt_type, field)                       \
    ((request)->struct_size >=                                                 \
         offsetof(type, options) + offsetof(opt_type, field)                   \
             + sizeof(((opt_type *)0)->field)                                  \
     &&                                                                        \
     (request)->options.struct_size >=                                         \
         offsetof(opt_type, field) + sizeof(((opt_type *)0)->field))

void ovstorage_plugin_stat_request_release(
    const OvStoragePlugin_StatRequest *request)
{
    OvStoragePlugin_StatRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_StatRequest, address)) {
        ovc_pval_str_clear(&moved.address);
    }
}

void ovstorage_plugin_read_request_release(
    const OvStoragePlugin_ReadRequest *request)
{
    OvStoragePlugin_ReadRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_ReadRequest, address)) {
        ovc_pval_str_clear(&moved.address);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_ReadRequest,
                         OvStoragePlugin_ReadOptions,
                         if_match)) {
        ovc_pval_opt_str_clear(&moved.options.if_match);
    }
}

void ovstorage_plugin_write_request_release(
    const OvStoragePlugin_WriteRequest *request)
{
    OvStoragePlugin_WriteRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_WriteRequest, address)) {
        ovc_pval_str_clear(&moved.address);
    }
    if (OVC_PVAL_HAS(request, OvStoragePlugin_WriteRequest, body)) {
        ovstorage_plugin_body_free(&moved.body);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_WriteRequest,
                         OvStoragePlugin_WriteOptions,
                         if_dest)
        && moved.options.if_dest.tag == OvStoragePlugin_IfDestExistsTag_MatchEtag) {
        ovc_pval_str_clear(&moved.options.if_dest.match_etag.etag);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_WriteRequest,
                         OvStoragePlugin_WriteOptions,
                         user_metadata)
        && moved.options.user_metadata.present) {
        ovc_pval_key_values_clear(&moved.options.user_metadata.value);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_WriteRequest,
                         OvStoragePlugin_WriteOptions,
                         message)) {
        ovc_pval_opt_str_clear(&moved.options.message);
    }
}

void ovstorage_plugin_list_request_release(
    const OvStoragePlugin_ListRequest *request)
{
    OvStoragePlugin_ListRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_ListRequest, prefix)) {
        ovc_pval_str_clear(&moved.prefix);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_ListRequest,
                         OvStoragePlugin_ListOptions,
                         page_token)) {
        ovc_pval_opt_str_clear(&moved.options.page_token);
    }
}

void ovstorage_plugin_delete_request_release(
    const OvStoragePlugin_DeleteRequest *request)
{
    OvStoragePlugin_DeleteRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_DeleteRequest, address)) {
        ovc_pval_str_clear(&moved.address);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_DeleteRequest,
                         OvStoragePlugin_DeleteOptions,
                         if_match)) {
        ovc_pval_opt_str_clear(&moved.options.if_match);
    }
}

void ovstorage_plugin_copy_request_release(
    const OvStoragePlugin_CopyRequest *request)
{
    OvStoragePlugin_CopyRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_CopyRequest, source)) {
        ovc_pval_str_clear(&moved.source);
    }
    if (OVC_PVAL_HAS(request, OvStoragePlugin_CopyRequest, destination)) {
        ovc_pval_str_clear(&moved.destination);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_CopyRequest,
                         OvStoragePlugin_CopyOptions,
                         if_source)) {
        ovc_pval_opt_str_clear(&moved.options.if_source);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_CopyRequest,
                         OvStoragePlugin_CopyOptions,
                         if_dest)
        && moved.options.if_dest.tag ==
               OvStoragePlugin_IfDestExistsTag_MatchEtag) {
        ovc_pval_str_clear(&moved.options.if_dest.match_etag.etag);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_CopyRequest,
                         OvStoragePlugin_CopyOptions,
                         message)) {
        ovc_pval_opt_str_clear(&moved.options.message);
    }
}

void ovstorage_plugin_rename_request_release(
    const OvStoragePlugin_RenameRequest *request)
{
    OvStoragePlugin_RenameRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_RenameRequest, source)) {
        ovc_pval_str_clear(&moved.source);
    }
    if (OVC_PVAL_HAS(request, OvStoragePlugin_RenameRequest, destination)) {
        ovc_pval_str_clear(&moved.destination);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_RenameRequest,
                         OvStoragePlugin_RenameOptions,
                         if_source)) {
        ovc_pval_opt_str_clear(&moved.options.if_source);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_RenameRequest,
                         OvStoragePlugin_RenameOptions,
                         if_dest)
        && moved.options.if_dest.tag ==
               OvStoragePlugin_IfDestExistsTag_MatchEtag) {
        ovc_pval_str_clear(&moved.options.if_dest.match_etag.etag);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_RenameRequest,
                         OvStoragePlugin_RenameOptions,
                         message)) {
        ovc_pval_opt_str_clear(&moved.options.message);
    }
}

void ovstorage_plugin_update_metadata_request_release(
    const OvStoragePlugin_UpdateMetadataRequest *request)
{
    OvStoragePlugin_UpdateMetadataRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_UpdateMetadataRequest, address)) {
        ovc_pval_str_clear(&moved.address);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_UpdateMetadataRequest,
                         OvStoragePlugin_UpdateMetadataOptions,
                         if_match)) {
        ovc_pval_opt_str_clear(&moved.options.if_match);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_UpdateMetadataRequest,
                         OvStoragePlugin_UpdateMetadataOptions,
                         user_metadata_set)) {
        ovc_pval_key_values_clear(&moved.options.user_metadata_set);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_UpdateMetadataRequest,
                         OvStoragePlugin_UpdateMetadataOptions,
                         user_metadata_remove)) {
        ovc_pval_str_list_clear(&moved.options.user_metadata_remove);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_UpdateMetadataRequest,
                         OvStoragePlugin_UpdateMetadataOptions,
                         message)) {
        ovc_pval_opt_str_clear(&moved.options.message);
    }
}

void ovstorage_plugin_check_access_request_release(
    const OvStoragePlugin_CheckAccessRequest *request)
{
    OvStoragePlugin_CheckAccessRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_CheckAccessRequest, address)) {
        ovc_pval_str_clear(&moved.address);
    }
}

void ovstorage_plugin_list_versions_request_release(
    const OvStoragePlugin_ListVersionsRequest *request)
{
    OvStoragePlugin_ListVersionsRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_ListVersionsRequest, address)) {
        ovc_pval_str_clear(&moved.address);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_ListVersionsRequest,
                         OvStoragePlugin_ListVersionsOptions,
                         page_token)) {
        ovc_pval_opt_str_clear(&moved.options.page_token);
    }
}

void ovstorage_plugin_watch_directory_request_release(
    const OvStoragePlugin_WatchDirectoryRequest *request)
{
    OvStoragePlugin_WatchDirectoryRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_WatchDirectoryRequest, prefix)) {
        ovc_pval_str_clear(&moved.prefix);
    }
    if (OVC_PVAL_OPT_HAS(request,
                         OvStoragePlugin_WatchDirectoryRequest,
                         OvStoragePlugin_WatchDirectoryOptions,
                         since) && moved.options.since.present) {
        ovc_pval_bytes_clear(&moved.options.since.value.bytes);
    }
}

void ovstorage_plugin_create_directory_request_release(
    const OvStoragePlugin_CreateDirectoryRequest *request)
{
    OvStoragePlugin_CreateDirectoryRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_CreateDirectoryRequest, address)) {
        ovc_pval_str_clear(&moved.address);
    }
}

void ovstorage_plugin_delete_directory_request_release(
    const OvStoragePlugin_DeleteDirectoryRequest *request)
{
    OvStoragePlugin_DeleteDirectoryRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_DeleteDirectoryRequest, address)) {
        ovc_pval_str_clear(&moved.address);
    }
}

/* `ContinueWriteRequest.results` is the one leaf family the request releases
 * needed that the codec surface did not already carry. */
static void ovc_pval_redirect_result_batch_clear(
    OvStoragePlugin_RedirectResultBatch *batch)
{
    size_t index;

    if (batch == NULL) {
        return;
    }
    if (batch->results.ptr != NULL) {
        for (index = 0; index < batch->results.len; ++index) {
            ovc_pval_key_values_clear(&batch->results.ptr[index].captured_headers);
            ovc_pval_bytes_clear(&batch->results.ptr[index].captured_body);
        }
    }
    ovc_abi_free(batch->results.ptr);
    memset(batch, 0, sizeof(*batch));
}

static void ovc_pval_connection_key_clear(OvStoragePlugin_ConnectionKey *key)
{
    if (key == NULL) {
        return;
    }
    ovc_pval_str_clear(&key->target);
    ovc_pval_str_clear(&key->id);
}

void ovstorage_plugin_root_info_for_request_release(
    const OvStoragePlugin_RootInfoForRequest *request)
{
    OvStoragePlugin_RootInfoForRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_RootInfoForRequest, url)) {
        ovc_pval_str_clear(&moved.url);
    }
}

void ovstorage_plugin_continue_write_request_release(
    const OvStoragePlugin_ContinueWriteRequest *request)
{
    OvStoragePlugin_ContinueWriteRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_ContinueWriteRequest, address)) {
        ovc_pval_str_clear(&moved.address);
    }
    if (OVC_PVAL_HAS(request, OvStoragePlugin_ContinueWriteRequest, redirects)) {
        ovc_pval_write_redirect_batch_clear(&moved.redirects);
    }
    if (OVC_PVAL_HAS(request, OvStoragePlugin_ContinueWriteRequest, results)) {
        ovc_pval_redirect_result_batch_clear(&moved.results);
    }
}

void ovstorage_plugin_layer_connection_request_release(
    const OvStoragePlugin_LayerConnectionRequest *request)
{
    OvStoragePlugin_LayerConnectionRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_LayerConnectionRequest, target)) {
        ovc_pval_str_clear(&moved.target);
    }
    /* Carries the connection's SecretBundle, so this is the release that
     * secret material flows through. The wipe lives in the leaf, not here. */
    if (OVC_PVAL_HAS(request, OvStoragePlugin_LayerConnectionRequest, connection)) {
        ovstorage_plugin_connection_request_free(&moved.connection);
    }
}

void ovstorage_plugin_remove_connection_request_release(
    const OvStoragePlugin_RemoveConnectionRequest *request)
{
    OvStoragePlugin_RemoveConnectionRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_RemoveConnectionRequest, key)) {
        ovc_pval_connection_key_clear(&moved.key);
    }
}

void ovstorage_plugin_update_connection_credentials_request_release(
    const OvStoragePlugin_UpdateConnectionCredentialsRequest *request)
{
    OvStoragePlugin_UpdateConnectionCredentialsRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_UpdateConnectionCredentialsRequest, key)) {
        ovc_pval_connection_key_clear(&moved.key);
    }
    if (OVC_PVAL_HAS(request, OvStoragePlugin_UpdateConnectionCredentialsRequest, credentials)) {
        ovc_pval_secret_bundle_clear(&moved.credentials);
    }
}

void ovstorage_plugin_update_connection_attributes_request_release(
    const OvStoragePlugin_UpdateConnectionAttributesRequest *request)
{
    OvStoragePlugin_UpdateConnectionAttributesRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_UpdateConnectionAttributesRequest, key)) {
        ovc_pval_connection_key_clear(&moved.key);
    }
    /* All four owning members of the patch. `visible` is an Optional<bool>
     * and owns nothing. `AttributePatch` has no `struct_size` of its own, so
     * the outer prefix decides whether the patch is present at all. */
    if (OVC_PVAL_HAS(request,
                     OvStoragePlugin_UpdateConnectionAttributesRequest,
                     patch)) {
        ovc_pval_opt_str_clear(&moved.patch.display_name);
        ovc_pval_opt_str_clear(&moved.patch.access_mode);
        ovc_pval_key_values_clear(&moved.patch.set_user_metadata);
        ovc_pval_str_list_clear(&moved.patch.remove_user_metadata);
    }
}

void ovstorage_plugin_authenticate_request_release(
    const OvStoragePlugin_AuthenticateRequest *request)
{
    OvStoragePlugin_AuthenticateRequest moved;

    if (request == NULL) {
        return;
    }
    ovc_pval_copy_prefix(&moved,
                         request,
                         sizeof(moved),
                         request->struct_size);
    if (OVC_PVAL_HAS(request, OvStoragePlugin_AuthenticateRequest, key)) {
        ovc_pval_connection_key_clear(&moved.key);
    }
}

/* These two own nothing. They exist so a slot author calls a release for
 * every request type without having to know which ones are empty -- and so a
 * later field addition has an obvious home. */
void ovstorage_plugin_list_address_roots_request_release(
    const OvStoragePlugin_ListAddressRootsRequest *request)
{
    (void)request;
}

void ovstorage_plugin_list_connections_request_release(
    const OvStoragePlugin_ListConnectionsRequest *request)
{
    (void)request;
}
