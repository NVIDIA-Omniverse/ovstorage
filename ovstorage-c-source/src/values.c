/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Owned value handles and allocation-free value accessors.
 */

#include "internal.h"

#include <stdlib.h>
#include <string.h>

static const char OVC_OUT_OF_MEMORY[] = "out of memory";

static char *ovc_string_duplicate(const char *value)
{
    size_t length;
    char *copy;

    length = strlen(value);
    if (length == SIZE_MAX) {
        return NULL;
    }
    copy = (char *)malloc(length + 1);
    if (copy != NULL) {
        memcpy(copy, value, length + 1);
    }
    return copy;
}

static bool ovc_string_is_utf8(const char *value)
{
    return value != NULL && ovc_utf8_is_valid(value, strlen(value));
}

static void ovc_error_set(OvStorage_Error *error,
                          OvStorage_Status code,
                          const char *message)
{
    if (error == NULL) {
        return;
    }
    ovstorage_error_clear(error);
    error->code = code;
    error->message = ovc_string_duplicate(message);
    error->code_name = ovc_status_code_name(code);
}

static OvStorage_Status ovc_invalid_argument(OvStorage_Error *error,
                                             const char *message)
{
    ovc_error_set(error, OvStorage_Status_InvalidArgument, message);
    return OvStorage_Status_InvalidArgument;
}

static OvStorage_Status ovc_allocation_failed(OvStorage_Error *error)
{
    ovc_error_set(error, OvStorage_Status_Internal, OVC_OUT_OF_MEMORY);
    return OvStorage_Status_Internal;
}

static void ovc_metadata_destroy(const ovc_metadata_entry *entries,
                                 size_t length)
{
    size_t index;

    if (entries == NULL) {
        return;
    }
    for (index = 0; index < length; ++index) {
        free((void *)entries[index].key);
        free((void *)entries[index].value);
    }
    free((void *)entries);
}

static bool ovc_metadata_clone(const ovc_metadata_entry *source,
                               size_t length,
                               ovc_metadata_entry **out)
{
    ovc_metadata_entry *copy;
    size_t index;

    *out = NULL;
    if (length == 0) {
        return true;
    }
    if (source == NULL || length > SIZE_MAX / sizeof(*copy)) {
        return false;
    }
    copy = (ovc_metadata_entry *)calloc(length, sizeof(*copy));
    if (copy == NULL) {
        return false;
    }
    for (index = 0; index < length; ++index) {
        copy[index].key = ovc_string_duplicate(source[index].key);
        copy[index].value = ovc_string_duplicate(source[index].value);
        if (copy[index].key == NULL || copy[index].value == NULL) {
            ovc_metadata_destroy(copy, length);
            return false;
        }
    }
    *out = copy;
    return true;
}

static bool ovc_set_entries_reserve(OvStorage_UpdateMetadataOptions *options)
{
    size_t capacity;
    ovc_metadata_entry *entries;

    if (options->set_len < options->set_capacity) {
        return true;
    }
    capacity = options->set_capacity == 0 ? 4 : options->set_capacity * 2;
    if (capacity < options->set_capacity ||
        capacity > SIZE_MAX / sizeof(*entries)) {
        return false;
    }
    entries = (ovc_metadata_entry *)realloc(
        options->set_entries, capacity * sizeof(*entries));
    if (entries == NULL) {
        return false;
    }
    options->set_entries = entries;
    options->set_capacity = capacity;
    return true;
}

static bool ovc_remove_keys_reserve(OvStorage_UpdateMetadataOptions *options)
{
    size_t capacity;
    char **keys;

    if (options->remove_len < options->remove_capacity) {
        return true;
    }
    capacity = options->remove_capacity == 0 ? 4 : options->remove_capacity * 2;
    if (capacity < options->remove_capacity ||
        capacity > SIZE_MAX / sizeof(*keys)) {
        return false;
    }
    keys = (char **)realloc(options->remove_keys,
                           capacity * sizeof(*keys));
    if (keys == NULL) {
        return false;
    }
    options->remove_keys = keys;
    options->remove_capacity = capacity;
    return true;
}

static const char *ovc_kind_descriptor_field(
    const OvStorage_KindDescriptorList *list,
    size_t index,
    size_t *out_len,
    bool display_name)
{
    const ovc_string_slice *field;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (list == NULL || list->items == NULL || index >= list->len) {
        return NULL;
    }
    field = display_name ? &list->items[index].display_name
                         : &list->items[index].kind;
    if (field->ptr == NULL || memchr(field->ptr, '\0', field->len) != NULL) {
        return NULL;
    }
    if (out_len != NULL) {
        *out_len = field->len;
    }
    return field->ptr;
}

void ovstorage_error_clear(OvStorage_Error *error)
{
    if (error == NULL) {
        return;
    }
    free(error->message);
    error->code = OvStorage_Status_Ok;
    error->message = NULL;
    /* Static string owned by the implementation — reset, never freed. */
    error->code_name = NULL;
}

const char *ovstorage_error_message(const OvStorage_Error *error)
{
    return error == NULL ? NULL : error->message;
}

const char *ovstorage_error_code_name(const OvStorage_Error *error)
{
    return error == NULL ? NULL : error->code_name;
}

bool ovstorage_status_is_retryable(OvStorage_Status status)
{
    return status == OvStorage_Status_Transient ||
           status == OvStorage_Status_ResourceExhausted;
}

/*
 * Status/error taxonomy tables (see internal.h).
 *
 * Kept in the declaration order of the enums they map, so a newly added
 * code shows up as an obvious gap rather than an appended special case.
 */

OvStorage_Status ovc_status_from_plugin_code(OvStoragePlugin_ErrorCode code)
{
    switch (code) {
    /* Codes with an exact, finer-than-bucket status. */
    case OvStoragePlugin_ErrorCode_NotFound:
        return OvStorage_Status_NotFound;
    case OvStoragePlugin_ErrorCode_AlreadyExists:
        return OvStorage_Status_AlreadyExists;
    case OvStoragePlugin_ErrorCode_PermissionDenied:
        return OvStorage_Status_PermissionDenied;
    case OvStoragePlugin_ErrorCode_PreconditionFailed:
        return OvStorage_Status_PreconditionFailed;
    case OvStoragePlugin_ErrorCode_Conflict:
        return OvStorage_Status_Conflict;
    case OvStoragePlugin_ErrorCode_DirectoryNotEmpty:
        return OvStorage_Status_DirectoryNotEmpty;
    case OvStoragePlugin_ErrorCode_Unsupported:
        return OvStorage_Status_Unsupported;
    case OvStoragePlugin_ErrorCode_InvalidArgument:
        return OvStorage_Status_InvalidArgument;
    case OvStoragePlugin_ErrorCode_ObjectModified:
        return OvStorage_Status_ObjectModified;
    case OvStoragePlugin_ErrorCode_NoRoute:
        return OvStorage_Status_NoRoute;
    case OvStoragePlugin_ErrorCode_Transient:
        return OvStorage_Status_Transient;
    case OvStoragePlugin_ErrorCode_Cancelled:
        return OvStorage_Status_Cancelled;
    case OvStoragePlugin_ErrorCode_IncompatibleType:
        return OvStorage_Status_IncompatibleType;
    /* ErrorBucket::NotFound — absent object / route / configuration. */
    case OvStoragePlugin_ErrorCode_NotConfigured:
        return OvStorage_Status_NotFound;
    /* The host's own refusal to use a plugin, not a backend's answer
     * about an object: the remedy is a configuration change, so it does
     * not fold onto PermissionDenied. */
    case OvStoragePlugin_ErrorCode_PluginRejected:
        return OvStorage_Status_PluginRejected;
    /* ErrorBucket::Permission — authn/authz failures (folded). */
    case OvStoragePlugin_ErrorCode_CredentialExpired:
    case OvStoragePlugin_ErrorCode_CredentialUnavailable:
    case OvStoragePlugin_ErrorCode_AuthRequired:
    case OvStoragePlugin_ErrorCode_AuthCancelled:
    case OvStoragePlugin_ErrorCode_AuthExpired:
        return OvStorage_Status_PermissionDenied;
    /* ErrorBucket::Precondition — server/object state not met. */
    case OvStoragePlugin_ErrorCode_Locked:
    case OvStoragePlugin_ErrorCode_RouteConflict:
    case OvStoragePlugin_ErrorCode_PolicyEpochStale:
    case OvStoragePlugin_ErrorCode_RedirectExpired:
    case OvStoragePlugin_ErrorCode_StagingExpired:
    case OvStoragePlugin_ErrorCode_BrokerRequired:
    case OvStoragePlugin_ErrorCode_StateRootUnavailable:
    case OvStoragePlugin_ErrorCode_ContentMismatch:
    case OvStoragePlugin_ErrorCode_ContentChecksumMismatch:
        return OvStorage_Status_PreconditionFailed;
    /* ErrorBucket::Invalid — malformed / semantically invalid request. */
    case OvStoragePlugin_ErrorCode_AliasChainTooLong:
        return OvStorage_Status_InvalidArgument;
    /* ErrorBucket::Transient — retryable transient failures. */
    case OvStoragePlugin_ErrorCode_BrokerUnavailable:
    case OvStoragePlugin_ErrorCode_DeadlineExceeded:
    case OvStoragePlugin_ErrorCode_CacheLockContention:
    case OvStoragePlugin_ErrorCode_AuthorizationLeaseExpired:
        return OvStorage_Status_Transient;
    /* ErrorBucket::ResourceExhausted — retryable quota / capacity. */
    case OvStoragePlugin_ErrorCode_ResourceExhausted:
        return OvStorage_Status_ResourceExhausted;
    /* Committed one stage, failed a later one. Bucket is Internal, but it
     * gets its own status: collapsing it onto Internal would hide from a C
     * host that part of the operation is durable, which is the one fact
     * that decides whether retrying or rolling back is safe. */
    case OvStoragePlugin_ErrorCode_PartialCompletion:
        return OvStorage_Status_PartialCompletion;
    /* ErrorBucket::Internal — server-side, not blindly retryable. */
    case OvStoragePlugin_ErrorCode_Internal:
    case OvStoragePlugin_ErrorCode_IntegrityFailure:
    case OvStoragePlugin_ErrorCode_CacheCorrupt:
    case OvStoragePlugin_ErrorCode_CommitAmbiguous:
    case OvStoragePlugin_ErrorCode_NetworkFilesystemRefused:
        return OvStorage_Status_Internal;
    default:
        /* A code minted by a newer plugin ABI: Internal-equivalent per
         * the unknown-code forward-compat rule. */
        return OvStorage_Status_Internal;
    }
}

const char *ovc_plugin_error_code_name(OvStoragePlugin_ErrorCode code)
{
    switch (code) {
    case OvStoragePlugin_ErrorCode_NotFound:
        return "NotFound";
    case OvStoragePlugin_ErrorCode_AlreadyExists:
        return "AlreadyExists";
    case OvStoragePlugin_ErrorCode_PermissionDenied:
        return "PermissionDenied";
    case OvStoragePlugin_ErrorCode_PreconditionFailed:
        return "PreconditionFailed";
    case OvStoragePlugin_ErrorCode_Conflict:
        return "Conflict";
    case OvStoragePlugin_ErrorCode_DirectoryNotEmpty:
        return "DirectoryNotEmpty";
    case OvStoragePlugin_ErrorCode_Unsupported:
        return "Unsupported";
    case OvStoragePlugin_ErrorCode_InvalidArgument:
        return "InvalidArgument";
    case OvStoragePlugin_ErrorCode_IncompatibleType:
        return "IncompatibleType";
    case OvStoragePlugin_ErrorCode_Locked:
        return "Locked";
    case OvStoragePlugin_ErrorCode_Cancelled:
        return "Cancelled";
    case OvStoragePlugin_ErrorCode_DeadlineExceeded:
        return "DeadlineExceeded";
    case OvStoragePlugin_ErrorCode_Transient:
        return "Transient";
    case OvStoragePlugin_ErrorCode_ResourceExhausted:
        return "ResourceExhausted";
    case OvStoragePlugin_ErrorCode_IntegrityFailure:
        return "IntegrityFailure";
    case OvStoragePlugin_ErrorCode_Internal:
        return "Internal";
    case OvStoragePlugin_ErrorCode_BrokerUnavailable:
        return "BrokerUnavailable";
    case OvStoragePlugin_ErrorCode_BrokerRequired:
        return "BrokerRequired";
    case OvStoragePlugin_ErrorCode_RedirectExpired:
        return "RedirectExpired";
    case OvStoragePlugin_ErrorCode_PolicyEpochStale:
        return "PolicyEpochStale";
    case OvStoragePlugin_ErrorCode_AuthorizationLeaseExpired:
        return "AuthorizationLeaseExpired";
    case OvStoragePlugin_ErrorCode_CacheCorrupt:
        return "CacheCorrupt";
    case OvStoragePlugin_ErrorCode_StagingExpired:
        return "StagingExpired";
    case OvStoragePlugin_ErrorCode_CommitAmbiguous:
        return "CommitAmbiguous";
    case OvStoragePlugin_ErrorCode_CacheLockContention:
        return "CacheLockContention";
    case OvStoragePlugin_ErrorCode_StateRootUnavailable:
        return "StateRootUnavailable";
    case OvStoragePlugin_ErrorCode_NetworkFilesystemRefused:
        return "NetworkFilesystemRefused";
    case OvStoragePlugin_ErrorCode_ObjectModified:
        return "ObjectModified";
    case OvStoragePlugin_ErrorCode_NoRoute:
        return "NoRoute";
    case OvStoragePlugin_ErrorCode_RouteConflict:
        return "RouteConflict";
    case OvStoragePlugin_ErrorCode_NotConfigured:
        return "NotConfigured";
    case OvStoragePlugin_ErrorCode_AliasChainTooLong:
        return "AliasChainTooLong";
    case OvStoragePlugin_ErrorCode_CredentialExpired:
        return "CredentialExpired";
    case OvStoragePlugin_ErrorCode_CredentialUnavailable:
        return "CredentialUnavailable";
    case OvStoragePlugin_ErrorCode_AuthRequired:
        return "AuthRequired";
    case OvStoragePlugin_ErrorCode_AuthCancelled:
        return "AuthCancelled";
    case OvStoragePlugin_ErrorCode_AuthExpired:
        return "AuthExpired";
    case OvStoragePlugin_ErrorCode_ContentMismatch:
        return "ContentMismatch";
    case OvStoragePlugin_ErrorCode_ContentChecksumMismatch:
        return "ContentChecksumMismatch";
    case OvStoragePlugin_ErrorCode_PluginRejected:
        return "PluginRejected";
    case OvStoragePlugin_ErrorCode_PartialCompletion:
        return "PartialCompletion";
    default:
        return "Internal";
    }
}

const char *ovc_status_code_name(OvStorage_Status status)
{
    switch (status) {
    case OvStorage_Status_Ok:
        return NULL;
    case OvStorage_Status_NotFound:
        return "NotFound";
    case OvStorage_Status_AlreadyExists:
        return "AlreadyExists";
    case OvStorage_Status_PermissionDenied:
        return "PermissionDenied";
    case OvStorage_Status_PreconditionFailed:
        return "PreconditionFailed";
    case OvStorage_Status_Conflict:
        return "Conflict";
    case OvStorage_Status_DirectoryNotEmpty:
        return "DirectoryNotEmpty";
    case OvStorage_Status_Unsupported:
        return "Unsupported";
    case OvStorage_Status_InvalidArgument:
        return "InvalidArgument";
    case OvStorage_Status_ObjectModified:
        return "ObjectModified";
    case OvStorage_Status_NoRoute:
        return "NoRoute";
    case OvStorage_Status_Transient:
        return "Transient";
    case OvStorage_Status_Cancelled:
        return "Cancelled";
    case OvStorage_Status_IncompatibleType:
        return "IncompatibleType";
    case OvStorage_Status_ResourceExhausted:
        return "ResourceExhausted";
    case OvStorage_Status_PartialCompletion:
        return "PartialCompletion";
    case OvStorage_Status_PluginRejected:
        return "PluginRejected";
    case OvStorage_Status_Internal:
        return "Internal";
    default:
        return NULL;
    }
}

void ovstorage_bytes_destroy(OvStorage_Bytes *bytes)
{
    if (bytes == NULL) {
        return;
    }
    free(bytes->free_ctx);
    bytes->data = NULL;
    bytes->len = 0;
    bytes->free_ctx = NULL;
}

void ovstorage_access_decision_clear(OvStorage_AccessDecision *decision)
{
    if (decision == NULL) {
        return;
    }
    free(decision->reason);
    decision->reason = NULL;
}

OvStorage_ConfigValue *ovstorage_config_value_create_bool(bool value)
{
    OvStorage_ConfigValue *result;

    result = (OvStorage_ConfigValue *)malloc(sizeof(*result));
    if (result == NULL) {
        return NULL;
    }
    result->kind = OvStorage_ConfigValueKind_Bool;
    result->payload.boolean = value;
    return result;
}

OvStorage_ConfigValue *ovstorage_config_value_create_int(int64_t value)
{
    OvStorage_ConfigValue *result;

    result = (OvStorage_ConfigValue *)malloc(sizeof(*result));
    if (result == NULL) {
        return NULL;
    }
    result->kind = OvStorage_ConfigValueKind_Int;
    result->payload.integer = value;
    return result;
}

static OvStorage_ConfigValue *ovc_config_value_create_string(
    OvStorage_ConfigValueKind kind,
    const char *value)
{
    OvStorage_ConfigValue *result;
    char *copy;

    if (value == NULL || !ovc_string_is_utf8(value)) {
        return NULL;
    }
    copy = ovc_string_duplicate(value);
    if (copy == NULL) {
        return NULL;
    }
    result = (OvStorage_ConfigValue *)malloc(sizeof(*result));
    if (result == NULL) {
        free(copy);
        return NULL;
    }
    result->kind = kind;
    result->payload.string = copy;
    return result;
}

OvStorage_ConfigValue *ovstorage_config_value_create_string(const char *value)
{
    return ovc_config_value_create_string(OvStorage_ConfigValueKind_String,
                                          value);
}

OvStorage_ConfigValue *ovstorage_config_value_create_toml(const char *toml)
{
    return ovc_config_value_create_string(OvStorage_ConfigValueKind_Toml,
                                          toml);
}

bool ovstorage_config_value_as_bool(const OvStorage_ConfigValue *value)
{
    if (value == NULL || value->kind != OvStorage_ConfigValueKind_Bool) {
        return false;
    }
    return value->payload.boolean;
}

int64_t ovstorage_config_value_as_int(const OvStorage_ConfigValue *value)
{
    if (value == NULL || value->kind != OvStorage_ConfigValueKind_Int) {
        return 0;
    }
    return value->payload.integer;
}

const char *ovstorage_config_value_as_string(
    const OvStorage_ConfigValue *value)
{
    if (value == NULL || value->kind != OvStorage_ConfigValueKind_String) {
        return NULL;
    }
    return value->payload.string;
}

const char *ovstorage_config_value_as_toml(
    const OvStorage_ConfigValue *value)
{
    if (value == NULL || value->kind != OvStorage_ConfigValueKind_Toml) {
        return NULL;
    }
    return value->payload.string;
}

OvStorage_ConfigValueKind ovstorage_config_value_kind(
    const OvStorage_ConfigValue *value)
{
    return value == NULL ? OvStorage_ConfigValueKind_String : value->kind;
}

void ovstorage_config_value_destroy(OvStorage_ConfigValue *value)
{
    if (value == NULL) {
        return;
    }
    if (value->kind == OvStorage_ConfigValueKind_String ||
        value->kind == OvStorage_ConfigValueKind_Toml) {
        free(value->payload.string);
    }
    free(value);
}

OvStorage_UpdateMetadataOptions *ovstorage_update_metadata_options_create(void)
{
    return (OvStorage_UpdateMetadataOptions *)calloc(
        1, sizeof(OvStorage_UpdateMetadataOptions));
}

void ovstorage_update_metadata_options_destroy(
    OvStorage_UpdateMetadataOptions *options)
{
    size_t index;

    if (options == NULL) {
        return;
    }
    ovc_metadata_destroy(options->set_entries, options->set_len);
    for (index = 0; index < options->remove_len; ++index) {
        free(options->remove_keys[index]);
    }
    free(options->remove_keys);
    free(options);
}

OvStorage_Status ovstorage_update_metadata_options_set(
    OvStorage_UpdateMetadataOptions *options,
    const char *key,
    const char *value,
    OvStorage_Error *out_error)
{
    char *key_copy;
    char *value_copy;

    if (options == NULL) {
        return ovc_invalid_argument(out_error, "options must not be null");
    }
    if (key == NULL) {
        return ovc_invalid_argument(out_error, "key must not be null");
    }
    if (!ovc_string_is_utf8(key)) {
        return ovc_invalid_argument(out_error, "key is not UTF-8");
    }
    if (value == NULL) {
        return ovc_invalid_argument(out_error, "value must not be null");
    }
    if (!ovc_string_is_utf8(value)) {
        return ovc_invalid_argument(out_error, "value is not UTF-8");
    }

    key_copy = ovc_string_duplicate(key);
    if (key_copy == NULL) {
        return ovc_allocation_failed(out_error);
    }
    value_copy = ovc_string_duplicate(value);
    if (value_copy == NULL) {
        free(key_copy);
        return ovc_allocation_failed(out_error);
    }
    if (!ovc_set_entries_reserve(options)) {
        free(key_copy);
        free(value_copy);
        return ovc_allocation_failed(out_error);
    }
    options->set_entries[options->set_len].key = key_copy;
    options->set_entries[options->set_len].value = value_copy;
    ++options->set_len;
    ovstorage_error_clear(out_error);
    return OvStorage_Status_Ok;
}

OvStorage_Status ovstorage_update_metadata_options_remove(
    OvStorage_UpdateMetadataOptions *options,
    const char *key,
    OvStorage_Error *out_error)
{
    char *key_copy;

    if (options == NULL) {
        return ovc_invalid_argument(out_error, "options must not be null");
    }
    if (key == NULL) {
        return ovc_invalid_argument(out_error, "key must not be null");
    }
    if (!ovc_string_is_utf8(key)) {
        return ovc_invalid_argument(out_error, "key is not UTF-8");
    }
    key_copy = ovc_string_duplicate(key);
    if (key_copy == NULL) {
        return ovc_allocation_failed(out_error);
    }
    if (!ovc_remove_keys_reserve(options)) {
        free(key_copy);
        return ovc_allocation_failed(out_error);
    }
    options->remove_keys[options->remove_len] = key_copy;
    ++options->remove_len;
    ovstorage_error_clear(out_error);
    return OvStorage_Status_Ok;
}

void ovc_checksums_destroy(const OvStorage_ChecksumEntry *entries,
                          size_t length)
{
    size_t index;

    if (entries == NULL) {
        return;
    }
    for (index = 0; index < length; ++index) {
        free((void *)entries[index].algorithm);
        free((void *)entries[index].bytes);
    }
    free((void *)entries);
}

static bool ovc_checksums_clone(const OvStorage_ChecksumEntry *source,
                                size_t length,
                                OvStorage_ChecksumEntry **out)
{
    OvStorage_ChecksumEntry *copy;
    uint8_t *bytes;
    size_t index;

    *out = NULL;
    if (length == 0) {
        return true;
    }
    if (source == NULL || length > SIZE_MAX / sizeof(*copy)) {
        return false;
    }
    copy = (OvStorage_ChecksumEntry *)calloc(length, sizeof(*copy));
    if (copy == NULL) {
        return false;
    }
    for (index = 0; index < length; ++index) {
        copy[index].algorithm =
            source[index].algorithm == NULL
                ? NULL
                : ovc_string_duplicate(source[index].algorithm);
        if (source[index].algorithm != NULL &&
            copy[index].algorithm == NULL) {
            ovc_checksums_destroy(copy, index + 1);
            return false;
        }
        copy[index].bytes_len = source[index].bytes_len;
        if (source[index].bytes_len != 0) {
            bytes = (uint8_t *)malloc(source[index].bytes_len);
            if (bytes == NULL) {
                ovc_checksums_destroy(copy, index + 1);
                return false;
            }
            memcpy(bytes, source[index].bytes, source[index].bytes_len);
            copy[index].bytes = bytes;
        }
    }
    *out = copy;
    return true;
}

void ovc_info_clear(OvStorage_Info *info)
{
    if (info == NULL) {
        return;
    }
    free((void *)info->address);
    free((void *)info->etag);
    free((void *)info->version);
    free((void *)info->modified_by);
    ovc_metadata_destroy(info->user_metadata, info->user_metadata_len);
    ovc_metadata_destroy(info->system_metadata, info->system_metadata_len);
    ovc_checksums_destroy(info->checksums, info->checksums_len);
    memset(info, 0, sizeof(*info));
}

void ovstorage_info_destroy(OvStorage_Info *info)
{
    if (info == NULL) {
        return;
    }
    ovc_info_clear(info);
    free(info);
}

OvStorage_Info *ovstorage_info_clone(const OvStorage_Info *info)
{
    OvStorage_Info *copy;
    ovc_metadata_entry *user_metadata;
    ovc_metadata_entry *system_metadata;
    OvStorage_ChecksumEntry *checksums;

    if (info == NULL) {
        return NULL;
    }
    copy = (OvStorage_Info *)calloc(1, sizeof(*copy));
    if (copy == NULL) {
        return NULL;
    }
    copy->kind = info->kind;
    copy->has_size = info->has_size;
    copy->size = info->size;
    copy->has_mtime_unix_nanos = info->has_mtime_unix_nanos;
    copy->mtime_unix_nanos = info->mtime_unix_nanos;
    copy->user_metadata_len = info->user_metadata_len;
    copy->system_metadata_len = info->system_metadata_len;
    copy->has_effective_permissions = info->has_effective_permissions;
    copy->effective_permissions = info->effective_permissions;
    copy->address =
        info->address == NULL ? NULL : ovc_string_duplicate(info->address);
    copy->etag = info->etag == NULL ? NULL : ovc_string_duplicate(info->etag);
    copy->version =
        info->version == NULL ? NULL : ovc_string_duplicate(info->version);
    copy->modified_by = info->modified_by == NULL
                            ? NULL
                            : ovc_string_duplicate(info->modified_by);
    if ((info->address != NULL && copy->address == NULL) ||
        (info->etag != NULL && copy->etag == NULL) ||
        (info->version != NULL && copy->version == NULL) ||
        (info->modified_by != NULL && copy->modified_by == NULL)) {
        ovstorage_info_destroy(copy);
        return NULL;
    }
    if (!ovc_metadata_clone(
            info->user_metadata, info->user_metadata_len, &user_metadata)) {
        ovstorage_info_destroy(copy);
        return NULL;
    }
    copy->user_metadata = user_metadata;
    if (!ovc_metadata_clone(info->system_metadata,
                            info->system_metadata_len,
                            &system_metadata)) {
        ovstorage_info_destroy(copy);
        return NULL;
    }
    copy->system_metadata = system_metadata;
    if (!ovc_checksums_clone(
            info->checksums, info->checksums_len, &checksums)) {
        ovstorage_info_destroy(copy);
        return NULL;
    }
    copy->checksums = checksums;
    copy->checksums_len = info->checksums_len;
    return copy;
}

void ovstorage_list_destroy(OvStorage_List *list)
{
    OvStorage_Info *items;
    size_t index;

    if (list == NULL) {
        return;
    }
    items = (OvStorage_Info *)(void *)list->items;
    if (items != NULL) {
        for (index = 0; index < list->len; ++index) {
            ovc_info_clear(&items[index]);
        }
    }
    free(items);
    free((void *)list->next_page_token);
    free(list);
}

void ovstorage_version_list_destroy(OvStorage_VersionList *list)
{
    OvStorage_Info *items;
    size_t index;

    if (list == NULL) {
        return;
    }
    items = (OvStorage_Info *)(void *)list->items;
    if (items != NULL) {
        for (index = 0; index < list->len; ++index) {
            ovc_info_clear(&items[index]);
        }
    }
    free(items);
    free((void *)list->next_page_token);
    free(list);
}

void ovstorage_local_delegate_destroy(OvStorage_LocalDelegate *delegate)
{
    if (delegate == NULL) {
        return;
    }
    if (delegate->release != NULL) {
        delegate->release(delegate->release_context);
    }
    ovstorage_info_destroy(delegate->info);
    free(delegate->path);
    free(delegate);
}

const OvStorage_Info *ovstorage_local_delegate_info(
    const OvStorage_LocalDelegate *delegate)
{
    return delegate == NULL ? NULL : delegate->info;
}

const char *ovstorage_local_delegate_path(
    const OvStorage_LocalDelegate *delegate)
{
    return delegate == NULL ? NULL : delegate->path;
}

void ovstorage_kind_descriptor_list_destroy(
    OvStorage_KindDescriptorList *list)
{
    if (list == NULL) {
        return;
    }
    free(list->items);
    free(list->string_storage);
    free(list);
}

const char *ovstorage_kind_descriptor_list_item_display_name(
    const OvStorage_KindDescriptorList *list,
    size_t index,
    size_t *out_len)
{
    return ovc_kind_descriptor_field(list, index, out_len, true);
}

const char *ovstorage_kind_descriptor_list_item_kind(
    const OvStorage_KindDescriptorList *list,
    size_t index,
    size_t *out_len)
{
    return ovc_kind_descriptor_field(list, index, out_len, false);
}

int32_t ovstorage_kind_descriptor_list_item_layer_type(
    const OvStorage_KindDescriptorList *list,
    size_t index)
{
    if (list == NULL || list->items == NULL || index >= list->len) {
        return -1;
    }
    return list->items[index].layer_type;
}

size_t ovstorage_kind_descriptor_list_len(
    const OvStorage_KindDescriptorList *list)
{
    return list == NULL ? 0 : list->len;
}
