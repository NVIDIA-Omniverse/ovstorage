/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Connection, authentication, secret, and root-info value handles.
 */

#include "internal.h"

#include <stdlib.h>
#include <string.h>

static char *ovc_conn_string_duplicate(const char *value)
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

static bool ovc_conn_string_is_utf8(const char *value)
{
    return value != NULL && ovc_utf8_is_valid(value, strlen(value));
}

static bool ovc_config_entries_reserve(OvStorage_ConnectionRequest *request)
{
    size_t capacity;
    ovc_config_entry *entries;

    if (request->config_len < request->config_capacity) {
        return true;
    }
    capacity = request->config_capacity == 0
                   ? 4
                   : request->config_capacity * 2;
    if (capacity < request->config_capacity ||
        capacity > SIZE_MAX / sizeof(*entries)) {
        return false;
    }
    entries = (ovc_config_entry *)realloc(request->config,
                                          capacity * sizeof(*entries));
    if (entries == NULL) {
        return false;
    }
    request->config = entries;
    request->config_capacity = capacity;
    return true;
}

static bool ovc_secret_entries_reserve(OvStorage_SecretBundle *bundle)
{
    size_t capacity;
    ovc_secret_entry *entries;

    if (bundle->len < bundle->capacity) {
        return true;
    }
    capacity = bundle->capacity == 0 ? 4 : bundle->capacity * 2;
    if (capacity < bundle->capacity ||
        capacity > SIZE_MAX / sizeof(*entries)) {
        return false;
    }
    entries = (ovc_secret_entry *)realloc(bundle->entries,
                                          capacity * sizeof(*entries));
    if (entries == NULL) {
        return false;
    }
    bundle->entries = entries;
    bundle->capacity = capacity;
    return true;
}

static size_t ovc_config_entry_find(const OvStorage_ConnectionRequest *request,
                                    const char *key)
{
    size_t index;

    for (index = 0; index < request->config_len; ++index) {
        if (strcmp(request->config[index].key, key) == 0) {
            return index;
        }
    }
    return SIZE_MAX;
}

static size_t ovc_secret_entry_find(const OvStorage_SecretBundle *bundle,
                                    const char *key)
{
    size_t index;

    for (index = 0; index < bundle->len; ++index) {
        if (strcmp(bundle->entries[index].key, key) == 0) {
            return index;
        }
    }
    return SIZE_MAX;
}

static bool ovc_secret_bytes_copy(ovc_secret_bytes *out,
                                  const uint8_t *data,
                                  size_t len)
{
    out->data = NULL;
    out->len = 0;
    if (data == NULL || len == 0) {
        return true;
    }
    out->data = (uint8_t *)malloc(len);
    if (out->data == NULL) {
        return false;
    }
    memcpy(out->data, data, len);
    out->len = len;
    return true;
}

static void ovc_secret_bytes_clear(ovc_secret_bytes *bytes)
{
    if (bytes->data != NULL) {
        ovc_secure_zero(bytes->data, bytes->len);
        free(bytes->data);
    }
    bytes->data = NULL;
    bytes->len = 0;
}

static void ovc_secret_bundle_clear(OvStorage_SecretBundle *bundle)
{
    size_t index;

    if (bundle == NULL) {
        return;
    }
    for (index = 0; index < bundle->len; ++index) {
        free(bundle->entries[index].key);
        ovstorage_secret_value_destroy(bundle->entries[index].value);
    }
    free(bundle->entries);
    bundle->entries = NULL;
    bundle->len = 0;
    bundle->capacity = 0;
    bundle->consumed = true;
}

static void ovc_metadata_entries_destroy(const ovc_metadata_entry *entries,
                                         size_t len)
{
    size_t index;

    if (entries == NULL) {
        return;
    }
    for (index = 0; index < len; ++index) {
        free((void *)entries[index].key);
        free((void *)entries[index].value);
    }
    free((void *)entries);
}

static OvStorage_SecretValue *ovc_secret_value_create_bytes_kind(
    ovc_secret_value_kind kind,
    const uint8_t *data,
    size_t len)
{
    OvStorage_SecretValue *value;

    value = (OvStorage_SecretValue *)calloc(1, sizeof(*value));
    if (value == NULL) {
        return NULL;
    }
    value->kind = kind;
    if (!ovc_secret_bytes_copy(&value->payload.bytes, data, len)) {
        free(value);
        return NULL;
    }
    return value;
}

OvStorage_SecretValue *ovstorage_secret_value_create_bytes(
    const uint8_t *data,
    size_t len)
{
    return ovc_secret_value_create_bytes_kind(OVC_SECRET_VALUE_BYTES,
                                              data,
                                              len);
}

OvStorage_SecretValue *ovstorage_secret_value_create_file(
    const uint8_t *data,
    size_t len)
{
    return ovc_secret_value_create_bytes_kind(OVC_SECRET_VALUE_FILE,
                                              data,
                                              len);
}

OvStorage_SecretValue *ovstorage_secret_value_create_oauth_token(
    const uint8_t *token,
    size_t token_len,
    const uint8_t *refresh,
    size_t refresh_len,
    bool has_refresh,
    uint64_t expires_at_unix_nanos,
    bool has_expires_at)
{
    OvStorage_SecretValue *value;

    value = (OvStorage_SecretValue *)calloc(1, sizeof(*value));
    if (value == NULL) {
        return NULL;
    }
    value->kind = OVC_SECRET_VALUE_OAUTH_TOKEN;
    value->payload.oauth_token.has_refresh = has_refresh;
    value->payload.oauth_token.has_expires_at = has_expires_at;
    value->payload.oauth_token.expires_at_unix_nanos =
        has_expires_at ? expires_at_unix_nanos : 0;
    if (!ovc_secret_bytes_copy(&value->payload.oauth_token.token,
                               token,
                               token_len) ||
        (has_refresh &&
         !ovc_secret_bytes_copy(&value->payload.oauth_token.refresh,
                                refresh,
                                refresh_len))) {
        ovstorage_secret_value_destroy(value);
        return NULL;
    }
    return value;
}

OvStorage_SecretValue *ovstorage_secret_value_create_mtls_cert_pair(
    const uint8_t *cert_pem,
    size_t cert_len,
    const uint8_t *key_pem,
    size_t key_len)
{
    OvStorage_SecretValue *value;

    value = (OvStorage_SecretValue *)calloc(1, sizeof(*value));
    if (value == NULL) {
        return NULL;
    }
    value->kind = OVC_SECRET_VALUE_MTLS_CERT_PAIR;
    if (!ovc_secret_bytes_copy(&value->payload.mtls_cert_pair.cert_pem,
                               cert_pem,
                               cert_len) ||
        !ovc_secret_bytes_copy(&value->payload.mtls_cert_pair.key_pem,
                               key_pem,
                               key_len)) {
        ovstorage_secret_value_destroy(value);
        return NULL;
    }
    return value;
}

OvStorage_SecretValue *ovstorage_secret_value_create_system_identity(void)
{
    OvStorage_SecretValue *value;

    value = (OvStorage_SecretValue *)calloc(1, sizeof(*value));
    if (value != NULL) {
        value->kind = OVC_SECRET_VALUE_SYSTEM_IDENTITY;
    }
    return value;
}

void ovstorage_secret_value_destroy(OvStorage_SecretValue *value)
{
    if (value == NULL) {
        return;
    }
    switch (value->kind) {
    case OVC_SECRET_VALUE_BYTES:
    case OVC_SECRET_VALUE_FILE:
        ovc_secret_bytes_clear(&value->payload.bytes);
        break;
    case OVC_SECRET_VALUE_OAUTH_TOKEN:
        ovc_secret_bytes_clear(&value->payload.oauth_token.token);
        ovc_secret_bytes_clear(&value->payload.oauth_token.refresh);
        break;
    case OVC_SECRET_VALUE_MTLS_CERT_PAIR:
        ovc_secret_bytes_clear(&value->payload.mtls_cert_pair.cert_pem);
        ovc_secret_bytes_clear(&value->payload.mtls_cert_pair.key_pem);
        break;
    case OVC_SECRET_VALUE_SYSTEM_IDENTITY:
        break;
    }
    free(value);
}

OvStorage_ConnectionRequest *ovstorage_connection_request_create(
    const char *backend_kind)
{
    OvStorage_ConnectionRequest *request;
    char *kind_copy;

    if (backend_kind == NULL || !ovc_conn_string_is_utf8(backend_kind)) {
        return NULL;
    }
    kind_copy = ovc_conn_string_duplicate(backend_kind);
    if (kind_copy == NULL) {
        return NULL;
    }
    request = (OvStorage_ConnectionRequest *)calloc(1, sizeof(*request));
    if (request == NULL) {
        free(kind_copy);
        return NULL;
    }
    request->backend_kind = kind_copy;
    return request;
}

void ovstorage_connection_request_destroy(OvStorage_ConnectionRequest *request)
{
    size_t index;

    if (request == NULL) {
        return;
    }
    for (index = 0; index < request->config_len; ++index) {
        free(request->config[index].key);
        ovstorage_config_value_destroy(request->config[index].value);
    }
    free(request->config);
    ovc_secret_bundle_clear(&request->credentials);
    free(request->backend_kind);
    free(request->display_name);
    free(request);
}

void ovstorage_connection_request_set_display_name(
    OvStorage_ConnectionRequest *request,
    const char *display_name)
{
    char *copy;

    if (request == NULL || request->consumed) {
        return;
    }
    if (display_name == NULL) {
        free(request->display_name);
        request->display_name = NULL;
        return;
    }
    if (!ovc_conn_string_is_utf8(display_name)) {
        return;
    }
    copy = ovc_conn_string_duplicate(display_name);
    if (copy == NULL) {
        return;
    }
    free(request->display_name);
    request->display_name = copy;
}

void ovstorage_connection_request_set_persist(
    OvStorage_ConnectionRequest *request,
    bool persist)
{
    if (request != NULL && !request->consumed) {
        request->persist = persist;
    }
}

bool ovstorage_connection_request_add_config(
    OvStorage_ConnectionRequest *request,
    const char *key,
    OvStorage_ConfigValue *value)
{
    size_t index;
    char *key_copy;

    if (request == NULL || request->consumed || key == NULL ||
        value == NULL || !ovc_conn_string_is_utf8(key)) {
        return false;
    }
    index = ovc_config_entry_find(request, key);
    if (index != SIZE_MAX) {
        ovstorage_config_value_destroy(request->config[index].value);
        request->config[index].value = value;
        return true;
    }
    key_copy = ovc_conn_string_duplicate(key);
    if (key_copy == NULL) {
        return false;
    }
    if (!ovc_config_entries_reserve(request)) {
        free(key_copy);
        return false;
    }
    request->config[request->config_len].key = key_copy;
    request->config[request->config_len].value = value;
    ++request->config_len;
    return true;
}

bool ovstorage_connection_request_add_credential(
    OvStorage_ConnectionRequest *request,
    const char *key,
    OvStorage_SecretValue *value)
{
    size_t index;
    char *key_copy;
    OvStorage_SecretBundle *credentials;

    if (request == NULL || request->consumed || key == NULL ||
        value == NULL || !ovc_conn_string_is_utf8(key)) {
        return false;
    }
    credentials = &request->credentials;
    index = ovc_secret_entry_find(credentials, key);
    if (index != SIZE_MAX) {
        ovstorage_secret_value_destroy(credentials->entries[index].value);
        credentials->entries[index].value = value;
        return true;
    }
    key_copy = ovc_conn_string_duplicate(key);
    if (key_copy == NULL) {
        return false;
    }
    if (!ovc_secret_entries_reserve(credentials)) {
        free(key_copy);
        return false;
    }
    credentials->entries[credentials->len].key = key_copy;
    credentials->entries[credentials->len].value = value;
    ++credentials->len;
    return true;
}

OvStorage_SecretBundle *ovstorage_secret_bundle_create(void)
{
    return (OvStorage_SecretBundle *)calloc(1,
                                            sizeof(OvStorage_SecretBundle));
}

void ovstorage_secret_bundle_destroy(OvStorage_SecretBundle *bundle)
{
    if (bundle == NULL) {
        return;
    }
    ovc_secret_bundle_clear(bundle);
    free(bundle);
}

bool ovstorage_secret_bundle_add(OvStorage_SecretBundle *bundle,
                                 const char *key,
                                 OvStorage_SecretValue *value)
{
    size_t index;
    char *key_copy;

    if (bundle == NULL || bundle->consumed || key == NULL || value == NULL ||
        !ovc_conn_string_is_utf8(key)) {
        return false;
    }
    index = ovc_secret_entry_find(bundle, key);
    if (index != SIZE_MAX) {
        ovstorage_secret_value_destroy(bundle->entries[index].value);
        bundle->entries[index].value = value;
        return true;
    }
    key_copy = ovc_conn_string_duplicate(key);
    if (key_copy == NULL) {
        return false;
    }
    if (!ovc_secret_entries_reserve(bundle)) {
        free(key_copy);
        return false;
    }
    bundle->entries[bundle->len].key = key_copy;
    bundle->entries[bundle->len].value = value;
    ++bundle->len;
    return true;
}

bool ovc_connection_request_mark_consumed(OvStorage_ConnectionRequest *request)
{
    if (request == NULL || request->consumed) {
        return false;
    }
    request->consumed = true;
    return true;
}

bool ovc_secret_bundle_mark_consumed(OvStorage_SecretBundle *bundle)
{
    if (bundle == NULL || bundle->consumed) {
        return false;
    }
    bundle->consumed = true;
    return true;
}

void ovc_connection_clear(OvStorage_Connection *connection)
{
    size_t index;

    if (connection == NULL) {
        return;
    }
    free((void *)connection->id);
    free((void *)connection->backend_kind);
    free((void *)connection->display_name);
    if (connection->addresses != NULL) {
        for (index = 0; index < connection->addresses_len; ++index) {
            free((void *)connection->addresses[index]);
        }
    }
    free((void *)connection->addresses);
    ovc_metadata_entries_destroy(connection->user_metadata,
                                 connection->user_metadata_len);
    free((void *)connection->source_broker_principal);
    free((void *)connection->auth_failed_message);
    free((void *)connection->awaiting_auth_unknown_details);
    memset(connection, 0, sizeof(*connection));
}

void ovstorage_connection_destroy(OvStorage_Connection *connection)
{
    if (connection == NULL) {
        return;
    }
    ovc_connection_clear(connection);
    free(connection);
}

void ovstorage_connection_list_destroy(OvStorage_ConnectionList *list)
{
    OvStorage_Connection *items;
    size_t index;

    if (list == NULL) {
        return;
    }
    items = (OvStorage_Connection *)(void *)list->items;
    if (items != NULL) {
        for (index = 0; index < list->len; ++index) {
            ovc_connection_clear(&items[index]);
        }
    }
    free(items);
    free(list);
}

void ovstorage_auth_event_destroy(OvStorage_AuthEvent *event)
{
    if (event == NULL) {
        return;
    }
    switch (event->kind) {
    case OvStorage_AuthEventKind_OpenBrowser:
        free((void *)event->as.open_browser.url);
        break;
    case OvStorage_AuthEventKind_DeviceCode:
        free((void *)event->as.device_code.user_code);
        free((void *)event->as.device_code.verification_url);
        break;
    case OvStorage_AuthEventKind_Progress:
        free((void *)event->as.progress.message);
        break;
    case OvStorage_AuthEventKind_Succeeded:
        ovstorage_connection_destroy(
            (OvStorage_Connection *)(void *)event->as.succeeded.connection);
        break;
    case OvStorage_AuthEventKind_Failed:
        free((void *)event->as.failed.message);
        break;
    case OvStorage_AuthEventKind_Cancelled:
    default:
        break;
    }
    free(event);
}

void ovc_root_info_clear(OvStorage_RootInfo *info)
{
    if (info == NULL) {
        return;
    }
    free((void *)info->root);
    free((void *)info->layer_kind);
    free((void *)info->display_name);
    free((void *)info->connection_id);
    free((void *)info->source_connection_id);
    free((void *)info->source_broker_principal);
    free((void *)info->source_alias_to);
    free((void *)info->source_alias_source_broker_principal);
    free((void *)info->alias_state_chain_too_long_reason);
    free((void *)info->owning_target);
    ovc_metadata_entries_destroy(info->user_metadata,
                                 info->user_metadata_len);
    free((void *)info->icon);
    memset(info, 0, sizeof(*info));
}

void ovstorage_root_info_destroy(OvStorage_RootInfo *info)
{
    if (info == NULL) {
        return;
    }
    ovc_root_info_clear(info);
    free(info);
}

void ovstorage_root_info_list_destroy(OvStorage_RootInfoList *list)
{
    OvStorage_RootInfo *items;
    size_t index;

    if (list == NULL) {
        return;
    }
    items = (OvStorage_RootInfo *)(void *)list->items;
    if (items != NULL) {
        for (index = 0; index < list->len; ++index) {
            ovc_root_info_clear(&items[index]);
        }
    }
    free(items);
    free(list);
}

#if defined(OVC_VALUES_CONN_TEST_MAIN)

#include <assert.h>
#include <stdio.h>

#if defined(NDEBUG)
#error "OVC_VALUES_CONN_TEST_MAIN requires assertions to be enabled"
#endif

static void ovc_values_conn_test_info_clone_and_inline_list(void)
{
    OvStorage_Info *clone;
    OvStorage_Info *items;
    OvStorage_Info *source;
    OvStorage_List *list;
    OvStorage_MetadataEntry *metadata;

    source = (OvStorage_Info *)calloc(1, sizeof(*source));
    metadata =
        (OvStorage_MetadataEntry *)calloc(1, sizeof(*metadata));
    assert(source != NULL);
    assert(metadata != NULL);
    source->address = ovc_conn_string_duplicate("file:///source");
    source->etag = ovc_conn_string_duplicate("etag-1");
    source->kind = OvStorage_ObjectKind_File;
    source->has_size = true;
    source->size = 42;
    metadata[0].key = ovc_conn_string_duplicate("owner");
    metadata[0].value = ovc_conn_string_duplicate("test");
    source->user_metadata = metadata;
    source->user_metadata_len = 1;
    assert(source->address != NULL);
    assert(source->etag != NULL);
    assert(metadata[0].key != NULL);
    assert(metadata[0].value != NULL);

    clone = ovstorage_info_clone(source);
    assert(clone != NULL);
    assert(clone != source);
    assert(clone->address != source->address);
    assert(clone->user_metadata != source->user_metadata);
    assert(clone->user_metadata[0].key != source->user_metadata[0].key);
    ovstorage_info_destroy(source);
    assert(strcmp(clone->address, "file:///source") == 0);
    assert(strcmp(clone->etag, "etag-1") == 0);
    assert(strcmp(clone->user_metadata[0].key, "owner") == 0);

    list = (OvStorage_List *)calloc(1, sizeof(*list));
    items = (OvStorage_Info *)calloc(2, sizeof(*items));
    assert(list != NULL);
    assert(items != NULL);
    items[0].address = ovc_conn_string_duplicate("file:///one");
    items[1].address = ovc_conn_string_duplicate("file:///two");
    assert(items[0].address != NULL);
    assert(items[1].address != NULL);
    list->items = items;
    list->len = 2;
    assert(&list->items[1] == list->items + 1);
    source = ovstorage_info_clone(&list->items[1]);
    assert(source != NULL);
    ovstorage_list_destroy(list);
    assert(strcmp(source->address, "file:///two") == 0);
    ovstorage_info_destroy(source);
    ovstorage_info_destroy(clone);
}

static void ovc_values_conn_test_auth_event_variants(void)
{
    OvStorage_AuthEvent *event;
    OvStorage_Connection *connection;

    event = (OvStorage_AuthEvent *)calloc(1, sizeof(*event));
    assert(event != NULL);
    event->kind = OvStorage_AuthEventKind_OpenBrowser;
    event->as.open_browser.url = ovc_conn_string_duplicate("https://auth");
    assert(event->as.open_browser.url != NULL);
    ovstorage_auth_event_destroy(event);

    event = (OvStorage_AuthEvent *)calloc(1, sizeof(*event));
    assert(event != NULL);
    event->kind = OvStorage_AuthEventKind_DeviceCode;
    event->as.device_code.user_code = ovc_conn_string_duplicate("ABCD");
    event->as.device_code.verification_url =
        ovc_conn_string_duplicate("https://verify");
    assert(event->as.device_code.user_code != NULL);
    assert(event->as.device_code.verification_url != NULL);
    ovstorage_auth_event_destroy(event);

    event = (OvStorage_AuthEvent *)calloc(1, sizeof(*event));
    assert(event != NULL);
    event->kind = OvStorage_AuthEventKind_Progress;
    event->as.progress.message = ovc_conn_string_duplicate("waiting");
    assert(event->as.progress.message != NULL);
    ovstorage_auth_event_destroy(event);

    event = (OvStorage_AuthEvent *)calloc(1, sizeof(*event));
    connection =
        (OvStorage_Connection *)calloc(1, sizeof(*connection));
    assert(event != NULL);
    assert(connection != NULL);
    connection->id = ovc_conn_string_duplicate("connection");
    assert(connection->id != NULL);
    event->kind = OvStorage_AuthEventKind_Succeeded;
    event->as.succeeded.connection = connection;
    ovstorage_auth_event_destroy(event);

    event = (OvStorage_AuthEvent *)calloc(1, sizeof(*event));
    assert(event != NULL);
    event->kind = OvStorage_AuthEventKind_Failed;
    event->as.failed.message = ovc_conn_string_duplicate("denied");
    assert(event->as.failed.message != NULL);
    ovstorage_auth_event_destroy(event);

    event = (OvStorage_AuthEvent *)calloc(1, sizeof(*event));
    assert(event != NULL);
    event->kind = OvStorage_AuthEventKind_Cancelled;
    ovstorage_auth_event_destroy(event);

    /*
     * OOM conversion failures destroy partially initialized active variants.
     * The tag must therefore select exactly the payloads allocated so far.
     */
    event = (OvStorage_AuthEvent *)calloc(1, sizeof(*event));
    assert(event != NULL);
    event->kind = OvStorage_AuthEventKind_DeviceCode;
    event->as.device_code.user_code = ovc_conn_string_duplicate("ABCD");
    assert(event->as.device_code.user_code != NULL);
    ovstorage_auth_event_destroy(event);

    event = (OvStorage_AuthEvent *)calloc(1, sizeof(*event));
    assert(event != NULL);
    event->kind = OvStorage_AuthEventKind_Succeeded;
    ovstorage_auth_event_destroy(event);
}

int main(void)
{
    ovc_values_conn_test_info_clone_and_inline_list();
    ovc_values_conn_test_auth_event_variants();
    printf("values_conn suite passed\n");
    return 0;
}

#endif /* OVC_VALUES_CONN_TEST_MAIN */
