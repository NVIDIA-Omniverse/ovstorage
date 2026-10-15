/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure-C implementation of the canonical AUTH_CREDENTIAL wire decoder.
 */

#include "internal.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if defined(OVC_ABI_FREE)
void OVC_ABI_FREE(void *allocation);
#define ovc_auth_abi_free OVC_ABI_FREE
#else
#define ovc_auth_abi_free ovc_abi_free
#endif

typedef enum ovc_auth_decode_error {
    OVC_AUTH_DECODE_OK = 0,
    OVC_AUTH_DECODE_UNSUPPORTED_VERSION,
    OVC_AUTH_DECODE_TRUNCATED,
    OVC_AUTH_DECODE_BAD_TAG,
    OVC_AUTH_DECODE_UTF8,
    OVC_AUTH_DECODE_TRAILING_DATA
} ovc_auth_decode_error;

typedef struct ovc_auth_cursor {
    const uint8_t *bytes;
    size_t len;
    size_t pos;
    ovc_auth_decode_error error;
} ovc_auth_cursor;

static const uint8_t *ovc_auth_take(ovc_auth_cursor *cursor, size_t count)
{
    const uint8_t *value;

    if (cursor->error != OVC_AUTH_DECODE_OK) {
        return NULL;
    }
    if (cursor->pos > cursor->len || count > cursor->len - cursor->pos) {
        cursor->error = OVC_AUTH_DECODE_TRUNCATED;
        return NULL;
    }
    value = cursor->bytes + cursor->pos;
    cursor->pos += count;
    return value;
}

static uint8_t ovc_auth_u8(ovc_auth_cursor *cursor)
{
    const uint8_t *bytes = ovc_auth_take(cursor, 1);

    return bytes == NULL ? 0 : bytes[0];
}

static uint32_t ovc_auth_u32(ovc_auth_cursor *cursor)
{
    const uint8_t *bytes = ovc_auth_take(cursor, 4);

    if (bytes == NULL) {
        return 0;
    }
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static int32_t ovc_auth_i32(ovc_auth_cursor *cursor)
{
    uint32_t bits = ovc_auth_u32(cursor);
    int32_t value = 0;

    if (cursor->error == OVC_AUTH_DECODE_OK) {
        memcpy(&value, &bits, sizeof(value));
    }
    return value;
}

static const uint8_t *ovc_auth_bytes(ovc_auth_cursor *cursor,
                                     size_t *out_len)
{
    uint32_t len = ovc_auth_u32(cursor);

    if (cursor->error != OVC_AUTH_DECODE_OK) {
        *out_len = 0;
        return NULL;
    }
    *out_len = (size_t)len;
    return ovc_auth_take(cursor, *out_len);
}

static void *ovc_auth_allocate(size_t size)
{
    void *allocation = ovc_abi_alloc(size);

    if (allocation == NULL) {
        abort();
    }
    return allocation;
}

static OvStoragePlugin_Bytes ovc_auth_copy_bytes(const uint8_t *bytes,
                                                  size_t len)
{
    OvStoragePlugin_Bytes out;

    out.ptr = (uint8_t *)ovc_auth_allocate(len);
    out.len = len;
    if (len != 0) {
        memcpy(out.ptr, bytes, len);
    }
    return out;
}

static OvStoragePlugin_Str ovc_auth_copy_string(ovc_auth_cursor *cursor)
{
    OvStoragePlugin_Str out = {0};
    const uint8_t *bytes;
    size_t len;

    bytes = ovc_auth_bytes(cursor, &len);
    if (cursor->error != OVC_AUTH_DECODE_OK) {
        return out;
    }
    if (!ovc_utf8_is_valid(bytes, len)) {
        cursor->error = OVC_AUTH_DECODE_UTF8;
        return out;
    }
    out.ptr = (char *)ovc_auth_allocate(len);
    out.len = len;
    if (len != 0) {
        memcpy(out.ptr, bytes, len);
    }
    return out;
}

static void ovc_auth_str_clear(OvStoragePlugin_Str *value)
{
    if (value == NULL) {
        return;
    }
    ovc_auth_abi_free(value->ptr);
    value->ptr = NULL;
    value->len = 0;
}

static void ovc_auth_bytes_clear(OvStoragePlugin_Bytes *value)
{
    if (value == NULL) {
        return;
    }
    ovc_auth_abi_free(value->ptr);
    value->ptr = NULL;
    value->len = 0;
}

static void ovc_auth_transport_clear(
    OvStoragePlugin_AuthCredentialTransport *transport)
{
    if (transport == NULL) {
        return;
    }
    switch (transport->tag) {
    case OvStoragePlugin_AuthCredentialTransportTag_Tcp:
        ovc_auth_str_clear(&transport->tcp.peer_addr);
        if (transport->tcp.tls_client_cert.present) {
            ovc_auth_bytes_clear(&transport->tcp.tls_client_cert.value);
            transport->tcp.tls_client_cert.present = false;
        }
        break;
    case OvStoragePlugin_AuthCredentialTransportTag_NamedPipe:
        ovc_auth_str_clear(&transport->named_pipe.sid);
        break;
    case OvStoragePlugin_AuthCredentialTransportTag_Uds:
    default:
        break;
    }
}

static void ovc_auth_credential_clear(OvStoragePlugin_AuthCredential *value)
{
    size_t index;

    if (value == NULL) {
        return;
    }
    if (value->bearer.present) {
        volatile uint8_t *bytes = value->bearer.value.ptr;

        for (index = 0; index < value->bearer.value.len; ++index) {
            bytes[index] = 0;
        }
        ovc_auth_bytes_clear(&value->bearer.value);
        value->bearer.present = false;
    }
    ovc_auth_transport_clear(&value->transport);
    if (value->forwarded_headers.ptr != NULL) {
        for (index = 0; index < value->forwarded_headers.len; ++index) {
            ovc_auth_str_clear(&value->forwarded_headers.ptr[index].name);
            ovc_auth_str_clear(&value->forwarded_headers.ptr[index].value);
        }
    }
    ovc_auth_abi_free(value->forwarded_headers.ptr);
    value->forwarded_headers.ptr = NULL;
    value->forwarded_headers.len = 0;
}

static const char *ovc_auth_decode_error_message(ovc_auth_decode_error error)
{
    switch (error) {
    case OVC_AUTH_DECODE_UNSUPPORTED_VERSION:
        return "AuthCredential decode failed: unsupported wire version";
    case OVC_AUTH_DECODE_TRUNCATED:
        return "AuthCredential decode failed: truncated buffer";
    case OVC_AUTH_DECODE_BAD_TAG:
        return "AuthCredential decode failed: bad transport tag";
    case OVC_AUTH_DECODE_UTF8:
        return "AuthCredential decode failed: invalid utf-8 in string field";
    case OVC_AUTH_DECODE_TRAILING_DATA:
        return "AuthCredential decode failed: trailing data after credential";
    case OVC_AUTH_DECODE_OK:
    default:
        return "AuthCredential decode failed";
    }
}

static OvStoragePlugin_Error *ovc_auth_error(OvStoragePlugin_ErrorCode code,
                                              const char *message)
{
    OvStoragePlugin_Error *error;
    size_t message_len = strlen(message);

    error = (OvStoragePlugin_Error *)ovc_auth_allocate(sizeof(*error));
    memset(error, 0, sizeof(*error));
    error->message_ptr = (char *)ovc_auth_allocate(message_len);
    if (message_len != 0) {
        memcpy(error->message_ptr, message, message_len);
    }
    error->code = code;
    error->message_len = message_len;
    return error;
}

static OvStoragePlugin_FfiStatus ovc_auth_fail(
    OvStoragePlugin_Error **err,
    ovc_auth_decode_error decode_error)
{
    OvStoragePlugin_ErrorCode code =
        decode_error == OVC_AUTH_DECODE_UNSUPPORTED_VERSION
            ? OvStoragePlugin_ErrorCode_IncompatibleType
            : OvStoragePlugin_ErrorCode_InvalidArgument;

    if (err != NULL) {
        *err = ovc_auth_error(code,
                              ovc_auth_decode_error_message(decode_error));
    }
    return OvStoragePlugin_FFI_STATUS_ERR;
}

static OvStoragePlugin_FfiStatus ovc_auth_fail_argument(
    OvStoragePlugin_Error **err,
    const char *message)
{
    if (err != NULL) {
        *err = ovc_auth_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                              message);
    }
    return OvStoragePlugin_FFI_STATUS_ERR;
}

OvStoragePlugin_FfiStatus ovstorage_plugin_auth_credential_decode(
    const uint8_t *bytes,
    size_t len,
    OvStoragePlugin_AuthCredential **out,
    OvStoragePlugin_Error **err)
{
    ovc_auth_cursor cursor;
    OvStoragePlugin_AuthCredential *credential;
    const uint8_t *field;
    size_t field_len;
    uint8_t version;
    uint8_t tag;
    uint32_t forwarded_count;
    size_t index;

    if (out != NULL) {
        *out = NULL;
    }
    if (err != NULL) {
        *err = NULL;
    }
    if (out == NULL || err == NULL) {
        return ovc_auth_fail_argument(
            err,
            "AuthCredential decode requires non-null out and err parameters");
    }
    if (bytes == NULL && len != 0) {
        return ovc_auth_fail_argument(
            err,
            "AuthCredential bytes pointer is null with non-zero length");
    }

    cursor.bytes = bytes;
    cursor.len = len;
    cursor.pos = 0;
    cursor.error = OVC_AUTH_DECODE_OK;

    version = ovc_auth_u8(&cursor);
    if (cursor.error != OVC_AUTH_DECODE_OK) {
        return ovc_auth_fail(err, cursor.error);
    }
    if (version != 1u && version != OVSTORAGE_AUTH_CREDENTIAL_WIRE_VERSION) {
        return ovc_auth_fail(err, OVC_AUTH_DECODE_UNSUPPORTED_VERSION);
    }

    credential = (OvStoragePlugin_AuthCredential *)
        ovc_auth_allocate(sizeof(*credential));
    memset(credential, 0, sizeof(*credential));
    credential->struct_size = sizeof(*credential);

    field = ovc_auth_bytes(&cursor, &field_len);
    if (cursor.error == OVC_AUTH_DECODE_OK && field_len != 0) {
        credential->bearer.present = true;
        credential->bearer.value = ovc_auth_copy_bytes(field, field_len);
    }

    tag = ovc_auth_u8(&cursor);
    if (cursor.error == OVC_AUTH_DECODE_OK) {
        switch (tag) {
        case OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_TCP:
            credential->transport.tag =
                OvStoragePlugin_AuthCredentialTransportTag_Tcp;
            credential->transport.tcp.peer_addr =
                ovc_auth_copy_string(&cursor);
            field = ovc_auth_bytes(&cursor, &field_len);
            if (cursor.error == OVC_AUTH_DECODE_OK && field_len != 0) {
                credential->transport.tcp.tls_client_cert.present = true;
                credential->transport.tcp.tls_client_cert.value =
                    ovc_auth_copy_bytes(field, field_len);
            }
            break;
        case OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_UDS:
            credential->transport.tag =
                OvStoragePlugin_AuthCredentialTransportTag_Uds;
            credential->transport.uds.uid = ovc_auth_u32(&cursor);
            credential->transport.uds.gid = ovc_auth_u32(&cursor);
            credential->transport.uds.pid = ovc_auth_i32(&cursor);
            break;
        case OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_NAMED_PIPE:
            credential->transport.tag =
                OvStoragePlugin_AuthCredentialTransportTag_NamedPipe;
            credential->transport.named_pipe.sid =
                ovc_auth_copy_string(&cursor);
            credential->transport.named_pipe.pid = ovc_auth_u32(&cursor);
            break;
        default:
            cursor.error = OVC_AUTH_DECODE_BAD_TAG;
            break;
        }
    }

    if (cursor.error == OVC_AUTH_DECODE_OK &&
        version == OVSTORAGE_AUTH_CREDENTIAL_WIRE_VERSION) {
        forwarded_count = ovc_auth_u32(&cursor);
        if (cursor.error == OVC_AUTH_DECODE_OK &&
            (size_t)forwarded_count > (cursor.len - cursor.pos) / 8u) {
            cursor.error = OVC_AUTH_DECODE_TRUNCATED;
        }
        if (cursor.error == OVC_AUTH_DECODE_OK && forwarded_count != 0) {
            size_t allocation_count = (size_t)forwarded_count;

            if (allocation_count >
                SIZE_MAX / sizeof(*credential->forwarded_headers.ptr)) {
                cursor.error = OVC_AUTH_DECODE_TRUNCATED;
            } else {
                credential->forwarded_headers.ptr =
                    (OvStoragePlugin_AuthCredentialForwardedHeader *)
                        ovc_auth_allocate(
                            allocation_count *
                            sizeof(*credential->forwarded_headers.ptr));
                memset(credential->forwarded_headers.ptr,
                       0,
                       allocation_count *
                           sizeof(*credential->forwarded_headers.ptr));
            }
        }
        for (index = 0;
             cursor.error == OVC_AUTH_DECODE_OK &&
                 index < (size_t)forwarded_count;
             ++index) {
            credential->forwarded_headers.ptr[index].name =
                ovc_auth_copy_string(&cursor);
            if (cursor.error == OVC_AUTH_DECODE_OK) {
                credential->forwarded_headers.len = index + 1;
                credential->forwarded_headers.ptr[index].value =
                    ovc_auth_copy_string(&cursor);
            }
        }
    }

    if (cursor.error == OVC_AUTH_DECODE_OK && cursor.pos != cursor.len) {
        cursor.error = OVC_AUTH_DECODE_TRAILING_DATA;
    }
    if (cursor.error != OVC_AUTH_DECODE_OK) {
        ovc_auth_credential_clear(credential);
        ovc_auth_abi_free(credential);
        return ovc_auth_fail(err, cursor.error);
    }

    if (credential->forwarded_headers.ptr == NULL) {
        credential->forwarded_headers.ptr =
            (OvStoragePlugin_AuthCredentialForwardedHeader *)
                ovc_auth_allocate(
                    sizeof(*credential->forwarded_headers.ptr));
    }

    *out = credential;
    return OvStoragePlugin_FFI_STATUS_OK;
}

void ovstorage_plugin_auth_credential_free(
    OvStoragePlugin_AuthCredential *value)
{
    if (value == NULL) {
        return;
    }
    ovc_auth_credential_clear(value);
    ovc_auth_abi_free(value);
}
