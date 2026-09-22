/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "internal.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(OVC_CREDENTIAL_STORE_TEST_MAIN)
#include "temp_dir.h"

#if !defined(_WIN32)
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#endif

/*
 * The standalone host uses a plain-file credential store instead of sqlite:
 * it stays dependency-free, each application has only a few records, and the
 * required durability primitives already live in this source distribution.
 * Each namespace has one record file, named by a lowercase hexadecimal
 * encoding that stays injective on case-insensitive filesystems. File
 * integration performs whole-file read-modify-write while holding that
 * namespace's separate lock file.
 */

static const uint8_t OVC_CRED_MAGIC[16] = {
    'o', 'v', 's', 't', 'o', 'r', 'a', 'g',
    'e', '-', 'c', 'r', 'e', 'd', 's', 0};

#define OVC_CRED_HEADER_BYTES 24u
#define OVC_CRED_RECORD_HEADER_BYTES 16u
#define OVC_CRED_CHECKSUM_BYTES 8u
#define OVC_CRED_FNV_OFFSET UINT64_C(0xcbf29ce484222325)
#define OVC_CRED_FNV_PRIME UINT64_C(0x100000001b3)

static void ovc_cred_strerror(int error, char *message, size_t message_size)
{
#if defined(_WIN32)
    if (strerror_s(message, message_size, error) == 0) {
        return;
    }
#elif defined(__GLIBC__) && defined(_GNU_SOURCE)
    {
        const char *description;

        description = strerror_r(error, message, message_size);
        if (description != NULL) {
            if (description != message) {
                (void)snprintf(message, message_size, "%s", description);
            }
            return;
        }
    }
#else
    if (strerror_r(error, message, message_size) == 0) {
        return;
    }
#endif
    (void)snprintf(message, message_size, "system error %d", error);
}

struct ovc_cred_store {
    char *auth_dir;
    char *dir;
    char *record_path;
    char *temp_path;
    char *lock_path;
};

typedef struct ovc_cred_store_operation {
    ovc_lockfile lock;
    ovc_cred_records records;
    uint8_t *raw;
    size_t raw_len;
} ovc_cred_store_operation;

#if defined(OVC_CREDENTIAL_STORE_TEST_MAIN) || \
    defined(OVC_HOST_CALLBACKS_TEST_MAIN)
static void (*g_ovc_cred_release_observer)(const uint8_t *, size_t);

void ovc_cred_test_set_release_observer(
    void (*observer)(const uint8_t *, size_t))
{
    g_ovc_cred_release_observer = observer;
}
#endif

static void ovc_cred_error_reset(ovc_cred_error *err)
{
    if (err != NULL) {
        err->status = OVC_CRED_OK;
        err->message[0] = '\0';
    }
}

static int ovc_cred_error_text(ovc_cred_error *err,
                               ovc_cred_status status,
                               const char *message)
{
    if (err != NULL) {
        err->status = status;
        (void)snprintf(err->message, sizeof(err->message), "%s", message);
    }
    return 0;
}

static int ovc_cred_error_at(ovc_cred_error *err,
                             ovc_cred_status status,
                             const char *reason,
                             size_t offset)
{
    if (err != NULL) {
        err->status = status;
        (void)snprintf(err->message,
                       sizeof(err->message),
                       "%s at byte offset %lu",
                       reason,
                       (unsigned long)offset);
    }
    return 0;
}

static uint32_t ovc_cred_read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint64_t ovc_cred_read_u64(const uint8_t *bytes)
{
    return (uint64_t)bytes[0] |
           ((uint64_t)bytes[1] << 8) |
           ((uint64_t)bytes[2] << 16) |
           ((uint64_t)bytes[3] << 24) |
           ((uint64_t)bytes[4] << 32) |
           ((uint64_t)bytes[5] << 40) |
           ((uint64_t)bytes[6] << 48) |
           ((uint64_t)bytes[7] << 56);
}

static void ovc_cred_write_u32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void ovc_cred_write_u64(uint8_t *bytes, uint64_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
    bytes[4] = (uint8_t)(value >> 32);
    bytes[5] = (uint8_t)(value >> 40);
    bytes[6] = (uint8_t)(value >> 48);
    bytes[7] = (uint8_t)(value >> 56);
}

static uint64_t ovc_cred_checksum(const uint8_t *bytes, size_t len)
{
    uint64_t checksum;
    size_t index;

    checksum = OVC_CRED_FNV_OFFSET;
    for (index = 0; index < len; ++index) {
        checksum ^= bytes[index];
        checksum *= OVC_CRED_FNV_PRIME;
    }
    return checksum;
}

static int ovc_cred_size_add(size_t *total, size_t addition)
{
    if (*total > SIZE_MAX - addition) {
        return 0;
    }
    *total += addition;
    return 1;
}

static int ovc_cred_slice_equal(const uint8_t *left,
                                size_t left_len,
                                const uint8_t *right,
                                size_t right_len)
{
    return left_len == right_len &&
           (left_len == 0 || memcmp(left, right, left_len) == 0);
}

static uint8_t *ovc_cred_copy_bytes(const uint8_t *bytes, size_t len)
{
    size_t allocation_len;
    uint8_t *copy;

    allocation_len = len == 0 ? 1 : len;
    copy = (uint8_t *)malloc(allocation_len);
    if (copy == NULL) {
        return NULL;
    }
    if (len != 0) {
        memcpy(copy, bytes, len);
    } else {
        copy[0] = 0;
    }
    return copy;
}

static void ovc_cred_buffer_release(uint8_t *bytes,
                                    size_t len,
                                    int is_value)
{
    size_t allocation_len;

    if (bytes == NULL) {
        return;
    }
    allocation_len = len == 0 ? 1 : len;
    ovc_secure_zero(bytes, allocation_len);
#if defined(OVC_CREDENTIAL_STORE_TEST_MAIN) || \
    defined(OVC_HOST_CALLBACKS_TEST_MAIN)
    if (is_value && g_ovc_cred_release_observer != NULL) {
        g_ovc_cred_release_observer(bytes, allocation_len);
    }
#else
    (void)is_value;
#endif
    free(bytes);
}

static void ovc_cred_record_clear(ovc_cred_record *record)
{
    if (record == NULL) {
        return;
    }
    ovc_cred_buffer_release(record->backend_kind,
                            record->backend_kind_len,
                            0);
    ovc_cred_buffer_release(record->connection_id,
                            record->connection_id_len,
                            0);
    ovc_cred_buffer_release(record->field, record->field_len, 0);
    ovc_cred_buffer_release(record->value, record->value_len, 1);
    memset(record, 0, sizeof(*record));
}

static int ovc_cred_slice_input_valid(const uint8_t *bytes, size_t len)
{
    return len == 0 || bytes != NULL;
}

int ovc_cred_namespace_valid(const char *ns)
{
    size_t length;
    unsigned char byte;

    if (ns == NULL || ns[0] == '\0') {
        return 0;
    }
    byte = (unsigned char)ns[0];
    if (!((byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
          (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
          (byte >= (unsigned char)'0' && byte <= (unsigned char)'9'))) {
        return 0;
    }
    for (length = 0; ns[length] != '\0'; ++length) {
        if (length == OVC_CRED_NAMESPACE_MAX) {
            return 0;
        }
        byte = (unsigned char)ns[length];
        if (!((byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'.' || byte == (unsigned char)'_' ||
              byte == (unsigned char)'-')) {
            return 0;
        }
    }
    return length != 0;
}

char *ovc_cred_namespace_file_stem(const char *ns)
{
    static const char hex[] = "0123456789abcdef";
    char *stem;
    size_t index;
    size_t length;

    if (!ovc_cred_namespace_valid(ns)) {
        errno = EINVAL;
        return NULL;
    }
    length = strlen(ns);
    if (length > (SIZE_MAX - 1) / 2) {
        errno = ENOMEM;
        return NULL;
    }
    stem = (char *)malloc(length * 2 + 1);
    if (stem == NULL) {
        return NULL;
    }
    for (index = 0; index < length; ++index) {
        unsigned char byte;

        byte = (unsigned char)ns[index];
        stem[index * 2] = hex[byte >> 4];
        stem[index * 2 + 1] = hex[byte & 0x0fu];
    }
    stem[length * 2] = '\0';
    return stem;
}

int ovc_cred_encode(const ovc_cred_records *records,
                    uint8_t **out,
                    size_t *out_len,
                    ovc_cred_error *err)
{
    uint8_t *bytes;
    size_t total;
    size_t offset;
    size_t index;
    const ovc_cred_record *record;

    ovc_cred_error_reset(err);
    if (out == NULL || out_len == NULL) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "encode output pointer is null");
    }
    *out = NULL;
    *out_len = 0;
    if (records == NULL ||
        (records->count != 0 && records->items == NULL)) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "record collection is malformed");
    }
    if (records->count > UINT32_MAX) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "record count exceeds the v1 limit");
    }

    total = OVC_CRED_HEADER_BYTES + OVC_CRED_CHECKSUM_BYTES;
    for (index = 0; index < records->count; ++index) {
        record = &records->items[index];
        if (!ovc_cred_slice_input_valid(record->backend_kind,
                                        record->backend_kind_len) ||
            !ovc_cred_slice_input_valid(record->connection_id,
                                        record->connection_id_len) ||
            !ovc_cred_slice_input_valid(record->field,
                                        record->field_len) ||
            !ovc_cred_slice_input_valid(record->value,
                                        record->value_len)) {
            return ovc_cred_error_text(
                err, OVC_CRED_INVALID, "record contains a null byte slice");
        }
        if (record->backend_kind_len > OVC_CRED_MAX_FIELD_BYTES) {
            return ovc_cred_error_text(
                err, OVC_CRED_INVALID, "backend_kind exceeds the field limit");
        }
        if (record->connection_id_len > OVC_CRED_MAX_FIELD_BYTES) {
            return ovc_cred_error_text(
                err, OVC_CRED_INVALID, "connection_id exceeds the field limit");
        }
        if (record->field_len > OVC_CRED_MAX_FIELD_BYTES) {
            return ovc_cred_error_text(
                err, OVC_CRED_INVALID, "field exceeds the field limit");
        }
        if (record->value_len > OVC_CRED_MAX_FIELD_BYTES) {
            return ovc_cred_error_text(
                err, OVC_CRED_INVALID, "value exceeds the field limit");
        }
        if (!ovc_cred_size_add(&total, OVC_CRED_RECORD_HEADER_BYTES) ||
            !ovc_cred_size_add(&total, record->backend_kind_len) ||
            !ovc_cred_size_add(&total, record->connection_id_len) ||
            !ovc_cred_size_add(&total, record->field_len) ||
            !ovc_cred_size_add(&total, record->value_len) ||
            total > OVC_CRED_MAX_FILE_BYTES) {
            return ovc_cred_error_text(
                err,
                OVC_CRED_INVALID,
                "encoded credential file exceeds the size limit");
        }
    }

    bytes = (uint8_t *)malloc(total);
    if (bytes == NULL) {
        return ovc_cred_error_text(
            err, OVC_CRED_NOMEM, "out of memory encoding credential records");
    }
    memcpy(bytes, OVC_CRED_MAGIC, sizeof(OVC_CRED_MAGIC));
    ovc_cred_write_u32(bytes + 16, OVC_CRED_FORMAT_VERSION);
    ovc_cred_write_u32(bytes + 20, (uint32_t)records->count);
    offset = OVC_CRED_HEADER_BYTES;
    for (index = 0; index < records->count; ++index) {
        record = &records->items[index];
        ovc_cred_write_u32(bytes + offset,
                           (uint32_t)record->backend_kind_len);
        ovc_cred_write_u32(bytes + offset + 4,
                           (uint32_t)record->connection_id_len);
        ovc_cred_write_u32(bytes + offset + 8,
                           (uint32_t)record->field_len);
        ovc_cred_write_u32(bytes + offset + 12,
                           (uint32_t)record->value_len);
        offset += OVC_CRED_RECORD_HEADER_BYTES;
        if (record->backend_kind_len != 0) {
            memcpy(bytes + offset,
                   record->backend_kind,
                   record->backend_kind_len);
            offset += record->backend_kind_len;
        }
        if (record->connection_id_len != 0) {
            memcpy(bytes + offset,
                   record->connection_id,
                   record->connection_id_len);
            offset += record->connection_id_len;
        }
        if (record->field_len != 0) {
            memcpy(bytes + offset, record->field, record->field_len);
            offset += record->field_len;
        }
        if (record->value_len != 0) {
            memcpy(bytes + offset, record->value, record->value_len);
            offset += record->value_len;
        }
    }
    ovc_cred_write_u64(bytes + offset, ovc_cred_checksum(bytes, offset));
    offset += OVC_CRED_CHECKSUM_BYTES;
    assert(offset == total);
    *out = bytes;
    *out_len = total;
    return 1;
}

ovc_cred_record *ovc_cred_records_find(ovc_cred_records *records,
                                       const uint8_t *backend_kind,
                                       size_t backend_kind_len,
                                       const uint8_t *connection_id,
                                       size_t connection_id_len,
                                       const uint8_t *field,
                                       size_t field_len)
{
    size_t index;
    ovc_cred_record *record;

    if (records == NULL ||
        (records->count != 0 && records->items == NULL) ||
        !ovc_cred_slice_input_valid(backend_kind, backend_kind_len) ||
        !ovc_cred_slice_input_valid(connection_id, connection_id_len) ||
        !ovc_cred_slice_input_valid(field, field_len)) {
        return NULL;
    }
    for (index = 0; index < records->count; ++index) {
        record = &records->items[index];
        if (ovc_cred_slice_equal(record->backend_kind,
                                 record->backend_kind_len,
                                 backend_kind,
                                 backend_kind_len) &&
            ovc_cred_slice_equal(record->connection_id,
                                 record->connection_id_len,
                                 connection_id,
                                 connection_id_len) &&
            ovc_cred_slice_equal(record->field,
                                 record->field_len,
                                 field,
                                 field_len)) {
            return record;
        }
    }
    return NULL;
}

void ovc_cred_records_clear(ovc_cred_records *records)
{
    size_t index;

    if (records == NULL) {
        return;
    }
    if (records->items != NULL) {
        for (index = 0; index < records->count; ++index) {
            ovc_cred_record_clear(&records->items[index]);
        }
        ovc_secure_zero(records->items,
                        records->count * sizeof(*records->items));
        free(records->items);
    }
    records->items = NULL;
    records->count = 0;
}

static int ovc_cred_decode_copy(uint8_t **out,
                                const uint8_t *bytes,
                                size_t len,
                                ovc_cred_error *err,
                                size_t offset)
{
    *out = ovc_cred_copy_bytes(bytes, len);
    if (*out == NULL) {
        return ovc_cred_error_at(
            err, OVC_CRED_NOMEM, "out of memory decoding a record", offset);
    }
    return 1;
}

int ovc_cred_decode(const uint8_t *bytes,
                    size_t len,
                    ovc_cred_records *out,
                    ovc_cred_error *err)
{
    ovc_cred_records decoded;
    ovc_cred_record *record;
    uint32_t version;
    uint32_t record_count;
    uint32_t lengths[4];
    uint64_t stored_checksum;
    uint64_t computed_checksum;
    size_t offset;
    size_t header_offset;
    size_t payload_limit;
    size_t index;
    size_t prior;
    size_t mismatch;

    ovc_cred_error_reset(err);
    if (out == NULL) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "decode output pointer is null");
    }
    memset(out, 0, sizeof(*out));
    memset(&decoded, 0, sizeof(decoded));
    if (len == 0) {
        return ovc_cred_error_at(err, OVC_CRED_CORRUPT, "empty file", 0);
    }
    if (bytes == NULL) {
        return ovc_cred_error_at(
            err, OVC_CRED_INVALID, "input pointer is null", 0);
    }
    if (len > OVC_CRED_MAX_FILE_BYTES) {
        return ovc_cred_error_at(err,
                                 OVC_CRED_CORRUPT,
                                 "credential file exceeds the size limit",
                                 OVC_CRED_MAX_FILE_BYTES);
    }
    if (len < sizeof(OVC_CRED_MAGIC)) {
        return ovc_cred_error_at(
            err, OVC_CRED_CORRUPT, "truncated magic", len);
    }
    if (memcmp(bytes, OVC_CRED_MAGIC, sizeof(OVC_CRED_MAGIC)) != 0) {
        mismatch = 0;
        while (mismatch < sizeof(OVC_CRED_MAGIC) &&
               bytes[mismatch] == OVC_CRED_MAGIC[mismatch]) {
            ++mismatch;
        }
        return ovc_cred_error_at(
            err, OVC_CRED_CORRUPT, "bad credential-file magic", mismatch);
    }
    offset = sizeof(OVC_CRED_MAGIC);
    if (len - offset < 4) {
        return ovc_cred_error_at(
            err, OVC_CRED_CORRUPT, "truncated format version", len);
    }
    version = ovc_cred_read_u32(bytes + offset);
    if (version > OVC_CRED_FORMAT_VERSION) {
        return ovc_cred_error_at(
            err,
            OVC_CRED_NEWER_FORMAT,
            "written by a newer ovstorage; refusing to read or overwrite it",
            offset);
    }
    if (version != OVC_CRED_FORMAT_VERSION) {
        return ovc_cred_error_at(
            err, OVC_CRED_CORRUPT, "unsupported credential-file version", offset);
    }
    offset += 4;
    if (len - offset < 4) {
        return ovc_cred_error_at(
            err, OVC_CRED_CORRUPT, "truncated record count", len);
    }
    record_count = ovc_cred_read_u32(bytes + offset);
    offset += 4;
    if (len - offset < OVC_CRED_CHECKSUM_BYTES) {
        return ovc_cred_error_at(
            err, OVC_CRED_CORRUPT, "truncated checksum", len);
    }
    payload_limit = len - OVC_CRED_CHECKSUM_BYTES;
    if ((size_t)record_count >
        (payload_limit - offset) / OVC_CRED_RECORD_HEADER_BYTES) {
        return ovc_cred_error_at(err,
                                 OVC_CRED_CORRUPT,
                                 "record count exceeds remaining data",
                                 20);
    }
    if (record_count != 0 &&
        sizeof(*decoded.items) > SIZE_MAX / (size_t)record_count) {
        return ovc_cred_error_at(
            err, OVC_CRED_CORRUPT, "record count overflows memory size", 20);
    }
    if (record_count != 0) {
        decoded.items = (ovc_cred_record *)calloc(
            (size_t)record_count, sizeof(*decoded.items));
        if (decoded.items == NULL) {
            return ovc_cred_error_at(
                err, OVC_CRED_NOMEM, "out of memory decoding records", 20);
        }
    }

    for (index = 0; index < (size_t)record_count; ++index) {
        header_offset = offset;
        if (payload_limit - offset < OVC_CRED_RECORD_HEADER_BYTES) {
            ovc_cred_error_at(
                err, OVC_CRED_CORRUPT, "truncated record header", offset);
            goto fail;
        }
        lengths[0] = ovc_cred_read_u32(bytes + offset);
        lengths[1] = ovc_cred_read_u32(bytes + offset + 4);
        lengths[2] = ovc_cred_read_u32(bytes + offset + 8);
        lengths[3] = ovc_cred_read_u32(bytes + offset + 12);
        offset += OVC_CRED_RECORD_HEADER_BYTES;
        if (lengths[0] > OVC_CRED_MAX_FIELD_BYTES) {
            ovc_cred_error_at(err,
                              OVC_CRED_CORRUPT,
                              "backend_kind length exceeds the field limit",
                              header_offset);
            goto fail;
        }
        if (lengths[1] > OVC_CRED_MAX_FIELD_BYTES) {
            ovc_cred_error_at(err,
                              OVC_CRED_CORRUPT,
                              "connection_id length exceeds the field limit",
                              header_offset + 4);
            goto fail;
        }
        if (lengths[2] > OVC_CRED_MAX_FIELD_BYTES) {
            ovc_cred_error_at(err,
                              OVC_CRED_CORRUPT,
                              "field length exceeds the field limit",
                              header_offset + 8);
            goto fail;
        }
        if (lengths[3] > OVC_CRED_MAX_FIELD_BYTES) {
            ovc_cred_error_at(err,
                              OVC_CRED_CORRUPT,
                              "value length exceeds the field limit",
                              header_offset + 12);
            goto fail;
        }
        if ((size_t)lengths[0] > payload_limit - offset) {
            ovc_cred_error_at(err,
                              OVC_CRED_CORRUPT,
                              "backend_kind exceeds remaining data",
                              header_offset);
            goto fail;
        }
        offset += lengths[0];
        if ((size_t)lengths[1] > payload_limit - offset) {
            ovc_cred_error_at(err,
                              OVC_CRED_CORRUPT,
                              "connection_id exceeds remaining data",
                              header_offset + 4);
            goto fail;
        }
        offset += lengths[1];
        if ((size_t)lengths[2] > payload_limit - offset) {
            ovc_cred_error_at(err,
                              OVC_CRED_CORRUPT,
                              "field exceeds remaining data",
                              header_offset + 8);
            goto fail;
        }
        offset += lengths[2];
        if ((size_t)lengths[3] > payload_limit - offset) {
            ovc_cred_error_at(err,
                              OVC_CRED_CORRUPT,
                              "value exceeds remaining data",
                              header_offset + 12);
            goto fail;
        }
        offset = header_offset + OVC_CRED_RECORD_HEADER_BYTES;
        record = &decoded.items[index];
        decoded.count = index + 1;
        if (!ovc_cred_decode_copy(&record->backend_kind,
                                  bytes + offset,
                                  lengths[0],
                                  err,
                                  offset)) {
            goto fail;
        }
        record->backend_kind_len = lengths[0];
        offset += lengths[0];
        if (!ovc_cred_decode_copy(&record->connection_id,
                                  bytes + offset,
                                  lengths[1],
                                  err,
                                  offset)) {
            goto fail;
        }
        record->connection_id_len = lengths[1];
        offset += lengths[1];
        if (!ovc_cred_decode_copy(&record->field,
                                  bytes + offset,
                                  lengths[2],
                                  err,
                                  offset)) {
            goto fail;
        }
        record->field_len = lengths[2];
        offset += lengths[2];
        if (!ovc_cred_decode_copy(&record->value,
                                  bytes + offset,
                                  lengths[3],
                                  err,
                                  offset)) {
            goto fail;
        }
        record->value_len = lengths[3];
        offset += lengths[3];

        for (prior = 0; prior < index; ++prior) {
            if (ovc_cred_slice_equal(
                    decoded.items[prior].backend_kind,
                    decoded.items[prior].backend_kind_len,
                    record->backend_kind,
                    record->backend_kind_len) &&
                ovc_cred_slice_equal(
                    decoded.items[prior].connection_id,
                    decoded.items[prior].connection_id_len,
                    record->connection_id,
                    record->connection_id_len) &&
                ovc_cred_slice_equal(decoded.items[prior].field,
                                     decoded.items[prior].field_len,
                                     record->field,
                                     record->field_len)) {
                ovc_cred_error_at(err,
                                  OVC_CRED_CORRUPT,
                                  "duplicate credential key",
                                  header_offset);
                goto fail;
            }
        }
    }

    if (len - offset < OVC_CRED_CHECKSUM_BYTES) {
        ovc_cred_error_at(
            err, OVC_CRED_CORRUPT, "truncated checksum", offset);
        goto fail;
    }
    stored_checksum = ovc_cred_read_u64(bytes + offset);
    computed_checksum = ovc_cred_checksum(bytes, offset);
    offset += OVC_CRED_CHECKSUM_BYTES;
    if (offset != len) {
        ovc_cred_error_at(
            err, OVC_CRED_CORRUPT, "trailing bytes after checksum", offset);
        goto fail;
    }
    if (stored_checksum != computed_checksum) {
        ovc_cred_error_at(err,
                          OVC_CRED_CORRUPT,
                          "credential-file checksum mismatch",
                          offset - OVC_CRED_CHECKSUM_BYTES);
        goto fail;
    }
    *out = decoded;
    return 1;

fail:
    ovc_cred_records_clear(&decoded);
    return 0;
}

int ovc_cred_records_upsert(ovc_cred_records *records,
                            const uint8_t *backend_kind,
                            size_t backend_kind_len,
                            const uint8_t *connection_id,
                            size_t connection_id_len,
                            const uint8_t *field,
                            size_t field_len,
                            const uint8_t *value,
                            size_t value_len,
                            ovc_cred_error *err)
{
    ovc_cred_record candidate;
    ovc_cred_record *existing;
    ovc_cred_record *grown;

    ovc_cred_error_reset(err);
    memset(&candidate, 0, sizeof(candidate));
    if (records == NULL ||
        (records->count != 0 && records->items == NULL) ||
        !ovc_cred_slice_input_valid(backend_kind, backend_kind_len) ||
        !ovc_cred_slice_input_valid(connection_id, connection_id_len) ||
        !ovc_cred_slice_input_valid(field, field_len) ||
        !ovc_cred_slice_input_valid(value, value_len)) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "upsert input contains a null byte slice");
    }
    if (backend_kind_len > OVC_CRED_MAX_FIELD_BYTES ||
        connection_id_len > OVC_CRED_MAX_FIELD_BYTES ||
        field_len > OVC_CRED_MAX_FIELD_BYTES ||
        value_len > OVC_CRED_MAX_FIELD_BYTES) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "upsert field exceeds the field limit");
    }

    existing = ovc_cred_records_find(records,
                                      backend_kind,
                                      backend_kind_len,
                                      connection_id,
                                      connection_id_len,
                                      field,
                                      field_len);
    if (existing != NULL) {
        candidate.value = ovc_cred_copy_bytes(value, value_len);
        if (candidate.value == NULL) {
            return ovc_cred_error_text(
                err, OVC_CRED_NOMEM, "out of memory replacing credential value");
        }
        candidate.value_len = value_len;
        ovc_cred_buffer_release(existing->value, existing->value_len, 1);
        existing->value = candidate.value;
        existing->value_len = candidate.value_len;
        return 1;
    }

    candidate.backend_kind = ovc_cred_copy_bytes(backend_kind,
                                                  backend_kind_len);
    candidate.backend_kind_len = backend_kind_len;
    candidate.connection_id = ovc_cred_copy_bytes(connection_id,
                                                   connection_id_len);
    candidate.connection_id_len = connection_id_len;
    candidate.field = ovc_cred_copy_bytes(field, field_len);
    candidate.field_len = field_len;
    candidate.value = ovc_cred_copy_bytes(value, value_len);
    candidate.value_len = value_len;
    if (candidate.backend_kind == NULL || candidate.connection_id == NULL ||
        candidate.field == NULL || candidate.value == NULL) {
        ovc_cred_record_clear(&candidate);
        return ovc_cred_error_text(
            err, OVC_CRED_NOMEM, "out of memory adding credential record");
    }
    if (records->count == SIZE_MAX ||
        records->count + 1 > SIZE_MAX / sizeof(*records->items)) {
        ovc_cred_record_clear(&candidate);
        return ovc_cred_error_text(
            err, OVC_CRED_NOMEM, "credential record count overflows memory size");
    }
    grown = (ovc_cred_record *)realloc(
        records->items, (records->count + 1) * sizeof(*records->items));
    if (grown == NULL) {
        ovc_cred_record_clear(&candidate);
        return ovc_cred_error_text(
            err, OVC_CRED_NOMEM, "out of memory growing credential records");
    }
    records->items = grown;
    records->items[records->count] = candidate;
    ++records->count;
    return 1;
}

int ovc_cred_records_remove(ovc_cred_records *records,
                            const uint8_t *backend_kind,
                            size_t backend_kind_len,
                            const uint8_t *connection_id,
                            size_t connection_id_len,
                            const uint8_t *field,
                            size_t field_len)
{
    ovc_cred_record *record;
    size_t index;

    record = ovc_cred_records_find(records,
                                   backend_kind,
                                   backend_kind_len,
                                   connection_id,
                                   connection_id_len,
                                   field,
                                   field_len);
    if (record == NULL) {
        return 0;
    }
    index = (size_t)(record - records->items);
    ovc_cred_record_clear(record);
    if (index + 1 < records->count) {
        memmove(&records->items[index],
                &records->items[index + 1],
                (records->count - index - 1) * sizeof(*records->items));
    }
    --records->count;
    memset(&records->items[records->count],
           0,
           sizeof(*records->items));
    return 1;
}

/* The longest reason a path-carrying message keeps. Reasons in this file are
 * short literals or a strerror text; the cap only matters for the arithmetic
 * that reserves their room before the path is laid down. */
#define OVC_CRED_REASON_MAX 120

/* `<lead> <path><separator><reason>` into `err->message`.
 *
 * The reason is reserved first and kept whole (to OVC_CRED_REASON_MAX), and
 * the path takes whatever room remains. A path that does not fit is elided
 * from the LEFT behind "...": the leaf is the part an operator acts on, and
 * a diagnostic whose tail has been cut no longer says why the store was
 * refused. Formatting the path first and unbounded lost the reason at about
 * 250 bytes of path and the file name itself at about 294 -- lengths a deep
 * home or CI scratch root reaches without anything hostile. */
static void ovc_cred_error_path_message(ovc_cred_error *err,
                                        ovc_cred_status status,
                                        const char *lead,
                                        const char *path,
                                        const char *separator,
                                        const char *reason)
{
    static const char ellipsis[] = "...";
    size_t reason_len;
    size_t fixed;
    size_t room;
    size_t path_len;

    err->status = status;
    reason_len = strlen(reason);
    if (reason_len > OVC_CRED_REASON_MAX) {
        reason_len = OVC_CRED_REASON_MAX;
    }
    /* lead, one space, separator, reason, terminator. */
    fixed = strlen(lead) + 1 + strlen(separator) + reason_len + 1;
    if (fixed + sizeof(ellipsis) > sizeof(err->message)) {
        /* Every lead and separator here is a short literal, so this cannot
         * happen for a caller in this file; keep the message well formed
         * rather than trusting that. */
        (void)snprintf(err->message,
                       sizeof(err->message),
                       "%s%s%.*s",
                       lead,
                       separator,
                       (int)reason_len,
                       reason);
        return;
    }
    room = sizeof(err->message) - fixed;
    path_len = strlen(path);
    if (path_len > room) {
        (void)snprintf(err->message,
                       sizeof(err->message),
                       "%s %s%s%s%.*s",
                       lead,
                       ellipsis,
                       path + (path_len - (room - (sizeof(ellipsis) - 1))),
                       separator,
                       (int)reason_len,
                       reason);
        return;
    }
    (void)snprintf(err->message,
                   sizeof(err->message),
                   "%s %s%s%.*s",
                   lead,
                   path,
                   separator,
                   (int)reason_len,
                   reason);
}

static int ovc_cred_store_error_errno(ovc_cred_error *err,
                                      const char *step,
                                      const char *path,
                                      int error_code)
{
    if (err != NULL) {
        char system_message[256];

        ovc_cred_strerror(error_code,
                          system_message,
                          sizeof(system_message));
        ovc_cred_error_path_message(err,
                                    OVC_CRED_UNAVAILABLE,
                                    step,
                                    path,
                                    " failed: ",
                                    system_message);
    }
    return 0;
}

static int ovc_cred_store_error_corrupt(ovc_cred_error *err,
                                        ovc_cred_status status,
                                        const char *record_path,
                                        const char *reason)
{
    if (err != NULL) {
        ovc_cred_error_path_message(err,
                                    status,
                                    status == OVC_CRED_NEWER_FORMAT
                                        ? "newer-format credential store"
                                        : "corrupt credential store",
                                    record_path,
                                    ": ",
                                    reason);
    }
    return 0;
}

static void ovc_cred_store_bytes_clear(uint8_t **bytes, size_t len)
{
    if (*bytes == NULL) {
        return;
    }
    ovc_secure_zero(*bytes, len == 0 ? 1 : len);
    free(*bytes);
    *bytes = NULL;
}

static char *ovc_cred_store_string_dup(const char *value)
{
    size_t length;
    char *copy;

    length = strlen(value);
    if (length == SIZE_MAX) {
        errno = ENOMEM;
        return NULL;
    }
    copy = (char *)malloc(length + 1);
    if (copy != NULL) {
        memcpy(copy, value, length + 1);
    }
    return copy;
}

void ovc_cred_store_close(ovc_cred_store *store)
{
    if (store == NULL) {
        return;
    }
    free(store->lock_path);
    free(store->temp_path);
    free(store->record_path);
    free(store->dir);
    free(store->auth_dir);
    memset(store, 0, sizeof(*store));
    free(store);
}

int ovc_cred_store_open(const char *auth_dir,
                        const char *credential_namespace,
                        ovc_cred_store **out,
                        ovc_cred_error *err)
{
    ovc_cred_store *store;
    char *stem;
    char child[OVC_CRED_NAMESPACE_MAX * 2 + sizeof(".creds.tmp")];

    ovc_cred_error_reset(err);
    if (out == NULL) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "credential store output pointer is null");
    }
    *out = NULL;
    if (auth_dir == NULL || auth_dir[0] == '\0') {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "credential store auth directory is empty");
    }
    if (!ovc_cred_namespace_valid(credential_namespace)) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "credential namespace is invalid");
    }

    store = (ovc_cred_store *)calloc(1, sizeof(*store));
    if (store == NULL) {
        return ovc_cred_error_text(
            err, OVC_CRED_NOMEM, "out of memory opening credential store");
    }
    stem = ovc_cred_namespace_file_stem(credential_namespace);
    if (stem == NULL) {
        ovc_cred_store_close(store);
        return ovc_cred_error_text(
            err, OVC_CRED_NOMEM, "out of memory encoding credential namespace");
    }
    store->auth_dir = ovc_cred_store_string_dup(auth_dir);
    store->dir = ovc_path_join(auth_dir, "c-credentials");
    (void)snprintf(child, sizeof(child), "%s.creds", stem);
    if (store->dir != NULL) {
        store->record_path = ovc_path_join(store->dir, child);
    }
    (void)snprintf(child, sizeof(child), "%s.creds.tmp", stem);
    if (store->dir != NULL) {
        store->temp_path = ovc_path_join(store->dir, child);
    }
    (void)snprintf(child, sizeof(child), "%s.lock", stem);
    if (store->dir != NULL) {
        store->lock_path = ovc_path_join(store->dir, child);
    }
    free(stem);
    if (store->auth_dir == NULL || store->dir == NULL ||
        store->record_path == NULL || store->temp_path == NULL ||
        store->lock_path == NULL) {
        ovc_cred_store_close(store);
        return ovc_cred_error_text(
            err, OVC_CRED_NOMEM, "out of memory building credential store paths");
    }

    *out = store;
    return 1;
}

static void ovc_cred_store_operation_finish(
    ovc_cred_store_operation *operation)
{
    ovc_cred_records_clear(&operation->records);
    ovc_cred_store_bytes_clear(&operation->raw, operation->raw_len);
    operation->raw_len = 0;
    ovc_transient_retry_end();
    /* Release last: all protected state is gone before another writer runs. */
    ovc_lockfile_release(&operation->lock);
}

static int ovc_cred_store_begin(ovc_cred_store *store,
                                ovc_cred_store_operation *operation,
                                ovc_cred_error *err)
{
    ovc_file file;
    uint64_t file_size;
    ovc_cred_error decode_error;
    int error_code;

    memset(operation, 0, sizeof(*operation));
    operation->lock.file = OVC_INVALID_FILE;
    file = OVC_INVALID_FILE;

    if (ovc_private_dir_ensure(store->auth_dir) != 0) {
        error_code = errno;
        return ovc_cred_store_error_errno(err,
                                          "prepare credential store directory",
                                          store->auth_dir,
                                          error_code);
    }
    if (ovc_private_dir_ensure(store->dir) != 0) {
        error_code = errno;
        return ovc_cred_store_error_errno(err,
                                          "prepare credential store directory",
                                          store->dir,
                                          error_code);
    }
    if (ovc_lockfile_acquire(store->lock_path,
                             OVC_CRED_LOCK_TIMEOUT_NS,
                             &operation->lock) != 0) {
        error_code = errno;
        if (error_code == ETIMEDOUT) {
            if (err != NULL) {
                ovc_cred_error_path_message(
                    err,
                    OVC_CRED_LOCKED,
                    "credential store lock",
                    store->lock_path,
                    " ",
                    "held by another process for more than 10 s");
            }
            goto fail;
        }
        ovc_cred_store_error_errno(err,
                                   "acquire credential store lock",
                                   store->lock_path,
                                   error_code);
        goto fail;
    }
    /* One transient-retry budget for the whole operation, opened once the lock
     * is held so the wait it bounds is the one other processes are queued on
     * and cannot stack per primitive against their lock timeout. */
    ovc_transient_retry_begin(OVC_CRED_TRANSIENT_RETRY_NS);

    file = ovc_private_file_open(store->record_path,
                                 OVC_PRIVATE_OPEN_EXISTING);
    if (file == OVC_INVALID_FILE) {
        error_code = errno;
        if (error_code == ENOENT) {
            return 1;
        }
        ovc_cred_store_error_errno(err,
                                   "open credential store file",
                                   store->record_path,
                                   error_code);
        goto fail;
    }
    if (ovc_file_size(file, &file_size) != 0) {
        error_code = errno;
        ovc_cred_store_error_errno(err,
                                   "inspect credential store file",
                                   store->record_path,
                                   error_code);
        goto fail;
    }
    if (file_size > OVC_CRED_MAX_FILE_BYTES) {
        ovc_cred_store_error_corrupt(
            err,
            OVC_CRED_CORRUPT,
            store->record_path,
            "credential file exceeds the size limit");
        goto fail;
    }
    if (ovc_file_read_all(file,
                          OVC_CRED_MAX_FILE_BYTES,
                          &operation->raw,
                          &operation->raw_len) != 0) {
        error_code = errno;
        if (error_code == EFBIG) {
            ovc_cred_store_error_corrupt(
                err,
                OVC_CRED_CORRUPT,
                store->record_path,
                "credential file exceeds the size limit");
        } else {
            ovc_cred_store_error_errno(err,
                                       "read credential store file",
                                       store->record_path,
                                       error_code);
        }
        goto fail;
    }
    if (ovc_file_close(file) != 0) {
        error_code = errno;
        file = OVC_INVALID_FILE;
        ovc_cred_store_error_errno(err,
                                   "close credential store file",
                                   store->record_path,
                                   error_code);
        goto fail;
    }
    file = OVC_INVALID_FILE;

    if (!ovc_cred_decode(operation->raw,
                         operation->raw_len,
                         &operation->records,
                         &decode_error)) {
        if (decode_error.status == OVC_CRED_CORRUPT ||
            decode_error.status == OVC_CRED_NEWER_FORMAT) {
            ovc_cred_store_error_corrupt(err,
                                         decode_error.status,
                                         store->record_path,
                                         decode_error.message);
        } else if (err != NULL) {
            *err = decode_error;
        }
        goto fail;
    }
    return 1;

fail:
    if (file != OVC_INVALID_FILE) {
        (void)ovc_file_close(file);
    }
    ovc_cred_store_operation_finish(operation);
    return 0;
}

static int ovc_cred_store_key_valid(const ovc_cred_record *key,
                                    int include_value,
                                    ovc_cred_error *err)
{
    if (key == NULL ||
        !ovc_cred_slice_input_valid(key->backend_kind,
                                    key->backend_kind_len) ||
        !ovc_cred_slice_input_valid(key->connection_id,
                                    key->connection_id_len) ||
        !ovc_cred_slice_input_valid(key->field, key->field_len) ||
        (include_value &&
         !ovc_cred_slice_input_valid(key->value, key->value_len))) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "credential contains a null byte slice");
    }
    if (key->backend_kind_len > OVC_CRED_MAX_FIELD_BYTES ||
        key->connection_id_len > OVC_CRED_MAX_FIELD_BYTES ||
        key->field_len > OVC_CRED_MAX_FIELD_BYTES ||
        (include_value && key->value_len > OVC_CRED_MAX_FIELD_BYTES)) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "credential field exceeds the field limit");
    }
    return 1;
}

static int ovc_cred_store_commit(ovc_cred_store *store,
                                 ovc_cred_store_operation *operation,
                                 ovc_cred_error *err)
{
    uint8_t *encoded;
    size_t encoded_len;
    ovc_file file;
    int error_code;
    int temp_exists;

    encoded = NULL;
    encoded_len = 0;
    file = OVC_INVALID_FILE;
    temp_exists = 0;
    if (!ovc_cred_encode(&operation->records,
                         &encoded,
                         &encoded_len,
                         err)) {
        goto fail;
    }

    if (ovc_file_unlink(store->temp_path) != 0 && errno != ENOENT) {
        error_code = errno;
        ovc_cred_store_error_errno(err,
                                   "remove stale credential store temporary file",
                                   store->temp_path,
                                   error_code);
        goto fail;
    }
    file = ovc_private_file_open(store->temp_path,
                                 OVC_PRIVATE_OPEN_CREATE_NEW);
    if (file == OVC_INVALID_FILE) {
        error_code = errno;
        ovc_cred_store_error_errno(err,
                                   "create credential store temporary file",
                                   store->temp_path,
                                   error_code);
        goto fail;
    }
    temp_exists = 1;
    if (ovc_file_write_all_from_start(file, encoded, encoded_len) != 0) {
        error_code = errno;
        ovc_cred_store_error_errno(err,
                                   "write credential store temporary file",
                                   store->temp_path,
                                   error_code);
        goto fail;
    }
    if (ovc_file_sync(file) != 0) {
        error_code = errno;
        ovc_cred_store_error_errno(err,
                                   "sync credential store temporary file",
                                   store->temp_path,
                                   error_code);
        goto fail;
    }
    if (ovc_file_close(file) != 0) {
        error_code = errno;
        file = OVC_INVALID_FILE;
        ovc_cred_store_error_errno(err,
                                   "close credential store temporary file",
                                   store->temp_path,
                                   error_code);
        goto fail;
    }
    file = OVC_INVALID_FILE;
    if (ovc_file_rename_replace(store->temp_path, store->record_path) != 0) {
        error_code = errno;
        ovc_cred_store_error_errno(err,
                                   "replace credential store file from",
                                   store->temp_path,
                                   error_code);
        goto fail;
    }
    temp_exists = 0;
    if (ovc_dir_sync(store->dir) != 0) {
        error_code = errno;
        ovc_cred_store_error_errno(
            err,
            "credential store record was replaced; sync directory",
            store->dir,
            error_code);
        goto fail;
    }

    ovc_cred_store_bytes_clear(&encoded, encoded_len);
    ovc_cred_store_operation_finish(operation);
    return 1;

fail:
    if (file != OVC_INVALID_FILE) {
        (void)ovc_file_close(file);
    }
    if (temp_exists) {
        (void)ovc_file_unlink(store->temp_path);
    }
    ovc_cred_store_bytes_clear(&encoded, encoded_len);
    ovc_cred_store_operation_finish(operation);
    return 0;
}

int ovc_cred_store_get(ovc_cred_store *store,
                       const ovc_cred_record *key,
                       uint8_t **out_copy,
                       size_t *out_len,
                       int *out_found,
                       ovc_cred_error *err)
{
    ovc_cred_store_operation operation;
    ovc_cred_record *found;
    uint8_t *copy;

    ovc_cred_error_reset(err);
    if (out_copy != NULL) {
        *out_copy = NULL;
    }
    if (out_len != NULL) {
        *out_len = 0;
    }
    if (out_found != NULL) {
        *out_found = 0;
    }
    if (store == NULL || out_copy == NULL || out_len == NULL ||
        out_found == NULL) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "credential get argument is null");
    }
    if (!ovc_cred_store_key_valid(key, 0, err)) {
        return 0;
    }
    if (!ovc_cred_store_begin(store, &operation, err)) {
        return 0;
    }

    found = ovc_cred_records_find(&operation.records,
                                  key->backend_kind,
                                  key->backend_kind_len,
                                  key->connection_id,
                                  key->connection_id_len,
                                  key->field,
                                  key->field_len);
    if (found == NULL) {
        ovc_cred_store_operation_finish(&operation);
        return 1;
    }
    copy = (uint8_t *)ovc_abi_copy_bytes(found->value, found->value_len);
    if (copy == NULL) {
        ovc_cred_error_text(
            err, OVC_CRED_NOMEM, "out of memory copying credential value");
        ovc_cred_store_operation_finish(&operation);
        return 0;
    }
    *out_copy = copy;
    *out_len = found->value_len;
    *out_found = 1;
    ovc_cred_store_operation_finish(&operation);
    return 1;
}

int ovc_cred_store_put(ovc_cred_store *store,
                       const ovc_cred_record *record,
                       ovc_cred_error *err)
{
    ovc_cred_store_operation operation;

    ovc_cred_error_reset(err);
    if (store == NULL) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "credential store is null");
    }
    if (!ovc_cred_store_key_valid(record, 1, err)) {
        return 0;
    }
    if (!ovc_cred_store_begin(store, &operation, err)) {
        return 0;
    }
    if (!ovc_cred_records_upsert(&operation.records,
                                  record->backend_kind,
                                  record->backend_kind_len,
                                  record->connection_id,
                                  record->connection_id_len,
                                  record->field,
                                  record->field_len,
                                  record->value,
                                  record->value_len,
                                  err)) {
        ovc_cred_store_operation_finish(&operation);
        return 0;
    }
    return ovc_cred_store_commit(store, &operation, err);
}

int ovc_cred_store_delete(ovc_cred_store *store,
                          const ovc_cred_record *key,
                          ovc_cred_error *err)
{
    ovc_cred_store_operation operation;

    ovc_cred_error_reset(err);
    if (store == NULL) {
        return ovc_cred_error_text(
            err, OVC_CRED_INVALID, "credential store is null");
    }
    if (!ovc_cred_store_key_valid(key, 0, err)) {
        return 0;
    }
    if (!ovc_cred_store_begin(store, &operation, err)) {
        return 0;
    }
    if (!ovc_cred_records_remove(&operation.records,
                                 key->backend_kind,
                                 key->backend_kind_len,
                                 key->connection_id,
                                 key->connection_id_len,
                                 key->field,
                                 key->field_len)) {
        ovc_cred_store_operation_finish(&operation);
        return 1;
    }
    return ovc_cred_store_commit(store, &operation, err);
}

#if defined(OVC_CREDENTIAL_STORE_TEST_MAIN)

#if defined(NDEBUG)
#error "OVC_CREDENTIAL_STORE_TEST_MAIN requires assertions to be enabled"
#endif

static size_t g_ovc_cred_test_release_count;

static void ovc_cred_test_observe_release(const uint8_t *bytes, size_t len)
{
    size_t index;

    assert(bytes != NULL);
    assert(len != 0);
    for (index = 0; index < len; ++index) {
        assert(bytes[index] == 0);
    }
    ++g_ovc_cred_test_release_count;
}

static void ovc_cred_test_assert_record_equal(
    const ovc_cred_record *left,
    const ovc_cred_record *right)
{
    assert(ovc_cred_slice_equal(left->backend_kind,
                                left->backend_kind_len,
                                right->backend_kind,
                                right->backend_kind_len));
    assert(ovc_cred_slice_equal(left->connection_id,
                                left->connection_id_len,
                                right->connection_id,
                                right->connection_id_len));
    assert(ovc_cred_slice_equal(left->field,
                                left->field_len,
                                right->field,
                                right->field_len));
    assert(ovc_cred_slice_equal(left->value,
                                left->value_len,
                                right->value,
                                right->value_len));
}

static void ovc_cred_test_round_trip(void)
{
    static uint8_t empty_sentinel;
    static uint8_t binary_backend[] = {0xff, 0x00, 0x7f};
    static uint8_t binary_connection[] = {0x80, 0x01};
    static uint8_t binary_field[] = {0x00, 0xfe};
    static uint8_t binary_value[] = {0x00, 0xff, 0x80, 0x42};
    ovc_cred_record items[4];
    ovc_cred_records source;
    ovc_cred_records decoded;
    ovc_cred_error error;
    uint8_t *encoded;
    size_t encoded_len;
    size_t index;

    memset(items, 0, sizeof(items));
    items[0].backend_kind = (uint8_t *)(void *)"s3";
    items[0].backend_kind_len = 2;
    items[0].connection_id = (uint8_t *)(void *)"connection-a";
    items[0].connection_id_len = 12;
    items[0].field = (uint8_t *)(void *)"token";
    items[0].field_len = 5;
    items[0].value = &empty_sentinel;
    items[0].value_len = 0;

    items[1].backend_kind = &empty_sentinel;
    items[1].backend_kind_len = 0;
    items[1].connection_id = (uint8_t *)(void *)"connection-b";
    items[1].connection_id_len = 12;
    items[1].field = (uint8_t *)(void *)"token";
    items[1].field_len = 5;
    items[1].value = (uint8_t *)(void *)"value-b";
    items[1].value_len = 7;

    items[2].backend_kind = (uint8_t *)(void *)"gcs";
    items[2].backend_kind_len = 3;
    items[2].connection_id = (uint8_t *)(void *)"connection-c";
    items[2].connection_id_len = 12;
    items[2].field = &empty_sentinel;
    items[2].field_len = 0;
    items[2].value = (uint8_t *)(void *)"value-c";
    items[2].value_len = 7;

    items[3].backend_kind = binary_backend;
    items[3].backend_kind_len = sizeof(binary_backend);
    items[3].connection_id = binary_connection;
    items[3].connection_id_len = sizeof(binary_connection);
    items[3].field = binary_field;
    items[3].field_len = sizeof(binary_field);
    items[3].value = binary_value;
    items[3].value_len = sizeof(binary_value);

    source.items = items;
    source.count = sizeof(items) / sizeof(items[0]);
    memset(&decoded, 0, sizeof(decoded));
    assert(ovc_cred_encode(&source, &encoded, &encoded_len, &error));
    assert(error.status == OVC_CRED_OK);
    assert(error.message[0] == '\0');
    assert(ovc_cred_decode(encoded, encoded_len, &decoded, &error));
    assert(decoded.count == source.count);
    for (index = 0; index < source.count; ++index) {
        ovc_cred_test_assert_record_equal(&source.items[index],
                                          &decoded.items[index]);
    }
    assert(ovc_cred_records_find(&decoded,
                                 binary_backend,
                                 sizeof(binary_backend),
                                 binary_connection,
                                 sizeof(binary_connection),
                                 binary_field,
                                 sizeof(binary_field)) == &decoded.items[3]);
    ovc_cred_records_clear(&decoded);
    ovc_secure_zero(encoded, encoded_len);
    free(encoded);
}

static void ovc_cred_test_expect_decode_failure(const uint8_t *bytes,
                                                size_t len,
                                                ovc_cred_status status)
{
    ovc_cred_records decoded;
    ovc_cred_error error;

    decoded.items = (ovc_cred_record *)(uintptr_t)1;
    decoded.count = 99;
    memset(&error, 0, sizeof(error));
    assert(!ovc_cred_decode(bytes, len, &decoded, &error));
    assert(decoded.items == NULL);
    assert(decoded.count == 0);
    assert(error.status == status);
    assert(error.message[0] != '\0');
}

static uint8_t *ovc_cred_test_copy(const uint8_t *bytes, size_t len)
{
    uint8_t *copy;

    copy = (uint8_t *)malloc(len);
    assert(copy != NULL);
    memcpy(copy, bytes, len);
    return copy;
}

static void ovc_cred_test_corruption(void)
{
    static uint8_t key[] = {'k'};
    static uint8_t value[] = {'v'};
    ovc_cred_record item;
    ovc_cred_records source;
    ovc_cred_error error;
    uint8_t *encoded;
    uint8_t *changed;
    size_t encoded_len;
    size_t index;

    memset(&item, 0, sizeof(item));
    item.backend_kind = key;
    item.backend_kind_len = sizeof(key);
    item.connection_id = key;
    item.connection_id_len = sizeof(key);
    item.field = key;
    item.field_len = sizeof(key);
    item.value = value;
    item.value_len = sizeof(value);
    source.items = &item;
    source.count = 1;
    assert(ovc_cred_encode(&source, &encoded, &encoded_len, &error));

    ovc_cred_test_expect_decode_failure(NULL, 0, OVC_CRED_CORRUPT);

    changed = ovc_cred_test_copy(encoded, encoded_len);
    changed[0] ^= 1;
    ovc_cred_test_expect_decode_failure(changed,
                                        encoded_len,
                                        OVC_CRED_CORRUPT);
    free(changed);

    changed = ovc_cred_test_copy(encoded, encoded_len);
    ovc_cred_write_u32(changed + 16, OVC_CRED_FORMAT_VERSION + 1);
    ovc_cred_test_expect_decode_failure(changed,
                                        encoded_len,
                                        OVC_CRED_NEWER_FORMAT);
    free(changed);

    changed = ovc_cred_test_copy(encoded, encoded_len);
    ovc_cred_write_u32(changed + 16, 0);
    ovc_cred_test_expect_decode_failure(changed,
                                        encoded_len,
                                        OVC_CRED_CORRUPT);
    free(changed);

    for (index = 0; index < 4; ++index) {
        changed = ovc_cred_test_copy(encoded, encoded_len);
        ovc_cred_write_u32(changed + OVC_CRED_HEADER_BYTES + index * 4,
                           OVC_CRED_MAX_FIELD_BYTES + 1);
        ovc_cred_test_expect_decode_failure(changed,
                                            encoded_len,
                                            OVC_CRED_CORRUPT);
        free(changed);
    }

    changed = (uint8_t *)malloc(encoded_len + 1);
    assert(changed != NULL);
    memcpy(changed, encoded, encoded_len);
    changed[encoded_len] = 0;
    ovc_cred_test_expect_decode_failure(changed,
                                        encoded_len + 1,
                                        OVC_CRED_CORRUPT);
    free(changed);

    changed = ovc_cred_test_copy(encoded, encoded_len);
    ovc_cred_write_u32(changed + 20, UINT32_MAX);
    ovc_cred_test_expect_decode_failure(changed,
                                        encoded_len,
                                        OVC_CRED_CORRUPT);
    free(changed);

    for (index = 0; index < encoded_len; ++index) {
        ovc_cred_test_expect_decode_failure(encoded,
                                            index,
                                            OVC_CRED_CORRUPT);
    }
    for (index = encoded_len - OVC_CRED_CHECKSUM_BYTES;
         index < encoded_len;
         ++index) {
        changed = ovc_cred_test_copy(encoded, encoded_len);
        changed[index] ^= 1;
        ovc_cred_test_expect_decode_failure(changed,
                                            encoded_len,
                                            OVC_CRED_CORRUPT);
        free(changed);
    }

    ovc_secure_zero(encoded, encoded_len);
    free(encoded);
}

static void ovc_cred_test_duplicate_key(void)
{
    static uint8_t backend[] = {'s', '3'};
    static uint8_t connection[] = {'c'};
    static uint8_t field[] = {'f'};
    static uint8_t first_value[] = {1};
    static uint8_t second_value[] = {2};
    ovc_cred_record items[2];
    ovc_cred_records source;
    ovc_cred_error error;
    uint8_t *encoded;
    size_t encoded_len;

    memset(items, 0, sizeof(items));
    items[0].backend_kind = backend;
    items[0].backend_kind_len = sizeof(backend);
    items[0].connection_id = connection;
    items[0].connection_id_len = sizeof(connection);
    items[0].field = field;
    items[0].field_len = sizeof(field);
    items[0].value = first_value;
    items[0].value_len = sizeof(first_value);
    items[1] = items[0];
    items[1].value = second_value;
    items[1].value_len = sizeof(second_value);
    source.items = items;
    source.count = 2;

    assert(ovc_cred_encode(&source, &encoded, &encoded_len, &error));
    ovc_cred_test_expect_decode_failure(encoded,
                                        encoded_len,
                                        OVC_CRED_CORRUPT);
    ovc_secure_zero(encoded, encoded_len);
    free(encoded);
}

static void ovc_cred_test_mutation_and_wipe(void)
{
    static uint8_t backend[] = {'s', '3'};
    static uint8_t connection[] = {'c'};
    static uint8_t field[] = {'f'};
    static uint8_t first_value[] = {1, 2, 3};
    static uint8_t second_value[] = {4, 5};
    ovc_cred_records records;
    ovc_cred_error error;
    ovc_cred_record *found;

    memset(&records, 0, sizeof(records));
    g_ovc_cred_test_release_count = 0;
    ovc_cred_test_set_release_observer(ovc_cred_test_observe_release);
    assert(ovc_cred_records_upsert(&records,
                                   backend,
                                   sizeof(backend),
                                   connection,
                                   sizeof(connection),
                                   field,
                                   sizeof(field),
                                   first_value,
                                   sizeof(first_value),
                                   &error));
    assert(records.count == 1);
    assert(ovc_cred_records_upsert(&records,
                                   backend,
                                   sizeof(backend),
                                   connection,
                                   sizeof(connection),
                                   field,
                                   sizeof(field),
                                   second_value,
                                   sizeof(second_value),
                                   &error));
    assert(records.count == 1);
    assert(g_ovc_cred_test_release_count == 1);
    found = ovc_cred_records_find(&records,
                                  backend,
                                  sizeof(backend),
                                  connection,
                                  sizeof(connection),
                                  field,
                                  sizeof(field));
    assert(found != NULL);
    assert(found->value_len == sizeof(second_value));
    assert(memcmp(found->value, second_value, sizeof(second_value)) == 0);
    assert(ovc_cred_records_remove(&records,
                                   backend,
                                   sizeof(backend),
                                   connection,
                                   sizeof(connection),
                                   field,
                                   sizeof(field)));
    assert(records.count == 0);
    assert(g_ovc_cred_test_release_count == 2);
    assert(!ovc_cred_records_remove(&records,
                                    backend,
                                    sizeof(backend),
                                    connection,
                                    sizeof(connection),
                                    field,
                                    sizeof(field)));
    ovc_cred_records_clear(&records);
    ovc_cred_test_set_release_observer(NULL);
}

static void ovc_cred_test_encode_limits(void)
{
    static uint8_t byte;
    ovc_cred_record item;
    ovc_cred_records records;
    ovc_cred_error error;
    uint8_t *encoded;
    size_t encoded_len;

    memset(&item, 0, sizeof(item));
    item.backend_kind = &byte;
    item.backend_kind_len = OVC_CRED_MAX_FIELD_BYTES + 1;
    records.items = &item;
    records.count = 1;
    assert(!ovc_cred_encode(&records, &encoded, &encoded_len, &error));
    assert(error.status == OVC_CRED_INVALID);
    assert(error.message[0] != '\0');

    item.backend_kind_len = OVC_CRED_MAX_FIELD_BYTES;
    item.connection_id = &byte;
    item.connection_id_len = OVC_CRED_MAX_FIELD_BYTES;
    item.field = &byte;
    item.field_len = OVC_CRED_MAX_FIELD_BYTES;
    item.value = &byte;
    item.value_len = OVC_CRED_MAX_FIELD_BYTES;
    assert(!ovc_cred_encode(&records, &encoded, &encoded_len, &error));
    assert(error.status == OVC_CRED_INVALID);
    assert(error.message[0] != '\0');
}

static void ovc_cred_test_namespaces(void)
{
    char too_long[OVC_CRED_NAMESPACE_MAX + 2];
    char non_ascii[3];

    memset(too_long, 'a', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';
    non_ascii[0] = 'a';
    non_ascii[1] = (char)(unsigned char)0x80;
    non_ascii[2] = '\0';

    assert(ovc_cred_namespace_valid("default"));
    assert(ovc_cred_namespace_valid("my-app.v2"));
    assert(!ovc_cred_namespace_valid(""));
    assert(!ovc_cred_namespace_valid(".hidden"));
    assert(!ovc_cred_namespace_valid(".."));
    assert(!ovc_cred_namespace_valid("a/b"));
    assert(!ovc_cred_namespace_valid("a\\b"));
    assert(!ovc_cred_namespace_valid(too_long));
    assert(!ovc_cred_namespace_valid(non_ascii));
}

static int ovc_cred_test_path_exists(const char *path)
{
#if defined(_WIN32)
    wchar_t *wide;
    DWORD attributes;

    wide = ovc_utf8_to_wide(path);
    assert(wide != NULL);
    attributes = GetFileAttributesW(wide);
    free(wide);
    return attributes != INVALID_FILE_ATTRIBUTES;
#else
    struct stat status;

    return lstat(path, &status) == 0;
#endif
}

static void ovc_cred_test_remove_file(const char *path)
{
    if (ovc_file_unlink(path) != 0) {
        assert(errno == ENOENT);
    }
}

static void ovc_cred_test_remove_dir(const char *path)
{
#if defined(_WIN32)
    wchar_t *wide;

    wide = ovc_utf8_to_wide(path);
    assert(wide != NULL);
    assert(RemoveDirectoryW(wide));
    free(wide);
#else
    assert(rmdir(path) == 0);
#endif
}

static void ovc_cred_test_write_file(const char *path,
                                     const uint8_t *bytes,
                                     size_t len)
{
    ovc_file file;

    if (ovc_file_unlink(path) != 0) {
        assert(errno == ENOENT);
    }
    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_CREATE_NEW);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_file_write_all_from_start(file, bytes, len) == 0);
    assert(ovc_file_sync(file) == 0);
    assert(ovc_file_close(file) == 0);
}

static uint8_t *ovc_cred_test_read_file(const char *path, size_t *out_len)
{
    ovc_file file;
    uint8_t *bytes;

    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_EXISTING);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_file_read_all(file,
                             OVC_CRED_MAX_FILE_BYTES,
                             &bytes,
                             out_len) == 0);
    assert(ovc_file_close(file) == 0);
    return bytes;
}

static void ovc_cred_test_assert_file_equal(const char *path,
                                            const uint8_t *expected,
                                            size_t expected_len)
{
    uint8_t *actual;
    size_t actual_len;

    actual = ovc_cred_test_read_file(path, &actual_len);
    assert(actual_len == expected_len);
    assert(actual_len == 0 || memcmp(actual, expected, actual_len) == 0);
    ovc_cred_store_bytes_clear(&actual, actual_len);
}

static void ovc_cred_test_expect_store_rejection(
    ovc_cred_store *store,
    const ovc_cred_record *record,
    ovc_cred_status expected_status,
    const char *record_path,
    const uint8_t *expected_bytes,
    size_t expected_len)
{
    ovc_cred_error error;
    uint8_t *copy;
    size_t copy_len;
    int found;

    copy = (uint8_t *)(uintptr_t)1;
    copy_len = 99;
    found = 1;
    assert(!ovc_cred_store_get(store,
                               record,
                               &copy,
                               &copy_len,
                               &found,
                               &error));
    assert(copy == NULL);
    assert(copy_len == 0);
    assert(found == 0);
    assert(error.status == expected_status);
    assert(strstr(error.message, record_path) != NULL);
    ovc_cred_test_assert_file_equal(record_path,
                                    expected_bytes,
                                    expected_len);

    assert(!ovc_cred_store_put(store, record, &error));
    assert(error.status == expected_status);
    assert(strstr(error.message, record_path) != NULL);
    ovc_cred_test_assert_file_equal(record_path,
                                    expected_bytes,
                                    expected_len);

    assert(!ovc_cred_store_delete(store, record, &error));
    assert(error.status == expected_status);
    assert(strstr(error.message, record_path) != NULL);
    ovc_cred_test_assert_file_equal(record_path,
                                    expected_bytes,
                                    expected_len);
}

#if !defined(_WIN32)
static void ovc_cred_test_assert_private_layout(const char *auth_dir,
                                                const char *store_dir,
                                                const char *record_path,
                                                const char *lock_path)
{
    struct stat status;
    DIR *directory;
    struct dirent *entry;
    size_t file_count;

    assert(stat(auth_dir, &status) == 0);
    assert(S_ISDIR(status.st_mode));
    assert((status.st_mode & 0777) == 0700);
    assert(stat(store_dir, &status) == 0);
    assert(S_ISDIR(status.st_mode));
    assert((status.st_mode & 0777) == 0700);
    assert(stat(record_path, &status) == 0);
    assert(S_ISREG(status.st_mode));
    assert((status.st_mode & 0777) == 0600);
    assert(stat(lock_path, &status) == 0);
    assert(S_ISREG(status.st_mode));
    assert((status.st_mode & 0777) == 0600);

    directory = opendir(store_dir);
    assert(directory != NULL);
    file_count = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        assert(strcmp(entry->d_name, "746573742d617070.creds") == 0 ||
               strcmp(entry->d_name, "746573742d617070.lock") == 0);
        ++file_count;
    }
    assert(closedir(directory) == 0);
    assert(file_count == 2);
}
#endif

static void ovc_cred_test_durable_store(void)
{
    static uint8_t backend[] = {'s', '3'};
    static uint8_t connection[] = {'p', 'r', 'o', 'd'};
    static uint8_t field[] = {'t', 'o', 'k', 'e', 'n'};
    static uint8_t first_value[] = {0, 1, 2, 0xff};
    static uint8_t second_value[] = {9, 8, 7};
    static uint8_t garbage[] = {'n', 'o', 't', '-', 'a', '-', 's', 't', 'o', 'r', 'e'};
    static uint8_t stale[] = {'s', 't', 'a', 'l', 'e'};
    char scratch[OVC_TEMP_DIR_PATH_MAX];
    ovc_cred_store *first;
    ovc_cred_store *second;
    ovc_cred_store *other;
    ovc_cred_store *case_variant;
    ovc_cred_store *unavailable;
    ovc_cred_error error;
    ovc_cred_record record;
    uint8_t *copy;
    uint8_t *valid;
    uint8_t *changed;
    size_t copy_len;
    size_t valid_len;
    int found;
    char *auth_dir;
    char *store_dir;
    char *record_path;
    char *temp_path;
    char *lock_path;
    char *other_record_path;
    char *other_temp_path;
    char *other_lock_path;
    char *case_record_path;
    char *case_temp_path;
    char *case_lock_path;
    char *blocker;
    char *blocked_auth;

    assert(ovc_temp_dir_create("ovstorage-credential-store",
                               scratch,
                               sizeof(scratch)) == 0);
    auth_dir = ovc_path_join(scratch, "auth");
    assert(auth_dir != NULL);
    store_dir = ovc_path_join(auth_dir, "c-credentials");
    assert(store_dir != NULL);
    record_path = ovc_path_join(store_dir, "746573742d617070.creds");
    temp_path = ovc_path_join(store_dir, "746573742d617070.creds.tmp");
    lock_path = ovc_path_join(store_dir, "746573742d617070.lock");
    other_record_path = ovc_path_join(store_dir, "6f746865722d617070.creds");
    other_temp_path = ovc_path_join(store_dir,
                                    "6f746865722d617070.creds.tmp");
    other_lock_path = ovc_path_join(store_dir, "6f746865722d617070.lock");
    case_record_path = ovc_path_join(store_dir, "546573742d417070.creds");
    case_temp_path = ovc_path_join(store_dir,
                                   "546573742d417070.creds.tmp");
    case_lock_path = ovc_path_join(store_dir, "546573742d417070.lock");
    assert(record_path != NULL && temp_path != NULL && lock_path != NULL);
    assert(other_record_path != NULL && other_temp_path != NULL &&
           other_lock_path != NULL);
    assert(case_record_path != NULL && case_temp_path != NULL &&
           case_lock_path != NULL);

    assert(ovc_cred_store_open(auth_dir, "test-app", &first, &error));
    assert(ovc_cred_store_open(auth_dir, "test-app", &second, &error));
    assert(ovc_cred_store_open(auth_dir, "other-app", &other, &error));
    assert(ovc_cred_store_open(auth_dir, "Test-App", &case_variant, &error));
    assert(!ovc_cred_test_path_exists(auth_dir));
    assert(!ovc_cred_store_open(auth_dir, "../escape", &unavailable, &error));
    assert(error.status == OVC_CRED_INVALID);

    memset(&record, 0, sizeof(record));
    record.backend_kind = backend;
    record.backend_kind_len = sizeof(backend);
    record.connection_id = connection;
    record.connection_id_len = sizeof(connection);
    record.field = field;
    record.field_len = sizeof(field);
    record.value = first_value;
    record.value_len = sizeof(first_value);

    assert(ovc_cred_store_put(first, &record, &error));
    assert(error.status == OVC_CRED_OK);
    assert(!ovc_cred_test_path_exists(temp_path));
#if !defined(_WIN32)
    ovc_cred_test_assert_private_layout(auth_dir,
                                        store_dir,
                                        record_path,
                                        lock_path);
#endif

    copy = NULL;
    copy_len = 0;
    found = 0;
    assert(ovc_cred_store_get(second,
                              &record,
                              &copy,
                              &copy_len,
                              &found,
                              &error));
    assert(found);
    assert(copy_len == sizeof(first_value));
    assert(memcmp(copy, first_value, copy_len) == 0);
    ovc_secure_zero(copy, copy_len);
    ovc_abi_free(copy);

    record.value = second_value;
    record.value_len = sizeof(second_value);
    assert(ovc_cred_store_put(case_variant, &record, &error));
    assert(strcmp(record_path, case_record_path) != 0);
    assert(ovc_cred_test_path_exists(record_path));
    assert(ovc_cred_test_path_exists(case_record_path));

    copy = NULL;
    assert(ovc_cred_store_get(first,
                              &record,
                              &copy,
                              &copy_len,
                              &found,
                              &error));
    assert(found);
    assert(copy_len == sizeof(first_value));
    assert(memcmp(copy, first_value, copy_len) == 0);
    ovc_secure_zero(copy, copy_len);
    ovc_abi_free(copy);

    copy = NULL;
    assert(ovc_cred_store_get(case_variant,
                              &record,
                              &copy,
                              &copy_len,
                              &found,
                              &error));
    assert(found);
    assert(copy_len == sizeof(second_value));
    assert(memcmp(copy, second_value, copy_len) == 0);
    ovc_secure_zero(copy, copy_len);
    ovc_abi_free(copy);

    copy = NULL;
    assert(ovc_cred_store_get(other,
                              &record,
                              &copy,
                              &copy_len,
                              &found,
                              &error));
    assert(!found);
    assert(copy == NULL);
    assert(copy_len == 0);

    assert(ovc_cred_store_delete(second, &record, &error));
    assert(ovc_cred_store_get(first,
                              &record,
                              &copy,
                              &copy_len,
                              &found,
                              &error));
    assert(!found);
    assert(ovc_cred_store_delete(first, &record, &error));

    ovc_cred_test_write_file(temp_path, stale, sizeof(stale));
    record.value = second_value;
    record.value_len = sizeof(second_value);
    assert(ovc_cred_store_put(first, &record, &error));
    assert(!ovc_cred_test_path_exists(temp_path));
    copy = NULL;
    assert(ovc_cred_store_get(second,
                              &record,
                              &copy,
                              &copy_len,
                              &found,
                              &error));
    assert(found);
    assert(copy_len == sizeof(second_value));
    assert(memcmp(copy, second_value, copy_len) == 0);
    ovc_secure_zero(copy, copy_len);
    ovc_abi_free(copy);

    valid = ovc_cred_test_read_file(record_path, &valid_len);
    ovc_cred_test_write_file(record_path, garbage, sizeof(garbage));
    ovc_cred_test_expect_store_rejection(first,
                                         &record,
                                         OVC_CRED_CORRUPT,
                                         record_path,
                                         garbage,
                                         sizeof(garbage));

    assert(valid_len > 1);
    ovc_cred_test_write_file(record_path, valid, valid_len - 1);
    ovc_cred_test_expect_store_rejection(first,
                                         &record,
                                         OVC_CRED_CORRUPT,
                                         record_path,
                                         valid,
                                         valid_len - 1);

    changed = ovc_cred_test_copy(valid, valid_len);
    ovc_cred_write_u32(changed + 16, OVC_CRED_FORMAT_VERSION + 1);
    ovc_cred_test_write_file(record_path, changed, valid_len);
    ovc_cred_test_expect_store_rejection(first,
                                         &record,
                                         OVC_CRED_NEWER_FORMAT,
                                         record_path,
                                         changed,
                                         valid_len);
    ovc_cred_store_bytes_clear(&changed, valid_len);
    ovc_cred_test_write_file(record_path, valid, valid_len);
    ovc_cred_store_bytes_clear(&valid, valid_len);

    blocker = ovc_path_join(scratch, "regular-file");
    assert(blocker != NULL);
    ovc_cred_test_write_file(blocker, stale, sizeof(stale));
    blocked_auth = ovc_path_join(blocker, "auth");
    assert(blocked_auth != NULL);
    assert(ovc_cred_store_open(blocked_auth,
                               "test-app",
                               &unavailable,
                               &error));
    assert(!ovc_cred_store_put(unavailable, &record, &error));
    assert(error.status == OVC_CRED_UNAVAILABLE);
    assert(strstr(error.message, blocked_auth) != NULL);
    ovc_cred_store_close(unavailable);
    free(blocked_auth);
    ovc_cred_test_remove_file(blocker);
    free(blocker);

#if !defined(_WIN32)
    {
        ovc_cred_store *linked;
        char *linked_auth;
        char *linked_store_dir;
        char *link_target;

        linked_auth = ovc_path_join(scratch, "linked-auth");
        link_target = ovc_path_join(scratch, "link-target");
        assert(linked_auth != NULL && link_target != NULL);
        assert(ovc_private_dir_ensure(linked_auth) == 0);
        assert(ovc_private_dir_ensure(link_target) == 0);
        linked_store_dir = ovc_path_join(linked_auth, "c-credentials");
        assert(linked_store_dir != NULL);
        assert(symlink(link_target, linked_store_dir) == 0);
        assert(ovc_cred_store_open(linked_auth,
                                   "test-app",
                                   &linked,
                                   &error));
        assert(!ovc_cred_store_put(linked, &record, &error));
        assert(error.status == OVC_CRED_UNAVAILABLE);
        assert(strstr(error.message, linked_store_dir) != NULL);
        ovc_cred_store_close(linked);
        ovc_cred_test_remove_file(linked_store_dir);
        ovc_cred_test_remove_dir(link_target);
        ovc_cred_test_remove_dir(linked_auth);
        free(linked_store_dir);
        free(link_target);
        free(linked_auth);
    }
#endif

    /* The process driver covers lock timeout: POSIX record locks are
     * process-scoped, so two handles in this suite cannot contend. */
    ovc_cred_store_close(case_variant);
    ovc_cred_store_close(other);
    ovc_cred_store_close(second);
    ovc_cred_store_close(first);
    ovc_cred_test_remove_file(other_temp_path);
    ovc_cred_test_remove_file(other_record_path);
    ovc_cred_test_remove_file(other_lock_path);
    ovc_cred_test_remove_file(case_temp_path);
    ovc_cred_test_remove_file(case_record_path);
    ovc_cred_test_remove_file(case_lock_path);
    ovc_cred_test_remove_file(temp_path);
    ovc_cred_test_remove_file(record_path);
    ovc_cred_test_remove_file(lock_path);
    ovc_cred_test_remove_dir(store_dir);
    ovc_cred_test_remove_dir(auth_dir);
    ovc_cred_test_remove_dir(scratch);
    free(other_lock_path);
    free(other_temp_path);
    free(other_record_path);
    free(case_lock_path);
    free(case_temp_path);
    free(case_record_path);
    free(lock_path);
    free(temp_path);
    free(record_path);
    free(store_dir);
    free(auth_dir);
}

/* A legal but deep auth directory must not cost the diagnostic its reason or
 * its file name. 420 bytes of record path is well past the 320-byte message;
 * the reason has to survive whole, the leaf has to be recognisable, and a
 * path that fits has to read exactly as before. */
static void ovc_cred_test_long_path_diagnostics(void)
{
    static const char reason[] = "bad credential-file magic at byte offset 0";
    static const char leaf[] = "/c-credentials/7472756e632d70726f6265.creds";
    static const char short_path[] = "/tmp/auth/c-credentials/00.creds";
    char long_path[420];
    char system_message[256];
    char expected[400];
    ovc_cred_error error;
    size_t fill;
    size_t length;

    memset(long_path, 'd', sizeof(long_path) - 1);
    long_path[0] = '/';
    fill = sizeof(long_path) - sizeof(leaf);
    memcpy(long_path + fill, leaf, sizeof(leaf));
    assert(strlen(long_path) == sizeof(long_path) - 1);

    memset(&error, 0, sizeof(error));
    (void)ovc_cred_store_error_corrupt(&error,
                                       OVC_CRED_CORRUPT,
                                       long_path,
                                       reason);
    assert(error.status == OVC_CRED_CORRUPT);
    length = strlen(error.message);
    assert(length == sizeof(error.message) - 1);
    assert(strncmp(error.message,
                   "corrupt credential store ...",
                   strlen("corrupt credential store ...")) == 0);
    assert(strstr(error.message, leaf) != NULL);
    assert(strcmp(error.message + length - (sizeof(reason) - 1), reason) == 0);

    (void)ovc_cred_store_error_corrupt(&error,
                                       OVC_CRED_NEWER_FORMAT,
                                       long_path,
                                       reason);
    assert(error.status == OVC_CRED_NEWER_FORMAT);
    assert(strncmp(error.message,
                   "newer-format credential store ...",
                   strlen("newer-format credential store ...")) == 0);
    assert(strstr(error.message, leaf) != NULL);
    assert(strstr(error.message, reason) != NULL);

    ovc_cred_strerror(ENOENT, system_message, sizeof(system_message));
    (void)ovc_cred_store_error_errno(&error, "open", long_path, ENOENT);
    assert(error.status == OVC_CRED_UNAVAILABLE);
    assert(strncmp(error.message, "open ...", strlen("open ...")) == 0);
    assert(strstr(error.message, leaf) != NULL);
    assert(strstr(error.message, " failed: ") != NULL);
    assert(strstr(error.message, system_message) != NULL);

    (void)ovc_cred_store_error_corrupt(&error,
                                       OVC_CRED_CORRUPT,
                                       short_path,
                                       reason);
    assert(snprintf(expected,
                    sizeof(expected),
                    "corrupt credential store %s: %s",
                    short_path,
                    reason) > 0);
    assert(strcmp(error.message, expected) == 0);
    (void)ovc_cred_store_error_errno(&error, "open", short_path, ENOENT);
    assert(snprintf(expected,
                    sizeof(expected),
                    "open %s failed: %s",
                    short_path,
                    system_message) > 0);
    assert(strcmp(error.message, expected) == 0);
}

int main(void)
{
    ovc_cred_test_round_trip();
    ovc_cred_test_corruption();
    ovc_cred_test_long_path_diagnostics();
    ovc_cred_test_duplicate_key();
    ovc_cred_test_mutation_and_wipe();
    ovc_cred_test_encode_limits();
    ovc_cred_test_namespaces();
    ovc_cred_test_durable_store();
    puts("credential store codec and durable-store tests passed");
    return 0;
}

#endif /* OVC_CREDENTIAL_STORE_TEST_MAIN */
