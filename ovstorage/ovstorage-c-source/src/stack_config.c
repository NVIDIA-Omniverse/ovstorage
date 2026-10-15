/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Declarative [ovstorage] TOML loading and translation to the C Stack builder.
 */

#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "internal.h"

#include "ovstorage_defaults.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#if !defined(_WIN32)
#include <sys/stat.h>
extern char **environ;
#endif

static double ovc_config_strtod_c_locale(const char *text, char **end)
{
    double value;
    int saved_error;

#if defined(_WIN32)
    _locale_t numeric_locale;

    numeric_locale = _create_locale(LC_NUMERIC, "C");
    if (numeric_locale == NULL) {
        if (end != NULL) {
            *end = (char *)text;
        }
        return 0.0;
    }
    value = _strtod_l(text, end, numeric_locale);
    saved_error = errno;
    _free_locale(numeric_locale);
#else
    locale_t numeric_locale;

    numeric_locale = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
    if (numeric_locale == (locale_t)0) {
        if (end != NULL) {
            *end = (char *)text;
        }
        return 0.0;
    }
    value = strtod_l(text, end, numeric_locale);
    saved_error = errno;
    freelocale(numeric_locale);
#endif
    errno = saved_error;
    return value;
}

static int ovc_config_format_float_c_locale(char *buffer,
                                             size_t capacity,
                                             double value)
{
    int written;
    int saved_error;

#if defined(_WIN32)
    _locale_t numeric_locale;

    numeric_locale = _create_locale(LC_NUMERIC, "C");
    if (numeric_locale == NULL) {
        return -1;
    }
    written = _snprintf_s_l(buffer,
                            capacity,
                            _TRUNCATE,
                            "%.17g",
                            numeric_locale,
                            value);
    saved_error = errno;
    _free_locale(numeric_locale);
#else
    locale_t numeric_locale;
    locale_t previous_locale;

    numeric_locale = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
    if (numeric_locale == (locale_t)0) {
        return -1;
    }
    previous_locale = uselocale(numeric_locale);
    if (previous_locale == (locale_t)0) {
        saved_error = errno;
        freelocale(numeric_locale);
        errno = saved_error;
        return -1;
    }
    written = snprintf(buffer, capacity, "%.17g", value);
    saved_error = errno;
    (void)uselocale(previous_locale);
    freelocale(numeric_locale);
#endif
    errno = saved_error;
    return written;
}

/* tomlc17 is private implementation detail. Prefix every externally visible
 * parser symbol before including its amalgamated source so embedding
 * ovstorage alongside another tomlc17 user cannot collide at link time. */
#define DATUM_ZERO ovc_toml_datum_zero
#define toml_default_option ovc_toml_default_option
#define toml_equiv ovc_toml_equiv
#define toml_free ovc_toml_free
#define toml_get ovc_toml_get
#define toml_merge ovc_toml_merge
#define toml_parse ovc_toml_parse
#define toml_parse_file ovc_toml_parse_file
#define toml_parse_file_ex ovc_toml_parse_file_ex
#define toml_parse_file_named ovc_toml_parse_file_named
#define toml_parse_named ovc_toml_parse_named
#define toml_seek ovc_toml_seek
#define toml_set_option ovc_toml_set_option
#define strtod ovc_config_strtod_c_locale
#if defined(_MSC_VER)
#pragma warning(push)
/* Keep /WX on ovstorage code while containing known warnings in upstream. */
#pragma warning(disable : 4232 4244 4267 4996)
#endif
#include "vendor/tomlc17/tomlc17.c"
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#undef strtod
#undef toml_set_option
#undef toml_seek
#undef toml_parse_named
#undef toml_parse_file_named
#undef toml_parse_file_ex
#undef toml_parse_file
#undef toml_parse
#undef toml_merge
#undef toml_get
#undef toml_free
#undef toml_equiv
#undef toml_default_option
#undef DATUM_ZERO

#define OVC_STACK_CONFIG_ENV_PREFIX "OVSTORAGE__"
#define OVC_STACK_CONFIG_ENV_PREFIX_LEN 11U
#define OVC_STACK_CONFIG_MAX_DEPTH 128U
#define OVC_EMPTY_KIND "empty"

#if defined(_WIN32)
static const char *ovc_config_strerror(int error)
{
    static __declspec(thread) char message[256];

    if (strerror_s(message, sizeof(message), error) != 0) {
        (void)snprintf(message, sizeof(message), "system error %d", error);
    }
    return message;
}
#else
#define ovc_config_strerror(error) strerror(error)
#endif

struct OvStorage_StackConfig {
    toml_result_t document;
};

typedef struct ovc_config_text {
    char *data;
    size_t len;
    size_t capacity;
} ovc_config_text;

typedef struct ovc_config_env_entry {
    char *text;
} ovc_config_env_entry;

static bool ovc_config_append_value(ovc_config_text *text,
                                    const toml_datum_t *datum,
                                    unsigned depth);

static OvStorage_Status ovc_config_error(OvStorage_Error *out_error,
                                         OvStorage_Status status,
                                         const char *format,
                                         ...)
{
    char message[1024];
    size_t length;
    va_list arguments;

    if (out_error == NULL) {
        return status;
    }
    ovstorage_error_clear(out_error);
    out_error->code = status;
    out_error->code_name = ovc_status_code_name(status);
    if (format == NULL) {
        return status;
    }
    va_start(arguments, format);
    if (vsnprintf(message, sizeof(message), format, arguments) < 0) {
        message[0] = '\0';
    }
    va_end(arguments);
    message[sizeof(message) - 1] = '\0';
    length = strlen(message);
    out_error->message = (char *)malloc(length + 1);
    if (out_error->message != NULL) {
        memcpy(out_error->message, message, length + 1);
    }
    return status;
}

static void ovc_config_success(OvStorage_Error *out_error)
{
    ovstorage_error_clear(out_error);
}

static char *ovc_config_duplicate(const char *value)
{
    size_t length;
    char *copy;

    if (value == NULL) {
        return NULL;
    }
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

static char *ovc_config_slice_duplicate(const char *value, size_t length)
{
    char *copy;

    if (value == NULL || length == SIZE_MAX) {
        return NULL;
    }
    copy = (char *)malloc(length + 1);
    if (copy != NULL) {
        memcpy(copy, value, length);
        copy[length] = '\0';
    }
    return copy;
}

static bool ovc_config_ascii_alpha(unsigned char value)
{
    return (value >= (unsigned char)'A' && value <= (unsigned char)'Z') ||
           (value >= (unsigned char)'a' && value <= (unsigned char)'z');
}

static bool ovc_config_ascii_digit(unsigned char value)
{
    return value >= (unsigned char)'0' && value <= (unsigned char)'9';
}

static bool ovc_config_ascii_alnum(unsigned char value)
{
    return ovc_config_ascii_alpha(value) || ovc_config_ascii_digit(value);
}

static bool ovc_config_text_reserve(ovc_config_text *text, size_t extra)
{
    size_t required;
    size_t capacity;
    char *data;

    if (text == NULL || text->len == SIZE_MAX ||
        extra > SIZE_MAX - text->len - 1) {
        return false;
    }
    required = text->len + extra + 1;
    if (required <= text->capacity) {
        return true;
    }
    capacity = text->capacity == 0 ? 128 : text->capacity;
    while (capacity < required) {
        if (capacity > SIZE_MAX / 2) {
            capacity = required;
            break;
        }
        capacity *= 2;
    }
    data = (char *)realloc(text->data, capacity);
    if (data == NULL) {
        return false;
    }
    text->data = data;
    text->capacity = capacity;
    return true;
}

static bool ovc_config_text_append_n(ovc_config_text *text,
                                     const char *value,
                                     size_t length)
{
    if (value == NULL || !ovc_config_text_reserve(text, length)) {
        return false;
    }
    if (length != 0) {
        memcpy(text->data + text->len, value, length);
        text->len += length;
    }
    text->data[text->len] = '\0';
    return true;
}

static bool ovc_config_text_append(ovc_config_text *text, const char *value)
{
    return value != NULL &&
           ovc_config_text_append_n(text, value, strlen(value));
}

static bool ovc_config_text_append_char(ovc_config_text *text, char value)
{
    return ovc_config_text_append_n(text, &value, 1);
}

static void ovc_config_text_clear(ovc_config_text *text, bool secret)
{
    if (text == NULL) {
        return;
    }
    if (secret && text->data != NULL) {
        ovc_secure_zero(text->data, text->capacity);
    }
    free(text->data);
    memset(text, 0, sizeof(*text));
}

static bool ovc_config_append_toml_string(ovc_config_text *text,
                                          const char *value,
                                          size_t length)
{
    size_t index;
    char escape[7];
    unsigned char byte;

    if (!ovc_config_text_append_char(text, '"')) {
        return false;
    }
    for (index = 0; index < length; ++index) {
        byte = (unsigned char)value[index];
        switch (byte) {
        case '\b':
            if (!ovc_config_text_append(text, "\\b")) return false;
            break;
        case '\t':
            if (!ovc_config_text_append(text, "\\t")) return false;
            break;
        case '\n':
            if (!ovc_config_text_append(text, "\\n")) return false;
            break;
        case '\f':
            if (!ovc_config_text_append(text, "\\f")) return false;
            break;
        case '\r':
            if (!ovc_config_text_append(text, "\\r")) return false;
            break;
        case '"':
            if (!ovc_config_text_append(text, "\\\"")) return false;
            break;
        case '\\':
            if (!ovc_config_text_append(text, "\\\\")) return false;
            break;
        default:
            if (byte < 0x20U || byte == 0x7fU) {
                (void)snprintf(escape, sizeof(escape), "\\u%04X", byte);
                if (!ovc_config_text_append(text, escape)) return false;
            } else if (!ovc_config_text_append_char(text, (char)byte)) {
                return false;
            }
            break;
        }
    }
    return ovc_config_text_append_char(text, '"');
}

static bool ovc_config_slice_valid(const char *value, int length)
{
    size_t size;

    if (value == NULL || length < 0) {
        return false;
    }
    size = (size_t)length;
    return memchr(value, '\0', size) == NULL &&
           ovc_utf8_is_valid(value, size);
}

static bool ovc_config_key_valid(toml_datum_t table, int index)
{
    if (table.type != TOML_TABLE || index < 0 || index >= table.u.tab.size) {
        return false;
    }
    return ovc_config_slice_valid(table.u.tab.key[index],
                                  table.u.tab.len[index]);
}

static bool ovc_config_key_equals(toml_datum_t table,
                                  int index,
                                  const char *key)
{
    size_t key_length;

    if (!ovc_config_key_valid(table, index) || key == NULL) {
        return false;
    }
    key_length = strlen(key);
    return key_length == (size_t)table.u.tab.len[index] &&
           memcmp(table.u.tab.key[index], key, key_length) == 0;
}

static const toml_datum_t *ovc_config_table_get(toml_datum_t table,
                                                const char *key)
{
    int index;

    if (table.type != TOML_TABLE || key == NULL) {
        return NULL;
    }
    for (index = 0; index < table.u.tab.size; ++index) {
        if (ovc_config_key_equals(table, index, key)) {
            return &table.u.tab.value[index];
        }
    }
    return NULL;
}

static bool ovc_config_datum_string_valid(const toml_datum_t *datum)
{
    return datum != NULL && datum->type == TOML_STRING &&
           ovc_config_slice_valid(datum->u.str.ptr, datum->u.str.len);
}

static OvStorage_Status ovc_config_validate_schema(
    const toml_result_t *document,
    OvStorage_Error *out_error)
{
    const toml_datum_t *ovstorage;
    const toml_datum_t *root;
    const toml_datum_t *layers;
    const toml_datum_t *connections;
    int index;
    int child_index;

    if (document == NULL || !document->ok ||
        document->toptab.type != TOML_TABLE) {
        return ovc_config_error(out_error,
                                OvStorage_Status_Internal,
                                "parsed TOML has no top-level table");
    }
    ovstorage = ovc_config_table_get(document->toptab, "ovstorage");
    if (ovstorage == NULL) {
        return OvStorage_Status_Ok;
    }
    if (ovstorage->type != TOML_TABLE) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "invalid ovstorage config: 'ovstorage' must be a table");
    }
    root = ovc_config_table_get(*ovstorage, "root");
    if (root != NULL && !ovc_config_datum_string_valid(root)) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "invalid ovstorage config: 'ovstorage.root' must be a UTF-8 string without NUL bytes");
    }
    layers = ovc_config_table_get(*ovstorage, "layers");
    if (layers != NULL && layers->type != TOML_TABLE) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "invalid ovstorage config: 'ovstorage.layers' must be a table");
    }
    if (layers != NULL) {
        for (index = 0; index < layers->u.tab.size; ++index) {
            const toml_datum_t *layer;
            const toml_datum_t *kind;
            const toml_datum_t *inner;
            const toml_datum_t *children;

            if (!ovc_config_key_valid(*layers, index)) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_InvalidArgument,
                                        "invalid ovstorage config: a layer name is not a UTF-8 C string");
            }
            layer = &layers->u.tab.value[index];
            if (layer->type != TOML_TABLE) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_InvalidArgument,
                                        "invalid ovstorage config: every 'ovstorage.layers' entry must be a table");
            }
            kind = ovc_config_table_get(*layer, "kind");
            inner = ovc_config_table_get(*layer, "inner");
            children = ovc_config_table_get(*layer, "children");
            if (kind != NULL && !ovc_config_datum_string_valid(kind)) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_InvalidArgument,
                                        "invalid ovstorage config: layer 'kind' must be a UTF-8 string without NUL bytes");
            }
            if (inner != NULL && !ovc_config_datum_string_valid(inner)) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_InvalidArgument,
                                        "invalid ovstorage config: layer 'inner' must be a UTF-8 string without NUL bytes");
            }
            if (children != NULL && children->type != TOML_ARRAY) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_InvalidArgument,
                                        "invalid ovstorage config: layer 'children' must be an array of strings");
            }
            if (children != NULL) {
                for (child_index = 0; child_index < children->u.arr.size;
                     ++child_index) {
                    if (!ovc_config_datum_string_valid(
                            &children->u.arr.elem[child_index])) {
                        return ovc_config_error(out_error,
                                                OvStorage_Status_InvalidArgument,
                                                "invalid ovstorage config: layer 'children' must be an array of UTF-8 strings without NUL bytes");
                    }
                }
            }
        }
    }
    connections = ovc_config_table_get(*ovstorage, "connections");
    if (connections != NULL && connections->type != TOML_ARRAY) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "invalid ovstorage config: 'ovstorage.connections' must be an array of tables");
    }
    if (connections != NULL) {
        for (index = 0; index < connections->u.arr.size; ++index) {
            const toml_datum_t *connection;
            const toml_datum_t *backend_kind;
            const toml_datum_t *target;
            const toml_datum_t *display_name;
            const toml_datum_t *config;
            const toml_datum_t *credentials;

            connection = &connections->u.arr.elem[index];
            if (connection->type != TOML_TABLE) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_InvalidArgument,
                                        "invalid ovstorage config: every connection must be a table");
            }
            backend_kind = ovc_config_table_get(*connection, "backend_kind");
            target = ovc_config_table_get(*connection, "target");
            display_name = ovc_config_table_get(*connection, "display_name");
            config = ovc_config_table_get(*connection, "config");
            credentials = ovc_config_table_get(*connection, "credentials");
            if (!ovc_config_datum_string_valid(backend_kind)) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_InvalidArgument,
                                        "invalid ovstorage config: every connection needs a UTF-8 string 'backend_kind'");
            }
            if (target != NULL && !ovc_config_datum_string_valid(target)) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_InvalidArgument,
                                        "invalid ovstorage config: connection 'target' must be a UTF-8 string without NUL bytes");
            }
            if (display_name != NULL &&
                !ovc_config_datum_string_valid(display_name)) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_InvalidArgument,
                                        "invalid ovstorage config: connection 'display_name' must be a UTF-8 string without NUL bytes");
            }
            if (config != NULL && config->type != TOML_TABLE) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_InvalidArgument,
                                        "invalid ovstorage config: connection 'config' must be a table");
            }
            if (credentials != NULL && credentials->type != TOML_TABLE) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_InvalidArgument,
                                        "invalid ovstorage config: connection 'credentials' must be a table of strings");
            }
            if (credentials != NULL) {
                for (child_index = 0;
                     child_index < credentials->u.tab.size;
                     ++child_index) {
                    if (!ovc_config_key_valid(*credentials, child_index) ||
                        !ovc_config_datum_string_valid(
                            &credentials->u.tab.value[child_index])) {
                        return ovc_config_error(out_error,
                                                OvStorage_Status_InvalidArgument,
                                                "invalid ovstorage config: connection credentials must map UTF-8 string keys to strings");
                    }
                }
            }
        }
    }
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_config_adopt_result(
    toml_result_t document,
    OvStorage_StackConfig **out_config,
    OvStorage_Error *out_error)
{
    OvStorage_StackConfig *config;
    OvStorage_Status status;

    status = ovc_config_validate_schema(&document, out_error);
    if (status != OvStorage_Status_Ok) {
        ovc_toml_free(document);
        return status;
    }
    config = (OvStorage_StackConfig *)malloc(sizeof(*config));
    if (config == NULL) {
        ovc_toml_free(document);
        return ovc_config_error(out_error,
                                OvStorage_Status_Internal,
                                "out of memory retaining parsed ovstorage config");
    }
    config->document = document;
    *out_config = config;
    ovc_config_success(out_error);
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_config_parse(const char *source,
                                         size_t source_length,
                                         const char *source_name,
                                         toml_result_t *out_document,
                                         OvStorage_Error *out_error)
{
    toml_result_t document;
    char parser_error[sizeof(document.errmsg)];
    OvStorage_Status status;

    memset(out_document, 0, sizeof(*out_document));
    if (source_length > (size_t)INT_MAX) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "ovstorage config is larger than the parser limit");
    }
    if (!ovc_utf8_is_valid(source, source_length)) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "ovstorage config is not valid UTF-8");
    }
    document = ovc_toml_parse_named(source,
                                    (int)source_length,
                                    source_name);
    if (!document.ok) {
        status = strstr(document.errmsg, "out of memory") == NULL
                     ? OvStorage_Status_InvalidArgument
                     : OvStorage_Status_Internal;
        memcpy(parser_error, document.errmsg, sizeof(parser_error));
        parser_error[sizeof(parser_error) - 1] = '\0';
        ovc_toml_free(document);
        return ovc_config_error(out_error,
                                status,
                                "invalid ovstorage config%s%s%s: %s",
                                source_name == NULL ? "" : " '",
                                source_name == NULL ? "" : source_name,
                                source_name == NULL ? "" : "'",
                                parser_error);
    }
    *out_document = document;
    return OvStorage_Status_Ok;
}

OvStorage_Status ovstorage_stack_config_from_toml_str(
    const char *toml,
    OvStorage_StackConfig **out_config,
    OvStorage_Error *out_error)
{
    toml_result_t document;
    OvStorage_Status status;

    if (out_config == NULL) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "out_config must not be null");
    }
    *out_config = NULL;
    if (toml == NULL) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "toml must not be null");
    }
    status = ovc_config_parse(toml,
                              strlen(toml),
                              NULL,
                              &document,
                              out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    return ovc_config_adopt_result(document, out_config, out_error);
}

static FILE *ovc_config_open_file(const char *path)
{
#if defined(_WIN32)
    wchar_t *wide;
    FILE *file;

    wide = ovc_utf8_to_wide(path);
    if (wide == NULL) {
        return NULL;
    }
    file = NULL;
    if (_wfopen_s(&file, wide, L"rb") != 0) {
        file = NULL;
    }
    free(wide);
    return file;
#else
    return fopen(path, "rb");
#endif
}

static OvStorage_Status ovc_config_read_file(const char *path,
                                             char **out_data,
                                             size_t *out_length,
                                             OvStorage_Error *out_error)
{
    FILE *file;
    char *data;
    char *grown;
    size_t length;
    size_t capacity;
    size_t count;
    int saved_error;

    *out_data = NULL;
    *out_length = 0;
    file = ovc_config_open_file(path);
    if (file == NULL) {
        saved_error = errno;
        return ovc_config_error(out_error,
                                OvStorage_Status_NotFound,
                                "could not read %s: %s",
                                path,
                                ovc_config_strerror(saved_error));
    }
    capacity = 4096;
    data = (char *)malloc(capacity + 1);
    if (data == NULL) {
        (void)fclose(file);
        return ovc_config_error(out_error,
                                OvStorage_Status_Internal,
                                "out of memory reading %s",
                                path);
    }
    length = 0;
    for (;;) {
        if (length == capacity) {
            if (capacity > (size_t)INT_MAX / 2) {
                ovc_secure_zero(data, capacity + 1);
                free(data);
                (void)fclose(file);
                return ovc_config_error(out_error,
                                        OvStorage_Status_InvalidArgument,
                                        "ovstorage config %s is larger than the parser limit",
                                        path);
            }
            capacity *= 2;
            grown = (char *)malloc(capacity + 1);
            if (grown == NULL) {
                ovc_secure_zero(data, capacity / 2 + 1);
                free(data);
                (void)fclose(file);
                return ovc_config_error(out_error,
                                        OvStorage_Status_Internal,
                                        "out of memory reading %s",
                                        path);
            }
            memcpy(grown, data, length);
            ovc_secure_zero(data, capacity / 2 + 1);
            free(data);
            data = grown;
        }
        count = fread(data + length, 1, capacity - length, file);
        length += count;
        if (count == 0) {
            break;
        }
    }
    if (ferror(file)) {
        saved_error = errno;
        ovc_secure_zero(data, capacity + 1);
        free(data);
        (void)fclose(file);
        return ovc_config_error(out_error,
                                OvStorage_Status_NotFound,
                                "could not read %s: %s",
                                path,
                                ovc_config_strerror(saved_error));
    }
    (void)fclose(file);
    data[length] = '\0';
    *out_data = data;
    *out_length = length;
    return OvStorage_Status_Ok;
}

static bool ovc_config_env_has_prefix(const char *entry)
{
    size_t index;

    if (entry == NULL) {
        return false;
    }
    /* Figment represents environment keys as UncasedStr, so its prefix
     * filter is ASCII case-insensitive on every platform. */
    for (index = 0; index < OVC_STACK_CONFIG_ENV_PREFIX_LEN; ++index) {
        unsigned char actual;
        unsigned char expected;

        actual = (unsigned char)entry[index];
        expected = (unsigned char)OVC_STACK_CONFIG_ENV_PREFIX[index];
        if (actual == '\0') {
            return false;
        }
        if (actual >= (unsigned char)'a' &&
            actual <= (unsigned char)'z') {
            actual = (unsigned char)(actual - (unsigned char)'a' +
                                     (unsigned char)'A');
        }
        if (actual != expected) {
            return false;
        }
    }
    return true;
}

static bool ovc_config_env_entries_reserve(ovc_config_env_entry **entries,
                                           size_t *capacity,
                                           size_t required)
{
    size_t next;
    ovc_config_env_entry *grown;

    if (required <= *capacity) {
        return true;
    }
    next = *capacity == 0 ? 8 : *capacity;
    while (next < required) {
        if (next > SIZE_MAX / 2) {
            next = required;
            break;
        }
        next *= 2;
    }
    if (next > SIZE_MAX / sizeof(**entries)) {
        return false;
    }
    grown = (ovc_config_env_entry *)realloc(*entries,
                                            next * sizeof(**entries));
    if (grown == NULL) {
        return false;
    }
    *entries = grown;
    *capacity = next;
    return true;
}

static bool ovc_config_env_entries_push(ovc_config_env_entry **entries,
                                        size_t *length,
                                        size_t *capacity,
                                        char *owned_entry)
{
    if (!ovc_config_env_entries_reserve(entries,
                                        capacity,
                                        *length + 1)) {
        return false;
    }
    (*entries)[*length].text = owned_entry;
    ++*length;
    return true;
}

static void ovc_config_env_entries_clear(ovc_config_env_entry *entries,
                                         size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (entries[index].text != NULL) {
            ovc_secure_zero(entries[index].text,
                            strlen(entries[index].text) + 1);
        }
        free(entries[index].text);
    }
    free(entries);
}

static OvStorage_Status ovc_config_collect_environment(
    ovc_config_env_entry **out_entries,
    size_t *out_length,
    OvStorage_Error *out_error)
{
    ovc_config_env_entry *entries;
    size_t length;
    size_t capacity;
    char *copy;

    entries = NULL;
    length = 0;
    capacity = 0;
#if defined(_WIN32)
    {
        LPWCH environment;
        const wchar_t *cursor;

        environment = GetEnvironmentStringsW();
        if (environment == NULL) {
            return ovc_config_error(out_error,
                                    OvStorage_Status_Internal,
                                    "could not enumerate OVSTORAGE__ environment variables");
        }
        cursor = environment;
        while (*cursor != L'\0') {
            size_t wide_length;

            wide_length = wcslen(cursor);
            copy = ovc_wide_to_utf8(cursor);
            if (copy == NULL) {
                FreeEnvironmentStringsW(environment);
                ovc_config_env_entries_clear(entries, length);
                return ovc_config_error(out_error,
                                        OvStorage_Status_Internal,
                                        "could not decode an environment variable as UTF-8");
            }
            if (ovc_config_env_has_prefix(copy)) {
                if (!ovc_config_env_entries_push(&entries,
                                                  &length,
                                                  &capacity,
                                                  copy)) {
                    ovc_secure_zero(copy, strlen(copy) + 1);
                    free(copy);
                    FreeEnvironmentStringsW(environment);
                    ovc_config_env_entries_clear(entries, length);
                    return ovc_config_error(out_error,
                                            OvStorage_Status_Internal,
                                            "out of memory reading OVSTORAGE__ environment variables");
                }
            } else {
                ovc_secure_zero(copy, strlen(copy) + 1);
                free(copy);
            }
            cursor += wide_length + 1;
        }
        FreeEnvironmentStringsW(environment);
    }
#else
    {
        char **cursor;

        for (cursor = environ; cursor != NULL && *cursor != NULL; ++cursor) {
            if (!ovc_config_env_has_prefix(*cursor)) {
                continue;
            }
            copy = ovc_config_duplicate(*cursor);
            if (copy == NULL ||
                !ovc_config_env_entries_push(&entries,
                                              &length,
                                              &capacity,
                                              copy)) {
                if (copy != NULL) {
                    ovc_secure_zero(copy, strlen(copy) + 1);
                }
                free(copy);
                ovc_config_env_entries_clear(entries, length);
                return ovc_config_error(out_error,
                                        OvStorage_Status_Internal,
                                        "out of memory reading OVSTORAGE__ environment variables");
            }
        }
    }
#endif
    *out_entries = entries;
    *out_length = length;
    return OvStorage_Status_Ok;
}

static bool ovc_config_append_env_key(ovc_config_text *text,
                                      const char *key,
                                      size_t key_length)
{
    size_t segment_start;
    size_t cursor;
    size_t index;
    char *lower;

    if (!ovc_config_text_append(text, "\"ovstorage\".")) {
        return false;
    }
    segment_start = 0;
    cursor = 0;
    while (cursor <= key_length) {
        bool separator;

        separator = cursor == key_length || key[cursor] == '.' ||
                    (cursor + 1 < key_length && key[cursor] == '_' &&
                     key[cursor + 1] == '_');
        if (!separator) {
            ++cursor;
            continue;
        }
        if (cursor == segment_start) {
            return false;
        }
        lower = ovc_config_slice_duplicate(key + segment_start,
                                           cursor - segment_start);
        if (lower == NULL) {
            return false;
        }
        for (index = 0; index < cursor - segment_start; ++index) {
            if (lower[index] >= 'A' && lower[index] <= 'Z') {
                lower[index] = (char)(lower[index] - 'A' + 'a');
            }
        }
        if (!ovc_config_append_toml_string(text,
                                           lower,
                                           cursor - segment_start)) {
            free(lower);
            return false;
        }
        free(lower);
        if (cursor == key_length) {
            break;
        }
        if (!ovc_config_text_append_char(text, '.')) {
            return false;
        }
        cursor += key[cursor] == '.' ? 1 : 2;
        segment_start = cursor;
    }
    return true;
}

static bool ovc_config_env_key_has_empty_segment(const char *key,
                                                 size_t key_length)
{
    size_t segment_start;
    size_t cursor;

    segment_start = 0;
    cursor = 0;
    while (cursor <= key_length) {
        bool separator;

        separator = cursor == key_length || key[cursor] == '.' ||
                    (cursor + 1 < key_length && key[cursor] == '_' &&
                     key[cursor + 1] == '_');
        if (!separator) {
            ++cursor;
            continue;
        }
        if (cursor == segment_start) {
            return true;
        }
        if (cursor == key_length) {
            break;
        }
        cursor += key[cursor] == '.' ? 1 : 2;
        segment_start = cursor;
    }
    return false;
}

typedef struct ovc_config_figment_parser {
    const char *value;
    size_t length;
    size_t cursor;
} ovc_config_figment_parser;

static void ovc_config_figment_skip_space(ovc_config_figment_parser *parser)
{
    while (parser->cursor < parser->length &&
           isspace((unsigned char)parser->value[parser->cursor])) {
        ++parser->cursor;
    }
}

static bool ovc_config_figment_append_quoted(
    ovc_config_figment_parser *parser,
    ovc_config_text *output)
{
    size_t start;
    size_t required;
    size_t index;
    char escaped;

    if (parser->cursor >= parser->length ||
        parser->value[parser->cursor] != '"') {
        return false;
    }
    start = parser->cursor++;
    while (parser->cursor < parser->length) {
        unsigned char byte;

        byte = (unsigned char)parser->value[parser->cursor++];
        if (byte == '"') {
            return ovc_config_text_append_n(
                output,
                parser->value + start,
                parser->cursor - start);
        }
        if (byte < 0x20U || byte == 0x7fU) {
            return false;
        }
        if (byte != '\\') {
            continue;
        }
        if (parser->cursor >= parser->length) {
            return false;
        }
        escaped = parser->value[parser->cursor++];
        if (escaped == 'b' || escaped == 't' || escaped == 'n' ||
            escaped == 'f' || escaped == 'r' || escaped == '"' ||
            escaped == '\\') {
            continue;
        }
        if (escaped != 'u' && escaped != 'U') {
            return false;
        }
        required = escaped == 'u' ? 4 : 8;
        if (required > parser->length - parser->cursor) {
            return false;
        }
        for (index = 0; index < required; ++index) {
            if (!isxdigit(
                    (unsigned char)parser->value[parser->cursor + index])) {
                return false;
            }
        }
        parser->cursor += required;
    }
    return false;
}

static bool ovc_config_figment_append_literal_char(
    ovc_config_figment_parser *parser,
    ovc_config_text *output)
{
    size_t start;
    size_t character_length;
    unsigned char first;

    if (parser->cursor >= parser->length ||
        parser->value[parser->cursor] != '\'') {
        return false;
    }
    ++parser->cursor;
    start = parser->cursor;
    if (start >= parser->length) {
        return false;
    }
    first = (unsigned char)parser->value[start];
    if (first < 0x80U) {
        character_length = 1;
    } else if ((first & 0xe0U) == 0xc0U) {
        character_length = 2;
    } else if ((first & 0xf0U) == 0xe0U) {
        character_length = 3;
    } else {
        character_length = 4;
    }
    if (character_length > parser->length - start) {
        return false;
    }
    parser->cursor += character_length;
    if (parser->cursor >= parser->length ||
        parser->value[parser->cursor] != '\'') {
        return false;
    }
    ++parser->cursor;
    return ovc_config_append_toml_string(output,
                                         parser->value + start,
                                         character_length);
}

static bool ovc_config_figment_append_atom(
    ovc_config_figment_parser *parser,
    ovc_config_text *output)
{
    const char *start;
    const char *end;
    char *copy;
    char *parse_end;
    size_t length;
    intmax_t signed_value;
    uintmax_t unsigned_value;
    double float_value;
    toml_datum_t datum;
    bool numeric;

    start = parser->value + parser->cursor;
    while (parser->cursor < parser->length) {
        char byte;

        byte = parser->value[parser->cursor];
        if (byte == ',' || byte == '{' || byte == '}' ||
            byte == '[' || byte == ']') {
            break;
        }
        ++parser->cursor;
    }
    end = parser->value + parser->cursor;
    while (start < end && isspace((unsigned char)*start)) ++start;
    while (end > start && isspace((unsigned char)end[-1])) --end;
    length = (size_t)(end - start);
    if (length == 4 && memcmp(start, "true", 4) == 0) {
        return ovc_config_text_append(output, "true");
    }
    if (length == 5 && memcmp(start, "false", 5) == 0) {
        return ovc_config_text_append(output, "false");
    }
    copy = ovc_config_slice_duplicate(start, length);
    if (copy == NULL) {
        return false;
    }
    numeric = false;
    if (memchr(copy, '.', length) != NULL) {
        errno = 0;
        parse_end = NULL;
        float_value = ovc_config_strtod_c_locale(copy, &parse_end);
        if (errno != ERANGE && parse_end == copy + length) {
            memset(&datum, 0, sizeof(datum));
            datum.type = TOML_FP64;
            datum.u.fp64 = float_value;
            numeric = ovc_config_append_value(output, &datum, 0);
        }
    } else if (length != 0 && copy[0] == '-') {
        errno = 0;
        parse_end = NULL;
        signed_value = strtoimax(copy, &parse_end, 10);
        if (errno != ERANGE && parse_end == copy + length &&
            signed_value >= INT64_MIN && signed_value <= INT64_MAX) {
            memset(&datum, 0, sizeof(datum));
            datum.type = TOML_INT64;
            datum.u.int64 = (int64_t)signed_value;
            numeric = ovc_config_append_value(output, &datum, 0);
        }
    } else if (length != 0) {
        errno = 0;
        parse_end = NULL;
        unsigned_value = strtoumax(copy, &parse_end, 10);
        if (errno != ERANGE && parse_end == copy + length &&
            unsigned_value <= (uintmax_t)INT64_MAX) {
            memset(&datum, 0, sizeof(datum));
            datum.type = TOML_INT64;
            datum.u.int64 = (int64_t)unsigned_value;
            numeric = ovc_config_append_value(output, &datum, 0);
        }
    }
    ovc_secure_zero(copy, length + 1);
    free(copy);
    if (numeric) {
        return true;
    }
    return ovc_config_append_toml_string(output, start, length);
}

static bool ovc_config_figment_append_value(
    ovc_config_figment_parser *parser,
    ovc_config_text *output,
    unsigned depth);

static bool ovc_config_figment_append_array(
    ovc_config_figment_parser *parser,
    ovc_config_text *output,
    unsigned depth)
{
    bool first;

    if (parser->value[parser->cursor] != '[' ||
        !ovc_config_text_append_char(output, '[')) {
        return false;
    }
    ++parser->cursor;
    first = true;
    for (;;) {
        ovc_config_figment_skip_space(parser);
        if (parser->cursor >= parser->length) {
            return false;
        }
        if (parser->value[parser->cursor] == ']') {
            ++parser->cursor;
            return ovc_config_text_append_char(output, ']');
        }
        if (!first && !ovc_config_text_append(output, ", ")) {
            return false;
        }
        if (!ovc_config_figment_append_value(parser, output, depth + 1)) {
            return false;
        }
        first = false;
        ovc_config_figment_skip_space(parser);
        if (parser->cursor >= parser->length) {
            return false;
        }
        if (parser->value[parser->cursor] == ',') {
            ++parser->cursor;
            continue;
        }
        if (parser->value[parser->cursor] != ']') {
            return false;
        }
    }
}

static bool ovc_config_figment_append_key(
    ovc_config_figment_parser *parser,
    ovc_config_text *output)
{
    size_t start;

    ovc_config_figment_skip_space(parser);
    if (parser->cursor >= parser->length) {
        return false;
    }
    if (parser->value[parser->cursor] == '"') {
        return ovc_config_figment_append_quoted(parser, output);
    }
    start = parser->cursor;
    while (parser->cursor < parser->length) {
        unsigned char byte;

        byte = (unsigned char)parser->value[parser->cursor];
        if (!(ovc_config_ascii_alnum(byte) || byte == '_' || byte == '-')) {
            break;
        }
        ++parser->cursor;
    }
    return parser->cursor != start &&
           ovc_config_append_toml_string(output,
                                         parser->value + start,
                                         parser->cursor - start);
}

static bool ovc_config_figment_append_dict(
    ovc_config_figment_parser *parser,
    ovc_config_text *output,
    unsigned depth)
{
    bool first;

    if (parser->value[parser->cursor] != '{' ||
        !ovc_config_text_append_char(output, '{')) {
        return false;
    }
    ++parser->cursor;
    first = true;
    for (;;) {
        ovc_config_figment_skip_space(parser);
        if (parser->cursor >= parser->length) {
            return false;
        }
        if (parser->value[parser->cursor] == '}') {
            ++parser->cursor;
            return ovc_config_text_append_char(output, '}');
        }
        if (!first && !ovc_config_text_append(output, ", ")) {
            return false;
        }
        if (!ovc_config_figment_append_key(parser, output)) {
            return false;
        }
        ovc_config_figment_skip_space(parser);
        if (parser->cursor >= parser->length ||
            parser->value[parser->cursor] != '=' ||
            !ovc_config_text_append(output, " = ")) {
            return false;
        }
        ++parser->cursor;
        if (!ovc_config_figment_append_value(parser, output, depth + 1)) {
            return false;
        }
        first = false;
        ovc_config_figment_skip_space(parser);
        if (parser->cursor >= parser->length) {
            return false;
        }
        if (parser->value[parser->cursor] == ',') {
            ++parser->cursor;
            continue;
        }
        if (parser->value[parser->cursor] != '}') {
            return false;
        }
    }
}

static bool ovc_config_figment_append_value(
    ovc_config_figment_parser *parser,
    ovc_config_text *output,
    unsigned depth)
{
    if (depth > OVC_STACK_CONFIG_MAX_DEPTH) {
        return false;
    }
    ovc_config_figment_skip_space(parser);
    if (parser->cursor >= parser->length) {
        return ovc_config_text_append(output, "\"\"");
    }
    switch (parser->value[parser->cursor]) {
    case '{':
        return ovc_config_figment_append_dict(parser, output, depth);
    case '[':
        return ovc_config_figment_append_array(parser, output, depth);
    case '"':
        return ovc_config_figment_append_quoted(parser, output);
    case '\'':
        return ovc_config_figment_append_literal_char(parser, output);
    default:
        return ovc_config_figment_append_atom(parser, output);
    }
}

static bool ovc_config_append_figment_value(ovc_config_text *output,
                                            const char *value,
                                            size_t length)
{
    ovc_config_figment_parser parser;
    ovc_config_text canonical;
    bool parsed;

    parser.value = value;
    parser.length = length;
    parser.cursor = 0;
    memset(&canonical, 0, sizeof(canonical));
    parsed = ovc_config_figment_append_value(&parser, &canonical, 0);
    ovc_config_figment_skip_space(&parser);
    parsed = parsed && parser.cursor == parser.length;
    if (!parsed) {
        ovc_config_text_clear(&canonical, true);
        return ovc_config_append_toml_string(output, value, length);
    }
    parsed = ovc_config_text_append_n(output,
                                      canonical.data,
                                      canonical.len);
    ovc_config_text_clear(&canonical, true);
    return parsed;
}

static bool ovc_config_env_key_is_ascii(const char *key, size_t key_length)
{
    size_t index;

    for (index = 0; index < key_length; ++index) {
        if ((unsigned char)key[index] >= 0x80U) {
            return false;
        }
    }
    return true;
}

static OvStorage_Status ovc_config_environment_overlay(
    toml_result_t *out_overlay,
    bool *out_has_overlay,
    OvStorage_Error *out_error)
{
    ovc_config_env_entry *entries;
    size_t entry_count;
    size_t index;
    const char *equals;
    const char *key;
    const char *value;
    size_t key_length;
    size_t value_length;
    char *source_name;
    ovc_config_text document;
    toml_result_t overlay;
    toml_result_t parsed;
    toml_result_t merged;
    bool has_overlay;
    OvStorage_Status status;

    memset(out_overlay, 0, sizeof(*out_overlay));
    *out_has_overlay = false;
    entries = NULL;
    entry_count = 0;
    memset(&document, 0, sizeof(document));
    memset(&overlay, 0, sizeof(overlay));
    has_overlay = false;
    status = ovc_config_collect_environment(&entries,
                                            &entry_count,
                                            out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    for (index = 0; index < entry_count; ++index) {
        equals = strchr(entries[index].text +
                            OVC_STACK_CONFIG_ENV_PREFIX_LEN,
                        '=');
        if (equals == NULL) {
            status = ovc_config_error(out_error,
                                      OvStorage_Status_InvalidArgument,
                                      "invalid OVSTORAGE__ environment key");
            goto fail;
        }
        key = entries[index].text + OVC_STACK_CONFIG_ENV_PREFIX_LEN;
        key_length = (size_t)(equals - key);
        value = equals + 1;
        value_length = strlen(value);
        if (ovc_config_env_key_has_empty_segment(key, key_length)) {
            continue;
        }
        source_name = ovc_config_slice_duplicate(
            entries[index].text,
            (size_t)(equals - entries[index].text));
        if (source_name == NULL) {
            status = ovc_config_error(
                out_error,
                OvStorage_Status_Internal,
                "out of memory applying OVSTORAGE__ environment variables");
            goto fail;
        }
        if (!ovc_config_env_key_is_ascii(key, key_length)) {
            status = ovc_config_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "environment key '%s' uses a non-ASCII OVSTORAGE__ path",
                source_name);
            free(source_name);
            goto fail;
        }
        if (!ovc_utf8_is_valid(value, value_length)) {
            status = ovc_config_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "environment value for '%s' is not valid UTF-8",
                source_name);
            free(source_name);
            goto fail;
        }
        if (!ovc_config_append_env_key(&document, key, key_length) ||
            !ovc_config_text_append(&document, " = ") ||
            !ovc_config_append_figment_value(&document,
                                             value,
                                             value_length) ||
            !ovc_config_text_append_char(&document, '\n')) {
            status = ovc_config_error(
                out_error,
                OvStorage_Status_Internal,
                "out of memory applying environment key '%s'",
                source_name);
            free(source_name);
            goto fail;
        }
        status = ovc_config_parse(document.data,
                                  document.len,
                                  source_name,
                                  &parsed,
                                  out_error);
        ovc_config_text_clear(&document, true);
        if (status != OvStorage_Status_Ok) {
            free(source_name);
            goto fail;
        }
        if (!has_overlay) {
            overlay = parsed;
            has_overlay = true;
        } else {
            merged = ovc_toml_merge(&overlay, &parsed);
            ovc_toml_free(overlay);
            ovc_toml_free(parsed);
            if (!merged.ok) {
                char merge_error[sizeof(merged.errmsg)];

                status = strstr(merged.errmsg, "out of memory") == NULL
                             ? OvStorage_Status_InvalidArgument
                             : OvStorage_Status_Internal;
                memcpy(merge_error, merged.errmsg, sizeof(merge_error));
                merge_error[sizeof(merge_error) - 1] = '\0';
                ovc_toml_free(merged);
                (void)ovc_config_error(
                    out_error,
                    status,
                    "could not apply environment key '%s': %s",
                    source_name,
                    merge_error);
                free(source_name);
                memset(&overlay, 0, sizeof(overlay));
                has_overlay = false;
                goto fail;
            }
            overlay = merged;
        }
        free(source_name);
    }
    ovc_config_env_entries_clear(entries, entry_count);
    *out_overlay = overlay;
    *out_has_overlay = has_overlay;
    return OvStorage_Status_Ok;

fail:
    ovc_config_text_clear(&document, true);
    if (has_overlay) {
        ovc_toml_free(overlay);
    }
    ovc_config_env_entries_clear(entries, entry_count);
    return status;
}

OvStorage_Status ovstorage_stack_config_from_toml_path(
    const char *path,
    OvStorage_StackConfig **out_config,
    OvStorage_Error *out_error)
{
    char *contents;
    size_t contents_length;
    toml_result_t base;
    toml_result_t overlay;
    toml_result_t merged;
    bool has_overlay;
    OvStorage_Status status;

    if (out_config == NULL) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "out_config must not be null");
    }
    *out_config = NULL;
    if (path == NULL || !ovc_utf8_is_valid(path, strlen(path))) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "path must be a valid UTF-8 string");
    }
    contents = NULL;
    status = ovc_config_read_file(path,
                                  &contents,
                                  &contents_length,
                                  out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovc_config_parse(contents,
                              contents_length,
                              path,
                              &base,
                              out_error);
    ovc_secure_zero(contents, contents_length + 1);
    free(contents);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovc_config_environment_overlay(&overlay,
                                            &has_overlay,
                                            out_error);
    if (status != OvStorage_Status_Ok) {
        ovc_toml_free(base);
        return status;
    }
    if (!has_overlay) {
        return ovc_config_adopt_result(base, out_config, out_error);
    }
    merged = ovc_toml_merge(&base, &overlay);
    ovc_toml_free(base);
    ovc_toml_free(overlay);
    if (!merged.ok) {
        char merge_error[sizeof(merged.errmsg)];

        status = strstr(merged.errmsg, "out of memory") == NULL
                     ? OvStorage_Status_InvalidArgument
                     : OvStorage_Status_Internal;
        memcpy(merge_error, merged.errmsg, sizeof(merge_error));
        merge_error[sizeof(merge_error) - 1] = '\0';
        ovc_toml_free(merged);
        return ovc_config_error(
            out_error,
            status,
            "invalid ovstorage config after OVSTORAGE__ overlay: %s",
            merge_error);
    }
    return ovc_config_adopt_result(merged, out_config, out_error);
}

static bool ovc_config_path_is_file(const char *path)
{
#if defined(_WIN32)
    wchar_t *wide;
    DWORD attributes;

    wide = ovc_utf8_to_wide(path);
    if (wide == NULL) {
        return false;
    }
    attributes = GetFileAttributesW(wide);
    free(wide);
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
#else
    struct stat info;

    return stat(path, &info) == 0 && S_ISREG(info.st_mode);
#endif
}

static char *ovc_config_default_user_path(void)
{
    char *base;
    const char *suffix;
    size_t base_length;
    size_t suffix_length;
    size_t separator_length;
    char *path;

    errno = 0;
    base = ovc_env_dup("XDG_CONFIG_HOME");
    suffix = "ovstorage/ovstorage.toml";
    if (base == NULL && errno != 0) {
        return NULL;
    }
    if (base == NULL) {
        errno = 0;
        base = ovc_env_dup("HOME");
        suffix = ".config/ovstorage/ovstorage.toml";
        if (base == NULL && errno != 0) {
            return NULL;
        }
    }
    if (base == NULL) {
        return NULL;
    }
    base_length = strlen(base);
    suffix_length = strlen(suffix);
    separator_length = base_length == 0 || base[base_length - 1] == '/' ||
                               base[base_length - 1] == '\\'
                           ? 0
                           : 1;
    if (base_length > SIZE_MAX - separator_length ||
        base_length + separator_length > SIZE_MAX - suffix_length - 1) {
        free(base);
        errno = ENOMEM;
        return NULL;
    }
    path = (char *)malloc(base_length + separator_length + suffix_length + 1);
    if (path != NULL) {
        memcpy(path, base, base_length);
        if (separator_length != 0) {
            path[base_length] = '/';
        }
        memcpy(path + base_length + separator_length,
               suffix,
               suffix_length + 1);
    } else {
        errno = ENOMEM;
    }
    free(base);
    return path;
}

OvStorage_Status ovstorage_stack_config_from_default_path(
    OvStorage_StackConfig **out_config,
    OvStorage_Error *out_error)
{
    char *user_path;
    OvStorage_Status status;

    if (out_config == NULL) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "out_config must not be null");
    }
    *out_config = NULL;
    if (ovc_config_path_is_file("./ovstorage.toml")) {
        return ovstorage_stack_config_from_toml_path("./ovstorage.toml",
                                                     out_config,
                                                     out_error);
    }
    user_path = ovc_config_default_user_path();
    if (user_path == NULL && errno != 0) {
        return ovc_config_error(out_error,
                                OvStorage_Status_Internal,
                                "could not resolve the default ovstorage config path: %s",
                                ovc_config_strerror(errno));
    }
    if (user_path != NULL && !ovc_utf8_is_valid(user_path, strlen(user_path))) {
        free(user_path);
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "the default ovstorage config path is not valid UTF-8");
    }
    if (user_path != NULL && ovc_config_path_is_file(user_path)) {
        status = ovstorage_stack_config_from_toml_path(user_path,
                                                       out_config,
                                                       out_error);
        free(user_path);
        return status;
    }
    free(user_path);
    ovc_config_success(out_error);
    return OvStorage_Status_Ok;
}

static bool ovc_config_append_timestamp(ovc_config_text *text,
                                        const toml_datum_t *datum)
{
    char buffer[96];
    char fraction[16];
    int written;
    int timezone;
    int timezone_hours;
    int timezone_minutes;
    size_t fraction_length;

    written = 0;
    if (datum->type == TOML_DATE) {
        written = snprintf(buffer,
                           sizeof(buffer),
                           "%04d-%02d-%02d",
                           datum->u.ts.year,
                           datum->u.ts.month,
                           datum->u.ts.day);
    } else if (datum->type == TOML_TIME) {
        written = snprintf(buffer,
                           sizeof(buffer),
                           "%02d:%02d:%02d",
                           datum->u.ts.hour,
                           datum->u.ts.minute,
                           datum->u.ts.second);
    } else {
        written = snprintf(buffer,
                           sizeof(buffer),
                           "%04d-%02d-%02dT%02d:%02d:%02d",
                           datum->u.ts.year,
                           datum->u.ts.month,
                           datum->u.ts.day,
                           datum->u.ts.hour,
                           datum->u.ts.minute,
                           datum->u.ts.second);
    }
    if (written < 0 || (size_t)written >= sizeof(buffer) ||
        !ovc_config_text_append_n(text, buffer, (size_t)written)) {
        return false;
    }
    if (datum->type != TOML_DATE && datum->u.ts.usec > 0) {
        written = snprintf(fraction,
                           sizeof(fraction),
                           ".%09d",
                           (int)datum->u.ts.usec);
        if (written < 0 || (size_t)written >= sizeof(fraction)) {
            return false;
        }
        fraction_length = (size_t)written;
        while (fraction_length > 1 &&
               fraction[fraction_length - 1] == '0') {
            --fraction_length;
        }
        if (!ovc_config_text_append_n(text, fraction, fraction_length)) {
            return false;
        }
    }
    if (datum->type == TOML_DATETIMETZ) {
        timezone = datum->u.ts.tz;
        if (timezone == 0) {
            return ovc_config_text_append_char(text, 'Z');
        }
        timezone_hours = abs(timezone) / 60;
        timezone_minutes = abs(timezone) % 60;
        written = snprintf(buffer,
                           sizeof(buffer),
                           "%c%02d:%02d",
                           timezone < 0 ? '-' : '+',
                           timezone_hours,
                           timezone_minutes);
        if (written < 0 || (size_t)written >= sizeof(buffer)) {
            return false;
        }
        return ovc_config_text_append_n(text, buffer, (size_t)written);
    }
    return true;
}

static bool ovc_config_append_value(ovc_config_text *text,
                                    const toml_datum_t *datum,
                                    unsigned depth)
{
    char number[128];
    int written;
    int index;
    bool needs_float_marker;

    if (datum == NULL || depth > OVC_STACK_CONFIG_MAX_DEPTH) {
        return false;
    }
    switch (datum->type) {
    case TOML_STRING:
        return ovc_config_slice_valid(datum->u.str.ptr, datum->u.str.len) &&
               ovc_config_append_toml_string(text,
                                             datum->u.str.ptr,
                                             (size_t)datum->u.str.len);
    case TOML_INT64:
        written = snprintf(number,
                           sizeof(number),
                           "%" PRId64,
                           datum->u.int64);
        return written >= 0 && (size_t)written < sizeof(number) &&
               ovc_config_text_append_n(text, number, (size_t)written);
    case TOML_FP64:
        if (isnan(datum->u.fp64)) {
            return ovc_config_text_append(text,
                                          signbit(datum->u.fp64)
                                              ? "-nan"
                                              : "nan");
        }
        if (isinf(datum->u.fp64)) {
            return ovc_config_text_append(text,
                                          datum->u.fp64 < 0.0
                                              ? "-inf"
                                              : "inf");
        }
        written = ovc_config_format_float_c_locale(number,
                                                    sizeof(number),
                                                    datum->u.fp64);
        if (written < 0 || (size_t)written >= sizeof(number) ||
            !ovc_config_text_append_n(text, number, (size_t)written)) {
            return false;
        }
        needs_float_marker = strchr(number, '.') == NULL &&
                             strchr(number, 'e') == NULL &&
                             strchr(number, 'E') == NULL;
        return !needs_float_marker || ovc_config_text_append(text, ".0");
    case TOML_BOOLEAN:
        return ovc_config_text_append(text,
                                      datum->u.boolean ? "true" : "false");
    case TOML_DATE:
    case TOML_TIME:
    case TOML_DATETIME:
    case TOML_DATETIMETZ:
        return ovc_config_append_timestamp(text, datum);
    case TOML_ARRAY:
        if (!ovc_config_text_append_char(text, '[')) {
            return false;
        }
        for (index = 0; index < datum->u.arr.size; ++index) {
            if (index != 0 && !ovc_config_text_append(text, ", ")) {
                return false;
            }
            if (!ovc_config_append_value(text,
                                         &datum->u.arr.elem[index],
                                         depth + 1)) {
                return false;
            }
        }
        return ovc_config_text_append_char(text, ']');
    case TOML_TABLE:
        if (!ovc_config_text_append_char(text, '{')) {
            return false;
        }
        for (index = 0; index < datum->u.tab.size; ++index) {
            if (!ovc_config_key_valid(*datum, index)) {
                return false;
            }
            if (index != 0 && !ovc_config_text_append(text, ", ")) {
                return false;
            }
            if (!ovc_config_append_toml_string(
                    text,
                    datum->u.tab.key[index],
                    (size_t)datum->u.tab.len[index]) ||
                !ovc_config_text_append(text, " = ") ||
                !ovc_config_append_value(text,
                                         &datum->u.tab.value[index],
                                         depth + 1)) {
                return false;
            }
        }
        return ovc_config_text_append_char(text, '}');
    default:
        return false;
    }
}

static OvStorage_Status ovc_config_value_create(
    const char *key,
    const toml_datum_t *datum,
    OvStorage_ConfigValue **out_value,
    OvStorage_Error *out_error)
{
    ovc_config_text serialized;

    *out_value = NULL;
    switch (datum->type) {
    case TOML_STRING:
        if (!ovc_config_datum_string_valid(datum)) {
            return ovc_config_error(out_error,
                                    OvStorage_Status_InvalidArgument,
                                    "config field '%s' is not a UTF-8 C string",
                                    key);
        }
        *out_value = ovstorage_config_value_create_string(datum->u.str.ptr);
        break;
    case TOML_INT64:
        *out_value = ovstorage_config_value_create_int(datum->u.int64);
        break;
    case TOML_BOOLEAN:
        *out_value = ovstorage_config_value_create_bool(datum->u.boolean);
        break;
    case TOML_ARRAY:
    case TOML_TABLE:
        memset(&serialized, 0, sizeof(serialized));
        if (!ovc_config_append_toml_string(&serialized,
                                           key,
                                           strlen(key)) ||
            !ovc_config_text_append(&serialized, " = ") ||
            !ovc_config_append_value(&serialized, datum, 0) ||
            !ovc_config_text_append_char(&serialized, '\n')) {
            ovc_config_text_clear(&serialized, false);
            return ovc_config_error(out_error,
                                    OvStorage_Status_Internal,
                                    "config field '%s' could not be serialized",
                                    key);
        }
        *out_value = ovstorage_config_value_create_toml(serialized.data);
        ovc_config_text_clear(&serialized, false);
        break;
    case TOML_FP64:
    case TOML_DATE:
    case TOML_TIME:
    case TOML_DATETIME:
    case TOML_DATETIMETZ:
    default:
        return ovc_config_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "config field '%s' has an unsupported type (only string, integer, boolean, table, and array are accepted)",
            key);
    }
    if (*out_value == NULL) {
        return ovc_config_error(out_error,
                                OvStorage_Status_Internal,
                                "out of memory creating config field '%s'",
                                key);
    }
    return OvStorage_Status_Ok;
}

static void ovc_config_plugin_string_clear(OvStoragePlugin_Str *value)
{
    if (value == NULL) {
        return;
    }
    ovc_abi_free(value->ptr);
    value->ptr = NULL;
    value->len = 0;
}

static void ovc_config_plugin_value_clear(OvStoragePlugin_ConfigValue *value)
{
    if (value == NULL) {
        return;
    }
    if (value->tag == OvStoragePlugin_ConfigValueTag_String) {
        ovc_config_plugin_string_clear(&value->string_value);
    } else if (value->tag == OvStoragePlugin_ConfigValueTag_Toml) {
        ovc_config_plugin_string_clear(&value->toml_value);
    }
}

static void ovc_config_create_backend_request_clear(
    OvStoragePlugin_CreateBackendRequest *request)
{
    size_t index;

    if (request == NULL) {
        return;
    }
    ovc_config_plugin_string_clear(&request->kind);
    ovc_config_plugin_string_clear(&request->instance_id);
    for (index = 0; index < request->config.len; ++index) {
        ovc_config_plugin_string_clear(&request->config.ptr[index].key);
        ovc_config_plugin_value_clear(&request->config.ptr[index].value);
    }
    ovc_abi_free(request->config.ptr);
    request->config.ptr = NULL;
    request->config.len = 0;
}

static OvStoragePlugin_Error *ovc_config_plugin_error(
    OvStoragePlugin_ErrorCode code,
    const char *message)
{
    OvStoragePlugin_Error *error;
    size_t length;

    length = strlen(message);
    error = (OvStoragePlugin_Error *)ovc_abi_alloc(sizeof(*error));
    if (error == NULL) {
        abort();
    }
    memset(error, 0, sizeof(*error));
    error->message_ptr = (char *)ovc_abi_alloc(length == 0 ? 1 : length);
    if (error->message_ptr == NULL) {
        abort();
    }
    if (length == 0) {
        error->message_ptr[0] = '\0';
    } else {
        memcpy(error->message_ptr, message, length);
    }
    error->message_len = length;
    error->code = code;
    return error;
}

typedef struct ovc_config_empty_layer {
    OvStoragePlugin_LayerVTableV1 vtable;
} ovc_config_empty_layer;

static char g_ovc_config_empty_kind[] = OVC_EMPTY_KIND;
static char g_ovc_config_empty_display_name[] = "Empty";
static char g_ovc_config_empty_description[] = "no stack configured";

static void *ovc_config_empty_abi_callocate(size_t byte_count)
{
    void *allocation;

    allocation = ovc_abi_alloc(byte_count);
    if (allocation == NULL) {
        abort();
    }
    memset(allocation, 0, byte_count);
    return allocation;
}

static OvStoragePlugin_Str ovc_config_empty_owned_string(
    const char *value,
    size_t length)
{
    OvStoragePlugin_Str result;

    result.ptr = (char *)ovc_config_empty_abi_callocate(
        length == 0 ? 1 : length);
    if (length != 0) {
        memcpy(result.ptr, value, length);
    }
    result.len = length;
    return result;
}

static void ovc_config_empty_descriptor_fill(
    OvStoragePlugin_LayerKindDescriptor *out)
{
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->layer_type = OvStoragePlugin_LayerType_Backend;
    out->kind = ovc_config_empty_owned_string(
        g_ovc_config_empty_kind,
        sizeof(g_ovc_config_empty_kind) - 1);
    out->display_name = ovc_config_empty_owned_string(
        g_ovc_config_empty_display_name,
        sizeof(g_ovc_config_empty_display_name) - 1);
    out->description.present = true;
    out->description.value = ovc_config_empty_owned_string(
        g_ovc_config_empty_description,
        sizeof(g_ovc_config_empty_description) - 1);
    out->config_schema.ptr = (OvStoragePlugin_ConfigField *)
        ovc_config_empty_abi_callocate(sizeof(*out->config_schema.ptr));
    out->credential_schema.ptr = (OvStoragePlugin_CredentialField *)
        ovc_config_empty_abi_callocate(sizeof(*out->credential_schema.ptr));
    out->credential_methods.ptr = (OvStoragePlugin_CredentialMethod *)
        ovc_config_empty_abi_callocate(sizeof(*out->credential_methods.ptr));
}

static void ovc_config_empty_layer_drop(void *state)
{
    free(state);
}

static void ovc_config_empty_layer_name(void *state,
                                        OvStoragePlugin_Str *out)
{
    (void)state;
    *out = ovc_config_empty_owned_string(g_ovc_config_empty_kind,
                                         sizeof(g_ovc_config_empty_kind) - 1);
}

static void ovc_config_empty_layer_descriptor(
    void *state,
    OvStoragePlugin_LayerKindDescriptor *out)
{
    (void)state;
    ovc_config_empty_descriptor_fill(out);
}

static void ovc_config_empty_layer_owned_targets(
    void *state,
    OvStoragePlugin_List_Str *out)
{
    (void)state;
    out->ptr = (OvStoragePlugin_Str *)
        ovc_config_empty_abi_callocate(sizeof(*out->ptr));
    out->len = 0;
}

static OvStoragePlugin_Error *ovc_config_empty_layer_list_kinds(
    void *state,
    const OvStoragePlugin_Extensions *extensions,
    OvStoragePlugin_List_LayerKindDescriptor *out)
{
    (void)state;
    (void)extensions;
    out->ptr = (OvStoragePlugin_LayerKindDescriptor *)
        ovc_config_empty_abi_callocate(sizeof(*out->ptr));
    out->len = 1;
    ovc_config_empty_descriptor_fill(&out->ptr[0]);
    return NULL;
}

static void ovc_config_empty_layer_list_address_roots(
    void *state,
    const OvStoragePlugin_ListAddressRootsRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_ListAddressRootsResult *result;

    (void)state;
    (void)cancel;
    if (request == NULL || request->struct_size < sizeof(*request)) {
        ovstorage_plugin_list_address_roots_request_release(request);
        on_complete(
            OvStoragePlugin_FFI_STATUS_ERR,
            NULL,
            ovc_config_plugin_error(
                OvStoragePlugin_ErrorCode_InvalidArgument,
                "empty list_address_roots request struct_size is too small"),
            user_data);
        return;
    }
    ovstorage_plugin_list_address_roots_request_release(request);
    result = (OvStoragePlugin_ListAddressRootsResult *)
        ovc_config_empty_abi_callocate(sizeof(*result));
    result->snapshot.roots.ptr = (OvStoragePlugin_RootInfo *)
        ovc_config_empty_abi_callocate(sizeof(*result->snapshot.roots.ptr));
    on_complete(OvStoragePlugin_FFI_STATUS_OK, result, NULL, user_data);
}

static void ovc_config_empty_layer_list_connections(
    void *state,
    const OvStoragePlugin_ListConnectionsRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_ListConnectionsResult *result;

    (void)state;
    (void)cancel;
    if (request == NULL || request->struct_size < sizeof(*request)) {
        ovstorage_plugin_list_connections_request_release(request);
        on_complete(
            OvStoragePlugin_FFI_STATUS_ERR,
            NULL,
            ovc_config_plugin_error(
                OvStoragePlugin_ErrorCode_InvalidArgument,
                "empty list_connections request struct_size is too small"),
            user_data);
        return;
    }
    ovstorage_plugin_list_connections_request_release(request);
    result = (OvStoragePlugin_ListConnectionsResult *)
        ovc_config_empty_abi_callocate(sizeof(*result));
    result->snapshot.connections.ptr = (OvStoragePlugin_Connection *)
        ovc_config_empty_abi_callocate(
            sizeof(*result->snapshot.connections.ptr));
    on_complete(OvStoragePlugin_FFI_STATUS_OK, result, NULL, user_data);
}

static OvStoragePlugin_FfiStatus ovc_config_empty_create_backend(
    void *plugin_state,
    const OvStoragePlugin_CreateBackendRequest *request,
    OvStoragePlugin_LayerHandle *out,
    OvStoragePlugin_Error **err)
{
    OvStoragePlugin_CreateBackendRequest moved;
    ovc_config_empty_layer *layer;
    bool valid;

    (void)plugin_state;
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    if (err != NULL) {
        *err = NULL;
    }
    if (request == NULL || request->struct_size < sizeof(*request) ||
        out == NULL || err == NULL) {
        if (err != NULL) {
            *err = ovc_config_plugin_error(
                OvStoragePlugin_ErrorCode_InvalidArgument,
                "empty create_backend request is invalid");
        }
        return OvStoragePlugin_FFI_STATUS_ERR;
    }
    moved = *request;
    valid = moved.kind.ptr != NULL &&
            moved.kind.len == sizeof(OVC_EMPTY_KIND) - 1 &&
            memcmp(moved.kind.ptr,
                   OVC_EMPTY_KIND,
                   sizeof(OVC_EMPTY_KIND) - 1) == 0 &&
            moved.instance_id.ptr != NULL && moved.instance_id.len != 0 &&
            moved.config.len == 0;
    ovc_config_create_backend_request_clear(&moved);
    if (!valid) {
        *err = ovc_config_plugin_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "empty create_backend needs kind=empty, a name, and no config");
        return OvStoragePlugin_FFI_STATUS_ERR;
    }
    layer = (ovc_config_empty_layer *)calloc(1, sizeof(*layer));
    if (layer == NULL) {
        *err = ovc_config_plugin_error(OvStoragePlugin_ErrorCode_Internal,
                                       "could not allocate the empty Layer");
        return OvStoragePlugin_FFI_STATUS_ERR;
    }
    layer->vtable = OVSTORAGE_UNSUPPORTED_VTABLE;
    layer->vtable.drop = ovc_config_empty_layer_drop;
    layer->vtable.name = ovc_config_empty_layer_name;
    layer->vtable.descriptor = ovc_config_empty_layer_descriptor;
    layer->vtable.owned_targets = ovc_config_empty_layer_owned_targets;
    layer->vtable.list_kinds = ovc_config_empty_layer_list_kinds;
    layer->vtable.list_address_roots =
        ovc_config_empty_layer_list_address_roots;
    layer->vtable.list_connections = ovc_config_empty_layer_list_connections;
    out->state = layer;
    out->vtable = &layer->vtable;
    return OvStoragePlugin_FFI_STATUS_OK;
}

static void ovc_config_empty_plugin_drop(void *plugin_state)
{
    (void)plugin_state;
}

static const OvStoragePlugin_LayerKindDescriptor
    g_ovc_config_empty_descriptor = {
        .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
        .layer_type = OvStoragePlugin_LayerType_Backend,
        .accepts_connections = false,
        .supports_user_metadata = false,
        .kind = {g_ovc_config_empty_kind,
                 sizeof(g_ovc_config_empty_kind) - 1},
        .display_name = {g_ovc_config_empty_display_name,
                         sizeof(g_ovc_config_empty_display_name) - 1},
        .description = {
            true,
            {g_ovc_config_empty_description,
             sizeof(g_ovc_config_empty_description) - 1}},
};
static const OvStoragePlugin_PluginVTableV1
    g_ovc_config_empty_plugin_vtable = {
        .struct_size = sizeof(OvStoragePlugin_PluginVTableV1),
        .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
        .drop = ovc_config_empty_plugin_drop,
        .create_backend = ovc_config_empty_create_backend,
        .create_wrapper = NULL,
        .create_router = NULL,
};

static OvStorage_Status ovc_config_make_empty_stack(
    OvStorage_Stack **out_stack,
    OvStorage_Error *out_error)
{
    OvStorage_Registry *registry;
    OvStorage_Stack *stack;
    OvStorage_Status status;

    registry = ovstorage_registry_create();
    stack = ovstorage_stack_create();
    if (registry == NULL || stack == NULL) {
        ovstorage_registry_destroy(registry);
        ovstorage_stack_destroy(stack);
        return ovc_config_error(out_error,
                                OvStorage_Status_Internal,
                                "out of memory creating the empty stack");
    }
    status = ovc_registry_register_builtin_kind(
        registry,
        &g_ovc_config_empty_descriptor,
        NULL,
        &g_ovc_config_empty_plugin_vtable,
        out_error);
    if (status == OvStorage_Status_Ok) {
        status = ovstorage_stack_add_layer(stack,
                                           registry,
                                           OVC_EMPTY_KIND,
                                           OVC_EMPTY_KIND,
                                           out_error);
    }
    if (status == OvStorage_Status_Ok) {
        status = ovstorage_stack_set_root(stack,
                                          OVC_EMPTY_KIND,
                                          out_error);
    }
    ovstorage_registry_destroy(registry);
    if (status != OvStorage_Status_Ok) {
        ovstorage_stack_destroy(stack);
        return status;
    }
    *out_stack = stack;
    return OvStorage_Status_Ok;
}

static void ovc_config_string_array_clear(char **strings, size_t length)
{
    size_t index;

    if (strings == NULL) {
        return;
    }
    for (index = 0; index < length; ++index) {
        free(strings[index]);
    }
    free(strings);
}

static const char *ovc_config_removed_layer_kind_help(const char *kind)
{
    if (kind != NULL && strcmp(kind, "directory_normalize") == 0) {
        return "layer kind 'directory_normalize' was removed: every backend "
               "now derives the directory form of an address itself, so the "
               "wrapper has nothing left to do. Delete the "
               "[ovstorage.layers.directory_normalize] table and repoint "
               "whichever layer named it as `inner` at what it wrapped";
    }
    return NULL;
}

static OvStorage_Status ovc_config_add_layers(
    OvStorage_Stack *stack,
    const OvStorage_Registry *registry,
    const toml_datum_t *layers,
    OvStorage_Error *out_error)
{
    int index;

    for (index = 0; index < layers->u.tab.size; ++index) {
        const toml_datum_t *layer;
        const toml_datum_t *kind_value;
        char *instance_id;
        char *kind;
        OvStorage_Status status;

        layer = &layers->u.tab.value[index];
        kind_value = ovc_config_table_get(*layer, "kind");
        instance_id = ovc_config_slice_duplicate(
            layers->u.tab.key[index],
            (size_t)layers->u.tab.len[index]);
        kind = kind_value == NULL
                   ? ovc_config_slice_duplicate(
                         layers->u.tab.key[index],
                         (size_t)layers->u.tab.len[index])
                   : ovc_config_slice_duplicate(
                         kind_value->u.str.ptr,
                         (size_t)kind_value->u.str.len);
        if (instance_id == NULL || kind == NULL) {
            free(instance_id);
            free(kind);
            return ovc_config_error(out_error,
                                    OvStorage_Status_Internal,
                                    "out of memory resolving a layer declaration");
        }
        status = ovstorage_stack_add_layer(stack,
                                           registry,
                                           instance_id,
                                           kind,
                                           out_error);
        if (status != OvStorage_Status_Ok) {
            const char *migration;

            migration = ovc_config_removed_layer_kind_help(kind);
            if (migration != NULL) {
                status = ovc_config_error(out_error,
                                          OvStorage_Status_InvalidArgument,
                                          "%s",
                                          migration);
            }
        }
        free(instance_id);
        free(kind);
        if (status != OvStorage_Status_Ok) {
            return status;
        }
    }
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_config_configure_layer(
    OvStorage_Stack *stack,
    const char *instance_id,
    const toml_datum_t *layer,
    OvStorage_Error *out_error)
{
    int index;
    const toml_datum_t *inner;
    const toml_datum_t *children;
    OvStorage_Status status;

    for (index = 0; index < layer->u.tab.size; ++index) {
        char *key;
        OvStorage_ConfigValue *value;

        if (ovc_config_key_equals(*layer, index, "kind") ||
            ovc_config_key_equals(*layer, index, "inner") ||
            ovc_config_key_equals(*layer, index, "children")) {
            continue;
        }
        if (!ovc_config_key_valid(*layer, index)) {
            return ovc_config_error(out_error,
                                    OvStorage_Status_InvalidArgument,
                                    "a layer config key is not a UTF-8 C string");
        }
        key = ovc_config_slice_duplicate(layer->u.tab.key[index],
                                         (size_t)layer->u.tab.len[index]);
        if (key == NULL) {
            return ovc_config_error(out_error,
                                    OvStorage_Status_Internal,
                                    "out of memory resolving a layer config key");
        }
        value = NULL;
        status = ovc_config_value_create(key,
                                         &layer->u.tab.value[index],
                                         &value,
                                         out_error);
        if (status == OvStorage_Status_Ok) {
            status = ovstorage_stack_add_layer_config(stack,
                                                      instance_id,
                                                      key,
                                                      value,
                                                      out_error);
        }
        if (status != OvStorage_Status_Ok) {
            ovstorage_config_value_destroy(value);
            free(key);
            return status;
        }
        free(key);
    }
    inner = ovc_config_table_get(*layer, "inner");
    if (inner != NULL) {
        char *inner_id;

        inner_id = ovc_config_slice_duplicate(inner->u.str.ptr,
                                              (size_t)inner->u.str.len);
        if (inner_id == NULL) {
            return ovc_config_error(out_error,
                                    OvStorage_Status_Internal,
                                    "out of memory resolving a wrapper edge");
        }
        status = ovstorage_stack_set_inner(stack,
                                           instance_id,
                                           inner_id,
                                           out_error);
        free(inner_id);
        if (status != OvStorage_Status_Ok) {
            return status;
        }
    }
    children = ovc_config_table_get(*layer, "children");
    if (children != NULL && children->u.arr.size != 0) {
        char **child_ids;
        size_t child_count;
        size_t child_index;

        child_count = (size_t)children->u.arr.size;
        if (child_count > SIZE_MAX / sizeof(*child_ids)) {
            return ovc_config_error(out_error,
                                    OvStorage_Status_Internal,
                                    "router child count overflow");
        }
        child_ids = (char **)calloc(child_count, sizeof(*child_ids));
        if (child_ids == NULL) {
            return ovc_config_error(out_error,
                                    OvStorage_Status_Internal,
                                    "out of memory resolving router edges");
        }
        for (child_index = 0; child_index < child_count; ++child_index) {
            const toml_datum_t *child;

            child = &children->u.arr.elem[child_index];
            child_ids[child_index] = ovc_config_slice_duplicate(
                child->u.str.ptr,
                (size_t)child->u.str.len);
            if (child_ids[child_index] == NULL) {
                ovc_config_string_array_clear(child_ids, child_count);
                return ovc_config_error(out_error,
                                        OvStorage_Status_Internal,
                                        "out of memory resolving router edges");
            }
        }
        status = ovstorage_stack_set_children(
            stack,
            instance_id,
            (const char *const *)child_ids,
            child_count,
            out_error);
        ovc_config_string_array_clear(child_ids, child_count);
        if (status != OvStorage_Status_Ok) {
            return status;
        }
    }
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_config_configure_layers(
    OvStorage_Stack *stack,
    const toml_datum_t *layers,
    OvStorage_Error *out_error)
{
    int index;

    for (index = 0; index < layers->u.tab.size; ++index) {
        char *instance_id;
        OvStorage_Status status;

        instance_id = ovc_config_slice_duplicate(
            layers->u.tab.key[index],
            (size_t)layers->u.tab.len[index]);
        if (instance_id == NULL) {
            return ovc_config_error(out_error,
                                    OvStorage_Status_Internal,
                                    "out of memory resolving a layer name");
        }
        status = ovc_config_configure_layer(stack,
                                            instance_id,
                                            &layers->u.tab.value[index],
                                            out_error);
        free(instance_id);
        if (status != OvStorage_Status_Ok) {
            return status;
        }
    }
    return OvStorage_Status_Ok;
}

static bool ovc_config_env_ref_at(const char *value,
                                  size_t length,
                                  size_t start,
                                  size_t *out_name_end,
                                  size_t *out_end)
{
    size_t cursor;
    unsigned char byte;

    if (start + 3 >= length || value[start] != '$' ||
        value[start + 1] != '{') {
        return false;
    }
    cursor = start + 2;
    byte = (unsigned char)value[cursor];
    if (!(ovc_config_ascii_alpha(byte) || byte == '_')) {
        return false;
    }
    ++cursor;
    while (cursor < length) {
        byte = (unsigned char)value[cursor];
        if (!(ovc_config_ascii_alnum(byte) || byte == '_')) {
            break;
        }
        ++cursor;
    }
    if (cursor >= length || value[cursor] != '}') {
        return false;
    }
    *out_name_end = cursor;
    *out_end = cursor + 1;
    return true;
}

static OvStorage_Status ovc_config_resolve_credential(
    const char *key,
    const toml_datum_t *raw,
    ovc_config_text *out_value,
    OvStorage_Error *out_error)
{
    size_t cursor;
    size_t literal_start;
    size_t name_end;
    size_t reference_end;

    cursor = 0;
    literal_start = 0;
    while (cursor + 1 < (size_t)raw->u.str.len) {
        if (ovc_config_env_ref_at(raw->u.str.ptr,
                                  (size_t)raw->u.str.len,
                                  cursor,
                                  &name_end,
                                  &reference_end)) {
            char *name;
            char *environment_value;
            size_t environment_length;

            if (!ovc_config_text_append_n(out_value,
                                          raw->u.str.ptr + literal_start,
                                          cursor - literal_start)) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_Internal,
                                        "out of memory resolving credential '%s'",
                                        key);
            }
            name = ovc_config_slice_duplicate(raw->u.str.ptr + cursor + 2,
                                              name_end - cursor - 2);
            if (name == NULL) {
                return ovc_config_error(out_error,
                                        OvStorage_Status_Internal,
                                        "out of memory resolving credential '%s'",
                                        key);
            }
            errno = 0;
            environment_value = ovc_env_dup(name);
            if (environment_value == NULL) {
                OvStorage_Status status;

                /* The application C ABI deliberately maps the plugin
                 * NotConfigured bucket to NotFound (see values.c). */
                status = errno == 0 ? OvStorage_Status_NotFound
                                    : OvStorage_Status_Internal;
                if (status == OvStorage_Status_Internal) {
                    (void)ovc_config_error(
                        out_error,
                        status,
                        "could not read env var '%s' for credential '%s': %s",
                        name,
                        key,
                        ovc_config_strerror(errno));
                } else {
                    (void)ovc_config_error(
                        out_error,
                        status,
                        "credential '%s': env var '%s' is not set",
                        key,
                        name);
                }
                free(name);
                return status;
            }
            environment_length = strlen(environment_value);
            if (!ovc_utf8_is_valid(environment_value, environment_length)) {
                ovc_secure_zero(environment_value, environment_length + 1);
                free(environment_value);
                (void)ovc_config_error(out_error,
                                       OvStorage_Status_NotFound,
                                       "credential '%s': env var '%s' is not valid UTF-8",
                                       key,
                                       name);
                free(name);
                return OvStorage_Status_NotFound;
            }
            if (!ovc_config_text_append_n(out_value,
                                          environment_value,
                                          environment_length)) {
                ovc_secure_zero(environment_value, environment_length + 1);
                free(environment_value);
                free(name);
                return ovc_config_error(out_error,
                                        OvStorage_Status_Internal,
                                        "out of memory resolving credential '%s'",
                                        key);
            }
            ovc_secure_zero(environment_value, environment_length + 1);
            free(environment_value);
            free(name);
            cursor = reference_end;
            literal_start = cursor;
            continue;
        }
        ++cursor;
    }
    if (!ovc_config_text_append_n(out_value,
                                  raw->u.str.ptr + literal_start,
                                  (size_t)raw->u.str.len - literal_start)) {
        return ovc_config_error(out_error,
                                OvStorage_Status_Internal,
                                "out of memory resolving credential '%s'",
                                key);
    }
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_config_add_connection(
    OvStorage_Stack *stack,
    const toml_datum_t *connection,
    OvStorage_Error *out_error)
{
    const toml_datum_t *backend_kind;
    const toml_datum_t *target;
    const toml_datum_t *display_name;
    const toml_datum_t *config;
    const toml_datum_t *credentials;
    OvStorage_ConnectionRequest *request;
    char *backend_kind_string;
    char *target_string;
    int index;
    OvStorage_Status status;

    backend_kind = ovc_config_table_get(*connection, "backend_kind");
    target = ovc_config_table_get(*connection, "target");
    display_name = ovc_config_table_get(*connection, "display_name");
    config = ovc_config_table_get(*connection, "config");
    credentials = ovc_config_table_get(*connection, "credentials");
    backend_kind_string = ovc_config_slice_duplicate(
        backend_kind->u.str.ptr,
        (size_t)backend_kind->u.str.len);
    target_string = target == NULL
                        ? ovc_config_slice_duplicate(
                              backend_kind->u.str.ptr,
                              (size_t)backend_kind->u.str.len)
                        : ovc_config_slice_duplicate(
                              target->u.str.ptr,
                              (size_t)target->u.str.len);
    if (backend_kind_string == NULL || target_string == NULL) {
        free(backend_kind_string);
        free(target_string);
        return ovc_config_error(out_error,
                                OvStorage_Status_Internal,
                                "out of memory resolving a connection declaration");
    }
    request = ovstorage_connection_request_create(backend_kind_string);
    free(backend_kind_string);
    if (request == NULL) {
        free(target_string);
        return ovc_config_error(out_error,
                                OvStorage_Status_Internal,
                                "out of memory creating a connection request");
    }
    if (display_name != NULL) {
        ovstorage_connection_request_set_display_name(
            request,
            display_name->u.str.ptr);
    }
    if (config != NULL) {
        for (index = 0; index < config->u.tab.size; ++index) {
            char *key;
            OvStorage_ConfigValue *value;

            if (!ovc_config_key_valid(*config, index)) {
                status = ovc_config_error(
                    out_error,
                    OvStorage_Status_InvalidArgument,
                    "a connection config key is not a UTF-8 C string");
                goto fail;
            }
            key = ovc_config_slice_duplicate(config->u.tab.key[index],
                                             (size_t)config->u.tab.len[index]);
            if (key == NULL) {
                status = ovc_config_error(
                    out_error,
                    OvStorage_Status_Internal,
                    "out of memory resolving a connection config key");
                goto fail;
            }
            value = NULL;
            status = ovc_config_value_create(key,
                                             &config->u.tab.value[index],
                                             &value,
                                             out_error);
            if (status == OvStorage_Status_Ok &&
                !ovstorage_connection_request_add_config(request,
                                                         key,
                                                         value)) {
                status = ovc_config_error(
                    out_error,
                    OvStorage_Status_Internal,
                    "could not record connection config field '%s'",
                    key);
            }
            if (status != OvStorage_Status_Ok) {
                ovstorage_config_value_destroy(value);
                free(key);
                goto fail;
            }
            free(key);
        }
    }
    if (credentials != NULL) {
        for (index = 0; index < credentials->u.tab.size; ++index) {
            char *key;
            ovc_config_text resolved;
            OvStorage_SecretValue *secret;

            key = ovc_config_slice_duplicate(
                credentials->u.tab.key[index],
                (size_t)credentials->u.tab.len[index]);
            if (key == NULL) {
                status = ovc_config_error(
                    out_error,
                    OvStorage_Status_Internal,
                    "out of memory resolving a credential key");
                goto fail;
            }
            memset(&resolved, 0, sizeof(resolved));
            status = ovc_config_resolve_credential(
                key,
                &credentials->u.tab.value[index],
                &resolved,
                out_error);
            secret = NULL;
            if (status == OvStorage_Status_Ok) {
                secret = ovstorage_secret_value_create_bytes(
                    (const uint8_t *)resolved.data,
                    resolved.len);
                if (secret == NULL) {
                    status = ovc_config_error(
                        out_error,
                        OvStorage_Status_Internal,
                        "out of memory creating credential '%s'",
                        key);
                }
            }
            if (status == OvStorage_Status_Ok &&
                !ovstorage_connection_request_add_credential(request,
                                                             key,
                                                             secret)) {
                status = ovc_config_error(
                    out_error,
                    OvStorage_Status_Internal,
                    "could not record credential '%s'",
                    key);
            }
            ovc_config_text_clear(&resolved, true);
            if (status != OvStorage_Status_Ok) {
                ovstorage_secret_value_destroy(secret);
                free(key);
                goto fail;
            }
            free(key);
        }
    }
    status = ovstorage_stack_add_connection(stack,
                                            target_string,
                                            &request,
                                            out_error);
    ovstorage_connection_request_destroy(request);
    free(target_string);
    return status;

fail:
    ovstorage_connection_request_destroy(request);
    free(target_string);
    return status;
}

static OvStorage_Status ovc_config_make_stack(
    const OvStorage_StackConfig *config,
    const OvStorage_Registry *registry,
    OvStorage_Stack **out_stack,
    OvStorage_Error *out_error)
{
    const toml_datum_t *ovstorage;
    const toml_datum_t *layers;
    const toml_datum_t *root;
    const toml_datum_t *connections;
    OvStorage_Stack *stack;
    OvStorage_Status status;
    int index;
    char *root_string;

    *out_stack = NULL;
    if (config == NULL) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "config must not be null");
    }
    if (registry == NULL) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "registry must not be null");
    }
    ovstorage = ovc_config_table_get(config->document.toptab, "ovstorage");
    layers = ovstorage == NULL
                 ? NULL
                 : ovc_config_table_get(*ovstorage, "layers");
    connections = ovstorage == NULL
                      ? NULL
                      : ovc_config_table_get(*ovstorage, "connections");
    if (layers == NULL || layers->u.tab.size == 0) {
        if (connections != NULL && connections->u.arr.size != 0) {
            return ovc_config_error(
                out_error,
                OvStorage_Status_InvalidArgument,
                "[[ovstorage.connections]] declared but no [ovstorage.layers] to attach them to");
        }
        return ovc_config_make_empty_stack(out_stack, out_error);
    }
    root = ovc_config_table_get(*ovstorage, "root");
    if (root == NULL) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "stack has layers but no root is set");
    }
    stack = ovstorage_stack_create();
    if (stack == NULL) {
        return ovc_config_error(out_error,
                                OvStorage_Status_Internal,
                                "out of memory creating a Stack builder");
    }
    status = ovc_config_add_layers(stack, registry, layers, out_error);
    if (status == OvStorage_Status_Ok) {
        status = ovc_config_configure_layers(stack, layers, out_error);
    }
    root_string = NULL;
    if (status == OvStorage_Status_Ok) {
        root_string = ovc_config_slice_duplicate(root->u.str.ptr,
                                                 (size_t)root->u.str.len);
        if (root_string == NULL) {
            status = ovc_config_error(out_error,
                                      OvStorage_Status_Internal,
                                      "out of memory resolving the stack root");
        }
    }
    if (status == OvStorage_Status_Ok) {
        status = ovstorage_stack_set_root(stack,
                                          root_string,
                                          out_error);
    }
    free(root_string);
    if (status == OvStorage_Status_Ok && connections != NULL) {
        for (index = 0; index < connections->u.arr.size; ++index) {
            status = ovc_config_add_connection(
                stack,
                &connections->u.arr.elem[index],
                out_error);
            if (status != OvStorage_Status_Ok) {
                break;
            }
        }
    }
    if (status != OvStorage_Status_Ok) {
        ovstorage_stack_destroy(stack);
        return status;
    }
    *out_stack = stack;
    ovc_config_success(out_error);
    return OvStorage_Status_Ok;
}

OvStorage_Status ovstorage_stack_build_from_config(
    const OvStorage_StackConfig *config,
    const OvStorage_Registry *registry,
    const OvStorage_StackBuildOptions *options,
    OvStorage_LayerHandle **out_handle,
    OvStorage_Error *out_error)
{
    OvStorage_Stack *stack;
    OvStorage_Status status;

    if (out_handle == NULL) {
        return ovc_config_error(out_error,
                                OvStorage_Status_InvalidArgument,
                                "out_handle must not be null");
    }
    *out_handle = NULL;
    stack = NULL;
    status = ovc_config_make_stack(config,
                                   registry,
                                   &stack,
                                   out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovstorage_stack_build(stack,
                                   options,
                                   out_handle,
                                   out_error);
    if (status != OvStorage_Status_Ok) {
        ovstorage_stack_destroy(stack);
    }
    return status;
}

typedef struct ovc_config_async_build {
    OvStorage_Stack *stack;
    OvStorage_StackBuildCallback on_complete;
    void *user_data;
} ovc_config_async_build;

static void ovc_config_async_complete(OvStorage_Status status,
                                      OvStorage_LayerHandle *handle,
                                      const OvStorage_Error *error,
                                      void *user_data)
{
    ovc_config_async_build *build;

    build = (ovc_config_async_build *)user_data;
    if (status != OvStorage_Status_Ok) {
        ovstorage_stack_destroy(build->stack);
    }
    build->on_complete(status, handle, error, build->user_data);
    free(build);
}

static void ovc_config_async_reject(OvStorage_StackBuildCallback on_complete,
                                    void *user_data,
                                    OvStorage_Status status,
                                    const char *message)
{
    OvStorage_Error error;

    memset(&error, 0, sizeof(error));
    (void)ovc_config_error(&error, status, "%s", message);
    on_complete(status, NULL, &error, user_data);
    ovstorage_error_clear(&error);
}

void ovstorage_stack_build_from_config_async(
    const OvStorage_StackConfig *config,
    const OvStorage_Registry *registry,
    const OvStorage_StackBuildOptions *options,
    const OvStorage_CancelToken *cancel,
    OvStorage_StackBuildCallback on_complete,
    void *user_data)
{
    OvStorage_Stack *stack;
    OvStorage_Error error;
    OvStorage_Status status;
    ovc_config_async_build *build;

    if (on_complete == NULL) {
        return;
    }
    stack = NULL;
    memset(&error, 0, sizeof(error));
    status = ovc_config_make_stack(config, registry, &stack, &error);
    if (status != OvStorage_Status_Ok) {
        on_complete(status, NULL, &error, user_data);
        ovstorage_error_clear(&error);
        return;
    }
    build = (ovc_config_async_build *)malloc(sizeof(*build));
    if (build == NULL) {
        ovstorage_stack_destroy(stack);
        ovc_config_async_reject(on_complete,
                                user_data,
                                OvStorage_Status_Internal,
                                "out of memory starting the config-driven stack build");
        return;
    }
    build->stack = stack;
    build->on_complete = on_complete;
    build->user_data = user_data;
    ovstorage_stack_build_async(stack,
                                options,
                                cancel,
                                ovc_config_async_complete,
                                build);
}

void ovstorage_stack_config_destroy(OvStorage_StackConfig *config)
{
    if (config == NULL) {
        return;
    }
    ovc_toml_free(config->document);
    free(config);
}

#if defined(OVC_STACK_CONFIG_TEST_MAIN)

#include <assert.h>

#include "temp_dir.h"

#if defined(_WIN32)
#include <direct.h>
#define ovc_config_test_chdir _chdir
#define ovc_config_test_getcwd _getcwd
#define ovc_config_test_rmdir _rmdir
#else
#include <unistd.h>
#define ovc_config_test_chdir chdir
#define ovc_config_test_getcwd getcwd
#define ovc_config_test_rmdir rmdir
#endif

#if defined(NDEBUG)
#error "OVC_STACK_CONFIG_TEST_MAIN requires assertions to be enabled"
#endif

typedef struct ovc_config_test_completion {
    ovc_completion_latch latch;
    OvStorage_Status status;
    OvStorage_LayerHandle *handle;
    int callback_count;
} ovc_config_test_completion;

typedef struct ovc_config_test_list_completion {
    ovc_completion_latch latch;
    OvStorage_Status status;
    size_t length;
    int callback_count;
} ovc_config_test_list_completion;

static void ovc_config_test_complete(OvStorage_Status status,
                                     OvStorage_LayerHandle *handle,
                                     const OvStorage_Error *error,
                                     void *user_data)
{
    ovc_config_test_completion *completion;

    completion = (ovc_config_test_completion *)user_data;
    completion->status = status;
    completion->handle = handle;
    ++completion->callback_count;
    assert((status == OvStorage_Status_Ok) == (error == NULL));
    assert(ovc_completion_latch_complete(&completion->latch) == 0);
}

static void ovc_config_test_roots_complete(
    OvStorage_Status status,
    OvStorage_RootInfoList *list,
    const OvStorage_Error *error,
    void *user_data)
{
    ovc_config_test_list_completion *completion;

    completion = (ovc_config_test_list_completion *)user_data;
    completion->status = status;
    completion->length = list == NULL ? SIZE_MAX : list->len;
    ++completion->callback_count;
    assert((status == OvStorage_Status_Ok) == (error == NULL));
    ovstorage_root_info_list_destroy(list);
    assert(ovc_completion_latch_complete(&completion->latch) == 0);
}

static void ovc_config_test_connections_complete(
    OvStorage_Status status,
    OvStorage_ConnectionList *list,
    const OvStorage_Error *error,
    void *user_data)
{
    ovc_config_test_list_completion *completion;

    completion = (ovc_config_test_list_completion *)user_data;
    completion->status = status;
    completion->length = list == NULL ? SIZE_MAX : list->len;
    ++completion->callback_count;
    assert((status == OvStorage_Status_Ok) == (error == NULL));
    ovstorage_connection_list_destroy(list);
    assert(ovc_completion_latch_complete(&completion->latch) == 0);
}

static void ovc_config_test_set_env(const char *name, const char *value)
{
#if defined(_WIN32)
    wchar_t *wide_name;
    wchar_t *wide_value;

    wide_name = ovc_utf8_to_wide(name);
    assert(wide_name != NULL);
    wide_value = value == NULL ? NULL : ovc_utf8_to_wide(value);
    assert(value == NULL || wide_value != NULL);
    if (SetEnvironmentVariableW(wide_name, wide_value) == 0) {
        assert(value == NULL && GetLastError() == ERROR_ENVVAR_NOT_FOUND);
    }
    free(wide_value);
    free(wide_name);
#else
    if (value == NULL) {
        assert(unsetenv(name) == 0);
    } else {
        assert(setenv(name, value, 1) == 0);
    }
#endif
}

static void ovc_config_test_mkdir(const char *path)
{
#if defined(_WIN32)
    wchar_t *wide;

    wide = ovc_utf8_to_wide(path);
    assert(wide != NULL);
    assert(_wmkdir(wide) == 0);
    free(wide);
#else
    assert(mkdir(path, 0700) == 0);
#endif
}

static void ovc_config_test_write(const char *path, const char *contents)
{
    FILE *file;
    size_t length;

#if defined(_WIN32)
    {
        wchar_t *wide;

        wide = ovc_utf8_to_wide(path);
        assert(wide != NULL);
        file = NULL;
        assert(_wfopen_s(&file, wide, L"wb") == 0);
        free(wide);
    }
#else
    file = fopen(path, "wb");
#endif
    assert(file != NULL);
    length = strlen(contents);
    assert(fwrite(contents, 1, length, file) == length);
    assert(fclose(file) == 0);
}

static const toml_datum_t *ovc_config_test_ovstorage(
    const OvStorage_StackConfig *config)
{
    return ovc_config_table_get(config->document.toptab, "ovstorage");
}

static void ovc_config_test_build_reusable(void)
{
    static const char source[] =
        "[ovstorage]\n"
        "root = \"files\"\n"
        "[ovstorage.layers.files]\n"
        "kind = \"file\"\n";
    OvStorage_StackConfig *config;
    OvStorage_Registry *registry;
    OvStorage_LayerHandle *handle;
    OvStorage_Error error;
    OvStorage_Status status;
    ovc_config_test_completion completion;
    int iteration;

    config = NULL;
    memset(&error, 0, sizeof(error));
    assert(ovstorage_stack_config_from_toml_str(source,
                                                &config,
                                                &error) ==
           OvStorage_Status_Ok);
    assert(config != NULL);
    registry = ovstorage_registry_create();
    assert(registry != NULL);
    for (iteration = 0; iteration < 2; ++iteration) {
        handle = NULL;
        status = ovstorage_stack_build_from_config(config,
                                                   registry,
                                                   NULL,
                                                   &handle,
                                                   &error);
        assert(status == OvStorage_Status_Ok);
        assert(handle != NULL);
        ovstorage_layer_handle_destroy(handle);
    }
    memset(&completion, 0, sizeof(completion));
    assert(ovc_completion_latch_init(&completion.latch) == 0);
    ovstorage_stack_build_from_config_async(config,
                                            registry,
                                            NULL,
                                            NULL,
                                            ovc_config_test_complete,
                                            &completion);
    assert(ovc_completion_latch_wait(&completion.latch) == 0);
    assert(completion.callback_count == 1);
    assert(completion.status == OvStorage_Status_Ok);
    assert(completion.handle != NULL);
    ovstorage_layer_handle_destroy(completion.handle);
    assert(ovc_completion_latch_destroy(&completion.latch) == 0);
    ovstorage_stack_config_destroy(config);
    ovstorage_registry_destroy(registry);
    ovstorage_error_clear(&error);
}

static void ovc_config_test_empty_and_errors(void)
{
    static const char connections_only[] =
        "[[ovstorage.connections]]\n"
        "backend_kind = \"file\"\n";
    static const char unknown_kind[] =
        "[ovstorage]\n"
        "root = \"root\"\n"
        "[ovstorage.layers.root]\n"
        "kind = \"not-registered\"\n";
    static const char removed_kind[] =
        "[ovstorage]\n"
        "root = \"directory_normalize\"\n"
        "[ovstorage.layers.directory_normalize]\n";
    static const char float_config[] =
        "[ovstorage]\n"
        "root = \"files\"\n"
        "[ovstorage.layers.files]\n"
        "kind = \"file\"\n"
        "ratio = 1.25\n";
    OvStorage_StackConfig *config;
    OvStorage_Registry *registry;
    OvStorage_LayerHandle *handle;
    OvStoragePlugin_LayerHandle exported;
    OvStoragePlugin_Str name;
    OvStoragePlugin_LayerKindDescriptor descriptor;
    OvStoragePlugin_List_LayerKindDescriptor kinds;
    OvStoragePlugin_Error *plugin_error;
    OvStorage_Error error;
    OvStorage_Status status;
    ovc_config_test_list_completion list_completion;

    memset(&error, 0, sizeof(error));
    registry = ovstorage_registry_create();
    assert(registry != NULL);

    config = NULL;
    assert(ovstorage_stack_config_from_toml_str("", &config, &error) ==
           OvStorage_Status_Ok);
    handle = NULL;
    assert(ovstorage_stack_build_from_config(config,
                                             registry,
                                             NULL,
                                             &handle,
                                             &error) ==
           OvStorage_Status_Ok);
    assert(handle != NULL);

    memset(&exported, 0, sizeof(exported));
    assert(ovstorage_export_handle(handle, &exported, &error) ==
           OvStorage_Status_Ok);
    assert(exported.state != NULL && exported.vtable != NULL);
    memset(&name, 0, sizeof(name));
    exported.vtable->name(exported.state, &name);
    assert(name.len == sizeof(g_ovc_config_empty_kind) - 1);
    assert(memcmp(name.ptr,
                  g_ovc_config_empty_kind,
                  sizeof(g_ovc_config_empty_kind) - 1) == 0);
    ovstorage_plugin_str_free(&name);

    memset(&descriptor, 0, sizeof(descriptor));
    exported.vtable->descriptor(exported.state, &descriptor);
    assert(descriptor.kind.len == sizeof(g_ovc_config_empty_kind) - 1);
    assert(memcmp(descriptor.kind.ptr,
                  g_ovc_config_empty_kind,
                  sizeof(g_ovc_config_empty_kind) - 1) == 0);
    assert(descriptor.display_name.len ==
           sizeof(g_ovc_config_empty_display_name) - 1);
    assert(memcmp(descriptor.display_name.ptr,
                  g_ovc_config_empty_display_name,
                  sizeof(g_ovc_config_empty_display_name) - 1) == 0);
    assert(descriptor.description.present);
    assert(descriptor.description.value.len ==
           sizeof(g_ovc_config_empty_description) - 1);
    ovstorage_plugin_layer_kind_descriptor_free(&descriptor);

    memset(&kinds, 0, sizeof(kinds));
    plugin_error = exported.vtable->list_kinds(exported.state,
                                                NULL,
                                                &kinds);
    assert(plugin_error == NULL);
    assert(kinds.len == 1);
    assert(kinds.ptr[0].kind.len == sizeof(g_ovc_config_empty_kind) - 1);
    assert(memcmp(kinds.ptr[0].kind.ptr,
                  g_ovc_config_empty_kind,
                  sizeof(g_ovc_config_empty_kind) - 1) == 0);
    ovstorage_plugin_layer_kind_descriptor_free(&kinds.ptr[0]);
    ovc_abi_free(kinds.ptr);

    memset(&list_completion, 0, sizeof(list_completion));
    assert(ovc_completion_latch_init(&list_completion.latch) == 0);
    ovstorage_list_address_roots(handle,
                                 NULL,
                                 ovc_config_test_roots_complete,
                                 &list_completion);
    assert(ovc_completion_latch_wait(&list_completion.latch) == 0);
    assert(list_completion.callback_count == 1);
    assert(list_completion.status == OvStorage_Status_Ok);
    assert(list_completion.length == 0);
    assert(ovc_completion_latch_destroy(&list_completion.latch) == 0);

    memset(&list_completion, 0, sizeof(list_completion));
    assert(ovc_completion_latch_init(&list_completion.latch) == 0);
    ovstorage_list_connections(handle,
                               NULL,
                               ovc_config_test_connections_complete,
                               &list_completion);
    assert(ovc_completion_latch_wait(&list_completion.latch) == 0);
    assert(list_completion.callback_count == 1);
    assert(list_completion.status == OvStorage_Status_Ok);
    assert(list_completion.length == 0);
    assert(ovc_completion_latch_destroy(&list_completion.latch) == 0);

    exported.vtable->drop(exported.state);
    ovstorage_layer_handle_destroy(handle);
    ovstorage_stack_config_destroy(config);

    config = NULL;
    assert(ovstorage_stack_config_from_toml_str(connections_only,
                                                &config,
                                                &error) ==
           OvStorage_Status_Ok);
    handle = (OvStorage_LayerHandle *)(uintptr_t)1;
    status = ovstorage_stack_build_from_config(config,
                                               registry,
                                               NULL,
                                               &handle,
                                               &error);
    assert(status == OvStorage_Status_InvalidArgument);
    assert(handle == NULL);
    ovstorage_stack_config_destroy(config);
    ovstorage_error_clear(&error);

    config = NULL;
    assert(ovstorage_stack_config_from_toml_str(removed_kind,
                                                &config,
                                                &error) ==
           OvStorage_Status_Ok);
    handle = NULL;
    status = ovstorage_stack_build_from_config(config,
                                               registry,
                                               NULL,
                                               &handle,
                                               &error);
    assert(status == OvStorage_Status_InvalidArgument);
    assert(handle == NULL);
    assert(strstr(ovstorage_error_message(&error),
                  "directory form of an address") != NULL);
    ovstorage_stack_config_destroy(config);
    ovstorage_error_clear(&error);

    config = NULL;
    assert(ovstorage_stack_config_from_toml_str(unknown_kind,
                                                &config,
                                                &error) ==
           OvStorage_Status_Ok);
    handle = NULL;
    status = ovstorage_stack_build_from_config(config,
                                               registry,
                                               NULL,
                                               &handle,
                                               &error);
    assert(status == OvStorage_Status_InvalidArgument);
    assert(handle == NULL);
    assert(strstr(ovstorage_error_message(&error), "not-registered") != NULL);
    ovstorage_stack_config_destroy(config);
    ovstorage_error_clear(&error);

    config = NULL;
    assert(ovstorage_stack_config_from_toml_str(float_config,
                                                &config,
                                                &error) ==
           OvStorage_Status_Ok);
    handle = NULL;
    status = ovstorage_stack_build_from_config(config,
                                               registry,
                                               NULL,
                                               &handle,
                                               &error);
    assert(status == OvStorage_Status_InvalidArgument);
    assert(handle == NULL);
    assert(strstr(ovstorage_error_message(&error),
                  "unsupported type") != NULL);
    ovstorage_stack_config_destroy(config);
    ovstorage_registry_destroy(registry);
    ovstorage_error_clear(&error);
}

static void ovc_config_test_toml_grammar(void)
{
    static const char *invalid[] = {
        "[ovstorage]\nvalue = \"\\e\"\n",
        "[ovstorage]\nvalue = \"\\x41\"\n",
        "[ovstorage]\nvalue = { one = 1, }\n",
        "[ovstorage]\nvalue = { one = 1,\n two = 2 }\n",
        "[ovstorage]\nvalue = 07:32\n",
        "[ovstorage]\ncaf\xc3\xa9 = 1\n",
    };
    static const char valid[] =
        "[ovstorage]\n"
        "local = 07:32:00.123456789012345678901234567890\n"
        "stamp = 1979-05-27T07:32:00.123456789012345678901234567890Z\n";
    OvStorage_StackConfig *config;
    OvStorage_Error error;
    size_t index;

    memset(&error, 0, sizeof(error));
    for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        config = (OvStorage_StackConfig *)(uintptr_t)1;
        assert(ovstorage_stack_config_from_toml_str(invalid[index],
                                                    &config,
                                                    &error) ==
               OvStorage_Status_InvalidArgument);
        assert(config == NULL);
        ovstorage_error_clear(&error);
    }
    config = NULL;
    assert(ovstorage_stack_config_from_toml_str(valid, &config, &error) ==
           OvStorage_Status_Ok);
    assert(config != NULL);
    ovstorage_stack_config_destroy(config);
    ovstorage_error_clear(&error);
}

static void ovc_config_test_path_overlay(const char *directory)
{
    static const char source[] =
        "[ovstorage]\n"
        "overlay_probe = [{ value = \"old-a\" }, { value = \"old-b\" }]\n"
        "[ovstorage.layers.files]\n"
        "kind = \"file\"\n";
    char path[OVC_TEMP_DIR_PATH_MAX + 32];
    int written;
    OvStorage_StackConfig *direct;
    OvStorage_StackConfig *loaded;
    OvStorage_Registry *registry;
    OvStorage_LayerHandle *handle;
    OvStorage_Error error;
    const toml_datum_t *ovstorage;
    const toml_datum_t *root;
    const toml_datum_t *overlay_probe;
    const toml_datum_t *overlay_value;
    const toml_datum_t *layers;
    const toml_datum_t *files;
    const toml_datum_t *kind;
    const toml_datum_t *layer_root;
    const toml_datum_t *aliases;
    const toml_datum_t *big;
    const toml_datum_t *exponent;

    written = snprintf(path, sizeof(path), "%s/config.toml", directory);
    assert(written > 0 && (size_t)written < sizeof(path));
    ovc_config_test_write(path, source);
    ovc_config_test_set_env("OVSTORAGE__ROOT", NULL);
    ovc_config_test_set_env("OvStorage__Root", NULL);
    ovc_config_test_set_env("OVSTORAGE__ROOT", "first");
    ovc_config_test_set_env("OvStorage__Root", "files");
    ovc_config_test_set_env("OVSTORAGE__OVERLAY_PROBE",
                            "[{value=new}]");
    ovc_config_test_set_env("OVSTORAGE__IGNORED____KEY", "ignored");
    ovc_config_test_set_env("OVSTORAGE__LAYERS__FILES", "{kind=file}");
    ovc_config_test_set_env("OVSTORAGE__LAYERS__FILES__ROOT", "/tmp");
    ovc_config_test_set_env(
        "OVSTORAGE__LAYERS__FILES__ALIASES",
        "[hi,true,{a=b}]");
    ovc_config_test_set_env("OVSTORAGE__OVERLAY_BIG",
                            "9223372036854775808");
    ovc_config_test_set_env("OVSTORAGE__OVERLAY_EXPONENT", "1e3");

    direct = NULL;
    memset(&error, 0, sizeof(error));
    assert(ovstorage_stack_config_from_toml_str(source,
                                                &direct,
                                                &error) ==
           OvStorage_Status_Ok);
    ovstorage = ovc_config_test_ovstorage(direct);
    assert(ovstorage != NULL);
    assert(ovc_config_table_get(*ovstorage, "root") == NULL);
    ovstorage_stack_config_destroy(direct);

    loaded = NULL;
    assert(ovstorage_stack_config_from_toml_path(path,
                                                 &loaded,
                                                 &error) ==
           OvStorage_Status_Ok);
    ovstorage = ovc_config_test_ovstorage(loaded);
    assert(ovstorage != NULL);
    root = ovc_config_table_get(*ovstorage, "root");
    assert(ovc_config_datum_string_valid(root));
    assert(strcmp(root->u.str.ptr, "files") == 0);
    overlay_probe = ovc_config_table_get(*ovstorage, "overlay_probe");
    assert(overlay_probe != NULL && overlay_probe->type == TOML_ARRAY);
    assert(overlay_probe->u.arr.size == 1);
    assert(overlay_probe->u.arr.elem[0].type == TOML_TABLE);
    overlay_value = ovc_config_table_get(overlay_probe->u.arr.elem[0],
                                         "value");
    assert(ovc_config_datum_string_valid(overlay_value));
    assert(strcmp(overlay_value->u.str.ptr, "new") == 0);
    assert(ovc_config_table_get(*ovstorage, "ignored") == NULL);
    layers = ovc_config_table_get(*ovstorage, "layers");
    assert(layers != NULL);
    files = ovc_config_table_get(*layers, "files");
    assert(files != NULL);
    kind = ovc_config_table_get(*files, "kind");
    assert(ovc_config_datum_string_valid(kind));
    assert(strcmp(kind->u.str.ptr, "file") == 0);
    layer_root = ovc_config_table_get(*files, "root");
    assert(ovc_config_datum_string_valid(layer_root));
    assert(strcmp(layer_root->u.str.ptr, "/tmp") == 0);
    aliases = ovc_config_table_get(*files, "aliases");
    assert(aliases != NULL && aliases->type == TOML_ARRAY);
    assert(aliases->u.arr.size == 3);
    assert(aliases->u.arr.elem[0].type == TOML_STRING);
    assert(strcmp(aliases->u.arr.elem[0].u.str.ptr, "hi") == 0);
    assert(aliases->u.arr.elem[1].type == TOML_BOOLEAN);
    assert(aliases->u.arr.elem[2].type == TOML_TABLE);
    big = ovc_config_table_get(*ovstorage, "overlay_big");
    assert(ovc_config_datum_string_valid(big));
    assert(strcmp(big->u.str.ptr, "9223372036854775808") == 0);
    exponent = ovc_config_table_get(*ovstorage, "overlay_exponent");
    assert(ovc_config_datum_string_valid(exponent));
    assert(strcmp(exponent->u.str.ptr, "1e3") == 0);
    ovstorage_stack_config_destroy(loaded);

    ovc_config_test_set_env("OVSTORAGE__LAYERS__FILES__ALIASES", NULL);
    ovc_config_test_set_env("OVSTORAGE__LAYERS__FILES__ROOT", NULL);
    ovc_config_test_set_env("OVSTORAGE__LAYERS__FILES", NULL);
    ovc_config_test_set_env("OVSTORAGE__OVERLAY_BIG", NULL);
    ovc_config_test_set_env("OVSTORAGE__OVERLAY_EXPONENT", NULL);
    ovc_config_test_set_env("OVSTORAGE__OVERLAY_PROBE", NULL);
    ovc_config_test_set_env("OVSTORAGE__IGNORED____KEY", NULL);

    ovc_config_test_set_env("OVSTORAGE__L\xc3\x84" "YER", "invalid");
    loaded = (OvStorage_StackConfig *)(uintptr_t)1;
    assert(ovstorage_stack_config_from_toml_path(path,
                                                 &loaded,
                                                 &error) ==
           OvStorage_Status_InvalidArgument);
    assert(loaded == NULL);
    assert(error.message != NULL);
    assert(strstr(error.message, "non-ASCII") != NULL);
    ovstorage_error_clear(&error);
    ovc_config_test_set_env("OVSTORAGE__L\xc3\x84" "YER", NULL);

    loaded = NULL;
    assert(ovstorage_stack_config_from_toml_path(path,
                                                 &loaded,
                                                 &error) ==
           OvStorage_Status_Ok);
    registry = ovstorage_registry_create();
    assert(registry != NULL);
    handle = NULL;
    assert(ovstorage_stack_build_from_config(loaded,
                                             registry,
                                             NULL,
                                             &handle,
                                             &error) ==
           OvStorage_Status_Ok);
    assert(handle != NULL);
    ovstorage_layer_handle_destroy(handle);
    ovstorage_registry_destroy(registry);
    ovstorage_stack_config_destroy(loaded);
    ovstorage_error_clear(&error);
    ovc_config_test_set_env("OVSTORAGE__ROOT", NULL);
    ovc_config_test_set_env("OvStorage__Root", NULL);
    assert(remove(path) == 0);
}

static void ovc_config_test_numeric_locale(const char *directory)
{
    static const char source[] = "[ovstorage]\nratio = 1.25\n";
#if defined(_WIN32)
    static const char *candidates[] = {
        "German_Germany.1252",
        "French_France.1252",
    };
#else
    static const char *candidates[] = {
        "de_DE.UTF-8",
        "de_DE.utf8",
        "fr_FR.UTF-8",
        "fr_FR.utf8",
    };
#endif
    char path[OVC_TEMP_DIR_PATH_MAX + 32];
    char *previous;
    const char *active;
    size_t index;
    int written;
    OvStorage_StackConfig *config;
    OvStorage_Error error;
    const toml_datum_t *ovstorage;
    const toml_datum_t *ratio;

    active = setlocale(LC_NUMERIC, NULL);
    previous = ovc_config_duplicate(active);
    assert(previous != NULL);
    active = NULL;
    for (index = 0; index < sizeof(candidates) / sizeof(candidates[0]);
         ++index) {
        if (setlocale(LC_NUMERIC, candidates[index]) != NULL &&
            strcmp(localeconv()->decimal_point, ",") == 0) {
            active = candidates[index];
            break;
        }
    }
    if (active == NULL) {
        assert(setlocale(LC_NUMERIC, previous) != NULL);
        free(previous);
        return;
    }

    memset(&error, 0, sizeof(error));
    config = NULL;
    assert(ovstorage_stack_config_from_toml_str(source, &config, &error) ==
           OvStorage_Status_Ok);
    ovstorage = ovc_config_test_ovstorage(config);
    ratio = ovc_config_table_get(*ovstorage, "ratio");
    assert(ratio != NULL && ratio->type == TOML_FP64);
    assert(ratio->u.fp64 == 1.25);
    ovstorage_stack_config_destroy(config);

    written = snprintf(path, sizeof(path), "%s/locale.toml", directory);
    assert(written > 0 && (size_t)written < sizeof(path));
    ovc_config_test_write(path, "[ovstorage]\n");
    ovc_config_test_set_env("OVSTORAGE__RATIO", "1.25");
    config = NULL;
    assert(ovstorage_stack_config_from_toml_path(path, &config, &error) ==
           OvStorage_Status_Ok);
    ovstorage = ovc_config_test_ovstorage(config);
    ratio = ovc_config_table_get(*ovstorage, "ratio");
    assert(ratio != NULL && ratio->type == TOML_FP64);
    assert(ratio->u.fp64 == 1.25);
    ovstorage_stack_config_destroy(config);
    ovc_config_test_set_env("OVSTORAGE__RATIO", NULL);
    assert(remove(path) == 0);
    ovstorage_error_clear(&error);
    assert(setlocale(LC_NUMERIC, previous) != NULL);
    free(previous);
}

static void ovc_config_test_default_path(const char *directory)
{
    static const char user_source[] =
        "[ovstorage]\n"
        "root = \"user\"\n"
        "[ovstorage.layers.user]\n"
        "kind = \"file\"\n";
    static const char local_source[] =
        "[ovstorage]\n"
        "root = \"local\"\n"
        "[ovstorage.layers.local]\n"
        "kind = \"file\"\n";
    char previous[OVC_TEMP_DIR_PATH_MAX * 2];
    OvStorage_StackConfig *config;
    OvStorage_Error error;
    const toml_datum_t *ovstorage;
    const toml_datum_t *root;

    assert(ovc_config_test_getcwd(previous, sizeof(previous)) != NULL);
    assert(ovc_config_test_chdir(directory) == 0);
    ovc_config_test_set_env("XDG_CONFIG_HOME", directory);
    memset(&error, 0, sizeof(error));
    config = (OvStorage_StackConfig *)(uintptr_t)1;
    assert(ovstorage_stack_config_from_default_path(&config, &error) ==
           OvStorage_Status_Ok);
    assert(config == NULL);

    ovc_config_test_mkdir("./ovstorage");
    ovc_config_test_write("./ovstorage/ovstorage.toml", user_source);
    assert(ovstorage_stack_config_from_default_path(&config, &error) ==
           OvStorage_Status_Ok);
    assert(config != NULL);
    ovstorage = ovc_config_test_ovstorage(config);
    root = ovc_config_table_get(*ovstorage, "root");
    assert(ovc_config_datum_string_valid(root));
    assert(strcmp(root->u.str.ptr, "user") == 0);
    ovstorage_stack_config_destroy(config);

    ovc_config_test_write("./ovstorage.toml", local_source);
    config = NULL;
    assert(ovstorage_stack_config_from_default_path(&config, &error) ==
           OvStorage_Status_Ok);
    assert(config != NULL);
    ovstorage = ovc_config_test_ovstorage(config);
    root = ovc_config_table_get(*ovstorage, "root");
    assert(ovc_config_datum_string_valid(root));
    assert(strcmp(root->u.str.ptr, "local") == 0);
    ovstorage_stack_config_destroy(config);
    assert(remove("./ovstorage.toml") == 0);
    assert(remove("./ovstorage/ovstorage.toml") == 0);
    assert(ovc_config_test_rmdir("./ovstorage") == 0);
    assert(ovc_config_test_chdir(previous) == 0);
    ovc_config_test_set_env("XDG_CONFIG_HOME", NULL);
    ovstorage_error_clear(&error);
}

static void ovc_config_test_credentials(void)
{
    static const char raw_text[] = "before-${OVC_CONFIG_SECRET}-after";
    static const char source[] =
        "[ovstorage]\n"
        "root = \"files\"\n"
        "[ovstorage.layers.files]\n"
        "kind = \"file\"\n"
        "[[ovstorage.connections]]\n"
        "backend_kind = \"file\"\n"
        "target = \"files\"\n"
        "credentials = { token = \"${OVC_CONFIG_SECRET}\" }\n";
    toml_datum_t raw;
    ovc_config_text resolved;
    OvStorage_StackConfig *config;
    OvStorage_Registry *registry;
    OvStorage_LayerHandle *handle;
    OvStorage_Error error;

    memset(&raw, 0, sizeof(raw));
    raw.type = TOML_STRING;
    raw.u.str.ptr = raw_text;
    raw.u.str.len = (int)(sizeof(raw_text) - 1);
    memset(&resolved, 0, sizeof(resolved));
    memset(&error, 0, sizeof(error));
    ovc_config_test_set_env("OVC_CONFIG_SECRET", "s\xc3\xab" "cret");
    assert(ovc_config_resolve_credential("token",
                                         &raw,
                                         &resolved,
                                         &error) ==
           OvStorage_Status_Ok);
    assert(strcmp(resolved.data, "before-s\xc3\xab" "cret-after") == 0);
    ovc_config_text_clear(&resolved, true);
    ovc_config_test_set_env("OVC_CONFIG_SECRET", NULL);
    memset(&resolved, 0, sizeof(resolved));
    assert(ovc_config_resolve_credential("token",
                                         &raw,
                                         &resolved,
                                         &error) ==
           OvStorage_Status_NotFound);
    assert(strstr(ovstorage_error_message(&error),
                  "OVC_CONFIG_SECRET") != NULL);
    ovc_config_text_clear(&resolved, true);
    ovstorage_error_clear(&error);

    config = NULL;
    assert(ovstorage_stack_config_from_toml_str(source, &config, &error) ==
           OvStorage_Status_Ok);
    registry = ovstorage_registry_create();
    assert(registry != NULL);
    handle = (OvStorage_LayerHandle *)(uintptr_t)1;
    assert(ovstorage_stack_build_from_config(config,
                                             registry,
                                             NULL,
                                             &handle,
                                             &error) ==
           OvStorage_Status_NotFound);
    assert(handle == NULL);
    assert(strstr(ovstorage_error_message(&error),
                  "OVC_CONFIG_SECRET") != NULL);
    ovstorage_registry_destroy(registry);
    ovstorage_stack_config_destroy(config);
    ovstorage_error_clear(&error);
}

int main(void)
{
    char directory[OVC_TEMP_DIR_PATH_MAX];

    assert(ovc_temp_dir_create("ovstorage-stack-config",
                               directory,
                               sizeof(directory)) == 0);
    ovc_config_test_build_reusable();
    ovc_config_test_empty_and_errors();
    ovc_config_test_toml_grammar();
    ovc_config_test_path_overlay(directory);
    ovc_config_test_numeric_locale(directory);
    ovc_config_test_default_path(directory);
    ovc_config_test_credentials();
    assert(ovc_config_test_rmdir(directory) == 0);
    return EXIT_SUCCESS;
}

#endif
