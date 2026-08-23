/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(OVSTORAGE_CC_TEST_FILE_URL_H)
#define OVSTORAGE_CC_TEST_FILE_URL_H

#include <stdio.h>
#include <stddef.h>

/* Append one byte of a `file://` URL path component to `out`, percent-encoding
 * it if it is outside the set that passes through literally.
 *
 * The rule is RFC 3986: pass the unreserved set through, escape every other
 * byte.  `/` is kept because it is already the URL separator by the time this
 * runs, and `:` because a Windows drive letter needs it.  Escaping a byte that
 * did not strictly need it is harmless -- the receiver decodes.
 *
 * Bytes are escaped individually, so a UTF-8 path encodes correctly and any
 * other encoding survives round-trip unchanged.
 *
 * `*written` is the offset to append at, advanced by what this wrote.  Room is
 * always left for the terminator the caller writes.
 *
 * Returns 0 on success, -1 if `out_size` is too small, -2 if `directory` is a
 * UNC path the file backend cannot address. */
static inline int test_percent_encode_byte(unsigned char byte,
                                           char *out,
                                           size_t out_size,
                                           size_t *written)
{
    static const char hex_digits[] = "0123456789ABCDEF";
    int literal = (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
                  (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' ||
                  byte == '_' || byte == '~' || byte == '/' || byte == ':';

    if (literal) {
        if (*written + 1 >= out_size) {
            return -1;
        }
        out[(*written)++] = (char)byte;
        return 0;
    }
    if (*written + 3 >= out_size) {
        return -1;
    }
    out[(*written)++] = '%';
    out[(*written)++] = hex_digits[byte >> 4];
    out[(*written)++] = hex_digits[byte & 0x0FU];
    return 0;
}

/* Render a NATIVE directory path as the path component of a `file://` URL.
 *
 * `ovc_temp_dir_create` hands back a NATIVE path, and the caller owns the
 * conversion (see src/temp_dir.h).  It matters: a temp root holding `#`, `?`
 * or `%` changes how the address parses, or is rejected outright, and the
 * default Windows temp root sits under `C:\Users\<username>\...` where spaces
 * are routine.
 *
 * This is the whole conversion -- the platform-specific separator handling and
 * the percent-encoding.  It lives here once because the two halves have to
 * agree and because the Win32 half must never run on POSIX.
 *
 * On Win32 a drive path needs the third slash after `file://`, and `\` is a
 * path separator that becomes the URL separator `/`.
 *
 * A UNC root is REJECTED rather than converted.  Suppressing the third slash
 * for `\\server\share` yields `file:` + `//server/share/...`, and the file
 * backend's parser reads the leading `//` as an authority and refuses a
 * non-empty one, while its Win32 native-path normalizer accepts drive-letter
 * roots only.  Emitting that address moves the failure to Stack build time
 * with an `InvalidArgument` that names nothing; failing here names the cause.
 * `GetTempPathW` returns a UNC path when TMP/TEMP points at a share, so this
 * is reachable on a real developer machine even though CI runners use a
 * local drive.
 *
 * On POSIX the path is already rooted at `/`, and a `\` in it is an ordinary
 * filename byte -- rewriting it would address a different path, or none at all
 * -- so only the encoding applies.
 *
 * Callers prepend `file://` and append their own object suffix.
 *
 * Returns 0 on success, -1 if `out_size` is too small, -2 if `directory` is a
 * UNC path the file backend cannot address. */
static inline int test_file_url_path(const char *directory,
                                     char *out,
                                     size_t out_size)
{
    size_t written = 0;
    size_t index;

#if defined(_WIN32)
    if (directory[0] == '\\' && directory[1] == '\\') {
        (void)fprintf(stderr,
                      "the temporary root is a UNC path (%s); the file "
                      "backend addresses drive-letter roots only. Point "
                      "TMP/TEMP at a local drive.\n",
                      directory);
        return -2;
    }
    if (test_percent_encode_byte('/', out, out_size, &written) != 0) {
        return -1;
    }
#endif
    for (index = 0; directory[index] != '\0'; ++index) {
        unsigned char byte = (unsigned char)directory[index];

#if defined(_WIN32)
        if (byte == '\\') {
            byte = '/';
        }
#endif
        if (test_percent_encode_byte(byte, out, out_size, &written) != 0) {
            return -1;
        }
    }
    out[written] = '\0';
    return 0;
}

#endif /* OVSTORAGE_CC_TEST_FILE_URL_H */
