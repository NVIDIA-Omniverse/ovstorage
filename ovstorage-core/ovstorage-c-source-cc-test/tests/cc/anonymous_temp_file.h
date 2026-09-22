/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef OVSTORAGE_CC_TEST_ANONYMOUS_TEMP_FILE_H
#define OVSTORAGE_CC_TEST_ANONYMOUS_TEMP_FILE_H

#include "../../../../ovstorage-c-source/src/temp_dir.h"

#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

/* An unnamed read/write temporary file for redirected-stream captures.
 * `tmpfile()` ignores the configured temporary root on glibc and the MSVC
 * CRT, so both branches create beneath ovc_temp_root_dup() and immediately
 * arrange delete-on-close semantics. */
static FILE *ovc_test_open_anonymous_temp_file(void)
{
#if defined(_WIN32)
    char path[OVC_TEMP_DIR_PATH_MAX];
    char *root;
    FILE *stream;
    int written;
    int descriptor;

    root = ovc_temp_root_dup();
    if (root == NULL) {
        return NULL;
    }
    written = snprintf(path,
                       sizeof(path),
                       "%s\\ovstorage-capture-%lu-%u",
                       root,
                       (unsigned long)GetCurrentProcessId(),
                       (unsigned)GetTickCount());
    free(root);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return NULL;
    }
    if (_sopen_s(&descriptor,
                 path,
                 _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY | _O_TEMPORARY,
                 _SH_DENYNO,
                 _S_IREAD | _S_IWRITE) != 0) {
        return NULL;
    }
    stream = _fdopen(descriptor, "w+b");
    if (stream == NULL) {
        _close(descriptor);
    }
    return stream;
#else
    char path[OVC_TEMP_DIR_PATH_MAX];
    char *root;
    FILE *stream;
    int written;
    int descriptor;

    root = ovc_temp_root_dup();
    if (root == NULL) {
        return NULL;
    }
    written = snprintf(path,
                       sizeof(path),
                       "%s/ovstorage-c-source-capture-XXXXXX",
                       root);
    free(root);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return NULL;
    }
    descriptor = mkstemp(path);
    if (descriptor < 0) {
        return NULL;
    }
    if (unlink(path) != 0) {
        (void)close(descriptor);
        return NULL;
    }
    stream = fdopen(descriptor, "w+b");
    if (stream == NULL) {
        (void)close(descriptor);
        return NULL;
    }
    return stream;
#endif
}

#endif /* OVSTORAGE_CC_TEST_ANONYMOUS_TEMP_FILE_H */
