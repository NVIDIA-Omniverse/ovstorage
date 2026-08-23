/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(OVSTORAGE_CC_TEST_SIDECAR_CLEANUP_H)
#define OVSTORAGE_CC_TEST_SIDECAR_CLEANUP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <wchar.h>

#include "windows_posix_compat.h"
#else
#include <dirent.h>
#include <unistd.h>
#endif

/* Best-effort removal of the file backend's user-metadata sidecar directory
 * (`<parent>/.ovstorage-meta/`) so a final rmdir sees an empty tree even if a
 * failing run left sidecars behind.
 *
 * One definition, shared by the C round-trip and handoff drivers. The Win32
 * half is a ~40-line FindFirstFileW/FindNextFileW walk, so a per-driver copy
 * would have to be fixed or extended in every driver at once. */
static inline void ovc_test_remove_metadata_sidecars(const char *directory)
{
    char meta_directory[600];
#if defined(_WIN32)
    wchar_t *wide_directory;
    wchar_t pattern[600];
    wchar_t entry_path[1200];
    WIN32_FIND_DATAW entry;
    HANDLE handle;
#else
    char entry_path[1200];
    DIR *handle;
    struct dirent *entry;
#endif
    int written;

    written = snprintf(meta_directory,
                       sizeof(meta_directory),
                       "%s/.ovstorage-meta",
                       directory);
    if (written < 0 || (size_t)written >= sizeof(meta_directory)) {
        return;
    }
#if defined(_WIN32)
    wide_directory = ovc_test_wide_path(meta_directory);
    if (wide_directory == NULL) {
        return;
    }
    if (swprintf_s(pattern, 600, L"%ls\\*", wide_directory) < 0) {
        free(wide_directory);
        return;
    }
    handle = FindFirstFileW(pattern, &entry);
    if (handle != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(entry.cFileName, L".") == 0 ||
                wcscmp(entry.cFileName, L"..") == 0) {
                continue;
            }
            if (swprintf_s(entry_path,
                           1200,
                           L"%ls\\%ls",
                           wide_directory,
                           entry.cFileName) >= 0) {
                if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                    (void)RemoveDirectoryW(entry_path);
                } else {
                    (void)DeleteFileW(entry_path);
                }
            }
        } while (FindNextFileW(handle, &entry) != 0);
        (void)FindClose(handle);
    }
    (void)RemoveDirectoryW(wide_directory);
    free(wide_directory);
#else
    handle = opendir(meta_directory);
    if (handle != NULL) {
        while ((entry = readdir(handle)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            written = snprintf(entry_path,
                               sizeof(entry_path),
                               "%s/%s",
                               meta_directory,
                               entry->d_name);
            if (written > 0 && (size_t)written < sizeof(entry_path)) {
                (void)unlink(entry_path);
            }
        }
        (void)closedir(handle);
    }
    (void)rmdir(meta_directory);
#endif
}

#endif /* OVSTORAGE_CC_TEST_SIDECAR_CLEANUP_H */
