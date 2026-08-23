/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(OVSTORAGE_CC_TEST_WINDOWS_POSIX_COMPAT_H)
#define OVSTORAGE_CC_TEST_WINDOWS_POSIX_COMPAT_H

#if !defined(_WIN32)
#error "windows_posix_compat.h is Windows-only"
#endif

/* Scope: exactly what the C and C++ cc-test drivers use on Windows, and
 * nothing more.
 *
 * Covered:
 *   - the pthread subset the drivers call: `pthread_create` / `pthread_join`,
 *     `pthread_mutex_*`, and `pthread_cond_init` / `_destroy` / `_wait` /
 *     `_signal`, over SRWLOCK and CONDITION_VARIABLE;
 *   - dynamic loading: `dlopen` / `dlsym` / `dlerror` and the `RTLD_*` flags
 *     the drivers pass, over LoadLibraryW / GetProcAddress;
 *   - the small file helpers `ovc_test_remove_file` / `ovc_test_remove_dir` /
 *     `ovc_test_strerror`, which are spelled with their own names rather than
 *     as `unlink` / `rmdir` / `strerror` because their Win32 semantics differ
 *     (each caller #defines the POSIX spelling onto them if it wants to).
 *
 * Deliberately NOT covered, among others: `pthread_cond_broadcast`, thread
 * attributes, cancellation, `pthread_rwlock_*`, `pthread_key_*`, and
 * `<dirent.h>` directory iteration.
 *
 * An absence is not an oversight, and it fails at COMPILE time rather than
 * behaving subtly differently at run time, which is the point. When a driver
 * needs something not here, the two correct responses are to add it here
 * deliberately -- with the same "is this really equivalent on Win32" scrutiny
 * as the entries above -- or to leave it out and target-gate that driver.
 * Do not approximate a POSIX primitive whose Win32 counterpart differs in
 * observable behaviour.
 */

#include <errno.h>
#include <process.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
/* `strerror_s` below: declare it directly instead of relying on <windows.h>
 * pulling <string.h> in transitively. */
#include <string.h>
#include <windows.h>

typedef SRWLOCK pthread_mutex_t;
typedef CONDITION_VARIABLE pthread_cond_t;
typedef HANDLE pthread_t;

typedef struct ovc_test_pthread_start {
    void *(*start_routine)(void *);
    void *argument;
} ovc_test_pthread_start;

static unsigned __stdcall ovc_test_pthread_trampoline(void *argument)
{
    ovc_test_pthread_start start;
    void *result;

    start = *(ovc_test_pthread_start *)argument;
    free(argument);
    result = start.start_routine(start.argument);
    return (unsigned)(uintptr_t)result;
}

static inline int pthread_create(pthread_t *thread,
                                 const void *attributes,
                                 void *(*start_routine)(void *),
                                 void *argument)
{
    ovc_test_pthread_start *start;
    uintptr_t handle;

    (void)attributes;
    start = (ovc_test_pthread_start *)malloc(sizeof(*start));
    if (start == NULL) {
        return errno != 0 ? errno : ENOMEM;
    }
    start->start_routine = start_routine;
    start->argument = argument;
    handle = _beginthreadex(NULL, 0, ovc_test_pthread_trampoline, start, 0, NULL);
    if (handle == 0) {
        free(start);
        return errno != 0 ? errno : EAGAIN;
    }
    *thread = (HANDLE)handle;
    return 0;
}

static inline int pthread_join(pthread_t thread, void **value_ptr)
{
    DWORD wait_status;

    (void)value_ptr;
    wait_status = WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    return wait_status == WAIT_OBJECT_0 ? 0 : EIO;
}

static inline int pthread_mutex_init(pthread_mutex_t *mutex,
                                     const void *attributes)
{
    (void)attributes;
    InitializeSRWLock(mutex);
    return 0;
}

static inline int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    (void)mutex;
    return 0;
}

static inline int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    AcquireSRWLockExclusive(mutex);
    return 0;
}

static inline int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    ReleaseSRWLockExclusive(mutex);
    return 0;
}

static inline int pthread_cond_init(pthread_cond_t *condition,
                                    const void *attributes)
{
    (void)attributes;
    InitializeConditionVariable(condition);
    return 0;
}

static inline int pthread_cond_destroy(pthread_cond_t *condition)
{
    (void)condition;
    return 0;
}

static inline int pthread_cond_wait(pthread_cond_t *condition,
                                    pthread_mutex_t *mutex)
{
    return SleepConditionVariableSRW(condition, mutex, INFINITE, 0) ? 0 : EIO;
}

static inline int pthread_cond_signal(pthread_cond_t *condition)
{
    WakeConditionVariable(condition);
    return 0;
}

static inline wchar_t *ovc_test_wide_path(const char *path)
{
    int count;
    wchar_t *wide;

    count = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (count <= 0) {
        errno = EINVAL;
        return NULL;
    }
    wide = (wchar_t *)malloc((size_t)count * sizeof(*wide));
    if (wide == NULL) {
        return NULL;
    }
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, count) <= 0) {
        free(wide);
        errno = EINVAL;
        return NULL;
    }
    return wide;
}

static inline int ovc_test_remove_file(const char *path)
{
    wchar_t *wide;
    DWORD error;

    wide = ovc_test_wide_path(path);
    if (wide == NULL) {
        return -1;
    }
    if (DeleteFileW(wide) != 0) {
        free(wide);
        return 0;
    }
    error = GetLastError();
    free(wide);
    /* Both codes mean "absent" and both occur: the leaf being absent reports
     * ERROR_FILE_NOT_FOUND, an absent parent component reports
     * ERROR_PATH_NOT_FOUND.  Callers treat these removals as best-effort
     * cleanup keyed on ENOENT, so folding either into EIO would turn an
     * already-absent path into a hard error. */
    errno = (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
                ? ENOENT
                : EIO;
    return -1;
}

static inline int ovc_test_remove_dir(const char *path)
{
    wchar_t *wide;
    DWORD error;

    wide = ovc_test_wide_path(path);
    if (wide == NULL) {
        return -1;
    }
    if (RemoveDirectoryW(wide) != 0) {
        free(wide);
        return 0;
    }
    error = GetLastError();
    free(wide);
    /* RemoveDirectoryW reports an absent leaf directory as
     * ERROR_FILE_NOT_FOUND, not ERROR_PATH_NOT_FOUND; the latter means an
     * absent parent component.  The absent leaf is the common cleanup case,
     * so accepting only one of the two would map it to EIO. */
    errno = (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
                ? ENOENT
                : EIO;
    return -1;
}

static inline const char *ovc_test_strerror(int error)
{
    static __declspec(thread) char message[256];

    if (strerror_s(message, sizeof(message), error) != 0) {
        (void)snprintf(message, sizeof(message), "system error %d", error);
    }
    return message;
}

/* The parked-discovery and inspect drivers use the POSIX dlopen surface.
 * Map it onto LoadLibraryW / GetProcAddress so those contracts compile and
 * run against Windows DLLs without a separate Windows-only call path. */
#define RTLD_NOW 0
#define RTLD_LOCAL 0

static inline void *dlopen(const char *path, int flags)
{
    wchar_t *wide;
    HMODULE module;

    (void)flags;
    wide = ovc_test_wide_path(path);
    if (wide == NULL) {
        return NULL;
    }
    module = LoadLibraryW(wide);
    free(wide);
    return (void *)module;
}

static inline void *dlsym(void *handle, const char *symbol)
{
    if (handle == NULL || symbol == NULL) {
        return NULL;
    }
    {
        /* `memcpy` rather than a cast. The cast form did not emit C4152 on
         * cl.exe 14.44.35207 under /W4 /WX in either C or C++ -- measured
         * both ways -- but the diagnostic exists for exactly this
         * conversion, other MSVC versions may differ, and this spelling is
         * unambiguously conforming at no cost. `plat.c` does the same. */
        FARPROC symbol_address = GetProcAddress((HMODULE)handle, symbol);
        void *result = NULL;

        memcpy(&result, &symbol_address, sizeof(result));
        return result;
    }
}

static inline char *dlerror(void)
{
    static __declspec(thread) char message[128];
    DWORD error;

    error = GetLastError();
    if (error == 0) {
        return NULL;
    }
    (void)snprintf(message, sizeof(message), "Win32 error %lu", (unsigned long)error);
    return message;
}

#endif
