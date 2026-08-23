/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "internal.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Source-distribution CI compiles both platform branches with their native
 * toolchains. */

#if defined(OVC_ABI_ALLOC_FAILURE_TEST)
/* Test-only predicate supplied by the leak-contract driver. The one-shot trap
 * is thread-local there, so unrelated runtime workers cannot consume an
 * arming intended for a synchronous dispatcher prologue. */
int ovc_test_abi_alloc_should_fail(size_t byte_count);
#endif

struct ovc_thread_start {
    ovc_thread_fn function;
    void *argument;
};

#if defined(_WIN32)

#include <process.h>

#if defined(_MSC_VER)
#define OVC_THREAD_LOCAL __declspec(thread)
#else
#define OVC_THREAD_LOCAL __thread
#endif

struct ovc_loader_error {
    char message[512];
    int pending;
};

static OVC_THREAD_LOCAL struct ovc_loader_error g_ovc_loader_error;

static void ovc_loader_error_clear(void)
{
    g_ovc_loader_error.message[0] = '\0';
    g_ovc_loader_error.pending = 0;
}

static void ovc_loader_error_set(DWORD error_code)
{
    wchar_t wide_message[512];
    DWORD wide_length;
    int utf8_length;

    wide_length = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM |
                                     FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL,
                                 error_code,
                                 0,
                                 wide_message,
                                 (DWORD)(sizeof(wide_message) /
                                         sizeof(wide_message[0])),
                                 NULL);
    utf8_length = 0;
    if (wide_length != 0) {
        utf8_length = WideCharToMultiByte(
            CP_UTF8,
            0,
            wide_message,
            (int)wide_length,
            g_ovc_loader_error.message,
            (int)sizeof(g_ovc_loader_error.message) - 1,
            NULL,
            NULL);
    }
    if (utf8_length == 0) {
        (void)snprintf(g_ovc_loader_error.message,
                       sizeof(g_ovc_loader_error.message),
                       "Win32 loader error %lu",
                       (unsigned long)error_code);
    } else {
        g_ovc_loader_error.message[utf8_length] = '\0';
        while (utf8_length > 0 &&
               (g_ovc_loader_error.message[utf8_length - 1] == '\r' ||
                g_ovc_loader_error.message[utf8_length - 1] == '\n')) {
            --utf8_length;
            g_ovc_loader_error.message[utf8_length] = '\0';
        }
    }
    g_ovc_loader_error.pending = 1;
}

wchar_t *ovc_utf8_to_wide(const char *utf8)
{
    int wide_count;
    wchar_t *wide;

    if (utf8 == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    wide_count = MultiByteToWideChar(CP_UTF8,
                                     MB_ERR_INVALID_CHARS,
                                     utf8,
                                     -1,
                                     NULL,
                                     0);
    if (wide_count == 0) {
        return NULL;
    }
    if ((size_t)wide_count > SIZE_MAX / sizeof(*wide)) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    wide = (wchar_t *)malloc((size_t)wide_count * sizeof(*wide));
    if (wide == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    if (MultiByteToWideChar(CP_UTF8,
                            MB_ERR_INVALID_CHARS,
                            utf8,
                            -1,
                            wide,
                            wide_count) == 0) {
        DWORD error_code;

        error_code = GetLastError();
        free(wide);
        SetLastError(error_code);
        return NULL;
    }
    return wide;
}

/* The reverse of ovc_utf8_to_wide: an owned UTF-8 copy of a wide string, or
 * NULL with errno set.
 *
 * Win32 path APIs come in ANSI and wide pairs, and the ANSI ones transcode
 * through the active code page -- so a path outside that page round-trips
 * to something else, or fails. Everything here carries UTF-8, so the wide
 * form is the only correct one to call and this pair is how callers get
 * back. */
char *ovc_wide_to_utf8(const wchar_t *wide)
{
    int count;
    char *utf8;

    count = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    if (count <= 0) {
        errno = EINVAL;
        return NULL;
    }
    utf8 = (char *)malloc((size_t)count);
    if (utf8 == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, count, NULL, NULL)
        <= 0) {
        free(utf8);
        errno = EINVAL;
        return NULL;
    }
    return utf8;
}

static unsigned __stdcall ovc_thread_entry(void *opaque)
{
    struct ovc_thread_start *start;
    ovc_thread_fn function;
    void *argument;

    start = (struct ovc_thread_start *)opaque;
    function = start->function;
    argument = start->argument;
    free(start);
    function(argument);
    return 0;
}

void ovc_win32_set_errno(DWORD error_code)
{
    switch (error_code) {
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
        errno = EACCES;
        break;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_DRIVE:
        errno = ENOENT;
        break;
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:
        errno = EEXIST;
        break;
    case ERROR_NOT_SAME_DEVICE:
        errno = EXDEV;
        break;
#ifdef ERROR_DIR_NOT_EMPTY
    case ERROR_DIR_NOT_EMPTY:
        errno = ENOTEMPTY;
        break;
#endif
    case ERROR_INVALID_HANDLE:
        errno = EBADF;
        break;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
        errno = ENOMEM;
        break;
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:
        errno = ENOSPC;
        break;
    case ERROR_OPERATION_ABORTED:
#ifdef ECANCELED
        errno = ECANCELED;
#else
        errno = EINTR;
#endif
        break;
    case ERROR_FILENAME_EXCED_RANGE:
    /* On a long-path-enabled host a >255-char (hex-doubled) sidecar
     * component passes Win32 normalization but NTFS rejects it as
     * STATUS_OBJECT_NAME_INVALID -> ERROR_INVALID_NAME.  Like an
     * over-long path, such a name cannot exist, so the file backend's
     * sidecar probes' "cannot exist => absent" tolerance depends on this
     * mapping. */
    case ERROR_INVALID_NAME:
        errno = ENAMETOOLONG;
        break;
    case ERROR_ARITHMETIC_OVERFLOW:
#ifdef EOVERFLOW
        errno = EOVERFLOW;
#else
        errno = ERANGE;
#endif
        break;
    default:
        errno = EIO;
        break;
    }
}

static size_t ovc_win_io_size(size_t byte_count)
{
    size_t maximum;

    maximum = (size_t)MAXDWORD;
    if ((size_t)INTPTR_MAX < maximum) {
        maximum = (size_t)INTPTR_MAX;
    }
    return byte_count < maximum ? byte_count : maximum;
}

/* Return floor(numerator * 1e9 / denominator) without overflowing. */
static uint64_t ovc_fraction_to_ns(uint64_t numerator, uint64_t denominator)
{
    uint64_t quotient;
    uint64_t remainder;
    uint64_t bit;

    quotient = 0;
    remainder = 0;
    bit = UINT64_C(1);
    while (bit <= UINT64_C(1000000000) / 2) {
        bit <<= 1;
    }

    for (; bit != 0; bit >>= 1) {
        quotient <<= 1;
        if (remainder >= denominator - remainder) {
            remainder -= denominator - remainder;
            ++quotient;
        } else {
            remainder <<= 1;
        }

        if ((UINT64_C(1000000000) & bit) != 0) {
            if (remainder >= denominator - numerator) {
                remainder -= denominator - numerator;
                ++quotient;
            } else {
                remainder += numerator;
            }
        }
    }
    return quotient;
}

int ovc_thread_create(ovc_thread *thread,
                      ovc_thread_fn function,
                      void *argument)
{
    struct ovc_thread_start *start;
    uintptr_t handle;
    int error_code;

    if (thread == NULL || function == NULL) {
        return EINVAL;
    }
    thread->handle = NULL;
    thread->joinable = 0;

    start = (struct ovc_thread_start *)malloc(sizeof(*start));
    if (start == NULL) {
        return ENOMEM;
    }
    start->function = function;
    start->argument = argument;

    errno = 0;
    handle = _beginthreadex(NULL, 0, ovc_thread_entry, start, 0, NULL);
    if (handle == 0) {
        error_code = errno != 0 ? errno : EAGAIN;
        free(start);
        return error_code;
    }

    thread->handle = (HANDLE)handle;
    thread->joinable = 1;
    return 0;
}

int ovc_thread_join(ovc_thread *thread)
{
    DWORD result;
    DWORD error_code;

    if (thread == NULL || !thread->joinable) {
        return EINVAL;
    }

    result = WaitForSingleObject(thread->handle, INFINITE);
    if (result != WAIT_OBJECT_0) {
        return result == WAIT_FAILED ? (int)GetLastError() : EINVAL;
    }
    if (!CloseHandle(thread->handle)) {
        error_code = GetLastError();
        return (int)error_code;
    }

    thread->handle = NULL;
    thread->joinable = 0;
    return 0;
}

int ovc_mutex_init(ovc_mutex *mutex)
{
    if (mutex == NULL) {
        return EINVAL;
    }
    InitializeSRWLock(&mutex->native);
    return 0;
}

int ovc_mutex_destroy(ovc_mutex *mutex)
{
    /* SRW locks own no resources, so Win32 has no destroy operation. */
    return mutex == NULL ? EINVAL : 0;
}

int ovc_mutex_lock(ovc_mutex *mutex)
{
    if (mutex == NULL) {
        return EINVAL;
    }
    AcquireSRWLockExclusive(&mutex->native);
    return 0;
}

int ovc_mutex_unlock(ovc_mutex *mutex)
{
    if (mutex == NULL) {
        return EINVAL;
    }
    ReleaseSRWLockExclusive(&mutex->native);
    return 0;
}

int ovc_cond_init(ovc_cond *condition)
{
    if (condition == NULL) {
        return EINVAL;
    }
    InitializeConditionVariable(&condition->native);
    return 0;
}

int ovc_cond_destroy(ovc_cond *condition)
{
    /* Condition variables own no resources on Win32. */
    return condition == NULL ? EINVAL : 0;
}

int ovc_cond_wait(ovc_cond *condition, ovc_mutex *mutex)
{
    if (condition == NULL || mutex == NULL) {
        return EINVAL;
    }
    if (!SleepConditionVariableSRW(&condition->native,
                                   &mutex->native,
                                   INFINITE,
                                   0)) {
        return (int)GetLastError();
    }
    return 0;
}

int ovc_cond_signal(ovc_cond *condition)
{
    if (condition == NULL) {
        return EINVAL;
    }
    WakeConditionVariable(&condition->native);
    return 0;
}

int ovc_cond_broadcast(ovc_cond *condition)
{
    if (condition == NULL) {
        return EINVAL;
    }
    WakeAllConditionVariable(&condition->native);
    return 0;
}

int ovc_cond_timedwait_ns(ovc_cond *condition,
                          ovc_mutex *mutex,
                          uint64_t wait_ns)
{
    DWORD timeout_ms;

    if (condition == NULL || mutex == NULL) {
        return EINVAL;
    }
    /* Win32 waits take a relative timeout, so wall-clock steps cannot stall
     * them.  Round up so a short nonzero wait cannot spin at zero. */
    if (wait_ns >= ((uint64_t)INFINITE - 1u) * 1000000u) {
        timeout_ms = INFINITE - 1u;
    } else {
        timeout_ms = (DWORD)((wait_ns + 999999u) / 1000000u);
    }
    if (!SleepConditionVariableSRW(&condition->native,
                                   &mutex->native,
                                   timeout_ms,
                                   0)) {
        DWORD error_code;

        error_code = GetLastError();
        return error_code == ERROR_TIMEOUT ? ETIMEDOUT : (int)error_code;
    }
    return 0;
}

ovc_dlhandle ovc_dlopen(const char *utf8_path)
{
    wchar_t *wide_path;
    HMODULE module;
    DWORD error_code;

    ovc_loader_error_clear();
    wide_path = ovc_utf8_to_wide(utf8_path);
    if (wide_path == NULL) {
        ovc_loader_error_set(GetLastError());
        return NULL;
    }

    module = LoadLibraryW(wide_path);
    error_code = module == NULL ? GetLastError() : ERROR_SUCCESS;
    free(wide_path);
    if (module == NULL) {
        ovc_loader_error_set(error_code);
    }
    return module;
}

/* `GetProcAddress` yields a FARPROC that `ovc_dlsym` republishes as a
 * `void *`.  C99 has no `_Static_assert`, so this typedef is the portable
 * spelling: it fails to compile if the two ever differ in width. */
typedef char ovc_dlsym_pointer_width_check
    [(sizeof(FARPROC) == sizeof(void *)) ? 1 : -1];

void *ovc_dlsym(ovc_dlhandle handle, const char *symbol_name)
{
    FARPROC symbol;
    void *result;

    ovc_loader_error_clear();
    if (handle == NULL || symbol_name == NULL) {
        ovc_loader_error_set(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    symbol = GetProcAddress(handle, symbol_name);
    if (symbol == NULL) {
        ovc_loader_error_set(GetLastError());
        return NULL;
    }
    /* The width equality below is a property of the target, not of this
     * call, so it is asserted at compile time.  Spelling it as a runtime
     * `if` made MSVC's /W4 reject the translation unit under /WX with
     * C4127 (conditional expression is constant), and left a branch that
     * can never be taken in shipped source. */
    result = NULL;
    memcpy(&result, &symbol, sizeof(result));
    return result;
}

const char *ovc_dlerror(void)
{
    if (!g_ovc_loader_error.pending) {
        return NULL;
    }
    g_ovc_loader_error.pending = 0;
    return g_ovc_loader_error.message;
}

void ovc_dlclose(ovc_dlhandle handle)
{
    if (handle != NULL) {
        (void)FreeLibrary(handle);
    }
}

/* The ABI heap is the process heap on Win32 so a value can cross a module
 * boundary and be released by whichever side owns it, which is the whole
 * point of having a dedicated allocator pair.
 *
 * `OVC_ABI_ALLOC_VIA_CRT` routes it through the CRT allocator instead, and
 * exists for one caller: the Windows leak-contract gate. `HeapAlloc` blocks
 * are invisible to `_CrtMemDumpAllObjectsSince`, so with the process heap
 * every ABI value the contracts allocate escapes the gate, so a leaked
 * `ovc_abi_alloc` block inside a measured contract passes green.
 * The substitution keeps the gate testing the ownership logic, which
 * is what it exists for, rather than testing which heap the bytes came from.
 * DO NOT define it in a production build. No shipped build file does, and
 * defining it swaps the ABI heap for the CRT heap — a value allocated by a
 * module built with it and freed by one built without it would cross
 * allocators. It exists for the leak gate and nothing else. */
void *ovc_abi_alloc(size_t byte_count)
{
#if defined(OVC_ABI_ALLOC_FAILURE_TEST)
    if (ovc_test_abi_alloc_should_fail(byte_count)) {
        return NULL;
    }
#endif
#if defined(OVC_ABI_ALLOC_VIA_CRT)
    return malloc(byte_count == 0 ? 1 : byte_count);
#else
    HANDLE process_heap;

    process_heap = GetProcessHeap();
    return process_heap == NULL
               ? NULL
               : HeapAlloc(process_heap, 0, byte_count == 0 ? 1 : byte_count);
#endif
}

void ovc_abi_free(void *allocation)
{
#if defined(OVC_ABI_ALLOC_VIA_CRT)
    free(allocation);
#else
    HANDLE process_heap;

    if (allocation == NULL) {
        return;
    }
    process_heap = GetProcessHeap();
    if (process_heap == NULL || !HeapFree(process_heap, 0, allocation)) {
        abort();
    }
#endif
}

ovc_ssize_t ovc_pread(ovc_file file,
                      void *buffer,
                      size_t byte_count,
                      uint64_t offset)
{
    OVERLAPPED overlapped;
    HANDLE event;
    DWORD transferred;
    DWORD error_code;
    BOOL completed;
    size_t request_size;

    if (file == NULL || file == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return (ovc_ssize_t)-1;
    }
    if (buffer == NULL && byte_count != 0) {
        errno = EINVAL;
        return (ovc_ssize_t)-1;
    }
    if (offset > (uint64_t)INT64_MAX) {
#ifdef EOVERFLOW
        errno = EOVERFLOW;
#else
        errno = ERANGE;
#endif
        return (ovc_ssize_t)-1;
    }
    if (byte_count == 0) {
        return 0;
    }

    request_size = ovc_win_io_size(byte_count);
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.Offset = (DWORD)(offset & UINT64_C(0xffffffff));
    overlapped.OffsetHigh = (DWORD)(offset >> 32);
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (event == NULL) {
        ovc_win32_set_errno(GetLastError());
        return (ovc_ssize_t)-1;
    }
    overlapped.hEvent = event;

    transferred = 0;
    completed = ReadFile(file,
                         buffer,
                         (DWORD)request_size,
                         &transferred,
                         &overlapped);
    if (!completed) {
        error_code = GetLastError();
        if (error_code == ERROR_IO_PENDING) {
            completed = GetOverlappedResult(file,
                                            &overlapped,
                                            &transferred,
                                            TRUE);
            error_code = completed ? ERROR_SUCCESS : GetLastError();
        }
        if (!completed && error_code == ERROR_HANDLE_EOF) {
            (void)CloseHandle(event);
            return 0;
        }
        if (!completed) {
            (void)CloseHandle(event);
            ovc_win32_set_errno(error_code);
            return (ovc_ssize_t)-1;
        }
    } else if (!GetOverlappedResult(file,
                                    &overlapped,
                                    &transferred,
                                    FALSE)) {
        error_code = GetLastError();
        (void)CloseHandle(event);
        ovc_win32_set_errno(error_code);
        return (ovc_ssize_t)-1;
    }

    (void)CloseHandle(event);
    return (ovc_ssize_t)transferred;
}

ovc_ssize_t ovc_pwrite(ovc_file file,
                       const void *buffer,
                       size_t byte_count,
                       uint64_t offset)
{
    OVERLAPPED overlapped;
    HANDLE event;
    DWORD transferred;
    DWORD error_code;
    BOOL completed;
    size_t request_size;

    if (file == NULL || file == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return (ovc_ssize_t)-1;
    }
    if (buffer == NULL && byte_count != 0) {
        errno = EINVAL;
        return (ovc_ssize_t)-1;
    }
    if (offset > (uint64_t)INT64_MAX) {
#ifdef EOVERFLOW
        errno = EOVERFLOW;
#else
        errno = ERANGE;
#endif
        return (ovc_ssize_t)-1;
    }
    if (byte_count == 0) {
        return 0;
    }

    request_size = ovc_win_io_size(byte_count);
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.Offset = (DWORD)(offset & UINT64_C(0xffffffff));
    overlapped.OffsetHigh = (DWORD)(offset >> 32);
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (event == NULL) {
        ovc_win32_set_errno(GetLastError());
        return (ovc_ssize_t)-1;
    }
    overlapped.hEvent = event;

    transferred = 0;
    completed = WriteFile(file,
                          buffer,
                          (DWORD)request_size,
                          &transferred,
                          &overlapped);
    if (!completed) {
        error_code = GetLastError();
        if (error_code == ERROR_IO_PENDING) {
            completed = GetOverlappedResult(file,
                                            &overlapped,
                                            &transferred,
                                            TRUE);
            error_code = completed ? ERROR_SUCCESS : GetLastError();
        }
        if (!completed) {
            (void)CloseHandle(event);
            ovc_win32_set_errno(error_code);
            return (ovc_ssize_t)-1;
        }
    } else if (!GetOverlappedResult(file,
                                    &overlapped,
                                    &transferred,
                                    FALSE)) {
        error_code = GetLastError();
        (void)CloseHandle(event);
        ovc_win32_set_errno(error_code);
        return (ovc_ssize_t)-1;
    }

    (void)CloseHandle(event);
    return (ovc_ssize_t)transferred;
}

char *ovc_env_dup(const char *name)
{
    char *value;
    size_t value_size;

    value = NULL;
    value_size = 0;
    if (_dupenv_s(&value, &value_size, name) != 0) {
        errno = ENOMEM;
        return NULL;
    }
    return value; /* NULL when unset, which is not an error */
}

void ovc_secure_zero(void *data, size_t byte_count)
{
    if (byte_count != 0) {
        (void)SecureZeroMemory(data, byte_count);
    }
}

uint64_t ovc_monotonic_ns(void)
{
    LARGE_INTEGER counter;
    LARGE_INTEGER frequency;
    uint64_t seconds;
    uint64_t remainder;
    uint64_t whole_nanoseconds;
    uint64_t fractional_nanoseconds;

    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0 ||
        !QueryPerformanceCounter(&counter) || counter.QuadPart < 0) {
        errno = EIO;
        return 0;
    }

    seconds = (uint64_t)(counter.QuadPart / frequency.QuadPart);
    remainder = (uint64_t)(counter.QuadPart % frequency.QuadPart);
    if (seconds > UINT64_MAX / UINT64_C(1000000000)) {
#ifdef EOVERFLOW
        errno = EOVERFLOW;
#else
        errno = ERANGE;
#endif
        return 0;
    }
    whole_nanoseconds = seconds * UINT64_C(1000000000);
    fractional_nanoseconds =
        ovc_fraction_to_ns(remainder, (uint64_t)frequency.QuadPart);
    if (whole_nanoseconds > UINT64_MAX - fractional_nanoseconds) {
#ifdef EOVERFLOW
        errno = EOVERFLOW;
#else
        errno = ERANGE;
#endif
        return 0;
    }
    return whole_nanoseconds + fractional_nanoseconds;
}

unsigned int ovc_cpu_count(void)
{
    SYSTEM_INFO information;

    GetSystemInfo(&information);
    return information.dwNumberOfProcessors == 0
               ? 1U
               : (unsigned int)information.dwNumberOfProcessors;
}

#else

#include <dlfcn.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
/*
 * Darwin hides this extension under the source tree's strict POSIX feature
 * macros, but it is the platform's relative condition-variable wait. Declare
 * the stable pthread symbol directly so a wall-clock step cannot extend a
 * monotonic timeout.
 */
extern int pthread_cond_timedwait_relative_np(
    pthread_cond_t *condition,
    pthread_mutex_t *mutex,
    const struct timespec *relative);
#endif

static void *ovc_thread_entry(void *opaque)
{
    struct ovc_thread_start *start;
    ovc_thread_fn function;
    void *argument;

    start = (struct ovc_thread_start *)opaque;
    function = start->function;
    argument = start->argument;
    free(start);
    function(argument);
    return NULL;
}

static int ovc_offset_to_native(uint64_t offset, off_t *native_offset)
{
    off_t converted;

    converted = (off_t)offset;
    if (converted < 0 || (uint64_t)converted != offset) {
        errno = EOVERFLOW;
        return -1;
    }
    *native_offset = converted;
    return 0;
}

int ovc_thread_create(ovc_thread *thread,
                      ovc_thread_fn function,
                      void *argument)
{
    struct ovc_thread_start *start;
    int result;

    if (thread == NULL || function == NULL) {
        return EINVAL;
    }
    thread->joinable = 0;

    start = (struct ovc_thread_start *)malloc(sizeof(*start));
    if (start == NULL) {
        return ENOMEM;
    }
    start->function = function;
    start->argument = argument;

    result = pthread_create(&thread->handle, NULL, ovc_thread_entry, start);
    if (result != 0) {
        free(start);
        return result;
    }
    thread->joinable = 1;
    return 0;
}

int ovc_thread_join(ovc_thread *thread)
{
    int result;

    if (thread == NULL || !thread->joinable) {
        return EINVAL;
    }
    result = pthread_join(thread->handle, NULL);
    if (result == 0) {
        thread->joinable = 0;
    }
    return result;
}

int ovc_mutex_init(ovc_mutex *mutex)
{
    return mutex == NULL ? EINVAL : pthread_mutex_init(&mutex->native, NULL);
}

int ovc_mutex_destroy(ovc_mutex *mutex)
{
    return mutex == NULL ? EINVAL : pthread_mutex_destroy(&mutex->native);
}

int ovc_mutex_lock(ovc_mutex *mutex)
{
    return mutex == NULL ? EINVAL : pthread_mutex_lock(&mutex->native);
}

int ovc_mutex_unlock(ovc_mutex *mutex)
{
    return mutex == NULL ? EINVAL : pthread_mutex_unlock(&mutex->native);
}

int ovc_cond_init(ovc_cond *condition)
{
    if (condition == NULL) {
        return EINVAL;
    }
    condition->monotonic = 0;
#if defined(CLOCK_MONOTONIC) && !defined(__APPLE__)
    {
        pthread_condattr_t attributes;
        int result;

        result = pthread_condattr_init(&attributes);
        if (result != 0) {
            return result;
        }
        if (pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC) == 0) {
            result = pthread_cond_init(&condition->native, &attributes);
            if (result == 0) {
                condition->monotonic = 1;
            }
        } else {
            result = pthread_cond_init(&condition->native, NULL);
        }
        (void)pthread_condattr_destroy(&attributes);
        return result;
    }
#else
    return pthread_cond_init(&condition->native, NULL);
#endif
}

int ovc_cond_destroy(ovc_cond *condition)
{
    return condition == NULL
               ? EINVAL
               : pthread_cond_destroy(&condition->native);
}

int ovc_cond_wait(ovc_cond *condition, ovc_mutex *mutex)
{
    if (condition == NULL || mutex == NULL) {
        return EINVAL;
    }
    return pthread_cond_wait(&condition->native, &mutex->native);
}

int ovc_cond_signal(ovc_cond *condition)
{
    return condition == NULL
               ? EINVAL
               : pthread_cond_signal(&condition->native);
}

int ovc_cond_broadcast(ovc_cond *condition)
{
    return condition == NULL
               ? EINVAL
               : pthread_cond_broadcast(&condition->native);
}

int ovc_cond_timedwait_ns(ovc_cond *condition,
                          ovc_mutex *mutex,
                          uint64_t wait_ns)
{
    if (condition == NULL || mutex == NULL) {
        return EINVAL;
    }
#if defined(__APPLE__)
    {
        struct timespec relative;

        relative.tv_sec = (time_t)(wait_ns / UINT64_C(1000000000));
        relative.tv_nsec =
            (long)(wait_ns % UINT64_C(1000000000));
        return pthread_cond_timedwait_relative_np(&condition->native,
                                                  &mutex->native,
                                                  &relative);
    }
#else
    /* Platforms whose condvars cannot use CLOCK_MONOTONIC wait against a
     * wall-clock deadline. Callers re-check their own predicate and deadline
     * after each return. */
    {
        struct timespec deadline;

        if (clock_gettime(condition->monotonic ? CLOCK_MONOTONIC
                                               : CLOCK_REALTIME,
                          &deadline) != 0) {
            return errno;
        }
        deadline.tv_sec += (time_t)(wait_ns / 1000000000u);
        deadline.tv_nsec += (long)(wait_ns % 1000000000u);
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1000000000L;
        }
        return pthread_cond_timedwait(&condition->native,
                                      &mutex->native,
                                      &deadline);
    }
#endif
}

ovc_dlhandle ovc_dlopen(const char *utf8_path)
{
    int flags;

    (void)dlerror();
    if (utf8_path == NULL) {
        errno = EINVAL;
        return NULL;
    }
    flags = RTLD_NOW;
#ifdef RTLD_LOCAL
    flags |= RTLD_LOCAL;
#endif
    return dlopen(utf8_path, flags);
}

void *ovc_dlsym(ovc_dlhandle handle, const char *symbol_name)
{
    (void)dlerror();
    if (handle == NULL || symbol_name == NULL) {
        errno = EINVAL;
        return NULL;
    }
    return dlsym(handle, symbol_name);
}

const char *ovc_dlerror(void)
{
    return dlerror();
}

void ovc_dlclose(ovc_dlhandle handle)
{
    if (handle != NULL) {
        (void)dlclose(handle);
    }
}

void *ovc_abi_alloc(size_t byte_count)
{
#if defined(OVC_ABI_ALLOC_FAILURE_TEST)
    if (ovc_test_abi_alloc_should_fail(byte_count)) {
        return NULL;
    }
#endif
    return malloc(byte_count == 0 ? 1 : byte_count);
}

void ovc_abi_free(void *allocation)
{
    free(allocation);
}

ovc_ssize_t ovc_pread(ovc_file file,
                      void *buffer,
                      size_t byte_count,
                      uint64_t offset)
{
    off_t native_offset;
    ssize_t result;

    if (buffer == NULL && byte_count != 0) {
        errno = EINVAL;
        return (ovc_ssize_t)-1;
    }
    if (ovc_offset_to_native(offset, &native_offset) != 0) {
        return (ovc_ssize_t)-1;
    }
    if (byte_count > (size_t)SSIZE_MAX) {
        byte_count = (size_t)SSIZE_MAX;
    }

    do {
        result = pread(file, buffer, byte_count, native_offset);
    } while (result < 0 && errno == EINTR);
    return result;
}

ovc_ssize_t ovc_pwrite(ovc_file file,
                       const void *buffer,
                       size_t byte_count,
                       uint64_t offset)
{
    off_t native_offset;
    ssize_t result;

    if (buffer == NULL && byte_count != 0) {
        errno = EINVAL;
        return (ovc_ssize_t)-1;
    }
    if (ovc_offset_to_native(offset, &native_offset) != 0) {
        return (ovc_ssize_t)-1;
    }
    if (byte_count > (size_t)SSIZE_MAX) {
        byte_count = (size_t)SSIZE_MAX;
    }

    do {
        result = pwrite(file, buffer, byte_count, native_offset);
    } while (result < 0 && errno == EINTR);
    return result;
}

char *ovc_env_dup(const char *name)
{
    const char *value;
    char *copy;
    size_t length;

    value = getenv(name);
    if (value == NULL) {
        return NULL;
    }
    length = strlen(value);
    copy = (char *)malloc(length + 1);
    if (copy == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(copy, value, length + 1);
    return copy;
}

void ovc_secure_zero(void *data, size_t byte_count)
{
    volatile unsigned char *cursor;

    cursor = (volatile unsigned char *)data;
    while (byte_count != 0) {
        *cursor = 0;
        ++cursor;
        --byte_count;
    }
}

uint64_t ovc_monotonic_ns(void)
{
    struct timespec now;
    uint64_t seconds;
    uint64_t whole_nanoseconds;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    if (now.tv_sec < 0 || now.tv_nsec < 0 ||
        now.tv_nsec >= 1000000000L) {
        errno = EIO;
        return 0;
    }

    seconds = (uint64_t)now.tv_sec;
    if (seconds > UINT64_MAX / UINT64_C(1000000000)) {
        errno = EOVERFLOW;
        return 0;
    }
    whole_nanoseconds = seconds * UINT64_C(1000000000);
    if (whole_nanoseconds > UINT64_MAX - (uint64_t)now.tv_nsec) {
        errno = EOVERFLOW;
        return 0;
    }
    return whole_nanoseconds + (uint64_t)now.tv_nsec;
}

unsigned int ovc_cpu_count(void)
{
    long count;

    count = sysconf(_SC_NPROCESSORS_ONLN);
    if (count < 1) {
        return 1U;
    }
    if ((unsigned long)count > (unsigned long)UINT_MAX) {
        return UINT_MAX;
    }
    return (unsigned int)count;
}

#endif

int ovc_path_is_separator(char character)
{
#if defined(_WIN32)
    return character == '/' || character == '\\';
#else
    return character == '/';
#endif
}

int ovc_path_is_absolute(const char *utf8_path)
{
    if (utf8_path == NULL || utf8_path[0] == '\0') {
        return 0;
    }
#if defined(_WIN32)
    if (ovc_path_is_separator(utf8_path[0]) &&
        ovc_path_is_separator(utf8_path[1])) {
        return 1;
    }
    return ((utf8_path[0] >= 'A' && utf8_path[0] <= 'Z') ||
            (utf8_path[0] >= 'a' && utf8_path[0] <= 'z')) &&
           utf8_path[1] == ':' && ovc_path_is_separator(utf8_path[2]);
#else
    return utf8_path[0] == '/';
#endif
}

char *ovc_path_join(const char *base, const char *child)
{
    size_t base_length;
    size_t child_offset;
    size_t child_length;
    size_t separator_count;
    size_t result_length;
    char *result;
    size_t cursor;

    if (base == NULL || child == NULL) {
        errno = EINVAL;
        return NULL;
    }

    base_length = strlen(base);
    child_offset = 0;
    child_length = strlen(child);
    separator_count = 0;

    if (base_length != 0 && child_length != 0) {
        if (ovc_path_is_separator(base[base_length - 1]) &&
            ovc_path_is_separator(child[0])) {
            child_offset = 1;
            --child_length;
        } else if (!ovc_path_is_separator(base[base_length - 1]) &&
                   !ovc_path_is_separator(child[0])) {
            separator_count = 1;
        }
    }

    if (base_length > SIZE_MAX - separator_count ||
        base_length + separator_count > SIZE_MAX - child_length ||
        base_length + separator_count + child_length == SIZE_MAX) {
        errno = ENOMEM;
        return NULL;
    }
    result_length = base_length + separator_count + child_length;
    result = (char *)malloc(result_length + 1);
    if (result == NULL) {
        return NULL;
    }

    cursor = 0;
    if (base_length != 0) {
        memcpy(result + cursor, base, base_length);
        cursor += base_length;
    }
    if (separator_count != 0) {
        result[cursor++] = OVC_PATH_SEPARATOR;
    }
    if (child_length != 0) {
        memcpy(result + cursor, child + child_offset, child_length);
        cursor += child_length;
    }
    result[cursor] = '\0';
    return result;
}

void *ovc_abi_copy_bytes(const void *bytes, size_t byte_count)
{
    unsigned char *copy;

    copy = (unsigned char *)ovc_abi_alloc(byte_count);
    if (copy == NULL) {
        return NULL;
    }
    if (byte_count != 0) {
        memcpy(copy, bytes, byte_count);
    } else {
        copy[0] = 0;
    }
    return copy;
}
