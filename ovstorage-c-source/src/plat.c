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

#include <aclapi.h>
#include <process.h>

/* The owner-only DACL below needs advapi32 (OpenProcessToken,
 * GetTokenInformation, InitializeAcl, AddAccessAllowedAce,
 * InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
 * SetSecurityDescriptorOwner, SetSecurityDescriptorControl, GetSecurityInfo,
 * SetSecurityInfo, IsValidSid, EqualSid).
 *
 * Requested here rather than by adding a library to every consumer's link
 * line: this ships as SOURCE, so a new link requirement would be a breaking
 * change to each customer's build. `#pragma comment(lib, ...)` keeps the
 * dependency with the code that needs it, and MSVC is the only compiler
 * that reaches this arm. A consumer building with clang-cl or MinGW links
 * advapi32 by default. */
#if defined(_MSC_VER)
#pragma comment(lib, "advapi32.lib")
#endif

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
    /* On a long-path-enabled host a >255-char component passes Win32
     * normalization but NTFS rejects it as STATUS_OBJECT_NAME_INVALID ->
     * ERROR_INVALID_NAME.  Like an over-long path, such a name cannot
     * exist, so it shares ENAMETOOLONG; the file backend's canonical-scope
     * walk treats that as "keep walking up" alongside ENOENT. */
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

/* A security descriptor granting only the calling user, or NULL on failure.
 *
 * This is the Win32 analogue of mode 0700: a protected DACL with one ACE for
 * the process token's user and no inherited entries, so a parent shared
 * between principals cannot widen it.  The caller owns the returned
 * descriptor and frees it with ovc_win32_owner_only_sd_free. */
PSECURITY_DESCRIPTOR ovc_win32_owner_only_sd_create(
    PACL *out_acl,
    PTOKEN_USER *out_user)
{
    HANDLE token;
    DWORD needed;
    DWORD error_code;
    PTOKEN_USER user;
    DWORD acl_size;
    PACL acl;
    PSECURITY_DESCRIPTOR descriptor;

    *out_acl = NULL;
    *out_user = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return NULL;
    }
    needed = 0;
    (void)GetTokenInformation(token, TokenUser, NULL, 0, &needed);
    if (needed == 0) {
        error_code = GetLastError();
        (void)CloseHandle(token);
        SetLastError(error_code);
        return NULL;
    }
    user = (PTOKEN_USER)malloc(needed);
    if (user == NULL) {
        (void)CloseHandle(token);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    if (!GetTokenInformation(token, TokenUser, user, needed, &needed)) {
        error_code = GetLastError();
        free(user);
        (void)CloseHandle(token);
        SetLastError(error_code);
        return NULL;
    }
    (void)CloseHandle(token);

    acl_size = (DWORD)(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE)
                       - sizeof(DWORD)
                       + GetLengthSid(user->User.Sid));
    acl = (PACL)malloc(acl_size);
    if (acl == NULL) {
        free(user);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    if (!InitializeAcl(acl, acl_size, ACL_REVISION)
        || !AddAccessAllowedAce(acl,
                                ACL_REVISION,
                                FILE_ALL_ACCESS,
                                user->User.Sid)) {
        free(acl);
        free(user);
        return NULL;
    }
    descriptor = (PSECURITY_DESCRIPTOR)malloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (descriptor == NULL) {
        free(acl);
        free(user);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    /* SE_DACL_PROTECTED states the owner-only invariant rather than leaving it
     * to inherit rules. Supplying an explicit DACL at creation already
     * suppresses the merge of the parent's inheritable ACEs -- measured under a
     * root carrying an inheritable Everyone:Read, the created directory holds
     * exactly one ACE and Windows stamps it `D:P` unprompted, while a sibling
     * created with a NULL descriptor inherits three. Auto-inherit behaviour is
     * subtle enough that the guarantee belongs in the descriptor, not in a
     * reader's recollection of when the merge applies. */
    if (!InitializeSecurityDescriptor(descriptor, SECURITY_DESCRIPTOR_REVISION)
        || !SetSecurityDescriptorOwner(descriptor,
                                       user->User.Sid,
                                       FALSE)
        || !SetSecurityDescriptorDacl(descriptor, TRUE, acl, FALSE)
        || !SetSecurityDescriptorControl(descriptor,
                                         SE_DACL_PROTECTED,
                                         SE_DACL_PROTECTED)) {
        error_code = GetLastError();
        free(descriptor);
        free(acl);
        free(user);
        SetLastError(error_code);
        return NULL;
    }
    *out_acl = acl;
    *out_user = user;
    return descriptor;
}

void ovc_win32_owner_only_sd_free(PSECURITY_DESCRIPTOR descriptor,
                                  PACL acl,
                                  PTOKEN_USER user)
{
    free(descriptor);
    free(acl);
    free(user);
}

static PTOKEN_OWNER ovc_win32_token_owner_create(void)
{
    HANDLE token;
    DWORD needed;
    DWORD error_code;
    PTOKEN_OWNER owner;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return NULL;
    }
    needed = 0;
    (void)GetTokenInformation(token, TokenOwner, NULL, 0, &needed);
    if (needed == 0) {
        error_code = GetLastError();
        (void)CloseHandle(token);
        SetLastError(error_code);
        return NULL;
    }
    owner = (PTOKEN_OWNER)malloc(needed);
    if (owner == NULL) {
        (void)CloseHandle(token);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    if (!GetTokenInformation(token, TokenOwner, owner, needed, &needed)) {
        error_code = GetLastError();
        free(owner);
        (void)CloseHandle(token);
        SetLastError(error_code);
        return NULL;
    }
    (void)CloseHandle(token);
    return owner;
}

int ovc_win32_handle_owner_is(HANDLE handle,
                              PSID token_user,
                              PSID token_default_owner)
{
    DWORD status;
    PSID actual_owner;
    PSECURITY_DESCRIPTOR descriptor;

    if (handle == NULL || handle == INVALID_HANDLE_VALUE ||
        token_user == NULL || !IsValidSid(token_user) ||
        token_default_owner == NULL ||
        !IsValidSid(token_default_owner)) {
        errno = EINVAL;
        return -1;
    }
    actual_owner = NULL;
    descriptor = NULL;
    status = GetSecurityInfo(handle,
                             SE_FILE_OBJECT,
                             OWNER_SECURITY_INFORMATION,
                             &actual_owner,
                             NULL,
                             NULL,
                             NULL,
                             &descriptor);
    if (status != ERROR_SUCCESS) {
        ovc_win32_set_errno(status);
        return -1;
    }
    if (actual_owner == NULL || !IsValidSid(actual_owner)) {
        (void)LocalFree(descriptor);
        errno = EIO;
        return -1;
    }
    if (!EqualSid(actual_owner, token_user) &&
        !EqualSid(actual_owner, token_default_owner)) {
        (void)LocalFree(descriptor);
        errno = EACCES;
        return -1;
    }
    (void)LocalFree(descriptor);
    return 0;
}

static int ovc_win32_handle_owner_is_process_owned(HANDLE handle,
                                                    PSID token_user)
{
    PTOKEN_OWNER token_owner;
    DWORD error_code;
    int result;
    int saved_errno;

    token_owner = ovc_win32_token_owner_create();
    if (token_owner == NULL) {
        error_code = GetLastError();
        ovc_win32_set_errno(error_code);
        return -1;
    }
    result = ovc_win32_handle_owner_is(handle,
                                       token_user,
                                       token_owner->Owner);
    saved_errno = errno;
    free(token_owner);
    errno = saved_errno;
    return result;
}

static int ovc_win32_parent_dirs_ensure(const char *path)
{
    char *parent;
    wchar_t *wide;
    DWORD error_code;

    parent = ovc_path_parent_dup(path);
    if (parent == NULL) {
        return -1;
    }
    if (parent[0] == '\0' || strcmp(parent, path) == 0) {
        free(parent);
        return 0;
    }
    wide = ovc_utf8_to_wide(parent);
    if (wide == NULL) {
        error_code = GetLastError();
        free(parent);
        ovc_win32_set_errno(error_code);
        return -1;
    }
    if (CreateDirectoryW(wide, NULL) != 0) {
        free(wide);
        free(parent);
        return 0;
    }
    error_code = GetLastError();
    free(wide);
    if (error_code == ERROR_ALREADY_EXISTS ||
        error_code == ERROR_FILE_EXISTS) {
        free(parent);
        return 0;
    }
    if (error_code == ERROR_FILE_NOT_FOUND ||
        error_code == ERROR_PATH_NOT_FOUND) {
        if (ovc_win32_parent_dirs_ensure(parent) != 0) {
            free(parent);
            return -1;
        }
        wide = ovc_utf8_to_wide(parent);
        if (wide == NULL) {
            error_code = GetLastError();
            free(parent);
            ovc_win32_set_errno(error_code);
            return -1;
        }
        if (CreateDirectoryW(wide, NULL) != 0) {
            free(wide);
            free(parent);
            return 0;
        }
        error_code = GetLastError();
        free(wide);
        if (error_code == ERROR_ALREADY_EXISTS ||
            error_code == ERROR_FILE_EXISTS) {
            free(parent);
            return 0;
        }
    }
    free(parent);
    ovc_win32_set_errno(error_code);
    return -1;
}

static int ovc_win32_private_dir_restrict(wchar_t *wide)
{
    DWORD error_code;
    DWORD status;
    PSECURITY_DESCRIPTOR descriptor;
    PACL owner_acl;
    PTOKEN_USER owner_user;
    HANDLE directory;
    BY_HANDLE_FILE_INFORMATION information;
    int saved_errno;

    descriptor = ovc_win32_owner_only_sd_create(&owner_acl, &owner_user);
    if (descriptor == NULL) {
        error_code = GetLastError();
        ovc_win32_set_errno(error_code);
        return -1;
    }
    directory = CreateFileW(wide,
                            READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE |
                                FILE_SHARE_DELETE,
                            NULL,
                            OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS |
                                FILE_FLAG_OPEN_REPARSE_POINT,
                            NULL);
    if (directory == INVALID_HANDLE_VALUE) {
        error_code = GetLastError();
        ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
        ovc_win32_set_errno(error_code);
        return -1;
    }
    if (!GetFileInformationByHandle(directory, &information)) {
        error_code = GetLastError();
        (void)CloseHandle(directory);
        ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
        ovc_win32_set_errno(error_code);
        return -1;
    }
    if ((information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        (void)CloseHandle(directory);
        ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
        errno =
            (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                ? ELOOP
                : ENOTDIR;
        return -1;
    }
    if (ovc_win32_handle_owner_is_process_owned(
            directory, owner_user->User.Sid) != 0) {
        saved_errno = errno;
        (void)CloseHandle(directory);
        ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
        errno = saved_errno;
        return -1;
    }
    status = SetSecurityInfo(
        directory,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        owner_acl,
        NULL);
    (void)CloseHandle(directory);
    ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
    if (status != ERROR_SUCCESS) {
        ovc_win32_set_errno(status);
        return -1;
    }
    return 0;
}

int ovc_private_dir_ensure(const char *path)
{
    wchar_t *wide;
    DWORD attributes;
    DWORD error_code;
    SECURITY_ATTRIBUTES security_attributes;
    PSECURITY_DESCRIPTOR descriptor;
    PACL owner_acl;
    PTOKEN_USER owner_user;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    wide = ovc_utf8_to_wide(path);
    if (wide == NULL) {
        ovc_win32_set_errno(GetLastError());
        return -1;
    }
    attributes = GetFileAttributesW(wide);
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        int result;

        result = ovc_win32_private_dir_restrict(wide);
        free(wide);
        return result;
    }
    error_code = GetLastError();
    if (error_code != ERROR_FILE_NOT_FOUND &&
        error_code != ERROR_PATH_NOT_FOUND) {
        free(wide);
        ovc_win32_set_errno(error_code);
        return -1;
    }
    if (ovc_win32_parent_dirs_ensure(path) != 0) {
        free(wide);
        return -1;
    }

    descriptor = ovc_win32_owner_only_sd_create(&owner_acl, &owner_user);
    if (descriptor == NULL) {
        error_code = GetLastError();
        free(wide);
        ovc_win32_set_errno(error_code);
        return -1;
    }
    security_attributes.nLength = (DWORD)sizeof(security_attributes);
    security_attributes.lpSecurityDescriptor = descriptor;
    security_attributes.bInheritHandle = FALSE;
    if (CreateDirectoryW(wide, &security_attributes) != 0) {
        ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
        free(wide);
        return 0;
    }
    error_code = GetLastError();
    ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
    if (error_code == ERROR_ALREADY_EXISTS ||
        error_code == ERROR_FILE_EXISTS) {
        int result;

        result = ovc_win32_private_dir_restrict(wide);
        free(wide);
        return result;
    }
    free(wide);
    ovc_win32_set_errno(error_code);
    return -1;
}

/* Win32 sharing failures that clear on their own.
 *
 * A freshly written file, or one about to be replaced, is routinely held open
 * for a few milliseconds by an antivirus scanner or the search indexer. Those
 * handles rarely grant FILE_SHARE_WRITE or FILE_SHARE_DELETE, so for that
 * moment CreateFileW on the record reports ERROR_SHARING_VIOLATION, MoveFileExW
 * and DeleteFileW report ERROR_SHARING_VIOLATION or ERROR_ACCESS_DENIED, and a
 * name whose deletion is pending behind such a handle refuses CREATE_NEW with
 * ERROR_ACCESS_DENIED; every one of them succeeds immediately afterwards.
 * Without a retry the moment surfaces as a spurious EACCES from a `secret_get`
 * or `secret_put` that did everything right, which is what the cross-process
 * contention suite saw on the Windows runner.
 *
 * The budget belongs to the operation, not the call. A credential store
 * operation opens a scope with ovc_transient_retry_begin() once it holds the
 * namespace lock, and every retried primitive on that thread then answers to
 * the one deadline, so a held file costs an operation at most the scoped
 * budget however many primitives it touches, rather than one budget per
 * primitive stacking inside the lock that other processes are queued on.
 * Outside a scope each primitive gets its own OVC_WIN32_TRANSIENT_RETRY_NS.
 * A file that really is held still fails with the same errno once the budget
 * is spent.
 *
 * ERROR_ACCESS_DENIED is also the permanent answer for a read-only file under
 * DeleteFileW and for a genuinely denied DACL under CreateFileW, so those
 * failures spend the budget before reporting the same error. That is bounded,
 * and the coverage is worth more than the delay. */
#define OVC_WIN32_TRANSIENT_RETRY_NS UINT64_C(2000000000)

static OVC_THREAD_LOCAL int g_ovc_win32_transient_scoped;
static OVC_THREAD_LOCAL uint64_t g_ovc_win32_transient_scope_deadline;

/* The monotonic deadline `budget_ns` from now, or 0 when the clock is
 * unavailable, which disables retrying rather than guessing. */
static uint64_t ovc_win32_transient_deadline_from_now(uint64_t budget_ns)
{
    uint64_t started;

    errno = 0;
    started = ovc_monotonic_ns();
    if (started == 0 && errno != 0) {
        return 0;
    }
    return budget_ns > UINT64_MAX - started ? UINT64_MAX : started + budget_ns;
}

void ovc_transient_retry_begin(uint64_t budget_ns)
{
    g_ovc_win32_transient_scope_deadline =
        ovc_win32_transient_deadline_from_now(budget_ns);
    g_ovc_win32_transient_scoped = 1;
}

void ovc_transient_retry_end(void)
{
    g_ovc_win32_transient_scoped = 0;
    g_ovc_win32_transient_scope_deadline = 0;
}

static int ovc_win32_error_is_transient(DWORD error_code)
{
    return error_code == ERROR_SHARING_VIOLATION ||
           error_code == ERROR_ACCESS_DENIED ||
           error_code == ERROR_LOCK_VIOLATION;
}

/* Retry state for one primitive: the deadline it answers to and the next
 * backoff step (1 ms doubling to 50 ms, the lock file's schedule). */
typedef struct ovc_win32_retry {
    uint64_t deadline;
    uint64_t backoff_ns;
} ovc_win32_retry;

static void ovc_win32_retry_init(ovc_win32_retry *retry)
{
    retry->deadline = g_ovc_win32_transient_scoped
                          ? g_ovc_win32_transient_scope_deadline
                          : ovc_win32_transient_deadline_from_now(
                                OVC_WIN32_TRANSIENT_RETRY_NS);
    retry->backoff_ns = UINT64_C(1000000);
}

/* Decide whether a failed Win32 call is made again: sleep for the next backoff
 * step and return 1 when `error_code` is transient and the deadline has not
 * passed, else return 0 so the caller reports `error_code` as it stands. */
static int ovc_win32_retry_transient(ovc_win32_retry *retry, DWORD error_code)
{
    uint64_t now;
    uint64_t remaining;

    if (!ovc_win32_error_is_transient(error_code)) {
        return 0;
    }
    errno = 0;
    now = ovc_monotonic_ns();
    if ((now == 0 && errno != 0) || now >= retry->deadline) {
        return 0;
    }
    remaining = retry->deadline - now;
    ovc_sleep_ns(retry->backoff_ns < remaining ? retry->backoff_ns : remaining);
    if (retry->backoff_ns < UINT64_C(50000000)) {
        retry->backoff_ns *= 2u;
        if (retry->backoff_ns > UINT64_C(50000000)) {
            retry->backoff_ns = UINT64_C(50000000);
        }
    }
    return 1;
}

ovc_file ovc_private_file_open(const char *path,
                               ovc_private_open_mode mode)
{
    wchar_t *wide;
    DWORD disposition;
    DWORD error_code;
    DWORD opened_status;
    DWORD security_status;
    SECURITY_ATTRIBUTES security_attributes;
    PSECURITY_DESCRIPTOR descriptor;
    PACL owner_acl;
    PTOKEN_USER owner_user;
    HANDLE file;
    BY_HANDLE_FILE_INFORMATION information;
    ovc_win32_retry retry;
    int pre_existing;
    int saved_errno;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return OVC_INVALID_FILE;
    }
    switch (mode) {
    case OVC_PRIVATE_OPEN_CREATE_NEW:
        disposition = CREATE_NEW;
        break;
    case OVC_PRIVATE_OPEN_ALWAYS:
        disposition = OPEN_ALWAYS;
        break;
    case OVC_PRIVATE_OPEN_EXISTING:
        disposition = OPEN_EXISTING;
        break;
    default:
        errno = EINVAL;
        return OVC_INVALID_FILE;
    }

    wide = ovc_utf8_to_wide(path);
    if (wide == NULL) {
        ovc_win32_set_errno(GetLastError());
        return OVC_INVALID_FILE;
    }
    descriptor = ovc_win32_owner_only_sd_create(&owner_acl, &owner_user);
    if (descriptor == NULL) {
        error_code = GetLastError();
        free(wide);
        ovc_win32_set_errno(error_code);
        return OVC_INVALID_FILE;
    }
    security_attributes.nLength = (DWORD)sizeof(security_attributes);
    security_attributes.lpSecurityDescriptor = descriptor;
    security_attributes.bInheritHandle = FALSE;
    ovc_win32_retry_init(&retry);
    for (;;) {
        SetLastError(ERROR_SUCCESS);
        file = CreateFileW(wide,
                           GENERIC_READ | GENERIC_WRITE | READ_CONTROL |
                               WRITE_DAC,
                           FILE_SHARE_READ | FILE_SHARE_WRITE |
                               FILE_SHARE_DELETE,
                           &security_attributes,
                           disposition,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED |
                               FILE_FLAG_OPEN_REPARSE_POINT,
                           NULL);
        opened_status = GetLastError();
        if (file != INVALID_HANDLE_VALUE ||
            !ovc_win32_retry_transient(&retry, opened_status)) {
            break;
        }
    }
    if (file == INVALID_HANDLE_VALUE) {
        ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
        free(wide);
        ovc_win32_set_errno(opened_status);
        return OVC_INVALID_FILE;
    }
    if (!GetFileInformationByHandle(file, &information)) {
        error_code = GetLastError();
        (void)CloseHandle(file);
        ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
        free(wide);
        ovc_win32_set_errno(error_code);
        return OVC_INVALID_FILE;
    }
    if ((information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        (void)CloseHandle(file);
        ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
        free(wide);
        errno =
            (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                ? ELOOP
                : EINVAL;
        return OVC_INVALID_FILE;
    }

    pre_existing = mode == OVC_PRIVATE_OPEN_EXISTING ||
                   (mode == OVC_PRIVATE_OPEN_ALWAYS &&
                    opened_status == ERROR_ALREADY_EXISTS);
    if (pre_existing) {
        if (ovc_win32_handle_owner_is_process_owned(
                file, owner_user->User.Sid) != 0) {
            saved_errno = errno;
            (void)CloseHandle(file);
            ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
            free(wide);
            errno = saved_errno;
            return OVC_INVALID_FILE;
        }
        security_status = SetSecurityInfo(
            file,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL,
            NULL,
            owner_acl,
            NULL);
        if (security_status != ERROR_SUCCESS) {
            (void)CloseHandle(file);
            ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
            free(wide);
            ovc_win32_set_errno(security_status);
            return OVC_INVALID_FILE;
        }
    }
    ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
    free(wide);
    return file;
}

int ovc_file_close(ovc_file file)
{
    if (CloseHandle(file)) {
        return 0;
    }
    ovc_win32_set_errno(GetLastError());
    return -1;
}

int ovc_file_sync(ovc_file file)
{
    if (FlushFileBuffers(file)) {
        return 0;
    }
    ovc_win32_set_errno(GetLastError());
    return -1;
}

int ovc_file_size(ovc_file file, uint64_t *out)
{
    LARGE_INTEGER size;

    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (!GetFileSizeEx(file, &size)) {
        ovc_win32_set_errno(GetLastError());
        return -1;
    }
    if (size.QuadPart < 0) {
        errno = EIO;
        return -1;
    }
    *out = (uint64_t)size.QuadPart;
    return 0;
}

void ovc_sleep_ns(uint64_t nanoseconds)
{
    uint64_t milliseconds;
    uint64_t maximum_finite_milliseconds;

    if (nanoseconds == 0) {
        return;
    }
    milliseconds = nanoseconds / UINT64_C(1000000);
    if (nanoseconds % UINT64_C(1000000) != 0) {
        ++milliseconds;
    }
    maximum_finite_milliseconds = (uint64_t)MAXDWORD - 1u;
    while (milliseconds > maximum_finite_milliseconds) {
        Sleep(MAXDWORD - 1u);
        milliseconds -= maximum_finite_milliseconds;
    }
    Sleep((DWORD)milliseconds);
}

int ovc_lockfile_acquire(const char *path,
                         uint64_t timeout_ns,
                         ovc_lockfile *out)
{
    ovc_file file;
    uint64_t started;
    uint64_t deadline;
    uint64_t backoff_ns;

    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    out->file = OVC_INVALID_FILE;
    errno = 0;
    started = ovc_monotonic_ns();
    if (started == 0 && errno != 0) {
        return -1;
    }
    deadline = timeout_ns > UINT64_MAX - started
                   ? UINT64_MAX
                   : started + timeout_ns;
    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_ALWAYS);
    if (file == OVC_INVALID_FILE) {
        return -1;
    }

    backoff_ns = UINT64_C(1000000);
    for (;;) {
        OVERLAPPED overlapped;
        DWORD error_code;
        uint64_t now;
        uint64_t remaining;
        uint64_t sleep_ns;

        memset(&overlapped, 0, sizeof(overlapped));
        if (LockFileEx(file,
                       LOCKFILE_EXCLUSIVE_LOCK |
                           LOCKFILE_FAIL_IMMEDIATELY,
                       0,
                       MAXDWORD,
                       MAXDWORD,
                       &overlapped)) {
            out->file = file;
            return 0;
        }
        error_code = GetLastError();
        if (error_code != ERROR_LOCK_VIOLATION &&
            error_code != ERROR_IO_PENDING) {
            (void)ovc_file_close(file);
            ovc_win32_set_errno(error_code);
            return -1;
        }

        errno = 0;
        now = ovc_monotonic_ns();
        if (now == 0 && errno != 0) {
            int error;

            error = errno;
            (void)ovc_file_close(file);
            errno = error;
            return -1;
        }
        if (now >= deadline) {
            (void)ovc_file_close(file);
            errno = ETIMEDOUT;
            return -1;
        }
        remaining = deadline - now;
        sleep_ns = backoff_ns < remaining ? backoff_ns : remaining;
        ovc_sleep_ns(sleep_ns);
        errno = 0;
        now = ovc_monotonic_ns();
        if (now == 0 && errno != 0) {
            int error;

            error = errno;
            (void)ovc_file_close(file);
            errno = error;
            return -1;
        }
        if (now >= deadline) {
            (void)ovc_file_close(file);
            errno = ETIMEDOUT;
            return -1;
        }
        if (backoff_ns < UINT64_C(50000000)) {
            backoff_ns *= 2u;
            if (backoff_ns > UINT64_C(50000000)) {
                backoff_ns = UINT64_C(50000000);
            }
        }
    }
}

void ovc_lockfile_release(ovc_lockfile *lock)
{
    OVERLAPPED overlapped;

    if (lock == NULL || lock->file == OVC_INVALID_FILE) {
        return;
    }
    memset(&overlapped, 0, sizeof(overlapped));
    (void)UnlockFileEx(lock->file,
                       0,
                       MAXDWORD,
                       MAXDWORD,
                       &overlapped);
    (void)ovc_file_close(lock->file);
    lock->file = OVC_INVALID_FILE;
}

int ovc_file_rename_replace(const char *source, const char *destination)
{
    wchar_t *source_wide;
    wchar_t *destination_wide;
    DWORD error_code;
    ovc_win32_retry retry;

    source_wide = ovc_utf8_to_wide(source);
    if (source_wide == NULL) {
        ovc_win32_set_errno(GetLastError());
        return -1;
    }
    destination_wide = ovc_utf8_to_wide(destination);
    if (destination_wide == NULL) {
        error_code = GetLastError();
        free(source_wide);
        ovc_win32_set_errno(error_code);
        return -1;
    }
    ovc_win32_retry_init(&retry);
    for (;;) {
        if (MoveFileExW(source_wide,
                        destination_wide,
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            free(destination_wide);
            free(source_wide);
            return 0;
        }
        error_code = GetLastError();
        if (!ovc_win32_retry_transient(&retry, error_code)) {
            break;
        }
    }
    free(destination_wide);
    free(source_wide);
    ovc_win32_set_errno(error_code);
    return -1;
}

int ovc_file_unlink(const char *path)
{
    wchar_t *wide;
    DWORD error_code;
    ovc_win32_retry retry;

    wide = ovc_utf8_to_wide(path);
    if (wide == NULL) {
        ovc_win32_set_errno(GetLastError());
        return -1;
    }
    ovc_win32_retry_init(&retry);
    for (;;) {
        if (DeleteFileW(wide)) {
            free(wide);
            return 0;
        }
        error_code = GetLastError();
        if (!ovc_win32_retry_transient(&retry, error_code)) {
            break;
        }
    }
    free(wide);
    ovc_win32_set_errno(error_code);
    return -1;
}

int ovc_dir_sync(const char *dir)
{
    (void)dir;
    /* MoveFileExW(MOVEFILE_WRITE_THROUGH) is the Win32 commit barrier. */
    return 0;
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
    wchar_t *wide_name;
    wchar_t *wide_value;
    char *value;
    DWORD required;
    DWORD written;
    DWORD error_code;
    size_t byte_count;

    wide_name = ovc_utf8_to_wide(name);
    if (wide_name == NULL) {
        return NULL;
    }
    for (;;) {
        SetLastError(ERROR_SUCCESS);
        required = GetEnvironmentVariableW(wide_name, NULL, 0);
        if (required == 0) {
            error_code = GetLastError();
            free(wide_name);
            if (error_code == ERROR_ENVVAR_NOT_FOUND) {
                errno = 0;
                return NULL;
            }
            if (error_code == ERROR_SUCCESS) {
                value = (char *)malloc(1);
                if (value == NULL) {
                    errno = ENOMEM;
                    return NULL;
                }
                value[0] = '\0';
                return value;
            }
            ovc_win32_set_errno(error_code);
            return NULL;
        }
        if ((size_t)required > SIZE_MAX / sizeof(*wide_value)) {
            free(wide_name);
            errno = ENOMEM;
            return NULL;
        }
        byte_count = (size_t)required * sizeof(*wide_value);
        wide_value = (wchar_t *)malloc(byte_count);
        if (wide_value == NULL) {
            free(wide_name);
            errno = ENOMEM;
            return NULL;
        }
        SetLastError(ERROR_SUCCESS);
        written = GetEnvironmentVariableW(wide_name,
                                          wide_value,
                                          required);
        if (written == 0) {
            error_code = GetLastError();
            ovc_secure_zero(wide_value, byte_count);
            free(wide_value);
            if (error_code == ERROR_ENVVAR_NOT_FOUND) {
                free(wide_name);
                errno = 0;
                return NULL;
            }
            if (error_code == ERROR_SUCCESS) {
                free(wide_name);
                value = (char *)malloc(1);
                if (value == NULL) {
                    errno = ENOMEM;
                    return NULL;
                }
                value[0] = '\0';
                return value;
            }
            free(wide_name);
            ovc_win32_set_errno(error_code);
            return NULL;
        }
        if (written < required) {
            value = ovc_wide_to_utf8(wide_value);
            ovc_secure_zero(wide_value, byte_count);
            free(wide_value);
            free(wide_name);
            return value;
        }
        ovc_secure_zero(wide_value, byte_count);
        free(wide_value);
    }
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
#include <fcntl.h>
#include <sys/stat.h>
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
        errno = 0;
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

/* Create the missing ancestors of `path`, each owner-only.
 *
 * The leaf is `0700` and a pre-existing ancestor keeps whatever mode it has,
 * so the intermediates this host creates are `0700` as well rather than
 * `0777 & ~umask`: under `umask 0` the latter would leave the credential
 * store's parents world-writable, and a directory that anyone can rename or
 * unlink is a local denial of service against a store whose own directory is
 * otherwise carefully private. */
static int ovc_posix_parent_dirs_ensure(const char *path)
{
    char *parent;
    int error_code;

    parent = ovc_path_parent_dup(path);
    if (parent == NULL) {
        return -1;
    }
    if (parent[0] == '\0' || strcmp(parent, path) == 0) {
        free(parent);
        return 0;
    }
    if (mkdir(parent, 0700) == 0) {
        free(parent);
        return 0;
    }
    error_code = errno;
    if (error_code == EEXIST) {
        free(parent);
        return 0;
    }
    if (error_code == ENOENT) {
        if (ovc_posix_parent_dirs_ensure(parent) != 0) {
            free(parent);
            return -1;
        }
        if (mkdir(parent, 0700) == 0 || errno == EEXIST) {
            free(parent);
            return 0;
        }
        error_code = errno;
    }
    free(parent);
    errno = error_code;
    return -1;
}

int ovc_private_dir_ensure(const char *path)
{
    struct stat status;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    if (lstat(path, &status) != 0) {
        if (errno != ENOENT) {
            return -1;
        }
        if (ovc_posix_parent_dirs_ensure(path) != 0) {
            return -1;
        }
        if (mkdir(path, 0700) == 0) {
            return 0;
        }
        if (errno != EEXIST) {
            return -1;
        }
        if (lstat(path, &status) != 0) {
            return -1;
        }
    }
    if (S_ISLNK(status.st_mode)) {
        errno = ELOOP;
        return -1;
    }
    if (!S_ISDIR(status.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    if (status.st_uid != getuid()) {
        errno = EACCES;
        return -1;
    }
    if ((status.st_mode & 0777) != 0700 && chmod(path, 0700) != 0) {
        return -1;
    }
    return 0;
}

ovc_file ovc_private_file_open(const char *path,
                               ovc_private_open_mode mode)
{
    struct stat status;
    int flags;
    int file;
    int error_code;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return OVC_INVALID_FILE;
    }
    flags = O_RDWR | O_CLOEXEC | O_NOFOLLOW;
    switch (mode) {
    case OVC_PRIVATE_OPEN_CREATE_NEW:
        flags |= O_CREAT | O_EXCL;
        break;
    case OVC_PRIVATE_OPEN_ALWAYS:
        flags |= O_CREAT;
        break;
    case OVC_PRIVATE_OPEN_EXISTING:
        break;
    default:
        errno = EINVAL;
        return OVC_INVALID_FILE;
    }

    file = open(path, flags, (mode_t)0600);
    if (file < 0) {
        if (errno == EISDIR) {
            errno = EINVAL;
        }
        return OVC_INVALID_FILE;
    }
    if (fstat(file, &status) != 0) {
        error_code = errno;
        (void)close(file);
        errno = error_code;
        return OVC_INVALID_FILE;
    }
    if (!S_ISREG(status.st_mode)) {
        (void)close(file);
        errno = EINVAL;
        return OVC_INVALID_FILE;
    }
    if (status.st_uid != getuid()) {
        (void)close(file);
        errno = EACCES;
        return OVC_INVALID_FILE;
    }
    if ((status.st_mode & 0777) != 0600 &&
        fchmod(file, (mode_t)0600) != 0) {
        error_code = errno;
        (void)close(file);
        errno = error_code;
        return OVC_INVALID_FILE;
    }
    return file;
}

int ovc_file_close(ovc_file file)
{
    /* POSIX leaves the descriptor state unspecified after close(2) returns
     * EINTR; retrying can close an unrelated descriptor that reused the
     * number. */
    return close(file);
}

int ovc_file_sync(ovc_file file)
{
    int result;

    do {
        result = fsync(file);
    } while (result != 0 && errno == EINTR);
    return result;
}

int ovc_file_size(ovc_file file, uint64_t *out)
{
    struct stat status;

    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (fstat(file, &status) != 0) {
        return -1;
    }
    if (status.st_size < 0) {
        errno = EIO;
        return -1;
    }
    *out = (uint64_t)status.st_size;
    return 0;
}

void ovc_sleep_ns(uint64_t nanoseconds)
{
    struct timespec requested;
    struct timespec remaining;

    requested.tv_sec = (time_t)(nanoseconds / UINT64_C(1000000000));
    requested.tv_nsec = (long)(nanoseconds % UINT64_C(1000000000));
    while (nanosleep(&requested, &remaining) != 0) {
        if (errno != EINTR) {
            return;
        }
        requested = remaining;
    }
}

int ovc_lockfile_acquire(const char *path,
                         uint64_t timeout_ns,
                         ovc_lockfile *out)
{
    ovc_file file;
    uint64_t started;
    uint64_t deadline;
    uint64_t backoff_ns;

    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }
    out->file = OVC_INVALID_FILE;
    errno = 0;
    started = ovc_monotonic_ns();
    if (started == 0 && errno != 0) {
        return -1;
    }
    deadline = timeout_ns > UINT64_MAX - started
                   ? UINT64_MAX
                   : started + timeout_ns;
    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_ALWAYS);
    if (file == OVC_INVALID_FILE) {
        return -1;
    }

    backoff_ns = UINT64_C(1000000);
    for (;;) {
        struct flock request;
        int lock_error;
        uint64_t now;
        uint64_t remaining;
        uint64_t sleep_ns;

        memset(&request, 0, sizeof(request));
        request.l_type = F_WRLCK;
        request.l_whence = SEEK_SET;
        request.l_start = 0;
        request.l_len = 0;
        if (fcntl(file, F_SETLK, &request) == 0) {
            out->file = file;
            return 0;
        }
        lock_error = errno;
        if (lock_error != EINTR && lock_error != EACCES &&
            lock_error != EAGAIN) {
            (void)ovc_file_close(file);
            errno = lock_error;
            return -1;
        }

        errno = 0;
        now = ovc_monotonic_ns();
        if (now == 0 && errno != 0) {
            int error;

            error = errno;
            (void)ovc_file_close(file);
            errno = error;
            return -1;
        }
        if (now >= deadline) {
            (void)ovc_file_close(file);
            errno = ETIMEDOUT;
            return -1;
        }
        if (lock_error == EINTR) {
            continue;
        }
        remaining = deadline - now;
        sleep_ns = backoff_ns < remaining ? backoff_ns : remaining;
        ovc_sleep_ns(sleep_ns);
        errno = 0;
        now = ovc_monotonic_ns();
        if (now == 0 && errno != 0) {
            int error;

            error = errno;
            (void)ovc_file_close(file);
            errno = error;
            return -1;
        }
        if (now >= deadline) {
            (void)ovc_file_close(file);
            errno = ETIMEDOUT;
            return -1;
        }
        if (backoff_ns < UINT64_C(50000000)) {
            backoff_ns *= 2u;
            if (backoff_ns > UINT64_C(50000000)) {
                backoff_ns = UINT64_C(50000000);
            }
        }
    }
}

void ovc_lockfile_release(ovc_lockfile *lock)
{
    struct flock request;

    if (lock == NULL || lock->file == OVC_INVALID_FILE) {
        return;
    }
    memset(&request, 0, sizeof(request));
    request.l_type = F_UNLCK;
    request.l_whence = SEEK_SET;
    request.l_start = 0;
    request.l_len = 0;
    while (fcntl(lock->file, F_SETLK, &request) != 0 && errno == EINTR) {
    }
    (void)ovc_file_close(lock->file);
    lock->file = OVC_INVALID_FILE;
}

int ovc_file_rename_replace(const char *source, const char *destination)
{
    return renameat(AT_FDCWD, source, AT_FDCWD, destination);
}

int ovc_file_unlink(const char *path)
{
    return unlinkat(AT_FDCWD, path, 0);
}

/* POSIX rename and unlink are not refused by another process's open handle,
 * so there is no transient sharing class to retry and a scope is a no-op. */
void ovc_transient_retry_begin(uint64_t budget_ns)
{
    (void)budget_ns;
}

void ovc_transient_retry_end(void)
{
}

int ovc_dir_sync(const char *dir)
{
    int descriptor;
    int result;
    int error_code;

    descriptor = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (descriptor < 0) {
        return -1;
    }
    do {
        result = fsync(descriptor);
    } while (result != 0 && errno == EINTR);
    error_code = result == 0 ? 0 : errno;
    if (close(descriptor) != 0 && error_code == 0) {
        error_code = errno;
    }
    if (error_code != 0) {
        errno = error_code;
        return -1;
    }
    return 0;
}

#endif

/* These credential-store helpers parallel file_backend.c's static
 * equivalents.  Consolidation belongs to a separate change so the backend
 * remains untouched here. */

int ovc_file_read_all(ovc_file file,
                      size_t max_len,
                      uint8_t **out_bytes,
                      size_t *out_len)
{
    uint64_t file_size;
    size_t length;
    uint8_t *bytes;
    size_t offset;

    if (out_bytes == NULL || out_len == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out_bytes = NULL;
    *out_len = 0;
    if (ovc_file_size(file, &file_size) != 0) {
        return -1;
    }
    if (file_size > (uint64_t)max_len) {
        errno = EFBIG;
        return -1;
    }
    length = (size_t)file_size;
    bytes = (uint8_t *)malloc(length == 0 ? 1 : length);
    if (bytes == NULL) {
        errno = ENOMEM;
        return -1;
    }

    offset = 0;
    while (offset < length) {
        ovc_ssize_t count;

        do {
            count = ovc_pread(file,
                              bytes + offset,
                              length - offset,
                              (uint64_t)offset);
        } while (count < 0 && errno == EINTR);
        if (count < 0) {
            int error;

            error = errno;
            ovc_secure_zero(bytes, length);
            free(bytes);
            errno = error;
            return -1;
        }
        if (count == 0 || (size_t)count > length - offset) {
            ovc_secure_zero(bytes, length);
            free(bytes);
            errno = EIO;
            return -1;
        }
        offset += (size_t)count;
    }
    *out_bytes = bytes;
    *out_len = length;
    return 0;
}

int ovc_file_write_all_from_start(ovc_file file,
                                  const void *bytes,
                                  size_t len)
{
    const uint8_t *cursor;
    size_t offset;

    if (bytes == NULL && len != 0) {
        errno = EINVAL;
        return -1;
    }
    cursor = (const uint8_t *)bytes;
    offset = 0;
    while (offset < len) {
        ovc_ssize_t count;

        do {
            count = ovc_pwrite(file,
                               cursor + offset,
                               len - offset,
                               (uint64_t)offset);
        } while (count < 0 && errno == EINTR);
        if (count < 0) {
            return -1;
        }
        if (count == 0 || (size_t)count > len - offset) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

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

char *ovc_path_parent_dup(const char *path)
{
    char *copy;
    size_t length;

    if (path == NULL) {
        errno = EINVAL;
        return NULL;
    }
    length = strlen(path);
    if (length == SIZE_MAX) {
        errno = ENOMEM;
        return NULL;
    }
    copy = (char *)malloc(length + 1);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, path, length + 1);
    while (length > 0 && !ovc_path_is_separator(copy[length - 1])) {
        --length;
    }
    while (length > 1 && ovc_path_is_separator(copy[length - 1])) {
        --length;
    }
#if defined(_WIN32)
    if (length == 2 && copy[1] == ':') {
        copy[length++] = OVC_PATH_SEPARATOR;
    }
#endif
    copy[length] = '\0';
    return copy;
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
