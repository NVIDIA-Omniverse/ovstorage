/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "internal.h"

#include "temp_dir.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <unistd.h>
#endif

static char *ovc_temp_dir_duplicate(const char *value, size_t length)
{
    char *copy;

    if (length == SIZE_MAX) {
        errno = ENOMEM;
        return NULL;
    }
    copy = (char *)malloc(length + 1);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, value, length);
    copy[length] = '\0';
    return copy;
}

#if !defined(_WIN32)

/* Join a relative configured root onto the working directory.
 *
 * `getcwd` with a NULL buffer is a glibc/BSD extension; POSIX.1-2008 leaves it
 * unspecified, so the buffer is grown explicitly. */
static char *ovc_temp_dir_resolve_relative(const char *relative)
{
    size_t capacity;
    char *working;

    capacity = 256;
    working = NULL;
    for (;;) {
        char *replacement;

        replacement = (char *)realloc(working, capacity);
        if (replacement == NULL) {
            free(working);
            return NULL;
        }
        working = replacement;
        if (getcwd(working, capacity) != NULL) {
            break;
        }
        if (errno != ERANGE) {
            free(working);
            return NULL;
        }
        if (capacity > SIZE_MAX / 2) {
            free(working);
            errno = ENAMETOOLONG;
            return NULL;
        }
        capacity *= 2;
    }
    {
        char *joined;

        joined = ovc_path_join(working, relative);
        free(working);
        return joined;
    }
}

#endif /* !_WIN32 */

/* Drop trailing separators so callers can join with exactly one.  A root that
 * is nothing but separators keeps its first character: "/" is a real
 * directory, "" is not. */
static void ovc_temp_dir_trim_separators(char *path)
{
    size_t length;

    length = strlen(path);
    while (length > 1 && ovc_path_is_separator(path[length - 1])) {
        path[length - 1] = '\0';
        length--;
    }
}

char *ovc_temp_root_dup(void)
{
#if defined(_WIN32)
    wchar_t *wide;
    DWORD capacity;
    DWORD length;
    int utf8_size;
    char *utf8;

    capacity = MAX_PATH + 1;
    wide = NULL;
    for (;;) {
        wchar_t *replacement;

        if ((size_t)capacity > SIZE_MAX / sizeof(*wide)) {
            errno = ENOMEM;
            free(wide);
            return NULL;
        }
        replacement = (wchar_t *)realloc(
            wide, (size_t)capacity * sizeof(*wide));
        if (replacement == NULL) {
            free(wide);
            return NULL;
        }
        wide = replacement;
        length = GetTempPathW(capacity, wide);
        if (length == 0) {
            free(wide);
            errno = EIO;
            return NULL;
        }
        if (length < capacity) {
            break;
        }
        if (length == MAXDWORD) {
            free(wide);
            errno = ENOMEM;
            return NULL;
        }
        capacity = length + 1;
    }

    utf8_size = WideCharToMultiByte(CP_UTF8,
                                    WC_ERR_INVALID_CHARS,
                                    wide,
                                    -1,
                                    NULL,
                                    0,
                                    NULL,
                                    NULL);
    if (utf8_size <= 0) {
        free(wide);
        errno = EIO;
        return NULL;
    }
    utf8 = (char *)malloc((size_t)utf8_size);
    if (utf8 == NULL) {
        free(wide);
        return NULL;
    }
    if (WideCharToMultiByte(CP_UTF8,
                            WC_ERR_INVALID_CHARS,
                            wide,
                            -1,
                            utf8,
                            utf8_size,
                            NULL,
                            NULL) == 0) {
        free(utf8);
        free(wide);
        errno = EIO;
        return NULL;
    }
    free(wide);
    ovc_temp_dir_trim_separators(utf8);
    return utf8;
#else
    const char *configured;
    char *root;

    configured = getenv("TMPDIR");
    if (configured == NULL || configured[0] == '\0') {
        configured = "/tmp";
    }
    if (ovc_path_is_absolute(configured)) {
        root = ovc_temp_dir_duplicate(configured, strlen(configured));
    } else {
        /* The header promises an absolute path and the callers rely on it:
         * they interpolate the result into `file://%s/`, where a relative
         * root would land in the URL's AUTHORITY -- `file://build/tmp/x`
         * names host "build" -- and the file backend rejects it. Resolve
         * against the working directory rather than returning something the
         * contract says cannot happen. */
        root = ovc_temp_dir_resolve_relative(configured);
    }
    if (root == NULL) {
        return NULL;
    }
    ovc_temp_dir_trim_separators(root);
    return root;
#endif
}

int ovc_temp_dir_create(const char *prefix, char *out, size_t out_size)
{
    const char *scan;
    char *root;
    int written;

    if (prefix == NULL || out == NULL || out_size == 0 || prefix[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    /* A prefix is a name, not a path. Enforcing that keeps a caller from
     * splicing `../` into the template and creating the directory outside the
     * resolved temporary root -- "documented but unchecked" is how a
     * documented rule stops being true, and this is shipped source that
     * consumers compile against. */
    for (scan = prefix; *scan != '\0'; ++scan) {
        if (ovc_path_is_separator(*scan)) {
            errno = EINVAL;
            return -1;
        }
    }
    root = ovc_temp_root_dup();
    if (root == NULL) {
        return -1;
    }
#if defined(_WIN32)
    /* Permissions match the POSIX mkdtemp branch below: the directory is
     * created with a protected, explicit DACL granting the calling user
     * alone, which is the Win32 spelling of 0700.  A NULL descriptor would
     * inherit the parent's ACL instead -- equivalent under the per-user
     * default root, but weaker under a temp root shared between principals,
     * where the inherited ACL can admit readers the POSIX mode bits would
     * exclude.  Documenting that exposure is not the same as removing it,
     * so it is removed.
     *
     * Predictability: the candidate name is derived from the process id, the
     * tick count and a counter, with no randomness, so a concurrent process
     * can predict it.  That is not a hijack: CreateDirectoryW fails rather
     * than opening an existing directory, so an occupied name yields
     * ERROR_ALREADY_EXISTS and the loop moves on to a name this process
     * created.  The result is never a directory somebody else owns. */
    {
        static volatile LONG counter;
        unsigned int attempt;
        SECURITY_ATTRIBUTES attributes;
        PSECURITY_DESCRIPTOR descriptor;
        PACL owner_acl;
        PTOKEN_USER owner_user;

        descriptor = ovc_win32_owner_only_sd_create(&owner_acl, &owner_user);
        if (descriptor == NULL) {
            free(root);
            errno = EACCES;
            return -1;
        }
        attributes.nLength = (DWORD)sizeof(attributes);
        attributes.lpSecurityDescriptor = descriptor;
        attributes.bInheritHandle = FALSE;

        for (attempt = 0; attempt < 256u; ++attempt) {
            wchar_t *wide;
            DWORD error;
            LONG sequence;

            sequence = InterlockedIncrement(&counter);
            written = snprintf(out,
                               out_size,
                               "%s%c%s-%08lx-%08lx-%08lx",
                               root,
                               OVC_PATH_SEPARATOR,
                               prefix,
                               (unsigned long)GetCurrentProcessId(),
                               (unsigned long)GetTickCount(),
                               (unsigned long)sequence);
            if (written < 0) {
                free(root);
                errno = EIO;
                return -1;
            }
            if ((size_t)written >= out_size) {
                ovc_win32_owner_only_sd_free(descriptor,
                                             owner_acl,
                                             owner_user);
                free(root);
                errno = ENAMETOOLONG;
                return -1;
            }
            wide = ovc_utf8_to_wide(out);
            if (wide == NULL) {
                ovc_win32_owner_only_sd_free(descriptor,
                                             owner_acl,
                                             owner_user);
                free(root);
                return -1;
            }
            if (CreateDirectoryW(wide, &attributes) != 0) {
                ovc_win32_owner_only_sd_free(descriptor,
                                             owner_acl,
                                             owner_user);
                free(wide);
                free(root);
                return 0;
            }
            error = GetLastError();
            free(wide);
            /* ERROR_FILE_EXISTS is defensive and measured UNREACHABLE:
             * `CreateDirectoryW` over a name held by a regular file reports
             * ERROR_ALREADY_EXISTS (183), not ERROR_FILE_EXISTS (80) --
             * verified directly on Windows. Kept because it costs nothing
             * and the mapping is Microsoft's to change, but no test can
             * drive it, so do not read its presence as covered. */
            if (error != ERROR_ALREADY_EXISTS &&
                error != ERROR_FILE_EXISTS) {
                ovc_win32_owner_only_sd_free(descriptor,
                                             owner_acl,
                                             owner_user);
                free(root);
                ovc_win32_set_errno(error);
                return -1;
            }
        }
        ovc_win32_owner_only_sd_free(descriptor, owner_acl, owner_user);
        free(root);
        errno = EEXIST;
        return -1;
    }
#else
    written = snprintf(out,
                       out_size,
                       "%s%c%s-XXXXXX",
                       root,
                       OVC_PATH_SEPARATOR,
                       prefix);
    free(root);
    if (written < 0) {
        errno = EIO;
        return -1;
    }
    if ((size_t)written >= out_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (mkdtemp(out) == NULL) {
        return -1;
    }
    return 0;
#endif
}

/* ------------------------------------------------------------------------- */

#if defined(OVC_TEMP_DIR_TEST_MAIN)

#include <assert.h>

#include <sys/stat.h>

#if defined(NDEBUG)
#error "OVC_TEMP_DIR_TEST_MAIN requires assertions to be enabled"
#endif

#if defined(_WIN32)

#include <aclapi.h>

#if !defined(SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif

static char g_scratch[OVC_TEMP_DIR_PATH_MAX];

static void ovc_temp_dir_test_set(const char *value)
{
    assert(_putenv_s("TMP", value) == 0);
    assert(_putenv_s("TEMP", value) == 0);
}

static void ovc_temp_dir_test_remove(const char *path)
{
    wchar_t *wide;

    wide = ovc_utf8_to_wide(path);
    assert(wide != NULL);
    assert(RemoveDirectoryW(wide) != 0);
    free(wide);
}

static void ovc_temp_dir_test_remove_file(const char *path)
{
    wchar_t *wide;

    wide = ovc_utf8_to_wide(path);
    assert(wide != NULL);
    assert(DeleteFileW(wide) != 0);
    free(wide);
}

static void ovc_temp_dir_test_env_is_honoured(void)
{
    char created[OVC_TEMP_DIR_PATH_MAX];
    char *root;
    size_t scratch_len;
    wchar_t *wide;
    DWORD attributes;

    ovc_temp_dir_test_set(g_scratch);
    root = ovc_temp_root_dup();
    assert(root != NULL);
    assert(strcmp(root, g_scratch) == 0);
    free(root);

    assert(ovc_temp_dir_create("honoured", created, sizeof(created)) == 0);
    scratch_len = strlen(g_scratch);
    assert(strncmp(created, g_scratch, scratch_len) == 0);
    assert(ovc_path_is_separator(created[scratch_len]));
    wide = ovc_utf8_to_wide(created);
    assert(wide != NULL);
    attributes = GetFileAttributesW(wide);
    assert(attributes != INVALID_FILE_ATTRIBUTES);
    assert((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
    free(wide);
    ovc_temp_dir_test_remove(created);
}

/* Split a created name into the stem before its tick field and the two
 * trailing hex fields, so the next candidate name can be reconstructed.  The
 * name shape is `<root><sep><prefix>-<pid>-<tick>-<sequence>`. */
static void ovc_temp_dir_test_split_name(const char *name,
                                         size_t *out_stem_len,
                                         unsigned long *out_tick,
                                         unsigned long *out_sequence)
{
    const char *sequence_dash;
    const char *tick_dash;
    const char *scan;

    sequence_dash = strrchr(name, '-');
    assert(sequence_dash != NULL);
    tick_dash = NULL;
    for (scan = sequence_dash - 1; scan > name; --scan) {
        if (*scan == '-') {
            tick_dash = scan;
            break;
        }
    }
    assert(tick_dash != NULL);
    *out_stem_len = (size_t)(tick_dash - name);
    *out_tick = strtoul(tick_dash + 1, NULL, 16);
    *out_sequence = strtoul(sequence_dash + 1, NULL, 16);
}

/* Two sequential creates differ by construction -- the name embeds an
 * InterlockedIncrement counter -- so comparing them never reaches the
 * ERROR_ALREADY_EXISTS retry in the create loop.  Occupying the exact name
 * the next call will try first does reach it, and pins the property that
 * actually matters: a taken name yields a different directory rather than a
 * failure.
 *
 * The candidate embeds GetTickCount(), which may advance between the probe
 * create and the create under test; when it does, the occupied name is not
 * the one tried and the trial proves nothing.  Trials therefore repeat until
 * the tick is observed to hold still, which back-to-back calls achieve
 * immediately given the ~15ms tick granularity.  Confirming the retry ran
 * requires the returned sequence to have skipped past the occupied one. */
static void ovc_temp_dir_test_names_are_exclusive(void)
{
    char first[OVC_TEMP_DIR_PATH_MAX];
    char second[OVC_TEMP_DIR_PATH_MAX];
    char occupied[OVC_TEMP_DIR_PATH_MAX];
    unsigned int attempt;
    int retry_observed;

    ovc_temp_dir_test_set(g_scratch);
    assert(ovc_temp_dir_create("exclusive", first, sizeof(first)) == 0);
    assert(ovc_temp_dir_create("exclusive", second, sizeof(second)) == 0);
    assert(strcmp(first, second) != 0);
    ovc_temp_dir_test_remove(first);
    ovc_temp_dir_test_remove(second);

    retry_observed = 0;
    for (attempt = 0; attempt < 64u && !retry_observed; ++attempt) {
        size_t stem_len;
        unsigned long probe_tick;
        unsigned long probe_sequence;
        unsigned long taken_tick;
        unsigned long taken_sequence;
        wchar_t *wide;
        int written;

        assert(ovc_temp_dir_create("exclusive", first, sizeof(first)) == 0);
        ovc_temp_dir_test_split_name(first,
                                     &stem_len,
                                     &probe_tick,
                                     &probe_sequence);
        written = snprintf(occupied,
                           sizeof(occupied),
                           "%.*s-%08lx-%08lx",
                           (int)stem_len,
                           first,
                           probe_tick,
                           probe_sequence + 1uL);
        assert(written > 0 && (size_t)written < sizeof(occupied));
        wide = ovc_utf8_to_wide(occupied);
        assert(wide != NULL);
        assert(CreateDirectoryW(wide, NULL) != 0);
        free(wide);

        assert(ovc_temp_dir_create("exclusive", second, sizeof(second)) == 0);
        assert(strcmp(second, occupied) != 0);
        ovc_temp_dir_test_split_name(second,
                                     &stem_len,
                                     &taken_tick,
                                     &taken_sequence);
        if (taken_tick == probe_tick) {
            assert(taken_sequence > probe_sequence + 1uL);
            retry_observed = 1;
        }
        ovc_temp_dir_test_remove(second);
        ovc_temp_dir_test_remove(occupied);
        ovc_temp_dir_test_remove(first);
    }
    assert(retry_observed);

    /* The trial above occupies the predicted name with a DIRECTORY. This one
     * occupies it with a regular FILE, which is a distinct collision a caller
     * can hit and which nothing else covered.
     *
     * It does NOT reach the loop's ERROR_FILE_EXISTS arm: `CreateDirectoryW`
     * reports ERROR_ALREADY_EXISTS (183) for a file collision too, measured
     * directly on Windows. Deleting that arm leaves this trial green, which
     * is why the arm itself carries a comment saying it is unreachable rather
     * than a claim of coverage. What this trial proves is that a file in the
     * way is retried past rather than failing creation. */
    {
        char file_first[OVC_TEMP_DIR_PATH_MAX];
        char file_occupied[OVC_TEMP_DIR_PATH_MAX];
        char file_second[OVC_TEMP_DIR_PATH_MAX];
        size_t file_stem_len;
        unsigned long file_tick;
        unsigned long file_sequence;
        int file_written;
        wchar_t *file_wide;
        HANDLE occupier;

        ovc_temp_dir_test_set(g_scratch);
        assert(ovc_temp_dir_create("filecollide", file_first, sizeof(file_first)) == 0);
        ovc_temp_dir_test_split_name(file_first,
                                     &file_stem_len,
                                     &file_tick,
                                     &file_sequence);
        file_written = snprintf(file_occupied,
                           sizeof(file_occupied),
                           "%.*s-%lu-%lu",
                           (int)file_stem_len,
                           file_first,
                           file_tick,
                           file_sequence + 1uL);
        assert(file_written > 0 && (size_t)file_written < sizeof(file_occupied));
        file_wide = ovc_utf8_to_wide(file_occupied);
        assert(file_wide != NULL);
        occupier = CreateFileW(file_wide,
                               GENERIC_WRITE,
                               0,
                               NULL,
                               CREATE_NEW,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);
        free(file_wide);
        assert(occupier != INVALID_HANDLE_VALUE);
        (void)CloseHandle(occupier);

        assert(ovc_temp_dir_create("filecollide", file_second, sizeof(file_second))
               == 0);
        assert(strcmp(file_second, file_occupied) != 0);

        ovc_temp_dir_test_remove(file_second);
        ovc_temp_dir_test_remove_file(file_occupied);
        ovc_temp_dir_test_remove(file_first);
    }
}

static void ovc_temp_dir_test_errors_are_named(void)
{
    char created[OVC_TEMP_DIR_PATH_MAX];
    char tiny[2];

    ovc_temp_dir_test_set(g_scratch);
    errno = 0;
    assert(ovc_temp_dir_create("overlong", tiny, sizeof(tiny)) == -1);
    assert(errno == ENAMETOOLONG);

    errno = 0;
    assert(ovc_temp_dir_create("nested/name", created, sizeof(created)) == -1);
    assert(errno == EINVAL);
    errno = 0;
    assert(ovc_temp_dir_create("nested\\name", created, sizeof(created)) == -1);
    assert(errno == EINVAL);
    errno = 0;
    assert(ovc_temp_dir_create("", created, sizeof(created)) == -1);
    assert(errno == EINVAL);
}

/* Create a symlink for the ELOOP legs, or report that this host cannot.
 * SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE only lifts the
 * SeCreateSymbolicLinkPrivilege requirement when Developer Mode is enabled;
 * on a stock Windows box an unelevated CreateSymbolicLinkW fails with
 * ERROR_PRIVILEGE_NOT_HELD. That is a machine configuration, not a defect,
 * so the leg is skipped (loudly) instead of aborting the suite. Any other
 * failure is still a hard error. */
static int ovc_temp_dir_test_symlink_create(const wchar_t *link,
                                            const wchar_t *target,
                                            DWORD flags,
                                            const char *leg)
{
    DWORD error_code;

    if (CreateSymbolicLinkW(link, target, flags) != 0) {
        return 1;
    }
    error_code = GetLastError();
    if (error_code == ERROR_PRIVILEGE_NOT_HELD) {
        fprintf(stderr,
                "skipping the %s ELOOP leg: CreateSymbolicLinkW needs "
                "Developer Mode or SeCreateSymbolicLinkPrivilege on this "
                "host\n",
                leg);
        return 0;
    }
    fprintf(stderr,
            "CreateSymbolicLinkW failed for the %s ELOOP leg: error %lu\n",
            leg,
            (unsigned long)error_code);
    assert(error_code == ERROR_PRIVILEGE_NOT_HELD);
    return 0;
}

static void ovc_temp_dir_test_owner_only_acl(const char *path,
                                             int expect_token_user_owner)
{
    wchar_t *wide;
    PACL dacl;
    PSID owner;
    PSECURITY_DESCRIPTOR actual_descriptor;
    PSECURITY_DESCRIPTOR expected_descriptor;
    PACL expected_acl;
    PTOKEN_USER expected_user;
    SECURITY_DESCRIPTOR_CONTROL control;
    DWORD revision;
    DWORD status;
    void *ace;
    ACCESS_ALLOWED_ACE *allowed;

    wide = ovc_utf8_to_wide(path);
    assert(wide != NULL);
    dacl = NULL;
    owner = NULL;
    actual_descriptor = NULL;
    status = GetNamedSecurityInfoW(wide,
                                   SE_FILE_OBJECT,
                                   OWNER_SECURITY_INFORMATION |
                                       DACL_SECURITY_INFORMATION,
                                   &owner,
                                   NULL,
                                   &dacl,
                                   NULL,
                                   &actual_descriptor);
    free(wide);
    assert(status == ERROR_SUCCESS);
    assert(actual_descriptor != NULL);
    assert(owner != NULL);
    assert(dacl != NULL);
    assert(dacl->AceCount == 1);
    control = 0;
    revision = 0;
    assert(GetSecurityDescriptorControl(actual_descriptor,
                                        &control,
                                        &revision) != 0);
    assert((control & SE_DACL_PROTECTED) != 0);
    ace = NULL;
    assert(GetAce(dacl, 0, &ace) != 0);
    assert(ace != NULL);
    allowed = (ACCESS_ALLOWED_ACE *)ace;
    assert(allowed->Header.AceType == ACCESS_ALLOWED_ACE_TYPE);
    assert(allowed->Mask == FILE_ALL_ACCESS);
    expected_descriptor =
        ovc_win32_owner_only_sd_create(&expected_acl, &expected_user);
    assert(expected_descriptor != NULL);
    assert(IsValidSid(owner) != 0);
    assert(IsValidSid((PSID)&allowed->SidStart) != 0);
    assert(EqualSid((PSID)&allowed->SidStart,
                    expected_user->User.Sid) != 0);
    if (expect_token_user_owner) {
        assert(EqualSid(owner, expected_user->User.Sid) != 0);
    }
    ovc_win32_owner_only_sd_free(expected_descriptor,
                                 expected_acl,
                                 expected_user);
    assert(LocalFree(actual_descriptor) == NULL);
}

static void ovc_temp_dir_test_owner_validation(const char *path)
{
    wchar_t *wide;
    HANDLE directory;
    PSECURITY_DESCRIPTOR descriptor;
    PACL acl;
    PTOKEN_USER user;
    unsigned char world_sid[SECURITY_MAX_SID_SIZE];
    DWORD world_sid_size;

    wide = ovc_utf8_to_wide(path);
    assert(wide != NULL);
    directory = CreateFileW(wide,
                            READ_CONTROL,
                            FILE_SHARE_READ | FILE_SHARE_WRITE |
                                FILE_SHARE_DELETE,
                            NULL,
                            OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS |
                                FILE_FLAG_OPEN_REPARSE_POINT,
                            NULL);
    free(wide);
    assert(directory != INVALID_HANDLE_VALUE);
    descriptor = ovc_win32_owner_only_sd_create(&acl, &user);
    assert(descriptor != NULL);
    assert(ovc_win32_handle_owner_is(directory,
                                     user->User.Sid,
                                     user->User.Sid) == 0);

    world_sid_size = (DWORD)sizeof(world_sid);
    assert(CreateWellKnownSid(WinWorldSid,
                              NULL,
                              (PSID)world_sid,
                              &world_sid_size) != 0);
    assert(ovc_win32_handle_owner_is(directory,
                                     (PSID)world_sid,
                                     user->User.Sid) == 0);
    errno = 0;
    assert(ovc_win32_handle_owner_is(directory,
                                     (PSID)world_sid,
                                     (PSID)world_sid) == -1);
    assert(errno == EACCES);

    ovc_win32_owner_only_sd_free(descriptor, acl, user);
    assert(CloseHandle(directory) != 0);
}

static void ovc_temp_dir_test_make_permissive_acl(const char *path)
{
    unsigned char world_sid[SECURITY_MAX_SID_SIZE];
    DWORD world_sid_size;
    DWORD acl_size;
    PACL permissive_acl;
    wchar_t *wide;
    DWORD status;
    PACL actual_acl;
    PSECURITY_DESCRIPTOR actual_descriptor;
    SECURITY_DESCRIPTOR_CONTROL control;
    DWORD revision;
    DWORD ace_index;
    int found_world;

    world_sid_size = (DWORD)sizeof(world_sid);
    assert(CreateWellKnownSid(WinWorldSid,
                              NULL,
                              (PSID)world_sid,
                              &world_sid_size) != 0);
    acl_size = (DWORD)(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) -
                       sizeof(DWORD) + GetLengthSid((PSID)world_sid));
    permissive_acl = (PACL)malloc(acl_size);
    assert(permissive_acl != NULL);
    assert(InitializeAcl(permissive_acl, acl_size, ACL_REVISION) != 0);
    assert(AddAccessAllowedAce(permissive_acl,
                               ACL_REVISION,
                               FILE_ALL_ACCESS,
                               (PSID)world_sid) != 0);

    wide = ovc_utf8_to_wide(path);
    assert(wide != NULL);
    status = SetNamedSecurityInfoW(
        wide,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        permissive_acl,
        NULL);
    free(permissive_acl);
    assert(status == ERROR_SUCCESS);

    actual_acl = NULL;
    actual_descriptor = NULL;
    status = GetNamedSecurityInfoW(wide,
                                   SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION,
                                   NULL,
                                   NULL,
                                   &actual_acl,
                                   NULL,
                                   &actual_descriptor);
    free(wide);
    assert(status == ERROR_SUCCESS);
    assert(actual_acl != NULL);
    assert(actual_descriptor != NULL);
    control = 0;
    revision = 0;
    assert(GetSecurityDescriptorControl(actual_descriptor,
                                        &control,
                                        &revision) != 0);
    assert((control & SE_DACL_PROTECTED) == 0);
    found_world = 0;
    for (ace_index = 0; ace_index < actual_acl->AceCount; ++ace_index) {
        void *ace;
        ACCESS_ALLOWED_ACE *allowed;

        ace = NULL;
        assert(GetAce(actual_acl, ace_index, &ace) != 0);
        assert(ace != NULL);
        allowed = (ACCESS_ALLOWED_ACE *)ace;
        if (allowed->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            allowed->Mask == FILE_ALL_ACCESS &&
            EqualSid((PSID)&allowed->SidStart, (PSID)world_sid)) {
            found_world = 1;
        }
    }
    assert(found_world);
    assert(LocalFree(actual_descriptor) == NULL);
}

static void ovc_temp_dir_test_private_directory_primitive(void)
{
    char *parent;
    char *leaf;
    char *existing;
    char *file_path;
    char *link_path;
    wchar_t *wide;
    wchar_t *wide_link;
    wchar_t *wide_target;
    HANDLE file;

    parent = ovc_path_parent_dup("C:\\child");
    assert(parent != NULL);
    assert(strcmp(parent, "C:\\") == 0);
    free(parent);
    parent = ovc_path_parent_dup("child");
    assert(parent != NULL);
    assert(parent[0] == '\0');
    free(parent);

    parent = ovc_path_join(g_scratch, "private-parent");
    assert(parent != NULL);
    leaf = ovc_path_join(parent, "leaf");
    assert(leaf != NULL);
    assert(ovc_private_dir_ensure(leaf) == 0);
    ovc_temp_dir_test_owner_only_acl(leaf, 1);
    ovc_temp_dir_test_owner_validation(leaf);
    assert(ovc_private_dir_ensure(leaf) == 0);
    ovc_temp_dir_test_remove(leaf);
    ovc_temp_dir_test_remove(parent);
    free(leaf);
    free(parent);

    existing = ovc_path_join(g_scratch, "private-existing");
    assert(existing != NULL);
    wide = ovc_utf8_to_wide(existing);
    assert(wide != NULL);
    /* A NULL descriptor selects TokenOwner. The explicit Everyone DACL is
     * the permissive precondition the hardening call must replace. */
    assert(CreateDirectoryW(wide, NULL) != 0);
    free(wide);
    ovc_temp_dir_test_make_permissive_acl(existing);
    assert(ovc_private_dir_ensure(existing) == 0);
    ovc_temp_dir_test_owner_only_acl(existing, 0);
    ovc_temp_dir_test_remove(existing);
    free(existing);

    link_path = ovc_path_join(g_scratch, "private-directory-link");
    assert(link_path != NULL);
    wide_link = ovc_utf8_to_wide(link_path);
    wide_target = ovc_utf8_to_wide(g_scratch);
    assert(wide_link != NULL);
    assert(wide_target != NULL);
    if (ovc_temp_dir_test_symlink_create(
            wide_link,
            wide_target,
            SYMBOLIC_LINK_FLAG_DIRECTORY |
                SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
            "private directory symlink")) {
        errno = 0;
        assert(ovc_private_dir_ensure(link_path) == -1);
        assert(errno == ELOOP);
        ovc_temp_dir_test_remove(link_path);
    }
    free(wide_target);
    free(wide_link);
    free(link_path);

    file_path = ovc_path_join(g_scratch, "private-file");
    assert(file_path != NULL);
    wide = ovc_utf8_to_wide(file_path);
    assert(wide != NULL);
    file = CreateFileW(wide,
                       GENERIC_WRITE,
                       0,
                       NULL,
                       CREATE_NEW,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
    free(wide);
    assert(file != INVALID_HANDLE_VALUE);
    assert(CloseHandle(file) != 0);
    errno = 0;
    assert(ovc_private_dir_ensure(file_path) == -1);
    assert(errno == ENOTDIR);
    ovc_temp_dir_test_remove_file(file_path);
    free(file_path);
}

static void ovc_temp_dir_test_private_file_primitive(void)
{
    static const unsigned char contents[] = { 0x61, 0x62, 0x63 };
    char *path;
    char *second_path;
    char *default_owner_path;
    char *link_path;
    wchar_t *wide_path;
    wchar_t *wide_default_owner_path;
    wchar_t *wide_link;
    HANDLE native_file;
    ovc_file file;
    uint64_t size;

    path = ovc_path_join(g_scratch, "owner-only-record");
    assert(path != NULL);
    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_CREATE_NEW);
    assert(file != OVC_INVALID_FILE);
    ovc_temp_dir_test_owner_only_acl(path, 1);
    assert(ovc_pwrite(file, contents, sizeof(contents), 0) ==
           (ovc_ssize_t)sizeof(contents));
    assert(ovc_file_sync(file) == 0);
    assert(ovc_file_size(file, &size) == 0);
    assert(size == sizeof(contents));
    assert(ovc_file_close(file) == 0);

    errno = 0;
    assert(ovc_private_file_open(path, OVC_PRIVATE_OPEN_CREATE_NEW) ==
           OVC_INVALID_FILE);
    assert(errno == EEXIST);
    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_ALWAYS);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_file_close(file) == 0);
    ovc_temp_dir_test_owner_only_acl(path, 1);
    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_EXISTING);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_file_close(file) == 0);

    second_path = ovc_path_join(g_scratch, "owner-only-always");
    assert(second_path != NULL);
    file = ovc_private_file_open(second_path, OVC_PRIVATE_OPEN_ALWAYS);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_file_close(file) == 0);
    ovc_temp_dir_test_owner_only_acl(second_path, 1);

    default_owner_path = ovc_path_join(g_scratch, "default-owner-record");
    assert(default_owner_path != NULL);
    wide_default_owner_path = ovc_utf8_to_wide(default_owner_path);
    assert(wide_default_owner_path != NULL);
    native_file = CreateFileW(wide_default_owner_path,
                              GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE |
                                  FILE_SHARE_DELETE,
                              NULL,
                              CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    free(wide_default_owner_path);
    assert(native_file != INVALID_HANDLE_VALUE);
    assert(CloseHandle(native_file) != 0);
    ovc_temp_dir_test_make_permissive_acl(default_owner_path);
    file = ovc_private_file_open(default_owner_path,
                                 OVC_PRIVATE_OPEN_EXISTING);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_file_close(file) == 0);
    ovc_temp_dir_test_owner_only_acl(default_owner_path, 0);

    errno = 0;
    assert(ovc_private_file_open(g_scratch, OVC_PRIVATE_OPEN_EXISTING) ==
           OVC_INVALID_FILE);

    link_path = ovc_path_join(g_scratch, "owner-only-link");
    assert(link_path != NULL);
    wide_path = ovc_utf8_to_wide(path);
    wide_link = ovc_utf8_to_wide(link_path);
    assert(wide_path != NULL);
    assert(wide_link != NULL);
    if (ovc_temp_dir_test_symlink_create(
            wide_link,
            wide_path,
            SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
            "owner-only file symlink")) {
        errno = 0;
        assert(ovc_private_file_open(link_path, OVC_PRIVATE_OPEN_EXISTING) ==
               OVC_INVALID_FILE);
        assert(errno == ELOOP);
        ovc_temp_dir_test_remove_file(link_path);
    }
    free(wide_link);
    free(wide_path);
    free(link_path);
    ovc_temp_dir_test_remove_file(default_owner_path);
    ovc_temp_dir_test_remove_file(second_path);
    ovc_temp_dir_test_remove_file(path);
    free(default_owner_path);
    free(second_path);
    free(path);
}

struct ovc_temp_dir_hold {
    HANDLE handle;
    uint64_t hold_ns;
};

static void ovc_temp_dir_test_release_after(void *argument)
{
    struct ovc_temp_dir_hold *hold;

    hold = (struct ovc_temp_dir_hold *)argument;
    ovc_sleep_ns(hold->hold_ns);
    assert(CloseHandle(hold->handle) != 0);
}

/* A handle on the destination without FILE_SHARE_DELETE, which is what an
 * antivirus scanner or the indexer holds for a moment, makes MoveFileExW fail
 * with ERROR_ACCESS_DENIED and DeleteFileW with ERROR_SHARING_VIOLATION. The
 * replace and unlink primitives must outlive a short hold rather than report
 * it: a helper thread lets go after 300 ms and both calls must still succeed,
 * where a single attempt would have failed at once. */
static void ovc_temp_dir_test_replace_outlives_a_transient_hold(void)
{
    static const unsigned char source_bytes[] = { 1, 2, 3, 4, 5 };
    static const unsigned char target_bytes[] = { 9, 9 };
    struct ovc_temp_dir_hold hold;
    ovc_thread thread;
    char *source;
    char *target;
    wchar_t *wide_source;
    wchar_t *wide_target;
    ovc_file file;
    uint64_t size;

    source = ovc_path_join(g_scratch, "replace-source");
    assert(source != NULL);
    target = ovc_path_join(g_scratch, "replace-target");
    assert(target != NULL);
    file = ovc_private_file_open(source, OVC_PRIVATE_OPEN_CREATE_NEW);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_pwrite(file, source_bytes, sizeof(source_bytes), 0) ==
           (ovc_ssize_t)sizeof(source_bytes));
    assert(ovc_file_close(file) == 0);
    file = ovc_private_file_open(target, OVC_PRIVATE_OPEN_CREATE_NEW);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_pwrite(file, target_bytes, sizeof(target_bytes), 0) ==
           (ovc_ssize_t)sizeof(target_bytes));
    assert(ovc_file_close(file) == 0);
    wide_source = ovc_utf8_to_wide(source);
    assert(wide_source != NULL);
    wide_target = ovc_utf8_to_wide(target);
    assert(wide_target != NULL);

    hold.handle = CreateFileW(wide_target,
                              GENERIC_READ,
                              FILE_SHARE_READ,
                              NULL,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    assert(hold.handle != INVALID_HANDLE_VALUE);
    hold.hold_ns = UINT64_C(300000000);
    assert(ovc_thread_create(&thread, ovc_temp_dir_test_release_after, &hold) ==
           0);
    assert(ovc_file_rename_replace(source, target) == 0);
    assert(ovc_thread_join(&thread) == 0);
    assert(GetFileAttributesW(wide_source) == INVALID_FILE_ATTRIBUTES);
    file = ovc_private_file_open(target, OVC_PRIVATE_OPEN_EXISTING);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_file_size(file, &size) == 0);
    assert(size == sizeof(source_bytes));
    assert(ovc_file_close(file) == 0);

    hold.handle = CreateFileW(wide_target,
                              GENERIC_READ,
                              FILE_SHARE_READ,
                              NULL,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    assert(hold.handle != INVALID_HANDLE_VALUE);
    assert(ovc_thread_create(&thread, ovc_temp_dir_test_release_after, &hold) ==
           0);
    assert(ovc_file_unlink(target) == 0);
    assert(ovc_thread_join(&thread) == 0);
    assert(GetFileAttributesW(wide_target) == INVALID_FILE_ATTRIBUTES);

    free(wide_target);
    free(wide_source);
    free(target);
    free(source);
}

/* The open of the record is on every store operation, `secret_get` included,
 * and asks for GENERIC_WRITE, so it needs FILE_SHARE_WRITE from any other
 * holder: a stricter ask than the delete sharing MoveFileExW needs, and one a
 * read-only scanner handle does not grant. Then the conditional case: a holder
 * that did grant delete sharing lets DeleteFileW succeed at once but leaves the
 * name delete-pending until it closes, and CREATE_NEW on that name reports
 * ERROR_ACCESS_DENIED. Both opens must outlive a 300 ms hold. (Where the
 * platform removes the name immediately, the second leg simply succeeds
 * without needing the retry, which the assertions accept.) */
static void ovc_temp_dir_test_open_outlives_a_transient_hold(void)
{
    static const unsigned char bytes[] = { 7, 7, 7 };
    struct ovc_temp_dir_hold hold;
    ovc_thread thread;
    char *path;
    wchar_t *wide;
    ovc_file file;
    uint64_t size;

    path = ovc_path_join(g_scratch, "open-held");
    assert(path != NULL);
    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_CREATE_NEW);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_pwrite(file, bytes, sizeof(bytes), 0) ==
           (ovc_ssize_t)sizeof(bytes));
    assert(ovc_file_close(file) == 0);
    wide = ovc_utf8_to_wide(path);
    assert(wide != NULL);

    hold.handle = CreateFileW(wide,
                              GENERIC_READ,
                              FILE_SHARE_READ,
                              NULL,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    assert(hold.handle != INVALID_HANDLE_VALUE);
    hold.hold_ns = UINT64_C(300000000);
    assert(ovc_thread_create(&thread, ovc_temp_dir_test_release_after, &hold) ==
           0);
    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_EXISTING);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_thread_join(&thread) == 0);
    assert(ovc_file_size(file, &size) == 0);
    assert(size == sizeof(bytes));
    assert(ovc_file_close(file) == 0);

    hold.handle = CreateFileW(wide,
                              GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_DELETE,
                              NULL,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    assert(hold.handle != INVALID_HANDLE_VALUE);
    assert(ovc_thread_create(&thread, ovc_temp_dir_test_release_after, &hold) ==
           0);
    assert(ovc_file_unlink(path) == 0);
    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_CREATE_NEW);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_thread_join(&thread) == 0);
    assert(ovc_file_size(file, &size) == 0);
    assert(size == 0);
    assert(ovc_file_close(file) == 0);
    assert(ovc_file_unlink(path) == 0);

    free(wide);
    free(path);
}

/* The retry budget is the operation's, not the primitive's. Inside a scope
 * every primitive answers to one deadline, so a hold that outlasts it costs
 * one budget in total: the first primitive retries until the scope's deadline
 * and the next reports at once, instead of each waiting its own two seconds
 * inside the lock other processes are queued on. Outside the scope the
 * primitives are whole again. */
static void ovc_temp_dir_test_transient_budget_is_shared_by_an_operation(void)
{
    static const unsigned char bytes[] = { 4, 2 };
    struct ovc_temp_dir_hold hold;
    ovc_thread thread;
    char *source;
    char *target;
    wchar_t *wide_target;
    ovc_file file;
    uint64_t started;
    uint64_t elapsed;

    source = ovc_path_join(g_scratch, "budget-source");
    assert(source != NULL);
    target = ovc_path_join(g_scratch, "budget-target");
    assert(target != NULL);
    file = ovc_private_file_open(source, OVC_PRIVATE_OPEN_CREATE_NEW);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_pwrite(file, bytes, sizeof(bytes), 0) ==
           (ovc_ssize_t)sizeof(bytes));
    assert(ovc_file_close(file) == 0);
    file = ovc_private_file_open(target, OVC_PRIVATE_OPEN_CREATE_NEW);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_file_close(file) == 0);
    wide_target = ovc_utf8_to_wide(target);
    assert(wide_target != NULL);

    hold.handle = CreateFileW(wide_target,
                              GENERIC_READ,
                              FILE_SHARE_READ,
                              NULL,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
    assert(hold.handle != INVALID_HANDLE_VALUE);
    hold.hold_ns = UINT64_C(1500000000);
    assert(ovc_thread_create(&thread, ovc_temp_dir_test_release_after, &hold) ==
           0);

    ovc_transient_retry_begin(UINT64_C(200000000));
    started = ovc_monotonic_ns();
    assert(ovc_file_rename_replace(source, target) != 0);
    assert(errno == EACCES);
    elapsed = ovc_monotonic_ns() - started;
    /* It retried to the scope's deadline, and not to a fresh 2 s of its own. */
    assert(elapsed >= UINT64_C(150000000));
    assert(elapsed < UINT64_C(1000000000));
    started = ovc_monotonic_ns();
    assert(ovc_file_unlink(target) != 0);
    assert(errno == EACCES);
    elapsed = ovc_monotonic_ns() - started;
    /* The budget is spent: the second primitive does not wait again. */
    assert(elapsed < UINT64_C(100000000));
    ovc_transient_retry_end();

    assert(ovc_thread_join(&thread) == 0);
    assert(ovc_file_rename_replace(source, target) == 0);
    assert(ovc_file_unlink(target) == 0);
    assert(GetFileAttributesW(wide_target) == INVALID_FILE_ATTRIBUTES);

    free(wide_target);
    free(target);
    free(source);
}

int main(void)
{
    assert(ovc_temp_dir_create("ovstorage-temp-dir-suite",
                               g_scratch,
                               sizeof(g_scratch)) == 0);
    ovc_temp_dir_test_env_is_honoured();
    ovc_temp_dir_test_names_are_exclusive();
    ovc_temp_dir_test_errors_are_named();
    ovc_temp_dir_test_private_directory_primitive();
    ovc_temp_dir_test_private_file_primitive();
    ovc_temp_dir_test_replace_outlives_a_transient_hold();
    ovc_temp_dir_test_open_outlives_a_transient_hold();
    ovc_temp_dir_test_transient_budget_is_shared_by_an_operation();
    ovc_temp_dir_test_remove(g_scratch);
    (void)printf("temp_dir suite passed\n");
    return 0;
}

#else

/*
 * The $TMPDIR resolution this module exists for, exercised with $TMPDIR
 * actually SET.
 *
 * Every other consumer in the tree runs with whatever $TMPDIR the environment
 * happens to hold, and in CI that is nothing -- so `configured` is NULL, the
 * `/tmp` fallback is taken, and the module behaves byte-for-byte like an
 * unconditional `/tmp`. A build that deleted the `getenv` and returned
 * "/tmp" unconditionally would pass every other gate in this repo.
 * This suite is the one place the environment is controlled, so the branches
 * that depend on `$TMPDIR` are reached: the `getenv` itself, separator
 * trimming, relative-root resolution, the prefix guard, and the
 * ENAMETOOLONG ceiling.
 */

/* Scratch roots are created under the AMBIENT temporary directory, before any
 * case overwrites $TMPDIR -- the suite has to bootstrap somewhere the process
 * may actually write, and that is the same question the module answers. */
static char g_scratch[OVC_TEMP_DIR_PATH_MAX];

static void ovc_temp_dir_test_set(const char *value)
{
    assert(setenv("TMPDIR", value, 1) == 0);
}

/* $TMPDIR is honoured: the resolved root IS the configured directory, and a
 * created directory lands beneath it rather than under /tmp. */
static void ovc_temp_dir_test_env_is_honoured(void)
{
    char created[OVC_TEMP_DIR_PATH_MAX];
    char *root;
    size_t scratch_len;

    ovc_temp_dir_test_set(g_scratch);
    root = ovc_temp_root_dup();
    assert(root != NULL);
    assert(strcmp(root, g_scratch) == 0);
    free(root);

    assert(ovc_temp_dir_create("honoured", created, sizeof(created)) == 0);
    scratch_len = strlen(g_scratch);
    assert(strncmp(created, g_scratch, scratch_len) == 0);
    assert(created[scratch_len] == '/');
    /* Not merely named under the root -- actually there. */
    assert(rmdir(created) == 0);
}

/* Trailing separators are trimmed, so callers join with exactly one. */
static void ovc_temp_dir_test_trailing_separators_are_trimmed(void)
{
    char configured[OVC_TEMP_DIR_PATH_MAX];
    char created[OVC_TEMP_DIR_PATH_MAX];
    char *root;
    int written;

    written = snprintf(configured, sizeof(configured), "%s///", g_scratch);
    assert(written > 0 && (size_t)written < sizeof(configured));
    ovc_temp_dir_test_set(configured);

    root = ovc_temp_root_dup();
    assert(root != NULL);
    assert(strcmp(root, g_scratch) == 0);
    free(root);

    assert(ovc_temp_dir_create("trimmed", created, sizeof(created)) == 0);
    /* One separator at the join, not four. */
    assert(strstr(created, "//") == NULL);
    assert(rmdir(created) == 0);
}

/* A root that is nothing but separators keeps its first character: "/" is a
 * real directory, "" is not. */
static void ovc_temp_dir_test_root_directory_survives_trimming(void)
{
    char *root;

    ovc_temp_dir_test_set("///");
    root = ovc_temp_root_dup();
    assert(root != NULL);
    assert(strcmp(root, "/") == 0);
    free(root);
}

/* A relative $TMPDIR is resolved against the working directory, because the
 * header promises an absolute path and the callers interpolate the result
 * into `file://%s/` where a relative root would become the URL authority. */
static void ovc_temp_dir_test_relative_root_is_made_absolute(void)
{
    char created[OVC_TEMP_DIR_PATH_MAX];
    char relative[64];
    char *root;

    /* Work inside the scratch root so the relative name resolves somewhere
     * writable and the suite leaves nothing behind. */
    assert(chdir(g_scratch) == 0);
    assert(snprintf(relative, sizeof(relative), "relative-root") > 0);
    assert(mkdir(relative, 0700) == 0);
    ovc_temp_dir_test_set(relative);

    root = ovc_temp_root_dup();
    assert(root != NULL);
    assert(ovc_path_is_absolute(root));
    assert(strncmp(root, g_scratch, strlen(g_scratch)) == 0);
    assert(strstr(root, "relative-root") != NULL);
    free(root);

    assert(ovc_temp_dir_create("relative", created, sizeof(created)) == 0);
    assert(ovc_path_is_absolute(created));
    assert(rmdir(created) == 0);
    assert(rmdir(relative) == 0);
}

/* Unset and empty both fall back to /tmp. Asserted on the resolved string
 * rather than by creating anything: /tmp is not writable everywhere this
 * suite runs, which is why the module exists. */
static void ovc_temp_dir_test_unset_and_empty_fall_back(void)
{
    char *root;

    assert(unsetenv("TMPDIR") == 0);
    root = ovc_temp_root_dup();
    assert(root != NULL);
    assert(strcmp(root, "/tmp") == 0);
    free(root);

    ovc_temp_dir_test_set("");
    root = ovc_temp_root_dup();
    assert(root != NULL);
    assert(strcmp(root, "/tmp") == 0);
    free(root);
}

/* A root too long for the caller's buffer is a named error, never a
 * truncated path that would resolve somewhere unintended. */
static void ovc_temp_dir_test_overlong_root_reports_enametoolong(void)
{
    char configured[OVC_TEMP_DIR_PATH_MAX * 2];
    char created[OVC_TEMP_DIR_PATH_MAX];
    size_t index;

    configured[0] = '/';
    for (index = 1; index < sizeof(configured) - 1; ++index) {
        configured[index] = 'x';
    }
    configured[sizeof(configured) - 1] = '\0';
    ovc_temp_dir_test_set(configured);

    errno = 0;
    assert(ovc_temp_dir_create("overlong", created, sizeof(created)) == -1);
    assert(errno == ENAMETOOLONG);
}

/* A prefix is a name, not a path: a separator is rejected rather than
 * spliced into the template, so the directory cannot land outside the root. */
static void ovc_temp_dir_test_prefix_must_not_be_a_path(void)
{
    char created[OVC_TEMP_DIR_PATH_MAX];

    ovc_temp_dir_test_set(g_scratch);

    errno = 0;
    assert(ovc_temp_dir_create("../escape", created, sizeof(created)) == -1);
    assert(errno == EINVAL);

    errno = 0;
    assert(ovc_temp_dir_create("nested/name", created, sizeof(created)) == -1);
    assert(errno == EINVAL);

    errno = 0;
    assert(ovc_temp_dir_create("", created, sizeof(created)) == -1);
    assert(errno == EINVAL);

    errno = 0;
    assert(ovc_temp_dir_create(NULL, created, sizeof(created)) == -1);
    assert(errno == EINVAL);

    errno = 0;
    assert(ovc_temp_dir_create("valid", NULL, sizeof(created)) == -1);
    assert(errno == EINVAL);

    errno = 0;
    assert(ovc_temp_dir_create("valid", created, 0) == -1);
    assert(errno == EINVAL);
}

static void ovc_temp_dir_test_private_directory_primitive(void)
{
    char *parent;
    char *middle;
    char *leaf;
    char *existing;
    char *file_path;
    char *link_path;
    char *foreign;
    FILE *file;
    struct stat status;
    mode_t old_umask;

    parent = ovc_path_parent_dup("/child");
    assert(parent != NULL);
    assert(strcmp(parent, "/") == 0);
    free(parent);
    parent = ovc_path_parent_dup("child");
    assert(parent != NULL);
    assert(parent[0] == '\0');
    free(parent);

    /* Two missing ancestors, created under `umask 0`: the intermediates the
     * host creates must come out `0700` like the leaf, not `0777 & ~umask`,
     * or a permissive umask would leave the store's parents world-writable.
     * Two levels exercise both mkdir sites, the direct one and the retry
     * after the recursive ENOENT repair. */
    parent = ovc_path_join(g_scratch, "private-parent");
    assert(parent != NULL);
    middle = ovc_path_join(parent, "middle");
    assert(middle != NULL);
    leaf = ovc_path_join(middle, "leaf");
    assert(leaf != NULL);
    old_umask = umask(0000);
    assert(ovc_private_dir_ensure(leaf) == 0);
    (void)umask(old_umask);
    assert(stat(parent, &status) == 0);
    assert((status.st_mode & 0777) == 0700);
    assert(stat(middle, &status) == 0);
    assert((status.st_mode & 0777) == 0700);
    assert(stat(leaf, &status) == 0);
    assert((status.st_mode & 0777) == 0700);
    assert(ovc_private_dir_ensure(leaf) == 0);
    assert(rmdir(leaf) == 0);
    assert(rmdir(middle) == 0);
    assert(rmdir(parent) == 0);
    free(leaf);
    free(middle);
    free(parent);

    existing = ovc_path_join(g_scratch, "private-existing");
    assert(existing != NULL);
    assert(mkdir(existing, 0755) == 0);
    assert(chmod(existing, 0755) == 0);
    assert(ovc_private_dir_ensure(existing) == 0);
    assert(stat(existing, &status) == 0);
    assert((status.st_mode & 0777) == 0700);
    assert(rmdir(existing) == 0);
    free(existing);

    file_path = ovc_path_join(g_scratch, "private-file");
    assert(file_path != NULL);
    file = fopen(file_path, "wb");
    assert(file != NULL);
    assert(fclose(file) == 0);
    errno = 0;
    assert(ovc_private_dir_ensure(file_path) == -1);
    assert(errno == ENOTDIR);
    assert(unlink(file_path) == 0);
    free(file_path);

    link_path = ovc_path_join(g_scratch, "private-link");
    assert(link_path != NULL);
    assert(symlink(g_scratch, link_path) == 0);
    errno = 0;
    assert(ovc_private_dir_ensure(link_path) == -1);
    assert(errno == ELOOP);
    assert(unlink(link_path) == 0);
    free(link_path);

    if (geteuid() == 0) {
        foreign = ovc_path_join(g_scratch, "private-foreign");
        assert(foreign != NULL);
        assert(mkdir(foreign, 0700) == 0);
        assert(chown(foreign, getuid() == 0 ? 1 : 0, (gid_t)-1) == 0);
        errno = 0;
        assert(ovc_private_dir_ensure(foreign) == -1);
        assert(errno == EACCES);
        assert(chown(foreign, getuid(), (gid_t)-1) == 0);
        assert(rmdir(foreign) == 0);
        free(foreign);
    } else {
        assert(lstat("/", &status) == 0);
        if (status.st_uid != getuid()) {
            errno = 0;
            assert(ovc_private_dir_ensure("/") == -1);
            assert(errno == EACCES);
        }
    }
}

static void ovc_temp_dir_test_private_file_primitive(void)
{
    static const unsigned char contents[] = { 0x61, 0x62, 0x63 };
    char *path;
    char *second_path;
    char *link_path;
    ovc_file file;
    uint64_t size;
    struct stat status;
    mode_t old_umask;

    path = ovc_path_join(g_scratch, "owner-only-record");
    assert(path != NULL);
    old_umask = umask(0000);
    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_CREATE_NEW);
    (void)umask(old_umask);
    assert(file != OVC_INVALID_FILE);
    assert(fstat(file, &status) == 0);
    assert((status.st_mode & 0777) == 0600);
    assert(ovc_pwrite(file, contents, sizeof(contents), 0) ==
           (ovc_ssize_t)sizeof(contents));
    assert(ovc_file_sync(file) == 0);
    assert(ovc_file_size(file, &size) == 0);
    assert(size == sizeof(contents));
    assert(ovc_file_close(file) == 0);

    errno = 0;
    assert(ovc_private_file_open(path, OVC_PRIVATE_OPEN_CREATE_NEW) ==
           OVC_INVALID_FILE);
    assert(errno == EEXIST);
    assert(chmod(path, 0666) == 0);
    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_ALWAYS);
    assert(file != OVC_INVALID_FILE);
    assert(fstat(file, &status) == 0);
    assert((status.st_mode & 0777) == 0600);
    assert(ovc_file_close(file) == 0);
    file = ovc_private_file_open(path, OVC_PRIVATE_OPEN_EXISTING);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_file_close(file) == 0);

    second_path = ovc_path_join(g_scratch, "owner-only-always");
    assert(second_path != NULL);
    file = ovc_private_file_open(second_path, OVC_PRIVATE_OPEN_ALWAYS);
    assert(file != OVC_INVALID_FILE);
    assert(ovc_file_close(file) == 0);

    link_path = ovc_path_join(g_scratch, "owner-only-link");
    assert(link_path != NULL);
    assert(symlink(path, link_path) == 0);
    errno = 0;
    assert(ovc_private_file_open(link_path, OVC_PRIVATE_OPEN_EXISTING) ==
           OVC_INVALID_FILE);
    assert(errno == ELOOP);
    assert(unlink(link_path) == 0);

    errno = 0;
    assert(ovc_private_file_open(g_scratch, OVC_PRIVATE_OPEN_EXISTING) ==
           OVC_INVALID_FILE);
    assert(errno == EINVAL);

    assert(unlink(second_path) == 0);
    assert(unlink(path) == 0);
    free(link_path);
    free(second_path);
    free(path);
}

int main(void)
{
    char *entry_directory;

    /* Bootstrap under the ambient $TMPDIR, before any case rewrites it. */
    assert(ovc_temp_dir_create("ovstorage-temp-dir-suite",
                               g_scratch,
                               sizeof(g_scratch)) == 0);
    entry_directory = getcwd(NULL, 0);
    assert(entry_directory != NULL);

    ovc_temp_dir_test_env_is_honoured();
    ovc_temp_dir_test_trailing_separators_are_trimmed();
    ovc_temp_dir_test_root_directory_survives_trimming();
    ovc_temp_dir_test_relative_root_is_made_absolute();
    ovc_temp_dir_test_unset_and_empty_fall_back();
    ovc_temp_dir_test_overlong_root_reports_enametoolong();
    ovc_temp_dir_test_prefix_must_not_be_a_path();
    ovc_temp_dir_test_private_directory_primitive();
    ovc_temp_dir_test_private_file_primitive();

    assert(chdir(entry_directory) == 0);
    free(entry_directory);
    assert(rmdir(g_scratch) == 0);
    (void)printf("temp_dir suite passed\n");
    return 0;
}

#endif /* !_WIN32 */

#endif /* OVC_TEMP_DIR_TEST_MAIN */
