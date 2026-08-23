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

#if defined(_WIN32)

/* The owner-only DACL below needs advapi32 (OpenProcessToken,
 * GetTokenInformation, InitializeAcl, AddAccessAllowedAce,
 * InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
 * SetSecurityDescriptorControl).
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

/* A security descriptor granting only the calling user, or NULL on failure.
 *
 * This is the Win32 analogue of mkdtemp's 0700: a protected DACL with one
 * ACE for the process token's user and no inherited entries, so a temp root
 * shared between principals cannot widen it.  The caller owns the returned
 * descriptor and frees it with ovc_temp_dir_free_owner_only_sd. */
static PSECURITY_DESCRIPTOR ovc_temp_dir_owner_only_sd(PACL *out_acl,
                                                       PTOKEN_USER *out_user)
{
    HANDLE token;
    DWORD needed;
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
        (void)CloseHandle(token);
        return NULL;
    }
    user = (PTOKEN_USER)malloc(needed);
    if (user == NULL) {
        (void)CloseHandle(token);
        return NULL;
    }
    if (!GetTokenInformation(token, TokenUser, user, needed, &needed)) {
        free(user);
        (void)CloseHandle(token);
        return NULL;
    }
    (void)CloseHandle(token);

    acl_size = (DWORD)(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE)
                       - sizeof(DWORD)
                       + GetLengthSid(user->User.Sid));
    acl = (PACL)malloc(acl_size);
    if (acl == NULL) {
        free(user);
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
        || !SetSecurityDescriptorDacl(descriptor, TRUE, acl, FALSE)
        || !SetSecurityDescriptorControl(descriptor,
                                         SE_DACL_PROTECTED,
                                         SE_DACL_PROTECTED)) {
        free(descriptor);
        free(acl);
        free(user);
        return NULL;
    }
    *out_acl = acl;
    *out_user = user;
    return descriptor;
}

static void ovc_temp_dir_free_owner_only_sd(PSECURITY_DESCRIPTOR descriptor,
                                            PACL acl,
                                            PTOKEN_USER user)
{
    free(descriptor);
    free(acl);
    free(user);
}
#endif /* _WIN32 */

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

        descriptor = ovc_temp_dir_owner_only_sd(&owner_acl, &owner_user);
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
                ovc_temp_dir_free_owner_only_sd(descriptor,
                                                owner_acl,
                                                owner_user);
                free(root);
                errno = ENAMETOOLONG;
                return -1;
            }
            wide = ovc_utf8_to_wide(out);
            if (wide == NULL) {
                ovc_temp_dir_free_owner_only_sd(descriptor,
                                                owner_acl,
                                                owner_user);
                free(root);
                return -1;
            }
            if (CreateDirectoryW(wide, &attributes) != 0) {
                ovc_temp_dir_free_owner_only_sd(descriptor,
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
                ovc_temp_dir_free_owner_only_sd(descriptor,
                                                owner_acl,
                                                owner_user);
                free(root);
                ovc_win32_set_errno(error);
                return -1;
            }
        }
        ovc_temp_dir_free_owner_only_sd(descriptor, owner_acl, owner_user);
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

int main(void)
{
    assert(ovc_temp_dir_create("ovstorage-temp-dir-suite",
                               g_scratch,
                               sizeof(g_scratch)) == 0);
    ovc_temp_dir_test_env_is_honoured();
    ovc_temp_dir_test_names_are_exclusive();
    ovc_temp_dir_test_errors_are_named();
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

    assert(chdir(entry_directory) == 0);
    free(entry_directory);
    assert(rmdir(g_scratch) == 0);
    (void)printf("temp_dir suite passed\n");
    return 0;
}

#endif /* !_WIN32 */

#endif /* OVC_TEMP_DIR_TEST_MAIN */
