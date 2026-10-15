/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Process temporary-directory resolution for the pure-C implementation, its
 * embedded *_TEST_MAIN suites, the shipped examples, and the cross-language
 * fixtures.
 *
 * This header is deliberately standalone -- no `internal.h`, no libc headers
 * beyond <stddef.h> -- so the shipped examples and the out-of-tree test
 * fixtures can include it by relative path without inheriting the private
 * portability interface.
 */

#ifndef OVSTORAGE_C_SOURCE_TEMP_DIR_H
#define OVSTORAGE_C_SOURCE_TEMP_DIR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Buffer size callers should give `ovc_temp_dir_create`.
 *
 * A deliberate fixed cap rather than a caller-sized or heap-allocated path.
 * The callers do not stop at the directory: every one of them composes
 * `file://<dir>/<name>` into its own fixed address buffers (512 bytes in the
 * shipped examples, 1024 in the C fixtures), so those buffers are the real
 * constraint and a dynamically sized temporary root would only move the
 * failure one line later. 256 leaves room for the composition in the
 * smallest of them.
 *
 * Overflow is never a truncation. `ovc_temp_dir_create` composes with
 * `snprintf`, checks the returned length against `out_size`, and fails with
 * ENAMETOOLONG before creating anything, so an over-long `$TMPDIR` produces a
 * named error rather than a short path that resolves somewhere unintended.
 */
#define OVC_TEMP_DIR_PATH_MAX 256

/**
 * Resolve the process temporary directory as a UTF-8 absolute path.
 *
 * `GetTempPathW` on Windows; `$TMPDIR` elsewhere, falling back to `/tmp` when
 * it is unset or empty.  A relative `$TMPDIR` is resolved against the working
 * directory, so the result is absolute whatever the environment holds -- the
 * callers interpolate it into `file://%s/`, where a relative root would land
 * in the URL authority instead of the path.  Any trailing separator is
 * stripped unless the whole path is one.  The caller owns the returned
 * allocation.  NULL is returned with errno set on failure.
 *
 * The result is a native path, not a URL component: a caller that builds a
 * `file://` address from it owns any percent-encoding its own root requires.
 */
char *ovc_temp_root_dup(void);

/**
 * Create a fresh directory beneath `<temp-root>` whose name starts with
 * `<prefix>-`, and write its
 * absolute path into `out`.
 *
 * `prefix` names the caller: it must be non-empty and contain no path
 * separator, and a separator is rejected rather than merely documented so it
 * cannot splice the created directory outside the resolved root.  Returns 0
 * on success.  On failure returns -1 with errno set -- EINVAL for a rejected
 * prefix, ENAMETOOLONG when `out_size` cannot hold the result -- and the
 * contents of `out` are unspecified.  Removing the directory is the caller's
 * job.
 *
 * Resolving the root rather than hard-coding `/tmp` is the entire point: the
 * directory has to land where the environment says the process may write.
 *
 */
int ovc_temp_dir_create(const char *prefix, char *out, size_t out_size);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OVSTORAGE_C_SOURCE_TEMP_DIR_H */
