/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Sanitizer driver for the stream cancellation/error and live-handoff
 * contracts.
 *
 * The cancel-races-Failed contract requires the dispatcher to release the
 * producer's error while reporting Cancelled, and the handoff contract
 * requires import failures to dispose (or deliberately retain) a foreign
 * handle per the ABI handshake — behaviors observable only as leaks.
 * tools/ovtasks builds this TU together with the distribution sources,
 * tests/cc/streams_c.c, and tests/cc/handoff_c.c under
 * AddressSanitizer+LeakSanitizer and runs it inside
 * `make c-source-examples`, so a regression that stops freeing a
 * plugin-minted error (or leaks an exported root proxy) fails CI.
 * tests/roundtrip.rs runs the same entry points unsanitized; like
 * completeness.c, this TU lives at the crate root so build.rs never links
 * it (its main would collide with the Rust test harness).
 *
 * On Windows the same contracts run under the MSVC debug CRT's leak
 * reporter instead of LeakSanitizer, measured against a baseline taken
 * once the process-lifetime runtime exists (see main).
 */

#if defined(_WIN32) && defined(_MSC_VER)
/* internal.h must precede every libc header in this translation unit. */
#include "../../ovstorage-c-source/src/internal.h"

#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if defined(OVC_ABI_ALLOC_FAILURE_TEST)
#if defined(_MSC_VER)
#define OVC_TEST_THREAD_LOCAL __declspec(thread)
#elif defined(__GNUC__) || defined(__clang__)
#define OVC_TEST_THREAD_LOCAL __thread
#else
#error "the allocation-failure contract needs a thread-local storage spelling"
#endif

typedef struct ovc_abi_alloc_trap {
    size_t armed_size;
    const char *site;
    int open;
    int enabled;
    int fired;
    int protocol_violated;
} ovc_abi_alloc_trap;

static OVC_TEST_THREAD_LOCAL ovc_abi_alloc_trap g_ovc_abi_alloc_trap;

/* Arming claims that the next allocation of exactly `byte_count` on this
 * thread belongs to `site`. The dispatcher copies arguments synchronously
 * before it submits work, so thread-local state excludes unrelated runtime
 * allocations without weakening the path under test. */
void ovc_test_abi_alloc_arm(size_t byte_count, const char *site);
void ovc_test_abi_alloc_arm(size_t byte_count, const char *site)
{
    if (g_ovc_abi_alloc_trap.open) {
        fprintf(stderr,
                "%s armed the ABI allocation trap while %s's arming was "
                "still unchecked\n",
                site,
                g_ovc_abi_alloc_trap.site);
        g_ovc_abi_alloc_trap.protocol_violated = 1;
        return;
    }
    g_ovc_abi_alloc_trap.armed_size = byte_count;
    g_ovc_abi_alloc_trap.site = site;
    g_ovc_abi_alloc_trap.open = 1;
    g_ovc_abi_alloc_trap.enabled = 1;
    g_ovc_abi_alloc_trap.fired = 0;
}

/* Called by ovc_abi_alloc in the instrumented leak-contract binary. */
int ovc_test_abi_alloc_should_fail(size_t byte_count);
int ovc_test_abi_alloc_should_fail(size_t byte_count)
{
    if (!g_ovc_abi_alloc_trap.open ||
        !g_ovc_abi_alloc_trap.enabled ||
        byte_count != g_ovc_abi_alloc_trap.armed_size) {
        return 0;
    }
    g_ovc_abi_alloc_trap.enabled = 0;
    ++g_ovc_abi_alloc_trap.fired;
    return 1;
}

/* The check is the only operation that closes an arming. A test that arms but
 * forgets to prove the trap fired leaves the protocol open, and main rejects
 * the whole run. */
int ovc_test_abi_alloc_expect_fired(const char *site);
int ovc_test_abi_alloc_expect_fired(const char *site)
{
    int fired;
    int site_matches;

    if (!g_ovc_abi_alloc_trap.open) {
        fprintf(stderr,
                "%s checked the ABI allocation trap without arming it\n",
                site);
        g_ovc_abi_alloc_trap.protocol_violated = 1;
        return 0;
    }
    site_matches =
        site == g_ovc_abi_alloc_trap.site ||
        (site != NULL && g_ovc_abi_alloc_trap.site != NULL &&
         strcmp(site, g_ovc_abi_alloc_trap.site) == 0);
    if (!site_matches) {
        fprintf(stderr,
                "%s checked the ABI allocation trap armed by %s\n",
                site != NULL ? site : "(null)",
                g_ovc_abi_alloc_trap.site != NULL
                    ? g_ovc_abi_alloc_trap.site
                    : "(null)");
        g_ovc_abi_alloc_trap.protocol_violated = 1;
    }
    g_ovc_abi_alloc_trap.enabled = 0;
    fired = g_ovc_abi_alloc_trap.fired;
    if (fired != 1) {
        fprintf(stderr,
                "%s: the ABI allocation-failure injection fired %d times, "
                "wanted exactly once\n",
                g_ovc_abi_alloc_trap.site,
                fired);
    }
    g_ovc_abi_alloc_trap.open = 0;
    g_ovc_abi_alloc_trap.site = NULL;
    return site_matches && fired == 1;
}

static int ovc_test_abi_alloc_protocol_held(void)
{
    if (g_ovc_abi_alloc_trap.open) {
        fprintf(stderr,
                "%s armed the ABI allocation trap and never checked whether "
                "it fired\n",
                g_ovc_abi_alloc_trap.site);
        return 0;
    }
    return !g_ovc_abi_alloc_trap.protocol_violated;
}
#endif

int ovstorage_c_source_runtime_contracts(void);
int ovstorage_c_source_stream_cancel_contracts(void);
int ovstorage_c_source_auth_cancel_failed_step(void);
int ovstorage_c_source_auth_nul_progress(void);
int ovstorage_c_source_pump_reap_contract(void);
int ovstorage_c_source_auth_terminal_contract(void);
int ovstorage_c_source_default_vtables_reserved_null(void);
int ovstorage_c_source_connection_ownership_contract(void);
int ovstorage_c_source_handoff_contract(void);
int ovstorage_c_source_declined_release_contract(void);

#if defined(_WIN32) && defined(_MSC_VER)
#define OVC_RUNTIME_QUIESCENCE_TIMEOUT_NS UINT64_C(5000000000)

/* Counts the per-block lines `_CrtMemDumpAllObjectsSince` emits.
 *
 * The dump prints a header, one line per outstanding block, and a trailer.
 * Only the block lines carry the "normal block at 0x..." / "client block at
 * 0x..." shape, so matching that is what distinguishes a real outstanding
 * allocation from the surrounding chrome.  Returning FALSE lets the CRT go
 * on printing to the destination configured above, so counting costs no
 * diagnostic. */
static int g_ovc_leaked_blocks;

static int ovc_count_leak_report(int report_type, char *message, int *returned)
{
    if (returned != NULL) {
        *returned = 0;
    }
    if (report_type == _CRT_WARN && message != NULL
        && (strstr(message, "normal block at") != NULL
            || strstr(message, "client block at") != NULL)) {
        g_ovc_leaked_blocks++;
    }
    return 0;
}

static int ovc_quiesce_runtime_for_crt(const char *snapshot)
{
    int status;

    status =
        ovc_runtime_wait_for_idle(OVC_RUNTIME_QUIESCENCE_TIMEOUT_NS);
    if (status == 0) {
        return 0;
    }
    fprintf(stderr,
            "pure-C runtime did not quiesce before the CRT %s "
            "(status %d)\n",
            snapshot,
            status);
    return 1;
}
#endif

int main(void)
{
#if defined(_WIN32) && defined(_MSC_VER)
    _CrtMemState baseline;
    int primed;

    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF);

    /*
     * The pure-C runtime's worker pool is created on first use and has no
     * teardown by design (src/internal.h): its workers are detached and it
     * stays reachable from a process-global until the process exits.
     * LeakSanitizer scans globals as roots and so does not report it; the
     * CRT reporter has no notion of reachability and counts every block
     * still allocated at the dump, so it would fail this gate on a block
     * nobody can free.
     *
     * Run the contract that materializes the pool once before taking the
     * baseline, then measure the full list against that baseline.
     *
     * KNOW WHAT THIS DOES NOT COVER.  Everything the primer touches is
     * exempt, and `ovc_runtime_ensure` is one-shot: it takes the init
     * mutex, sees the pool already exists and returns immediately, so the
     * second run inside the loop never re-enters the creation path.  A
     * leak in runtime initialization is therefore invisible to this gate
     * — not merely in the pool block itself, but anywhere reached only on
     * first use.  Measured on cl.exe 14.44.35207: deleting the
     * `free(configured)` from `runtime.c`'s `_dupenv_s` arm leaks on every
     * run and this gate still exits 0, while the same leak planted inside
     * a contract in the list below exits 1.  Do not read a green run here
     * as "the pure-C runtime is leak-free"; read it as "nothing the
     * measured contracts allocate outlives them".
     *
     * LeakSanitizer covers the other half on the POSIX leg: it reports by
     * reachability rather than by liveness, so a first-use block that no
     * global points at is caught there even though it is exempt here.
     */
    primed = ovstorage_c_source_runtime_contracts();
    if (primed != 0) {
        fprintf(stderr,
                "contract runtime_contracts failed with status %d\n",
                primed);
        return primed;
    }
    /*
     * The primer's own cleanup is handed to detached runtime workers. Waiting
     * here makes its exemption boundary deterministic: the baseline covers
     * everything the primer reached, not only what happened to finish before
     * this thread resumed.
     */
    if (ovc_quiesce_runtime_for_crt("baseline") != 0) {
        return 1;
    }
    printf("contract runtime_contracts primed the process-global runtime\n");
    _CrtMemCheckpoint(&baseline);
#endif
    static const struct {
        const char *name;
        int (*entry)(void);
    } contracts[] = {
        /* The runtime contract runs first: it fixes the process-global
         * worker pool the pump-reap contract's runtime submits need. */
        {"runtime_contracts", ovstorage_c_source_runtime_contracts},
        {"stream_cancel_contracts",
         ovstorage_c_source_stream_cancel_contracts},
        {"auth_cancel_failed_step",
         ovstorage_c_source_auth_cancel_failed_step},
        {"auth_nul_progress", ovstorage_c_source_auth_nul_progress},
        {"pump_reap_contract", ovstorage_c_source_pump_reap_contract},
        {"auth_terminal_contract",
         ovstorage_c_source_auth_terminal_contract},
        {"default_vtables_reserved_null",
         ovstorage_c_source_default_vtables_reserved_null},
        {"connection_ownership_contract",
         ovstorage_c_source_connection_ownership_contract},
        {"handoff_contract", ovstorage_c_source_handoff_contract},
        {"declined_release_contract",
         ovstorage_c_source_declined_release_contract},
    };
    size_t index;

    for (index = 0; index < sizeof(contracts) / sizeof(contracts[0]);
         ++index) {
        int status;

        status = contracts[index].entry();
        if (status != 0) {
            fprintf(stderr,
                    "contract %s failed with status %d\n",
                    contracts[index].name,
                    status);
            return status;
        }
        printf("contract %s passed\n", contracts[index].name);
    }
#if defined(_WIN32) && defined(_MSC_VER)
    /*
     * Contract callbacks have completed and their own helper threads have
     * joined, but cleanup they handed to the process-global runtime may still
     * be queued or executing. The workers are detached, so a heap snapshot
     * alone cannot distinguish that tail from a persistent leak. Test
     * instrumentation counts queued plus executing tasks, including work one
     * task submits before it returns. Waiting for zero establishes the
     * quiescent point the snapshot requires.
     *
     * A fixed timeout keeps a stranded task a hard, bounded failure instead
     * of turning the leak gate into a hang or a silent pass.
     */
    if (ovc_quiesce_runtime_for_crt("heap snapshot") != 0) {
        return 1;
    }

    /* The reporter writes to the debugger by default, which a CI log never
     * sees, so point it at stderr: a leak count nobody can turn into a file
     * and line is not actionable.  Resolve the target here rather than at
     * startup, because _CrtSetReportFile caches the handle GetStdHandle
     * returns and the runtime contract redirects fd 2 while it captures the
     * runtime's warning. */
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);

    /* Dump BY IDENTITY, not by net delta, and let the hook below decide.
     *
     * `_CrtMemDifference` reports a net: one block allocated before the
     * baseline and freed inside the measured region is credit that cancels
     * one leaked block of the same type, and the run passes with a real leak
     * outstanding.  The pool's workers are detached and process-lifetime, so
     * an asynchronous free landing after the checkpoint is exactly that
     * credit — the cancellation is reachable, not theoretical.
     *
     * `_CrtMemDumpAllObjectsSince` walks the blocks allocated since the
     * baseline and emits one report line per block, so a leak cannot be
     * netted away by an unrelated free.  The hook counts those lines while
     * still passing every one through to stderr, which keeps the diagnostic
     * a maintainer needs. */
    g_ovc_leaked_blocks = 0;
    _CrtSetReportHook(ovc_count_leak_report);
    _CrtMemDumpAllObjectsSince(&baseline);
    _CrtSetReportHook(NULL);

    if (g_ovc_leaked_blocks != 0) {
        fprintf(stderr,
                "CRT debug heap reported %d leaked block(s)\n",
                g_ovc_leaked_blocks);
        return 1;
    }
#endif
#if defined(OVC_ABI_ALLOC_FAILURE_TEST)
    if (!ovc_test_abi_alloc_protocol_held()) {
        return 1;
    }
#endif
    return 0;
}
