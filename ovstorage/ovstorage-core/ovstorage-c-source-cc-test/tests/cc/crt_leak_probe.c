/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Self-check for the MSVC debug CRT leak reporter used by the Windows
 * leak-contract gate.
 *
 * Exit convention (the gate runs this TU TWICE):
 *   * compile with -DOVC_CRT_LEAK_PROBE=1 → deliberate leaks → exit 23
 *   * compile with -DOVC_CRT_LEAK_PROBE=0 → free every block → exit 0
 *
 * Exit 23 means "the reporter saw leaks and the probe is working". Exit 0
 * means "no leaks". Any other exit is a broken reporter or a build failure.
 * OVC_CRT_LEAK_PROBE is a compile-time switch, not an environment variable:
 * the gate must not be able to flip the arm at runtime and silently pass.
 *
 * The block count (64 x 1 KiB) is large enough that the CRT's leak dump is
 * unmistakable and small enough that the probe stays cheap. A count that is
 * too small or too large lets a dead reporter pass as green, so keep the
 * count and the exit code in lockstep with
 * tools/ovtasks/_c_source_examples.py.
 *
 * This probe measures the way leak_contracts_main.c measures — checkpoint,
 * identity dump, and outstanding block COUNTS — and leaks AFTER the baseline,
 * so it exercises the oracle the gate actually consults. Measuring through
 * any other reporter proves nothing about the gate.
 *
 * The clean arm also frees a block allocated BEFORE the baseline. That is
 * deliberate: it produces negative count credit across the measured
 * region, and the gate's verdict must not read that as a failure. Testing
 * `_CrtMemDifference`'s return instead of the counts would fail here.
 */

#if !defined(_WIN32) || !defined(_MSC_VER)
#error "crt_leak_probe.c requires the MSVC debug CRT"
#endif

#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#if !defined(OVC_CRT_LEAK_PROBE)
#error "OVC_CRT_LEAK_PROBE must select the leaky or clean probe"
#endif

/* Counts the per-block lines the dump emits, mirroring the gate's hook. */
static int g_ovc_probe_blocks;

static int ovc_probe_count_report(int report_type, char *message, int *returned)
{
    if (returned != NULL) {
        *returned = 0;
    }
    if (report_type == _CRT_WARN && message != NULL
        && (strstr(message, "normal block at") != NULL
            || strstr(message, "client block at") != NULL)) {
        g_ovc_probe_blocks++;
    }
    return 0;
}

int main(void)
{
    void *blocks[64];
    void *before_baseline;
    _CrtMemState baseline;
    size_t index;

    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF);

    /* Allocated before the checkpoint and released inside the measured
     * region below, so the difference carries negative credit. */
    before_baseline = malloc(4096);
    if (before_baseline == NULL) {
        abort();
    }
    *(volatile unsigned char *)before_baseline = 1;

    _CrtMemCheckpoint(&baseline);

    for (index = 0; index < sizeof(blocks) / sizeof(blocks[0]); ++index) {
        blocks[index] = malloc(1024);
        if (blocks[index] == NULL) {
            abort();
        }
        *(volatile unsigned char *)blocks[index] = 1;
    }
    free(before_baseline);
#if OVC_CRT_LEAK_PROBE == 0
    for (index = 0; index < sizeof(blocks) / sizeof(blocks[0]); ++index) {
        free(blocks[index]);
    }
#endif

    /* Measure the way leak_contracts_main.c measures: dump the blocks
     * allocated since the baseline and count the per-block report lines.
     *
     * This has to track the gate's oracle exactly. A probe that measures
     * through `_CrtMemDifference` while the gate consults the dump
     * validates a mechanism nothing uses, and passes while proving
     * nothing about the gate.
     *
     * It also pins the string match. `_CrtMemDumpAllObjectsSince` emits one
     * "normal block at" / "client block at" line per outstanding block, and
     * the gate counts those with `strstr`. If a CRT update ever reworded
     * them, that match would silently find nothing and the gate would exit
     * 0 with a leak outstanding — reporting success while observing
     * nothing. The leaky arm below deliberately leaks a known number of
     * blocks and requires the count to come back, so a wording change fails
     * HERE, loudly, instead of quietly disarming the gate. */
    g_ovc_probe_blocks = 0;
    _CrtSetReportHook(ovc_probe_count_report);
    _CrtMemDumpAllObjectsSince(&baseline);
    _CrtSetReportHook(NULL);

#if OVC_CRT_LEAK_PROBE == 0
    /* Clean arm: the 64 blocks are freed and one PRE-baseline block was
     * freed inside the measured region, so a verdict that reads a net delta
     * instead of counting blocks would see negative credit and misreport. */
    return g_ovc_probe_blocks == 0 ? 0 : 23;
#else
    /* Leaky arm: exactly LEAK_BLOCKS blocks must be reported. Fewer means
     * the dump or the match is not seeing what it is supposed to see. */
    return g_ovc_probe_blocks == (int)(sizeof(blocks) / sizeof(blocks[0]))
               ? 23
               : 0;
#endif
}
