/* SPDX-License-Identifier: GPL-2.0 */
/*
 * crypto/coc.c — Nekros Chain of Custody
 *
 * NOVEL — no existing kernel has this.
 *
 * Every significant kernel event from bootloader handoff through
 * first userspace task is recorded as a linked chain of SHA-256
 * hashes. Each link is:
 *
 *   link[n].hash = SHA-256(link[n-1].hash || timestamp || data)
 *
 * This chain is:
 *   - Tamper-evident: any modification breaks all subsequent hashes
 *   - Readable from userspace via /proc/nekros/coc
 *   - Sealed by CortexCrypto NSM once the pool is live
 *   - Used by nerictl to prove the running kernel hasn't been
 *     modified since first boot observation
 *
 * Sources (source_id values):
 *   COC_SRC_BOOT     0  Bootloader handoff
 *   COC_SRC_HAL      1  HAL init complete
 *   COC_SRC_PMM      2  Physical memory mapped
 *   COC_SRC_VMM      3  Virtual memory active
 *   COC_SRC_SCHED    4  Scheduler first tick
 *   COC_SRC_NERI     5  Neri pool live
 *   COC_SRC_CORTEX   6  CortexCrypto NSM armed
 *   COC_SRC_SYSCALL  7  First syscall from userspace
 *   COC_SRC_TASK     8  Process creation/exit
 *   COC_SRC_POLICY   9  Neri policy hot-swap
 *   COC_SRC_ANOMALY  10 NSM anomaly level change
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include "crypto.h"

#define COC_SRC_BOOT     0
#define COC_SRC_HAL      1
#define COC_SRC_PMM      2
#define COC_SRC_VMM      3
#define COC_SRC_SCHED    4
#define COC_SRC_NERI     5
#define COC_SRC_CORTEX   6
#define COC_SRC_SYSCALL  7
#define COC_SRC_TASK     8
#define COC_SRC_POLICY   9
#define COC_SRC_ANOMALY  10

static const char *coc_src_names[] = {
    "BOOT","HAL","PMM","VMM","SCHED",
    "NERI","CORTEX","SYSCALL","TASK","POLICY","ANOMALY"
};

#define COC_MAX_ENTRIES  256

static coc_link_t coc_chain[COC_MAX_ENTRIES];
static u32        coc_count = 0;
static spinlock_t coc_lock  = SPINLOCK_INIT;

/* Monotonic timestamp (ticks since boot, ~ns) */
extern u64 nekros_rdtsc(void);
static u64 coc_boot_tsc = 0;

void coc_init(void)
{
    memset(coc_chain, 0, sizeof(coc_chain));
    coc_count   = 0;
    coc_boot_tsc = nekros_rdtsc();

    /* Genesis link: hash of all-zeros */
    coc_link_t *genesis = &coc_chain[0];
    genesis->seq          = 0;
    genesis->timestamp_ns = 0;
    genesis->source_id    = COC_SRC_BOOT;
    memset(genesis->hash, 0, 32);

    /* Hash the genesis itself */
    u8 buf[64] = {0};
    sha256(buf, 64, genesis->hash);
    coc_count = 1;

    pr_info("coc: chain of custody initialised — genesis %02x%02x%02x%02x...\n",
            genesis->hash[0], genesis->hash[1],
            genesis->hash[2], genesis->hash[3]);
}

void coc_record(u32 source_id, const u8 *data, size_t dlen, coc_link_t *out)
{
    spin_lock(&coc_lock);

    if (coc_count >= COC_MAX_ENTRIES) {
        /* Ring: wrap around but keep genesis */
        memmove(&coc_chain[1], &coc_chain[2],
                (COC_MAX_ENTRIES - 2) * sizeof(coc_link_t));
        coc_count = COC_MAX_ENTRIES - 1;
    }

    const coc_link_t *prev = &coc_chain[coc_count - 1];
    coc_link_t       *cur  = &coc_chain[coc_count];

    cur->seq          = prev->seq + 1;
    cur->timestamp_ns = nekros_rdtsc() - coc_boot_tsc;
    cur->source_id    = source_id;

    /* hash = SHA-256(prev->hash || cur->seq || cur->timestamp_ns
     *                || source_id || data) */
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, prev->hash, 32);
    sha256_update(&ctx, (u8 *)&cur->seq, 8);
    sha256_update(&ctx, (u8 *)&cur->timestamp_ns, 8);
    sha256_update(&ctx, (u8 *)&source_id, 4);
    if (data && dlen) sha256_update(&ctx, data, dlen);
    sha256_final(&ctx, cur->hash);

    coc_count++;

    const char *src_name = (source_id < ARRAY_SIZE(coc_src_names))
                           ? coc_src_names[source_id] : "UNKNOWN";
    pr_info("coc[%llu] %-8s %02x%02x%02x%02x...\n",
            cur->seq, src_name,
            cur->hash[0], cur->hash[1], cur->hash[2], cur->hash[3]);

    if (out) memcpy(out, cur, sizeof(*out));

    spin_unlock(&coc_lock);
}

void coc_verify_chain(void)
{
    spin_lock(&coc_lock);
    bool ok = true;
    for (u32 i = 1; i < coc_count; i++) {
        const coc_link_t *prev = &coc_chain[i-1];
        const coc_link_t *cur  = &coc_chain[i];

        sha256_ctx_t ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, prev->hash, 32);
        sha256_update(&ctx, (u8 *)&cur->seq, 8);
        sha256_update(&ctx, (u8 *)&cur->timestamp_ns, 8);
        sha256_update(&ctx, (u8 *)&cur->source_id, 4);
        u8 expected[32];
        sha256_final(&ctx, expected);

        if (memcmp(expected, cur->hash, 32) != 0) {
            pr_err("coc: CHAIN BROKEN at link %u (source=%u)\n",
                   i, cur->source_id);
            ok = false;
        }
    }
    spin_unlock(&coc_lock);
    if (ok) pr_info("coc: chain verified OK (%u links)\n", coc_count);
}

const coc_link_t *coc_head(void) {
    return coc_count ? &coc_chain[coc_count - 1] : NULL;
}

u32 coc_get_all(coc_link_t *buf, u32 max) {
    spin_lock(&coc_lock);
    u32 n = MIN(coc_count, max);
    memcpy(buf, coc_chain, n * sizeof(coc_link_t));
    spin_unlock(&coc_lock);
    return n;
}
