/* SPDX-License-Identifier: GPL-2.0 */
/* drivers/neri/include/neri_utb.h */
#ifndef NERI_UTB_H
#define NERI_UTB_H
#include <nekros/types.h>

/* IPC classification from Intel HFI or CPUID */
#define NERI_IPC_CLASS_COMPUTE  0
#define NERI_IPC_CLASS_MEMORY   1
#define NERI_IPC_CLASS_MIXED    2
#define NERI_IPC_CLASS_IDLE     3

/* RAPL unit bounds */
#define UTB_MIN_RAPL_UNIT_MW 100
#define UTB_MAX_RAPL_UNIT_MW 100000

typedef struct {
    u64  pkg_power_mw;          /* current package power */
    u64  pp0_power_mw;          /* core power */
    u64  dram_power_mw;         /* DRAM power */
    u8   ipc_class[256];        /* per-CPU IPC classification */
    u64  aperf[256];            /* actual performance */
    u64  mperf[256];            /* max performance */
    u64  tsc_snapshot;
    u64  sample_epoch;
} neri_utb_snapshot_t;

extern neri_utb_snapshot_t g_utb_snapshot;
extern bool g_utb_ready;

int  neri_utb_init(void);
void neri_utb_sample(neri_pool_t *pool, u64 epoch);
#endif
