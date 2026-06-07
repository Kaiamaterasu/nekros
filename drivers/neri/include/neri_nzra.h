/* SPDX-License-Identifier: GPL-2.0 */
/* drivers/neri/include/neri_nzra.h */
#ifndef NERI_NZRA_H
#define NERI_NZRA_H
#include <nekros/types.h>
#include "neri.h"

typedef struct {
    bool  prefer_pcore;
    u32   prefer_numa_node;
    u64   cpu_timeslice_ns;
    u32   ram_tier;         /* NERI_MEM_TIER_* */
    bool  assign_gpu;
    q16_t cost;
} neri_nzra_decision_t;

void neri_nzra_init(void);
void neri_nzra_decide(const neri_proc_t *p, neri_nzra_decision_t *dec);
void neri_nzra_update_weights(q16_t alpha, q16_t beta, q16_t gamma);
#endif
