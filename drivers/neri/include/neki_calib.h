/* drivers/neri/include/neki_calib.h */
#ifndef NEKI_CALIB_H
#define NEKI_CALIB_H
#include <nekros/types.h>
#include "neri.h"
void neki_tick(neri_pool_t *pool, u64 epoch);
void neki_calib_init(neri_pool_t *pool);
void neki_get_policy(u32 *cpu_bias, u32 *gpu_burst,
                     u32 *ram_prefetch, u8 *reclaim_aggr);
#endif
