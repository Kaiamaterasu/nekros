/* SPDX-License-Identifier: GPL-2.0 */
/* drivers/neri/core/neri_pool.c — Unified resource pool */
#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include "../include/neri.h"
#include "../include/neri_sec.h"
#include "../include/neri_version.h"
#include "../../../mm/pmm.h"

/* Saturating subtraction — never underflows to UINT64_MAX */
static __always_inline u64 sat_sub(u64 a, u64 b) {
    return (a >= b) ? a - b : 0;
}

extern u64 nekros_rdtsc(void);
extern u64 nekros_tsc_to_ns(u64);

#define NERI_EPOCH_NS 10000000ULL

neri_pool_t g_neri_pool;
bool        g_neri_ready = false;
static spinlock_t pool_lock = SPINLOCK_INIT;
LIST_HEAD(neri_admitted);
static u32 neri_admitted_count = 0;

void neri_pool_init(u64 total_ram_pages, u32 ncpus, u32 gpu_slots)
{
    memset(&g_neri_pool, 0, sizeof(g_neri_pool));
    g_neri_pool.cpu_total_ns    = (u64)ncpus * NERI_EPOCH_NS;
    g_neri_pool.ram_total_pages = total_ram_pages;
    g_neri_pool.gpu_total_slots = gpu_slots;
    atomic64_set((atomic64_t*)&g_neri_pool.epoch, 1);
    g_neri_pool.epoch_start_tsc = nekros_rdtsc();
    list_init(&neri_admitted);
    g_neri_ready = true;
    pr_info("neri: pool init — CPU %llu ns/epoch RAM %llu pages GPU %llu slots\n",
            g_neri_pool.cpu_total_ns, g_neri_pool.ram_total_pages, ( u64)g_neri_pool.gpu_total_slots);
    pr_info("neri: v%d.%d.%d ready\n", NERI_VERSION_MAJOR, NERI_VERSION_MINOR, NERI_VERSION_PATCH);
}

int neri_sched_admit(neri_pool_t *pool, neri_proc_t *proc)
{
    if (!pool || !proc) return -EINVAL;
    spin_lock(&pool_lock);
    neri_sec_anomaly_t anm = {0};
    neri_sec_get_anomaly(&anm);
    if (anm.block_admits) { spin_unlock(&pool_lock); return -EPERM; }
    u64 cpu_head = pool->cpu_total_ns * 2;
    u64 ram_head = pool->ram_total_pages * 3 / 2;
    if (pool->cpu_alloc_ns + proc->cpu_demand_ns > cpu_head ||
        pool->ram_alloc_pages + proc->ram_demand_pages > ram_head) {
        spin_unlock(&pool_lock); return -EBUSY;
    }
    proc->cpu_granted_ns    = proc->cpu_demand_ns;
    proc->ram_granted_pages = proc->ram_demand_pages;
    proc->gpu_granted_slots = proc->gpu_demand_slots;
    proc->epoch_admitted    = (u64)atomic64_read((atomic64_t*)&pool->epoch);
    pool->cpu_alloc_ns    += proc->cpu_granted_ns;
    pool->ram_alloc_pages += proc->ram_granted_pages;
    pool->gpu_alloc_slots += proc->gpu_granted_slots;
    list_add_tail(&proc->node, &neri_admitted);
    neri_admitted_count++;
    spin_unlock(&pool_lock);
    return 0;
}

void neri_sched_release(neri_pool_t *pool, neri_proc_t *proc)
{
    if (!pool || !proc) return;
    spin_lock(&pool_lock);
    pool->cpu_alloc_ns    = sat_sub(pool->cpu_alloc_ns,    proc->cpu_granted_ns);
    pool->ram_alloc_pages = sat_sub(pool->ram_alloc_pages, proc->ram_granted_pages);
    pool->gpu_alloc_slots = sat_sub(pool->gpu_alloc_slots, proc->gpu_granted_slots);
    if (proc->node.next) list_del(&proc->node);
    if (neri_admitted_count > 0) neri_admitted_count--;
    spin_unlock(&pool_lock);
}

void neri_sched_tick(neri_pool_t *pool)
{
    if (!pool) return;
    u64 now   = nekros_rdtsc();
    u64 delta = nekros_tsc_to_ns(now - pool->epoch_start_tsc);
    if (delta < NERI_EPOCH_NS) return;
    pool->epoch_start_tsc = now;
    u64 ep = (u64)atomic64_inc_return((atomic64_t*)&pool->epoch);
    u64 total_p, free_p;
    pmm_stats(&total_p, &free_p);
    pool->ram_total_pages = total_p;
    pool->ram_alloc_pages = total_p > free_p ? total_p - free_p : 0;
    extern void neri_utb_sample(neri_pool_t*, u64);
    neri_utb_sample(pool, ep);
    extern void neki_tick(neri_pool_t*, u64);
    if ((ep & 63) == 0) neki_tick(pool, ep);
    extern void neri_sec_rescore(neri_pool_t*);
    if ((ep & 31) == 0) neri_sec_rescore(pool);
}

void neri_pool_status(char *buf, size_t buflen) {
    (void)buf; (void)buflen;
}
