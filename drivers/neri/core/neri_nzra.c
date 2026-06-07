/* SPDX-License-Identifier: GPL-2.0 */
/*
 * drivers/neri/core/neri_nzra.c — Non-Zone Random Access cost engine
 *
 * NZRA computes C_Neri for every schedulable process:
 *
 *   C_Neri(p, r) = α·E_p(r) + β·ARG(p, r) + γ·L_c(p, r)
 *
 *   E_p(r)  = energy penalty    (RAPL watts × demand duration)
 *   ARG(p,r)= resource gap      (|demand − grant| / capacity)
 *   L_c(p,r)= coherency latency (NUMA distance × page migrations)
 *
 *   α, β, γ are tuned dynamically by Neki's EMA optimizer.
 *
 * Input:  neri_proc_t  (per-process resource demand)
 * Output: neri_nzra_decision_t
 *           .prefer_pcore    — use P-core (high-IPC) vs E-core
 *           .prefer_numa_node— NUMA node with least pressure
 *           .cpu_timeslice_ns— recommended timeslice
 *           .ram_tier        — DRAM vs CXL placement
 *           .cost            — scalar cost (lower = better)
 *
 * The ADO (neri_ado.c) takes this decision and applies it to the
 * Linux—err, Nekros—scheduler and memory placer.
 *
 * Novel: no existing kernel has a unified cross-resource cost
 * function driving placement decisions in real time.
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include "../include/neri.h"
#include "../include/neri_nzra.h"
#include "../include/neri_utb.h"
#include "../../../arch/x86/hal/hal.h"

/* ── NZRA weights (tuned by Neki) ────────────────────────── */
/* Q16 fixed-point, initialised to equal weighting           */
static q16_t g_alpha = Q16(1);   /* energy penalty weight    */
static q16_t g_beta  = Q16(1);   /* resource gap weight      */
static q16_t g_gamma = Q16(1);   /* coherency latency weight */
static spinlock_t nzra_lock = SPINLOCK_INIT;

/* ── UTB telemetry snapshot (updated by neri_utb_sample) ─── */
extern neri_utb_snapshot_t g_utb_snapshot;
extern bool g_utb_ready;

/* ── NUMA node pressure (from neri_pool) ─────────────────── */
extern neri_pool_t g_neri_pool;

/* ── Cost sub-functions ──────────────────────────────────── */

/*
 * Energy penalty E_p(r):
 * Estimates the energy cost of running process p on resource r.
 * Uses UTB's per-CPU wattage × demand duration.
 * Returns a Q16 value.
 */
static q16_t energy_penalty(const neri_proc_t *p, bool pcore)
{
    if (!g_utb_ready) return Q16(1);

    /* P-cores: higher IPC but higher wattage */
    /* E-cores: lower IPC but lower wattage   */
    u64 pkg_mw = g_utb_snapshot.pkg_power_mw;
    if (!pkg_mw) pkg_mw = 15000; /* assume 15W if unknown */

    /* Estimate energy as power × demand_duration */
    /* E = pkg_mw × cpu_demand_ns / 10^12 (in mJ) */
    u64 e_mj = (pkg_mw * (p->cpu_demand_ns / 1000000ULL)) / 1000000ULL;
    if (!e_mj) e_mj = 1;

    /* P-core costs 2× energy vs E-core (approximate) */
    if (pcore) e_mj = e_mj * 2;

    /* Normalise to Q16: divide by a reference energy (100mJ = 100) */
    return Q16(e_mj) / 100;
}

/*
 * Resource gap ARG(p, r):
 * Measures how well the available resource matches the demand.
 * ARG = |demand − available| / capacity
 * Returns Q16 in [0, UINT16_MAX].
 */
static q16_t resource_gap(const neri_proc_t *p)
{
    u64 cpu_cap  = g_neri_pool.cpu_total_ns;
    u64 ram_cap  = g_neri_pool.ram_total_pages;
    u64 cpu_free = cpu_cap > g_neri_pool.cpu_alloc_ns ?
                   cpu_cap - g_neri_pool.cpu_alloc_ns : 0;
    u64 ram_free = ram_cap > g_neri_pool.ram_alloc_pages ?
                   ram_cap - g_neri_pool.ram_alloc_pages : 0;

    if (!cpu_cap || !ram_cap) return Q16(1);

    /* Gap: how much of the demand we can't immediately satisfy */
    u64 cpu_gap = p->cpu_demand_ns > cpu_free ?
                  p->cpu_demand_ns - cpu_free : 0;
    u64 ram_gap = p->ram_demand_pages > ram_free ?
                  p->ram_demand_pages - ram_free : 0;

    /* Normalise each to [0,1] Q16 and average */
    q16_t cpu_gap_q = cpu_gap ? Q16(cpu_gap) / (cpu_cap / 64) : 0;
    q16_t ram_gap_q = ram_gap ? Q16(ram_gap) / (ram_cap / 64) : 0;

    return (cpu_gap_q + ram_gap_q) / 2;
}

/*
 * Coherency latency L_c(p, r):
 * On NUMA systems: distance between current CPU and preferred NUMA node.
 * On UMA: constant zero (no NUMA cost).
 * Returns Q16.
 */
static q16_t coherency_latency(const neri_proc_t *p, u32 target_cpu)
{
    /* Single-socket: always zero coherency cost */
    if (g_ncpus <= 4) return 0;

    /* Multi-socket: estimate NUMA distance */
    /* Simplified: assume 2 NUMA nodes, node 0 = CPUs 0..n/2-1 */
    u32 half = g_ncpus / 2;
    u32 node_a = (u32)(p->last_cpu < half ? 0 : 1);
    u32 node_b = target_cpu < half ? 0 : 1;
    if (node_a == node_b) return 0;

    /* Cross-NUMA penalty: 2× latency (80ns vs 40ns typical) */
    return Q16(2);
}

/* ── Main decision function ─────────────────────────────── */
void neri_nzra_decide(const neri_proc_t *p, neri_nzra_decision_t *dec)
{
    if (!p || !dec) return;
    memset(dec, 0, sizeof(*dec));

    spin_lock(&nzra_lock);
    q16_t alpha = g_alpha;
    q16_t beta  = g_beta;
    q16_t gamma = g_gamma;
    spin_unlock(&nzra_lock);

    /* Evaluate cost for P-core vs E-core placement */
    q16_t ep_p = energy_penalty(p, true);
    q16_t ep_e = energy_penalty(p, false);
    q16_t arg  = resource_gap(p);

    /* P-core: high IPC → CPU-bound tasks benefit */
    /* E-core: efficiency → IO/background tasks   */
    q16_t lc_p = coherency_latency(p, 0);
    q16_t lc_e = g_ncpus > 1 ? coherency_latency(p, g_ncpus-1) : 0;

    q16_t cost_pcore = Q16_TO_INT(alpha * Q16_TO_INT(ep_p))
                     + Q16_TO_INT(beta  * Q16_TO_INT(arg))
                     + Q16_TO_INT(gamma * Q16_TO_INT(lc_p));

    q16_t cost_ecore = Q16_TO_INT(alpha * Q16_TO_INT(ep_e))
                     + Q16_TO_INT(beta  * Q16_TO_INT(arg))
                     + Q16_TO_INT(gamma * Q16_TO_INT(lc_e));

    dec->prefer_pcore = (cost_pcore <= cost_ecore);
    dec->cost         = dec->prefer_pcore ? cost_pcore : cost_ecore;

    /* NUMA node: pick least-pressured (simplified: node 0) */
    dec->prefer_numa_node = 0;

    /* Timeslice: scale with demand, clamp 1ms–20ms */
    u64 ts = p->cpu_demand_ns / 4;
    if (ts < 1000000ULL)  ts = 1000000ULL;   /* min 1ms */
    if (ts > 20000000ULL) ts = 20000000ULL;  /* max 20ms */
    dec->cpu_timeslice_ns = ts;

    /* Memory tier: if demand is large and pool has CXL, use CXL */
    dec->ram_tier = (p->ram_demand_pages > 256 &&
                     g_neri_pool.ram_total_pages > 4096) ?
                    NERI_MEM_TIER_CXL : NERI_MEM_TIER_DRAM;

    /* GPU: only assign if demanded and available */
    dec->assign_gpu = (p->gpu_demand_slots > 0 &&
                       g_neri_pool.gpu_alloc_slots <
                       g_neri_pool.gpu_total_slots);
}

/* ── Weight update (called by Neki) ──────────────────────── */
void neri_nzra_update_weights(q16_t alpha, q16_t beta, q16_t gamma)
{
    spin_lock(&nzra_lock);
    g_alpha = alpha;
    g_beta  = beta;
    g_gamma = gamma;
    spin_unlock(&nzra_lock);
}

void neri_nzra_init(void)
{
    g_alpha = Q16(1);
    g_beta  = Q16(1);
    g_gamma = Q16(1);
    pr_info("neri-nzra: cost engine online α=β=γ=1.0 (Neki will tune)\n");
}
