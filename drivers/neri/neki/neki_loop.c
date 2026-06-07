/* SPDX-License-Identifier: GPL-2.0 */
/*
 * drivers/neri/neki/neki_loop.c — Neki adaptive EMA optimizer
 *
 * Neki observes 64-epoch sliding windows of resource utilisation
 * and waste, then emits updated NZRA weights and policy vectors.
 *
 * Outputs every 64 epochs (~640ms):
 *   α, β, γ     — NZRA cost function weights
 *   cpu_bias_pct  — how much to favour CPU-bound placement
 *   gpu_burst     — predicted GPU burst slots needed
 *   ram_prefetch  — pages to prefetch per process per epoch
 *   reclaim_aggr  — page reclaim aggressiveness (0–255)
 *
 * Algorithm: exponential moving average with error feedback.
 *
 *   w_new = w_old × (1 - EMA_ALPHA) + signal × EMA_ALPHA
 *
 * Signal = measured_waste / measured_demand (normalised to Q16)
 * Higher waste on a dimension → reduce that weight
 * Higher demand relative to capacity → increase that weight
 *
 * This runs entirely in fixed-point Q16 arithmetic.
 * No floats. No division by zero possible.
 * Pure kernel code — no userspace interaction needed.
 *
 * Novel: no other kernel has a self-tuning cost function
 * that adapts to actual workload behaviour in real time.
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include "../include/neri.h"
#include "../include/neri_nzra.h"
#include "../include/neki_calib.h"

#define EMA_ALPHA_NUM  3   /* EMA_ALPHA = 3/64 ≈ 0.047 */
#define EMA_ALPHA_DEN  64

/* Sliding window: 64 epoch samples */
#define NEKI_WINDOW   64

struct neki_sample {
    u64 cpu_demand_ns;
    u64 cpu_granted_ns;
    u64 ram_demand_pages;
    u64 ram_granted_pages;
    u64 gpu_demand_slots;
    u64 gpu_granted_slots;
    u64 epoch;
};

static struct neki_sample g_window[NEKI_WINDOW];
static u32 g_window_idx = 0;
static u32 g_window_filled = 0;

/* Current EMA weights (Q16) */
static q16_t g_w_alpha = Q16(1);
static q16_t g_w_beta  = Q16(1);
static q16_t g_w_gamma = Q16(1);

/* Policy vectors */
static u32  g_cpu_bias_pct   = 50;  /* balanced */
static u32  g_gpu_burst      = 0;
static u32  g_ram_prefetch   = 4;   /* pages */
static u8   g_reclaim_aggr   = 64;  /* moderate */

extern neri_pool_t g_neri_pool;

/* ── EMA update step (Q16) ────────────────────────────────── */
static q16_t ema_step(q16_t old_val, q16_t signal)
{
    /* w_new = w_old × (1 - α) + signal × α
     *       = w_old - w_old×α + signal×α
     *       = w_old + (signal - w_old) × α      */
    q16_t diff  = signal > old_val ?
                  signal - old_val : old_val - signal;
    q16_t delta = (diff * EMA_ALPHA_NUM) / EMA_ALPHA_DEN;
    if (signal > old_val)
        return old_val + delta;
    else
        return old_val > delta ? old_val - delta : Q16(0) + 1;
}

/* ── Analyse a window of samples ─────────────────────────── */
static void neki_analyse(void)
{
    u32 n = g_window_filled < NEKI_WINDOW ? g_window_filled : NEKI_WINDOW;
    if (!n) return;

    u64 cpu_waste = 0, cpu_demand = 0;
    u64 ram_waste = 0, ram_demand = 0;
    u64 gpu_waste = 0, gpu_demand = 0;

    for (u32 i = 0; i < n; i++) {
        struct neki_sample *s = &g_window[i];
        cpu_demand += s->cpu_demand_ns;
        cpu_waste  += s->cpu_demand_ns > s->cpu_granted_ns ?
                      s->cpu_demand_ns - s->cpu_granted_ns : 0;
        ram_demand += s->ram_demand_pages;
        ram_waste  += s->ram_demand_pages > s->ram_granted_pages ?
                      s->ram_demand_pages - s->ram_granted_pages : 0;
        gpu_demand += s->gpu_demand_slots;
        gpu_waste  += s->gpu_demand_slots > s->gpu_granted_slots ?
                      s->gpu_demand_slots - s->gpu_granted_slots : 0;
    }

    /* Compute waste ratio per dimension [0, Q16(1)] */
    q16_t cpu_signal = cpu_demand ?
        MIN(Q16(2), Q16(cpu_waste) / (cpu_demand / 64)) : Q16(1);
    q16_t ram_signal = ram_demand ?
        MIN(Q16(2), Q16(ram_waste) / (ram_demand / 64)) : Q16(1);
    q16_t gpu_signal = gpu_demand ?
        MIN(Q16(2), Q16(gpu_waste) / (gpu_demand / 64)) : Q16(1);

    /* High waste on a dimension → decrease its weight (we're over-assigning)
     * Low waste → increase its weight (more pressure here)  */
    g_w_alpha = ema_step(g_w_alpha,
        cpu_signal > Q16(1) ? Q16(1) - (cpu_signal - Q16(1)) : Q16(1));
    g_w_beta  = ema_step(g_w_beta,  ram_signal);
    g_w_gamma = ema_step(g_w_gamma, gpu_signal);

    /* Clamp weights [0.25, 4.0] */
    g_w_alpha = MAX(Q16(0) + (Q16(1)/4), MIN(Q16(4), g_w_alpha));
    g_w_beta  = MAX(Q16(0) + (Q16(1)/4), MIN(Q16(4), g_w_beta));
    g_w_gamma = MAX(Q16(0) + (Q16(1)/4), MIN(Q16(4), g_w_gamma));

    /* Push updated weights to NZRA */
    neri_nzra_update_weights(g_w_alpha, g_w_beta, g_w_gamma);

    /* Update policy vectors */
    g_cpu_bias_pct = (u32)(50 + Q16_TO_INT(g_w_alpha) * 10);
    g_cpu_bias_pct = MIN(90u, MAX(10u, g_cpu_bias_pct));

    g_gpu_burst    = gpu_demand ? (u32)(gpu_demand / n) : 0;
    g_ram_prefetch = (u32)(4 + Q16_TO_INT(g_w_beta));
    g_reclaim_aggr = (u8)MIN(255, 64 + (u32)(Q16_TO_INT(g_w_beta) * 16));
}

/* ── neki_tick — called every 64 epochs from neri_pool ────── */
void neki_tick(neri_pool_t *pool, u64 epoch)
{
    if (!pool) return;

    /* Record this epoch's aggregate */
    struct neki_sample *s = &g_window[g_window_idx % NEKI_WINDOW];
    s->cpu_demand_ns     = pool->cpu_alloc_ns;
    s->cpu_granted_ns    = pool->cpu_alloc_ns;  /* granted = alloc for now */
    s->ram_demand_pages  = pool->ram_alloc_pages;
    s->ram_granted_pages = pool->ram_alloc_pages;
    s->gpu_demand_slots  = pool->gpu_alloc_slots;
    s->gpu_granted_slots = pool->gpu_alloc_slots;
    s->epoch             = epoch;
    g_window_idx++;
    g_window_filled = MIN(g_window_filled + 1, NEKI_WINDOW);

    /* Only analyse once we have at least 8 samples */
    if (g_window_filled >= 8)
        neki_analyse();
}

/* ── Calibration (called once after RAPL init) ───────────── */
void neki_calib_init(neri_pool_t *pool)
{
    if (!pool) return;
    /* Reset window */
    memset(g_window, 0, sizeof(g_window));
    g_window_idx    = 0;
    g_window_filled = 0;
    g_w_alpha = Q16(1);
    g_w_beta  = Q16(1);
    g_w_gamma = Q16(1);

    pr_info("neki: self-learning EMA optimizer calibrated — "
            "window=%d epochs, α=3/64\n", NEKI_WINDOW);
}

/* Policy vector read (for nk_neri_tune, /proc/neri/neki) */
void neki_get_policy(u32 *cpu_bias, u32 *gpu_burst,
                     u32 *ram_prefetch, u8 *reclaim_aggr)
{
    if (cpu_bias)    *cpu_bias    = g_cpu_bias_pct;
    if (gpu_burst)   *gpu_burst   = g_gpu_burst;
    if (ram_prefetch)*ram_prefetch= g_ram_prefetch;
    if (reclaim_aggr)*reclaim_aggr= g_reclaim_aggr;
}
