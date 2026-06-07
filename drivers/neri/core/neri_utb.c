/* SPDX-License-Identifier: GPL-2.0 */
/*
 * drivers/neri/core/neri_utb.c — Universal Telemetry Bus
 *
 * Reads Intel HFI / RAPL / MSR data and fills neri_utb_snapshot_t.
 * Called every Neri epoch from neri_sched_tick().
 *
 * On CPUs without HFI the snapshot still populates power data
 * from RAPL and basic frequency data from APERF/MPERF.
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include "../include/neri.h"
#include "../include/neri_utb.h"
#include "../../../arch/x86/hal/hal.h"

neri_utb_snapshot_t g_utb_snapshot;
bool                g_utb_ready = false;

/* RAPL energy unit: read once at init */
static u64  g_rapl_unit_mw = 1000;   /* milliwatt per RAPL unit */
static u64  g_last_pkg_raw  = 0;
static u64  g_last_dram_raw = 0;
static u64  g_last_tsc      = 0;

static u64 read_rapl_energy_mj(u32 msr)
{
    return neri_hal_read_msr(msr) & 0xFFFFFFFF;
}

/* Convert raw RAPL counter delta → milliwatts */
static u64 rapl_delta_to_mw(u64 raw_delta, u64 elapsed_ns)
{
    if (!elapsed_ns) return 0;
    /* energy_mj = raw_delta * energy_unit_mj
     * power_mw  = energy_mj * 1e6 / elapsed_ns  (ns → s gives 1e9, mj→w gives 1e-3) */
    u64 energy_mj = raw_delta * g_rapl_unit_mw / 1000ULL;
    return energy_mj * 1000000ULL / elapsed_ns;
}

/* Read per-CPU APERF/MPERF ratio → IPC class */
static u8 classify_cpu_ipc(u32 cpu)
{
    if (cpu >= NCPUS_MAX) return NERI_IPC_CLASS_IDLE;
    /* MPERF = ref cycles, APERF = actual cycles
     * ratio > 0.9 → compute-heavy, < 0.5 → memory-bound */
    u64 ap = g_utb_snapshot.aperf[cpu];
    u64 mp = g_utb_snapshot.mperf[cpu];
    if (!mp) return NERI_IPC_CLASS_IDLE;
    /* ratio as percentage (ap*100/mp) */
    u64 ratio = (ap * 100ULL) / mp;
    if (ratio > 85) return NERI_IPC_CLASS_COMPUTE;
    if (ratio < 40) return NERI_IPC_CLASS_MEMORY;
    return NERI_IPC_CLASS_MIXED;
}

int neri_utb_init(void)
{
    memset(&g_utb_snapshot, 0, sizeof(g_utb_snapshot));

    /* Read RAPL power unit (bits 12:8 = energy unit in 1/2^n joules) */
    u64 pu = neri_hal_read_msr(MSR_RAPL_POWER_UNIT);
    u32 energy_unit_exp = (u32)((pu >> 8) & 0x1F);
    /* energy unit in millijoules = 1000 / 2^energy_unit_exp */
    g_rapl_unit_mw = 1000ULL / (1ULL << energy_unit_exp);
    /* Clamp RAPL unit to known-sane range; a firmware value of 0 or
     * an exponent of 0 produces 1000 mJ/unit which is physically absurd. */
    if (g_rapl_unit_mw < UTB_MIN_RAPL_UNIT_MW)
        g_rapl_unit_mw = UTB_MIN_RAPL_UNIT_MW;
    if (g_rapl_unit_mw > UTB_MAX_RAPL_UNIT_MW)
        g_rapl_unit_mw = UTB_MAX_RAPL_UNIT_MW;

    g_last_pkg_raw  = read_rapl_energy_mj(MSR_PKG_ENERGY_STATUS);
    g_last_dram_raw = read_rapl_energy_mj(MSR_DRAM_ENERGY_STATUS);
    g_last_tsc      = nekros_rdtsc();

    /* Read initial APERF/MPERF for CPU 0 */
    g_utb_snapshot.aperf[0] = neri_hal_read_msr(MSR_IA32_APERF);
    g_utb_snapshot.mperf[0] = neri_hal_read_msr(MSR_IA32_MPERF);

    g_utb_ready = true;
    pr_info("neri-utb: online — RAPL unit=%llu mJ/unit HFI=%s\n",
            g_rapl_unit_mw,
            g_cpu_info.has_hfi ? "yes" : "no");
    return 0;
}

/* ── Telemetry sanity bounds (physical hardware limits) ──────
 *
 * HFI and RAPL values come from firmware-controlled memory and MSRs.
 * A compromised or buggy firmware update, or an exploit in the
 * HFI-to-OS memory interface, can produce arbitrarily large or
 * nonsensical values that the NZRA cost engine then acts on.
 *
 * Concrete threat: a poisoned HFI table sets every CPU's perf_cap to
 * 255 and energy_eff to 0.  NZRA always places security-critical
 * CortexCrypto processes on the same "best" core.  An attacker on
 * that core runs a cache-timing loop to extract the key — the
 * firmware-directed co-location amplifies the timing signal enough
 * to recover AES-256 keys within seconds.
 *
 * Mitigation: validate every telemetry value against documented
 * hardware limits BEFORE it reaches neri_nzra_decide().  Out-of-range
 * values are clamped, not trusted, so the NZRA engine always sees a
 * plausible physical picture even if firmware is misbehaving.
 *
 * Bounds are intentionally conservative — real Ryzen 7 5800H TDP is
 * 35–54 W; we cap at 300 W to accommodate future server-class parts.
 */
#define UTB_MAX_PKG_POWER_MW   300000ULL  /* 300 W absolute max         */
#define UTB_MAX_DRAM_POWER_MW   50000ULL  /* 50 W DRAM max (ECC server) */
#define UTB_MAX_PP0_POWER_MW   280000ULL  /* CPU die ≤ pkg              */
#define UTB_MAX_APERF          0xFFFFFFFFFFFFFFFFULL  /* full 64-bit OK  */
#define UTB_MAX_MPERF          0xFFFFFFFFFFFFFFFFULL
#define UTB_MIN_RAPL_UNIT_MW   1ULL       /* at least 1 mJ/unit         */
#define UTB_MAX_RAPL_UNIT_MW   1000ULL    /* at most 1 J/unit           */
#define UTB_HFI_PERF_MAX       255        /* u8 field, always ≤ 255     */
#define UTB_HFI_EFF_MAX        255

static void utb_sanitize_snapshot(neri_utb_snapshot_t *s)
{
    /* Power readings: clamp to physical maxima.
     * A value above ceiling is a firmware error or poisoned input. */
    if (s->pkg_power_mw  > UTB_MAX_PKG_POWER_MW)  {
        pr_warn("neri-utb: pkg_power_mw=%llu out of range — clamped
",
                s->pkg_power_mw);
        s->pkg_power_mw = UTB_MAX_PKG_POWER_MW;
    }
    if (s->dram_power_mw > UTB_MAX_DRAM_POWER_MW) {
        pr_warn("neri-utb: dram_power_mw=%llu out of range — clamped
",
                s->dram_power_mw);
        s->dram_power_mw = UTB_MAX_DRAM_POWER_MW;
    }
    if (s->pp0_power_mw  > UTB_MAX_PP0_POWER_MW)  {
        pr_warn("neri-utb: pp0_power_mw=%llu out of range — clamped
",
                s->pp0_power_mw);
        s->pp0_power_mw = UTB_MAX_PP0_POWER_MW;
    }
    /* pp0 must never exceed pkg (it is a subset) */
    if (s->pp0_power_mw > s->pkg_power_mw)
        s->pp0_power_mw = s->pkg_power_mw;

    /* APERF/MPERF: APERF should never exceed MPERF
     * (actual cycles cannot exceed reference cycles over the same window).
     * A poisoned value with APERF > MPERF would give a ratio > 1,
     * misclassifying an idle core as COMPUTE → bad scheduling decisions. */
    for (u32 i = 0; i < NCPUS_MAX; i++) {
        if (s->mperf[i] == 0) {
            /* No reference cycles → cannot classify; force IDLE */
            s->ipc_class[i] = NERI_IPC_CLASS_IDLE;
            s->aperf[i] = 0;
        } else if (s->aperf[i] > s->mperf[i]) {
            pr_warn("neri-utb: CPU%u aperf(%llu) > mperf(%llu) — "
                    "clamping to mperf
", i, s->aperf[i], s->mperf[i]);
            s->aperf[i] = s->mperf[i];  /* ratio → exactly 1.0 (COMPUTE) */
        }
    }

    /* HFI ipc_class: must be one of the three defined enum values.
     * Any other byte value (firmware garbage) defaults to IDLE to
     * prevent NZRA from making scheduling decisions on unknown states. */
    for (u32 i = 0; i < NCPUS_MAX; i++) {
        u8 cls = s->ipc_class[i];
        if (cls != NERI_IPC_CLASS_IDLE    &&
            cls != NERI_IPC_CLASS_COMPUTE &&
            cls != NERI_IPC_CLASS_MEMORY  &&
            cls != NERI_IPC_CLASS_MIXED) {
            pr_warn("neri-utb: CPU%u unknown ipc_class=0x%x — "
                    "defaulting to IDLE
", i, cls);
            s->ipc_class[i] = NERI_IPC_CLASS_IDLE;
        }
    }
}

void neri_utb_sample(neri_pool_t *pool, u64 epoch)
{
    if (!g_utb_ready) return;

    u64 now_tsc   = nekros_rdtsc();
    u64 elapsed_ns= nekros_tsc_to_ns(now_tsc - g_last_tsc);
    g_last_tsc    = now_tsc;

    /* --- RAPL power sampling --- */
    u64 pkg_raw  = read_rapl_energy_mj(MSR_PKG_ENERGY_STATUS);
    u64 dram_raw = read_rapl_energy_mj(MSR_DRAM_ENERGY_STATUS);

    /* Handle 32-bit counter wraparound */
    u64 pkg_delta  = (pkg_raw  >= g_last_pkg_raw)  ?
                      pkg_raw  - g_last_pkg_raw  :
                      0x100000000ULL - g_last_pkg_raw + pkg_raw;
    u64 dram_delta = (dram_raw >= g_last_dram_raw) ?
                      dram_raw - g_last_dram_raw :
                      0x100000000ULL - g_last_dram_raw + dram_raw;

    g_last_pkg_raw  = pkg_raw;
    g_last_dram_raw = dram_raw;

    g_utb_snapshot.pkg_power_mw  = rapl_delta_to_mw(pkg_delta,  elapsed_ns);
    g_utb_snapshot.dram_power_mw = rapl_delta_to_mw(dram_delta, elapsed_ns);
    /* PP0 approximation: pkg - dram */
    g_utb_snapshot.pp0_power_mw  =
        g_utb_snapshot.pkg_power_mw > g_utb_snapshot.dram_power_mw ?
        g_utb_snapshot.pkg_power_mw - g_utb_snapshot.dram_power_mw : 0;

    /* --- APERF/MPERF for IPC classification (CPU 0 only for now) --- */
    u64 new_aperf = neri_hal_read_msr(MSR_IA32_APERF);
    u64 new_mperf = neri_hal_read_msr(MSR_IA32_MPERF);
    g_utb_snapshot.aperf[0] = new_aperf;
    g_utb_snapshot.mperf[0] = new_mperf;
    g_utb_snapshot.ipc_class[0] = classify_cpu_ipc(0);

    /* --- Intel HFI table (if available) --- */
    if (g_cpu_info.has_hfi) {
        u64 hfi_ptr = neri_hal_read_msr(MSR_HFI_TABLE_PTR);
        if (hfi_ptr) {
            /* HFI table: 2 bytes per CPU: [perf_cap, energy_eff] */
            u8 *hfi = (u8 *)(uintptr_t)(hfi_ptr & ~0xFULL);
            u32 ncpus = MIN(g_ncpus, (u32)NCPUS_MAX);
            for (u32 i = 0; i < ncpus; i++) {
                u8 perf = hfi[i * 2];
                /* High perf + low energy → compute; low perf → memory/idle */
                if (perf >= 200)      g_utb_snapshot.ipc_class[i] = NERI_IPC_CLASS_COMPUTE;
                else if (perf >= 100) g_utb_snapshot.ipc_class[i] = NERI_IPC_CLASS_MIXED;
                else                  g_utb_snapshot.ipc_class[i] = NERI_IPC_CLASS_MEMORY;
            }
        }
    }

    g_utb_snapshot.tsc_snapshot  = now_tsc;
    g_utb_snapshot.sample_epoch  = epoch;

    /* Sanitize all telemetry fields before the NZRA cost engine reads them.
     * Must be the LAST step so every field above is already populated. */
    utb_sanitize_snapshot(&g_utb_snapshot);
}
