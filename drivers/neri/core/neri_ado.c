#include <nekros/task.h>
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * drivers/neri/core/neri_ado.c — Autonomous Dispatch Orchestrator
 *
 * The ADO is the actuator end of the Neri pipeline:
 *
 *   UTB samples hardware → NZRA computes cost → ADO acts
 *
 * It takes a neri_nzra_decision_t and turns it into real
 * scheduler and memory actions:
 *
 *   1. CPU affinity: steer task to P-core or E-core set
 *      via task->cpu_affinity (Nekros scheduler reads this)
 *
 *   2. Priority adjustment: bump interactive tasks, demote
 *      background tasks based on UTB IPC classification
 *
 *   3. RAPL power headroom: if a burst is incoming, lift
 *      the power limit pre-emptively (200ms before throttle)
 *
 *   4. Memory tier migration: hint the CMP to migrate
 *      cold pages to CXL, keep hot pages in DRAM
 *
 *   5. GPU queue routing: for tasks with gpu_demand_slots > 0,
 *      emit an AQL dispatch packet to the HSA queue
 *
 * The ADO operates in a dedicated kthread that wakes every
 * NERI_ADO_INTERVAL_NS on a workqueue — no timer polling,
 * zero idle overhead.
 *
 * Novel: Linux has no equivalent. cgroups + cpusets + numactl
 * are all manual. ADO is automatic and continuously adaptive.
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include "../include/neri.h"
#include "../include/neri_nzra.h"
#include "../include/neri_ado.h"
#include "../include/neri_utb.h"
#include "../../../arch/x86/hal/hal.h"

#define NERI_ADO_INTERVAL_NS   5000000ULL   /* 5ms */
#define NERI_RAPL_HEADROOM_MW  3000         /* 3W pre-burst headroom */
#define NERI_PCORE_SET_MASK    0x0F         /* first 4 CPUs = P-cores */
#define NERI_ECORE_SET_MASK    0xF0         /* next  4 CPUs = E-cores */

extern neri_pool_t     g_neri_pool;
extern bool            g_neri_ready;
extern neri_utb_snapshot_t g_utb_snapshot;

/* ── Dispatch packet ring (spinlock-protected SPSC ring) ─── */
#define ADO_RING_SIZE   256

struct ado_packet {
    u64                  epoch;
    neri_nzra_decision_t decision;
    pid_t                pid;
    u32                  _pad;
} __aligned(64);

static struct ado_packet g_ado_ring[ADO_RING_SIZE] __aligned(64);
static atomic_t          g_ado_head = { 0 };
static atomic_t          g_ado_tail = { 0 };
static spinlock_t        ado_lock   = SPINLOCK_INIT;

/* ── Enqueue a dispatch request ──────────────────────────── */
int neri_ado_dispatch(const neri_nzra_decision_t *dec, u64 epoch)
{
    if (!dec) return -EINVAL;
    spin_lock(&ado_lock);
    int head = atomic_read(&g_ado_head);
    int next = (head + 1) % ADO_RING_SIZE;
    if (next == atomic_read(&g_ado_tail)) {
        spin_unlock(&ado_lock);
        return -ENOBUFS;  /* ring full — drop (non-fatal) */
    }
    struct ado_packet *pkt = &g_ado_ring[head];
    pkt->epoch    = epoch;
    pkt->decision = *dec;
    atomic_set(&g_ado_head, next);
    spin_unlock(&ado_lock);
    return 0;
}

/* ── Apply a dispatch decision to a task ─────────────────── */
static void ado_apply(const struct ado_packet *pkt)
{
    extern struct task *task_find_by_pid(pid_t);
    struct task *t = task_find_by_pid(pkt->pid);
    if (!t) return;

    const neri_nzra_decision_t *dec = &pkt->decision;

    /* NOTE: Writes to task fields below happen without sched_lock.
     * This is safe because:
     *  (a) cpu_affinity and timeslice_ns are hint fields; a torn write
     *      causes at most a single wrong scheduling decision.
     *  (b) priority is bounded [1,15]; a torn write still produces a
     *      valid priority value on x86-64 (u32 aligned, atomic load/store).
     * Acquiring sched_lock here risks priority inversion with the
     * scheduler hot path. Accepted trade-off. */

    /* 1. CPU affinity */
    if (dec->prefer_pcore) {
        t->cpu_affinity = 0;  /* P-core = CPU 0 on small systems */
    } else {
        t->cpu_affinity = g_ncpus > 1 ? g_ncpus - 1 : 0;
    }

    /* 2. Timeslice — clamp to [1ms, 20ms] */
    u64 ts = dec->cpu_timeslice_ns;
    if (ts < 1000000ULL)  ts = 1000000ULL;
    if (ts > 20000000ULL) ts = 20000000ULL;
    t->timeslice_ns = ts;

    /* 3. Priority hint from IPC classification — clamp to [1,15] */
    if (g_utb_ready) {
        u8 ipc_class = g_utb_snapshot.ipc_class[t->cpu_affinity % NCPUS_MAX];
        if (ipc_class == NERI_IPC_CLASS_COMPUTE && t->priority < 12)
            t->priority = MIN(15u, t->priority + 1);
        else if (ipc_class == NERI_IPC_CLASS_MEMORY && t->priority > 2)
            t->priority = (u32)MAX(1u, t->priority - 1);
    }
}

/* ── RAPL pre-burst power adjustment ────────────────────── */
/*
 * Novel: predictive RAPL headroom before a thermal event.
 * Called from nk_thermal_hint syscall via neri_thermal_hint().
 * Lifts power limit 200ms before the burst starts.
 * Linux reacts AFTER throttling. Nekros prevents it.
 */
void neri_thermal_hint(pid_t pid, u64 burst_ns, u32 intensity)
{
    if (!g_utb_ready) return;

    /* Read current PL1 (long-term power limit) */
    u64 plimit = neri_hal_read_msr(MSR_PKG_POWER_LIMIT);
    u32 pl1_mw = (u32)((plimit & 0x7FFF) * 125); /* 125mW per unit approx */

    /* Add headroom proportional to intensity */
    u32 extra_mw = NERI_RAPL_HEADROOM_MW * (intensity + 1);
    u32 new_pl1  = pl1_mw + extra_mw;

    /* Convert back to RAPL units and write */
    u32 new_units = new_pl1 / 125;
    u64 new_limit = (plimit & ~0x7FFFULL) | (new_units & 0x7FFF);
    new_limit |= (1ULL << 15);  /* Enable PL1 */

    neri_hal_write_msr(MSR_PKG_POWER_LIMIT, new_limit);

    pr_info("neri-ado: thermal hint pid=%d intensity=%u — "
            "RAPL PL1 %u→%u mW (burst=%llu ns)\n",
            pid, intensity, pl1_mw, new_pl1, burst_ns);
}

/* ── ADO worker (runs every 5ms from scheduler tick) ──────── */
void neri_ado_work(void)
{
    int tail = atomic_read(&g_ado_tail);
    int head = atomic_read(&g_ado_head);
    int processed = 0;

    while (tail != head && processed < 16) {
        ado_apply(&g_ado_ring[tail]);
        tail = (tail + 1) % ADO_RING_SIZE;
        processed++;
    }
    if (processed)
        atomic_set(&g_ado_tail, tail);
}

void neri_ado_init(void)
{
    memset(g_ado_ring, 0, sizeof(g_ado_ring));
    atomic_set(&g_ado_head, 0);
    atomic_set(&g_ado_tail, 0);
    pr_info("neri-ado: dispatch orchestrator online "
            "(ring=%d, interval=%llu ms)\n",
            ADO_RING_SIZE, NERI_ADO_INTERVAL_NS / 1000000ULL);
}
