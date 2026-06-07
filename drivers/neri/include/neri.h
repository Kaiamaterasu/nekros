/* SPDX-License-Identifier: GPL-2.0 */
/* drivers/neri/include/neri.h — master Neri header */
#ifndef NERI_H
#define NERI_H
#include <nekros/types.h>

#define NERI_VERSION_MAJOR 0
#define NERI_VERSION_MINOR 5
#define NERI_VERSION_PATCH 0

/* ── Per-process resource record (embedded in task_t) ─────── */
typedef struct {
    pid_t  pid;
    u8     priority;
    u8     _pad[3];

    /* Demand (what the process wants) */
    u64    cpu_demand_ns;
    u64    ram_demand_pages;
    u64    gpu_demand_slots;

    /* Grant (what Neri gave) */
    u64    cpu_granted_ns;
    u64    ram_granted_pages;
    u64    gpu_granted_slots;

    /* Usage tracking */
    u64    cpu_used_ns;
    u64    ram_used_pages;
    u64    gpu_used_slots;

    /* Neri tracking */
    u64    epoch_admitted;
    u32    last_cpu;
    u32    numa_node;

    list_head_t node;
} neri_proc_t;

/* ── Global resource pool ─────────────────────────────────── */
typedef struct {
    /* CPU budget */
    u64  cpu_total_ns;
    u64  cpu_alloc_ns;

    /* RAM budget */
    u64  ram_total_pages;
    u64  ram_alloc_pages;

    /* GPU budget */
    u64  gpu_total_slots;
    u64  gpu_alloc_slots;

    /* Epoch */
    volatile s64 epoch;           /* atomic64 */
    u64  epoch_start_tsc;
} neri_pool_t;

/* Memory tier constants */
#define NERI_MEM_TIER_DRAM  0
#define NERI_MEM_TIER_CXL   1
#define NERI_MEM_TIER_NVM   2

/* Capability bitmask */
#define NERI_CAPS_NUMA    (1 << 0)
#define NERI_CAPS_POWER   (1 << 1)
#define NERI_CAPS_UTB     (1 << 2)
#define NERI_CAPS_NZRA    (1 << 3)
#define NERI_CAPS_ADO     (1 << 4)
#define NERI_CAPS_CXL     (1 << 5)
#define NERI_CAPS_NSM     (1 << 6)
#define NERI_CAPS_NEKI    (1 << 7)
#define NERI_CAPS_ALL     0xFF

/* ── Pool API ──────────────────────────────────────────────── */
extern neri_pool_t g_neri_pool;
extern bool        g_neri_ready;

void neri_pool_init(u64 total_ram_pages, u32 ncpus, u32 gpu_slots);
int  neri_sched_admit(neri_pool_t *pool, neri_proc_t *proc);
void neri_sched_release(neri_pool_t *pool, neri_proc_t *proc);
void neri_sched_tick(neri_pool_t *pool);
void neri_pool_status(char *buf, size_t buflen);

/* ── Module init ───────────────────────────────────────────── */
int  neri_module_init(const u8 machine_fp[32],
                      u64 ram_pages, u32 ncpus, u32 gpu_slots);
void neri_module_exit(void);

/* ── /dev/neri ioctl ───────────────────────────────────────── */
int neri_dev_ioctl(u32 cmd, u64 arg);

/* ── Thermal hint (from syscall) ─────────────────────────── */
void neri_thermal_hint(pid_t pid, u64 burst_ns, u32 intensity);

/* ── Task lookup (used by ADO and attestation) ─────────────── */
struct task;
struct task *task_find_by_pid(pid_t pid);

#endif /* NERI_H */
