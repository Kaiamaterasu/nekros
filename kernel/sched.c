/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kernel/sched.c — Nekros process scheduler
 *
 * CFS-inspired weighted fair scheduling, with Neri integration
 * at every admit/release/tick boundary.
 *
 * Every runnable process has a neri_proc_t that lives inside
 * its task_t. The scheduler calls:
 *   neri_sched_admit()   — on fork/exec
 *   neri_sched_release() — on exit
 *   neri_sched_tick()    — on timer tick (called from IRQ 0)
 *   neri_ado_dispatch()  — after NZRA decides placement
 *
 * The ADO sets task->cpu_affinity and task->priority adjustments.
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include <nekros/sched.h>
#include "../mm/vmm.h"
#include "../mm/pmm.h"
/* Neri integration headers */
#include "../drivers/neri/include/neri.h"
#include "../drivers/neri/include/neri_nzra.h"
#include "../drivers/neri/include/neri_ado.h"
#include "../drivers/neri/include/neri_sec.h"

/* ── Task states ──────────────────────────────────────────── */
#define TASK_RUNNING    0
#define TASK_READY      1
#define TASK_BLOCKED    2
#define TASK_ZOMBIE     3
#define TASK_STOPPED    4

/* ── Task structure ───────────────────────────────────────── */
#define KERNEL_STACK_PAGES  4
#define TASK_NAME_LEN       32
/* NEKROS_STACK_CANARY is defined authoritatively in mm/vmm.h.
 * Do NOT redefine it here — a mismatch causes every context switch
 * to trigger a false stack-overflow panic. */

struct task {
    /* Identity */
    pid_t            pid;
    pid_t            ppid;
    uid_t            uid;
    gid_t            gid;
    char             name[TASK_NAME_LEN];

    /* Scheduler state */
    u32              state;          /* TASK_* */
    u32              priority;       /* 1–15 (higher = more CPU) */
    u64              vruntime;       /* virtual runtime (ns, CFS) */
    u64              weight;         /* nice→weight (sched_weight[priority]) */
    u64              timeslice_ns;   /* remaining timeslice */
    u64              cpu_time_ns;    /* total CPU time consumed */
    u32              cpu_affinity;   /* CPU to run on (set by ADO) */
    u32              on_cpu;         /* currently running CPU */

    /* Memory */
    u64             *pml4;           /* page table (NULL = use kernel PML4) */
    virt_addr_t      kstack_top;     /* top of kernel stack */
    phys_addr_t      kstack_pa;      /* physical address of stack pages */

    /* Saved context (callee-saved regs + rip + rsp) */
    u64              ctx_rsp;
    u64              ctx_rbp;
    u64              ctx_rbx;
    u64              ctx_r12;
    u64              ctx_r13;
    u64              ctx_r14;
    u64              ctx_r15;
    u64              ctx_rip;
    u64              ctx_rflags;

    /* Neri resource tracking */
    neri_proc_t      neri;           /* embedded directly — no alloc */

    /* Syscall return value slot */
    u64              syscall_ret;

    /* Signal mask */
    u64              sig_pending;
    u64              sig_blocked;

    /* File descriptor table pointer */
    struct fd_table *fdt;

    /* List: run queue or wait queue */
    list_head_t      rq_node;
    list_head_t      all_tasks;
};

/* ── Global scheduler state ───────────────────────────────── */

#define MAX_TASKS  1024

static struct task *tasks[MAX_TASKS];
static atomic_t     task_count = { 0 };
static pid_t        next_pid   = 1;
static spinlock_t   sched_lock = SPINLOCK_INIT;

/* Run queues (one per priority band 0–15) */
static list_head_t  runqueues[16];
static u64          rq_min_vruntime[16];

/* All-tasks list for /proc and Neri */
LIST_HEAD(all_tasks_list);

/* Currently running task per CPU */
static struct task *current_task[NCPUS_MAX];

/* ── Neri global pool (initialised by neri_module_init) ───── */
extern neri_pool_t g_neri_pool;
extern bool        g_neri_ready;

/* ── Priority weights (mimicking Linux nice-to-weight) ─────── */
static const u64 sched_weight[16] = {
     88761, 71755, 56483, 46273, 36291,
     29154, 23254, 18705, 14949, 11916,
      9548,  7620,  6100,  4904,  3906, 3121
};

static u64 calc_vruntime_delta(struct task *t, u64 real_ns)
{
    /* vruntime_delta = real_ns * (NICE_0_WEIGHT / weight) */
    return real_ns * 56483 / (t->weight ? t->weight : 56483);
}

/* ── Context switch (ASM stub in sched_asm.S) ─────────────── */
extern void __switch_to(struct task *prev, struct task *next);

struct task *sched_current(void)
{
    extern u32 smp_processor_id(void);
    return current_task[smp_processor_id()];
}

/* ── Enqueue / dequeue ────────────────────────────────────── */
static void enqueue(struct task *t)
{
    int band = MIN(t->priority, 15);
    /* Start new tasks at the current min vruntime */
    if (t->vruntime == 0)
        t->vruntime = rq_min_vruntime[band];
    list_add_tail(&t->rq_node, &runqueues[band]);
}

static void dequeue(struct task *t)
{
    list_del(&t->rq_node);
}

static struct task *pick_next(void)
{
    /* Walk priority bands highest→lowest; within a band pick min vruntime */
    for (int band = 15; band >= 0; band--) {
        if (list_empty(&runqueues[band])) continue;
        struct task *best = NULL;
        list_head_t *pos;
        list_for_each(pos, &runqueues[band]) {
            struct task *t = list_entry(pos, struct task, rq_node);
            if (t->state != TASK_READY) continue;
            if (!best || t->vruntime < best->vruntime) best = t;
        }
        if (best) return best;
    }
    return NULL;
}

/* ── Task creation ────────────────────────────────────────── */
struct task *task_create(const char *name, void (*entry)(void *),
                         void *arg, u32 priority, u64 cpu_demand_ns,
                         u64 ram_demand_pages)
{
    /* Check Neri admission gate */
    if (g_neri_ready && !neri_sec_admit_allowed()) {
        pr_warn("sched: admission blocked by Neri NSM (threat level CRITICAL)\n");
        return ERR_PTR(-EPERM);
    }

    struct task *t = (struct task *)kzalloc(sizeof(*t));
    if (!t) return ERR_PTR(-ENOMEM);

    spin_lock(&sched_lock);
    t->pid   = next_pid++;
    spin_unlock(&sched_lock);

    t->ppid     = sched_current() ? sched_current()->pid : 0;
    t->uid      = t->gid = 0;
    t->priority = MIN(priority, 15);
    t->weight   = sched_weight[t->priority];
    t->state    = TASK_READY;
    strlcpy(t->name, name ? name : "kthread", TASK_NAME_LEN);

    /* Kernel stack */
    t->kstack_pa  = pmm_alloc_pages(2);  /* 4×4KB = 16KB stack */
    if (!t->kstack_pa) {
        /* Safe: task not yet on any list, no UAF possible */
        kfree(t);
        return ERR_PTR(-ENOMEM);
    }
    t->kstack_top = phys_to_virt(t->kstack_pa) + KERNEL_STACK_PAGES * PAGE_SIZE;
    /* Write stack canary at the very bottom of the new stack.
     * kstack_canary_write() is the canonical helper (vmm.c);
     * do not duplicate the write logic here. */
    kstack_canary_write((virt_addr_t)phys_to_virt(t->kstack_pa));

    /* Set up initial stack frame for __switch_to */
    u64 *sp = (u64 *)t->kstack_top;
    *--sp = (u64)arg;      /* function argument */
    *--sp = 0;             /* fake return address (entry should never return) */
    t->ctx_rsp = (u64)sp;
    t->ctx_rip = (u64)entry;
    t->ctx_rflags = 0x200; /* IF = 1 */

    /* Register with Neri */
    t->neri.pid              = t->pid;
    t->neri.priority         = (u8)t->priority;
    t->neri.cpu_demand_ns    = cpu_demand_ns  ? cpu_demand_ns  : 1000000ULL;
    t->neri.ram_demand_pages = ram_demand_pages ? ram_demand_pages : 4;
    t->neri.gpu_demand_slots = 0;
    list_init(&t->neri.node);
    list_init(&t->rq_node);
    list_init(&t->all_tasks);

    if (g_neri_ready)
        neri_sched_admit(&g_neri_pool, &t->neri);

    /* Register in task table */
    spin_lock(&sched_lock);
    for (int i = 0; i < MAX_TASKS; i++) {
        if (!tasks[i]) { tasks[i] = t; break; }
    }
    list_add_tail(&t->all_tasks, &all_tasks_list);
    enqueue(t);
    atomic_inc_return(&task_count);
    spin_unlock(&sched_lock);

    /* Ask Neri NZRA where to place this task */
    if (g_neri_ready) {
        neri_nzra_decision_t dec;
        neri_nzra_decide(&t->neri, &dec);
        t->cpu_affinity = dec.prefer_pcore ? 0 : (g_ncpus > 1 ? 1 : 0);

        neri_ado_dispatch(&dec, atomic64_read((atomic64_t*)&g_neri_pool.epoch));
    }

    pr_info("sched: task '%s' pid=%d priority=%u cpu_affinity=%u\n",
            t->name, t->pid, t->priority, t->cpu_affinity);
    return t;
}

/* ── Schedule (called on timer tick or explicit yield) ──────── */
void schedule(void)
{
    extern u32 smp_processor_id(void);
    u32 cpu = smp_processor_id();

    if (cpu >= NCPUS_MAX) cpu = 0; /* safety clamp */
    spin_lock(&sched_lock);
    struct task *prev = current_task[cpu];
    if (prev && prev->state == TASK_RUNNING) {
        prev->state = TASK_READY;
        enqueue(prev);
    }

    struct task *next = pick_next();
    if (!next) {
        /* idle — re-run prev or spin */
        if (prev) { prev->state = TASK_RUNNING; current_task[cpu] = prev; }
        spin_unlock(&sched_lock);
        return;
    }

    dequeue(next);
    next->state     = TASK_RUNNING;
    next->on_cpu    = cpu;
    next->timeslice_ns = 4000000ULL; /* 4ms default timeslice */
    current_task[cpu] = next;

    /* Update Neri tick */
    if (g_neri_ready)
        neri_sched_tick(&g_neri_pool);

    spin_unlock(&sched_lock);

    /* Stack canary check — detect kernel stack overflow before switch.
     * kstack_canary_check() is the canonical helper (vmm.c).
     * Must be called on the OUTGOING task while its stack is still live. */
    if (prev && prev->kstack_pa) {
        if (!kstack_canary_check((virt_addr_t)phys_to_virt(prev->kstack_pa))) {
            extern void panic(const char*, ...) __attribute__((noreturn));
            panic("STACK OVERFLOW: pid=%d name=%s canary corrupt\n",
                  prev->pid, prev->name);
        }
    }
    if (prev != next)
        __switch_to(prev, next);
}

/* ── Timer tick (called from IRQ handler) ─────────────────── */
void sched_tick(void)
{
    extern u32 smp_processor_id(void);
    u32 cpu = smp_processor_id();
    struct task *t = current_task[cpu];
    if (!t) { schedule(); return; }

    u64 tick_ns = 1000000ULL; /* 1ms tick */
    t->cpu_time_ns    += tick_ns;
    t->neri.cpu_granted_ns += tick_ns;
    t->vruntime       += calc_vruntime_delta(t, tick_ns);

    if (t->timeslice_ns > tick_ns) {
        t->timeslice_ns -= tick_ns;
    } else {
        t->timeslice_ns = 0;
        schedule();
    }
}

/* ── Task exit ────────────────────────────────────────────── */
void task_exit(struct task *t, int code)
{
    if (!t) return;
    spin_lock(&sched_lock);
    t->state = TASK_ZOMBIE;
    if (g_neri_ready)
        neri_sched_release(&g_neri_pool, &t->neri);
    dequeue(t);
    if (t->all_tasks.next) list_del(&t->all_tasks);
    spin_unlock(&sched_lock);
    pr_info("sched: task '%s' pid=%d exited code=%d\n",
            t->name, t->pid, code);
    /* Free kernel stack after context switch */
    if (t->kstack_pa)
        pmm_free_pages(t->kstack_pa, KERNEL_STACK_PAGES / 2);
    schedule();
}

/* ── Init ─────────────────────────────────────────────────── */
void sched_init(void)
{
    for (int i = 0; i < 16; i++) {
        list_init(&runqueues[i]);
        rq_min_vruntime[i] = 0;
    }
    for (u32 i = 0; i < NCPUS_MAX; i++)
        current_task[i] = NULL;

    pr_info("sched: CFS scheduler initialised, %d priority bands\n", 16);
}
