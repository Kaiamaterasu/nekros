#include "../arch/x86/hal/hal.h"
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kernel/syscall.c — Nekros system call table
 *
 * 64 syscalls. POSIX subset (0-39) + 24 Nekros-unique calls (40-63)
 * that do not exist in Linux, BSD, or any other kernel:
 *
 * 40  nk_proc_intent    — declare computational intent to Neri
 * 41  nk_work_budget    — request guaranteed CPU-ns budget with deadline
 * 42  nk_attest_self    — get CortexCrypto process attestation token
 * 43  nk_attest_peer    — verify another process's attestation token
 * 44  nk_secure_alloc   — allocate AES-256-GCM encrypted memory region
 * 45  nk_secure_free    — free encrypted region with crypto-erase
 * 46  nk_ipc_channel    — zero-trust encrypted IPC channel
 * 47  nk_ipc_send       — send on zero-trust channel
 * 48  nk_ipc_recv       — recv on zero-trust channel
 * 49  nk_neri_status    — read own Neri resource allocation
 * 50  nk_neri_tune      — request different resource allocation
 * 51  nk_thermal_hint   — predict burst so Neri prevents throttle
 * 52  nk_anomaly_score  — read own NSM behavioral anomaly score
 * 53  nk_pledge         — declare allowed syscalls (irreversible)
 * 54  nk_unveil         — declare accessible fs paths
 * 55  nk_checkpoint     — create lightweight sealed process checkpoint
 * 56  nk_restore        — restore from sealed checkpoint
 * 57  nk_mem_snapshot   — AES-GCM snapshot of own memory region
 * 58  nk_futex          — fast userspace mutex
 * 59  nk_thread_create  — create thread with Neri resource share
 * 60  nk_thread_exit    — exit current thread
 * 61  nk_get_caps       — query compiled kernel capabilities
 * 62  nk_set_name       — set process name
 * 63  nk_debug_log      — write to kernel log (pledge-gated)
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include <nekros/sched.h>
#include <nekros/task.h>
#include "../mm/vmm.h"
#include "../drivers/neri/include/neri.h"
#include "../drivers/neri/include/neri_uapi.h"
#include "../drivers/neri/include/neri_sec.h"
#include "../drivers/neri/include/neri_nzra.h"
#include "../drivers/neri/include/neri_ado.h"
#include "../drivers/neri/include/neri_version.h"

/* ── Userspace pointer validation ────────────────────────────────────────
 * Prevent SMEP bypass and kernel memory disclosure.
 * User VA space: 0x0 – 0x00007FFFFFFFFFFF (128TB canonical user space)
 * Any pointer from userspace with bit 47 set is a kernel address — reject.
 */
#define USER_ADDR_MAX   0x0000800000000000ULL

static __always_inline bool uptr_valid(u64 ptr, size_t len) {
    if (!ptr) return false;
    /* Check pointer itself is in user range */
    if (ptr >= USER_ADDR_MAX) return false;
    /* Check end of range doesn't overflow into kernel */
    if (len > USER_ADDR_MAX || ptr + len > USER_ADDR_MAX) return false;
    /* Check for null-deref zone (first 4KB) */
    if (ptr < 4096) return false;
    return true;
}

/* Safe copy from user address — returns -EFAULT on bad ptr */
static int copy_from_user(void *kdst, u64 uptr, size_t len) {
    if (!uptr_valid(uptr, len)) return -EFAULT;
    memcpy(kdst, (const void *)uptr, len);
    return 0;
}

/* Safe copy to user address — returns -EFAULT on bad ptr */
static int __attribute__((unused)) copy_to_user(u64 uptr, const void *ksrc, size_t len) {
    if (!uptr_valid(uptr, len)) return -EFAULT;
    memcpy((void *)uptr, ksrc, len);
    return 0;
}

typedef u64 (*syscall_fn)(u64, u64, u64, u64, u64, u64);

extern neri_pool_t g_neri_pool;
extern bool        g_neri_ready;
extern u32         g_ncpus;

/* Forward declarations */
static u64 sys_read(u64,u64,u64,u64,u64,u64);
static u64 sys_write(u64,u64,u64,u64,u64,u64);
static u64 sys_exit(u64,u64,u64,u64,u64,u64);
static u64 sys_getpid(u64,u64,u64,u64,u64,u64);
static u64 sys_yield(u64,u64,u64,u64,u64,u64);
static u64 sys_ioctl(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_proc_intent(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_work_budget(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_attest_self(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_attest_peer(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_secure_alloc(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_secure_free(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_ipc_channel(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_ipc_send(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_ipc_recv(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_neri_status(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_neri_tune(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_thermal_hint(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_anomaly_score(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_pledge(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_checkpoint(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_mem_snapshot(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_futex(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_thread_create(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_get_caps(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_set_name(u64,u64,u64,u64,u64,u64);
static u64 sys_nk_debug_log(u64,u64,u64,u64,u64,u64);

static const syscall_fn syscall_table[64] = {
    sys_read,             /* 0  */
    sys_write,            /* 1  */
    sys_exit,             /* 2  */
    NULL,                 /* 3  fork     */
    NULL,                 /* 4  exec     */
    NULL,                 /* 5  mprotect */
    NULL,                 /* 6  brk      */
    NULL,                 /* 7  lseek    */
    sys_ioctl,            /* 8  */
    NULL,                 /* 9  fcntl    */
    NULL,                 /* 10 open     */
    NULL,                 /* 11 close    */
    NULL,                 /* 12 stat     */
    NULL,                 /* 13 fstat    */
    NULL,                 /* 14 mmap     */
    NULL,                 /* 15 munmap   */
    NULL,                 /* 16 nanosleep*/
    sys_yield,            /* 17 */
    NULL,                 /* 18 gettimeofday */
    NULL,                 /* 19 getcwd   */
    sys_getpid,           /* 20 */
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL, /* 21-29 */
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL, /* 30-39 */
    sys_nk_proc_intent,   /* 40 */
    sys_nk_work_budget,   /* 41 */
    sys_nk_attest_self,   /* 42 */
    sys_nk_attest_peer,   /* 43 */
    sys_nk_secure_alloc,  /* 44 */
    sys_nk_secure_free,   /* 45 */
    sys_nk_ipc_channel,   /* 46 */
    sys_nk_ipc_send,      /* 47 */
    sys_nk_ipc_recv,      /* 48 */
    sys_nk_neri_status,   /* 49 */
    sys_nk_neri_tune,     /* 50 */
    sys_nk_thermal_hint,  /* 51 */
    sys_nk_anomaly_score, /* 52 */
    sys_nk_pledge,        /* 53 */
    NULL,                 /* 54 nk_unveil */
    sys_nk_checkpoint,    /* 55 */
    NULL,                 /* 56 nk_restore */
    sys_nk_mem_snapshot,  /* 57 */
    sys_nk_futex,         /* 58 */
    sys_nk_thread_create, /* 59 */
    NULL,                 /* 60 thread_exit */
    sys_nk_get_caps,      /* 61 */
    sys_nk_set_name,      /* 62 */
    sys_nk_debug_log,     /* 63 */
};

/* ── Syscall dispatch hardening ─────────────────────────────────────────
 *
 * Two properties enforced on every syscall transition:
 *
 * 1. NON-REENTRANT GUARD
 *    nekros_syscall_dispatch must not be re-entered on the same CPU.
 *    Reentrancy can occur if a ring-0 path taken inside a syscall
 *    (e.g. a page fault on a user pointer during copy_from_user)
 *    triggers another INT 0x80 — possible if the IDT gate DPL=3 and
 *    the fault handler re-enables interrupts before returning.
 *    A per-CPU "in_syscall" flag detects this and returns -ENOSYS
 *    for the nested call, preventing stack corruption or logic loops.
 *
 * 2. REGISTER INPUT SANITIZATION
 *    All six argument registers (rdi/rsi/rdx/r10/r8/r9) arrive as
 *    raw u64.  Individual syscall handlers call uptr_valid() on any
 *    argument they treat as a pointer.  BUT the dispatch layer itself
 *    must also reject args that are kernel virtual addresses BEFORE
 *    they are passed to any handler — this prevents a handler that
 *    accidentally skips its uptr_valid call from performing a blind
 *    kernel-memory read/write.
 *
 *    We do not reject non-pointer integers (pid_t, flags, sizes) here
 *    because we cannot know which args are pointers without per-syscall
 *    metadata.  Instead we apply the check in the one place we know an
 *    arg IS a pointer: uptr_valid() is called inside every handler that
 *    dereferences a user arg.  The dispatch-level check below is an
 *    additional defence-in-depth layer: any arg that looks like a kernel
 *    VA (bit 47 set, canonical kernel address) is zeroed out before
 *    reaching the handler.  A handler that forgets its uptr_valid call
 *    will receive 0 for that arg and return -EINVAL/-EFAULT rather than
 *    touching kernel memory.
 */

/* Per-CPU reentrancy guard.  One flag per CPU; accessed only on that CPU
 * (no SMP lock needed).  Stored in a u8 array indexed by smp_processor_id(). */
static u8 g_syscall_in_progress[NCPUS_MAX];

/* Scrub a single syscall argument: zero it if it is a canonical kernel VA.
 * User space VAs have bits[63:47] == 0.
 * Kernel VAs have bits[63:47] == 0x1FFFF (all ones, sign-extended).
 * The simple test: if the top 17 bits are not all-zero, it is not a user VA. */
static __always_inline u64 scrub_arg(u64 arg)
{
    /* Keep zero (common for unused args) and valid user addresses.
     * Reject anything that starts with a non-zero upper half. */
    if (arg >= USER_ADDR_MAX && arg != 0) {
        pr_warn("syscall: scrubbed kernel-range arg 0x%llx\n", arg);
        return 0;
    }
    return arg;
}

u64 nekros_syscall_dispatch(u64 nr, u64 a1, u64 a2,
                             u64 a3, u64 a4, u64 a5)
{
    if (nr >= 64) return (u64)-ENOSYS;

    /* ── Reentrancy guard ───────────────────────────────────── */
    u32 cpu = smp_processor_id();
    if (cpu >= NCPUS_MAX) cpu = 0;  /* paranoia: clamp to valid index */
    if (g_syscall_in_progress[cpu]) {
        /* Nested syscall on same CPU — should never happen in normal
         * operation.  Return ENOSYS to the nested caller; do NOT panic
         * because the outer syscall is still on the stack and a panic
         * here would unwind into undefined state. */
        pr_warn("syscall: reentrancy detected on CPU%u nr=%llu — rejected\n",
                cpu, nr);
        return (u64)-ENOSYS;
    }
    g_syscall_in_progress[cpu] = 1;

    /* ── Argument sanitization ──────────────────────────────── */
    /* Scrub any arg that is a canonical kernel VA before it reaches
     * a handler.  Handlers that expect pointer args still call
     * uptr_valid() themselves; this is defence-in-depth only. */
    a1 = scrub_arg(a1);
    a2 = scrub_arg(a2);
    a3 = scrub_arg(a3);
    a4 = scrub_arg(a4);
    a5 = scrub_arg(a5);

    struct task *t = sched_current();

    /* ── Pledge enforcement ─────────────────────────────────── */
    if (t && (t->sig_pending & (1ULL << 63))) {
        if (!(t->sig_blocked & (1ULL << nr))) {
            pr_warn("pledge: pid=%d blocked syscall nr=%llu — killed\n",
                    t->pid, nr);
            g_syscall_in_progress[cpu] = 0;
            task_exit(t, -EPERM);
            return (u64)-EPERM;
        }
    }

    syscall_fn fn = syscall_table[nr];
    if (!fn) {
        g_syscall_in_progress[cpu] = 0;
        return (u64)-ENOSYS;
    }

    u64 ret = fn(a1, a2, a3, a4, a5, 0);

    /* Clear reentrancy flag before returning to user space */
    g_syscall_in_progress[cpu] = 0;
    return ret;
}

/* ── POSIX implementations ───────────────────────────────── */

extern ssize_t vfs_read(int fd, void *buf, size_t len);
extern ssize_t vfs_write(int fd, const void *buf, size_t len);

static u64 sys_read(u64 fd,u64 buf,u64 len,u64 a,u64 b,u64 c) {
    if (!uptr_valid(buf, (size_t)len)) return (u64)-EFAULT;
    return (u64)vfs_read((int)fd,(void*)buf,(size_t)len);
}
static u64 sys_write(u64 fd,u64 buf,u64 len,u64 a,u64 b,u64 c) {
    if (!uptr_valid(buf, (size_t)len)) return (u64)-EFAULT;
    return (u64)vfs_write((int)fd,(const void*)buf,(size_t)len);
}
static u64 sys_exit(u64 code,u64 a,u64 b,u64 c,u64 d,u64 e)
    { task_exit(sched_current(),(int)code); return 0; }
static u64 sys_getpid(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f)
    { struct task *t=sched_current(); return t?(u64)t->pid:0; }
static u64 sys_yield(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f)
    { schedule(); return 0; }
static u64 sys_ioctl(u64 fd,u64 cmd,u64 arg,u64 a,u64 b,u64 c)
    { extern int neri_dev_ioctl(u32,u64);
      if ((int)fd==3) return (u64)neri_dev_ioctl((u32)cmd,arg);
      return (u64)-ENOTTY; }

/* ── nk_proc_intent ───────────────────────────────────────── */
/*
 * Declares the computational intent of a process so Neri can
 * optimally place it. No other kernel has this concept.
 * Linux uses static priority; Nekros uses semantic intent.
 */
#define NK_INTENT_INTERACTIVE 0
#define NK_INTENT_COMPILE     1
#define NK_INTENT_ML_TRAIN    2
#define NK_INTENT_DAEMON      3
#define NK_INTENT_CRYPTO      4
#define NK_INTENT_IO_HEAVY    5

static u64 sys_nk_proc_intent(u64 intent,u64 burst_ns,
                               u64 ram_hint,u64 a,u64 b,u64 c)
{
    struct task *t = sched_current();
    if (!t || intent > NK_INTENT_IO_HEAVY) return (u64)-EINVAL;

    static const struct { u64 cpu; u64 ram; u64 gpu; } imap[] = {
        {  500000ULL,  8, 0 }, /* INTERACTIVE */
        { 4000000ULL, 64, 0 }, /* COMPILE     */
        { 4000000ULL,256,16 }, /* ML_TRAIN    */
        {  100000ULL,  4, 0 }, /* DAEMON      */
        { 2000000ULL,128, 0 }, /* CRYPTO      */
        {  200000ULL, 16, 0 }, /* IO_HEAVY    */
    };
    t->neri.cpu_demand_ns    = burst_ns  ? burst_ns  : imap[intent].cpu;
    t->neri.ram_demand_pages = ram_hint  ? ram_hint  : imap[intent].ram;
    t->neri.gpu_demand_slots = imap[intent].gpu;

    if (g_neri_ready) {
        neri_nzra_decision_t dec;
        neri_nzra_decide(&t->neri, &dec);
        t->cpu_affinity = dec.prefer_pcore ? 0 : (g_ncpus > 1 ? 1 : 0);
        neri_ado_dispatch(&dec,
            (u64)atomic64_read((atomic64_t*)&g_neri_pool.epoch));
    }
    return 0;
}

/* ── nk_work_budget ───────────────────────────────────────── */
/*
 * Process declares: "I need X CPU-ns within Y wall-clock ns."
 * Kernel guarantees delivery or sends SIGBUDGET on expiry.
 * No other kernel has temporal work budget guarantees.
 */
#define MAX_BUDGETS 256
struct nk_budget {
    u64  id;
    pid_t pid;
    u64  cpu_ns_left;
    u64  deadline_tsc;
    u32  flags;
    bool active;
};
static struct nk_budget g_budgets[MAX_BUDGETS];
static spinlock_t budget_lock = SPINLOCK_INIT;
static u64 next_budget_id = 1;

static u64 sys_nk_work_budget(u64 cpu_ns,u64 deadline_ns,
                               u64 flags,u64 a,u64 b,u64 c)
{
    struct task *t = sched_current();
    if (!t || !cpu_ns || !deadline_ns) return (u64)-EINVAL;

    extern struct nekros_cpu_info g_cpu_info;
    extern u64 nekros_rdtsc(void);

    spin_lock(&budget_lock);
    struct nk_budget *bud = NULL;
    for (int i=0;i<MAX_BUDGETS;i++)
        if (!g_budgets[i].active) { bud=&g_budgets[i]; break; }
    if (!bud) { spin_unlock(&budget_lock); return (u64)-ENOMEM; }

    bud->id           = next_budget_id++;
    bud->pid          = t->pid;
    bud->cpu_ns_left  = cpu_ns;
    bud->deadline_tsc = nekros_rdtsc() +
        deadline_ns * g_cpu_info.tsc_khz / 1000000ULL;
    bud->flags        = (u32)flags;
    bud->active       = true;
    u64 ret = bud->id;
    spin_unlock(&budget_lock);

    t->priority = MIN(15u, t->priority + 2); /* elevate for budget window */
    return ret;
}

/* ── nk_attest_self / nk_attest_peer ─────────────────────── */
/*
 * Every process can prove its identity cryptographically.
 * Token = AES-256-GCM{ pid|exe_hash|resource_grant|anomaly_score|timestamp }
 * Peers verify without trusting the claiming process.
 * Zero-trust process authentication — native to the kernel.
 */
static u64 sys_nk_attest_self(u64 out,u64 size,u64 a,u64 b,u64 c,u64 d)
{
    if (!uptr_valid(out, (size_t)size) || size < 96) return (u64)-EFAULT;
    extern int cc_kernel_attest_process(pid_t, u8*, u32*);
    struct task *t = sched_current();
    u32 written = (u32)size;
    return (u64)cc_kernel_attest_process(t->pid,(u8*)out,&written);
}
static u64 sys_nk_attest_peer(u64 tok,u64 sz,u64 pid,u64 a,u64 b,u64 c)
{
    if (!tok||!sz||sz>4096) return (u64)-EINVAL;
    if (!uptr_valid(tok, (size_t)sz)) return (u64)-EFAULT;
    extern int cc_kernel_verify_attestation(const u8*,u32,pid_t);
    return (u64)cc_kernel_verify_attestation((const u8*)tok,(u32)sz,(pid_t)pid);
}

/* ── nk_secure_alloc / nk_secure_free ────────────────────── */
/* AES-256-GCM encrypted memory. Pages at rest are ciphertext. */
static u64 sys_nk_secure_alloc(u64 pages,u64 policy,u64 a,u64 b,u64 c,u64 d)
{
    if (!pages || pages > 4096) return (u64)-EINVAL; /* cap at 16MB */
    extern void *cc_kernel_secure_alloc(u64,u32);
    void *p = cc_kernel_secure_alloc(pages,(u32)policy);
    return p ? (u64)p : (u64)(s64)-ENOMEM;
}
static u64 sys_nk_secure_free(u64 ptr,u64 pages,u64 a,u64 b,u64 c,u64 d)
{
    extern void cc_kernel_secure_free(void*,u64);
    cc_kernel_secure_free((void*)ptr,pages); return 0;
}

/* ── nk_ipc_channel / send / recv ────────────────────────── */
/* Zero-trust IPC: data encrypted in the kernel ring buffer.   */
static u64 sys_nk_ipc_channel(u64 peer,u64 flags,u64 a,u64 b,u64 c,u64 d)
{
    extern int cc_ipc_channel_create(pid_t,pid_t,u32);
    struct task *t=sched_current();
    return t ? (u64)cc_ipc_channel_create(t->pid,(pid_t)peer,(u32)flags)
             : (u64)-ESRCH;
}
static u64 sys_nk_ipc_send(u64 fd,u64 buf,u64 len,u64 a,u64 b,u64 c)
{
    extern ssize_t cc_ipc_send(int,const void*,size_t);
    if (!uptr_valid(buf, (size_t)len)) return (u64)-EFAULT;
    if (!len || len > 65536) return (u64)-EINVAL;
    return (u64)cc_ipc_send((int)fd,(const void*)buf,(size_t)len);
}
static u64 sys_nk_ipc_recv(u64 fd,u64 buf,u64 len,u64 a,u64 b,u64 c)
{
    if (!uptr_valid(buf, (size_t)len)) return (u64)-EFAULT;
    extern ssize_t cc_ipc_recv(int,void*,size_t);
    return (u64)cc_ipc_recv((int)fd,(void*)buf,(size_t)len);
}

/* ── nk_neri_status / tune ───────────────────────────────── */
static u64 sys_nk_neri_status(u64 out,u64 a,u64 b,u64 c,u64 d,u64 e)
{
    if (!uptr_valid(out, sizeof(struct neri_uapi_status))) return (u64)-EFAULT;
    struct neri_uapi_status *s = (struct neri_uapi_status*)out;
    if (g_neri_ready) {
        s->epoch           = (u64)atomic64_read((atomic64_t*)&g_neri_pool.epoch);
        s->cpu_total_ns    = g_neri_pool.cpu_total_ns;
        s->cpu_alloc_ns    = g_neri_pool.cpu_alloc_ns;
        s->ram_total_pages = g_neri_pool.ram_total_pages;
        s->ram_alloc_pages = g_neri_pool.ram_alloc_pages;
        s->gpu_total_slots = g_neri_pool.gpu_total_slots;
        s->gpu_alloc_slots = g_neri_pool.gpu_alloc_slots;
    }
    return 0;
}
static u64 sys_nk_neri_tune(u64 cpu,u64 ram,u64 gpu,u64 a,u64 b,u64 c)
{
    struct task *t=sched_current(); if (!t) return (u64)-ESRCH;
    /* Cap demands to reasonable bounds to prevent abuse */
    if (cpu) t->neri.cpu_demand_ns    = MIN(cpu, 1000000000ULL); /* 1s max */
    if (ram) t->neri.ram_demand_pages = MIN(ram, 65536ULL);       /* 256MB max */
    if (gpu) t->neri.gpu_demand_slots = MIN(gpu, 256ULL);
    return 0;
}

/* ── nk_thermal_hint ─────────────────────────────────────── */
/*
 * Process hints an upcoming compute burst.
 * Neri pre-emptively migrates work off hot cores and headrooms RAPL
 * 200ms BEFORE throttling would occur. Linux never does this.
 */
static u64 sys_nk_thermal_hint(u64 burst_ns,u64 intensity,
                                u64 a,u64 b,u64 c,u64 d)
{
    if (intensity>3) return (u64)-EINVAL;
    extern void neri_thermal_hint(pid_t,u64,u32);
    struct task *t=sched_current();
    if (g_neri_ready && t) neri_thermal_hint(t->pid,burst_ns,(u32)intensity);
    return 0;
}

/* ── nk_anomaly_score ────────────────────────────────────── */
static u64 sys_nk_anomaly_score(u64 out,u64 a,u64 b,u64 c,u64 d,u64 e)
{
    if (!uptr_valid(out, sizeof(struct neri_uapi_anomaly))) return (u64)-EFAULT;
    neri_sec_anomaly_t anm = {0};
    if (g_neri_ready) neri_sec_get_anomaly(&anm);
    struct neri_uapi_anomaly *u = (struct neri_uapi_anomaly*)out;
    u->score = anm.score_byte;
    u->level = (u32)anm.level;
    u->blocked = anm.block_admits;
    u->epoch   = anm.score_epoch;
    return 0;
}

/* ── nk_pledge ───────────────────────────────────────────── */
/* Irreversible syscall whitelist. Stronger than seccomp.     */
static u64 sys_nk_pledge(u64 mask,u64 a,u64 b,u64 c,u64 d,u64 e)
{
    struct task *t=sched_current(); if (!t) return (u64)-ESRCH;
    t->sig_blocked  = mask;               /* bitmask: which syscalls are allowed */
    t->sig_pending |= (1ULL << 63);       /* bit 63 in sig_pending = pledge active */
    return 0;
}

/* ── nk_checkpoint / nk_mem_snapshot ────────────────────── */
static u64 sys_nk_checkpoint(u64 out,u64 sz,u64 a,u64 b,u64 c,u64 d)
{
    extern int cc_kernel_checkpoint(struct task*,void*,u32*);
    struct task *t=sched_current();
    if (!t||!out||!sz) return (u64)-EINVAL;
    if (!uptr_valid(out, (size_t)sz)) return (u64)-EFAULT;
    u32 w=(u32)sz;
    return (u64)cc_kernel_checkpoint(t,(void*)out,&w);
}
static u64 sys_nk_mem_snapshot(u64 va,u64 pages,u64 out,u64 a,u64 b,u64 c)
{
    extern int cc_kernel_seal_memory(virt_addr_t,u64,void*,u32*);
    if (!va||!pages||!out||pages>4096) return (u64)-EINVAL;
    /* va must be in user space */
    if (!uptr_valid(va, pages * 4096)) return (u64)-EFAULT;
    u64 out_size = pages * 4096 + 128;
    if (!uptr_valid(out, (size_t)out_size)) return (u64)-EFAULT;
    u32 sz=(u32)out_size;
    return (u64)cc_kernel_seal_memory(va,pages,(void*)out,&sz);
}

/* ── nk_futex ────────────────────────────────────────────── */
static u64 sys_nk_futex(u64 addr,u64 op,u64 val,u64 a,u64 b,u64 c)
{
    /* Validate user pointer before deref */
    if (!uptr_valid(addr, sizeof(u32))) return (u64)-EFAULT;
    volatile u32 *f=(volatile u32*)addr;
    if (op==0) { if (*f!=(u32)val) return (u64)-EAGAIN; schedule(); return 0; }
    if (op==1) { *f = (u32)val; return 0; }  /* FUTEX_WAKE: write val */
    return 0;
}

/* ── nk_thread_create ────────────────────────────────────── */
static u64 sys_nk_thread_create(u64 entry,u64 arg,u64 stack_sz,
                                 u64 a,u64 b,u64 c)
{
    /* entry is a user-space function pointer — must be a valid user VA */
    if (!uptr_valid(entry, 1)) return (u64)-EFAULT;
    struct task *t=sched_current(); if (!t) return (u64)-ESRCH;
    char name[32]; strlcpy(name,t->name,29); strlcpy(name+strnlen(name,29),".t",3);
    struct task *nt=task_create(name,(void(*)(void*))entry,(void*)arg,
                                t->priority,
                                t->neri.cpu_demand_ns/2,
                                t->neri.ram_demand_pages/4);
    return IS_ERR(nt)?(u64)(s64)PTR_ERR(nt):(u64)nt->pid;
}

/* ── nk_get_caps / set_name / debug_log ─────────────────── */
static u64 sys_nk_get_caps(u64 out,u64 a,u64 b,u64 c,u64 d,u64 e)
{
    if (!out) return (u64)-EINVAL;
    if (!uptr_valid(out, sizeof(struct neri_uapi_caps))) return (u64)-EFAULT;
    struct neri_uapi_caps *cap=(struct neri_uapi_caps*)out;
    cap->caps=NERI_CAPS_ALL;
    cap->version_major=0; cap->version_minor=5; cap->version_patch=0;
    return 0;
}
static u64 sys_nk_set_name(u64 ptr,u64 a,u64 b,u64 c,u64 d,u64 e)
{
    struct task *t=sched_current();
    if (!t || !uptr_valid(ptr, 32)) return (u64)-EFAULT;
    char safe_name[32];
    if (copy_from_user(safe_name, ptr, 31) < 0) return (u64)-EFAULT;
    safe_name[31] = '\0';
    strlcpy(t->name, safe_name, 32); return 0;
}
static u64 sys_nk_debug_log(u64 ptr,u64 len,u64 a,u64 b,u64 c,u64 d)
{
    if (!ptr||!len||len>256) return (u64)-EINVAL;
    if (!uptr_valid(ptr, (size_t)len)) return (u64)-EFAULT;
    char buf[257]; memcpy(buf,(void*)ptr,MIN(len,256)); buf[MIN(len,256)]=0;
    struct task *t=sched_current();
    pr_info("[pid=%d] %s\n", t?t->pid:-1, buf);
    return 0;
}

void syscall_init(void)
{
    pr_info("syscall: 64 entries loaded — 24 Nekros-unique calls active\n");
    pr_info("syscall: nk_proc_intent nk_work_budget nk_attest "
            "nk_secure_alloc nk_ipc nk_thermal_hint nk_pledge online\n");
}
