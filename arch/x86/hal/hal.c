/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arch/x86/hal/hal.c — Nekros x86-64 Hardware Abstraction Layer
 *
 * Initialises all hardware before the kernel subsystems start:
 *   - CPU feature detection (CPUID)
 *   - IDT with 256 entries (exceptions 0–31, IRQs 32–47, syscall 0x80)
 *   - APIC and IOAPIC (replaces legacy PIC)
 *   - TSC calibration via CPUID leaf 0x15 or HPET
 *   - MSR access helpers (RDMSR/WRMSR with #GP guard)
 *   - SMP CPU topology scan (MADT)
 *   - Neri UTB hook: exposes neri_hal_read_msr(), neri_hal_hfi_table()
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include "hal.h"

/* ── CPUID ────────────────────────────────────────────────── */

void cpuid(u32 leaf, u32 subleaf,
           u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
    __asm__ volatile(
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(subleaf)
    );
}

struct nekros_cpu_info g_cpu_info;

static void detect_cpu(void)
{
    u32 eax, ebx, ecx, edx;

    /* Vendor string */
    cpuid(0, 0, &eax, &ebx, &ecx, &edx);
    *(u32 *)(g_cpu_info.vendor)     = ebx;
    *(u32 *)(g_cpu_info.vendor + 4) = edx;
    *(u32 *)(g_cpu_info.vendor + 8) = ecx;
    g_cpu_info.vendor[12] = '\0';
    g_cpu_info.max_leaf = eax;

    /* Family/model/stepping */
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    g_cpu_info.stepping = eax & 0xF;
    g_cpu_info.model    = ((eax >> 4) & 0xF) | (((eax >> 16) & 0xF) << 4);
    g_cpu_info.family   = ((eax >> 8) & 0xF) + ((eax >> 20) & 0xFF);
    g_cpu_info.logical_cpus = (ebx >> 16) & 0xFF;

    /* Feature flags */
    g_cpu_info.has_sse2     = !!(edx & (1 << 26));
    g_cpu_info.has_avx      = !!(ecx & (1 << 28));
    g_cpu_info.has_avx2     = 0;
    g_cpu_info.has_rdrand   = !!(ecx & (1 << 30));
    g_cpu_info.has_tsc_invariant = 0;

    if (g_cpu_info.max_leaf >= 7) {
        cpuid(7, 0, &eax, &ebx, &ecx, &edx);
        g_cpu_info.has_avx2    = !!(ebx & (1 << 5));
        g_cpu_info.has_rdseed  = !!(ebx & (1 << 18));
        g_cpu_info.has_sha     = !!(ebx & (1 << 29));
        /* NERI: check for Intel HFI (Thread Director) */
        g_cpu_info.has_hfi     = !!(edx & (1 << 23));
    }

    /* Extended: invariant TSC */
    cpuid(0x80000007, 0, &eax, &ebx, &ecx, &edx);
    g_cpu_info.has_tsc_invariant = !!(edx & (1 << 8));

    /* TSC frequency from CPUID leaf 0x15 */
    g_cpu_info.tsc_khz = 0;
    if (g_cpu_info.max_leaf >= 0x15) {
        u32 num, den, crystal_hz;
        cpuid(0x15, 0, &den, &num, &crystal_hz, &eax);
        if (den && num && crystal_hz)
            g_cpu_info.tsc_khz = ((u64)crystal_hz * num / den) / 1000;
    }
    /* Fallback: leaf 0x16 base frequency */
    if (!g_cpu_info.tsc_khz && g_cpu_info.max_leaf >= 0x16) {
        cpuid(0x16, 0, &eax, &ebx, &ecx, &edx);
        g_cpu_info.tsc_khz = (eax & 0xFFFF) * 1000;
    }
    if (!g_cpu_info.tsc_khz)
        g_cpu_info.tsc_khz = 2000000; /* assume 2 GHz if unknown */

    pr_info("hal: CPU %s family %u model %u stepping %u "
            "TSC %llu MHz HFI=%d\n",
            g_cpu_info.vendor, g_cpu_info.family,
            g_cpu_info.model, g_cpu_info.stepping,
            g_cpu_info.tsc_khz / 1000,
            g_cpu_info.has_hfi);
}

/* ── MSR access ───────────────────────────────────────────── */

u64 rdmsr(u32 msr)
{
    u32 lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((u64)hi << 32) | lo;
}

void wrmsr(u32 msr, u64 val)
{
    __asm__ volatile("wrmsr"
        :: "c"(msr), "a"((u32)val), "d"((u32)(val >> 32)));
}

/* wrmsr_safe — fault-recovering WRMSR for runtime kernel paths.
 *
 * Problem: the CPU raises a Ring-0 #GP fault when WRMSR is called with
 * an invalid value (e.g. a non-canonical address for MSR_FS_BASE, or a
 * reserved bit set in a power-limit MSR).  Nekros does not yet have a
 * full exception-table subsystem (Linux _ASM_EXTABLE), so a #GP in raw
 * wrmsr() falls through to nekros_interrupt_dispatch() → panic().  Any
 * unprivileged user that can trigger the right syscall path can therefore
 * bring down the entire system.
 *
 * Solution: "asm goto" with an inline recovery label.
 * The GCC asm-goto extension lets us name a C label as a possible jump
 * target inside the inline assembly.  We place the WRMSR inside a
 * try-block and label a recovery path.  If the CPU delivers a #GP the
 * fault handler returns to the instruction after WRMSR; because we use
 * the "asm goto" the compiler knows the recovery label is reachable and
 * generates a correct landing pad without a global exception table.
 *
 * Note: this requires the kernel IDT #GP handler to implement "fixup
 * dispatch" — searching a per-translation-unit fixup table.  The minimal
 * version below places the fixup record in the .fixup ELF section and
 * exposes gp_fixup_find() for the #GP dispatcher in nekros_interrupt_dispatch.
 *
 * Until that dispatcher is wired up, wrmsr_safe provides defence-in-depth
 * by:
 *   (a) canonicalising the value for known MSRs before writing, and
 *   (b) using asm-goto so the compiler at least generates correct code
 *       for the fixup path even without the table walk.
 *
 * Returns 0 on success, -EFAULT if a #GP was taken.
 */
int wrmsr_safe(u32 msr, u64 val)
{
    /* Canonicalise value for address-class MSRs before attempting write.
     * A non-canonical address (bits[63:48] not all equal to bit 47)
     * unconditionally causes #GP on WRMSR for FS_BASE / GS_BASE. */
    if (msr == MSR_FS_BASE || msr == MSR_GS_BASE) {
        /* Sign-extend bit 47 to enforce canonical form */
        s64 sval = (s64)val;
        sval = (sval << 16) >> 16;   /* arithmetic shift sign-extends */
        if ((u64)sval != val) {
            pr_warn("hal: wrmsr_safe MSR 0x%x rejected non-canonical "
                    "address 0x%llx\n", msr, val);
            return -EFAULT;
        }
    }

    int ret = 0;
    /* asm goto: on #GP the CPU jumps to the .fixup handler, which
     * transfers control to the `fault` label below.
     * The fixup record in .fixup section is read by gp_fixup_find()
     * called from the #GP path in nekros_interrupt_dispatch(). */
    __asm__ goto(
        "1: wrmsr\n"
        "   jmp %l[ok]\n"
        ".pushsection .fixup,\"ax\"\n"
        "2: movl $-14, %0\n"          /* -EFAULT = -14 */
        "   jmp %l[fault]\n"
        ".popsection\n"
        ".pushsection __ex_table,\"a\"\n"
        "   .balign 4\n"
        "   .long 1b - .\n"           /* insn offset */
        "   .long 2b - .\n"           /* fixup offset */
        ".popsection\n"
        : "+r"(ret)
        : "c"(msr), "a"((u32)val), "d"((u32)(val >> 32))
        : "memory"
        : ok, fault
    );
ok:
    return 0;
fault:
    pr_warn("hal: wrmsr_safe #GP on MSR 0x%x val=0x%llx\n", msr, val);
    return ret ? ret : -EFAULT;
}

/* Exported for Neri UTB (neri_power.c, neri_utb.c) */
u64 neri_hal_read_msr(u32 msr)  { return rdmsr(msr); }

/* MSR write whitelist — prevents security features from being disabled
 * via a kernel bug that ends up calling neri_hal_write_msr() with
 * an attacker-controlled MSR number.
 */
/* msr_write_allowed — runtime whitelist for neri_hal_write_msr().
 *
 * SECURITY: MSR_LSTAR, MSR_STAR, MSR_SYSCALL_MASK, and MSR_EFER are
 * intentionally EXCLUDED from this list.
 *
 * MSR_LSTAR holds the Ring 0 RIP that the CPU jumps to on SYSCALL.
 * If an attacker leverages any kernel bug reaching neri_hal_write_msr()
 * with controlled arguments, allowing MSR_LSTAR would let them redirect
 * every future syscall to arbitrary code — immediate Ring 0 escalation,
 * bypassing CortexCrypto, NSM, pledge, and SMEP entirely.
 *
 * These MSRs are written ONCE during hal_init() via the raw wrmsr()
 * helper, which is only called from boot code. After hal_init() returns,
 * no runtime path must ever write to them again.
 *
 * The neri_hal_write_msr() wrapper (used by Neri UTB / ADO for RAPL
 * power-limit adjustments) only needs access to power management MSRs.
 * Nothing else belongs here.
 */
static bool msr_write_allowed(u32 msr) {
    switch (msr) {
    /* Power management — required for Neri RAPL pre-burst headroom */
    case MSR_PKG_POWER_LIMIT:  return true;
    /* Per-thread FS/GS base — needed for future TLS support */
    case MSR_FS_BASE:          return true;
    case MSR_GS_BASE:          return true;
    /* All other MSRs — including MSR_LSTAR, MSR_STAR, MSR_SYSCALL_MASK,
     * MSR_EFER, APIC_BASE, IA32_MISC_ENABLE — are BLOCKED at runtime.
     * They are written only once by hal_init() via raw wrmsr(). */
    default:
        pr_warn("hal: BLOCKED runtime write to MSR 0x%x\n", msr);
        return false;
    }
}
void neri_hal_write_msr(u32 msr, u64 val) {
    if (!msr_write_allowed(msr)) {
        return;
    }
    /* Use wrmsr_safe: an invalid value (e.g. non-canonical FS_BASE,
     * reserved bits in PKG_POWER_LIMIT) causes a Ring-0 #GP with raw
     * wrmsr(). wrmsr_safe recovers via the inline fixup record and
     * returns -EFAULT instead of panicking the entire system. */
    int rc = wrmsr_safe(msr, val);
    if (rc)
        pr_warn("hal: neri_hal_write_msr MSR=0x%x val=0x%llx failed (%d)\n",
                msr, val, rc);
}

/* ── IDT ──────────────────────────────────────────────────── */

typedef struct {
    u16  offset_lo;
    u16  selector;
    u8   ist;
    u8   type_attr;  /* P | DPL | 0 | type */
    u16  offset_mid;
    u32  offset_hi;
    u32  reserved;
} __packed idt_entry_t;

typedef struct {
    u16  limit;
    u64  base;
} __packed idtr_t;

static idt_entry_t idt[256] __aligned(16);
static idtr_t      idtr;

/* ISR stubs — defined in isr_stubs.S */
extern void *isr_stub_table[256];

static void idt_set_gate(int vec, void *handler, u8 dpl, u8 ist)
{
    u64 addr = (u64)handler;
    idt[vec].offset_lo  = addr & 0xFFFF;
    idt[vec].selector   = 0x08;             /* kernel code segment */
    idt[vec].ist        = ist & 0x7;
    idt[vec].type_attr  = 0x8E | ((dpl & 3) << 5); /* present, 64-bit gate */
    idt[vec].offset_mid = (addr >> 16) & 0xFFFF;
    idt[vec].offset_hi  = (addr >> 32) & 0xFFFFFFFF;
    idt[vec].reserved   = 0;
}

/* Common interrupt dispatch — called from ISR stubs */
void nekros_interrupt_dispatch(u64 vec, u64 errcode, struct isr_frame *frame)
{
    if (vec < 32) {
        /* CPU exception */
        static const char *names[] = {
            "DE","DB","NMI","BP","OF","BR","UD","NM",
            "DF","CSO","TS","NP","SS","GP","PF","res",
            "MF","AC","MC","XF","VE","CP","res","res",
            "res","res","res","res","HV","VC","SX","res"
        };
        /* Before panicking on a #GP (vector 13), check whether the
         * faulting RIP has a registered fixup record in __ex_table.
         * wrmsr_safe (and future copy_from_user / copy_to_user) emit
         * fixup records so that expected faults can be recovered
         * without crashing the system.
         *
         * gp_fixup_find() returns the fixup RIP if a record exists,
         * or 0 if there is none (genuine kernel bug → panic). */
        if (vec == 13 /* #GP */) {
            extern u64 gp_fixup_find(u64 fault_rip);
            u64 fixup_rip = gp_fixup_find(frame->rip);
            if (fixup_rip) {
                /* Redirect execution to the recovery label */
                frame->rip = fixup_rip;
                return;   /* resume at fixup handler, do not panic */
            }
        }
        panic("CPU exception #%llu (%s) errcode=%llx rip=%llx\n",
              vec, names[vec], errcode, frame->rip);
    } else if (vec == 0x80) {
        /* Syscall trap — forward to syscall handler */
        extern u64 nekros_syscall_dispatch(u64, u64, u64, u64, u64, u64);
        frame->rax = nekros_syscall_dispatch(
            frame->rax, frame->rdi, frame->rsi,
            frame->rdx, frame->r10, frame->r8);
    } else if (vec >= 32 && vec < 48) {
        /* Hardware IRQ — forward to driver IRQ table */
        extern void irq_dispatch(u32);
        irq_dispatch((u32)(vec - 32));
        /* Send EOI to APIC */
        apic_eoi();
    }
}

/* ── APIC ─────────────────────────────────────────────────── */

#define APIC_BASE_MSR    0x1B
#define APIC_SVR         0x0F0   /* Spurious vector register */
#define APIC_EOI         0x0B0
#define APIC_ICR_LO      0x300
#define APIC_ICR_HI      0x310
#define APIC_TIMER_LVT   0x320
#define APIC_TIMER_ICR   0x380
#define APIC_TIMER_CCR   0x390
#define APIC_TIMER_DCR   0x3E0
#define APIC_ID          0x020
#define APIC_VER         0x030

static volatile u32 *g_apic_base;

static u32 apic_read(u32 reg) { return g_apic_base[reg / 4]; }
static void apic_write(u32 reg, u32 val) { g_apic_base[reg / 4] = val; }

void apic_eoi(void) { apic_write(APIC_EOI, 0); }

static void apic_init(void)
{
    u64 base = rdmsr(APIC_BASE_MSR);
    base |= (1 << 11);  /* enable APIC globally */
    wrmsr(APIC_BASE_MSR, base);

    g_apic_base = (volatile u32 *)(phys_to_virt(base & ~0xFFFULL));

    /* Enable spurious interrupt vector, set spurious vector 0xFF */
    apic_write(APIC_SVR, apic_read(APIC_SVR) | 0x1FF);

    /* Set up APIC timer: periodic, vector 32, divide by 16 */
    apic_write(APIC_TIMER_DCR, 0x3);           /* divide by 16 */
    apic_write(APIC_TIMER_ICR, 0x10000);       /* initial count */
    apic_write(APIC_TIMER_LVT, 0x20020);       /* periodic, vector 32 */

    pr_info("hal: APIC id=%u version=%u base=%llx\n",
            apic_read(APIC_ID) >> 24,
            apic_read(APIC_VER) & 0xFF,
            base & ~0xFFFULL);
}

/* ── TSC utilities (used by Neri UTB) ────────────────────── */

u64 nekros_rdtsc(void)
{
    u32 lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((u64)hi << 32) | lo;
}

/* Returns ns since boot — Q32 multiplication avoids division */
u64 nekros_tsc_to_ns(u64 tsc_delta)
{
    /* ns = tsc_delta * (1_000_000_000 / tsc_hz)
     * = tsc_delta * 1_000_000 / tsc_khz */
    return tsc_delta * 1000000ULL / g_cpu_info.tsc_khz;
}

/* ── CPU topology (SMP) ───────────────────────────────────── */

u32 g_ncpus = 1;
u32 g_cpu_ids[NCPUS_MAX];

static void detect_topology(void)
{
    /* Simple: use logical CPU count from CPUID leaf 1 */
    g_ncpus = MIN(g_cpu_info.logical_cpus, NCPUS_MAX);
    if (!g_ncpus) g_ncpus = 1;

    for (u32 i = 0; i < g_ncpus; i++)
        g_cpu_ids[i] = i;

    pr_info("hal: %u logical CPU(s) detected\n", g_ncpus);
}

/* ── SSE/AVX enable ──────────────────────────────────────── */

static void enable_fpu_sse(void)
{
    u64 cr0, cr4;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 &= ~(1ULL << 2);  /* clear EM */
    cr0 |=  (1ULL << 1);  /* set  MP */
    __asm__ volatile("mov %0, %%cr0" :: "r"(cr0));

    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= (1ULL << 9);   /* OSFXSR */
    cr4 |= (1ULL << 10);  /* OSXMMEXCPT */
    /* Security features */
    cr4 |= (1ULL << 7);   /* PGE: global page entries */
    /* SMEP (bit 20): prevent kernel executing user pages */
    cr4 |= (1ULL << 20);  /* SMEP */
    /* Note: SMAP (bit 21) disabled — we use uptr_valid() instead.
     * SMAP would require STAC/CLAC around every copy_from/to_user.
     * Enable in a future revision when all copy paths are audited. */
    __asm__ volatile("mov %0, %%cr4" :: "r"(cr4));
    pr_info("hal: SMEP enabled (CR4.bit20) — user-page execution blocked\n");
}

/* ── HAL main init ───────────────────────────────────────── */

void hal_init(void)
{
    detect_cpu();
    enable_fpu_sse();

    /* Set up IDT */
    for (int i = 0; i < 256; i++)
        idt_set_gate(i, isr_stub_table[i], 0, 0);

    /* Syscall via int 0x80: DPL=3 so userspace can call it */
    idt_set_gate(0x80, isr_stub_table[0x80], 3, 0);

    idtr.limit = sizeof(idt) - 1;
    idtr.base  = (u64)idt;
    __asm__ volatile("lidt %0" :: "m"(idtr));

    apic_init();
    detect_topology();

    pr_info("hal: initialised — IDT loaded, APIC online\n");
}

/* ── Current CPU id ──────────────────────────────────────── */

u32 smp_processor_id(void)
{
    if (!g_apic_base) return 0;
    return apic_read(APIC_ID) >> 24;
}
