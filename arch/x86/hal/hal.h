/* SPDX-License-Identifier: GPL-2.0 */
/* arch/x86/hal/hal.h */
#ifndef NEKROS_HAL_H
#define NEKROS_HAL_H

#include <nekros/types.h>

/* ── ISR frame pushed by stub ──────────────────────────────── */
struct isr_frame {
    u64 r15, r14, r13, r12, r11, r10, r9,  r8;
    u64 rbp, rdi, rsi, rdx, rcx, rbx, rax;
    u64 vec, errcode;
    u64 rip, cs, rflags, rsp, ss;
};

/* ── CPU info ───────────────────────────────────────────────── */
struct nekros_cpu_info {
    char vendor[13];
    u32  max_leaf;
    u32  family, model, stepping;
    u32  logical_cpus;
    u64  tsc_khz;
    u8   has_sse2, has_avx, has_avx2, has_sha;
    u8   has_rdrand, has_rdseed;
    u8   has_tsc_invariant;
    u8   has_hfi;         /* Intel HFI / Thread Director */
};

extern struct nekros_cpu_info g_cpu_info;
extern u32 g_ncpus;
extern u32 g_cpu_ids[NCPUS_MAX];

/* ── API ────────────────────────────────────────────────────── */
void hal_init(void);
void cpuid(u32 leaf, u32 subleaf, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx);
u64  rdmsr(u32 msr);
void wrmsr(u32 msr, u64 val);
int  wrmsr_safe(u32 msr, u64 val);  /* fault-recovering WRMSR; returns -EFAULT on #GP */
u64  gp_fixup_find(u64 fault_rip);  /* walk __ex_table for #GP recovery RIP */
void apic_eoi(void);
u32  smp_processor_id(void);
u64  nekros_rdtsc(void);
u64  nekros_tsc_to_ns(u64 tsc_delta);

/* Neri HAL hooks (called from neri_utb.c, neri_power.c) */
u64  neri_hal_read_msr(u32 msr);
void neri_hal_write_msr(u32 msr, u64 val);

/* MSR numbers used by Neri */
#define MSR_IA32_MPERF            0x000000E7
#define MSR_IA32_APERF            0x000000E8
#define MSR_PKG_ENERGY_STATUS     0x00000611
#define MSR_PKG_POWER_LIMIT       0x00000610
#define MSR_PKG_POWER_INFO        0x00000614
#define MSR_DRAM_ENERGY_STATUS    0x00000619
#define MSR_PP0_ENERGY_STATUS     0x00000639
#define MSR_HFI_TABLE_PTR         0x00000800  /* Intel HFI table pointer */
#define MSR_RAPL_POWER_UNIT       0x00000606
#define MSR_EFER                  0xC0000080
#define MSR_STAR                  0xC0000081
#define MSR_LSTAR                 0xC0000082
#define MSR_SYSCALL_MASK          0xC0000084
#define MSR_FS_BASE               0xC0000100
#define MSR_GS_BASE               0xC0000101

/* IRQ dispatch table (set by drivers) */
typedef void (*irq_handler_t)(u32 irq);
void  irq_register(u32 irq, irq_handler_t h);
void  irq_dispatch(u32 irq);

#endif /* NEKROS_HAL_H */
