/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arch/x86/boot/entry.S — Nekros x86-64 boot entry point
 *
 * Receives control from a Multiboot2-compliant bootloader (GRUB2).
 * Steps:
 *   1. Verify Multiboot2 magic
 *   2. Set up a minimal 32-bit GDT
 *   3. Enable PAE + long mode (IA-32e) via CR0/CR4/EFER MSRs
 *   4. Load 64-bit GDT + jump to 64-bit C kernel entry
 *
 * Memory layout on entry (32-bit protected mode):
 *   EAX = 0x36d76289  (Multiboot2 magic)
 *   EBX = physical address of Multiboot2 info structure
 *   ESP = undefined — we set our own stack immediately
 *
 * Kernel is linked at KERNEL_VIRT_BASE = 0xFFFFFFFF80000000
 * Physical load address = 0x00100000 (1 MB)
 */

#include "boot.h"

/* ── Multiboot2 header (must be in first 32KB of kernel image) */
    .section ".multiboot2", "a"
    .align 8
mb2_header:
    .long   MB2_MAGIC
    .long   MB2_ARCH_I386
    .long   mb2_header_end - mb2_header
    .long  -(MB2_MAGIC + MB2_ARCH_I386 + (mb2_header_end - mb2_header))

    /* Tag: framebuffer request */
    .align 8
    .short  MB2_TAG_FRAMEBUFFER
    .short  0
    .long   20
    .long   0       /* preferred width  (0=don't care) */
    .long   0       /* preferred height (0=don't care) */
    .long   32      /* preferred depth */

    /* Tag: end */
    .align 8
    .short  0
    .short  0
    .long   8
mb2_header_end:

/* ── 32-bit entry point ──────────────────────────────────── */
    .section ".boot.text", "ax"
    .code32
    .global _start32
_start32:
    cli
    /* Save multiboot2 pointer before we trash registers */
    movl    %ebx, mb2_info_phys - KERNEL_PHYS_BASE

    /* Set up a minimal 32-bit stack */
    movl    $boot_stack_top - KERNEL_PHYS_BASE, %esp

    /* Verify Multiboot2 magic */
    cmpl    $MB2_MAGIC, %eax
    jne     boot_panic_nomultiboot

    /* Build a minimal PML4 page table (identity + high-half) */
    call    setup_paging

    /* Enable PAE */
    movl    %cr4, %eax
    orl     $(CR4_PAE | CR4_PSE), %eax
    movl    %eax, %cr4

    /* Load PML4 */
    movl    $pml4 - KERNEL_PHYS_BASE, %eax
    movl    %eax, %cr3

    /* Enable IA-32e (long mode) via EFER.LME */
    movl    $MSR_EFER, %ecx
    rdmsr
    orl     $(EFER_LME | EFER_NX), %eax
    wrmsr

    /* Enable paging + protected mode (CR0.PE already set by bootloader) */
    movl    %cr0, %eax
    orl     $(CR0_PG | CR0_WP), %eax
    movl    %eax, %cr0

    /* Load 64-bit GDT and far-jump to 64-bit code segment */
    lgdt    gdt64_ptr - KERNEL_PHYS_BASE
    ljmp    $GDT64_CODE_SEL, $(long_mode_entry - KERNEL_PHYS_BASE)

/* ── Minimal identity + high-half page tables ────────────── */
    .align PAGE_SIZE
pml4:   .space PAGE_SIZE, 0    /* PML4 — 512 entries × 8 bytes */
pdpt_lo:.space PAGE_SIZE, 0    /* Low  PDPT (identity 0..1GB)   */
pdpt_hi:.space PAGE_SIZE, 0    /* High PDPT (kernel -2GB..-1GB) */
pd:     .space PAGE_SIZE, 0    /* PD  (2MB pages, 1GB coverage) */

setup_paging:
    /* PML4[0] → pdpt_lo (identity map for boot) */
    movl    $pdpt_lo - KERNEL_PHYS_BASE, %eax
    orl     $(PTE_P | PTE_W), %eax
    movl    %eax, pml4 - KERNEL_PHYS_BASE

    /* PML4[511] → pdpt_hi (kernel virtual base -512GB) */
    movl    $pdpt_hi - KERNEL_PHYS_BASE, %eax
    orl     $(PTE_P | PTE_W), %eax
    movl    %eax, (pml4 - KERNEL_PHYS_BASE + 511*8)

    /* pdpt_lo[0] → pd (identity 0..1GB) */
    movl    $pd - KERNEL_PHYS_BASE, %eax
    orl     $(PTE_P | PTE_W), %eax
    movl    %eax, pdpt_lo - KERNEL_PHYS_BASE

    /* pdpt_hi[510] → pd (maps 0xFFFFFFFF80000000 → phys 0) */
    movl    $pd - KERNEL_PHYS_BASE, %eax
    orl     $(PTE_P | PTE_W), %eax
    movl    %eax, (pdpt_hi - KERNEL_PHYS_BASE + 510*8)

    /* Fill PD with 512 × 2MB huge pages (0..1GB identity) */
    xorl    %ecx, %ecx
1:  movl    $pd - KERNEL_PHYS_BASE, %edx
    leal    (%edx, %ecx, 8), %edx
    movl    %ecx, %eax
    shll    $21, %eax           /* 2MB per entry */
    orl     $(PTE_P | PTE_W | PTE_PS), %eax
    movl    %eax, (%edx)
    movl    $0, 4(%edx)
    incl    %ecx
    cmpl    $512, %ecx
    jl      1b
    ret

/* ── 64-bit long mode entry ──────────────────────────────── */
    .code64
long_mode_entry:
    /* Reload all segment registers with flat 64-bit data selector */
    movw    $GDT64_DATA_SEL, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss
    xorw    %ax, %ax
    movw    %ax, %fs
    movw    %ax, %gs

    /* Switch to virtual high-half stack */
    movabsq $boot_stack_top, %rsp

    /* Load TSS */
    movw    $GDT64_TSS_SEL, %ax
    ltr     %ax

    /* Load IDT (initially just a blank table; exceptions set up in hal_init) */
    lidt    idt_ptr

    /* Clear BSS */
    movabsq $__bss_start, %rdi
    movabsq $__bss_end,   %rcx
    subq    %rdi, %rcx
    xorl    %eax, %eax
    rep stosb

    /* Pass Multiboot2 pointer as first argument (physical addr in low 4GB) */
    movl    mb2_info_phys(%rip), %edi

    /* Call C kernel main */
    movabsq $nekros_main, %rax
    callq   *%rax

    /* Should never return */
    cli
1:  hlt
    jmp 1b

/* ── Panic handlers ──────────────────────────────────────── */
boot_panic_nomultiboot:
    /* Write "NO MB2" to VGA text buffer at 0xB8000 */
    movl    $0xB8000, %edi
    movl    $0x4F4F4F4E, (%edi)   /* "NO" in red */
    movl    $0x4F324F20, 4(%edi)  /* " 2" in red */
1:  hlt
    jmp 1b

/* ── 64-bit GDT ──────────────────────────────────────────── */
    .align 8
gdt64:
    .quad 0                        /* 0x00: null */
    /* 0x08: 64-bit code, DPL0 */
    .quad 0x00AF9A000000FFFF
    /* 0x10: 64-bit data, DPL0 */
    .quad 0x00CF92000000FFFF
    /* 0x18: 64-bit code, DPL3 */
    .quad 0x00AFFA000000FFFF
    /* 0x20: 64-bit data, DPL3 */
    .quad 0x00CFF2000000FFFF
    /* 0x28/0x30: TSS descriptor (16 bytes) */
tss_desc:
    .quad 0
    .quad 0
gdt64_end:

gdt64_ptr:
    .word   gdt64_end - gdt64 - 1
    .quad   gdt64

    .align 8
idt_ptr:
    .word   0       /* limit 0 = empty IDT initially */
    .quad   0

/* ── Boot data ───────────────────────────────────────────── */
mb2_info_phys:
    .long   0

/* ── Boot stack (16KB, 16-byte aligned) ─────────────────── */
    .section ".boot.bss", "aw", @nobits
    .align 16
boot_stack:
    .space  16384
boot_stack_top:
    .section .note.GNU-stack,"",@progbits
