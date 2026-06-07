/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arch/x86/boot/boot.h — constants shared between entry.S and C boot code
 */
#ifndef BOOT_H
#define BOOT_H

/* Kernel link / load addresses */
#define KERNEL_VIRT_BASE    0xFFFFFFFF80000000ULL
#define KERNEL_PHYS_BASE    0x0000000000100000ULL  /* 1 MB physical load */

/* Multiboot2 */
#define MB2_MAGIC           0xE85250D6
#define MB2_ARCH_I386       0
#define MB2_TAG_FRAMEBUFFER 5

/* Page table entry flags */
#define PTE_P   0x001   /* Present */
#define PTE_W   0x002   /* Writable */
#define PTE_U   0x004   /* User-accessible */
#define PTE_PS  0x080   /* Page Size (2MB/1GB huge page) */
#define PTE_NX  (1ULL << 63)  /* No-execute */

/* CR0 bits */
#define CR0_PE  (1 << 0)    /* Protected mode */
#define CR0_WP  (1 << 16)   /* Write protect */
#define CR0_PG  (1 << 31)   /* Paging */

/* CR4 bits */
#define CR4_PSE (1 << 4)    /* Page size extension */
#define CR4_PAE (1 << 5)    /* Physical address extension */
#define CR4_PGE (1 << 7)    /* Global pages */
#define CR4_OSFXSR (1 << 9) /* SSE support */

/* EFER MSR */
#define MSR_EFER    0xC0000080
#define EFER_LME    (1 << 8)    /* Long mode enable */
#define EFER_LMA    (1 << 10)   /* Long mode active */
#define EFER_NX     (1 << 11)   /* No-execute enable */

/* GDT selectors */
#define GDT64_NULL_SEL   0x00
#define GDT64_CODE_SEL   0x08
#define GDT64_DATA_SEL   0x10
#define GDT64_USER_CODE  0x18
#define GDT64_USER_DATA  0x20
#define GDT64_TSS_SEL    0x28

/* Page size */
#define PAGE_SIZE   0x1000
#define HUGE_2M     0x200000

#endif /* BOOT_H */
