/* SPDX-License-Identifier: GPL-2.0 */
/*
 * nekros.ld — Nekros kernel linker script
 *
 * Kernel is linked at virtual base 0xFFFFFFFF80000000
 * Physical load address 0x00100000 (1 MB, above BIOS)
 *
 * Section layout:
 *   .multiboot2   — Multiboot2 header (must be in first 32KB)
 *   .boot.text    — 32-bit boot code (runs before paging)
 *   .boot.bss     — boot stack
 *   .text         — 64-bit kernel code
 *   .rodata       — read-only data
 *   .data         — mutable kernel data
 *   .bss          — zero-initialised data (zeroed by entry.S)
 */

KERNEL_PHYS = 0x00100000;
KERNEL_VIRT = 0xFFFFFFFF80000000;

ENTRY(_start32)

SECTIONS {
    /* Multiboot2 header must appear before 32KB mark */
    . = KERNEL_PHYS;

    .multiboot2 : AT(KERNEL_PHYS) {
        KEEP(*(.multiboot2))
    }

    /* 32-bit boot code runs at physical addresses */
    .boot.text : AT(ADDR(.boot.text)) {
        *(.boot.text)
    }

    .boot.bss (NOLOAD) : {
        /* Boot stack canary: export the bottom-of-stack address so
         * nekros_main can write the sentinel before any C logic runs.
         * entry.S places the boot stack in .boot.bss; the stack grows
         * downward so the LOWEST address is the overflow trip-wire. */
        __boot_stack_bottom = .;
        *(.boot.bss)
        __boot_stack_top = .;
    }

    /* Switch to high-half virtual addresses for main kernel */
    . = KERNEL_VIRT + SIZEOF(.multiboot2)
          + SIZEOF(.boot.text)
          + SIZEOF(.boot.bss);

    . = ALIGN(4096);

    __text_start = .;
    .text : AT(ADDR(.text) - KERNEL_VIRT + KERNEL_PHYS) {
        *(.text .text.*)
    }
    . = ALIGN(4096);
    __text_end = .;

    .rodata : AT(ADDR(.rodata) - KERNEL_VIRT + KERNEL_PHYS) {
        *(.rodata .rodata.*)
    }
    . = ALIGN(4096);

    /* Exception fixup table — walked by gp_fixup_find() at runtime.
     * Each entry is two s32 PC-relative offsets: {insn_rel, fixup_rel}.
     * Must be 4-byte aligned (struct ex_entry uses s32 fields).
     * __start___ex_table and __stop___ex_table are exported so
     * gp_fixup.c can iterate the array without a hardcoded size. */
    . = ALIGN(4);
    __start___ex_table = .;
    __ex_table : AT(ADDR(__ex_table) - KERNEL_VIRT + KERNEL_PHYS) {
        KEEP(*(__ex_table))
    }
    . = ALIGN(4);
    __stop___ex_table = .;

    /* Fixup handlers — jumped to by the CPU after a caught #GP.
     * Lives in an executable section so the recovered RIP is valid.
     * Placed after __ex_table so the linker resolves forward refs. */
    .fixup : AT(ADDR(.fixup) - KERNEL_VIRT + KERNEL_PHYS) {
        *(.fixup)
    }
    . = ALIGN(4096);

    .data : AT(ADDR(.data) - KERNEL_VIRT + KERNEL_PHYS) {
        *(.data .data.*)
    }
    . = ALIGN(4096);

    __bss_start = .;
    .bss (NOLOAD) : {
        *(.bss .bss.*)
        *(COMMON)
    }
    . = ALIGN(4096);
    __bss_end = .;

    /* Discard debug sections in release builds */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.debug*)
    }
}
