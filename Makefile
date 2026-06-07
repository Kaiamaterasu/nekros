# SPDX-License-Identifier: GPL-2.0
# Nekros kernel master Makefile
#
# Usage:
#   make              — build nekros.iso (bootable with GRUB2/QEMU)
#   make run          — boot in QEMU (serial output to terminal)
#   make run-debug    — boot in QEMU with GDB stub on :1234
#   make clean        — remove build artefacts
#   make size         — show kernel image section sizes
#
# Requirements:
#   x86_64-elf-gcc  (cross compiler) or gcc with -m64 -ffreestanding
#   x86_64-elf-ld   or ld with appropriate flags
#   nasm or as      (GNU assembler)
#   grub-mkrescue   (for ISO generation)
#   qemu-system-x86_64 (for testing)

# ── Toolchain ────────────────────────────────────────────────
CC      := gcc
AS      := gcc   # use gcc for .S files (handles -m64 properly)
LD      := ld
OBJCOPY := objcopy

ARCH    := x86_64

# ── Directories ──────────────────────────────────────────────
K       := .
BUILD   := $(K)/build
ISO_DIR := $(BUILD)/iso
BOOT_DIR:= $(ISO_DIR)/boot/grub

# ── Compiler flags ────────────────────────────────────────────
CFLAGS := \
    -std=gnu11              \
    -m64                    \
    -ffreestanding          \
    -fno-builtin            \
    -fno-stack-protector    \
    -fno-pie                \
    -fno-pic                \
    -mno-red-zone           \
    -mno-mmx                \
    -mno-sse                \
    -mno-sse2               \
    -mcmodel=kernel         \
    -O2                     \
    -Wall                   \
    -Wextra                 \
    -Wno-unused-parameter   \
    -Wno-sign-compare       \
    -I$(K)/include          \
    -I$(K)/drivers/neri/include \
    -I$(K)/drivers/cortexcrypto/include \
    -I$(K)/arch/x86/hal     \
    -I$(K)/arch/x86/boot    \
    -I$(K)/mm               \
    -DNEKROS_KERNEL=1

# ASM flags (for .S files)
ASFLAGS := \
    -m64                    \
    -ffreestanding          \
    -fno-pie                \
    -fno-pic                \
    -I$(K)/arch/x86/boot

# Linker flags
LDFLAGS := \
    -T $(K)/scripts/nekros.ld   \
    -nostdlib                   \
    -z max-page-size=0x1000     \
    --no-dynamic-linker

# ── Source files ──────────────────────────────────────────────

# Boot + HAL (ASM first so entry point is at the start)
ASM_SRCS := \
    $(K)/arch/x86/boot/entry.S          \
    $(K)/arch/x86/kernel/isr_stubs.S    \
    $(K)/arch/x86/kernel/sched_asm.S

# Core C sources
C_SRCS := \
    $(K)/kernel/printk.c                \
    $(K)/kernel/sched.c                 \
    $(K)/kernel/syscall.c               \
    $(K)/arch/x86/hal/hal.c             \
    $(K)/mm/pmm.c                       \
    $(K)/mm/vmm.c                       \
    $(K)/fs/vfs.c                       \
    $(K)/init/nekros_main.c             \
    $(K)/crypto/sha256.c                \
    $(K)/crypto/aes_gcm.c               \
    $(K)/ipc/ipc.c

# Neri subsystem
NERI_SRCS := \
    $(K)/drivers/neri/core/neri_pool.c  \
    $(K)/drivers/neri/core/neri_utb.c   \
    $(K)/drivers/neri/core/neri_sec.c   \
    $(K)/drivers/neri/core/neri_nzra.c  \
    $(K)/drivers/neri/core/neri_ado.c   \
    $(K)/drivers/neri/neki/neki_loop.c

# CortexCrypto subsystem
CORTEX_SRCS := \
    $(K)/drivers/cortexcrypto/core/aes256.c     \
    $(K)/drivers/cortexcrypto/core/cc_proc.c

ALL_SRCS := $(ASM_SRCS) $(C_SRCS) $(NERI_SRCS) $(CORTEX_SRCS)

# ── Object files ──────────────────────────────────────────────
ASM_OBJS := $(patsubst $(K)/%.S, $(BUILD)/%.o, $(ASM_SRCS))
C_OBJS   := $(patsubst $(K)/%.c, $(BUILD)/%.o, \
             $(C_SRCS) $(NERI_SRCS) $(CORTEX_SRCS))
ALL_OBJS := $(ASM_OBJS) $(C_OBJS)

KERNEL_ELF := $(BUILD)/nekros.elf
KERNEL_BIN := $(BUILD)/nekros.bin
KERNEL_ISO := $(BUILD)/nekros.iso

# ── Default target ─────────────────────────────────────────────
.PHONY: all run run-debug clean size install-tools

all: $(KERNEL_ISO)
	@echo ""
	@echo "  ╔══════════════════════════════════════╗"
	@echo "  ║  Nekros kernel build complete!       ║"
	@echo "  ║  Image: $(KERNEL_ISO)"
	@echo "  ║  Run:   make run                     ║"
	@echo "  ╚══════════════════════════════════════╝"

# ── Compile ASM ────────────────────────────────────────────────
$(BUILD)/%.o: $(K)/%.S
	@mkdir -p $(dir $@)
	@echo "  AS    $<"
	@$(AS) $(ASFLAGS) -c $< -o $@

# ── Compile C ──────────────────────────────────────────────────
$(BUILD)/%.o: $(K)/%.c
	@mkdir -p $(dir $@)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# ── Link ───────────────────────────────────────────────────────
$(KERNEL_ELF): $(ALL_OBJS) $(K)/scripts/nekros.ld
	@mkdir -p $(BUILD)
	@echo "  LD    $@"
	@$(LD) $(LDFLAGS) $(ALL_OBJS) -o $@

# ── Strip to binary ────────────────────────────────────────────
$(KERNEL_BIN): $(KERNEL_ELF)
	@$(OBJCOPY) -O binary $< $@
	@echo "  BIN   $@ ($(shell wc -c < $@) bytes)"

# ── Bootable ISO with GRUB2 ────────────────────────────────────
$(KERNEL_ISO): $(KERNEL_ELF)
	@mkdir -p $(BOOT_DIR)
	@cp $(KERNEL_ELF) $(ISO_DIR)/boot/nekros.elf
	@cat > $(BOOT_DIR)/grub.cfg << 'GRUBCFG'
set timeout=3
set default=0

menuentry "Nekros — Secure Developer Kernel" {
    multiboot2 /boot/nekros.elf
    boot
}

menuentry "Nekros (serial debug)" {
    multiboot2 /boot/nekros.elf debug
    boot
}
GRUBCFG
	@grub-mkrescue -o $@ $(ISO_DIR) 2>/dev/null || \
	 grub2-mkrescue -o $@ $(ISO_DIR) 2>/dev/null || \
	 (echo "  NOTE: grub-mkrescue not found — ELF is ready, create ISO manually"; exit 0)
	@echo "  ISO   $@"

# ── Run in QEMU ────────────────────────────────────────────────
QEMU_FLAGS := \
    -machine q35             \
    -cpu host                \
    -m 512M                  \
    -serial stdio            \
    -display none            \
    -no-reboot               \
    -d int,cpu_reset

run: $(KERNEL_ELF)
	@echo "  Booting Nekros in QEMU (Ctrl+A X to exit)..."
	qemu-system-x86_64 $(QEMU_FLAGS) \
	    -kernel $(KERNEL_ELF) \
	    -append "console=ttyS0"

run-iso: $(KERNEL_ISO)
	qemu-system-x86_64 $(QEMU_FLAGS) -cdrom $(KERNEL_ISO)

run-debug: $(KERNEL_ELF)
	@echo "  Starting QEMU with GDB stub on :1234"
	@echo "  In another terminal: gdb build/nekros.elf"
	@echo "    (gdb) target remote :1234"
	@echo "    (gdb) break nekros_main"
	@echo "    (gdb) continue"
	qemu-system-x86_64 $(QEMU_FLAGS) \
	    -kernel $(KERNEL_ELF) \
	    -s -S

# ── Size report ────────────────────────────────────────────────
size: $(KERNEL_ELF)
	@echo ""
	@echo "Nekros kernel section sizes:"
	@size $(KERNEL_ELF)
	@echo ""
	@echo "Symbol count:"
	@nm $(KERNEL_ELF) | wc -l
	@echo ""
	@echo "Top 10 largest symbols:"
	@nm --size-sort $(KERNEL_ELF) | tail -10

# ── Clean ──────────────────────────────────────────────────────
clean:
	@rm -rf $(BUILD)
	@echo "  Cleaned build directory"

# ── Install cross-compiler (one-time setup) ───────────────────
install-tools:
	@echo "Installing build dependencies..."
	apt-get install -y build-essential gcc binutils nasm \
	    grub-common grub-pc-bin xorriso qemu-system-x86 \
	    gdb 2>/dev/null || \
	    (echo "Please install: gcc binutils grub-mkrescue xorriso qemu-system-x86_64")
