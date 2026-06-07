# Nekros kernel master Makefile
# Ensure all lines starting with @, $(CC), $(LD), or $(AS) are indented with a HARD TAB.

CC      := gcc
AS      := gcc
LD      := ld
OBJCOPY := objcopy

ARCH    := x86_64
K       := .
BUILD   := $(K)/build
ISO_DIR := $(BUILD)/iso
BOOT_DIR:= $(ISO_DIR)/boot/grub

# Compilation Flags
CFLAGS   := -std=gnu11 -m64 -ffreestanding -fno-builtin -fno-stack-protector -fno-pie -fno-pic -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -mcmodel=kernel -O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -I$(K)/include -I$(K)/drivers/neri/include -I$(K)/drivers/cortexcrypto/include -I$(K)/arch/x86/hal -I$(K)/arch/x86/boot -I$(K)/mm -DNEKROS_KERNEL=1
ASFLAGS  := -m64 -ffreestanding -fno-pie -fno-pic -I$(K)/arch/x86/boot
LDFLAGS  := -T $(K)/scripts/nekros.ld -nostdlib -z max-page-size=0x1000 --no-dynamic-linker

# Source Management
ASM_SRCS := $(wildcard $(K)/arch/x86/boot/*.S) $(wildcard $(K)/arch/x86/kernel/*.S)
C_SRCS   := $(wildcard $(K)/kernel/*.c) $(wildcard $(K)/mm/*.c) $(wildcard $(K)/fs/*.c) $(wildcard $(K)/init/*.c) $(wildcard $(K)/crypto/*.c) $(wildcard $(K)/ipc/*.c) $(wildcard $(K)/drivers/neri/core/*.c) $(wildcard $(K)/drivers/neri/neki/*.c) $(wildcard $(K)/drivers/cortexcrypto/core/*.c)

ALL_OBJS := $(patsubst $(K)/%.S, $(BUILD)/%.o, $(ASM_SRCS)) $(patsubst $(K)/%.c, $(BUILD)/%.o, $(C_SRCS))
KERNEL_ELF := $(BUILD)/nekros.elf
KERNEL_ISO := $(BUILD)/nekros.iso

.PHONY: all run clean

all: $(KERNEL_ISO)

$(BUILD)/%.o: $(K)/%.S
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -c $< -o $@

$(BUILD)/%.o: $(K)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(KERNEL_ELF): $(ALL_OBJS)
	@mkdir -p $(BUILD)
	$(LD) $(LDFLAGS) $(ALL_OBJS) -o $@

$(KERNEL_ISO): $(KERNEL_ELF)
	@mkdir -p $(BOOT_DIR)
	@cp $(KERNEL_ELF) $(ISO_DIR)/boot/nekros.elf
	@echo 'set timeout=3' > $(BOOT_DIR)/grub.cfg
	@echo 'set default=0' >> $(BOOT_DIR)/grub.cfg
	@echo 'menuentry "Nekros" {' >> $(BOOT_DIR)/grub.cfg
	@echo '    multiboot2 /boot/nekros.elf' >> $(BOOT_DIR)/grub.cfg
	@echo '    boot' >> $(BOOT_DIR)/grub.cfg
	@echo '}' >> $(BOOT_DIR)/grub.cfg
	grub-mkrescue -o $@ $(ISO_DIR) 2>/dev/null || grub2-mkrescue -o $@ $(ISO_DIR)

run: $(KERNEL_ELF)
	qemu-system-x86_64 -machine q35 -cpu host -m 512M -serial stdio -display none -no-reboot -d int,cpu_reset -kernel $(KERNEL_ELF) -append "console=ttyS0"

clean:
	@rm -rf $(BUILD)
