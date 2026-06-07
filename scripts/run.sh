#!/usr/bin/env bash
# scripts/run.sh — Launch Nekros in QEMU
#
# Usage:
#   ./scripts/run.sh              — boot, serial to terminal
#   ./scripts/run.sh debug        — boot with GDB stub on :1234
#   ./scripts/run.sh iso          — boot from nekros.iso
#   ./scripts/run.sh serial-only  — no GUI, serial to terminal
#
# Requirements: qemu-system-x86_64
#   Debian/Ubuntu: sudo apt install qemu-system-x86
#   Arch:          sudo pacman -S qemu-system-x86
#   macOS:         brew install qemu

set -euo pipefail

K="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ELF="$K/build/nekros.elf"
ISO="$K/build/nekros.iso"

if [ ! -f "$ELF" ]; then
    echo "Error: $ELF not found. Run: make"
    exit 1
fi

# QEMU base flags
BASE=(
    qemu-system-x86_64
    -machine q35
    -cpu host,+rdrand,+rdseed              # expose RDRAND/RDSEED to kernel
    -m 512M
    -no-reboot
    -serial stdio                           # COM1 → terminal (all printk output)
    -display none                           # headless — use serial
    -monitor unix:"$K/build/qemu-monitor.sock",server,nowait
)

# Add QEMU KVM if available (much faster)
if [ -e /dev/kvm ] && [ -r /dev/kvm ]; then
    BASE+=(-enable-kvm)
    echo "KVM acceleration enabled"
fi

MODE="${1:-run}"

case "$MODE" in
    debug)
        echo "Starting Nekros with GDB stub on :1234"
        echo "Connect with:"
        echo "  gdb $ELF"
        echo "  (gdb) target remote :1234"
        echo "  (gdb) break nekros_main"
        echo "  (gdb) break neri_pool_init"
        echo "  (gdb) break cc_proc_init"
        echo "  (gdb) continue"
        "${BASE[@]}" \
            -kernel "$ELF" \
            -s -S &               # -s = :1234, -S = wait for debugger
        QEMU_PID=$!
        echo "QEMU PID: $QEMU_PID"
        gdb -q "$ELF" \
            -ex "target remote :1234" \
            -ex "break nekros_main" \
            -ex "break neri_pool_init" \
            -ex "break cc_proc_init" \
            -ex "break neri_nzra_decide" \
            -ex "continue"
        ;;
    iso)
        if [ ! -f "$ISO" ]; then
            echo "Error: $ISO not found. Run: make iso"
            exit 1
        fi
        echo "Booting Nekros from ISO..."
        "${BASE[@]}" -cdrom "$ISO"
        ;;
    serial-only)
        echo "Booting Nekros (serial only, Ctrl+A X to exit)..."
        "${BASE[@]}" -kernel "$ELF" -append "console=ttyS0"
        ;;
    run|*)
        echo "Booting Nekros (Ctrl+A X to exit QEMU serial)..."
        echo ""
        echo "Expected boot sequence:"
        echo "  1. Multiboot2 handoff"
        echo "  2. HAL init (IDT, APIC, CPU detection)"
        echo "  3. PMM + VMM init"
        echo "  4. Neri pool + UTB + NSM init"
        echo "  5. CortexCrypto kernel bridge"
        echo "  6. PID 1 (init) running"
        echo "  7. Nekros banner on COM1"
        echo ""
        "${BASE[@]}" -kernel "$ELF"
        ;;
esac
