# Nekros — Secure Developer Kernel

A complete x86-64 operating system kernel built from scratch.
Integrates **Neri v0.5.0** (unified resource intelligence) and
**CortexCrypto** (neural-augmented encryption) as first-class kernel
subsystems — not patches, not modules, but part of the core design.

---

## What makes Nekros different from Linux

### 24 syscalls that don't exist in any other kernel

| Syscall | What it does | Why Linux doesn't have it |
|---------|-------------|--------------------------|
| `nk_proc_intent` | Process declares semantic intent (COMPILE, ML_TRAIN, CRYPTO, etc.) | Linux uses static priority; Neri uses this to optimally place the process immediately |
| `nk_work_budget` | Request a guaranteed `cpu_ns` budget within a `deadline_ns` | No kernel has temporal CPU guarantees for user processes |
| `nk_attest_self` | Get a CortexCrypto-sealed process identity token | Zero-trust process auth without a CA, built into the kernel |
| `nk_attest_peer` | Verify another process's identity cryptographically | Peers verify without trusting the claiming process |
| `nk_secure_alloc` | Allocate AES-256-GCM encrypted memory pages | Memory at rest is ciphertext; DEK managed by kernel |
| `nk_ipc_channel` | Zero-trust encrypted IPC between processes | Data in kernel ring buffer is AES-256-GCM; root cannot intercept |
| `nk_thermal_hint` | Hint an upcoming compute burst so Neri pre-adjusts RAPL | Linux reacts to thermal throttling *after* it degrades perf; Nekros prevents it |
| `nk_anomaly_score` | Read the live NSM behavioral anomaly score | No kernel exposes a real-time behavioral threat score |
| `nk_pledge` | Irreversible syscall whitelist (stronger than seccomp) | Zero runtime overhead; no BPF required |
| `nk_mem_snapshot` | AES-256-GCM snapshot of a process's own memory | Sealed, tamper-evident, machine-bound memory states |
| `nk_checkpoint` | Lightweight sealed process checkpoint | Smaller and faster than CRIU; cryptographically sealed |

### Neri resource intelligence (built-in, not bolted on)

The Neri pool is not a kernel module — it's called at every scheduler tick,
every fork, every exit. The `neri_proc_t` is embedded in `struct task`.

- **UTB**: reads Intel HFI / RAPL / APERF/MPERF every epoch
- **NZRA**: computes `C = α·E + β·ARG + γ·L` to pick P-core vs E-core
- **ADO**: applies placement decisions, adjusts RAPL pre-burst
- **Neki**: EMA optimizer tunes α/β/γ weights every 640ms based on observed waste
- **NSM**: 12-feature behavioral model; scales CortexCrypto KDF cost under threat

### CortexCrypto security layer

AES-256-GCM with HMAC-SHA256 key derivation wired into the kernel from boot:

- Machine fingerprint at `SHA-256(machine_id || cpu_model || dmi_uuid)` — available at `/proc/cortexcrypto/machine_id`
- Every process attestation token is `AES-256-GCM{pid, exe_hash, resource_grant, anomaly_score}`
- IPC session keys derived from both processes' attestation tokens
- NSM anomaly score → cortexd KDF cost scaling (NORMAL → base, MEDIUM → ×1.5, HIGH → ×3.0, CRITICAL → block)

---

## Build

```bash
# Requirements: gcc, ld (GNU binutils)
make

# Result: build/nekros.elf (Multiboot2 x86-64 ELF, ~110KB)
```

## Boot (QEMU)

```bash
# Install QEMU first:
# Ubuntu: sudo apt install qemu-system-x86
# macOS:  brew install qemu

chmod +x scripts/run.sh
./scripts/run.sh          # serial output to terminal

# Debug with GDB:
./scripts/run.sh debug
# In the GDB prompt:
#   break nekros_main
#   break neri_nzra_decide
#   continue
```

## Boot (real hardware / USB)

```bash
# Create bootable ISO (requires grub-mkrescue + xorriso):
make iso

# Write to USB:
sudo dd if=build/nekros.iso of=/dev/sdX bs=4M status=progress

# Or install ELF to an existing GRUB2 partition:
sudo cp build/nekros.elf /boot/nekros.elf
# Add the entry from scripts/grub.cfg to /boot/grub/grub.cfg
sudo update-grub
```

---

## Kernel source layout

```
nekros/
├── arch/x86/
│   ├── boot/entry.S          32→64 bit mode switch, Multiboot2 header
│   ├── hal/hal.c             IDT, APIC, CPUID, MSR, SMP topology
│   └── kernel/
│       ├── isr_stubs.S       256 interrupt stubs
│       └── sched_asm.S       __switch_to context switch
├── mm/
│   ├── pmm.c                 Binary buddy physical allocator
│   └── vmm.c                 4-level PML4 VMM + slab allocator
├── kernel/
│   ├── printk.c              COM1 serial + VGA text output
│   ├── sched.c               CFS scheduler with Neri integration
│   ├── syscall.c             64 syscalls (40 POSIX + 24 Nekros-unique)
│   └── glue.c                Symbol bridge between subsystems
├── fs/vfs.c                  ramfs + devfs + procfs
├── init/nekros_main.c        C kernel entry point, boot sequence
├── lib/string.c              memset/memcpy/memmove/memcmp
├── drivers/
│   ├── neri/
│   │   ├── core/
│   │   │   ├── neri_pool.c   Unified CPU/RAM/GPU resource pool
│   │   │   ├── neri_utb.c    Universal Telemetry Bus (HFI/RAPL/MSR)
│   │   │   ├── neri_sec.c    Security Module (NSM, anomaly scoring)
│   │   │   ├── neri_nzra.c   Cost engine (α·E + β·ARG + γ·L)
│   │   │   └── neri_ado.c    Autonomous Dispatch Orchestrator
│   │   └── neki/neki_loop.c  EMA self-learning weight optimizer
│   └── cortexcrypto/
│       └── core/
│           ├── aes256.c      AES-256-GCM (no external dependencies)
│           └── cc_proc.c     Process attestation, encrypted memory,
│                              zero-trust IPC, checkpointing
├── tools/
│   ├── nerictl/nerictl.c     Developer control CLI
│   ├── cortexcrypt/          Encryption CLI
│   └── init/init.c           PID 1
└── scripts/
    ├── nekros.ld             Linker script
    ├── grub.cfg              GRUB2 boot menu
    └── run.sh                QEMU launch script
```

---

## Expected boot output (COM1 serial)

```
=== Nekros kernel starting ===
Neri v0.5.0 + CortexCrypto · built from scratch

hal: CPU GenuineIntel family 6 model 142 stepping 10 TSC 2400 MHz HFI=1
hal: 4 logical CPU(s) detected
hal: initialised — IDT loaded, APIC online
pmm: 488 MB usable RAM across detected regions
vmm: initialised PML4=... slab caches 8 sizes
vfs: ramfs mounted at /
vfs: /dev/neri  /dev/null  /dev/zero  /dev/tty0
vfs: /proc/neri/status  /proc/cortexcrypto/machine_id
sched: CFS scheduler initialised, 16 priority bands
syscall: 64 entries loaded — 24 Nekros-unique calls active
nekros: machine fingerprint 3a7f2b1c...
neri: pool init — CPU 40000000 ns/epoch RAM 124928 pages GPU 256 slots
neri: v0.5.0 ready
neri-utb: online — RAPL unit=61 mJ/unit HFI=yes
neri-nzra: cost engine online α=β=γ=1.0 (Neki will tune)
neri-ado: dispatch orchestrator online (ring=256, interval=5 ms)
neki: self-learning EMA optimizer calibrated — window=64 epochs, α=3/64
cc_proc: CortexCrypto kernel subsystem ready
cc_proc: attest + secure_alloc + zero-trust IPC + checkpoint online
nekros: all subsystems online. Enabling interrupts.

███╗   ██╗███████╗██╗  ██╗██████╗  ██████╗ ███████╗
████╗  ██║██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗██╔════╝
██╔██╗ ██║█████╗  █████╔╝ ██████╔╝██║   ██║███████╗
██║╚██╗██║██╔══╝  ██╔═██╗ ██╔══██╗██║   ██║╚════██║
██║ ╚████║███████╗██║  ██╗██║  ██║╚██████╔╝███████║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝

  Secure developer kernel · Neri v0.5.0 · CortexCrypto
  nk_proc_intent · nk_work_budget · nk_attest · nk_pledge · nk_thermal_hint

init: PID 1 ready. Waiting for kernel events...
```

---

## License

- Kernel core, Neri integration: GPL-2.0
- CortexCrypto subsystem: Dual GPL-2.0 / Apache-2.0
- AES-256-GCM implementation: GPL-2.0 / Apache-2.0
- Tools (nerictl, cortexcrypt, init): GPL-2.0
