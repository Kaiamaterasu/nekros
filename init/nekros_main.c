#include <nekros/task.h>
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * init/nekros_main.c — Nekros kernel C entry point
 *
 * Called from arch/x86/boot/entry.S after long mode is active,
 * BSS is zeroed, and a 16KB boot stack is set up.
 *
 * Boot sequence:
 *   1. serial_init()          — COM1 console (all printk goes here)
 *   2. hal_init()             — IDT, APIC, CPU topology
 *   3. pmm_init() + map mem   — physical memory manager
 *   4. vmm_init()             — virtual memory + slab allocator
 *   5. vfs_init()             — VFS + ramfs root
 *   6. sched_init()           — CFS scheduler
 *   7. syscall_init()         — syscall table
 *   8. Machine fingerprint    — SHA-256 of hardware identity
 *   9. neri_module_init()     — Neri resource pool + UTB + NSM
 *  10. cc_proc_init()         — CortexCrypto kernel subsystem
 *  11. neri_ado_init()        — ADO dispatch orchestrator
 *  12. neri_nzra_init()       — NZRA cost engine
 *  13. neki_calib_init()      — Neki EMA optimizer
 *  14. Enable interrupts       — kernel is live
 *  15. Spawn init process      — PID 1 runs tools/init/init.c
 *  16. Idle loop               — schedule() forever
 *
 * Every subsystem prints its own init message to COM1.
 * Boot should complete in < 50ms on any modern x86-64 machine.
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include <nekros/sched.h>
#include "../arch/x86/hal/hal.h"
#include "../mm/pmm.h"
#include "../mm/vmm.h"
#include "../drivers/neri/include/neri.h"
#include "../drivers/neri/include/neri_sec.h"
#include "../drivers/neri/include/neri_utb.h"
#include "../drivers/neri/include/neri_nzra.h"
#include "../drivers/neri/include/neri_ado.h"
#include "../drivers/neri/include/neki_calib.h"
#include "../drivers/cortexcrypto/include/cc_proc.h"

/* ── Multiboot2 memory map parser ────────────────────────── */

#define MB2_TAG_MMAP      6
#define MB2_MMAP_AVAILABLE 1

struct mb2_tag {
    u32 type;
    u32 size;
};
struct mb2_mmap_entry {
    u64 base_addr;
    u64 length;
    u32 type;
    u32 reserved;
};
struct mb2_tag_mmap {
    u32 type;
    u32 size;
    u32 entry_size;
    u32 entry_version;
    /* entries follow */
};
struct mb2_info {
    u32 total_size;
    u32 reserved;
    /* tags follow */
};

static void parse_multiboot2(u32 mb2_phys,
                              u64 *total_ram_out,
                              phys_addr_t *bitmap_pa_out)
{
    struct mb2_info *info = (struct mb2_info *)phys_to_virt(mb2_phys);
    u64 total_ram = 0;

    /* First pass: find largest usable region for bitmap */
    phys_addr_t bitmap_pa = 0x200000ULL; /* default: 2MB */

    u8 *tag_ptr = (u8 *)info + 8;
    u8 *end_ptr = (u8 *)info + info->total_size;

    while (tag_ptr < end_ptr) {
        struct mb2_tag *tag = (struct mb2_tag *)tag_ptr;
        if (tag->type == 0) break; /* end tag */

        if (tag->type == MB2_TAG_MMAP) {
            struct mb2_tag_mmap *mmap = (struct mb2_tag_mmap *)tag;
            u8 *entry_ptr = (u8 *)mmap + sizeof(*mmap);
            u8 *mmap_end  = (u8 *)mmap + mmap->size;

            while (entry_ptr < mmap_end) {
                struct mb2_mmap_entry *e =
                    (struct mb2_mmap_entry *)entry_ptr;
                if (e->type == MB2_MMAP_AVAILABLE) {
                    total_ram += e->length;
                    /* Skip first 4MB (kernel + stack) */
                    if (e->base_addr >= 0x400000ULL) {
                        phys_addr_t bpa = ALIGN(e->base_addr, PAGE_SIZE);
                        /* Reserve space for bitmap: 1 bit per 4KB page */
                        u64 pages = e->length / PAGE_SIZE;
                        u64 bm_bytes = ALIGN(pages / 8 + 1, PAGE_SIZE);
                        if (bm_bytes < e->length)
                            pmm_add_region(bpa + bm_bytes, e->length - bm_bytes);
                        if (!bitmap_pa) bitmap_pa = bpa;
                    }
                }
                entry_ptr += mmap->entry_size;
            }
        }
        /* Advance to next tag (8-byte aligned) — guard against zero-size */
        u32 advance = ALIGN(tag->size, 8);
        if (advance < 8) advance = 8;  /* minimum tag size is 8 bytes */
        tag_ptr += advance;
    }

    *total_ram_out  = total_ram / PAGE_SIZE;
    *bitmap_pa_out  = bitmap_pa;

    pr_info("mb2: total RAM %llu MB across detected regions\n",
            total_ram / (1024 * 1024));
}

/* ── Machine fingerprint from hardware ───────────────────── */

static void compute_machine_fp(u8 fp[32])
{
    /*
     * SHA-256(CPUID.0:EBX||CPUID.0:ECX||CPUID.0:EDX
     *        ||CPUID.1:EAX||TSC_low32||"nekros-bind-v1")
     *
     * We use a simple hash chain here using the crypto layer.
     * The full DMI-based fingerprint is in cc_machine_id.c.
     */
    u8 buf[64];
    memset(buf, 0, sizeof(buf));

    u32 eax, ebx, ecx, edx;
    cpuid(0, 0, &eax, &ebx, &ecx, &edx);
    *(u32*)(buf+0)  = ebx;
    *(u32*)(buf+4)  = ecx;
    *(u32*)(buf+8)  = edx;

    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    *(u32*)(buf+12) = eax;

    u64 tsc = nekros_rdtsc();
    *(u32*)(buf+16) = (u32)(tsc & 0xFFFFFFFF);

    /* "nekros-bind-v1" */
    static const u8 tag[] = "nekros-bind-v1";
    memcpy(buf+20, tag, sizeof(tag)-1);

    /* SHA-256 via crypto layer */
    extern void sha256(const u8*, size_t, u8*);
    sha256(buf, sizeof(buf), fp);

    memzero_explicit(buf, sizeof(buf));
}

/* ── VFS init stub (full VFS in fs/) ────────────────────────── */
extern void vfs_init(void);

/* ── Init process entry ──────────────────────────────────── */
static void init_process(void *arg)
{
    (void)arg;
    pr_info("init: PID 1 starting\n");

    /* Declare intent: daemon (low-overhead background) */
    extern u64 nekros_syscall_dispatch(u64,u64,u64,u64,u64,u64);
    nekros_syscall_dispatch(40, 3, 0, 0, 0, 0); /* nk_proc_intent DAEMON */

    /* Pledge: allow only safe syscalls */
    u64 pledge_mask =
        (1ULL <<  0) |  /* read */
        (1ULL <<  1) |  /* write */
        (1ULL <<  2) |  /* exit */
        (1ULL << 17) |  /* yield */
        (1ULL << 20) |  /* getpid */
        (1ULL << 40) |  /* nk_proc_intent */
        (1ULL << 49) |  /* nk_neri_status */
        (1ULL << 52) |  /* nk_anomaly_score */
        (1ULL << 53) |  /* nk_pledge */
        (1ULL << 62) |  /* nk_set_name */
        (1ULL << 63);   /* nk_debug_log */
    nekros_syscall_dispatch(53, pledge_mask, 0, 0, 0, 0);

    pr_info("init: pledged. Nekros is running.\n");
    pr_info("\n");
    pr_info("  ███╗   ██╗███████╗██╗  ██╗██████╗  ██████╗ ███████╗\n");
    pr_info("  ████╗  ██║██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗██╔════╝\n");
    pr_info("  ██╔██╗ ██║█████╗  █████╔╝ ██████╔╝██║   ██║███████╗\n");
    pr_info("  ██║╚██╗██║██╔══╝  ██╔═██╗ ██╔══██╗██║   ██║╚════██║\n");
    pr_info("  ██║ ╚████║███████╗██║  ██╗██║  ██║╚██████╔╝███████║\n");
    pr_info("  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝\n");
    pr_info("\n");
    pr_info("  Secure developer kernel · Neri v0.5.0 · CortexCrypto\n");
    pr_info("  nk_proc_intent · nk_work_budget · nk_attest · "
            "nk_pledge · nk_thermal_hint\n\n");

    /* Idle loop — real init would exec a shell here */
    for (;;) {
        nekros_syscall_dispatch(17, 0, 0, 0, 0, 0); /* yield */
    }
}

/* ── Kernel main ─────────────────────────────────────────── */
void __noreturn nekros_main(u32 mb2_phys)
{
    /* 1. Serial console — must be first */
    extern void serial_init(void);
    serial_init();

    pr_info("\n=== Nekros kernel starting ===\n");
    pr_info("Neri v0.5.0 + CortexCrypto · built from scratch\n\n");

    /* 2. HAL: IDT, APIC, CPU detection */
    /* Write stack canary at the bottom of the boot stack FIRST — before
     * any complex C logic that could overflow it.  __boot_stack_bottom
     * is the lowest address of the .boot.bss stack region (defined in
     * nekros.ld).  hal_init() is the first function that calls deeply
     * into other subsystems; we must be protected before that point. */
    extern u64 __boot_stack_bottom;
    kstack_canary_write((virt_addr_t)&__boot_stack_bottom);

    hal_init();

    /* 3. Physical memory manager */
    u64 total_ram_pages;
    phys_addr_t bitmap_pa;

    /* Bootstrap: temporarily mark all RAM as available from 4MB up */
    /* Real map comes from Multiboot2 */
    /* Bitmap at 2MB — 1MB offset avoids the kernel image at ~1MB */
    pmm_init(0x200000ULL, 0x100000ULL); /* bitmap at 2MB, 1MB size */
    parse_multiboot2(mb2_phys, &total_ram_pages, &bitmap_pa);
    pr_info("pmm: %llu MB usable RAM\n",
            total_ram_pages * PAGE_SIZE / (1024*1024));

    /* 4. Virtual memory manager */
    /* Get PML4 from CR3 (set up by boot asm) */
    u64 cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    vmm_init((u64 *)cr3);

    /* 5. VFS */
    vfs_init();

    /* 6. Scheduler */
    sched_init();

    /* 7. Syscall table */
    syscall_init();

    /* 8. Machine fingerprint */
    u8 machine_fp[32];
    compute_machine_fp(machine_fp);
    pr_info("nekros: machine fingerprint %02x%02x%02x%02x...\n",
            machine_fp[0], machine_fp[1],
            machine_fp[2], machine_fp[3]);

    /* 9. Neri: resource pool + UTB + NSM */
    neri_module_init(machine_fp, total_ram_pages, g_ncpus, 256);

    /* 10. CortexCrypto kernel subsystem */
    cc_proc_init(machine_fp);

    /* 11. ADO + NZRA + Neki */
    neri_ado_init();
    neri_nzra_init();
    neki_calib_init(&g_neri_pool);

    /* Clear machine fingerprint from stack — it's in Neri/CC now */
    memzero_explicit(machine_fp, 32);

    /* 12. Enable interrupts */
    __asm__ volatile("sti");
    pr_info("\nnekros: all subsystems online. Enabling interrupts.\n\n");

    /* 13. Spawn PID 1 */
    /* Priority 8 (mid-range), 500µs CPU demand, 16 RAM pages for init */
    struct task *init = task_create("init", init_process, NULL, 8,
                                    500000ULL, 16ULL);
    if (IS_ERR(init))
        panic("nekros: failed to create init process: %lld\n",
              PTR_ERR(init));

    /* 14. Idle loop — schedule() forever */
    for (;;) {
        schedule();
        __asm__ volatile("hlt");  /* sleep until next interrupt */
    }
}

/* ── task_find_by_pid (used by ADO, attestation) ─────────── */
extern list_head_t all_tasks_list;

struct task *task_find_by_pid(pid_t pid)
{
    /* Simple linear scan — replace with hash table for production */
    struct task *t;
    list_for_each_entry(t, &all_tasks_list, all_tasks)
        if (t->pid == pid) return t;
    return NULL;
}

/* ── neri_module_init — starts all Neri subsystems ─────────── */
int neri_module_init(const u8 machine_fp[32],
                     u64 ram_pages, u32 ncpus, u32 gpu_slots)
{
    neri_pool_init(ram_pages, ncpus, gpu_slots);
    neri_utb_init();
    neri_sec_init(machine_fp);
    pr_info("neri: all subsystems initialised\n");
    return 0;
}

void neri_module_exit(void) { neri_sec_exit(); }
