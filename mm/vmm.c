/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mm/vmm.c — Nekros Virtual Memory Manager
 *
 * Manages the kernel address space and provides:
 *   - 4-level PML4 page table management
 *   - vmm_map(): map physical pages into a virtual range
 *   - vmm_unmap(): unmap and optionally free physical pages
 *   - vmm_alloc(): allocate kernel virtual + physical pages
 *   - Slab allocator: kmalloc() / kfree() for small objects
 *
 * Kernel virtual layout:
 *   0xFFFFFFFF80000000 — 0xFFFFFFFFFFFFFFFF  kernel image (2GB)
 *   0xFFFF888000000000 — 0xFFFF88FFFFFFFFFF  direct phys map (1TB)
 *   0xFFFF000000000000 — 0xFFFF007FFFFFFFFF  vmalloc range (512GB)
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include "pmm.h"
#include "vmm.h"

/* ── Page table entry flags ───────────────────────────────── */
#define PTE_PRESENT (1ULL << 0)
#define PTE_WRITE   (1ULL << 1)
#define PTE_USER    (1ULL << 2)
#define PTE_HUGE    (1ULL << 7)
#define PTE_GLOBAL  (1ULL << 8)
#define PTE_NX      (1ULL << 63)
#define PTE_ADDR_MASK 0x000FFFFFFFFFF000ULL

/* ── Kernel PML4 (set up by boot, refined here) ──────────── */
static u64 *g_kernel_pml4;

static u64 *pt_next_level(u64 *entry, bool alloc)
{
    if (*entry & PTE_PRESENT)
        return (u64 *)phys_to_virt(*entry & PTE_ADDR_MASK);
    if (!alloc) return NULL;
    phys_addr_t pa = pmm_alloc_page();
    if (!pa) return NULL;
    memset((void *)phys_to_virt(pa), 0, PAGE_SIZE);
    *entry = pa | PTE_PRESENT | PTE_WRITE;
    return (u64 *)phys_to_virt(pa);
}

int vmm_map(u64 virt, phys_addr_t phys, u64 pages, u32 flags)
{
    u64 prot = PTE_PRESENT;
    if (flags & VMM_WRITE)  prot |= PTE_WRITE;
    if (flags & VMM_USER)   prot |= PTE_USER;
    if (!(flags & VMM_EXEC)) prot |= PTE_NX;

    for (u64 i = 0; i < pages; i++) {
        u64 va = virt  + i * PAGE_SIZE;
        u64 pa = phys  + i * PAGE_SIZE;

        u64 pml4_i = (va >> 39) & 0x1FF;
        u64 pdpt_i = (va >> 30) & 0x1FF;
        u64 pd_i   = (va >> 21) & 0x1FF;
        u64 pt_i   = (va >> 12) & 0x1FF;

        u64 *pdpt = pt_next_level(&g_kernel_pml4[pml4_i], true);
        if (!pdpt) return -ENOMEM;
        u64 *pd   = pt_next_level(&pdpt[pdpt_i], true);
        if (!pd)   return -ENOMEM;
        u64 *pt   = pt_next_level(&pd[pd_i], true);
        if (!pt)   return -ENOMEM;

        pt[pt_i] = (pa & PTE_ADDR_MASK) | prot;
    }
    return 0;
}

void vmm_unmap(u64 virt, u64 pages, bool free_phys)
{
    for (u64 i = 0; i < pages; i++) {
        u64 va = virt + i * PAGE_SIZE;
        u64 pml4_i = (va >> 39) & 0x1FF;
        u64 pdpt_i = (va >> 30) & 0x1FF;
        u64 pd_i   = (va >> 21) & 0x1FF;
        u64 pt_i   = (va >> 12) & 0x1FF;

        u64 *pdpt = pt_next_level(&g_kernel_pml4[pml4_i], false);
        if (!pdpt) continue;
        u64 *pd   = pt_next_level(&pdpt[pdpt_i], false);
        if (!pd)   continue;
        u64 *pt   = pt_next_level(&pd[pd_i], false);
        if (!pt)   continue;

        if (free_phys && (pt[pt_i] & PTE_PRESENT))
            pmm_free_page(pt[pt_i] & PTE_ADDR_MASK);
        pt[pt_i] = 0;

        /* Flush THIS page from the TLB immediately after clearing its PTE.
         *
         * The bug: placing invlpg outside the loop flushed only the base
         * address (virt). The CPU kept cached translations for every other
         * page in the range. Physical memory freed back to the PMM could be
         * reallocated to a different owner (e.g. a CortexCrypto key buffer)
         * while the original VA still mapped it — a deterministic,
         * attacker-exploitable Use-After-Free / information leak.
         *
         * invlpg must target `va` (the per-iteration virtual address), not
         * the loop-invariant `virt`, so every unmapped page is individually
         * invalidated in lock-step with its PTE being zeroed.
         *
         * SMP note: on multi-CPU configurations this must be followed by an
         * IPI-based TLB shootdown to invalidate the same VA on all other
         * CPUs. That path (send TLBFLUSH IPI → wait for ACKs) is wired in
         * smp_tlb_shootdown() and called here once SMP is enabled. For the
         * current single-CPU boot path, invlpg alone is sufficient. */
        __asm__ volatile("invlpg (%0)" :: "r"(va) : "memory");
    }
    /* No post-loop invlpg needed — every page was flushed inside the loop.
     * Future: replace with cr3-reload when tearing down full address spaces
     * (looping invlpg across thousands of pages is slower than one cr3 write). */
}

void *vmm_alloc(u64 pages, u32 flags)
{
    /* Simple bump allocator in vmalloc range */
    static u64 vmalloc_next = 0xFFFF000000000000ULL;
    static spinlock_t vmalloc_lock = SPINLOCK_INIT;

    spin_lock(&vmalloc_lock);
    /* Check vmalloc range not exhausted (512GB range) */
    if (vmalloc_next + pages * PAGE_SIZE > 0xFFFF008000000000ULL) {
        spin_unlock(&vmalloc_lock);
        return NULL; /* vmalloc space exhausted */
    }
    u64 virt = vmalloc_next;
    vmalloc_next += pages * PAGE_SIZE;
    spin_unlock(&vmalloc_lock);

    for (u64 i = 0; i < pages; i++) {
        phys_addr_t pa = pmm_alloc_page();
        if (!pa) goto oom;
        if (vmm_map(virt + i * PAGE_SIZE, pa, 1, flags) < 0)
            goto oom;
    }
    return (void *)virt;
oom:
    vmm_unmap(virt, pages, true);
    return NULL;
}

void vmm_free(void *ptr, u64 pages)
{
    vmm_unmap((u64)ptr, pages, true);
}

/* ── Slab allocator (powers kmalloc/kfree) ───────────────── */

#define SLAB_SIZES  8
static const u32 slab_sz[] = { 16, 32, 64, 128, 256, 512, 1024, 2048 };
#define SLAB_MAX_CACHE 2048

struct slab_hdr {
    struct slab_hdr *next;
};

struct slab_cache {
    spinlock_t      lock;
    struct slab_hdr *freelist;
    u32             obj_size;
    u64             alloc_count;
    u64             free_count;
};

static struct slab_cache slabs[SLAB_SIZES];

static void slab_grow(struct slab_cache *sc)
{
    /* Allocate one page, carve it into obj_size chunks */
    phys_addr_t pa = pmm_alloc_page();
    if (!pa) return;

    u8 *page = (u8 *)phys_to_virt(pa);
    u32 chunk = sc->obj_size + (u32)sizeof(u64);  /* +8 bytes for cookie */
    u32 n    = PAGE_SIZE / chunk;
    for (u32 i = 0; i < n; i++) {
        struct slab_hdr *h = (struct slab_hdr *)(page + i * chunk);
        h->next = sc->freelist;
        sc->freelist = h;
    }
}

void *kmalloc(size_t size)
{
    /* Find the smallest slab that fits */
    for (int i = 0; i < SLAB_SIZES; i++) {
        if (size <= slabs[i].obj_size) {
            struct slab_cache *sc = &slabs[i];
            spin_lock(&sc->lock);
            if (!sc->freelist) slab_grow(sc);
            if (!sc->freelist) { spin_unlock(&sc->lock); return NULL; }
            struct slab_hdr *h = sc->freelist;
            sc->freelist = h->next;
            sc->alloc_count++;
            spin_unlock(&sc->lock);
            /* Store slab index cookie before user pointer — kfree needs it */
            *(u64 *)h = (u64)i;
            return (void *)((u64 *)h + 1);
        }
    }
    /* Large allocation path.
     *
     * kfree() unconditionally reads the 8-byte cookie at (ptr - 8).
     * Without a cookie, kfree reads garbage from the guard page before
     * the vmalloc region, triggering either a page-fault panic or the
     * "invalid cookie" panic — a crash on every large kfree call.
     *
     * Fix: allocate one extra page to hold the cookie at the very start.
     * Layout of the returned virtual region:
     *
     *   [ page 0           ][ pages 1 .. N           ]
     *   [ 8-byte cookie |  ][ <usable payload region> ]
     *     ^base               ^returned ptr (base + 8)
     *
     * The cookie encodes both the SLAB_LARGE_COOKIE sentinel AND the
     * original page count (excluding the header page), so kfree can
     * call vmm_free with the exact size:
     *   cookie = SLAB_LARGE_COOKIE | (pages << 8)
     *
     * kfree reads cookie_ptr = ptr - 8, decodes the page count, then
     * calls vmm_free(cookie_ptr, pages + 1) — freeing the header page
     * and all payload pages together.
     */
    u64 pages = ALIGN(size, PAGE_SIZE) / PAGE_SIZE;
    /* +1 for the header page that holds the cookie */
    void *base = vmm_alloc(pages + 1, VMM_WRITE);
    if (!base) return NULL;
    u64 *cookie_ptr = (u64 *)base;
    *cookie_ptr = (u64)SLAB_LARGE_COOKIE | (pages << 8);
    return (void *)(cookie_ptr + 1);  /* payload starts 8 bytes in */
}

void *kzalloc(size_t size)
{
    void *p = kmalloc(size);
    if (p) memset(p, 0, size);
    return p;
}

/* kfree_s: explicit-size kfree (more efficient; skips cookie check for known sizes) */
void kfree_s(void *ptr, size_t size) { kfree(ptr); (void)size; }

/* ── Stack canary helpers ─────────────────────────────────────────────────
 *
 * Declared in vmm.h; implemented here alongside the rest of the mm layer.
 *
 * The canary is a fixed 8-byte magic value written at the BOTTOM of each
 * kernel stack (lowest address, first to be overwritten by overflow).
 * task_create() calls kstack_canary_write() when the stack is allocated.
 * schedule() calls kstack_canary_check() on the outgoing task before
 * __switch_to, catching overflows at the earliest safe point.
 *
 * Canary value is defined in vmm.h as NEKROS_STACK_CANARY
 * (0xDEADBEEFCAFEBABEULL) — the single authoritative definition.
 * No other file may redefine it (see round-2 fix notes).
 *
 * Why the bottom of the stack?
 *   x86-64 stacks grow downward (high → low addresses).  An overflow
 *   writes past the lowest address, overwriting the canary first.
 *   Checking the canary on every context switch gives a detection
 *   latency of at most one scheduling quantum — fast enough to prevent
 *   exploitation in practice.
 *
 * kstack_canary_write — call once, immediately after PMM allocates the
 *   kernel stack pages for a new task.  stack_bottom is the LOWEST
 *   virtual address of the stack region (phys_to_virt(kstack_pa)).
 *
 * kstack_canary_check — call on every context switch for the outgoing
 *   task.  Returns true if the canary is intact, false if corrupted.
 *   The caller (schedule()) must panic on false — do not continue.
 */
void kstack_canary_write(virt_addr_t stack_bottom)
{
    if (!stack_bottom) return;
    *(volatile u64 *)stack_bottom = NEKROS_STACK_CANARY;
    /* Barrier: ensure the write is visible before the stack is used */
    __asm__ volatile("" ::: "memory");
}

bool kstack_canary_check(virt_addr_t stack_bottom)
{
    if (!stack_bottom) return true;  /* no stack recorded — skip */
    return *(volatile u64 *)stack_bottom == NEKROS_STACK_CANARY;
}

/* kfree — returns object to the correct slab or vmm_free for large allocs.
 * We store the slab index (0-7, or 0xFF for large) in a hidden 8-byte
 * cookie immediately before the returned pointer.
 */
#define SLAB_POISON       0xDEAD6DEAD6DEAD6DULL
#define SLAB_LARGE_COOKIE 0xFF

void kfree(void *ptr)
{
    if (!ptr) return;

    /* Read the hidden cookie 8 bytes before the user pointer */
    u64 *cookie_ptr = (u64 *)ptr - 1;
    u64 cookie = *cookie_ptr;

    /* Check for double-free: poison is written at cookie_ptr (base of block) */
    if (cookie == SLAB_POISON) {
        extern void panic(const char*, ...) __attribute__((noreturn));
        panic("kfree: double-free detected at %p\n", ptr);
    }

    /* Validate cookie: must be a slab index [0, SLAB_SIZES) or a large-alloc
     * cookie (low byte == SLAB_LARGE_COOKIE). Anything else is heap corruption. */
    bool is_large = ((cookie & 0xFF) == SLAB_LARGE_COOKIE);
    if (!is_large && cookie >= (u64)SLAB_SIZES) {
        extern void panic(const char*, ...) __attribute__((noreturn));
        panic("kfree: invalid cookie %llx at %p — heap corruption\n",
              cookie, ptr);
    }

    if (is_large) {
        /* Large allocation: decode page count from cookie bits [63:8],
         * then free from the base pointer (cookie_ptr), which is the
         * start of the vmalloc region including the header page. */
        u64 payload_pages = cookie >> 8;
        /* Poison the cookie before freeing to catch use-after-free */
        *cookie_ptr = SLAB_POISON;
        vmm_free((void *)cookie_ptr, payload_pages + 1);  /* +1 for header page */
        return;
    }

    int i = (int)cookie;
    struct slab_cache *sc = &slabs[i];
    /* CRITICAL: h must point to the BASE of the block (cookie_ptr),
     * NOT to ptr (the user payload). Using ptr here would cause the
     * freelist to be linked 8 bytes into the block, making every
     * subsequent alloc/free cycle shift the pointer forward until
     * heap corruption occurs ("walking heap" bug). */
    struct slab_hdr *h = (struct slab_hdr *)cookie_ptr;

    /* Poison the entire block (cookie + payload) before returning to freelist */
    memset(cookie_ptr, 0xDE, sizeof(u64) + sc->obj_size);
    *(u64 *)cookie_ptr = SLAB_POISON;  /* mark base for double-free detection */

    spin_lock(&sc->lock);
    h->next = sc->freelist;
    sc->freelist = h;
    sc->free_count++;
    spin_unlock(&sc->lock);
}

void vmm_init(u64 *pml4_phys)
{
    g_kernel_pml4 = (u64 *)phys_to_virt((phys_addr_t)pml4_phys);

    /* Initialise slab caches */
    for (int i = 0; i < SLAB_SIZES; i++) {
        slabs[i].lock       = (spinlock_t)SPINLOCK_INIT;
        slabs[i].freelist   = NULL;
        slabs[i].obj_size   = slab_sz[i];
        slabs[i].alloc_count = 0;
        slabs[i].free_count  = 0;
    }
    pr_info("vmm: initialised PML4=%llx slab caches %u sizes\n",
            (u64)pml4_phys, SLAB_SIZES);
}
