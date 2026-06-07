/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mm/pmm.c — Nekros Physical Memory Manager
 *
 * Implements a classic binary buddy allocator over all usable
 * RAM regions reported by the Multiboot2 memory map.
 *
 * Orders 0–10 (4KB – 4MB chunks).
 * Thread-safe via a single spinlock per NUMA node (extended later).
 *
 * Neri integration:
 *   neri_pool_t is informed of total/free pages on every alloc/free
 *   so Neri's RAM sample always reflects reality.
 */

#include <nekros/types.h>
#include <nekros/printk.h>
#include <nekros/string.h>
#include "pmm.h"

#define PMM_MAX_ORDER    10          /* 2^10 = 1024 pages = 4 MB */
#define PMM_MAX_NODES    8

/* ── Free list node (stored inside the free page itself) ──── */
struct free_block {
    struct free_block *next;
    struct free_block *prev;
};

/* ── Per-NUMA-node free lists ─────────────────────────────── */
struct pmm_node {
    spinlock_t           lock;
    struct free_block   *free[PMM_MAX_ORDER + 1];
    u64                  free_pages;
    u64                  total_pages;
    phys_addr_t          base;
    phys_addr_t          limit;
};

static struct pmm_node pmm_nodes[PMM_MAX_NODES];
static u32             pmm_nnodes;
u64 g_total_ram_pages;
u64 g_free_ram_pages;
/* g_pmm_global removed — per-node spinlocks used instead */

/* ── Bitmap of allocated pages (1 bit per 4KB page) ──────── */
/* We store the bitmap in the first few pages of RAM itself.   */
static u8 *pmm_bitmap;
static u64  pmm_bitmap_pages;  /* how many pages hold the bitmap */
static u64  pmm_total_pages;   /* total pages in the system */

static void bitmap_set(u64 pfn)  {
    if (!pmm_bitmap || pfn >= pmm_bitmap_pages * PAGE_SIZE * 8) return;
    pmm_bitmap[pfn/8] |= (u8)(1u << (pfn % 8)); }
static void bitmap_clear(u64 pfn){
    if (!pmm_bitmap || pfn >= pmm_bitmap_pages * PAGE_SIZE * 8) return;
    pmm_bitmap[pfn/8] &= (u8)~(1u << (pfn % 8)); }
static bool bitmap_test(u64 pfn) {
    if (!pmm_bitmap || pfn >= pmm_bitmap_pages * PAGE_SIZE * 8) return true; /* treat as used */
    return (pmm_bitmap[pfn/8] >> (pfn % 8)) & 1; }

/* ── Free list helpers ───────────────────────────────────── */
static void fl_push(struct pmm_node *nd, int ord, phys_addr_t pa)
{
    struct free_block *b = (struct free_block *)phys_to_virt(pa);
    b->next = nd->free[ord];
    b->prev = NULL;
    if (nd->free[ord]) nd->free[ord]->prev = b;
    nd->free[ord] = b;
}

static phys_addr_t fl_pop(struct pmm_node *nd, int ord)
{
    struct free_block *b = nd->free[ord];
    if (!b) return 0;
    nd->free[ord] = b->next;
    if (b->next) b->next->prev = NULL;
    return virt_to_phys((virt_addr_t)b);
}

static void fl_remove(struct pmm_node *nd, int ord, phys_addr_t pa)
{
    struct free_block *b = (struct free_block *)phys_to_virt(pa);
    if (b->prev) b->prev->next = b->next;
    else nd->free[ord] = b->next;
    if (b->next) b->next->prev = b->prev;
}

/* ── Buddy address ───────────────────────────────────────── */
static phys_addr_t buddy_of(phys_addr_t pa, int ord, phys_addr_t node_base)
{
    u64 offset = pa - node_base;
    u64 size   = (u64)PAGE_SIZE << ord;
    return node_base + (offset ^ size);
}

/* ── Node lookup by physical address ────────────────────── */
static struct pmm_node *pmm_node_of(phys_addr_t pa)
{
    for (u32 i = 0; i < pmm_nnodes; i++)
        if (pa >= pmm_nodes[i].base && pa < pmm_nodes[i].limit)
            return &pmm_nodes[i];
    return NULL;
}

/* ── Add a range of physical memory to the allocator ─────── */
void pmm_add_region(phys_addr_t base, u64 length)
{
    /* Align up base, align down end */
    phys_addr_t start = ALIGN(base, PAGE_SIZE);
    phys_addr_t end   = ALIGN_DOWN(base + length, PAGE_SIZE);
    if (end <= start) return;
    /* Never give out first 16MB (kernel image + boot stack) */
    if (start < 0x1000000ULL) start = 0x1000000ULL;
    if (end <= start) return;

    /* Find or create a node for this range */
    struct pmm_node *nd = pmm_node_of(start);
    if (!nd) {
        if (pmm_nnodes >= PMM_MAX_NODES) {
            pr_warn("pmm: too many memory nodes, ignoring %llx-%llx\n",
                    start, end);
            return;
        }
        nd = &pmm_nodes[pmm_nnodes++];
        nd->lock  = (spinlock_t)SPINLOCK_INIT;
        nd->base  = start;
        nd->limit = end;
    } else {
        if (end > nd->limit) nd->limit = end;
    }

    u64 pages = (end - start) / PAGE_SIZE;
    nd->total_pages += pages;
    g_total_ram_pages += pages;
    pmm_total_pages   += pages;

    /* Add pages to the largest possible buddy order */
    phys_addr_t pa = start;
    while (pa < end) {
        int ord = PMM_MAX_ORDER;
        u64 size = (u64)PAGE_SIZE << ord;
        /* Reduce order until block is aligned and fits */
        while (ord > 0 && ((pa & (size - 1)) || pa + size > end)) {
            ord--;
            size >>= 1;
        }
        spin_lock(&nd->lock);
        fl_push(nd, ord, pa);
        nd->free_pages += (1ULL << ord);
        spin_unlock(&nd->lock);
        pa += size;
    }
    g_free_ram_pages = nd->free_pages;
}

/* ── Allocate 2^order physically contiguous pages ─────────── */
phys_addr_t pmm_alloc_pages(int ord)
{
    if (ord < 0 || ord > PMM_MAX_ORDER) return 0; /* clamp to buddy allocator range */

    for (u32 i = 0; i < pmm_nnodes; i++) {
        struct pmm_node *nd = &pmm_nodes[i];
        spin_lock(&nd->lock);

        /* Find smallest free order >= ord */
        int avail = ord;
        while (avail <= PMM_MAX_ORDER && !nd->free[avail]) avail++;
        if (avail > PMM_MAX_ORDER) { spin_unlock(&nd->lock); continue; }

        phys_addr_t pa = fl_pop(nd, avail);

        /* Split down to the requested order */
        while (avail > ord) {
            avail--;
            phys_addr_t buddy = pa + ((u64)PAGE_SIZE << avail);
            fl_push(nd, avail, buddy);
        }

        nd->free_pages -= (1ULL << ord);

        /* Mark pages as allocated INSIDE the spinlock.
         * bitmap_set is a read-modify-write (|=) on a shared byte.
         * If done after spin_unlock, two CPUs racing on adjacent pages
         * in the same bitmap byte will corrupt each other's updates,
         * causing the PMM to later see a free buddy where there is none
         * and hand the same physical page to two different processes
         * (TOCTOU → double-allocation → privilege escalation). */
        u64 pfn_start = pa / PAGE_SIZE;
        for (u64 k = 0; k < (u64)(1ULL << ord); k++)
            bitmap_set(pfn_start + k);

        spin_unlock(&nd->lock);

        __atomic_sub_fetch(&g_free_ram_pages, 1 << ord, __ATOMIC_RELAXED);
        return pa;
    }
    return 0;  /* OOM */
}

phys_addr_t pmm_alloc_page(void) { return pmm_alloc_pages(0); }

/* ── Free 2^order pages at pa ─────────────────────────────── */
void pmm_free_pages(phys_addr_t pa, int ord)
{
    if (!pa || ord < 0 || ord > PMM_MAX_ORDER) return;

    struct pmm_node *nd = pmm_node_of(pa);
    if (!nd) { pr_warn("pmm: free of untracked address %llx\n", pa); return; }

    spin_lock(&nd->lock);

    /* Clear bitmap INSIDE the spinlock.
     * bitmap_clear is a read-modify-write (&= ~(...)) on a shared byte.
     * If done before spin_lock, two CPUs freeing pages that share the
     * same bitmap byte race: one CPU's &= load-store silently overwrites
     * the other's, leaving a bit set (memory leak) or clearing the wrong
     * bit (corrupt buddy coalescing → double-allocation).
     * Mirror of the alloc-path fix applied in v2. */
    u64 pfn_start = pa / PAGE_SIZE;
    for (u64 k = 0; k < (u64)(1ULL << ord); k++)
        bitmap_clear(pfn_start + k);

    /* Coalesce with buddy if free */
    while (ord < PMM_MAX_ORDER) {
        phys_addr_t buddy = buddy_of(pa, ord, nd->base);
        if (buddy < nd->base || buddy >= nd->limit) break;
        /* Check if buddy is free (not in bitmap) */
        u64 bpfn = buddy / PAGE_SIZE;
        bool buddy_free = true;
        for (u64 k = 0; k < (u64)(1ULL << ord); k++)
            if (bitmap_test(bpfn + k)) { buddy_free = false; break; }
        if (!buddy_free) break;
        fl_remove(nd, ord, buddy);
        pa = MIN(pa, buddy);
        ord++;
    }
    fl_push(nd, ord, pa);
    nd->free_pages += (1ULL << ord);
    spin_unlock(&nd->lock);

    __atomic_add_fetch(&g_free_ram_pages, 1 << ord, __ATOMIC_RELAXED);
}

void pmm_free_page(phys_addr_t pa) { pmm_free_pages(pa, 0); }

/* ── Init ─────────────────────────────────────────────────── */
void pmm_init(phys_addr_t bitmap_pa, u64 bitmap_size)
{
    pmm_bitmap      = (u8 *)phys_to_virt(bitmap_pa);
    pmm_bitmap_pages = ALIGN(bitmap_size, PAGE_SIZE) / PAGE_SIZE;
    memset(pmm_bitmap, 0xFF, bitmap_size);  /* all allocated initially */
    pmm_nnodes = 0;
    g_total_ram_pages = g_free_ram_pages = 0;
    pr_info("pmm: initialised bitmap at %llx (%llu pages)\n",
            bitmap_pa, pmm_bitmap_pages);
}

/* Stats for Neri RAM pool */
void pmm_stats(u64 *total, u64 *free_p)
{
    *total  = g_total_ram_pages;
    *free_p = g_free_ram_pages;
}
