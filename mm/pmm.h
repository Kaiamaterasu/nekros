/* SPDX-License-Identifier: GPL-2.0 */
/* mm/pmm.h */
#ifndef NEKROS_PMM_H
#define NEKROS_PMM_H
#include <nekros/types.h>

extern u64 g_total_ram_pages;
extern u64 g_free_ram_pages;

void        pmm_init(phys_addr_t bitmap_pa, u64 bitmap_size);
void        pmm_add_region(phys_addr_t base, u64 length);
phys_addr_t pmm_alloc_page(void);
phys_addr_t pmm_alloc_pages(int order);
void        pmm_free_page(phys_addr_t pa);
void        pmm_free_pages(phys_addr_t pa, int order);
void        pmm_stats(u64 *total, u64 *free_pages);
#endif
