/* SPDX-License-Identifier: GPL-2.0 */
/* mm/vmm.h */
#ifndef NEKROS_VMM_H
#define NEKROS_VMM_H
#include <nekros/types.h>

#define VMM_WRITE  (1 << 0)
#define VMM_USER   (1 << 1)
#define VMM_EXEC   (1 << 2)
#define VMM_NOCACHE (1 << 3)

void  vmm_init(u64 *pml4_phys);
int   vmm_map(u64 virt, phys_addr_t phys, u64 pages, u32 flags);
void  vmm_unmap(u64 virt, u64 pages, bool free_phys);
void *vmm_alloc(u64 pages, u32 flags);
void  vmm_free(void *ptr, u64 pages);

void *kmalloc(size_t size);
void *kzalloc(size_t size);
void  kfree(void *ptr);
#endif

/* Stack canary */
#define NEKROS_STACK_CANARY 0xDEADBEEFCAFEBABEULL
void kstack_canary_write(virt_addr_t stack_bottom);
bool kstack_canary_check(virt_addr_t stack_bottom);
