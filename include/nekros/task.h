/* SPDX-License-Identifier: GPL-2.0 */
/* include/nekros/task.h — full struct task definition */
#ifndef NEKROS_TASK_H
#define NEKROS_TASK_H
#include <nekros/types.h>
#include "../../drivers/neri/include/neri.h"

#define TASK_RUNNING  0
#define TASK_READY    1
#define TASK_BLOCKED  2
#define TASK_ZOMBIE   3
#define TASK_NAME_LEN 32
#define KERNEL_STACK_PAGES 4

struct fd_table;

struct task {
    pid_t       pid, ppid;
    uid_t       uid; gid_t gid;
    char        name[TASK_NAME_LEN];
    u32         state, priority;
    u64         vruntime, weight, timeslice_ns, cpu_time_ns;
    u32         cpu_affinity, on_cpu;
    u64        *pml4;
    virt_addr_t kstack_top;
    phys_addr_t kstack_pa;
    u64 ctx_rsp, ctx_rbp, ctx_rbx;
    u64 ctx_r12, ctx_r13, ctx_r14, ctx_r15;
    u64 ctx_rip, ctx_rflags;
    neri_proc_t neri;
    u64         syscall_ret;
    u64         sig_pending, sig_blocked;
    struct fd_table *fdt;
    list_head_t rq_node, all_tasks;
};
#endif
