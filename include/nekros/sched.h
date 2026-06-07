/* SPDX-License-Identifier: GPL-2.0 */
/* include/nekros/sched.h */
#ifndef NEKROS_SCHED_H
#define NEKROS_SCHED_H
#include <nekros/types.h>
extern u32 g_ncpus;
struct task;
void         sched_init(void);
void         schedule(void);
void         sched_tick(void);
struct task *task_create(const char *name, void (*entry)(void *),
                         void *arg, u32 priority,
                         u64 cpu_demand_ns, u64 ram_demand_pages);
void         task_exit(struct task *t, int code);
struct task *sched_current(void);
#endif
