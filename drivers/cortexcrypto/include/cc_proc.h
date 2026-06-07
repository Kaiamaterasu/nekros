/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/* drivers/cortexcrypto/include/cc_proc.h */
#ifndef CC_PROC_H
#define CC_PROC_H
#include <nekros/types.h>

struct task;

void cc_proc_init(const u8 machine_fingerprint[32]);

/* Attestation */
int cc_kernel_attest_process(pid_t pid, u8 *token, u32 *size);
int cc_kernel_verify_attestation(const u8 *token, u32 size, pid_t expected);

/* Encrypted memory */
void *cc_kernel_secure_alloc(u64 pages, u32 policy);
void  cc_kernel_secure_free(void *ptr, u64 pages);
int   cc_kernel_seal_memory(virt_addr_t va, u64 pages,
                             void *out, u32 *size);

/* Zero-trust IPC */
int     cc_ipc_channel_create(pid_t self, pid_t peer, u32 flags);
ssize_t cc_ipc_send(int fd, const void *buf, size_t len);
ssize_t cc_ipc_recv(int fd, void *buf, size_t len);

/* Checkpoint */
int cc_kernel_checkpoint(struct task *t, void *out, u32 *size);

/* Machine fingerprint (for sysfs) */
int cc_get_machine_fingerprint(char *buf, size_t buflen);

#endif
