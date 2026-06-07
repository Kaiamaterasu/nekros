/* SPDX-License-Identifier: GPL-2.0 */
/* drivers/neri/include/neri_uapi.h — kernel↔userspace ABI */
#ifndef NERI_UAPI_H
#define NERI_UAPI_H
#include <nekros/types.h>

/* Returned by nk_neri_status syscall */
struct neri_uapi_status {
    u64 epoch;
    u64 cpu_total_ns;
    u64 cpu_alloc_ns;
    u64 ram_total_pages;
    u64 ram_alloc_pages;
    u64 gpu_total_slots;
    u64 gpu_alloc_slots;
};

/* Returned by nk_anomaly_score syscall */
struct neri_uapi_anomaly {
    u8   score;
    u32  level;
    u8   blocked;
    u64  epoch;
};

/* Returned by nk_get_caps syscall */
struct neri_uapi_caps {
    u32  caps;
    u16  version_major;
    u16  version_minor;
    u16  version_patch;
    u8   _pad[2];
};

/* ioctl commands on /dev/neri */
#define NERI_IOC_STATUS   0x4E01
#define NERI_IOC_ANOMALY  0x4E02
#define NERI_IOC_CAPS     0x4E03
#define NERI_IOC_TUNE     0x4E04

#endif
