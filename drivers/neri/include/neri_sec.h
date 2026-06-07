/* SPDX-License-Identifier: GPL-2.0 */
/* drivers/neri/include/neri_sec.h */
#ifndef NERI_SEC_H
#define NERI_SEC_H
#include <nekros/types.h>
#include "neri.h"

/* Anomaly levels */
#define NERI_SEC_LEVEL_NORMAL    0
#define NERI_SEC_LEVEL_MEDIUM    1
#define NERI_SEC_LEVEL_HIGH      2
#define NERI_SEC_LEVEL_CRITICAL  3

typedef struct {
    u8   score_byte;        /* 0-255 scalar score */
    u32  level;             /* NERI_SEC_LEVEL_* */
    bool block_admits;      /* true when CRITICAL */
    u64  score_epoch;       /* epoch when scored */
} neri_sec_anomaly_t;

int  neri_sec_init(const u8 machine_fp[32]);
void neri_sec_exit(void);
void neri_sec_get_anomaly(neri_sec_anomaly_t *out);
void neri_sec_rescore(neri_pool_t *pool);
bool neri_sec_admit_allowed(void);
void neri_sec_record_admin_attempt(void);
void neri_sec_record_admit_failure(void);
#endif
