/* SPDX-License-Identifier: GPL-2.0 */
/* drivers/neri/include/neri_ado.h */
#ifndef NERI_ADO_H
#define NERI_ADO_H
#include "neri_nzra.h"
void neri_ado_init(void);
int  neri_ado_dispatch(const neri_nzra_decision_t *dec, u64 epoch);
void neri_ado_work(void);
#endif
