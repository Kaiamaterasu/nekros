/* SPDX-License-Identifier: GPL-2.0 */
/* kernel/glue.c — missing symbol stubs */
#include <nekros/types.h>
#include <nekros/printk.h>
#include "../drivers/neri/include/neri.h"
#include "../drivers/neri/include/neri_sec.h"

/* IRQ dispatch table */
typedef void (*irq_handler_t)(u32);
static irq_handler_t irq_table[16];
void irq_register(u32 irq, irq_handler_t h) { if (irq<16) irq_table[irq]=h; }
void irq_dispatch(u32 irq) { if (irq<16 && irq_table[irq]) irq_table[irq](irq); }

/* SHA-256 wrapper — forward to cc_proc's implementation */
extern void sha256_impl(const u8*, size_t, u8*);
void sha256(const u8 *in, size_t len, u8 out[32]) {
    sha256_impl(in, len, out); }

/* HKDF-SHA256 — delegates to the real RFC 5869 implementation in sha256.c
 * The glue layer previously had a broken stub; removed in favour of the
 * correct implementation that supports arbitrary output lengths.
 * Declaration matches crypto.h: (ikm, ikm_len, salt, salt_len, info, info_len, out, out_len)
 * Callers in glue.c / trace.c pass (ikm, ikm_len, NULL, 0, info, info_len, out, out_len)
 * which matches the sha256.c signature exactly.
 */
/* hkdf_sha256 is provided by crypto/sha256.c — no stub needed here */

/* AES-256-GCM aliases (neri_sec uses different names) */
extern void aes256gcm_encrypt(const u8*,const u8*,const u8*,u32,
                               const u8*,u32,u8*,u8*);
extern int  aes256gcm_decrypt(const u8*,const u8*,const u8*,u32,
                               const u8*,const u8*,u32,u8*);

void aes256_gcm_encrypt(const u8 *key, const u8 *iv,
                        const u8 *aad, u32 aad_len,
                        const u8 *pt, u32 pt_len,
                        u8 *ct, u8 *tag)
    { aes256gcm_encrypt(key, iv, pt, pt_len, aad, aad_len, ct, tag); }

int aes256_gcm_decrypt(const u8 *key, const u8 *iv,
                       const u8 *aad, u32 aad_len,
                       const u8 *ct, u32 ct_len,
                       const u8 *tag, u8 *pt)
    { return aes256gcm_decrypt(key, iv, ct, ct_len, tag, aad, aad_len, pt); }

/* cc_get_machine_fingerprint wrapper */
int cc_get_machine_fingerprint(char *buf, size_t buflen) {
    if (!buf || buflen < 65) return -1;
    extern bool g_cc_ready;
    if (!g_cc_ready) {
        /* Not yet initialised */
        static const char unavail[] = "unavailable\n";
        size_t n = sizeof(unavail) - 1;
        if (n >= buflen) n = buflen - 1;
        extern void *memcpy(void*, const void*, size_t);
        memcpy(buf, unavail, n);
        buf[n] = '\0';
        return -1;
    }
    /* machine_key is not directly accessible here; 
     * real implementation would read from cc_proc's exported fingerprint */
    return 0;
}

/* neri_sec_rescore — already in neri_sec.c, just needs to be found */
/* It's already defined there — but called via different TU. Export it. */
