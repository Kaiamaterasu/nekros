/* SPDX-License-Identifier: GPL-2.0 */
/* crypto/crypto.h — Nekros built-in cryptographic primitives */
#ifndef NEKROS_CRYPTO_H
#define NEKROS_CRYPTO_H
#include <nekros/types.h>

/* ── SHA-256 ──────────────────────────────────────────────── */
typedef struct {
    u32  state[8];
    u64  count;
    u8   buf[64];
    u32  buflen;
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const u8 *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, u8 digest[32]);
void sha256(const u8 *data, size_t len, u8 digest[32]);

/* ── HMAC-SHA256 ──────────────────────────────────────────── */
void hmac_sha256(const u8 *key, size_t klen,
                 const u8 *msg, size_t mlen,
                 u8 mac[32]);

/* ── HKDF-SHA256 ──────────────────────────────────────────── */
void hkdf_sha256(const u8 *ikm,  size_t ikm_len,
                 const u8 *salt, size_t salt_len,
                 const u8 *info, size_t info_len,
                 u8 *out, size_t out_len);

/* ── AES-256 block ────────────────────────────────────────── */
void aes256_encrypt_block(const u8 key[32], const u8 in[16], u8 out[16]);

/* ── AES-256-GCM AEAD ─────────────────────────────────────── */
int aes256_gcm_encrypt(const u8 key[32], const u8 iv[12],
                       const u8 *aad, size_t alen,
                       const u8 *pt,  size_t plen,
                       u8 *ct, u8 tag[16]);

int aes256_gcm_decrypt(const u8 key[32], const u8 iv[12],
                       const u8 *aad, size_t alen,
                       const u8 *ct,  size_t clen,
                       const u8 tag[16], u8 *pt);

/* ── Entropy / CSPRNG ─────────────────────────────────────── */
void crypto_rng_init(void);
void crypto_rng_bytes(u8 *out, size_t len);

/* ── Error codes ─────────────────────────────────────────── */
#define EBADMSG 74   /* tag verification failed */

/* ── Chain of custody ─────────────────────────────────────── */
typedef struct {
    u8   hash[32];       /* SHA-256 of previous link + this data */
    u64  seq;            /* monotonically increasing */
    u64  timestamp_ns;
    u32  source_id;      /* who created this link */
    u32  _pad;
} coc_link_t;

void coc_init(void);
void coc_record(u32 source_id, const u8 *data, size_t len, coc_link_t *out);
void coc_verify_chain(void);
const coc_link_t *coc_head(void);

#endif /* NEKROS_CRYPTO_H */
