/* SPDX-License-Identifier: GPL-2.0 */
/*
 * crypto/sha256.c — Nekros built-in SHA-256 / HMAC-SHA256
 *
 * Pure C, no external dependencies, constant-time where it matters.
 * Used by CortexCrypto NSM for snapshot sealing and the boot chain
 * of custody. Also used as the KDF primitive when the full
 * Argon2id daemon is not yet running.
 */

#include <nekros/types.h>
#include <nekros/string.h>
#include "crypto.h"

/* ── SHA-256 constants ────────────────────────────────────── */
static const u32 K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x,n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)    (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROTR32(x,2)  ^ ROTR32(x,13) ^ ROTR32(x,22))
#define EP1(x)       (ROTR32(x,6)  ^ ROTR32(x,11) ^ ROTR32(x,25))
#define SIG0(x)      (ROTR32(x,7)  ^ ROTR32(x,18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10))

static inline u32 be32(const u8 *p)
{
    return ((u32)p[0]<<24)|((u32)p[1]<<16)|((u32)p[2]<<8)|p[3];
}
static inline void put_be32(u8 *p, u32 v)
{
    p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v;
}
static inline void put_be64(u8 *p, u64 v)
{
    put_be32(p, (u32)(v>>32)); put_be32(p+4, (u32)v);
}

static void sha256_transform(u32 state[8], const u8 block[64])
{
    u32 w[64], a,b,c,d,e,f,g,h,t1,t2;
    for (int i=0;i<16;i++) w[i]=be32(block+i*4);
    for (int i=16;i<64;i++)
        w[i]=SIG1(w[i-2])+w[i-7]+SIG0(w[i-15])+w[i-16];
    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];
    for (int i=0;i<64;i++){
        t1=h+EP1(e)+CH(e,f,g)+K[i]+w[i];
        t2=EP0(a)+MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

void sha256_init(sha256_ctx_t *ctx)
{
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
    ctx->count=0; ctx->buflen=0;
}

void sha256_update(sha256_ctx_t *ctx, const u8 *data, size_t len)
{
    ctx->count += len;
    while (len) {
        size_t room = 64 - ctx->buflen;
        size_t copy = len < room ? len : room;
        memcpy(ctx->buf + ctx->buflen, data, copy);
        ctx->buflen += copy;
        data += copy; len -= copy;
        if (ctx->buflen == 64) {
            sha256_transform(ctx->state, ctx->buf);
            ctx->buflen = 0;
        }
    }
}

void sha256_final(sha256_ctx_t *ctx, u8 digest[32])
{
    u64 bits = ctx->count * 8;
    u8 pad = 0x80;
    sha256_update(ctx, &pad, 1);
    while (ctx->buflen != 56) {
        u8 zero = 0;
        sha256_update(ctx, &zero, 1);
    }
    u8 len_be[8];
    put_be64(len_be, bits);
    sha256_update(ctx, len_be, 8);
    for (int i=0;i<8;i++) put_be32(digest+i*4, ctx->state[i]);
    memzero_explicit(ctx, sizeof(*ctx));
}

void sha256(const u8 *data, size_t len, u8 digest[32])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

/* ── HMAC-SHA256 ──────────────────────────────────────────── */

void hmac_sha256(const u8 *key, size_t klen,
                 const u8 *msg, size_t mlen,
                 u8 mac[32])
{
    u8 k[64], ipad[64], opad[64], inner[32];

    memset(k, 0, 64);
    if (klen > 64) sha256(key, klen, k);
    else memcpy(k, key, klen);

    for (int i=0;i<64;i++) { ipad[i]=k[i]^0x36; opad[i]=k[i]^0x5c; }

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, msg, mlen);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, mac);

    memzero_explicit(k,     sizeof(k));
    memzero_explicit(ipad,  sizeof(ipad));
    memzero_explicit(opad,  sizeof(opad));
    memzero_explicit(inner, sizeof(inner));
}

/* ── HKDF-SHA256 (RFC 5869) ───────────────────────────────── */

void hkdf_sha256(const u8 *ikm,  size_t ikm_len,
                 const u8 *salt, size_t salt_len,
                 const u8 *info, size_t info_len,
                 u8 *out, size_t out_len)
{
    /* Extract */
    u8 prk[32];
    static const u8 zero_salt[32] = {0};
    if (!salt || !salt_len) { salt = zero_salt; salt_len = 32; }
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    /* Expand */
    u8 T[32] = {0};
    u8 ctr = 0;
    size_t done = 0;
    while (done < out_len) {
        ctr++;
        sha256_ctx_t ctx;
        sha256_init(&ctx);
        /* HMAC(PRK, T || info || ctr) */
        u8 ipad[64], opad[64];
        u8 k[64]; memset(k,0,64);
        memcpy(k, prk, 32);
        for (int i=0;i<64;i++){ ipad[i]=k[i]^0x36; opad[i]=k[i]^0x5c; }
        sha256_init(&ctx);
        sha256_update(&ctx, ipad, 64);
        if (ctr > 1) sha256_update(&ctx, T, 32);
        sha256_update(&ctx, info, info_len);
        sha256_update(&ctx, &ctr, 1);
        sha256_final(&ctx, T);

        sha256_ctx_t ctx2;
        sha256_init(&ctx2);
        sha256_update(&ctx2, opad, 64);
        sha256_update(&ctx2, T, 32);
        sha256_final(&ctx2, T);

        size_t copy = MIN(32, out_len - done);
        memcpy(out + done, T, copy);
        done += copy;
    }
    memzero_explicit(prk, sizeof(prk));
    memzero_explicit(T,   sizeof(T));
}
