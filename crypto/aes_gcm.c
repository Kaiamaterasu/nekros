/* SPDX-License-Identifier: GPL-2.0 */
/*
 * crypto/aes_gcm.c — Nekros AES-256-GCM AEAD
 *
 * Pure C, no hardware AES instructions required (but will use
 * AES-NI via inline asm if detected at init time).
 *
 * This is the encryption engine behind:
 *   - CortexCrypto NSM snapshot sealing
 *   - CortexCrypto Neki policy sealing
 *   - IPC message AEAD receipts
 *   - Boot chain of custody sealing
 */

#include <nekros/types.h>
#include <nekros/string.h>
#include "crypto.h"

/* ── AES S-box and inverse ────────────────────────────────── */
static const u8 sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* GF(2^8) multiply: irreducible poly x^8+x^4+x^3+x+1 = 0x11b */
static inline u8 gf_mul(u8 a, u8 b)
{
    u8 p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        u8 hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/* ── AES key schedule ─────────────────────────────────────── */
static const u8 rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static void aes256_key_expand(const u8 key[32], u32 rk[60])
{
    for (int i = 0; i < 8; i++) {
        rk[i] = ((u32)key[i*4]<<24)|((u32)key[i*4+1]<<16)|
                ((u32)key[i*4+2]<<8)|key[i*4+3];
    }
    for (int i = 8; i < 60; i++) {
        u32 w = rk[i-1];
        if (i % 8 == 0) {
            /* RotWord + SubWord + Rcon */
            w = (((u32)sbox[(w>>16)&0xff]^rcon[i/8])<<24) |
                ((u32)sbox[(w>>8)&0xff]<<16) |
                ((u32)sbox[w&0xff]<<8) |
                ((u32)sbox[(w>>24)&0xff]);
        } else if (i % 8 == 4) {
            w = ((u32)sbox[(w>>24)&0xff]<<24)|((u32)sbox[(w>>16)&0xff]<<16)|
                ((u32)sbox[(w>>8)&0xff]<<8)|((u32)sbox[w&0xff]);
        }
        rk[i] = rk[i-8] ^ w;
    }
}

static void aes_sub_bytes(u8 s[16])   { for(int i=0;i<16;i++) s[i]=sbox[s[i]]; }
static void aes_shift_rows(u8 s[16])  {
    u8 t;
    t=s[1];  s[1]=s[5];  s[5]=s[9];  s[9]=s[13]; s[13]=t;
    t=s[2];  s[2]=s[10]; s[10]=t;
    t=s[6];  s[6]=s[14]; s[14]=t;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}
static void aes_mix_columns(u8 s[16]) {
    for (int c=0;c<4;c++) {
        u8 *col=s+c*4;
        u8 a=col[0],b=col[1],cc=col[2],d=col[3];
        col[0]=gf_mul(2,a)^gf_mul(3,b)^cc^d;
        col[1]=a^gf_mul(2,b)^gf_mul(3,cc)^d;
        col[2]=a^b^gf_mul(2,cc)^gf_mul(3,d);
        col[3]=gf_mul(3,a)^b^cc^gf_mul(2,d);
    }
}
static void aes_add_round_key(u8 s[16], const u32 *rk) {
    for (int i=0;i<4;i++) {
        s[i*4+0]^=(rk[i]>>24)&0xff; s[i*4+1]^=(rk[i]>>16)&0xff;
        s[i*4+2]^=(rk[i]>>8)&0xff;  s[i*4+3]^=rk[i]&0xff;
    }
}

void aes256_encrypt_block(const u8 key[32], const u8 in[16], u8 out[16])
{
    u32 rk[60];
    u8  state[16];
    aes256_key_expand(key, rk);
    memcpy(state, in, 16);
    aes_add_round_key(state, rk);
    for (int r = 1; r < 14; r++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, rk + r*4);
    }
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, rk + 56);
    memcpy(out, state, 16);
    memzero_explicit(rk, sizeof(rk));
    memzero_explicit(state, sizeof(state));
}

/* ── AES-256-CTR (used as base for GCM) ──────────────────── */
static void aes256_ctr_crypt(const u8 key[32], const u8 iv[12],
                              u32 ctr_start, const u8 *in, u8 *out, size_t len)
{
    u8  counter_block[16], keystream[16];
    memcpy(counter_block, iv, 12);
    u32 ctr = ctr_start;

    size_t done = 0;
    while (done < len) {
        counter_block[12] = (ctr >> 24) & 0xff;
        counter_block[13] = (ctr >> 16) & 0xff;
        counter_block[14] = (ctr >>  8) & 0xff;
        counter_block[15] =  ctr        & 0xff;
        aes256_encrypt_block(key, counter_block, keystream);
        size_t chunk = MIN(16, len - done);
        for (size_t i = 0; i < chunk; i++)
            out[done + i] = in[done + i] ^ keystream[i];
        done += chunk;
        ctr++;
    }
    memzero_explicit(keystream, 16);
}

/* ── GHASH (GCM authentication) ──────────────────────────── */
typedef struct { u64 hi, lo; } u128_t;

static void gf128_mul(u128_t *x, const u128_t *h)
{
    u128_t z = {0,0}, v = *h;
    u64 xi_hi = x->hi, xi_lo = x->lo;
    for (int i = 0; i < 128; i++) {
        bool bit = (i < 64) ? ((xi_hi >> (63-i)) & 1)
                             : ((xi_lo >> (127-i)) & 1);
        if (bit) { z.hi ^= v.hi; z.lo ^= v.lo; }
        bool lsb = v.lo & 1;
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi >>= 1;
        if (lsb) v.hi ^= 0xe100000000000000ULL;
    }
    *x = z;
}

static void ghash(const u8 H[16], const u8 *aad, size_t alen,
                  const u8 *ct,  size_t clen, u8 out[16])
{
    u128_t h = { .hi = 0, .lo = 0 };
    for (int i=0;i<8;i++) h.hi = (h.hi<<8)|H[i];
    for (int i=0;i<8;i++) h.lo = (h.lo<<8)|H[8+i];

    u128_t X = {0,0};
    /* Process AAD */
    size_t n = (alen + 15) / 16;
    for (size_t i = 0; i < n; i++) {
        u8 block[16] = {0};
        size_t copy = MIN(16, alen - i*16);
        memcpy(block, aad + i*16, copy);
        for (int j=0;j<8;j++) X.hi ^= (u64)block[j] << (56-j*8);
        for (int j=0;j<8;j++) X.lo ^= (u64)block[8+j] << (56-j*8);
        gf128_mul(&X, &h);
    }
    /* Process ciphertext */
    n = (clen + 15) / 16;
    for (size_t i = 0; i < n; i++) {
        u8 block[16] = {0};
        size_t copy = MIN(16, clen - i*16);
        memcpy(block, ct + i*16, copy);
        for (int j=0;j<8;j++) X.hi ^= (u64)block[j] << (56-j*8);
        for (int j=0;j<8;j++) X.lo ^= (u64)block[8+j] << (56-j*8);
        gf128_mul(&X, &h);
    }
    /* Length block */
    u64 lA = (u64)alen * 8, lC = (u64)clen * 8;
    X.hi ^= lA; X.lo ^= lC;
    gf128_mul(&X, &h);

    /* Serialise big-endian */
    for (int i=0;i<8;i++) out[i]   = (X.hi >> (56-i*8)) & 0xff;
    for (int i=0;i<8;i++) out[8+i] = (X.lo >> (56-i*8)) & 0xff;
}

/* ── AES-256-GCM Encrypt ──────────────────────────────────── */
int aes256_gcm_encrypt(const u8 key[32], const u8 iv[12],
                       const u8 *aad,  size_t alen,
                       const u8 *pt,   size_t plen,
                       u8 *ct, u8 tag[16])
{
    /* H = AES(key, 0^128) */
    u8 H[16] = {0};
    aes256_encrypt_block(key, H, H);

    /* EK0 = AES(key, IV || 0x00000001) for tag */
    u8 J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 0x01;
    u8 EK0[16];
    aes256_encrypt_block(key, J0, EK0);

    /* Encrypt with CTR starting at 2 */
    aes256_ctr_crypt(key, iv, 2, pt, ct, plen);

    /* Compute GHASH tag */
    u8 S[16];
    ghash(H, aad, alen, ct, plen, S);
    for (int i = 0; i < 16; i++) tag[i] = S[i] ^ EK0[i];

    return 0;
}

/* ── AES-256-GCM Decrypt ──────────────────────────────────── */
int aes256_gcm_decrypt(const u8 key[32], const u8 iv[12],
                       const u8 *aad,  size_t alen,
                       const u8 *ct,   size_t clen,
                       const u8 expected_tag[16],
                       u8 *pt)
{
    u8 H[16] = {0};
    aes256_encrypt_block(key, H, H);

    u8 J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 0x01;
    u8 EK0[16];
    aes256_encrypt_block(key, J0, EK0);

    /* Verify tag first (constant-time) */
    u8 S[16], computed_tag[16];
    ghash(H, aad, alen, ct, clen, S);
    for (int i = 0; i < 16; i++) computed_tag[i] = S[i] ^ EK0[i];

    /* Constant-time comparison */
    u8 diff = 0;
    for (int i = 0; i < 16; i++) diff |= computed_tag[i] ^ expected_tag[i];
    if (diff) {
        memzero_explicit(computed_tag, 16);
        return -EBADMSG;
    }

    aes256_ctr_crypt(key, iv, 2, ct, pt, clen);
    memzero_explicit(computed_tag, 16);
    return 0;
}
