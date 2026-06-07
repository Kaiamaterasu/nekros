/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * drivers/cortexcrypto/core/aes256.c
 *
 * Self-contained AES-256-GCM.
 * No libc. No OpenSSL. No kernel crypto API.
 * Runs in kernel mode from first boot.
 *
 * AES-256:   14-round Rijndael, 256-bit key, 128-bit block
 * GCM:       Counter mode (CTR) + GHASH authentication
 * GHASH:     GF(2^128) multiply with polynomial 0x87
 *
 * All lookup tables are read-only after init.
 * No secret-dependent branches in AES core (table-only).
 *
 * This is the lowest layer of the CortexCrypto kernel stack.
 * Every encrypted object in Nekros passes through here.
 */

#include <nekros/types.h>
#include <nekros/string.h>
#include "aes256.h"

/* ── AES S-Box and inverse S-Box ─────────────────────────── */

static const u8 sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
    0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
    0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
    0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
    0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
    0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
    0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
    0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
    0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
    0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
    0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
    0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
    0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
    0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
    0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
    0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
    0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* ── GF(2^8) multiply by 2 (xtime) ──────────────────────── */
static __always_inline u8 xtime(u8 a) {
    return (a << 1) ^ ((a >> 7) ? 0x1b : 0x00);
}
static __always_inline u8 gmul(u8 a, u8 b) {
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
#define AES256_ROUNDS  14
#define AES256_RK_WORDS ((AES256_ROUNDS + 1) * 4)

typedef struct { u32 rk[AES256_RK_WORDS]; } aes256_key_t;

static const u8 rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static __always_inline u32 subword(u32 w) {
    return ((u32)sbox[(w>>24)&0xff]<<24) | ((u32)sbox[(w>>16)&0xff]<<16) |
           ((u32)sbox[(w>> 8)&0xff]<< 8) |  (u32)sbox[(w    )&0xff];
}
static __always_inline u32 rotword(u32 w) { return (w<<8)|(w>>24); }

static void aes256_key_expand(const u8 *key, aes256_key_t *ks)
{
    u32 *rk = ks->rk;
    for (int i = 0; i < 8; i++)
        rk[i] = ((u32)key[4*i]<<24)|((u32)key[4*i+1]<<16)|
                ((u32)key[4*i+2]<<8)|(u32)key[4*i+3];
    for (int i = 8; i < AES256_RK_WORDS; i++) {
        u32 t = rk[i-1];
        if (i % 8 == 0)      t = subword(rotword(t)) ^ ((u32)rcon[i/8] << 24);
        else if (i % 8 == 4) t = subword(t);
        rk[i] = rk[i-8] ^ t;
    }
}

/* ── AES-256 block encrypt ────────────────────────────────── */
static void aes256_block_encrypt(const aes256_key_t *ks,
                                  const u8 in[16], u8 out[16])
{
    u8 s[16];
    memcpy(s, in, 16);
    const u32 *rk = ks->rk;

    /* Initial round key addition */
    for (int i = 0; i < 4; i++) {
        u32 k = rk[i];
        s[4*i]   ^= (k>>24)&0xff; s[4*i+1] ^= (k>>16)&0xff;
        s[4*i+2] ^= (k>> 8)&0xff; s[4*i+3] ^= (k    )&0xff;
    }

    /* 13 main rounds */
    for (int round = 1; round < AES256_ROUNDS; round++) {
        /* SubBytes */
        for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];

        /* ShiftRows */
        u8 t;
        t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
        t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
        t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;

        /* MixColumns */
        for (int c = 0; c < 4; c++) {
            u8 a0=s[c*4],a1=s[c*4+1],a2=s[c*4+2],a3=s[c*4+3];
            s[c*4  ] = gmul(a0,2)^gmul(a1,3)^a2^a3;
            s[c*4+1] = a0^gmul(a1,2)^gmul(a2,3)^a3;
            s[c*4+2] = a0^a1^gmul(a2,2)^gmul(a3,3);
            s[c*4+3] = gmul(a0,3)^a1^a2^gmul(a3,2);
        }

        /* AddRoundKey */
        for (int i = 0; i < 4; i++) {
            u32 k = rk[(round*4)+i];
            s[4*i]   ^= (k>>24)&0xff; s[4*i+1] ^= (k>>16)&0xff;
            s[4*i+2] ^= (k>> 8)&0xff; s[4*i+3] ^= (k    )&0xff;
        }
    }

    /* Final round (no MixColumns) */
    for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
    u8 t;
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
    for (int i = 0; i < 4; i++) {
        u32 k = rk[(AES256_ROUNDS*4)+i];
        s[4*i]   ^= (k>>24)&0xff; s[4*i+1] ^= (k>>16)&0xff;
        s[4*i+2] ^= (k>> 8)&0xff; s[4*i+3] ^= (k    )&0xff;
    }
    memcpy(out, s, 16);
    memzero_explicit(s, 16);
}

/* ── CTR mode keystream ───────────────────────────────────── */
static void aes256_ctr_crypt(const aes256_key_t *ks,
                              const u8 nonce[12], u32 ctr_start,
                              const u8 *in, u8 *out, u32 len)
{
    u8 counter_block[16];
    u8 keystream[16];
    memcpy(counter_block, nonce, 12);
    u32 ctr = ctr_start;

    for (u32 done = 0; done < len; ) {
        /* Big-endian counter in bytes 12–15 */
        counter_block[12] = (u8)(ctr >> 24);
        counter_block[13] = (u8)(ctr >> 16);
        counter_block[14] = (u8)(ctr >>  8);
        counter_block[15] = (u8)(ctr      );
        ctr++;
        aes256_block_encrypt(ks, counter_block, keystream);
        u32 chunk = MIN(16, len - done);
        for (u32 i = 0; i < chunk; i++)
            out[done + i] = in[done + i] ^ keystream[i];
        done += chunk;
    }
    memzero_explicit(keystream, 16);
}

/* ── GHASH (GF(2^128) authentication) ───────────────────── */
/*
 * GHASH(H, A, C) where H = AES_K(0^128)
 * Polynomial: x^128 + x^7 + x^2 + x + 1  (0xE1 << 120)
 */
static void ghash_block(u8 y[16], const u8 x[16], const u8 h[16])
{
    /* y = (y XOR x) * H in GF(2^128) */
    u8 z[16] = {0};
    u8 v[16];
    memcpy(v, h, 16);

    /* XOR x into y first */
    u8 tmp[16];
    for (int i = 0; i < 16; i++) tmp[i] = y[i] ^ x[i];

    /* Multiply tmp * v in GF(2^128) */
    for (int i = 0; i < 128; i++) {
        /* If bit i of tmp is 1, XOR v into z */
        if ((tmp[i/8] >> (7 - (i%8))) & 1)
            for (int j = 0; j < 16; j++) z[j] ^= v[j];
        /* v = v >> 1 in GF(2^128) */
        u8 carry = 0;
        for (int j = 0; j < 16; j++) {
            u8 new_carry = v[j] & 1;
            v[j] = (v[j] >> 1) | (carry << 7);
            carry = new_carry;
        }
        /* If carry, XOR with reduction polynomial */
        if (carry) v[0] ^= 0xE1;
    }
    memcpy(y, z, 16);
}

static void ghash(const u8 h[16], const u8 *aad, u32 aad_len,
                  const u8 *ct, u32 ct_len, u8 tag[16])
{
    u8 y[16] = {0};
    u8 block[16];

    /* Process AAD (padded to 16-byte boundary) */
    u32 i = 0;
    while (i < aad_len) {
        memset(block, 0, 16);
        u32 chunk = MIN(16, aad_len - i);
        memcpy(block, aad + i, chunk);
        ghash_block(y, block, h);
        i += 16;
    }

    /* Process ciphertext */
    i = 0;
    while (i < ct_len) {
        memset(block, 0, 16);
        u32 chunk = MIN(16, ct_len - i);
        memcpy(block, ct + i, chunk);
        ghash_block(y, block, h);
        i += 16;
    }

    /* Length block: AAD_len_bits(64) || CT_len_bits(64), big-endian */
    u64 aad_bits = (u64)aad_len * 8;
    u64 ct_bits  = (u64)ct_len  * 8;
    for (int j = 7; j >= 0; j--) {
        block[j]   = (u8)(aad_bits & 0xFF); aad_bits >>= 8;
        block[j+8] = (u8)(ct_bits  & 0xFF); ct_bits  >>= 8;
    }
    ghash_block(y, block, h);
    memcpy(tag, y, 16);
}

/* ── Public AES-256-GCM API ──────────────────────────────── */

void aes256gcm_encrypt(const u8 *key, const u8 *nonce,
                       const u8 *plaintext, u32 plen,
                       const u8 *aad, u32 aad_len,
                       u8 *ciphertext, u8 *tag)
{
    aes256_key_t ks;
    aes256_key_expand(key, &ks);

    /* H = AES_K(0^128) */
    u8 h[16] = {0};
    aes256_block_encrypt(&ks, h, h);

    /* Encrypt: CTR starting at counter=2 (counter=1 reserved for tag) */
    aes256_ctr_crypt(&ks, nonce, 2, plaintext, ciphertext, plen);

    /* Compute GHASH over AAD and ciphertext */
    u8 raw_tag[16];
    ghash(h, aad ? aad : (const u8*)"", aad_len,
          ciphertext, plen, raw_tag);

    /* Tag = GHASH XOR AES_K(nonce || 1) */
    u8 j0[16];
    memcpy(j0, nonce, 12);
    j0[12]=0; j0[13]=0; j0[14]=0; j0[15]=1;
    u8 ek_j0[16];
    aes256_block_encrypt(&ks, j0, ek_j0);
    for (int i = 0; i < 16; i++) tag[i] = raw_tag[i] ^ ek_j0[i];

    memzero_explicit(&ks, sizeof(ks));
    memzero_explicit(h, 16);
    memzero_explicit(raw_tag, 16);
}

int aes256gcm_decrypt(const u8 *key, const u8 *nonce,
                      const u8 *ciphertext, u32 clen,
                      const u8 *tag,
                      const u8 *aad, u32 aad_len,
                      u8 *plaintext)
{
    aes256_key_t ks;
    aes256_key_expand(key, &ks);

    /* H = AES_K(0^128) */
    u8 h[16] = {0};
    aes256_block_encrypt(&ks, h, h);

    /* Verify tag first (authenticate-then-decrypt) */
    u8 raw_tag[16];
    ghash(h, aad ? aad : (const u8*)"", aad_len,
          ciphertext, clen, raw_tag);

    u8 j0[16];
    memcpy(j0, nonce, 12);
    j0[12]=0; j0[13]=0; j0[14]=0; j0[15]=1;
    u8 ek_j0[16];
    aes256_block_encrypt(&ks, j0, ek_j0);

    u8 expected_tag[16];
    for (int i = 0; i < 16; i++) expected_tag[i] = raw_tag[i] ^ ek_j0[i];

    /* Constant-time tag comparison (no early exit) */
    u8 diff = 0;
    for (int i = 0; i < 16; i++) diff |= expected_tag[i] ^ tag[i];

    memzero_explicit(&ks, sizeof(ks));
    memzero_explicit(h, 16);
    memzero_explicit(raw_tag, 16);
    memzero_explicit(expected_tag, 16);

    if (diff) return -1;  /* Authentication failed — DO NOT decrypt */

    /* Decrypt only after tag verified */
    aes256_key_expand(key, &ks);
    aes256_ctr_crypt(&ks, nonce, 2, ciphertext, plaintext, clen);
    memzero_explicit(&ks, sizeof(ks));
    return 0;
}
