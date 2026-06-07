/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * drivers/cortexcrypto/core/aes256.h
 * Compact AES-256 + GCM declarations for kernel use.
 */
#ifndef AES256_H
#define AES256_H
#include <nekros/types.h>

/*
 * aes256gcm_encrypt - AES-256-GCM authenticated encryption
 *
 * key        32-byte key
 * nonce      12-byte nonce (96-bit)
 * plaintext  input plaintext
 * plen       plaintext length in bytes
 * aad        additional authenticated data (may be NULL)
 * aad_len    length of AAD
 * ciphertext output (must be plen bytes)
 * tag        output authentication tag (16 bytes)
 */
void aes256gcm_encrypt(const u8 *key, const u8 *nonce,
                       const u8 *plaintext, u32 plen,
                       const u8 *aad, u32 aad_len,
                       u8 *ciphertext, u8 *tag);

/*
 * aes256gcm_decrypt - AES-256-GCM authenticated decryption
 *
 * Returns 0 on success, -1 if tag verification fails.
 * plaintext is NOT written if tag verification fails.
 */
int aes256gcm_decrypt(const u8 *key, const u8 *nonce,
                      const u8 *ciphertext, u32 clen,
                      const u8 *tag,
                      const u8 *aad, u32 aad_len,
                      u8 *plaintext);

#endif /* AES256_H */
