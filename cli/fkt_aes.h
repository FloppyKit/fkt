/* fkt_aes.h – AES-256 encrypt (Warm wallet only). C89. */
#ifndef FKT_AES_H
#define FKT_AES_H

#include "fkt_compat.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Expand 32-byte key → 60 round words (AES-256). */
void fkt_aes256_set_encrypt_key(const uint8_t key[32], uint32_t rk[60]);

/* Encrypt one 16-byte block in-place (or out may equal in). */
void fkt_aes256_encrypt_block(const uint32_t rk[60],
                              const uint8_t in[16],
                              uint8_t out[16]);

#ifdef __cplusplus
}
#endif
#endif
