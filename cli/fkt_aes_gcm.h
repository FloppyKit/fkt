/* fkt_aes_gcm.h – AES-256-GCM (Warm seed file). C89. */
#ifndef FKT_AES_GCM_H
#define FKT_AES_GCM_H

#include "fkt_compat.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Encrypt: ciphertext may be same buffer as plaintext (in-place).
 * aad may be NULL if aad_len==0.
 * nonce_len must be 12 (recommended). tag is 16 bytes.
 * Returns 0 ok, -1 on bad args.
 */
int fkt_aes256_gcm_encrypt(const uint8_t key[32],
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct,
                           uint8_t tag[16]);

/*
 * Decrypt + verify tag. Returns 0 ok, -1 auth fail or bad args.
 * On failure, pt contents are not trusted (zeroed when possible).
 */
int fkt_aes256_gcm_decrypt(const uint8_t key[32],
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[16],
                           uint8_t *pt);

#ifdef __cplusplus
}
#endif
#endif
