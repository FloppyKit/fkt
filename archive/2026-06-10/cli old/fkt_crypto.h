/* fkt_crypto.h - Cryptographic primitives for FKT signer (v0.1) */
#ifndef FKT_CRYPTO_H
#define FKT_CRYPTO_H

#include "fkt_compat.h"        /* provides uint8_t, uint32_t, int64_t, etc. */
#include "secp256k1.h"         /* secp256k1_context, secp256k1_pubkey, ... */

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise crypto library (secp256k1 context, etc.). Safe to call multiple times. */
void fkt_crypto_init(void);

/* Return the global secp256k1 context. Created on first use if needed. */
secp256k1_context* fkt_crypto_ctx(void);

/* -------------------------------------------------------------------------
 * SHA-256 – streaming and one‑shot
 * ------------------------------------------------------------------------- */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} fkt_sha256_ctx;

void fkt_sha256_init(fkt_sha256_ctx *ctx);
void fkt_sha256_update(fkt_sha256_ctx *ctx, const uint8_t *data, size_t len);
void fkt_sha256_final(fkt_sha256_ctx *ctx, uint8_t digest[32]);

/* One‑shot SHA-256 */
void fkt_sha256(const uint8_t *message, size_t len, uint8_t digest[32]);

/* Double SHA-256 (Bitcoin standard) */
void fkt_sha256d(const uint8_t *message, size_t len, uint8_t digest[32]);

/* -------------------------------------------------------------------------
 * RIPEMD-160 (one‑shot, little‑endian length encoding)
 * ------------------------------------------------------------------------- */
void fkt_ripemd160(const uint8_t *message, size_t len, uint8_t digest[20]);

/* HASH160 = RIPEMD160(SHA256(x)) */
void fkt_hash160(const uint8_t *message, size_t len, uint8_t digest[20]);

/* -------------------------------------------------------------------------
 * SHA-512 – one‑shot
 * ------------------------------------------------------------------------- */
void fkt_sha512(const uint8_t *message, size_t len, uint8_t digest[64]);

/* HMAC-SHA512 (RFC 2104) */
void fkt_hmac_sha512(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[64]);

/* -------------------------------------------------------------------------
 * BIP32 key derivation
 * ------------------------------------------------------------------------- */

/* Master key from a 64‑byte seed */
void fkt_bip32_master(const uint8_t seed[64],
                      uint8_t master_priv[32],
                      uint8_t master_chain[32]);

/* Derive a single child key. Returns 0 on success, -1 on error. */
int fkt_bip32_derive_child(const uint8_t parent_priv[32],
                           const uint8_t parent_chain[32],
                           uint32_t index, int hardened,
                           uint8_t child_priv[32],
                           uint8_t child_chain[32]);

/* Derive a full 5‑hop BIP32 path (e.g. m/84'/0'/0'/0/0).
   On success, returns 0 and fills derived_priv (32) and derived_pub33 (33, compressed). */
int fkt_derive_path(const uint8_t master_priv[32],
                    const uint8_t master_chain[32],
                    const uint32_t path[5],
                    uint8_t derived_priv[32],
                    uint8_t derived_pub33[33]);

 int fkt_schnorr_sign(const uint8_t privkey[32], const uint8_t msg[32],
                     uint8_t sig[64], int *sig_len);

/* -------------------------------------------------------------------------
 * Secure memory zeroing
 * ------------------------------------------------------------------------- */
void fkt_zerobytes(volatile void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* FKT_CRYPTO_H */