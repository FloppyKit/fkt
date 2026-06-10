/* fkt_crypto.h — function prototypes for v0.99 Phase 1 */

#ifndef FKT_CRYPTO_H
#define FKT_CRYPTO_H

#include "fkt_compat.h"
#include <stddef.h>
#include <stdint.h>

void init_secp256k1(void);

void fkt_sha512(const uint8_t *message, size_t len, uint8_t digest[64]);
void fkt_hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[64]);
void fkt_pbkdf2_hmac_sha512(const char *password, const char *salt, int iterations, uint8_t *out, size_t out_len);

void fkt_sha256(const uint8_t *message, size_t len, uint8_t digest[32]);
void fkt_sha256d(const uint8_t *message, size_t len, uint8_t digest[32]);
void fkt_ripemd160(const uint8_t *message, size_t len, uint8_t digest[20]);
void fkt_hash160(const uint8_t *message, size_t len, uint8_t digest[20]);

void fkt_bip32_master_from_seed(const uint8_t *seed, size_t seed_len, uint8_t chain_code[32], uint8_t master_priv[32]);
void fkt_derive_full_bip84_child(const uint8_t *master_priv, const uint8_t *master_chain,
                                 uint8_t child_priv[32], uint8_t child_chain[32]);

int  fkt_ecdsa_sign(const uint8_t *privkey, const uint8_t *msg32, uint8_t *sig_out, size_t *sig_len);
void finalize_psbt_with_witness(const char *psbt_input, char *out_signed, size_t out_size, const uint8_t *child_priv);
void generate_ascii_qr(const char *data, char *out_qr, size_t out_size);
void print_xpub(const uint8_t *chain_code, const uint8_t *master_priv);

#endif /* FKT_CRYPTO_H */