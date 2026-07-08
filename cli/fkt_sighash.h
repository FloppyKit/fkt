/* fkt_sighash.h */
#ifndef FKT_SIGHASH_H
#define FKT_SIGHASH_H
#include <stdint.h>
#include "fkt_compat.h"
#ifdef __cplusplus
extern "C" {
#endif

void fkt_compute_hash_caches(void);

/* BIP-143 for P2WPKH */
int fkt_bip143_sighash(int input_index,
                       const uint8_t scriptpubkey[22],
                       uint8_t sighash[32]);

/* BIP-143 for P2SH-P2WPKH (redeem script = witness program) */
int fkt_bip143_sighash_p2sh_p2wpkh(int input_index,
                                   const uint8_t redeem_script[22],
                                   uint8_t sighash[32]);

/* BIP-143 for P2WSH (scriptCode = full witness/redeem script) */
int fkt_bip143_sighash_p2wsh(int input_index,
                             const uint8_t *witness_script, size_t witness_script_len,
                             uint8_t sighash[32]);

/* BIP-341 key-path (basic) */
int fkt_bip341_sighash(int input_index, uint8_t sighash[32]);

/* Legacy pre-segwit P2PKH (SIGHASH_ALL) */
int fkt_legacy_p2pkh_sighash(int input_index,
                             const uint8_t *scriptpubkey, size_t scriptpubkey_len,
                             uint32_t sighash_type,
                             uint8_t sighash[32]);

#ifdef __cplusplus
}
#endif
#endif