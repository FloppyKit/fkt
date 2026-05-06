/* fkt_psbt.h — PSBT decoder, BIP-143 sighash, and signer for BIP-84 (v0.1) */
#ifndef FKT_PSBT_H
#define FKT_PSBT_H

#include <stdint.h>
#include <stddef.h>

enum {
    FKT_OK = 0,
    FKT_ERR_INVALID_MAGIC = -1,
    FKT_ERR_PATH_PARSE = -2,
    FKT_ERR_MASTER_KEY = -3,
    FKT_ERR_MALLOC = -4,
    FKT_ERR_MISSING_GLOBAL_TX = -5,
    FKT_ERR_NO_MATCHING_INPUT = -6,
    FKT_ERR_FILE_IO = -7,
    FKT_ERR_PARSE = -8,
    FKT_ERR_MISSING_UTXO = -9,
};

int fkt_psbt_sign(const uint8_t *psbt_in, size_t psbt_len,
                  const uint8_t *master_priv, const uint8_t *master_chain,
                  const char *fixed_path,
                  uint8_t **psbt_out, size_t *psbt_out_len);

#endif /* FKT_PSBT_H */