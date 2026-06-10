#ifndef FKT_PSBT_H
#define FKT_PSBT_H
#define SCRIPT_TYPE_P2SH_P2WPKH 5

#include "fkt_compat.h"   /* provides uint8_t, uint16_t, uint32_t, int64_t etc. */
#include <stddef.h>     

/* -------------------------------------------------------------------------
 * PSBT magic and structural constants (BIP-174)
 * ------------------------------------------------------------------------- */
#define FKT_PSBT_MAGIC_0  0x70
#define FKT_PSBT_MAGIC_1  0x73
#define FKT_PSBT_MAGIC_2  0x62
#define FKT_PSBT_MAGIC_3  0x74
#define FKT_PSBT_MAGIC_4  0xFF

#define FKT_PSBT_SEPARATOR  0x00

#define FKT_PSBT_MAX_SIZE   1572864UL

/* global */
#define FKT_PSBT_GLOBAL_UNSIGNED_TX   0x00

/* input */
#define FKT_PSBT_IN_NON_WITNESS_UTXO       0x00
#define FKT_PSBT_IN_WITNESS_UTXO           0x01
#define FKT_PSBT_IN_PARTIAL_SIG            0x02
#define FKT_PSBT_IN_SIGHASH_TYPE           0x03
#define FKT_PSBT_IN_REDEEM_SCRIPT          0x04   /* Redeem script (key 0x04) */
#define FKT_PSBT_IN_WITNESS_SCRIPT_05      0x05   /* Witness script (key 0x05) */
#define FKT_PSBT_IN_BIP32_DERIVATION       0x06   /* BIP32 derivation (key 0x06) */
#define FKT_PSBT_IN_FINAL_SCRIPTSIG        0x07
#define FKT_PSBT_IN_FINAL_SCRIPTWITNESS    0x08
#define FKT_PSBT_IN_TAP_BIP32_DERIVATION   0x16   /* Taproot BIP32 derivation (key 0x16) */
#define FKT_PSBT_IN_TAP_INTERNAL_KEY       0x18
#define FKT_PSBT_IN_TAP_MERKLE_ROOT        0x19
#define FKT_PSBT_IN_PROPRIETARY            0xFC

/* output */
#define FKT_PSBT_OUT_WITNESS_SCRIPT        0x00
#define FKT_PSBT_OUT_REDEEM_SCRIPT         0x01
#define FKT_PSBT_OUT_BIP32_DERIVATION      0x02

/* SIGHASH values */
#define FKT_SIGHASH_ALL                    0x01
#define FKT_SIGHASH_DEFAULT                0x00

/* script type identifiers */
#define SCRIPT_TYPE_UNKNOWN                0
#define SCRIPT_TYPE_P2WPKH                 1
#define SCRIPT_TYPE_P2WSH                  3
#define SCRIPT_TYPE_P2TR                   2
#define SCRIPT_TYPE_P2SH                   4


int fkt_derive_from_path(const uint8_t seed[64],
                         const char *path_str,
                         uint8_t child_priv[32],
                         uint8_t child_pub33[33]);

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */
void fkt_psbt_init(void);
int  fkt_psbt_load_file(const char *path);
int  fkt_psbt_load_base64(const char *b64_str);
void fkt_psbt_parse(void);
void fkt_psbt_preview(void);
/* Key derivation demo (temporary) */
void fkt_key_derive_demo(void);
int fkt_test_bip32(void);
void fkt_sign_demo(const char *psbt_file);

int fkt_sign_psbt(const uint8_t seed[64], const char *path_str,
                  const char *psbt_file, const char *output_file);

/* Return the witness script for a parsed input.  out_len receives the length.
   Returns NULL if the input doesn't have a witness script. */
const uint8_t* fkt_get_witness_script(int input_index, size_t *out_len);

#endif /* FKT_PSBT_H */