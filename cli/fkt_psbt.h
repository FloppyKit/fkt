#ifndef FKT_PSBT_H
#define FKT_PSBT_H

#include "fkt_compat.h"   /* provides uint8_t, uint16_t, uint32_t, int64_t etc. */

/* -------------------------------------------------------------------------
 * PSBT magic and structural constants (BIP-174)
 * ------------------------------------------------------------------------- */
#define FKT_PSBT_MAGIC_0  0x70
#define FKT_PSBT_MAGIC_1  0x73
#define FKT_PSBT_MAGIC_2  0x62
#define FKT_PSBT_MAGIC_3  0x74
#define FKT_PSBT_MAGIC_4  0xFF

#define FKT_PSBT_SEPARATOR  0x00   /* map terminator */

/* Maximum total PSBT size: 1.5 MiB */
#define FKT_PSBT_MAX_SIZE   1572864UL

/* ---- documented key types for each map ---- */
/* global */
#define FKT_PSBT_GLOBAL_UNSIGNED_TX   0x00

/* input */
#define FKT_PSBT_IN_NON_WITNESS_UTXO       0x00
#define FKT_PSBT_IN_WITNESS_UTXO           0x01
#define FKT_PSBT_IN_SIGHASH_TYPE           0x03
#define FKT_PSBT_IN_REDEEM_SCRIPT          0x06
#define FKT_PSBT_IN_FINAL_SCRIPTSIG        0x07
#define FKT_PSBT_IN_FINAL_SCRIPTWITNESS    0x08
#define FKT_PSBT_IN_WITNESS_SCRIPT         0x16
#define FKT_PSBT_IN_TAP_INTERNAL_KEY       0x17
#define FKT_PSBT_IN_TAP_MERKLE_ROOT        0x18

/* output: none are recognised (refuse any key) */

/* SIGHASH values we enforce */
#define FKT_SIGHASH_ALL                    0x01
#define FKT_SIGHASH_DEFAULT                0x00   /* Taproot */

/* script type identifiers (derived from witness UTXO) */
#define SCRIPT_TYPE_UNKNOWN                0
#define SCRIPT_TYPE_P2WPKH                 1
#define SCRIPT_TYPE_P2TR                   2

/* -------------------------------------------------------------------------
 * Public API – parser & preview (read‑only, no secret material touched)
 * ------------------------------------------------------------------------- */
void fkt_psbt_init(void);
int  fkt_psbt_load_file(const char *path);
int  fkt_psbt_load_base64(const char *b64_str);
void fkt_psbt_parse(void);
void fkt_psbt_preview(void);

#endif /* FKT_PSBT_H */