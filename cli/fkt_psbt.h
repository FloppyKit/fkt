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

/* Maximum total PSBT size: 1.5 MiB (fits in a static buffer) */
#define FKT_PSBT_MAX_SIZE   1572864UL

/* ---- documented key types for each map ---- */
/* global */
#define FKT_PSBT_GLOBAL_UNSIGNED_TX   0x00

/* input */
#define FKT_PSBT_IN_NON_WITNESS_UTXO  0x00
#define FKT_PSBT_IN_WITNESS_UTXO      0x01
#define FKT_PSBT_IN_FINAL_SCRIPTSIG   0x07   /* forbidden during parsing */
#define FKT_PSBT_IN_FINAL_SCRIPTWITNESS 0x08 /* forbidden during parsing */

/* output: none are recognised (refuse any key) */

/* -------------------------------------------------------------------------
 * Public API – parser & preview (read‑only, no secret material touched)
 * ------------------------------------------------------------------------- */
void fkt_psbt_init(void);

/* load PSBT from a binary file (returns 0 on success, -1 on failure) */
int  fkt_psbt_load_file(const char *path);

/* load PSBT from a null‑terminated Base64 string (returns 0 on success, -1 on failure) */
int  fkt_psbt_load_base64(const char *b64_str);

/* strict parse – hard‑aborts on any violation */
void fkt_psbt_parse(void);

/* human‑readable preview (txid, inputs, outputs, fee, fingerprint) */
void fkt_psbt_preview(void);

#endif /* FKT_PSBT_H */