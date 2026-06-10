#ifndef FKT_PSBT_H
#define FKT_PSBT_H

#include "fkt_compat.h"   /* uint8_t, uint32_t, etc. */
#include <stddef.h>       /* size_t */

/* -------------------------------------------------------------------------
 * PSBT constants (BIP-174)
 * ------------------------------------------------------------------------- */
#define FKT_PSBT_MAGIC_0              0x70
#define FKT_PSBT_MAGIC_1              0x73
#define FKT_PSBT_MAGIC_2              0x62
#define FKT_PSBT_MAGIC_3              0x74
#define FKT_PSBT_MAGIC_4              0xFF

#define FKT_PSBT_SEPARATOR            0x00

#define FKT_PSBT_MAX_SIZE             1572864UL

/* global map key types */
#define FKT_PSBT_GLOBAL_UNSIGNED_TX   0x00

/* input map key types */
#define FKT_PSBT_IN_NON_WITNESS_UTXO      0x00
#define FKT_PSBT_IN_WITNESS_UTXO          0x01
#define FKT_PSBT_IN_PARTIAL_SIG           0x02
#define FKT_PSBT_IN_SIGHASH_TYPE          0x03
#define FKT_PSBT_IN_REDEEM_SCRIPT         0x04
#define FKT_PSBT_IN_WITNESS_SCRIPT_05     0x05
#define FKT_PSBT_IN_BIP32_DERIVATION      0x06
#define FKT_PSBT_IN_FINAL_SCRIPTSIG       0x07
#define FKT_PSBT_IN_FINAL_SCRIPTWITNESS   0x08
#define FKT_PSBT_IN_TAP_BIP32_DERIVATION  0x16
#define FKT_PSBT_IN_TAP_INTERNAL_KEY      0x18
#define FKT_PSBT_IN_TAP_MERKLE_ROOT       0x19
#define FKT_PSBT_IN_PROPRIETARY           0xFC

/* output map key types */
#define FKT_PSBT_OUT_WITNESS_SCRIPT       0x00
#define FKT_PSBT_OUT_REDEEM_SCRIPT        0x01
#define FKT_PSBT_OUT_BIP32_DERIVATION     0x02

/* sighash types */
#define FKT_SIGHASH_DEFAULT     0x00
#define FKT_SIGHASH_ALL         0x01
#define FKT_SIGHASH_NONE        0x02
#define FKT_SIGHASH_SINGLE      0x03

/* script type identifiers */
#define SCRIPT_TYPE_UNKNOWN      0
#define SCRIPT_TYPE_P2WPKH       1
#define SCRIPT_TYPE_P2WSH        2
#define SCRIPT_TYPE_P2TR         3
#define SCRIPT_TYPE_P2SH         4
#define SCRIPT_TYPE_P2SH_P2WPKH  5

/* ---- shared data (used by sighash and signer) ---- */
#define MAX_PSBT_ITEMS 256

typedef struct {
    uint8_t  raw_unsigned_tx[FKT_PSBT_MAX_SIZE];
    size_t   unsigned_tx_len;
    int      num_inputs;
    int      num_outputs;

    uint8_t  input_redeem_script     [MAX_PSBT_ITEMS][520];
    size_t   input_redeem_script_len [MAX_PSBT_ITEMS];
    int      input_has_redeem_script [MAX_PSBT_ITEMS];

    uint8_t  input_txid        [MAX_PSBT_ITEMS][32];
    uint32_t input_vout        [MAX_PSBT_ITEMS];
    uint32_t input_sequence    [MAX_PSBT_ITEMS];
    int64_t  input_amount      [MAX_PSBT_ITEMS];
    int      input_has_amount  [MAX_PSBT_ITEMS];
    uint8_t  input_script_type [MAX_PSBT_ITEMS];
    uint32_t input_sighash     [MAX_PSBT_ITEMS];
    int      input_has_sighash [MAX_PSBT_ITEMS];
    int      input_has_tap_int_key [MAX_PSBT_ITEMS];
    uint8_t  input_witness_script     [MAX_PSBT_ITEMS][520];
    size_t   input_witness_script_len [MAX_PSBT_ITEMS];
    int      input_has_witness_script [MAX_PSBT_ITEMS];

    int64_t  output_amount      [MAX_PSBT_ITEMS];
    uint8_t  output_script      [MAX_PSBT_ITEMS][520];
    size_t   output_script_len  [MAX_PSBT_ITEMS];

    uint32_t locktime;
    uint8_t  psbt_fingerprint[32];
    uint8_t  txid[32];
    int      hashes_computed;
} fkt_psbt_state;

extern fkt_psbt_state psbt_data;

extern uint8_t hashPrevouts[32];
extern uint8_t hashSequence[32];
extern uint8_t hashOutputs[32];
extern size_t input_separator_offsets[MAX_PSBT_ITEMS];
extern int    input_separator_count;
extern uint8_t sha_prevouts[32];
extern uint8_t sha_amounts[32];
extern uint8_t sha_scriptpubkeys[32];
extern uint8_t sha_sequences[32];
extern uint8_t sha_outputs[32];
extern uint8_t  psbt_buffer[FKT_PSBT_MAX_SIZE];
extern size_t   psbt_size;


/* parser / preview API */
void fkt_psbt_init(void);
int  fkt_psbt_load_file(const char *path);
int  fkt_psbt_load_base64(const char *b64_str);
void fkt_psbt_parse(void);
void fkt_psbt_preview(void);

const uint8_t* fkt_get_witness_script(int input_index, size_t *out_len);

#endif