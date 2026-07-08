#ifndef FKT_PSBT_H
#define FKT_PSBT_H

#include "fkt_compat.h"   /* uint8_t, uint32_t, etc. */
#include <stddef.h>       /* size_t */
#include <setjmp.h>

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
#define FKT_PSBT_UNSIGNED_TX_MAX      102400UL
#define FKT_PSBT_NON_WITNESS_UTXO_MAX 102400UL
#define FKT_PSBT_MAX_OUTPUTS          64
/* Max chars for UI/CLI PSBT path or pasted base64 (≈6 KB raw PSBT). */
#define FKT_PSBT_INPUT_MAX            8192

/* global map key types */
#define FKT_PSBT_GLOBAL_UNSIGNED_TX   0x00
#define FKT_PSBT_GLOBAL_XPUB          0x01

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
#define FKT_PSBT_IN_TAP_INTERNAL_KEY      0x17
#define FKT_PSBT_IN_TAP_MERKLE_ROOT       0x18
#define FKT_PSBT_IN_PROPRIETARY           0xFC

/* output map key types */
#define FKT_PSBT_OUT_WITNESS_SCRIPT       0x00
#define FKT_PSBT_OUT_REDEEM_SCRIPT        0x01
#define FKT_PSBT_OUT_BIP32_DERIVATION     0x02
#define FKT_PSBT_OUT_TAP_INTERNAL_KEY     0x05
#define FKT_PSBT_OUT_TAP_TREE             0x06
#define FKT_PSBT_OUT_TAP_BIP32_DERIVATION 0x07
#define FKT_PSBT_OUT_PROPRIETARY          0xFC

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
#define SCRIPT_TYPE_P2PKH        6

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
    uint8_t  input_tap_int_key     [MAX_PSBT_ITEMS][32];
    uint8_t  input_witness_script     [MAX_PSBT_ITEMS][520];
    size_t   input_witness_script_len [MAX_PSBT_ITEMS];
    int      input_has_witness_script [MAX_PSBT_ITEMS];
    uint8_t  input_redeem_witness_script     [MAX_PSBT_ITEMS][520];
    size_t   input_redeem_witness_script_len [MAX_PSBT_ITEMS];
    int      input_has_redeem_witness_script [MAX_PSBT_ITEMS];

    uint32_t input_deriv_path         [MAX_PSBT_ITEMS][10];
    int      input_deriv_depth        [MAX_PSBT_ITEMS];
    int      input_has_deriv_path     [MAX_PSBT_ITEMS];
    uint8_t  input_deriv_parent_pub   [MAX_PSBT_ITEMS][33];
    int      input_has_deriv_parent_pub [MAX_PSBT_ITEMS];
    int      input_had_final_witness    [MAX_PSBT_ITEMS];
    int      input_had_final_scriptsig  [MAX_PSBT_ITEMS];

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
extern size_t input_map_start_offsets[MAX_PSBT_ITEMS];
extern int    input_separator_count;
extern size_t output_separator_offsets[MAX_PSBT_ITEMS];
extern size_t output_map_start_offsets[MAX_PSBT_ITEMS];
extern int    output_separator_count;
extern uint8_t sha_prevouts[32];
extern uint8_t sha_amounts[32];
extern uint8_t sha_scriptpubkeys[32];
extern uint8_t sha_sequences[32];
extern uint8_t sha_outputs[32];
extern uint8_t  psbt_buffer[FKT_PSBT_MAX_SIZE];
extern size_t   psbt_size;


/* parser / preview API */
void fkt_psbt_init(void);
void fkt_psbt_set_argv0(const char *argv0);
int  fkt_psbt_load_file(const char *path);
int  fkt_psbt_load_base64(const char *b64_str);
int  fkt_psbt_bytes_to_base64(const uint8_t *data, size_t len, char *out, size_t out_max);
int  fkt_psbt_loaded_to_base64(char *out, size_t out_max);
int  fkt_psbt_file_to_base64(const char *path, char *out, size_t out_max);
int  fkt_psbt_load_input(const char *input);
void fkt_psbt_parse(void);

/* Fuzz-only: skips finalized-witness, sighash, and fee checks. Never set in production. */
extern int fkt_psbt_lenient_parse;
extern int fkt_psbt_fuzz_mode;
extern jmp_buf fkt_psbt_fuzz_jmp;

int  fkt_psbt_load_memory(const uint8_t *data, size_t len);
int  fkt_psbt_try_parse(void);

const uint8_t* fkt_get_witness_script(int input_index, size_t *out_len);

int  fkt_psbt_input_has_derivation(int input_index);
int  fkt_psbt_input_derivation_depth(int input_index);
const uint32_t *fkt_psbt_input_derivation_path(int input_index);
const uint8_t *fkt_psbt_input_derivation_parent_pub(int input_index);
int  fkt_psbt_format_derivation_path(int input_index, char *buf, size_t buf_len);

#endif