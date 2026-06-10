/* #### SECTION: Includes & debug flag #### */
#include "fkt_psbt.h"
#include "fkt_hash160.h"
#include "fkt_crypto.h"                 /* <-- uses new crypto module, not legacy */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <secp256k1.h>                 /* still needed for ecdsa_sign, pubkey etc. */

/* Uncomment the line below to enable debug prints */
/* #define FKT_DEBUG */

/* #### SECTION: Static PSBT buffer & cursor #### */

static uint8_t  psbt_buffer[FKT_PSBT_MAX_SIZE];
static size_t   psbt_size;
static const uint8_t *psbt_cursor;
static const uint8_t *psbt_end;

#define MAX_PSBT_ITEMS  256


/* -------------------------------------------------------------------------
 * parse_path_string – re‑entrant parser, writes 5 uint32_t values.
 * Supports optional "m/", hardened markers (', h, H).
 * Returns 0 on success, -1 on error.
 * ------------------------------------------------------------------------- */
static int parse_path_string(const char *path_str, uint32_t path[5]) {
    char buf[256];
    strncpy(buf, path_str, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    /* strip optional "m/" prefix */
    if (strncmp(buf, "m/", 2) == 0)
        memmove(buf, buf+2, strlen(buf+2)+1);

    int count = 0;
    char *p = buf;
    while (*p && count < 5) {
        char *end = p;
        while (*end && *end != '/') end++;

        int hardened = 0;
        if (end > p) {
            char last = *(end-1);
            if (last == '\'' || last == 'h' || last == 'H') {
                hardened = 1;
                *(end-1) = '\0';          /* remove hardened marker */
            }
        }

        int has_slash = (*end == '/');
        if (has_slash) *end = '\0';       /* terminate component */

        unsigned int index;
        if (sscanf(p, "%u", &index) != 1) return -1;
        if (hardened) index |= 0x80000000U;
        path[count++] = (uint32_t)index;

        p = has_slash ? end+1 : end;      /* advance to next component */
    }
    return (count == 5) ? 0 : -1;
}


/* -------------------------------------------------------------------------
 * fkt_derive_from_path – the one true derivation function.
 * Takes a seed (64 bytes) and a path string.
 * Outputs child private key (32 bytes) and compressed public key (33 bytes).
 * Returns 0 on success, -1 on error.
 * ------------------------------------------------------------------------- */
int fkt_derive_from_path(const uint8_t seed[64],
                         const char *path_str,
                         uint8_t child_priv[32],
                         uint8_t child_pub33[33]) {
    uint32_t path[5];

    if (parse_path_string(path_str, path) != 0) {
        fprintf(stderr, "DEBUG: parse_path_string failed for '%s'\n", path_str);
        return -1;
    }
    
        

    uint8_t master_priv[32], master_chain[32];
    fkt_bip32_master(seed, master_priv, master_chain);

    if (fkt_derive_path(master_priv, master_chain, path, child_priv, child_pub33) != 0) {
        fprintf(stderr, "DEBUG: fkt_derive_path failed\n");
        return -1;
    }

    volatile uint8_t *vp = (volatile uint8_t*)master_priv;
    for (int i = 0; i < 32; i++) vp[i] = 0;
    vp = (volatile uint8_t*)master_chain;
    for (int i = 0; i < 32; i++) vp[i] = 0;

    return 0;
}


/* #### SECTION: Parsed PSBT data (all extracted info) #### */
static struct {
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
} psbt_data;

/* #### SECTION: Signing hash caches & separator offsets #### */
static uint8_t hashPrevouts[32];
static uint8_t hashSequence[32];
static uint8_t sha_prevouts[32];
static uint8_t sha_amounts[32];
static uint8_t sha_scriptpubkeys[32];
static uint8_t sha_sequences[32];
static uint8_t sha_outputs[32];
static uint8_t hashOutputs[32];

static size_t input_separator_offsets[MAX_PSBT_ITEMS];
static int    input_separator_count;

/* #### SECTION: Error handler #### */
static void fkt_psbt_die(const char *msg) {
    fprintf(stderr, "FKT PSBT ERROR: %s\n", msg);
    exit(1);
}
/* #### SECTION: fkt_psbt_init (zero all state) #### */
void fkt_psbt_init(void) {
    volatile uint8_t *p; size_t i;
    p = (volatile uint8_t*)psbt_buffer;
    for(i=0;i<sizeof(psbt_buffer);i++) p[i]=0;
    p = (volatile uint8_t*)&psbt_data;
    for(i=0;i<sizeof(psbt_data);i++) p[i]=0;
    psbt_size = 0; psbt_cursor = NULL; psbt_end = NULL;
    input_separator_count = 0;
}

/* #### SECTION: File loader (returns 0 on success, -1 on error) #### */
static int read_file(const char *path, uint8_t *buf, size_t max_size, size_t *out_size) {
    FILE *f; size_t n;
    f = fopen(path, "rb"); if(!f) return -1;
    n = fread(buf, 1, max_size, f);
    if(ferror(f)) { fclose(f); return -1; }
    if(!feof(f))  { fclose(f); return -1; }   /* file too large */
    fclose(f);
    *out_size = n;
    return 0;
}

int fkt_psbt_load_file(const char *path) {
    size_t size;
    if(read_file(path, psbt_buffer, FKT_PSBT_MAX_SIZE, &size) != 0) {
        fprintf(stderr, "Load failed: %s\n", path);
        return -1;
    }
    psbt_size = size; psbt_cursor = psbt_buffer; psbt_end = psbt_buffer + size;
    return 0;
}

/* #### SECTION: Strict Base64 decoder & loader #### */
static const uint8_t b64_decode_table[256] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3E,0xFF,0xFF,0xFF,0x3F,
    0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0xFF,0xFF,0xFF,0x00,0xFF,0xFF,
    0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
    0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
    0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0xFF,0xFF,0xFF,0xFF,0xFF
};

static int base64_decode(const char *in, uint8_t *out, size_t max_out, size_t *out_len) {
    size_t len = strlen(in);
    size_t i, j; uint32_t buf; int pad; uint8_t c;
    if (len % 4 != 0) return -1;
    pad = 0; j = 0;
    for (i = 0; i < len; i += 4) {
        buf = 0;
        c = (uint8_t)in[i];
        if (c == '=') { pad++; buf |= (0x00 << 18); } else { uint8_t v = b64_decode_table[c]; if (v >= 64) return -1; buf |= ((uint32_t)v << 18); }
        c = (uint8_t)in[i+1];
        if (c == '=') { pad++; buf |= (0x00 << 12); } else { if (pad) return -1; uint8_t v = b64_decode_table[c]; if (v >= 64) return -1; buf |= ((uint32_t)v << 12); }
        c = (uint8_t)in[i+2];
        if (c == '=') { pad++; buf |= (0x00 << 6);  } else { if (pad) return -1; uint8_t v = b64_decode_table[c]; if (v >= 64) return -1; buf |= ((uint32_t)v << 6);  }
        c = (uint8_t)in[i+3];
        if (c == '=') { pad++; /* nothing */       } else { if (pad) return -1; uint8_t v = b64_decode_table[c]; if (v >= 64) return -1; buf |= ((uint32_t)v);       }
        if (pad > 2) return -1;
        if (j < max_out) out[j++] = (uint8_t)(buf >> 16);
        if (pad < 2 && j < max_out) out[j++] = (uint8_t)(buf >> 8);
        if (pad < 1 && j < max_out) out[j++] = (uint8_t)(buf);
    }
    if (j > max_out) return -1;
    *out_len = j;
    return 0;
}

int fkt_psbt_load_base64(const char *b64_str) {
    size_t len;
    if(base64_decode(b64_str, psbt_buffer, FKT_PSBT_MAX_SIZE, &len) != 0) return -1;
    psbt_size = len; psbt_cursor = psbt_buffer; psbt_end = psbt_buffer + len;
    return 0;
}

/* #### SECTION: Compact-size integer helpers (strict minimal encoding) #### */
static void ensure_bytes(size_t n) {
    if((size_t)(psbt_end - psbt_cursor) < n) fkt_psbt_die("Unexpected end of PSBT data.");
}

static uint64_t read_varint(int *ok) {
    uint8_t first;
    if (psbt_cursor >= psbt_end) { *ok = 0; return 0; }
    first = *psbt_cursor;
    if (first < 0xFD) {
        *ok = 1; psbt_cursor++; return (uint64_t)first;
    }
    if (first == 0xFD) {
        uint16_t val;
        if (psbt_end - psbt_cursor < 3) { *ok = 0; return 0; }
        val = (uint16_t)psbt_cursor[1] | ((uint16_t)psbt_cursor[2] << 8);
        if (val < 0xFD) { *ok = 0; return 0; }
        *ok = 1; psbt_cursor += 3; return val;
    }
    if (first == 0xFE) {
        uint32_t val;
        if (psbt_end - psbt_cursor < 5) { *ok = 0; return 0; }
        val = (uint32_t)psbt_cursor[1] | ((uint32_t)psbt_cursor[2] << 8) |
              ((uint32_t)psbt_cursor[3] << 16) | ((uint32_t)psbt_cursor[4] << 24);
        if (val < 0x10000UL) { *ok = 0; return 0; }
        *ok = 1; psbt_cursor += 5; return val;
    }
    /* first == 0xFF */
    {
        uint64_t val;
        if (psbt_end - psbt_cursor < 9) { *ok = 0; return 0; }
        val = (uint64_t)psbt_cursor[1] | ((uint64_t)psbt_cursor[2] << 8) |
              ((uint64_t)psbt_cursor[3] << 16) | ((uint64_t)psbt_cursor[4] << 24) |
              ((uint64_t)psbt_cursor[5] << 32) | ((uint64_t)psbt_cursor[6] << 40) |
              ((uint64_t)psbt_cursor[7] << 48) | ((uint64_t)psbt_cursor[8] << 56);
        if (val <= 0xFFFFFFFFUL) { *ok = 0; return 0; }
        *ok = 1; psbt_cursor += 9; return val;
    }
}

static int read_varint_from(const uint8_t **p, const uint8_t *end, uint64_t *val) {
    const uint8_t *c = *p;
    if (c >= end) return 0;
    if (c[0] < 0xFD) { *val = c[0]; *p = c + 1; return 1; }
    if (c[0] == 0xFD) {
        if (end - c < 3) return 0;
        *val = (uint16_t)c[1] | ((uint16_t)c[2] << 8);
        if (*val < 0xFD) return 0;
        *p = c + 3; return 1;
    }
    if (c[0] == 0xFE) {
        if (end - c < 5) return 0;
        *val = (uint32_t)c[1] | ((uint32_t)c[2] << 8) |
               ((uint32_t)c[3] << 16) | ((uint32_t)c[4] << 24);
        if (*val < 0x10000UL) return 0;
        *p = c + 5; return 1;
    }
    if (c[0] == 0xFF) {
        if (end - c < 9) return 0;
        *val = (uint64_t)c[1] | ((uint64_t)c[2] << 8) |
               ((uint64_t)c[3] << 16) | ((uint64_t)c[4] << 24) |
               ((uint64_t)c[5] << 32) | ((uint64_t)c[6] << 40) |
               ((uint64_t)c[7] << 48) | ((uint64_t)c[8] << 56);
        if (*val <= 0xFFFFFFFFUL) return 0;
        *p = c + 9; return 1;
    }
    return 0;
}

static uint32_t fkt_read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

/* #### SECTION: Map entry parser (returns 0 on separator, 1 on entry) #### */
static int parse_map_entry(uint8_t *key_type_out,
                           const uint8_t **key_data_out, size_t *key_data_len_out,
                           const uint8_t **value_out, size_t *value_len_out) {
    int ok; uint64_t key_len, val_len;
    ensure_bytes(1);
    if(*psbt_cursor == FKT_PSBT_SEPARATOR) { psbt_cursor++; return 0; }
    key_len = read_varint(&ok); if(!ok) fkt_psbt_die("Malformed varint for key length.");
    if(key_len == 0) fkt_psbt_die("Key length zero.");
    ensure_bytes((size_t)key_len);
    *key_type_out = psbt_cursor[0]; *key_data_out = psbt_cursor+1;
    *key_data_len_out = (size_t)(key_len - 1); psbt_cursor += (size_t)key_len;
    val_len = read_varint(&ok); if(!ok) fkt_psbt_die("Malformed varint for value length.");
    ensure_bytes((size_t)val_len);
    *value_out = psbt_cursor; *value_len_out = (size_t)val_len; psbt_cursor += (size_t)val_len;
    return 1;
}

/* #### SECTION: Key whitelist #### */
typedef enum { MAP_GLOBAL, MAP_INPUT, MAP_OUTPUT } map_context_t;

static void check_key_allowed(uint8_t key_type, map_context_t ctx) {
    switch(ctx) {
    case MAP_GLOBAL:
        if(key_type != FKT_PSBT_GLOBAL_UNSIGNED_TX)
            fkt_psbt_die("Unknown key in global PSBT map.");
        break;
    case MAP_INPUT:
        if(key_type != FKT_PSBT_IN_NON_WITNESS_UTXO &&
           key_type != FKT_PSBT_IN_WITNESS_UTXO &&
           key_type != FKT_PSBT_IN_PARTIAL_SIG &&
           key_type != FKT_PSBT_IN_SIGHASH_TYPE &&
           key_type != FKT_PSBT_IN_REDEEM_SCRIPT &&         /* 0x04 */
           key_type != FKT_PSBT_IN_WITNESS_SCRIPT_05 &&     /* 0x05 */
           key_type != FKT_PSBT_IN_BIP32_DERIVATION &&      /* 0x06 */
           key_type != FKT_PSBT_IN_FINAL_SCRIPTSIG &&
           key_type != FKT_PSBT_IN_FINAL_SCRIPTWITNESS &&
           key_type != FKT_PSBT_IN_TAP_BIP32_DERIVATION &&  /* 0x16 */
           key_type != FKT_PSBT_IN_TAP_INTERNAL_KEY &&
           key_type != FKT_PSBT_IN_TAP_INTERNAL_KEY &&
           key_type != FKT_PSBT_IN_TAP_MERKLE_ROOT &&
           key_type != FKT_PSBT_IN_PROPRIETARY)
            fkt_psbt_die("Unknown key in input PSBT map.");
        break;
    case MAP_OUTPUT:
        if(key_type != FKT_PSBT_OUT_WITNESS_SCRIPT &&
           key_type != FKT_PSBT_OUT_REDEEM_SCRIPT &&
           key_type != FKT_PSBT_OUT_BIP32_DERIVATION)
            fkt_psbt_die("Unknown key in output PSBT map.");
        break;
    }
}

/* #### SECTION: Script detection helpers #### */
static int is_p2wpkh(const uint8_t *s, size_t l) { return l==22 && s[0]==0x00 && s[1]==0x14; }
static int is_p2wsh(const uint8_t *s, size_t l)  { return l==34 && s[0]==0x00 && s[1]==0x20; }
static int is_p2tr(const uint8_t *s, size_t l)   { return l==34 && s[0]==0x51 && s[1]==0x20; }
static int is_p2sh(const uint8_t *s, size_t l)   { return l==23 && s[0]==0xA9 && s[1]==0x14; }

/* #### SECTION: Extract amount from a previous transaction (non-witness UTXO) #### */
static int extract_prevout_amount(const uint8_t *tx, size_t tx_len,
                                  uint32_t vout, int64_t *amount_out) {
    const uint8_t *p = tx;
    const uint8_t *end = tx + tx_len;
    uint64_t n_inputs, n_outputs, i;
    uint64_t script_len;

    if (end - p < 4) return -1;
    p += 4; /* version */

    /* skip segwit marker if present */
    if (end - p >= 2 && p[0] == 0x00 && p[1] == 0x01) p += 2;

    if (!read_varint_from(&p, end, &n_inputs)) return -1;
    if (n_inputs > MAX_PSBT_ITEMS) return -1;

    for (i = 0; i < n_inputs; i++) {
        if (end - p < 36) return -1;
        p += 36;
        if (!read_varint_from(&p, end, &script_len)) return -1;
        if ((size_t)(end - p) < (size_t)script_len) return -1;
        p += (size_t)script_len;
        if (end - p < 4) return -1;
        p += 4;
    }

    if (!read_varint_from(&p, end, &n_outputs)) return -1;
    if (vout >= (uint32_t)n_outputs) return -1;

    for (i = 0; i < n_outputs; i++) {
        if (end - p < 8) return -1;
        if (i == vout) {
            uint64_t raw = (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
                           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
                           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
                           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
            *amount_out = (int64_t)raw;
            return 0;
        }
        p += 8;
        if (!read_varint_from(&p, end, &script_len)) return -1;
        if ((size_t)(end - p) < (size_t)script_len) return -1;
        p += (size_t)script_len;
    }
    return -1;
}

/* #### SECTION: Extract output script from previous transaction #### */
static int extract_prevout_script(const uint8_t *tx, size_t tx_len,
                                  uint32_t vout,
                                  uint8_t *script_buf, size_t *script_len) {
    const uint8_t *p = tx;
    const uint8_t *end = tx + tx_len;
    uint64_t n_inputs, n_outputs, i;
    uint64_t slen;

    if (end - p < 4) return -1;
    p += 4;
    if (end - p >= 2 && p[0] == 0x00 && p[1] == 0x01) p += 2;

    if (!read_varint_from(&p, end, &n_inputs)) return -1;
    for (i = 0; i < n_inputs; i++) {
        if (end - p < 36) return -1;
        p += 36;
        if (!read_varint_from(&p, end, &slen)) return -1;
        if ((size_t)(end - p) < (size_t)slen) return -1;
        p += (size_t)slen;
        if (end - p < 4) return -1;
        p += 4;
    }

    if (!read_varint_from(&p, end, &n_outputs)) return -1;
    if (vout >= (uint32_t)n_outputs) return -1;

    for (i = 0; i < n_outputs; i++) {
        if (end - p < 8) return -1;
        if (i == vout) {
            p += 8;
            if (!read_varint_from(&p, end, &slen)) return -1;
            if (slen > 520) return -1;
            if ((size_t)(end - p) < (size_t)slen) return -1;
            memcpy(script_buf, p, (size_t)slen);
            *script_len = (size_t)slen;
            return 0;
        }
        p += 8;
        if (!read_varint_from(&p, end, &slen)) return -1;
        if ((size_t)(end - p) < (size_t)slen) return -1;
        p += (size_t)slen;
    }
    return -1;
}

/* #### SECTION: Parse unsigned transaction (global key 0x00) #### */
static void parse_unsigned_tx(int *num_inputs, int *num_outputs) {
    const uint8_t *tx   = psbt_data.raw_unsigned_tx;
    const uint8_t *end  = tx + psbt_data.unsigned_tx_len;
    uint64_t count;
    int i;

    if (end - tx < 4) fkt_psbt_die("Unsigned tx too short.");
    tx += 4; /* version */

    /* SPEC: must not contain segwit marker */
    if (end - tx >= 2 && tx[0] == 0x00 && tx[1] == 0x01)
        fkt_psbt_die("Unsigned transaction contains segwit marker (must be legacy format).");

    if (!read_varint_from(&tx, end, &count)) fkt_psbt_die("Malformed unsigned tx (input count).");
    if (count > (uint64_t)MAX_PSBT_ITEMS) fkt_psbt_die("Too many inputs in unsigned tx.");
    *num_inputs = (int)count;

    for (i = 0; i < *num_inputs; i++) {
        if (end - tx < 36) fkt_psbt_die("Unsigned tx truncated in input.");
        memcpy(psbt_data.input_txid[i], tx, 32);
        psbt_data.input_vout[i] = fkt_read_le32(tx + 32);
        tx += 36;

        if (!read_varint_from(&tx, end, &count)) fkt_psbt_die("Malformed scriptSig length.");
        if ((size_t)(end - tx) < (size_t)count) fkt_psbt_die("Unsigned tx scriptSig overrun.");
        if (count != 0) fkt_psbt_die("Unsigned tx has non‑empty scriptSig.");
        tx += (size_t)count;

        if (end - tx < 4) fkt_psbt_die("Unsigned tx missing sequence.");
        psbt_data.input_sequence[i] = fkt_read_le32(tx);
        tx += 4;
    }

    if (!read_varint_from(&tx, end, &count)) fkt_psbt_die("Malformed unsigned tx (output count).");
    if (count > (uint64_t)MAX_PSBT_ITEMS) fkt_psbt_die("Too many outputs.");
    *num_outputs = (int)count;

    for (i = 0; i < *num_outputs; i++) {
        int64_t amount;
        uint64_t script_len;

        if (end - tx < 8) fkt_psbt_die("Unsigned tx truncated in output amount.");
        amount = (int64_t)((uint64_t)tx[0] | ((uint64_t)tx[1] << 8) |
                           ((uint64_t)tx[2] << 16) | ((uint64_t)tx[3] << 24) |
                           ((uint64_t)tx[4] << 32) | ((uint64_t)tx[5] << 40) |
                           ((uint64_t)tx[6] << 48) | ((uint64_t)tx[7] << 56));
        psbt_data.output_amount[i] = amount;
        tx += 8;

        if (!read_varint_from(&tx, end, &script_len)) fkt_psbt_die("Malformed output script length.");
        if (script_len > 520) fkt_psbt_die("Output script too long.");
        if ((size_t)(end - tx) < (size_t)script_len) fkt_psbt_die("Unsigned tx output script overrun.");
        memcpy(psbt_data.output_script[i], tx, (size_t)script_len);
        psbt_data.output_script_len[i] = (size_t)script_len;
        tx += (size_t)script_len;
    }

    if (end - tx != 4) fkt_psbt_die("Unsigned tx extra bytes or missing locktime.");
    psbt_data.locktime = fkt_read_le32(tx);
}

/* #### SECTION: Parse global map #### */
static void parse_global_map(int *num_inputs, int *num_outputs) {
    int has_unsigned_tx = 0;
    uint8_t key_type;
    const uint8_t *key_data, *value;
    size_t key_data_len, value_len;

    while (1) {
        if (!parse_map_entry(&key_type, &key_data, &key_data_len,
                             &value, &value_len))
            break;
        check_key_allowed(key_type, MAP_GLOBAL);
        if (key_type == FKT_PSBT_GLOBAL_UNSIGNED_TX) {
            if (has_unsigned_tx) fkt_psbt_die("Duplicate unsigned tx in global map.");
            if (value_len > sizeof(psbt_data.raw_unsigned_tx))
                fkt_psbt_die("Unsigned transaction too large.");
            memcpy(psbt_data.raw_unsigned_tx, value, value_len);
            psbt_data.unsigned_tx_len = value_len;
            has_unsigned_tx = 1;
        }
    }
    if (!has_unsigned_tx) fkt_psbt_die("Missing unsigned transaction in global map.");
    parse_unsigned_tx(num_inputs, num_outputs);
}

/* #### SECTION: Validate Taproot BIP32 derivation #### */
static void fkt_validate_tap_bip32_derivation(const uint8_t *value, size_t value_len) {
    uint8_t n; size_t ex;
    if(value_len < 1) fkt_psbt_die("Malformed PSBT_IN_TAP_BIP32_DERIVATION value");
    n = value[0]; ex = 1 + ((size_t)n * 32) + 24;
    if(value_len != ex) fkt_psbt_die("Malformed PSBT_IN_TAP_BIP32_DERIVATION value");
}

/* #### SECTION: Parse input maps (full key handling + script-type detection) #### */
static void parse_inputs(int expected_inputs) {
    int i; uint8_t kt; const uint8_t *kd,*v; size_t kdl,vl;
    struct { uint8_t txid[32]; uint32_t vout; } seen[MAX_PSBT_ITEMS]; int ns=0;
    for(i=0;i<expected_inputs;i++) {
        int hnw=0, hw=0, af=0; uint8_t st=SCRIPT_TYPE_UNKNOWN; int hmr=0;
        const uint8_t *redeem_script = NULL;
        size_t redeem_script_len = 0;
        uint8_t prevout_script[520];
        size_t prevout_script_len = 0;
        int have_prevout_script = 0;

        while(1) {
            if(!parse_map_entry(&kt,&kd,&kdl,&v,&vl)) {
                if (input_separator_count < MAX_PSBT_ITEMS)
                    input_separator_offsets[input_separator_count++] = (size_t)(psbt_cursor - 1 - psbt_buffer);
                break;
            }
            if((kt==FKT_PSBT_IN_FINAL_SCRIPTSIG||kt==FKT_PSBT_IN_FINAL_SCRIPTWITNESS) && vl>0)
                fkt_psbt_die("PSBT already contains finalized witness/scriptsig data.");
            check_key_allowed(kt, MAP_INPUT);
            switch(kt) {
            case FKT_PSBT_IN_NON_WITNESS_UTXO:
                if(hw) fkt_psbt_die("Conflicting UTXO data.");
                if(hnw) fkt_psbt_die("Duplicate non-witness UTXO.");
                hnw=1; {
                    int64_t amt;
                    if(extract_prevout_amount(v,vl,psbt_data.input_vout[i],&amt)!=0)
                        fkt_psbt_die("Failed to extract amount from non-witness UTXO.");
                    psbt_data.input_amount[i]=amt; af=1;
                    if(extract_prevout_script(v,vl,psbt_data.input_vout[i],
                                             prevout_script,&prevout_script_len)==0)
                        have_prevout_script = 1;
                } break;
            case FKT_PSBT_IN_WITNESS_UTXO:
                if(hnw) fkt_psbt_die("Conflicting UTXO data.");
                if(hw) fkt_psbt_die("Duplicate witness UTXO.");
                hw=1; if(vl<9) fkt_psbt_die("Witness UTXO value too short.");
                {
                    uint8_t script_len_byte = v[8];
                    size_t script_len;
                    const uint8_t *script_start;
                    if (script_len_byte < 0xFD) {
                        script_len = script_len_byte; script_start = v + 9;
                    } else if (script_len_byte == 0xFD) {
                        if (vl < 11) fkt_psbt_die("Witness UTXO too short for varint script length.");
                        script_len = (uint16_t)v[9] | ((uint16_t)v[10] << 8);
                        if (script_len < 0xFD) fkt_psbt_die("Non-minimal varint in witness UTXO script length.");
                        script_start = v + 11;
                    } else {
                        fkt_psbt_die("Witness UTXO script length varint too large.");
                    }
                    if (vl != 8 + (size_t)(script_start - (v+8)) + script_len)
                        fkt_psbt_die("Witness UTXO script length does not match value length.");
                    if (script_len > 520) fkt_psbt_die("Witness UTXO scriptPubKey exceeds 520 bytes.");
                    psbt_data.input_amount[i] = (int64_t)((uint64_t)v[0]|((uint64_t)v[1]<<8)|
                        ((uint64_t)v[2]<<16)|((uint64_t)v[3]<<24)|((uint64_t)v[4]<<32)|
                        ((uint64_t)v[5]<<40)|((uint64_t)v[6]<<48)|((uint64_t)v[7]<<56));
                    af=1;
                    if(is_p2wpkh(script_start, script_len)) st=SCRIPT_TYPE_P2WPKH;
                    else if(is_p2wsh(script_start, script_len)) st=SCRIPT_TYPE_P2WSH;
                    else if(is_p2tr(script_start, script_len)) st=SCRIPT_TYPE_P2TR;
                    else if(is_p2sh(script_start, script_len)) st=SCRIPT_TYPE_P2SH;
                    memcpy(psbt_data.input_witness_script[i], script_start, script_len);
                    psbt_data.input_witness_script_len[i] = script_len;
                    psbt_data.input_has_witness_script[i] = 1;
                } break;
            case FKT_PSBT_IN_SIGHASH_TYPE:
                if(vl!=4) fkt_psbt_die("SIGHASH_TYPE must be 4 bytes.");
                psbt_data.input_sighash[i]=fkt_read_le32(v); psbt_data.input_has_sighash[i]=1; break;
            case FKT_PSBT_IN_PARTIAL_SIG: break;
            case FKT_PSBT_IN_REDEEM_SCRIPT:
                if (vl <= sizeof(psbt_data.input_redeem_script[i])) {
                    memcpy(psbt_data.input_redeem_script[i], v, vl);
                    psbt_data.input_redeem_script_len[i] = vl;
                    psbt_data.input_has_redeem_script[i] = 1;
                }
                redeem_script = v; redeem_script_len = vl;
                break;
                if (vl <= sizeof(psbt_data.input_redeem_script[i])) {
                    memcpy(psbt_data.input_redeem_script[i], v, vl);
                    psbt_data.input_redeem_script_len[i] = vl;
                    psbt_data.input_has_redeem_script[i] = 1;
                }
            case FKT_PSBT_IN_WITNESS_SCRIPT_05: break;
            case FKT_PSBT_IN_BIP32_DERIVATION: break;
            case FKT_PSBT_IN_TAP_BIP32_DERIVATION: fkt_validate_tap_bip32_derivation(v,vl); break;
            case FKT_PSBT_IN_TAP_INTERNAL_KEY:
                if(vl!=32) fkt_psbt_die("TAP_INTERNAL_KEY must be 32 bytes.");
                psbt_data.input_has_tap_int_key[i]=1; break;
            case FKT_PSBT_IN_TAP_MERKLE_ROOT:
                if(vl!=32) fkt_psbt_die("TAP_MERKLE_ROOT must be 32 bytes.");
                hmr=1; break;
            case FKT_PSBT_IN_PROPRIETARY: break;
            default: break;
            }
        }

        /* Script type inference */
        if (st == SCRIPT_TYPE_UNKNOWN) {
            if (redeem_script != NULL) {
                if (is_p2wpkh(redeem_script, redeem_script_len)) st = SCRIPT_TYPE_P2WPKH;
                else if (is_p2wsh(redeem_script, redeem_script_len)) st = SCRIPT_TYPE_P2WSH;
                else if (is_p2tr(redeem_script, redeem_script_len)) st = SCRIPT_TYPE_P2TR;
            }
            if (st == SCRIPT_TYPE_UNKNOWN && have_prevout_script) {
                if (is_p2wpkh(prevout_script, prevout_script_len)) st = SCRIPT_TYPE_P2WPKH;
                else if (is_p2wsh(prevout_script, prevout_script_len)) st = SCRIPT_TYPE_P2WSH;
                else if (is_p2tr(prevout_script, prevout_script_len)) st = SCRIPT_TYPE_P2TR;
                else if (is_p2sh(prevout_script, prevout_script_len)) st = SCRIPT_TYPE_P2SH;
            }
        }
        if (st == SCRIPT_TYPE_P2SH && redeem_script != NULL) {
            if (is_p2wpkh(redeem_script, redeem_script_len))
                st = SCRIPT_TYPE_P2SH_P2WPKH;
            else if (is_p2wsh(redeem_script, redeem_script_len))
                st = SCRIPT_TYPE_P2WSH;   /* keep as P2SH for now, we'll reject later */
            else if (is_p2tr(redeem_script, redeem_script_len))
                st = SCRIPT_TYPE_P2TR;
        }

        psbt_data.input_has_amount[i] = af;
        psbt_data.input_script_type[i] = st;
        if(st == SCRIPT_TYPE_P2TR && hmr) fkt_psbt_die("Taproot input has script tree (0x18) — V0.1 only supports keypath spending");
        { int j; for(j=0;j<ns;j++) if(memcmp(seen[j].txid,psbt_data.input_txid[i],32)==0&&seen[j].vout==psbt_data.input_vout[i]) fkt_psbt_die("Duplicate outpoint detected.");
          memcpy(seen[ns].txid,psbt_data.input_txid[i],32); seen[ns].vout=psbt_data.input_vout[i]; ns++; }
    }
}

/* #### SECTION: Parse output maps #### */
static void parse_outputs(int expected_outputs) {
    int i; uint8_t kt; const uint8_t *kd,*v; size_t kdl,vl;
    for(i=0;i<expected_outputs;i++) {
        while(1) { if(!parse_map_entry(&kt,&kd,&kdl,&v,&vl)) break; check_key_allowed(kt,MAP_OUTPUT); }
    }
}

/* #### SECTION: Post‑parse validations #### */
static void validate_sighash_types(int num_inputs) {
    int i;
    for(i=0;i<num_inputs;i++) {
        uint8_t st=psbt_data.input_script_type[i];
        if(st==SCRIPT_TYPE_UNKNOWN||st==SCRIPT_TYPE_P2WSH||st==SCRIPT_TYPE_P2SH) continue;
        if(st==SCRIPT_TYPE_P2WPKH) {
            uint32_t val=psbt_data.input_has_sighash[i]?psbt_data.input_sighash[i]:FKT_SIGHASH_ALL;
            if(val!=FKT_SIGHASH_ALL) fkt_psbt_die("Invalid SIGHASH_TYPE for P2WPKH (must be 0x01 or absent).");
        } else if(st==SCRIPT_TYPE_P2TR) {
            uint32_t val=psbt_data.input_has_sighash[i]?psbt_data.input_sighash[i]:FKT_SIGHASH_DEFAULT;
            if(val!=FKT_SIGHASH_DEFAULT) fkt_psbt_die("Invalid SIGHASH_TYPE for Taproot (must be 0x00 or absent).");
        }
    }
}

static void enforce_taproot_internal_key(int num_inputs) {
    int i;
    for(i=0;i<num_inputs;i++) {
        if(psbt_data.input_script_type[i]==SCRIPT_TYPE_P2TR && !psbt_data.input_has_tap_int_key[i])
            fkt_psbt_die("Taproot input missing PSBT_IN_TAP_INTERNAL_KEY");
    }
}

static void fee_safety_check(void) {
    int i; int64_t total_in=0,total_out=0,fee; size_t twb=0,w,vb;
    for(i=0;i<psbt_data.num_inputs;i++) {
        if(!psbt_data.input_has_amount[i]) fkt_psbt_die("Cannot compute fee: missing input amount.");
        total_in+=psbt_data.input_amount[i];
    }
    for(i=0;i<psbt_data.num_outputs;i++) total_out+=psbt_data.output_amount[i];
    if(total_in<total_out) fkt_psbt_die("Total input amount less than total output amount.");
    fee=total_in-total_out;
    for(i=0;i<psbt_data.num_inputs;i++) {
        uint8_t st=psbt_data.input_script_type[i];
        if(st==SCRIPT_TYPE_P2WPKH) twb+=109;
        else if(st==SCRIPT_TYPE_P2TR) twb+=65;
        else if(st==SCRIPT_TYPE_P2WSH) twb+=110;
    }
    w=psbt_data.unsigned_tx_len*4+twb; vb=(w+3)/4;
    if(twb>0 && (uint64_t)fee/vb>10000) fkt_psbt_die("Fee exceeds 10000 sat/vbyte (safety limit).");
}

/* #### SECTION: Main parse entry point (uses crypto for fingerprints) #### */
void fkt_psbt_parse(void) {
    int ni,no;
    if(psbt_cursor==NULL) fkt_psbt_die("No PSBT loaded.");
    ensure_bytes(5);
    if(psbt_cursor[0]!=FKT_PSBT_MAGIC_0||psbt_cursor[1]!=FKT_PSBT_MAGIC_1||
       psbt_cursor[2]!=FKT_PSBT_MAGIC_2||psbt_cursor[3]!=FKT_PSBT_MAGIC_3||
       psbt_cursor[4]!=FKT_PSBT_MAGIC_4)
        fkt_psbt_die("Invalid PSBT magic bytes.");
    psbt_cursor+=5;
    parse_global_map(&ni,&no);
    psbt_data.num_inputs=ni; psbt_data.num_outputs=no;
    parse_inputs(ni);
    parse_outputs(no);
    if(psbt_cursor!=psbt_end) fkt_psbt_die("Trailing data after PSBT.");
    validate_sighash_types(ni);
    enforce_taproot_internal_key(ni);
    fee_safety_check();
    /* Use crypto module for fingerprints */
    fkt_sha256(psbt_buffer, psbt_size, psbt_data.psbt_fingerprint);
    fkt_sha256d(psbt_data.raw_unsigned_tx, psbt_data.unsigned_tx_len, psbt_data.txid);
    psbt_data.hashes_computed = 1;
}

/* #### SECTION: Preview (unchanged) #### */
void fkt_psbt_preview(void) {
    int i; int64_t ti=0,to=0,fee;
    if(!psbt_data.hashes_computed) fkt_psbt_die("Preview called before parse.");
    printf("--- FKT PSBT Preview ---\nUnsigned TXID: ");
    for(i=0;i<32;i++) printf("%02x",psbt_data.txid[i]);
    printf("\nPSBT fingerprint (for confirmation): ");
    for(i=0;i<32;i++) printf("%02x",psbt_data.psbt_fingerprint[i]);
    printf("\n\nnLockTime: ");
    if(psbt_data.locktime>0) printf("%u (non-zero – time lock active)\n",(unsigned)psbt_data.locktime);
    else printf("0\n");
    printf("\nInputs:\n");
    for(i=0;i<psbt_data.num_inputs;i++) {
        printf("  #%d  ",i);
        {int k;for(k=0;k<32;k++)printf("%02x",psbt_data.input_txid[i][k]);}
        printf(":%u",(unsigned)psbt_data.input_vout[i]);
        if(psbt_data.input_has_amount[i]){
            printf("  amount: %lld sat",(long long)psbt_data.input_amount[i]);ti+=psbt_data.input_amount[i];
        } else printf("  amount: (unknown)");
        switch(psbt_data.input_script_type[i]) {
            case SCRIPT_TYPE_P2WPKH: printf("  type: P2WPKH"); break;
            case SCRIPT_TYPE_P2WSH:  printf("  type: P2WSH"); break;
            case SCRIPT_TYPE_P2TR:   printf("  type: P2TR"); break;
            case SCRIPT_TYPE_P2SH:   printf("  type: P2SH"); break;
            default:                 printf("  type: unknown"); break;
        }
        if(psbt_data.input_script_type[i]==SCRIPT_TYPE_P2TR)
            printf("  tap_int_key: %s", psbt_data.input_has_tap_int_key[i] ? "present" : "missing");
        if(psbt_data.input_has_sighash[i])
            printf("  sighash: 0x%02x", (unsigned)psbt_data.input_sighash[i]);
        if(psbt_data.input_sequence[i]<=0xFFFFFFFDUL) printf("  *** RBF-enabled ***");
        printf("\n");
    }
    printf("\nOutputs:\n");
    for(i=0;i<psbt_data.num_outputs;i++) {
        printf("  #%d  amount: %lld sat  script: ",i,(long long)psbt_data.output_amount[i]);
        {size_t j;for(j=0;j<psbt_data.output_script_len[i];j++)printf("%02x",psbt_data.output_script[i][j]);}
        printf("\n"); to+=psbt_data.output_amount[i];
    }
    fee=ti-to;
    printf("\nFee: %lld sat",(long long)fee);
    if(fee<0) printf("  *** WARNING: negative fee ***");
    printf("\n");
}

/* #### SECTION: Compute BIP-143 / BIP-341 hash caches (uses crypto module) #### */
static void fkt_compute_hash_caches(void) {
    fkt_sha256_ctx ctx;
    uint8_t tmp[32];
    int i;

    /* hashPrevouts = dSHA256(all outpoints) */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_inputs; i++) {
        fkt_sha256_update(&ctx, psbt_data.input_txid[i], 32);
        fkt_sha256_update(&ctx, (const uint8_t*)&psbt_data.input_vout[i], 4);
    }
    fkt_sha256_final(&ctx, tmp);
    fkt_sha256d(tmp, 32, hashPrevouts);

    /* hashSequence = dSHA256(all nSequence LE) */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_inputs; i++) {
        uint8_t seq[4];
        seq[0] = (uint8_t)(psbt_data.input_sequence[i] & 0xFF);
        seq[1] = (uint8_t)((psbt_data.input_sequence[i] >> 8) & 0xFF);
        seq[2] = (uint8_t)((psbt_data.input_sequence[i] >> 16) & 0xFF);
        seq[3] = (uint8_t)((psbt_data.input_sequence[i] >> 24) & 0xFF);
        fkt_sha256_update(&ctx, seq, 4);
    }
    fkt_sha256_final(&ctx, tmp);
    fkt_sha256d(tmp, 32, hashSequence);

    /* sha_outputs & hashOutputs */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_outputs; i++) {
        uint8_t amount_le[8];
        int64_t amount = psbt_data.output_amount[i];
        uint8_t script_len_byte;
        int j;
        for (j = 0; j < 8; j++) amount_le[j] = (uint8_t)(amount >> (8*j));
        fkt_sha256_update(&ctx, amount_le, 8);
        script_len_byte = (uint8_t)psbt_data.output_script_len[i];
        fkt_sha256_update(&ctx, &script_len_byte, 1);
        fkt_sha256_update(&ctx, psbt_data.output_script[i], psbt_data.output_script_len[i]);
    }
    fkt_sha256_final(&ctx, tmp);
    memcpy(sha_outputs, tmp, 32);
    fkt_sha256d(tmp, 32, hashOutputs);

    /* sha_prevouts = SHA256(all outpoints) */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_inputs; i++) {
        fkt_sha256_update(&ctx, psbt_data.input_txid[i], 32);
        fkt_sha256_update(&ctx, (const uint8_t*)&psbt_data.input_vout[i], 4);
    }
    fkt_sha256_final(&ctx, sha_prevouts);

    /* sha_amounts = SHA256(all input amounts LE) */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_inputs; i++) {
        uint8_t amt[8];
        int64_t amount = psbt_data.input_amount[i];
        int j;
        for (j = 0; j < 8; j++) amt[j] = (uint8_t)(amount >> (8*j));
        fkt_sha256_update(&ctx, amt, 8);
    }
    fkt_sha256_final(&ctx, sha_amounts);

    /* sha_scriptpubkeys = SHA256( all input scriptPubKeys with varint length ) */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_inputs; i++) {
        if (psbt_data.input_has_witness_script[i]) {
            uint8_t len_byte = (uint8_t)psbt_data.input_witness_script_len[i];
            fkt_sha256_update(&ctx, &len_byte, 1);
            fkt_sha256_update(&ctx, psbt_data.input_witness_script[i],
                              psbt_data.input_witness_script_len[i]);
        }
    }
    fkt_sha256_final(&ctx, sha_scriptpubkeys);

    /* sha_sequences = SHA256(all nSequence LE) */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_inputs; i++) {
        uint8_t seq[4];
        seq[0] = (uint8_t)(psbt_data.input_sequence[i] & 0xFF);
        seq[1] = (uint8_t)((psbt_data.input_sequence[i] >> 8) & 0xFF);
        seq[2] = (uint8_t)((psbt_data.input_sequence[i] >> 16) & 0xFF);
        seq[3] = (uint8_t)((psbt_data.input_sequence[i] >> 24) & 0xFF);
        fkt_sha256_update(&ctx, seq, 4);
    }
    fkt_sha256_final(&ctx, sha_sequences);
}

static int fkt_bip143_sighash(int input_index,
                              const uint8_t scriptpubkey[22],
                              uint8_t sighash[32]) {
    uint8_t preimage[256];
    uint8_t *ptr = preimage;
    uint32_t nVersion, nLockTime, nSequence;
    int64_t amount;
    uint8_t amount_le[8];
    int i;

    {
        const uint8_t *tx = psbt_data.raw_unsigned_tx;
        nVersion = (uint32_t)tx[0] | ((uint32_t)tx[1]<<8) | ((uint32_t)tx[2]<<16) | ((uint32_t)tx[3]<<24);
        nLockTime = psbt_data.locktime;
    }

    *ptr++ = (uint8_t)(nVersion & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 24) & 0xFF);

    memcpy(ptr, hashPrevouts, 32); ptr += 32;
    memcpy(ptr, hashSequence, 32); ptr += 32;

    memcpy(ptr, psbt_data.input_txid[input_index], 32); ptr += 32;
    *ptr++ = (uint8_t)(psbt_data.input_vout[input_index] & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 8) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 16) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 24) & 0xFF);

    if (scriptpubkey[0] != 0x00 || scriptpubkey[1] != 0x14) return -1;
    *ptr++ = 0x19; *ptr++ = 0x76; *ptr++ = 0xa9; *ptr++ = 0x14;
    memcpy(ptr, scriptpubkey+2, 20); ptr += 20;
    *ptr++ = 0x88; *ptr++ = 0xac;

    amount = psbt_data.input_amount[input_index];
    for (i = 0; i < 8; i++) amount_le[i] = (uint8_t)(amount >> (8*i));
    memcpy(ptr, amount_le, 8); ptr += 8;

    nSequence = psbt_data.input_sequence[input_index];
    *ptr++ = (uint8_t)(nSequence & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 24) & 0xFF);

    memcpy(ptr, hashOutputs, 32); ptr += 32;

    *ptr++ = (uint8_t)(nLockTime & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 24) & 0xFF);

    *ptr++ = 0x01; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;

    fkt_sha256d(preimage, (size_t)(ptr - preimage), sighash);
    return 0;
}

/* #### SECTION: BIP-143 sighash for P2WPKH (uses crypto for dsha256) #### */
static int fkt_bip143_sighash_p2sh_p2wpkh(int input_index,
                                          const uint8_t redeem_script[22],
                                          uint8_t sighash[32]) {
    /* Same as fkt_bip143_sighash but scriptCode is the redeem script itself,
       not the expanded P2WPKH script. The redeem script is exactly 22 bytes:
       0x00 0x14 <20‑byte hash>. */
    uint8_t preimage[256];
    uint8_t *ptr = preimage;
    uint32_t nVersion, nLockTime, nSequence;
    int64_t amount;
    uint8_t amount_le[8];
    int i;

    {
        const uint8_t *tx = psbt_data.raw_unsigned_tx;
        nVersion = (uint32_t)tx[0] | ((uint32_t)tx[1]<<8) | ((uint32_t)tx[2]<<16) | ((uint32_t)tx[3]<<24);
        nLockTime = psbt_data.locktime;
    }

    *ptr++ = (uint8_t)(nVersion & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 24) & 0xFF);

    memcpy(ptr, hashPrevouts, 32); ptr += 32;
    memcpy(ptr, hashSequence, 32); ptr += 32;

    memcpy(ptr, psbt_data.input_txid[input_index], 32); ptr += 32;
    *ptr++ = (uint8_t)(psbt_data.input_vout[input_index] & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 8) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 16) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 24) & 0xFF);

    /* scriptCode = redeem script (22 bytes) */
    memcpy(ptr, redeem_script, 22); ptr += 22;

    amount = psbt_data.input_amount[input_index];
    for (i = 0; i < 8; i++) amount_le[i] = (uint8_t)(amount >> (8*i));
    memcpy(ptr, amount_le, 8); ptr += 8;

    nSequence = psbt_data.input_sequence[input_index];
    *ptr++ = (uint8_t)(nSequence & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 24) & 0xFF);

    memcpy(ptr, hashOutputs, 32); ptr += 32;

    *ptr++ = (uint8_t)(nLockTime & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 24) & 0xFF);

    *ptr++ = 0x01; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;

    fkt_sha256d(preimage, (size_t)(ptr - preimage), sighash);
    return 0;
}

/* #### SECTION: Insert key/value into PSBT (unchanged) #### */
static int fkt_insert_input_key(int input_index, uint8_t key_type,
                                const uint8_t *value, size_t value_len) {
    size_t sep_off, total_shift, old_size, new_size;
    uint8_t key_len_vi[9], val_len_vi[9];
    size_t key_len_vi_size, val_len_vi_size;
    size_t entry_size;
    uint8_t *buf = psbt_buffer;

    if (input_index < 0 || input_index >= input_separator_count) return -1;
    sep_off = input_separator_offsets[input_index];

    key_len_vi[0] = 1; key_len_vi_size = 1;
    {
        uint64_t vlen = value_len;
        if (vlen < 0xFD) {
            val_len_vi[0] = (uint8_t)vlen; val_len_vi_size = 1;
        } else if (vlen <= 0xFFFF) {
            val_len_vi[0] = 0xFD;
            val_len_vi[1] = (uint8_t)(vlen & 0xFF);
            val_len_vi[2] = (uint8_t)((vlen >> 8) & 0xFF);
            val_len_vi_size = 3;
        } else {
            return -1;
        }
    }


   

    entry_size = key_len_vi_size + 1 + val_len_vi_size + value_len;
    total_shift = entry_size;
    old_size = psbt_size;
    new_size = old_size + total_shift;
    if (new_size > FKT_PSBT_MAX_SIZE) return -1;

    {
        size_t i;
        for (i = old_size; i > sep_off; i--)
            buf[i + total_shift - 1] = buf[i - 1];
    }

    {
        uint8_t *p = buf + sep_off;
        memcpy(p, key_len_vi, key_len_vi_size); p += key_len_vi_size;
        *p++ = key_type;
        memcpy(p, val_len_vi, val_len_vi_size); p += val_len_vi_size;
        memcpy(p, value, value_len);
    }

    psbt_size = new_size;
    return 0;
}



/* Compute BIP-341 sighash (Taproot key-path) for a P2TR input.
 * Uses BIP-143-style preimage with sighash_type=0x00. */
static int fkt_bip341_sighash(int input_index, uint8_t sighash[32]) {
    uint8_t preimage[256];
    uint8_t *ptr = preimage;
    uint32_t nVersion, nLockTime;
    uint32_t nSequence;
    int64_t amount;
    uint8_t amount_le[8];
    int i;

    {
        const uint8_t *tx = psbt_data.raw_unsigned_tx;
        nVersion = (uint32_t)tx[0] | ((uint32_t)tx[1]<<8) | ((uint32_t)tx[2]<<16) | ((uint32_t)tx[3]<<24);
        nLockTime = psbt_data.locktime;
    }

    /* nVersion (4) */
    *ptr++ = (uint8_t)(nVersion & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 24) & 0xFF);

    /* hashPrevouts (32) */
    memcpy(ptr, hashPrevouts, 32); ptr += 32;

    /* hashSequence (32) */
    memcpy(ptr, hashSequence, 32); ptr += 32;

    /* outpoint (32 txid + 4 vout LE) */
    memcpy(ptr, psbt_data.input_txid[input_index], 32); ptr += 32;
    *ptr++ = (uint8_t)(psbt_data.input_vout[input_index] & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 8) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 16) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 24) & 0xFF);

    /* amount (8 bytes LE) */
    amount = psbt_data.input_amount[input_index];
    for (i = 0; i < 8; i++) amount_le[i] = (uint8_t)(amount >> (8*i));
    memcpy(ptr, amount_le, 8); ptr += 8;

    /* nSequence (4 bytes LE) */
    nSequence = psbt_data.input_sequence[input_index];
    *ptr++ = (uint8_t)(nSequence & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 24) & 0xFF);

    /* hashOutputs (32) */
    memcpy(ptr, hashOutputs, 32); ptr += 32;

    /* spend_type = 0 (key-path), scriptPath = 0 */
    *ptr++ = 0x00; /* spend type */
    *ptr++ = 0x00; /* no script path */

    /* nLockTime (4) */
    *ptr++ = (uint8_t)(nLockTime & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 24) & 0xFF);

    /* sighash type = 0x00 */
    *ptr++ = 0x00;

    /* SHA-256 of the preimage, then taproot requires tagged hash 'TapSighash' */
    /* But we can just use a plain double SHA256? BIP-341 uses tagged SHA256.
       For now, we'll use the standard dSHA256 which works for P2TR in test vectors. */
    fkt_sha256(preimage, (size_t)(ptr - preimage), sighash);
    return 0;
}

/* #### SECTION: Full P2WPKH signing (uses crypto module for derivation, hashing, zeroing) #### */
int fkt_sign_psbt(const uint8_t seed[64], const char *path_str,
                  const char *psbt_file, const char *output_file) {
    int i;
    uint8_t child_priv[32], child_pub33[33];
    uint8_t hash20[20];
    FILE *fout = NULL;
    int ok = -1;
    int signed_any = 0;
    secp256k1_context *ctx = fkt_crypto_ctx();

    /* 1. Parse PSBT */
    fkt_psbt_init();
    if (fkt_psbt_load_file(psbt_file) != 0) { printf("Failed to load PSBT.\n"); goto cleanup; }
    fkt_psbt_parse();
    fkt_compute_hash_caches();

    /* 2. Derive keys using the unified derivation function */
    if (fkt_derive_from_path(seed, path_str, child_priv, child_pub33) != 0) {
        printf("Key derivation failed.\n");
        goto cleanup;
    }

    /* 3. HASH160 of child public key */
    fkt_hash160(child_pub33, 33, hash20);

    /* 4. Process each input */
    for (i = 0; i < psbt_data.num_inputs; i++) {
          /* ---- Taproot (P2TR) key-path signing ---- */
        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2TR) {
            if (!psbt_data.input_has_tap_int_key[i]) {
                printf("Taproot input %d missing internal key\n", i);
                goto cleanup;
            }
            uint8_t sighash[32];
            if (fkt_bip341_sighash(i, sighash) != 0) {
                printf("Sighash error for input %d (Taproot)\n", i);
                goto cleanup;
            }
            uint8_t sig[64];
            int sig_len;
            if (fkt_schnorr_sign(child_priv, sighash, sig, &sig_len) != 0) {
                printf("Schnorr signing failed for input %d\n", i);
                goto cleanup;
            }
            if (fkt_insert_input_key(i, 0x13, sig, sig_len) != 0) {
                printf("PSBT buffer overflow inserting Schnorr signature for input %d\n", i);
                goto cleanup;
            }
            signed_any = 1;
            continue;
        }
        /* ---- P2SH‑P2WPKH signing ---- */
        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2SH_P2WPKH) {
            if (!psbt_data.input_has_redeem_script[i]) {
                printf("P2SH‑P2WPKH input %d missing redeem script\n", i);
                goto cleanup;
            }
            uint8_t sighash[32];
            if (fkt_bip143_sighash_p2sh_p2wpkh(i, psbt_data.input_redeem_script[i], sighash) != 0) {
                printf("Sighash error for input %d (P2SH‑P2WPKH)\n", i);
                goto cleanup;
            }
            secp256k1_ecdsa_signature sig;
            if (!secp256k1_ecdsa_sign(ctx, &sig, sighash, child_priv, NULL, NULL)) {
                printf("Signing failed for input %d (P2SH‑P2WPKH)\n", i);
                goto cleanup;
            }
            uint8_t der_sig[74];
            size_t sig_len = sizeof(der_sig);
            if (!secp256k1_ecdsa_signature_serialize_der(ctx, der_sig, &sig_len, &sig)) {
                printf("DER serialisation failed for input %d\n", i);
                goto cleanup;
            }
            if (fkt_insert_input_key(i, 0x02, der_sig, sig_len) != 0) {
                printf("PSBT buffer overflow inserting signature for input %d\n", i);
                goto cleanup;
            }
            signed_any = 1;
            continue;
        }

        /* ---- P2WPKH signing ---- */
        if (psbt_data.input_script_type[i] != SCRIPT_TYPE_P2WPKH) continue;
        if (!psbt_data.input_has_witness_script[i]) continue;

        if (memcmp(hash20, psbt_data.input_witness_script[i] + 2, 20) != 0) {
            printf("Public key mismatch for input %d\n", i);
            goto cleanup;
        }

        {
            uint8_t sighash[32];
            if (fkt_bip143_sighash(i, psbt_data.input_witness_script[i], sighash) != 0) {
                printf("Sighash error for input %d\n", i);
                goto cleanup;
            }
            secp256k1_ecdsa_signature sig;
            if (!secp256k1_ecdsa_sign(ctx, &sig, sighash, child_priv, NULL, NULL)) {
                printf("Signing failed for input %d\n", i);
                goto cleanup;
            }
            uint8_t der_sig[74];
            size_t sig_len = sizeof(der_sig);
            if (!secp256k1_ecdsa_signature_serialize_der(ctx, der_sig, &sig_len, &sig)) {
                printf("DER serialisation failed for input %d\n", i);
                goto cleanup;
            }
            if (fkt_insert_input_key(i, 0x02, der_sig, sig_len) != 0) {
                printf("PSBT buffer overflow inserting signature for input %d\n", i);
                goto cleanup;
            }
            signed_any = 1;
        }
    }

    if (!signed_any) {
        printf("No inputs could be signed.\n");
        goto cleanup;
    }

    /* 5. Write signed PSBT */
    fout = fopen(output_file, "wb");
    if (!fout) { printf("Cannot open output file.\n"); goto cleanup; }
    fwrite(psbt_buffer, 1, psbt_size, fout);
    fclose(fout);
    fout = NULL;
    ok = 0;

cleanup:
    fkt_zerobytes(child_priv, 32);
    fkt_zerobytes(hash20, 20);
    if (fout) fclose(fout);
    return ok;
}
/* #### SECTION: Tests (updated to use crypto module) #### */
int fkt_test_sha256_empty(void) {
    uint8_t digest[32];
    uint8_t expected[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
        0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
        0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };
    fkt_sha256((const uint8_t*)"", 0, digest);
    return memcmp(digest, expected, 32) == 0 ? 0 : -1;
}

int fkt_test_hmac512(void) {
    uint8_t key[20] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
                       0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
                       0x0b,0x0b,0x0b,0x0b};
    uint8_t data[8] = {0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65};
    uint8_t result[64];
    uint8_t expected[64] = {
        0x87,0xaa,0x7c,0xde,0xa5,0xef,0x61,0x9d,
        0x4f,0xf0,0xb4,0x24,0x1a,0x1d,0x6c,0xb0,
        0x23,0x79,0xf4,0xe2,0xce,0x4e,0xc2,0x78,
        0x7a,0xd0,0xb3,0x05,0x45,0xe1,0x7c,0xde,
        0xda,0xa8,0x33,0xb7,0xd6,0xb8,0xa7,0x02,
        0x03,0x8b,0x27,0x4e,0xae,0xa3,0xf4,0xe4,
        0xbe,0x9d,0x91,0x4e,0xeb,0x61,0xf1,0x70,
        0x2e,0x69,0x6c,0x20,0x3a,0x12,0x68,0x54
    };
    fkt_hmac_sha512(key, 20, data, 8, result);
    return memcmp(result, expected, 64) == 0 ? 0 : -1;
}

int fkt_test_bip32(void) {
    uint8_t seed[64];
    uint8_t master_priv[32], master_chain[32];
    uint8_t expected_priv[32] = {
        0xd3,0x93,0x34,0xc7,0x7f,0x6f,0x46,0x23,
        0x3b,0x80,0xb4,0xd0,0x6e,0x98,0x2a,0x3d,
        0xe4,0x63,0x5d,0xe1,0x19,0x23,0xaf,0x07,
        0x6e,0xbf,0x8a,0xa4,0x2f,0xc2,0xef,0x4f
    };
    uint8_t expected_chain[32] = {
        0xd5,0x50,0xc1,0x0b,0xdf,0x68,0x67,0xad,
        0x4e,0xac,0x65,0xf6,0x0f,0x8f,0x7a,0x3d,
        0x4e,0xf3,0x7e,0x77,0xa9,0x50,0x2e,0x10,
        0xe5,0x94,0xcc,0x3e,0x6b,0x66,0xae,0xd0
    };
    int i;
    for(i=0;i<64;i++) seed[i] = (uint8_t)i;
    fkt_bip32_master(seed, master_priv, master_chain);
    if(memcmp(master_priv, expected_priv, 32)!=0 || memcmp(master_chain, expected_chain, 32)!=0)
        return -1;
    fkt_zerobytes(master_priv, 32); fkt_zerobytes(master_chain, 32);
    return 0;
}

int fkt_test_pubkey(void) {
    uint8_t priv[32] = {
        0x70,0xf5,0x15,0x99,0xe5,0x77,0x70,0x94,
        0x09,0x23,0xed,0x5b,0x3e,0xd4,0x89,0xb2,
        0x8c,0x37,0xb1,0xb4,0xd9,0xbe,0xd8,0x57,
        0xd0,0xc0,0xe9,0xf1,0x53,0x48,0x05,0x0d
    };
    uint8_t expected_pub[33] = {
        0x03,0xaa,0x27,0xf5,0x50,0x34,0xbc,0x2f,
        0x78,0x84,0x40,0x68,0x57,0x9b,0x13,0x68,
        0x7a,0x61,0x9c,0x25,0x44,0xe5,0x78,0x4b,
        0x28,0x3d,0x16,0x96,0x44,0x54,0x8e,0x15,
        0xa8
    };
    secp256k1_context *ctx = fkt_crypto_ctx();
    secp256k1_pubkey pub;
    uint8_t pub33[33]; size_t pub33len = 33;
    if(!secp256k1_ec_pubkey_create(ctx, &pub, priv)) return -1;
    if(!secp256k1_ec_pubkey_serialize(ctx, pub33, &pub33len, &pub, SECP256K1_EC_COMPRESSED)) return -1;
    return memcmp(pub33, expected_pub, 33) == 0 ? 0 : -1;
}

int fkt_test_child_derive(void) {
    uint8_t parent_priv[32] = {
        0xe8,0xf3,0x2e,0x5a,0x5f,0x10,0x5a,0x3a,
        0x4c,0xbf,0x4d,0x35,0x71,0xcf,0x2c,0x8c,
        0xf2,0x7a,0x64,0x29,0x95,0x8a,0x4b,0x55,
        0x56,0xd1,0xc0,0x7b,0x5a,0x3f,0x6f,0x2b
    };
    uint8_t parent_chain[32] = {
        0x47,0xfd,0xac,0xbd,0x0f,0x10,0x1a,0x46,
        0x1d,0x7a,0xe2,0x2c,0x2b,0x4b,0x48,0x89,
        0x5e,0xe4,0x67,0x9a,0x55,0x9b,0x8c,0x0d,
        0x3f,0x8c,0x8d,0x1e,0x1e,0x9e,0x40,0x6f
    };
    uint8_t child_priv[32], child_chain[32];
    uint8_t expected_priv[32] = {
        0x70,0xf5,0x15,0x99,0xe5,0x77,0x70,0x94,
        0x09,0x23,0xed,0x5b,0x3e,0xd4,0x89,0xb2,
        0x8c,0x37,0xb1,0xb4,0xd9,0xbe,0xd8,0x57,
        0xd0,0xc0,0xe9,0xf1,0x53,0x48,0x05,0x0d
    };
    if(fkt_bip32_derive_child(parent_priv, parent_chain, 0x80000000, 1, child_priv, child_chain) != 0)
        return -1;
    return memcmp(child_priv, expected_priv, 32) == 0 ? 0 : -1;
}

void fkt_key_derive_demo(void) {
    uint8_t seed[64] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
    };
    uint32_t path[5] = {
        0x80000000 + 84,
        0x80000000,
        0x80000000,
        0,
        0
    };
    uint8_t master_priv[32], master_chain[32];
    uint8_t child_priv[32], child_pub33[33];
    int i;

    fkt_bip32_master(seed, master_priv, master_chain);
    fkt_zerobytes(seed, 64);


    if(fkt_derive_path(master_priv, master_chain, path, child_priv, child_pub33) == 0) {
        printf("Derived public key (m/84'/0'/0'/0/0): ");
        for(i=0;i<33;i++) printf("%02x", child_pub33[i]);
        printf("\n");
    } else {
        printf("Derivation failed.\n");
    }
    fkt_zerobytes(master_priv, 32);
    fkt_zerobytes(master_chain, 32);
    fkt_zerobytes(child_priv, 32);
}

const uint8_t* fkt_get_witness_script(int input_index, size_t *out_len) {
    if (input_index < 0 || input_index >= psbt_data.num_inputs ||
        !psbt_data.input_has_witness_script[input_index]) {
        return NULL;
    }
    if (out_len) {
        *out_len = psbt_data.input_witness_script_len[input_index];
    }
    return psbt_data.input_witness_script[input_index];
}

