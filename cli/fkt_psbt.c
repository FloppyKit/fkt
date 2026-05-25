#include "fkt_psbt.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>       /* exit() */

/* =========================================================================
 * static working memory – no malloc, all sensitive areas zeroed after use
 * ========================================================================= */
static uint8_t  psbt_buffer[FKT_PSBT_MAX_SIZE];
static size_t   psbt_size;
static const uint8_t *psbt_cursor;   /* current read position */
static const uint8_t *psbt_end;      /* one past last loaded byte */

/* ---- extracted transaction data for preview ---- */
#define MAX_PSBT_ITEMS  256          /* maximum number of inputs / outputs we handle */

static struct {
    /* unsigned transaction blob (for txid & output scripts) */
    uint8_t  raw_unsigned_tx[FKT_PSBT_MAX_SIZE];
    size_t   unsigned_tx_len;

    int      num_inputs;
    int      num_outputs;

    /* input data */
    uint8_t  input_txid  [MAX_PSBT_ITEMS][32];   /* previous txid */
    uint32_t input_vout  [MAX_PSBT_ITEMS];       /* output index */
    int64_t  input_amount[MAX_PSBT_ITEMS];       /* satoshis, from UTXO data */
    int      input_has_amount[MAX_PSBT_ITEMS];   /* 1 if amount was successfully read */

    /* output data */
    int64_t  output_amount      [MAX_PSBT_ITEMS];
    uint8_t  output_script      [MAX_PSBT_ITEMS][520];  /* max P2WSH script */
    size_t   output_script_len  [MAX_PSBT_ITEMS];
} psbt_data;

/* =========================================================================
 * fatal error handler – single exit path, loud message
 * ========================================================================= */
static void fkt_psbt_die(const char *msg)
{
    fprintf(stderr, "FKT PSBT ERROR: %s\n", msg);
    exit(1);
}

/* =========================================================================
 * initialisation – zero static memory with volatile writes
 * ========================================================================= */
void fkt_psbt_init(void)
{
    volatile uint8_t *p;
    size_t i;

    p = (volatile uint8_t *)psbt_buffer;
    for (i = 0; i < sizeof(psbt_buffer); i++)   p[i] = 0;

    p = (volatile uint8_t *)&psbt_data;
    for (i = 0; i < sizeof(psbt_data); i++)     p[i] = 0;

    psbt_size   = 0;
    psbt_cursor = NULL;
    psbt_end    = NULL;
}

/* =========================================================================
 * file loading (returns 0 on success, -1 on failure – never calls die())
 * ========================================================================= */
static int read_file(const char *path, uint8_t *buf, size_t max_size, size_t *out_size)
{
    FILE *f;
    size_t n;

    f = fopen(path, "rb");
    if (!f) return -1;

    n = fread(buf, 1, max_size, f);
    if (ferror(f)) { fclose(f); return -1; }
    if (!feof(f)) {
        /* file too large – refuse */
        fclose(f);
        return -1;
    }
    fclose(f);
    *out_size = n;
    return 0;
}

int fkt_psbt_load_file(const char *path)
{
    size_t size;
    if (read_file(path, psbt_buffer, FKT_PSBT_MAX_SIZE, &size) != 0)
        return -1;
    psbt_size   = size;
    psbt_cursor = psbt_buffer;
    psbt_end    = psbt_buffer + size;
    return 0;
}

/* =========================================================================
 * strict Base64 decoder (RFC 4648, no whitespace, requires correct padding)
 * ========================================================================= */
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

static int base64_decode(const char *in, uint8_t *out, size_t max_out, size_t *out_len)
{
    size_t len = strlen(in);
    size_t i, j;
    uint32_t buf;
    int pad;
    uint8_t c;

    if (len % 4 != 0) return -1;
    pad = 0;
    j = 0;
    for (i = 0; i < len; i += 4) {
        buf = 0;
        /* decode 4 characters into 3 bytes */
        c = (uint8_t)in[i];
        if (c == '=') { pad++; buf |= (0x00 << 18); } else { uint8_t v = b64_decode_table[c]; if (v >= 64) return -1; buf |= ((uint32_t)v << 18); }
        c = (uint8_t)in[i+1];
        if (c == '=') { pad++; buf |= (0x00 << 12); } else { if (pad) return -1; uint8_t v = b64_decode_table[c]; if (v >= 64) return -1; buf |= ((uint32_t)v << 12); }
        c = (uint8_t)in[i+2];
        if (c == '=') { pad++; buf |= (0x00 << 6);  } else { if (pad) return -1; uint8_t v = b64_decode_table[c]; if (v >= 64) return -1; buf |= ((uint32_t)v << 6);  }
        c = (uint8_t)in[i+3];
        if (c == '=') { pad++; /* nothing */        } else { if (pad) return -1; uint8_t v = b64_decode_table[c]; if (v >= 64) return -1; buf |= ((uint32_t)v);       }

        if (pad > 2) return -1;  /* invalid padding */

        /* output bytes */
        if (j < max_out) out[j++] = (uint8_t)(buf >> 16);
        if (pad < 2 && j < max_out) out[j++] = (uint8_t)(buf >> 8);
        if (pad < 1 && j < max_out) out[j++] = (uint8_t)(buf);
    }
    if (j > max_out) return -1;
    *out_len = j;
    return 0;
}

int fkt_psbt_load_base64(const char *b64_str)
{
    size_t len;
    if (base64_decode(b64_str, psbt_buffer, FKT_PSBT_MAX_SIZE, &len) != 0)
        return -1;
    psbt_size   = len;
    psbt_cursor = psbt_buffer;
    psbt_end    = psbt_buffer + len;
    return 0;
}

/* =========================================================================
 * compact-size integer helpers (strict minimal encoding)
 * ========================================================================= */
static void ensure_bytes(size_t n)
{
    if ((size_t)(psbt_end - psbt_cursor) < n)
        fkt_psbt_die("Unexpected end of PSBT data.");
}

static uint64_t read_varint(int *ok)
{
    uint8_t first;
    if (psbt_cursor >= psbt_end) { *ok = 0; return 0; }
    first = *psbt_cursor;
    if (first < 0xFD) {
        *ok = 1;
        psbt_cursor++;
        return (uint64_t)first;
    }
    if (first == 0xFD) {
        uint16_t val;
        if (psbt_end - psbt_cursor < 3) { *ok = 0; return 0; }
        val = (uint16_t)psbt_cursor[1] | ((uint16_t)psbt_cursor[2] << 8);
        if (val < 0xFD) { *ok = 0; return 0; }       /* non‑minimal */
        *ok = 1;
        psbt_cursor += 3;
        return val;
    }
    if (first == 0xFE) {
        uint32_t val;
        if (psbt_end - psbt_cursor < 5) { *ok = 0; return 0; }
        val = (uint32_t)psbt_cursor[1] | ((uint32_t)psbt_cursor[2] << 8) |
              ((uint32_t)psbt_cursor[3] << 16) | ((uint32_t)psbt_cursor[4] << 24);
        if (val < 0x10000UL) { *ok = 0; return 0; }  /* non‑minimal */
        *ok = 1;
        psbt_cursor += 5;
        return val;
    }
    /* first == 0xFF */
    {
        uint64_t val;
        if (psbt_end - psbt_cursor < 9) { *ok = 0; return 0; }
        val = (uint64_t)psbt_cursor[1] | ((uint64_t)psbt_cursor[2] << 8) |
              ((uint64_t)psbt_cursor[3] << 16) | ((uint64_t)psbt_cursor[4] << 24) |
              ((uint64_t)psbt_cursor[5] << 32) | ((uint64_t)psbt_cursor[6] << 40) |
              ((uint64_t)psbt_cursor[7] << 48) | ((uint64_t)psbt_cursor[8] << 56);
        if (val <= 0xFFFFFFFFUL) { *ok = 0; return 0; } /* non‑minimal */
        *ok = 1;
        psbt_cursor += 9;
        return val;
    }
}

/* ---- same, but operates on an arbitrary buffer (used for unsigned tx parsing) ---- */
static int read_varint_from(const uint8_t **p, const uint8_t *end, uint64_t *val)
{
    const uint8_t *c = *p;
    if (c >= end) return 0;
    if (c[0] < 0xFD) {
        *val = c[0];
        *p = c + 1;
        return 1;
    }
    if (c[0] == 0xFD) {
        if (end - c < 3) return 0;
        *val = (uint16_t)c[1] | ((uint16_t)c[2] << 8);
        if (*val < 0xFD) return 0;
        *p = c + 3;
        return 1;
    }
    if (c[0] == 0xFE) {
        if (end - c < 5) return 0;
        *val = (uint32_t)c[1] | ((uint32_t)c[2] << 8) |
               ((uint32_t)c[3] << 16) | ((uint32_t)c[4] << 24);
        if (*val < 0x10000UL) return 0;
        *p = c + 5;
        return 1;
    }
    if (c[0] == 0xFF) {
        if (end - c < 9) return 0;
        *val = (uint64_t)c[1] | ((uint64_t)c[2] << 8) |
               ((uint64_t)c[3] << 16) | ((uint64_t)c[4] << 24) |
               ((uint64_t)c[5] << 32) | ((uint64_t)c[6] << 40) |
               ((uint64_t)c[7] << 48) | ((uint64_t)c[8] << 56);
        if (*val <= 0xFFFFFFFFUL) return 0;
        *p = c + 9;
        return 1;
    }
    return 0;
}

/* =========================================================================
 * map entry parser – returns 0 on separator, 1 on valid entry
 * ========================================================================= */
static int parse_map_entry(uint8_t *key_type_out,
                           const uint8_t **key_data_out, size_t *key_data_len_out,
                           const uint8_t **value_out, size_t *value_len_out)
{
    int ok;
    uint64_t key_len, val_len;

    ensure_bytes(1);
    if (*psbt_cursor == FKT_PSBT_SEPARATOR) {
        psbt_cursor++;
        return 0;   /* separator hit */
    }

    key_len = read_varint(&ok);
    if (!ok) fkt_psbt_die("Malformed varint for key length.");
    if (key_len == 0) fkt_psbt_die("Key length zero.");
    ensure_bytes((size_t)key_len);

    *key_type_out     = psbt_cursor[0];
    *key_data_out     = psbt_cursor + 1;
    *key_data_len_out = (size_t)(key_len - 1);
    psbt_cursor      += (size_t)key_len;

    val_len = read_varint(&ok);
    if (!ok) fkt_psbt_die("Malformed varint for value length.");
    ensure_bytes((size_t)val_len);

    *value_out     = psbt_cursor;
    *value_len_out = (size_t)val_len;
    psbt_cursor   += (size_t)val_len;
    return 1;
}

/* =========================================================================
 * key type whitelist
 * ========================================================================= */
typedef enum { MAP_GLOBAL, MAP_INPUT, MAP_OUTPUT } map_context_t;

static void check_key_allowed(uint8_t key_type, map_context_t ctx)
{
    switch (ctx) {
    case MAP_GLOBAL:
        if (key_type != FKT_PSBT_GLOBAL_UNSIGNED_TX)
            fkt_psbt_die("Unknown key in global PSBT map.");
        break;
    case MAP_INPUT:
        if (key_type != FKT_PSBT_IN_NON_WITNESS_UTXO &&
            key_type != FKT_PSBT_IN_WITNESS_UTXO &&
            key_type != FKT_PSBT_IN_FINAL_SCRIPTSIG &&
            key_type != FKT_PSBT_IN_FINAL_SCRIPTWITNESS)
            fkt_psbt_die("Unknown key in input PSBT map.");
        break;
    case MAP_OUTPUT:
        /* no keys allowed */
        fkt_psbt_die("Unknown key in output PSBT map.");
        break;
    }
}

/* =========================================================================
 * helper: extract amount from a previous transaction for a given vout
 * (used for non‑witness UTXO key 0x00)
 * ========================================================================= */
static int extract_prevout_amount(const uint8_t *tx, size_t tx_len,
                                  uint32_t vout, int64_t *amount_out)
{
    const uint8_t *p = tx;
    const uint8_t *end = tx + tx_len;
    int segwit = 0;
    uint64_t n_inputs, n_outputs, i;
    uint64_t script_len;

    if (end - p < 4) return -1;
    p += 4; /* version */

    /* check for segwit marker + flag (0x00 0x01) */
    if (end - p >= 2 && p[0] == 0x00 && p[1] == 0x01) {
        segwit = 1;
        p += 2;
    }

    /* input count */
    if (!read_varint_from(&p, end, &n_inputs)) return -1;
    if (n_inputs > MAX_PSBT_ITEMS) return -1;

    /* skip all inputs */
    for (i = 0; i < n_inputs; i++) {
        if (end - p < 36) return -1;
        p += 36; /* txid + vout */
        if (!read_varint_from(&p, end, &script_len)) return -1;
        if ((size_t)(end - p) < (size_t)script_len) return -1;
        p += (size_t)script_len;
        if (end - p < 4) return -1;
        p += 4; /* sequence */
    }

    /* output count */
    if (!read_varint_from(&p, end, &n_outputs)) return -1;
    if (vout >= (uint32_t)n_outputs) return -1; /* index out of bounds */

    /* scan outputs until we reach the desired one */
    for (i = 0; i < n_outputs; i++) {
        if (end - p < 8) return -1;
        if (i == vout) {
            /* read amount (little‑endian 8 bytes) */
            uint64_t raw = (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
                           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
                           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
                           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
            *amount_out = (int64_t)raw;
            return 0;
        }
        p += 8; /* skip amount */
        if (!read_varint_from(&p, end, &script_len)) return -1;
        if ((size_t)(end - p) < (size_t)script_len) return -1;
        p += (size_t)script_len;
    }
    return -1; /* shouldn't get here */
}

/* =========================================================================
 * parsing the unsigned transaction (global key 0x00)
 * ========================================================================= */
static void parse_unsigned_tx(int *num_inputs, int *num_outputs)
{
    const uint8_t *tx   = psbt_data.raw_unsigned_tx;
    const uint8_t *end  = tx + psbt_data.unsigned_tx_len;
    uint64_t count;
    int i;

    if (end - tx < 4) fkt_psbt_die("Unsigned tx too short.");

    /* version */
    tx += 4;

    /* SPEC REQUIREMENT: unsigned transaction must NOT contain segwit marker+flag */
    if (end - tx >= 2 && tx[0] == 0x00 && tx[1] == 0x01)
        fkt_psbt_die("Unsigned transaction contains segwit marker (must be legacy format).");

    /* input count */
    if (!read_varint_from(&tx, end, &count)) fkt_psbt_die("Malformed unsigned tx (input count).");
    if (count > (uint64_t)MAX_PSBT_ITEMS) fkt_psbt_die("Too many inputs in unsigned tx.");
    *num_inputs = (int)count;

    /* iterate over inputs to extract outpoints and skip scripts/sequences */
    for (i = 0; i < *num_inputs; i++) {
        if (end - tx < 36) fkt_psbt_die("Unsigned tx truncated in input.");
        memcpy(psbt_data.input_txid[i], tx, 32);
        psbt_data.input_vout[i] = (uint32_t)tx[32] | ((uint32_t)tx[33] << 8) |
                                  ((uint32_t)tx[34] << 16) | ((uint32_t)tx[35] << 24);
        tx += 36;

        /* scriptSig length */
        if (!read_varint_from(&tx, end, &count)) fkt_psbt_die("Malformed scriptSig length.");
        if ((size_t)(end - tx) < (size_t)count) fkt_psbt_die("Unsigned tx scriptSig overrun.");
        tx += (size_t)count;

        /* sequence */
        if (end - tx < 4) fkt_psbt_die("Unsigned tx missing sequence.");
        tx += 4;
    }

    /* output count */
    if (!read_varint_from(&tx, end, &count)) fkt_psbt_die("Malformed unsigned tx (output count).");
    if (count > (uint64_t)MAX_PSBT_ITEMS) fkt_psbt_die("Too many outputs.");
    *num_outputs = (int)count;

    /* parse outputs */
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

    /* locktime */
    if (end - tx != 4) fkt_psbt_die("Unsigned tx extra bytes or missing locktime.");
}

/* =========================================================================
 * parse global map, input maps, output maps
 * ========================================================================= */
static void parse_global_map(int *num_inputs, int *num_outputs)
{
    int has_unsigned_tx = 0;
    uint8_t key_type;
    const uint8_t *key_data, *value;
    size_t key_data_len, value_len;

    while (1) {
        if (!parse_map_entry(&key_type, &key_data, &key_data_len,
                             &value, &value_len))
            break;   /* separator */
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

    if (!has_unsigned_tx)
        fkt_psbt_die("Missing unsigned transaction in global map.");

    /* now extract input/output counts and output data */
    parse_unsigned_tx(num_inputs, num_outputs);
}

static void parse_inputs(int expected_inputs)
{
    int i;
    uint8_t key_type;
    const uint8_t *key_data, *value;
    size_t key_data_len, value_len;

    /* duplicate outpoint detection – linear scan (fine for ≤256) */
    struct { uint8_t txid[32]; uint32_t vout; } seen[MAX_PSBT_ITEMS];
    int num_seen = 0;

    for (i = 0; i < expected_inputs; i++) {
        int has_non_witness = 0, has_witness = 0;
        int amount_found = 0;

        while (1) {
            if (!parse_map_entry(&key_type, &key_data, &key_data_len,
                                 &value, &value_len))
                break;   /* separator after this input map */

            /* immediately reject finalized fields that indicate a signed PSBT */
            if ((key_type == FKT_PSBT_IN_FINAL_SCRIPTSIG ||
                 key_type == FKT_PSBT_IN_FINAL_SCRIPTWITNESS) && value_len > 0)
                fkt_psbt_die("PSBT already contains finalized witness/scriptsig data.");

            check_key_allowed(key_type, MAP_INPUT);

            if (key_type == FKT_PSBT_IN_NON_WITNESS_UTXO) {
                if (has_witness) fkt_psbt_die("Conflicting UTXO data (both non-witness and witness).");
                if (has_non_witness) fkt_psbt_die("Duplicate non-witness UTXO in input.");
                has_non_witness = 1;

                /* parse the previous transaction to extract the output amount */
                {
                    int64_t amt;
                    if (extract_prevout_amount(value, value_len,
                                              psbt_data.input_vout[i], &amt) != 0)
                        fkt_psbt_die("Failed to extract amount from non-witness UTXO.");
                    psbt_data.input_amount[i] = amt;
                    amount_found = 1;
                }
            } else if (key_type == FKT_PSBT_IN_WITNESS_UTXO) {
                if (has_non_witness) fkt_psbt_die("Conflicting UTXO data (both witness and non-witness).");
                if (has_witness) fkt_psbt_die("Duplicate witness UTXO in input.");
                has_witness = 1;

                /* witness UTXO: 8-byte amount (LE) + scriptPubKey */
                if (value_len < 8) fkt_psbt_die("Witness UTXO value too short.");
                {
                    size_t script_len = value_len - 8;
                    if (script_len > 520)
                        fkt_psbt_die("Witness UTXO scriptPubKey exceeds 520 bytes.");
                    /* read amount */
                    {
                        const uint8_t *vp = value;
                        int64_t amt = (int64_t)((uint64_t)vp[0] | ((uint64_t)vp[1] << 8) |
                                                ((uint64_t)vp[2] << 16) | ((uint64_t)vp[3] << 24) |
                                                ((uint64_t)vp[4] << 32) | ((uint64_t)vp[5] << 40) |
                                                ((uint64_t)vp[6] << 48) | ((uint64_t)vp[7] << 56));
                        psbt_data.input_amount[i] = amt;
                        amount_found = 1;
                    }
                }
            }
            /* ignore other allowed keys (0x07,0x08 empty) */
        }

        psbt_data.input_has_amount[i] = amount_found;

        /* duplicate outpoint check */
        {
            int j;
            for (j = 0; j < num_seen; j++) {
                if (memcmp(seen[j].txid, psbt_data.input_txid[i], 32) == 0 &&
                    seen[j].vout == psbt_data.input_vout[i]) {
                    fkt_psbt_die("Duplicate outpoint detected.");
                }
            }
            memcpy(seen[num_seen].txid, psbt_data.input_txid[i], 32);
            seen[num_seen].vout = psbt_data.input_vout[i];
            num_seen++;
        }
    }
}

static void parse_outputs(int expected_outputs)
{
    int i;
    uint8_t key_type;
    const uint8_t *key_data, *value;
    size_t key_data_len, value_len;

    for (i = 0; i < expected_outputs; i++) {
        while (1) {
            if (!parse_map_entry(&key_type, &key_data, &key_data_len,
                                 &value, &value_len))
                break;
            check_key_allowed(key_type, MAP_OUTPUT);  /* always fatal */
        }
    }
}

/* =========================================================================
 * main parse entry point
 * ========================================================================= */
void fkt_psbt_parse(void)
{
    int num_inputs, num_outputs;

    if (psbt_cursor == NULL) fkt_psbt_die("No PSBT loaded.");

    /* magic */
    ensure_bytes(5);
    if (psbt_cursor[0] != FKT_PSBT_MAGIC_0 ||
        psbt_cursor[1] != FKT_PSBT_MAGIC_1 ||
        psbt_cursor[2] != FKT_PSBT_MAGIC_2 ||
        psbt_cursor[3] != FKT_PSBT_MAGIC_3 ||
        psbt_cursor[4] != FKT_PSBT_MAGIC_4)
        fkt_psbt_die("Invalid PSBT magic bytes.");
    psbt_cursor += 5;

    /* global map (separator checked implicitly) */
    parse_global_map(&num_inputs, &num_outputs);
    psbt_data.num_inputs  = num_inputs;
    psbt_data.num_outputs = num_outputs;

    /* input maps */
    parse_inputs(num_inputs);

    /* output maps */
    parse_outputs(num_outputs);

    /* strict: nothing left after final separator */
    if (psbt_cursor != psbt_end)
        fkt_psbt_die("Trailing data after PSBT.");
}

/* =========================================================================
 * preview (no secret material touched)
 * ========================================================================= */
void fkt_psbt_preview(void)
{
    int i;
    int64_t total_in = 0, total_out = 0, fee;
    char txid_str[65]; /* placeholder */

    /* TXID would be computed from raw_unsigned_tx later */
    printf("--- FKT PSBT Preview ---\n");
    printf("TXID: (computation pending)\n\n");

    printf("Inputs:\n");
    for (i = 0; i < psbt_data.num_inputs; i++) {
        printf("  #%d  ", i);
        /* txid hex */
        {
            int k;
            for (k = 0; k < 32; k++) printf("%02x", psbt_data.input_txid[i][k]);
        }
        printf(":%u", (unsigned)psbt_data.input_vout[i]);
        if (psbt_data.input_has_amount[i]) {
            printf("  amount: %lld sat", (long long)psbt_data.input_amount[i]);
            total_in += psbt_data.input_amount[i];
        } else {
            printf("  amount: (unknown)");
        }
        printf("\n");
    }

    printf("\nOutputs:\n");
    for (i = 0; i < psbt_data.num_outputs; i++) {
        printf("  #%d  amount: %lld sat  script: ", i,
               (long long)psbt_data.output_amount[i]);
        {
            size_t j;
            for (j = 0; j < psbt_data.output_script_len[i]; j++)
                printf("%02x", psbt_data.output_script[i][j]);
        }
        printf("\n");
        total_out += psbt_data.output_amount[i];
    }

    fee = total_in - total_out;
    printf("\nFee: %lld sat", (long long)fee);
    if (total_in > 0 && fee < 0)
        printf("  *** WARNING: fee is negative ***");
    printf("\n\nPSBT fingerprint (SHA256 of raw bytes): (pending)\n");
}