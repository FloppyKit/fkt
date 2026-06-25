#include "fkt_psbt.h"
#include "fkt_sha256.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>           

/* Uncomment the line below to enable debug prints */
/* #define FKT_DEBUG */

/* #### SECTION: Static PSBT buffer & cursor #### */

uint8_t  psbt_buffer[FKT_PSBT_MAX_SIZE];
size_t   psbt_size;
static const uint8_t *psbt_cursor;
static const uint8_t *psbt_end;

#define MAX_PSBT_ITEMS  256



/* #### SECTION: Parsed PSBT data (all extracted info) #### */
fkt_psbt_state psbt_data;

/* #### SECTION: Signing hash caches & separator offsets #### */
uint8_t hashPrevouts[32];
uint8_t hashSequence[32];
uint8_t sha_prevouts[32];
uint8_t sha_amounts[32];
uint8_t sha_scriptpubkeys[32];
uint8_t sha_sequences[32];
uint8_t sha_outputs[32];
uint8_t hashOutputs[32];

size_t input_separator_offsets[MAX_PSBT_ITEMS];
size_t input_map_start_offsets[MAX_PSBT_ITEMS];
int    input_separator_count;
size_t output_separator_offsets[MAX_PSBT_ITEMS];
size_t output_map_start_offsets[MAX_PSBT_ITEMS];
int    output_separator_count;

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
    output_separator_count = 0;
    memset(input_separator_offsets, 0, sizeof(input_separator_offsets));
    memset(input_map_start_offsets, 0, sizeof(input_map_start_offsets));
    memset(output_separator_offsets, 0, sizeof(output_separator_offsets));
    memset(output_map_start_offsets, 0, sizeof(output_map_start_offsets));
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
        if(key_type != FKT_PSBT_GLOBAL_UNSIGNED_TX &&
           key_type != 0x01 &&
           key_type != 0xFC)
            fkt_psbt_die("Unknown key in global PSBT map.");
        break;
    case MAP_INPUT:
        break;
    case MAP_OUTPUT:
        break;
    }
}

/* TRUNCATED_FOR_PUSH_TEST */