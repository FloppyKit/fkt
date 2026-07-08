#define _POSIX_C_SOURCE 200809L
#include "fkt_psbt.h"
#include "fkt_error.h"
#include "fkt_sha256.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif           

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

/* Default strict. fkt_fuzz.c sets this to 1 while exploring malformed inputs. */
int fkt_psbt_lenient_parse = 0;
int fkt_psbt_fuzz_mode = 0;
jmp_buf fkt_psbt_fuzz_jmp;

/* #### SECTION: Error handler #### */
static void fkt_psbt_die(const char *msg) {
    fkt_last_error_set(msg);
    if (fkt_psbt_fuzz_mode)
        longjmp(fkt_psbt_fuzz_jmp, 1);
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

static int fkt_exe_dir(char *buf, size_t len) {
#ifdef __linux__
    char linkpath[PATH_MAX];
    ssize_t n;
    char *slash;

    n = readlink("/proc/self/exe", linkpath, sizeof(linkpath) - 1);
    if (n <= 0) return -1;
    linkpath[n] = '\0';
    slash = strrchr(linkpath, '/');
    if (!slash) return -1;
    *slash = '\0';
    if (strlen(linkpath) + 1 >= len) return -1;
    strcpy(buf, linkpath);
    return 0;
#else
    (void)buf;
    (void)len;
    return -1;
#endif
}

static int fkt_try_load_path(const char *candidate, uint8_t *buf, size_t max_size,
                             size_t *out_size, char *resolved, size_t resolved_len) {
    char canon[PATH_MAX];
    const char *report;

    if (read_file(candidate, buf, max_size, out_size) != 0)
        return -1;

    report = candidate;
    if (realpath(candidate, canon) != NULL)
        report = canon;
    if (resolved && resolved_len > 0) {
        strncpy(resolved, report, resolved_len - 1);
        resolved[resolved_len - 1] = '\0';
    }
    return 0;
}

static int fkt_psbt_resolve_load(const char *path, uint8_t *buf, size_t max_size,
                                 size_t *out_size, char *resolved, size_t resolved_len) {
    const char *candidates[8];
    char exe_dir[PATH_MAX];
    char cwd[PATH_MAX];
    char buf1[PATH_MAX], buf2[PATH_MAX], buf3[PATH_MAX];
    int n = 0;
    int i;

    if (!path || path[0] == '\0') return -1;

    candidates[n++] = path;

    if (path[0] != '/') {
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            snprintf(buf1, sizeof(buf1), "%s/%s", cwd, path);
            candidates[n++] = buf1;
            snprintf(buf2, sizeof(buf2), "%s/cli/%s", cwd, path);
            candidates[n++] = buf2;
        }
        if (fkt_exe_dir(exe_dir, sizeof(exe_dir)) == 0) {
            snprintf(buf3, sizeof(buf3), "%s/%s", exe_dir, path);
            candidates[n++] = buf3;
        }
    }

    for (i = 0; i < n; i++) {
        if (fkt_try_load_path(candidates[i], buf, max_size, out_size, resolved, resolved_len) == 0)
            return 0;
    }

    fprintf(stderr, "DEBUG: PSBT file not found: '%s'\n", path);
    if (getcwd(cwd, sizeof(cwd)) != NULL)
        fprintf(stderr, "DEBUG: cwd=%s\n", cwd);
    if (fkt_exe_dir(exe_dir, sizeof(exe_dir)) == 0)
        fprintf(stderr, "DEBUG: exe_dir=%s\n", exe_dir);
    for (i = 0; i < n; i++)
        fprintf(stderr, "DEBUG: tried: %s (errno=%d)\n", candidates[i], errno);
    return -1;
}

int fkt_psbt_load_file(const char *path) {
    size_t size;
    char resolved[PATH_MAX];

    if (fkt_psbt_resolve_load(path, psbt_buffer, FKT_PSBT_MAX_SIZE, &size,
                              resolved, sizeof(resolved)) != 0) {
        fprintf(stderr, "Load failed: %s\n", path);
        return -1;
    }
    psbt_size = size;
    psbt_cursor = psbt_buffer;
    psbt_end = psbt_buffer + size;
    return 0;
}

int fkt_psbt_load_memory(const uint8_t *data, size_t len) {
    if (data == NULL || len == 0 || len > FKT_PSBT_MAX_SIZE)
        return -1;
    memcpy(psbt_buffer, data, len);
    psbt_size = len;
    psbt_cursor = psbt_buffer;
    psbt_end = psbt_buffer + len;
    return 0;
}

int fkt_psbt_try_parse(void) {
    fkt_last_error_clear();
    fkt_psbt_fuzz_mode = 1;
    if (setjmp(fkt_psbt_fuzz_jmp) != 0) {
        fkt_psbt_fuzz_mode = 0;
        return -1;
    }
    fkt_psbt_parse();
    fkt_psbt_fuzz_mode = 0;
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

static const char b64_encode_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int fkt_psbt_bytes_to_base64(const uint8_t *data, size_t len, char *out, size_t out_max) {
    size_t i;
    size_t pos = 0;

    if (!data || !out || out_max < 4)
        return -1;
    for (i = 0; i < len; i += 3) {
        uint32_t n;
        int pad = 0;

        if (pos + 4 >= out_max)
            return -1;
        n = ((uint32_t)data[i]) << 16;
        if (i + 1 < len)
            n |= ((uint32_t)data[i + 1]) << 8;
        else
            pad = 2;
        if (i + 2 < len)
            n |= (uint32_t)data[i + 2];
        else if (pad == 0)
            pad = 1;
        out[pos++] = b64_encode_table[(n >> 18) & 63];
        out[pos++] = b64_encode_table[(n >> 12) & 63];
        out[pos++] = (pad > 1) ? '=' : b64_encode_table[(n >> 6) & 63];
        out[pos++] = (pad > 0) ? '=' : b64_encode_table[n & 63];
    }
    if (pos >= out_max)
        return -1;
    out[pos] = '\0';
    return 0;
}

int fkt_psbt_loaded_to_base64(char *out, size_t out_max) {
    if (!out || out_max == 0 || psbt_size == 0)
        return -1;
    return fkt_psbt_bytes_to_base64(psbt_buffer, psbt_size, out, out_max);
}

int fkt_psbt_file_to_base64(const char *path, char *out, size_t out_max) {
    FILE *f;
    long sz;
    uint8_t raw[8192];
    size_t raw_len;

    if (!path || !out || out_max == 0)
        return -1;
    f = fopen(path, "rb");
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    sz = ftell(f);
    if (sz < 0 || (size_t)sz > sizeof(raw)) {
        fclose(f);
        return -1;
    }
    rewind(f);
    raw_len = (size_t)sz;
    if (fread(raw, 1, raw_len, f) != raw_len) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return fkt_psbt_bytes_to_base64(raw, raw_len, out, out_max);
}

int fkt_psbt_load_base64(const char *b64_str) {
    size_t len;
    if(base64_decode(b64_str, psbt_buffer, FKT_PSBT_MAX_SIZE, &len) != 0) return -1;
    psbt_size = len; psbt_cursor = psbt_buffer; psbt_end = psbt_buffer + len;
    return 0;
}

static int fkt_psbt_has_magic(void) {
    if (psbt_size < 5)
        return 0;
    if (psbt_buffer[0] != FKT_PSBT_MAGIC_0 || psbt_buffer[1] != FKT_PSBT_MAGIC_1 ||
        psbt_buffer[2] != FKT_PSBT_MAGIC_2 || psbt_buffer[3] != FKT_PSBT_MAGIC_3 ||
        psbt_buffer[4] != FKT_PSBT_MAGIC_4)
        return 0;
    return 1;
}

static char g_b64_strip[FKT_PSBT_INPUT_MAX];

static void fkt_psbt_strip_b64_ws(const char *in, char *out, size_t out_len) {
    size_t j = 0;

    if (!in || !out || out_len == 0)
        return;
    while (*in) {
        if (*in != ' ' && *in != '\n' && *in != '\r' && *in != '\t') {
            if (j + 1 >= out_len) {
                out[0] = '\0';
                return;
            }
            out[j++] = *in;
        }
        in++;
    }
    out[j] = '\0';
}

static void fkt_psbt_trim_edges(char *s) {
    size_t len;
    size_t start = 0;

    if (!s)
        return;
    while (s[start] == ' ' || s[start] == '\t' ||
           s[start] == '\n' || s[start] == '\r')
        start++;
    if (start > 0)
        memmove(s, s + start, strlen(s + start) + 1);
    len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' ||
                       s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[len - 1] = '\0';
        len--;
    }
}

static int fkt_psbt_is_b64_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

static int fkt_psbt_validate_loaded(void) {
    return fkt_psbt_has_magic();
}

static int fkt_psbt_decode_buffer_as_b64(void) {
    size_t j = 0;
    size_t i;

    for (i = 0; i < psbt_size && j + 1 < sizeof(g_b64_strip); i++) {
        char c = (char)psbt_buffer[i];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t')
            continue;
        if (!fkt_psbt_is_b64_char(c))
            return -1;
        g_b64_strip[j++] = c;
    }
    if (j < 8 || (j % 4) != 0)
        return -1;
    g_b64_strip[j] = '\0';
    return fkt_psbt_load_base64(g_b64_strip);
}

int fkt_psbt_load_input(const char *input) {
    char pathbuf[FKT_PSBT_INPUT_MAX];

    if (!input || input[0] == '\0')
        return -1;

    strncpy(pathbuf, input, sizeof(pathbuf) - 1);
    pathbuf[sizeof(pathbuf) - 1] = '\0';
    fkt_psbt_trim_edges(pathbuf);
    if (pathbuf[0] == '\0')
        return -1;

    /* Always try filesystem path first (binary .psbt or base64 .txt sidecar). */
    fkt_psbt_init();
    if (fkt_psbt_load_file(pathbuf) == 0) {
        if (fkt_psbt_validate_loaded())
            return 0;
        if (fkt_psbt_decode_buffer_as_b64() == 0 && fkt_psbt_validate_loaded())
            return 0;
    }

    /* Fall back to pasted base64 string. */
    fkt_psbt_init();
    fkt_psbt_strip_b64_ws(pathbuf, g_b64_strip, sizeof(g_b64_strip));
    if (g_b64_strip[0] != '\0' && fkt_psbt_load_base64(g_b64_strip) == 0) {
        if (fkt_psbt_validate_loaded())
            return 0;
    }

    fkt_psbt_init();
    return -1;
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

/* #### SECTION: Key whitelist + per-map integrity (PR2) #### */
#define FKT_PSBT_MAX_GLOBAL_XPUB_KEYS     16
#define FKT_PSBT_GLOBAL_XPUB_KEY_MAX      80
#define FKT_PSBT_MAX_INPUT_KEYS_PER_MAP   32
#define FKT_PSBT_MAX_OUTPUT_KEYS_PER_MAP  16
#define FKT_PSBT_MAP_KEY_DATA_MAX         33

typedef struct {
    uint8_t type;
    uint8_t data[FKT_PSBT_MAP_KEY_DATA_MAX];
    uint8_t dlen;
} fkt_psbt_map_key_t;

static int input_key_is_allowed(uint8_t key_type) {
    switch (key_type) {
    case FKT_PSBT_IN_NON_WITNESS_UTXO:
    case FKT_PSBT_IN_WITNESS_UTXO:
    case FKT_PSBT_IN_SIGHASH_TYPE:
    case FKT_PSBT_IN_REDEEM_SCRIPT:
    case FKT_PSBT_IN_WITNESS_SCRIPT_05:
    case FKT_PSBT_IN_BIP32_DERIVATION:
    case FKT_PSBT_IN_FINAL_SCRIPTSIG:
    case FKT_PSBT_IN_FINAL_SCRIPTWITNESS:
    case FKT_PSBT_IN_TAP_BIP32_DERIVATION:
    case FKT_PSBT_IN_TAP_INTERNAL_KEY:
    case FKT_PSBT_IN_TAP_MERKLE_ROOT:
        return 1;
    default:
        return 0;
    }
}

static void validate_input_key_field(uint8_t key_type, size_t key_data_len) {
    switch (key_type) {
    case FKT_PSBT_IN_NON_WITNESS_UTXO:
    case FKT_PSBT_IN_WITNESS_UTXO:
    case FKT_PSBT_IN_SIGHASH_TYPE:
    case FKT_PSBT_IN_REDEEM_SCRIPT:
    case FKT_PSBT_IN_WITNESS_SCRIPT_05:
    case FKT_PSBT_IN_FINAL_SCRIPTSIG:
    case FKT_PSBT_IN_FINAL_SCRIPTWITNESS:
    case FKT_PSBT_IN_TAP_INTERNAL_KEY:
    case FKT_PSBT_IN_TAP_MERKLE_ROOT:
        if (key_data_len != 0)
            fkt_psbt_die("Invalid key field length.");
        break;
    case FKT_PSBT_IN_BIP32_DERIVATION:
        if (key_data_len != 33)
            fkt_psbt_die("Invalid key field length for BIP32 derivation.");
        break;
    case FKT_PSBT_IN_TAP_BIP32_DERIVATION:
        if (key_data_len != 32)
            fkt_psbt_die("Invalid key field length for Taproot BIP32 derivation.");
        break;
    default:
        break;
    }
}

static void map_key_track(fkt_psbt_map_key_t *keys, int *nkeys, int max_keys,
                          uint8_t key_type, const uint8_t *key_data,
                          size_t key_data_len) {
    int j;

    if (*nkeys >= max_keys)
        fkt_psbt_die("Too many keys in PSBT map.");
    if (key_data_len > FKT_PSBT_MAP_KEY_DATA_MAX)
        fkt_psbt_die("PSBT key field too long.");

    for (j = 0; j < *nkeys; j++) {
        if (keys[j].type == key_type &&
            keys[j].dlen == (uint8_t)key_data_len &&
            (key_data_len == 0 ||
             memcmp(keys[j].data, key_data, key_data_len) == 0))
            fkt_psbt_die("Duplicate PSBT key.");
    }

    keys[*nkeys].type = key_type;
    keys[*nkeys].dlen = (uint8_t)key_data_len;
    if (key_data_len > 0)
        memcpy(keys[*nkeys].data, key_data, key_data_len);
    (*nkeys)++;
}

/* #### SECTION: Script detection helpers #### */
static int is_p2wpkh(const uint8_t *s, size_t l) { return l==22 && s[0]==0x00 && s[1]==0x14; }
static int is_p2wsh(const uint8_t *s, size_t l)  { return l==34 && s[0]==0x00 && s[1]==0x20; }
static int is_p2tr(const uint8_t *s, size_t l)   { return l==34 && s[0]==0x51 && s[1]==0x20; }
static int is_p2sh(const uint8_t *s, size_t l)   { return l==23 && s[0]==0xA9 && s[1]==0x14; }
static int is_p2pkh(const uint8_t *s, size_t l) {
    return l == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 &&
           s[23] == 0x88 && s[24] == 0xac;
}

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

static void verify_non_witness_utxo_txid(int input_index,
                                         const uint8_t *tx, size_t tx_len) {
    uint8_t hash[32];

    fkt_sha256d(tx, tx_len, hash);
    if (memcmp(hash, psbt_data.input_txid[input_index], 32) != 0)
        fkt_psbt_die("non-witness UTXO txid mismatch.");
}

/* #### SECTION: Parse unsigned transaction (global key 0x00) #### */
static void parse_unsigned_tx(int *num_inputs, int *num_outputs) {
    const uint8_t *tx   = psbt_data.raw_unsigned_tx;
    const uint8_t *end  = tx + psbt_data.unsigned_tx_len;
    uint64_t count;
    uint32_t version;
    int i;

    if (end - tx < 4) fkt_psbt_die("Unsigned tx too short.");
    version = fkt_read_le32(tx);
    if (version != 1 && version != 2)
        fkt_psbt_die("Unsupported unsigned transaction version.");
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
    if (count > (uint64_t)FKT_PSBT_MAX_OUTPUTS) fkt_psbt_die("Too many outputs.");
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

static void global_xpub_track(const uint8_t *key_data, size_t key_data_len,
                              uint8_t keys[FKT_PSBT_MAX_GLOBAL_XPUB_KEYS][FKT_PSBT_GLOBAL_XPUB_KEY_MAX],
                              size_t key_lens[FKT_PSBT_MAX_GLOBAL_XPUB_KEYS],
                              int *nkeys) {
    int j;

    if (key_data_len > FKT_PSBT_GLOBAL_XPUB_KEY_MAX)
        fkt_psbt_die("PSBT key field too long.");
    if (*nkeys >= FKT_PSBT_MAX_GLOBAL_XPUB_KEYS)
        fkt_psbt_die("Too many keys in PSBT map.");
    for (j = 0; j < *nkeys; j++) {
        if (key_lens[j] == key_data_len &&
            memcmp(keys[j], key_data, key_data_len) == 0)
            fkt_psbt_die("Duplicate PSBT key.");
    }
    memcpy(keys[*nkeys], key_data, key_data_len);
    key_lens[*nkeys] = key_data_len;
    (*nkeys)++;
}

/* #### SECTION: Parse global map #### */
static void parse_global_map(int *num_inputs, int *num_outputs) {
    int has_unsigned_tx = 0;
    uint8_t key_type;
    const uint8_t *key_data, *value;
    size_t key_data_len, value_len;
    uint8_t xpub_keys[FKT_PSBT_MAX_GLOBAL_XPUB_KEYS][FKT_PSBT_GLOBAL_XPUB_KEY_MAX];
    size_t xpub_key_lens[FKT_PSBT_MAX_GLOBAL_XPUB_KEYS];
    int xpub_nkeys = 0;

    while (1) {
        if (!parse_map_entry(&key_type, &key_data, &key_data_len,
                             &value, &value_len))
            break;
        if (key_type == FKT_PSBT_GLOBAL_XPUB) {
            /* BIP174 wallet metadata (Sparrow always includes this). Read-only. */
            if (key_data_len == 0)
                fkt_psbt_die("Invalid key field length.");
            if (value_len < 4 || ((value_len - 4) % 4) != 0)
                fkt_psbt_die("Malformed PSBT_GLOBAL_XPUB value.");
            global_xpub_track(key_data, key_data_len, xpub_keys, xpub_key_lens,
                              &xpub_nkeys);
            continue;
        }
        if (key_type != FKT_PSBT_GLOBAL_UNSIGNED_TX)
            fkt_psbt_die("Unknown PSBT key.");
        if (key_data_len != 0)
            fkt_psbt_die("Invalid key field length.");
        if (key_type == FKT_PSBT_GLOBAL_UNSIGNED_TX) {
            if (has_unsigned_tx) fkt_psbt_die("Duplicate PSBT key.");
            if (value_len > FKT_PSBT_UNSIGNED_TX_MAX)
                fkt_psbt_die("Unsigned transaction too large.");
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

static void fkt_store_derivation_path(int input_index,
                                      const uint8_t *path_start,
                                      size_t path_bytes) {
    int depth;
    int j;

    if (path_bytes == 0 || (path_bytes % 4) != 0)
        fkt_psbt_die("Malformed BIP32 derivation path.");
    depth = (int)(path_bytes / 4);
    if (depth < 1 || depth > 10)
        fkt_psbt_die("BIP32 derivation path length out of range.");

    psbt_data.input_deriv_depth[input_index] = depth;
    psbt_data.input_has_deriv_path[input_index] = 1;
    for (j = 0; j < depth; j++)
        psbt_data.input_deriv_path[input_index][j] =
            fkt_read_le32(path_start + (size_t)j * 4);
}

static void fkt_parse_bip32_derivation(int input_index,
                                       const uint8_t *key_data, size_t key_data_len,
                                       const uint8_t *value, size_t value_len) {
    const uint8_t *path_start;
    size_t path_bytes;

    if (value_len < 4)
        fkt_psbt_die("Malformed PSBT_IN_BIP32_DERIVATION value.");
    if (key_data_len == 33) {
        memcpy(psbt_data.input_deriv_parent_pub[input_index], key_data, 33);
        psbt_data.input_has_deriv_parent_pub[input_index] = 1;
    }

    if (value_len >= 5 && value[4] <= 10 &&
        value_len == 5 + ((size_t)value[4] * 4)) {
        path_start = value + 5;
        path_bytes = (size_t)value[4] * 4;
    } else if (((value_len - 4) % 4) == 0) {
        path_start = value + 4;
        path_bytes = value_len - 4;
    } else {
        fkt_psbt_die("Malformed PSBT_IN_BIP32_DERIVATION value.");
    }
    fkt_store_derivation_path(input_index, path_start, path_bytes);
}

static void fkt_parse_tap_bip32_derivation(int input_index,
                                           const uint8_t *value, size_t value_len) {
    uint8_t n;
    size_t off;
    size_t path_bytes;

    if (value_len < 1)
        fkt_psbt_die("Malformed PSBT_IN_TAP_BIP32_DERIVATION value.");
    n = value[0];
    off = 1 + ((size_t)n * 32);
    if (value_len < off + 4)
        fkt_psbt_die("Malformed PSBT_IN_TAP_BIP32_DERIVATION value.");
    path_bytes = value_len - off - 4;
    if (path_bytes == 0 || (path_bytes % 4) != 0)
        fkt_psbt_die("Malformed PSBT_IN_TAP_BIP32_DERIVATION value.");
    fkt_store_derivation_path(input_index, value + off + 4, path_bytes);
}

/* #### SECTION: Parse input maps (full key handling + script-type detection) #### */
static void parse_inputs(int expected_inputs) {
    int i; uint8_t kt; const uint8_t *kd,*v; size_t kdl,vl;
    struct { uint8_t txid[32]; uint32_t vout; } seen[MAX_PSBT_ITEMS]; int ns=0;
    for(i=0;i<expected_inputs;i++) {
        int af=0; uint8_t st=SCRIPT_TYPE_UNKNOWN; int hmr=0;
        fkt_psbt_map_key_t map_keys[FKT_PSBT_MAX_INPUT_KEYS_PER_MAP];
        int map_nkeys = 0;
        int has_non_witness_utxo = 0;
        int has_witness_utxo = 0;
        int has_bip32_deriv = 0;
        int has_tap_bip32_deriv = 0;
        int64_t nw_utxo_amt = 0;
        int have_nw_utxo_amt = 0;
        uint8_t nw_utxo_script[520];
        size_t nw_utxo_script_len = 0;
        int have_nw_utxo_script = 0;
        input_map_start_offsets[i] = (size_t)(psbt_cursor - psbt_buffer);
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
            if (!input_key_is_allowed(kt))
                fkt_psbt_die("Unknown PSBT key.");
            validate_input_key_field(kt, kdl);
            map_key_track(map_keys, &map_nkeys, FKT_PSBT_MAX_INPUT_KEYS_PER_MAP,
                          kt, kd, kdl);

            if((kt==FKT_PSBT_IN_FINAL_SCRIPTSIG||kt==FKT_PSBT_IN_FINAL_SCRIPTWITNESS) && vl>0) {
                if (kt == FKT_PSBT_IN_FINAL_SCRIPTWITNESS)
                    psbt_data.input_had_final_witness[i] = 1;
                if (kt == FKT_PSBT_IN_FINAL_SCRIPTSIG)
                    psbt_data.input_had_final_scriptsig[i] = 1;
                if (!fkt_psbt_lenient_parse)
                    fkt_psbt_die("PSBT already contains finalized witness/scriptsig data.");
            }
            switch(kt) {
            case FKT_PSBT_IN_NON_WITNESS_UTXO:
                 {
                    int64_t amt;
                    has_non_witness_utxo = 1;
                    if (vl > FKT_PSBT_NON_WITNESS_UTXO_MAX)
                        fkt_psbt_die("non-witness UTXO too large.");
                    if(extract_prevout_amount(v,vl,psbt_data.input_vout[i],&amt)!=0)
                        fkt_psbt_die("Failed to extract amount from non-witness UTXO.");
                    verify_non_witness_utxo_txid(i, v, vl);
                    nw_utxo_amt = amt;
                    have_nw_utxo_amt = 1;
                    psbt_data.input_amount[i]=amt; af=1;
                    if(extract_prevout_script(v,vl,psbt_data.input_vout[i],
                                             nw_utxo_script,&nw_utxo_script_len)==0) {
                        have_nw_utxo_script = 1;
                        memcpy(prevout_script, nw_utxo_script, nw_utxo_script_len);
                        prevout_script_len = nw_utxo_script_len;
                        have_prevout_script = 1;
                    }
                } break;
            case FKT_PSBT_IN_WITNESS_UTXO:
                 has_witness_utxo = 1;

                 if(vl<9) fkt_psbt_die("Witness UTXO value too short.");
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
                    else if(is_p2pkh(script_start, script_len)) st=SCRIPT_TYPE_P2PKH;
                    else if(is_p2sh(script_start, script_len)) st=SCRIPT_TYPE_P2SH;
                    memcpy(psbt_data.input_witness_script[i], script_start, script_len);
                    psbt_data.input_witness_script_len[i] = script_len;
                    psbt_data.input_has_witness_script[i] = 1;
                } break;
            case FKT_PSBT_IN_SIGHASH_TYPE:
                if(vl!=4) fkt_psbt_die("SIGHASH_TYPE must be 4 bytes.");
                psbt_data.input_sighash[i]=fkt_read_le32(v); psbt_data.input_has_sighash[i]=1; break;
            case FKT_PSBT_IN_REDEEM_SCRIPT:
                if (vl <= sizeof(psbt_data.input_redeem_script[i])) {
                    memcpy(psbt_data.input_redeem_script[i], v, vl);
                    psbt_data.input_redeem_script_len[i] = vl;
                    psbt_data.input_has_redeem_script[i] = 1;
                }
                redeem_script = v; redeem_script_len = vl;
                break;
            case FKT_PSBT_IN_WITNESS_SCRIPT_05:
                if (vl <= sizeof(psbt_data.input_redeem_witness_script[i])) {
                    memcpy(psbt_data.input_redeem_witness_script[i], v, vl);
                    psbt_data.input_redeem_witness_script_len[i] = vl;
                    psbt_data.input_has_redeem_witness_script[i] = 1;
                }
                break;
            case FKT_PSBT_IN_BIP32_DERIVATION:
                has_bip32_deriv = 1;
                fkt_parse_bip32_derivation(i, kd, kdl, v, vl);
                break;
            case FKT_PSBT_IN_TAP_BIP32_DERIVATION:
                has_tap_bip32_deriv = 1;
                fkt_parse_tap_bip32_derivation(i, v, vl);
                break;
            case FKT_PSBT_IN_TAP_INTERNAL_KEY:
                if(vl!=32) fkt_psbt_die("TAP_INTERNAL_KEY must be 32 bytes.");
                memcpy(psbt_data.input_tap_int_key[i], v, 32);
                psbt_data.input_has_tap_int_key[i]=1; break;
            case FKT_PSBT_IN_TAP_MERKLE_ROOT:
                if(vl!=32) fkt_psbt_die("TAP_MERKLE_ROOT must be 32 bytes.");
                hmr=1; break;
            case FKT_PSBT_IN_FINAL_SCRIPTSIG:
            case FKT_PSBT_IN_FINAL_SCRIPTWITNESS:
                break;
            default:
                fkt_psbt_die("Unknown PSBT key.");
                break;
            }
        }

        if (has_non_witness_utxo && has_witness_utxo) {
            if (!have_nw_utxo_amt || !af || !psbt_data.input_has_witness_script[i])
                fkt_psbt_die("Conflicting UTXO data.");
            if (nw_utxo_amt != psbt_data.input_amount[i])
                fkt_psbt_die("Conflicting UTXO data.");
            if (!have_nw_utxo_script)
                fkt_psbt_die("Conflicting UTXO data.");
            if (nw_utxo_script_len != psbt_data.input_witness_script_len[i] ||
                memcmp(nw_utxo_script, psbt_data.input_witness_script[i],
                       nw_utxo_script_len) != 0)
                fkt_psbt_die("Conflicting UTXO data.");
        }
        if (!has_non_witness_utxo && !has_witness_utxo)
            fkt_psbt_die("Missing verifiable UTXO on input.");
        if (has_bip32_deriv && has_tap_bip32_deriv)
            fkt_psbt_die("Conflicting derivation keys.");

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
                else if (is_p2pkh(prevout_script, prevout_script_len)) st = SCRIPT_TYPE_P2PKH;
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
        if (!psbt_data.input_has_witness_script[i] && have_prevout_script &&
            prevout_script_len <= sizeof(psbt_data.input_witness_script[i])) {
            memcpy(psbt_data.input_witness_script[i], prevout_script, prevout_script_len);
            psbt_data.input_witness_script_len[i] = prevout_script_len;
            psbt_data.input_has_witness_script[i] = 1;
        }
        if(st == SCRIPT_TYPE_P2TR && hmr) fkt_psbt_die("Taproot input has script tree (0x18) — V0.1 only supports keypath spending");
        { int j; for(j=0;j<ns;j++) if(memcmp(seen[j].txid,psbt_data.input_txid[i],32)==0&&seen[j].vout==psbt_data.input_vout[i]) fkt_psbt_die("Duplicate outpoint detected.");
          memcpy(seen[ns].txid,psbt_data.input_txid[i],32); seen[ns].vout=psbt_data.input_vout[i]; ns++; }
    }
}

/* #### SECTION: Parse output maps #### */
static void parse_outputs(int expected_outputs) {
    int i; uint8_t kt; const uint8_t *kd,*v; size_t kdl,vl;
    for(i=0;i<expected_outputs;i++) {
        fkt_psbt_map_key_t map_keys[FKT_PSBT_MAX_OUTPUT_KEYS_PER_MAP];
        int map_nkeys = 0;

        output_map_start_offsets[i] = (size_t)(psbt_cursor - psbt_buffer);
        while(1) {
            if(!parse_map_entry(&kt,&kd,&kdl,&v,&vl)) {
                if (output_separator_count < MAX_PSBT_ITEMS)
                    output_separator_offsets[output_separator_count++] =
                        (size_t)(psbt_cursor - 1 - psbt_buffer);
                break;
            }
            /* Output maps: unknown keys are ignored (BIP174), but duplicates abort. */
            map_key_track(map_keys, &map_nkeys, FKT_PSBT_MAX_OUTPUT_KEYS_PER_MAP,
                          kt, kd, kdl);
        }
    }
}

/* #### SECTION: Post‑parse validations #### */
static void validate_sighash_types(int num_inputs) {
    int i;
    if (fkt_psbt_lenient_parse) return;
    for(i=0;i<num_inputs;i++) {
        uint8_t st=psbt_data.input_script_type[i];
        if(st==SCRIPT_TYPE_UNKNOWN||st==SCRIPT_TYPE_P2WSH||st==SCRIPT_TYPE_P2SH) continue;
        if(st==SCRIPT_TYPE_P2WPKH || st==SCRIPT_TYPE_P2PKH) {
            uint32_t val=psbt_data.input_has_sighash[i]?psbt_data.input_sighash[i]:FKT_SIGHASH_ALL;
            if(val!=FKT_SIGHASH_ALL) fkt_psbt_die("Invalid SIGHASH_TYPE for P2WPKH/P2PKH (must be 0x01 or absent).");
        } else if(st==SCRIPT_TYPE_P2TR) {
            uint32_t val=psbt_data.input_has_sighash[i]?psbt_data.input_sighash[i]:FKT_SIGHASH_DEFAULT;
            if(val!=FKT_SIGHASH_DEFAULT) fkt_psbt_die("Invalid SIGHASH_TYPE for Taproot (must be 0x00 or absent).");
        }
    }
}



static void validate_map_counts(int num_inputs, int num_outputs) {
    if (fkt_psbt_lenient_parse) return;
    if (num_inputs == 0) fkt_psbt_die("Transaction has no inputs.");
    if (num_outputs == 0) fkt_psbt_die("Transaction has no outputs.");
    if (input_separator_count != num_inputs)
        fkt_psbt_die("PSBT input map count mismatch.");
    if (output_separator_count != num_outputs)
        fkt_psbt_die("PSBT output map count mismatch.");
}

static void validate_inputs_post_parse(int num_inputs) {
    int i;

    if (fkt_psbt_lenient_parse) return;
    for (i = 0; i < num_inputs; i++) {
        if (!psbt_data.input_has_amount[i])
            fkt_psbt_die("Missing verifiable amount on input.");
        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2TR &&
            !psbt_data.input_has_tap_int_key[i])
            fkt_psbt_die("Taproot input missing PSBT_IN_TAP_INTERNAL_KEY.");
    }
}

static void fee_safety_check(void) {
    int i; int64_t total_in=0,total_out=0,fee; size_t twb=0,w,vb;
    if (fkt_psbt_lenient_parse) return;
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
        else if(st==SCRIPT_TYPE_P2PKH) twb+=107;
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
    validate_map_counts(ni, no);
    validate_inputs_post_parse(ni);
    validate_sighash_types(ni);
    fee_safety_check();
    /* Use crypto module for fingerprints */
    fkt_sha256(psbt_buffer, psbt_size, psbt_data.psbt_fingerprint);
    fkt_sha256d(psbt_data.raw_unsigned_tx, psbt_data.unsigned_tx_len, psbt_data.txid);
    psbt_data.hashes_computed = 1;
}

int fkt_psbt_input_has_derivation(int input_index) {
    if (input_index < 0 || input_index >= psbt_data.num_inputs) return 0;
    return psbt_data.input_has_deriv_path[input_index];
}

int fkt_psbt_input_derivation_depth(int input_index) {
    if (input_index < 0 || input_index >= psbt_data.num_inputs) return 0;
    return psbt_data.input_deriv_depth[input_index];
}

const uint32_t *fkt_psbt_input_derivation_path(int input_index) {
    if (input_index < 0 || input_index >= psbt_data.num_inputs) return NULL;
    if (!psbt_data.input_has_deriv_path[input_index]) return NULL;
    return psbt_data.input_deriv_path[input_index];
}

const uint8_t *fkt_psbt_input_derivation_parent_pub(int input_index) {
    if (input_index < 0 || input_index >= psbt_data.num_inputs) return NULL;
    if (!psbt_data.input_has_deriv_parent_pub[input_index]) return NULL;
    return psbt_data.input_deriv_parent_pub[input_index];
}

int fkt_psbt_format_derivation_path(int input_index, char *buf, size_t buf_len) {
    int depth, j, written, total;
    uint32_t idx;

    if (!buf || buf_len == 0) return -1;
    if (!fkt_psbt_input_has_derivation(input_index)) return -1;

    depth = fkt_psbt_input_derivation_depth(input_index);
    written = snprintf(buf, buf_len, "m");
    if (written < 0 || (size_t)written >= buf_len) return -1;
    total = written;

    for (j = 0; j < depth; j++) {
        idx = psbt_data.input_deriv_path[input_index][j];
        written = snprintf(buf + total, buf_len - (size_t)total,
                           "/%u%s",
                           (unsigned)(idx & 0x7FFFFFFFu),
                           (idx & 0x80000000u) ? "'" : "");
        if (written < 0 || (size_t)(total + written) >= buf_len) return -1;
        total += written;
    }
    return 0;
}