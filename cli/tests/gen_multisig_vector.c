/*
 * gen_multisig_vector.c — synthetic native P2WSH m-of-n PSBTs (V2).
 *
 * Kinds:
 *   1of1  — one seed; full finalize after one FKT sign
 *   2of2  — seedA seedB; two cosign passes
 *   2of3  — seedA seedB seedC; any two finalize
 *
 * Keys: BIP67-sorted compressed pubs in bare OP_CHECKMULTISIG script.
 * Path per cosigner: m/48'/1'/0'/2'/0/0 (BIP48 native multi, testnet coin).
 *
 * Usage:
 *   ./gen_multisig_vector 1of1 out.psbt <seedA_hex128>
 *   ./gen_multisig_vector 2of2 out.psbt <seedA_hex128> <seedB_hex128>
 *   ./gen_multisig_vector 2of3 out.psbt <A> <B> <C>
 */
#include "../fkt_bip32.h"
#include "../fkt_secp256k1.h"
#include "../fkt_hash160.h"
#include "../fkt_compat.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <secp256k1.h>

void fkt_ui_term_restore(void) {}

#define OP_1 0x51
#define OP_CHECKMULTISIG 0xAE
#define MAX_KEYS 3

static int hex_decode(const char *hex, uint8_t *out, int max_out) {
    int len = (int)strlen(hex);
    int i;
    if (len % 2 != 0 || len / 2 > max_out) return -1;
    for (i = 0; i < len / 2; i++) {
        unsigned int byte;
        if (sscanf(&hex[i * 2], "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return len / 2;
}

static size_t write_vi(uint8_t *out, uint64_t n) {
    if (n < 0xFDu) {
        out[0] = (uint8_t)n;
        return 1;
    }
    if (n <= 0xFFFFu) {
        out[0] = 0xFD;
        out[1] = (uint8_t)(n & 0xFF);
        out[2] = (uint8_t)((n >> 8) & 0xFF);
        return 3;
    }
    return 0;
}

static size_t append_kv(uint8_t *buf, size_t pos, size_t max,
                        const uint8_t *key, size_t klen,
                        const uint8_t *val, size_t vlen) {
    uint8_t tmp[16];
    size_t n;
    n = write_vi(tmp, (uint64_t)klen);
    if (pos + n + klen + 9 + vlen > max) return 0;
    memcpy(buf + pos, tmp, n); pos += n;
    memcpy(buf + pos, key, klen); pos += klen;
    n = write_vi(tmp, (uint64_t)vlen);
    memcpy(buf + pos, tmp, n); pos += n;
    memcpy(buf + pos, val, vlen); pos += vlen;
    return pos;
}

/* BIP48 native multi: m/48'/1'/0'/2'/0/0 */
static void path_bip48(uint32_t path[6]) {
    path[0] = 48u | 0x80000000u;
    path[1] = 1u | 0x80000000u;
    path[2] = 0u | 0x80000000u;
    path[3] = 2u | 0x80000000u;
    path[4] = 0;
    path[5] = 0;
}

static int master_fp(const uint8_t seed[64], uint8_t fp4[4]) {
    uint8_t mpriv[32], mchain[32], mpub[33];
    uint8_t h160[20];
    secp256k1_context *ctx;
    secp256k1_pubkey pk;
    size_t len = 33;

    fkt_bip32_master(seed, mpriv, mchain);
    ctx = fkt_secp256k1_ctx();
    if (!ctx || !secp256k1_ec_pubkey_create(ctx, &pk, mpriv)) {
        memset(mpriv, 0, 32);
        return -1;
    }
    if (!secp256k1_ec_pubkey_serialize(ctx, mpub, &len, &pk, SECP256K1_EC_COMPRESSED)) {
        memset(mpriv, 0, 32);
        return -1;
    }
    fkt_hash160(mpub, 33, h160);
    memcpy(fp4, h160, 4);
    memset(mpriv, 0, 32);
    memset(mchain, 0, 32);
    return 0;
}

static int derive_cosigner(const uint8_t seed[64], uint8_t pub33[33], uint8_t fp4[4]) {
    uint32_t path[6];
    uint8_t priv[32];
    path_bip48(path);
    if (master_fp(seed, fp4) != 0)
        return -1;
    if (fkt_derive_from_indices(seed, path, 6, priv, pub33, NULL) != 0)
        return -1;
    memset(priv, 0, 32);
    return 0;
}

/* Lexicographic sort of compressed pubs (BIP67). Order index maps sorted→original. */
static void bip67_sort(uint8_t pubs[][33], int n, int order[MAX_KEYS]) {
    int i, j;
    for (i = 0; i < n; i++)
        order[i] = i;
    for (i = 0; i < n; i++) {
        for (j = i + 1; j < n; j++) {
            if (memcmp(pubs[order[i]], pubs[order[j]], 33) > 0) {
                int t = order[i];
                order[i] = order[j];
                order[j] = t;
            }
        }
    }
}

static size_t build_multisig_script(int m, int n, uint8_t pubs[][33], const int order[MAX_KEYS],
                                    uint8_t *script, size_t max) {
    size_t p = 0;
    int i;
    if (m < 1 || m > 16 || n < m || n > MAX_KEYS)
        return 0;
    if ((size_t)(1 + n * 34 + 2) > max)
        return 0;
    script[p++] = (uint8_t)(0x50 + m); /* OP_m */
    for (i = 0; i < n; i++) {
        script[p++] = 0x21;
        memcpy(script + p, pubs[order[i]], 33);
        p += 33;
    }
    script[p++] = (uint8_t)(0x50 + n); /* OP_n */
    script[p++] = OP_CHECKMULTISIG;
    return p;
}

#include "../fkt_sha256.h"

int main(int argc, char **argv) {
    const char *kind;
    const char *out_path;
    int m, n, nseeds, i, j;
    uint8_t seeds[MAX_KEYS][64];
    uint8_t pubs[MAX_KEYS][33];
    uint8_t fps[MAX_KEYS][4];
    int order[MAX_KEYS];
    uint8_t script[200];
    size_t script_len;
    uint8_t script_hash[32];
    uint8_t spk[34];
    uint8_t wutxo[8 + 1 + 34];
    uint8_t tx[200];
    size_t tlen, pos;
    uint8_t psbt[2048];
    uint8_t key_buf[40];
    uint8_t bip32_val[4 + 24];
    uint32_t path[6];
    FILE *f;
    uint64_t amt;
    uint32_t nsequence = 0xfffffffd;
    uint32_t nlocktime = 0;

    if (argc < 4) {
        fprintf(stderr,
                "usage: %s 1of1|2of2|2of3 out.psbt <seedA_hex> [seedB_hex] [seedC_hex]\n",
                argv[0]);
        return 1;
    }
    kind = argv[1];
    out_path = argv[2];

    if (strcmp(kind, "1of1") == 0) {
        m = 1; n = 1; nseeds = 1;
    } else if (strcmp(kind, "2of2") == 0) {
        m = 2; n = 2; nseeds = 2;
    } else if (strcmp(kind, "2of3") == 0) {
        m = 2; n = 3; nseeds = 3;
    } else {
        fprintf(stderr, "unknown kind '%s'\n", kind);
        return 1;
    }
    if (argc != 3 + nseeds) {
        fprintf(stderr, "kind %s needs %d seed hex args\n", kind, nseeds);
        return 1;
    }

    fkt_secp256k1_init();
    for (i = 0; i < nseeds; i++) {
        if (hex_decode(argv[3 + i], seeds[i], 64) != 64) {
            fprintf(stderr, "seed %d: need 128 hex chars\n", i);
            return 1;
        }
        if (derive_cosigner(seeds[i], pubs[i], fps[i]) != 0) {
            fprintf(stderr, "derive failed for seed %d\n", i);
            return 1;
        }
    }

    bip67_sort(pubs, n, order);
    script_len = build_multisig_script(m, n, pubs, order, script, sizeof(script));
    if (script_len == 0) {
        fprintf(stderr, "script build failed\n");
        return 1;
    }
    fkt_sha256(script, script_len, script_hash);
    spk[0] = 0x00;
    spk[1] = 0x20;
    memcpy(spk + 2, script_hash, 32);

    /* Unsigned tx: 1-in 1-out */
    pos = 0;
    tx[pos++] = 0x02; tx[pos++] = 0x00; tx[pos++] = 0x00; tx[pos++] = 0x00; /* version */
    tx[pos++] = 0x01; /* 1 input */
    memset(tx + pos, 0xab, 32); pos += 32; /* fake prev txid */
    tx[pos++] = 0x00; tx[pos++] = 0x00; tx[pos++] = 0x00; tx[pos++] = 0x00; /* vout 0 */
    tx[pos++] = 0x00; /* empty scriptSig */
    tx[pos++] = (uint8_t)(nsequence & 0xFF);
    tx[pos++] = (uint8_t)((nsequence >> 8) & 0xFF);
    tx[pos++] = (uint8_t)((nsequence >> 16) & 0xFF);
    tx[pos++] = (uint8_t)((nsequence >> 24) & 0xFF);
    tx[pos++] = 0x01; /* 1 output */
    amt = 50000;
    for (j = 0; j < 8; j++)
        tx[pos++] = (uint8_t)((amt >> (8 * j)) & 0xFF);
    tx[pos++] = 34;
    memcpy(tx + pos, spk, 34); pos += 34;
    tx[pos++] = (uint8_t)(nlocktime & 0xFF);
    tx[pos++] = (uint8_t)((nlocktime >> 8) & 0xFF);
    tx[pos++] = (uint8_t)((nlocktime >> 16) & 0xFF);
    tx[pos++] = (uint8_t)((nlocktime >> 24) & 0xFF);
    tlen = pos;

    amt = 100000;
    for (j = 0; j < 8; j++)
        wutxo[j] = (uint8_t)((amt >> (8 * j)) & 0xFF);
    wutxo[8] = 34;
    memcpy(wutxo + 9, spk, 34);

    path_bip48(path);

    pos = 0;
    memcpy(psbt, "psbt\xff", 5); pos = 5;
    key_buf[0] = 0x00;
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 1, tx, tlen);
    if (!pos) return 1;
    psbt[pos++] = 0x00; /* end global */

    key_buf[0] = 0x01; /* WITNESS_UTXO */
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 1, wutxo, 8 + 1 + 34);
    if (!pos) return 1;

    key_buf[0] = 0x05; /* WITNESS_SCRIPT */
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 1, script, script_len);
    if (!pos) return 1;

    /* BIP32 derivation for each cosigner (original seed order, not BIP67) */
    for (i = 0; i < n; i++) {
        key_buf[0] = 0x06;
        memcpy(key_buf + 1, pubs[i], 33);
        memcpy(bip32_val, fps[i], 4);
        for (j = 0; j < 6; j++) {
            uint32_t v = path[j];
            bip32_val[4 + j * 4 + 0] = (uint8_t)(v & 0xFF);
            bip32_val[4 + j * 4 + 1] = (uint8_t)((v >> 8) & 0xFF);
            bip32_val[4 + j * 4 + 2] = (uint8_t)((v >> 16) & 0xFF);
            bip32_val[4 + j * 4 + 3] = (uint8_t)((v >> 24) & 0xFF);
        }
        pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 34, bip32_val, 4 + 24);
        if (!pos) return 1;
    }

    psbt[pos++] = 0x00; /* end input */
    psbt[pos++] = 0x00; /* empty output map */

    f = fopen(out_path, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fwrite(psbt, 1, pos, f);
    fclose(f);

    fprintf(stderr, "wrote %s (%zu bytes) kind=%s m=%d n=%d script_len=%zu\n",
            out_path, pos, kind, m, n, script_len);
    for (i = 0; i < n; i++) {
        fprintf(stderr, "  key[%d] pub=", i);
        for (j = 0; j < 33; j++)
            fprintf(stderr, "%02x", pubs[i][j]);
        fprintf(stderr, "\n");
    }
    (void)OP_1;
    return 0;
}
