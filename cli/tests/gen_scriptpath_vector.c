/*
 * gen_scriptpath_vector.c — synthetic single-leaf script-path PSBTs.
 *
 * Leaf kinds (bark-shaped, not production bark):
 *   checksig  — <P> OP_CHECKSIG
 *   csv       — <10> OP_CSV OP_DROP <P> OP_CHECKSIG
 *   cltv      — <100> OP_CLTV OP_DROP <P> OP_CHECKSIG
 *   csv_cltv  — both delays then CHECKSIG
 *   reject_noleaf — merkle root only (for expect=reject harness)
 *
 * Path: m/86'/1'/0'/0/0 from BIP39 seed hex.
 * Usage: ./gen_scriptpath_vector <seed_hex128> <out.psbt> [kind]
 */
#include "../fkt_bip32.h"
#include "../fkt_secp256k1.h"
#include "../fkt_sighash.h"
#include "../fkt_compat.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

/* fkt_memzero.o may reference UI restore on SIGINT — stub for this tool. */
void fkt_ui_term_restore(void) {}

#define OP_DROP   0x75
#define OP_CLTV   0xb1
#define OP_CSV    0xb2
#define OP_CHECKSIG 0xac

enum leaf_kind {
    KIND_CHECKSIG = 0,
    KIND_CSV,
    KIND_CLTV,
    KIND_CSV_CLTV,
    KIND_REJECT_NOLEAF
};

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

static enum leaf_kind parse_kind(const char *s) {
    if (!s || !s[0] || strcmp(s, "checksig") == 0)
        return KIND_CHECKSIG;
    if (strcmp(s, "csv") == 0)
        return KIND_CSV;
    if (strcmp(s, "cltv") == 0)
        return KIND_CLTV;
    if (strcmp(s, "csv_cltv") == 0 || strcmp(s, "csv+cltv") == 0)
        return KIND_CSV_CLTV;
    if (strcmp(s, "reject_noleaf") == 0 || strcmp(s, "noleaf") == 0)
        return KIND_REJECT_NOLEAF;
    fprintf(stderr, "unknown kind '%s' (checksig|csv|cltv|csv_cltv|reject_noleaf)\n", s);
    exit(1);
    return KIND_CHECKSIG;
}

/* Build leaf script; returns length. xonly is 32 bytes. */
static size_t build_leaf_script(enum leaf_kind kind, const uint8_t xonly[32],
                                uint8_t *script, size_t script_max) {
    size_t p = 0;

    if (kind == KIND_CSV || kind == KIND_CSV_CLTV) {
        /* <10> OP_CSV OP_DROP */
        if (p + 4 > script_max) return 0;
        script[p++] = 0x01;
        script[p++] = 0x0a;
        script[p++] = OP_CSV;
        script[p++] = OP_DROP;
    }
    if (kind == KIND_CLTV || kind == KIND_CSV_CLTV) {
        /* <100> OP_CLTV OP_DROP */
        if (p + 4 > script_max) return 0;
        script[p++] = 0x01;
        script[p++] = 0x64;
        script[p++] = OP_CLTV;
        script[p++] = OP_DROP;
    }
    /* <P> OP_CHECKSIG */
    if (p + 34 > script_max) return 0;
    script[p++] = 0x20;
    memcpy(script + p, xonly, 32);
    p += 32;
    script[p++] = OP_CHECKSIG;
    return p;
}

int main(int argc, char **argv) {
    uint8_t seed[64];
    uint8_t child_priv[32], child_pub33[33], xonly[32];
    uint8_t leaf_script[128];
    size_t leaf_len = 0;
    uint8_t leaf_hash[32];
    uint8_t tweak_in[64], tweak[32];
    uint8_t control[33];
    uint8_t leaf_val[129];
    uint8_t spk[34];
    uint8_t tx[128];
    uint8_t wutxo[8 + 1 + 34];
    uint8_t psbt[2048];
    size_t pos, tlen;
    uint8_t key_buf[40];
    uint8_t tap_bip32_val[1 + 4 + 5 * 4];
    FILE *f;
    secp256k1_context *ctx;
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey xpub;
    int pk_parity;
    const char *bip_path = "m/86'/1'/0'/0/0";
    uint32_t path_idx[5];
    int i;
    enum leaf_kind kind;
    uint32_t nsequence;
    uint32_t nlocktime;
    const char *kind_name;

    if (argc < 3 || argc > 4) {
        fprintf(stderr,
                "Usage: %s <seed_hex128> <out.psbt> [checksig|csv|cltv|csv_cltv|reject_noleaf]\n",
                argv[0]);
        return 1;
    }
    if (hex_decode(argv[1], seed, 64) != 64) {
        fprintf(stderr, "bad seed hex\n");
        return 1;
    }
    kind = parse_kind(argc == 4 ? argv[3] : "checksig");
    kind_name = (argc == 4) ? argv[3] : "checksig";

    fkt_secp256k1_init();
    ctx = fkt_secp256k1_ctx();

    if (fkt_derive_from_path(seed, bip_path, child_priv, child_pub33, NULL) != 0) {
        fprintf(stderr, "derive failed\n");
        return 1;
    }
    memcpy(xonly, child_pub33 + 1, 32);

    if (kind != KIND_REJECT_NOLEAF) {
        leaf_len = build_leaf_script(kind, xonly, leaf_script, sizeof(leaf_script));
        if (leaf_len == 0) {
            fprintf(stderr, "leaf build failed\n");
            return 1;
        }
        if (fkt_tapleaf_hash(0xc0, leaf_script, leaf_len, leaf_hash) != 0) {
            fprintf(stderr, "tapleaf hash failed\n");
            return 1;
        }
    } else {
        /* Dummy merkle root so 0x18 is present without a leaf */
        memset(leaf_hash, 0xab, 32);
        leaf_len = 0;
    }

    /* single-leaf: merkle_root = tapleaf_hash (or dummy for reject) */
    memcpy(tweak_in, xonly, 32);
    memcpy(tweak_in + 32, leaf_hash, 32);
    if (fkt_tagged_sha256("TapTweak", 8, tweak_in, 64, tweak) != 0) {
        fprintf(stderr, "taptweak failed\n");
        return 1;
    }

    if (!secp256k1_keypair_create(ctx, &keypair, child_priv)) return 1;
    if (!secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak)) {
        fprintf(stderr, "tweak add failed\n");
        return 1;
    }
    if (!secp256k1_keypair_xonly_pub(ctx, &xpub, &pk_parity, &keypair)) return 1;
    {
        uint8_t out_xonly[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, out_xonly, &xpub)) return 1;
        spk[0] = 0x51;
        spk[1] = 0x20;
        memcpy(spk + 2, out_xonly, 32);
    }

    control[0] = (uint8_t)(0xc0 | (pk_parity ? 1 : 0));
    memcpy(control + 1, xonly, 32);

    if (kind != KIND_REJECT_NOLEAF) {
        memcpy(leaf_val, leaf_script, leaf_len);
        leaf_val[leaf_len] = 0xc0;
    }

    /* Sequence / locktime per leaf kind */
    nsequence = 0xfffffffdU;
    nlocktime = 0;
    if (kind == KIND_CSV || kind == KIND_CSV_CLTV)
        nsequence = 10;
    if (kind == KIND_CLTV || kind == KIND_CSV_CLTV) {
        nlocktime = 100;
        if (kind == KIND_CLTV)
            nsequence = 0xfffffffeU;
    }

    /* unsigned tx */
    {
        uint8_t prev_txid[32];
        uint64_t amt;
        int j;
        memset(prev_txid, 0x11, 32);
        prev_txid[0] = (uint8_t)kind; /* distinct prev per kind */
        pos = 0;
        tx[pos++] = 2; tx[pos++] = 0; tx[pos++] = 0; tx[pos++] = 0;
        tx[pos++] = 1;
        memcpy(tx + pos, prev_txid, 32); pos += 32;
        tx[pos++] = 0; tx[pos++] = 0; tx[pos++] = 0; tx[pos++] = 0;
        tx[pos++] = 0; /* empty scriptSig */
        tx[pos++] = (uint8_t)(nsequence & 0xFF);
        tx[pos++] = (uint8_t)((nsequence >> 8) & 0xFF);
        tx[pos++] = (uint8_t)((nsequence >> 16) & 0xFF);
        tx[pos++] = (uint8_t)((nsequence >> 24) & 0xFF);
        tx[pos++] = 1;
        amt = 10000;
        for (j = 0; j < 8; j++)
            tx[pos++] = (uint8_t)((amt >> (8 * j)) & 0xFF);
        tx[pos++] = 34;
        memcpy(tx + pos, spk, 34); pos += 34;
        tx[pos++] = (uint8_t)(nlocktime & 0xFF);
        tx[pos++] = (uint8_t)((nlocktime >> 8) & 0xFF);
        tx[pos++] = (uint8_t)((nlocktime >> 16) & 0xFF);
        tx[pos++] = (uint8_t)((nlocktime >> 24) & 0xFF);
        tlen = pos;
    }

    {
        uint64_t amt = 20000;
        int j;
        for (j = 0; j < 8; j++)
            wutxo[j] = (uint8_t)((amt >> (8 * j)) & 0xFF);
        wutxo[8] = 34;
        memcpy(wutxo + 9, spk, 34);
    }

    path_idx[0] = 86u | 0x80000000u;
    path_idx[1] = 1u | 0x80000000u;
    path_idx[2] = 0u | 0x80000000u;
    path_idx[3] = 0;
    path_idx[4] = 0;
    tap_bip32_val[0] = 0;
    memset(tap_bip32_val + 1, 0x95, 4);
    for (i = 0; i < 5; i++) {
        uint32_t v = path_idx[i];
        tap_bip32_val[5 + i * 4 + 0] = (uint8_t)(v & 0xFF);
        tap_bip32_val[5 + i * 4 + 1] = (uint8_t)((v >> 8) & 0xFF);
        tap_bip32_val[5 + i * 4 + 2] = (uint8_t)((v >> 16) & 0xFF);
        tap_bip32_val[5 + i * 4 + 3] = (uint8_t)((v >> 24) & 0xFF);
    }

    pos = 0;
    memcpy(psbt, "psbt\xff", 5); pos = 5;
    key_buf[0] = 0x00;
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 1, tx, tlen);
    if (!pos) return 1;
    psbt[pos++] = 0x00;

    key_buf[0] = 0x01;
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 1, wutxo, 8 + 1 + 34);
    if (!pos) return 1;

    key_buf[0] = 0x17;
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 1, xonly, 32);
    if (!pos) return 1;

    key_buf[0] = 0x18;
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 1, leaf_hash, 32);
    if (!pos) return 1;

    if (kind != KIND_REJECT_NOLEAF) {
        key_buf[0] = 0x15;
        memcpy(key_buf + 1, control, 33);
        pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 34, leaf_val, leaf_len + 1);
        if (!pos) return 1;
    }

    key_buf[0] = 0x16;
    memcpy(key_buf + 1, xonly, 32);
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 33, tap_bip32_val, 1 + 4 + 20);
    if (!pos) return 1;

    psbt[pos++] = 0x00;
    psbt[pos++] = 0x00;

    f = fopen(argv[2], "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fwrite(psbt, 1, pos, f);
    fclose(f);
    fprintf(stderr, "wrote %s (%zu bytes) kind=%s leaf_len=%zu seq=%u lock=%u\n",
            argv[2], pos, kind_name, leaf_len,
            (unsigned)nsequence, (unsigned)nlocktime);
    return 0;
}
