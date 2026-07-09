/*
 * gen_scriptpath_vector.c — build a synthetic single-leaf script-path PSBT.
 *
 * Leaf: <xonly_pk> OP_CHECKSIG
 * Internal key = leaf key (single-leaf tree)
 * Path: m/86'/1'/0'/0/0 from test seed (call release...)
 *
 * Usage: ./gen_scriptpath_vector <seed_hex128> <out.psbt>
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

int main(int argc, char **argv) {
    uint8_t seed[64];
    uint8_t child_priv[32], child_pub33[33], xonly[32];
    uint8_t leaf_script[34];
    uint8_t leaf_hash[32];
    uint8_t tweak_in[64], tweak[32];
    uint8_t control[33];
    uint8_t leaf_val[35];
    uint8_t spk[34];
    uint8_t tx[128];
    uint8_t wutxo[8 + 1 + 34];
    uint8_t psbt[1024];
    size_t pos, tlen;
    uint8_t key_buf[40];
    uint8_t tap_bip32_val[1 + 4 + 5 * 4];
    FILE *f;
    secp256k1_context *ctx;
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey xpub;
    int pk_parity;
    const char *path = "m/86'/1'/0'/0/0";
    uint32_t path_idx[5];
    int i;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <seed_hex128> <out.psbt>\n", argv[0]);
        return 1;
    }
    if (hex_decode(argv[1], seed, 64) != 64) {
        fprintf(stderr, "bad seed hex\n");
        return 1;
    }

    fkt_secp256k1_init();
    ctx = fkt_secp256k1_ctx();

    if (fkt_derive_from_path(seed, path, child_priv, child_pub33, NULL) != 0) {
        fprintf(stderr, "derive failed\n");
        return 1;
    }
    /* x-only from compressed pubkey (drop prefix) */
    memcpy(xonly, child_pub33 + 1, 32);

    /* leaf script: OP_PUSH32 xonly OP_CHECKSIG */
    leaf_script[0] = 0x20;
    memcpy(leaf_script + 1, xonly, 32);
    leaf_script[33] = 0xac;

    if (fkt_tapleaf_hash(0xc0, leaf_script, 34, leaf_hash) != 0) {
        fprintf(stderr, "tapleaf hash failed\n");
        return 1;
    }

    /* single-leaf: merkle_root = tapleaf_hash; tweak internal||merkle */
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

    /* control block: (leaf_version | parity) || internal_key */
    control[0] = (uint8_t)(0xc0 | (pk_parity ? 1 : 0));
    memcpy(control + 1, xonly, 32);

    /* leaf value: script || leaf_version */
    memcpy(leaf_val, leaf_script, 34);
    leaf_val[34] = 0xc0;

    /* fake prevout + unsigned tx: version=2, 1 in, 1 out, lock=0 */
    {
        uint8_t prev_txid[32];
        uint64_t amt;
        int j;
        memset(prev_txid, 0x11, 32);
        pos = 0;
        tx[pos++] = 2; tx[pos++] = 0; tx[pos++] = 0; tx[pos++] = 0; /* version */
        tx[pos++] = 1; /* nIn */
        memcpy(tx + pos, prev_txid, 32); pos += 32;
        tx[pos++] = 0; tx[pos++] = 0; tx[pos++] = 0; tx[pos++] = 0; /* vout */
        tx[pos++] = 0; /* empty scriptSig compact size */
        /* sequence 0xfffffffd */
        tx[pos++] = 0xfd; tx[pos++] = 0xff; tx[pos++] = 0xff; tx[pos++] = 0xff;
        tx[pos++] = 1; /* nOut */
        amt = 10000;
        for (j = 0; j < 8; j++)
            tx[pos++] = (uint8_t)((amt >> (8 * j)) & 0xFF);
        tx[pos++] = 34;
        memcpy(tx + pos, spk, 34); pos += 34;
        tx[pos++] = 0; tx[pos++] = 0; tx[pos++] = 0; tx[pos++] = 0; /* locktime */
        tlen = pos;
    }

    /* witness utxo value */
    {
        uint64_t amt = 20000;
        int j;
        for (j = 0; j < 8; j++)
            wutxo[j] = (uint8_t)((amt >> (8 * j)) & 0xFF);
        wutxo[8] = 34;
        memcpy(wutxo + 9, spk, 34);
    }

    /* tap bip32 value: n_hashes=0, fingerprint dummy, path indices */
    path_idx[0] = 86u | 0x80000000u;
    path_idx[1] = 1u | 0x80000000u;
    path_idx[2] = 0u | 0x80000000u;
    path_idx[3] = 0;
    path_idx[4] = 0;
    tap_bip32_val[0] = 0; /* no leaf hashes in value for this path binding style */
    memset(tap_bip32_val + 1, 0x95, 4); /* fake fp */
    for (i = 0; i < 5; i++) {
        uint32_t v = path_idx[i];
        tap_bip32_val[5 + i * 4 + 0] = (uint8_t)(v & 0xFF);
        tap_bip32_val[5 + i * 4 + 1] = (uint8_t)((v >> 8) & 0xFF);
        tap_bip32_val[5 + i * 4 + 2] = (uint8_t)((v >> 16) & 0xFF);
        tap_bip32_val[5 + i * 4 + 3] = (uint8_t)((v >> 24) & 0xFF);
    }

    /* Build PSBT */
    pos = 0;
    memcpy(psbt, "psbt\xff", 5); pos = 5;
    /* global unsigned tx */
    key_buf[0] = 0x00;
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 1, tx, tlen);
    if (!pos) return 1;
    psbt[pos++] = 0x00; /* end global */

    /* input map */
    key_buf[0] = 0x01; /* WITNESS_UTXO */
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 1, wutxo, 8 + 1 + 34);
    if (!pos) return 1;

    key_buf[0] = 0x17; /* TAP_INTERNAL_KEY */
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 1, xonly, 32);
    if (!pos) return 1;

    key_buf[0] = 0x18; /* TAP_MERKLE_ROOT */
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 1, leaf_hash, 32);
    if (!pos) return 1;

    /* TAP_LEAF_SCRIPT: key = 0x15 || control */
    key_buf[0] = 0x15;
    memcpy(key_buf + 1, control, 33);
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 34, leaf_val, 35);
    if (!pos) return 1;

    /* TAP_BIP32_DERIVATION: key = 0x16 || xonly */
    key_buf[0] = 0x16;
    memcpy(key_buf + 1, xonly, 32);
    pos = append_kv(psbt, pos, sizeof(psbt), key_buf, 33, tap_bip32_val, 1 + 4 + 20);
    if (!pos) return 1;

    psbt[pos++] = 0x00; /* end input */
    psbt[pos++] = 0x00; /* empty output map */

    f = fopen(argv[2], "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fwrite(psbt, 1, pos, f);
    fclose(f);
    fprintf(stderr, "wrote %s (%zu bytes) script-path synthetic\n", argv[2], pos);
    return 0;
}
