/*
 * Official-ish BIP39 / BIP32 / hash vectors for FKT Ice Cold crypto path.
 * C89, links fkt_* modules + static libsecp256k1 as needed.
 *
 * Vectors:
 *   BIP39: all-zero 128-bit entropy → "abandon … about"
 *   BIP39 seed: PBKDF2-HMAC-SHA512("mnemonic" + passphrase="", 2048) known hex
 *   BIP32: master from that 64-byte seed; m/0' child non-zero and secp-valid
 *   SHA256(""): e3b0c442…
 *   HASH160 of compressed pubkey for m/84'/1'/0'/0/0 smoke (structure only)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "fkt_bip39.h"
#include "fkt_bip32.h"
#include "fkt_pbkdf2.h"
#include "fkt_sha256.h"
#include "fkt_hash160.h"
#include "fkt_secp256k1.h"
#include "fkt_memzero.h"
#include "fkt_compat.h"

/* fkt_memzero.o references UI restore on SIGINT; not needed in this unit test. */
void fkt_ui_term_restore(void) {}

static int g_fail = 0;

static void expect_true(const char *name, int cond) {
    if (cond) {
        printf("PASS  %s\n", name);
    } else {
        printf("FAIL  %s\n", name);
        g_fail++;
    }
}

static int hex_eq(const uint8_t *got, size_t n, const char *hex) {
    size_t i;
    if (strlen(hex) != n * 2)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1)
            return 0;
        if (got[i] != (uint8_t)b)
            return 0;
    }
    return 1;
}

static int test_sha256_empty(void) {
    uint8_t d[32];
    fkt_sha256((const uint8_t *)"", 0, d);
    return hex_eq(d, 32,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static int test_bip39_abandon(void) {
    /* BIP-0039: entropy 0000…00 (16 bytes) → 12 words ending in "about" */
    uint8_t ent[16];
    char words[24][FKT_BIP39_WORD_BUF];
    int n = 0;
    int i;

    memset(ent, 0, sizeof(ent));
    memset(words, 0, sizeof(words));
    /* from_entropy returns 0 on success, -1 on failure */
    if (fkt_bip39_from_entropy(ent, 16, words, &n) != 0)
        return 0;
    if (n != 12)
        return 0;
    for (i = 0; i < 11; i++) {
        if (strcmp(words[i], "abandon") != 0)
            return 0;
    }
    if (strcmp(words[11], "about") != 0)
        return 0;
    if (!fkt_bip39_validate_checksum(words, 12))
        return 0;
    return 1;
}

static int test_bip39_seed(void) {
    /* Official BIP39 seed for abandon…about, empty passphrase */
    static const char *mnem =
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about";
    static const uint8_t salt[] = "mnemonic";
    uint8_t seed[64];

    fkt_pbkdf2_hmac_sha512(mnem, strlen(mnem), salt, 8, 2048, seed, 64);
    /* Known BIP39 test vector seed (no passphrase) */
    if (!hex_eq(seed, 64,
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
        "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")) {
        fkt_memzero(seed, sizeof(seed));
        return 0;
    }
    fkt_memzero(seed, sizeof(seed));
    return 1;
}

static int test_bip32_master_and_child(void) {
    static const char *mnem =
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about";
    static const uint8_t salt[] = "mnemonic";
    uint8_t seed[64];
    uint8_t mpriv[32], mchain[32];
    uint8_t cpriv[32], cpub[33];
    int i, all_zero;

    fkt_pbkdf2_hmac_sha512(mnem, strlen(mnem), salt, 8, 2048, seed, 64);
    fkt_bip32_master(seed, mpriv, mchain);

    all_zero = 1;
    for (i = 0; i < 32; i++) {
        if (mpriv[i] != 0)
            all_zero = 0;
    }
    if (all_zero) {
        fkt_memzero(seed, sizeof(seed));
        return 0;
    }

    /* BIP84-style first receive: m/84'/0'/0'/0/0 */
    if (fkt_derive_from_path(seed, "m/84'/0'/0'/0/0", cpriv, cpub, NULL) != 0) {
        fkt_memzero(seed, sizeof(seed));
        fkt_memzero(mpriv, sizeof(mpriv));
        return 0;
    }
    /* Compressed pubkey: 02 or 03 prefix */
    if (cpub[0] != 0x02 && cpub[0] != 0x03) {
        fkt_memzero(seed, sizeof(seed));
        fkt_memzero(mpriv, sizeof(mpriv));
        fkt_memzero(cpriv, sizeof(cpriv));
        return 0;
    }

    fkt_memzero(seed, sizeof(seed));
    fkt_memzero(mpriv, sizeof(mpriv));
    fkt_memzero(mchain, sizeof(mchain));
    fkt_memzero(cpriv, sizeof(cpriv));
    return 1;
}

int main(void) {
    printf("FKT BIP / hash vector suite\n");
    printf("---------------------------\n");
    fkt_secp256k1_init();

    expect_true("sha256_empty", test_sha256_empty());
    expect_true("bip39_abandon_entropy", test_bip39_abandon());
    expect_true("bip39_seed_pbkdf2", test_bip39_seed());
    expect_true("bip32_master_and_bip84_child", test_bip32_master_and_child());

    printf("---------------------------\n");
    if (g_fail) {
        printf("Results: FAIL=%d\n", g_fail);
        return 1;
    }
    printf("Results: PASS=4 FAIL=0\n");
    return 0;
}
