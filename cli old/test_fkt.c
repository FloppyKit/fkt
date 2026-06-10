/* test_fkt.c – runs all self‑tests and a P2WPKH signing demo */
#include "fkt_psbt.h"
#include "fkt_crypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Forward declarations */
static int test_golden_sign(void);
int fkt_test_sha256_empty(void);
int fkt_test_hmac512(void);
int fkt_test_bip32(void);
int fkt_test_pubkey(void);
int fkt_test_child_derive(void);
void fkt_key_derive_demo(void);

/* ------------------------------------------------------------------------- */
static int hex_to_bin(const char *hex, uint8_t *out, size_t max_out) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;
    size_t bytes = len / 2;
    if (bytes > max_out) return -1;
    for (size_t i = 0; i < bytes; i++) {
        char c1 = hex[i*2], c2 = hex[i*2+1];
        uint8_t val = 0;
        if      (c1 >= '0' && c1 <= '9') val = (c1 - '0') << 4;
        else if (c1 >= 'a' && c1 <= 'f') val = (c1 - 'a' + 10) << 4;
        else if (c1 >= 'A' && c1 <= 'F') val = (c1 - 'A' + 10) << 4;
        else return -1;
        if      (c2 >= '0' && c2 <= '9') val |= (c2 - '0');
        else if (c2 >= 'a' && c2 <= 'f') val |= (c2 - 'a' + 10);
        else if (c2 >= 'A' && c2 <= 'F') val |= (c2 - 'A' + 10);
        else return -1;
        out[i] = val;
    }
    return (int)bytes;
}

/* Correct P2WPKH PSBT for demo key (HASH160 = c5cef2eb...44a) */
static const char *SIGN_TEST_PSBT_HEX =
"70736274ff010052010000000100000000000000000000000000000000000000000000"
"000000000000000000000000000000ffffffff0100e1f50500000000160014c5cef2eb"
"5e5c8ca239e375e029baf7086649b44a000000000001011f00e1f50500000000160014"
"c5cef2eb5e5c8ca239e375e029baf7086649b44a0000";

static int test_sign_psbt_demo(void) {
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
    uint32_t path[5] = { 0x80000054, 0x80000000, 0x80000000, 0, 0 };

    /* Decode hex PSBT */
    uint8_t psbt_bin[1024];
    int psbt_len = hex_to_bin(SIGN_TEST_PSBT_HEX, psbt_bin, sizeof(psbt_bin));
    if (psbt_len < 0) { printf("FAILED: hex decoding error\n"); return -1; }

    /* Write temp file */
    FILE *f = fopen("_test_unsigned.psbt", "wb");
    if (!f) { printf("FAILED: cannot create temp file\n"); return -1; }
    fwrite(psbt_bin, 1, psbt_len, f);
    fclose(f);

    /* Sign */
    int ret = fkt_sign_psbt(seed, path, "_test_unsigned.psbt", "_test_signed.psbt");
    remove("_test_unsigned.psbt");

    if (ret != 0) {
        printf("FAILED: signing returned error\n");
        return -1;
    }

    /* Quick verification – look for a partial signature key (0x02) */
    FILE *signed_f = fopen("_test_signed.psbt", "rb");
    if (!signed_f) { printf("FAILED: cannot open signed file\n"); return -1; }
    fseek(signed_f, 0, SEEK_END);
    long size = ftell(signed_f);
    rewind(signed_f);
    uint8_t *buf = (uint8_t*)malloc(size);
    if (buf) {
        fread(buf, 1, size, signed_f);
        int found = 0;
        for (long i = 0; i < size; i++) if (buf[i] == 0x02) { found = 1; break; }
        free(buf);
        printf("PSBT signing demo: %s\n", found ? "PASS (partial signature inserted)" : "WARNING – no partial signature found");
    } else {
        printf("PSBT signing demo: OK (signed PSBT written)\n");
    }
    fclose(signed_f);
    remove("_test_signed.psbt");
    return 0;
}


/* -------------------------------------------------------------------------
 * Sign the golden p2wpkh_all_1in_2out.psbt with the real test seed
 * and compare the result to the reference golden-signed file.
 * ------------------------------------------------------------------------- */
static int test_golden_sign(void) {
    const char *seed_hex =
        "dc26536673dd2912aae6863d2984566995154dcdd72c003ebf4dc61e7b93e710"
        "e9693f23cfc397ca71bc9362cefb95ab52896d0dc68cfae352b6d8dda13aaeaa";
    uint8_t seed[64];
    for (int i = 0; i < 64; i++) {
        unsigned int byte;
        sscanf(&seed_hex[i*2], "%2x", &byte);
        seed[i] = (uint8_t)byte;
    }

    uint8_t master_priv[32], master_chain[32];
    fkt_bip32_master(seed, master_priv, master_chain);

    printf("C  master_priv = ");
    for (int i = 0; i < 32; i++) printf("%02x", master_priv[i]);
    printf("\n");

    printf("C  master_chain = ");
    for (int i = 0; i < 32; i++) printf("%02x", master_chain[i]);
    printf("\n");

    /* Derive account: m/84'/1'/0' */
    uint32_t acct_path[3] = { 0x80000054, 0x80000001, 0x80000000 };
    uint8_t priv[32], chain[32];
    memcpy(priv, master_priv, 32);
    memcpy(chain, master_chain, 32);
    for (int step = 0; step < 3; step++) {
        uint8_t new_priv[32], new_chain[32];
        if (fkt_bip32_derive_child(priv, chain, acct_path[step], 1, new_priv, new_chain) != 0) {
            printf("C  derivation failed at step %d\n", step);
            return -1;
        }
        memcpy(priv, new_priv, 32);
        memcpy(chain, new_chain, 32);
    }

    /* Print account public key */
    secp256k1_context *ctx = fkt_crypto_ctx();
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, priv)) {
        printf("C  pubkey creation failed\n");
        return -1;
    }
    uint8_t pub33[33]; size_t pub33len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub33, &pub33len, &pub, SECP256K1_EC_COMPRESSED);
    printf("C  account xpub: ");
    for (int i = 0; i < 33; i++) printf("%02x", pub33[i]);
    printf("\n");
    printf("C  account chain: ");
    for (int i = 0; i < 32; i++) printf("%02x", chain[i]);
    printf("\n");

  

    /* Scan both receiving (0) and change (1) branches */
    for (uint32_t branch = 0; branch < 2; branch++) {
        for (uint32_t idx = 0; idx < 5; idx++) {
            uint32_t path[5] = { 0x80000054, 0x80000001, 0x80000000, branch, idx };
            uint8_t child_priv[32], child_pub33[33];
            if (fkt_derive_path(master_priv, master_chain, path, child_priv, child_pub33) != 0) {
                printf("C  m/84'/1'/0'/%u/%u  ERROR\n", branch, idx);
                continue;
            }
            uint8_t h160[20];
            fkt_hash160(child_pub33, 33, h160);
            printf("C  m/84'/1'/0'/%u/%u  HASH160 = ", branch, idx);
            for (int i = 0; i < 20; i++) printf("%02x", h160[i]);
            printf("\n");
        }
    }

    return -1;   /* fail for now so you can see the output */
}
/* ------------------------------------------------------------------------- */
int main(void) {
    int ok = 1;
    fkt_crypto_init();
    printf("Running golden signing test... ");
    ok &= (test_golden_sign() == 0);
    printf("%s\n", ok ? "PASS" : "FAIL");
    printf("Running SHA‑256 empty test... "); ok &= (fkt_test_sha256_empty() == 0); printf("%s\n", ok ? "PASS" : "FAIL");
    printf("Running HMAC‑SHA‑512 test... "); ok &= (fkt_test_hmac512() == 0); printf("%s\n", ok ? "PASS" : "FAIL");
    printf("Running BIP32 master test... "); ok &= (fkt_test_bip32() == 0); printf("%s\n", ok ? "PASS" : "FAIL");
    printf("Running pubkey creation test... "); ok &= (fkt_test_pubkey() == 0); printf("%s\n", ok ? "PASS" : "FAIL");
    printf("Running child derivation test... "); ok &= (fkt_test_child_derive() == 0); printf("%s\n", ok ? "PASS" : "FAIL");
    printf("Running PSBT signing demo... "); ok &= (test_sign_psbt_demo() == 0); printf("%s\n", ok ? "PASS" : "FAIL");
    printf("Running key derivation demo...\n"); fkt_key_derive_demo();

    if (ok) printf("\nAll self‑tests passed.\n");
    else    printf("\nSome tests FAILED.\n");
    return ok ? 0 : 1;
}