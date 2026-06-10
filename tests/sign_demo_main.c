#include <stdio.h>
#include <string.h>
#include "../cli/fkt_psbt.h"

int fkt_test_sha512_abc(void);
int fkt_test_ripemd_empty(void);
int fkt_test_hmac512(void);
int fkt_test_child_derive(void);
int fkt_test_pubkey(void);
int fkt_test_bip32(void);

static uint8_t hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <psbt_in> <seed_hex> <path>\n", argv[0]);
        printf("  path e.g. m/84'/1'/0'/0/0\n");
        return 1;
    }
    const char *psbt_in = argv[1];
    const char *seed_hex = argv[2];
    const char *path_str = argv[3];

    uint8_t seed[64];
    size_t hexlen = strlen(seed_hex);
    if (hexlen != 128) { printf("Seed must be 128 hex chars (64 bytes)\n"); return 1; }
    size_t i;
    for (i = 0; i < 64; i++)
        seed[i] = (hexval(seed_hex[i*2]) << 4) | hexval(seed_hex[i*2 + 1]);

    uint32_t path[5];
    int parts = sscanf(path_str, "m/%u'/%u'/%u'/%u/%u", &path[0], &path[1], &path[2], &path[3], &path[4]);
    if (parts != 5) { printf("Invalid path format\n"); return 1; }
    path[0] |= 0x80000000;
    path[1] |= 0x80000000;
    path[2] |= 0x80000000;

    /* Self‑test sequence */
   
    if (fkt_test_sha512_abc() != 0) { printf("SHA‑512 self‑test FAILED\n"); return 1; }
    else                              printf("SHA‑512 self‑test PASSED\n");

    if (fkt_test_hmac512() != 0) { printf("HMAC-SHA512 self‑test FAILED\n"); return 1; }
    else                           printf("HMAC-SHA512 self‑test PASSED\n");

    if (fkt_test_child_derive() != 0) { printf("Child derivation self‑test FAILED\n"); return 1; }
    else                                printf("Child derivation self‑test PASSED\n");

    if (fkt_test_pubkey() != 0) { printf("Public‑key self‑test FAILED\n"); return 1; }
    else                          printf("Public‑key self‑test PASSED\n");

    if (fkt_test_bip32() != 0) { printf("BIP32 self‑test FAILED\n"); return 1; }
    else                         printf("BIP32 self‑test PASSED\n");

    /* Sign */
    const char *outfile = "signed.psbt";
    if (fkt_sign_psbt(seed, path, psbt_in, outfile) == 0)
        printf("Signed PSBT written to %s\n", outfile);
    else
        printf("Signing failed.\n");

    return 0;
}