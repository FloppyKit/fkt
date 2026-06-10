/* main.c – FKT signer CLI */
#include "fkt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int hex_decode(const char *hex, uint8_t *out, int max_out) {
    int len = strlen(hex);
    int i;
    if (len % 2 != 0 || len/2 > max_out) return -1;
    for (i = 0; i < len/2; i++) {
        unsigned int byte;
        if (sscanf(&hex[i*2], "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return len/2;
}

int main(int argc, char **argv) {
    int i;
    if (argc == 4 && strcmp(argv[1], "--pubkey") == 0) {
        uint8_t seed[64];
        uint8_t child_priv[32], child_pub33[33];
        if (hex_decode(argv[2], seed, sizeof(seed)) != 64) {
            fprintf(stderr, "Invalid seed hex.\n");
            return 1;
        }
        if (fkt_derive_from_path(seed, argv[3], child_priv, child_pub33) != 0) {
            fprintf(stderr, "Derivation failed.\n");
            return 1;
        }
        for (i = 0; i < 33; i++) printf("%02x", child_pub33[i]);
        printf("\n");
        return 0;
    }

    if (argc != 5) {
        fprintf(stderr, "Usage: %s <seed_hex> <path> <input.psbt> <output.psbt>\n", argv[0]);
        fprintf(stderr, "       %s --pubkey <seed_hex> <path>\n", argv[0]);
        return 1;
    }
    {
        uint8_t seed[64];
        int ret;
        if (hex_decode(argv[1], seed, sizeof(seed)) != 64) {
            fprintf(stderr, "Invalid seed hex.\n");
            return 1;
        }
        fkt_secp256k1_init();
        ret = fkt_sign_psbt(seed, argv[2], argv[3], argv[4]);
        if (ret != 0) {
            fprintf(stderr, "Signing failed.\n");
            return 1;
        }
    }
    return 0;
}