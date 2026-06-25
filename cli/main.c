/* main.c – FKT signer CLI */
#include "fkt.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int psbt_to_base64(const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i += 3) {
        uint32_t n;
        int pad = 0;
        n = ((uint32_t)data[i]) << 16;
        if (i + 1 < len) n |= ((uint32_t)data[i + 1]) << 8;
        else pad = 2;
        if (i + 2 < len) n |= (uint32_t)data[i + 2];
        else if (pad == 0) pad = 1;
        putchar(b64_table[(n >> 18) & 63]);
        putchar(b64_table[(n >> 12) & 63]);
        putchar(pad > 1 ? '=' : b64_table[(n >> 6) & 63]);
        putchar(pad > 0 ? '=' : b64_table[n & 63]);
    }
    putchar('\n');
    return 0;
}

/*
 * Sparrow testnet4 v1 P2WPKH seed (64-byte BIP39 seed, hex):
 *   46b6b71e4a52ba6259aae7a9eaa991aea07fead2850cb9710aea4b234b73dcc
 *   26f21d986924ec4224f0fff3b2c73788de8e1f925451b79fcccbed9951b9b184d
 *
 * Example (path comes from PSBT BIP32 derivation field):
 *   ./fktsigner <seed_hex> m/84'/1'/0'/0/29 unsigned.psbt signed.psbt
 */

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
        if (fkt_derive_from_path(seed, argv[3], child_priv, child_pub33, NULL) != 0) {
            fprintf(stderr, "Derivation failed.\n");
            return 1;
        }
        for (i = 0; i < 33; i++) printf("%02x", child_pub33[i]);
        printf("\n");
        return 0;
    }
    if (argc == 7 && strcmp(argv[1], "--parent-pubkey") == 0) {
        uint8_t seed[64], pub33[33];
        if (hex_decode(argv[2], seed, sizeof(seed)) != 64) {
            fprintf(stderr, "Invalid seed hex.\n");
            return 1;
        }
        if (hex_decode(argv[4], pub33, sizeof(pub33)) != 33) {
            fprintf(stderr, "Invalid pubkey hex.\n");
            return 1;
        }
        fkt_secp256k1_init();
        if (fkt_sign_psbt_with_parent(seed, argv[3], argv[5], argv[6], pub33) != 0) {
            fprintf(stderr, "Signing failed.\n");
            return 1;
        }
        return 0;
    }

    if (argc == 3 && strcmp(argv[1], "--base64") == 0) {
        FILE *f;
        long sz;
        uint8_t *buf;
        f = fopen(argv[2], "rb");
        if (!f) {
            fprintf(stderr, "Cannot open %s\n", argv[2]);
            return 1;
        }
        if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
        sz = ftell(f);
        if (sz < 0 || (size_t)sz > FKT_PSBT_MAX_SIZE) { fclose(f); return 1; }
        rewind(f);
        buf = (uint8_t *)malloc((size_t)sz);
        if (!buf) { fclose(f); return 1; }
        if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
            free(buf);
            fclose(f);
            return 1;
        }
        fclose(f);
        psbt_to_base64(buf, (size_t)sz);
        free(buf);
        return 0;
    }

    if (argc != 5) {
        fprintf(stderr, "Usage: %s <seed_hex> <path> <input.psbt> <output.psbt>\n", argv[0]);
        fprintf(stderr, "       %s --pubkey <seed_hex> <path>\n", argv[0]);
        fprintf(stderr, "       %s --parent-pubkey <seed_hex> <path> <pub33_hex> <in.psbt> <out.psbt>\n", argv[0]);
        fprintf(stderr, "       %s --base64 <signed.psbt>\n", argv[0]);
        return 1;
    }
    {
        uint8_t seed[64];
        if (hex_decode(argv[1], seed, sizeof(seed)) != 64) {
            fprintf(stderr, "Invalid seed hex (need 128 hex chars = 64-byte BIP39 seed).\n");
            return 1;
        }
        fkt_secp256k1_init();
        if (fkt_sign_psbt(seed, argv[2], argv[3], argv[4]) != 0) {
            fprintf(stderr, "Signing failed.\n");
            return 1;
        }
    }
    return 0;
}