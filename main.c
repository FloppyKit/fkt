#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fkt_crypto.h"
#include "fkt_psbt.h"

/* Count inputs in the unsigned tx of a v0 PSBT. Returns -1 on parse failure. */
/* Assumes PSBT_GLOBAL_UNSIGNED_TX (key 0x00) is the first global record, as  */
/* every BIP-174 v0 producer emits.                                           */
static int psbt_count_inputs(const uint8_t *psbt, size_t psbt_len) {
    const uint8_t *p = psbt;
    const uint8_t *end = psbt + psbt_len;
    uint64_t vlen;
    if (psbt_len < 8) return -1;
    if (memcmp(p, "psbt\xff\x01\x00", 7) != 0) return -1;
    p += 7;
    if (p >= end) return -1;
    if (*p < 0xfd) { vlen = *p; p += 1; }
    else if (*p == 0xfd && p + 3 <= end) { vlen = (uint64_t)p[1] | ((uint64_t)p[2] << 8); p += 3; }
    else if (*p == 0xfe && p + 5 <= end) {
        vlen = (uint64_t)p[1] | ((uint64_t)p[2] << 8) |
               ((uint64_t)p[3] << 16) | ((uint64_t)p[4] << 24);
        p += 5;
    } else return -1;
    if (p + vlen > end || vlen < 5) return -1;
    p += 4; /* skip nVersion of unsigned tx */
    if (*p < 0xfd) return (int)*p;
    if (*p == 0xfd && p + 3 <= end) return (int)((uint64_t)p[1] | ((uint64_t)p[2] << 8));
    return -1;
}

int main(int argc, char **argv) {
    const char *seed_phrase = NULL;
    const char *derivation_path = NULL;
    int i;

    if (argc < 4 || strcmp(argv[1], "sign") != 0) {
        fprintf(stderr, "Usage: %s sign <input.psbt> <output.psbt> [seed phrase] [--path <derivation>]\n", argv[0]);
        fprintf(stderr, "Example: %s sign tx.psbt signed.psbt \"seed words\" --path \"m/86'/1'/0'/0/29\"\n", argv[0]);
        return 1;
    }

    init_secp256k1();

    for (i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--path") == 0 && i+1 < argc) {
            derivation_path = argv[++i];
        } else if (!seed_phrase) {
            seed_phrase = argv[i];
        }
    }

    if (!seed_phrase) {
        fprintf(stderr, "Error: seed phrase required\n");
        return 1;
    }

    {
        uint8_t master_priv[32], master_chain[32], bip39_seed[64];

        fkt_pbkdf2_hmac_sha512(seed_phrase, "mnemonic", 2048, bip39_seed, 64);
        fkt_bip32_master_from_seed(bip39_seed, 64, master_chain, master_priv);

        printf("🔑 Using seed phrase: %s\n", seed_phrase);
        if (derivation_path) {
            printf("🔀 Derivation path override: %s\n", derivation_path);
        }

        {
            FILE *f = fopen(argv[2], "rb");
            size_t len;
            uint8_t *psbt;
            if (!f) { perror("Cannot open input PSBT"); return 1; }
            fseek(f, 0, SEEK_END);
            len = ftell(f);
            fseek(f, 0, SEEK_SET);
            psbt = malloc(len);
            if (!psbt) { fprintf(stderr, "Out of memory\n"); fclose(f); return 1; }
            fread(psbt, 1, len, f);
            fclose(f);

            printf("📄 PSBT loaded: %s (%zu bytes)\n", argv[2], len);
            printf("🔍 Parsing and previewing transaction...\n");

            {
                uint8_t *out = NULL;
                size_t out_len = 0;
                int ret = fkt_psbt_sign(psbt, len, master_priv, master_chain,
                                        derivation_path, &out, &out_len);
                int total_inputs = psbt_count_inputs(psbt, len);
                free(psbt);

                if (ret < 0 || !out) {
                    fprintf(stderr, "Signing failed (error code %d)\n", ret);
                    return 1;
                }

                {
                    FILE *fo = fopen(argv[3], "wb");
                    if (!fo) { perror("Cannot create output"); free(out); return 1; }
                    fwrite(out, 1, out_len, fo);
                    fclose(fo);
                    free(out);
                }

                if (total_inputs > 0) {
                    printf("\nSigned %d of %d inputs.\n", ret, total_inputs);
                } else {
                    printf("\nSigned %d inputs.\n", ret);
                }
                printf(" Output PSBT: %s (%zu bytes)\n", argv[3], out_len);
                if (ret == 0) {
                    fprintf(stderr, "Warning: no inputs were signed; output equals input.\n");
                    return 2;
                }
            }
        }
    }

    return 0;
}