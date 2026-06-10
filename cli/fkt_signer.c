#include "fkt_signer.h"
#include "fkt_psbt.h"
#include "fkt_sighash.h"
#include "fkt_hash160.h"
#include "fkt_bip32.h"
#include "fkt_secp256k1.h"
#include "fkt_compat.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


/* #### SECTION: Insert key/value into PSBT (unchanged) #### */
static int fkt_insert_input_key(int input_index, uint8_t key_type,
                                const uint8_t *value, size_t value_len) {
    size_t sep_off, total_shift, old_size, new_size;
    uint8_t key_len_vi[9], val_len_vi[9];
    size_t key_len_vi_size, val_len_vi_size;
    size_t entry_size;
    uint8_t *buf = psbt_buffer;

    if (input_index < 0 || input_index >= input_separator_count) return -1;
    sep_off = input_separator_offsets[input_index];

    key_len_vi[0] = 1; key_len_vi_size = 1;
    {
        uint64_t vlen = value_len;
        if (vlen < 0xFD) {
            val_len_vi[0] = (uint8_t)vlen; val_len_vi_size = 1;
        } else if (vlen <= 0xFFFF) {
            val_len_vi[0] = 0xFD;
            val_len_vi[1] = (uint8_t)(vlen & 0xFF);
            val_len_vi[2] = (uint8_t)((vlen >> 8) & 0xFF);
            val_len_vi_size = 3;
        } else {
            return -1;
        }
    }


   

    entry_size = key_len_vi_size + 1 + val_len_vi_size + value_len;
    total_shift = entry_size;
    old_size = psbt_size;
    new_size = old_size + total_shift;
    if (new_size > FKT_PSBT_MAX_SIZE) return -1;

    {
        size_t i;
        for (i = old_size; i > sep_off; i--)
            buf[i + total_shift - 1] = buf[i - 1];
    }

    {
        uint8_t *p = buf + sep_off;
        memcpy(p, key_len_vi, key_len_vi_size); p += key_len_vi_size;
        *p++ = key_type;
        memcpy(p, val_len_vi, val_len_vi_size); p += val_len_vi_size;
        memcpy(p, value, value_len);
    }

    psbt_size = new_size;
    return 0;
}

/* #### SECTION: Full P2WPKH signing (uses crypto module for derivation, hashing, zeroing) #### */
int fkt_sign_psbt(const uint8_t seed[64], const char *path_str,
                  const char *psbt_file, const char *output_file) {
    int i;
    uint8_t child_priv[32], child_pub33[33];
    uint8_t hash20[20];
    FILE *fout = NULL;
    int ok = -1;
    int signed_any = 0;
    secp256k1_context *ctx = fkt_secp256k1_ctx();

    /* 1. Parse PSBT */
    fkt_psbt_init();
    if (fkt_psbt_load_file(psbt_file) != 0) { printf("Failed to load PSBT.\n"); goto cleanup; }
    fkt_psbt_parse();
    fkt_compute_hash_caches();

    /* 2. Derive keys using the unified derivation function */
    if (fkt_derive_from_path(seed, path_str, child_priv, child_pub33) != 0) {
        printf("Key derivation failed.\n");
        goto cleanup;
    }

    /* 3. HASH160 of child public key */
    fkt_hash160(child_pub33, 33, hash20);

    /* 4. Process each input */
    for (i = 0; i < psbt_data.num_inputs; i++) {
          /* ---- Taproot (P2TR) key-path signing ---- */
        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2TR) {

            uint8_t sighash[32];
            if (fkt_bip341_sighash(i, sighash) != 0) {
                printf("Sighash error for input %d (Taproot)\n", i);
                goto cleanup;
            }
            uint8_t sig[64];
            int sig_len;
            if (fkt_schnorr_sign(child_priv, sighash, sig, &sig_len) != 0) {
                printf("Schnorr signing failed for input %d\n", i);
                goto cleanup;
            }
            if (fkt_insert_input_key(i, 0x13, sig, sig_len) != 0) {
                printf("PSBT buffer overflow inserting Schnorr signature for input %d\n", i);
                goto cleanup;
            }
            signed_any = 1;
            continue;
        }
        /* ---- P2SH‑P2WPKH signing ---- */
        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2SH_P2WPKH) {
            if (!psbt_data.input_has_redeem_script[i]) {
                printf("P2SH‑P2WPKH input %d missing redeem script\n", i);
                goto cleanup;
            }
            uint8_t sighash[32];
            if (fkt_bip143_sighash_p2sh_p2wpkh(i, psbt_data.input_redeem_script[i], sighash) != 0) {
                printf("Sighash error for input %d (P2SH‑P2WPKH)\n", i);
                goto cleanup;
            }
            secp256k1_ecdsa_signature sig;
            if (!secp256k1_ecdsa_sign(ctx, &sig, sighash, child_priv, NULL, NULL)) {
                printf("Signing failed for input %d (P2SH‑P2WPKH)\n", i);
                goto cleanup;
            }
            uint8_t der_sig[74];
            size_t sig_len = sizeof(der_sig);
            if (!secp256k1_ecdsa_signature_serialize_der(ctx, der_sig, &sig_len, &sig)) {
                printf("DER serialisation failed for input %d\n", i);
                goto cleanup;
            }
            if (fkt_insert_input_key(i, 0x02, der_sig, sig_len) != 0) {
                printf("PSBT buffer overflow inserting signature for input %d\n", i);
                goto cleanup;
            }
            signed_any = 1;
            continue;
        }

        /* ---- P2WPKH signing ---- */
        if (psbt_data.input_script_type[i] != SCRIPT_TYPE_P2WPKH) continue;
        if (!psbt_data.input_has_witness_script[i]) continue;

        { int k;
        printf("DEBUG: derived hash20 = ");
        for (k = 0; k < 20; k++) printf("%02x", hash20[k]);
        printf("\nDEBUG: PSBT witness hash = ");
        for (k = 0; k < 20; k++) printf("%02x", psbt_data.input_witness_script[i][2+k]);
        printf("\n");
        }

        if (memcmp(hash20, psbt_data.input_witness_script[i] + 2, 20) != 0) {
            printf("Public key mismatch for input %d\n", i);
            goto cleanup;
        }

        {
            uint8_t sighash[32];
            if (fkt_bip143_sighash(i, psbt_data.input_witness_script[i], sighash) != 0) {
                printf("Sighash error for input %d\n", i);
                goto cleanup;
            }
            secp256k1_ecdsa_signature sig;
            if (!secp256k1_ecdsa_sign(ctx, &sig, sighash, child_priv, NULL, NULL)) {
                printf("Signing failed for input %d\n", i);
                goto cleanup;
            }
            uint8_t der_sig[74];
            size_t sig_len = sizeof(der_sig);
            if (!secp256k1_ecdsa_signature_serialize_der(ctx, der_sig, &sig_len, &sig)) {
                printf("DER serialisation failed for input %d\n", i);
                goto cleanup;
            }
            if (fkt_insert_input_key(i, 0x02, der_sig, sig_len) != 0) {
                printf("PSBT buffer overflow inserting signature for input %d\n", i);
                goto cleanup;
            }
            signed_any = 1;
        }
    }

    if (!signed_any) {
        printf("No inputs could be signed.\n");
        goto cleanup;
    }

    /* 5. Write signed PSBT */
    fout = fopen(output_file, "wb");
    if (!fout) { printf("Cannot open output file.\n"); goto cleanup; }
    fwrite(psbt_buffer, 1, psbt_size, fout);
    fclose(fout);
    fout = NULL;
    ok = 0;

cleanup:
    fkt_zerobytes(child_priv, 32);
    fkt_zerobytes(hash20, 20);
    if (fout) fclose(fout);
    return ok;
}