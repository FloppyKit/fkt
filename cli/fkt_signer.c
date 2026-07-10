#include "fkt_signer.h"
#include "fkt_confirm.h"
#include "fkt_error.h"
#include "fkt_psbt.h"
#include "fkt_sighash.h"
#include "fkt_hash160.h"
#include "fkt_bip32.h"
#include "fkt_secp256k1.h"
#include "fkt_finalizer.h"
#include "fkt_memzero.h"
#include "fkt_compat.h"
#include "fkt_platform.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Uncomment to enable signer debug prints */
/* #define DEBUG_SIGNER 1 */

#ifdef DEBUG_SIGNER
static void fkt_debug_hex(const char *label, const uint8_t *buf, size_t len) {
    size_t i;
    printf("[DEBUG_SIGNER] %s:", label);
    for (i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static void fkt_debug_master_fp(const uint8_t seed[64]) {
    uint8_t master_priv[32], master_chain[32], master_pub[33];
    uint8_t hash20[20];
    secp256k1_context *ctx = fkt_secp256k1_ctx();
    secp256k1_pubkey pubkey;
    size_t pub_len = 33;

    fkt_bip32_master(seed, master_priv, master_chain);
    if (secp256k1_ec_pubkey_create(ctx, &pubkey, master_priv)) {
        secp256k1_ec_pubkey_serialize(ctx, master_pub, &pub_len, &pubkey,
                                      SECP256K1_EC_COMPRESSED);
        fkt_hash160(master_pub, 33, hash20);
        fkt_debug_hex("master fingerprint", hash20, 4);
    }
    fkt_memzero(master_priv, 32);
    fkt_memzero(master_chain, 32);
}
#else
#define fkt_debug_hex(label, buf, len) ((void)0)
#define fkt_debug_master_fp(seed) ((void)0)
#endif

int fkt_signer_signed_inputs[FKT_MAX_PSBT_INPUTS];

void fkt_signer_clear_signed_inputs(void) {
    int i;
    for (i = 0; i < FKT_MAX_PSBT_INPUTS; i++)
        fkt_signer_signed_inputs[i] = 0;
}

static void fkt_shift_output_offsets(size_t from, long delta) {
    int j;
    if (delta == 0) return;
    for (j = 0; j < output_separator_count; j++) {
        if (output_map_start_offsets[j] >= from) {
            output_map_start_offsets[j] = (size_t)((long)output_map_start_offsets[j] + delta);
            output_separator_offsets[j] = (size_t)((long)output_separator_offsets[j] + delta);
        }
    }
}

static size_t fkt_write_compact_size(uint8_t *out, uint64_t val) {
    if (val < 0xFD) {
        out[0] = (uint8_t)val;
        return 1;
    }
    if (val <= 0xFFFF) {
        out[0] = 0xFD;
        out[1] = (uint8_t)(val & 0xFF);
        out[2] = (uint8_t)((val >> 8) & 0xFF);
        return 3;
    }
    return 0;
}

static int fkt_insert_input_key(int input_index, uint8_t key_type,
                                const uint8_t *key_extra, size_t key_extra_len,
                                const uint8_t *value, size_t value_len) {
    size_t sep_off, total_shift, old_size, new_size;
    uint8_t key_len_vi[9], val_len_vi[9];
    size_t key_len_vi_size, val_len_vi_size;
    size_t key_body_len, entry_size;
    uint8_t *buf = psbt_buffer;
    int j;

    if (input_index < 0 || input_index >= input_separator_count) return -1;
    sep_off = input_separator_offsets[input_index];

    key_body_len = 1 + key_extra_len;
    key_len_vi_size = fkt_write_compact_size(key_len_vi, (uint64_t)key_body_len);
    if (key_len_vi_size == 0) return -1;

    val_len_vi_size = fkt_write_compact_size(val_len_vi, (uint64_t)value_len);
    if (val_len_vi_size == 0) return -1;

    entry_size = key_len_vi_size + key_body_len + val_len_vi_size + value_len;
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
        if (key_extra_len > 0) {
            memcpy(p, key_extra, key_extra_len);
            p += key_extra_len;
        }
        memcpy(p, val_len_vi, val_len_vi_size); p += val_len_vi_size;
        memcpy(p, value, value_len);
    }

    psbt_size = new_size;
    input_separator_offsets[input_index] += total_shift;
    for (j = input_index + 1; j < input_separator_count; j++) {
        input_separator_offsets[j] += total_shift;
        input_map_start_offsets[j] += total_shift;
    }
    fkt_shift_output_offsets(sep_off, (long)total_shift);
    return 0;
}

static int fkt_read_varint_at(const uint8_t *buf, size_t buf_len, size_t pos,
                              uint64_t *val_out, size_t *next_pos) {
    uint8_t first;
    if (pos >= buf_len) return -1;
    first = buf[pos];
    if (first < 0xFD) {
        *val_out = first;
        *next_pos = pos + 1;
        return 0;
    }
    if (first == 0xFD) {
        if (pos + 3 > buf_len) return -1;
        *val_out = (uint64_t)buf[pos + 1] | ((uint64_t)buf[pos + 2] << 8);
        *next_pos = pos + 3;
        return 0;
    }
    if (first == 0xFE) {
        if (pos + 5 > buf_len) return -1;
        *val_out = (uint64_t)buf[pos + 1] | ((uint64_t)buf[pos + 2] << 8) |
                   ((uint64_t)buf[pos + 3] << 16) | ((uint64_t)buf[pos + 4] << 24);
        *next_pos = pos + 5;
        return 0;
    }
    if (pos + 9 > buf_len) return -1;
    *val_out = (uint64_t)buf[pos + 1] | ((uint64_t)buf[pos + 2] << 8) |
               ((uint64_t)buf[pos + 3] << 16) | ((uint64_t)buf[pos + 4] << 24) |
               ((uint64_t)buf[pos + 5] << 32) | ((uint64_t)buf[pos + 6] << 40) |
               ((uint64_t)buf[pos + 7] << 48) | ((uint64_t)buf[pos + 8] << 56);
    *next_pos = pos + 9;
    return 0;
}

static int fkt_remove_output_key_type(int output_index, uint8_t key_type) {
    size_t start, end, pos, remove_off, remove_len;
    uint64_t key_len, val_len;
    size_t next_pos;
    int j;

    if (output_index < 0 || output_index >= output_separator_count) return -1;
    start = output_map_start_offsets[output_index];
    end = output_separator_offsets[output_index];
    pos = start;
    remove_off = 0;
    remove_len = 0;

    while (pos < end) {
        size_t entry_start = pos;
        if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &key_len, &next_pos) != 0)
            return -1;
        pos = next_pos;
        if (pos + key_len > end) return -1;
        if (key_len >= 1 && psbt_buffer[pos] == key_type) {
            remove_off = entry_start;
            pos += (size_t)key_len;
            if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &val_len, &next_pos) != 0)
                return -1;
            pos = next_pos + (size_t)val_len;
            remove_len = pos - remove_off;
            break;
        }
        pos += (size_t)key_len;
        if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &val_len, &next_pos) != 0)
            return -1;
        pos = next_pos + (size_t)val_len;
    }

    if (remove_len == 0) return 0;

    memmove(psbt_buffer + remove_off, psbt_buffer + remove_off + remove_len,
            psbt_size - (remove_off + remove_len));
    psbt_size -= remove_len;
    output_separator_offsets[output_index] -= remove_len;
    for (j = output_index + 1; j < output_separator_count; j++) {
        output_separator_offsets[j] -= remove_len;
        output_map_start_offsets[j] -= remove_len;
    }
    return 0;
}

static void fkt_cleanup_signed_psbt_maps(void) {
    int i;

    for (i = 0; i < psbt_data.num_outputs; i++) {
        fkt_remove_output_key_type(i, FKT_PSBT_OUT_BIP32_DERIVATION);
        fkt_remove_output_key_type(i, FKT_PSBT_OUT_TAP_TREE);
        fkt_remove_output_key_type(i, FKT_PSBT_OUT_TAP_BIP32_DERIVATION);
        /* Proprietary 0xFC: pass through (bark ClaimInput / wallet metadata). */
    }
}

static int fkt_ecdsa_sign_der_normalized(secp256k1_context *ctx,
                                           const uint8_t sighash[32],
                                           const uint8_t privkey[32],
                                           uint8_t der_sig[74],
                                           size_t *sig_len_out) {
    secp256k1_ecdsa_signature sig, norm;

    if (!secp256k1_ecdsa_sign(ctx, &sig, sighash, privkey, NULL, NULL))
        return -1;
    secp256k1_ecdsa_signature_normalize(ctx, &norm, &sig);
    *sig_len_out = 74;
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, der_sig, sig_len_out, &norm))
        return -1;
    return 0;
}

static int fkt_remove_input_key_type(int input_index, uint8_t key_type) {
    size_t start, end, pos, remove_off, remove_len;
    uint64_t key_len, val_len;
    size_t next_pos;
    int j;

    if (input_index < 0 || input_index >= input_separator_count) return -1;
    start = input_map_start_offsets[input_index];
    end = input_separator_offsets[input_index];
    pos = start;
    remove_off = 0;
    remove_len = 0;

    while (pos < end) {
        size_t entry_start = pos;
        if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &key_len, &next_pos) != 0)
            return -1;
        pos = next_pos;
        if (pos + key_len > end) return -1;
        if (key_len >= 1 && psbt_buffer[pos] == key_type) {
            remove_off = entry_start;
            pos += (size_t)key_len;
            if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &val_len, &next_pos) != 0)
                return -1;
            pos = next_pos + (size_t)val_len;
            remove_len = pos - remove_off;
            break;
        }
        pos += (size_t)key_len;
        if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &val_len, &next_pos) != 0)
            return -1;
        pos = next_pos + (size_t)val_len;
    }

    if (remove_len == 0) return 0;

    memmove(psbt_buffer + remove_off, psbt_buffer + remove_off + remove_len,
            psbt_size - (remove_off + remove_len));
    psbt_size -= remove_len;
    input_separator_offsets[input_index] -= remove_len;
    for (j = input_index + 1; j < input_separator_count; j++) {
        input_separator_offsets[j] -= remove_len;
        input_map_start_offsets[j] -= remove_len;
    }
    fkt_shift_output_offsets(remove_off, -(long)remove_len);
    return 0;
}

static int fkt_witness_script_has_pubkey(const uint8_t *witness_script,
                                         size_t witness_script_len,
                                         const uint8_t pub33[33]) {
    size_t pos = 0;
    if (witness_script_len < 4) return 0;
    pos = 1; /* skip OP_m */
    while (pos < witness_script_len) {
        uint8_t op = witness_script[pos];
        if (op == 0xAE) break; /* OP_CHECKMULTISIG */
        if (op >= 0x51 && op <= 0x60) break; /* OP_n threshold */
        if (op != 0x21 && op != 0x20) return 0;
        if (pos + 1 + op > witness_script_len) return 0;
        if (op == 0x21 && memcmp(witness_script + pos + 1, pub33, 33) == 0)
            return 1;
        pos += 1 + op;
    }
    return 0;
}

static int fkt_input_has_partial_sig(int input_index, const uint8_t pub33[33]) {
    size_t start, end, pos;
    uint64_t key_len, val_len;
    size_t next_pos;

    if (input_index < 0 || input_index >= input_separator_count) return 0;
    start = input_map_start_offsets[input_index];
    end = input_separator_offsets[input_index];
    pos = start;
    while (pos < end) {
        if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &key_len, &next_pos) != 0)
            return 0;
        pos = next_pos;
        if (pos + key_len > end) return 0;
        if (key_len == 34 && psbt_buffer[pos] == FKT_PSBT_IN_PARTIAL_SIG &&
            memcmp(psbt_buffer + pos + 1, pub33, 33) == 0)
            return 1;
        pos += (size_t)key_len;
        if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &val_len, &next_pos) != 0)
            return 0;
        pos = next_pos + (size_t)val_len;
    }
    return 0;
}

static int fkt_insert_partial_sig(int input_index,
                                  const uint8_t pub33[33],
                                  const uint8_t der_sig[74], size_t sig_len) {
    if (fkt_input_has_partial_sig(input_index, pub33))
        return 0;
    return fkt_insert_input_key(input_index, FKT_PSBT_IN_PARTIAL_SIG,
                                pub33, 33, der_sig, sig_len);
}

static int fkt_insert_finalized_p2pkh(int input_index,
                                      const uint8_t der_sig[74], size_t sig_len,
                                      const uint8_t pub33[33]) {
    uint8_t scriptsig[150];
    uint8_t *sp = scriptsig;
    size_t slen;

    sp += fkt_write_compact_size(sp, (uint64_t)sig_len);
    memcpy(sp, der_sig, sig_len);
    sp += sig_len;
    sp += fkt_write_compact_size(sp, 33);
    memcpy(sp, pub33, 33);
    sp += 33;
    slen = (size_t)(sp - scriptsig);

    if (fkt_insert_input_key(input_index, FKT_PSBT_IN_FINAL_SCRIPTSIG, NULL, 0,
                             scriptsig, slen) != 0)
        return -1;
    return 0;
}

static int fkt_insert_finalized_p2wpkh(int input_index,
                                       const uint8_t der_sig[74], size_t sig_len,
                                       const uint8_t pub33[33]) {
    uint8_t witness[120];
    uint8_t *wp = witness;
    size_t wlen;

    if (fkt_insert_input_key(input_index, 0x07, NULL, 0, NULL, 0) != 0)
        return -1;

    *wp++ = 0x02;
    wp += fkt_write_compact_size(wp, (uint64_t)sig_len);
    memcpy(wp, der_sig, sig_len); wp += sig_len;
    wp += fkt_write_compact_size(wp, 33);
    memcpy(wp, pub33, 33); wp += 33;
    wlen = (size_t)(wp - witness);

    if (fkt_insert_input_key(input_index, 0x08, NULL, 0, witness, wlen) != 0)
        return -1;
    return 0;
}

static int fkt_derive_input_keys(const uint8_t seed[64],
                                 int input_index,
                                 const char *path_override,
                                 const uint8_t *parent_pub_override,
                                 uint8_t child_priv[32],
                                 uint8_t child_pub33[33]) {
    if (fkt_psbt_input_has_derivation(input_index)) {
        return fkt_derive_from_indices(seed,
                                       fkt_psbt_input_derivation_path(input_index),
                                       fkt_psbt_input_derivation_depth(input_index),
                                       child_priv, child_pub33,
                                       parent_pub_override);
    }

    if (path_override != NULL && path_override[0] != '\0') {
        return fkt_derive_from_path(seed, path_override,
                                    child_priv, child_pub33,
                                    parent_pub_override);
    }

    printf("No derivation path for input %d.\n", input_index);
    return -1;
}

int fkt_sign_loaded_psbt(const uint8_t seed[64],
                         const char *path_override,
                         const uint8_t *parent_pub_override,
                         const char *output_file) {
    int i;
    FILE *fout = NULL;
    int ok = -1;
    int signed_any = 0;
    secp256k1_context *ctx = fkt_secp256k1_ctx();

    fkt_debug_master_fp(seed);
    fkt_signer_clear_signed_inputs();

    if (fkt_confirm_fingerprint_verify() != 0)
        goto cleanup;

    for (i = 0; i < psbt_data.num_inputs; i++) {
        uint8_t child_priv[32], child_pub33[33];
        uint8_t hash20[20];

        if (fkt_derive_input_keys(seed, i, path_override, parent_pub_override,
                                  child_priv, child_pub33) != 0) {
            fkt_last_error_set("BIP32 derivation failed (check seed and PSBT paths).");
            goto cleanup;
        }
        fkt_debug_hex("derived child privkey", child_priv, 32);
        fkt_hash160(child_pub33, 33, hash20);

        if (psbt_data.input_had_final_witness[i]) {
            continue;
        }

        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2TR) {
            uint8_t sighash[32];
            uint8_t sig[64];
            int sig_len;
            uint8_t tap_int_key[32];
            int has_tap_int_key = psbt_data.input_has_tap_int_key[i];
            int is_script_path = psbt_data.input_is_script_path[i];

            fkt_remove_input_key_type(i, 0x03);
            fkt_remove_input_key_type(i, 0x16);
            fkt_remove_input_key_type(i, FKT_PSBT_IN_TAP_LEAF_SCRIPT);
            fkt_remove_input_key_type(i, FKT_PSBT_IN_TAP_MERKLE_ROOT);
            if (has_tap_int_key) {
                memcpy(tap_int_key, psbt_data.input_tap_int_key[i], 32);
                fkt_remove_input_key_type(i, FKT_PSBT_IN_TAP_INTERNAL_KEY);
            }

            if (is_script_path) {
                uint8_t witness[1 + 1 + 64 + 1 + FKT_TAP_LEAF_SCRIPT_MAX + 3 + FKT_TAP_CONTROL_BLOCK_MAX];
                uint8_t *wp;
                size_t wlen;
                size_t script_len = psbt_data.input_tap_leaf_script_len[i];
                size_t cb_len = psbt_data.input_tap_control_block_len[i];

                if (!psbt_data.input_has_tap_leaf[i] || script_len == 0 || cb_len < 33) {
                    fkt_last_error_set("Taproot script-path data incomplete.");
                    goto cleanup;
                }
                if (fkt_bip341_sighash_scriptpath(i, sighash) != 0) {
                    fkt_last_error_set("Taproot script-path sighash failed.");
                    goto cleanup;
                }
                fkt_debug_hex("sighash scriptpath", sighash, 32);
                /* Untweaked leaf key */
                if (fkt_schnorr_sign(child_priv, sighash, sig, &sig_len) != 0) {
                    fkt_last_error_set(
                        "Wrong seed — key does not match this PSBT (script-path).");
                    goto cleanup;
                }
                fkt_debug_hex("schnorr sig scriptpath", sig, 64);

                if (fkt_insert_input_key(i, 0x07, NULL, 0, NULL, 0) != 0) {
                    printf("PSBT buffer overflow inserting scriptsig for input %d\n", i);
                    goto cleanup;
                }
                wp = witness;
                *wp++ = 0x03;
                *wp++ = 64;
                memcpy(wp, sig, 64); wp += 64;
                if (script_len < 0xFDu) {
                    *wp++ = (uint8_t)script_len;
                } else {
                    fkt_last_error_set("Leaf script too long.");
                    goto cleanup;
                }
                memcpy(wp, psbt_data.input_tap_leaf_script[i], script_len);
                wp += script_len;
                if (cb_len < 0xFDu) {
                    *wp++ = (uint8_t)cb_len;
                } else if (cb_len <= 0xFFFFu) {
                    *wp++ = 0xFD;
                    *wp++ = (uint8_t)(cb_len & 0xFF);
                    *wp++ = (uint8_t)((cb_len >> 8) & 0xFF);
                } else {
                    fkt_last_error_set("Control block too long.");
                    goto cleanup;
                }
                memcpy(wp, psbt_data.input_tap_control_block[i], cb_len);
                wp += cb_len;
                wlen = (size_t)(wp - witness);
                if (fkt_insert_input_key(i, 0x08, NULL, 0, witness, wlen) != 0) {
                    printf("PSBT buffer overflow inserting script-path witness for input %d\n", i);
                    goto cleanup;
                }
                fkt_memzero(witness, sizeof(witness));
            } else {
                uint8_t witness[66];
                const uint8_t *merkle = NULL;
                size_t merkle_len = 0;

                if (!has_tap_int_key) {
                    fkt_last_error_set(
                        "Taproot input missing internal key (0x17) — cannot sign.");
                    goto cleanup;
                }
                if (psbt_data.input_has_tap_merkle_root[i]) {
                    merkle = psbt_data.input_tap_merkle_root[i];
                    merkle_len = 32;
                }
                if (fkt_bip341_sighash(i, sighash) != 0) {
                    fkt_last_error_set("Taproot sighash failed.");
                    goto cleanup;
                }
                fkt_debug_hex("sighash", sighash, 32);
                if (fkt_schnorr_sign_taproot(child_priv, sighash, tap_int_key,
                                             merkle, merkle_len, sig, &sig_len) != 0) {
                    fkt_last_error_set(
                        "Wrong seed — key does not match this PSBT (Taproot).");
                    goto cleanup;
                }
                fkt_debug_hex("schnorr sig", sig, 64);
                if (fkt_insert_input_key(i, 0x07, NULL, 0, NULL, 0) != 0) {
                    printf("PSBT buffer overflow inserting scriptsig for input %d\n", i);
                    goto cleanup;
                }
                witness[0] = 0x01;
                witness[1] = 64;
                memcpy(witness + 2, sig, 64);
                if (fkt_insert_input_key(i, 0x08, NULL, 0, witness, 66) != 0) {
                    printf("PSBT buffer overflow inserting witness stack for input %d\n", i);
                    goto cleanup;
                }
                fkt_memzero(witness, sizeof(witness));
            }
            if (has_tap_int_key) {
                if (fkt_insert_input_key(i, FKT_PSBT_IN_TAP_INTERNAL_KEY, NULL, 0, tap_int_key, 32) != 0) {
                    printf("PSBT buffer overflow inserting tap internal key for input %d\n", i);
                    goto cleanup;
                }
            }
            signed_any = 1;
            fkt_signer_signed_inputs[i] = 1;
            fkt_memzero(sighash, sizeof(sighash));
            fkt_memzero(sig, sizeof(sig));
            fkt_memzero(tap_int_key, sizeof(tap_int_key));
            fkt_memzero(child_priv, sizeof(child_priv));
            fkt_memzero(child_pub33, sizeof(child_pub33));
            continue;
        }

        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2WSH) {
            const uint8_t *ws;
            size_t ws_len;

            if (!psbt_data.input_has_redeem_witness_script[i]) continue;
            ws = psbt_data.input_redeem_witness_script[i];
            ws_len = psbt_data.input_redeem_witness_script_len[i];
            if (!fkt_witness_script_has_pubkey(ws, ws_len, child_pub33)) continue;

            {
                uint8_t sighash[32];
                uint8_t der_sig[74];
                size_t sig_len = sizeof(der_sig);

                if (fkt_bip143_sighash_p2wsh(i, ws, ws_len, sighash) != 0) {
                    printf("Sighash error for input %d (P2WSH)\n", i);
                    goto cleanup;
                }
                fkt_debug_hex("sighash", sighash, 32);
                if (fkt_ecdsa_sign_der_normalized(ctx, sighash, child_priv, der_sig, &sig_len) != 0) {
                    printf("Signing failed for input %d (P2WSH)\n", i);
                    goto cleanup;
                }
                if (sig_len + 1 > sizeof(der_sig)) {
                    printf("DER signature too long for input %d\n", i);
                    goto cleanup;
                }
                der_sig[sig_len++] = 0x01;
                fkt_debug_hex("DER sig", der_sig, sig_len);
                if (fkt_insert_partial_sig(i, child_pub33, der_sig, sig_len) != 0) {
                    printf("PSBT buffer overflow inserting partial sig for input %d\n", i);
                    goto cleanup;
                }
                fkt_memzero(sighash, sizeof(sighash));
                fkt_memzero(der_sig, sizeof(der_sig));
            }
            signed_any = 1;
            fkt_signer_signed_inputs[i] = 1;
            fkt_memzero(child_priv, sizeof(child_priv));
            fkt_memzero(child_pub33, sizeof(child_pub33));
            continue;
        }

        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2SH_P2WPKH) {
            if (!psbt_data.input_has_redeem_script[i]) {
                printf("P2SH-P2WPKH input %d missing redeem script\n", i);
                goto cleanup;
            }
            if (psbt_data.input_redeem_script_len[i] != 22 ||
                psbt_data.input_redeem_script[i][0] != 0x00 ||
                psbt_data.input_redeem_script[i][1] != 0x14 ||
                memcmp(hash20, psbt_data.input_redeem_script[i] + 2, 20) != 0) {
                continue;
            }
            {
                uint8_t sighash[32];
                uint8_t der_sig[74];
                size_t sig_len = sizeof(der_sig);

                if (fkt_bip143_sighash_p2sh_p2wpkh(i, psbt_data.input_redeem_script[i], sighash) != 0) {
                    printf("Sighash error for input %d (P2SH-P2WPKH)\n", i);
                    goto cleanup;
                }
                fkt_debug_hex("sighash", sighash, 32);
                if (fkt_ecdsa_sign_der_normalized(ctx, sighash, child_priv, der_sig, &sig_len) != 0) {
                    printf("Signing failed for input %d (P2SH-P2WPKH)\n", i);
                    goto cleanup;
                }
                if (sig_len + 1 > sizeof(der_sig)) {
                    printf("DER signature too long for input %d\n", i);
                    goto cleanup;
                }
                der_sig[sig_len++] = 0x01;
                fkt_debug_hex("DER sig", der_sig, sig_len);
                if (fkt_insert_partial_sig(i, child_pub33, der_sig, sig_len) != 0) {
                    printf("PSBT buffer overflow inserting partial sig for input %d\n", i);
                    goto cleanup;
                }
                fkt_memzero(sighash, sizeof(sighash));
                fkt_memzero(der_sig, sizeof(der_sig));
            }
            signed_any = 1;
            fkt_signer_signed_inputs[i] = 1;
            fkt_memzero(child_priv, sizeof(child_priv));
            fkt_memzero(child_pub33, sizeof(child_pub33));
            continue;
        }

        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2PKH) {
            if (!psbt_data.input_has_witness_script[i]) continue;

            fkt_remove_input_key_type(i, 0x03);
            fkt_remove_input_key_type(i, 0x02);

            if (psbt_data.input_witness_script_len[i] != 25 ||
                memcmp(hash20, psbt_data.input_witness_script[i] + 3, 20) != 0) {
                continue;
            }

            {
                uint8_t sighash[32];
                uint8_t der_sig[74];
                size_t sig_len = sizeof(der_sig);
                uint32_t sighash_type = psbt_data.input_has_sighash[i]
                    ? psbt_data.input_sighash[i] : FKT_SIGHASH_ALL;

                if (fkt_legacy_p2pkh_sighash(i, psbt_data.input_witness_script[i],
                                               psbt_data.input_witness_script_len[i],
                                               sighash_type, sighash) != 0) {
                    printf("Sighash error for input %d (P2PKH)\n", i);
                    goto cleanup;
                }
                fkt_debug_hex("sighash", sighash, 32);
                if (fkt_ecdsa_sign_der_normalized(ctx, sighash, child_priv, der_sig, &sig_len) != 0) {
                    printf("Signing failed for input %d (P2PKH)\n", i);
                    goto cleanup;
                }
                if (sig_len + 1 > sizeof(der_sig)) {
                    printf("DER signature too long for input %d\n", i);
                    goto cleanup;
                }
                der_sig[sig_len++] = 0x01;
                fkt_debug_hex("DER sig", der_sig, sig_len);
                if (fkt_insert_finalized_p2pkh(i, der_sig, sig_len, child_pub33) != 0) {
                    printf("PSBT buffer overflow finalizing input %d (P2PKH)\n", i);
                    goto cleanup;
                }
                signed_any = 1;
                fkt_signer_signed_inputs[i] = 1;
                fkt_memzero(sighash, sizeof(sighash));
                fkt_memzero(der_sig, sizeof(der_sig));
            }
            fkt_memzero(child_priv, sizeof(child_priv));
            fkt_memzero(child_pub33, sizeof(child_pub33));
            continue;
        }

        if (psbt_data.input_script_type[i] != SCRIPT_TYPE_P2WPKH) continue;
        if (!psbt_data.input_has_witness_script[i]) continue;

        fkt_remove_input_key_type(i, 0x03);
        fkt_remove_input_key_type(i, 0x02);

        if (memcmp(hash20, psbt_data.input_witness_script[i] + 2, 20) != 0) {
            fkt_last_error_set(
                "Wrong seed — public key does not match this PSBT.");
            goto cleanup;
        }

        {
            uint8_t sighash[32];
            uint8_t der_sig[74];
            size_t sig_len = sizeof(der_sig);

            if (fkt_bip143_sighash(i, psbt_data.input_witness_script[i], sighash) != 0) {
                fkt_last_error_set("P2WPKH sighash failed.");
                goto cleanup;
            }
            fkt_debug_hex("sighash", sighash, 32);
            if (fkt_ecdsa_sign_der_normalized(ctx, sighash, child_priv, der_sig, &sig_len) != 0) {
                fkt_last_error_set(
                    "Wrong seed — ECDSA sign failed (key mismatch).");
                goto cleanup;
            }
            if (sig_len + 1 > sizeof(der_sig)) {
                printf("DER signature too long for input %d\n", i);
                goto cleanup;
            }
            der_sig[sig_len++] = 0x01;
            fkt_debug_hex("DER sig", der_sig, sig_len);
            if (fkt_insert_finalized_p2wpkh(i, der_sig, sig_len, child_pub33) != 0) {
                printf("PSBT buffer overflow finalizing input %d\n", i);
                goto cleanup;
            }
            signed_any = 1;
            fkt_signer_signed_inputs[i] = 1;
            fkt_memzero(sighash, sizeof(sighash));
            fkt_memzero(der_sig, sizeof(der_sig));
        }
        fkt_memzero(child_priv, sizeof(child_priv));
        fkt_memzero(child_pub33, sizeof(child_pub33));
    }

    fkt_cleanup_signed_psbt_maps();
#if !FKT_BUILD_NO_FINALIZER
    fkt_psbt_finalize(seed, path_override, parent_pub_override);
#endif

    if (!signed_any) {
        int had_presigned = 0;
        for (i = 0; i < psbt_data.num_inputs; i++) {
            if (psbt_data.input_had_final_witness[i])
                had_presigned = 1;
        }
        if (!had_presigned) {
            int had_unknown = 0;
            for (i = 0; i < psbt_data.num_inputs; i++) {
                if (psbt_data.input_script_type[i] == SCRIPT_TYPE_UNKNOWN)
                    had_unknown = 1;
            }
            if (had_unknown)
                fkt_last_error_set(
                    "No inputs could be signed (unsupported input type).");
            else
                fkt_last_error_set(
                    "Wrong seed — no inputs match this PSBT.");
            goto cleanup;
        }
    }

    if (fkt_confirm_post_sign_auto(output_file) != 0)
        goto cleanup;

    fout = fopen(output_file, "wb");
    if (!fout) {
        fkt_last_error_set("Cannot write output file (check filename and permissions).");
        goto cleanup;
    }
    fwrite(psbt_buffer, 1, psbt_size, fout);
    fclose(fout);
    fout = NULL;
    ok = 0;

cleanup:
    if (fout) fclose(fout);
    fkt_confirm_fingerprint_clear();
    /* Never return failure with an empty last_error (TUI falls back to vague text). */
    if (ok != 0) {
        const char *e = fkt_last_error_get();
        if (!e || e[0] == '\0')
            fkt_last_error_set("Signing failed (check seed, PSBT, and output path).");
    }
    return ok;
}

int fkt_sign_psbt(const uint8_t seed[64], const char *path_str,
                  const char *psbt_file, const char *output_file) {
    fkt_secp256k1_init();
    fkt_psbt_init();
    if (fkt_psbt_load_input(psbt_file) != 0) {
        fkt_last_error_set("Failed to reload PSBT (invalid file path or base64).");
        return -1;
    }
    if (fkt_psbt_try_parse() != 0) {
        const char *perr = fkt_last_error_get();
        if (!perr || perr[0] == '\0')
            fkt_last_error_set("PSBT parse failed (malformed or unsupported transaction).");
        return -1;
    }
    fkt_compute_hash_caches();
    return fkt_sign_loaded_psbt(seed, path_str, NULL, output_file);
}

int fkt_sign_psbt_with_parent(const uint8_t seed[64],
                              const char *path_str,
                              const char *psbt_file,
                              const char *output_file,
                              const uint8_t parent_pub33[33]) {
    fkt_secp256k1_init();
    fkt_psbt_init();
    if (fkt_psbt_load_input(psbt_file) != 0) {
        printf("Failed to load PSBT.\n");
        return -1;
    }
    if (fkt_psbt_try_parse() != 0) {
        const char *perr = fkt_last_error_get();
        if (!perr || perr[0] == '\0')
            fkt_last_error_set("PSBT parse failed (malformed or unsupported transaction).");
        return -1;
    }
    fkt_compute_hash_caches();
    return fkt_sign_loaded_psbt(seed, path_str, parent_pub33, output_file);
}
