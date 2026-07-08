/* fkt_finalizer.c – PSBT finalization with per-input status */
#include "fkt_finalizer.h"
#include "fkt_psbt.h"
#include "fkt_bip32.h"
#include "fkt_hash160.h"
#include "fkt_secp256k1.h"
#include "fkt_memzero.h"
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>

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
        if (value_len > 0)
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

static int fkt_remove_input_key_type(int input_index, uint8_t key_type) {
    size_t start, end, pos, remove_off, remove_len;
    uint64_t key_len, val_len;
    size_t next_pos;
    int j;
    int removed = 0;

    if (input_index < 0 || input_index >= input_separator_count) return -1;
    start = input_map_start_offsets[input_index];
    end = input_separator_offsets[input_index];

    while (1) {
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

        if (remove_len == 0) break;

        memmove(psbt_buffer + remove_off, psbt_buffer + remove_off + remove_len,
                psbt_size - (remove_off + remove_len));
        psbt_size -= remove_len;
        input_separator_offsets[input_index] -= remove_len;
        for (j = input_index + 1; j < input_separator_count; j++) {
            input_separator_offsets[j] -= remove_len;
            input_map_start_offsets[j] -= remove_len;
        }
        fkt_shift_output_offsets(remove_off, -(long)remove_len);
        end = input_separator_offsets[input_index];
        removed = 1;
    }
    return removed ? 1 : 0;
}

static int fkt_input_has_final_witness(int input_index) {
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
        if (key_len >= 1 && psbt_buffer[pos] == FKT_PSBT_IN_FINAL_SCRIPTWITNESS) {
            pos += (size_t)key_len;
            if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &val_len, &next_pos) != 0)
                return 0;
            return val_len > 0;
        }
        pos += (size_t)key_len;
        if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &val_len, &next_pos) != 0)
            return 0;
        pos = next_pos + (size_t)val_len;
    }
    return 0;
}

#define MAX_PARTIAL_SIGS 16

typedef struct {
    uint8_t pub33[33];
    uint8_t der[74];
    size_t der_len;
} fkt_partial_sig_entry;

static int fkt_collect_partial_sigs(int input_index, fkt_partial_sig_entry *out, int max_out) {
    size_t start, end, pos;
    uint64_t key_len, val_len;
    size_t next_pos;
    int count = 0;

    if (input_index < 0 || input_index >= input_separator_count) return 0;
    start = input_map_start_offsets[input_index];
    end = input_separator_offsets[input_index];
    pos = start;
    while (pos < end && count < max_out) {
        if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &key_len, &next_pos) != 0)
            break;
        pos = next_pos;
        if (pos + key_len > end) break;
        if (key_len == 34 && psbt_buffer[pos] == FKT_PSBT_IN_PARTIAL_SIG) {
            memcpy(out[count].pub33, psbt_buffer + pos + 1, 33);
            pos += (size_t)key_len;
            if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &val_len, &next_pos) != 0)
                break;
            pos = next_pos;
            if (val_len > sizeof(out[count].der)) break;
            memcpy(out[count].der, psbt_buffer + pos, (size_t)val_len);
            out[count].der_len = (size_t)val_len;
            count++;
            pos += (size_t)val_len;
            continue;
        }
        pos += (size_t)key_len;
        if (fkt_read_varint_at(psbt_buffer, psbt_size, pos, &val_len, &next_pos) != 0)
            break;
        pos = next_pos + (size_t)val_len;
    }
    return count;
}

static int fkt_witness_script_has_pubkey(const uint8_t *witness_script,
                                         size_t witness_script_len,
                                         const uint8_t pub33[33]) {
    size_t pos = 0;
    if (witness_script_len < 4) return 0;
    pos = 1;
    while (pos < witness_script_len) {
        uint8_t op = witness_script[pos];
        if (op == 0xAE) break;
        if (op >= 0x51 && op <= 0x60) break;
        if (op != 0x21 && op != 0x20) return 0;
        if (pos + 1 + op > witness_script_len) return 0;
        if (op == 0x21 && memcmp(witness_script + pos + 1, pub33, 33) == 0)
            return 1;
        pos += 1 + op;
    }
    return 0;
}

static int fkt_parse_multisig_threshold(const uint8_t *ws, size_t ws_len, int *threshold_out) {
    if (ws_len < 3) return -1;
    if (ws[0] >= 0x51 && ws[0] <= 0x60) {
        *threshold_out = (int)(ws[0] - 0x50);
        return 0;
    }
    return -1;
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
    return -1;
}

static int fkt_key_matches_input(int input_index, const uint8_t child_pub33[33]) {
    uint8_t hash20[20];

    fkt_hash160(child_pub33, 33, hash20);

    if (psbt_data.input_script_type[input_index] == SCRIPT_TYPE_P2WPKH) {
        if (!psbt_data.input_has_witness_script[input_index]) return 0;
        if (psbt_data.input_witness_script_len[input_index] != 22) return 0;
        return memcmp(hash20, psbt_data.input_witness_script[input_index] + 2, 20) == 0;
    }
    if (psbt_data.input_script_type[input_index] == SCRIPT_TYPE_P2PKH) {
        if (!psbt_data.input_has_witness_script[input_index]) return 0;
        if (psbt_data.input_witness_script_len[input_index] != 25) return 0;
        return memcmp(hash20, psbt_data.input_witness_script[input_index] + 3, 20) == 0;
    }
    if (psbt_data.input_script_type[input_index] == SCRIPT_TYPE_P2SH_P2WPKH) {
        if (!psbt_data.input_has_redeem_script[input_index]) return 0;
        if (psbt_data.input_redeem_script_len[input_index] != 22) return 0;
        return memcmp(hash20, psbt_data.input_redeem_script[input_index] + 2, 20) == 0;
    }
    if (psbt_data.input_script_type[input_index] == SCRIPT_TYPE_P2WSH) {
        if (!psbt_data.input_has_redeem_witness_script[input_index]) return 0;
        return fkt_witness_script_has_pubkey(
            psbt_data.input_redeem_witness_script[input_index],
            psbt_data.input_redeem_witness_script_len[input_index],
            child_pub33);
    }
    if (psbt_data.input_script_type[input_index] == SCRIPT_TYPE_P2TR) {
        secp256k1_context *ctx = fkt_secp256k1_ctx();
        secp256k1_pubkey pubkey;
        unsigned char ser[33];
        size_t ser_len = 33;
        if (!psbt_data.input_has_tap_int_key[input_index]) return 0;
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, child_pub33, 33)) return 0;
        if (!secp256k1_ec_pubkey_serialize(ctx, ser, &ser_len, &pubkey,
                                           SECP256K1_EC_COMPRESSED))
            return 0;
        return memcmp(ser + 1, psbt_data.input_tap_int_key[input_index], 32) == 0;
    }
    return 0;
}

static int fkt_finalize_p2wpkh(int input_index,
                               const uint8_t der_sig[74], size_t sig_len,
                               const uint8_t pub33[33]) {
    uint8_t witness[120];
    uint8_t *wp = witness;
    size_t wlen;

    if (fkt_insert_input_key(input_index, FKT_PSBT_IN_FINAL_SCRIPTSIG, NULL, 0, NULL, 0) != 0)
        return -1;

    *wp++ = 0x02;
    wp += fkt_write_compact_size(wp, (uint64_t)sig_len);
    memcpy(wp, der_sig, sig_len); wp += sig_len;
    wp += fkt_write_compact_size(wp, 33);
    memcpy(wp, pub33, 33); wp += 33;
    wlen = (size_t)(wp - witness);

    if (fkt_insert_input_key(input_index, FKT_PSBT_IN_FINAL_SCRIPTWITNESS, NULL, 0, witness, wlen) != 0)
        return -1;
    return 0;
}

static int fkt_finalize_p2sh_p2wpkh(int input_index,
                                      const uint8_t redeem[22],
                                      const uint8_t der_sig[74], size_t sig_len,
                                      const uint8_t pub33[33]) {
    uint8_t witness[120];
    uint8_t *wp = witness;
    size_t wlen;

    if (fkt_insert_input_key(input_index, FKT_PSBT_IN_FINAL_SCRIPTSIG, NULL, 0, redeem, 22) != 0)
        return -1;

    *wp++ = 0x02;
    wp += fkt_write_compact_size(wp, (uint64_t)sig_len);
    memcpy(wp, der_sig, sig_len); wp += sig_len;
    wp += fkt_write_compact_size(wp, 33);
    memcpy(wp, pub33, 33); wp += 33;
    wlen = (size_t)(wp - witness);

    if (fkt_insert_input_key(input_index, FKT_PSBT_IN_FINAL_SCRIPTWITNESS, NULL, 0, witness, wlen) != 0)
        return -1;
    return 0;
}

static const fkt_partial_sig_entry *fkt_find_sig_for_pubkey(
    const fkt_partial_sig_entry *sigs, int nsigs, const uint8_t pub33[33]) {
    int i;
    for (i = 0; i < nsigs; i++) {
        if (memcmp(sigs[i].pub33, pub33, 33) == 0)
            return &sigs[i];
    }
    return NULL;
}

static int fkt_finalize_p2wsh_multisig(int input_index,
                                         const uint8_t *ws, size_t ws_len,
                                         const fkt_partial_sig_entry *sigs, int nsigs) {
    uint8_t witness[520];
    uint8_t *wp = witness;
    int threshold = 0;
    int sigs_found = 0;
    size_t pos = 1;
    size_t wlen;

    if (fkt_parse_multisig_threshold(ws, ws_len, &threshold) != 0 || threshold < 1)
        return -1;

    while (pos < ws_len) {
        uint8_t op = ws[pos];
        if (op == 0xAE) break;
        if (op >= 0x51 && op <= 0x60) break;
        if (op != 0x21) return -1;
        if (pos + 34 > ws_len) return -1;
        if (fkt_find_sig_for_pubkey(sigs, nsigs, ws + pos + 1) != NULL)
            sigs_found++;
        pos += 34;
    }

    if (sigs_found < threshold)
        return 0;

    if (fkt_insert_input_key(input_index, FKT_PSBT_IN_FINAL_SCRIPTSIG, NULL, 0, NULL, 0) != 0)
        return -1;

    *wp++ = (uint8_t)(threshold + 1);
    wp += fkt_write_compact_size(wp, 0);

    pos = 1;
    while (pos < ws_len) {
        uint8_t op = ws[pos];
        const fkt_partial_sig_entry *entry;
        if (op == 0xAE) break;
        if (op >= 0x51 && op <= 0x60) break;
        if (op != 0x21) return -1;
        entry = fkt_find_sig_for_pubkey(sigs, nsigs, ws + pos + 1);
        if (entry != NULL) {
            wp += fkt_write_compact_size(wp, (uint64_t)entry->der_len);
            memcpy(wp, entry->der, entry->der_len);
            wp += entry->der_len;
        }
        pos += 34;
    }

    wlen = (size_t)(wp - witness);
    if (fkt_insert_input_key(input_index, FKT_PSBT_IN_FINAL_SCRIPTWITNESS, NULL, 0, witness, wlen) != 0)
        return -1;

    while (fkt_remove_input_key_type(input_index, FKT_PSBT_IN_PARTIAL_SIG))
        ;
    return 1;
}

static void fkt_print_input_status(int input_index, const char *status) {
    printf("  input %d: %s\n", input_index, status);
}

int fkt_psbt_finalize(const uint8_t seed[64], const char *path_override,
                      const uint8_t *parent_pub_override) {
    int i;

    for (i = 0; i < psbt_data.num_inputs; i++) {
        uint8_t child_priv[32], child_pub33[33];
        int key_ok = 0;
        int finalized_now = 0;

        if (psbt_data.input_had_final_witness[i]) {
            fkt_print_input_status(i, "[SKIPPED]");
            continue;
        }

        if (fkt_input_has_final_witness(i) && !fkt_signer_signed_inputs[i]) {
            fkt_print_input_status(i, "[SKIPPED]");
            continue;
        }

        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2TR) {
            if (fkt_signer_signed_inputs[i])
                fkt_print_input_status(i, "[SIGNED]");
            else if (fkt_input_has_final_witness(i))
                fkt_print_input_status(i, "[SKIPPED]");
            else
                fkt_print_input_status(i, "[WRONG KEY]");
            continue;
        }

        if (fkt_derive_input_keys(seed, i, path_override, parent_pub_override,
                                  child_priv, child_pub33) == 0) {
            key_ok = fkt_key_matches_input(i, child_pub33);
        }
        fkt_memzero(child_priv, sizeof(child_priv));

        if (!key_ok) {
            fkt_print_input_status(i, "[WRONG KEY]");
            fkt_memzero(child_pub33, sizeof(child_pub33));
            continue;
        }

        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2WSH) {
            fkt_partial_sig_entry sigs[MAX_PARTIAL_SIGS];
            int nsigs;
            const uint8_t *ws;
            size_t ws_len;
            int result;

            if (!psbt_data.input_has_redeem_witness_script[i]) {
                fkt_print_input_status(i, "[WRONG KEY]");
                continue;
            }
            ws = psbt_data.input_redeem_witness_script[i];
            ws_len = psbt_data.input_redeem_witness_script_len[i];
            nsigs = fkt_collect_partial_sigs(i, sigs, MAX_PARTIAL_SIGS);

            result = fkt_finalize_p2wsh_multisig(i, ws, ws_len, sigs, nsigs);
            if (result == 1) {
                fkt_print_input_status(i, "[FINALIZED]");
                continue;
            }
            if (fkt_signer_signed_inputs[i]) {
                fkt_print_input_status(i, "[SIGNED]");
                continue;
            }
            fkt_print_input_status(i, "[WRONG KEY]");
            continue;
        }

        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2SH_P2WPKH &&
            !fkt_input_has_final_witness(i)) {
            fkt_partial_sig_entry sigs[MAX_PARTIAL_SIGS];
            int nsigs;
            const fkt_partial_sig_entry *entry;

            nsigs = fkt_collect_partial_sigs(i, sigs, MAX_PARTIAL_SIGS);
            entry = fkt_find_sig_for_pubkey(sigs, nsigs, child_pub33);
            if (entry != NULL && psbt_data.input_has_redeem_script[i]) {
                if (fkt_finalize_p2sh_p2wpkh(i, psbt_data.input_redeem_script[i],
                                             entry->der, entry->der_len, child_pub33) == 0) {
                    while (fkt_remove_input_key_type(i, FKT_PSBT_IN_PARTIAL_SIG))
                        ;
                    finalized_now = 1;
                }
            }
        }

        if (psbt_data.input_script_type[i] == SCRIPT_TYPE_P2WPKH &&
            !fkt_input_has_final_witness(i)) {
            fkt_partial_sig_entry sigs[MAX_PARTIAL_SIGS];
            int nsigs;
            const fkt_partial_sig_entry *entry;

            nsigs = fkt_collect_partial_sigs(i, sigs, MAX_PARTIAL_SIGS);
            entry = fkt_find_sig_for_pubkey(sigs, nsigs, child_pub33);
            if (entry != NULL) {
                if (fkt_finalize_p2wpkh(i, entry->der, entry->der_len, child_pub33) == 0) {
                    while (fkt_remove_input_key_type(i, FKT_PSBT_IN_PARTIAL_SIG))
                        ;
                    finalized_now = 1;
                }
            }
        }

        if (fkt_input_has_final_witness(i)) {
            if (finalized_now)
                fkt_print_input_status(i, "[FINALIZED]");
            else if (fkt_signer_signed_inputs[i])
                fkt_print_input_status(i, "[SIGNED]");
            else
                fkt_print_input_status(i, "[SKIPPED]");
        } else if (fkt_signer_signed_inputs[i]) {
            fkt_print_input_status(i, "[SIGNED]");
        } else {
            fkt_print_input_status(i, "[WRONG KEY]");
        }

        fkt_memzero(child_pub33, sizeof(child_pub33));
    }

    return 0;
}