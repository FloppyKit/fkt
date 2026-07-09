#include "fkt_sighash.h"
#include "fkt_psbt.h"          /* for psbt_data access */
#include "fkt_sha256.h"
#include "fkt_secp256k1.h"
#include "fkt_memzero.h"
#include <string.h>

/* External data from fkt_psbt.c */
extern uint8_t hashPrevouts[32];
extern uint8_t hashSequence[32];
extern uint8_t hashOutputs[32];
/* etc. */

/* #### SECTION: Compute BIP-143 / BIP-341 hash caches (uses crypto module) #### */
void fkt_compute_hash_caches(void) {
    fkt_sha256_ctx ctx;
    uint8_t tmp[32];
    int i;

    /* hashPrevouts = dSHA256(all outpoints) */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_inputs; i++) {
        fkt_sha256_update(&ctx, psbt_data.input_txid[i], 32);
        fkt_sha256_update(&ctx, (const uint8_t*)&psbt_data.input_vout[i], 4);
    }
    fkt_sha256_final(&ctx, tmp);
    fkt_sha256(tmp, 32, hashPrevouts);

    /* hashSequence = dSHA256(all nSequence LE) */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_inputs; i++) {
        uint8_t seq[4];
        seq[0] = (uint8_t)(psbt_data.input_sequence[i] & 0xFF);
        seq[1] = (uint8_t)((psbt_data.input_sequence[i] >> 8) & 0xFF);
        seq[2] = (uint8_t)((psbt_data.input_sequence[i] >> 16) & 0xFF);
        seq[3] = (uint8_t)((psbt_data.input_sequence[i] >> 24) & 0xFF);
        fkt_sha256_update(&ctx, seq, 4);
    }
    fkt_sha256_final(&ctx, tmp);
    fkt_sha256(tmp, 32, hashSequence);

    /* sha_outputs & hashOutputs */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_outputs; i++) {
        uint8_t amount_le[8];
        int64_t amount = psbt_data.output_amount[i];
        uint8_t script_len_byte;
        int j;
        for (j = 0; j < 8; j++) amount_le[j] = (uint8_t)(amount >> (8*j));
        fkt_sha256_update(&ctx, amount_le, 8);
        script_len_byte = (uint8_t)psbt_data.output_script_len[i];
        fkt_sha256_update(&ctx, &script_len_byte, 1);
        fkt_sha256_update(&ctx, psbt_data.output_script[i], psbt_data.output_script_len[i]);
    }
    fkt_sha256_final(&ctx, tmp);
    memcpy(sha_outputs, tmp, 32);
    fkt_sha256(tmp, 32, hashOutputs);

    /* sha_prevouts = SHA256(all outpoints) */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_inputs; i++) {
        fkt_sha256_update(&ctx, psbt_data.input_txid[i], 32);
        fkt_sha256_update(&ctx, (const uint8_t*)&psbt_data.input_vout[i], 4);
    }
    fkt_sha256_final(&ctx, sha_prevouts);

    /* sha_amounts = SHA256(all input amounts LE) */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_inputs; i++) {
        uint8_t amt[8];
        int64_t amount = psbt_data.input_amount[i];
        int j;
        for (j = 0; j < 8; j++) amt[j] = (uint8_t)(amount >> (8*j));
        fkt_sha256_update(&ctx, amt, 8);
    }
    fkt_sha256_final(&ctx, sha_amounts);

    /* sha_scriptpubkeys = SHA256( all input scriptPubKeys with varint length ) */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_inputs; i++) {
        if (psbt_data.input_has_witness_script[i]) {
            uint8_t len_byte = (uint8_t)psbt_data.input_witness_script_len[i];
            fkt_sha256_update(&ctx, &len_byte, 1);
            fkt_sha256_update(&ctx, psbt_data.input_witness_script[i],
                              psbt_data.input_witness_script_len[i]);
        }
    }
    fkt_sha256_final(&ctx, sha_scriptpubkeys);

    /* sha_sequences = SHA256(all nSequence LE) */
    fkt_sha256_init(&ctx);
    for (i = 0; i < psbt_data.num_inputs; i++) {
        uint8_t seq[4];
        seq[0] = (uint8_t)(psbt_data.input_sequence[i] & 0xFF);
        seq[1] = (uint8_t)((psbt_data.input_sequence[i] >> 8) & 0xFF);
        seq[2] = (uint8_t)((psbt_data.input_sequence[i] >> 16) & 0xFF);
        seq[3] = (uint8_t)((psbt_data.input_sequence[i] >> 24) & 0xFF);
        fkt_sha256_update(&ctx, seq, 4);
    }
    fkt_sha256_final(&ctx, sha_sequences);
}

int fkt_bip143_sighash(int input_index,
                              const uint8_t scriptpubkey[22],
                              uint8_t sighash[32]) {
    uint8_t preimage[256];
    uint8_t *ptr = preimage;
    uint32_t nVersion, nLockTime, nSequence;
    int64_t amount;
    uint8_t amount_le[8];
    int i;

    {
        const uint8_t *tx = psbt_data.raw_unsigned_tx;
        nVersion = (uint32_t)tx[0] | ((uint32_t)tx[1]<<8) | ((uint32_t)tx[2]<<16) | ((uint32_t)tx[3]<<24);
        nLockTime = psbt_data.locktime;
    }

    *ptr++ = (uint8_t)(nVersion & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 24) & 0xFF);

    memcpy(ptr, hashPrevouts, 32); ptr += 32;
    memcpy(ptr, hashSequence, 32); ptr += 32;

    memcpy(ptr, psbt_data.input_txid[input_index], 32); ptr += 32;
    *ptr++ = (uint8_t)(psbt_data.input_vout[input_index] & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 8) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 16) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 24) & 0xFF);

    if (scriptpubkey[0] != 0x00 || scriptpubkey[1] != 0x14) return -1;
    *ptr++ = 0x19; *ptr++ = 0x76; *ptr++ = 0xa9; *ptr++ = 0x14;
    memcpy(ptr, scriptpubkey+2, 20); ptr += 20;
    *ptr++ = 0x88; *ptr++ = 0xac;

    amount = psbt_data.input_amount[input_index];
    for (i = 0; i < 8; i++) amount_le[i] = (uint8_t)(amount >> (8*i));
    memcpy(ptr, amount_le, 8); ptr += 8;

    nSequence = psbt_data.input_sequence[input_index];
    *ptr++ = (uint8_t)(nSequence & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 24) & 0xFF);

    memcpy(ptr, hashOutputs, 32); ptr += 32;

    *ptr++ = (uint8_t)(nLockTime & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 24) & 0xFF);

    *ptr++ = 0x01; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;

    fkt_sha256d(preimage, (size_t)(ptr - preimage), sighash);
    fkt_memzero(preimage, sizeof(preimage));
    return 0;
}

static size_t fkt_write_script_compact(uint8_t *out, const uint8_t *script, size_t script_len) {
    if (script_len < 0xFD) {
        out[0] = (uint8_t)script_len;
        memcpy(out + 1, script, script_len);
        return 1 + script_len;
    }
    if (script_len <= 0xFFFF) {
        out[0] = 0xFD;
        out[1] = (uint8_t)(script_len & 0xFF);
        out[2] = (uint8_t)((script_len >> 8) & 0xFF);
        memcpy(out + 3, script, script_len);
        return 3 + script_len;
    }
    return 0;
}

/* BIP-143 for native P2WSH (scriptCode = witness script with compact size prefix). */
int fkt_bip143_sighash_p2wsh(int input_index,
                             const uint8_t *witness_script, size_t witness_script_len,
                             uint8_t sighash[32]) {
    uint8_t preimage[600];
    uint8_t script_code[530];
    uint8_t *ptr = preimage;
    uint32_t nVersion, nLockTime, nSequence;
    int64_t amount;
    uint8_t amount_le[8];
    size_t script_code_len;
    int i;

    if (witness_script == NULL || witness_script_len == 0 || witness_script_len > 520)
        return -1;

    {
        const uint8_t *tx = psbt_data.raw_unsigned_tx;
        nVersion = (uint32_t)tx[0] | ((uint32_t)tx[1]<<8) | ((uint32_t)tx[2]<<16) | ((uint32_t)tx[3]<<24);
        nLockTime = psbt_data.locktime;
    }

    script_code_len = fkt_write_script_compact(script_code, witness_script, witness_script_len);
    if (script_code_len == 0) return -1;

    *ptr++ = (uint8_t)(nVersion & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 24) & 0xFF);

    memcpy(ptr, hashPrevouts, 32); ptr += 32;
    memcpy(ptr, hashSequence, 32); ptr += 32;

    memcpy(ptr, psbt_data.input_txid[input_index], 32); ptr += 32;
    *ptr++ = (uint8_t)(psbt_data.input_vout[input_index] & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 8) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 16) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 24) & 0xFF);

    memcpy(ptr, script_code, script_code_len); ptr += script_code_len;

    amount = psbt_data.input_amount[input_index];
    for (i = 0; i < 8; i++) amount_le[i] = (uint8_t)(amount >> (8*i));
    memcpy(ptr, amount_le, 8); ptr += 8;

    nSequence = psbt_data.input_sequence[input_index];
    *ptr++ = (uint8_t)(nSequence & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 24) & 0xFF);

    memcpy(ptr, hashOutputs, 32); ptr += 32;

    *ptr++ = (uint8_t)(nLockTime & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 24) & 0xFF);

    *ptr++ = 0x01; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00;

    fkt_sha256d(preimage, (size_t)(ptr - preimage), sighash);
    fkt_memzero(preimage, sizeof(preimage));
    fkt_memzero(script_code, sizeof(script_code));
    return 0;
}

/* #### SECTION: BIP-143 sighash for P2WPKH (uses crypto for dsha256) #### */
int fkt_bip143_sighash_p2sh_p2wpkh(int input_index,
                                          const uint8_t redeem_script[22],
                                          uint8_t sighash[32]) {
    /* BIP-143: P2SH-wrapped P2WPKH uses the expanded P2PKH scriptCode
       (0x19 0x76 0xa9 0x14 <hash> 0x88 0xac), not the 22-byte redeem script. */
    return fkt_bip143_sighash(input_index, redeem_script, sighash);
}

/* BIP-341 key-path sighash (SIGHASH_DEFAULT = 0x00). */
int fkt_bip341_sighash(int input_index, uint8_t sighash[32]) {
    uint8_t preimage[256];
    uint8_t *ptr = preimage;
    uint32_t nVersion, nLockTime;
    const uint8_t *tx = psbt_data.raw_unsigned_tx;

    if (input_index < 0 || input_index >= psbt_data.num_inputs) return -1;

    nVersion = (uint32_t)tx[0] | ((uint32_t)tx[1] << 8) |
               ((uint32_t)tx[2] << 16) | ((uint32_t)tx[3] << 24);
    nLockTime = psbt_data.locktime;

    *ptr++ = 0x00; /* epoch */
    *ptr++ = 0x00; /* SIGHASH_DEFAULT */

    *ptr++ = (uint8_t)(nVersion & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 24) & 0xFF);

    *ptr++ = (uint8_t)(nLockTime & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 24) & 0xFF);

    memcpy(ptr, sha_prevouts, 32); ptr += 32;
    memcpy(ptr, sha_amounts, 32); ptr += 32;
    memcpy(ptr, sha_scriptpubkeys, 32); ptr += 32;
    memcpy(ptr, sha_sequences, 32); ptr += 32;
    memcpy(ptr, sha_outputs, 32); ptr += 32;

    *ptr++ = 0x00; /* spend_type: key-path, no annex */

    *ptr++ = (uint8_t)(input_index & 0xFF);
    *ptr++ = (uint8_t)((input_index >> 8) & 0xFF);
    *ptr++ = (uint8_t)((input_index >> 16) & 0xFF);
    *ptr++ = (uint8_t)((input_index >> 24) & 0xFF);

    if (fkt_tagged_sha256("TapSighash", 10, preimage, (size_t)(ptr - preimage), sighash) != 0) {
        fkt_memzero(preimage, sizeof(preimage));
        return -1;
    }
    fkt_memzero(preimage, sizeof(preimage));
    return 0;
}

/* BIP-342 TapLeaf hash */
int fkt_tapleaf_hash(uint8_t leaf_version,
                     const uint8_t *script, size_t script_len,
                     uint8_t out[32]) {
    uint8_t buf[1 + 9 + FKT_TAP_LEAF_SCRIPT_MAX];
    size_t pos = 0;

    if (!script || !out) return -1;
    if (script_len > FKT_TAP_LEAF_SCRIPT_MAX) return -1;

    buf[pos++] = leaf_version;
    if (script_len < 0xFDu) {
        buf[pos++] = (uint8_t)script_len;
    } else if (script_len <= 0xFFFFu) {
        buf[pos++] = 0xFD;
        buf[pos++] = (uint8_t)(script_len & 0xFF);
        buf[pos++] = (uint8_t)((script_len >> 8) & 0xFF);
    } else {
        return -1;
    }
    memcpy(buf + pos, script, script_len);
    pos += script_len;

    if (fkt_tagged_sha256("TapLeaf", 7, buf, pos, out) != 0) {
        fkt_memzero(buf, sizeof(buf));
        return -1;
    }
    fkt_memzero(buf, sizeof(buf));
    return 0;
}

/* BIP-341 script-path sighash */
int fkt_bip341_sighash_scriptpath(int input_index, uint8_t sighash[32]) {
    uint8_t preimage[320];
    uint8_t *ptr = preimage;
    uint8_t leaf_hash[32];
    uint32_t nVersion, nLockTime;
    const uint8_t *tx = psbt_data.raw_unsigned_tx;

    if (input_index < 0 || input_index >= psbt_data.num_inputs) return -1;
    if (!psbt_data.input_has_tap_leaf[input_index]) return -1;

    if (fkt_tapleaf_hash(psbt_data.input_tap_leaf_version[input_index],
                         psbt_data.input_tap_leaf_script[input_index],
                         psbt_data.input_tap_leaf_script_len[input_index],
                         leaf_hash) != 0)
        return -1;

    nVersion = (uint32_t)tx[0] | ((uint32_t)tx[1] << 8) |
               ((uint32_t)tx[2] << 16) | ((uint32_t)tx[3] << 24);
    nLockTime = psbt_data.locktime;

    *ptr++ = 0x00;
    *ptr++ = 0x00;
    *ptr++ = (uint8_t)(nVersion & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 24) & 0xFF);
    *ptr++ = (uint8_t)(nLockTime & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 24) & 0xFF);
    memcpy(ptr, sha_prevouts, 32); ptr += 32;
    memcpy(ptr, sha_amounts, 32); ptr += 32;
    memcpy(ptr, sha_scriptpubkeys, 32); ptr += 32;
    memcpy(ptr, sha_sequences, 32); ptr += 32;
    memcpy(ptr, sha_outputs, 32); ptr += 32;
    *ptr++ = 0x02; /* script-path, no annex */
    *ptr++ = (uint8_t)(input_index & 0xFF);
    *ptr++ = (uint8_t)((input_index >> 8) & 0xFF);
    *ptr++ = (uint8_t)((input_index >> 16) & 0xFF);
    *ptr++ = (uint8_t)((input_index >> 24) & 0xFF);
    memcpy(ptr, leaf_hash, 32); ptr += 32;
    *ptr++ = 0x00;
    *ptr++ = 0xFF; *ptr++ = 0xFF; *ptr++ = 0xFF; *ptr++ = 0xFF;

    if (fkt_tagged_sha256("TapSighash", 10, preimage, (size_t)(ptr - preimage), sighash) != 0) {
        fkt_memzero(preimage, sizeof(preimage));
        fkt_memzero(leaf_hash, sizeof(leaf_hash));
        return -1;
    }
    fkt_memzero(preimage, sizeof(preimage));
    fkt_memzero(leaf_hash, sizeof(leaf_hash));
    return 0;
}

static size_t fkt_sighash_write_compact_size(uint8_t *out, uint64_t val) {
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

static size_t fkt_sighash_write_script(uint8_t *out,
                                       const uint8_t *script, size_t script_len) {
    size_t n = fkt_sighash_write_compact_size(out, (uint64_t)script_len);
    if (n == 0) return 0;
    memcpy(out + n, script, script_len);
    return n + script_len;
}

/* Classic P2PKH sighash (pre-segwit, SIGHASH_ALL). */
int fkt_legacy_p2pkh_sighash(int input_index,
                             const uint8_t *scriptpubkey, size_t scriptpubkey_len,
                             uint32_t sighash_type,
                             uint8_t sighash[32]) {
    uint8_t buf[4096];
    uint8_t *ptr = buf;
    const uint8_t *tx = psbt_data.raw_unsigned_tx;
    uint32_t nVersion;
    size_t n;
    int i, j;

    if (input_index < 0 || input_index >= psbt_data.num_inputs) return -1;
    if (scriptpubkey == NULL || scriptpubkey_len == 0 || scriptpubkey_len > 520)
        return -1;

    nVersion = (uint32_t)tx[0] | ((uint32_t)tx[1] << 8) |
               ((uint32_t)tx[2] << 16) | ((uint32_t)tx[3] << 24);

    *ptr++ = (uint8_t)(nVersion & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 24) & 0xFF);

    n = fkt_sighash_write_compact_size(ptr, (uint64_t)psbt_data.num_inputs);
    if (n == 0) return -1;
    ptr += n;

    for (i = 0; i < psbt_data.num_inputs; i++) {
        memcpy(ptr, psbt_data.input_txid[i], 32);
        ptr += 32;
        *ptr++ = (uint8_t)(psbt_data.input_vout[i] & 0xFF);
        *ptr++ = (uint8_t)((psbt_data.input_vout[i] >> 8) & 0xFF);
        *ptr++ = (uint8_t)((psbt_data.input_vout[i] >> 16) & 0xFF);
        *ptr++ = (uint8_t)((psbt_data.input_vout[i] >> 24) & 0xFF);

        if (i == input_index) {
            n = fkt_sighash_write_script(ptr, scriptpubkey, scriptpubkey_len);
            if (n == 0) return -1;
            ptr += n;
        } else {
            *ptr++ = 0x00;
        }

        *ptr++ = (uint8_t)(psbt_data.input_sequence[i] & 0xFF);
        *ptr++ = (uint8_t)((psbt_data.input_sequence[i] >> 8) & 0xFF);
        *ptr++ = (uint8_t)((psbt_data.input_sequence[i] >> 16) & 0xFF);
        *ptr++ = (uint8_t)((psbt_data.input_sequence[i] >> 24) & 0xFF);
    }

    n = fkt_sighash_write_compact_size(ptr, (uint64_t)psbt_data.num_outputs);
    if (n == 0) return -1;
    ptr += n;

    for (i = 0; i < psbt_data.num_outputs; i++) {
        int64_t amount = psbt_data.output_amount[i];
        for (j = 0; j < 8; j++)
            ptr[j] = (uint8_t)(amount >> (8 * j));
        ptr += 8;

        n = fkt_sighash_write_script(ptr,
                                     psbt_data.output_script[i],
                                     psbt_data.output_script_len[i]);
        if (n == 0) return -1;
        ptr += n;
    }

    *ptr++ = (uint8_t)(psbt_data.locktime & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.locktime >> 8) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.locktime >> 16) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.locktime >> 24) & 0xFF);

    *ptr++ = (uint8_t)(sighash_type & 0xFF);
    *ptr++ = (uint8_t)((sighash_type >> 8) & 0xFF);
    *ptr++ = (uint8_t)((sighash_type >> 16) & 0xFF);
    *ptr++ = (uint8_t)((sighash_type >> 24) & 0xFF);

    if ((size_t)(ptr - buf) > sizeof(buf)) return -1;
    fkt_sha256d(buf, (size_t)(ptr - buf), sighash);
    fkt_memzero(buf, sizeof(buf));
    return 0;
}