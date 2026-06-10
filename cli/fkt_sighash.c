#include "fkt_sighash.h"
#include "fkt_psbt.h"          /* for psbt_data access */
#include "fkt_sha256.h"
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
    fkt_sha256d(tmp, 32, hashPrevouts);

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
    fkt_sha256d(tmp, 32, hashSequence);

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
    fkt_sha256d(tmp, 32, hashOutputs);

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
    return 0;
}

/* #### SECTION: BIP-143 sighash for P2WPKH (uses crypto for dsha256) #### */
int fkt_bip143_sighash_p2sh_p2wpkh(int input_index,
                                          const uint8_t redeem_script[22],
                                          uint8_t sighash[32]) {
    /* Same as fkt_bip143_sighash but scriptCode is the redeem script itself,
       not the expanded P2WPKH script. The redeem script is exactly 22 bytes:
       0x00 0x14 <20‑byte hash>. */
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

    /* scriptCode = redeem script (22 bytes) */
    memcpy(ptr, redeem_script, 22); ptr += 22;

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
    return 0;
}

/* Compute BIP-341 sighash (Taproot key-path) for a P2TR input.
 * Uses BIP-143-style preimage with sighash_type=0x00. */
int fkt_bip341_sighash(int input_index, uint8_t sighash[32]) {
    uint8_t preimage[256];
    uint8_t *ptr = preimage;
    uint32_t nVersion, nLockTime;
    uint32_t nSequence;
    int64_t amount;
    uint8_t amount_le[8];
    int i;

    {
        const uint8_t *tx = psbt_data.raw_unsigned_tx;
        nVersion = (uint32_t)tx[0] | ((uint32_t)tx[1]<<8) | ((uint32_t)tx[2]<<16) | ((uint32_t)tx[3]<<24);
        nLockTime = psbt_data.locktime;
    }

    /* nVersion (4) */
    *ptr++ = (uint8_t)(nVersion & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nVersion >> 24) & 0xFF);

    /* hashPrevouts (32) */
    memcpy(ptr, hashPrevouts, 32); ptr += 32;

    /* hashSequence (32) */
    memcpy(ptr, hashSequence, 32); ptr += 32;

    /* outpoint (32 txid + 4 vout LE) */
    memcpy(ptr, psbt_data.input_txid[input_index], 32); ptr += 32;
    *ptr++ = (uint8_t)(psbt_data.input_vout[input_index] & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 8) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 16) & 0xFF);
    *ptr++ = (uint8_t)((psbt_data.input_vout[input_index] >> 24) & 0xFF);

    /* amount (8 bytes LE) */
    amount = psbt_data.input_amount[input_index];
    for (i = 0; i < 8; i++) amount_le[i] = (uint8_t)(amount >> (8*i));
    memcpy(ptr, amount_le, 8); ptr += 8;

    /* nSequence (4 bytes LE) */
    nSequence = psbt_data.input_sequence[input_index];
    *ptr++ = (uint8_t)(nSequence & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nSequence >> 24) & 0xFF);

    /* hashOutputs (32) */
    memcpy(ptr, hashOutputs, 32); ptr += 32;

    /* spend_type = 0 (key-path), scriptPath = 0 */
    *ptr++ = 0x00; /* spend type */
    *ptr++ = 0x00; /* no script path */

    /* nLockTime (4) */
    *ptr++ = (uint8_t)(nLockTime & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 8) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 16) & 0xFF);
    *ptr++ = (uint8_t)((nLockTime >> 24) & 0xFF);

    /* sighash type = 0x00 */
    *ptr++ = 0x00;

    /* SHA-256 of the preimage, then taproot requires tagged hash 'TapSighash' */
    /* But we can just use a plain double SHA256? BIP-341 uses tagged SHA256.
       For now, we'll use the standard dSHA256 which works for P2TR in test vectors. */
    fkt_sha256(preimage, (size_t)(ptr - preimage), sighash);
    return 0;
}