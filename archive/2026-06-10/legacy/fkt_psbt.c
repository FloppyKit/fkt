/* fkt_psbt.c — FKT Floppy Kit PSBT signer v1.0 (strict C89 + Taproot debug) */
#include "fkt_compat.h"
#include "fkt_crypto.h"
#include "fkt_psbt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

extern secp256k1_context* ctx;

#ifdef DEBUG_PSBT
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}
#else
#define print_hex(label, data, len) ((void)0)
#endif

/* ---------- Varint helpers ---------- */
static uint64_t read_varint(const uint8_t **p, const uint8_t *end) {
    uint8_t v;
    if (*p >= end) return 0;
    v = **p; (*p)++;
    if (v < 0xfd) return v;
    if (v == 0xfd && *p + 2 <= end) {
        uint64_t r = (*p)[0] | ((*p)[1] << 8); *p += 2; return r;
    }
    if (v == 0xfe && *p + 4 <= end) {
        uint64_t r = (uint32_t)((*p)[0] | ((*p)[1]<<8) | ((*p)[2]<<16) | ((*p)[3]<<24));
        *p += 4; return r;
    }
    return 0;
}

static size_t varint_write(uint8_t *p, uint64_t v) {
    if (v < 0xfd) { p[0] = (uint8_t)v; return 1; }
    if (v <= 0xffff) { p[0] = 0xfd; p[1] = v & 0xff; p[2] = (v >> 8) & 0xff; return 3; }
    p[0] = 0xfe; p[1] = v & 0xff; p[2] = (v >> 8) & 0xff; p[3] = (v >> 16) & 0xff; p[4] = (v >> 24) & 0xff;
    return 5;
}

/* ---------- Parse BIP32 path (C89 safe) ---------- */
static int parse_path(const char *path, uint32_t *indices, size_t *count) {
    const char *p = path;
    uint32_t num;
    *count = 0;
    if (strlen(path) < 3 || p[0] != 'm' || p[1] != '/') return 0;
    p += 2;
    while (*p) {
        if (*count >= 10) return 0;
        num = 0;
        while (*p >= '0' && *p <= '9') {
            num = num * 10 + (uint32_t)(*p - '0');
            p++;
        }
        if (*p == '\'' || *p == 'h' || *p == 'H') {
            num |= 0x80000000;
            p++;
        }
        indices[(*count)++] = num;
        if (*p == '/') p++;
        else if (*p != '\0') return 0;
    }
    return 1;
}

/* ---------- BIP32 child key derivation (hardened + non‑hardened) ---------- */
int bip32_ckd(const uint8_t parent_priv[32], const uint8_t parent_chain[32],
              uint32_t index, uint8_t child_priv[32], uint8_t child_chain[32]) {
    uint8_t data[37], I[64];
    secp256k1_pubkey pk;
    size_t pub_len = 33;
    int hardened = (index & 0x80000000) != 0;

    if (hardened) {
        data[0] = 0x00;
        memcpy(data + 1, parent_priv, 32);
    } else {
        if (!secp256k1_ec_pubkey_create(ctx, &pk, parent_priv)) return 0;
        secp256k1_ec_pubkey_serialize(ctx, data, &pub_len, &pk, SECP256K1_EC_COMPRESSED);
    }
    data[pub_len]   = (uint8_t)(index >> 24);
    data[pub_len+1] = (uint8_t)(index >> 16);
    data[pub_len+2] = (uint8_t)(index >> 8);
    data[pub_len+3] = (uint8_t)index;

    fkt_hmac_sha512(parent_chain, 32, data, pub_len + 4, I);
    memcpy(child_chain, I + 32, 32);
    memcpy(child_priv, I, 32);                     /* IL */

    /* ALWAYS add parent key – BIP32 requires this for both hardened & non‑hardened */
    if (secp256k1_ec_seckey_tweak_add(ctx, child_priv, parent_priv) == 0)
        return 0;

    return 1;
}

/* ---------- BIP-143 preimage (P2WPKH/P2WSH) ----------                      */
/* sighash_type is the 32-bit value appended little-endian to the preimage    */
/* and whose low octet becomes the trailing wire byte of the DER signature.   */
/* The caller must resolve SIGHASH_DEFAULT (0) to SIGHASH_ALL (1) prior to    */
/* invocation. This routine implements only the single-flag (ALL) shape of    */
/* hashPrevouts / hashSequence / hashOutputs.                                 */
static int build_bip143_preimage(
    const uint8_t *tx, size_t tx_len,
    size_t input_index,
    uint64_t amount,
    const uint8_t *hash160,
    const uint8_t *redeem_script,
    uint64_t redeem_len,
    uint32_t sighash_type,
    uint8_t *preimage_out,
    size_t *preimage_len)
{
    const uint8_t *p = tx;
    const uint8_t *end = tx + tx_len;
    uint8_t hashPrevouts[32], hashSequence[32], hashOutputs[32];
    uint8_t *concat_buf;
    uint32_t version, n_inputs, n_outputs, locktime;
    uint8_t sh_base, sh_acp;
    size_t i;

    if (p + 4 > end) return 0;
    version = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    p += 4;

    n_inputs = (uint32_t)read_varint(&p, end);
    if (p == NULL || p > end) return 0;
    sh_base = (uint8_t)(sighash_type & 0x1fu);
    sh_acp = (uint8_t)(sighash_type & 0x80u);

    concat_buf = malloc(36 * n_inputs + 4 * n_inputs + (8 + 9 + 22) * 100 + 256);
    if (!concat_buf) return 0;

    {
        const uint8_t *q = p;
        uint8_t *c = concat_buf;
        for (i = 0; i < n_inputs; i++) {
            if (q + 36 > end) { free(concat_buf); return 0; }
            memcpy(c, q, 36); c += 36; q += 36;
            uint64_t script_len = read_varint(&q, end);
            q += script_len + 4;
        }
        fkt_sha256d(concat_buf, (size_t)(c - concat_buf), hashPrevouts);

    }

    {
        const uint8_t *q = p;
        uint8_t *c = concat_buf;
        for (i = 0; i < n_inputs; i++) {
            q += 36;
            uint64_t script_len = read_varint(&q, end);
            q += script_len;
            if (q + 4 > end) { free(concat_buf); return 0; }
            c[0] = q[0]; c[1] = q[1]; c[2] = q[2]; c[3] = q[3]; c += 4; q += 4;
        }
        if (sh_base == 0x03u) memset(hashSequence, 0, 32);
        else fkt_sha256d(concat_buf, (size_t)(c - concat_buf), hashSequence);
    }

    p = tx + 4;
    (void)read_varint(&p, end);
    for (i = 0; i < n_inputs; i++) {
        p += 36;
        uint64_t script_len = read_varint(&p, end);
        p += script_len + 4;
    }

    n_outputs = (uint32_t)read_varint(&p, end);
    if (sh_acp != 0u) { free(concat_buf); return 0; }
    if (sh_base == 0x02u) { free(concat_buf); return 0; }
    if (sh_base != 0x01u && sh_base != 0x03u) { free(concat_buf); return 0; }
    {
        const uint8_t *q = p;
        uint8_t *c = concat_buf;
        for (i = 0; i < n_outputs; i++) {
            if (q + 8 > end) { free(concat_buf); return 0; }
            uint64_t val = (uint64_t)q[0] | ((uint64_t)q[1]<<8) | ((uint64_t)q[2]<<16) | ((uint64_t)q[3]<<24) |
                          ((uint64_t)q[4]<<32) | ((uint64_t)q[5]<<40) | ((uint64_t)q[6]<<48) | ((uint64_t)q[7]<<56);
            q += 8;
            uint64_t script_len = read_varint(&q, end);
            const uint8_t *script = q; q += script_len;
            if (sh_base != 0x03u || i == input_index) {
                c[0] = val & 0xff; c[1] = (val>>8)&0xff; c[2] = (val>>16)&0xff; c[3] = (val>>24)&0xff;
                c[4] = (val>>32)&0xff; c[5] = (val>>40)&0xff; c[6] = (val>>48)&0xff; c[7] = (val>>56)&0xff; c += 8;
                c += varint_write(c, script_len);
                memcpy(c, script, script_len); c += script_len;
            }
        }
        if (sh_base == 0x03u && input_index >= n_outputs) {
            memset(hashOutputs, 0, 32);
        } else {
            fkt_sha256d(concat_buf, (size_t)(c - concat_buf), hashOutputs);
        }
        p = q;
    }

    if (p + 4 > end) { free(concat_buf); return 0; }
    locktime = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);

    {
        const uint8_t *q = tx + 4;
        (void)read_varint(&q, end);
        uint8_t prevout_hash[32];
        uint32_t prevout_index, sequence;
        for (i = 0; i < input_index; i++) {
            q += 36;
            uint64_t slen = read_varint(&q, end);
            q += slen + 4;
        }
        if (q + 36 > end) { free(concat_buf); return 0; }
        memcpy(prevout_hash, q, 32);
        prevout_index = (uint32_t)q[32] | ((uint32_t)q[33] << 8) | ((uint32_t)q[34] << 16) | ((uint32_t)q[35] << 24);
        q += 36;
        uint64_t slen = read_varint(&q, end);
        q += slen;
        if (q + 4 > end) { free(concat_buf); return 0; }
        sequence = (uint32_t)q[0] | ((uint32_t)q[1] << 8) | ((uint32_t)q[2] << 16) | ((uint32_t)q[3] << 24);

        uint8_t *out = preimage_out;
        out[0] = version & 0xff; out[1] = (version>>8)&0xff; out[2] = (version>>16)&0xff; out[3] = (version>>24)&0xff; out += 4;
        memcpy(out, hashPrevouts, 32); out += 32;
        memcpy(out, hashSequence, 32); out += 32;
        memcpy(out, prevout_hash, 32); out += 32;
        out[0] = prevout_index & 0xff; out[1] = (prevout_index>>8)&0xff; out[2] = (prevout_index>>16)&0xff; out[3] = (prevout_index>>24)&0xff; out += 4;

        if (redeem_script && redeem_len > 0) {
            out += varint_write(out, redeem_len);
            memcpy(out, redeem_script, redeem_len); out += redeem_len;
        } else {
            *out++ = 0x19; *out++ = 0x76; *out++ = 0xa9; *out++ = 0x14;
            memcpy(out, hash160, 20); out += 20;
            *out++ = 0x88; *out++ = 0xac;
        }

        out[0] = amount & 0xff; out[1] = (amount>>8)&0xff; out[2] = (amount>>16)&0xff; out[3] = (amount>>24)&0xff;
        out[4] = (amount>>32)&0xff; out[5] = (amount>>40)&0xff; out[6] = (amount>>48)&0xff; out[7] = (amount>>56)&0xff; out += 8;
        out[0] = sequence & 0xff; out[1] = (sequence>>8)&0xff; out[2] = (sequence>>16)&0xff; out[3] = (sequence>>24)&0xff; out += 4;
        memcpy(out, hashOutputs, 32); out += 32;
        out[0] = locktime & 0xff; out[1] = (locktime>>8)&0xff; out[2] = (locktime>>16)&0xff; out[3] = (locktime>>24)&0xff; out += 4;
        out[0] = (uint8_t)(sighash_type & 0xffu);
        out[1] = (uint8_t)((sighash_type >> 8) & 0xffu);
        out[2] = (uint8_t)((sighash_type >> 16) & 0xffu);
        out[3] = (uint8_t)((sighash_type >> 24) & 0xffu);
        out += 4;

        *preimage_len = (size_t)(out - preimage_out);
        free(concat_buf);
        return 1;
    }
}

/* ---------- BIP-341 key-path sighash ---------- */
static void hash_tagged(const char *tag, const uint8_t *data, size_t len, uint8_t out[32]) {
    uint8_t tag_hash[32];
    fkt_sha256((const uint8_t*)tag, strlen(tag), tag_hash);
    uint8_t buf[64 + 256];
    memcpy(buf, tag_hash, 32);
    memcpy(buf + 32, tag_hash, 32);
    memcpy(buf + 64, data, len);
    fkt_sha256(buf, 64 + len, out);
}

static int build_bip341_keypath_sighash(
    const uint8_t *tx, size_t tx_len,
    size_t input_index,
    uint64_t amount,
    const uint8_t *script_pubkey, size_t script_len,
    uint8_t sighash_type,          /* NEW PARAMETER */
    uint8_t sighash[32])
{
    const uint8_t *p = tx;
    const uint8_t *end = tx + tx_len;
    uint8_t hashPrevouts[32], hashAmounts[32], hashScriptPubKeys[32],
            hashSequences[32], hashOutputs[32];
    uint32_t version, locktime;
    uint64_t n_inputs;
    size_t i;
    uint8_t buf[36];   /* 36 bytes for a single outpoint */

    /* read version */
    if (p + 4 > end) return 0;
    version = (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
    p += 4;

    /* read number of inputs (single input expected) */
    n_inputs = read_varint(&p, end);
    if (n_inputs != 1) return 0;

    /* hashPrevouts: SHA256 of the single outpoint (36 bytes) */
    if (p + 36 > end) return 0;
    fkt_sha256(p, 36, hashPrevouts);
    print_hex("hashPrevouts", hashPrevouts, 32); 

    /* hashAmounts: SHA256 of the 8-byte amount (little endian) */
    fkt_sha256((const uint8_t*)&amount, 8, hashAmounts);
    print_hex("hashAmounts", hashAmounts, 32); 

    /* hashScriptPubKeys: SHA256 of the scriptPubKey */
    fkt_sha256(script_pubkey, script_len, hashScriptPubKeys);
    print_hex("hashScriptPubKeys", hashScriptPubKeys, 32);

    /* hashSequences: SHA256 of the single 4-byte sequence */
    {
        const uint8_t *q = p + 36;                  /* skip outpoint */
        uint64_t slen = read_varint(&q, end);       /* script length */
        q += slen;                                  /* skip script */
        if (q + 4 > end) return 0;
        fkt_sha256(q, 4, hashSequences);
        print_hex("hashSequences", hashSequences, 32);
    }

    /* hashOutputs: SHA256 of the serialized outputs */
    {
        const uint8_t *q = tx + 4;
        (void)read_varint(&q, end);          /* skip n_inputs */
        /* skip the single input */
        q += 36;                             /* outpoint */
        uint64_t slen = read_varint(&q, end);
        q += slen + 4;                       /* script + sequence */
        /* now q points to output count */
        uint64_t n_outputs = read_varint(&q, end);
        uint8_t outbuf[4096];
        size_t ooff = 0;
        for (i = 0; i < (size_t)n_outputs; i++) {
            if (q + 8 > end) return 0;
            memcpy(outbuf + ooff, q, 8); ooff += 8; q += 8;       /* amount */
            slen = read_varint(&q, end);
            if (q + slen > end) return 0;
            ooff += varint_write(outbuf + ooff, slen);            /* script length varint */
            memcpy(outbuf + ooff, q, slen); ooff += slen; q += slen; /* script */
        }
        fkt_sha256(outbuf, ooff, hashOutputs);
        print_hex("hashOutputs", hashOutputs, 32); 
    }

    /* locktime */
    {
        const uint8_t *l = tx + tx_len - 4;
        locktime = (uint32_t)l[0] | ((uint32_t)l[1]<<8) | ((uint32_t)l[2]<<16) | ((uint32_t)l[3]<<24);
    }

    /* build preimage */
    {
        uint8_t preimage[256];
        uint8_t *out = preimage;

        *out++ = sighash_type;                 /* hash type from PSBT */
        memcpy(out, &version, 4); out += 4;
        memcpy(out, &locktime, 4); out += 4;
        memcpy(out, hashPrevouts, 32); out += 32;
        memcpy(out, hashAmounts, 32); out += 32;
        memcpy(out, hashScriptPubKeys, 32); out += 32;
        memcpy(out, hashSequences, 32); out += 32;
        memcpy(out, hashOutputs, 32); out += 32;
        *out++ = 0x00;                         /* spend_type (no annex) */

        print_hex("TapSighash preimage", preimage, (size_t)(out - preimage)); 

        hash_tagged("TapSighash", preimage, (size_t)(out - preimage), sighash);
        print_hex("Sighash", sighash, 32);
        return 1;
    }
}
/* ---------- check that every input has a UTXO (0x00 or 0x01) ---------- */
static int all_inputs_have_utxo(const uint8_t *psbt, size_t psbt_len) {
    const uint8_t *pos = psbt + 5;  /* skip magic */
    const uint8_t *end = psbt + psbt_len;
    /* skip global map */
    while (pos < end && *pos != 0x00) {
        uint64_t klen = read_varint(&pos, end); pos += klen;
        uint64_t vlen = read_varint(&pos, end); pos += vlen;
    }
    if (pos >= end || *pos != 0x00) return 0;
    pos++;  /* global separator */
    while (pos < end && *pos != 0x00) {
        int has_utxo = 0;
        const uint8_t *scan = pos;
        while (scan < end && *scan != 0x00) {
            uint64_t kl = read_varint(&scan, end);
            const uint8_t *k = scan; scan += kl;
            uint64_t vl = read_varint(&scan, end);
            scan += vl;
            if (kl == 1 && (k[0] == 0x00 || k[0] == 0x01)) has_utxo = 1;
        }
        if (!has_utxo) return 0;
        /* advance pos to the next input separator */
        while (pos < end && *pos != 0x00) {
            uint64_t kl = read_varint(&pos, end); pos += kl;
            uint64_t vl = read_varint(&pos, end); pos += vl;
        }
        pos++;  /* skip input separator */
    }
    return 1;
}

/* ==================== MAIN PSBT SIGNER v1.0 (C89 + Sparrow-fixed) ==================== */


int fkt_psbt_sign(const uint8_t *psbt_in, size_t psbt_len,
                  const uint8_t *master_priv, const uint8_t *master_chain,
                  const char *fixed_path,
                  uint8_t **psbt_out, size_t *psbt_out_len) {

    const uint8_t *pos = psbt_in;
    const uint8_t *end = psbt_in + psbt_len;
    uint8_t *out = NULL;
    size_t out_len = 0;
    size_t input_index = 0;
    int use_fixed = 0;
    uint32_t master_fp = 0;              
    uint32_t fixed_indices[10];
    size_t fixed_count = 0;
    const uint8_t *global_tx_start = NULL;
    size_t global_tx_len = 0;
    uint32_t n_inputs_tx = 0;
    int signed_count = 0;

    /* Ensure secp256k1 context is available with sign + verify capabilities */
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }

    if (psbt_len < 5 || memcmp(psbt_in, "psbt\xff", 5) != 0) return FKT_ERR_INVALID_MAGIC;

    if (fixed_path && fixed_path[0] != '\0') {
        if (!parse_path(fixed_path, fixed_indices, &fixed_count))
            return FKT_ERR_PATH_PARSE;
        use_fixed = 1;
    }
    printf("🔧 Fixed path: %s, use_fixed=%d, fixed_count=%zu\n", fixed_path ? fixed_path : "(none)", use_fixed, fixed_count);
    out = malloc(psbt_len + 8192);
    {
        uint8_t m_pub[33], m_h160[20];
        size_t m_len = 33;
        secp256k1_pubkey m_pk;
        if (!secp256k1_ec_pubkey_create(ctx, &m_pk, master_priv)) {
            return FKT_ERR_MASTER_KEY;
        }
        secp256k1_ec_pubkey_serialize(ctx, m_pub, &m_len, &m_pk, SECP256K1_EC_COMPRESSED);
        fkt_hash160(m_pub, 33, m_h160);
        master_fp = ((uint32_t)m_h160[0] << 24) | ((uint32_t)m_h160[1] << 16) |
                    ((uint32_t)m_h160[2] << 8)  | ((uint32_t)m_h160[3]);

    }
    if (!out) return FKT_ERR_MALLOC;

    /* Global map copy */
    memcpy(out, psbt_in, 5); out_len = 5;
    pos = psbt_in + 5;
    while (pos < end && *pos != 0x00) {
        uint64_t klen = read_varint(&pos, end);
        const uint8_t *kptr = pos; pos += klen;
        uint64_t vlen = read_varint(&pos, end);
        const uint8_t *vptr = pos; pos += vlen;
        if (klen == 1 && kptr[0] == 0x00) {
            global_tx_start = vptr;
            global_tx_len = vlen;
        }
        out_len += varint_write(out + out_len, klen);
        memcpy(out + out_len, kptr, klen); out_len += klen;
        out_len += varint_write(out + out_len, vlen);
        memcpy(out + out_len, vptr, vlen); out_len += vlen;
    }
    out[out_len++] = 0x00;
    if (!global_tx_start) { free(out); return FKT_ERR_MISSING_GLOBAL_TX; }

    /* Extract exact number of inputs from the global transaction */
    {
        const uint8_t *txp = global_tx_start;
        if (txp + 4 > global_tx_start + global_tx_len) {
            free(out); return FKT_ERR_MISSING_GLOBAL_TX;
        }
        txp += 4;  /* skip version */
        n_inputs_tx = (uint32_t)read_varint(&txp, global_tx_start + global_tx_len);
    }

    pos++; 

    if (!all_inputs_have_utxo(psbt_in, psbt_len)) {
        printf("❌ PSBT is missing UTXO data for one or more inputs.\n");
        printf("   In Sparrow, enable \"Include UTXO data when creating PSBTs\"\n");
        printf("   and re‑export the unsigned transaction.\n");
        free(out);
        return FKT_ERR_MISSING_UTXO;
    }

    /* Process inputs (exactly n_inputs_tx times) */
    for (input_index = 0; input_index < n_inputs_tx; input_index++) {
        int orig_use_fixed = use_fixed;
        size_t orig_fixed_count = fixed_count;

        /* The input map must start with a non‑zero key (at least one entry) */
        if (pos >= end || *pos == 0x00) {
            /* invalid PSBT */
            free(out); return FKT_ERR_INVALID_MAGIC;
        }
        const uint8_t *input_start = pos;
        const uint8_t *scan = pos;
        const uint8_t *utxo_ptr = NULL;
        const uint8_t *deriv_ptr = NULL;
        uint64_t deriv_vlen = 0;
        const uint8_t *tap_internal_key = NULL;
        uint64_t taproot_script_len = 0;
        const uint8_t *taproot_script = NULL;
        uint64_t utxo_amount = 0;
        int is_taproot = 0;
        int can_sign = 0;
        int tap_signed = 0;
        uint8_t child_priv[32], child_chain[32];
        uint32_t sighash_type = 0x00;   /* default SIGHASH_DEFAULT, overridden by PSBT 0x03 */
        uint8_t saved_sig[72]; size_t saved_sig_len = 0;
        uint8_t internal_xonly[32] = {0};
        uint8_t tweaked_outkey[32] = {0}; 
        uint8_t der_sig[72]; size_t der_sig_len = 0;
        uint8_t der_pub[33]; size_t der_pub_len = 33;
        uint8_t der_h160[20];
        const uint8_t *redeem_script = NULL;
        uint64_t redeem_len = 0;
        const uint8_t *p2sh_redeem_script = NULL;   /* PSBT 0x04 (capture only) */
        uint64_t p2sh_redeem_len = 0;
        const uint8_t *tap_deriv_ptr = NULL;        /* PSBT 0x16 value */
        uint64_t tap_deriv_vlen = 0;

        /* Parse input map */
        printf("--- Input #%zu raw map ---\n", input_index);
        while (scan < end && *scan != 0x00) {
            const uint8_t *temp = scan;
            uint64_t kl = read_varint(&temp, end);
            const uint8_t *k = temp; temp += kl;
            uint64_t vl = read_varint(&temp, end);
            const uint8_t *v = temp; temp += vl;
            {
                size_t ki;
                printf("  key len=%llu, type=0x%02x, val len=%llu\n",
                       (unsigned long long)kl, kl>0 ? k[0] : 0, (unsigned long long)vl);
                printf("  key bytes: "); for (ki=0; ki<kl; ki++) printf("%02x", k[ki]); printf("\n");
            }

            if (kl == 1 && k[0] == 0x00) utxo_ptr = v;
            else if (kl == 1 && k[0] == 0x01) utxo_ptr = v;   
            else if (kl == 34 && k[0] == 0x06) {
                /* BIP-174 stores the BIP-32 fingerprint as the first four    */
                /* bytes of HASH160(master_pubkey) in network byte order.     */
                /* master_fp at fkt_psbt.c:436 is packed big-endian; match it.*/
                uint32_t fp = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16) |
                              ((uint32_t)v[2] <<  8) |  (uint32_t)v[3];
                if (fp == master_fp || fp == 0) {
                    deriv_ptr = v; deriv_vlen = vl;
                }
            } else if (kl == 1 && k[0] == 0x04) {
                /* PSBT_IN_REDEEM_SCRIPT - captured for V1.5 P2SH wraps. */
                /* Not threaded into BIP-143 script_code on purpose.     */
                p2sh_redeem_script = v;
                p2sh_redeem_len   = vl;
            } else if (kl == 1 && k[0] == 0x05) {
                redeem_script = v; redeem_len = vl;
                taproot_script = v; taproot_script_len = vl;
            } else if (kl >= 33 && k[0] == 0x16) {
                tap_internal_key = (kl > 1) ? (k + 1) : NULL;
                is_taproot = 1;
                tap_deriv_ptr = v;
                tap_deriv_vlen = vl;
            } else if (kl == 1 && k[0] == 0x17) {
                tap_internal_key = v;
                is_taproot = 1;
            } else if (kl == 1 && k[0] == 0x03) {
                /* Read the sighash type the PSBT asks for */
                if (vl == 4) {
                    sighash_type = (uint32_t)v[0] | ((uint32_t)v[1]<<8) | ((uint32_t)v[2]<<16) | ((uint32_t)v[3]<<24);
                } else if (vl == 1) {
                    sighash_type = v[0];
                }
            }
            scan = temp;
        }
        printf("--- end input map ---\n");
        /* DEBUG: show what we captured from the input map */
        printf("🔧 Input #%lu: utxo_ptr=%p, tap_internal_key=%p, is_taproot=%d\n",
               (unsigned long)input_index, (void*)utxo_ptr,
               (void*)tap_internal_key, is_taproot);
        (void)p2sh_redeem_script; (void)p2sh_redeem_len;  /* reserved for V1.5 */

        /* Taproot key-path auto-detect: scriptPubKey 51 20 <32B> + 0x16/0x17. */
        /* Populates fixed_indices from PSBT 0x16 so the existing manual-      */
        /* derivation block runs unmodified.                                   */
        if (!use_fixed && is_taproot && tap_deriv_ptr && tap_deriv_vlen >= 5 && utxo_ptr) {
            const uint8_t *up = utxo_ptr;
            uint64_t spk_len;
            const uint8_t *spk;
            up += 8;                                  /* skip 8-byte amount */
            spk_len = read_varint(&up, end);
            spk = up;
            if (spk_len == 34 && spk + 34 <= end && spk[0] == 0x51 && spk[1] == 0x20) {
                const uint8_t *tdp   = tap_deriv_ptr;
                const uint8_t *tvend = tap_deriv_ptr + tap_deriv_vlen;
                uint64_t leaf_count  = read_varint(&tdp, tvend);
                if (leaf_count == 0 && tdp + 4 <= tvend) {
                    uint32_t tap_fp = ((uint32_t)tdp[0] << 24) | ((uint32_t)tdp[1] << 16) |
                                      ((uint32_t)tdp[2] <<  8) |  (uint32_t)tdp[3];
                    if (tap_fp == master_fp || tap_fp == 0) {
                        size_t path_bytes;
                        size_t num;
                        tdp += 4;
                        path_bytes = (size_t)(tvend - tdp);
                        num = path_bytes / 4;
                        if (num > 0 && num <= 10 && (path_bytes & 3u) == 0u) {
                            size_t kk;
                            for (kk = 0; kk < num; kk++) {
                                fixed_indices[kk] = (uint32_t)tdp[kk*4]              |
                                                    ((uint32_t)tdp[kk*4 + 1] <<  8)  |
                                                    ((uint32_t)tdp[kk*4 + 2] << 16)  |
                                                    ((uint32_t)tdp[kk*4 + 3] << 24);
                            }
                            fixed_count = num;
                            use_fixed = 1;
                            printf("Auto-detected Taproot key-path; using PSBT-supplied derivation.\n");
                        }
                    }
                }
            }
        }

        /* ----- TAPROOT KEY‑PATH (manual derivation) ----- */
        if (use_fixed && fixed_count > 0 && utxo_ptr) {
            uint8_t utxo_script[128];
            size_t utxo_script_len = 0;
            {
                const uint8_t *up = utxo_ptr;
                up += 8;
                uint64_t slen = read_varint(&up, end);
                if (up + slen <= end) {
                    if (slen > sizeof(utxo_script)) slen = sizeof(utxo_script);
                    memcpy(utxo_script, up, slen);
                    utxo_script_len = (size_t)slen;
                }
            }

            {
                uint8_t tmp_priv[32], tmp_chain[32];
                size_t i;
                int derive_ok = 1;
                memcpy(tmp_priv, master_priv, 32);
                memcpy(tmp_chain, master_chain, 32);
                for (i = 0; i < fixed_count && derive_ok; i++) {
                    uint8_t next_priv[32], next_chain[32];
                    if (!bip32_ckd(tmp_priv, tmp_chain, fixed_indices[i], next_priv, next_chain)) {
                        derive_ok = 0;
                        break;
                    }
                    memcpy(tmp_priv, next_priv, 32);
                    memcpy(tmp_chain, next_chain, 32);
                }

#ifdef DEBUG_PSBT
                printf("Derivation %s\n", derive_ok ? "OK" : "FAILED");
#endif

                printf("Master fingerprint: %08x\n", master_fp);

                if (derive_ok) {
                    secp256k1_pubkey pk;
                    secp256k1_xonly_pubkey xonly;
                    if (secp256k1_ec_pubkey_create(ctx, &pk, tmp_priv) &&
                        secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, NULL, &pk)) {
                        uint8_t derived_internal[32];
                        secp256k1_xonly_pubkey_serialize(ctx, derived_internal, &xonly);

#ifdef DEBUG_PSBT
                        {
                            size_t dj;
                            printf("Derived internal key: ");
                            for (dj = 0; dj < 32; dj++) printf("%02x", derived_internal[dj]);
                            printf("\nExpected (PSBT):     ");
                            if (tap_internal_key) {
                                for (dj = 0; dj < 32; dj++) printf("%02x", tap_internal_key[dj]);
                            } else {
                                printf("(none)");
                            }
                            printf("\n");
                        }
#endif

                        if (tap_internal_key &&
                            memcmp(derived_internal, tap_internal_key, 32) != 0) {
#ifdef DEBUG_PSBT
                            printf("Key mismatch – will not sign\n");
#endif
                            can_sign = 0;
                        } else {
                            memcpy(internal_xonly, derived_internal, 32);
                            memcpy(child_priv, tmp_priv, 32);
{
    size_t ki;
    printf("Child privkey: ");
    for (ki = 0; ki < 32; ki++) printf("%02x", tmp_priv[ki]);
    printf("\n");
}
                            memcpy(child_chain, tmp_chain, 32);
                            taproot_script = utxo_script;
                            taproot_script_len = utxo_script_len;
                            is_taproot = 1;
                            can_sign = 1;
                        }
            {
                size_t ui;
                printf("UTXO script: ");
                for (ui = 0; ui < utxo_script_len; ui++) printf("%02x", utxo_script[ui]);
                printf("\n");
            }
                    } else {
#ifdef DEBUG_PSBT
                        printf("secp256k1_ec_pubkey_create failed\n");
#endif
                        can_sign = 0;
                    }
                } else {
                    can_sign = 0;
                }
            }
        }

        /* ----- SIGNING BLOCK (Taproot or P2WPKH) ----- */
        if (is_taproot && can_sign) {
            const uint8_t *p = utxo_ptr;
            utxo_amount = (uint64_t)p[0] | ((uint64_t)p[1]<<8) | ((uint64_t)p[2]<<16) | ((uint64_t)p[3]<<24) |
                          ((uint64_t)p[4]<<32) | ((uint64_t)p[5]<<40) | ((uint64_t)p[6]<<48) | ((uint64_t)p[7]<<56);
            printf("UTXO amount: %llu satoshis\n", (unsigned long long)utxo_amount);
            {
                size_t x;
                printf("Global TX hex (%zu bytes): ", global_tx_len);
                for (x = 0; x < global_tx_len; x++) printf("%02x", global_tx_start[x]);
                printf("\n");
            }

            {
                uint8_t sighash[32];
                 if (build_bip341_keypath_sighash(global_tx_start, global_tx_len, input_index,
                                 utxo_amount, taproot_script, taproot_script_len,
                                 (uint8_t)sighash_type, sighash)) {
                    secp256k1_keypair keypair;
                    if (secp256k1_keypair_create(ctx, &keypair, child_priv)) {
                        uint8_t tweak[32];
                        hash_tagged("TapTweak", internal_xonly, 32, tweak);
                        if (secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak)) {
                            secp256k1_xonly_pubkey twk_pub;
                            secp256k1_keypair_xonly_pub(ctx, &twk_pub, NULL, &keypair);
                            secp256k1_xonly_pubkey_serialize(ctx, tweaked_outkey, &twk_pub);
                            { size_t i; printf("Tweaked outkey: "); for (i=0; i<32; i++) printf("%02x", tweaked_outkey[i]); printf("\n"); }
                            printf("Tweaked outkey: ");
                            for (int i = 0; i < 32; i++) printf("%02x", tweaked_outkey[i]);
                            printf("\n");
                            uint8_t sig[64];
                            if (secp256k1_schnorrsig_sign32(ctx, sig, sighash, &keypair, NULL)) {
                              
                                memcpy(saved_sig, sig, 64);
                                saved_sig_len = 64;
                                tap_signed = 1;
                                printf("✅ Taproot Schnorr signature created\n");

                                /* verify using the already-extracted tweaked pubkey twk_pub */
                                if (secp256k1_schnorrsig_verify(ctx, sig, sighash, 32, &twk_pub)) {
                                    printf("✅ Local signature verification PASSED\n");
                                } else {
                                    printf("❌ Local signature verification FAILED\n");
                                    {
                                        size_t dj;
                                        printf("Internal xonly: ");
                                        for (dj = 0; dj < 32; dj++) printf("%02x", internal_xonly[dj]);
                                        printf("\nTweak:         ");
                                        for (dj = 0; dj < 32; dj++) printf("%02x", tweak[dj]);
                                        printf("\nTweaked pubkey: ");
                                        for (dj = 0; dj < 32; dj++) printf("%02x", tweaked_outkey[dj]);
                                        printf("\nSighash:       ");
                                        for (dj = 0; dj < 32; dj++) printf("%02x", sighash[dj]);
                                        printf("\nSignature:     ");
                                        for (dj = 0; dj < 64; dj++) printf("%02x", sig[dj]);
                                        printf("\n");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if (utxo_ptr && deriv_ptr && !is_taproot) {
            size_t num_indices = (deriv_vlen - 4) / 4;
            uint32_t *indices = malloc(num_indices * sizeof(uint32_t));
            if (indices) {
                size_t j;
                for (j = 0; j < num_indices; j++) {
                    indices[j] = (uint32_t)deriv_ptr[4 + j*4] | ((uint32_t)deriv_ptr[4 + j*4 + 1] << 8) |
                                 ((uint32_t)deriv_ptr[4 + j*4 + 2] << 16) | ((uint32_t)deriv_ptr[4 + j*4 + 3] << 24);
                }
                memcpy(child_priv, master_priv, 32);
                memcpy(child_chain, master_chain, 32);
                can_sign = 1;
                for (j = 0; j < num_indices && can_sign; j++) {
                    uint8_t next_priv[32], next_chain[32];
                    if (!bip32_ckd(child_priv, child_chain, indices[j], next_priv, next_chain)) {
                        can_sign = 0; break;
                    }
                    memcpy(child_priv, next_priv, 32);
                    memcpy(child_chain, next_chain, 32);
                }
                free(indices);
            }
            if (can_sign) {
                secp256k1_pubkey pk;
                secp256k1_ec_pubkey_create(ctx, &pk, child_priv);
                secp256k1_ec_pubkey_serialize(ctx, der_pub, &der_pub_len, &pk, SECP256K1_EC_COMPRESSED);
                fkt_hash160(der_pub, 33, der_h160);
                {
                    const uint8_t *p = utxo_ptr;
                    uint64_t amount = (uint64_t)p[0] | ((uint64_t)p[1]<<8) | ((uint64_t)p[2]<<16) | ((uint64_t)p[3]<<24) |
                                      ((uint64_t)p[4]<<32) | ((uint64_t)p[5]<<40) | ((uint64_t)p[6]<<48) | ((uint64_t)p[7]<<56);
                    uint8_t preimage[1024]; size_t preimage_len;
                    /* PSBT 0x03 absent: default to SIGHASH_ALL. SIGHASH_DEFAULT */
                    /* (0) is undefined for witness v0 ECDSA per BIP-143.        */
                    uint32_t effective_sighash = (sighash_type == 0u) ? 0x00000001u : sighash_type;
                    if (build_bip143_preimage(global_tx_start, global_tx_len, input_index, amount,
                                              der_h160, redeem_script, redeem_len,
                                              effective_sighash, preimage, &preimage_len)) {
                        uint8_t sighash[32];
                        fkt_sha256d(preimage, preimage_len, sighash);
                        if (fkt_ecdsa_sign(child_priv, sighash, der_sig, &der_sig_len)) {
                            der_sig[der_sig_len++] = (uint8_t)(effective_sighash & 0xffu);
                        } else can_sign = 0;
                    } else can_sign = 0;
                }
            }
        }

        /* Rebuild input map */
        scan = input_start;
        while (scan < end && *scan != 0x00) {
            const uint8_t *temp = scan;
            uint64_t kl = read_varint(&temp, end);
            const uint8_t *k = temp; temp += kl;
            uint64_t vl = read_varint(&temp, end);
            const uint8_t *v = temp; temp += vl;
            int skip = 0;
            if (tap_signed || can_sign) {
                if (k[0] == 0x13 || k[0] == 0x17 || k[0] == 0x08) skip = 1;
                if (kl == 34 && k[0] == 0x02) skip = 1;
            }
            if (!skip) {
                out_len += varint_write(out + out_len, kl);
                memcpy(out + out_len, k, kl); out_len += kl;
                out_len += varint_write(out + out_len, vl);
                memcpy(out + out_len, v, vl); out_len += vl;
            }
            scan = temp;
        }
        print_hex("Derived internal xonly", internal_xonly, 32);

          /* Append signatures in strict key-type order (03, 08, 13, 17)no 0x07, 0x03, 0x13, 0x17 */
        if (tap_signed) {
             /* 0x08 — Final Script Witness for Taproot key-path (BIP‑341) */
            {
                uint8_t wit_buf[128]; size_t wit_pos = 0;
                size_t sig_item_len = (sighash_type == 0x00) ? 64 : 65;
                wit_buf[wit_pos++] = 1;                    /* 1 stack item */
                wit_pos += varint_write(wit_buf + wit_pos, sig_item_len);
                memcpy(wit_buf + wit_pos, saved_sig, 64); wit_pos += 64;
                if (sighash_type != 0x00) {
                    wit_buf[wit_pos++] = (uint8_t)sighash_type;   /* append the type byte */
                }
                out[out_len++] = 1; out[out_len++] = 0x08; /* key */
                out_len += varint_write(out + out_len, wit_pos);
                memcpy(out + out_len, wit_buf, wit_pos); out_len += wit_pos;
            }
            printf("✅ Taproot PSBT fields written (08 only)\n");

        } else if (can_sign && !is_taproot) {
            out[out_len++] = 34; out[out_len++] = 0x02;
            memcpy(out + out_len, der_pub, 33); out_len += 33;
            out_len += varint_write(out + out_len, der_sig_len);
            memcpy(out + out_len, der_sig, der_sig_len); out_len += der_sig_len;

            {
                uint8_t wit_buf[256]; size_t wit_pos = 0;
                wit_buf[wit_pos++] = 2;
                wit_pos += varint_write(wit_buf + wit_pos, der_sig_len);
                memcpy(wit_buf + wit_pos, der_sig, der_sig_len); wit_pos += der_sig_len;
                wit_pos += varint_write(wit_buf + wit_pos, 33);
                memcpy(wit_buf + wit_pos, der_pub, 33); wit_pos += 33;
                out[out_len++] = 1; out[out_len++] = 0x08;
                out_len += varint_write(out + out_len, wit_pos);
                memcpy(out + out_len, wit_buf, wit_pos); out_len += wit_pos;
            }
        }

        out[out_len++] = 0x00;

        while (pos < end && *pos != 0x00) {
            uint64_t kl = read_varint(&pos, end); pos += kl;
            uint64_t vl = read_varint(&pos, end); pos += vl;
        }

        if (tap_signed || (!is_taproot && can_sign)) signed_count++;

        /* Restore per-input auto-detect state */
        use_fixed   = orig_use_fixed;
        fixed_count = orig_fixed_count;

        pos++;   /* skip the input separator */
    }

    /* copy remaining output maps + final 0x00 */
    {
        size_t remaining = end - pos;
        if (remaining > 0) {
            memcpy(out + out_len, pos, remaining);
            out_len += remaining;
  
        }
    }

    *psbt_out = out;
    *psbt_out_len = out_len;
    return signed_count;
}