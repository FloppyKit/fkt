/* fkt_bip32.c – BIP32 derivation + optional CKDpub for non‑hardened steps */
#include "fkt_secp256k1.h"
#include "fkt_bip32.h"
#include "fkt_sha512.h"
#include "fkt_hmac.h"
#include "fkt_compat.h"
#include <string.h>
#include <stdio.h>

#define FKT_BIP32_MAX_DEPTH 10

static void fkt_ser32_index(uint8_t out[4], uint32_t index) {
    out[0] = (uint8_t)((index >> 24) & 0xFF);
    out[1] = (uint8_t)((index >> 16) & 0xFF);
    out[2] = (uint8_t)((index >> 8) & 0xFF);
    out[3] = (uint8_t)(index & 0xFF);
}

void fkt_bip32_master(const uint8_t seed[64],
                      uint8_t master_priv[32],
                      uint8_t master_chain[32]) {
    uint8_t I[64];
    const char *key = "Bitcoin seed";
    fkt_hmac_sha512((const uint8_t*)key, 12, seed, 64, I);
    memcpy(master_priv, I, 32);
    memcpy(master_chain, I+32, 32);
    fkt_zerobytes(I, sizeof(I));
}

/* secp256k1 curve order (n) for modular addition */
static const uint8_t secp256k1_order[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

/* Add two 32‑byte big‑endian numbers mod n. result = (a + b) % n */
static void fkt_add_mod_n(uint8_t *result, const uint8_t *a, const uint8_t *b) {
    int i;
    uint32_t carry = 0;
    uint8_t sum[32];

    for (i = 31; i >= 0; i--) {
        uint32_t s = (uint32_t)a[i] + (uint32_t)b[i] + carry;
        sum[i] = (uint8_t)(s & 0xFF);
        carry = s >> 8;
    }

    if (carry || memcmp(sum, secp256k1_order, 32) >= 0) {
        int borrow = 0;
        for (i = 31; i >= 0; i--) {
            int diff = (int)sum[i] - (int)secp256k1_order[i] - borrow;
            if (diff < 0) {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[i] = (uint8_t)diff;
        }
    } else {
        memcpy(result, sum, 32);
    }
}

int fkt_bip32_derive_child(const uint8_t parent_priv[32],
                           const uint8_t parent_chain[32],
                           uint32_t index, int hardened,
                           uint8_t child_priv[32],
                           uint8_t child_chain[32]) {
    secp256k1_context *ctx = fkt_secp256k1_ctx();
    uint8_t data[37];
    uint8_t I[64];
    int i;

    if (!ctx) return -1;

    if (hardened) {
        data[0] = 0x00;
        memcpy(data + 1, parent_priv, 32);
    } else {
        secp256k1_pubkey parent_pub;
        uint8_t pub33[33];
        size_t pub33len = 33;

        if (!secp256k1_ec_pubkey_create(ctx, &parent_pub, parent_priv)) return -1;
        if (!secp256k1_ec_pubkey_serialize(ctx, pub33, &pub33len, &parent_pub, SECP256K1_EC_COMPRESSED)) return -1;
        memcpy(data, pub33, 33);
    }

    fkt_ser32_index(data + 33, index);
    fkt_hmac_sha512(parent_chain, 32, data, 37, I);
    memcpy(child_priv, I, 32);
    memcpy(child_chain, I+32, 32);
    fkt_add_mod_n(child_priv, child_priv, parent_priv);

    {
        volatile uint8_t *vp = (volatile uint8_t*)I;
        for (i = 0; i < 64; i++) vp[i] = 0;
    }

    return 0;
}

int fkt_ckdpub(const uint8_t parent_pub33[33],
               const uint8_t parent_chain[32],
               uint32_t index,
               uint8_t child_pub33[33],
               uint8_t child_chain[32])
{
    secp256k1_context *ctx = fkt_secp256k1_ctx();
    uint8_t data[37];
    uint8_t I[64];
    secp256k1_pubkey pub;
    int ret;
    size_t len = 33;

    if (!ctx) return -1;

    memcpy(data, parent_pub33, 33);
    fkt_ser32_index(data + 33, index);
    fkt_hmac_sha512(parent_chain, 32, data, 37, I);

    if (!secp256k1_ec_pubkey_parse(ctx, &pub, parent_pub33, 33)) return -1;
    ret = secp256k1_ec_pubkey_tweak_add(ctx, &pub, I);
    if (!ret) return -1;

    secp256k1_ec_pubkey_serialize(ctx, child_pub33, &len, &pub, SECP256K1_EC_COMPRESSED);
    memcpy(child_chain, I + 32, 32);

    return 0;
}

static int parse_path_string(const char *path_str,
                             uint32_t path[FKT_BIP32_MAX_DEPTH],
                             int *depth_out) {
    const char *p = path_str;
    int depth = 0;

    if (strncmp(path_str, "m/", 2) == 0)
        p = path_str + 2;

    while (*p) {
        uint32_t val = 0;
        int hard = 0;

        if (*p == '/') p++;
        if (*p == '\0') break;
        while (*p >= '0' && *p <= '9') {
            val = val * 10u + (uint32_t)(*p - '0');
            p++;
        }
        if (*p == '\'' || *p == 'h' || *p == 'H') {
            hard = 1;
            p++;
        }
        if (depth >= FKT_BIP32_MAX_DEPTH) return -1;
        path[depth] = hard ? (val | 0x80000000U) : val;
        depth++;
    }

    if (depth < 1) return -1;
    *depth_out = depth;
    return 0;
}

int fkt_derive_path(const uint8_t master_priv[32],
                    const uint8_t master_chain[32],
                    const uint32_t *path,
                    int depth,
                    uint8_t child_priv[32],
                    uint8_t child_pub33[33],
                    const uint8_t *parent_pub33)
{
    uint8_t priv[32], chain[32];
    int i;
    secp256k1_context *ctx = fkt_secp256k1_ctx();

    if (depth < 1 || depth > FKT_BIP32_MAX_DEPTH) return -1;

    memcpy(priv, master_priv, 32);
    memcpy(chain, master_chain, 32);

    for (i = 0; i < depth; i++) {
        uint8_t new_priv[32], new_chain[32];
        int hardened = (path[i] >= 0x80000000U) ? 1 : 0;
        if (fkt_bip32_derive_child(priv, chain, path[i], hardened, new_priv, new_chain) != 0)
            return -1;
        memcpy(priv, new_priv, 32);
        memcpy(chain, new_chain, 32);
    }
    memcpy(child_priv, priv, 32);

    if (parent_pub33 != NULL) {
        int first_nonhard = -1;
        uint8_t account_chain[32];
        int j;

        for (i = 0; i < depth; i++) {
            if ((path[i] & 0x80000000U) == 0) {
                first_nonhard = i;
                break;
            }
        }
        if (first_nonhard < 0) return -1;

        memcpy(priv, master_priv, 32);
        memcpy(chain, master_chain, 32);
        for (j = 0; j < first_nonhard; j++) {
            uint8_t new_priv[32], new_chain[32];
            if (fkt_bip32_derive_child(priv, chain, path[j], 1, new_priv, new_chain) != 0)
                return -1;
            memcpy(priv, new_priv, 32);
            memcpy(chain, new_chain, 32);
        }
        memcpy(account_chain, chain, 32);

        memset(priv, 0, 32);
        memcpy(chain, account_chain, 32);
        {
            uint8_t pub[33];
            memcpy(pub, parent_pub33, 33);
            for (i = first_nonhard; i < depth; i++) {
                uint8_t child_pub_tmp[33], child_chain_tmp[32];
                if (path[i] & 0x80000000U) return -1;
                if (fkt_ckdpub(pub, chain, path[i], child_pub_tmp, child_chain_tmp) != 0)
                    return -1;
                memcpy(pub, child_pub_tmp, 33);
                memcpy(chain, child_chain_tmp, 32);
            }
            memcpy(child_pub33, pub, 33);
        }
    } else {
        secp256k1_pubkey pubkey;
        size_t pub_len = 33;
        if (!ctx) return -1;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, child_priv)) return -1;
        if (!secp256k1_ec_pubkey_serialize(ctx, child_pub33, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED))
            return -1;
    }

    fkt_zerobytes(priv, 32);
    fkt_zerobytes(chain, 32);
    return 0;
}

int fkt_derive_from_path(const uint8_t seed[64],
                         const char *path_str,
                         uint8_t child_priv[32],
                         uint8_t child_pub33[33],
                         const uint8_t *parent_pub33)
{
    uint8_t master_priv[32], master_chain[32];
    uint32_t path[FKT_BIP32_MAX_DEPTH];
    int depth;

    if (parse_path_string(path_str, path, &depth) != 0)
        return -1;

    fkt_bip32_master(seed, master_priv, master_chain);
    if (fkt_derive_path(master_priv, master_chain, path, depth,
                        child_priv, child_pub33, parent_pub33) != 0) {
        fkt_zerobytes(master_priv, 32);
        fkt_zerobytes(master_chain, 32);
        return -1;
    }

    fkt_zerobytes(master_priv, 32);
    fkt_zerobytes(master_chain, 32);
    return 0;
}

int fkt_derive_from_indices(const uint8_t seed[64],
                            const uint32_t *path,
                            int depth,
                            uint8_t child_priv[32],
                            uint8_t child_pub33[33],
                            const uint8_t *parent_pub33)
{
    uint8_t master_priv[32], master_chain[32];

    if (!path || depth < 1 || depth > FKT_BIP32_MAX_DEPTH)
        return -1;

    fkt_bip32_master(seed, master_priv, master_chain);
    if (fkt_derive_path(master_priv, master_chain, path, depth,
                        child_priv, child_pub33, parent_pub33) != 0) {
        fkt_zerobytes(master_priv, 32);
        fkt_zerobytes(master_chain, 32);
        return -1;
    }

    fkt_zerobytes(master_priv, 32);
    fkt_zerobytes(master_chain, 32);
    return 0;
}
