#include "fkt_secp256k1.h"
#include "fkt_memzero.h"
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <string.h>

void fkt_secp256k1_init(void) {
    (void)fkt_secp256k1_ctx();
}

secp256k1_context* fkt_secp256k1_ctx(void) {
    static secp256k1_context *ctx = NULL;
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
    return ctx;
}

int fkt_tagged_sha256(const char *tag, size_t tag_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t hash[32]) {
    secp256k1_context *ctx = fkt_secp256k1_ctx();
    if (!ctx || !tag || !msg || !hash) return -1;
    if (!secp256k1_tagged_sha256(ctx, hash, (const unsigned char *)tag, tag_len,
                                 msg, msg_len))
        return -1;
    return 0;
}

static int fkt_keypair_for_internal_key(secp256k1_context *ctx,
                                        const uint8_t privkey[32],
                                        const uint8_t internal_key[32],
                                        secp256k1_keypair *keypair) {
    secp256k1_xonly_pubkey xonly_derived;
    uint8_t derived_xonly[32];
    uint8_t sk[32];

    memcpy(sk, privkey, 32);
    if (!secp256k1_keypair_create(ctx, keypair, sk))
        return -1;
    if (!secp256k1_keypair_xonly_pub(ctx, &xonly_derived, NULL, keypair))
        return -1;
    if (!secp256k1_xonly_pubkey_serialize(ctx, derived_xonly, &xonly_derived))
        return -1;
    if (memcmp(derived_xonly, internal_key, 32) == 0) {
        fkt_memzero(sk, 32);
        return 0;
    }

    if (!secp256k1_ec_seckey_negate(ctx, sk))
        return -1;
    if (!secp256k1_keypair_create(ctx, keypair, sk))
        return -1;
    if (!secp256k1_keypair_xonly_pub(ctx, &xonly_derived, NULL, keypair))
        return -1;
    if (!secp256k1_xonly_pubkey_serialize(ctx, derived_xonly, &xonly_derived))
        return -1;
    fkt_memzero(sk, 32);
    return memcmp(derived_xonly, internal_key, 32) == 0 ? 0 : -1;
}

int fkt_schnorr_sign(const uint8_t privkey[32], const uint8_t msg[32],
                     uint8_t sig[64], int *sig_len) {
    secp256k1_context *ctx = fkt_secp256k1_ctx();
    secp256k1_keypair keypair;
    uint8_t aux_rand[32];

    memset(aux_rand, 0, sizeof(aux_rand));
    if (!secp256k1_keypair_create(ctx, &keypair, privkey))
        return -1;
    if (!secp256k1_schnorrsig_sign32(ctx, sig, msg, &keypair, aux_rand))
        return -1;
    fkt_memzero(aux_rand, sizeof(aux_rand));
    *sig_len = 64;
    return 0;
}

int fkt_schnorr_sign_taproot(const uint8_t privkey[32], const uint8_t msg[32],
                             const uint8_t internal_key[32],
                             const uint8_t *merkle_root, size_t merkle_root_len,
                             uint8_t sig[64], int *sig_len) {
    secp256k1_context *ctx = fkt_secp256k1_ctx();
    secp256k1_keypair keypair;
    uint8_t tweak_input[64];
    uint8_t tweak[32];
    uint8_t aux_rand[32];
    size_t tweak_input_len;

    if (!ctx || !privkey || !msg || !internal_key || !sig || !sig_len)
        return -1;
    if (merkle_root_len > 32)
        return -1;

    if (fkt_keypair_for_internal_key(ctx, privkey, internal_key, &keypair) != 0)
        return -1;

    memcpy(tweak_input, internal_key, 32);
    tweak_input_len = 32;
    if (merkle_root != NULL && merkle_root_len > 0) {
        memcpy(tweak_input + 32, merkle_root, merkle_root_len);
        tweak_input_len += merkle_root_len;
    }

    if (fkt_tagged_sha256("TapTweak", 8, tweak_input, tweak_input_len, tweak) != 0)
        return -1;
    if (!secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak))
        return -1;

    memset(aux_rand, 0, sizeof(aux_rand));
    if (!secp256k1_schnorrsig_sign32(ctx, sig, msg, &keypair, aux_rand)) {
        fkt_memzero(aux_rand, sizeof(aux_rand));
        fkt_memzero(tweak, sizeof(tweak));
        fkt_memzero(tweak_input, sizeof(tweak_input));
        return -1;
    }
    fkt_memzero(aux_rand, sizeof(aux_rand));
    fkt_memzero(tweak, sizeof(tweak));
    fkt_memzero(tweak_input, sizeof(tweak_input));

    *sig_len = 64;
    return 0;
}