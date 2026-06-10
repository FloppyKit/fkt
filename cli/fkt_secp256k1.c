#include "fkt_secp256k1.h"
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>

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

int fkt_schnorr_sign(const uint8_t privkey[32], const uint8_t msg[32],
                     uint8_t sig[64], int *sig_len) {
    secp256k1_context *ctx = fkt_secp256k1_ctx();
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ctx, &keypair, privkey))
        return -1;
    if (!secp256k1_schnorrsig_sign32(ctx, sig, msg, &keypair, NULL))
        return -1;
    *sig_len = 64;
    return 0;
}