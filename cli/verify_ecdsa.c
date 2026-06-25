/* verify_ecdsa.c – verify DER ECDSA signature against 32-byte sighash */
#include <stdio.h>
#include <string.h>
#include <secp256k1.h>

static int hex_decode(const char *hex, unsigned char *out, int max_out) {
    int len = (int)strlen(hex);
    int i;
    if (len % 2 != 0 || len / 2 > max_out) return -1;
    for (i = 0; i < len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return len / 2;
}

int main(int argc, char **argv) {
    unsigned char msg[32], pub[33], der[80];
    secp256k1_ecdsa_signature sig, norm;
    secp256k1_pubkey pubkey;
    secp256k1_context *ctx;
    int der_len;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s <sighash_hex> <pubkey_hex> <der_sig_hex>\n", argv[0]);
        return 2;
    }
    if (hex_decode(argv[1], msg, 32) != 32) return 1;
    if (hex_decode(argv[2], pub, 33) != 33) return 1;
    der_len = hex_decode(argv[3], der, (int)sizeof(der));
    if (der_len < 8) return 1;
    if (der[der_len - 1] == 0x01) der_len--;

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pub, 33)) {
        secp256k1_context_destroy(ctx);
        return 1;
    }
    if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, der, (size_t)der_len)) {
        secp256k1_context_destroy(ctx);
        return 1;
    }
    secp256k1_ecdsa_signature_normalize(ctx, &norm, &sig);
    if (secp256k1_ecdsa_verify(ctx, &sig, msg, &pubkey) ||
        secp256k1_ecdsa_verify(ctx, &norm, msg, &pubkey)) {
        secp256k1_context_destroy(ctx);
        return 0;
    }
    secp256k1_context_destroy(ctx);
    return 1;
}