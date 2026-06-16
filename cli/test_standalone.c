#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <secp256k1.h>

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pub;
    uint8_t priv[32] = {
        0xe8,0xf3,0x2e,0x5a,0x5f,0x10,0x5a,0x3a,
        0x4c,0xbf,0x4d,0x35,0x71,0xcf,0x2c,0x8c,
        0xf2,0x7a,0x64,0x29,0x95,0x8a,0x4b,0x55,
        0x56,0xd1,0xc0,0x7b,0x5a,0x3f,0x6f,0x2b
    };
    uint8_t pub33[33];
    size_t pub33len = 33;
    int i;

    if (!secp256k1_ec_seckey_verify(ctx, priv)) {
        printf("PRIVATE KEY INVALID\n");
        return 1;
    }
    if (!secp256k1_ec_pubkey_create(ctx, &pub, priv)) {
        printf("Pubkey creation failed\n");
        return 1;
    }
    secp256k1_ec_pubkey_serialize(ctx, pub33, &pub33len, &pub, SECP256K1_EC_COMPRESSED);
    printf("pubkey: ");
    for (i = 0; i < 33; i++) printf("%02x", pub33[i]);
    printf("\nexpected: 03aa27f55034bc2f78844068579b13687a619c2544e5784b283d169644548e15a8\n");

    secp256k1_context_destroy(ctx);
    return 0;
}
