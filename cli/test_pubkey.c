#include "fkt_secp256k1.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t priv[32] = {
        0xe8,0xf3,0x2e,0x5a,0x5f,0x10,0x5a,0x3a,
        0x4c,0xbf,0x4d,0x35,0x71,0xcf,0x2c,0x8c,
        0xf2,0x7a,0x64,0x29,0x95,0x8a,0x4b,0x55,
        0x56,0xd1,0xc0,0x7b,0x5a,0x3f,0x6f,0x2b
    };
    secp256k1_context *ctx = fkt_secp256k1_ctx();
    secp256k1_pubkey pub;
    uint8_t pub33[33]; size_t pub33len = 33;

    if (!secp256k1_ec_pubkey_create(ctx, &pub, priv)) {
        printf("pubkey creation failed\n");
        return 1;
    }
    secp256k1_ec_pubkey_serialize(ctx, pub33, &pub33len, &pub, SECP256K1_EC_COMPRESSED);
    {
        int i;
        printf("pubkey: ");
        for (i = 0; i < 33; i++) printf("%02x", pub33[i]);
        printf("\n");
    }
        printf("expected: 03aa27f55034bc2f78844068579b13687a619c2544e5784b283d169644548e15a8\n");
    return 0;
}
