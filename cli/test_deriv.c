#include "fkt_hmac.h"
#include "fkt_sha512.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    const char *key = "Bitcoin seed";
    const uint8_t seed[64] = {0};
    uint8_t I[64];
    int i;

    fkt_hmac_sha512((const uint8_t*)key, strlen(key), seed, 64, I);

    printf("HMAC output: ");
    for (i = 0; i < 64; i++) {
        printf("%02x", I[i]);
    }
    printf("\n");

    return 0;
}
