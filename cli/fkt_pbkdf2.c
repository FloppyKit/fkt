/* fkt_pbkdf2.c – PBKDF2-HMAC-SHA512 (BIP39), C89 */
#include "fkt_pbkdf2.h"
#include "fkt_hmac.h"
#include "fkt_memzero.h"
#include <string.h>

void fkt_pbkdf2_hmac_sha512(const char *pass, size_t passlen,
                            const uint8_t *salt, size_t saltlen,
                            int iterations,
                            uint8_t *out, size_t outlen) {
    uint8_t block[128 + 256];
    uint8_t U[64];
    uint8_t T[64];
    uint32_t block_index;
    size_t offset = 0;
    size_t to_copy;
    int i;
    int j;

    block_index = 1;
    while (offset < outlen) {
        memcpy(block, salt, saltlen);
        block[saltlen + 0] = (uint8_t)((block_index >> 24) & 0xFF);
        block[saltlen + 1] = (uint8_t)((block_index >> 16) & 0xFF);
        block[saltlen + 2] = (uint8_t)((block_index >> 8) & 0xFF);
        block[saltlen + 3] = (uint8_t)(block_index & 0xFF);

        fkt_hmac_sha512((const uint8_t *)pass, passlen,
                        block, saltlen + 4, U);
        memcpy(T, U, 64);

        for (i = 2; i <= iterations; i++) {
            fkt_hmac_sha512((const uint8_t *)pass, passlen, U, 64, U);
            for (j = 0; j < 64; j++)
                T[j] ^= U[j];
        }

        to_copy = outlen - offset;
        if (to_copy > 64) to_copy = 64;
        memcpy(out + offset, T, to_copy);
        offset += to_copy;
        block_index++;
    }
    fkt_memzero(block, sizeof(block));
    fkt_memzero(U, sizeof(U));
    fkt_memzero(T, sizeof(T));
}