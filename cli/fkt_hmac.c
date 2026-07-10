/* fkt_hmac.c – HMAC-SHA512 / HMAC-SHA256 (RFC 2104), C89 */
#include "fkt_hmac.h"
#include "fkt_sha512.h"
#include "fkt_sha256.h"
#include <string.h>

void fkt_hmac_sha512(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[64]) {
    uint8_t k[128];            /* padded key */
    uint8_t ipad[128], opad[128];
    uint8_t inner[64];
    uint8_t tmp[128 + 256];    /* enough for ipad+data or opad+inner */
    size_t i;

    /* if key is longer than block size, hash it first */
    if (key_len > 128) {
        fkt_sha512(key, key_len, k);
        key = k;
        key_len = 64;          /* SHA-512 output length */
    } else {
        memcpy(k, key, key_len);
    }
    /* pad with zeros up to 128 bytes */
    for (i = key_len; i < 128; i++) k[i] = 0;

    /* ipad = k xor 0x36, opad = k xor 0x5c */
    for (i = 0; i < 128; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    /* inner = SHA512(ipad || data) */
    memcpy(tmp, ipad, 128);
    memcpy(tmp + 128, data, data_len);
    fkt_sha512(tmp, 128 + data_len, inner);

    /* outer = SHA512(opad || inner) */
    memcpy(tmp, opad, 128);
    memcpy(tmp + 128, inner, 64);
    fkt_sha512(tmp, 192, out);
}

void fkt_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[32]) {
    uint8_t k[64];
    uint8_t ipad[64], opad[64];
    uint8_t inner[32];
    uint8_t tmp[64 + 256];
    size_t i;

    if (key_len > 64) {
        fkt_sha256(key, key_len, k);
        key = k;
        key_len = 32;
    } else {
        memcpy(k, key, key_len);
    }
    for (i = key_len; i < 64; i++) k[i] = 0;

    for (i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    memcpy(tmp, ipad, 64);
    memcpy(tmp + 64, data, data_len);
    fkt_sha256(tmp, 64 + data_len, inner);

    memcpy(tmp, opad, 64);
    memcpy(tmp + 64, inner, 32);
    fkt_sha256(tmp, 96, out);
}