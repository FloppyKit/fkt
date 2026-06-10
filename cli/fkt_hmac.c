#include "fkt_hmac.h"
#include "fkt_sha512.h"
#include <string.h>


/* =========================================================================
 * HMAC-SHA512 (RFC 2104)
 * ========================================================================= */
void fkt_hmac_sha512(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[64]) {
    uint8_t k[128] = {0};
    uint8_t ipad[128], opad[128];
    uint8_t inner[64];
    uint8_t temp[128 + 256]; /* stack, enough for our usage */

    if (key_len > 128) {
        fkt_sha512(key, key_len, k);
        key = k; key_len = 64;
    } else {
        memcpy(k, key, key_len);
    }

    {
        size_t i;
        for (i = 0; i < 128; i++) {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }
    }

    /* inner = SHA512(ipad || data) */
    {
        size_t inner_len = 128 + data_len;
        if (inner_len > sizeof(temp)) inner_len = sizeof(temp);
        memcpy(temp, ipad, 128);
        memcpy(temp + 128, data, data_len);
        fkt_sha512(temp, 128 + data_len, inner);
    }

    /* outer = SHA512(opad || inner) */
    {
        memcpy(temp, opad, 128);
        memcpy(temp + 128, inner, 64);
        fkt_sha512(temp, 192, out);
    }
}