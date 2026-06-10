/* fkt_hmac.h */
#ifndef FKT_HMAC_H
#define FKT_HMAC_H
#include <stddef.h>
#include "fkt_compat.h"
#ifdef __cplusplus
extern "C" {
#endif
void fkt_hmac_sha512(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[64]);
void fkt_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[32]);
#ifdef __cplusplus
}
#endif
#endif