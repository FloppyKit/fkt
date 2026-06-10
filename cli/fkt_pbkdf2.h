/* fkt_pbkdf2.h */
#ifndef FKT_PBKDF2_H
#define FKT_PBKDF2_H
#include <stddef.h>
#include "fkt_compat.h"
#ifdef __cplusplus
extern "C" {
#endif
void fkt_pbkdf2_hmac_sha512(const char *pass, size_t passlen,
                            const uint8_t *salt, size_t saltlen,
                            int iterations,
                            uint8_t *out, size_t outlen);
#ifdef __cplusplus
}
#endif
#endif