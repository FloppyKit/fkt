/* fkt_sha512.h */
#ifndef FKT_SHA512_H
#define FKT_SHA512_H
#include <stddef.h>
#include "fkt_compat.h"
#ifdef __cplusplus
extern "C" {
#endif
void fkt_sha512(const uint8_t *msg, size_t len, uint8_t digest[64]);
#ifdef __cplusplus
}
#endif
#endif