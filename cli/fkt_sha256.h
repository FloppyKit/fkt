/* fkt_sha256.h */
#ifndef FKT_SHA256_H
#define FKT_SHA256_H
#include <stddef.h>
#include "fkt_compat.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} fkt_sha256_ctx;

void fkt_sha256_init(fkt_sha256_ctx *ctx);
void fkt_sha256_update(fkt_sha256_ctx *ctx, const uint8_t *data, size_t len);
void fkt_sha256_final(fkt_sha256_ctx *ctx, uint8_t digest[32]);
void fkt_sha256(const uint8_t *msg, size_t len, uint8_t digest[32]);
void fkt_sha256d(const uint8_t *msg, size_t len, uint8_t digest[32]);  /* double SHA‑256 */

#ifdef __cplusplus
}
#endif
#endif