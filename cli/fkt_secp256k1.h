/* fkt_secp256k1.h */
#ifndef FKT_SECP256K1_H
#define FKT_SECP256K1_H
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include "fkt_compat.h"
#ifdef __cplusplus
extern "C" {
#endif

void fkt_secp256k1_init(void);
secp256k1_context* fkt_secp256k1_ctx(void);
int fkt_schnorr_sign(const uint8_t privkey[32], const uint8_t msg[32],
                     uint8_t sig[64], int *sig_len);

#ifdef __cplusplus
}
#endif
#endif