/* fkt_signer.h */
#ifndef FKT_SIGNER_H
#define FKT_SIGNER_H
#include <stdint.h>
#include "fkt_compat.h"
#ifdef __cplusplus
extern "C" {
#endif

int fkt_sign_psbt(const uint8_t seed[64], const char *path_str,
                  const char *psbt_file, const char *output_file);

#ifdef __cplusplus
}
#endif
#endif