#ifndef FKT_FINALIZER_H
#define FKT_FINALIZER_H

#include "fkt_compat.h"

#define FKT_MAX_PSBT_INPUTS 256

extern int fkt_signer_signed_inputs[FKT_MAX_PSBT_INPUTS];

void fkt_signer_clear_signed_inputs(void);

int fkt_psbt_finalize(const uint8_t seed[64], const char *path_override,
                      const uint8_t *parent_pub_override);

#endif