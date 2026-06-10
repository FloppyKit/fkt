#ifndef FKT_RIPEMD160_H
#define FKT_RIPEMD160_H

#include <stddef.h>
#include "fkt_compat.h"   /* for uint8_t, etc. */

void fkt_ripemd160(const uint8_t *message, size_t len, uint8_t digest[20]);

#endif