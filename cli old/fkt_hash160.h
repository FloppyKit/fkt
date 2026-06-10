#ifndef FKT_HASH160_H
#define FKT_HASH160_H

#include <stddef.h>
#include "fkt_compat.h"   /* uint8_t */

void fkt_hash160(const uint8_t *message, size_t len, uint8_t digest[20]);

#endif