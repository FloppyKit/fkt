/* fkt_util.c – secure zeroing helper */
#include "fkt_compat.h"
#include "fkt_memzero.h"
#include <stddef.h>

void fkt_zerobytes(volatile void *buf, size_t len) {
    fkt_memzero(buf, len);
}