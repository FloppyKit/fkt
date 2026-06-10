/* fkt_util.c – secure zeroing helper */
#include "fkt_compat.h"
#include <stddef.h>

void fkt_zerobytes(volatile void *buf, size_t len) {
    volatile uint8_t *p = (volatile uint8_t*)buf;
    size_t i;
    for (i = 0; i < len; i++) p[i] = 0;
}