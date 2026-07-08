/* fkt_qrgen_wrap.h - C89-safe facade to Nayuki encoder (fkt_qrgen.c) */
#ifndef FKT_QRGEN_WRAP_H
#define FKT_QRGEN_WRAP_H

#include "fkt_compat.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Encode bytes at temp[0..len-1]; write QR bitmap to out[]. Returns 0 or -1. */
int fkt_qrgen_encode_binary(uint8_t *temp, size_t len, uint8_t *out, int max_version);

/* Module grid width; 0 on invalid out[]. */
int fkt_qrgen_get_size(const uint8_t *qrcode);

/* 1 dark, 0 light; 0 if out of range or invalid. */
int fkt_qrgen_get_module(const uint8_t *qrcode, int x, int y);

#ifdef __cplusplus
}
#endif

#endif