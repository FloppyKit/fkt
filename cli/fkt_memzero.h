#ifndef FKT_MEMZERO_H
#define FKT_MEMZERO_H

#include "fkt_compat.h"
#include <stddef.h>

void fkt_memzero(volatile void *ptr, size_t len);

void fkt_memzero_register_seed(volatile uint8_t *seed, size_t len);
void fkt_memzero_register_mnemonic(volatile char *mnemonic, size_t len);
void fkt_memzero_register_words(volatile void *words, size_t len);
void fkt_memzero_register_b64(volatile void *buf, size_t len);

void fkt_memzero_wipe_all(void);
void fkt_memzero_install_sigint(void);

#endif