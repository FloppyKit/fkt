#ifndef FKT_BIP39_H
#define FKT_BIP39_H

#include "fkt_compat.h"

#define FKT_BIP39_WORD_BUF 32

int fkt_bip39_word_index(const char *word);
int fkt_bip39_valid_word(const char *word);
int fkt_bip39_validate_checksum(const char words[][FKT_BIP39_WORD_BUF], int num_words);

#endif