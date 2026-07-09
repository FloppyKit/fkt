#ifndef FKT_BIP39_H
#define FKT_BIP39_H

#include "fkt_compat.h"

#define FKT_BIP39_WORD_BUF 32

int fkt_bip39_word_index(const char *word);
const char *fkt_bip39_word_at(int index);
int fkt_bip39_valid_word(const char *word);
/* Resolve full word, 1-2048 index, or unique 1-4 letter prefix into out_word. */
int fkt_bip39_resolve_token(const char *token, char out_word[FKT_BIP39_WORD_BUF]);
int fkt_bip39_validate_checksum(const char words[][FKT_BIP39_WORD_BUF], int num_words);
int fkt_bip39_from_entropy(const uint8_t *ent, int ent_len,
                           char words[][FKT_BIP39_WORD_BUF], int *num_words);

#endif