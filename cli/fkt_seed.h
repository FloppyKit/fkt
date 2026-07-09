#ifndef FKT_SEED_H
#define FKT_SEED_H

#include "fkt_compat.h"

#define MAX_WORDS 24
#define WORD_BUF 32

int fkt_interactive_seed(char words[MAX_WORDS][WORD_BUF], int *num_words);
int fkt_verify_seed(char words[MAX_WORDS][WORD_BUF], int num_words);
int fkt_seed_from_string(const char *str, char words[MAX_WORDS][WORD_BUF], int *num_words);
int fkt_sign_psbt_from_words(const char *input_psbt, const char *output_psbt,
                             char words[MAX_WORDS][WORD_BUF], int num_words);

void fkt_secure_zero(void *ptr, size_t len);

#endif