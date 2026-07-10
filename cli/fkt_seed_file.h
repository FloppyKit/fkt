/* fkt_seed_file.h – encrypted BIP39 seed file (Warm only). */
#ifndef FKT_SEED_FILE_H
#define FKT_SEED_FILE_H

#include "fkt_compat.h"
#include "fkt_seed.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Magic "FKTSEED1" + AES-256-GCM + PBKDF2-HMAC-SHA512 key. */
#define FKT_SEED_FILE_MAGIC     "FKTSEED1"
#define FKT_SEED_FILE_VERSION   1
#define FKT_SEED_FILE_FLAG_PASS 0x01  /* passphrase was non-empty at save */

/*
 * Save mnemonic words to path.
 * passphrase may be "" (allowed with loud stderr warning for ritual machines).
 * Returns 0 ok, -1 fail (error string via fkt_last_error_set when possible).
 */
int fkt_seed_file_save(const char *path,
                       char words[MAX_WORDS][WORD_BUF], int num_words,
                       const char *passphrase);

/*
 * Load into words/num_words. passphrase must match save (or both empty).
 * Returns 0 ok, -1 fail.
 */
int fkt_seed_file_load(const char *path,
                       char words[MAX_WORDS][WORD_BUF], int *num_words,
                       const char *passphrase);

#ifdef __cplusplus
}
#endif
#endif
