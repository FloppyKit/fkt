/* fkt_address.h – derive BIP84/BIP86 receive addresses from BIP39 seed words */
#ifndef FKT_ADDRESS_H
#define FKT_ADDRESS_H

#include "fkt_compat.h"
#include "fkt_seed.h" /* MAX_WORDS, WORD_BUF */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* script_kind: 0 = BIP84 P2WPKH, 1 = BIP86 P2TR keypath
 * network:     0 = mainnet (bc), 1 = testnet (tb)
 * index:       receive chain m/.../0'/0/index
 *
 * On success writes NUL-terminated address and path strings.
 * Wipes all key material before return. Returns 0 or -1.
 */
int fkt_address_receive_from_words(const char words[][WORD_BUF], int num_words,
                                   int script_kind, int network, uint32_t index,
                                   char *addr_out, size_t addr_max,
                                   char *path_out, size_t path_max);

#ifdef __cplusplus
}
#endif
#endif
