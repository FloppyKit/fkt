/* fkt_bip32.h */
#ifndef FKT_BIP32_H
#define FKT_BIP32_H
#include <stddef.h>
#include <stdint.h>
#include "fkt_compat.h"
#ifdef __cplusplus
extern "C" {
#endif

void fkt_bip32_master(const uint8_t seed[64],
                      uint8_t master_priv[32],
                      uint8_t master_chain[32]);

int fkt_bip32_derive_child(const uint8_t parent_priv[32],
                           const uint8_t parent_chain[32],
                           uint32_t index, int hardened,
                           uint8_t child_priv[32],
                           uint8_t child_chain[32]);




int fkt_ckdpub(const uint8_t parent_pub33[33],
               const uint8_t parent_chain[32],
               uint32_t index,
               uint8_t child_pub33[33],
               uint8_t child_chain[32]);

int fkt_derive_path(const uint8_t master_priv[32],
                    const uint8_t master_chain[32],
                    const uint32_t *path,
                    int depth,
                    uint8_t child_priv[32],
                    uint8_t child_pub33[33],
                    const uint8_t *parent_pub33);

int fkt_derive_from_path(const uint8_t seed[64],
                         const char *path_str,
                         uint8_t child_priv[32],
                         uint8_t child_pub33[33],
                         const uint8_t *parent_pub33);

int fkt_derive_from_indices(const uint8_t seed[64],
                            const uint32_t *path,
                            int depth,
                            uint8_t child_priv[32],
                            uint8_t child_pub33[33],
                            const uint8_t *parent_pub33);

#ifdef __cplusplus
}
#endif
#endif
