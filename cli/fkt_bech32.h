/* fkt_bech32.h – BIP-173 / BIP-350 encode (receive addresses only) */
#ifndef FKT_BECH32_H
#define FKT_BECH32_H

#include "fkt_compat.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Encode SegWit address.
 * witver: 0 for P2WPKH/P2WSH (bech32), 1 for P2TR (bech32m).
 * prog: witness program (20 or 32 bytes).
 * hrp: "bc" or "tb" (etc).
 * out: NUL-terminated, max ~90 chars; out_max >= 91 recommended.
 * Returns 0 on success, -1 on failure.
 */
int fkt_bech32_encode_segwit(const char *hrp, int witver,
                             const uint8_t *prog, size_t prog_len,
                             char *out, size_t out_max);

#ifdef __cplusplus
}
#endif
#endif
