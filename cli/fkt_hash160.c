#include "fkt_hash160.h"
#include "fkt_crypto.h"
#include "fkt_ripemd160.h"
#include <string.h>

void fkt_hash160(const uint8_t *message, size_t len, uint8_t digest[20]) {
    uint8_t sha[32];
    fkt_sha256(message, len, sha);
    fkt_ripemd160(sha, 32, digest);
}