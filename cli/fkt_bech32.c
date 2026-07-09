/* fkt_bech32.c – BIP-173 bech32 + BIP-350 bech32m encode (C89) */
#include "fkt_bech32.h"
#include <string.h>

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = (uint8_t)(pre >> 25);
    return ((pre & 0x1ffffffu) << 5) ^
           (-((b >> 0) & 1) & 0x3b6a57b2u) ^
           (-((b >> 1) & 1) & 0x26508e6du) ^
           (-((b >> 2) & 1) & 0x1ea119fau) ^
           (-((b >> 3) & 1) & 0x3d4233ddu) ^
           (-((b >> 4) & 1) & 0x2a1462b3u);
}

static int convert_bits(const uint8_t *in, size_t inlen, int frombits, int tobits,
                        int pad, uint8_t *out, size_t *outlen, size_t outmax) {
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    size_t i;
    uint32_t maxv = (1u << tobits) - 1u;

    for (i = 0; i < inlen; i++) {
        acc = (acc << frombits) | in[i];
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            if (n >= outmax)
                return -1;
            out[n++] = (uint8_t)((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits) {
            if (n >= outmax)
                return -1;
            out[n++] = (uint8_t)((acc << (tobits - bits)) & maxv);
        }
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return -1;
    }
    *outlen = n;
    return 0;
}

int fkt_bech32_encode_segwit(const char *hrp, int witver,
                             const uint8_t *prog, size_t prog_len,
                             char *out, size_t out_max) {
    uint8_t data[65];
    size_t datalen = 0;
    uint32_t chk = 1;
    size_t i;
    size_t hrplen;
    uint32_t const_val;

    if (!hrp || !prog || !out || out_max < 14)
        return -1;
    if (witver < 0 || witver > 16)
        return -1;
    if (prog_len < 2 || prog_len > 40)
        return -1;
    /* BIP-173: v0 programs must be 20 or 32 bytes */
    if (witver == 0 && prog_len != 20 && prog_len != 32)
        return -1;

    hrplen = strlen(hrp);
    if (hrplen < 1 || hrplen > 83)
        return -1;

    data[0] = (uint8_t)witver;
    if (convert_bits(prog, prog_len, 8, 5, 1, data + 1, &datalen,
                     sizeof(data) - 1) != 0)
        return -1;
    datalen += 1;

    /* Expand HRP into checksum */
    for (i = 0; i < hrplen; i++) {
        unsigned char c = (unsigned char)hrp[i];
        if (c < 33 || c > 126)
            return -1;
        if (c >= 'A' && c <= 'Z')
            return -1; /* require lowercase HRP for encode */
        chk = bech32_polymod_step(chk) ^ (c >> 5);
    }
    chk = bech32_polymod_step(chk);
    for (i = 0; i < hrplen; i++) {
        unsigned char c = (unsigned char)hrp[i];
        chk = bech32_polymod_step(chk) ^ (c & 0x1f);
    }
    for (i = 0; i < datalen; i++)
        chk = bech32_polymod_step(chk) ^ data[i];
    for (i = 0; i < 6; i++)
        chk = bech32_polymod_step(chk);

    /* BIP-350: witver 0 uses bech32; witver != 0 uses bech32m */
    const_val = (witver == 0) ? 1u : 0x2bc830a3u;
    chk ^= const_val;

    if (hrplen + 1 + datalen + 6 + 1 > out_max)
        return -1;
    memcpy(out, hrp, hrplen);
    out[hrplen] = '1';
    for (i = 0; i < datalen; i++)
        out[hrplen + 1 + i] = CHARSET[data[i]];
    for (i = 0; i < 6; i++)
        out[hrplen + 1 + datalen + i] =
            CHARSET[(chk >> (5 * (5 - (int)i))) & 31];
    out[hrplen + 1 + datalen + 6] = '\0';
    return 0;
}
