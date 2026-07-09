/* fkt_address.c – BIP84 / BIP86 receive address from BIP39 words (C89) */
#if !(defined(FKT_DOS) && FKT_DOS)
#define _POSIX_C_SOURCE 200809L
#endif
#include "fkt_address.h"
#include "fkt_bech32.h"
#include "fkt_bip32.h"
#include "fkt_hash160.h"
#include "fkt_pbkdf2.h"
#include "fkt_secp256k1.h"
#include "fkt_memzero.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <stdio.h>
#include <string.h>

int fkt_address_receive_from_words(const char words[][WORD_BUF], int num_words,
                                   int script_kind, int network, uint32_t index,
                                   char *addr_out, size_t addr_max,
                                   char *path_out, size_t path_max) {
    char mnemonic[512];
    uint8_t seed[64];
    uint8_t child_priv[32], child_pub33[33];
    char path[64];
    int pos = 0;
    int i;
    int coin;
    int purpose;
    const char *hrp;
    int rc = -1;
    static const uint8_t salt[8] = {
        'm', 'n', 'e', 'm', 'o', 'n', 'i', 'c'
    };

    if (!words || num_words < 12 || num_words > MAX_WORDS)
        return -1;
    if (!addr_out || addr_max < 14 || !path_out || path_max < 16)
        return -1;
    if (script_kind != 0 && script_kind != 1)
        return -1;
    if (network != 0 && network != 1)
        return -1;
    if (index > 0x7FFFFFFFu)
        return -1;

    purpose = (script_kind == 0) ? 84 : 86;
    coin = (network == 0) ? 0 : 1;
    hrp = (network == 0) ? "bc" : "tb";

    /* Build mnemonic string */
    for (i = 0; i < num_words; i++) {
        size_t wlen = strlen(words[i]);
        if (wlen == 0)
            return -1;
        if (i > 0) {
            if (pos + 1 >= (int)sizeof(mnemonic))
                return -1;
            mnemonic[pos++] = ' ';
        }
        if (pos + (int)wlen >= (int)sizeof(mnemonic))
            return -1;
        memcpy(mnemonic + pos, words[i], wlen);
        pos += (int)wlen;
    }
    mnemonic[pos] = '\0';

    snprintf(path, sizeof(path), "m/%d'/%d'/0'/0/%u", purpose, coin,
             (unsigned)index);
    if (strlen(path) + 1 > path_max)
        goto wipe;
    strcpy(path_out, path);

    fkt_pbkdf2_hmac_sha512(mnemonic, (size_t)pos, salt, 8, 2048, seed, 64);
    fkt_memzero(mnemonic, sizeof(mnemonic));

    fkt_secp256k1_init();
    if (fkt_derive_from_path(seed, path, child_priv, child_pub33, NULL) != 0)
        goto wipe;

    if (script_kind == 0) {
        uint8_t h20[20];
        fkt_hash160(child_pub33, 33, h20);
        if (fkt_bech32_encode_segwit(hrp, 0, h20, 20, addr_out, addr_max) != 0)
            goto wipe;
        fkt_memzero(h20, sizeof(h20));
        rc = 0;
    } else {
        /* BIP86: output key = internal xonly tweaked with TapTweak(internal) */
        secp256k1_context *ctx = fkt_secp256k1_ctx();
        secp256k1_keypair keypair;
        secp256k1_xonly_pubkey xonly;
        uint8_t internal[32];
        uint8_t tweak[32];
        uint8_t out_xonly[32];

        if (!ctx)
            goto wipe;
        if (!secp256k1_keypair_create(ctx, &keypair, child_priv))
            goto wipe;
        if (!secp256k1_keypair_xonly_pub(ctx, &xonly, NULL, &keypair))
            goto wipe;
        if (!secp256k1_xonly_pubkey_serialize(ctx, internal, &xonly))
            goto wipe;
        if (fkt_tagged_sha256("TapTweak", 8, internal, 32, tweak) != 0)
            goto wipe;
        if (!secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak))
            goto wipe;
        if (!secp256k1_keypair_xonly_pub(ctx, &xonly, NULL, &keypair))
            goto wipe;
        if (!secp256k1_xonly_pubkey_serialize(ctx, out_xonly, &xonly))
            goto wipe;
        if (fkt_bech32_encode_segwit(hrp, 1, out_xonly, 32, addr_out, addr_max) !=
            0)
            goto wipe;
        fkt_memzero(internal, sizeof(internal));
        fkt_memzero(tweak, sizeof(tweak));
        fkt_memzero(out_xonly, sizeof(out_xonly));
        rc = 0;
    }

wipe:
    fkt_memzero(seed, sizeof(seed));
    fkt_memzero(child_priv, sizeof(child_priv));
    fkt_memzero(child_pub33, sizeof(child_pub33));
    fkt_memzero(mnemonic, sizeof(mnemonic));
    return rc;
}
