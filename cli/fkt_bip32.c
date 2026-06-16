#include "fkt_secp256k1.h"
#include "fkt_bip32.h"
#include "fkt_sha512.h"
#include "fkt_hmac.h"
#include "fkt_compat.h"
#include <string.h>
#include <stdio.h>


/* =========================================================================
 * BIP32 master key derivation
 * ========================================================================= */
void fkt_bip32_master(const uint8_t seed[64],
                      uint8_t master_priv[32],
                      uint8_t master_chain[32]) {
    uint8_t I[64];
    const char *key = "Bitcoin seed";
    fkt_hmac_sha512((const uint8_t*)key, 12, seed, 64, I);
    memcpy(master_priv, I, 32);
    memcpy(master_chain, I+32, 32);
    {
        int i;
        printf("DEBUG: master_priv = ");
        for (i = 0; i < 32; i++) printf("%02x", master_priv[i]);
        printf("\nDEBUG: master_chain = ");
        for (i = 0; i < 32; i++) printf("%02x", master_chain[i]);
        printf("\n");
    }
    fkt_zerobytes(I, sizeof(I));
}
/* secp256k1 curve order (n) for modular addition */
static const uint8_t secp256k1_order[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

/* Add two 32‑byte big‑endian numbers mod n. result = (a + b) % n */
static void fkt_add_mod_n(uint8_t *result, const uint8_t *a, const uint8_t *b) {
    int i;
    uint32_t carry = 0;
    uint8_t sum[32];

    /* Big‑endian addition: sum = a + b (up to 256 bits) */
    for (i = 31; i >= 0; i--) {
        uint32_t s = (uint32_t)a[i] + (uint32_t)b[i] + carry;
        sum[i] = (uint8_t)(s & 0xFF);
        carry = s >> 8;
    }

    /* If carry is set, or sum >= n, subtract n (modular reduction) */
    if (carry || memcmp(sum, secp256k1_order, 32) >= 0) {
        int borrow = 0;
        for (i = 31; i >= 0; i--) {
            int diff = (int)sum[i] - (int)secp256k1_order[i] - borrow;
            if (diff < 0) {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[i] = (uint8_t)diff;
        }
    } else {
        memcpy(result, sum, 32);
    }
}
/* =========================================================================
 * BIP32 child key derivation (hardened / non‑hardened)
 * Correct version using secp256k1 for non-hardened steps
 * ========================================================================= */
int fkt_bip32_derive_child(const uint8_t parent_priv[32],
                           const uint8_t parent_chain[32],
                           uint32_t index, int hardened,
                           uint8_t child_priv[32],
                           uint8_t child_chain[32]) {
    secp256k1_context *ctx = fkt_secp256k1_ctx();
    uint8_t data[37];
    uint8_t I[64];
    int i;

    {
        int i;
        printf("DEBUG: parent_chain = ");
        for (i = 0; i < 32; i++) printf("%02x", parent_chain[i]);
        printf("\n");
    }

    if (!ctx) return -1;

    if (hardened) {
        data[0] = 0x00;
        memcpy(data + 1, parent_priv, 32);
    } else {
        secp256k1_pubkey parent_pub;
        uint8_t pub33[33];
        size_t pub33len = 33;

        if (!secp256k1_ec_pubkey_create(ctx, &parent_pub, parent_priv)) return -1;
        if (!secp256k1_ec_pubkey_serialize(ctx, pub33, &pub33len, &parent_pub, SECP256K1_EC_COMPRESSED)) return -1;
        memcpy(data, pub33, 33);
    }

    data[33] = index & 0xFF;
    data[34] = (index >> 8) & 0xFF;
    data[35] = (index >> 16) & 0xFF;
    data[36] = (index >> 24) & 0xFF;

    printf("DEBUG: hardened data = ");
    { int i; for (i = 0; i < 37; i++) printf("%02x", data[i]); printf("\n"); }
    fkt_hmac_sha512(parent_chain, 32, data, 37, I);
    printf("DEBUG: HMAC I = ");
    { int i; for (i = 0; i < 64; i++) printf("%02x", I[i]); printf("\n"); }

    fkt_hmac_sha512(parent_chain, 32, data, 37, I);
    memcpy(child_priv, I, 32);
    memcpy(child_chain, I+32, 32);
        {
        int i;
        printf("DEBUG: child_chain = ");
        for (i = 0; i < 32; i++) printf("%02x", child_chain[i]);
        printf("\n");
    }

    if (!hardened) {
        {
            int i;
            printf("DEBUG: IL (child_priv before tweak) = ");
            for (i = 0; i < 32; i++) printf("%02x", child_priv[i]);
            printf("\nDEBUG: parent_priv = ");
            for (i = 0; i < 32; i++) printf("%02x", parent_priv[i]);
            printf("\n");
        }
        fkt_add_mod_n(child_priv, child_priv, parent_priv);
        {
            int i;
            printf("DEBUG: child_priv after tweak = ");
            for (i = 0; i < 32; i++) printf("%02x", child_priv[i]);
            printf("\n");
        }
    }

    /* Secure zero */
    {
        volatile uint8_t *vp = (volatile uint8_t*)I;
        for (i = 0; i < 64; i++) vp[i] = 0;
    }

    return 0;
}
/* =========================================================================
 * Derive full 5‑hop BIP32 path
 * ========================================================================= */
int fkt_derive_path(const uint8_t master_priv[32],
                    const uint8_t master_chain[32],
                    const uint32_t path[5],
                    int depth,     
                    uint8_t derived_priv[32],
                    uint8_t derived_pub33[33]) {
    uint8_t priv[32], chain[32];
    int i;

    memcpy(priv, master_priv, 32);
    memcpy(chain, master_chain, 32);

    for (i = 0; i < depth; i++) {
        uint8_t new_priv[32], new_chain[32];
        int hardened = (path[i] >= 0x80000000) ? 1 : 0;
        if (fkt_bip32_derive_child(priv, chain, path[i], hardened, new_priv, new_chain) != 0)
            return -1;
        memcpy(priv, new_priv, 32);
        memcpy(chain, new_chain, 32);
    }

{
    /* Quick check: add two known values and compare with Python */
    uint8_t a[32] = { /* IL from first non-hardened step */ };
    uint8_t b[32] = { /* parent_priv from first non-hardened step */ };
    uint8_t result[32];
    fkt_add_mod_n(result, a, b);
    printf("tweak result: ");
    { int i; for (i = 0; i < 32; i++) printf("%02x", result[i]); }
    printf("\n");
}

    {
        int i;
        printf("DEBUG: final priv = ");
        for (i = 0; i < 32; i++) printf("%02x", priv[i]);
        printf("\n");
    }

    memcpy(derived_priv, priv, 32);
    {
        secp256k1_context *ctx = fkt_secp256k1_ctx();
        secp256k1_pubkey pub;
        size_t pub33len = 33;
        if (!secp256k1_ec_pubkey_create(ctx, &pub, priv)) return -1;
        if (!secp256k1_ec_pubkey_serialize(ctx, derived_pub33, &pub33len, &pub, SECP256K1_EC_COMPRESSED))
            return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * parse_path_string – re‑entrant parser, writes 5 uint32_t values.
 * Supports optional "m/", hardened markers (', h, H).
 * Returns 0 on success, -1 on error.
 * ------------------------------------------------------------------------- */
static int parse_path_string(const char *path_str, uint32_t path[5]) {
    char buf[256];
    strncpy(buf, path_str, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    /* strip optional "m/" prefix */
    if (strncmp(buf, "m/", 2) == 0)
        memmove(buf, buf+2, strlen(buf+2)+1);

    int count = 0;
    char *p = buf;
    while (*p && count < 5) {
        char *end = p;
        while (*end && *end != '/') end++;

        int hardened = 0;
        if (end > p) {
            char last = *(end-1);
            if (last == '\'' || last == 'h' || last == 'H') {
                hardened = 1;
                *(end-1) = '\0';          /* remove hardened marker */
            }
        }

        int has_slash = (*end == '/');
        if (has_slash) *end = '\0';       /* terminate component */

        unsigned int index;
        if (sscanf(p, "%u", &index) != 1) return -1;
        if (hardened) index |= 0x80000000U;
        path[count++] = (uint32_t)index;

        p = has_slash ? end+1 : end;      /* advance to next component */
    }
    int parsed = count;                  /* save original count */
    if (parsed < 1 || parsed > 5) return -1;
    while (count < 5) path[count++] = 0; /* pad, but don't affect parsed */
    return parsed;
}


/* -------------------------------------------------------------------------
 * fkt_derive_from_path – the one true derivation function.
 * Takes a seed (64 bytes) and a path string.
 * Outputs child private key (32 bytes) and compressed public key (33 bytes).
 * Returns 0 on success, -1 on error.
 * ------------------------------------------------------------------------- */
int fkt_derive_from_path(const uint8_t seed[64],
                         const char *path_str,
                         uint8_t child_priv[32],
                         uint8_t child_pub33[33]) {
                         int i;
                   
    uint32_t path[5];

int depth = parse_path_string(path_str, path);
    if (depth < 0) return -1;

    uint8_t master_priv[32], master_chain[32];
    fkt_bip32_master(seed, master_priv, master_chain);

    if (fkt_derive_path(master_priv, master_chain, path, depth, child_priv, child_pub33) != 0) {
        return -1;
    }

    volatile uint8_t *vp = (volatile uint8_t*)master_priv;
    for (i = 0; i < 32; i++) vp[i] = 0;
    vp = (volatile uint8_t*)master_chain;
    for (i = 0; i < 32; i++) vp[i] = 0;

    return 0;
}

