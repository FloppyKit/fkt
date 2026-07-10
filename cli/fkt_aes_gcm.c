/* fkt_aes_gcm.c – AES-256-GCM (NIST SP 800-38D), C89. Warm only. */
#include "fkt_aes_gcm.h"
#include "fkt_aes.h"
#include "fkt_memzero.h"
#include <string.h>

static void gcm_xor_block(uint8_t *d, const uint8_t *a, const uint8_t *b) {
    int i;
    for (i = 0; i < 16; i++)
        d[i] = (uint8_t)(a[i] ^ b[i]);
}

/* GF(2^128) multiply: X = X * Y  (NIST bit reflection / right-shift form). */
static void gcm_mult(uint8_t X[16], const uint8_t Y[16]) {
    uint8_t Z[16];
    uint8_t V[16];
    int i, j;

    memset(Z, 0, 16);
    memcpy(V, Y, 16);

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            uint8_t bit = (uint8_t)((X[i] >> (7 - j)) & 1);
            if (bit) {
                int k;
                for (k = 0; k < 16; k++)
                    Z[k] ^= V[k];
            }
            {
                uint8_t lsb = (uint8_t)(V[15] & 1);
                int k;
                for (k = 15; k > 0; k--)
                    V[k] = (uint8_t)((V[k] >> 1) | ((V[k - 1] & 1) << 7));
                V[0] = (uint8_t)(V[0] >> 1);
                if (lsb)
                    V[0] ^= 0xe1;
            }
        }
    }
    memcpy(X, Z, 16);
}

static void gcm_ghash(const uint8_t H[16],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t out[16]) {
    uint8_t Y[16];
    size_t i, n;

    memset(Y, 0, 16);

    n = (aad_len + 15) / 16;
    for (i = 0; i < n; i++) {
        uint8_t block[16];
        size_t off = i * 16;
        size_t left = aad_len - off;
        memset(block, 0, 16);
        memcpy(block, aad + off, left > 16 ? 16 : left);
        gcm_xor_block(Y, Y, block);
        gcm_mult(Y, H);
    }

    n = (ct_len + 15) / 16;
    for (i = 0; i < n; i++) {
        uint8_t block[16];
        size_t off = i * 16;
        size_t left = ct_len - off;
        memset(block, 0, 16);
        memcpy(block, ct + off, left > 16 ? 16 : left);
        gcm_xor_block(Y, Y, block);
        gcm_mult(Y, H);
    }

    {
        uint8_t lenb[16];
        uint64_t a_bits = (uint64_t)aad_len * 8;
        uint64_t c_bits = (uint64_t)ct_len * 8;
        memset(lenb, 0, 16);
        lenb[0] = (uint8_t)(a_bits >> 56);
        lenb[1] = (uint8_t)(a_bits >> 48);
        lenb[2] = (uint8_t)(a_bits >> 40);
        lenb[3] = (uint8_t)(a_bits >> 32);
        lenb[4] = (uint8_t)(a_bits >> 24);
        lenb[5] = (uint8_t)(a_bits >> 16);
        lenb[6] = (uint8_t)(a_bits >> 8);
        lenb[7] = (uint8_t)a_bits;
        lenb[8] = (uint8_t)(c_bits >> 56);
        lenb[9] = (uint8_t)(c_bits >> 48);
        lenb[10] = (uint8_t)(c_bits >> 40);
        lenb[11] = (uint8_t)(c_bits >> 32);
        lenb[12] = (uint8_t)(c_bits >> 24);
        lenb[13] = (uint8_t)(c_bits >> 16);
        lenb[14] = (uint8_t)(c_bits >> 8);
        lenb[15] = (uint8_t)c_bits;
        gcm_xor_block(Y, Y, lenb);
        gcm_mult(Y, H);
    }

    memcpy(out, Y, 16);
}

static void gcm_inc32(uint8_t counter[16]) {
    int i;
    for (i = 15; i >= 12; i--) {
        counter[i]++;
        if (counter[i] != 0)
            break;
    }
}

static void gcm_ctr(const uint32_t rk[60], uint8_t counter[16],
                    const uint8_t *in, size_t len, uint8_t *out) {
    size_t off = 0;
    while (off < len) {
        uint8_t stream[16];
        size_t chunk = len - off;
        size_t j;
        if (chunk > 16)
            chunk = 16;
        fkt_aes256_encrypt_block(rk, counter, stream);
        for (j = 0; j < chunk; j++)
            out[off + j] = (uint8_t)(in[off + j] ^ stream[j]);
        gcm_inc32(counter);
        off += chunk;
        fkt_memzero(stream, sizeof(stream));
    }
}

int fkt_aes256_gcm_encrypt(const uint8_t key[32],
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct,
                           uint8_t tag[16]) {
    uint32_t rk[60];
    uint8_t H[16], J0[16], counter[16], S[16], E0[16];

    if (!key || !nonce || !tag || (pt_len && (!pt || !ct)))
        return -1;
    if (nonce_len != 12)
        return -1;
    if (aad_len && !aad)
        return -1;

    fkt_aes256_set_encrypt_key(key, rk);
    memset(H, 0, 16);
    fkt_aes256_encrypt_block(rk, H, H);

    /* J0 = nonce || 0x00000001 for 96-bit nonce */
    memcpy(J0, nonce, 12);
    J0[12] = 0;
    J0[13] = 0;
    J0[14] = 0;
    J0[15] = 1;

    memcpy(counter, J0, 16);
    gcm_inc32(counter);
    if (pt_len)
        gcm_ctr(rk, counter, pt, pt_len, ct);

    gcm_ghash(H, aad, aad_len, ct, pt_len, S);
    fkt_aes256_encrypt_block(rk, J0, E0);
    gcm_xor_block(tag, S, E0);

    fkt_memzero(rk, sizeof(rk));
    fkt_memzero(H, sizeof(H));
    fkt_memzero(J0, sizeof(J0));
    fkt_memzero(counter, sizeof(counter));
    fkt_memzero(S, sizeof(S));
    fkt_memzero(E0, sizeof(E0));
    return 0;
}

int fkt_aes256_gcm_decrypt(const uint8_t key[32],
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[16],
                           uint8_t *pt) {
    uint32_t rk[60];
    uint8_t H[16], J0[16], counter[16], S[16], E0[16], expect[16];
    int i, diff;

    if (!key || !nonce || !tag || (ct_len && (!ct || !pt)))
        return -1;
    if (nonce_len != 12)
        return -1;
    if (aad_len && !aad)
        return -1;

    fkt_aes256_set_encrypt_key(key, rk);
    memset(H, 0, 16);
    fkt_aes256_encrypt_block(rk, H, H);

    memcpy(J0, nonce, 12);
    J0[12] = 0;
    J0[13] = 0;
    J0[14] = 0;
    J0[15] = 1;

    gcm_ghash(H, aad, aad_len, ct, ct_len, S);
    fkt_aes256_encrypt_block(rk, J0, E0);
    gcm_xor_block(expect, S, E0);

    diff = 0;
    for (i = 0; i < 16; i++)
        diff |= expect[i] ^ tag[i];

    if (diff != 0) {
        if (pt && ct_len)
            fkt_memzero(pt, ct_len);
        fkt_memzero(rk, sizeof(rk));
        fkt_memzero(expect, sizeof(expect));
        return -1;
    }

    memcpy(counter, J0, 16);
    gcm_inc32(counter);
    if (ct_len)
        gcm_ctr(rk, counter, ct, ct_len, pt);

    fkt_memzero(rk, sizeof(rk));
    fkt_memzero(H, sizeof(H));
    fkt_memzero(J0, sizeof(J0));
    fkt_memzero(counter, sizeof(counter));
    fkt_memzero(S, sizeof(S));
    fkt_memzero(E0, sizeof(E0));
    fkt_memzero(expect, sizeof(expect));
    return 0;
}
