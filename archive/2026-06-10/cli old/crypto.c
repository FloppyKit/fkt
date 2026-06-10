/* crypto.c – Cryptographic primitives for FKT (v0.1) */
#include "fkt_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../secp256k1/include/secp256k1_schnorrsig.h"
#include "fkt_ripemd160.h"

/* =========================================================================
 * internal secp256k1 context (lazy init)
 * ========================================================================= */
void fkt_crypto_init(void) {
    /* force creation of context if not already there */
    (void)fkt_crypto_ctx();
}

secp256k1_context* fkt_crypto_ctx(void) {
    static secp256k1_context *ctx = NULL;
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
    return ctx;
}

/* =========================================================================
 * SHA-256 (FIPS 180-4) – streaming
 * ========================================================================= */
#define ROR32(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x)      (ROR32(x,  2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define SIG1(x)      (ROR32(x,  6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define sig0(x)      (ROR32(x,  7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define sig1(x)      (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(fkt_sha256_ctx *ctx, const uint8_t *data) {
    uint32_t a,b,c,d,e,f,g,h,t1,t2,w[64]; int i,j;
    for(i=0,j=0;i<16;i++,j+=4)
        w[i]=((uint32_t)data[j]<<24)|((uint32_t)data[j+1]<<16)|((uint32_t)data[j+2]<<8)|(uint32_t)data[j+3];
    for(i=16;i<64;i++)
        w[i]=sig1(w[i-2])+w[i-7]+sig0(w[i-15])+w[i-16];
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for(i=0;i<64;i++){
        t1=h+SIG1(e)+CH(e,f,g)+sha256_k[i]+w[i];
        t2=SIG0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;
    ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}

void fkt_sha256_init(fkt_sha256_ctx *ctx) {
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
    ctx->count=0;
}

void fkt_sha256_update(fkt_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i;
    for(i=0;i<len;i++){
        ctx->buf[ctx->count & 63] = data[i];
        ctx->count++;
        if((ctx->count & 63) == 0) sha256_transform(ctx, ctx->buf);
    }
}

void fkt_sha256_final(fkt_sha256_ctx *ctx, uint8_t digest[32]) {
    uint64_t bits = ctx->count * 8;
    uint8_t pad = 0x80;
    int i;
    fkt_sha256_update(ctx, &pad, 1);
    while((ctx->count & 63) != 56) {
        pad = 0;
        fkt_sha256_update(ctx, &pad, 1);
    }
    {
        uint8_t len_buf[8];
        for(i=0;i<8;i++) len_buf[i] = (uint8_t)(bits >> (56 - 8*i));
        fkt_sha256_update(ctx, len_buf, 8);
    }
    for(i=0;i<8;i++){
        digest[i*4  ] = (uint8_t)(ctx->state[i]>>24);
        digest[i*4+1] = (uint8_t)(ctx->state[i]>>16);
        digest[i*4+2] = (uint8_t)(ctx->state[i]>>8);
        digest[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

void fkt_sha256(const uint8_t *message, size_t len, uint8_t digest[32]) {
    fkt_sha256_ctx ctx;
    fkt_sha256_init(&ctx);
    fkt_sha256_update(&ctx, message, len);
    fkt_sha256_final(&ctx, digest);
}

void fkt_sha256d(const uint8_t *message, size_t len, uint8_t digest[32]) {
    uint8_t tmp[32];
    fkt_sha256(message, len, tmp);
    fkt_sha256(tmp, 32, digest);
}



/* =========================================================================
 * SHA-512 (FIPS 180-4)
 * ========================================================================= */
static uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
static uint64_t sigma0_512(uint64_t x) { return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7); }
static uint64_t sigma1_512(uint64_t x) { return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6); }
static uint64_t Sigma0_512(uint64_t x) { return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39); }
static uint64_t Sigma1_512(uint64_t x) { return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41); }
static uint64_t CH512(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
static uint64_t MAJ512(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }

static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static void sha512_transform(uint64_t state[8], const uint8_t block[128]) {
    uint64_t w[80], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((uint64_t)block[i*8] << 56) | ((uint64_t)block[i*8+1] << 48) |
               ((uint64_t)block[i*8+2] << 40) | ((uint64_t)block[i*8+3] << 32) |
               ((uint64_t)block[i*8+4] << 24) | ((uint64_t)block[i*8+5] << 16) |
               ((uint64_t)block[i*8+6] << 8)  | ((uint64_t)block[i*8+7]);
    }
    for (i = 16; i < 80; i++) {
        w[i] = sigma1_512(w[i-2]) + w[i-7] + sigma0_512(w[i-15]) + w[i-16];
    }
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (i = 0; i < 80; i++) {
        t1 = h + Sigma1_512(e) + CH512(e, f, g) + sha512_k[i] + w[i];
        t2 = Sigma0_512(a) + MAJ512(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void fkt_sha512(const uint8_t *message, size_t len, uint8_t digest[64]) {
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    uint8_t block[128];
    size_t offset = 0;
    uint64_t bitlen = (uint64_t)len * 8;

    while (len - offset >= 128) {
        memcpy(block, message + offset, 128);
        sha512_transform(state, block);
        offset += 128;
    }

    memset(block, 0, 128);
    memcpy(block, message + offset, len - offset);
    block[len - offset] = 0x80;

    if (len - offset >= 112) {
        sha512_transform(state, block);
        memset(block, 0, 128);
    }

    {
        int i;
        for (i = 0; i < 8; i++) {
            block[120 + i] = (uint8_t)(bitlen >> (56 - i*8));
        }
    }
    sha512_transform(state, block);

    {
        int i;
        for (i = 0; i < 8; i++) {
            digest[i*8]   = (uint8_t)(state[i] >> 56);
            digest[i*8+1] = (uint8_t)(state[i] >> 48);
            digest[i*8+2] = (uint8_t)(state[i] >> 40);
            digest[i*8+3] = (uint8_t)(state[i] >> 32);
            digest[i*8+4] = (uint8_t)(state[i] >> 24);
            digest[i*8+5] = (uint8_t)(state[i] >> 16);
            digest[i*8+6] = (uint8_t)(state[i] >> 8);
            digest[i*8+7] = (uint8_t)state[i];
        }
    }
}

/* =========================================================================
 * HMAC-SHA512 (RFC 2104)
 * ========================================================================= */
void fkt_hmac_sha512(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t out[64]) {
    uint8_t k[128] = {0};
    uint8_t ipad[128], opad[128];
    uint8_t inner[64];
    uint8_t temp[128 + 256]; /* stack, enough for our usage */

    if (key_len > 128) {
        fkt_sha512(key, key_len, k);
        key = k; key_len = 64;
    } else {
        memcpy(k, key, key_len);
    }

    {
        size_t i;
        for (i = 0; i < 128; i++) {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }
    }

    /* inner = SHA512(ipad || data) */
    {
        size_t inner_len = 128 + data_len;
        if (inner_len > sizeof(temp)) inner_len = sizeof(temp);
        memcpy(temp, ipad, 128);
        memcpy(temp + 128, data, data_len);
        fkt_sha512(temp, 128 + data_len, inner);
    }

    /* outer = SHA512(opad || inner) */
    {
        memcpy(temp, opad, 128);
        memcpy(temp + 128, inner, 64);
        fkt_sha512(temp, 192, out);
    }
}

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
    int carry = 0;
    int i;
    uint8_t sum[32];
    /* add from LSB to MSB */
    for (i = 31; i >= 0; i--) {
        int s = (int)a[i] + (int)b[i] + carry;
        sum[i] = (uint8_t)(s & 0xFF);
        carry = s >> 8;
    }
    /* if carry or sum >= order, subtract order */
    if (carry || memcmp(sum, secp256k1_order, 32) >= 0) {
        int borrow = 0;
        for (i = 31; i >= 0; i--) {
            int diff = (int)sum[i] - (int)secp256k1_order[i] - borrow;
            if (diff < 0) { diff += 256; borrow = 1; }
            else borrow = 0;
            result[i] = (uint8_t)diff;
        }
    } else {
        memcpy(result, sum, 32);
    }
}
/* =========================================================================
 * BIP32 child key derivation (hardened / non‑hardened)
 * Uses secp256k1_ec_privkey_tweak_add for non‑hardened.
 * ========================================================================= */
int fkt_bip32_derive_child(const uint8_t parent_priv[32],
                           const uint8_t parent_chain[32],
                           uint32_t index, int hardened,
                           uint8_t child_priv[32],
                           uint8_t child_chain[32]) {
    secp256k1_context *ctx = fkt_crypto_ctx();
    secp256k1_pubkey parent_pub;
    uint8_t pub33[33]; size_t pub33len = 33;
    uint8_t data[37];
    uint8_t I[64];
    int i;

    if (!ctx) return -1;

    if (hardened) {
        data[0] = 0x00;
        memcpy(data+1, parent_priv, 32);
    } else {
        if (!secp256k1_ec_pubkey_create(ctx, &parent_pub, parent_priv)) return -1;
        if (!secp256k1_ec_pubkey_serialize(ctx, pub33, &pub33len, &parent_pub, SECP256K1_EC_COMPRESSED)) return -1;

        memcpy(data, pub33, 33);
    }

    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;

    fkt_hmac_sha512(parent_chain, 32, data, 37, I);
    memcpy(child_priv, I, 32);
    memcpy(child_chain, I+32, 32);

    if (!hardened) {
        /* Use manual mod‑n addition instead of missing library function */
        fkt_add_mod_n(child_priv, child_priv, parent_priv);
    }

    /* zero the HMAC output buffer */
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
                    uint8_t derived_priv[32],
                    uint8_t derived_pub33[33]) {
    uint8_t priv[32], chain[32];
    int i;

    memcpy(priv, master_priv, 32);
    memcpy(chain, master_chain, 32);

    for (i = 0; i < 5; i++) {
        uint8_t new_priv[32], new_chain[32];
        int hardened = (path[i] >= 0x80000000) ? 1 : 0;
        if (fkt_bip32_derive_child(priv, chain, path[i], hardened, new_priv, new_chain) != 0)
            return -1;
        memcpy(priv, new_priv, 32);
        memcpy(chain, new_chain, 32);
    }

    memcpy(derived_priv, priv, 32);
    {
        secp256k1_context *ctx = fkt_crypto_ctx();
        secp256k1_pubkey pub;
        size_t pub33len = 33;
        if (!secp256k1_ec_pubkey_create(ctx, &pub, priv)) return -1;
        if (!secp256k1_ec_pubkey_serialize(ctx, derived_pub33, &pub33len, &pub, SECP256K1_EC_COMPRESSED))
            return -1;
    }
    return 0;
}

/* =========================================================================
 * Secure zeroing
 * ========================================================================= */
void fkt_zerobytes(volatile void *buf, size_t len) {
    volatile uint8_t *p = (volatile uint8_t*)buf;
    size_t i;
    for (i = 0; i < len; i++) p[i] = 0;
}

/* Sign a 32-byte message (BIP-341 sighash) using Schnorr, producing a 64-byte signature.
 * Returns 0 on success, -1 on error. */
int fkt_schnorr_sign(const uint8_t privkey[32], const uint8_t msg[32],
                     uint8_t sig[64], int *sig_len) {
    secp256k1_context *ctx = fkt_crypto_ctx();
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ctx, &keypair, privkey))
        return -1;
    if (!secp256k1_schnorrsig_sign32(ctx, sig, msg, &keypair, NULL))
        return -1;
    *sig_len = 64;
    return 0;
}