/* fkt_ripemd160.c – Reference RIPEMD-160 (matches official test vectors) */
#include "fkt_ripemd160.h"
#include <string.h>

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* elementary functions */
#define F0(x, y, z)  ((x) ^ (y) ^ (z))
#define F1(x, y, z)  (((x) & (y)) | (~(x) & (z)))
#define F2(x, y, z)  (((x) | ~(y)) ^ (z))
#define F3(x, y, z)  (((x) & (z)) | ((y) & ~(z)))
#define F4(x, y, z)  ((x) ^ ((y) | ~(z)))

static const uint32_t IV[5] = {
    0x67452301UL, 0xefcdab89UL, 0x98badcfeUL, 0x10325476UL, 0xc3d2e1f0UL
};



/* -------------------------------------------------------------------------
 * RHash-based transform – guaranteed to pass all standard test vectors
 * ------------------------------------------------------------------------- */
#define RMD_FUNC(FUNC, A, B, C, D, E, X, S, K) \
    do {                                       \
        (A) += FUNC((B), (C), (D)) + (X) + K;  \
        (A) = ROL((A), (S)) + (E);             \
        (C) = ROL((C), 10);                    \
    } while(0)

/* left round macros */
#define L1(a1,b1,c1,d1,e1, X, S) RMD_FUNC(F0, a1,b1,c1,d1,e1, X, S, 0x00000000UL)
#define L2(a1,b1,c1,d1,e1, X, S) RMD_FUNC(F1, a1,b1,c1,d1,e1, X, S, 0x5a827999UL)
#define L3(a1,b1,c1,d1,e1, X, S) RMD_FUNC(F2, a1,b1,c1,d1,e1, X, S, 0x6ed9eba1UL)
#define L4(a1,b1,c1,d1,e1, X, S) RMD_FUNC(F3, a1,b1,c1,d1,e1, X, S, 0x8f1bbcdcUL)
#define L5(a1,b1,c1,d1,e1, X, S) RMD_FUNC(F4, a1,b1,c1,d1,e1, X, S, 0xa953fd4eUL)

/* right round macros */
#define R1(A,B,C,D,E, X, S) RMD_FUNC(F4, A,B,C,D,E, X, S, 0x50a28be6UL)
#define R2(A,B,C,D,E, X, S) RMD_FUNC(F3, A,B,C,D,E, X, S, 0x5c4dd124UL)
#define R3(A,B,C,D,E, X, S) RMD_FUNC(F2, A,B,C,D,E, X, S, 0x6d703ef3UL)
#define R4(A,B,C,D,E, X, S) RMD_FUNC(F1, A,B,C,D,E, X, S, 0x7a6d76e9UL)
#define R5(A,B,C,D,E, X, S) RMD_FUNC(F0, A,B,C,D,E, X, S, 0x00000000UL)

static void transform(uint32_t state[5], const uint8_t block[64]) {
    uint32_t A, B, C, D, E, a1, b1, c1, d1, e1;
    uint32_t X[16];
    int i;

    /* little-endian decode */
    for (i = 0; i < 16; i++) {
        X[i] = (uint32_t)block[i*4]       | ((uint32_t)block[i*4+1] << 8) |
               ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);
    }

    A = state[0]; B = state[1]; C = state[2]; D = state[3]; E = state[4];
    a1 = state[0]; b1 = state[1]; c1 = state[2]; d1 = state[3]; e1 = state[4];

    /* interleaved rounds (exactly as RHash) */
    L1(a1,b1,c1,d1,e1, X[ 0], 11); R1(A,B,C,D,E, X[ 5],  8);
    L1(e1,a1,b1,c1,d1, X[ 1], 14); R1(E,A,B,C,D, X[14],  9);
    L1(d1,e1,a1,b1,c1, X[ 2], 15); R1(D,E,A,B,C, X[ 7],  9);
    L1(c1,d1,e1,a1,b1, X[ 3], 12); R1(C,D,E,A,B, X[ 0], 11);
    L1(b1,c1,d1,e1,a1, X[ 4],  5); R1(B,C,D,E,A, X[ 9], 13);
    L1(a1,b1,c1,d1,e1, X[ 5],  8); R1(A,B,C,D,E, X[ 2], 15);
    L1(e1,a1,b1,c1,d1, X[ 6],  7); R1(E,A,B,C,D, X[11], 15);
    L1(d1,e1,a1,b1,c1, X[ 7],  9); R1(D,E,A,B,C, X[ 4],  5);
    L1(c1,d1,e1,a1,b1, X[ 8], 11); R1(C,D,E,A,B, X[13],  7);
    L1(b1,c1,d1,e1,a1, X[ 9], 13); R1(B,C,D,E,A, X[ 6],  7);
    L1(a1,b1,c1,d1,e1, X[10], 14); R1(A,B,C,D,E, X[15],  8);
    L1(e1,a1,b1,c1,d1, X[11], 15); R1(E,A,B,C,D, X[ 8], 11);
    L1(d1,e1,a1,b1,c1, X[12],  6); R1(D,E,A,B,C, X[ 1], 14);
    L1(c1,d1,e1,a1,b1, X[13],  7); R1(C,D,E,A,B, X[10], 14);
    L1(b1,c1,d1,e1,a1, X[14],  9); R1(B,C,D,E,A, X[ 3], 12);
    L1(a1,b1,c1,d1,e1, X[15],  8); R1(A,B,C,D,E, X[12],  6);

    L2(e1,a1,b1,c1,d1, X[ 7],  7); R2(E,A,B,C,D, X[ 6],  9);
    L2(d1,e1,a1,b1,c1, X[ 4],  6); R2(D,E,A,B,C, X[11], 13);
    L2(c1,d1,e1,a1,b1, X[13],  8); R2(C,D,E,A,B, X[ 3], 15);
    L2(b1,c1,d1,e1,a1, X[ 1], 13); R2(B,C,D,E,A, X[ 7],  7);
    L2(a1,b1,c1,d1,e1, X[10], 11); R2(A,B,C,D,E, X[ 0], 12);
    L2(e1,a1,b1,c1,d1, X[ 6],  9); R2(E,A,B,C,D, X[13],  8);
    L2(d1,e1,a1,b1,c1, X[15],  7); R2(D,E,A,B,C, X[ 5],  9);
    L2(c1,d1,e1,a1,b1, X[ 3], 15); R2(C,D,E,A,B, X[10], 11);
    L2(b1,c1,d1,e1,a1, X[12],  7); R2(B,C,D,E,A, X[14],  7);
    L2(a1,b1,c1,d1,e1, X[ 0], 12); R2(A,B,C,D,E, X[15],  7);
    L2(e1,a1,b1,c1,d1, X[ 9], 15); R2(E,A,B,C,D, X[ 8], 12);
    L2(d1,e1,a1,b1,c1, X[ 5],  9); R2(D,E,A,B,C, X[12],  7);
    L2(c1,d1,e1,a1,b1, X[ 2], 11); R2(C,D,E,A,B, X[ 4],  6);
    L2(b1,c1,d1,e1,a1, X[14],  7); R2(B,C,D,E,A, X[ 9], 15);
    L2(a1,b1,c1,d1,e1, X[11], 13); R2(A,B,C,D,E, X[ 1], 13);
    L2(e1,a1,b1,c1,d1, X[ 8], 12); R2(E,A,B,C,D, X[ 2], 11);

    L3(d1,e1,a1,b1,c1, X[ 3], 11); R3(D,E,A,B,C, X[15],  9);
    L3(c1,d1,e1,a1,b1, X[10], 13); R3(C,D,E,A,B, X[ 5],  7);
    L3(b1,c1,d1,e1,a1, X[14],  6); R3(B,C,D,E,A, X[ 1], 15);
    L3(a1,b1,c1,d1,e1, X[ 4],  7); R3(A,B,C,D,E, X[ 3], 11);
    L3(e1,a1,b1,c1,d1, X[ 9], 14); R3(E,A,B,C,D, X[ 7],  8);
    L3(d1,e1,a1,b1,c1, X[15],  9); R3(D,E,A,B,C, X[14],  6);
    L3(c1,d1,e1,a1,b1, X[ 8], 13); R3(C,D,E,A,B, X[ 6],  6);
    L3(b1,c1,d1,e1,a1, X[ 1], 15); R3(B,C,D,E,A, X[ 9], 14);
    L3(a1,b1,c1,d1,e1, X[ 2], 14); R3(A,B,C,D,E, X[11], 12);
    L3(e1,a1,b1,c1,d1, X[ 7],  8); R3(E,A,B,C,D, X[ 8], 13);
    L3(d1,e1,a1,b1,c1, X[ 0], 13); R3(D,E,A,B,C, X[12],  5);
    L3(c1,d1,e1,a1,b1, X[ 6],  6); R3(C,D,E,A,B, X[ 2], 14);
    L3(b1,c1,d1,e1,a1, X[13],  5); R3(B,C,D,E,A, X[10], 13);
    L3(a1,b1,c1,d1,e1, X[11], 12); R3(A,B,C,D,E, X[ 0], 13);
    L3(e1,a1,b1,c1,d1, X[ 5],  7); R3(E,A,B,C,D, X[ 4],  7);
    L3(d1,e1,a1,b1,c1, X[12],  5); R3(D,E,A,B,C, X[13],  5);

    L4(c1,d1,e1,a1,b1, X[ 1], 11); R4(C,D,E,A,B, X[ 8], 15);
    L4(b1,c1,d1,e1,a1, X[ 9], 12); R4(B,C,D,E,A, X[ 6],  5);
    L4(a1,b1,c1,d1,e1, X[11], 14); R4(A,B,C,D,E, X[ 4],  8);
    L4(e1,a1,b1,c1,d1, X[10], 15); R4(E,A,B,C,D, X[ 1], 11);
    L4(d1,e1,a1,b1,c1, X[ 0], 14); R4(D,E,A,B,C, X[ 3], 14);
    L4(c1,d1,e1,a1,b1, X[ 8], 15); R4(C,D,E,A,B, X[11], 14);
    L4(b1,c1,d1,e1,a1, X[12],  9); R4(B,C,D,E,A, X[15],  6);
    L4(a1,b1,c1,d1,e1, X[ 4],  8); R4(A,B,C,D,E, X[ 0], 14);
    L4(e1,a1,b1,c1,d1, X[13],  9); R4(E,A,B,C,D, X[ 5],  6);
    L4(d1,e1,a1,b1,c1, X[ 3], 14); R4(D,E,A,B,C, X[12],  9);
    L4(c1,d1,e1,a1,b1, X[ 7],  5); R4(C,D,E,A,B, X[ 2], 12);
    L4(b1,c1,d1,e1,a1, X[15],  6); R4(B,C,D,E,A, X[13],  9);
    L4(a1,b1,c1,d1,e1, X[14],  8); R4(A,B,C,D,E, X[ 9], 12);
    L4(e1,a1,b1,c1,d1, X[ 5],  6); R4(E,A,B,C,D, X[ 7],  5);
    L4(d1,e1,a1,b1,c1, X[ 6],  5); R4(D,E,A,B,C, X[10], 15);
    L4(c1,d1,e1,a1,b1, X[ 2], 12); R4(C,D,E,A,B, X[14],  8);

    L5(b1,c1,d1,e1,a1, X[ 4],  9); R5(B,C,D,E,A, X[12],  8);
    L5(a1,b1,c1,d1,e1, X[ 0], 15); R5(A,B,C,D,E, X[15],  5);
    L5(e1,a1,b1,c1,d1, X[ 5],  5); R5(E,A,B,C,D, X[10], 12);
    L5(d1,e1,a1,b1,c1, X[ 9], 11); R5(D,E,A,B,C, X[ 4],  9);
    L5(c1,d1,e1,a1,b1, X[ 7],  6); R5(C,D,E,A,B, X[ 1], 12);
    L5(b1,c1,d1,e1,a1, X[12],  8); R5(B,C,D,E,A, X[ 5],  5);
    L5(a1,b1,c1,d1,e1, X[ 2], 13); R5(A,B,C,D,E, X[ 8], 14);
    L5(e1,a1,b1,c1,d1, X[10], 12); R5(E,A,B,C,D, X[ 7],  6);
    L5(d1,e1,a1,b1,c1, X[14],  5); R5(D,E,A,B,C, X[ 6],  8);
    L5(c1,d1,e1,a1,b1, X[ 1], 12); R5(C,D,E,A,B, X[ 2], 13);
    L5(b1,c1,d1,e1,a1, X[ 3], 13); R5(B,C,D,E,A, X[13],  6);
    L5(a1,b1,c1,d1,e1, X[ 8], 14); R5(A,B,C,D,E, X[14],  5);
    L5(e1,a1,b1,c1,d1, X[11], 11); R5(E,A,B,C,D, X[ 0], 15);
    L5(d1,e1,a1,b1,c1, X[ 6],  8); R5(D,E,A,B,C, X[ 3], 13);
    L5(c1,d1,e1,a1,b1, X[15],  5); R5(C,D,E,A,B, X[ 9], 11);
    L5(b1,c1,d1,e1,a1, X[13],  6); R5(B,C,D,E,A, X[11], 11);

    /* final mixing (RHash‑style) */
    D += c1 + state[1];
    state[1] = state[2] + d1 + E;
    state[2] = state[3] + e1 + A;
    state[3] = state[4] + a1 + B;
    state[4] = state[0] + b1 + C;
    state[0] = D;
}

void fkt_ripemd160(const uint8_t *message, size_t len, uint8_t digest[20]) {
    uint32_t state[5];
    uint8_t block[64];
    size_t offset, rem;
    uint64_t bits;
    int i;

    memcpy(state, IV, sizeof(state));
    offset = 0;
    bits = (uint64_t)len * 8U;

    while (len - offset >= 64) {
        memcpy(block, message + offset, 64);
        transform(state, block);
        offset += 64;
    }

    memset(block, 0, 64);
    rem = len - offset;
    memcpy(block, message + offset, rem);
    block[rem] = 0x80;
    if (rem >= 56) {
        transform(state, block);
        memset(block, 0, 64);
    }
    for (i = 0; i < 8; i++) {
        block[56 + i] = (uint8_t)(bits >> (8 * i));
    }
    transform(state, block);

    for (i = 0; i < 5; i++) {
        digest[i*4 + 0] = (uint8_t)(state[i]);
        digest[i*4 + 1] = (uint8_t)(state[i] >> 8);
        digest[i*4 + 2] = (uint8_t)(state[i] >> 16);
        digest[i*4 + 3] = (uint8_t)(state[i] >> 24);
    }
}