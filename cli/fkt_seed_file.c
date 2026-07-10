/* fkt_seed_file.c – Warm encrypted seed file (AES-256-GCM). C89. */
#include "fkt_seed_file.h"
#include "fkt_aes_gcm.h"
#include "fkt_pbkdf2.h"
#include "fkt_memzero.h"
#include "fkt_error.h"
#include "fkt_bip39.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FKT_SEED_SALT_LEN   16
#define FKT_SEED_NONCE_LEN  12
#define FKT_SEED_TAG_LEN    16
#define FKT_SEED_PBKDF2_IT  100000
#define FKT_SEED_PLAIN_MAX  512
#define FKT_SEED_FILE_MAX   1024

static int fkt_seed_random_bytes(uint8_t *out, size_t n) {
    FILE *f;
    size_t got;

    f = fopen("/dev/urandom", "rb");
    if (!f)
        f = fopen("/dev/random", "rb");
    if (!f)
        return -1;
    got = fread(out, 1, n, f);
    fclose(f);
    return (got == n) ? 0 : -1;
}

static void fkt_seed_words_to_plain(char words[MAX_WORDS][WORD_BUF], int num_words,
                                   char *plain, size_t plain_max, size_t *out_len) {
    int i;
    size_t pos = 0;

    for (i = 0; i < num_words; i++) {
        size_t wlen = strlen(words[i]);
        if (i > 0) {
            if (pos + 1 >= plain_max)
                break;
            plain[pos++] = ' ';
        }
        if (pos + wlen >= plain_max)
            break;
        memcpy(plain + pos, words[i], wlen);
        pos += wlen;
    }
    plain[pos] = '\0';
    *out_len = pos;
}

static void fkt_seed_derive_key(const char *passphrase, const uint8_t salt[FKT_SEED_SALT_LEN],
                                uint8_t key[32]) {
    size_t plen = passphrase ? strlen(passphrase) : 0;
    /* 32-byte AES key from PBKDF2-HMAC-SHA512 */
    fkt_pbkdf2_hmac_sha512(passphrase ? passphrase : "",
                           plen,
                           salt, FKT_SEED_SALT_LEN,
                           FKT_SEED_PBKDF2_IT,
                           key, 32);
}

int fkt_seed_file_save(const char *path,
                       char words[MAX_WORDS][WORD_BUF], int num_words,
                       const char *passphrase) {
    uint8_t salt[FKT_SEED_SALT_LEN];
    uint8_t nonce[FKT_SEED_NONCE_LEN];
    uint8_t key[32];
    uint8_t tag[FKT_SEED_TAG_LEN];
    char plain[FKT_SEED_PLAIN_MAX];
    uint8_t ct[FKT_SEED_PLAIN_MAX];
    size_t plain_len = 0;
    uint8_t hdr[8 + 1 + 1 + FKT_SEED_SALT_LEN + FKT_SEED_NONCE_LEN + 4];
    FILE *f;
    uint32_t ct_len32;
    uint8_t flags = 0;
    size_t w;

    if (!path || !words || (num_words != 12 && num_words != 24)) {
        fkt_last_error_set("seed-file save: need 12 or 24 words.");
        return -1;
    }
    if (!passphrase)
        passphrase = "";

    if (passphrase[0] == '\0') {
        fprintf(stderr,
                "\n*** WARM WARNING: saving seed file with EMPTY passphrase.\n"
                "*** Ritual/education machines only. Not for real funds.\n\n");
    } else {
        flags = FKT_SEED_FILE_FLAG_PASS;
    }

    {
        char wcopy[MAX_WORDS][FKT_BIP39_WORD_BUF];
        int i;
        for (i = 0; i < num_words; i++) {
            strncpy(wcopy[i], words[i], FKT_BIP39_WORD_BUF - 1);
            wcopy[i][FKT_BIP39_WORD_BUF - 1] = '\0';
        }
        if (!fkt_bip39_validate_checksum(wcopy, num_words)) {
            fkt_last_error_set("seed-file save: invalid BIP39 checksum.");
            fkt_memzero(wcopy, sizeof(wcopy));
            return -1;
        }
        fkt_memzero(wcopy, sizeof(wcopy));
    }

    fkt_seed_words_to_plain(words, num_words, plain, sizeof(plain), &plain_len);
    if (plain_len == 0 || plain_len >= sizeof(ct)) {
        fkt_last_error_set("seed-file save: mnemonic too long.");
        fkt_memzero(plain, sizeof(plain));
        return -1;
    }

    if (fkt_seed_random_bytes(salt, sizeof(salt)) != 0 ||
        fkt_seed_random_bytes(nonce, sizeof(nonce)) != 0) {
        fkt_last_error_set("seed-file save: no entropy (/dev/urandom).");
        fkt_memzero(plain, sizeof(plain));
        return -1;
    }

    fkt_seed_derive_key(passphrase, salt, key);
    if (fkt_aes256_gcm_encrypt(key, nonce, FKT_SEED_NONCE_LEN,
                               (const uint8_t *)FKT_SEED_FILE_MAGIC, 8,
                               (const uint8_t *)plain, plain_len,
                               ct, tag) != 0) {
        fkt_memzero(key, sizeof(key));
        fkt_memzero(plain, sizeof(plain));
        fkt_last_error_set("seed-file save: encrypt failed.");
        return -1;
    }
    fkt_memzero(plain, sizeof(plain));
    fkt_memzero(key, sizeof(key));

    /* header */
    memcpy(hdr, FKT_SEED_FILE_MAGIC, 8);
    hdr[8] = (uint8_t)FKT_SEED_FILE_VERSION;
    hdr[9] = flags;
    memcpy(hdr + 10, salt, FKT_SEED_SALT_LEN);
    memcpy(hdr + 10 + FKT_SEED_SALT_LEN, nonce, FKT_SEED_NONCE_LEN);
    ct_len32 = (uint32_t)plain_len;
    hdr[10 + FKT_SEED_SALT_LEN + FKT_SEED_NONCE_LEN + 0] = (uint8_t)(ct_len32 & 0xff);
    hdr[10 + FKT_SEED_SALT_LEN + FKT_SEED_NONCE_LEN + 1] = (uint8_t)((ct_len32 >> 8) & 0xff);
    hdr[10 + FKT_SEED_SALT_LEN + FKT_SEED_NONCE_LEN + 2] = (uint8_t)((ct_len32 >> 16) & 0xff);
    hdr[10 + FKT_SEED_SALT_LEN + FKT_SEED_NONCE_LEN + 3] = (uint8_t)((ct_len32 >> 24) & 0xff);

    f = fopen(path, "wb");
    if (!f) {
        fkt_last_error_set("seed-file save: cannot open path.");
        fkt_memzero(ct, sizeof(ct));
        fkt_memzero(tag, sizeof(tag));
        return -1;
    }
    w = fwrite(hdr, 1, sizeof(hdr), f);
    w += fwrite(ct, 1, plain_len, f);
    w += fwrite(tag, 1, FKT_SEED_TAG_LEN, f);
    fclose(f);

    fkt_memzero(ct, sizeof(ct));
    fkt_memzero(tag, sizeof(tag));
    fkt_memzero(salt, sizeof(salt));
    fkt_memzero(nonce, sizeof(nonce));

    if (w != sizeof(hdr) + plain_len + FKT_SEED_TAG_LEN) {
        fkt_last_error_set("seed-file save: short write.");
        return -1;
    }

    fprintf(stderr,
            "WARM: encrypted seed written to %s\n"
            "      Preview-before-seed still applies at sign time.\n",
            path);
    return 0;
}

int fkt_seed_file_load(const char *path,
                       char words[MAX_WORDS][WORD_BUF], int *num_words,
                       const char *passphrase) {
    uint8_t buf[FKT_SEED_FILE_MAX];
    size_t nread;
    FILE *f;
    uint8_t version, flags;
    uint8_t salt[FKT_SEED_SALT_LEN];
    uint8_t nonce[FKT_SEED_NONCE_LEN];
    uint8_t tag[FKT_SEED_TAG_LEN];
    uint8_t key[32];
    uint8_t plain[FKT_SEED_PLAIN_MAX];
    uint32_t ct_len;
    size_t hdr_len = 8 + 1 + 1 + FKT_SEED_SALT_LEN + FKT_SEED_NONCE_LEN + 4;
    const uint8_t *ct;

    if (!path || !words || !num_words) {
        fkt_last_error_set("seed-file load: bad args.");
        return -1;
    }
    if (!passphrase)
        passphrase = "";

    f = fopen(path, "rb");
    if (!f) {
        fkt_last_error_set("seed-file load: cannot open path.");
        return -1;
    }
    nread = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    if (nread < hdr_len + FKT_SEED_TAG_LEN) {
        fkt_last_error_set("seed-file load: file too short.");
        return -1;
    }
    if (memcmp(buf, FKT_SEED_FILE_MAGIC, 8) != 0) {
        fkt_last_error_set("seed-file load: bad magic (not FKTSEED1).");
        return -1;
    }
    version = buf[8];
    flags = buf[9];
    if (version != FKT_SEED_FILE_VERSION) {
        fkt_last_error_set("seed-file load: unsupported version.");
        return -1;
    }
    memcpy(salt, buf + 10, FKT_SEED_SALT_LEN);
    memcpy(nonce, buf + 10 + FKT_SEED_SALT_LEN, FKT_SEED_NONCE_LEN);
    ct_len = (uint32_t)buf[10 + FKT_SEED_SALT_LEN + FKT_SEED_NONCE_LEN + 0] |
             ((uint32_t)buf[10 + FKT_SEED_SALT_LEN + FKT_SEED_NONCE_LEN + 1] << 8) |
             ((uint32_t)buf[10 + FKT_SEED_SALT_LEN + FKT_SEED_NONCE_LEN + 2] << 16) |
             ((uint32_t)buf[10 + FKT_SEED_SALT_LEN + FKT_SEED_NONCE_LEN + 3] << 24);

    if (ct_len == 0 || ct_len >= FKT_SEED_PLAIN_MAX) {
        fkt_last_error_set("seed-file load: bad ciphertext length.");
        return -1;
    }
    if (nread < hdr_len + ct_len + FKT_SEED_TAG_LEN) {
        fkt_last_error_set("seed-file load: truncated file.");
        return -1;
    }
    ct = buf + hdr_len;
    memcpy(tag, buf + hdr_len + ct_len, FKT_SEED_TAG_LEN);

    if (passphrase[0] == '\0' && (flags & FKT_SEED_FILE_FLAG_PASS)) {
        fprintf(stderr, "WARM: file was saved with a passphrase; empty pass may fail.\n");
    }
    if (passphrase[0] == '\0') {
        fprintf(stderr,
                "\n*** WARM WARNING: loading seed file with EMPTY passphrase.\n"
                "*** Ritual/education only. Not for real funds.\n\n");
    }

    fkt_seed_derive_key(passphrase, salt, key);
    memset(plain, 0, sizeof(plain));
    if (fkt_aes256_gcm_decrypt(key, nonce, FKT_SEED_NONCE_LEN,
                               (const uint8_t *)FKT_SEED_FILE_MAGIC, 8,
                               ct, ct_len, tag, plain) != 0) {
        fkt_memzero(key, sizeof(key));
        fkt_memzero(plain, sizeof(plain));
        fkt_last_error_set("seed-file load: decrypt/auth failed (wrong passphrase?).");
        return -1;
    }
    fkt_memzero(key, sizeof(key));
    plain[ct_len] = '\0';

    if (!fkt_seed_from_string((const char *)plain, words, num_words)) {
        fkt_memzero(plain, sizeof(plain));
        fkt_last_error_set("seed-file load: plaintext is not a valid mnemonic.");
        return -1;
    }
    fkt_memzero(plain, sizeof(plain));
    fkt_memzero(buf, sizeof(buf));
    return 0;
}
