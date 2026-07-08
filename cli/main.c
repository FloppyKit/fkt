/* main.c – FKT signer CLI */
#define _POSIX_C_SOURCE 200809L
#include "fkt.h"
#include "fkt_seed.h"
#include "fkt_preview.h"
#include "fkt_confirm.h"
#include "fkt_ui.h"
#include "fkt_psbt.h"
#include "fkt_signer.h"
#include "fkt_secp256k1.h"
#include "fkt_memzero.h"
#include "fkt_qr.h"
#include "fkt_version.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int arg_is_help(const char *s) {
    return s && (strcmp(s, "--help") == 0 || strcmp(s, "-h") == 0);
}

static int arg_is_version(const char *s) {
    return s && strcmp(s, "--version") == 0;
}

static void print_usage_brief(const char *prog) {
    fprintf(stderr, "Usage: %s [--help | --version | inspect <psbt> | sign ... | qr ...]\n",
            prog);
    fprintf(stderr, "       Run '%s --help' for the full command reference.\n", prog);
}

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int psbt_to_base64_buf(const uint8_t *data, size_t len, char *out, size_t out_max) {
    size_t i;
    size_t pos = 0;

    for (i = 0; i < len; i += 3) {
        uint32_t n;
        int pad = 0;

        if (pos + 4 >= out_max)
            return -1;
        n = ((uint32_t)data[i]) << 16;
        if (i + 1 < len)
            n |= ((uint32_t)data[i + 1]) << 8;
        else
            pad = 2;
        if (i + 2 < len)
            n |= (uint32_t)data[i + 2];
        else if (pad == 0)
            pad = 1;
        out[pos++] = b64_table[(n >> 18) & 63];
        out[pos++] = b64_table[(n >> 12) & 63];
        out[pos++] = (pad > 1) ? '=' : b64_table[(n >> 6) & 63];
        out[pos++] = (pad > 0) ? '=' : b64_table[n & 63];
    }
    if (pos >= out_max)
        return -1;
    out[pos] = '\0';
    return 0;
}

static int psbt_to_base64(const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i += 3) {
        uint32_t n;
        int pad = 0;
        n = ((uint32_t)data[i]) << 16;
        if (i + 1 < len) n |= ((uint32_t)data[i + 1]) << 8;
        else pad = 2;
        if (i + 2 < len) n |= (uint32_t)data[i + 2];
        else if (pad == 0) pad = 1;
        putchar(b64_table[(n >> 18) & 63]);
        putchar(b64_table[(n >> 12) & 63]);
        putchar(pad > 1 ? '=' : b64_table[(n >> 6) & 63]);
        putchar(pad > 0 ? '=' : b64_table[n & 63]);
    }
    putchar('\n');
    return 0;
}

/*
 * Sparrow testnet4 v1 P2WPKH seed (64-byte BIP39 seed, hex):
 *   46b6b71e4a52ba6259aae7a9eaa991aea07fead2850cb9710aea4b234b73dcc
 *   26f21d986924ec4224f0fff3b2c73788de8e1f925451b79fcccbed9951b9b184d
 *
 * Example (path comes from PSBT BIP32 derivation field):
 *   ./fktsigner <seed_hex> m/84'/1'/0'/0/29 unsigned.psbt signed.psbt
 */

static int hex_decode(const char *hex, uint8_t *out, int max_out) {
    int len = strlen(hex);
    int i;
    if (len % 2 != 0 || len/2 > max_out) return -1;
    for (i = 0; i < len/2; i++) {
        unsigned int byte;
        if (sscanf(&hex[i*2], "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return len/2;
}

static int fkt_cli_confirm_psbt(const char *input_psbt) {
    if (fkt_psbt_preview_prepare(input_psbt) != 0)
        return -1;
    if (fkt_confirm_before_sign_tty() != 0)
        return -1;
    fkt_confirm_fingerprint_capture();
    return 0;
}

static int fkt_psbt_sign_from_seed(const char *input_psbt, const char *output_psbt,
                                   char words[MAX_WORDS][WORD_BUF], int num_words) {
    char mnemonic[512];
    uint8_t seed[64];
    static const uint8_t salt[] = "mnemonic";
    int i;
    int pos = 0;

    for (i = 0; i < num_words; i++) {
        size_t wlen;
        if (i > 0) mnemonic[pos++] = ' ';
        wlen = strlen(words[i]);
        if (pos + (int)wlen >= (int)sizeof(mnemonic)) return -1;
        memcpy(mnemonic + pos, words[i], wlen);
        pos += (int)wlen;
    }
    mnemonic[pos] = '\0';

    fkt_memzero_register_seed(seed, sizeof(seed));
    fkt_memzero_register_mnemonic(mnemonic, sizeof(mnemonic));
    fkt_memzero_register_words(words, sizeof(words[0]) * MAX_WORDS);

    fkt_pbkdf2_hmac_sha512(mnemonic, (size_t)pos, salt, 8, 2048, seed, 64);
    fkt_memzero(mnemonic, sizeof(mnemonic));
    fkt_secp256k1_init();
    if (fkt_sign_psbt(seed, "", input_psbt, output_psbt) != 0) {
        fkt_memzero_wipe_all();
        return -1;
    }
    fkt_memzero_wipe_all();
    return 0;
}

int main(int argc, char **argv) {
    char words[MAX_WORDS][WORD_BUF];
    int num_words = 0;
    int i;

    fkt_memzero_install_sigint();
    fkt_confirm_set_ui_mode(0);
    if (getenv("FKT_NO_CONFIRM") != NULL)
        fkt_confirm_set_enabled(0);

    if (argc == 2 && arg_is_help(argv[1])) {
        fkt_cli_print_help(stdout);
        return 0;
    }
    if (argc == 2 && arg_is_version(argv[1])) {
        fkt_cli_print_version(stdout);
        return 0;
    }

    if (argc == 3 && (strcmp(argv[1], "inspect") == 0 ||
                        strcmp(argv[1], "preview") == 0)) {
        fkt_ui_term_init();
        return fkt_psbt_preview(argv[2]) != 0 ? 1 : 0;
    }

    if (argc >= 3 && strcmp(argv[1], "qr") == 0) {
        char b64[FKT_QR_MAX_PAYLOAD + 1];
        uint8_t raw[4096];
        size_t raw_len;
        const char *pbm_out;
        const char *psbt_path;
        FILE *f;
        long sz;
        int interactive;
        int force_term;
        int do_pbm;
        int argi;
        int total_mod;
        int px;

        fkt_ui_term_init();
        interactive = 1;
        force_term = 0;
        do_pbm = 0;
        pbm_out = NULL;
        psbt_path = NULL;

        if (strcmp(argv[2], "--psbt") == 0) {
            if (argc < 4) {
                fprintf(stderr, "Usage: %s qr --psbt <file.psbt> [--pbm out.pbm] [--term]\n", argv[0]);
                return 1;
            }
            psbt_path = argv[3];
            argi = 4;
        } else {
            argi = 3;
        }

        for (i = argi; i < argc; i++) {
            if (strcmp(argv[i], "--pbm") == 0 && i + 1 < argc) {
                pbm_out = argv[i + 1];
                do_pbm = 1;
                i++;
            } else if (strcmp(argv[i], "--term") == 0) {
                force_term = 1;
            }
        }

        if (psbt_path != NULL) {
            f = fopen(psbt_path, "rb");
            if (!f) {
                fprintf(stderr, "Cannot open %s\n", psbt_path);
                return 1;
            }
            if (fseek(f, 0, SEEK_END) != 0) {
                fclose(f);
                return 1;
            }
            sz = ftell(f);
            if (sz < 0 || (size_t)sz > sizeof(raw)) {
                fclose(f);
                fprintf(stderr, "PSBT too large for qr (max %lu bytes).\n",
                        (unsigned long)sizeof(raw));
                return 1;
            }
            rewind(f);
            raw_len = (size_t)sz;
            if (fread(raw, 1, raw_len, f) != raw_len) {
                fclose(f);
                return 1;
            }
            fclose(f);
            if (psbt_to_base64_buf(raw, raw_len, b64, sizeof(b64)) != 0) {
                fkt_memzero(raw, sizeof(raw));
                fprintf(stderr, "Base64 conversion failed.\n");
                return 1;
            }
            fkt_memzero(raw, sizeof(raw));
            if (fkt_qr_encode_text(b64) != 0) {
                fkt_memzero(b64, sizeof(b64));
                fprintf(stderr, "QR encode failed (len=%lu).\n", (unsigned long)strlen(b64));
                return 1;
            }
            printf("Signed PSBT base64 (%lu bytes)\n\n", (unsigned long)strlen(b64));
            fkt_memzero(b64, sizeof(b64));
        } else {
            if (argi != 3 || argc < 3) {
                fprintf(stderr, "Usage: %s qr <text> [--pbm out.pbm]\n", argv[0]);
                fprintf(stderr, "       %s qr --psbt <file.psbt> [--pbm out.pbm] [--term]\n", argv[0]);
                return 1;
            }
            if (fkt_qr_encode_text(argv[2]) != 0) {
                fprintf(stderr, "QR encode failed.\n");
                return 1;
            }
            printf("Payload: \"%s\"\n\n", argv[2]);
        }

        if (do_pbm) {
            if (pbm_out == NULL) {
                fprintf(stderr, "Usage: --pbm <file.pbm>\n");
                fkt_qr_clear();
                return 1;
            }
            total_mod = fkt_qr_size() + (FKT_QR_QUIET_ZONE * 2);
            px = total_mod * FKT_QR_PBM_SCALE_DEFAULT;
            if (fkt_qr_export_pbm(pbm_out, 0) != 0) {
                fprintf(stderr, "Failed to write %s\n", pbm_out);
                fkt_qr_clear();
                return 1;
            }
            printf("Scannable QR image: %s (%dx%d px, square)\n", pbm_out, px, px);
            printf("Open with: xdg-open %s\n", pbm_out);
            printf("(or any image viewer — zoom to fit screen, then scan)\n\n");
        }

        if (fkt_qr_display(fkt_ui_term_cols(), fkt_ui_term_rows(), interactive, force_term) != 0) {
            fkt_qr_clear();
            fprintf(stderr, "QR display failed.\n");
            return 1;
        }

        fkt_qr_clear();
        return 0;
    }

    if (argc >= 5 && strcmp(argv[1], "sign") == 0) {
        if (fkt_cli_confirm_psbt(argv[2]) != 0) {
            const char *cerr = fkt_last_error_get();
            if (cerr && cerr[0] != '\0')
                fprintf(stderr, "%s\n", cerr);
            else
                fprintf(stderr, "PSBT confirmation failed.\n");
            return 1;
        }
        if (fkt_seed_from_string(argv[4], words, &num_words)) {
            printf("Mnemonic loaded (%d words)\n", num_words);
            if (fkt_psbt_sign_from_seed(argv[2], argv[3], words, num_words) != 0) {
                fprintf(stderr, "Signing failed.\n");
                return 1;
            }
            fkt_cli_sign_success_interact(argv[3]);
            return 0;
        }
        fprintf(stderr, "Invalid mnemonic string.\n");
        return 1;
    }

    if (argc == 1) {
        return fkt_ui_main_menu();
    }

    if (argc == 4 && strcmp(argv[1], "--pubkey") == 0) {
        uint8_t seed[64];
        uint8_t child_priv[32], child_pub33[33];
        if (hex_decode(argv[2], seed, sizeof(seed)) != 64) {
            fprintf(stderr, "Invalid seed hex.\n");
            return 1;
        }
        if (fkt_derive_from_path(seed, argv[3], child_priv, child_pub33, NULL) != 0) {
            fprintf(stderr, "Derivation failed.\n");
            return 1;
        }
        for (i = 0; i < 33; i++) printf("%02x", child_pub33[i]);
        printf("\n");
        return 0;
    }
    if (argc == 7 && strcmp(argv[1], "--parent-pubkey") == 0) {
        uint8_t seed[64], pub33[33];
        fkt_secp256k1_init();
        if (fkt_cli_confirm_psbt(argv[5]) != 0) {
            const char *cerr = fkt_last_error_get();
            if (cerr && cerr[0] != '\0')
                fprintf(stderr, "%s\n", cerr);
            else
                fprintf(stderr, "PSBT confirmation failed.\n");
            return 1;
        }
        if (hex_decode(argv[2], seed, sizeof(seed)) != 64) {
            fprintf(stderr, "Invalid seed hex.\n");
            return 1;
        }
        if (hex_decode(argv[4], pub33, sizeof(pub33)) != 33) {
            fprintf(stderr, "Invalid pubkey hex.\n");
            return 1;
        }
        if (fkt_sign_psbt_with_parent(seed, argv[3], argv[5], argv[6], pub33) != 0) {
            fprintf(stderr, "Signing failed.\n");
            return 1;
        }
        fkt_cli_sign_success_interact(argv[6]);
        return 0;
    }

    if (argc == 3 && strcmp(argv[1], "--base64") == 0) {
        FILE *f;
        long sz;
        volatile uint8_t *buf;
        f = fopen(argv[2], "rb");
        if (!f) {
            fprintf(stderr, "Cannot open %s\n", argv[2]);
            return 1;
        }
        if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
        sz = ftell(f);
        if (sz < 0 || (size_t)sz > FKT_PSBT_MAX_SIZE) { fclose(f); return 1; }
        rewind(f);
        buf = (volatile uint8_t *)malloc((size_t)sz);
        if (!buf) { fclose(f); return 1; }
        if (fread((void *)buf, 1, (size_t)sz, f) != (size_t)sz) {
            free((void *)buf);
            fclose(f);
            return 1;
        }
        fclose(f);
        fkt_memzero_register_b64((volatile void *)buf, (size_t)sz);
        psbt_to_base64((const uint8_t *)buf, (size_t)sz);
        fkt_memzero(buf, (size_t)sz);
        free((void *)buf);
        return 0;
    }

    if (argc != 5) {
        print_usage_brief(argv[0]);
        return 1;
    }
    {
        uint8_t seed[64];
        fkt_secp256k1_init();
        if (fkt_cli_confirm_psbt(argv[3]) != 0) {
            const char *cerr = fkt_last_error_get();
            if (cerr && cerr[0] != '\0')
                fprintf(stderr, "%s\n", cerr);
            else
                fprintf(stderr, "PSBT confirmation failed.\n");
            return 1;
        }
        if (hex_decode(argv[1], seed, sizeof(seed)) != 64) {
            fprintf(stderr, "Invalid seed hex (need 128 hex chars = 64-byte BIP39 seed).\n");
            return 1;
        }
        if (fkt_sign_psbt(seed, argv[2], argv[3], argv[4]) != 0) {
            fprintf(stderr, "Signing failed.\n");
            return 1;
        }
        fkt_cli_sign_success_interact(argv[4]);
    }
    return 0;
}