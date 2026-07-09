/* main.c – FKT signer CLI */
#if !(defined(FKT_DOS) && FKT_DOS)
#define _POSIX_C_SOURCE 200809L
#endif

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
#include "fkt_platform.h"
#include "fkt_error.h"
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
    fprintf(stderr, "Usage: %s [--help | --version | inspect <psbt> | qr ...]\n", prog);
    fprintf(stderr, "       %s sign --psbt <in> --out <out> --seed \"words...\"\n", prog);
    fprintf(stderr, "       %s sign --psbt <in> --out <out>   (seed on stdin)\n", prog);
    fprintf(stderr, "       %s                    (interactive menu)\n", prog);
#if FKT_BUILD_DEV_HARNESS
    fprintf(stderr, "       Dev: sign <in> <out> \"mnemonic\" | --base64 <psbt> | <hex128> ...\n");
#endif
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

#if FKT_BUILD_DEV_HARNESS
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
#endif

static int fkt_cli_confirm_psbt(const char *input_psbt) {
    if (fkt_psbt_preview_prepare(input_psbt) != 0)
        return -1;
    if (fkt_confirm_before_sign_tty() != 0)
        return -1;
    fkt_confirm_fingerprint_capture();
    return 0;
}

/* PR5 pure CLI: always available (no TUI). */
static int fkt_cli_sign_psbt_words(const char *input_psbt, const char *output_psbt,
                                  char words[MAX_WORDS][WORD_BUF], int num_words) {
    if (fkt_sign_psbt_from_words(input_psbt, output_psbt, words, num_words) != 0)
        return -1;
    return 0;
}

/*
 * fkt sign --psbt in.psbt --out out.psbt --seed "w1 w2 ..."
 * fkt sign --psbt in.psbt --out out.psbt   (mnemonic on stdin, one line)
 * Optional: --yes  skip interactive CONFIRM (scripted / offline pipeline)
 */
static int fkt_cli_run_sign(int argc, char **argv) {
    const char *psbt_in = NULL;
    const char *psbt_out = NULL;
    const char *seed_str = NULL;
    int yes = 0;
    int i;
    char words[MAX_WORDS][WORD_BUF];
    int num_words = 0;
    char seed_line[512];

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--psbt") == 0 && i + 1 < argc) {
            psbt_in = argv[++i];
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            psbt_out = argv[++i];
        } else if ((strcmp(argv[i], "--seed") == 0 ||
                    strcmp(argv[i], "--mnemonic") == 0) && i + 1 < argc) {
            seed_str = argv[++i];
        } else if (strcmp(argv[i], "--yes") == 0 || strcmp(argv[i], "-y") == 0) {
            yes = 1;
        } else if (argv[i][0] != '-') {
            /* Legacy: sign <in> <out> "mnemonic" */
            if (!psbt_in)
                psbt_in = argv[i];
            else if (!psbt_out)
                psbt_out = argv[i];
            else if (!seed_str)
                seed_str = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    if (!psbt_in || !psbt_out) {
        fprintf(stderr,
                "Usage: %s sign --psbt <in.psbt> --out <out.psbt> "
                "[--seed \"words...\"] [--yes]\n",
                argv[0]);
        fprintf(stderr, "       Seed may also be piped on stdin (one line).\n");
        return 1;
    }

    if (!seed_str) {
        if (!fgets(seed_line, sizeof(seed_line), stdin)) {
            fprintf(stderr, "No seed on stdin and no --seed given.\n");
            return 1;
        }
        {
            size_t n = strlen(seed_line);
            while (n > 0 && (seed_line[n - 1] == '\n' || seed_line[n - 1] == '\r'))
                seed_line[--n] = '\0';
        }
        seed_str = seed_line;
    }

    if (!fkt_seed_from_string(seed_str, words, &num_words)) {
        fprintf(stderr, "Invalid mnemonic.\n");
        return 1;
    }

    if (yes)
        fkt_confirm_set_enabled(0);

    if (fkt_cli_confirm_psbt(psbt_in) != 0) {
        const char *cerr = fkt_last_error_get();
        if (cerr && cerr[0] != '\0')
            fprintf(stderr, "%s\n", cerr);
        else
            fprintf(stderr, "PSBT confirmation failed.\n");
        return 1;
    }

    if (fkt_cli_sign_psbt_words(psbt_in, psbt_out, words, num_words) != 0) {
        const char *cerr = fkt_last_error_get();
        if (cerr && cerr[0] != '\0')
            fprintf(stderr, "%s\n", cerr);
        else
            fprintf(stderr, "Signing failed.\n");
        return 1;
    }

    printf("Signed PSBT written: %s\n", psbt_out);
    return 0;
}

static int fkt_cli_run_qr(int argc, char **argv) {
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
    int i;

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

int main(int argc, char **argv) {
    int i;

    /* Do NOT fkt_dos_init here — pure CLI must not clear the host screen.
     * Interactive TUI calls fkt_dos_init via fkt_ui_term_init(). */

    fkt_memzero_install_sigint();
    fkt_psbt_set_argv0(argv[0]);
    fkt_confirm_set_ui_mode(0);
#if FKT_BUILD_DEV_HARNESS
    if (getenv("FKT_NO_CONFIRM") != NULL)
        fkt_confirm_set_enabled(0);
#endif

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

    if (argc >= 3 && strcmp(argv[1], "qr") == 0)
        return fkt_cli_run_qr(argc, argv);

    /* PR5: pure CLI sign (always on, DOS + Linux). */
    if (argc >= 2 && strcmp(argv[1], "sign") == 0)
        return fkt_cli_run_sign(argc, argv);

    if (argc == 1)
        return fkt_ui_main_menu();

#if FKT_BUILD_DEV_HARNESS
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
        if (fkt_psbt_load_file(argv[2]) != 0) {
            fprintf(stderr, "Cannot load PSBT: %s\n", argv[2]);
            return 1;
        }
        psbt_to_base64(psbt_buffer, psbt_size);
        return 0;
    }

    if (argc == 5) {
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
        return 0;
    }
#endif

    print_usage_brief(argv[0]);
    return 1;
}