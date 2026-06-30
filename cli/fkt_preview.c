/* fkt_preview.c - read-only PSBT preview (no seed required) */
#define _POSIX_C_SOURCE 200809L

#include "fkt_preview.h"
#include "fkt_psbt.h"
#include "fkt_ui.h"
#include <stdio.h>
#include <string.h>

#define PREVIEW_GREEN   "\033[1;32m"
#define PREVIEW_DIM     "\033[32m"
#define PREVIEW_RESET   "\033[0m"
#define PREVIEW_BG      "\033[40m"

static void preview_puts(const char *s) {
    fputs(PREVIEW_GREEN PREVIEW_BG, stdout);
    fputs(s, stdout);
    fputs(PREVIEW_RESET "\n", stdout);
}

static void print_txid_reversed(const uint8_t txid[32]) {
    int i;
    fputs(PREVIEW_GREEN PREVIEW_BG, stdout);
    for (i = 31; i >= 0; i--)
        printf("%02x", txid[i]);
    fputs(PREVIEW_RESET, stdout);
}

static const char *input_script_label(uint8_t st) {
    switch (st) {
    case SCRIPT_TYPE_P2WPKH:      return "P2WPKH";
    case SCRIPT_TYPE_P2WSH:       return "P2WSH";
    case SCRIPT_TYPE_P2TR:        return "P2TR";
    case SCRIPT_TYPE_P2SH:        return "P2SH";
    case SCRIPT_TYPE_P2SH_P2WPKH: return "Nested (P2SH-P2WPKH)";
    default:                      return "Unknown";
    }
}

static const char *output_script_label(const uint8_t *spk, size_t len) {
    if (len == 22 && spk[0] == 0x00 && spk[1] == 0x14) return "P2WPKH";
    if (len == 34 && spk[0] == 0x51 && spk[1] == 0x20) return "P2TR";
    if (len == 23 && spk[0] == 0xa9 && spk[1] == 0x14) return "P2SH";
    if (len == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14) return "P2PKH";
    if (len == 34 && spk[0] == 0x00 && spk[1] == 0x20) return "P2WSH";
    return "Unknown";
}

static void print_output_address(const uint8_t *spk, size_t len) {
    int i;

    fputs(PREVIEW_DIM PREVIEW_BG, stdout);
    if (len == 22 && spk[0] == 0x00 && spk[1] == 0x14) {
        printf("witv0:");
        for (i = 0; i < 20; i++) printf("%02x", spk[2 + i]);
    } else if (len == 34 && spk[0] == 0x51 && spk[1] == 0x20) {
        printf("tap:");
        for (i = 0; i < 32; i++) printf("%02x", spk[2 + i]);
    } else if (len >= 23 && spk[0] == 0xa9 && spk[1] == 0x14) {
        printf("sh:");
        for (i = 0; i < 20; i++) printf("%02x", spk[2 + i]);
    } else if (len >= 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14) {
        printf("pkh:");
        for (i = 0; i < 20; i++) printf("%02x", spk[3 + i]);
    } else {
        printf("script:");
        for (i = 0; i < (int)len && i < 16; i++) printf("%02x", spk[i]);
        if ((int)len > 16) printf("...");
    }
    fputs(PREVIEW_RESET, stdout);
}

static size_t estimate_vsize(void) {
    size_t twb = 0;
    size_t w;
    int i;

    for (i = 0; i < psbt_data.num_inputs; i++) {
        uint8_t st = psbt_data.input_script_type[i];
        if (st == SCRIPT_TYPE_P2WPKH || st == SCRIPT_TYPE_P2SH_P2WPKH) twb += 109;
        else if (st == SCRIPT_TYPE_P2TR) twb += 65;
        else if (st == SCRIPT_TYPE_P2WSH) twb += 110;
        else twb += 107;
    }
    w = (size_t)psbt_data.unsigned_tx_len * 4 + twb;
    return (w + 3) / 4;
}

static int any_rbf(void) {
    int i;
    for (i = 0; i < psbt_data.num_inputs; i++) {
        if (psbt_data.input_sequence[i] < 0xFFFFFFFEu)
            return 1;
    }
    return 0;
}

static void render_preview(void) {
    int i;
    int64_t total_in = 0;
    int64_t total_out = 0;
    int64_t fee;
    size_t vsize;
    uint32_t tx_version = 0;
    char path_buf[128];
    char lock_rbf[128];
    int b;

    fkt_ui_draw_banner(1);

    fputs(PREVIEW_GREEN PREVIEW_BG, stdout);
    printf("\n  +");
    for (b = 0; b < 50; b++) printf("-");
    printf("+\n");
    printf("  |     FKT PSBT PREVIEW  [READ-ONLY]          |\n");
    printf("  +");
    for (b = 0; b < 50; b++) printf("-");
    printf("+\n");
    fputs(PREVIEW_RESET, stdout);

    if (psbt_data.unsigned_tx_len >= 4) {
        tx_version = (uint32_t)psbt_data.raw_unsigned_tx[0] |
                     ((uint32_t)psbt_data.raw_unsigned_tx[1] << 8) |
                     ((uint32_t)psbt_data.raw_unsigned_tx[2] << 16) |
                     ((uint32_t)psbt_data.raw_unsigned_tx[3] << 24);
    }

    fputs(PREVIEW_DIM PREVIEW_BG, stdout);
    printf("  v0 (BIP-174) * TX v%u\n", (unsigned)tx_version);
    printf("  Unsigned txid: ");
    fputs(PREVIEW_RESET, stdout);
    print_txid_reversed(psbt_data.txid);
    fputs(PREVIEW_DIM PREVIEW_BG, stdout);
    printf("\n");

    if (psbt_data.locktime > 0)
        snprintf(lock_rbf, sizeof(lock_rbf),
                 "nLockTime: %u (active) * RBF: %s",
                 (unsigned)psbt_data.locktime,
                 any_rbf() ? "YES (BIP125)" : "no");
    else
        snprintf(lock_rbf, sizeof(lock_rbf),
                 "nLockTime: %u * RBF: %s",
                 (unsigned)psbt_data.locktime,
                 any_rbf() ? "YES (BIP125)" : "no");
    printf("  %s\n", lock_rbf);
    fputs(PREVIEW_RESET, stdout);

    preview_puts("");
    preview_puts("  -- INPUTS --");
    for (i = 0; i < psbt_data.num_inputs; i++) {
        fputs(PREVIEW_DIM PREVIEW_BG, stdout);
        printf("  [%d] ", i);
        if (psbt_data.input_has_amount[i]) {
            printf("%lld sats  ", (long long)psbt_data.input_amount[i]);
            total_in += psbt_data.input_amount[i];
        } else {
            printf("(amount unknown)  ");
        }
        printf("%s", input_script_label(psbt_data.input_script_type[i]));
        if (fkt_psbt_format_derivation_path(i, path_buf, sizeof(path_buf)) == 0)
            printf("  path %s", path_buf);
        if (psbt_data.input_sequence[i] < 0xFFFFFFFEu)
            printf("  [RBF]");
        fputs(PREVIEW_RESET, stdout);
        putchar('\n');
    }

    preview_puts("");
    preview_puts("  -- OUTPUTS --");
    for (i = 0; i < psbt_data.num_outputs; i++) {
        const uint8_t *spk = psbt_data.output_script[i];
        size_t slen = psbt_data.output_script_len[i];

        fputs(PREVIEW_DIM PREVIEW_BG, stdout);
        printf("  [%d] %lld sats  %s  ",
               i, (long long)psbt_data.output_amount[i],
               output_script_label(spk, slen));
        print_output_address(spk, slen);
        fputs(PREVIEW_RESET, stdout);
        putchar('\n');
        total_out += psbt_data.output_amount[i];
    }

    fee = total_in - total_out;
    vsize = estimate_vsize();

    preview_puts("");
    fputs(PREVIEW_DIM PREVIEW_BG, stdout);
    printf("  Fee:           %lld sats\n", (long long)fee);
    if (vsize > 0 && fee >= 0)
        printf("  Fee rate:      %llu sat/vB (est. vsize %lu)\n",
               (unsigned long long)((uint64_t)fee / (uint64_t)vsize),
               (unsigned long)vsize);
    else
        printf("  Fee rate:      n/a\n");
    fputs(PREVIEW_RESET, stdout);
    preview_puts("");
}

int fkt_psbt_preview(const char *psbt_path) {
    if (!psbt_path || psbt_path[0] == '\0') {
        fprintf(stderr, "Preview: missing PSBT path.\n");
        return -1;
    }

    fkt_ui_term_init();
    fkt_ui_clear_screen();
    fkt_psbt_init();
    if (fkt_psbt_load_file(psbt_path) != 0) {
        fprintf(stderr, "Preview: cannot load %s\n", psbt_path);
        return -1;
    }

    fkt_psbt_lenient_parse = 1;
    fkt_psbt_parse();
    render_preview();
    fkt_psbt_lenient_parse = 0;
    return 0;
}