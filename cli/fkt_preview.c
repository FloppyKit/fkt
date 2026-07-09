/* fkt_preview.c - read-only PSBT preview (no seed required) */
#if !(defined(FKT_DOS) && FKT_DOS)
#define _POSIX_C_SOURCE 200809L
#endif

#include "fkt_preview.h"
#include "fkt_psbt.h"
#include "fkt_error.h"
#include "fkt_ui.h"
#include "fkt_platform.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static void preview_color(void) {
    fputs(fkt_ui_green_str(), stdout);
}

static void preview_puts(const char *s) {
    fkt_ui_body_puts(s);
}

static void preview_body_printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs(fkt_ui_green_str(), stdout);
    {
        int col = fkt_ui_body_col();
        int i;
        for (i = 1; i < col; i++)
            putchar(' ');
    }
    vprintf(fmt, ap);
    va_end(ap);
}

static void print_txid_reversed(const uint8_t txid[32]) {
    int i;
    preview_color();
    for (i = 31; i >= 0; i--)
        printf("%02x", txid[i]);
}

static const char *input_script_label(uint8_t st) {
    switch (st) {
    case SCRIPT_TYPE_P2WPKH:      return "P2WPKH";
    case SCRIPT_TYPE_P2WSH:       return "P2WSH";
    case SCRIPT_TYPE_P2TR:        return "P2TR";
    case SCRIPT_TYPE_P2SH:        return "P2SH";
    case SCRIPT_TYPE_P2SH_P2WPKH: return "Nested (P2SH-P2WPKH)";
    case SCRIPT_TYPE_P2PKH:       return "P2PKH";
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

static void print_hex_full(const uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

/* One address/program per line. Compact labels so v1_tap (64 hex) fits 80-col. */
static void print_output_program_line(const uint8_t *spk, size_t len) {
    int col = fkt_ui_body_col();
    int cols = fkt_ui_term_cols();
    int j;
    const char *label;
    const uint8_t *hex;
    size_t hex_len;
    int need;
    int start_col;

    if (len == 22 && spk[0] == 0x00 && spk[1] == 0x14) {
        label = "v0_pkh:";
        hex = spk + 2;
        hex_len = 20;
    } else if (len == 34 && spk[0] == 0x51 && spk[1] == 0x20) {
        label = "v1_tap:";
        hex = spk + 2;
        hex_len = 32;
    } else if (len >= 23 && spk[0] == 0xa9 && spk[1] == 0x14) {
        label = "p2sh:";
        hex = spk + 2;
        hex_len = 20;
    } else if (len >= 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14) {
        label = "pkh:";
        hex = spk + 3;
        hex_len = 20;
    } else if (len == 34 && spk[0] == 0x00 && spk[1] == 0x20) {
        label = "v0_wsh:";
        hex = spk + 2;
        hex_len = 32;
    } else {
        label = NULL;
        hex = spk;
        hex_len = len > 32 ? 32 : len;
    }

    /* label + 2*hex_len chars; fit under body indent when possible. */
    if (label)
        need = (int)strlen(label) + (int)(hex_len * 2);
    else
        need = 12 + (int)(hex_len * 2); /* "script_NNB:" worst-ish */

    start_col = col;
    if (cols > 0 && start_col + need - 1 > cols)
        start_col = 1; /* use full width so longer programs do not wrap */
    if (cols > 0 && start_col + need - 1 > cols)
        start_col = 1;

    preview_color();
    for (j = 1; j < start_col; j++)
        putchar(' ');
    if (label) {
        fputs(label, stdout);
        print_hex_full(hex, hex_len);
    } else {
        printf("script_%luB:", (unsigned long)len);
        print_hex_full(spk, hex_len);
        if (len > 32)
            fputs("...", stdout);
    }
    putchar('\n');
}

static int preview_any_signed_input(void) {
    int i;
    for (i = 0; i < psbt_data.num_inputs; i++) {
        if (psbt_data.input_had_final_witness[i] ||
            psbt_data.input_had_final_scriptsig[i])
            return 1;
    }
    return 0;
}

static int any_rbf(void) {
    int i;
    for (i = 0; i < psbt_data.num_inputs; i++) {
        if (psbt_data.input_sequence[i] < 0xFFFFFFFEu)
            return 1;
    }
    return 0;
}

static size_t estimate_vsize(void) {
    size_t twb = 0;
    size_t w;
    int i;

    for (i = 0; i < psbt_data.num_inputs; i++) {
        uint8_t st = psbt_data.input_script_type[i];
        if (st == SCRIPT_TYPE_P2WPKH || st == SCRIPT_TYPE_P2SH_P2WPKH)
            twb += 109;
        else if (st == SCRIPT_TYPE_P2TR)
            twb += 65;
        else if (st == SCRIPT_TYPE_P2WSH)
            twb += 110;
        else if (st == SCRIPT_TYPE_P2PKH)
            twb += 107;
        else
            twb += 107;
    }
    w = (size_t)psbt_data.unsigned_tx_len * 4 + twb;
    return (w + 3) / 4;
}

/* Compact debug: never push fee/header off a 25-line screen. */
static void render_preview_debug(void) {
    if (!fkt_ui_debug_enabled())
        return;

    {
        char fp[17];
        int i;

        for (i = 0; i < 8; i++)
            snprintf(fp + i * 2, 3, "%02x",
                     (unsigned)psbt_data.psbt_fingerprint[i]);
        preview_puts("");
        preview_body_printf("DEBUG: %lu B  in/out %d/%d  %s\n",
                            (unsigned long)psbt_size,
                            psbt_data.num_inputs, psbt_data.num_outputs,
                            preview_any_signed_input() ? "SIGNED" : "UNSIGNED");
        preview_body_printf("DEBUG: fp %s...\n", fp);
    }
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

    fkt_ui_draw_banner(1);
    fkt_ui_draw_subtitle("PREVIEW");

    if (psbt_data.unsigned_tx_len >= 4) {
        tx_version = (uint32_t)psbt_data.raw_unsigned_tx[0] |
                     ((uint32_t)psbt_data.raw_unsigned_tx[1] << 8) |
                     ((uint32_t)psbt_data.raw_unsigned_tx[2] << 16) |
                     ((uint32_t)psbt_data.raw_unsigned_tx[3] << 24);
    }

    /* Version + locktime/RBF on one line to free a row on short terminals. */
    if (psbt_data.locktime > 0)
        snprintf(lock_rbf, sizeof(lock_rbf),
                 "v0 (BIP-174) * TX v%u * nLock %u* * RBF %s",
                 (unsigned)tx_version,
                 (unsigned)psbt_data.locktime,
                 any_rbf() ? "YES" : "no");
    else
        snprintf(lock_rbf, sizeof(lock_rbf),
                 "v0 (BIP-174) * TX v%u * nLock %u * RBF %s",
                 (unsigned)tx_version,
                 (unsigned)psbt_data.locktime,
                 any_rbf() ? "YES" : "no");
    /* locktime>0 marks active with trailing * on the nLock value. */
    preview_body_printf("%s\n", lock_rbf);

    preview_body_printf("Unsigned txid:\n");
    {
        int col = fkt_ui_body_col();
        int j;
        preview_color();
        for (j = 1; j < col + 2; j++)
            putchar(' ');
        print_txid_reversed(psbt_data.txid);
        putchar('\n');
    }

    preview_puts("");
    preview_puts("-- INPUTS --");
    for (i = 0; i < psbt_data.num_inputs; i++) {
        preview_color();
        {
            int col = fkt_ui_body_col();
            int j;
            for (j = 1; j < col; j++)
                putchar(' ');
        }
        printf("[%d] ", i);
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
        putchar('\n');
    }

    preview_puts("");
    preview_puts("-- OUTPUTS --");
    for (i = 0; i < psbt_data.num_outputs; i++) {
        const uint8_t *spk = psbt_data.output_script[i];
        size_t slen = psbt_data.output_script_len[i];

        /* Amount + type on one line; full address on the next line alone. */
        preview_body_printf("[%d] %lld sats  %s\n",
                            i, (long long)psbt_data.output_amount[i],
                            output_script_label(spk, slen));
        print_output_program_line(spk, slen);
        total_out += psbt_data.output_amount[i];
    }

    fee = total_in - total_out;
    vsize = estimate_vsize();

    preview_puts("");
    preview_body_printf("Fee:           %lld sats\n", (long long)fee);
    if (vsize > 0 && fee >= 0)
        preview_body_printf("Fee rate:      %llu sat/vB (est. vsize %lu)\n",
                            (unsigned long long)((uint64_t)fee / (uint64_t)vsize),
                            (unsigned long)vsize);
    else
        preview_body_printf("Fee rate:      n/a\n");

    /* Debug last so fee stays visible; keep it tiny. */
    render_preview_debug();
}

void fkt_psbt_preview_render(void) {
    render_preview();
}

int fkt_psbt_preview_prepare(const char *psbt_path) {
    int old_lenient;

    if (!psbt_path || psbt_path[0] == '\0')
        return -1;

    fkt_psbt_init();
    if (fkt_psbt_load_input(psbt_path) != 0) {
        fkt_last_error_set("Failed to load PSBT file.");
        return -1;
    }

    old_lenient = fkt_psbt_lenient_parse;
    fkt_psbt_lenient_parse = 1;
    if (fkt_psbt_try_parse() != 0) {
        fkt_psbt_lenient_parse = old_lenient;
        fkt_psbt_init();
        return -1;
    }
    fkt_psbt_lenient_parse = old_lenient;
    return 0;
}

static void preview_draw_interactive_screen(void) {
    fkt_ui_clear_screen();
    fkt_psbt_preview_render();
    fkt_ui_body_puts("");
    fkt_ui_body_puts("[Q] QR PSBT   [?] Help   [Enter] Exit");
    fkt_ui_pin_session_footer();
    /* No input cursor on preview — key-driven only. */
    fkt_ui_set_input_pos(0, 0);
    fkt_screen_cursor_hide();
    fkt_ui_set_redraw_cb(preview_draw_interactive_screen);
}

int fkt_psbt_preview(const char *psbt_path) {
    int ch;

    if (!psbt_path || psbt_path[0] == '\0') {
        fprintf(stderr, "Preview: missing PSBT path.\n");
        return -1;
    }

    fkt_ui_term_init();
    if (fkt_psbt_preview_prepare(psbt_path) != 0) {
        const char *err = fkt_last_error_get();
        if (err && err[0] != '\0')
            fprintf(stderr, "Preview: %s\n", err);
        else
            fprintf(stderr, "Preview: invalid PSBT input.\n");
        fkt_ui_term_restore();
        return -1;
    }

    for (;;) {
        preview_draw_interactive_screen();
        ch = fkt_tty_read_key_once();
        if (ch < 0 || ch == FKT_KEY_SPECIAL)
            continue;
        if (ch == 27 || ch == '\r' || ch == '\n')
            break;
        if (ch == 'q' || ch == 'Q') {
            if (fkt_ui_show_qr_loaded_psbt() != 0)
                fkt_ui_body_puts("[!] Could not encode PSBT as QR.");
            continue;
        }
        if (ch == '?' || ch == '!' || ch == '#') {
            char hk[2];
            hk[0] = (char)ch;
            hk[1] = '\0';
            if (fkt_ui_handle_hotkey(hk) == 2) /* FKT_UI_HK_MENU */
                break;
            continue;
        }
    }

    fkt_ui_term_restore();
    return 0;
}
