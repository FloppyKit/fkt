/* fkt_ui.c - shared terminal UI: retro ASCII frame (C89) */
#if !(defined(FKT_DOS) && FKT_DOS)
#define _POSIX_C_SOURCE 200809L
#endif

#include "fkt_ui.h"
#include "fkt_build.h"
#include "fkt_version.h"
#include "fkt_seed.h"
#include "fkt_preview.h"
#include "fkt_confirm.h"
#include "fkt_psbt.h"
#include "fkt_bip39.h"
#include "fkt_memzero.h"
#include "fkt_error.h"
#include "fkt_qr.h"
#include "fkt_qr_vga.h"
#include "fkt_sha256.h"
#include "fkt_platform.h"
#include "fkt_cam.h"
#include "fkt_address.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if FKT_PLATFORM_LINUX || FKT_PLATFORM_DOS
#include <unistd.h>
#endif

#define UI_GREEN     "\033[32m"
/* 256-color deep orange (was ANSI yellow 33). Falls back poorly only on
 * ancient 16-color terms; DOS uses VRAM brown attr instead (see fkt_screen). */
#define UI_AMBER     "\033[38;5;208m"
#define UI_PURPLE    "\033[35m"

#if (defined(FKT_ASCII_ONLY) && FKT_ASCII_ONLY) || FKT_PLATFORM_DOS
#define UI_HLINE       "-"
#define UI_EM_DASH     "-"
#define UI_BULLET_ON   "[*]"
#define UI_BULLET_OFF  "[ ]"
#define UI_BLOCK_FULL  "#"
#define UI_BLOCK_EMPTY "."
#else
#define UI_HLINE       "\342\224\200"
#define UI_EM_DASH     "\342\200\224"
#define UI_BULLET_ON   "\342\227\217"
#define UI_BULLET_OFF  "\342\227\213"
#define UI_BLOCK_FULL  "\342\226\210"
#define UI_BLOCK_EMPTY "\342\226\221"
#endif


/* Built each paint: "FKT SIGNER v" + FKT_VERSION_STRING */
#define UI_BODY_W      66

#define SIGN_DEFAULT_OUT "tx-2026-07-06-fkt.psbt"
#define ENTROPY_TARGET_BITS 256

#define WALLET_BOX_INNER  11
#define WALLET_BOX_HEIGHT (WALLET_BOX_INNER + 2)

#define ENTROPY_MEME_PCT 420
#define UI_TOGGLE_LABEL  "Toggle: ?/Help  !/Debug  #/Theme"
#define FKT_UI_HK_NONE    0
#define FKT_UI_HK_HANDLED 1
#define FKT_UI_HK_MENU    2

#define WALLET_BOX_TITLE "NEW SEED PHRASE (BIP39)"
#define WALLET_BOX_PROMPT "Enter number of words (12 or 24): "

#define GRID_PAD_H      2
#define GRID_CONTENT_W  45
#define GRID_INNER_W    (GRID_PAD_H + GRID_CONTENT_W + GRID_PAD_H)
#define GRID_VISIBLE    (GRID_INNER_W + 2)

static int g_ui_cols = 80;
static int g_ui_rows = 24;
static int g_ui_theme_amber = 0;
static int g_ui_debug = 0;
static int g_input_row = 0;
static int g_input_col = 0;
static int g_ui_input_hidden = 0;
static void (*g_ui_redraw_cb)(void);

static char g_psbt_path[FKT_PSBT_INPUT_MAX];
static char g_psbt_load_err[80];
static char g_sign_out_path[512];
static int  g_seed_loaded = 0;
static char g_session_words[MAX_WORDS][WORD_BUF];
static int  g_session_num_words = 0;
/* Session-only receive counters (Ice Cold: no disk). Reset on seed unload. */
static uint32_t g_recv_idx_wpkh = 0;
static uint32_t g_recv_idx_tr = 0;

static int g_term_raw = 0;
static int g_term_interactive = 0;

static void ui_draw_sign_screen(int done);
static void ui_draw_generated_seed_screen(const char words[][WORD_BUF], int num_words);
static void ui_recv_reset_indices(void);
static void ui_draw_receive_address_screen(void);
static void ui_draw_entropy_screen(int pct, int roll, int spin_frame, int animate,
                                   int locked, int quantum_flash, int num_words);
static int ui_handle_global_hotkey(const char *choice);

static const char *UI_DUMMY_WORDS[24] = {
    "abandon", "ability", "able", "about", "above", "absent",
    "absorb", "abstract", "absurd", "abuse", "access", "accident",
    "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual"
};

static const char *UI_SPINNER[] = { "|", "/", "-", "\\" };

static const char *ui_green(void) {
    if (!fkt_screen_has_ansi())
        return "";
    return g_ui_theme_amber ? UI_AMBER : UI_GREEN;
}

const char *fkt_ui_green_str(void) {
    return ui_green();
}

void fkt_ui_term_init(void) {
    /* DOS TUI only — pure CLI never forces mode 03 / banner. */
    fkt_dos_init();
    fkt_tty_init();
    g_ui_cols = fkt_tty_cols();
    g_ui_rows = fkt_tty_rows();
}

void fkt_ui_term_restore(void) {
    fkt_tty_restore();
    g_term_raw = 0;
    g_term_interactive = 0;
}

int fkt_ui_term_cols(void) { return g_ui_cols; }
int fkt_ui_term_rows(void) { return g_ui_rows; }

void fkt_ui_clear_screen(void) {
    fkt_screen_clear();
    fputs(ui_green(), stdout);
    fflush(stdout);
}

int fkt_ui_theme_bright(void) {
    return !g_ui_theme_amber;
}

int fkt_ui_debug_enabled(void) {
    return g_ui_debug;
}

void fkt_ui_toggle_theme(void) {
    g_ui_theme_amber = !g_ui_theme_amber;
#if FKT_PLATFORM_DOS
    /* VRAM attribute theme (green 0x0A <-> brown/orange 0x06). */
    fkt_screen_set_theme_amber(g_ui_theme_amber);
#endif
}

static int ui_line_w(void) {
    if (g_ui_cols < 40)
        return 40;
    return g_ui_cols;
}

void fkt_ui_draw_separator(void) {
    int w = ui_line_w();
    int i;

    fputs(ui_green(), stdout);
    for (i = 0; i < w; i++)
        fputs(UI_HLINE, stdout);
    putchar('\n');
}

/* Pin separator to an absolute row with NO trailing newline (avoids scroll). */
static void ui_draw_separator_at(int row) {
    int w = ui_line_w();
    int i;

    fkt_screen_clear_line(row);
    fputs(ui_green(), stdout);
    fkt_screen_goto(row, 1);
    for (i = 0; i < w; i++)
        fputs(UI_HLINE, stdout);
    fflush(stdout);
}

void fkt_ui_draw_footer(const char *seed_st, const char *psbt_st) {
    char left[96];
    char line[256];
    int lw;
    int left_len;
    int toggle_len;
    int toggle_at;
    int i;

    lw = ui_line_w();
    if (lw > (int)sizeof(line) - 1)
        lw = (int)sizeof(line) - 1;

    snprintf(left, sizeof(left), "  Seed %s | PSBT %s", seed_st, psbt_st);
    left_len = (int)strlen(left);
    toggle_len = (int)strlen(UI_TOGGLE_LABEL);
    toggle_at = lw - toggle_len;
    if (toggle_at < 0)
        toggle_at = 0;

    for (i = 0; i < lw; i++)
        line[i] = ' ';
    line[lw] = '\0';
    if (left_len > toggle_at)
        left_len = toggle_at;
    if (left_len > 0)
        memcpy(line, left, (size_t)left_len);
    memcpy(line + toggle_at, UI_TOGGLE_LABEL, (size_t)toggle_len);

    fputs(ui_green(), stdout);
    fwrite(line, 1, (size_t)lw, stdout);
    putchar('\n');
    fflush(stdout);
}

/* Pin footer text to absolute row — no trailing \n (last-row scroll killer). */
static void ui_draw_footer_at(int row, const char *seed_st, const char *psbt_st) {
    char left[96];
    char line[256];
    int lw;
    int left_len;
    int toggle_len;
    int toggle_at;
    int i;

    lw = ui_line_w();
    if (lw > (int)sizeof(line) - 1)
        lw = (int)sizeof(line) - 1;

    snprintf(left, sizeof(left), "  Seed %s | PSBT %s", seed_st, psbt_st);
    left_len = (int)strlen(left);
    toggle_len = (int)strlen(UI_TOGGLE_LABEL);
    toggle_at = lw - toggle_len;
    if (toggle_at < 0)
        toggle_at = 0;

    for (i = 0; i < lw; i++)
        line[i] = ' ';
    line[lw] = '\0';
    if (left_len > toggle_at)
        left_len = toggle_at;
    if (left_len > 0)
        memcpy(line, left, (size_t)left_len);
    memcpy(line + toggle_at, UI_TOGGLE_LABEL, (size_t)toggle_len);

    fkt_screen_clear_line(row);
    fputs(ui_green(), stdout);
    fkt_screen_goto(row, 1);
    fwrite(line, 1, (size_t)lw, stdout);
    fflush(stdout);
}

void fkt_ui_pin_footer(const char *seed_st, const char *psbt_st) {
    if (g_ui_rows >= 4) {
        /* Absolute rows, no newlines — a trailing \n on the last row scrolls
         * the permanent banner title off the top (cursor then looks 1 low). */
        ui_draw_separator_at(g_ui_rows - 2);
        ui_draw_footer_at(g_ui_rows - 1, seed_st, psbt_st);
        fkt_screen_recolor();
    } else {
        printf("\n");
        fkt_ui_draw_separator();
        fkt_ui_draw_footer(seed_st, psbt_st);
    }
}

static const char *ui_seed_status(void) {
    return g_seed_loaded ? UI_BULLET_ON " loaded" : UI_BULLET_OFF " not loaded";
}

static const char *ui_psbt_status(void) {
    return g_psbt_path[0] ? UI_BULLET_ON " loaded" : UI_BULLET_OFF " not loaded";
}

void fkt_ui_pin_session_footer(void) {
    fkt_ui_pin_footer(ui_seed_status(), ui_psbt_status());
}

static void ui_draw_top_banner(void) {
#if FKT_PLATFORM_DOS
    /*
     * Permanent banner is painted by fkt_screen_clear / fkt_dos_init
     * via VRAM (green attr). Do not printf another copy — that was
     * pushing the body cursor 2 lines too low under DOS.
     */
    (void)0;
#else
    char line[256];
    char left_label[40];
    int lw = ui_line_w();
    int left_len;
    int right_len = (int)strlen(FKT_WALLET_LABEL);
    int dbg_at = (lw - 3) / 2;
    int i;

    snprintf(left_label, sizeof(left_label), "FKT SIGNER v%s", FKT_VERSION_STRING);
    left_len = (int)strlen(left_label);

    if (lw > (int)sizeof(line) - 1)
        lw = (int)sizeof(line) - 1;

    for (i = 0; i < lw; i++)
        line[i] = ' ';
    line[lw] = '\0';
    if (left_len > lw)
        left_len = lw;
    memcpy(line, left_label, (size_t)left_len);
    if (right_len < lw)
        memcpy(line + lw - right_len, FKT_WALLET_LABEL, (size_t)right_len);
    if (g_ui_debug)
        memcpy(line + dbg_at, "DBG", 3);

    fputs(ui_green(), stdout);
    for (i = 0; i < lw; i++) {
        if (g_ui_debug && i == dbg_at) {
            fputs(UI_PURPLE, stdout);
            fputs("DBG", stdout);
            fputs(ui_green(), stdout);
            i += 2;
            continue;
        }
        putchar(line[i]);
    }
    putchar('\n');
    fkt_ui_draw_separator();
#endif
}

static void ui_show_cursor(void) {
    fkt_screen_cursor_show();
}

static void ui_hide_cursor(void) {
    fkt_screen_cursor_hide();
}

static int ui_apply_cbreak(void) {
    return fkt_tty_raw_begin();
}

static void ui_term_raw_on(void) {
    if (fkt_tty_raw_begin() == 0)
        g_term_raw = 1;
}

static void ui_term_raw_off(void) {
    if (g_term_raw) {
        fkt_ui_term_restore();
    } else {
        ui_show_cursor();
    }
}

static void ui_place_cursor(int row, int col) {
    fkt_screen_goto(row, col);
}

static int ui_str_display_width(const char *s) {
    int w = 0;
    if (!s)
        return 0;
    while (*s) {
        if (((unsigned char)*s & 0xC0) != 0x80)
            w++;
        s++;
    }
    return w;
}

static int ui_hpad(int width) {
    int pad = (g_ui_cols - width) / 2;
    return pad > 0 ? pad : 0;
}

static void ui_put_hpad(int width) {
    int pad = ui_hpad(width);
    while (pad-- > 0)
        putchar(' ');
}

static void ui_draw_centered_at(int row, const char *text) {
    fkt_screen_clear_line(row);
    fputs(ui_green(), stdout);
    ui_put_hpad(ui_str_display_width(text));
    fputs(text, stdout);
    fflush(stdout);
}

static void ui_draw_at_col(int row, int col, const char *text) {
    fkt_screen_clear_line(row);
    fputs(ui_green(), stdout);
    fkt_screen_goto(row, col);
    fputs(text, stdout);
    fflush(stdout);
}

int fkt_ui_body_col(void) {
    return ui_hpad(UI_BODY_W) + 1;
}

void fkt_ui_draw_subtitle(const char *title) {
    int row = FKT_UI_BANNER_ROWS + 1; /* first body row under permanent banner */
    int tw;
    int col;

    /* Absolute placement so DOS never draws under/into the banner rule. */
    tw = ui_str_display_width(title);
    col = ui_hpad(tw) + 1;
    fkt_screen_clear_line(row);
    fputs(ui_green(), stdout);
    fkt_screen_goto(row, col);
    fputs(title, stdout);
    fkt_screen_clear_line(row + 1);
    fkt_screen_goto(row + 2, 1);
    fflush(stdout);
}

void fkt_ui_body_puts(const char *text) {
    fputs(ui_green(), stdout);
    ui_put_hpad(UI_BODY_W);
    fputs(text, stdout);
    putchar('\n');
}

void fkt_ui_body_printf(const char *fmt, ...) {
    va_list ap;

    fputs(ui_green(), stdout);
    ui_put_hpad(UI_BODY_W);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

static int fkt_ui_show_qr_encoded_ex(int term_max_modules, const char *subtitle,
                                     int force_term) {
    fkt_ui_term_restore();
    /* Text chrome only when forcing ASCII (VGA owns the whole screen). */
    if (force_term || !fkt_qr_vga_available()) {
        fkt_ui_clear_screen();
        fkt_ui_draw_banner(1);
        if (subtitle != NULL && subtitle[0] != '\0')
            fkt_ui_draw_subtitle(subtitle);
    }
    fkt_qr_display_ex(fkt_ui_term_cols(), fkt_ui_term_rows(), 1, force_term,
                      term_max_modules);
    fkt_qr_clear();
    /* Idempotent: VGA wait_key already restored; ASCII needs a full text reset. */
    fkt_screen_after_graphics();
    return 0;
}

static int fkt_ui_show_qr_encoded(int term_max_modules, const char *subtitle) {
    return fkt_ui_show_qr_encoded_ex(term_max_modules, subtitle, 0);
}

static int fkt_ui_show_qr_psbt_ascii(const char *path) {
    char b64[FKT_QR_MAX_PAYLOAD + 1];

    if (!path || path[0] == '\0')
        return -1;
    if (fkt_psbt_file_to_base64(path, b64, sizeof(b64)) != 0)
        return -1;
    if (fkt_qr_encode_text(b64) != 0)
        return -1;
    return fkt_ui_show_qr_encoded_ex(FKT_QR_TERM_MAX_MODULES, "ASCII QR", 1);
}

int fkt_ui_show_qr_text(const char *text) {
    if (!text || text[0] == '\0')
        return -1;
    if (fkt_qr_encode_text(text) != 0)
        return -1;
    return fkt_ui_show_qr_encoded(FKT_QR_TERM_MAX_MODULES, "SCAN QR");
}

int fkt_ui_show_qr_loaded_psbt(void) {
    char b64[FKT_QR_MAX_PAYLOAD + 1];

    if (fkt_psbt_loaded_to_base64(b64, sizeof(b64)) != 0)
        return -1;
    return fkt_ui_show_qr_text(b64);
}

int fkt_ui_show_qr_psbt_file(const char *path) {
    char b64[FKT_QR_MAX_PAYLOAD + 1];

    if (!path || path[0] == '\0')
        return -1;
    if (fkt_psbt_file_to_base64(path, b64, sizeof(b64)) != 0)
        return -1;
    return fkt_ui_show_qr_text(b64);
}

int fkt_ui_show_qr_seed(const char words[][WORD_BUF], int num_words) {
    char payload[FKT_QR_MAX_PAYLOAD + 1];
    size_t pos = 0;
    int i;

    if (!words || num_words < 1)
        return -1;
    for (i = 0; i < num_words; i++) {
        size_t wlen;

        if (i > 0) {
            if (pos + 1 >= sizeof(payload))
                return -1;
            payload[pos++] = ' ';
        }
        wlen = strlen(words[i]);
        if (pos + wlen >= sizeof(payload))
            return -1;
        memcpy(payload + pos, words[i], wlen);
        pos += wlen;
    }
    payload[pos] = '\0';
    if (fkt_qr_encode_text(payload) != 0)
        return -1;
    return fkt_ui_show_qr_encoded(FKT_QR_TERM_MAX_SEED_MODULES,
                                  "SEED BACKUP " UI_EM_DASH " SCAN WITH PHONE");
}

static int ui_choice_is_qr(const char *line) {
    return line && (line[0] == 'q' || line[0] == 'Q');
}

void fkt_ui_set_input_pos(int row, int col) {
    g_input_row = row;
    g_input_col = col;
}

void fkt_ui_set_redraw_cb(void (*fn)(void)) {
    g_ui_redraw_cb = fn;
}

static void ui_echo_input(const char *buf, size_t len) {
    int col;
    int i;

    if (g_input_row <= 0 || g_input_col <= 0)
        return;
    fkt_screen_goto(g_input_row, g_input_col);
    fputs(ui_green(), stdout);
    fputs(buf, stdout);
    /* Wipe a few trailing glyphs so backspace does not leave ghosts. */
    for (i = 0; i < 3; i++)
        putchar(' ');
    col = g_input_col + (int)len;
    fkt_screen_goto(g_input_row, col);
    fflush(stdout);
}

static void ui_grid_pack_inner(char *out, const char *text) {
    int i;
    int tlen = text ? (int)strlen(text) : 0;

    for (i = 0; i < GRID_INNER_W; i++)
        out[i] = ' ';
    out[GRID_INNER_W] = '\0';
    if (tlen > GRID_CONTENT_W)
        tlen = GRID_CONTENT_W;
    if (tlen > 0)
        memcpy(out + GRID_PAD_H, text, (size_t)tlen);
}

static void ui_grid_build_line(const char words[][WORD_BUF], int num_words,
                               int row, char *line, size_t line_len) {
    int cols = 3;
    int grid_rows = num_words / cols;
    int c;
    size_t pos = 0;

    line[0] = '\0';
    for (c = 0; c < cols; c++) {
        char cell[16];
        int idx = c * grid_rows + row;
        int n;

        if (idx < num_words)
            n = snprintf(cell, sizeof(cell), "%2d.%-10s",
                           idx + 1, words[idx]);
        else
            n = snprintf(cell, sizeof(cell), "%2d.%-10s", idx + 1, "...");
        if (n < 0)
            return;
        if (c > 0 && pos + 3 < line_len) {
            memcpy(line + pos, " | ", 3);
            pos += 3;
            line[pos] = '\0';
        }
        if (pos + (size_t)n < line_len) {
            memcpy(line + pos, cell, (size_t)n);
            pos += (size_t)n;
            line[pos] = '\0';
        }
    }
}

static void ui_grid_draw_row(const char *text) {
    char inner[GRID_INNER_W + 1];

    ui_grid_pack_inner(inner, text);
    fputs(ui_green(), stdout);
    ui_put_hpad(GRID_VISIBLE);
    putchar('|');
    fputs(inner, stdout);
    putchar('|');
    putchar('\n');
}

static void ui_grid_edge(int bottom) {
    int i;

    (void)bottom;
    fputs(ui_green(), stdout);
    ui_put_hpad(GRID_VISIBLE);
    putchar('+');
    for (i = 0; i < GRID_INNER_W; i++)
        putchar('-');
    putchar('+');
    putchar('\n');
}

static void ui_box_pack_inner(char *out, const char *text, int center) {
    int i;
    int tlen = text ? (int)strlen(text) : 0;
    int start = GRID_PAD_H;

    for (i = 0; i < GRID_INNER_W; i++)
        out[i] = ' ';
    out[GRID_INNER_W] = '\0';
    if (tlen > GRID_CONTENT_W)
        tlen = GRID_CONTENT_W;
    if (center)
        start = GRID_PAD_H + (GRID_CONTENT_W - tlen) / 2;
    if (tlen > 0)
        memcpy(out + start, text, (size_t)tlen);
}

static void ui_box_row_at(int row, const char *text, int center) {
    char inner[GRID_INNER_W + 1];

    ui_box_pack_inner(inner, text, center);
    fkt_screen_clear_line(row);
    fputs(ui_green(), stdout);
    ui_put_hpad(GRID_VISIBLE);
    putchar('|');
    fputs(inner, stdout);
    putchar('|');
    fflush(stdout);
}

static void ui_box_edge_at(int row) {
    int i;

    fkt_screen_clear_line(row);
    fputs(ui_green(), stdout);
    ui_put_hpad(GRID_VISIBLE);
    putchar('+');
    for (i = 0; i < GRID_INNER_W; i++)
        putchar('-');
    putchar('+');
    fflush(stdout);
}

static int ui_wallet_box_vpad(void) {
    int avail = g_ui_rows - FKT_UI_BANNER_ROWS - 2;
    int vpad = FKT_UI_BANNER_ROWS + (avail - WALLET_BOX_HEIGHT) / 2;

    if (vpad < FKT_UI_BANNER_ROWS)
        vpad = FKT_UI_BANNER_ROWS;
    return vpad;
}

static void ui_draw_wallet_wordcount_screen(void) {
    int vpad = ui_wallet_box_vpad();
    int top = vpad + 1;
    int prompt_row = top + 1 + 8;
    int cursor_col;

    fkt_ui_clear_screen();
    ui_draw_top_banner();
    fputs(ui_green(), stdout);
    ui_box_edge_at(top);
    ui_box_row_at(top + 1, "", 0);
    ui_box_row_at(top + 2, "", 0);
    ui_box_row_at(top + 3, WALLET_BOX_TITLE, 1);
    ui_box_row_at(top + 4, "", 0);
    ui_box_row_at(top + 5, "", 0);
    ui_box_row_at(top + 6, "", 0);
    ui_box_row_at(top + 7, "", 0);
    ui_box_row_at(top + 8, "", 0);
    ui_box_row_at(prompt_row, WALLET_BOX_PROMPT, 0);
    ui_box_row_at(top + 10, "", 0);
    ui_box_row_at(top + 11, "", 0);
    ui_box_edge_at(top + 12);
    fkt_ui_pin_footer(UI_BULLET_OFF " not loaded", UI_BULLET_OFF " not loaded");
    cursor_col = ui_hpad(GRID_VISIBLE) + 2 + GRID_PAD_H +
                 (int)strlen(WALLET_BOX_PROMPT) + 1;
    fkt_ui_set_input_pos(prompt_row, cursor_col);
    ui_place_cursor(prompt_row, cursor_col);
    ui_show_cursor();
    g_ui_redraw_cb = ui_draw_wallet_wordcount_screen;
}

static int ui_prompt_wallet_word_count(int *num_words) {
    char buf[32];

    ui_draw_wallet_wordcount_screen();
    if (!fkt_ui_read_line(buf, sizeof(buf), 0))
        return 0;
    *num_words = atoi(buf);
    if (*num_words != 12 && *num_words != 24)
        return 0;
    return 1;
}

void fkt_show_seed_grid(const char words[][WORD_BUF], int num_words) {
    int rows;
    int r;

    fputs(ui_green(), stdout);
    if (num_words < 1)
        return;
    rows = num_words / 3;
    if (rows < 1)
        rows = 1;

    ui_grid_edge(0);
    for (r = 0; r < rows; r++) {
        char line[GRID_INNER_W + 1];
        ui_grid_build_line(words, num_words, r, line, sizeof(line));
        ui_grid_draw_row(line);
    }
    ui_grid_edge(1);
}

static void ui_draw_main_menu(void) {
    static const char *items[7] = {
        "1. Load seed",
        "2. Load PSBT",
        "3. Preview transaction",
        "4. Sign transaction",
        "5. Show seed",
        "6. Create new wallet",
        "0. Exit"
    };
    /* Always recover from sub-screens that hid the cursor / left raw mode. */
    g_ui_input_hidden = 0;
    fkt_mouse_hide();
    fkt_screen_cursor_show();
    const char *title = "MAIN MENU";
    const char *prompt = "Select option: ";
    int max_w = ui_str_display_width(title);
    int menu_col;
    int row;
    int i;
    int input_col;
    int block_h;
    int avail;
    int content_top;
    int prompt_row;

    for (i = 0; i < 7; i++) {
        int iw = ui_str_display_width(items[i]);
        if (iw > max_w)
            max_w = iw;
    }
    {
        int pw = ui_str_display_width(prompt);
        if (pw > max_w)
            max_w = pw;
    }

    menu_col = ui_hpad(max_w) + 1;
    block_h = 1 + 2 + 7 + 1;
    avail = g_ui_rows - FKT_UI_BANNER_ROWS - 3;
    content_top = FKT_UI_BANNER_ROWS + 1 + (avail - block_h) / 2;
    if (content_top < FKT_UI_BANNER_ROWS + 1)
        content_top = FKT_UI_BANNER_ROWS + 1;
    prompt_row = content_top + 1 + 2 + 7;

    fkt_ui_clear_screen();
    ui_draw_top_banner();

    row = content_top;
    ui_draw_centered_at(row, title);
    row += 2;
    for (i = 0; i < 7; i++) {
        ui_draw_at_col(row, menu_col, items[i]);
        row++;
    }

    ui_draw_at_col(prompt_row, menu_col, prompt);
    input_col = menu_col + (int)strlen(prompt);

    fkt_ui_pin_session_footer();
    fkt_ui_set_input_pos(prompt_row, input_col);
    ui_place_cursor(prompt_row, input_col);
    ui_show_cursor();
    g_ui_redraw_cb = ui_draw_main_menu;
}

static void ui_draw_load_psbt_screen(void) {
    char cwd[512];
    int body_col = fkt_ui_body_col();
    /* Keep prompt high enough that paste never collides with footer. */
    int prompt_row = FKT_UI_BANNER_ROWS + 7;

    fkt_ui_clear_screen();
    ui_draw_top_banner();
    fkt_ui_draw_subtitle("LOAD PSBT - TYPE PATH");
    if (getcwd(cwd, sizeof(cwd)) != NULL)
        fkt_ui_body_printf("Working directory: %s\n", cwd);
    else
        fkt_ui_body_printf("Working directory: (unknown)\n");
    fkt_ui_body_printf("PSBT file path or paste base64:\n");
    fkt_ui_body_printf("(Esc cancel  |  multi-line paste ok  |  Enter submits)\n");
    if (g_psbt_load_err[0])
        fkt_ui_body_printf("[!] %s\n", g_psbt_load_err);
    fkt_screen_clear_line(prompt_row);
    fputs(ui_green(), stdout);
    ui_put_hpad(UI_BODY_W);
    fputs("> ", stdout);
    fkt_ui_pin_session_footer();
    fkt_ui_set_input_pos(prompt_row, body_col + 2);
    ui_place_cursor(prompt_row, body_col + 2);
    ui_show_cursor();
    g_ui_redraw_cb = ui_draw_load_psbt_screen;
}

static void ui_trim_line(char *s) {
    size_t len;
    size_t start = 0;

    if (!s)
        return;
    while (s[start] == ' ' || s[start] == '\t')
        start++;
    if (start > 0)
        memmove(s, s + start, strlen(s + start) + 1);
    len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t')) {
        s[len - 1] = '\0';
        len--;
    }
}

static int ui_prompt_load_psbt_type(char *out, size_t out_len) {
    /* Stay on this screen until load succeeds or user cancels (Esc). */
    for (;;) {
        ui_draw_load_psbt_screen();
        if (!fkt_ui_read_line(out, out_len, 1))
            return 0;
        ui_trim_line(out);
        if (out[0] == '\0')
            return 0;
        if (fkt_psbt_load_input(out) == 0) {
            g_psbt_load_err[0] = '\0';
            return 1;
        }
        strncpy(g_psbt_load_err, "Not a valid PSBT file or base64.",
                sizeof(g_psbt_load_err) - 1);
        g_psbt_load_err[sizeof(g_psbt_load_err) - 1] = '\0';
        /* Loop: re-draw with error; do not bounce back to browse. */
    }
}

static void ui_load_psbt_camera_fallback(void) {
    fkt_ui_clear_screen();
    ui_draw_top_banner();
    fkt_ui_draw_subtitle("CAMERA / QR INPUT");
    if (fkt_cam_available()) {
        fkt_ui_body_puts("Camera probe: available.");
        fkt_ui_body_puts("Capture is not wired for this build yet.");
    } else {
        fkt_ui_body_puts("Camera not available on this machine.");
        fkt_ui_body_printf("%s\n", fkt_cam_unavailable_reason());
    }
    fkt_ui_body_puts("");
    fkt_ui_body_puts("Graceful fallback:");
    fkt_ui_body_puts("  - Browse a .psbt file from disk (recommended)");
    fkt_ui_body_puts("  - Or type/paste Base64 of the PSBT");
    fkt_ui_body_puts("");
    fkt_ui_body_puts("Press any key to continue...");
    fkt_ui_pin_session_footer();
    (void)fkt_tty_read_key_once();
}

/* Intermediate load chooser (kept for M=more from browse). Returns:
 * 1 loaded ok, 0 cancel/back to menu, -1 re-browse. */
static int ui_prompt_load_psbt_chooser(char *out, size_t out_len) {
    int ch;

    fkt_ui_clear_screen();
    ui_draw_top_banner();
    fkt_ui_draw_subtitle("LOAD PSBT");
    fkt_ui_body_puts("[B] Browse files");
    fkt_ui_body_puts("[T] Type path or paste Base64");
    fkt_ui_body_puts("[C] Camera / QR (graceful fallback)");
    fkt_ui_body_puts("[Esc] Cancel");
    fkt_ui_pin_session_footer();
    ch = fkt_tty_read_key_once();
    if (ch == 27)
        return 0;
    if (ch == 't' || ch == 'T') {
        int tr = ui_prompt_load_psbt_type(out, out_len);
        if (tr == 1)
            return 1;
        if (tr == 0)
            return 0;
        return -1;
    }
    if (ch == 'c' || ch == 'C') {
        char cap[FKT_PSBT_INPUT_MAX];
        if (fkt_cam_capture_text(cap, sizeof(cap)) == 0) {
            if (fkt_psbt_load_input(cap) == 0) {
                strncpy(out, "(camera)", out_len - 1);
                out[out_len - 1] = '\0';
                return 1;
            }
        }
        ui_load_psbt_camera_fallback();
        return -1;
    }
    if (ch == 'b' || ch == 'B')
        return -1;
    return 0;
}

static int ui_prompt_load_psbt(char *out, size_t out_len) {
    for (;;) {
        int pr;

        g_psbt_load_err[0] = '\0';
        /* Browse first (arrows + mouse). T=type  M=more  Esc=main menu. */
        pr = fkt_pick_file(out, out_len, ".psbt", "LOAD PSBT - BROWSE");
        if (pr == 1) {
            if (fkt_psbt_load_input(out) == 0) {
                g_psbt_load_err[0] = '\0';
                return 1;
            }
            strncpy(g_psbt_load_err, "Not a valid PSBT file.",
                    sizeof(g_psbt_load_err) - 1);
            g_psbt_load_err[sizeof(g_psbt_load_err) - 1] = '\0';
            fkt_ui_clear_screen();
            ui_draw_top_banner();
            fkt_ui_draw_subtitle("LOAD PSBT");
            fkt_ui_body_printf("[!] %s\n", g_psbt_load_err);
            fkt_ui_body_printf("Tried: %s\n", out);
            fkt_ui_body_puts("Press any key to browse again...");
            fkt_ui_pin_session_footer();
            (void)fkt_tty_read_key_once();
            continue;
        }
        if (pr == 2) {
            int tr = ui_prompt_load_psbt_type(out, out_len);
            if (tr == 1)
                return 1;
            return 0; /* cancel from type screen */
        }
        if (pr == 3) {
            int cr = ui_prompt_load_psbt_chooser(out, out_len);
            if (cr == 1)
                return 1;
            if (cr == 0)
                return 0;
            continue; /* re-browse */
        }
        /* Esc from browser → straight back to main menu. */
        return 0;
    }
}

static void ui_draw_preview_screen(void) {
    fkt_ui_clear_screen();
    fkt_psbt_preview_render();
    fkt_ui_body_puts("");
    fkt_ui_body_puts("[Q] QR PSBT   [?] Help   [Enter] Return");
    fkt_ui_pin_session_footer();
    /* No blinking cursor on preview (was shifting Fee rate layout). */
    g_ui_input_hidden = 1;
    g_input_row = 0;
    g_input_col = 0;
    ui_hide_cursor();
    g_ui_redraw_cb = ui_draw_preview_screen;
}

static int g_ui_sign_screen_done;

static void ui_redraw_sign_screen(void) {
    ui_draw_sign_screen(g_ui_sign_screen_done);
}

static void ui_draw_sign_screen(int done) {
    int body_col = fkt_ui_body_col();
    int prompt_row = FKT_UI_BANNER_ROWS + 7;
    /* "Filename: >" — '>' sits one space right of the label. */
    static const char fname_lab[] = "Filename: > ";
    int cursor_col = body_col + (int)strlen(fname_lab);

    fkt_ui_clear_screen();
    ui_draw_top_banner();
    fkt_ui_draw_subtitle("SIGN");
    if (!done) {
        fkt_ui_body_printf("default: %s  (Enter accepts default)\n",
                           SIGN_DEFAULT_OUT);
        fkt_ui_body_puts("");
        fkt_screen_clear_line(prompt_row);
        fkt_screen_goto(prompt_row, body_col);
        fputs(ui_green(), stdout);
        fputs(fname_lab, stdout);
        fkt_ui_pin_session_footer();
        fkt_ui_set_input_pos(prompt_row, cursor_col);
        ui_place_cursor(prompt_row, cursor_col);
        ui_show_cursor();
    } else {
        fkt_ui_body_printf("Filename: > %s\n", g_sign_out_path);
        fkt_ui_body_puts("");
        fkt_ui_body_puts("[OK] Signed PSBT written. Key material wiped.");
        fkt_ui_body_puts("");
        fkt_ui_body_puts("[Q] VGA/best QR   [A] ASCII QR   [Enter] Return");
        fkt_ui_pin_session_footer();
        /* Key-driven toggles — no blinking text cursor. */
        g_ui_input_hidden = 1;
        g_input_row = 0;
        g_input_col = 0;
        ui_hide_cursor();
    }
    g_ui_sign_screen_done = done;
    g_ui_redraw_cb = ui_redraw_sign_screen;
}

static void ui_fill_show_words(char out[MAX_WORDS][WORD_BUF], int *num_words) {
    int i;
    int live = 0;

    if (g_seed_loaded && g_session_num_words > 0 &&
        g_session_words[0][0] != '\0') {
        *num_words = g_session_num_words;
        for (i = 0; i < g_session_num_words; i++) {
            strncpy(out[i], g_session_words[i], WORD_BUF - 1);
            out[i][WORD_BUF - 1] = '\0';
        }
        live = 1;
    }
    if (live)
        return;

    /* Seed flag without words (wiped after successful sign) — show placeholder. */
    if (g_seed_loaded && g_session_num_words > 0 &&
        g_session_words[0][0] == '\0') {
        g_seed_loaded = 0;
        g_session_num_words = 0;
    }

    *num_words = 24;
    for (i = 0; i < 24; i++) {
        strncpy(out[i], UI_DUMMY_WORDS[i], WORD_BUF - 1);
        out[i][WORD_BUF - 1] = '\0';
    }
}

static void ui_draw_show_seed_screen(void) {
    char words[MAX_WORDS][WORD_BUF];
    int num_words;
    int grid_rows;
    int hint_row;

    ui_fill_show_words(words, &num_words);
    grid_rows = num_words / 3;
    if (grid_rows < 1)
        grid_rows = 1;

    fkt_ui_clear_screen();
    ui_draw_top_banner();
    fkt_ui_draw_subtitle("SEED " UI_EM_DASH " WRITE THIS DOWN");
    fkt_ui_body_puts("SECURITY WARNING: Never share these words. Anyone who has them");
    fkt_ui_body_puts("can steal your funds. Write on paper and store offline.");
    fkt_ui_body_puts("");
    fkt_show_seed_grid(words, num_words);
    fkt_ui_body_puts("");
    fkt_ui_body_puts("[Q] QR backup   [R] Receive address   [Enter/Esc] Return");
    fkt_ui_pin_session_footer();
    /* No blinking input cursor — key-driven screen only. */
    g_ui_input_hidden = 1;
    g_input_row = 0;
    g_input_col = 0;
    ui_hide_cursor();
    g_ui_redraw_cb = ui_draw_show_seed_screen;
    (void)hint_row;
    (void)grid_rows;
}

static char g_gen_words[MAX_WORDS][WORD_BUF];
static int  g_gen_num_words;

static void ui_redraw_generated_seed_screen(void) {
    ui_draw_generated_seed_screen(g_gen_words, g_gen_num_words);
}

static void ui_draw_generated_seed_screen(const char words[][WORD_BUF], int num_words) {
    int i;

    for (i = 0; i < num_words; i++) {
        strncpy(g_gen_words[i], words[i], WORD_BUF - 1);
        g_gen_words[i][WORD_BUF - 1] = '\0';
    }
    g_gen_num_words = num_words;

    fkt_ui_clear_screen();
    ui_draw_top_banner();
    fkt_ui_draw_subtitle("GENERATED SEED " UI_EM_DASH " WRITE THIS DOWN");
    fkt_ui_body_puts("SECURITY WARNING: Never share these words. Anyone who has them");
    fkt_ui_body_puts("can steal your funds. Write on paper and store offline.");
    fkt_ui_body_puts("");
    fkt_show_seed_grid(words, num_words);
    fkt_ui_body_puts("");
    fkt_ui_body_puts("[Q] show QR   [Enter] Accept & load   [Esc] Discard");
    fkt_ui_pin_session_footer();
    g_ui_input_hidden = 1;
    ui_hide_cursor();
    g_ui_redraw_cb = ui_redraw_generated_seed_screen;
}

static void ui_draw_entropy_bar(int pct) {
    int filled;
    int i;
    int bits;
    char line[160];
    int pos;

    if (pct <= 100)
        filled = pct * 30 / 100;
    else
        filled = 30;
    bits = (pct * ENTROPY_TARGET_BITS) / 100;
    if (bits > ENTROPY_TARGET_BITS * ENTROPY_MEME_PCT / 100)
        bits = ENTROPY_TARGET_BITS * ENTROPY_MEME_PCT / 100;

    pos = snprintf(line, sizeof(line), "Entropy collected: %4d bits   [", bits);
    for (i = 0; i < 30 && pos < (int)sizeof(line) - 8; i++) {
        const char *ch = i < filled ? UI_BLOCK_FULL : UI_BLOCK_EMPTY;
        pos += snprintf(line + pos, sizeof(line) - (size_t)pos, "%s", ch);
    }
    snprintf(line + pos, sizeof(line) - (size_t)pos, "]  %3d%%", pct);

    fputs(ui_green(), stdout);
    ui_put_hpad(UI_BODY_W);
    fputs(line, stdout);
    putchar('\n');
}

static int g_entropy_pct;
static int g_entropy_roll;
static int g_entropy_spin;
static int g_entropy_animate;
static int g_entropy_locked;
static int g_entropy_quantum;
static int g_entropy_num_words;

static void ui_redraw_entropy_screen(void) {
    ui_draw_entropy_screen(g_entropy_pct, g_entropy_roll, g_entropy_spin,
                           g_entropy_animate, g_entropy_locked, g_entropy_quantum,
                           g_entropy_num_words);
}

static void ui_draw_entropy_screen(int pct, int roll, int spin_frame, int animate,
                                   int locked, int quantum_flash, int num_words) {
    fkt_ui_clear_screen();
    ui_draw_top_banner();
    fkt_ui_draw_subtitle("CREATE NEW WALLET " UI_EM_DASH " ENTROPY RITUAL");
    fkt_ui_body_puts("Provide your own randomness. Press Space to roll dice.");
    fkt_ui_body_puts("");
    ui_draw_entropy_bar(pct);
    fkt_ui_body_puts("");
    fkt_ui_body_puts("Press Space repeatedly or wait between presses...");
    fkt_ui_body_puts("(The longer / more chaotic the better)");
    fkt_ui_body_puts("");
    {
        char roll_line[64];

        if (animate)
            snprintf(roll_line, sizeof(roll_line),
                     "Roll: %2d   Spin: %s  [*]",
                     roll, UI_SPINNER[spin_frame & 3]);
        else
            snprintf(roll_line, sizeof(roll_line),
                     "Roll: %2d   Spin: %s",
                     roll, UI_SPINNER[spin_frame & 3]);
        fkt_ui_body_puts(roll_line);
    }
    if (quantum_flash || locked)
        fkt_ui_body_puts("[ QUANTUM RESISTANCE REACHED ]");
    fkt_ui_body_puts("");
    if (pct < 100)
        fkt_ui_body_printf("[Enter] Finish & generate %d-word seed  (Need more chaos...)\n",
                       num_words);
    else
        fkt_ui_body_printf("[Enter] Finish & generate %d-word seed\n", num_words);
    if (locked) {
        /* ASCII only: em-dash / fancy dashes become garbage on DOS. */
        fkt_ui_body_puts("[Space] locked - quantum saturation reached");
        fkt_ui_body_puts("[Esc] Cancel");
    } else {
        fkt_ui_body_puts("[Space] Add entropy     [Esc] Cancel");
    }
    fkt_ui_body_puts("");
    fkt_ui_body_puts("Tip: This is more secure than most hardware wallets if you do it right.");
    fkt_ui_pin_footer(UI_BULLET_OFF " not loaded", UI_BULLET_OFF " not loaded");
    ui_hide_cursor();
    g_entropy_pct = pct;
    g_entropy_roll = roll;
    g_entropy_spin = spin_frame;
    g_entropy_animate = animate;
    g_entropy_locked = locked;
    g_entropy_quantum = quantum_flash;
    g_entropy_num_words = num_words;
    g_ui_redraw_cb = ui_redraw_entropy_screen;
}

static fkt_sha256_ctx g_entropy_sha;
static int g_entropy_strokes;

static void ui_entropy_reset(void) {
    fkt_sha256_init(&g_entropy_sha);
    g_entropy_strokes = 0;
}

static void ui_entropy_feed(int ch, int roll, int spin, int *pct, int bump) {
    uint8_t block[12];
    uint32_t t;

    t = (uint32_t)time(NULL);
    block[0] = (uint8_t)ch;
    block[1] = (uint8_t)(roll & 0xFF);
    block[2] = (uint8_t)(spin & 0xFF);
    block[3] = (uint8_t)(g_entropy_strokes & 0xFF);
    block[4] = (uint8_t)((g_entropy_strokes >> 8) & 0xFF);
    block[5] = (uint8_t)((g_entropy_strokes >> 16) & 0xFF);
    memcpy(block + 6, &t, sizeof(t));
    fkt_sha256_update(&g_entropy_sha, block, sizeof(block));
    g_entropy_strokes++;

    if (bump > 0 && *pct < ENTROPY_MEME_PCT) {
        *pct += bump;
        if (*pct > ENTROPY_MEME_PCT)
            *pct = ENTROPY_MEME_PCT;
    }
}

static void ui_entropy_finalize(uint8_t *ent, int target_len) {
    uint8_t digest[32];

    fkt_sha256_final(&g_entropy_sha, digest);
    memcpy(ent, digest, (size_t)target_len);
    fkt_memzero(digest, sizeof(digest));
    ui_entropy_reset();
}

static void help_emit_line(FILE *fp, int use_ui, const char *line) {
    if (use_ui)
        fkt_ui_body_puts(line);
    else
        fprintf(fp, "%s\n", line);
}

static void help_emit_arg(FILE *fp, int use_ui, const char *name, const char *desc) {
    char line[96];

    snprintf(line, sizeof(line), "  %-16s  %s", name, desc);
    help_emit_line(fp, use_ui, line);
}

static void fkt_emit_cli_help(FILE *fp, int use_ui) {
    help_emit_line(fp, use_ui, "Example (all forms):");
    help_emit_line(fp, use_ui, "  fkt  |  fkt preview <psbt>  |  fkt inspect <psbt>");
    help_emit_line(fp, use_ui, "  fkt sign --psbt in.psbt --out out.psbt --seed \"w1 w2 ...\" --yes");
    help_emit_line(fp, use_ui, "  fkt sign --base64 cHNidP... --out out.psbt --seed \"...\" --yes");
    help_emit_line(fp, use_ui, "  echo \"w1 w2 ...\" | fkt sign --psbt in.psbt --out out.psbt --yes");
    help_emit_line(fp, use_ui, "  fkt base64 signed.psbt  |  fkt qr --psbt signed.psbt [--term]");
#if FKT_BUILD_DEV_HARNESS
    help_emit_line(fp, use_ui, "  Dev: fkt <hex128> <path> <in> <out>");
#endif
    help_emit_line(fp, use_ui, "  fkt --help  |  fkt --version");
    help_emit_line(fp, use_ui, "");
    help_emit_line(fp, use_ui, "Arguments:");
    help_emit_arg(fp, use_ui, "fkt", "Open interactive wallet");
    help_emit_arg(fp, use_ui, "sign", "Preview→seed→sign (--psbt|--base64 --out)");
    help_emit_arg(fp, use_ui, "--psbt", "Binary .psbt path (or b64 file)");
    help_emit_arg(fp, use_ui, "--base64", "Input PSBT as Base64 string");
    help_emit_arg(fp, use_ui, "--out", "Output signed binary PSBT");
    help_emit_arg(fp, use_ui, "--seed", "12/24 BIP39 words (else TTY or stdin)");
    help_emit_arg(fp, use_ui, "--yes", "Skip interactive CONFIRM (scripted)");
    help_emit_arg(fp, use_ui, "--qr", "Show ASCII QR of signed PSBT");
    help_emit_arg(fp, use_ui, "base64", "Print clean Base64 of a PSBT file");
    help_emit_arg(fp, use_ui, "preview", "Read-only tx summary ([Q] QR)");
    help_emit_arg(fp, use_ui, "inspect", "Same as preview");
    help_emit_arg(fp, use_ui, "qr", "Show QR code");
    help_emit_arg(fp, use_ui, "<text>", "Any QR payload");
    help_emit_arg(fp, use_ui, "--term", "Force terminal QR");
    help_emit_arg(fp, use_ui, "--pbm", "Export PBM image");
#if FKT_BUILD_DEV_HARNESS
    help_emit_arg(fp, use_ui, "<hex128>", "64-byte seed hex (dev harness)");
    help_emit_arg(fp, use_ui, "<path>", "BIP32 derivation path");
    help_emit_arg(fp, use_ui, "--pubkey", "Print derived pubkey");
    help_emit_arg(fp, use_ui, "--parent-pubkey", "Advanced cosign path");
#endif
    help_emit_arg(fp, use_ui, "<psbt>", "File or pasted base64");
    help_emit_arg(fp, use_ui, "--help, -h", "Print this help");
    help_emit_arg(fp, use_ui, "--version", "Print version string");
    help_emit_arg(fp, use_ui, "[Q]", "Show QR on preview/sign screens");
    help_emit_line(fp, use_ui, "");
    help_emit_line(fp, use_ui, "Ice Cold: preview before seed; 12/24 words + random 3-word verify (TUI);");
    help_emit_line(fp, use_ui, "signed binary + clean Base64 out; optional --qr. DOS=floppy Linux=USB.");
    help_emit_line(fp, use_ui, "Supports: BIP39, P2WPKH, P2TR keypath/scriptpath, P2WSH multi cosign, 0xFC, QR");
    help_emit_line(fp, use_ui, "(Banner / --version use FKT_VERSION_STRING from fkt_version.h)");
}

void fkt_cli_print_help(FILE *fp) {
    if (!fp)
        fp = stdout;
    fprintf(fp, "FKT — Floppy Kit Tool (shell reference)\n\n");
    fkt_emit_cli_help(fp, 0);
}

void fkt_cli_print_version(FILE *fp) {
    if (!fp)
        fp = stdout;
    fprintf(fp, "fkt %s\n", FKT_VERSION_STRING);
}

int fkt_cli_sign_success_interact(const char *out_psbt) {
    char line[16];

    if (!out_psbt || out_psbt[0] == '\0')
        return 0;

    fkt_ui_term_init();
    for (;;) {
        fkt_ui_clear_screen();
        ui_draw_top_banner();
        fkt_ui_draw_subtitle("SIGN OK");
        fkt_ui_body_printf("Signed PSBT: %s\n", out_psbt);
        fkt_ui_body_puts("");
        fkt_ui_body_puts("ZEROED ALL KEY MATERIAL");
        fkt_ui_body_puts("");
        fkt_ui_body_puts("[Q] VGA/best QR   [A] ASCII QR   [Enter] Exit");
        fkt_ui_pin_session_footer();
        if (!fkt_ui_read_line(line, sizeof(line), 0))
            break;
        if (ui_choice_is_qr(line)) {
            if (fkt_ui_show_qr_psbt_file(out_psbt) != 0)
                fkt_ui_body_puts("[!] Could not encode signed PSBT as QR.");
            continue;
        }
        if (line[0] == 'a' || line[0] == 'A') {
            if (fkt_ui_show_qr_psbt_ascii(out_psbt) != 0)
                fkt_ui_body_puts("[!] ASCII QR failed (PSBT may be too large).");
            continue;
        }
        break;
    }
    fkt_ui_term_restore();
    return 0;
}

/* Scrollable help — absolute rows so banner/title never scroll off. */
static int ui_show_help_popup(void) {
    static const char *help_lines[] = {
        "Example (all forms):",
        "  fkt  |  fkt preview <psbt>  |  fkt inspect <psbt>",
        "  fkt sign --psbt in.psbt --out out.psbt --seed \"w1 w2 ...\"",
        "  echo \"w1 w2 ...\" | fkt sign --psbt in.psbt --out out.psbt --yes",
        "  fkt qr <text>  |  fkt qr --psbt <file> [--term] [--pbm f]",
#if FKT_BUILD_DEV_HARNESS
        "  Dev: fkt --base64 <psbt>  |  fkt <hex128> <path> <in> <out>",
#endif
        "  fkt --help  |  fkt --version",
        "",
        "Arguments:",
        "  fkt               Open interactive wallet",
        "  sign              CLI sign: --psbt --out [--seed] [--yes]",
        "  preview           Read-only tx summary ([Q] QR)",
        "  inspect           Same as preview",
        "  qr                Show QR code",
        "  <text>            Any QR payload",
        "  --psbt            QR signed PSBT",
        "  --term            Force terminal QR",
        "  --pbm             Export PBM image",
#if FKT_BUILD_DEV_HARNESS
        "  sign              Sign from mnemonic ([Q] QR after)",
        "  <in>              Input PSBT file",
        "  <out>             Output signed PSBT",
        "  \"mnemonic\"        Quoted seed words",
        "  --base64          Print PSBT base64",
        "  <hex128>          64-byte seed hex",
        "  <path>            BIP32 derivation path",
        "  --pubkey          Print derived pubkey",
        "  --parent-pubkey   Advanced cosign path",
        "  <pub33>           Parent pubkey hex",
#endif
        "  <psbt>            File or pasted base64",
        "  --help, -h        Print this help",
        "  --version         Print version string",
        "  [Q]               Show QR on preview/sign screens",
        "",
        "v0.1: BIP39, P2WPKH, P2TR keypath, preview, sign, QR",
        "Not in v0.1: camera, script-path Taproot, Ark, multisig cosign UX",
    };
    const int nlines = (int)(sizeof(help_lines) / sizeof(help_lines[0]));
    int scroll = 0;
    int title_row = FKT_UI_BANNER_ROWS + 1;
    int view_top = FKT_UI_BANNER_ROWS + 2; /* first content row under title */
    int view_bot;
    int view_h;
    int max_scroll;
    int i;
    int ch;
    int body_col;
    int title_col;

    view_bot = g_ui_rows - 3; /* hint row above footer */
    if (view_bot <= view_top + 2)
        view_bot = view_top + 8;
    view_h = view_bot - view_top;
    max_scroll = nlines - view_h;
    if (max_scroll < 0)
        max_scroll = 0;
    body_col = fkt_ui_body_col();
    title_col = ui_hpad((int)strlen("SHELL HELP")) + 1;

    g_ui_input_hidden = 1;
    ui_hide_cursor();

    for (;;) {
        fkt_ui_clear_screen();
        ui_draw_top_banner();

        /* Title on absolute row — no trailing blank from draw_subtitle. */
        fkt_screen_clear_line(title_row);
        fkt_screen_goto(title_row, title_col);
        fputs(ui_green(), stdout);
        fputs("SHELL HELP", stdout);

        for (i = 0; i < view_h; i++) {
            int idx = scroll + i;
            int row = view_top + i;
            fkt_screen_clear_line(row);
            if (idx < 0 || idx >= nlines)
                continue;
            fkt_screen_goto(row, body_col);
            fputs(ui_green(), stdout);
            fputs(help_lines[idx], stdout);
        }

        {
            char foot[72];
            int row = view_bot;
            fkt_screen_clear_line(row);
            fkt_screen_goto(row, body_col);
            fputs(ui_green(), stdout);
            if (max_scroll > 0)
                snprintf(foot, sizeof(foot),
                         "Up/Down scroll  %d/%d  |  any other key dismiss",
                         scroll + 1, max_scroll + 1);
            else
                snprintf(foot, sizeof(foot), "Press any key to dismiss...");
            fputs(foot, stdout);
        }
        fkt_ui_pin_session_footer();
        fkt_screen_recolor();
        fflush(stdout);

        ch = fkt_tty_read_key_once();
        if (ch < 0 || ch == FKT_KEY_SPECIAL)
            continue;
        if (ch == FKT_KEY_UP || ch == 'k' || ch == 'K') {
            if (scroll > 0)
                scroll--;
            continue;
        }
        if (ch == FKT_KEY_DOWN || ch == 'j' || ch == 'J') {
            if (scroll < max_scroll)
                scroll++;
            continue;
        }
        if (ch == FKT_KEY_PGUP) {
            scroll -= view_h;
            if (scroll < 0)
                scroll = 0;
            continue;
        }
        if (ch == FKT_KEY_PGDN) {
            scroll += view_h;
            if (scroll > max_scroll)
                scroll = max_scroll;
            continue;
        }
        g_ui_input_hidden = 0;
        return (ch == 27) ? 1 : 0;
    }
}

static int ui_is_hotkey_char(int ch) {
    return ch == '?' || ch == '!' || ch == '#';
}

static int ui_handle_global_hotkey(const char *choice) {
    if (!choice || choice[0] == '\0')
        return 0;
    if (strcmp(choice, "?") == 0) {
        if (ui_show_help_popup())
            return FKT_UI_HK_MENU;
        if (g_ui_redraw_cb)
            g_ui_redraw_cb();
        return FKT_UI_HK_HANDLED;
    }
    if (strcmp(choice, "!") == 0) {
        g_ui_debug = !g_ui_debug;
        fkt_ui_clear_screen();
        ui_draw_top_banner();
        fkt_ui_draw_subtitle("DEBUG");
        fkt_ui_body_printf("Debug mode: %s\n", g_ui_debug ? "ON" : "OFF");
        if (g_ui_debug) {
            fkt_ui_body_puts("Extra preview fields and path diagnostics enabled.");
            fkt_ui_body_printf("PSBT path: %s\n",
                               g_psbt_path[0] ? g_psbt_path : "(none)");
            fkt_ui_body_printf("Seed: %s (%d words)\n",
                               g_seed_loaded ? "loaded" : "not loaded",
                               g_session_num_words);
        } else {
            fkt_ui_body_puts("Debug details hidden.");
        }
        fkt_ui_body_puts("");
        fkt_ui_body_puts("Press any key...");
        fkt_ui_pin_session_footer();
        (void)fkt_tty_read_key_once();
        if (g_ui_redraw_cb)
            g_ui_redraw_cb();
        return FKT_UI_HK_HANDLED;
    }
    if (strcmp(choice, "#") == 0) {
        fkt_ui_toggle_theme();
        if (g_ui_redraw_cb)
            g_ui_redraw_cb();
        return FKT_UI_HK_HANDLED;
    }
    return FKT_UI_HK_NONE;
}

int fkt_ui_handle_hotkey(const char *choice) {
    return ui_handle_global_hotkey(choice);
}

/* 1 = accept seed, 0 = discard/cancel */
static int ui_generated_seed_interact(const char words[][WORD_BUF], int num_words) {
    int ch;

    ui_term_raw_on();
    ui_draw_generated_seed_screen(words, num_words);

    for (;;) {
        ch = fkt_tty_read_key();
        if (ch == EOF) {
            ui_term_raw_off();
            return 0;
        }
        if (ch < 0)
            continue; /* DOS extended keys already consumed */
        if (ui_is_hotkey_char(ch)) {
            char hk[2];

            hk[0] = (char)ch;
            hk[1] = '\0';
            if (ui_handle_global_hotkey(hk)) {
                ui_draw_generated_seed_screen(words, num_words);
                continue;
            }
        }
        if (ch == 27) {
            ui_term_raw_off();
            return 0;
        }
        if (ch == 'q' || ch == 'Q') {
            if (fkt_ui_show_qr_seed(words, num_words) != 0)
                fkt_ui_body_puts("[!] Could not encode seed as QR.");
            ui_term_raw_on();
            ui_draw_generated_seed_screen(words, num_words);
            continue;
        }
        if (ch == '\n' || ch == '\r') {
            ui_term_raw_off();
            return 1;
        }
    }
}

static int ui_read_line_fgets(char *out, size_t out_len, int reject_empty) {
    char line[FKT_PSBT_INPUT_MAX];
    size_t len;

    for (;;) {
        if (!fgets(line, sizeof(line), stdin))
            return 0;
        len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[len - 1] = '\0';
            len--;
        }
        {
            int hk = ui_handle_global_hotkey(line);
            if (hk == FKT_UI_HK_MENU)
                return 0;
            if (hk == FKT_UI_HK_HANDLED)
                continue;
        }
        if (reject_empty && len == 0)
            continue;
        if (len >= out_len)
            return 0;
        memcpy(out, line, len + 1);
        return 1;
    }
}

static int ui_read_line_interactive(char *out, size_t out_len, int reject_empty) {
    size_t pos = 0;
    int ch;

    if (ui_apply_cbreak() != 0)
        return ui_read_line_fgets(out, out_len, reject_empty);
    g_term_interactive = 1;

    out[0] = '\0';
    if (!g_ui_input_hidden) {
        ui_echo_input("", 0);
        ui_place_cursor(g_input_row, g_input_col);
        ui_show_cursor();
    } else {
        ui_hide_cursor();
    }

    for (;;) {
        ch = fkt_tty_read_key();
        if (ch == EOF) {
            g_ui_input_hidden = 0;
            fkt_ui_term_restore();
            return 0;
        }
        /* Extended / special keys (arrows, unmapped): never insert as text. */
        if (ch < 0 || ch >= 0x100 || ch == FKT_KEY_SPECIAL)
            continue;

        if (ch == 27) {
            /*
             * Drain CSI / bracketed-paste sequences (ESC [ ... letter/~).
             * Real Esc alone (no follow-up within kbhit) still cancels.
             */
            if (fkt_tty_kbhit()) {
                int n = fkt_tty_read_key();
                if (n == '[' || n == 'O') {
                    int k;
                    while (fkt_tty_kbhit()) {
                        k = fkt_tty_read_key();
                        if (k == EOF)
                            break;
                        /* End of CSI: letter or tilde */
                        if ((k >= 'A' && k <= 'Z') || (k >= 'a' && k <= 'z') ||
                            k == '~')
                            break;
                    }
                    continue; /* ignore sequence, keep editing */
                }
                /* Unknown ESC-prefix: ignore both bytes */
                continue;
            }
            g_ui_input_hidden = 0;
            fkt_ui_term_restore();
            if (g_ui_redraw_cb == ui_draw_main_menu) {
                ui_draw_main_menu();
                if (ui_apply_cbreak() != 0)
                    return 0;
                g_term_interactive = 1;
                out[0] = '\0';
                pos = 0;
                ui_echo_input("", 0);
                ui_place_cursor(g_input_row, g_input_col);
                ui_show_cursor();
                continue;
            }
            out[0] = '\0';
            return 0;
        }

        if (pos == 0 && ui_is_hotkey_char(ch)) {
            char hk[2];
            int hres;

            hk[0] = (char)ch;
            hk[1] = '\0';
            fkt_ui_term_restore();
            hres = ui_handle_global_hotkey(hk);
            if (hres == FKT_UI_HK_MENU) {
                g_ui_input_hidden = 0;
                out[0] = '\0';
                return 0;
            }
            if (hres == FKT_UI_HK_HANDLED) {
                out[0] = '\0';
                pos = 0;
                if (ui_apply_cbreak() != 0) {
                    g_ui_input_hidden = 0;
                    return 0;
                }
                g_term_interactive = 1;
                if (!g_ui_input_hidden) {
                    ui_echo_input("", 0);
                    ui_place_cursor(g_input_row, g_input_col);
                    ui_show_cursor();
                } else {
                    ui_hide_cursor();
                }
                continue;
            }
            if (ui_apply_cbreak() != 0)
                return 0;
            g_term_interactive = 1;
        }

        if (ch == '\n' || ch == '\r') {
            /* Soft newline: more paste still buffered → keep accumulating. */
            if (fkt_tty_kbhit() && pos + 1 < out_len) {
                /* Drop CR when CRLF; keep going for multi-line base64 paste. */
                continue;
            }
            if (reject_empty && pos == 0)
                continue;
            out[pos] = '\0';
            if (pos > 0) {
                int hres = ui_handle_global_hotkey(out);
                if (hres == FKT_UI_HK_MENU) {
                    g_ui_input_hidden = 0;
                    fkt_ui_term_restore();
                    out[0] = '\0';
                    return 0;
                }
                if (hres == FKT_UI_HK_HANDLED) {
                    pos = 0;
                    out[0] = '\0';
                    if (!g_ui_input_hidden) {
                        ui_echo_input("", 0);
                        ui_place_cursor(g_input_row, g_input_col);
                    }
                    continue;
                }
            }
            g_ui_input_hidden = 0;
            fkt_ui_term_restore();
            return 1;
        }

        if (ch == 127 || ch == 8) {
            if (pos > 0) {
                pos--;
                out[pos] = '\0';
                if (!g_ui_input_hidden)
                    ui_echo_input(out, pos);
            }
            continue;
        }

        if (ch >= 32 && ch < 127 && pos + 1 < out_len) {
            out[pos++] = (char)ch;
            out[pos] = '\0';
            if (!g_ui_input_hidden)
                ui_echo_input(out, pos);
        }
    }
}

int fkt_ui_read_line(char *out, size_t out_len, int reject_empty) {
    if (g_ui_input_hidden || (g_input_row > 0 && g_input_col > 0))
        return ui_read_line_interactive(out, out_len, reject_empty);
    return ui_read_line_fgets(out, out_len, reject_empty);
}

int fkt_ui_prompt_path(const char *label, char *out, size_t out_len) {
    printf("%s > ", label);
    fflush(stdout);
    if (!fkt_ui_read_line(out, out_len, 1))
        return 0;
    return out[0] != '\0';
}

void fkt_ui_draw_banner(int air_gapped) {
    (void)air_gapped;
    ui_draw_top_banner();
}

static int ui_menu_load_seed(void) {
    if (fkt_interactive_seed(g_session_words, &g_session_num_words)) {
        g_seed_loaded = 1;
        ui_recv_reset_indices();
        return 1;
    }
    g_seed_loaded = 0;
    g_session_num_words = 0;
    ui_recv_reset_indices();
    /* Surface failure — silent return to menu was confusing. */
    {
        const char *err = fkt_last_error_get();
        fkt_ui_clear_screen();
        ui_draw_top_banner();
        fkt_ui_draw_subtitle("LOAD SEED");
        fkt_ui_body_puts("[!] Seed not loaded.");
        if (err && err[0] != '\0')
            fkt_ui_body_printf("%s\n", err);
        else
            fkt_ui_body_puts("Invalid checksum, cancelled, or verification failed.");
        fkt_ui_body_puts("");
        fkt_ui_body_puts("Press Enter to return...");
        fkt_ui_pin_session_footer();
        {
            char dummy[8];
            g_ui_input_hidden = 0;
            fkt_ui_set_input_pos(FKT_UI_BANNER_ROWS + 10, fkt_ui_body_col());
            (void)fkt_ui_read_line(dummy, sizeof(dummy), 0);
        }
    }
    return 0;
}

static int ui_menu_load_psbt(void) {
    char path[FKT_PSBT_INPUT_MAX];

    g_psbt_load_err[0] = '\0';
    if (!ui_prompt_load_psbt(path, sizeof(path)))
        return 0;
    strncpy(g_psbt_path, path, sizeof(g_psbt_path) - 1);
    g_psbt_path[sizeof(g_psbt_path) - 1] = '\0';
    return 1;
}

static int ui_menu_preview(void) {
    if (g_psbt_path[0] == '\0') {
        g_psbt_load_err[0] = '\0';
        if (!ui_prompt_load_psbt(g_psbt_path, sizeof(g_psbt_path)))
            return 0;
    }
    if (fkt_psbt_preview_prepare(g_psbt_path) != 0) {
        const char *perr = fkt_last_error_get();
        fkt_ui_clear_screen();
        ui_draw_top_banner();
        fkt_ui_draw_subtitle("PREVIEW");
        fkt_ui_body_puts("[!] Could not parse PSBT for preview.");
        if (perr && perr[0] != '\0')
            fkt_ui_body_printf("%s\n", perr);
        fkt_ui_body_printf("Path: %s\n", g_psbt_path);
        fkt_ui_body_puts("Tip: use Browse so cwd matches the file folder.");
        fkt_ui_body_puts("");
        fkt_ui_body_puts("Press Enter to return...");
        fkt_ui_pin_session_footer();
        {
            char dummy[8];
            g_ui_input_hidden = 0;
            fkt_ui_set_input_pos(FKT_UI_BANNER_ROWS + 12, fkt_ui_body_col());
            if (!fkt_ui_read_line(dummy, sizeof(dummy), 0))
                return 0;
        }
        return 0;
    }
    for (;;) {
        int ch;

        ui_draw_preview_screen();
        ch = fkt_tty_read_key_once();
        if (ch < 0 || ch == FKT_KEY_SPECIAL)
            continue;
        if (ch == 27 || ch == '\r' || ch == '\n') {
            g_ui_input_hidden = 0;
            return 1;
        }
        if (ch == 'q' || ch == 'Q') {
            if (fkt_ui_show_qr_loaded_psbt() != 0)
                fkt_ui_body_puts("[!] Could not encode PSBT as QR.");
            continue;
        }
        if (ch == '?' || ch == '!' || ch == '#') {
            char hk[2];
            int hres;
            hk[0] = (char)ch;
            hk[1] = '\0';
            hres = ui_handle_global_hotkey(hk);
            if (hres == FKT_UI_HK_MENU) {
                g_ui_input_hidden = 0;
                return 1;
            }
            continue;
        }
    }
}

static int ui_wait_enter(const char *prompt) {
    char dummy[8];

    fputs(ui_green(), stdout);
    if (prompt && prompt[0])
        printf("\n  %s\n", prompt);
    else
        printf("\n  Press Enter to return...\n");
    fkt_ui_pin_session_footer();
    return fkt_ui_read_line(dummy, sizeof(dummy), 0);
}

static void ui_draw_sign_notice(const char *headline, const char *detail) {
    fkt_ui_clear_screen();
    ui_draw_top_banner();
    fkt_ui_draw_subtitle("SIGN");
    if (headline && headline[0])
        fkt_ui_body_puts(headline);
    if (detail && detail[0])
        fkt_ui_body_puts(detail);
}

static int ui_menu_sign(void) {
    char out_path[512];
    char line[512];
    char detail[384];
    const char *err;

    if (!g_seed_loaded) {
        ui_draw_sign_notice("[!] Load a seed first (option 1).", "");
        if (!ui_wait_enter("Press Enter to return..."))
            return 0;
        return 0;
    }
    if (g_psbt_path[0] == '\0') {
        g_psbt_load_err[0] = '\0';
        if (!ui_prompt_load_psbt(g_psbt_path, sizeof(g_psbt_path)))
            return 0;
    }

    ui_draw_sign_screen(0);
    if (!fkt_ui_read_line(line, sizeof(line), 0)) {
        ui_draw_sign_notice("Signing cancelled.", "");
        if (!ui_wait_enter("Press Enter to return..."))
            return 0;
        return 0;
    }
    if (line[0] == '\0')
        strcpy(out_path, SIGN_DEFAULT_OUT);
    else
        strncpy(out_path, line, sizeof(out_path) - 1);
    out_path[sizeof(out_path) - 1] = '\0';

    if (fkt_psbt_preview_prepare(g_psbt_path) != 0) {
        ui_draw_sign_notice("[!] Could not reload PSBT before signing.",
                            "Reload via option 2 (file path or pasted base64).");
        if (!ui_wait_enter("Press Enter to return..."))
            return 0;
        return 0;
    }

    /* Step 1: read-only preview — Enter continues, Esc cancels (no text cursor). */
    {
        int ch;
        for (;;) {
            fkt_ui_clear_screen();
            fkt_psbt_preview_render();
            fkt_ui_body_puts("");
            fkt_ui_body_puts("[Enter] Continue to CONFIRM   [Esc] Cancel");
            fkt_ui_pin_session_footer();
            g_ui_input_hidden = 1;
            g_input_row = 0;
            g_input_col = 0;
            ui_hide_cursor();
            ch = fkt_tty_read_key_once();
            if (ch < 0 || ch == FKT_KEY_SPECIAL)
                continue;
            if (ch == 27) {
                g_ui_input_hidden = 0;
                ui_draw_sign_notice("Signing cancelled.", "");
                if (!ui_wait_enter("Press Enter to return..."))
                    return 0;
                return 0;
            }
            if (ch == '\r' || ch == '\n' || ch == ' ')
                break;
        }
        g_ui_input_hidden = 0;
    }

    /* Step 2: dedicated CONFIRM screen — only place you type CONFIRM. */
    {
        char conf[64];
        char fp_line[80];
        char lower[64];
        int i;
        int row;
        int col;
        size_t pos = 0;
        size_t n;
        const char *p;

        fkt_ui_clear_screen();
        ui_draw_top_banner();
        fkt_ui_draw_subtitle("SIGN - TYPE CONFIRM");
        fkt_ui_body_puts("Review done. To authorize signing:");
        fkt_ui_body_puts("  Type CONFIRM  (any case) then press Enter");
        fkt_ui_body_puts("  Or press Esc to cancel");
        fkt_ui_body_puts("");
        fkt_ui_body_puts("Fingerprint:");
        for (i = 0; i < 32 && pos + 2 < sizeof(fp_line); i++) {
            snprintf(fp_line + pos, sizeof(fp_line) - pos, "%02x",
                     (unsigned)psbt_data.psbt_fingerprint[i]);
            pos += 2;
        }
        fp_line[sizeof(fp_line) - 1] = '\0';
        fkt_ui_body_puts(fp_line);
        fkt_ui_body_puts("");
        row = FKT_UI_BANNER_ROWS + 11;
        col = fkt_ui_body_col();
        fkt_screen_clear_line(row);
        fkt_screen_goto(row, col);
        fputs(ui_green(), stdout);
        fputs("CONFIRM> ", stdout);
        fkt_ui_pin_session_footer();
        fkt_ui_set_input_pos(row, col + 9);
        ui_place_cursor(row, col + 9);
        ui_show_cursor();
        conf[0] = '\0';
        if (!fkt_ui_read_line(conf, sizeof(conf), 1)) {
            ui_draw_sign_notice("Signing cancelled.", "");
            if (!ui_wait_enter("Press Enter to return..."))
                return 0;
            return 0;
        }
        n = 0;
        p = conf;
        while (*p == ' ' || *p == '\t')
            p++;
        while (*p && n + 1 < sizeof(lower)) {
            char c = *p++;
            if (c >= 'A' && c <= 'Z')
                c = (char)(c - 'A' + 'a');
            lower[n++] = c;
        }
        lower[n] = '\0';
        while (n > 0 && (lower[n - 1] == ' ' || lower[n - 1] == '\t'))
            lower[--n] = '\0';
        if (strcmp(lower, "confirm") != 0) {
            ui_draw_sign_notice(
                "[!] Signing did not proceed.",
                "You must type exactly: CONFIRM   then press Enter.");
            if (!ui_wait_enter("Press Enter to return..."))
                return 0;
            return 0;
        }
    }
    fkt_confirm_fingerprint_capture();

    strncpy(g_sign_out_path, out_path, sizeof(g_sign_out_path) - 1);
    g_sign_out_path[sizeof(g_sign_out_path) - 1] = '\0';

    if (fkt_sign_psbt_from_words(g_psbt_path, out_path,
                                g_session_words, g_session_num_words) != 0) {
        err = fkt_last_error_get();
        if (!err || err[0] == '\0')
            err = "Signing failed.";
        /* Only nudge about path when the failure is actually a write/path issue. */
        if (strstr(err, "Cannot write") || strstr(err, "filename") ||
            strstr(err, "permission") || strstr(err, "Missing output path")) {
            snprintf(detail, sizeof(detail),
                     "%s\n  Enter a writable .psbt filename, or press Enter\n"
                     "  at the prompt to use default: %s",
                     err, SIGN_DEFAULT_OUT);
        } else {
            snprintf(detail, sizeof(detail), "%s", err);
        }
        ui_draw_sign_notice("[!] Signing did not complete.", detail);
        if (!ui_wait_enter("Press Enter to return..."))
            return 0;
        return 0;
    }

    /* Success: key material from the sign path is wiped; clear session seed too. */
    fkt_memzero(g_session_words, sizeof(g_session_words));
    g_session_num_words = 0;
    g_seed_loaded = 0;
    ui_recv_reset_indices();

    for (;;) {
        int ch;

        ui_draw_sign_screen(1);
        ch = fkt_tty_read_key_once();
        if (ch < 0 || ch == FKT_KEY_SPECIAL)
            continue;
        if (ch == 27 || ch == '\r' || ch == '\n' || ch == ' ') {
            g_ui_input_hidden = 0;
            return 1;
        }
        if (ch == 'q' || ch == 'Q') {
            if (fkt_ui_show_qr_psbt_file(g_sign_out_path) != 0) {
                fkt_ui_body_puts("[!] Could not encode signed PSBT as QR.");
                (void)fkt_tty_read_key_once();
            }
            continue;
        }
        if (ch == 'a' || ch == 'A') {
            if (fkt_ui_show_qr_psbt_ascii(g_sign_out_path) != 0) {
                fkt_ui_body_puts("[!] ASCII QR failed (PSBT may be too large).");
                (void)fkt_tty_read_key_once();
            }
            continue;
        }
    }
}

/* --- Receive address (Ice Cold: session index; network chosen each time) --- */

static char g_recv_addr[96];
static char g_recv_path[64];
static int  g_recv_script_kind; /* 0 wpkh, 1 tr */
static int  g_recv_network;     /* 0 mainnet, 1 testnet */

static void ui_draw_receive_address_screen(void) {
    fkt_ui_clear_screen();
    ui_draw_top_banner();
    fkt_ui_draw_subtitle("RECEIVE ADDRESS");
    fkt_ui_body_puts("Share only this address to receive. Never share the seed.");
    fkt_ui_body_puts("");
    if (g_recv_script_kind == 0)
        fkt_ui_body_puts("Type: Native SegWit (BIP84 P2WPKH)");
    else
        fkt_ui_body_puts("Type: Taproot (BIP86 P2TR keypath)");
    if (g_recv_network == 0)
        fkt_ui_body_puts("Network: Mainnet");
    else
        fkt_ui_body_puts("Network: Testnet");
    fkt_ui_body_printf("Path: %s\n", g_recv_path);
    fkt_ui_body_puts("");
    fkt_ui_body_puts("Address:");
    fkt_ui_body_printf("%s\n", g_recv_addr);
    fkt_ui_body_puts("");
    fkt_ui_body_puts("[Q] QR code   [Enter/Esc] Back to seed");
    fkt_ui_pin_session_footer();
    g_ui_input_hidden = 1;
    g_input_row = 0;
    g_input_col = 0;
    ui_hide_cursor();
    g_ui_redraw_cb = ui_draw_receive_address_screen;
}

static int ui_session_seed_live(void) {
    return g_seed_loaded && g_session_num_words > 0 &&
           g_session_words[0][0] != '\0';
}

static void ui_recv_reset_indices(void) {
    g_recv_idx_wpkh = 0;
    g_recv_idx_tr = 0;
}

/* 1 = got choice, 0 = cancel */
static int ui_pick_one_two(const char *title, const char *line1, const char *line2,
                           int *out_choice) {
    int ch;

    for (;;) {
        fkt_ui_clear_screen();
        ui_draw_top_banner();
        fkt_ui_draw_subtitle(title);
        fkt_ui_body_puts(line1);
        fkt_ui_body_puts(line2);
        fkt_ui_body_puts("");
        fkt_ui_body_puts("[1] / [2] select   [Esc] Cancel");
        fkt_ui_pin_session_footer();
        g_ui_input_hidden = 1;
        ui_hide_cursor();
        ch = fkt_tty_read_key_once();
        if (ch < 0 || ch == FKT_KEY_SPECIAL)
            continue;
        if (ch == 27)
            return 0;
        if (ch == '1') {
            *out_choice = 0;
            return 1;
        }
        if (ch == '2') {
            *out_choice = 1;
            return 1;
        }
    }
}

static int ui_receive_address_flow(void) {
    char words[MAX_WORDS][WORD_BUF];
    int num_words;
    int script_kind;
    int network;
    uint32_t idx;
    int ch;

    if (!ui_session_seed_live()) {
        fkt_ui_clear_screen();
        ui_draw_top_banner();
        fkt_ui_draw_subtitle("RECEIVE ADDRESS");
        fkt_ui_body_puts("[!] No live seed in session.");
        fkt_ui_body_puts("Load or create a seed first (options 1 or 6).");
        fkt_ui_body_puts("Note: seed words are wiped after a successful sign.");
        fkt_ui_body_puts("");
        fkt_ui_body_puts("Press Enter to return...");
        fkt_ui_pin_session_footer();
        g_ui_input_hidden = 1;
        ui_hide_cursor();
        for (;;) {
            ch = fkt_tty_read_key_once();
            if (ch == 27 || ch == '\r' || ch == '\n')
                break;
        }
        return 0;
    }

    if (!ui_pick_one_two("RECEIVE " UI_EM_DASH " SCRIPT TYPE",
                         "[1] Native SegWit  BIP84  (bc1q / tb1q)",
                         "[2] Taproot        BIP86  (bc1p / tb1p)",
                         &script_kind))
        return 0;

    if (!ui_pick_one_two("RECEIVE " UI_EM_DASH " NETWORK",
                         "[1] Mainnet  (bc1...)",
                         "[2] Testnet  (tb1...)",
                         &network))
        return 0;

    ui_fill_show_words(words, &num_words);
    if (script_kind == 0) {
        idx = g_recv_idx_wpkh;
        g_recv_idx_wpkh++;
    } else {
        idx = g_recv_idx_tr;
        g_recv_idx_tr++;
    }

    if (fkt_address_receive_from_words(words, num_words, script_kind, network, idx,
                                       g_recv_addr, sizeof(g_recv_addr),
                                       g_recv_path, sizeof(g_recv_path)) != 0) {
        fkt_ui_clear_screen();
        ui_draw_top_banner();
        fkt_ui_draw_subtitle("RECEIVE ADDRESS");
        fkt_ui_body_puts("[!] Could not derive address.");
        fkt_ui_body_puts("Press Enter to return...");
        fkt_ui_pin_session_footer();
        g_ui_input_hidden = 1;
        ui_hide_cursor();
        for (;;) {
            ch = fkt_tty_read_key_once();
            if (ch == 27 || ch == '\r' || ch == '\n')
                break;
        }
        return 0;
    }

    g_recv_script_kind = script_kind;
    g_recv_network = network;

    for (;;) {
        ui_draw_receive_address_screen();
        ch = fkt_tty_read_key_once();
        if (ch < 0 || ch == FKT_KEY_SPECIAL)
            continue;
        if (ch == 27 || ch == '\r' || ch == '\n')
            break;
        if (ch == 'q' || ch == 'Q') {
            if (fkt_ui_show_qr_text(g_recv_addr) != 0) {
                fkt_ui_body_puts("[!] Could not encode address as QR.");
                (void)fkt_tty_read_key_once();
            }
            continue;
        }
    }
    fkt_memzero(g_recv_addr, sizeof(g_recv_addr));
    return 1;
}

static int ui_menu_show_seed(void) {
    char words[MAX_WORDS][WORD_BUF];
    int num_words;
    int ch;

    for (;;) {
        ui_draw_show_seed_screen();
        ch = fkt_tty_read_key_once();
        if (ch < 0 || ch == FKT_KEY_SPECIAL)
            continue;
        if (ch == 27 || ch == '\r' || ch == '\n') {
            g_ui_input_hidden = 0;
            return 1;
        }
        if (ch == 'q' || ch == 'Q') {
            ui_fill_show_words(words, &num_words);
            if (fkt_ui_show_qr_seed(words, num_words) != 0) {
                fkt_ui_body_puts("[!] Could not encode seed as QR.");
                (void)fkt_tty_read_key_once();
            }
            continue;
        }
        if (ch == 'r' || ch == 'R') {
            ui_receive_address_flow();
            continue;
        }
        /* Ignore V and everything else — no verify-from-view. */
    }
}

static int ui_menu_new_wallet(void) {
    uint8_t entropy[32];
    char generated[MAX_WORDS][WORD_BUF];
    int target_words = 0;
    int ent_bytes = 0;
    int pct = 0;
    int roll = 1;
    int spin_frame = 0;
    int locked = 0;
    int quantum_flash = 0;
    int ch;
    int num_words = 0;
    int i;

    if (!ui_prompt_wallet_word_count(&target_words))
        return 0;
    ent_bytes = (target_words == 12) ? 16 : 32;

    memset(entropy, 0, sizeof(entropy));
    ui_entropy_reset();
    ui_term_raw_on();
    ui_draw_entropy_screen(pct, roll, spin_frame, 0, locked, quantum_flash,
                           target_words);

    for (;;) {
        ch = fkt_tty_read_key();
        if (ch == EOF) {
            ui_term_raw_off();
            return 0;
        }
        if (ch < 0)
            continue; /* DOS extended keys already consumed */
        if (ui_is_hotkey_char(ch)) {
            char hk[2];

            hk[0] = (char)ch;
            hk[1] = '\0';
            if (ui_handle_global_hotkey(hk)) {
                ui_draw_entropy_screen(pct, roll, spin_frame, 0, locked,
                                       quantum_flash, target_words);
                continue;
            }
        }
        if (ch == 27) {
            ui_term_raw_off();
            return 0;
        }
        if (ch == '\n' || ch == '\r') {
            if (pct < 100)
                continue;
            break;
        }
        if (locked)
            continue;
        if (ch == ' ') {
            spin_frame++;
            roll = (spin_frame % 20) + 1;
            ui_entropy_feed(' ', roll, spin_frame, &pct, 5);
            if (pct >= ENTROPY_MEME_PCT) {
                pct = ENTROPY_MEME_PCT;
                locked = 1;
                quantum_flash = 1;
            }
            ui_draw_entropy_screen(pct, roll, spin_frame, 1, locked, quantum_flash,
                                   target_words);
            quantum_flash = 0;
            continue;
        }
        ui_entropy_feed(ch, roll, spin_frame, &pct, 0);
    }

    ui_term_raw_off();
    ui_entropy_finalize(entropy, ent_bytes);
    if (fkt_bip39_from_entropy(entropy, ent_bytes, generated, &num_words) != 0)
        return 0;

    if (!ui_generated_seed_interact(generated, num_words)) {
        fkt_memzero(entropy, sizeof(entropy));
        fkt_memzero(generated, sizeof(generated));
        return 0;
    }

    for (i = 0; i < num_words; i++) {
        strncpy(g_session_words[i], generated[i], WORD_BUF - 1);
        g_session_words[i][WORD_BUF - 1] = '\0';
    }
    g_session_num_words = num_words;
    g_seed_loaded = 1;
    ui_recv_reset_indices();
    fkt_memzero(entropy, sizeof(entropy));
    fkt_memzero(generated, sizeof(generated));
    return 1;
}

int fkt_ui_main_menu(void) {
    char choice[32];

    fkt_ui_term_init();
    fkt_confirm_set_ui_mode(1);
    g_psbt_path[0] = '\0';
    g_seed_loaded = 0;
    g_session_num_words = 0;
    g_ui_input_hidden = 0;

    for (;;) {
        /* Hard reset input state every loop — fixes dead keyboard after QR/Esc. */
        g_ui_input_hidden = 0;
        g_input_row = 0;
        g_input_col = 0;
        fkt_mouse_hide();
        (void)fkt_tty_raw_begin();

        ui_draw_main_menu();
        if (!fkt_ui_read_line(choice, sizeof(choice), 1)) {
            /* Esc on main menu: stay put, do not exit the app. */
            continue;
        }

        if (strcmp(choice, "0") == 0 || strcmp(choice, "q") == 0 ||
            strcmp(choice, "Q") == 0) {
            fkt_ui_term_restore();
            return 0;
        }
        if (strcmp(choice, "1") == 0)
            ui_menu_load_seed();
        else if (strcmp(choice, "2") == 0)
            ui_menu_load_psbt();
        else if (strcmp(choice, "3") == 0)
            ui_menu_preview();
        else if (strcmp(choice, "4") == 0)
            ui_menu_sign();
        else if (strcmp(choice, "5") == 0)
            ui_menu_show_seed();
        else if (strcmp(choice, "6") == 0)
            ui_menu_new_wallet();
        else {
            fkt_ui_body_puts("");
            fkt_ui_body_puts("Invalid option.");
        }
    }
}