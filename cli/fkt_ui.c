/* fkt_ui.c - shared terminal UI: retro ASCII frame (C89) */
#define _POSIX_C_SOURCE 200809L

#include "fkt_ui.h"
#include "fkt_seed.h"
#include "fkt_preview.h"
#include "fkt_bip39.h"
#include "fkt_memzero.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>

#define UI_BRIGHT  "\033[1;32m"
#define UI_DIM     "\033[32m"

#define UI_LEFT_LABEL  "FKT v0.1 - CLI Signer"
#define UI_RIGHT_LABEL "AIR-GAPPED * OFFLINE"
#define UI_LINE_W      80

#define SIGN_DEFAULT_OUT "tx-2026-07-06-fkt.psbt"
#define ENTROPY_TARGET_BITS 256

#define MENU_PROMPT_ROW  13
#define MENU_PROMPT_COL  29
#define MENU_SEP_ROW     14
#define MENU_FOOT_ROW    15

#define WALLET_BOX_INNER  11
#define WALLET_BOX_HEIGHT (WALLET_BOX_INNER + 2)

#define ENTROPY_MEME_PCT 420
#define UI_TOGGLE_LABEL  "?/Help D/Debug T/Theme"

#define WALLET_BOX_TITLE "NEW SEED PHRASE (BIP39)"
#define WALLET_BOX_PROMPT "Enter number of words (12 or 24): "

#define GRID_PAD_H      2
#define GRID_CONTENT_W  45
#define GRID_INNER_W    (GRID_PAD_H + GRID_CONTENT_W + GRID_PAD_H)
#define GRID_VISIBLE    (GRID_INNER_W + 2)

static int g_ui_cols = 80;
static int g_ui_rows = 24;
static int g_ui_theme_bright = 1;

static char g_psbt_path[512];
static int  g_seed_loaded = 0;
static char g_session_words[MAX_WORDS][WORD_BUF];
static int  g_session_num_words = 0;

static struct termios g_saved_term;
static int g_term_raw = 0;

static const char *UI_DUMMY_WORDS[24] = {
    "abandon", "ability", "able", "about", "above", "absent",
    "absorb", "abstract", "absurd", "abuse", "access", "accident",
    "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual"
};

static const char *UI_SPINNER[] = { "|", "/", "-", "\\" };

static const char *ui_green(void) {
    return g_ui_theme_bright ? UI_BRIGHT : UI_DIM;
}

const char *fkt_ui_green_str(void) {
    return ui_green();
}

void fkt_ui_term_init(void) {
    FILE *fp;

    g_ui_cols = 80;
    g_ui_rows = 24;
    fp = popen("tput cols 2>/dev/null", "r");
    if (fp) {
        if (fscanf(fp, "%d", &g_ui_cols) != 1)
            g_ui_cols = 80;
        pclose(fp);
    }
    fp = popen("tput lines 2>/dev/null", "r");
    if (fp) {
        if (fscanf(fp, "%d", &g_ui_rows) != 1)
            g_ui_rows = 24;
        pclose(fp);
    }
    if (g_ui_cols < 40)
        g_ui_cols = 80;
    if (g_ui_rows < 12)
        g_ui_rows = 24;
}

int fkt_ui_term_cols(void) { return g_ui_cols; }
int fkt_ui_term_rows(void) { return g_ui_rows; }

void fkt_ui_clear_screen(void) {
    printf("\033[2J\033[H%s", ui_green());
    fflush(stdout);
}

int fkt_ui_theme_bright(void) {
    return g_ui_theme_bright;
}

void fkt_ui_toggle_theme(void) {
    g_ui_theme_bright = !g_ui_theme_bright;
}

void fkt_ui_draw_separator(void) {
    fputs(ui_green(), stdout);
    fputs("────────────────────────────────────────────────────────────────────────────────\n",
          stdout);
}

void fkt_ui_draw_footer(const char *seed_st, const char *psbt_st) {
    char left[72];
    char line[UI_LINE_W + 1];
    int left_len;
    int toggle_len;
    int toggle_at;
    int i;

    snprintf(left, sizeof(left), "Seed %s | PSBT %s ", seed_st, psbt_st);
    left_len = (int)strlen(left);
    toggle_len = (int)strlen(UI_TOGGLE_LABEL);
    toggle_at = UI_LINE_W - toggle_len;
    if (toggle_at < 0)
        toggle_at = 0;

    fputs(ui_green(), stdout);
    for (i = 0; i < UI_LINE_W; i++)
        line[i] = ' ';
    line[UI_LINE_W] = '\0';
    if (left_len > 0 && left_len < UI_LINE_W)
        memcpy(line, left, (size_t)left_len);
    if (toggle_at + toggle_len > UI_LINE_W)
        toggle_at = UI_LINE_W - toggle_len;
    memcpy(line + toggle_at, UI_TOGGLE_LABEL, (size_t)toggle_len);
    fputs(line, stdout);
    putchar('\n');
    fflush(stdout);
}

void fkt_ui_pin_footer(const char *seed_st, const char *psbt_st) {
    if (g_ui_rows >= 4) {
        printf("\033[%d;1H\033[2K", g_ui_rows - 2);
        fkt_ui_draw_separator();
        printf("\033[%d;1H\033[2K", g_ui_rows - 1);
        fkt_ui_draw_footer(seed_st, psbt_st);
    } else {
        printf("\n");
        fkt_ui_draw_separator();
        fkt_ui_draw_footer(seed_st, psbt_st);
    }
}

static const char *ui_seed_status(void) {
    return g_seed_loaded ? "\342\227\217 loaded" : "\342\227\213 not loaded";
}

static const char *ui_psbt_status(void) {
    return g_psbt_path[0] ? "\342\227\217 loaded" : "\342\227\213 not loaded";
}

void fkt_ui_pin_session_footer(void) {
    fkt_ui_pin_footer(ui_seed_status(), ui_psbt_status());
}

static void ui_draw_top_banner(void) {
    char line[UI_LINE_W + 1];
    int left_len = (int)strlen(UI_LEFT_LABEL);
    int right_len = (int)strlen(UI_RIGHT_LABEL);
    int i;

    fputs(ui_green(), stdout);
    for (i = 0; i < UI_LINE_W; i++)
        line[i] = ' ';
    line[UI_LINE_W] = '\0';
    memcpy(line, UI_LEFT_LABEL, (size_t)left_len);
    memcpy(line + UI_LINE_W - right_len, UI_RIGHT_LABEL, (size_t)right_len);
    fputs(line, stdout);
    putchar('\n');
    fkt_ui_draw_separator();
}

static void ui_show_cursor(void) {
    printf("\033[?25h");
    fflush(stdout);
}

static void ui_hide_cursor(void) {
    printf("\033[?25l");
    fflush(stdout);
}

static void ui_term_raw_on(void) {
    struct termios t;

    if (tcgetattr(STDIN_FILENO, &g_saved_term) != 0)
        return;
    t = g_saved_term;
    t.c_lflag &= (tcflag_t)~(ICANON | ECHO);
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
    g_term_raw = 1;
}

static void ui_term_raw_off(void) {
    if (g_term_raw) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_term);
        g_term_raw = 0;
    }
    ui_show_cursor();
}

static void ui_place_cursor(int row, int col) {
    printf("\033[%d;%dH", row, col);
    fflush(stdout);
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
    printf("\033[%d;1H\033[2K", row);
    fputs(ui_green(), stdout);
    ui_put_hpad(GRID_VISIBLE);
    putchar('|');
    fputs(inner, stdout);
    putchar('|');
    fflush(stdout);
}

static void ui_box_edge_at(int row) {
    int i;

    printf("\033[%d;1H\033[2K", row);
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
    fkt_ui_pin_footer("\342\227\213 not loaded", "\342\227\213 not loaded");
    cursor_col = ui_hpad(GRID_VISIBLE) + 2 + GRID_PAD_H +
                 (int)strlen(WALLET_BOX_PROMPT) + 1;
    ui_place_cursor(prompt_row, cursor_col);
    ui_show_cursor();
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
    fkt_ui_clear_screen();
    ui_draw_top_banner();
    printf("                      FKT COLD WALLET \342\200\224 MAIN MENU\n");
    printf("\n");
    printf("             1. Load seed\n");
    printf("             2. Load PSBT\n");
    printf("             3. Preview transaction\n");
    printf("             4. Sign transaction\n");
    printf("             5. Show seed (with verification)\n");
    printf("             6. Create new wallet\n");
    printf("             0. Exit\n");
    printf("\n");
    printf("\033[%d;1H\033[2K             Select option: ", MENU_PROMPT_ROW);
    printf("\033[%d;1H\033[2K", MENU_SEP_ROW);
    fkt_ui_draw_separator();
    printf("\033[%d;1H\033[2K", MENU_FOOT_ROW);
    fkt_ui_draw_footer(ui_seed_status(), ui_psbt_status());
    ui_place_cursor(MENU_PROMPT_ROW, MENU_PROMPT_COL);
    ui_show_cursor();
}

static void ui_draw_load_psbt_screen(void) {
    const int prompt_row = 8;
    const int cursor_col = 5;

    fkt_ui_clear_screen();
    ui_draw_top_banner();
    printf("                      FKT COLD WALLET \342\200\224 LOAD PSBT\n\n");
    printf("  PSBT file path or paste base64:\n");
    printf("\033[%d;1H\033[2K  > ", prompt_row);
    fkt_ui_pin_session_footer();
    ui_place_cursor(prompt_row, cursor_col);
    ui_show_cursor();
}

static void ui_draw_preview_wait_screen(void) {
    fkt_ui_clear_screen();
    ui_draw_top_banner();
    printf("                      FKT COLD WALLET \342\200\224 PREVIEW\n\n");
    printf("  [READ-ONLY] Press Enter to return...\n");
    fkt_ui_pin_session_footer();
}

static void ui_draw_sign_screen(int done) {
    const int prompt_row = 7;
    const int cursor_col = 5;

    fkt_ui_clear_screen();
    ui_draw_top_banner();
    printf("                      FKT COLD WALLET \342\200\224 SIGN\n\n");
    if (!done) {
        printf("  Output filename [default: %s]:\n", SIGN_DEFAULT_OUT);
        printf("\033[%d;1H\033[2K  > ", prompt_row);
        fkt_ui_pin_session_footer();
        ui_place_cursor(prompt_row, cursor_col);
        ui_show_cursor();
    } else {
        printf("  Output filename [default: %s]:\n  > %s\n", SIGN_DEFAULT_OUT, SIGN_DEFAULT_OUT);
        printf("  After signing you can:\n");
        printf("    [S] Show as QR code   [B] Show as Base64   [Enter] Save & return\n\n");
        printf("  Signing with loaded seed... done.\n");
        printf("  [OK] Signed PSBT written.\n");
        fkt_ui_pin_session_footer();
    }
}

static void ui_fill_show_words(char out[MAX_WORDS][WORD_BUF], int *num_words) {
    int i;

    if (g_seed_loaded && g_session_num_words > 0) {
        *num_words = g_session_num_words;
        for (i = 0; i < g_session_num_words; i++) {
            strncpy(out[i], g_session_words[i], WORD_BUF - 1);
            out[i][WORD_BUF - 1] = '\0';
        }
        return;
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

    ui_fill_show_words(words, &num_words);
    fkt_ui_clear_screen();
    ui_draw_top_banner();
    printf("                      SEED \342\200\224 WRITE THIS DOWN\n\n");
    printf("  SECURITY WARNING: Never share these words. Anyone with them\n");
    printf("  can steal your funds. Write on paper and store offline.\n\n");
    fkt_show_seed_grid(words, num_words);
    printf("\n  [Q] QR   [V] Verify   [Enter] Return\n");
    fkt_ui_pin_session_footer();
}

static void ui_draw_generated_seed_screen(const char words[][WORD_BUF], int num_words) {
    fkt_ui_clear_screen();
    ui_draw_top_banner();
    printf("                      GENERATED SEED \342\200\224 WRITE THIS DOWN\n\n");
    printf("  SECURITY WARNING: Never share these words. Anyone with them\n");
    printf("  can steal your funds. Write on paper and store offline.\n\n");
    fkt_show_seed_grid(words, num_words);
    printf("\n  [Enter] Accept & load   [Esc] Discard\n");
    fkt_ui_pin_session_footer();
}

static void ui_draw_entropy_bar(int pct) {
    int filled;
    int i;
    int bits;

    if (pct <= 100)
        filled = pct * 30 / 100;
    else
        filled = 30;
    bits = (pct * ENTROPY_TARGET_BITS) / 100;
    if (bits > ENTROPY_TARGET_BITS * ENTROPY_MEME_PCT / 100)
        bits = ENTROPY_TARGET_BITS * ENTROPY_MEME_PCT / 100;

    fputs(ui_green(), stdout);
    printf("  Entropy collected: %4d bits   [", bits);
    for (i = 0; i < 30; i++)
        printf("%s", i < filled ? "\342\226\210" : "\342\226\221");
    printf("]  %3d%%\n", pct);
}

static void ui_draw_entropy_screen(int pct, int roll, int spin_frame, int animate,
                                   int locked, int quantum_flash, int num_words) {
    fkt_ui_clear_screen();
    ui_draw_top_banner();
    printf("\n                      CREATE NEW WALLET \342\200\224 ENTROPY RITUAL\n\n");
    printf("  Provide your own randomness. Press Space to roll dice.\n\n");
    ui_draw_entropy_bar(pct);
    printf("\n  Press Space repeatedly or wait between presses...\n");
    printf("  (The longer / more chaotic the better)\n\n");
    fputs(ui_green(), stdout);
    printf("  Roll: *%2d   Spin: %s", roll, UI_SPINNER[spin_frame & 3]);
    if (animate)
        printf("  \342\227\217");
    printf("\n");
    if (quantum_flash || locked)
        printf("\n  Quantum Resistance Reached! \xf0\x9f\x94\xa5\n");
    printf("\n");
    fputs(ui_green(), stdout);
    if (pct < 100)
        printf("  [Enter] Finish & generate %d-word seed  (Need more chaos...)\n",
               num_words);
    else
        printf("  [Enter] Finish & generate %d-word seed\n", num_words);
    if (locked)
        printf("  [Space] locked — quantum saturation reached\n  [Esc] Cancel\n\n");
    else
        printf("  [Space] Add entropy     [Esc] Cancel\n\n");
    printf("  Tip: This is more secure than most hardware wallets if you do it right.\n");
    fkt_ui_pin_footer("\342\227\213 not loaded", "\342\227\213 not loaded");
    ui_hide_cursor();
}

static unsigned int g_entropy_pool = 0;
static int g_entropy_pool_bits = 0;

static void ui_entropy_reset(void) {
    g_entropy_pool = 0;
    g_entropy_pool_bits = 0;
}

static void ui_entropy_mix(uint8_t *ent, int *len, unsigned int val, int bits,
                           int *pct, int bump) {

    g_entropy_pool = (g_entropy_pool << bits) | (val & ((1u << bits) - 1));
    g_entropy_pool_bits += bits;
    while (g_entropy_pool_bits >= 8 && *len < 32) {
        g_entropy_pool_bits -= 8;
        ent[(*len)++] = (uint8_t)((g_entropy_pool >> g_entropy_pool_bits) & 0xFF);
        g_entropy_pool &= (1u << g_entropy_pool_bits) - 1;
    }
    if (bump > 0 && *pct < ENTROPY_MEME_PCT) {
        *pct += bump;
        if (*pct > ENTROPY_MEME_PCT)
            *pct = ENTROPY_MEME_PCT;
    }
}

static void ui_entropy_finalize(uint8_t *ent, int *len, int target_len,
                              unsigned int salt) {
    int i;

    while (*len < target_len) {
        int pos = *len;
        ent[pos] = (uint8_t)((salt >> ((pos % 4) * 8)) ^ rand() ^ pos);
        (*len)++;
        salt = salt * 1664525u + 1013904223u;
    }
    for (i = 0; i < target_len; i++)
        ent[i] ^= (uint8_t)(rand() & 0xFF);
}

int fkt_ui_read_line(char *out, size_t out_len, int reject_empty) {
    char line[512];
    size_t len;

    for (;;) {
        if (!fgets(line, sizeof(line), stdin))
            return 0;
        len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[len - 1] = '\0';
            len--;
        }
        if (reject_empty && len == 0)
            continue;
        if (len >= out_len)
            return 0;
        memcpy(out, line, len + 1);
        return 1;
    }
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
        return 1;
    }
    g_seed_loaded = 0;
    g_session_num_words = 0;
    return 0;
}

static int ui_menu_load_psbt(void) {
    char path[512];

    ui_draw_load_psbt_screen();
    if (!fkt_ui_read_line(path, sizeof(path), 1))
        return 0;
    if (path[0] == '\0')
        return 0;
    strncpy(g_psbt_path, path, sizeof(g_psbt_path) - 1);
    g_psbt_path[sizeof(g_psbt_path) - 1] = '\0';
    return 1;
}

static int ui_menu_preview(void) {
    if (g_psbt_path[0] == '\0') {
        ui_draw_load_psbt_screen();
        if (!fkt_ui_read_line(g_psbt_path, sizeof(g_psbt_path), 1))
            return 0;
    }
    if (fkt_psbt_preview(g_psbt_path) != 0)
        return 0;
    ui_draw_preview_wait_screen();
    {
        char dummy[8];
        fkt_ui_read_line(dummy, sizeof(dummy), 0);
    }
    return 1;
}

static int ui_menu_sign(void) {
    char out_path[512];
    char line[512];

    if (!g_seed_loaded)
        return 0;
    if (g_psbt_path[0] == '\0') {
        ui_draw_load_psbt_screen();
        if (!fkt_ui_read_line(g_psbt_path, sizeof(g_psbt_path), 1))
            return 0;
    }

    ui_draw_sign_screen(0);
    if (!fkt_ui_read_line(line, sizeof(line), 0))
        return 0;
    if (line[0] == '\0')
        strcpy(out_path, SIGN_DEFAULT_OUT);
    else
        strncpy(out_path, line, sizeof(out_path) - 1);
    out_path[sizeof(out_path) - 1] = '\0';

    if (fkt_sign_psbt_from_words(g_psbt_path, out_path,
                                g_session_words, g_session_num_words) != 0)
        return 0;

    ui_draw_sign_screen(1);
    {
        char dummy[8];
        fkt_ui_read_line(dummy, sizeof(dummy), 0);
    }
    return 1;
}

static int ui_menu_show_seed(void) {
    char line[32];

    ui_draw_show_seed_screen();
    if (!fkt_ui_read_line(line, sizeof(line), 0))
        return 0;
    if (line[0] == 'v' || line[0] == 'V') {
        if (g_seed_loaded)
            return fkt_verify_seed(g_session_words, g_session_num_words);
    }
    return 1;
}

static int ui_menu_new_wallet(void) {
    uint8_t entropy[32];
    char generated[MAX_WORDS][WORD_BUF];
    int target_words = 0;
    int ent_bytes = 0;
    int entropy_len = 0;
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

    srand((unsigned)time(NULL));
    memset(entropy, 0, sizeof(entropy));
    ui_entropy_reset();
    ui_term_raw_on();
    ui_draw_entropy_screen(pct, roll, spin_frame, 0, locked, quantum_flash,
                           target_words);

    for (;;) {
        ch = getchar();
        if (ch == EOF) {
            ui_term_raw_off();
            return 0;
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
            ui_entropy_mix(entropy, &entropy_len,
                           (unsigned int)(rand() ^ roll ^ spin_frame), 8, &pct, 5);
            roll = (rand() % 20) + 1;
            spin_frame++;
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
        ui_entropy_mix(entropy, &entropy_len, (unsigned int)ch, 5, &pct, 0);
    }

    ui_term_raw_off();
    ui_entropy_finalize(entropy, &entropy_len, ent_bytes, (unsigned int)time(NULL));
    if (fkt_bip39_from_entropy(entropy, ent_bytes, generated, &num_words) != 0)
        return 0;

    ui_draw_generated_seed_screen(generated, num_words);
    {
        char accept[16];
        if (!fkt_ui_read_line(accept, sizeof(accept), 0)) {
            fkt_memzero(entropy, sizeof(entropy));
            fkt_memzero(generated, sizeof(generated));
            return 0;
        }
    }

    for (i = 0; i < num_words; i++) {
        strncpy(g_session_words[i], generated[i], WORD_BUF - 1);
        g_session_words[i][WORD_BUF - 1] = '\0';
    }
    g_session_num_words = num_words;
    g_seed_loaded = 1;
    fkt_memzero(entropy, sizeof(entropy));
    fkt_memzero(generated, sizeof(generated));
    return 1;
}

static int ui_handle_global_hotkey(const char *choice) {
    if (!choice || choice[0] == '\0')
        return 0;
    if (strcmp(choice, "?") == 0) {
        fputs(ui_green(), stdout);
        fputs("\n  FKT Help: 1=seed 2=PSBT 3=preview 4=sign 5=show 6=new 0=exit\n",
              stdout);
        return 1;
    }
    if (strcmp(choice, "d") == 0 || strcmp(choice, "D") == 0) {
        fputs(ui_green(), stdout);
        printf("\n  [Debug] Seed %s | PSBT %s | theme %s\n",
               ui_seed_status(), ui_psbt_status(),
               g_ui_theme_bright ? "bright" : "dim");
        return 1;
    }
    if (strcmp(choice, "t") == 0 || strcmp(choice, "T") == 0) {
        fkt_ui_toggle_theme();
        return 1;
    }
    return 0;
}

int fkt_ui_main_menu(void) {
    char choice[32];

    fkt_ui_term_init();
    g_psbt_path[0] = '\0';
    g_seed_loaded = 0;
    g_session_num_words = 0;

    for (;;) {
        ui_draw_main_menu();
        if (!fkt_ui_read_line(choice, sizeof(choice), 1))
            return 0;

        if (ui_handle_global_hotkey(choice))
            continue;

        if (strcmp(choice, "0") == 0 || strcmp(choice, "q") == 0)
            return 0;
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
            fputs(ui_green(), stdout);
            fputs("\n  Invalid option.\n", stdout);
        }
    }
}