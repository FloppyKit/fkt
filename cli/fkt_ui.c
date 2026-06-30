/* fkt_ui.c - shared terminal UI: banner, menu, theme (C89) */
#define _POSIX_C_SOURCE 200809L

#include "fkt_ui.h"
#include "fkt_seed.h"
#include "fkt_preview.h"
#include "fkt_memzero.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define UI_GREEN   "\033[1;32m"
#define UI_DIM     "\033[32m"
#define UI_YELLOW  "\033[1;33m"
#define UI_RESET   "\033[0m"
#define UI_BG      "\033[40m"

#define UI_BANNER_W  78

#define UI_LEFT_LABEL  "FKT v0.1 - CLI Signer"
#define UI_RIGHT_OFF   "OFFLINE * SECURE"
#define UI_RIGHT_AIR   "AIR-GAPPED * OFFLINE"

/* menu box matches seed box geometry for consistent centering */
#define MENU_PAD_H      2
#define MENU_PAD_V      2
#define MENU_CONTENT_W  45
#define MENU_INNER_W    (MENU_PAD_H + MENU_CONTENT_W + MENU_PAD_H)
#define MENU_VISIBLE    (MENU_INNER_W + 2)
#define MENU_TITLE      "FKT COLD WALLET - MAIN MENU"
#define MENU_PROMPT     "Select option: "
#define MENU_NUM_ITEMS  8

static int g_ui_cols = 80;
static int g_ui_rows = 24;
static int g_ui_theme_bright = 1;

/* session state for cold-wallet menu */
static char g_psbt_path[512];
static int  g_seed_loaded = 0;
static char g_session_words[MAX_WORDS][WORD_BUF];
static int  g_session_num_words = 0;

static const char *ui_green(void) {
    return g_ui_theme_bright ? UI_GREEN : UI_DIM;
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
    printf("\033[2J\033[H");
    fflush(stdout);
}

int fkt_ui_theme_bright(void) {
    return g_ui_theme_bright;
}

void fkt_ui_toggle_theme(void) {
    g_ui_theme_bright = !g_ui_theme_bright;
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

static int g_menu_vpad = 0;
static int g_menu_title_row = 0;
static int g_menu_items_row = 0;
static int g_menu_prompt_row = 0;
static int g_menu_bottom_row = 0;

static void ui_menu_pack_inner(char *out, const char *text) {
    int i;
    int tlen = text ? (int)strlen(text) : 0;

    for (i = 0; i < MENU_INNER_W; i++)
        out[i] = ' ';
    out[MENU_INNER_W] = '\0';
    if (tlen > MENU_CONTENT_W)
        tlen = MENU_CONTENT_W;
    if (tlen > 0)
        memcpy(out + MENU_PAD_H, text, (size_t)tlen);
}

static void ui_menu_draw_row(int row, const char *text) {
    char inner[MENU_INNER_W + 1];

    ui_menu_pack_inner(inner, text);
    printf("\033[%d;1H\033[2K", row);
    ui_put_hpad(MENU_VISIBLE);
    fputs(ui_green(), stdout);
    fputs(UI_BG "|" UI_RESET, stdout);
    fputs(ui_green(), stdout);
    fputs(UI_BG, stdout);
    fputs(inner, stdout);
    fputs(UI_RESET, stdout);
    fputs(ui_green(), stdout);
    fputs(UI_BG "|" UI_RESET, stdout);
    fflush(stdout);
}

static void ui_menu_edge_top(void) {
    int i;
    int row = g_menu_vpad + 1;

    printf("\033[%d;1H\033[2K", row);
    ui_put_hpad(MENU_VISIBLE);
    fputs(ui_green(), stdout);
    fputs(UI_BG "+", stdout);
    for (i = 0; i < MENU_INNER_W; i++)
        fputs("-", stdout);
    fputs("+" UI_RESET, stdout);
    fflush(stdout);
}

static void ui_menu_edge_bottom(void) {
    int i;
    int row = g_menu_bottom_row;

    printf("\033[%d;1H\033[2K", row);
    ui_put_hpad(MENU_VISIBLE);
    fputs(ui_green(), stdout);
    fputs(UI_BG "+", stdout);
    for (i = 0; i < MENU_INNER_W; i++)
        fputs("-", stdout);
    fputs("+" UI_RESET, stdout);
    fflush(stdout);
}

static void ui_menu_layout(void) {
    int inner = MENU_PAD_V + 1 + 1 + MENU_NUM_ITEMS + 1 + MENU_PAD_V;
    int box_h = inner + 2;
    int avail = g_ui_rows - FKT_UI_BANNER_ROWS;

    g_menu_vpad = FKT_UI_BANNER_ROWS + (avail - box_h) / 2;
    if (g_menu_vpad < FKT_UI_BANNER_ROWS)
        g_menu_vpad = FKT_UI_BANNER_ROWS;

    g_menu_title_row = g_menu_vpad + 2 + MENU_PAD_V;
    g_menu_items_row = g_menu_title_row + 2;
    g_menu_prompt_row = g_menu_items_row + MENU_NUM_ITEMS;
    g_menu_bottom_row = g_menu_prompt_row + 1 + MENU_PAD_V;
}

static void ui_menu_cursor_after_prompt(void) {
    int col = ui_hpad(MENU_VISIBLE) + 2 + MENU_PAD_H + (int)strlen(MENU_PROMPT);

    printf("\033[%d;%dH", g_menu_prompt_row, col);
    fflush(stdout);
}

static void ui_draw_banner_row(int row, const char *inner) {
    int i;
    int len = inner ? (int)strlen(inner) : 0;
    char buf[UI_BANNER_W + 1];

    for (i = 0; i < UI_BANNER_W; i++)
        buf[i] = ' ';
    buf[UI_BANNER_W] = '\0';
    if (len > UI_BANNER_W)
        len = UI_BANNER_W;
    if (len > 0)
        memcpy(buf, inner, (size_t)len);

    printf("\033[%d;1H\033[2K", row);
    ui_put_hpad(UI_BANNER_W + 2);
    fputs(ui_green(), stdout);
    fputs(UI_BG "|" UI_RESET, stdout);
    fputs(ui_green(), stdout);
    fputs(UI_BG, stdout);
    fputs(buf, stdout);
    fputs(UI_RESET, stdout);
    fputs(UI_BG, stdout);
    fputs(ui_green(), stdout);
    fputs("|" UI_RESET, stdout);
    fflush(stdout);
}

void fkt_ui_draw_banner(int air_gapped) {
    char line[UI_BANNER_W + 1];
    const char *right = air_gapped ? UI_RIGHT_AIR : UI_RIGHT_OFF;
    int left_len = (int)strlen(UI_LEFT_LABEL);
    int right_len = (int)strlen(right);
    int gap;
    int i;

    for (i = 0; i < UI_BANNER_W; i++)
        line[i] = '-';
    line[UI_BANNER_W] = '\0';

    ui_draw_banner_row(1, line);

    for (i = 0; i < UI_BANNER_W; i++)
        line[i] = ' ';
    line[UI_BANNER_W] = '\0';
    memcpy(line, UI_LEFT_LABEL, (size_t)left_len);
    gap = UI_BANNER_W - right_len;
    if (gap > left_len)
        memcpy(line + gap, right, (size_t)right_len);
    ui_draw_banner_row(2, line);

    for (i = 0; i < UI_BANNER_W; i++)
        line[i] = '-';
    ui_draw_banner_row(3, line);
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
    fputs(ui_green(), stdout);
    fputs(UI_BG, stdout);
    printf("\n  %s\n  > ", label);
    fputs(UI_RESET, stdout);
    fflush(stdout);
    if (!fkt_ui_read_line(out, out_len, 1))
        return 0;
    return out[0] != '\0';
}

static void ui_draw_menu_box(void) {
    static const char *items[MENU_NUM_ITEMS] = {
        "1. Load seed",
        "2. Load PSBT",
        "3. Preview transaction",
        "4. Sign transaction",
        "5. Show seed (with verification)",
        "6. Create new wallet",
        "7. Toggle theme",
        "0. Exit"
    };
    int i;
    int r;

    fkt_ui_clear_screen();
    fkt_ui_draw_banner(1);
    ui_menu_layout();

    ui_menu_edge_top();

    for (r = g_menu_vpad + 2; r < g_menu_title_row; r++)
        ui_menu_draw_row(r, "");

    ui_menu_draw_row(g_menu_title_row, MENU_TITLE);

    ui_menu_draw_row(g_menu_title_row + 1, "");

    for (i = 0; i < MENU_NUM_ITEMS; i++)
        ui_menu_draw_row(g_menu_items_row + i, items[i]);

    ui_menu_draw_row(g_menu_prompt_row, MENU_PROMPT);

    for (r = g_menu_prompt_row + 1; r < g_menu_bottom_row; r++)
        ui_menu_draw_row(r, "");

    ui_menu_edge_bottom();
    ui_menu_cursor_after_prompt();
}

static int ui_menu_load_seed(void) {
    if (fkt_interactive_seed(g_session_words, &g_session_num_words)) {
        g_seed_loaded = 1;
        fputs(ui_green(), stdout);
        fputs("\n  [OK] Seed loaded and verified.\n" UI_RESET, stdout);
        return 1;
    }
    g_seed_loaded = 0;
    g_session_num_words = 0;
    fputs(UI_YELLOW "\n  Seed load cancelled or failed.\n" UI_RESET, stdout);
    return 0;
}

static int ui_menu_load_psbt(void) {
    if (!fkt_ui_prompt_path("PSBT file path:", g_psbt_path, sizeof(g_psbt_path)))
        return 0;
    fputs(ui_green(), stdout);
    fputs("\n  [OK] PSBT path stored.\n" UI_RESET, stdout);
    return 1;
}

static int ui_menu_preview(void) {
    if (g_psbt_path[0] == '\0') {
        if (!fkt_ui_prompt_path("PSBT file path:", g_psbt_path, sizeof(g_psbt_path)))
            return 0;
    }
    if (fkt_psbt_preview(g_psbt_path) != 0) {
        fputs(UI_YELLOW "\n  Preview failed.\n" UI_RESET, stdout);
        return 0;
    }
    fputs(ui_green(), stdout);
    fputs("\n  [READ-ONLY] Press Enter to return to menu..." UI_RESET, stdout);
    fflush(stdout);
    {
        char dummy[8];
        fkt_ui_read_line(dummy, sizeof(dummy), 0);
    }
    return 1;
}

static int ui_menu_sign(void) {
    char out_path[512];

    if (!g_seed_loaded) {
        fputs(UI_YELLOW "\n  Load seed first (option 1).\n" UI_RESET, stdout);
        return 0;
    }
    if (g_psbt_path[0] == '\0') {
        if (!fkt_ui_prompt_path("Input PSBT path:", g_psbt_path, sizeof(g_psbt_path)))
            return 0;
    }
    if (!fkt_ui_prompt_path("Output signed PSBT path:", out_path, sizeof(out_path)))
        return 0;

    if (fkt_sign_psbt_from_words(g_psbt_path, out_path,
                                g_session_words, g_session_num_words) != 0) {
        fputs(UI_YELLOW "\n  Signing failed.\n" UI_RESET, stdout);
        return 0;
    }
    fputs(ui_green(), stdout);
    fputs("\n  [OK] Transaction signed.\n" UI_RESET, stdout);
    return 1;
}

static int ui_menu_show_seed(void) {
    int i;

    if (!g_seed_loaded) {
        fputs(UI_YELLOW "\n  No seed loaded.\n" UI_RESET, stdout);
        return 0;
    }
    fputs(ui_green(), stdout);
    fputs(UI_BG "\n  SEED (VERIFY BEFORE DISPLAY):\n" UI_RESET, stdout);
    for (i = 0; i < g_session_num_words; i++) {
        printf("  %2d. %s\n", i + 1, g_session_words[i]);
    }
    fputs(UI_YELLOW "\n  Re-run Load seed to re-verify.\n" UI_RESET, stdout);
    return 1;
}

static int ui_menu_new_wallet(void) {
    fputs(ui_green(), stdout);
    fputs("\n  Create new wallet: use option 1 (Load seed) with a new mnemonic.\n" UI_RESET, stdout);
    fputs("  Wallet generation from entropy is planned.\n", stdout);
    return 1;
}

int fkt_ui_main_menu(void) {
    char choice[32];

    fkt_ui_term_init();
    g_psbt_path[0] = '\0';
    g_seed_loaded = 0;
    g_session_num_words = 0;

    for (;;) {
        ui_draw_menu_box();
        if (!fkt_ui_read_line(choice, sizeof(choice), 1))
            return 0;

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
        else if (strcmp(choice, "7") == 0) {
            fkt_ui_toggle_theme();
            fputs(ui_green(), stdout);
            fputs("\n  Theme toggled.\n" UI_RESET, stdout);
        } else {
            fputs(UI_YELLOW "\n  Invalid option.\n" UI_RESET, stdout);
        }
    }
}