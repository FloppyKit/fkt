#define _POSIX_C_SOURCE 200809L

#include "fkt_seed.h"
#include "fkt_bip39.h"
#include "fkt_memzero.h"
#include "fkt_error.h"
#include "fkt_ui.h"
#include "fkt_pbkdf2.h"
#include "fkt_signer.h"
#include "fkt_secp256k1.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>

#define SEED_GREEN   "\033[1;32m"
#define SEED_RED     "\033[1;31m"
#define SEED_YELLOW  "\033[1;33m"
#define SEED_DIM     "\033[32m"
#define SEED_RESET   "\033[0m"

/*
 * Box layout (all drawing math lives here — 80-col safe):
 *   BOX_VISIBLE  = BOX_INNER_W + 2 borders (fits 80 cols with hpad >= 14)
 *   BOX_INNER_W  = BOX_PAD_H + BOX_CONTENT_W + BOX_PAD_H
 *   BOX_PAD_H    = 2 cols breathing room inside each vertical border
 *   BOX_PAD_V    = 2 blank rows above first content and below last content
 *   BOX_CONTENT_W = 45 fits 3-column grid: "NN.word     | NN.word     | ..."
 */
#define BOX_PAD_H      2
#define BOX_PAD_V      2
#define BOX_CONTENT_W  45
#define BOX_INNER_W    (BOX_PAD_H + BOX_CONTENT_W + BOX_PAD_H)
#define BOX_VISIBLE    (BOX_INNER_W + 2)

#define BOX_TITLE      "ENTER SEED PHRASE (BIP39)"

/* ASCII box only — no Unicode (safe on DOS / Zaurus / iPaq LCDs) */
#define BOX_TL "+"
#define BOX_TR "+"
#define BOX_BL "+"
#define BOX_BR "+"
#define BOX_H  "-"
#define BOX_V  "|"

#define SEED_MSG_INVALID_WORD   "INVALID WORD - TRY AGAIN"
#define SEED_MSG_AMBIGUOUS      "AMBIGUOUS - TYPE MORE LETTERS"
#define SEED_MSG_HINT           "b=back  e3=edit  word/#/4 letters"
#define SEED_MSG_NO_BACK        "No previous word to undo."
#define SEED_MSG_BAD_EDIT       "Use edit N (1..last entered word)."
#define SEED_MSG_VALID_CHECK    "[OK] Valid checksum"
#define SEED_MSG_BAD_CHECKSUM   "Invalid checksum - start over."
#define SEED_MSG_VERIFIED       "[OK] SEED VERIFIED AND LOADED - READY TO SIGN"
#define SEED_MSG_MISMATCH       "MISMATCH - ZEROING MEMORY"
#define SEED_MSG_NOT_CONFIRMED  "Backup not confirmed - ZEROING MEMORY"

static int g_term_cols = 80;
static int g_term_rows = 24;
static int g_vpad = 0;
static int g_title_row = 0;
static int g_grid_start_row = 0;
static int g_status_gap_row = 0;
static int g_status_row = 0;
static int g_input_row = 0;
static int g_bottom_row = 0;
static int g_box_drawn = 0;
static int g_box_total = 0;

static char g_redraw_words[MAX_WORDS][WORD_BUF];
static int  g_redraw_filled = 0;
static int  g_redraw_total = 0;
static char g_redraw_prompt[64];
static char g_redraw_status[80];
static int  g_redraw_await = 0;
static int  g_redraw_has_prompt = 0;

static void fkt_seed_term_size(void) {
    fkt_ui_term_init();
    g_term_cols = fkt_ui_term_cols();
    g_term_rows = fkt_ui_term_rows();
    if (g_term_cols < BOX_VISIBLE + 2)
        g_term_cols = 80;
    if (g_term_rows < 12)
        g_term_rows = 24;
}

static void fkt_seed_lowercase(char *s) {
    while (*s) {
        *s = (char)tolower((unsigned char)*s);
        s++;
    }
}

static void fkt_seed_draw_screen(const char words[MAX_WORDS][WORD_BUF],
                                 int filled, int total,
                                 const char *prompt,
                                 const char *status,
                                 int await_input);

static void fkt_seed_redraw_cb(void) {
    if (!g_redraw_has_prompt)
        return;
    fkt_seed_draw_screen(g_redraw_words, g_redraw_filled, g_redraw_total,
                         g_redraw_prompt, g_redraw_status, g_redraw_await);
}

static int fkt_seed_read_line(char *out, size_t out_len, int lowercase) {
    char line[128];

    for (;;) {
        if (!fkt_ui_read_line(line, sizeof(line), 0))
            return 0;
        if (line[0] == '\0')
            continue;
        if (sscanf(line, "%31s", out) != 1)
            continue;
        if (strlen(out) >= out_len)
            return 0;
        if (lowercase)
            fkt_seed_lowercase(out);
        return 1;
    }
}

static int fkt_seed_is_back_cmd(const char *s) {
    return strcmp(s, "back") == 0 || strcmp(s, "b") == 0;
}

static int fkt_seed_parse_edit_cmd(const char *s, int *word_num) {
    int n = 0;
    char c0;

    if (!s || !s[0] || !word_num)
        return 0;

    if (sscanf(s, "edit %d", &n) == 1) {
        *word_num = n;
        return 1;
    }
    if (sscanf(s, "edit%d", &n) == 1) {
        *word_num = n;
        return 1;
    }
    if (sscanf(s, "e %d", &n) == 1) {
        *word_num = n;
        return 1;
    }
    if (sscanf(s, "e%d%c", &n, &c0) == 1) {
        *word_num = n;
        return 1;
    }
    return 0;
}

static int fkt_seed_all_digits(const char *s) {
    if (!s || !s[0])
        return 0;
    while (*s) {
        if (!isdigit((unsigned char)*s))
            return 0;
        s++;
    }
    return 1;
}

static int fkt_seed_prefix_ambiguous(const char *token) {
    char lower[WORD_BUF];
    size_t len;
    int i;
    int matches = 0;

    if (!token || !token[0])
        return 0;
    if (fkt_seed_all_digits(token))
        return 0;

    strncpy(lower, token, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    fkt_seed_lowercase(lower);

    if (fkt_bip39_valid_word(lower))
        return 0;

    len = strlen(lower);
    if (len < 1 || len > 4)
        return 0;

    for (i = 0; i < 2048; i++) {
        const char *w = fkt_bip39_word_at(i);
        if (strncmp(w, lower, len) == 0) {
            matches++;
            if (matches > 1)
                return 1;
        }
    }
    return 0;
}

static int fkt_seed_resolve_entry(const char *input, char resolved[WORD_BUF]) {
    if (fkt_bip39_resolve_token(input, resolved))
        return 1;
    return 0;
}

static void fkt_seed_clear_from(char words[MAX_WORDS][WORD_BUF], int from, int num_words) {
    int i;

    for (i = from; i < num_words; i++)
        words[i][0] = '\0';
}

static void fkt_seed_build_word_prompt(int word_num, char *prompt, size_t prompt_len) {
    snprintf(prompt, prompt_len, "Word %d: ", word_num);
}

static int fkt_seed_hpad(int width) {
    int pad = (g_term_cols - width) / 2;
    return pad > 0 ? pad : 0;
}

static void fkt_seed_put_hpad(int width) {
    int pad = fkt_seed_hpad(width);
    while (pad-- > 0)
        putchar(' ');
}

static int fkt_seed_grid_rows(int total) {
    return total > 0 ? total / 3 : 1;
}

static int fkt_seed_inner_lines(int total) {
    /* top pad + title + mid pad + grid + status gap + status + input + bottom pad */
    return BOX_PAD_V + 1 + BOX_PAD_V + fkt_seed_grid_rows(total) +
           1 + 1 + 1 + BOX_PAD_V;
}

static void fkt_seed_layout(int total) {
    int box_h = fkt_seed_inner_lines(total) + 2;
    int avail = g_term_rows - FKT_UI_BANNER_ROWS - 2;

    g_vpad = FKT_UI_BANNER_ROWS + (avail - box_h) / 2;
    if (g_vpad < FKT_UI_BANNER_ROWS)
        g_vpad = FKT_UI_BANNER_ROWS;

    g_title_row = g_vpad + 2 + BOX_PAD_V;
    g_grid_start_row = g_title_row + 1 + BOX_PAD_V;
    g_status_gap_row = g_grid_start_row + fkt_seed_grid_rows(total);
    g_status_row = g_status_gap_row + 1;
    g_input_row = g_status_row + 1;
    g_bottom_row = g_input_row + 1 + BOX_PAD_V;
}

static void fkt_seed_clear_screen(void) {
    fkt_ui_clear_screen();
}

static void fkt_seed_clear_below_box(int total) {
    int box_h = fkt_seed_inner_lines(total) + 2;
    int clear_from = g_vpad + box_h + 1;
    int i;

    if (clear_from < g_term_rows - 2) {
        for (i = clear_from; i < g_term_rows - 2; i++)
            printf("\033[%d;1H\033[2K", i);
    }
    fflush(stdout);
}

/* Pack text into the inner band: [BOX_PAD_H spaces][BOX_CONTENT_W chars] */
static void fkt_seed_pack_inner(char *out, const char *text, int center) {
    int i;
    int tlen = text ? (int)strlen(text) : 0;
    int start = BOX_PAD_H;

    for (i = 0; i < BOX_INNER_W; i++)
        out[i] = ' ';
    out[BOX_INNER_W] = '\0';

    if (tlen > BOX_CONTENT_W)
        tlen = BOX_CONTENT_W;
    if (center)
        start = BOX_PAD_H + (BOX_CONTENT_W - tlen) / 2;
    if (tlen > 0)
        memcpy(out + start, text, (size_t)tlen);
}

/*
 * Draw one complete bordered row: ║ + inner(BOX_INNER_W) + ║
 * Right border is always column hpad+BOX_VISIBLE (no extra stray spaces).
 */
static void fkt_seed_draw_row(int row, const char *text, const char *color,
                              int center) {
    char inner[BOX_INNER_W + 1];

    (void)color;
    fkt_seed_pack_inner(inner, text, center);

    printf("\033[%d;1H\033[2K", row);
    fkt_seed_put_hpad(BOX_VISIBLE);
    fputs(fkt_ui_green_str(), stdout);
    fputs(BOX_V, stdout);
    fputs(inner, stdout);
    fputs(fkt_ui_green_str(), stdout);
    fputs(BOX_V, stdout);
    fflush(stdout);
}

static void fkt_seed_box_edge_top(void) {
    int i;
    int row = g_vpad + 1;

    printf("\033[%d;1H\033[2K", row);
    fkt_seed_put_hpad(BOX_VISIBLE);
    fputs(fkt_ui_green_str(), stdout);
    fputs(BOX_TL, stdout);
    for (i = 0; i < BOX_INNER_W; i++)
        fputs(BOX_H, stdout);
    fputs(BOX_TR, stdout);
    fflush(stdout);
}

static void fkt_seed_box_edge_bottom(void) {
    int i;
    int row = g_bottom_row;

    printf("\033[%d;1H\033[2K", row);
    fkt_seed_put_hpad(BOX_VISIBLE);
    fputs(fkt_ui_green_str(), stdout);
    fputs(BOX_BL, stdout);
    for (i = 0; i < BOX_INNER_W; i++)
        fputs(BOX_H, stdout);
    fputs(BOX_BR, stdout);
    fflush(stdout);
}

static void fkt_seed_box_blank_row(int row) {
    fkt_seed_draw_row(row, "", SEED_RESET, 0);
}

static const char *fkt_seed_status_color(const char *status);

static void fkt_seed_build_grid_line(const char words[MAX_WORDS][WORD_BUF],
                                     int filled, int total, int r,
                                     char *line, size_t line_len) {
    int cols = 3;
    int rows = total / cols;
    int c;
    size_t pos = 0;

    line[0] = '\0';
    for (c = 0; c < cols; c++) {
        char cell[16];
        int idx = c * rows + r;
        int n;

        if (idx < filled)
            n = snprintf(cell, sizeof(cell), "%2d.%-10s", idx + 1, words[idx]);
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

static void fkt_seed_render_grid(const char words[MAX_WORDS][WORD_BUF],
                                 int filled, int total) {
    int rows = fkt_seed_grid_rows(total);
    int r;
    char line[BOX_INNER_W + 1];

    for (r = 0; r < rows; r++) {
        fkt_seed_build_grid_line(words, filled, total, r, line, sizeof(line));
        fkt_seed_draw_row(g_grid_start_row + r, line, SEED_DIM, 0);
    }
}

/* Redraw grid + status gap + status + input without full-screen clear */
static void fkt_seed_redraw_content(const char words[MAX_WORDS][WORD_BUF],
                                    int filled, int total,
                                    const char *prompt,
                                    const char *status) {
    int r;

    if (total > 0) {
        fkt_seed_render_grid(words, filled, total);
    } else {
        fkt_seed_box_blank_row(g_grid_start_row);
    }

    fkt_seed_box_blank_row(g_status_gap_row);

    if (status && status[0])
        fkt_seed_draw_row(g_status_row, status,
                          fkt_seed_status_color(status), 0);
    else
        fkt_seed_box_blank_row(g_status_row);

    if (prompt && prompt[0])
        fkt_seed_draw_row(g_input_row, prompt, SEED_RESET, 0);
    else
        fkt_seed_box_blank_row(g_input_row);

    for (r = g_input_row + 1; r < g_bottom_row; r++)
        fkt_seed_box_blank_row(r);

    fkt_seed_box_edge_bottom();
    fkt_ui_pin_session_footer();
}

static const char *fkt_seed_status_color(const char *status) {
    if (!status || !status[0])
        return SEED_RESET;
    if (strstr(status, "INVALID") || strstr(status, "AMBIGUOUS") ||
        strstr(status, "MISMATCH") || strstr(status, "not confirmed") ||
        strstr(status, "Invalid") || strstr(status, "No previous") ||
        strstr(status, "Use edit"))
        return SEED_RED;
    if (strstr(status, "[OK]") || strstr(status, "Valid") ||
        strstr(status, "verified") || strstr(status, "VERIFIED"))
        return SEED_GREEN;
    return SEED_YELLOW;
}

static void fkt_seed_redraw_input_line(const char *prompt) {
    fkt_seed_draw_row(g_input_row, prompt, SEED_RESET, 0);
}

static void fkt_seed_cursor_after_prompt(const char *prompt) {
    /* one space after colon is part of prompt; cursor sits right after it */
    int col = fkt_seed_hpad(BOX_VISIBLE) + 2 + BOX_PAD_H + (int)strlen(prompt);

    fkt_ui_set_input_pos(g_input_row, col);
    printf("\033[%d;%dH", g_input_row, col);
    fflush(stdout);
}

static void fkt_seed_wipe_input_typed(void) {
    /* Enter lands on the bottom-border row; restore it, then reclaim input row */
    fkt_seed_box_edge_bottom();
    printf("\033[%d;1H", g_input_row);
    fflush(stdout);
}

static void fkt_seed_prompt_input(const char *prompt) {
    fkt_seed_redraw_input_line(prompt);
    fkt_seed_cursor_after_prompt(prompt);
}

static void fkt_seed_draw_screen(const char words[MAX_WORDS][WORD_BUF],
                                 int filled, int total,
                                 const char *prompt,
                                 const char *status,
                                 int await_input) {
    int r;

    fkt_seed_layout(total);
    fkt_seed_clear_screen();
    fkt_ui_draw_banner(1);
    fkt_seed_box_edge_top();

    /* BOX_PAD_V blank rows above first content */
    for (r = g_vpad + 2; r < g_title_row; r++)
        fkt_seed_box_blank_row(r);

    fkt_seed_draw_row(g_title_row, BOX_TITLE, SEED_GREEN, 1);

    /* BOX_PAD_V blank rows between title and grid / prompt area */
    for (r = g_title_row + 1; r < g_grid_start_row; r++)
        fkt_seed_box_blank_row(r);

    if (total > 0)
        fkt_seed_render_grid(words, filled, total);
    else
        fkt_seed_box_blank_row(g_grid_start_row);

    fkt_seed_box_blank_row(g_status_gap_row);

    if (status && status[0])
        fkt_seed_draw_row(g_status_row, status,
                          fkt_seed_status_color(status), 0);
    else
        fkt_seed_box_blank_row(g_status_row);

    if (prompt && prompt[0])
        fkt_seed_draw_row(g_input_row, prompt, SEED_RESET, 0);
    else
        fkt_seed_box_blank_row(g_input_row);

    /* BOX_PAD_V blank rows below last content, above bottom border */
    for (r = g_input_row + 1; r < g_bottom_row; r++)
        fkt_seed_box_blank_row(r);

    fkt_seed_box_edge_bottom();
    fkt_seed_clear_below_box(total);
    fkt_ui_pin_session_footer();

    g_box_drawn = 1;
    g_box_total = total;

    if (prompt && prompt[0]) {
        int i;

        g_redraw_has_prompt = 1;
        g_redraw_filled = filled;
        g_redraw_total = total;
        g_redraw_await = await_input;
        strncpy(g_redraw_prompt, prompt, sizeof(g_redraw_prompt) - 1);
        g_redraw_prompt[sizeof(g_redraw_prompt) - 1] = '\0';
        if (status && status[0]) {
            strncpy(g_redraw_status, status, sizeof(g_redraw_status) - 1);
            g_redraw_status[sizeof(g_redraw_status) - 1] = '\0';
        } else {
            g_redraw_status[0] = '\0';
        }
        for (i = 0; i < filled; i++) {
            strncpy(g_redraw_words[i], words[i], WORD_BUF - 1);
            g_redraw_words[i][WORD_BUF - 1] = '\0';
        }
        fkt_ui_set_redraw_cb(fkt_seed_redraw_cb);
        if (await_input)
            fkt_seed_cursor_after_prompt(prompt);
    } else {
        g_redraw_has_prompt = 0;
        fkt_ui_set_redraw_cb(NULL);
    }
}

static int fkt_seed_prompt_count(int *num_words) {
    char buf[32];

    g_box_drawn = 0;
    fkt_seed_draw_screen(NULL, 0, 0,
                         "Enter number of words (12 or 24): ", "", 1);
    if (!fkt_seed_read_line(buf, sizeof(buf), 0))
        return 0;
    fkt_seed_wipe_input_typed();
    *num_words = atoi(buf);
    if (*num_words != 12 && *num_words != 24) {
        fkt_seed_draw_screen(NULL, 0, 0,
                             "Enter number of words (12 or 24): ",
                             "Invalid word count.", 0);
        return 0;
    }
    return 1;
}

static int fkt_seed_collect_words(char words[MAX_WORDS][WORD_BUF], int num_words) {
    int filled = 0;
    char prompt[64];
    char status[80];

    g_box_drawn = 0;
    while (filled < num_words) {
        char input[WORD_BUF];
        char resolved[WORD_BUF];
        const char *status_msg = SEED_MSG_HINT;
        int edit_n = 0;

        fkt_seed_build_word_prompt(filled + 1, prompt, sizeof(prompt));

        if (!g_box_drawn || g_box_total != num_words) {
            fkt_seed_draw_screen(words, filled, num_words, prompt, SEED_MSG_HINT, 1);
        } else {
            fkt_seed_redraw_content(words, filled, num_words, prompt, SEED_MSG_HINT);
            fkt_seed_cursor_after_prompt(prompt);
        }

        if (!fkt_seed_read_line(input, sizeof(input), 1))
            return 0;
        fkt_seed_wipe_input_typed();
        fkt_seed_redraw_input_line(prompt);
        fkt_seed_box_edge_bottom();

        if (fkt_seed_is_back_cmd(input)) {
            if (filled == 0) {
                status_msg = SEED_MSG_NO_BACK;
            } else {
                filled--;
                fkt_seed_clear_from(words, filled, num_words);
                fkt_seed_build_word_prompt(filled + 1, prompt, sizeof(prompt));
                fkt_seed_redraw_content(words, filled, num_words, prompt, SEED_MSG_HINT);
                fkt_seed_cursor_after_prompt(prompt);
                continue;
            }
        } else if (fkt_seed_parse_edit_cmd(input, &edit_n)) {
            if (edit_n < 1 || edit_n > filled) {
                status_msg = SEED_MSG_BAD_EDIT;
            } else {
                filled = edit_n - 1;
                fkt_seed_clear_from(words, filled, num_words);
                fkt_seed_build_word_prompt(filled + 1, prompt, sizeof(prompt));
                fkt_seed_redraw_content(words, filled, num_words, prompt, SEED_MSG_HINT);
                fkt_seed_cursor_after_prompt(prompt);
                continue;
            }
        } else if (!fkt_seed_resolve_entry(input, resolved)) {
            if (fkt_seed_prefix_ambiguous(input))
                status_msg = SEED_MSG_AMBIGUOUS;
            else
                status_msg = SEED_MSG_INVALID_WORD;
        } else {
            strncpy(words[filled], resolved, WORD_BUF - 1);
            words[filled][WORD_BUF - 1] = '\0';
            filled++;
            if (filled < num_words) {
                fkt_seed_build_word_prompt(filled + 1, prompt, sizeof(prompt));
                fkt_seed_redraw_content(words, filled, num_words, prompt, SEED_MSG_HINT);
                fkt_seed_cursor_after_prompt(prompt);
                continue;
            }
            status_msg = "";
        }

        if (status_msg[0]) {
            fkt_seed_redraw_content(words, filled, num_words, prompt, status_msg);
            fkt_seed_cursor_after_prompt(prompt);
        }
    }

    snprintf(prompt, sizeof(prompt), "All %d words entered.", num_words);
    if (fkt_bip39_validate_checksum(words, num_words)) {
        strcpy(status, SEED_MSG_VALID_CHECK);
        fkt_seed_draw_screen(words, filled, num_words, prompt, status, 0);
    } else {
        fkt_seed_draw_screen(words, filled, num_words, prompt,
                             SEED_MSG_BAD_CHECKSUM, 0);
        fkt_secure_zero(words, sizeof(words[0]) * MAX_WORDS);
        return 0;
    }
    return 1;
}

int fkt_interactive_seed(char words[MAX_WORDS][WORD_BUF], int *num_words) {
    fkt_seed_term_size();
    fkt_seed_clear_screen();
    if (!fkt_seed_prompt_count(num_words))
        return 0;
    if (!fkt_seed_collect_words(words, *num_words))
        return 0;
    return fkt_verify_seed(words, *num_words);
}

int fkt_verify_seed(char words[MAX_WORDS][WORD_BUF], int num_words) {
    char reentry[WORD_BUF];
    char confirm[32];
    char prompt[64];
    int idx;

    if (!fkt_bip39_validate_checksum(words, num_words)) {
        fkt_secure_zero(words, sizeof(words[0]) * MAX_WORDS);
        return 0;
    }

    idx = rand() % num_words;

    snprintf(prompt, sizeof(prompt),
             "Confirm Backup - re-type word #%d: ", idx + 1);
    fkt_seed_draw_screen(words, num_words, num_words, prompt, "", 1);
    if (!fkt_seed_read_line(reentry, sizeof(reentry), 1)) {
        fkt_secure_zero(words, sizeof(words[0]) * MAX_WORDS);
        return 0;
    }
    fkt_seed_wipe_input_typed();
    fkt_seed_redraw_input_line(prompt);

    {
        char resolved[WORD_BUF];
        if (!fkt_seed_resolve_entry(reentry, resolved)) {
            fkt_seed_draw_screen(words, num_words, num_words, prompt,
                                 SEED_MSG_INVALID_WORD, 0);
            fkt_secure_zero(words, sizeof(words[0]) * MAX_WORDS);
            return 0;
        }
        strncpy(reentry, resolved, WORD_BUF - 1);
        reentry[WORD_BUF - 1] = '\0';
    }

    if (strcmp(reentry, words[idx]) != 0) {
        fkt_seed_draw_screen(words, num_words, num_words, prompt,
                             SEED_MSG_MISMATCH, 0);
        fkt_secure_zero(words, sizeof(words[0]) * MAX_WORDS);
        return 0;
    }

    fkt_seed_draw_screen(words, num_words, num_words,
                         "Type CONFIRM to accept seed:",
                         "Confirm Backup... verified.", 1);
    if (!fkt_seed_read_line(confirm, sizeof(confirm), 1)) {
        fkt_secure_zero(words, sizeof(words[0]) * MAX_WORDS);
        return 0;
    }
    fkt_seed_wipe_input_typed();
    fkt_seed_redraw_input_line("Type CONFIRM to accept seed:");

    if (strcmp(confirm, "confirm") != 0) {
        fkt_seed_draw_screen(words, num_words, num_words,
                             "Type CONFIRM to accept seed:",
                             SEED_MSG_NOT_CONFIRMED, 0);
        fkt_secure_zero(words, sizeof(words[0]) * MAX_WORDS);
        return 0;
    }

    fkt_seed_draw_screen(words, num_words, num_words, "",
                         SEED_MSG_VERIFIED, 0);
    return 1;
}

int fkt_seed_from_string(const char *str, char words[MAX_WORDS][WORD_BUF], int *num_words) {
    const char *p = str;
    int count = 0;

    *num_words = 0;
    while (*p && count < MAX_WORDS) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (sscanf(p, "%31s", words[count]) != 1)
            return 0;
        {
            char resolved[WORD_BUF];
            if (!fkt_bip39_resolve_token(words[count], resolved))
                return 0;
            strncpy(words[count], resolved, WORD_BUF - 1);
            words[count][WORD_BUF - 1] = '\0';
        }
        count++;
        while (*p && *p != ' ') p++;
    }

    if (count != 12 && count != 24)
        return 0;

    *num_words = count;
    return 1;
}

void fkt_secure_zero(void *ptr, size_t len) {
    fkt_memzero(ptr, len);
}

int fkt_sign_psbt_from_words(const char *input_psbt, const char *output_psbt,
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
    fkt_last_error_clear();
    if (fkt_sign_psbt(seed, "", input_psbt, output_psbt) != 0) {
        fkt_memzero_wipe_all();
        return -1;
    }
    fkt_memzero_wipe_all();
    return 0;
}