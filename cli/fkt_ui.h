#ifndef FKT_UI_H
#define FKT_UI_H

#include "fkt_compat.h"
#include "fkt_seed.h"
#include <stdio.h>

#define FKT_UI_BANNER_ROWS 2

void fkt_cli_print_help(FILE *fp);
void fkt_cli_print_version(FILE *fp);
int  fkt_cli_sign_success_interact(const char *out_psbt);

int  fkt_ui_body_col(void);
void fkt_ui_draw_subtitle(const char *title);
void fkt_ui_body_puts(const char *text);
void fkt_ui_body_printf(const char *fmt, ...);
int  fkt_ui_show_qr_text(const char *text);
int  fkt_ui_show_qr_loaded_psbt(void);
int  fkt_ui_show_qr_psbt_file(const char *path);
int  fkt_ui_show_qr_seed(const char words[][WORD_BUF], int num_words);

void fkt_ui_term_init(void);
void fkt_ui_term_restore(void);
int  fkt_ui_term_cols(void);
int  fkt_ui_term_rows(void);
void fkt_ui_clear_screen(void);
const char *fkt_ui_green_str(void);
void fkt_ui_draw_banner(int air_gapped);
void fkt_ui_draw_separator(void);
void fkt_ui_draw_footer(const char *seed_st, const char *psbt_st);
void fkt_ui_pin_footer(const char *seed_st, const char *psbt_st);
void fkt_ui_pin_session_footer(void);
void fkt_show_seed_grid(const char words[][WORD_BUF], int num_words);
int  fkt_ui_theme_bright(void);
int  fkt_ui_debug_enabled(void);
void fkt_ui_toggle_theme(void);
void fkt_ui_set_input_pos(int row, int col);
void fkt_ui_set_redraw_cb(void (*fn)(void));
/* Global hotkeys: ? help, ! debug, # theme. Returns 0 none, 1 handled, 2 menu. */
int  fkt_ui_handle_hotkey(const char *choice);
int  fkt_ui_read_line(char *out, size_t out_len, int reject_empty);
int  fkt_ui_prompt_path(const char *label, char *out, size_t out_len);
int  fkt_ui_main_menu(void);

#endif