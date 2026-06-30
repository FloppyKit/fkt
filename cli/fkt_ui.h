#ifndef FKT_UI_H
#define FKT_UI_H

#include "fkt_compat.h"

#define FKT_UI_BANNER_ROWS 3

void fkt_ui_term_init(void);
int  fkt_ui_term_cols(void);
int  fkt_ui_term_rows(void);
void fkt_ui_clear_screen(void);
void fkt_ui_draw_banner(int air_gapped);
int  fkt_ui_theme_bright(void);
void fkt_ui_toggle_theme(void);
int  fkt_ui_read_line(char *out, size_t out_len, int reject_empty);
int  fkt_ui_prompt_path(const char *label, char *out, size_t out_len);
int  fkt_ui_main_menu(void);

#endif