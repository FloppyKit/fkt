/* fkt_platform.h - build profile + platform I/O API (PR1 port layer) */
#ifndef FKT_PLATFORM_H
#define FKT_PLATFORM_H

#include "fkt_compat.h"
#include <stddef.h>

#if defined(FKT_DOS) && FKT_DOS
#define FKT_PLATFORM_DOS   1
#else
#define FKT_PLATFORM_LINUX 1
#endif

/* TTY */
int  fkt_tty_init(void);
void fkt_tty_restore(void);
int  fkt_tty_cols(void);
int  fkt_tty_rows(void);
int  fkt_tty_is_interactive(void);
int  fkt_tty_raw_begin(void);
int  fkt_tty_raw_end(void);
int  fkt_tty_read_key(void);
int  fkt_tty_read_key_once(void);

/* Screen (1-based row/col, ANSI when available) */
void fkt_screen_clear(void);
void fkt_screen_goto(int row, int col);
void fkt_screen_clear_line(int row);
void fkt_screen_cursor_show(void);
void fkt_screen_cursor_hide(void);
int  fkt_screen_has_ansi(void);

/* File helpers */
int  fkt_file_is_regular(const char *path);

#endif /* FKT_PLATFORM_H */