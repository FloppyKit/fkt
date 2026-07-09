/* fkt_platform.h - build profile + platform I/O API (PR1 port layer + PR2 input) */
#ifndef FKT_PLATFORM_H
#define FKT_PLATFORM_H

#include "fkt_compat.h"
#include <stddef.h>

#if defined(FKT_DOS) && FKT_DOS
#define FKT_PLATFORM_DOS   1
#else
#define FKT_PLATFORM_LINUX 1
#endif

/* Build profile (set by Makefile) */
#if defined(FKT_DEV_HARNESS) && FKT_DEV_HARNESS
#define FKT_BUILD_DEV_HARNESS 1
#endif

#if defined(FKT_NO_FINALIZER) && FKT_NO_FINALIZER
#define FKT_BUILD_NO_FINALIZER 1
#endif

/* Special keys (outside ASCII printable). Text input should ignore ch >= 0x100. */
#define FKT_KEY_UP      0x150
#define FKT_KEY_DOWN    0x151
#define FKT_KEY_LEFT    0x152
#define FKT_KEY_RIGHT   0x153
#define FKT_KEY_PGUP    0x154
#define FKT_KEY_PGDN    0x155
#define FKT_KEY_HOME    0x156
#define FKT_KEY_END     0x157
#define FKT_KEY_SPECIAL (-2) /* unmapped extended key; ignore */

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
int  fkt_tty_kbhit(void); /* 1 if a key is waiting */

/* Mouse (INT 33h on DOS; no-op / unavailable on Linux host shells).
 * No camera on any current build — browse/paste only. */
int  fkt_mouse_available(void);
void fkt_mouse_show(void);
void fkt_mouse_hide(void);
/* 1 = left-button press since last call; row/col are 1-based text cells */
int  fkt_mouse_click(int *row, int *col);

/* Screen (1-based row/col, ANSI when available) */
void fkt_dos_init(void); /* mode 03h, green-on-black, 1992 banner; no-op non-DOS */
void fkt_screen_clear(void);
void fkt_screen_goto(int row, int col);
void fkt_screen_clear_line(int row);
void fkt_screen_recolor(void);          /* DOS: force theme attrs after stdio draws */
void fkt_screen_after_graphics(void);   /* DOS: restore text mode + banner post VGA */
void fkt_screen_set_theme_amber(int amber); /* DOS: 0=green 1=amber; no-op Linux */
int  fkt_screen_theme_amber(void);
void fkt_screen_cursor_show(void);
void fkt_screen_cursor_hide(void);
int  fkt_screen_has_ansi(void);

/* File helpers */
int  fkt_file_is_regular(const char *path);
int  fkt_file_is_dir(const char *path);

/* File picker: list dir, keyboard + optional mouse. filter_ext e.g. ".psbt" or NULL.
 * Returns 1 and writes absolute/relative path to out; 0 = cancel. */
int  fkt_pick_file(char *out, size_t out_len, const char *filter_ext,
                   const char *title);

#endif /* FKT_PLATFORM_H */
