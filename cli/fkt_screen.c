/* fkt_screen.c - ANSI screen control (Linux; DOS stubs later) */
#include "fkt_platform.h"
#include <stdio.h>

void fkt_screen_clear(void) {
    if (fkt_screen_has_ansi())
        fputs("\033[2J\033[H", stdout);
    else
        putchar('\n');
    fflush(stdout);
}

void fkt_screen_goto(int row, int col) {
    if (fkt_screen_has_ansi())
        printf("\033[%d;%dH", row, col);
    fflush(stdout);
}

void fkt_screen_clear_line(int row) {
    if (fkt_screen_has_ansi())
        printf("\033[%d;1H\033[2K", row);
    fflush(stdout);
}

void fkt_screen_cursor_show(void) {
    if (fkt_screen_has_ansi())
        fputs("\033[?25h", stdout);
    fflush(stdout);
}

void fkt_screen_cursor_hide(void) {
    if (fkt_screen_has_ansi())
        fputs("\033[?25l", stdout);
    fflush(stdout);
}

int fkt_screen_has_ansi(void) {
#if FKT_PLATFORM_DOS
    return 0;
#else
    return 1;
#endif
}