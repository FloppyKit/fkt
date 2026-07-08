/* fkt_screen.c - screen control (ANSI on Linux, BIOS on DOS) */
#include "fkt_platform.h"
#include <stdio.h>

#if FKT_PLATFORM_DOS
#include <dos.h>
#endif

#if FKT_PLATFORM_DOS
static void fkt_dos_set_cursor(int row, int col) {
    union REGS regs;

    if (row < 1)
        row = 1;
    if (col < 1)
        col = 1;
    regs.h.ah = 2;
    regs.h.bh = 0;
    regs.h.dh = (unsigned char)(row - 1);
    regs.h.dl = (unsigned char)(col - 1);
    int86(0x10, &regs, &regs);
}

static void fkt_dos_clear_screen(void) {
    union REGS regs;

    regs.h.ah = 6;
    regs.h.al = 0;
    regs.h.bh = 7;
    regs.h.ch = 0;
    regs.h.cl = 0;
    regs.h.dh = 24;
    regs.h.dl = 79;
    int86(0x10, &regs, &regs);
    fkt_dos_set_cursor(1, 1);
}
#endif

void fkt_screen_clear(void) {
#if FKT_PLATFORM_DOS
    fkt_dos_clear_screen();
#elif FKT_PLATFORM_LINUX
    fputs("\033[2J\033[H", stdout);
#else
    putchar('\n');
#endif
    fflush(stdout);
}

void fkt_screen_goto(int row, int col) {
#if FKT_PLATFORM_DOS
    fkt_dos_set_cursor(row, col);
#elif FKT_PLATFORM_LINUX
    printf("\033[%d;%dH", row, col);
#endif
    fflush(stdout);
}

void fkt_screen_clear_line(int row) {
#if FKT_PLATFORM_DOS
    int i;

    fkt_dos_set_cursor(row, 1);
    for (i = 0; i < 80; i++)
        putchar(' ');
    fkt_dos_set_cursor(row, 1);
#elif FKT_PLATFORM_LINUX
    printf("\033[%d;1H\033[2K", row);
#endif
    fflush(stdout);
}

void fkt_screen_cursor_show(void) {
#if FKT_PLATFORM_DOS
    union REGS regs;

    regs.h.ah = 1;
    regs.h.ch = 0x06;
    regs.h.cl = 0x07;
    int86(0x10, &regs, &regs);
#elif FKT_PLATFORM_LINUX
    fputs("\033[?25h", stdout);
#endif
    fflush(stdout);
}

void fkt_screen_cursor_hide(void) {
#if FKT_PLATFORM_DOS
    union REGS regs;

    regs.h.ah = 1;
    regs.h.ch = 0x20;
    regs.h.cl = 0x00;
    int86(0x10, &regs, &regs);
#elif FKT_PLATFORM_LINUX
    fputs("\033[?25l", stdout);
#endif
    fflush(stdout);
}

int fkt_screen_has_ansi(void) {
#if FKT_PLATFORM_DOS
    return 0;
#else
    return 1;
#endif
}