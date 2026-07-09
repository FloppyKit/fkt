/* fkt_screen.c - screen control (ANSI on Linux, BIOS/VRAM on DOS) */
#include "fkt_platform.h"
#include <stdio.h>
#include <string.h>

#if FKT_PLATFORM_DOS
#include <conio.h>
#include <dos.h>
#include <pc.h>
#endif

#if FKT_PLATFORM_DOS
#define FKT_DOS_ATTR_GREEN  0x0A /* light green on black */
#define FKT_DOS_ATTR_AMBER  0x0E /* yellow/amber on black */
#define FKT_DOS_BANNER_ROWS 2

static const char fkt_dos_banner_text[] = "FKT SIGNER v0.1";

static int g_dos_inited = 0;
static int g_dos_cols = 80;
static int g_dos_rows = 25;
static unsigned char g_dos_attr = FKT_DOS_ATTR_GREEN;

static void fkt_dos_sync_geom(void) {
    int c;
    int r;

    c = ScreenCols();
    r = ScreenRows();
    if (c >= 40 && c <= 132)
        g_dos_cols = c;
    if (r >= 12 && r <= 50)
        g_dos_rows = r;
}

void fkt_screen_set_theme_amber(int amber) {
    g_dos_attr = amber ? FKT_DOS_ATTR_AMBER : FKT_DOS_ATTR_GREEN;
    ScreenAttrib = g_dos_attr;
    textattr((int)g_dos_attr);
    fkt_screen_recolor();
}

int fkt_screen_theme_amber(void) {
    return (g_dos_attr == FKT_DOS_ATTR_AMBER) ? 1 : 0;
}

void fkt_screen_recolor(void) {
    int x;
    int y;
    int ch;
    int attr;

    if (!g_dos_inited)
        return;
    fkt_dos_sync_geom();
    for (y = 0; y < g_dos_rows; y++) {
        for (x = 0; x < g_dos_cols; x++) {
            ScreenGetChar(&ch, &attr, x, y);
            if ((unsigned char)attr != g_dos_attr)
                ScreenPutChar(ch, (int)g_dos_attr, x, y);
        }
    }
}

static void fkt_dos_fill(int x0, int y0, int x1, int y1, int ch) {
    int x;
    int y;

    if (x0 < 0)
        x0 = 0;
    if (y0 < 0)
        y0 = 0;
    if (x1 >= g_dos_cols)
        x1 = g_dos_cols - 1;
    if (y1 >= g_dos_rows)
        y1 = g_dos_rows - 1;
    for (y = y0; y <= y1; y++) {
        for (x = x0; x <= x1; x++)
            ScreenPutChar(ch, (int)g_dos_attr, x, y);
    }
}

static void fkt_dos_put_str_at(int x, int y, const char *s) {
    int i;

    if (!s)
        return;
    for (i = 0; s[i] != '\0' && (x + i) < g_dos_cols; i++)
        ScreenPutChar((unsigned char)s[i], (int)g_dos_attr, x + i, y);
}

static void fkt_dos_paint_banner(void) {
    int i;

    fkt_dos_fill(0, 0, g_dos_cols - 1, FKT_DOS_BANNER_ROWS - 1, ' ');
    fkt_dos_put_str_at(0, 0, fkt_dos_banner_text);
    /* Right: full cold-wallet tag when it fits */
    {
        const char *tag = "ICED COLD WALLET";
        int tlen = (int)strlen(tag);
        int blen = (int)strlen(fkt_dos_banner_text);
        if (blen + tlen + 2 < g_dos_cols)
            fkt_dos_put_str_at(g_dos_cols - tlen, 0, tag);
    }
    for (i = 0; i < g_dos_cols; i++)
        ScreenPutChar('-', (int)g_dos_attr, i, 1);
}

static void fkt_dos_set_cursor(int row, int col) {
    if (row < 1)
        row = 1;
    if (col < 1)
        col = 1;
    if (row > g_dos_rows)
        row = g_dos_rows;
    if (col > g_dos_cols)
        col = g_dos_cols;

    ScreenSetCursor(row - 1, col - 1);
    gotoxy(col, row);
}

static void fkt_dos_clear_screen(void) {
    fkt_dos_sync_geom();
    ScreenAttrib = g_dos_attr;
    textattr((int)g_dos_attr);
    fkt_dos_fill(0, 0, g_dos_cols - 1, g_dos_rows - 1, ' ');
    fkt_dos_paint_banner();
    fkt_dos_set_cursor(FKT_DOS_BANNER_ROWS + 1, 1);
}

void fkt_dos_init(void) {
    union REGS regs;

    regs.h.ah = 0x00;
    regs.h.al = 0x03;
    int86(0x10, &regs, &regs);

    gppconio_init();
    ScreenAttrib = g_dos_attr;
    textattr((int)g_dos_attr);
    if (g_dos_attr == FKT_DOS_ATTR_AMBER) {
        textcolor(YELLOW);
    } else {
        textcolor(LIGHTGREEN);
    }
    textbackground(BLACK);

    setvbuf(stdout, (char *)0, _IONBF, 0);

    fkt_dos_sync_geom();
    fkt_dos_clear_screen();

    regs.h.ah = 0x01;
    regs.h.ch = 0x06;
    regs.h.cl = 0x07;
    int86(0x10, &regs, &regs);

    g_dos_inited = 1;
}

void fkt_screen_after_graphics(void) {
    g_dos_inited = 0;
    fkt_dos_init();
}
#else
void fkt_dos_init(void) {
}

void fkt_screen_recolor(void) {
}

void fkt_screen_after_graphics(void) {
}

void fkt_screen_set_theme_amber(int amber) {
    (void)amber;
}

int fkt_screen_theme_amber(void) {
    return 0;
}
#endif

void fkt_screen_clear(void) {
#if FKT_PLATFORM_DOS
    if (!g_dos_inited)
        fkt_dos_init();
    fkt_dos_clear_screen();
#elif FKT_PLATFORM_LINUX
    fputs("\033[2J\033[H", stdout);
    fflush(stdout);
#else
    putchar('\n');
    fflush(stdout);
#endif
}

void fkt_screen_goto(int row, int col) {
#if FKT_PLATFORM_DOS
    if (!g_dos_inited)
        fkt_dos_init();
    fkt_dos_set_cursor(row, col);
#elif FKT_PLATFORM_LINUX
    printf("\033[%d;%dH", row, col);
    fflush(stdout);
#endif
}

void fkt_screen_clear_line(int row) {
#if FKT_PLATFORM_DOS
    int x;
    int y;

    if (!g_dos_inited)
        fkt_dos_init();
    fkt_dos_sync_geom();
    if (row < 1)
        row = 1;
    if (row > g_dos_rows)
        row = g_dos_rows;
    y = row - 1;
    if (y < FKT_DOS_BANNER_ROWS) {
        fkt_dos_paint_banner();
        fkt_dos_set_cursor(FKT_DOS_BANNER_ROWS + 1, 1);
        return;
    }
    for (x = 0; x < g_dos_cols; x++)
        ScreenPutChar(' ', (int)g_dos_attr, x, y);
    fkt_dos_set_cursor(row, 1);
#elif FKT_PLATFORM_LINUX
    printf("\033[%d;1H\033[2K", row);
    fflush(stdout);
#endif
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
    fflush(stdout);
#endif
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
    fflush(stdout);
#endif
}

int fkt_screen_has_ansi(void) {
#if FKT_PLATFORM_DOS
    return 0;
#else
    return 1;
#endif
}
