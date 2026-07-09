/* fkt_tty.c - terminal size, raw mode, key + mouse input (PR2) */
#if !(defined(FKT_DOS) && FKT_DOS)
#define _POSIX_C_SOURCE 200809L
#endif

#include "fkt_platform.h"
#include <stdio.h>
#include <stdlib.h>

#if FKT_PLATFORM_LINUX
#include <termios.h>
#include <unistd.h>
#include <sys/select.h>
#endif

#if FKT_PLATFORM_DOS
#include <conio.h>
#include <dos.h>
#endif

static int g_tty_cols = 80;
static int g_tty_rows = 24;
static int g_tty_raw = 0;

#if FKT_PLATFORM_LINUX
static struct termios g_tty_orig;
static int g_tty_orig_saved = 0;
#endif

#if FKT_PLATFORM_DOS
static int g_mouse_ok = -1; /* -1 unknown, 0 no, 1 yes */
static int g_mouse_shown = 0;

static void fkt_dos_query_screen(void) {
    union REGS regs;

    regs.x.ax = 0x0F00;
    int86(0x10, &regs, &regs);
    g_tty_cols = (int)regs.h.al;
    if (g_tty_cols < 40)
        g_tty_cols = 80;
    g_tty_rows = 25;
}

static int fkt_dos_map_scan(int scan) {
    switch (scan) {
    case 0x48: return FKT_KEY_UP;
    case 0x50: return FKT_KEY_DOWN;
    case 0x4B: return FKT_KEY_LEFT;
    case 0x4D: return FKT_KEY_RIGHT;
    case 0x49: return FKT_KEY_PGUP;
    case 0x51: return FKT_KEY_PGDN;
    case 0x47: return FKT_KEY_HOME;
    case 0x4F: return FKT_KEY_END;
    default:   return FKT_KEY_SPECIAL;
    }
}

static int fkt_dos_read_key(void) {
    int ch;

    ch = getch();
    if (ch == 0 || ch == 0xE0) {
        ch = getch();
        return fkt_dos_map_scan(ch & 0xFF);
    }
    return ch;
}

static int fkt_dos_mouse_reset(void) {
    union REGS regs;

    regs.x.ax = 0x0000;
    int86(0x33, &regs, &regs);
    if (regs.x.ax == 0)
        return 0;
    return 1;
}
#endif

int fkt_tty_init(void) {
#if FKT_PLATFORM_LINUX
    FILE *fp;
#endif

    g_tty_cols = 80;
    g_tty_rows = 24;

#if FKT_PLATFORM_LINUX
    fp = popen("tput cols 2>/dev/null", "r");
    if (fp) {
        if (fscanf(fp, "%d", &g_tty_cols) != 1)
            g_tty_cols = 80;
        pclose(fp);
    }
    fp = popen("tput lines 2>/dev/null", "r");
    if (fp) {
        if (fscanf(fp, "%d", &g_tty_rows) != 1)
            g_tty_rows = 24;
        pclose(fp);
    }
    if (!g_tty_orig_saved && tcgetattr(STDIN_FILENO, &g_tty_orig) == 0) {
        g_tty_orig_saved = 1;
        atexit(fkt_tty_restore);
    }
#elif FKT_PLATFORM_DOS
    fkt_dos_query_screen();
    g_mouse_ok = fkt_dos_mouse_reset();
#endif

    if (g_tty_cols < 40)
        g_tty_cols = 80;
    if (g_tty_rows < 12)
        g_tty_rows = 24;
    return 0;
}

void fkt_tty_restore(void) {
#if FKT_PLATFORM_LINUX
    if (g_tty_orig_saved)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_tty_orig);
    fputs("\033[0m", stdout);
#endif
#if FKT_PLATFORM_DOS
    fkt_mouse_hide();
#endif
    g_tty_raw = 0;
    fkt_screen_cursor_show();
    fflush(stdout);
}

int fkt_tty_cols(void) {
    return g_tty_cols;
}

int fkt_tty_rows(void) {
    return g_tty_rows;
}

int fkt_tty_is_interactive(void) {
#if FKT_PLATFORM_LINUX
    return isatty(STDIN_FILENO) ? 1 : 0;
#else
    return 1;
#endif
}

int fkt_tty_raw_begin(void) {
#if FKT_PLATFORM_LINUX
    struct termios t;

    if (!g_tty_orig_saved)
        return -1;
    t = g_tty_orig;
    t.c_lflag &= (tcflag_t)~(ICANON | ECHO);
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) != 0)
        return -1;
#endif
    g_tty_raw = 1;
    return 0;
}

int fkt_tty_raw_end(void) {
    if (!g_tty_raw)
        return 0;
    fkt_tty_restore();
    return 0;
}

int fkt_tty_kbhit(void) {
#if FKT_PLATFORM_DOS
    return kbhit() ? 1 : 0;
#elif FKT_PLATFORM_LINUX
    {
        fd_set fds;
        struct timeval tv;

        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        return select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0 ? 1 : 0;
    }
#else
    return 0;
#endif
}

int fkt_tty_read_key(void) {
#if FKT_PLATFORM_DOS
    return fkt_dos_read_key();
#else
    return getchar();
#endif
}

int fkt_tty_read_key_once(void) {
    int ch;

#if FKT_PLATFORM_LINUX
    struct termios saved;
    struct termios raw;

    if (tcgetattr(STDIN_FILENO, &saved) != 0)
        return -1;
    raw = saved;
    raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved);
#elif FKT_PLATFORM_DOS
    ch = fkt_dos_read_key();
#else
    ch = getchar();
#endif
    return ch;
}

int fkt_mouse_available(void) {
#if FKT_PLATFORM_DOS
    if (g_mouse_ok < 0)
        g_mouse_ok = fkt_dos_mouse_reset();
    return g_mouse_ok ? 1 : 0;
#else
    return 0;
#endif
}

void fkt_mouse_show(void) {
#if FKT_PLATFORM_DOS
    union REGS regs;

    if (!fkt_mouse_available())
        return;
    /* Re-arm driver each time (after load/hide, DOSBox often stops reporting). */
    if (!g_mouse_shown) {
        regs.x.ax = 0x0000;
        int86(0x33, &regs, &regs);
        if (regs.x.ax == 0) {
            g_mouse_ok = 0;
            return;
        }
        g_mouse_ok = 1;
    }
    regs.x.ax = 0x0001;
    int86(0x33, &regs, &regs);
    g_mouse_shown = 1;
#endif
}

void fkt_mouse_hide(void) {
#if FKT_PLATFORM_DOS
    union REGS regs;

    if (!g_mouse_shown)
        return;
    regs.x.ax = 0x0002;
    int86(0x33, &regs, &regs);
    g_mouse_shown = 0;
#endif
}

int fkt_mouse_click(int *row, int *col) {
#if FKT_PLATFORM_DOS
    union REGS regs;
    int count;
    int mx;
    int my;

    if (!fkt_mouse_available())
        return 0;

    /* AX=5: button press info — more reliable than level-trigger AX=3 */
    regs.x.ax = 0x0005;
    regs.x.bx = 0; /* left button */
    int86(0x33, &regs, &regs);
    count = (int)regs.x.bx;
    mx = (int)regs.x.cx;
    my = (int)regs.x.dx;

    if (count <= 0)
        return 0;

    /* Text cell = pixel / 8 (standard VGA text). 1-based for FKT screen API. */
    if (col)
        *col = (mx / 8) + 1;
    if (row)
        *row = (my / 8) + 1;
    return 1;
#else
    (void)row;
    (void)col;
    return 0;
#endif
}
