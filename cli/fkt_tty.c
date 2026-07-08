/* fkt_tty.c - terminal size, raw mode, key input (Linux path; DOS in PR3) */
#define _POSIX_C_SOURCE 200809L

#include "fkt_platform.h"
#include <stdio.h>
#include <stdlib.h>

/* fkt_tty_restore uses fkt_screen_cursor_show (fkt_screen.c). */

#if FKT_PLATFORM_LINUX
#include <termios.h>
#include <unistd.h>
#endif

static int g_tty_cols = 80;
static int g_tty_rows = 24;
static int g_tty_raw = 0;

#if FKT_PLATFORM_LINUX
static struct termios g_tty_orig;
static int g_tty_orig_saved = 0;
#endif

int fkt_tty_init(void) {
    FILE *fp;

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
#endif
    g_tty_raw = 0;
    fkt_screen_cursor_show();
    fputs("\033[0m", stdout);
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

int fkt_tty_read_key(void) {
    return getchar();
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
#else
    ch = getchar();
#endif
    return ch;
}