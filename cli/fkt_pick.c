/* fkt_pick.c - directory browser (keyboard + mouse)
 *
 * Returns a path relative to the directory the user navigated into
 * (basename only). Caller loads with cwd already set to that folder.
 */
#if !(defined(FKT_DOS) && FKT_DOS)
#define _POSIX_C_SOURCE 200809L
#endif

#include "fkt_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/stat.h>

#if FKT_PLATFORM_DOS
#include <dir.h>
#include <dos.h>
#else
#include <dirent.h>
#endif

#define FKT_PICK_MAX     128
#define FKT_PICK_NAMELEN 80
#define FKT_PICK_PATHLEN 260

typedef struct {
    char name[FKT_PICK_NAMELEN];
    int  is_dir;
    int  is_psbt;
} fkt_pick_ent;

static fkt_pick_ent g_ents[FKT_PICK_MAX];
static int g_nent = 0;
static char g_cwd[FKT_PICK_PATHLEN];

static int pick_ci_endswith(const char *name, const char *ext) {
    size_t nlen;
    size_t elen;
    size_t i;

    if (!name || !ext || ext[0] == '\0')
        return 1;
    nlen = strlen(name);
    elen = strlen(ext);
    if (nlen < elen)
        return 0;
    for (i = 0; i < elen; i++) {
        if (tolower((unsigned char)name[nlen - elen + i]) !=
            tolower((unsigned char)ext[i]))
            return 0;
    }
    return 1;
}

static int pick_is_psbt_name(const char *name) {
    return pick_ci_endswith(name, ".psbt");
}

static int pick_cmp(const void *a, const void *b) {
    const fkt_pick_ent *ea = (const fkt_pick_ent *)a;
    const fkt_pick_ent *eb = (const fkt_pick_ent *)b;

    if (ea->is_dir != eb->is_dir)
        return eb->is_dir - ea->is_dir;
    if (!ea->is_dir && ea->is_psbt != eb->is_psbt)
        return eb->is_psbt - ea->is_psbt;
    return strcmp(ea->name, eb->name);
}

static int pick_add(const char *name, int is_dir) {
    size_t n;

    if (!name || name[0] == '\0' || g_nent >= FKT_PICK_MAX)
        return -1;
    if (name[0] == '.' && name[1] == '\0')
        return 0;
    n = strlen(name);
    if (n >= FKT_PICK_NAMELEN)
        n = FKT_PICK_NAMELEN - 1;
    memcpy(g_ents[g_nent].name, name, n);
    g_ents[g_nent].name[n] = '\0';
    g_ents[g_nent].is_dir = is_dir ? 1 : 0;
    g_ents[g_nent].is_psbt = (!is_dir && pick_is_psbt_name(name)) ? 1 : 0;
    g_nent++;
    return 0;
}

#if FKT_PLATFORM_DOS
static int pick_load_dir_dos(void) {
    struct ffblk ff;
    int done;
    int attr;

    g_nent = 0;
    if (getcwd(g_cwd, sizeof(g_cwd)) == NULL) {
        g_cwd[0] = '.';
        g_cwd[1] = '\0';
    }

    pick_add("..", 1);

    attr = FA_RDONLY | FA_ARCH | FA_DIREC | FA_HIDDEN | FA_SYSTEM;
    done = findfirst("*.*", &ff, attr);
    while (done == 0 && g_nent < FKT_PICK_MAX) {
        int is_dir = (ff.ff_attrib & FA_DIREC) ? 1 : 0;

        if (!(ff.ff_attrib & FA_LABEL)) {
            if (strcmp(ff.ff_name, ".") != 0)
                pick_add(ff.ff_name, is_dir);
        }
        done = findnext(&ff);
    }
    return 0;
}
#else
static int pick_load_dir_posix(void) {
    DIR *d;
    struct dirent *de;

    g_nent = 0;
    if (getcwd(g_cwd, sizeof(g_cwd)) == NULL) {
        g_cwd[0] = '.';
        g_cwd[1] = '\0';
    }

    pick_add("..", 1);

    d = opendir(".");
    if (!d)
        return -1;
    while ((de = readdir(d)) != NULL && g_nent < FKT_PICK_MAX) {
        struct stat st;
        int is_dir;

        if (de->d_name[0] == '.' && de->d_name[1] == '\0')
            continue;
        if (stat(de->d_name, &st) != 0)
            continue;
        is_dir = S_ISDIR(st.st_mode) ? 1 : 0;
        pick_add(de->d_name, is_dir);
    }
    closedir(d);
    return 0;
}
#endif

static int pick_load_dir(void) {
    int rc;
#if FKT_PLATFORM_DOS
    rc = pick_load_dir_dos();
#else
    rc = pick_load_dir_posix();
#endif
    if (g_nent > 1)
        qsort(g_ents + 1, (size_t)(g_nent - 1), sizeof(g_ents[0]), pick_cmp);
    return rc;
}

static void pick_drain_keys(void) {
    int n = 0;

    /* Flush any auto-repeat / double-buffered keys (DOSBox arrows). */
    while (fkt_tty_kbhit() && n < 8) {
        (void)fkt_tty_read_key();
        n++;
    }
}

static void pick_draw_line(int row, const char *text, int highlight) {
    char line[81];
    int i;
    int n;
    int w = 80;

    if (fkt_tty_cols() >= 40 && fkt_tty_cols() <= 80)
        w = fkt_tty_cols();

    for (i = 0; i < w; i++)
        line[i] = ' ';
    line[w] = '\0';

    n = (int)strlen(text);
    if (n > w - 2)
        n = w - 2;
    line[0] = highlight ? '>' : ' ';
    memcpy(line + 2, text, (size_t)n);

    fkt_screen_clear_line(row);
    fkt_screen_goto(row, 1);
    fwrite(line, 1, (size_t)w, stdout);
    fflush(stdout);
}

static void pick_draw(const char *title, int selected, int list_top,
                      int list_rows, int list_row0) {
    char hdr[100];
    char path_line[FKT_PICK_PATHLEN + 8];
    int i;
    int nfiles = 0;
    int ndirs = 0;
    int mouse_hint;

    fkt_mouse_hide();
    fkt_screen_clear();

    fkt_screen_goto(3, 2);
    fputs(title ? title : "BROWSE FILES", stdout);

    snprintf(path_line, sizeof(path_line), "Dir: %s", g_cwd);
    fkt_screen_clear_line(4);
    fkt_screen_goto(4, 2);
    fputs(path_line, stdout);

    for (i = 0; i < g_nent; i++) {
        if (g_ents[i].is_dir)
            ndirs++;
        else
            nfiles++;
    }
    snprintf(hdr, sizeof(hdr),
             "%d items  (%d dirs, %d files)", g_nent, ndirs, nfiles);
    fkt_screen_clear_line(5);
    fkt_screen_goto(5, 2);
    fputs(hdr, stdout);

    for (i = 0; i < list_rows; i++) {
        int idx = list_top + i;
        char label[FKT_PICK_NAMELEN + 12];
        int row = list_row0 + i;

        if (idx >= g_nent) {
            fkt_screen_clear_line(row);
            continue;
        }
        if (g_ents[idx].is_dir)
            snprintf(label, sizeof(label), "[DIR]  %s", g_ents[idx].name);
        else if (g_ents[idx].is_psbt)
            snprintf(label, sizeof(label), "[PSBT] %s", g_ents[idx].name);
        else
            snprintf(label, sizeof(label), "[FILE] %s", g_ents[idx].name);
        pick_draw_line(row, label, idx == selected);
    }

    mouse_hint = fkt_mouse_available();
    fkt_screen_clear_line(list_row0 + list_rows + 1);
    fkt_screen_goto(list_row0 + list_rows + 1, 2);
    if (mouse_hint)
        fputs("Up/Down Enter=open  click  T=type  M=more  Esc=menu", stdout);
    else
        fputs("Up/Down Enter=open  T=type path  M=more  Esc=menu", stdout);

    fkt_screen_recolor();
    fkt_screen_cursor_hide();
    if (mouse_hint)
        fkt_mouse_show();
}

/* Activate selection. Returns 1 if a file was chosen into out. */
static int pick_activate(int selected, char *out, size_t out_len,
                         const char *title, int *p_selected, int *p_list_top,
                         int list_rows, int list_row0) {
    fkt_pick_ent *e;

    if (selected < 0 || selected >= g_nent)
        return 0;
    e = &g_ents[selected];
    if (e->is_dir) {
        if (chdir(e->name) != 0)
            return 0;
        if (pick_load_dir() != 0)
            return 0;
        *p_selected = 0;
        *p_list_top = 0;
        pick_drain_keys();
        pick_draw(title, *p_selected, *p_list_top, list_rows, list_row0);
        return 0;
    }
    /* Basename only — cwd is already the folder containing the file.
     * Absolute join paths broke DOS load (mixed slashes / long paths). */
    if (strlen(e->name) + 1 > out_len)
        return 0;
    memcpy(out, e->name, strlen(e->name) + 1);
    return 1;
}

int fkt_pick_file(char *out, size_t out_len, const char *filter_ext,
                  const char *title) {
    int selected = 0;
    int list_top = 0;
    int list_rows;
    int list_row0 = 7;
    int rows;
    int done = 0;
    int accepted = 0;
    int mouse_on = 0;

    (void)filter_ext;

    if (!out || out_len < 2)
        return 0;

    fkt_tty_init();
    rows = fkt_tty_rows();
    list_rows = rows - list_row0 - 4;
    if (list_rows < 5)
        list_rows = 5;
    if (list_rows > 14)
        list_rows = 14;

    if (pick_load_dir() != 0) {
        fkt_screen_clear();
        fkt_screen_goto(4, 2);
        fputs("Cannot open directory.", stdout);
        fkt_screen_goto(6, 2);
        fputs("Press any key...", stdout);
        (void)fkt_tty_read_key_once();
        return 0;
    }

    if (fkt_mouse_available()) {
        fkt_mouse_show();
        mouse_on = 1;
    }

    pick_draw(title, selected, list_top, list_rows, list_row0);

    while (!done) {
        int ch = -1;
        int mrow = 0;
        int mcol = 0;

        if (fkt_tty_kbhit()) {
            ch = fkt_tty_read_key();
        } else if (mouse_on && fkt_mouse_click(&mrow, &mcol)) {
            int hit = mrow - list_row0;
            if (hit >= 0 && hit < list_rows) {
                int idx = list_top + hit;
                if (idx >= 0 && idx < g_nent) {
                    selected = idx;
                    /* Single click: open file or enter directory */
                    if (pick_activate(selected, out, out_len, title,
                                      &selected, &list_top,
                                      list_rows, list_row0)) {
                        accepted = 1;
                        done = 1;
                        break;
                    }
                    /* Directory entered — already redrawn */
                }
            }
            continue;
        } else if (mouse_on) {
#if FKT_PLATFORM_DOS
            {
                union REGS r;
                r.x.ax = 0x1680;
                int86(0x2F, &r, &r);
            }
#endif
            continue;
        } else {
            ch = fkt_tty_read_key();
        }

        if (ch < 0 || ch == FKT_KEY_SPECIAL)
            continue;

        if (ch == 27) {
            done = 1;
            accepted = 0;
            break;
        }

        if (ch == 't' || ch == 'T') {
            if (mouse_on)
                fkt_mouse_hide();
            fkt_screen_cursor_show();
            out[0] = '\0';
            return 2;
        }

        /* More options (type / camera chooser) without Esc trapping. */
        if (ch == 'm' || ch == 'M') {
            if (mouse_on)
                fkt_mouse_hide();
            fkt_screen_cursor_show();
            out[0] = '\0';
            return 3;
        }

        if (ch == FKT_KEY_UP) {
            if (selected > 0)
                selected--;
            if (selected < list_top)
                list_top = selected;
            pick_drain_keys();
            pick_draw(title, selected, list_top, list_rows, list_row0);
            continue;
        }
        if (ch == FKT_KEY_DOWN) {
            if (selected + 1 < g_nent)
                selected++;
            if (selected >= list_top + list_rows)
                list_top = selected - list_rows + 1;
            pick_drain_keys();
            pick_draw(title, selected, list_top, list_rows, list_row0);
            continue;
        }
        if (ch == FKT_KEY_PGUP) {
            selected -= list_rows;
            if (selected < 0)
                selected = 0;
            list_top = selected;
            pick_drain_keys();
            pick_draw(title, selected, list_top, list_rows, list_row0);
            continue;
        }
        if (ch == FKT_KEY_PGDN) {
            selected += list_rows;
            if (selected >= g_nent)
                selected = g_nent > 0 ? g_nent - 1 : 0;
            if (selected >= list_top + list_rows)
                list_top = selected - list_rows + 1;
            if (list_top < 0)
                list_top = 0;
            pick_drain_keys();
            pick_draw(title, selected, list_top, list_rows, list_row0);
            continue;
        }

        if (ch == '\r' || ch == '\n' || ch == ' ') {
            pick_drain_keys();
            if (pick_activate(selected, out, out_len, title,
                              &selected, &list_top, list_rows, list_row0)) {
                accepted = 1;
                done = 1;
                break;
            }
            continue;
        }
    }

    if (mouse_on)
        fkt_mouse_hide();
    fkt_screen_cursor_show();
    pick_drain_keys();
    return accepted ? 1 : 0;
}
