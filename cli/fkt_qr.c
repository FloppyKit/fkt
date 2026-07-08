/* fkt_qr.c - FKT QR facade over vendored Nayuki encoder (fkt_qrgen.c) */
#include "fkt_qr.h"
#include "fkt_qr_vga.h"
#include "fkt_qrgen_wrap.h"
#include "fkt_memzero.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint8_t g_fkt_qr_temp[FKT_QR_BUFFER_LEN];
static uint8_t g_fkt_qr_code[FKT_QR_BUFFER_LEN];
static int g_fkt_qr_ready = 0;
static int g_fkt_qr_version = 0;
static int g_fkt_qr_modules = 0;

static int fkt_qr_module_with_zone(int col, int row, int modules, int total);

#define FKT_QR_UPSCALE_MAX  4

#if defined(FKT_ASCII_ONLY)
#define FKT_QR_CH_DARK  "#"
#define FKT_QR_USE_ANSI  0
#else
#define FKT_QR_CH_DARK  "\xe2\x96\x88"
#define FKT_QR_USE_ANSI  1
#endif

void fkt_qr_clear(void) {
    fkt_memzero(g_fkt_qr_temp, sizeof(g_fkt_qr_temp));
    fkt_memzero(g_fkt_qr_code, sizeof(g_fkt_qr_code));
    g_fkt_qr_ready = 0;
    g_fkt_qr_version = 0;
    g_fkt_qr_modules = 0;
}

int fkt_qr_version(void) {
    if (!g_fkt_qr_ready)
        return 0;
    return g_fkt_qr_version;
}

int fkt_qr_size(void) {
    if (!g_fkt_qr_ready)
        return 0;
    return g_fkt_qr_modules;
}

int fkt_qr_get_module(int x, int y) {
    if (!g_fkt_qr_ready)
        return -1;
    if (x < 0 || y < 0 || x >= g_fkt_qr_modules || y >= g_fkt_qr_modules)
        return -1;
    if (fkt_qrgen_get_module(g_fkt_qr_code, x, y))
        return 1;
    return 0;
}

int fkt_qr_get_module_zoned(int col, int row) {
    int modules;
    int total;

    if (!g_fkt_qr_ready)
        return -1;
    modules = g_fkt_qr_modules;
    total = modules + (FKT_QR_QUIET_ZONE * 2);
    return fkt_qr_module_with_zone(col, row, modules, total);
}

int fkt_qr_too_large_for_terminal_ex(int term_max_modules) {
    if (!g_fkt_qr_ready)
        return 0;
    return g_fkt_qr_modules > term_max_modules ? 1 : 0;
}

int fkt_qr_too_large_for_terminal(void) {
    return fkt_qr_too_large_for_terminal_ex(FKT_QR_TERM_MAX_MODULES);
}

static int fkt_qr_module_with_zone(int col, int row, int modules, int total) {
    int q;

    if (col < 0 || row < 0 || col >= total || row >= total)
        return 0;
    q = FKT_QR_QUIET_ZONE;
    if (col < q || row < q || col >= q + modules || row >= q + modules)
        return 0;
    if (fkt_qr_get_module(col - q, row - q) == 1)
        return 1;
    return 0;
}

static void fkt_qr_emit_dark(FILE *fp, int dark) {
    if (dark)
        fputs(FKT_QR_CH_DARK, fp);
    else
        fputc(' ', fp);
}

#if FKT_QR_USE_ANSI
static void fkt_qr_emit_ansi(FILE *fp, int dark) {
    if (dark)
        fputs("\033[40m  \033[0m", fp);
    else
        fputs("\033[47m  \033[0m", fp);
}
#endif

static int fkt_qr_pick_upscale(int total, int max_w, int max_h, int cell_w) {
    int s;
    int best;

    best = 1;
    for (s = 1; s <= FKT_QR_UPSCALE_MAX; s++) {
        if (total * cell_w * s <= max_w && total * s <= max_h)
            best = s;
    }
    return best;
}

static int fkt_qr_render_blocks(FILE *fp, int term_cols, int modules, int total,
                                int upscale, int cell_w, int body_rows) {
    int line_w;
    int line_h;
    int pad;
    int vpad;
    int row;
    int col;
    int srow;
    int scol;
    int c;

    line_w = total * cell_w * upscale;
    line_h = total * upscale;
    pad = (term_cols - line_w) / 2;
    if (pad < 0)
        pad = 0;

    vpad = 0;
    if (line_h < body_rows)
        vpad = (body_rows - line_h) / 2;

    for (row = 0; row < vpad; row++)
        fputc('\n', fp);

    for (row = 0; row < total; row++) {
        for (srow = 0; srow < upscale; srow++) {
            for (col = 0; col < pad; col++)
                fputc(' ', fp);
            for (col = 0; col < total; col++) {
                int dark;

                dark = fkt_qr_module_with_zone(col, row, modules, total);
                for (scol = 0; scol < upscale; scol++) {
#if FKT_QR_USE_ANSI
                    if (cell_w == 2) {
                        fkt_qr_emit_ansi(fp, dark);
                        continue;
                    }
#endif
                    for (c = 0; c < cell_w; c++)
                        fkt_qr_emit_dark(fp, dark);
                }
            }
            fputc('\n', fp);
        }
    }
    return 0;
}

int fkt_qr_export_pbm(const char *path, int pixel_scale) {
    FILE *fp;
    int modules;
    int total;
    int width;
    int height;
    int py;
    int px;
    int row;
    int col;

    if (!g_fkt_qr_ready || path == NULL)
        return -1;
    if (pixel_scale < 1)
        pixel_scale = FKT_QR_PBM_SCALE_DEFAULT;
    if (pixel_scale > 32)
        pixel_scale = 32;

    modules = g_fkt_qr_modules;
    total = modules + (FKT_QR_QUIET_ZONE * 2);
    width = total * pixel_scale;
    height = total * pixel_scale;

    fp = fopen(path, "wb");
    if (fp == NULL)
        return -1;

    fprintf(fp, "P5\n%d %d\n255\n", width, height);
    for (py = 0; py < height; py++) {
        row = py / pixel_scale;
        for (px = 0; px < width; px++) {
            col = px / pixel_scale;
            if (fkt_qr_module_with_zone(col, row, modules, total))
                fputc(0, fp);
            else
                fputc(255, fp);
        }
    }
    fclose(fp);
    return 0;
}

static void fkt_qr_wait_enter(void) {
    printf("  -- Press Enter to continue --");
    fflush(stdout);
    (void)getchar();
}

static int fkt_qr_render_body(FILE *fp, int term_cols, int term_rows, int term_max) {
    int modules;
    int total;
    int header_rows;
    int body_rows;
    int max_w;
    int cell_w;
    int upscale;
    int line_w;
    int line_h;

    modules = g_fkt_qr_modules;
    total = modules + (FKT_QR_QUIET_ZONE * 2);

    if (modules > term_max) {
        fprintf(fp, "  QR version %d  |  %dx%d modules  |  +%d quiet zone\n",
                g_fkt_qr_version, modules, modules, FKT_QR_QUIET_ZONE);
        fprintf(fp, "  Too large for terminal scanning (>%d modules).\n",
                term_max);
        fprintf(fp, "  VGA unavailable — see hints above, or: qr --pbm out.pbm / --base64\n");
        return 0;
    }

    header_rows = 6;
    body_rows = term_rows - header_rows;
    if (body_rows < 8)
        body_rows = 8;
    max_w = term_cols - 2;
    if (max_w < 20)
        max_w = 78;

    cell_w = 1;
#if FKT_QR_USE_ANSI
    if (total * 2 <= max_w)
        cell_w = 2;
#endif

    upscale = fkt_qr_pick_upscale(total, max_w, body_rows, cell_w);
    line_w = total * cell_w * upscale;
    line_h = total * upscale;

    fprintf(fp, "  QR version %d  |  %dx%d modules  |  +%d quiet zone\n",
            g_fkt_qr_version, modules, modules, FKT_QR_QUIET_ZONE);
    fprintf(fp, "  Terminal %dx%d  |  display %dx%d", term_cols, term_rows, line_w, line_h);
    if (cell_w == 2)
        fprintf(fp, "  |  ansi square");
    else
        fprintf(fp, "  |  full block");
    if (upscale > 1)
        fprintf(fp, " %dx", upscale);
    fputc('\n', fp);
    if (line_h > body_rows)
        fprintf(fp, "  Scroll to see all %d rows, or shrink font until the full QR fits.\n", line_h);
    fprintf(fp, "  Tip: enlarge font (Ctrl++) until the QR fills the screen.\n");
    fprintf(fp, "\n");

    fkt_qr_render_blocks(fp, term_cols, modules, total, upscale, cell_w, body_rows);
    return 0;
}

int fkt_qr_render_ascii_fp(FILE *fp, int term_cols, int term_rows) {
    if (!g_fkt_qr_ready || fp == NULL)
        return -1;
    if (term_cols < 20)
        term_cols = 80;
    if (term_rows < 8)
        term_rows = 24;
    return fkt_qr_render_body(fp, term_cols, term_rows, FKT_QR_TERM_MAX_MODULES);
}

static int fkt_qr_render_ascii_ex(int term_cols, int term_rows, int interactive,
                                  int term_max) {
    if (!g_fkt_qr_ready)
        return -1;
    if (term_cols < 20)
        term_cols = 80;
    if (term_rows < 8)
        term_rows = 24;

    if (fkt_qr_render_body(stdout, term_cols, term_rows, term_max) != 0)
        return -1;

    if (interactive) {
        printf("\n");
        fkt_qr_wait_enter();
    }
    return 0;
}

int fkt_qr_render_ascii(int term_cols, int term_rows, int interactive) {
    return fkt_qr_render_ascii_ex(term_cols, term_rows, interactive,
                                  FKT_QR_TERM_MAX_MODULES);
}

int fkt_qr_display_ex(int term_cols, int term_rows, int interactive, int force_term,
                      int term_max_modules) {
    int modules;
    int total;

    if (!g_fkt_qr_ready)
        return -1;

    modules = g_fkt_qr_modules;
    total = modules + (FKT_QR_QUIET_ZONE * 2);

    /* Tier B first on 486/DOS (and Linux when /dev/fb0 works). Tier A is fallback. */
    if (!force_term && fkt_qr_vga_available()) {
#if !defined(__DJGPP__) && !defined(__WATCOMC__)
        printf("  QR version %d  |  %dx%d modules  |  +%d quiet zone\n",
               g_fkt_qr_version, modules, modules, FKT_QR_QUIET_ZONE);
        printf("  VGA %dx%d square modules (quiet zone included)\n\n", total, total);
#endif
        if (fkt_qr_vga_show() == 0) {
            fkt_qr_vga_wait_key();
            return 0;
        }
#if !defined(__DJGPP__) && !defined(__WATCOMC__)
        printf("  VGA display failed — falling back to terminal.\n\n");
#endif
    }

    if (!fkt_qr_too_large_for_terminal_ex(term_max_modules) || force_term)
        return fkt_qr_render_ascii_ex(term_cols, term_rows, interactive, term_max_modules);

    {
        const char *why;

        why = fkt_qr_vga_unavailable_reason();
        if (why != NULL && why[0] != '\0')
            printf("  VGA unavailable: %s\n", why);
        if (why != NULL && strstr(why, "permission") != NULL) {
            printf("  Fix: sudo usermod -aG video $USER  (then log out and back in)\n");
            printf("  Quick test without re-login: sg video -c './fkt qr --psbt poppy'\n");
        }
        printf("  VGA only works on the machine's physical display (Linux TTY), not SSH.\n");
        printf("  Dev fallback: ./fkt qr --psbt poppy --pbm poppy.qr.pbm\n\n");
    }

    return fkt_qr_render_ascii_ex(term_cols, term_rows, interactive, term_max_modules);
}

int fkt_qr_display(int term_cols, int term_rows, int interactive, int force_term) {
    return fkt_qr_display_ex(term_cols, term_rows, interactive, force_term,
                             FKT_QR_TERM_MAX_MODULES);
}

int fkt_qr_encode(const uint8_t *data, size_t len) {
    int ok;
    int size;
    int version;

    fkt_qr_clear();
    if (data == NULL || len == 0 || len > FKT_QR_MAX_PAYLOAD)
        return -1;

    memcpy(g_fkt_qr_temp, data, len);

    ok = fkt_qrgen_encode_binary(g_fkt_qr_temp, len, g_fkt_qr_code, FKT_QR_MAX_VERSION);
    if (ok != 0)
        return -1;

    size = fkt_qrgen_get_size(g_fkt_qr_code);
    if (size <= 0)
        return -1;

    version = (size - 17) / 4;
    if (version < 1 || version > 40)
        return -1;

    g_fkt_qr_ready = 1;
    g_fkt_qr_version = version;
    g_fkt_qr_modules = size;
    return 0;
}

int fkt_qr_encode_text(const char *text) {
    size_t len;

    if (text == NULL)
        return -1;
    len = strlen(text);
    if (len == 0 || len > FKT_QR_MAX_PAYLOAD)
        return -1;
    return fkt_qr_encode((const uint8_t *)text, len);
}