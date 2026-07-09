/* fkt_qr_vga.c - Tier B VGA QR viewer (no heap, no temp file) */
#define _POSIX_C_SOURCE 200809L

#include "fkt_qr_vga.h"
#include "fkt_qr.h"
#include "fkt_platform.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

#if defined(FKT_QR_VGA_FB)
#define _DEFAULT_SOURCE
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/fb.h>
#endif

#if defined(__DJGPP__)
#include <conio.h>
#include <dos.h>
#include <dpmi.h>
#include <sys/farptr.h>
#include <go32.h>
#endif

#if defined(__WATCOMC__)
#include <bios.h>
#include <conio.h>
#include <dos.h>
#endif

#define FKT_VGA_W  320
#define FKT_VGA_H  200

#if defined(FKT_QR_VGA_FB)
static int g_fb_fd = -1;
static unsigned char *g_fb_map = NULL;
static size_t g_fb_map_len = 0;
static struct fb_var_screeninfo g_fb_var;
static struct fb_fix_screeninfo g_fb_fix;
#endif

#if defined(__DJGPP__) || defined(__WATCOMC__)
static int g_dos_vga_on = 0;
#endif

static char g_vga_reason[160];

static void fkt_vga_set_reason(const char *msg) {
    if (msg == NULL)
        g_vga_reason[0] = '\0';
    else
        snprintf(g_vga_reason, sizeof(g_vga_reason), "%s", msg);
}

static int fkt_vga_pick_scale(int total, int screen_w, int screen_h) {
    int sx;
    int sy;
    int scale;

    sx = screen_w / total;
    sy = screen_h / total;
    scale = sx;
    if (sy < scale)
        scale = sy;
    if (scale < 1)
        scale = 1;
    return scale;
}

static void fkt_vga_draw_modules(int screen_w, int screen_h,
                                 void (*set_px)(int x, int y, int dark)) {
    int modules;
    int total;
    int scale;
    int draw_w;
    int draw_h;
    int off_x;
    int off_y;
    int row;
    int col;
    int dy;
    int dx;
    int x0;
    int y0;
    int dark;

    modules = fkt_qr_size();
    total = modules + (FKT_QR_QUIET_ZONE * 2);
    scale = fkt_vga_pick_scale(total, screen_w, screen_h);
    draw_w = total * scale;
    draw_h = total * scale;
    off_x = (screen_w - draw_w) / 2;
    off_y = (screen_h - draw_h) / 2;
    if (off_x < 0)
        off_x = 0;
    if (off_y < 0)
        off_y = 0;

    for (row = 0; row < screen_h; row++) {
        for (col = 0; col < screen_w; col++)
            set_px(col, row, 0);
    }

    for (row = 0; row < total; row++) {
        for (col = 0; col < total; col++) {
            dark = fkt_qr_get_module_zoned(col, row);
            if (dark <= 0)
                continue;
            y0 = off_y + row * scale;
            x0 = off_x + col * scale;
            for (dy = 0; dy < scale; dy++) {
                for (dx = 0; dx < scale; dx++) {
                    if (x0 + dx < screen_w && y0 + dy < screen_h)
                        set_px(x0 + dx, y0 + dy, 1);
                }
            }
        }
    }
}

#if defined(FKT_QR_VGA_FB)
static void fkt_fb_set_px32(int x, int y, int dark) {
    unsigned char *p;
    unsigned int v;

    if (g_fb_map == NULL)
        return;
    if (x < 0 || y < 0)
        return;
    if ((unsigned)x >= g_fb_var.xres || (unsigned)y >= g_fb_var.yres)
        return;
    p = g_fb_map + (size_t)y * g_fb_fix.line_length + (size_t)x * 4;
    if (dark)
        v = 0x00000000;
    else
        v = 0x00FFFFFF;
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = 0;
}

static void fkt_fb_set_px16(int x, int y, int dark) {
    unsigned char *p;
    unsigned short v;

    if (g_fb_map == NULL)
        return;
    if (x < 0 || y < 0)
        return;
    if ((unsigned)x >= g_fb_var.xres || (unsigned)y >= g_fb_var.yres)
        return;
    p = g_fb_map + (size_t)y * g_fb_fix.line_length + (size_t)x * 2;
    if (dark)
        v = 0x0000;
    else
        v = 0xFFFF;
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
}

static void fkt_fb_set_px_wrap(int x, int y, int dark) {
    if (g_fb_var.bits_per_pixel == 16)
        fkt_fb_set_px16(x, y, dark);
    else if (g_fb_var.bits_per_pixel == 32)
        fkt_fb_set_px32(x, y, dark);
}

static int fkt_fb_begin(int *out_w, int *out_h) {
    long page_size;

    g_fb_fd = open("/dev/fb0", O_RDWR);
    if (g_fb_fd < 0)
        return -1;
    if (ioctl(g_fb_fd, FBIOGET_VSCREENINFO, &g_fb_var) != 0)
        goto fail;
    if (ioctl(g_fb_fd, FBIOGET_FSCREENINFO, &g_fb_fix) != 0)
        goto fail;
    if (g_fb_var.bits_per_pixel != 16 && g_fb_var.bits_per_pixel != 32)
        goto fail;
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        goto fail;
    g_fb_map_len = g_fb_fix.smem_len;
    g_fb_map = (unsigned char *)mmap(NULL, g_fb_map_len, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, g_fb_fd, 0);
    if (g_fb_map == MAP_FAILED) {
        g_fb_map = NULL;
        goto fail;
    }
    *out_w = (int)g_fb_var.xres;
    *out_h = (int)g_fb_var.yres;
    return 0;
fail:
    if (g_fb_map != NULL && g_fb_map != MAP_FAILED) {
        munmap(g_fb_map, g_fb_map_len);
        g_fb_map = NULL;
    }
    if (g_fb_fd >= 0) {
        close(g_fb_fd);
        g_fb_fd = -1;
    }
    return -1;
}

static void fkt_fb_end(void) {
    if (g_fb_map != NULL && g_fb_map != MAP_FAILED) {
        munmap(g_fb_map, g_fb_map_len);
        g_fb_map = NULL;
    }
    if (g_fb_fd >= 0) {
        close(g_fb_fd);
        g_fb_fd = -1;
    }
}
#endif

#if defined(__DJGPP__)
static void fkt_dos_set_px(int x, int y, int dark) {
    unsigned long addr;

    if (!g_dos_vga_on)
        return;
    if (x < 0 || y < 0 || x >= FKT_VGA_W || y >= FKT_VGA_H)
        return;
    /* Mode 13h framebuffer is physical A000:0000. Under DJGPP DPMI you must
     * poke via the DOS-memory selector — a flat 0xA0000000 write page-faults. */
    addr = 0xA0000UL + (unsigned long)y * 320UL + (unsigned long)x;
    _farpokeb(_dos_ds, addr, (unsigned char)(dark ? 0 : 15));
}

static int fkt_dos_vga_begin(void) {
    union REGS regs;

    regs.x.ax = 0x0013;
    int86(0x10, &regs, &regs);
    g_dos_vga_on = 1;
    return 0;
}

static void fkt_dos_vga_end(void) {
    union REGS regs;

    if (!g_dos_vga_on)
        return;
    regs.x.ax = 0x0003;
    int86(0x10, &regs, &regs);
    g_dos_vga_on = 0;
}
#elif defined(__WATCOMC__)
static void fkt_dos_set_px(int x, int y, int dark) {
    unsigned char far *fb;
    int offset;

    if (!g_dos_vga_on)
        return;
    if (x < 0 || y < 0 || x >= FKT_VGA_W || y >= FKT_VGA_H)
        return;
    fb = (unsigned char far *)MK_FP(0xA000, 0);
    offset = y * 320 + x;
    fb[offset] = (unsigned char)(dark ? 0 : 15);
}

static int fkt_dos_vga_begin(void) {
    union REGS regs;

    regs.w.ax = 0x0013;
    int86(0x10, &regs, &regs);
    g_dos_vga_on = 1;
    return 0;
}

static void fkt_dos_vga_end(void) {
    union REGS regs;

    if (!g_dos_vga_on)
        return;
    regs.w.ax = 0x0003;
    int86(0x10, &regs, &regs);
    g_dos_vga_on = 0;
}
#endif

const char *fkt_qr_vga_unavailable_reason(void) {
    return g_vga_reason;
}

int fkt_qr_vga_available(void) {
#if defined(__DJGPP__) || defined(__WATCOMC__)
    fkt_vga_set_reason(NULL);
    return 1;
#elif defined(FKT_QR_VGA_FB)
    {
        int fd;

        fkt_vga_set_reason(NULL);
        fd = open("/dev/fb0", O_RDWR);
        if (fd < 0) {
            if (errno == EACCES || errno == EPERM)
                fkt_vga_set_reason("permission denied on /dev/fb0 (need video group)");
            else
                snprintf(g_vga_reason, sizeof(g_vga_reason),
                         "cannot open /dev/fb0: %s", strerror(errno));
            return 0;
        }
        close(fd);
        return 1;
    }
#else
    fkt_vga_set_reason("VGA backend not compiled in");
    return 0;
#endif
}

int fkt_qr_vga_show(void) {
    int w;
    int h;

#if defined(__DJGPP__) || defined(__WATCOMC__)
    if (fkt_dos_vga_begin() != 0)
        return -1;
    w = FKT_VGA_W;
    h = FKT_VGA_H;
    fkt_vga_draw_modules(w, h, fkt_dos_set_px);
    return 0;
#elif defined(FKT_QR_VGA_FB)
    if (fkt_fb_begin(&w, &h) != 0)
        return -1;
    fkt_vga_draw_modules(w, h, fkt_fb_set_px_wrap);
    return 0;
#else
    (void)w;
    (void)h;
    return -1;
#endif
}

void fkt_qr_vga_wait_key(void) {
#if defined(__DJGPP__) || defined(__WATCOMC__)
    (void)getch();
    fkt_dos_vga_end();
    /* Restore 80x25 green chrome (mode 03 alone leaves a blank white screen). */
    fkt_screen_after_graphics();
#elif defined(FKT_QR_VGA_FB)
    printf("  -- Press Enter to continue --");
    fflush(stdout);
    (void)getchar();
    fkt_fb_end();
#else
    (void)getchar();
#endif
}