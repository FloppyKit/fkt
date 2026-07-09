/* fkt_qr_vga.h - Tier B: square VGA framebuffer QR (DOS mode 13h / Linux fb) */
#ifndef FKT_QR_VGA_H
#define FKT_QR_VGA_H

#ifdef __cplusplus
extern "C" {
#endif

/* 1 if this build has a VGA backend compiled in. */
int fkt_qr_vga_available(void);

/* Human-readable reason when fkt_qr_vga_available() is 0 (empty if available). */
const char *fkt_qr_vga_unavailable_reason(void);

/*
 * Draw encoded QR to VGA (square modules, no temp file). Returns 0 on success.
 * On failure caller should use Tier A terminal or base64 export.
 */
int fkt_qr_vga_show(void);

/* Block until user acknowledges (any key / Enter). Restores text mode on DOS. */
void fkt_qr_vga_wait_key(void);

#ifdef __cplusplus
}
#endif

#endif