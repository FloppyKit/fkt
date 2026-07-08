/* fkt_qr.h - FKT QR encoder facade (static buffers, no heap) */
#ifndef FKT_QR_H
#define FKT_QR_H

#include "fkt_compat.h"
#include <stddef.h>
#include <stdio.h>

/* Max input bytes (Base64 PSBT etc.). Spec warns user above ~1 KB. */
#define FKT_QR_MAX_PAYLOAD   2048

/* Nayuki buffer size for QR versions 1..30 (covers FKT_QR_MAX_PAYLOAD at ECC-M). */
#define FKT_QR_MAX_VERSION   30
#define FKT_QR_BUFFER_LEN    2347

/* White border in modules (QR spec minimum 4). */
#define FKT_QR_QUIET_ZONE    4

/* Max rendered line width: modules + 2*quiet zone (version 30 = 177+8). */
#define FKT_QR_RENDER_MAX_W  185

/* Above this module count, terminal QR is not offered; use VGA/PBM. */
#define FKT_QR_TERM_MAX_MODULES       45
/* 24-word BIP39 mnemonic fits at QR v8 (49 modules); allow terminal scan. */
#define FKT_QR_TERM_MAX_SEED_MODULES  53

/* Default pixels per module in PBM export (square, scannable). */
#define FKT_QR_PBM_SCALE_DEFAULT 8

#ifdef __cplusplus
extern "C" {
#endif

/* Encode NUL-terminated text (byte mode). Returns 0 on success, -1 on failure. */
int fkt_qr_encode_text(const char *text);

/* Encode raw bytes (byte mode). Returns 0 on success, -1 on failure. */
int fkt_qr_encode(const uint8_t *data, size_t len);

/* QR version (1..40) after successful encode; 0 if none. */
int fkt_qr_version(void);

/* Module width in modules (21..177); 0 if none. */
int fkt_qr_size(void);

/* Module at (x,y): 1 dark, 0 light; -1 if no QR or out of range. */
int fkt_qr_get_module(int x, int y);

/* Pixel in quiet-zone grid: 1 dark, 0 light; -1 if no QR encoded. */
int fkt_qr_get_module_zoned(int col, int row);

/* Zero QR work buffers (call from cleanup path). */
void fkt_qr_clear(void);

/*
 * Dense terminal render of the last successful encode.
 * Full-block 1:1 (same style as scannable HELLO); optional lossless NxN upscale to fit.
 * FKT_ASCII_ONLY uses #/space. interactive: pause before return.
 * Returns 0 on success, -1 if no QR ready.
 */
int fkt_qr_render_ascii(int term_cols, int term_rows, int interactive);

/* Same as above but writes to fp (for tests); does not read stdin. */
int fkt_qr_render_ascii_fp(FILE *fp, int term_cols, int term_rows);

/* 1 if last encode exceeds FKT_QR_TERM_MAX_MODULES (use VGA or PBM). */
int fkt_qr_too_large_for_terminal(void);

/* 1 if last encode exceeds term_max_modules. */
int fkt_qr_too_large_for_terminal_ex(int term_max_modules);

/*
 * Show last encode: Tier B VGA when backend available (486/DOS primary path);
 * Tier A terminal ASCII as fallback (dev laptop, --term, or VGA failure).
 * term_max_modules caps terminal fallback size (seed vs PSBT limits).
 * Returns 0 on success, -1 if no QR ready.
 */
int fkt_qr_display_ex(int term_cols, int term_rows, int interactive, int force_term,
                      int term_max_modules);
int fkt_qr_display(int term_cols, int term_rows, int interactive, int force_term);

/* Write square PBM (P5) bitmap; pixel_scale modules->pixels (0 = default 8). */
int fkt_qr_export_pbm(const char *path, int pixel_scale);

#ifdef __cplusplus
}
#endif

#endif