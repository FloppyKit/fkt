#ifndef FKT_PREVIEW_H
#define FKT_PREVIEW_H

/* Load + lenient-parse into static PSBT buffer (no screen output). */
int  fkt_psbt_preview_prepare(const char *psbt_path);
/* Draw preview from prepared psbt_data (caller may clear screen first). */
void fkt_psbt_preview_render(void);
/* CLI helper: prepare, clear screen, render. */
int  fkt_psbt_preview(const char *psbt_path);

#endif