/* fkt_cam.h - optional camera / QR capture (PR4)
 *
 * Real floppy-era PCs almost never expose a camera via a portable API.
 * This module always offers a graceful path: probe, then fall back to
 * file browse or Base64 paste. Keep the binary small.
 */
#ifndef FKT_CAM_H
#define FKT_CAM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 1 if a capture backend claims readiness (rare on DOS). */
int fkt_cam_available(void);

/* Human reason when unavailable (never NULL). */
const char *fkt_cam_unavailable_reason(void);

/*
 * Attempt to capture a QR payload into out (NUL-terminated text/base64).
 * Returns 0 on success, -1 if unavailable or capture failed.
 * On failure, reason is available via fkt_cam_unavailable_reason().
 */
int fkt_cam_capture_text(char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* FKT_CAM_H */
