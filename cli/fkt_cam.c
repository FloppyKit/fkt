/* fkt_cam.c - optional camera capture with always-on graceful fallback (PR4)
 *
 * Vintage target: real 486 / FreeDOS / DOSBox — no standard camera API.
 * We probe a few historical hooks; if none work (the common case), callers
 * fall back to file browse or Base64 paste without growing the binary.
 */
#if !(defined(FKT_DOS) && FKT_DOS)
#define _POSIX_C_SOURCE 200809L
#endif

#include "fkt_cam.h"
#include "fkt_platform.h"

#include <stdio.h>
#include <string.h>

#if FKT_PLATFORM_DOS
#include <dos.h>
#endif

static char g_cam_reason[120];

static void cam_set_reason(const char *msg) {
    if (!msg) {
        g_cam_reason[0] = '\0';
        return;
    }
    strncpy(g_cam_reason, msg, sizeof(g_cam_reason) - 1);
    g_cam_reason[sizeof(g_cam_reason) - 1] = '\0';
}

const char *fkt_cam_unavailable_reason(void) {
    if (g_cam_reason[0] == '\0')
        return "Camera not available on this system.";
    return g_cam_reason;
}

int fkt_cam_available(void) {
#if FKT_PLATFORM_DOS
    /*
     * No portable INT for a USB/parallel camera on stock BIOS.
     * Future: optional vendor TSR could hook a magic multiplex.
     * Probe INT 2F for a reserved FKT id (none installed => absent).
     */
    (void)0; /* reserved: future INT 2F multiplex probe for a capture TSR */
    cam_set_reason(
        "No camera hardware / driver (use Browse or paste Base64).");
    return 0;
#else
    /* Linux host build: also no camera in offline signer path by design. */
    cam_set_reason(
        "Camera capture not built into this offline signer (use file/paste).");
    return 0;
#endif
}

int fkt_cam_capture_text(char *out, size_t out_len) {
    if (out && out_len > 0)
        out[0] = '\0';

    if (!fkt_cam_available())
        return -1;

    /* Reserved for a future capture backend. */
    cam_set_reason("Camera backend present but capture not implemented.");
    return -1;
}
