/* test_qr.c - QR-PR1/PR2 unit tests for fkt_qr encoder + ASCII renderer */
#include "../fkt_qr.h"
#include "../fkt_qr_vga.h"
#include "../fkt_memzero.h"
#include <stdio.h>
#include <string.h>

/* fkt_memzero.o references this from the SIGINT handler; stub for standalone test. */
void fkt_ui_term_restore(void) {}

static int failures = 0;

static void expect_int(const char *name, int got, int want) {
    if (got != want) {
        printf("FAIL %s: got %d want %d\n", name, got, want);
        failures++;
    } else {
        printf("PASS %s\n", name);
    }
}

static void expect_ok(const char *name, int rc) {
    if (rc != 0) {
        printf("FAIL %s: rc=%d\n", name, rc);
        failures++;
    } else {
        printf("PASS %s\n", name);
    }
}

static void expect_fail(const char *name, int rc) {
    if (rc == 0) {
        printf("FAIL %s: expected failure\n", name);
        failures++;
    } else {
        printf("PASS %s\n", name);
    }
}

static int count_dark_modules(void) {
    int n = fkt_qr_size();
    int x;
    int y;
    int count = 0;

    for (y = 0; y < n; y++) {
        for (x = 0; x < n; x++) {
            if (fkt_qr_get_module(x, y) == 1)
                count++;
        }
    }
    return count;
}

static int count_fp_lines(FILE *fp) {
    int lines = 0;
    int ch;

    rewind(fp);
    ch = fgetc(fp);
    while (ch != EOF) {
        if (ch == '\n')
            lines++;
        ch = fgetc(fp);
    }
    return lines;
}

static int load_file_bytes(const char *path, uint8_t *buf, size_t max_len, size_t *out_len) {
    FILE *f;
    long sz;

    f = fopen(path, "rb");
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    sz = ftell(f);
    if (sz < 0 || (size_t)sz > max_len) {
        fclose(f);
        return -1;
    }
    rewind(f);
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        return -1;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return 0;
}

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int psbt_to_base64(const uint8_t *data, size_t len, char *out, size_t out_max) {
    size_t i;
    size_t pos = 0;

    for (i = 0; i < len; i += 3) {
        uint32_t n;
        int pad = 0;

        if (pos + 4 >= out_max)
            return -1;
        n = ((uint32_t)data[i]) << 16;
        if (i + 1 < len)
            n |= ((uint32_t)data[i + 1]) << 8;
        else
            pad = 2;
        if (i + 2 < len)
            n |= (uint32_t)data[i + 2];
        else if (pad == 0)
            pad = 1;
        out[pos++] = b64_table[(n >> 18) & 63];
        out[pos++] = b64_table[(n >> 12) & 63];
        out[pos++] = (pad > 1) ? '=' : b64_table[(n >> 6) & 63];
        out[pos++] = (pad > 0) ? '=' : b64_table[n & 63];
    }
    if (pos >= out_max)
        return -1;
    out[pos] = '\0';
    return 0;
}

static int run_show_demo(int argc, char **argv) {
    const char *text;
    uint8_t raw[4096];
    char b64[FKT_QR_MAX_PAYLOAD + 1];
    size_t raw_len;
    int i;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s --show <text>\n", argv[0]);
        fprintf(stderr, "       %s --show --psbt <file.psbt>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[2], "--psbt") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Missing PSBT path.\n");
            return 1;
        }
        if (load_file_bytes(argv[3], raw, sizeof(raw), &raw_len) != 0) {
            fprintf(stderr, "Cannot read PSBT: %s\n", argv[3]);
            return 1;
        }
        if (psbt_to_base64(raw, raw_len, b64, sizeof(b64)) != 0) {
            fprintf(stderr, "Base64 conversion failed.\n");
            fkt_memzero(raw, sizeof(raw));
            return 1;
        }
        if (fkt_qr_encode_text(b64) != 0) {
            fprintf(stderr, "QR encode failed (len=%lu).\n", (unsigned long)strlen(b64));
            fkt_memzero(b64, sizeof(b64));
            fkt_memzero(raw, sizeof(raw));
            return 1;
        }
        printf("Payload: PSBT base64 (%lu bytes)\n\n", (unsigned long)strlen(b64));
        fkt_memzero(b64, sizeof(b64));
        fkt_memzero(raw, sizeof(raw));
    } else {
        text = argv[2];
        for (i = 3; i < argc; i++) {
            (void)text;
            /* allow multi-word only via quoting by shell; keep simple */
        }
        if (fkt_qr_encode_text(text) != 0) {
            fprintf(stderr, "QR encode failed.\n");
            return 1;
        }
        printf("Payload: \"%s\"\n\n", text);
    }

    if (fkt_qr_render_ascii(80, 24, 0) != 0) {
        fprintf(stderr, "QR render failed.\n");
        return 1;
    }
    fkt_qr_clear();
    return 0;
}

static void run_unit_tests(void) {
    int dark_hello;
    int dark_hello2;
    uint8_t raw[4096];
    char b64[FKT_QR_MAX_PAYLOAD + 1];
    size_t raw_len;
    int modules;
    int version;
    FILE *tmp;
    int lines;
    int total;
    int expect_body_lines;

    printf("=== fkt_qr tests (QR-PR1 + PR2 + VGA) ===\n");
    printf("  vga_available=%d\n", fkt_qr_vga_available());

    expect_fail("empty payload", fkt_qr_encode_text(""));
    expect_fail("null payload", fkt_qr_encode(NULL, 0));
    expect_fail("render without encode", fkt_qr_render_ascii_fp(stdout, 80, 24));

    expect_ok("HELLO encode", fkt_qr_encode_text("HELLO"));
    expect_int("HELLO version", fkt_qr_version(), 1);
    expect_int("HELLO modules", fkt_qr_size(), 21);
    expect_int("HELLO zoned quiet", fkt_qr_get_module_zoned(0, 0), 0);
    expect_int("HELLO zoned inner", fkt_qr_get_module_zoned(FKT_QR_QUIET_ZONE, FKT_QR_QUIET_ZONE),
                fkt_qr_get_module(0, 0));
    dark_hello = count_dark_modules();
    expect_int("HELLO dark>0", (dark_hello > 0) ? 1 : 0, 1);

    tmp = tmpfile();
    if (tmp == NULL) {
        printf("FAIL tmpfile for render\n");
        failures++;
    } else {
        expect_ok("HELLO render fp", fkt_qr_render_ascii_fp(tmp, 80, 24));
        lines = count_fp_lines(tmp);
        total = 21 + (FKT_QR_QUIET_ZONE * 2);
        expect_body_lines = (total + 1) / 2;
        expect_int("HELLO render ok", (lines >= 15 && lines <= 80) ? 1 : 0, 1);
        expect_int("HELLO render has body", (lines >= 10) ? 1 : 0, 1);
        (void)expect_body_lines;
        fclose(tmp);
    }

    expect_ok("HELLO re-encode", fkt_qr_encode_text("HELLO"));
    dark_hello2 = count_dark_modules();
    expect_int("HELLO deterministic", dark_hello, dark_hello2);

    fkt_qr_clear();
    expect_int("cleared version", fkt_qr_version(), 0);
    expect_int("cleared size", fkt_qr_size(), 0);
    expect_int("cleared module", fkt_qr_get_module(0, 0), -1);

    if (load_file_bytes("poppy", raw, sizeof(raw), &raw_len) == 0 ||
        load_file_bytes("../poppy", raw, sizeof(raw), &raw_len) == 0) {
        if (psbt_to_base64(raw, raw_len, b64, sizeof(b64)) == 0) {
            expect_ok("poppy b64 encode", fkt_qr_encode_text(b64));
            modules = fkt_qr_size();
            version = fkt_qr_version();
            printf("  poppy b64 len=%lu version=%d modules=%d\n",
                   (unsigned long)strlen(b64), version, modules);
            expect_int("poppy modules>=21", (modules >= 21) ? 1 : 0, 1);
            expect_int("poppy version>=1", (version >= 1) ? 1 : 0, 1);
            tmp = tmpfile();
            expect_ok("poppy pbm export", fkt_qr_export_pbm("/tmp/fkt_poppy_test.qr.pbm", 0));
            expect_int("poppy too large flag", fkt_qr_too_large_for_terminal(), 1);
            if (tmp != NULL) {
                expect_ok("poppy term skip msg", fkt_qr_render_ascii_fp(tmp, 115, 68));
                lines = count_fp_lines(tmp);
                expect_int("poppy no giant term dump", (lines < 50) ? 1 : 0, 1);
                fclose(tmp);
            }
            expect_ok("poppy display force_term", fkt_qr_display(80, 24, 0, 1));
        } else {
            printf("SKIP poppy b64 conversion\n");
        }
    } else {
        printf("SKIP poppy.psbt not found\n");
    }

    fkt_qr_clear();
    fkt_memzero(b64, sizeof(b64));
    fkt_memzero(raw, sizeof(raw));

    if (failures == 0)
        printf("All tests passed.\n");
    else
        printf("%d test(s) failed.\n", failures);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--show") == 0)
        return run_show_demo(argc, argv);
    run_unit_tests();
    return failures == 0 ? 0 : 1;
}