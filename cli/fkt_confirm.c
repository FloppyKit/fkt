/* fkt_confirm.c - PSBT fingerprint and post-sign confirmation gates (PR5) */
#define _POSIX_C_SOURCE 200809L

#include "fkt_confirm.h"
#include "fkt_psbt.h"
#include "fkt_error.h"
#include "fkt_sha256.h"
#include "fkt_memzero.h"
#include "fkt_ui.h"
#include "fkt_platform.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_confirm_enabled = 1;
static int g_confirm_ui_mode = 0;
static int g_fingerprint_captured = 0;
static uint8_t g_captured_fingerprint[32];

void fkt_confirm_set_enabled(int on) {
    g_confirm_enabled = on ? 1 : 0;
}

void fkt_confirm_set_ui_mode(int on) {
    g_confirm_ui_mode = on ? 1 : 0;
}

int fkt_confirm_active(void) {
    if (!g_confirm_enabled)
        return 0;
#if FKT_BUILD_DEV_HARNESS
    if (getenv("FKT_NO_CONFIRM") != NULL)
        return 0;
#endif
    if (!fkt_tty_is_interactive())
        return 0;
    return 1;
}

void fkt_confirm_fingerprint_capture(void) {
    if (!fkt_confirm_active())
        return;
    memcpy(g_captured_fingerprint, psbt_data.psbt_fingerprint, 32);
    g_fingerprint_captured = 1;
}

void fkt_confirm_fingerprint_clear(void) {
    fkt_memzero(g_captured_fingerprint, sizeof(g_captured_fingerprint));
    g_fingerprint_captured = 0;
}

int fkt_confirm_fingerprint_verify(void) {
    uint8_t hash[32];

    if (!fkt_confirm_active())
        return 0;
    if (!g_fingerprint_captured) {
        fkt_last_error_set("PSBT fingerprint not confirmed.");
        return -1;
    }
    fkt_sha256(psbt_buffer, psbt_size, hash);
    if (memcmp(hash, g_captured_fingerprint, 32) != 0) {
        fkt_last_error_set("PSBT buffer integrity check failed");
        return -1;
    }
    return 0;
}

static void confirm_print_hex(const uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

static void confirm_print_txid_reversed(const uint8_t txid[32]) {
    int i;
    for (i = 31; i >= 0; i--)
        printf("%02x", txid[i]);
}

static const char *confirm_output_label(const uint8_t *spk, size_t len) {
    if (len == 22 && spk[0] == 0x00 && spk[1] == 0x14) return "P2WPKH";
    if (len == 34 && spk[0] == 0x51 && spk[1] == 0x20) return "P2TR";
    if (len == 23 && spk[0] == 0xa9 && spk[1] == 0x14) return "P2SH";
    if (len == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14) return "P2PKH";
    if (len == 34 && spk[0] == 0x00 && spk[1] == 0x20) return "P2WSH";
    return "Unknown";
}

static void confirm_print_output_program(const uint8_t *spk, size_t len) {
    if (len == 22 && spk[0] == 0x00 && spk[1] == 0x14) {
        printf("v0_pkh_20B:");
        confirm_print_hex(spk + 2, 20);
    } else if (len == 34 && spk[0] == 0x51 && spk[1] == 0x20) {
        printf("v1_tap_32B:");
        confirm_print_hex(spk + 2, 32);
    } else if (len >= 23 && spk[0] == 0xa9 && spk[1] == 0x14) {
        printf("p2sh_hash20B:");
        confirm_print_hex(spk + 2, 20);
    } else if (len >= 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14) {
        printf("pkh_hash20B:");
        confirm_print_hex(spk + 3, 20);
    } else if (len == 34 && spk[0] == 0x00 && spk[1] == 0x20) {
        printf("v0_wsh_32B:");
        confirm_print_hex(spk + 2, 32);
    } else {
        printf("script_%luB:", (unsigned long)len);
        confirm_print_hex(spk, len);
    }
}

static int confirm_read_varint(const uint8_t **p, const uint8_t *end, uint64_t *val) {
    const uint8_t *tx;
    uint8_t ch;
    uint64_t v;
    size_t i;

    tx = *p;
    if (tx >= end)
        return 0;
    ch = *tx++;
    if (ch < 0xfd) {
        *val = (uint64_t)ch;
        *p = tx;
        return 1;
    }
    if (ch == 0xfd) {
        if ((size_t)(end - tx) < 2)
            return 0;
        v = (uint64_t)tx[0] | ((uint64_t)tx[1] << 8);
        tx += 2;
        *val = v;
        *p = tx;
        return 1;
    }
    if (ch == 0xfe) {
        if ((size_t)(end - tx) < 4)
            return 0;
        v = (uint64_t)tx[0] | ((uint64_t)tx[1] << 8) |
            ((uint64_t)tx[2] << 16) | ((uint64_t)tx[3] << 24);
        tx += 4;
        *val = v;
        *p = tx;
        return 1;
    }
    if ((size_t)(end - tx) < 8)
        return 0;
    v = 0;
    for (i = 0; i < 8; i++)
        v |= (uint64_t)tx[i] << (uint64_t)(8 * i);
    tx += 8;
    *val = v;
    *p = tx;
    return 1;
}

static int confirm_read_confirm_input(char *buf, size_t len, int ui_mode) {
    if (ui_mode)
        return fkt_ui_read_line(buf, len, 1);
    if (!fgets(buf, (int)len, stdin))
        return 0;
    {
        size_t n = strlen(buf);
        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
            buf[n - 1] = '\0';
            n--;
        }
    }
    return 1;
}

static int confirm_user_typed_confirm(const char *line) {
    if (!line)
        return 0;
    return (strcmp(line, "confirm") == 0 || strcmp(line, "CONFIRM") == 0);
}

static void confirm_show_fingerprint_banner(void) {
    fputs(fkt_ui_green_str(), stdout);
    printf("PSBT fingerprint (for confirmation): ");
    confirm_print_hex(psbt_data.psbt_fingerprint, 32);
    putchar('\n');
    fputs("\033[0m", stdout);
}

int fkt_confirm_before_sign_tty(void) {
    char line[64];

    if (!fkt_confirm_active())
        return 0;

    confirm_show_fingerprint_banner();
    printf("\nType CONFIRM to sign this PSBT: ");
    fflush(stdout);
    if (!confirm_read_confirm_input(line, sizeof(line), 0))
        return -1;
    if (!confirm_user_typed_confirm(line)) {
        fkt_last_error_set("Signing cancelled (fingerprint not confirmed).");
        return -1;
    }
    return 0;
}

int fkt_confirm_before_sign_ui(void) {
    char line[64];

    if (!fkt_confirm_active())
        return 0;

    fkt_ui_body_puts("");
    fkt_ui_body_puts("PSBT fingerprint (for confirmation):");
    {
        char fp_line[96];
        size_t pos;
        int i;

        pos = 0;
        for (i = 0; i < 32 && pos + 2 < sizeof(fp_line); i++) {
            snprintf(fp_line + pos, sizeof(fp_line) - pos, "%02x",
                     (unsigned)psbt_data.psbt_fingerprint[i]);
            pos += 2;
        }
        fp_line[sizeof(fp_line) - 1] = '\0';
        fkt_ui_body_puts(fp_line);
    }
    fkt_ui_body_puts("");
    fkt_ui_body_puts("Type CONFIRM to sign this PSBT:");
    fkt_ui_pin_session_footer();
    if (!confirm_read_confirm_input(line, sizeof(line), 1))
        return -1;
    if (!confirm_user_typed_confirm(line)) {
        fkt_last_error_set("Signing cancelled (fingerprint not confirmed).");
        return -1;
    }
    return 0;
}

static int confirm_render_post_sign_outputs_tty(const uint8_t txid[32]) {
    const uint8_t *tx;
    const uint8_t *end;
    const uint8_t *cursor;
    uint64_t count;
    uint64_t script_len;
    int64_t amount;
    int num_outputs;
    int i;
    uint8_t spk[520];

    tx = psbt_data.raw_unsigned_tx;
    end = tx + psbt_data.unsigned_tx_len;
    cursor = tx;
    if (end - cursor < 4)
        return -1;
    cursor += 4;
    if (end - cursor >= 2 && cursor[0] == 0x00 && cursor[1] == 0x01)
        return -1;
    if (!confirm_read_varint(&cursor, end, &count))
        return -1;
    for (i = 0; i < (int)count; i++) {
        if (end - cursor < 36)
            return -1;
        cursor += 36;
        if (!confirm_read_varint(&cursor, end, &count))
            return -1;
        if ((size_t)(end - cursor) < (size_t)count)
            return -1;
        cursor += (size_t)count;
        if (end - cursor < 4)
            return -1;
        cursor += 4;
    }
    if (!confirm_read_varint(&cursor, end, &count))
        return -1;
    num_outputs = (int)count;

    printf("\nUnsigned txid: ");
    confirm_print_txid_reversed(txid);
    putchar('\n');
    printf("\n-- OUTPUTS (from unsigned tx) --\n");
    for (i = 0; i < num_outputs; i++) {
        if (end - cursor < 8)
            return -1;
        amount = (int64_t)((uint64_t)cursor[0] | ((uint64_t)cursor[1] << 8) |
                           ((uint64_t)cursor[2] << 16) | ((uint64_t)cursor[3] << 24) |
                           ((uint64_t)cursor[4] << 32) | ((uint64_t)cursor[5] << 40) |
                           ((uint64_t)cursor[6] << 48) | ((uint64_t)cursor[7] << 56));
        cursor += 8;
        if (!confirm_read_varint(&cursor, end, &script_len))
            return -1;
        if (script_len > sizeof(spk) || (size_t)(end - cursor) < (size_t)script_len)
            return -1;
        memcpy(spk, cursor, (size_t)script_len);
        cursor += (size_t)script_len;
        printf("[%d] %lld sats  %s  ", i, (long long)amount,
               confirm_output_label(spk, (size_t)script_len));
        confirm_print_output_program(spk, (size_t)script_len);
        putchar('\n');
    }
    return 0;
}

static int confirm_render_post_sign_outputs_ui(const uint8_t txid[32]) {
    const uint8_t *tx;
    const uint8_t *end;
    const uint8_t *cursor;
    uint64_t count;
    uint64_t script_len;
    int64_t amount;
    int num_outputs;
    int i;
    uint8_t spk[520];
    char line[160];

    tx = psbt_data.raw_unsigned_tx;
    end = tx + psbt_data.unsigned_tx_len;
    cursor = tx;
    if (end - cursor < 4)
        return -1;
    cursor += 4;
    if (end - cursor >= 2 && cursor[0] == 0x00 && cursor[1] == 0x01)
        return -1;
    if (!confirm_read_varint(&cursor, end, &count))
        return -1;
    for (i = 0; i < (int)count; i++) {
        if (end - cursor < 36)
            return -1;
        cursor += 36;
        if (!confirm_read_varint(&cursor, end, &count))
            return -1;
        if ((size_t)(end - cursor) < (size_t)count)
            return -1;
        cursor += (size_t)count;
        if (end - cursor < 4)
            return -1;
        cursor += 4;
    }
    if (!confirm_read_varint(&cursor, end, &count))
        return -1;
    num_outputs = (int)count;

    fkt_ui_body_puts("");
    fkt_ui_body_puts("Unsigned txid:");
    {
        char txid_line[72];
        int j;
        size_t pos;

        pos = 0;
        for (j = 31; j >= 0 && pos + 2 < sizeof(txid_line); j--) {
            snprintf(txid_line + pos, sizeof(txid_line) - pos, "%02x",
                     (unsigned)txid[j]);
            pos += 2;
        }
        txid_line[sizeof(txid_line) - 1] = '\0';
        fkt_ui_body_puts(txid_line);
    }
    fkt_ui_body_puts("");
    fkt_ui_body_puts("-- OUTPUTS (from unsigned tx) --");
    for (i = 0; i < num_outputs; i++) {
        if (end - cursor < 8)
            return -1;
        amount = (int64_t)((uint64_t)cursor[0] | ((uint64_t)cursor[1] << 8) |
                           ((uint64_t)cursor[2] << 16) | ((uint64_t)cursor[3] << 24) |
                           ((uint64_t)cursor[4] << 32) | ((uint64_t)cursor[5] << 40) |
                           ((uint64_t)cursor[6] << 48) | ((uint64_t)cursor[7] << 56));
        cursor += 8;
        if (!confirm_read_varint(&cursor, end, &script_len))
            return -1;
        if (script_len > sizeof(spk) || (size_t)(end - cursor) < (size_t)script_len)
            return -1;
        memcpy(spk, cursor, (size_t)script_len);
        cursor += (size_t)script_len;
        snprintf(line, sizeof(line), "[%d] %lld sats  %s",
                 i, (long long)amount,
                 confirm_output_label(spk, (size_t)script_len));
        fkt_ui_body_puts(line);
    }
    return 0;
}

static int confirm_post_sign_prompt(const char *output_file, int ui_mode) {
    char line[64];
    uint8_t txid[32];

    if (!fkt_confirm_active())
        return 0;
    if (!output_file || output_file[0] == '\0') {
        fkt_last_error_set("Missing output path for post-sign confirmation.");
        return -1;
    }

    fkt_sha256d(psbt_data.raw_unsigned_tx, psbt_data.unsigned_tx_len, txid);

    if (ui_mode) {
        fkt_ui_clear_screen();
        fkt_ui_draw_banner(1);
        fkt_ui_draw_subtitle("CONFIRM WRITE");
        if (confirm_render_post_sign_outputs_ui(txid) != 0) {
            fkt_last_error_set("Post-sign output verification failed.");
            return -1;
        }
        fkt_ui_body_puts("");
        fkt_ui_body_printf("Write signed PSBT to:\n> %s\n", output_file);
        fkt_ui_body_puts("");
        fkt_ui_body_puts("Type CONFIRM to write file:");
        fkt_ui_pin_session_footer();
    } else {
        if (confirm_render_post_sign_outputs_tty(txid) != 0) {
            fkt_last_error_set("Post-sign output verification failed.");
            return -1;
        }
        printf("\nWrite signed PSBT to: %s\n", output_file);
        printf("\nType CONFIRM to write file: ");
        fflush(stdout);
    }

    if (!confirm_read_confirm_input(line, sizeof(line), ui_mode))
        return -1;
    if (!confirm_user_typed_confirm(line)) {
        fkt_last_error_set("Signing cancelled (output write not confirmed).");
        return -1;
    }
    return 0;
}

int fkt_confirm_post_sign_tty(const char *output_file) {
    return confirm_post_sign_prompt(output_file, 0);
}

int fkt_confirm_post_sign_ui(const char *output_file) {
    return confirm_post_sign_prompt(output_file, 1);
}

int fkt_confirm_post_sign_auto(const char *output_file) {
    if (g_confirm_ui_mode)
        return fkt_confirm_post_sign_ui(output_file);
    return fkt_confirm_post_sign_tty(output_file);
}