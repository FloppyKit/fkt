/* fkt_qrgen_wrap.c - C99 bridge to Nayuki qrcodegen (compiled separately) */
#include "fkt_qrgen_wrap.h"
#include "fkt_qrgen.h"

int fkt_qrgen_encode_binary(uint8_t *temp, size_t len, uint8_t *out, int max_version) {
    int ok;

    if (temp == NULL || out == NULL)
        return -1;
    if (max_version < qrcodegen_VERSION_MIN)
        max_version = qrcodegen_VERSION_MIN;
    if (max_version > qrcodegen_VERSION_MAX)
        max_version = qrcodegen_VERSION_MAX;

    ok = qrcodegen_encodeBinary(
        temp,
        len,
        out,
        qrcodegen_Ecc_MEDIUM,
        qrcodegen_VERSION_MIN,
        max_version,
        qrcodegen_Mask_AUTO,
        false);

    return ok ? 0 : -1;
}

int fkt_qrgen_get_size(const uint8_t *qrcode) {
    if (qrcode == NULL)
        return 0;
    return qrcodegen_getSize(qrcode);
}

int fkt_qrgen_get_module(const uint8_t *qrcode, int x, int y) {
    if (qrcode == NULL)
        return 0;
    if (qrcodegen_getModule(qrcode, x, y))
        return 1;
    return 0;
}