#include "base64.h"
#include <stdlib.h>
#include <string.h>

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *gv_base64_encode(const uint8_t *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = (char *)malloc(out_len + 1);
    if (!out) return NULL;

    size_t i = 0, o = 0;
    while (i + 3 <= len) {
        uint32_t n = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | data[i + 2];
        out[o++] = B64_TABLE[(n >> 18) & 0x3F];
        out[o++] = B64_TABLE[(n >> 12) & 0x3F];
        out[o++] = B64_TABLE[(n >> 6) & 0x3F];
        out[o++] = B64_TABLE[n & 0x3F];
        i += 3;
    }
    size_t rem = len - i;
    if (rem == 1) {
        uint32_t n = (uint32_t)data[i] << 16;
        out[o++] = B64_TABLE[(n >> 18) & 0x3F];
        out[o++] = B64_TABLE[(n >> 12) & 0x3F];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t n = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8);
        out[o++] = B64_TABLE[(n >> 18) & 0x3F];
        out[o++] = B64_TABLE[(n >> 12) & 0x3F];
        out[o++] = B64_TABLE[(n >> 6) & 0x3F];
        out[o++] = '=';
    }
    out[o] = '\0';
    return out;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

uint8_t *gv_base64_decode(const char *text, size_t *out_len) {
    size_t len = strlen(text);
    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r' ||
                        text[len - 1] == ' ' || text[len - 1] == '\t')) {
        len--;
    }

    if (len == 0) {
        uint8_t *out = (uint8_t *)malloc(1);
        if (out) *out_len = 0;
        return out;
    }
    if (len % 4 != 0) return NULL;

    size_t out_cap = (len / 4) * 3;
    uint8_t *out = (uint8_t *)malloc(out_cap > 0 ? out_cap : 1);
    if (!out) return NULL;

    size_t o = 0;
    for (size_t i = 0; i < len; i += 4) {
        int v0 = (text[i] == '=') ? -2 : b64_val(text[i]);
        int v1 = (text[i + 1] == '=') ? -2 : b64_val(text[i + 1]);
        int v2 = (text[i + 2] == '=') ? -2 : b64_val(text[i + 2]);
        int v3 = (text[i + 3] == '=') ? -2 : b64_val(text[i + 3]);

        if (v0 < 0 || v1 < 0) { free(out); return NULL; }  /* 2 karakter pertama tak boleh '=' */

        uint32_t n = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12);
        out[o++] = (uint8_t)((n >> 16) & 0xFF);

        if (v2 == -2) {
            if (i + 4 != len || v3 != -2) { free(out); return NULL; }
            break;
        }
        if (v2 < 0) { free(out); return NULL; }
        n |= (uint32_t)v2 << 6;
        out[o++] = (uint8_t)((n >> 8) & 0xFF);

        if (v3 == -2) {
            if (i + 4 != len) { free(out); return NULL; }
            break;
        }
        if (v3 < 0) { free(out); return NULL; }
        n |= (uint32_t)v3;
        out[o++] = (uint8_t)(n & 0xFF);
    }

    *out_len = o;
    return out;
}
