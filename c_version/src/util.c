#include "util.h"
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

void gv_wipe(void *ptr, size_t len) {
    if (ptr && len) OPENSSL_cleanse(ptr, len);
}

void gv_put_u16(uint8_t *buf, uint16_t v) {
    buf[0] = (uint8_t)(v >> 8);
    buf[1] = (uint8_t)(v);
}
void gv_put_u32(uint8_t *buf, uint32_t v) {
    buf[0] = (uint8_t)(v >> 24);
    buf[1] = (uint8_t)(v >> 16);
    buf[2] = (uint8_t)(v >> 8);
    buf[3] = (uint8_t)(v);
}
void gv_put_u64(uint8_t *buf, uint64_t v) {
    for (int i = 0; i < 8; i++) buf[i] = (uint8_t)(v >> (8 * (7 - i)));
}
uint16_t gv_get_u16(const uint8_t *buf) {
    return (uint16_t)((buf[0] << 8) | buf[1]);
}
uint32_t gv_get_u32(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
}
uint64_t gv_get_u64(const uint8_t *buf) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | buf[i];
    return v;
}

bool gv_read_exact(FILE *f, void *buf, size_t n) {
    if (n == 0) return true;
    size_t got = fread(buf, 1, n, f);
    return got == n;
}

void gv_format_bytes(double n, char *out, size_t out_size) {
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    int ui = 0;
    while (n >= 1024.0 && ui < 4) {
        n /= 1024.0;
        ui++;
    }
    if (ui == 0) snprintf(out, out_size, "%.0f%s", n, units[ui]);
    else         snprintf(out, out_size, "%.1f%s", n, units[ui]);
}

int64_t gv_now_unix(void) {
    return (int64_t)time(NULL);
}

void gv_buf_init(gv_buf_t *b) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

int gv_buf_append(gv_buf_t *b, const uint8_t *data, size_t n) {
    if (n == 0) return 1;
    if (b->len + n > b->cap) {
        size_t new_cap = b->cap ? b->cap * 2 : 4096;
        while (new_cap < b->len + n) new_cap *= 2;
        uint8_t *nb = (uint8_t *)realloc(b->data, new_cap);
        if (!nb) return 0;
        b->data = nb;
        b->cap = new_cap;
    }
    memcpy(b->data + b->len, data, n);
    b->len += n;
    return 1;
}

void gv_buf_consume(gv_buf_t *b, size_t n) {
    if (n >= b->len) {
        b->len = 0;
        return;
    }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
}

void gv_buf_free(gv_buf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

const char *gv_status_str(gv_status_t s) {
    switch (s) {
        case GV_OK:               return "OK";
        case GV_ERR_IO:            return "Gagal membaca/menulis file.";
        case GV_ERR_FORMAT:        return "Vault korup / bukan format CRYPTO//GOD VAULT (C edition) yang valid.";
        case GV_ERR_UNSUPPORTED:   return "Versi atau parameter KDF vault ini tidak didukung build ini.";
        case GV_ERR_AUTH:          return "GAGAL! Password salah, atau data korup/dimanipulasi.";
        case GV_ERR_POLICY:        return "Password tidak memenuhi kebijakan keamanan minimum.";
        case GV_ERR_RATE_LIMIT:    return "Rate limit aktif -- terlalu banyak percobaan gagal.";
        case GV_ERR_MEMORY:        return "Alokasi memori gagal.";
        case GV_ERR_CRYPTO:        return "Kegagalan internal pustaka kriptografi.";
        default:                   return "Kesalahan tidak dikenal.";
    }
}
