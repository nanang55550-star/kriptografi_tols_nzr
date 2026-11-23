#ifndef GODVAULT_BASE64_H
#define GODVAULT_BASE64_H

#include <stddef.h>
#include <stdint.h>

/* Base64 standar (RFC 4648, +/=). Ini encoding biasa (bukan primitif
 * kriptografis), jadi implementasi sendiri di sini wajar -- beda dgn
 * AES/HMAC/KDF yang wajib pakai pustaka teraudit. Divalidasi terhadap
 * modul base64 Python (lihat tests/). */

/* Return buffer malloc'd, null-terminated. NULL kalau gagal alokasi. */
char *gv_base64_encode(const uint8_t *data, size_t len);

/* Return buffer malloc'd berisi data biner hasil decode (out_len diisi).
 * NULL kalau input BUKAN base64 valid (panjang bukan kelipatan 4, karakter
 * di luar alfabet, padding '=' salah tempat, dst) -- divalidasi ketat,
 * tidak pernah overflow/out-of-bounds walau input sepenuhnya acak. */
uint8_t *gv_base64_decode(const char *text, size_t *out_len);

#endif /* GODVAULT_BASE64_H */
