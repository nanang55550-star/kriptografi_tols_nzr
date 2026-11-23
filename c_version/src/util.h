#ifndef GODVAULT_UTIL_H
#define GODVAULT_UTIL_H

#define _FILE_OFFSET_BITS 64   /* pastikan off_t 64-bit -- wajib utk file besar */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include "vault_format.h"

/* ---- Secure memory wipe ---------------------------------------------- */
/* Memakai OPENSSL_cleanse(): dijamin TIDAK dioptimasi-hilang oleh compiler
 * (beda dengan memset() biasa, yang boleh "dihapus" compiler kalau memori
 * tsb tidak dibaca lagi sesudahnya -- lubang keamanan klasik). Ini salah
 * satu keunggulan nyata versi C dibanding Python: di Python, penghapusan
 * memori password cuma best-effort lewat overwrite bytearray via API
 * biasa (tidak ada jaminan setingkat ini dari bahasanya sendiri). */
void gv_wipe(void *ptr, size_t len);

/* ---- Big-endian pack/unpack (portabel di semua arsitektur) ----------- */
void     gv_put_u16(uint8_t *buf, uint16_t v);
void     gv_put_u32(uint8_t *buf, uint32_t v);
void     gv_put_u64(uint8_t *buf, uint64_t v);
uint16_t gv_get_u16(const uint8_t *buf);
uint32_t gv_get_u32(const uint8_t *buf);
uint64_t gv_get_u64(const uint8_t *buf);

/* ---- I/O helper: baca PERSIS n byte atau gagal (bukan short read) ----- */
bool gv_read_exact(FILE *f, void *buf, size_t n);

/* ---- Format ukuran byte manusiawi (utk progress bar) ------------------ */
void gv_format_bytes(double n, char *out, size_t out_size);

/* ---- Waktu sekarang (unix epoch, utk header) --------------------------- */
int64_t gv_now_unix(void);

/* ---- Buffer biner yang bisa tumbuh (dipakai jalur kompresi streaming) - */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} gv_buf_t;

void gv_buf_init(gv_buf_t *b);
int  gv_buf_append(gv_buf_t *b, const uint8_t *data, size_t n);  /* 1 ok, 0 gagal alokasi */
void gv_buf_consume(gv_buf_t *b, size_t n);   /* buang n byte dari DEPAN (memmove sisanya) */
void gv_buf_free(gv_buf_t *b);

#endif /* GODVAULT_UTIL_H */
