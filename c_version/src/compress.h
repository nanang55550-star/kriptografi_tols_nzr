#ifndef GODVAULT_COMPRESS_H
#define GODVAULT_COMPRESS_H

#include "util.h"
#include <zlib.h>

/* ---- Kompresi streaming (dipakai saat ENKRIPSI) ------------------------
 * Memori terbatas: setiap panggilan feed() memakai buffer stack kecil
 * (bukan dialokasi proporsional ukuran data), output di-APPEND ke *out. */
typedef struct {
    z_stream strm;
    int      initialized;
} gv_deflate_t;

int  gv_deflate_init(gv_deflate_t *d);
int  gv_deflate_feed(gv_deflate_t *d, const uint8_t *data, size_t data_len,
                      gv_buf_t *out);
int  gv_deflate_finish(gv_deflate_t *d, gv_buf_t *out);
void gv_deflate_free(gv_deflate_t *d);

/* ---- Dekompresi streaming (dipakai saat DEKRIPSI) -----------------------
 * Output DITULIS LANGSUNG ke FILE* progresif, dibatasi buffer tetap per
 * panggilan inflate() -- idiom standar zlib (lihat zpipe.c resmi), jadi
 * satu potongan input dengan rasio kompresi ekstrem TIDAK bisa memaksa
 * alokasi output raksasa sekaligus. */
typedef struct {
    z_stream strm;
    int      initialized;
} gv_inflate_t;

int gv_inflate_init(gv_inflate_t *d);
/* Return 1 ok, 0 kalau data terkompresi tidak valid/korup. */
int gv_inflate_feed(gv_inflate_t *d, const uint8_t *data, size_t data_len, FILE *out);
void gv_inflate_free(gv_inflate_t *d);

#endif /* GODVAULT_COMPRESS_H */
