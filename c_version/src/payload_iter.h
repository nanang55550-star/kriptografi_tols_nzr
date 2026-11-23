#ifndef GODVAULT_PAYLOAD_ITER_H
#define GODVAULT_PAYLOAD_ITER_H

#include "util.h"
#include "compress.h"
#include <stdio.h>

/* Menghasilkan potongan payload siap dienkripsi, PERSIS chunk_size byte
 * kecuali potongan TERAKHIR (boleh lebih pendek, bahkan 0 byte). Kalau
 * compress=1, payload dibentuk lewat deflate streaming (memori terbatas,
 * TIDAK proporsional dgn ukuran input) -- lihat gv_deflate_feed(). */
typedef struct {
    FILE  *in;
    int    compress;
    size_t chunk_size;
    size_t read_block_size;

    gv_buf_t    pending;
    gv_deflate_t deflator;

    uint8_t *readbuf;         /* ukuran read_block_size */
    uint8_t *out_piece_buf;   /* ukuran chunk_size */

    int eof_reached;
    int finished;
    int error;
    uint64_t bytes_read;   /* total byte yg sudah dibaca dari `in` -- utk progress */
} gv_payload_iter_t;

int  gv_payload_iter_init(gv_payload_iter_t *it, FILE *in, int compress,
                           size_t chunk_size, size_t read_block_size);

/* Return 1: ada piece (out_piece valid SAMPAI panggilan next()/free berikutnya).
 * Return 0: selesai (kalau it->error==0) atau gagal (it->error==1). */
int gv_payload_iter_next(gv_payload_iter_t *it, const uint8_t **out_piece,
                          size_t *out_len, int *out_is_last);

void gv_payload_iter_free(gv_payload_iter_t *it);

#endif /* GODVAULT_PAYLOAD_ITER_H */
