#include "payload_iter.h"
#include <stdlib.h>
#include <string.h>

int gv_payload_iter_init(gv_payload_iter_t *it, FILE *in, int compress,
                          size_t chunk_size, size_t read_block_size) {
    memset(it, 0, sizeof(*it));
    it->in = in;
    it->compress = compress;
    it->chunk_size = chunk_size ? chunk_size : GV_DEFAULT_CHUNK_SIZE;
    it->read_block_size = read_block_size ? read_block_size : it->chunk_size;

    gv_buf_init(&it->pending);

    it->readbuf = (uint8_t *)malloc(it->read_block_size);
    it->out_piece_buf = (uint8_t *)malloc(it->chunk_size > 0 ? it->chunk_size : 1);
    if (!it->readbuf || !it->out_piece_buf) {
        it->error = 1;
        return 0;
    }

    if (compress) {
        if (!gv_deflate_init(&it->deflator)) {
            it->error = 1;
            return 0;
        }
    }
    return 1;
}

int gv_payload_iter_next(gv_payload_iter_t *it, const uint8_t **out_piece,
                          size_t *out_len, int *out_is_last) {
    if (it->finished || it->error) return 0;

    for (;;) {
        if (it->pending.len > it->chunk_size) {
            memcpy(it->out_piece_buf, it->pending.data, it->chunk_size);
            gv_buf_consume(&it->pending, it->chunk_size);
            *out_piece = it->out_piece_buf;
            *out_len = it->chunk_size;
            *out_is_last = 0;
            return 1;
        }

        if (it->eof_reached) {
            memcpy(it->out_piece_buf, it->pending.data, it->pending.len);
            *out_piece = it->out_piece_buf;
            *out_len = it->pending.len;
            *out_is_last = 1;
            gv_buf_consume(&it->pending, it->pending.len);
            it->finished = 1;
            return 1;
        }

        size_t got = fread(it->readbuf, 1, it->read_block_size, it->in);
        it->bytes_read += got;
        if (got > 0) {
            int ok = it->compress
                ? gv_deflate_feed(&it->deflator, it->readbuf, got, &it->pending)
                : gv_buf_append(&it->pending, it->readbuf, got);
            if (!ok) {
                it->error = 1;
                return 0;
            }
        }
        if (got < it->read_block_size) {
            if (ferror(it->in)) {
                it->error = 1;
                return 0;
            }
            /* EOF (feof true, atau got==0 dengan stream sudah abis) */
            it->eof_reached = 1;
            if (it->compress) {
                if (!gv_deflate_finish(&it->deflator, &it->pending)) {
                    it->error = 1;
                    return 0;
                }
            }
        }
        /* loop lagi: evaluasi ulang kondisi di atas dgn pending yg sudah bertambah */
    }
}

void gv_payload_iter_free(gv_payload_iter_t *it) {
    free(it->readbuf);
    free(it->out_piece_buf);
    gv_buf_free(&it->pending);
    if (it->compress) gv_deflate_free(&it->deflator);
    it->readbuf = NULL;
    it->out_piece_buf = NULL;
}
