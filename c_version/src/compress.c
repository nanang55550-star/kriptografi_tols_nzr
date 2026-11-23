#include "compress.h"
#include <string.h>

#define GV_DEFLATE_OUTBUF 65536

int gv_deflate_init(gv_deflate_t *d) {
    memset(&d->strm, 0, sizeof(d->strm));
    int ret = deflateInit(&d->strm, Z_BEST_COMPRESSION);
    d->initialized = (ret == Z_OK);
    return d->initialized ? 1 : 0;
}

static int deflate_pump(gv_deflate_t *d, int flush, gv_buf_t *out) {
    uint8_t outbuf[GV_DEFLATE_OUTBUF];
    int ret;
    do {
        d->strm.next_out = outbuf;
        d->strm.avail_out = sizeof(outbuf);
        ret = deflate(&d->strm, flush);
        if (ret == Z_STREAM_ERROR) return 0;
        size_t have = sizeof(outbuf) - d->strm.avail_out;
        if (have > 0 && !gv_buf_append(out, outbuf, have)) return 0;
    } while (d->strm.avail_out == 0);
    return 1;
}

int gv_deflate_feed(gv_deflate_t *d, const uint8_t *data, size_t data_len, gv_buf_t *out) {
    if (!d->initialized) return 0;
    d->strm.next_in = (Bytef *)data;
    d->strm.avail_in = (uInt)data_len;
    return deflate_pump(d, Z_NO_FLUSH, out);
}

int gv_deflate_finish(gv_deflate_t *d, gv_buf_t *out) {
    if (!d->initialized) return 0;
    d->strm.next_in = NULL;
    d->strm.avail_in = 0;
    return deflate_pump(d, Z_FINISH, out);
}

void gv_deflate_free(gv_deflate_t *d) {
    if (d->initialized) {
        deflateEnd(&d->strm);
        d->initialized = 0;
    }
}

int gv_inflate_init(gv_inflate_t *d) {
    memset(&d->strm, 0, sizeof(d->strm));
    int ret = inflateInit(&d->strm);
    d->initialized = (ret == Z_OK);
    return d->initialized ? 1 : 0;
}

int gv_inflate_feed(gv_inflate_t *d, const uint8_t *data, size_t data_len, FILE *out) {
    if (!d->initialized) return 0;
    uint8_t outbuf[GV_DECOMPRESS_MAX_OUTPUT];

    d->strm.next_in = (Bytef *)data;
    d->strm.avail_in = (uInt)data_len;

    int ret;
    do {
        d->strm.next_out = outbuf;
        d->strm.avail_out = sizeof(outbuf);
        ret = inflate(&d->strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_NEED_DICT ||
            ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            return 0;
        }
        size_t have = sizeof(outbuf) - d->strm.avail_out;
        if (have > 0) {
            if (fwrite(outbuf, 1, have, out) != have) return 0;
        }
    } while (d->strm.avail_out == 0);

    return 1;
}

void gv_inflate_free(gv_inflate_t *d) {
    if (d->initialized) {
        inflateEnd(&d->strm);
        d->initialized = 0;
    }
}
