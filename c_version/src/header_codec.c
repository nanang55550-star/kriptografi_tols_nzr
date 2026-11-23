#include "header_codec.h"
#include "util.h"
#include "kdf.h"
#include <string.h>
#include <stdlib.h>

size_t gv_header_packed_size(const gv_header_t *hdr) {
    /* magic(4) version(1) kdf_id(1) compressed(1) reserved(1)
     * kdf_mem_cost(4) kdf_time_cost(4) kdf_parallelism(1)
     * salt_len(1) salt(32) nonce_prefix(4)
     * filename_len(2) filename(N) source_size(8) timestamp(8) */
    return (size_t)(4 + 1 + 1 + 1 + 1) + (4 + 4 + 1) + (1 + GV_SALT_LEN) +
           GV_NONCE_PREFIX_LEN + 2 + hdr->filename_len + 8 + 8;
}

size_t gv_header_pack(const gv_header_t *hdr, uint8_t *out) {
    size_t o = 0;
    memcpy(out + o, GV_MAGIC, GV_MAGIC_LEN); o += GV_MAGIC_LEN;
    out[o++] = hdr->version;
    out[o++] = hdr->kdf_id;
    out[o++] = hdr->compressed ? 1 : 0;
    out[o++] = 0;  /* reserved, selalu 0 */

    gv_put_u32(out + o, hdr->kdf_mem_cost);  o += 4;
    gv_put_u32(out + o, hdr->kdf_time_cost); o += 4;
    out[o++] = hdr->kdf_parallelism;

    out[o++] = GV_SALT_LEN;
    memcpy(out + o, hdr->salt, GV_SALT_LEN); o += GV_SALT_LEN;

    memcpy(out + o, hdr->nonce_prefix, GV_NONCE_PREFIX_LEN); o += GV_NONCE_PREFIX_LEN;

    gv_put_u16(out + o, hdr->filename_len); o += 2;
    if (hdr->filename_len) {
        memcpy(out + o, hdr->filename, hdr->filename_len);
        o += hdr->filename_len;
    }

    gv_put_u64(out + o, hdr->source_size); o += 8;
    gv_put_u64(out + o, (uint64_t)hdr->timestamp); o += 8;
    return o;
}

gv_status_t gv_header_read(FILE *f, gv_header_t *hdr,
                            size_t *header_len_out, uint8_t **header_bytes_out) {
    memset(hdr, 0, sizeof(*hdr));
    gv_buf_t raw;
    gv_buf_init(&raw);

#define GV_FAIL(code) do { gv_buf_free(&raw); return (code); } while (0)
#define GV_READ_OR_FAIL(dst, n) \
    do { if (!gv_read_exact(f, (dst), (n))) GV_FAIL(GV_ERR_FORMAT); \
         if (!gv_buf_append(&raw, (dst), (n))) GV_FAIL(GV_ERR_MEMORY); } while (0)

    uint8_t fixed1[8];  /* magic(4) version(1) kdf_id(1) compressed(1) reserved(1) */
    GV_READ_OR_FAIL(fixed1, sizeof(fixed1));
    if (memcmp(fixed1, GV_MAGIC, GV_MAGIC_LEN) != 0) GV_FAIL(GV_ERR_FORMAT);
    hdr->version = fixed1[4];
    hdr->kdf_id = fixed1[5];
    hdr->compressed = fixed1[6];
    if (hdr->version != GV_VERSION) GV_FAIL(GV_ERR_UNSUPPORTED);

    uint8_t fixed2[9];  /* kdf_mem_cost(4) kdf_time_cost(4) parallelism(1) */
    GV_READ_OR_FAIL(fixed2, sizeof(fixed2));
    hdr->kdf_mem_cost = gv_get_u32(fixed2);
    hdr->kdf_time_cost = gv_get_u32(fixed2 + 4);
    hdr->kdf_parallelism = fixed2[8];

    uint8_t saltlen_b;
    GV_READ_OR_FAIL(&saltlen_b, 1);
    if (saltlen_b != GV_SALT_LEN) GV_FAIL(GV_ERR_FORMAT);

    GV_READ_OR_FAIL(hdr->salt, GV_SALT_LEN);
    GV_READ_OR_FAIL(hdr->nonce_prefix, GV_NONCE_PREFIX_LEN);

    uint8_t fnlen_b[2];
    GV_READ_OR_FAIL(fnlen_b, 2);
    hdr->filename_len = gv_get_u16(fnlen_b);
    if (hdr->filename_len > GV_MAX_FILENAME_LEN) GV_FAIL(GV_ERR_FORMAT);
    if (hdr->filename_len) {
        GV_READ_OR_FAIL((uint8_t *)hdr->filename, hdr->filename_len);
    }
    hdr->filename[hdr->filename_len] = '\0';

    uint8_t tail[16];  /* source_size(8) timestamp(8) */
    GV_READ_OR_FAIL(tail, sizeof(tail));
    hdr->source_size = gv_get_u64(tail);
    hdr->timestamp = (int64_t)gv_get_u64(tail + 8);

    if (hdr->kdf_id != GV_KDF_ARGON2ID && hdr->kdf_id != GV_KDF_PBKDF2) GV_FAIL(GV_ERR_UNSUPPORTED);
    if (hdr->kdf_id == GV_KDF_ARGON2ID && !gv_argon2_available()) GV_FAIL(GV_ERR_UNSUPPORTED);

#undef GV_READ_OR_FAIL
#undef GV_FAIL

    *header_bytes_out = raw.data;   /* alih kepemilikan ke caller */
    *header_len_out = raw.len;
    return GV_OK;
}
