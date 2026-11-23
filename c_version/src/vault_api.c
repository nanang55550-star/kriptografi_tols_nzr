#include "vault_api.h"
#include "util.h"
#include "kdf.h"
#include "crypto_core.h"
#include "header_codec.h"
#include "payload_iter.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/rand.h>

/* ==========================================================================
 * ENKRIPSI: tulis chunk demi chunk lewat payload_iter, nonce counter-based,
 * AAD = header+index+is_last, update HMAC global seiring jalan.
 * ========================================================================== */
static gv_status_t write_chunks_loop(FILE *out, const uint8_t *enc_key,
                                      const uint8_t nonce_prefix[GV_NONCE_PREFIX_LEN],
                                      const uint8_t *header_bytes, size_t header_len,
                                      gv_payload_iter_t *it, gv_hmac_stream_t *hmac,
                                      uint64_t input_total_size,
                                      gv_progress_cb cb, void *cbctx) {
    uint64_t idx = 0;
    const uint8_t *piece;
    size_t plen;
    int is_last;

    uint8_t *ct_buf = (uint8_t *)malloc(it->chunk_size > 0 ? it->chunk_size : 1);
    uint8_t *aad_buf = (uint8_t *)malloc(header_len + 9);
    if (!ct_buf || !aad_buf) {
        free(ct_buf);
        free(aad_buf);
        return GV_ERR_MEMORY;
    }

    gv_status_t result = GV_OK;

    for (;;) {
        int has = gv_payload_iter_next(it, &piece, &plen, &is_last);
        if (!has) {
            result = it->error ? GV_ERR_CRYPTO : GV_OK;
            break;
        }

        uint8_t nonce[GV_NONCE_LEN];
        gv_make_nonce(nonce_prefix, idx, nonce);

        size_t aad_len = gv_chunk_aad(header_bytes, header_len, idx, is_last, aad_buf);

        uint8_t tag[GV_GCM_TAG_LEN];
        if (!gv_aes_gcm_encrypt(enc_key, nonce, aad_buf, aad_len, piece, plen, ct_buf, tag)) {
            result = GV_ERR_CRYPTO;
            break;
        }

        uint8_t lenbuf[4];
        gv_put_u32(lenbuf, (uint32_t)(plen + GV_GCM_TAG_LEN));

        if (fwrite(lenbuf, 1, 4, out) != 4 ||
            (plen > 0 && fwrite(ct_buf, 1, plen, out) != plen) ||
            fwrite(tag, 1, GV_GCM_TAG_LEN, out) != GV_GCM_TAG_LEN) {
            result = GV_ERR_IO;
            break;
        }

        if (!gv_hmac_stream_update(hmac, lenbuf, 4) ||
            (plen > 0 && !gv_hmac_stream_update(hmac, ct_buf, plen)) ||
            !gv_hmac_stream_update(hmac, tag, GV_GCM_TAG_LEN)) {
            result = GV_ERR_CRYPTO;
            break;
        }

        idx++;
        if (cb) {
            uint64_t done = it->bytes_read;
            uint64_t total = input_total_size > done ? input_total_size : done;
            cb("read", done, total, cbctx);
        }

        if (is_last) break;
    }

    free(ct_buf);
    free(aad_buf);
    return result;
}

gv_status_t gv_encrypt_stream(FILE *in, uint64_t input_total_size, FILE *out,
                               const char *password, size_t password_len,
                               int compress, const char *filename, uint64_t source_size,
                               uint8_t kdf_id, size_t chunk_size,
                               gv_progress_cb cb, void *cbctx) {
    gv_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = GV_VERSION;
    hdr.compressed = compress ? 1 : 0;
    gv_kdf_default_params(&hdr, kdf_id);

    if (RAND_bytes(hdr.salt, GV_SALT_LEN) != 1) return GV_ERR_CRYPTO;
    if (RAND_bytes(hdr.nonce_prefix, GV_NONCE_PREFIX_LEN) != 1) return GV_ERR_CRYPTO;

    if (filename) {
        size_t flen = strlen(filename);
        if (flen > GV_MAX_FILENAME_LEN) flen = GV_MAX_FILENAME_LEN;
        memcpy(hdr.filename, filename, flen);
        hdr.filename[flen] = '\0';
        hdr.filename_len = (uint16_t)flen;
    }
    hdr.source_size = source_size;
    hdr.timestamp = gv_now_unix();

    uint8_t master_key[GV_KEY_LEN];
    uint8_t enc_key[GV_KEY_LEN];
    uint8_t hmac_key[GV_HMAC_KEY_LEN];
    uint8_t *header_bytes = NULL;
    gv_hmac_stream_t hmac = {0};
    gv_payload_iter_t it = {0};
    int hmac_active = 0, iter_active = 0;
    gv_status_t st;

    st = gv_kdf_derive(&hdr, password, password_len, master_key);
    if (st != GV_OK) goto cleanup;

    st = gv_derive_subkeys(master_key, hdr.salt, enc_key, hmac_key);
    gv_wipe(master_key, sizeof(master_key));
    if (st != GV_OK) goto cleanup;

    {
        size_t header_len = gv_header_packed_size(&hdr);
        header_bytes = (uint8_t *)malloc(header_len);
        if (!header_bytes) { st = GV_ERR_MEMORY; goto cleanup; }
        gv_header_pack(&hdr, header_bytes);

        if (fwrite(header_bytes, 1, header_len, out) != header_len) {
            st = GV_ERR_IO; goto cleanup;
        }

        if (!gv_hmac_stream_init(&hmac, hmac_key)) { st = GV_ERR_CRYPTO; goto cleanup; }
        hmac_active = 1;
        gv_wipe(hmac_key, sizeof(hmac_key));

        if (!gv_hmac_stream_update(&hmac, header_bytes, header_len)) {
            st = GV_ERR_CRYPTO; goto cleanup;
        }

        if (!gv_payload_iter_init(&it, in, compress,
                                   chunk_size ? chunk_size : GV_DEFAULT_CHUNK_SIZE,
                                   GV_READ_BLOCK_SIZE)) {
            st = GV_ERR_MEMORY; goto cleanup;
        }
        iter_active = 1;

        st = write_chunks_loop(out, enc_key, hdr.nonce_prefix, header_bytes, header_len,
                                &it, &hmac, input_total_size, cb, cbctx);
        if (st != GV_OK) goto cleanup;

        uint8_t digest[GV_HMAC_DIGEST_LEN];
        if (!gv_hmac_stream_final(&hmac, digest)) { hmac_active = 0; st = GV_ERR_CRYPTO; goto cleanup; }
        hmac_active = 0;
        if (fwrite(digest, 1, GV_HMAC_DIGEST_LEN, out) != GV_HMAC_DIGEST_LEN) {
            gv_wipe(digest, sizeof(digest));
            st = GV_ERR_IO; goto cleanup;
        }
        gv_wipe(digest, sizeof(digest));
    }

    st = GV_OK;

cleanup:
    if (iter_active) gv_payload_iter_free(&it);
    if (hmac_active) gv_hmac_stream_abort(&hmac);
    free(header_bytes);
    gv_wipe(enc_key, sizeof(enc_key));
    gv_wipe(hmac_key, sizeof(hmac_key));
    (void)cb; (void)cbctx;
    return st;
}

/* ==========================================================================
 * DEKRIPSI: PASS 1 verifikasi HMAC (constant-time), PASS 2 dekripsi+tulis.
 * ========================================================================== */
static gv_status_t verify_stream_hmac(FILE *in, const uint8_t *hmac_key,
                                       const uint8_t *header_bytes, size_t header_len,
                                       uint64_t ciphertext_region_size,
                                       gv_progress_cb cb, void *cbctx) {
    gv_hmac_stream_t hs;
    if (!gv_hmac_stream_init(&hs, hmac_key)) return GV_ERR_CRYPTO;
    if (!gv_hmac_stream_update(&hs, header_bytes, header_len)) {
        gv_hmac_stream_abort(&hs);
        return GV_ERR_CRYPTO;
    }

    uint8_t buf[GV_READ_BLOCK_SIZE];
    uint64_t remaining = ciphertext_region_size;
    while (remaining > 0) {
        size_t want = (remaining < sizeof(buf)) ? (size_t)remaining : sizeof(buf);
        size_t got = fread(buf, 1, want, in);
        if (got != want) { gv_hmac_stream_abort(&hs); return GV_ERR_FORMAT; }
        if (!gv_hmac_stream_update(&hs, buf, got)) { gv_hmac_stream_abort(&hs); return GV_ERR_CRYPTO; }
        remaining -= got;
        if (cb) cb("verify", ciphertext_region_size - remaining, ciphertext_region_size, cbctx);
    }

    uint8_t stored[GV_HMAC_DIGEST_LEN];
    if (!gv_read_exact(in, stored, GV_HMAC_DIGEST_LEN)) {
        gv_hmac_stream_abort(&hs);
        return GV_ERR_FORMAT;
    }

    uint8_t computed[GV_HMAC_DIGEST_LEN];
    if (!gv_hmac_stream_final(&hs, computed)) return GV_ERR_CRYPTO;

    gv_status_t result = gv_const_time_eq(computed, stored, GV_HMAC_DIGEST_LEN) ? GV_OK : GV_ERR_AUTH;
    gv_wipe(computed, sizeof(computed));
    return result;
}

static gv_status_t decrypt_chunks_loop(FILE *in, const uint8_t *enc_key,
                                        const uint8_t nonce_prefix[GV_NONCE_PREFIX_LEN],
                                        const uint8_t *header_bytes, size_t header_len,
                                        uint64_t ciphertext_region_size, int compressed,
                                        FILE *out, gv_progress_cb cb, void *cbctx) {
    uint64_t remaining = ciphertext_region_size;
    uint64_t idx = 0;
    gv_status_t result = GV_OK;

    gv_inflate_t inf = {0};
    int inf_active = 0;
    if (compressed) {
        if (!gv_inflate_init(&inf)) return GV_ERR_CRYPTO;
        inf_active = 1;
    }

    uint8_t *ct_buf = NULL;
    size_t ct_cap = 0;
    uint8_t *pt_buf = NULL;
    size_t pt_cap = 0;
    uint8_t *aad_buf = (uint8_t *)malloc(header_len + 9);
    if (!aad_buf) { result = GV_ERR_MEMORY; goto done; }

    while (remaining > 0) {
        if (remaining < 4) { result = GV_ERR_FORMAT; goto done; }
        uint8_t lenbuf[4];
        if (!gv_read_exact(in, lenbuf, 4)) { result = GV_ERR_FORMAT; goto done; }
        remaining -= 4;

        uint32_t reclen = gv_get_u32(lenbuf);
        if (reclen < GV_GCM_TAG_LEN || (uint64_t)reclen > remaining) {
            result = GV_ERR_FORMAT; goto done;
        }

        if (reclen > ct_cap) {
            uint8_t *nb = (uint8_t *)realloc(ct_buf, reclen);
            if (!nb) { result = GV_ERR_MEMORY; goto done; }
            ct_buf = nb; ct_cap = reclen;
        }
        if (!gv_read_exact(in, ct_buf, reclen)) { result = GV_ERR_FORMAT; goto done; }
        remaining -= reclen;

        size_t pt_len = reclen - GV_GCM_TAG_LEN;
        const uint8_t *tag = ct_buf + pt_len;
        int is_last = (remaining == 0);

        if (pt_len > pt_cap) {
            uint8_t *nb = (uint8_t *)realloc(pt_buf, pt_len > 0 ? pt_len : 1);
            if (!nb) { result = GV_ERR_MEMORY; goto done; }
            pt_buf = nb; pt_cap = pt_len;
        }

        uint8_t nonce[GV_NONCE_LEN];
        gv_make_nonce(nonce_prefix, idx, nonce);
        size_t aad_len = gv_chunk_aad(header_bytes, header_len, idx, is_last, aad_buf);

        /* Ini pemeriksaan otentikasi PER-CHUNK -- lapis kedua (defense in
         * depth) di atas HMAC global yang SUDAH lolos di PASS 1. Kalau
         * sampai gagal di sini padahal HMAC global sudah valid, berarti
         * ada bug internal (harusnya mustahil scr matematis krn kedua
         * kunci berasal dari master key & password yg sama) -- tetap
         * dilaporkan sbg GV_ERR_AUTH, bukan diasumsikan "tidak mungkin". */
        if (!gv_aes_gcm_decrypt(enc_key, nonce, aad_buf, aad_len, ct_buf, pt_len, tag, pt_buf)) {
            result = GV_ERR_AUTH; goto done;
        }

        if (compressed) {
            if (!gv_inflate_feed(&inf, pt_buf, pt_len, out)) { result = GV_ERR_FORMAT; goto done; }
        } else if (pt_len > 0) {
            if (fwrite(pt_buf, 1, pt_len, out) != pt_len) { result = GV_ERR_IO; goto done; }
        }

        idx++;
        if (cb) cb("decrypt", ciphertext_region_size - remaining, ciphertext_region_size, cbctx);
        if (is_last) break;
    }

done:
    free(ct_buf);
    free(pt_buf);
    free(aad_buf);
    if (inf_active) gv_inflate_free(&inf);
    return result;
}

gv_status_t gv_decrypt_stream(FILE *in, uint64_t total_size, FILE *out,
                               const char *password, size_t password_len,
                               gv_header_t *out_meta,
                               gv_progress_cb cb, void *cbctx) {
    gv_header_t hdr;
    size_t header_len = 0;
    uint8_t *header_bytes = NULL;
    uint8_t master_key[GV_KEY_LEN];
    uint8_t enc_key[GV_KEY_LEN];
    uint8_t hmac_key[GV_HMAC_KEY_LEN];
    gv_status_t st;

    st = gv_header_read(in, &hdr, &header_len, &header_bytes);
    if (st != GV_OK) return st;

    if (total_size < (uint64_t)header_len + GV_HMAC_DIGEST_LEN) {
        free(header_bytes);
        return GV_ERR_FORMAT;
    }
    uint64_t ciphertext_region_size = total_size - header_len - GV_HMAC_DIGEST_LEN;

    off_t header_end_pos = ftello(in);
    if (header_end_pos < 0) { free(header_bytes); return GV_ERR_IO; }

    st = gv_kdf_derive(&hdr, password, password_len, master_key);
    if (st != GV_OK) { free(header_bytes); return st; }

    st = gv_derive_subkeys(master_key, hdr.salt, enc_key, hmac_key);
    gv_wipe(master_key, sizeof(master_key));
    if (st != GV_OK) { free(header_bytes); return st; }

    st = verify_stream_hmac(in, hmac_key, header_bytes, header_len, ciphertext_region_size, cb, cbctx);
    gv_wipe(hmac_key, sizeof(hmac_key));
    if (st != GV_OK) {
        free(header_bytes);
        gv_wipe(enc_key, sizeof(enc_key));
        return st;
    }

    if (fseeko(in, header_end_pos, SEEK_SET) != 0) {
        free(header_bytes);
        gv_wipe(enc_key, sizeof(enc_key));
        return GV_ERR_IO;
    }

    st = decrypt_chunks_loop(in, enc_key, hdr.nonce_prefix, header_bytes, header_len,
                              ciphertext_region_size, hdr.compressed, out, cb, cbctx);

    free(header_bytes);
    gv_wipe(enc_key, sizeof(enc_key));

    if (st == GV_OK && out_meta) *out_meta = hdr;
    return st;
}

/* ==========================================================================
 * Level FILE
 * ========================================================================== */
gv_status_t gv_encrypt_file(const char *in_path, const char *out_path,
                             const char *password, size_t password_len,
                             int compress, uint8_t kdf_id, size_t chunk_size,
                             gv_progress_cb cb, void *cbctx) {
    struct stat st_buf;
    if (stat(in_path, &st_buf) != 0) return GV_ERR_IO;

    FILE *in = fopen(in_path, "rb");
    if (!in) return GV_ERR_IO;
    FILE *out = fopen(out_path, "wb");
    if (!out) { fclose(in); return GV_ERR_IO; }

    const char *base = strrchr(in_path, '/');
    base = base ? base + 1 : in_path;

    gv_status_t st = gv_encrypt_stream(in, (uint64_t)st_buf.st_size, out,
                                        password, password_len, compress, base,
                                        (uint64_t)st_buf.st_size, kdf_id, chunk_size, cb, cbctx);
    fclose(in);
    if (fclose(out) != 0 && st == GV_OK) st = GV_ERR_IO;
    if (st != GV_OK) remove(out_path);
    return st;
}

gv_status_t gv_decrypt_file(const char *in_path, const char *out_path,
                             const char *password, size_t password_len,
                             gv_header_t *out_meta,
                             gv_progress_cb cb, void *cbctx) {
    struct stat st_buf;
    if (stat(in_path, &st_buf) != 0) return GV_ERR_IO;

    FILE *in = fopen(in_path, "rb");
    if (!in) return GV_ERR_IO;
    FILE *out = fopen(out_path, "wb");
    if (!out) { fclose(in); return GV_ERR_IO; }

    gv_status_t st = gv_decrypt_stream(in, (uint64_t)st_buf.st_size, out,
                                        password, password_len, out_meta, cb, cbctx);
    fclose(in);
    fclose(out);
    if (st != GV_OK) remove(out_path);  /* jangan tinggalkan plaintext parsial blm terautentikasi penuh */
    return st;
}

/* ==========================================================================
 * Level BYTES (teks) -- lewat tmpfile() supaya portable (lihat header).
 * ========================================================================== */
static gv_status_t read_whole_file(FILE *f, uint8_t **out, size_t *out_len) {
    if (fseeko(f, 0, SEEK_END) != 0) return GV_ERR_IO;
    off_t sz = ftello(f);
    if (sz < 0) return GV_ERR_IO;
    if (fseeko(f, 0, SEEK_SET) != 0) return GV_ERR_IO;

    uint8_t *buf = (uint8_t *)malloc((size_t)sz > 0 ? (size_t)sz : 1);
    if (!buf) return GV_ERR_MEMORY;
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); return GV_ERR_IO; }

    *out = buf;
    *out_len = (size_t)sz;
    return GV_OK;
}

gv_status_t gv_encrypt_bytes(const uint8_t *data, size_t data_len,
                              const char *password, size_t password_len,
                              int compress, uint8_t kdf_id,
                              uint8_t **out_blob, size_t *out_len) {
    FILE *in = tmpfile();
    if (!in) return GV_ERR_IO;
    if (data_len > 0 && fwrite(data, 1, data_len, in) != data_len) { fclose(in); return GV_ERR_IO; }
    rewind(in);

    FILE *out = tmpfile();
    if (!out) { fclose(in); return GV_ERR_IO; }

    gv_status_t st = gv_encrypt_stream(in, data_len, out, password, password_len,
                                        compress, NULL, 0, kdf_id, GV_DEFAULT_CHUNK_SIZE,
                                        NULL, NULL);
    fclose(in);
    if (st != GV_OK) { fclose(out); return st; }

    rewind(out);
    st = read_whole_file(out, out_blob, out_len);
    fclose(out);
    return st;
}

gv_status_t gv_decrypt_bytes(const uint8_t *blob, size_t blob_len,
                              const char *password, size_t password_len,
                              uint8_t **out_data, size_t *out_len) {
    FILE *in = tmpfile();
    if (!in) return GV_ERR_IO;
    if (blob_len > 0 && fwrite(blob, 1, blob_len, in) != blob_len) { fclose(in); return GV_ERR_IO; }
    rewind(in);

    FILE *out = tmpfile();
    if (!out) { fclose(in); return GV_ERR_IO; }

    gv_status_t st = gv_decrypt_stream(in, blob_len, out, password, password_len,
                                        NULL, NULL, NULL);
    fclose(in);
    if (st != GV_OK) { fclose(out); return st; }

    rewind(out);
    st = read_whole_file(out, out_data, out_len);
    fclose(out);
    return st;
}
