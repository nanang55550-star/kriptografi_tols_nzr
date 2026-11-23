#ifndef GODVAULT_VAULT_API_H
#define GODVAULT_VAULT_API_H

#include "vault_format.h"
#include <stdio.h>

typedef void (*gv_progress_cb)(const char *stage, uint64_t done, uint64_t total, void *ctx);

/* ---- Level stream (FILE*) ---------------------------------------------
 * Sepenuhnya streaming, memori nyaris konstan (tidak proporsional dgn
 * ukuran data) baik compress aktif maupun tidak -- lihat payload_iter.c
 * & compress.c. Dua-pass di sisi dekripsi: PASS 1 verifikasi HMAC global
 * dulu (constant-time compare), BARU PASS 2 dekripsi & tulis progresif --
 * plaintext yang belum terautentikasi tidak pernah sempat ditulis. */

gv_status_t gv_encrypt_stream(FILE *in, uint64_t input_total_size, FILE *out,
                               const char *password, size_t password_len,
                               int compress, const char *filename, uint64_t source_size,
                               uint8_t kdf_id, size_t chunk_size,
                               gv_progress_cb cb, void *cbctx);

/* out_meta boleh NULL kalau metadata tidak dibutuhkan. */
gv_status_t gv_decrypt_stream(FILE *in, uint64_t total_size, FILE *out,
                               const char *password, size_t password_len,
                               gv_header_t *out_meta,
                               gv_progress_cb cb, void *cbctx);

/* ---- Level file --------------------------------------------------------- */
gv_status_t gv_encrypt_file(const char *in_path, const char *out_path,
                             const char *password, size_t password_len,
                             int compress, uint8_t kdf_id, size_t chunk_size,
                             gv_progress_cb cb, void *cbctx);

gv_status_t gv_decrypt_file(const char *in_path, const char *out_path,
                             const char *password, size_t password_len,
                             gv_header_t *out_meta,
                             gv_progress_cb cb, void *cbctx);

/* ---- Level bytes (utk teks/pesan) --------------------------------------
 * Internal memakai tmpfile() (bukan fmemopen/open_memstream) supaya
 * portable ke semua target termasuk Termux/Android, yang riwayat
 * dukungan fmemopen/open_memstream di Bionic libc-nya tidak konsisten
 * antar versi Android. */
gv_status_t gv_encrypt_bytes(const uint8_t *data, size_t data_len,
                              const char *password, size_t password_len,
                              int compress, uint8_t kdf_id,
                              uint8_t **out_blob, size_t *out_len);

gv_status_t gv_decrypt_bytes(const uint8_t *blob, size_t blob_len,
                              const char *password, size_t password_len,
                              uint8_t **out_data, size_t *out_len);

#endif /* GODVAULT_VAULT_API_H */
