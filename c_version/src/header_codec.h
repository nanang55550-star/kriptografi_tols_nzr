#ifndef GODVAULT_HEADER_CODEC_H
#define GODVAULT_HEADER_CODEC_H

#include "vault_format.h"
#include <stdio.h>

size_t gv_header_packed_size(const gv_header_t *hdr);

/* out harus buffer >= gv_header_packed_size(hdr) byte. Return jumlah byte ditulis. */
size_t gv_header_pack(const gv_header_t *hdr, uint8_t *out);

/* Baca & parse header LANGSUNG dari FILE* (streaming, tanpa perlu memuat
 * seluruh vault). *header_bytes_out diisi buffer BARU berisi byte mentah
 * PERSIS SEPERTI DIBACA (bukan hasil re-pack) -- supaya AAD/HMAC yang
 * dihitung dari situ dijamin cocok dgn apa yang benar-benar ada di disk,
 * termasuk untuk kasus tepi (byte reserved, dst). Caller wajib free()
 * *header_bytes_out setelah selesai.
 *
 * SEMUA kegagalan (byte kurang, magic salah, versi tak didukung, dll)
 * kembali sbg gv_status_t yang sesuai -- tidak pernah crash/UB walau
 * input sepenuhnya acak/dimanipulasi. */
gv_status_t gv_header_read(FILE *f, gv_header_t *hdr,
                            size_t *header_len_out, uint8_t **header_bytes_out);

#endif /* GODVAULT_HEADER_CODEC_H */
