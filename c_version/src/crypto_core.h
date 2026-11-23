#ifndef GODVAULT_CRYPTO_CORE_H
#define GODVAULT_CRYPTO_CORE_H

#include "vault_format.h"
#include <openssl/evp.h>

/* ---- Nonce & AAD (sama filosofi dgn versi Python: nonce COUNTER-based,
 * bukan acak per-chunk -- lihat catatan desain di README/komentar utama) */
void gv_make_nonce(const uint8_t prefix[GV_NONCE_PREFIX_LEN], uint64_t counter,
                    uint8_t out[GV_NONCE_LEN]);

/* aad_out harus buffer >= header_len + 9 byte. Return panjang AAD. */
size_t gv_chunk_aad(const uint8_t *header_bytes, size_t header_len,
                     uint64_t chunk_index, int is_last, uint8_t *aad_out);

/* ---- AES-256-GCM, satu chunk ------------------------------------------ */
/* ciphertext_out harus >= plaintext_len byte. tag_out harus GV_GCM_TAG_LEN byte. */
int gv_aes_gcm_encrypt(const uint8_t key[GV_KEY_LEN], const uint8_t nonce[GV_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext_out, uint8_t tag_out[GV_GCM_TAG_LEN]);

/* plaintext_out harus >= ciphertext_len byte. Return 1 kalau tag valid
 * (OTENTIK), 0 kalau GAGAL (password salah / data dimanipulasi) -- INI
 * PEMERIKSAAN KEAMANAN PALING KRITIS DI SELURUH MODUL, jangan pernah
 * diabaikan return value-nya. */
int gv_aes_gcm_decrypt(const uint8_t key[GV_KEY_LEN], const uint8_t nonce[GV_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t tag[GV_GCM_TAG_LEN],
                        uint8_t *plaintext_out);

/* ---- HMAC-SHA512 streaming (lapis autentikasi GLOBAL kedua) ----------- */
typedef struct {
    EVP_MAC_CTX *ctx;
} gv_hmac_stream_t;

int  gv_hmac_stream_init(gv_hmac_stream_t *hs, const uint8_t key[GV_HMAC_KEY_LEN]);
int  gv_hmac_stream_update(gv_hmac_stream_t *hs, const uint8_t *data, size_t len);
int  gv_hmac_stream_final(gv_hmac_stream_t *hs, uint8_t out[GV_HMAC_DIGEST_LEN]);
void gv_hmac_stream_abort(gv_hmac_stream_t *hs);  /* pembersihan kalau batal di tengah */

/* Constant-time compare -- WAJIB dipakai utk membandingkan HMAC/tag,
 * JANGAN PERNAH pakai memcmp() biasa (rentan timing side-channel). */
int gv_const_time_eq(const uint8_t *a, const uint8_t *b, size_t len);

#endif /* GODVAULT_CRYPTO_CORE_H */
