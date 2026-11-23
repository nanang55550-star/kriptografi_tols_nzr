#include "crypto_core.h"
#include "util.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

void gv_make_nonce(const uint8_t prefix[GV_NONCE_PREFIX_LEN], uint64_t counter,
                    uint8_t out[GV_NONCE_LEN]) {
    memcpy(out, prefix, GV_NONCE_PREFIX_LEN);
    gv_put_u64(out + GV_NONCE_PREFIX_LEN, counter);
}

size_t gv_chunk_aad(const uint8_t *header_bytes, size_t header_len,
                     uint64_t chunk_index, int is_last, uint8_t *aad_out) {
    memcpy(aad_out, header_bytes, header_len);
    gv_put_u64(aad_out + header_len, chunk_index);
    aad_out[header_len + 8] = is_last ? 1 : 0;
    return header_len + 9;
}

int gv_aes_gcm_encrypt(const uint8_t key[GV_KEY_LEN], const uint8_t nonce[GV_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext_out, uint8_t tag_out[GV_GCM_TAG_LEN]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int ok = 1;
    int len = 0, outlen = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) ok = 0;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GV_NONCE_LEN, NULL) != 1) ok = 0;
    if (ok && EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) ok = 0;
    if (ok && aad_len > 0 &&
        EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) ok = 0;
    if (ok && EVP_EncryptUpdate(ctx, ciphertext_out, &len, plaintext, (int)plaintext_len) != 1) ok = 0;
    if (ok) outlen = len;
    if (ok && EVP_EncryptFinal_ex(ctx, ciphertext_out + outlen, &len) != 1) ok = 0;
    if (ok) outlen += len;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GV_GCM_TAG_LEN, tag_out) != 1) ok = 0;

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int gv_aes_gcm_decrypt(const uint8_t key[GV_KEY_LEN], const uint8_t nonce[GV_NONCE_LEN],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t tag[GV_GCM_TAG_LEN],
                        uint8_t *plaintext_out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int ok = 1;
    int len = 0, outlen = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) ok = 0;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GV_NONCE_LEN, NULL) != 1) ok = 0;
    if (ok && EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) ok = 0;
    if (ok && aad_len > 0 &&
        EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) ok = 0;
    if (ok && EVP_DecryptUpdate(ctx, plaintext_out, &len, ciphertext, (int)ciphertext_len) != 1) ok = 0;
    if (ok) outlen = len;

    if (ok) {
        /* set_tag TIDAK boleh diabaikan; kalau gagal set, jangan lanjut final */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GV_GCM_TAG_LEN, (void *)tag) != 1)
            ok = 0;
    }

    /* EVP_DecryptFinal_ex mengembalikan <=0 KALAU TAG TIDAK COCOK -- ini
     * satu-satunya sinyal otentikasi GCM yang sah. Nilai baliknya WAJIB
     * diperiksa; mengabaikannya = melewatkan verifikasi otentikasi. */
    int final_ret = ok ? EVP_DecryptFinal_ex(ctx, plaintext_out + outlen, &len) : 0;

    EVP_CIPHER_CTX_free(ctx);
    return (ok && final_ret == 1) ? 1 : 0;
}

/* ---- HMAC-SHA512 streaming lewat EVP_MAC (API modern OpenSSL 3.x,
 * menggantikan HMAC_CTX yang deprecated) --------------------------------- */

int gv_hmac_stream_init(gv_hmac_stream_t *hs, const uint8_t key[GV_HMAC_KEY_LEN]) {
    hs->ctx = NULL;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) return 0;

    hs->ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!hs->ctx) return 0;

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA512", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(hs->ctx, key, GV_HMAC_KEY_LEN, params) != 1) {
        EVP_MAC_CTX_free(hs->ctx);
        hs->ctx = NULL;
        return 0;
    }
    return 1;
}

int gv_hmac_stream_update(gv_hmac_stream_t *hs, const uint8_t *data, size_t len) {
    if (!hs->ctx) return 0;
    if (len == 0) return 1;
    return EVP_MAC_update(hs->ctx, data, len) == 1;
}

int gv_hmac_stream_final(gv_hmac_stream_t *hs, uint8_t out[GV_HMAC_DIGEST_LEN]) {
    if (!hs->ctx) return 0;
    size_t outlen = 0;
    int ok = EVP_MAC_final(hs->ctx, out, &outlen, GV_HMAC_DIGEST_LEN) == 1 &&
             outlen == GV_HMAC_DIGEST_LEN;
    EVP_MAC_CTX_free(hs->ctx);
    hs->ctx = NULL;
    return ok;
}

void gv_hmac_stream_abort(gv_hmac_stream_t *hs) {
    if (hs->ctx) {
        EVP_MAC_CTX_free(hs->ctx);
        hs->ctx = NULL;
    }
}

int gv_const_time_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    return CRYPTO_memcmp(a, b, len) == 0;
}
