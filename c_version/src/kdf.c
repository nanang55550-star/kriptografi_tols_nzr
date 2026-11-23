#include "kdf.h"
#include "util.h"

#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#ifdef GV_WITH_ARGON2
#include <argon2.h>
#endif

int gv_argon2_available(void) {
#ifdef GV_WITH_ARGON2
    return 1;
#else
    return 0;
#endif
}

uint8_t gv_kdf_preferred(void) {
    return gv_argon2_available() ? GV_KDF_ARGON2ID : GV_KDF_PBKDF2;
}

void gv_kdf_default_params(gv_header_t *hdr, uint8_t kdf_id) {
    hdr->kdf_id = kdf_id;
    if (kdf_id == GV_KDF_ARGON2ID) {
        hdr->kdf_mem_cost    = GV_ARGON2_MEMORY_KIB;
        hdr->kdf_time_cost   = GV_ARGON2_TIME_COST;
        hdr->kdf_parallelism = GV_ARGON2_PARALLELISM;
    } else {
        hdr->kdf_mem_cost    = 0;
        hdr->kdf_time_cost   = GV_PBKDF2_ITERATIONS;
        hdr->kdf_parallelism = 0;
    }
}

static gv_status_t derive_argon2id(const gv_header_t *hdr, const char *password,
                                    size_t password_len, uint8_t *out_key) {
#ifdef GV_WITH_ARGON2
    int rc = argon2id_hash_raw(
        hdr->kdf_time_cost, hdr->kdf_mem_cost, hdr->kdf_parallelism,
        password, password_len, hdr->salt, GV_SALT_LEN, out_key, GV_KEY_LEN);
    return (rc == ARGON2_OK) ? GV_OK : GV_ERR_CRYPTO;
#else
    (void)hdr; (void)password; (void)password_len; (void)out_key;
    return GV_ERR_UNSUPPORTED;
#endif
}

static gv_status_t derive_pbkdf2(const gv_header_t *hdr, const char *password,
                                  size_t password_len, uint8_t *out_key) {
    int rc = PKCS5_PBKDF2_HMAC(password, (int)password_len,
                                hdr->salt, GV_SALT_LEN,
                                (int)hdr->kdf_time_cost, EVP_sha512(),
                                GV_KEY_LEN, out_key);
    return (rc == 1) ? GV_OK : GV_ERR_CRYPTO;
}

gv_status_t gv_kdf_derive(const gv_header_t *hdr, const char *password, size_t password_len,
                           uint8_t *out_key) {
    switch (hdr->kdf_id) {
        case GV_KDF_ARGON2ID: return derive_argon2id(hdr, password, password_len, out_key);
        case GV_KDF_PBKDF2:   return derive_pbkdf2(hdr, password, password_len, out_key);
        default:              return GV_ERR_UNSUPPORTED;
    }
}

/* ---- HKDF-SHA512 (RFC 5869), extract + satu blok expand -------------- */

static int hmac_sha512(const uint8_t *key, size_t keylen,
                        const uint8_t *data, size_t datalen,
                        uint8_t out[64]) {
    unsigned int outlen = 0;
    unsigned char *res = HMAC(EVP_sha512(), key, (int)keylen, data, datalen, out, &outlen);
    return (res != NULL && outlen == 64) ? 1 : 0;
}

int gv_hkdf_sha512(const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *okm, size_t okm_len) {
    if (okm_len == 0 || okm_len > 64) return 0;

    uint8_t prk[64];
    if (!hmac_sha512(salt, salt_len, ikm, ikm_len, prk)) return 0;

    uint8_t *msg = (uint8_t *)malloc(info_len + 1);
    if (!msg) { gv_wipe(prk, sizeof(prk)); return 0; }
    if (info_len) memcpy(msg, info, info_len);
    msg[info_len] = 0x01;   /* T(1) = HMAC(PRK, T(0)=empty || info || 0x01) */

    uint8_t t1[64];
    int ok = hmac_sha512(prk, sizeof(prk), msg, info_len + 1, t1);

    gv_wipe(msg, info_len + 1);
    free(msg);
    gv_wipe(prk, sizeof(prk));

    if (!ok) return 0;
    memcpy(okm, t1, okm_len);
    gv_wipe(t1, sizeof(t1));
    return 1;
}

gv_status_t gv_derive_subkeys(const uint8_t *master_key, const uint8_t *salt,
                               uint8_t *enc_key, uint8_t *hmac_key) {
    static const char info_enc[]  = "godvault-c-enc-key-v1";
    static const char info_hmac[] = "godvault-c-hmac-key-v1";

    if (!gv_hkdf_sha512(master_key, GV_KEY_LEN, salt, GV_SALT_LEN,
                         (const uint8_t *)info_enc, sizeof(info_enc) - 1,
                         enc_key, GV_KEY_LEN))
        return GV_ERR_CRYPTO;

    if (!gv_hkdf_sha512(master_key, GV_KEY_LEN, salt, GV_SALT_LEN,
                         (const uint8_t *)info_hmac, sizeof(info_hmac) - 1,
                         hmac_key, GV_HMAC_KEY_LEN))
        return GV_ERR_CRYPTO;

    return GV_OK;
}
