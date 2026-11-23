#ifndef GODVAULT_KDF_H
#define GODVAULT_KDF_H

#include "vault_format.h"

/* Derive kunci master GV_KEY_LEN byte dari password+salt, memakai KDF
 * yang ditentukan kdf_id & parameter di header. Return GV_OK atau kode
 * error. out harus buffer >= GV_KEY_LEN byte. */
gv_status_t gv_kdf_derive(const gv_header_t *hdr, const char *password, size_t password_len,
                           uint8_t *out_key);

/* Isi field kdf_* di header dengan parameter DEFAULT saat ini utk kdf_id
 * yang diminta (dipanggil saat ENKRIPSI, sebelum header ditulis). */
void gv_kdf_default_params(gv_header_t *hdr, uint8_t kdf_id);

/* 1 kalau libargon2 tersedia di build ini, 0 kalau tidak (fallback PBKDF2
 * saja) -- ekuivalen ARGON2_AVAILABLE di versi Python. */
int gv_argon2_available(void);

/* KDF_ARGON2ID kalau tersedia, else KDF_PBKDF2 -- ekuivalen
 * KDFEngine.preferred() di versi Python. */
uint8_t gv_kdf_preferred(void);

/* HKDF-SHA512 (RFC 5869), dibangun dari HMAC-SHA512 OpenSSL yang sudah
 * teraudit -- ini implementasi KONSTRUKSI standar (bukan primitif baru),
 * divalidasi silang terhadap output pustaka `cryptography` Python (lihat
 * tests/test_vault.c). Batas okm_len <= 64 (satu blok expand) -- cukup
 * utk semua kebutuhan modul ini (kunci 32 byte).
 * Return 1 sukses, 0 gagal. */
int gv_hkdf_sha512(const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *okm, size_t okm_len);

/* Turunkan kunci enkripsi & kunci HMAC yang TERPISAH dari master_key,
 * lewat HKDF-SHA512 dengan info-string berbeda -- persis filosofi
 * derive_subkeys() di versi Python (key separation). */
gv_status_t gv_derive_subkeys(const uint8_t *master_key, const uint8_t *salt,
                               uint8_t *enc_key /* GV_KEY_LEN */,
                               uint8_t *hmac_key /* GV_HMAC_KEY_LEN */);

#endif /* GODVAULT_KDF_H */
